// SPDX-License-Identifier: Elastic-2.0

//! Durable bindings between normalized provider sessions and Automonique runs.
//!
//! The provider's session identifier is observed from its normalized stdout,
//! never inferred from filenames or "most recent" state.  One row names the
//! latest Automonique run for that resumable provider session.  A follow-up
//! therefore has an exact provider binding and an exact run to observe after a
//! daemon restart.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use automonique_protocol::mobile_session::{
    MAX_MOBILE_HISTORY_DECIMAL, MAX_MOBILE_HISTORY_EVENTS, MobileHistoryBody, MobileHistoryCursor,
    MobileHistoryEvent, MobileHistoryMessage, MobileHistoryPage, MobileHistoryResync,
    MobileHistoryResyncReason, MobileMessageRole, MobileRunState, MobileToolState,
    MobileUnknownEventKind,
};
use automonique_protocol::platform::{IdempotencyKey, PlatformText, ReceiptOutcome, ResourceId};
use automonique_protocol::primitives::EpochMillis;
use automonique_protocol::tools::RunId;
use nix::unistd::geteuid;
use rusqlite::{Connection, OpenFlags, OptionalExtension as _, TransactionBehavior, params};

const SCHEMA_VERSION: u32 = 2;
const MAX_SESSIONS: usize = automonique_protocol::platform::MAX_SNAPSHOT_RESOURCES;

const SCHEMA: &str = r#"
CREATE TABLE managed_sessions (
    provider_session_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('open', 'lost')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    created_ms INTEGER NOT NULL CHECK (created_ms >= 0),
    updated_ms INTEGER NOT NULL CHECK (updated_ms >= created_ms)
) STRICT;
CREATE UNIQUE INDEX managed_sessions_by_run ON managed_sessions(run_id);
CREATE TABLE managed_receipt_intents (
    outbox_key TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    outcome TEXT NOT NULL CHECK (outcome IN ('completed', 'rejected')),
    explanation TEXT,
    created_ms INTEGER NOT NULL CHECK (created_ms >= 0)
) STRICT;
CREATE TABLE managed_session_history_meta (
    provider_session_id TEXT PRIMARY KEY,
    next_cursor INTEGER NOT NULL CHECK (next_cursor >= 1),
    retained_from INTEGER NOT NULL CHECK (retained_from >= 1),
    terminal_cursor INTEGER NOT NULL CHECK (terminal_cursor >= 0),
    FOREIGN KEY(provider_session_id) REFERENCES managed_sessions(provider_session_id)
) STRICT;
CREATE TABLE managed_session_history (
    provider_session_id TEXT NOT NULL,
    cursor INTEGER NOT NULL CHECK (cursor >= 1),
    source_run_id TEXT NOT NULL,
    source_sequence INTEGER NOT NULL CHECK (source_sequence >= 1),
    at_ms INTEGER NOT NULL CHECK (at_ms >= 0),
    event_kind TEXT NOT NULL CHECK (event_kind IN ('message','tool_state','run_state','unknown')),
    role TEXT,
    message TEXT,
    tool_state TEXT,
    run_state TEXT,
    unknown_kind TEXT,
    PRIMARY KEY(provider_session_id,cursor),
    UNIQUE(provider_session_id,source_run_id,source_sequence),
    FOREIGN KEY(provider_session_id) REFERENCES managed_sessions(provider_session_id)
) STRICT;
CREATE INDEX managed_session_history_source
    ON managed_session_history(provider_session_id,source_run_id,source_sequence);
"#;

const MIGRATE_V1_TO_V2: &str = r#"
CREATE TABLE managed_session_history_meta (
    provider_session_id TEXT PRIMARY KEY,
    next_cursor INTEGER NOT NULL CHECK (next_cursor >= 1),
    retained_from INTEGER NOT NULL CHECK (retained_from >= 1),
    terminal_cursor INTEGER NOT NULL CHECK (terminal_cursor >= 0),
    FOREIGN KEY(provider_session_id) REFERENCES managed_sessions(provider_session_id)
) STRICT;
CREATE TABLE managed_session_history (
    provider_session_id TEXT NOT NULL,
    cursor INTEGER NOT NULL CHECK (cursor >= 1),
    source_run_id TEXT NOT NULL,
    source_sequence INTEGER NOT NULL CHECK (source_sequence >= 1),
    at_ms INTEGER NOT NULL CHECK (at_ms >= 0),
    event_kind TEXT NOT NULL CHECK (event_kind IN ('message','tool_state','run_state','unknown')),
    role TEXT,
    message TEXT,
    tool_state TEXT,
    run_state TEXT,
    unknown_kind TEXT,
    PRIMARY KEY(provider_session_id,cursor),
    UNIQUE(provider_session_id,source_run_id,source_sequence),
    FOREIGN KEY(provider_session_id) REFERENCES managed_sessions(provider_session_id)
) STRICT;
CREATE INDEX managed_session_history_source
    ON managed_session_history(provider_session_id,source_run_id,source_sequence);
"#;

#[derive(Debug)]
pub enum ManagedSessionError {
    InvalidField(&'static str),
    InsecurePath,
    SchemaVersion,
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
}

impl ManagedSessionError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InvalidField(_) => "managed_session_invalid",
            Self::InsecurePath => "managed_session_insecure",
            Self::SchemaVersion => "managed_session_schema",
            Self::Sqlite(_) => "managed_session_sqlite",
            Self::Io(_) => "managed_session_io",
        }
    }
}

impl From<rusqlite::Error> for ManagedSessionError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<std::io::Error> for ManagedSessionError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Managed<T> = Result<T, ManagedSessionError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedSession {
    pub provider_session_id: String,
    pub run_id: String,
    pub open: bool,
    pub revision: u64,
    pub created_ms: i64,
    pub updated_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedReceiptIntent {
    pub outbox_key: String,
    pub idempotency_key: String,
    pub outcome: ReceiptOutcome,
    pub explanation: Option<String>,
    pub created_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagedHistoryPage {
    Page(MobileHistoryPage),
    Resync(MobileHistoryResync),
}

pub struct ManagedSessionStore {
    connection: Connection,
    path: PathBuf,
}

impl ManagedSessionStore {
    pub fn open(path: impl AsRef<Path>) -> Managed<Self> {
        let path = path.as_ref();
        secure_path(path)?;
        if !path.exists() {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
        }
        secure_path(path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = Connection::open_with_flags(path, flags)?;
        automonique_store::sqlite_policy::configure_authoritative(&connection)?;
        initialize(&mut connection)?;
        Ok(Self {
            connection,
            path: path.to_path_buf(),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn observe(
        &mut self,
        provider_session_id: &str,
        run_id: &str,
        now_ms: i64,
    ) -> Managed<ManagedSession> {
        validate(provider_session_id, run_id, now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = read(&transaction, provider_session_id)?;
        match existing {
            Some(existing) if existing.run_id == run_id && existing.open => {
                transaction.commit()?;
                return Ok(existing);
            }
            Some(existing) => {
                let revision = existing
                    .revision
                    .checked_add(1)
                    .ok_or(ManagedSessionError::InvalidField("revision"))?;
                transaction.execute(
                    "UPDATE managed_sessions SET run_id=?2,state='open',revision=?3,updated_ms=?4
                     WHERE provider_session_id=?1 AND revision=?5",
                    params![
                        provider_session_id,
                        run_id,
                        to_i64(revision)?,
                        now_ms,
                        to_i64(existing.revision)?
                    ],
                )?;
            }
            None => {
                transaction.execute(
                    "INSERT INTO managed_sessions(provider_session_id,run_id,state,revision,created_ms,updated_ms)
                     VALUES(?1,?2,'open',1,?3,?3)",
                    params![provider_session_id, run_id, now_ms],
                )?;
            }
        }
        let row = read(&transaction, provider_session_id)?
            .ok_or(ManagedSessionError::InvalidField("missing_session"))?;
        transaction.commit()?;
        Ok(row)
    }

    pub fn by_id(&self, provider_session_id: &str) -> Managed<Option<ManagedSession>> {
        ResourceId::new(provider_session_id)
            .map_err(|_| ManagedSessionError::InvalidField("provider_session_id"))?;
        read(&self.connection, provider_session_id)
    }

    pub fn by_run(&self, run_id: &str) -> Managed<Option<ManagedSession>> {
        RunId::new(run_id).map_err(|_| ManagedSessionError::InvalidField("run_id"))?;
        self.connection
            .query_row(
                "SELECT provider_session_id,run_id,state,revision,created_ms,updated_ms
                 FROM managed_sessions WHERE run_id=?1",
                [run_id],
                decode,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list(&self) -> Managed<Vec<ManagedSession>> {
        let mut statement = self.connection.prepare(
            "SELECT provider_session_id,run_id,state,revision,created_ms,updated_ms
             FROM managed_sessions ORDER BY updated_ms DESC,provider_session_id LIMIT ?1",
        )?;
        let limit =
            i64::try_from(MAX_SESSIONS).map_err(|_| ManagedSessionError::InvalidField("limit"))?;
        let rows = statement.query_map([limit], decode)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Mirror a platform receipt effect before the scheduler transaction that
    /// makes it eligible for delivery.  This tiny typed record is sufficient
    /// to prove the exact idempotent platform effect after an outbox lease is
    /// abandoned by a crashed generation.
    pub fn record_receipt_intent(
        &mut self,
        outbox_key: &str,
        idempotency_key: &str,
        outcome: ReceiptOutcome,
        explanation: Option<&str>,
        now_ms: i64,
    ) -> Managed<ManagedReceiptIntent> {
        validate_receipt_intent(outbox_key, idempotency_key, outcome, explanation, now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO managed_receipt_intents(outbox_key,idempotency_key,outcome,explanation,created_ms)
             VALUES(?1,?2,?3,?4,?5) ON CONFLICT(outbox_key) DO NOTHING",
            params![
                outbox_key,
                idempotency_key,
                outcome.as_str(),
                explanation,
                now_ms
            ],
        )?;
        let intent = read_receipt_intent(&transaction, outbox_key)?
            .ok_or(ManagedSessionError::InvalidField("missing_receipt_intent"))?;
        if intent.idempotency_key != idempotency_key
            || intent.outcome != outcome
            || intent.explanation.as_deref() != explanation
        {
            return Err(ManagedSessionError::InvalidField("receipt_intent_conflict"));
        }
        transaction.commit()?;
        Ok(intent)
    }

    pub fn receipt_intent(&self, outbox_key: &str) -> Managed<Option<ManagedReceiptIntent>> {
        IdempotencyKey::new(outbox_key)
            .map_err(|_| ManagedSessionError::InvalidField("outbox_key"))?;
        read_receipt_intent(&self.connection, outbox_key)
    }

    /// Persist one already-sanitized public event. The source coordinate makes
    /// retries idempotent; conflicting or rewinding source rows fail closed.
    pub fn append_history_event(
        &mut self,
        provider_session_id: &str,
        source_run_id: &str,
        source_sequence: u64,
        at_ms: i64,
        body: MobileHistoryBody,
    ) -> Managed<MobileHistoryEvent> {
        ResourceId::new(provider_session_id)
            .map_err(|_| ManagedSessionError::InvalidField("provider_session_id"))?;
        let run_id =
            RunId::new(source_run_id).map_err(|_| ManagedSessionError::InvalidField("run_id"))?;
        if source_sequence == 0
            || at_ms < 0
            || u64::try_from(at_ms).map_or(true, |value| value > MAX_MOBILE_HISTORY_DECIMAL)
        {
            return Err(ManagedSessionError::InvalidField("history_coordinate"));
        }
        validate_history_body(&body)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if read(&transaction, provider_session_id)?.is_none() {
            return Err(ManagedSessionError::InvalidField("unknown_session"));
        }
        if let Some(existing) = read_history_source(
            &transaction,
            provider_session_id,
            source_run_id,
            source_sequence,
        )? {
            if existing.at_ms == EpochMillis::from_millis(at_ms)
                && existing.run_id == run_id
                && existing.body == body
            {
                transaction.commit()?;
                return Ok(existing);
            }
            return Err(ManagedSessionError::InvalidField("history_source_conflict"));
        }
        let previous: Option<i64> = transaction.query_row(
            "SELECT MAX(source_sequence) FROM managed_session_history
             WHERE provider_session_id=?1 AND source_run_id=?2",
            params![provider_session_id, source_run_id],
            |row| row.get(0),
        )?;
        if previous.is_some_and(|value| value >= to_i64(source_sequence).unwrap_or(i64::MAX)) {
            return Err(ManagedSessionError::InvalidField("history_source_rewind"));
        }
        let (cursor, retained_from) = transaction
            .query_row(
                "SELECT next_cursor,retained_from FROM managed_session_history_meta
                 WHERE provider_session_id=?1",
                [provider_session_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .unwrap_or((1, 1));
        let next = cursor
            .checked_add(1)
            .ok_or(ManagedSessionError::InvalidField("history_cursor"))?;
        if u64::try_from(cursor).map_or(true, |value| value > MAX_MOBILE_HISTORY_DECIMAL) {
            return Err(ManagedSessionError::InvalidField("history_cursor"));
        }
        let (role, message, tool_state, run_state, unknown_kind) = history_columns(&body);
        transaction.execute(
            "INSERT INTO managed_session_history(
               provider_session_id,cursor,source_run_id,source_sequence,at_ms,event_kind,
               role,message,tool_state,run_state,unknown_kind)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                provider_session_id,
                cursor,
                source_run_id,
                to_i64(source_sequence)?,
                at_ms,
                body.kind(),
                role,
                message,
                tool_state,
                run_state,
                unknown_kind
            ],
        )?;
        transaction.execute(
            "INSERT INTO managed_session_history_meta(
               provider_session_id,next_cursor,retained_from,terminal_cursor)
             VALUES(?1,?2,?3,?4)
             ON CONFLICT(provider_session_id) DO UPDATE SET
               next_cursor=excluded.next_cursor,terminal_cursor=excluded.terminal_cursor",
            params![provider_session_id, next, retained_from, cursor],
        )?;
        let maximum = i64::try_from(MAX_MOBILE_HISTORY_EVENTS)
            .map_err(|_| ManagedSessionError::InvalidField("history_retention"))?;
        let wanted_floor = cursor.saturating_sub(maximum.saturating_sub(1)).max(1);
        if wanted_floor > retained_from {
            transaction.execute(
                "DELETE FROM managed_session_history
                 WHERE provider_session_id=?1 AND cursor<?2",
                params![provider_session_id, wanted_floor],
            )?;
            transaction.execute(
                "UPDATE managed_session_history_meta SET retained_from=?2
                 WHERE provider_session_id=?1",
                params![provider_session_id, wanted_floor],
            )?;
        }
        let event = read_history_cursor(&transaction, provider_session_id, cursor)?
            .ok_or(ManagedSessionError::InvalidField("missing_history_event"))?;
        transaction.commit()?;
        Ok(event)
    }

    /// Read a snapshot (`exclusive_cursor=None`) or a forward page. A cursor
    /// outside the retained contiguous window yields a typed resync result.
    pub fn history_page(
        &self,
        provider_session_id: &str,
        exclusive_cursor: Option<MobileHistoryCursor>,
        requested_limit: usize,
        authorization_limit: usize,
    ) -> Managed<ManagedHistoryPage> {
        ResourceId::new(provider_session_id)
            .map_err(|_| ManagedSessionError::InvalidField("provider_session_id"))?;
        if requested_limit == 0 || authorization_limit == 0 {
            return Err(ManagedSessionError::InvalidField("history_limit"));
        }
        if read(&self.connection, provider_session_id)?.is_none() {
            return Err(ManagedSessionError::InvalidField("unknown_session"));
        }
        let applied_limit = requested_limit
            .min(authorization_limit)
            .min(MAX_MOBILE_HISTORY_EVENTS);
        let meta = self
            .connection
            .query_row(
                "SELECT retained_from,terminal_cursor FROM managed_session_history_meta
                 WHERE provider_session_id=?1",
                [provider_session_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .unwrap_or((1, 0));
        let retained_from = from_i64(meta.0, "retained_from")?;
        let terminal = from_i64(meta.1, "terminal_cursor")?;
        let earliest_exclusive = retained_from.saturating_sub(1);
        let after = exclusive_cursor.map_or(earliest_exclusive, MobileHistoryCursor::get);
        if exclusive_cursor.is_some() && after < earliest_exclusive {
            return Ok(ManagedHistoryPage::Resync(MobileHistoryResync {
                schema: automonique_protocol::mobile_session::MOBILE_SESSION_SCHEMA_V1,
                session_id: provider_session_id.to_owned(),
                reason: MobileHistoryResyncReason::RetentionExpired,
                requested_cursor: MobileHistoryCursor::new(after),
                earliest_cursor: MobileHistoryCursor::new(earliest_exclusive),
                terminal_cursor: MobileHistoryCursor::new(terminal),
            }));
        }
        if after > terminal {
            return Ok(ManagedHistoryPage::Resync(MobileHistoryResync {
                schema: automonique_protocol::mobile_session::MOBILE_SESSION_SCHEMA_V1,
                session_id: provider_session_id.to_owned(),
                reason: MobileHistoryResyncReason::CursorGap,
                requested_cursor: MobileHistoryCursor::new(after),
                earliest_cursor: MobileHistoryCursor::new(earliest_exclusive),
                terminal_cursor: MobileHistoryCursor::new(terminal),
            }));
        }
        let query_limit = applied_limit
            .checked_add(1)
            .ok_or(ManagedSessionError::InvalidField("history_limit"))?;
        let mut statement = self.connection.prepare(
            "SELECT cursor,source_run_id,at_ms,event_kind,role,message,tool_state,run_state,unknown_kind
             FROM managed_session_history
             WHERE provider_session_id=?1 AND cursor>?2 AND cursor<=?3
             ORDER BY cursor LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![
                provider_session_id,
                to_i64(after)?,
                to_i64(terminal)?,
                i64::try_from(query_limit)
                    .map_err(|_| ManagedSessionError::InvalidField("history_limit"))?
            ],
            decode_history,
        )?;
        let mut events = rows.collect::<Result<Vec<_>, _>>()?;
        let has_more = events.len() > applied_limit;
        events.truncate(applied_limit);
        Ok(ManagedHistoryPage::Page(MobileHistoryPage {
            schema: automonique_protocol::mobile_session::MOBILE_SESSION_SCHEMA_V1,
            session_id: provider_session_id.to_owned(),
            requested_limit,
            applied_limit,
            exclusive_cursor: MobileHistoryCursor::new(after),
            terminal_cursor: MobileHistoryCursor::new(terminal),
            has_more,
            events,
        }))
    }
}

fn validate(provider_session_id: &str, run_id: &str, now_ms: i64) -> Managed<()> {
    ResourceId::new(provider_session_id)
        .map_err(|_| ManagedSessionError::InvalidField("provider_session_id"))?;
    RunId::new(run_id).map_err(|_| ManagedSessionError::InvalidField("run_id"))?;
    if now_ms < 0 {
        return Err(ManagedSessionError::InvalidField("now_ms"));
    }
    Ok(())
}

fn read(connection: &Connection, id: &str) -> Managed<Option<ManagedSession>> {
    connection
        .query_row(
            "SELECT provider_session_id,run_id,state,revision,created_ms,updated_ms
             FROM managed_sessions WHERE provider_session_id=?1",
            [id],
            decode,
        )
        .optional()
        .map_err(Into::into)
}

fn validate_receipt_intent(
    outbox_key: &str,
    idempotency_key: &str,
    outcome: ReceiptOutcome,
    explanation: Option<&str>,
    now_ms: i64,
) -> Managed<()> {
    IdempotencyKey::new(outbox_key).map_err(|_| ManagedSessionError::InvalidField("outbox_key"))?;
    IdempotencyKey::new(idempotency_key)
        .map_err(|_| ManagedSessionError::InvalidField("idempotency_key"))?;
    if !matches!(
        outcome,
        ReceiptOutcome::Completed | ReceiptOutcome::Rejected
    ) {
        return Err(ManagedSessionError::InvalidField("receipt_outcome"));
    }
    if let Some(explanation) = explanation {
        PlatformText::new(explanation)
            .map_err(|_| ManagedSessionError::InvalidField("explanation"))?;
    }
    if now_ms < 0 {
        return Err(ManagedSessionError::InvalidField("now_ms"));
    }
    Ok(())
}

fn read_receipt_intent(
    connection: &Connection,
    outbox_key: &str,
) -> Managed<Option<ManagedReceiptIntent>> {
    connection
        .query_row(
            "SELECT outbox_key,idempotency_key,outcome,explanation,created_ms
             FROM managed_receipt_intents WHERE outbox_key=?1",
            [outbox_key],
            |row| {
                let outcome = match row.get::<_, String>(2)?.as_str() {
                    "completed" => ReceiptOutcome::Completed,
                    "rejected" => ReceiptOutcome::Rejected,
                    _ => {
                        return Err(rusqlite::Error::InvalidColumnType(
                            2,
                            "outcome".to_owned(),
                            rusqlite::types::Type::Text,
                        ));
                    }
                };
                Ok(ManagedReceiptIntent {
                    outbox_key: row.get(0)?,
                    idempotency_key: row.get(1)?,
                    outcome,
                    explanation: row.get(3)?,
                    created_ms: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn validate_history_body(body: &MobileHistoryBody) -> Managed<()> {
    match body {
        MobileHistoryBody::Message { text, .. } if text.as_str().is_empty() => {
            Err(ManagedSessionError::InvalidField("history_message"))
        }
        MobileHistoryBody::Unknown { event_kind } if !valid_history_kind(event_kind.as_str()) => {
            Err(ManagedSessionError::InvalidField("history_unknown_kind"))
        }
        _ => Ok(()),
    }
}

fn valid_history_kind(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

type HistoryColumns<'a> = (
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a str>,
);

fn history_columns(body: &MobileHistoryBody) -> HistoryColumns<'_> {
    match body {
        MobileHistoryBody::Message { role, text } => {
            (Some(role.as_str()), Some(text.as_str()), None, None, None)
        }
        MobileHistoryBody::ToolState { state } => (None, None, Some(state.as_str()), None, None),
        MobileHistoryBody::RunState { state } => (None, None, None, Some(state.as_str()), None),
        MobileHistoryBody::Unknown { event_kind } => {
            (None, None, None, None, Some(event_kind.as_str()))
        }
    }
}

fn read_history_source(
    connection: &Connection,
    provider_session_id: &str,
    source_run_id: &str,
    source_sequence: u64,
) -> Managed<Option<MobileHistoryEvent>> {
    connection
        .query_row(
            "SELECT cursor,source_run_id,at_ms,event_kind,role,message,tool_state,run_state,unknown_kind
             FROM managed_session_history
             WHERE provider_session_id=?1 AND source_run_id=?2 AND source_sequence=?3",
            params![provider_session_id, source_run_id, to_i64(source_sequence)?],
            decode_history,
        )
        .optional()
        .map_err(Into::into)
}

fn read_history_cursor(
    connection: &Connection,
    provider_session_id: &str,
    cursor: i64,
) -> Managed<Option<MobileHistoryEvent>> {
    connection
        .query_row(
            "SELECT cursor,source_run_id,at_ms,event_kind,role,message,tool_state,run_state,unknown_kind
             FROM managed_session_history
             WHERE provider_session_id=?1 AND cursor=?2",
            params![provider_session_id, cursor],
            decode_history,
        )
        .optional()
        .map_err(Into::into)
}

fn decode_history(row: &rusqlite::Row<'_>) -> rusqlite::Result<MobileHistoryEvent> {
    let cursor = from_sql_u64(row.get(0)?, 0)?;
    let run_id = RunId::new(row.get::<_, String>(1)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let at_ms = row.get::<_, i64>(2)?;
    if at_ms < 0 || u64::try_from(at_ms).map_or(true, |value| value > MAX_MOBILE_HISTORY_DECIMAL) {
        return Err(rusqlite::Error::IntegralValueOutOfRange(2, at_ms));
    }
    let event_kind = row.get::<_, String>(3)?;
    let role = row.get::<_, Option<String>>(4)?;
    let message = row.get::<_, Option<String>>(5)?;
    let tool_state = row.get::<_, Option<String>>(6)?;
    let run_state = row.get::<_, Option<String>>(7)?;
    let unknown_kind = row.get::<_, Option<String>>(8)?;
    let body = match event_kind.as_str() {
        "message" if role.as_deref() == Some("assistant") => MobileHistoryBody::Message {
            role: MobileMessageRole::Assistant,
            text: MobileHistoryMessage::new(
                message.clone().ok_or_else(|| invalid_history_column(5))?,
            )
            .map_err(|error| conversion_failure(5, error))?,
        },
        "tool_state" => MobileHistoryBody::ToolState {
            state: match tool_state.as_deref() {
                Some("pending") => MobileToolState::Pending,
                Some("running") => MobileToolState::Running,
                Some("succeeded") => MobileToolState::Succeeded,
                Some("failed") => MobileToolState::Failed,
                Some("cancelled") => MobileToolState::Cancelled,
                _ => return Err(invalid_history_column(6)),
            },
        },
        "run_state" => MobileHistoryBody::RunState {
            state: match run_state.as_deref() {
                Some("running") => MobileRunState::Running,
                Some("completed") => MobileRunState::Completed,
                Some("failed") => MobileRunState::Failed,
                Some("cancelled") => MobileRunState::Cancelled,
                Some("timed_out") => MobileRunState::TimedOut,
                _ => return Err(invalid_history_column(7)),
            },
        },
        "unknown" => MobileHistoryBody::Unknown {
            event_kind: MobileUnknownEventKind::new(
                unknown_kind
                    .clone()
                    .ok_or_else(|| invalid_history_column(8))?,
            )
            .map_err(|error| conversion_failure(8, error))?,
        },
        _ => return Err(invalid_history_column(3)),
    };
    if history_columns(&body)
        != (
            role.as_deref(),
            message.as_deref(),
            tool_state.as_deref(),
            run_state.as_deref(),
            unknown_kind.as_deref(),
        )
        || validate_history_body(&body).is_err()
    {
        return Err(invalid_history_column(3));
    }
    Ok(MobileHistoryEvent {
        cursor: MobileHistoryCursor::new(cursor),
        at_ms: EpochMillis::from_millis(at_ms),
        run_id,
        body,
    })
}

fn invalid_history_column(index: usize) -> rusqlite::Error {
    rusqlite::Error::InvalidColumnType(index, "history".to_owned(), rusqlite::types::Type::Text)
}

fn conversion_failure(
    index: usize,
    error: impl std::error::Error + Send + Sync + 'static,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, Box::new(error))
}

fn from_sql_u64(value: i64, index: usize) -> rusqlite::Result<u64> {
    let converted = u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    if converted > MAX_MOBILE_HISTORY_DECIMAL {
        return Err(rusqlite::Error::IntegralValueOutOfRange(index, value));
    }
    Ok(converted)
}

fn from_i64(value: i64, field: &'static str) -> Managed<u64> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_MOBILE_HISTORY_DECIMAL)
        .ok_or(ManagedSessionError::InvalidField(field))
}

fn decode(row: &rusqlite::Row<'_>) -> rusqlite::Result<ManagedSession> {
    let revision = row.get::<_, i64>(3)?;
    Ok(ManagedSession {
        provider_session_id: row.get(0)?,
        run_id: row.get(1)?,
        open: row.get::<_, String>(2)? == "open",
        revision: u64::try_from(revision).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
        created_ms: row.get(4)?,
        updated_ms: row.get(5)?,
    })
}

fn to_i64(value: u64) -> Managed<i64> {
    i64::try_from(value).map_err(|_| ManagedSessionError::InvalidField("revision"))
}

fn initialize(connection: &mut Connection) -> Managed<()> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version == 0 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA)?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
    } else if version == 1 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(MIGRATE_V1_TO_V2)?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
    } else if version != SCHEMA_VERSION {
        return Err(ManagedSessionError::SchemaVersion);
    }
    Ok(())
}

fn secure_path(path: &Path) -> Managed<()> {
    if !path.is_absolute() {
        return Err(ManagedSessionError::InsecurePath);
    }
    let Some(parent) = path.parent() else {
        return Err(ManagedSessionError::InsecurePath);
    };
    validate_owned_private(&fs::symlink_metadata(parent)?, true)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        validate_owned_private(&metadata, false)?;
    }
    Ok(())
}

fn validate_owned_private(metadata: &fs::Metadata, directory: bool) -> Managed<()> {
    let expected_kind = if directory {
        metadata.file_type().is_dir()
    } else {
        metadata.file_type().is_file()
    };
    if !expected_kind
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ManagedSessionError::InsecurePath);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn observation_is_idempotent_and_follow_up_advances_the_binding() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = ManagedSessionStore::open(root.path().join("managed.sqlite3")).unwrap();
        let first = store.observe("session-1", "run-1", 10).unwrap();
        assert_eq!(first.revision, 1);
        assert_eq!(store.observe("session-1", "run-1", 11).unwrap(), first);
        let second = store.observe("session-1", "run-2", 12).unwrap();
        assert_eq!(second.revision, 2);
        assert_eq!(second.run_id, "run-2");
        assert_eq!(store.by_run("run-2").unwrap(), Some(second.clone()));
        assert_eq!(store.list().unwrap(), vec![second]);
    }

    #[test]
    fn receipt_intent_is_typed_idempotent_and_conflict_detecting() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = ManagedSessionStore::open(root.path().join("managed.sqlite3")).unwrap();
        let first = store
            .record_receipt_intent(
                "outbox-1",
                "request-1",
                ReceiptOutcome::Completed,
                Some("run=run-1;session=session-1"),
                10,
            )
            .unwrap();
        assert_eq!(
            store
                .record_receipt_intent(
                    "outbox-1",
                    "request-1",
                    ReceiptOutcome::Completed,
                    Some("run=run-1;session=session-1"),
                    11,
                )
                .unwrap(),
            first
        );
        assert_eq!(store.receipt_intent("outbox-1").unwrap(), Some(first));
        assert!(
            store
                .record_receipt_intent(
                    "outbox-1",
                    "request-1",
                    ReceiptOutcome::Rejected,
                    Some("different"),
                    12,
                )
                .is_err()
        );
    }

    fn message(value: &str) -> MobileHistoryBody {
        MobileHistoryBody::Message {
            role: MobileMessageRole::Assistant,
            text: MobileHistoryMessage::new(value).unwrap(),
        }
    }

    #[test]
    fn history_snapshot_pages_resume_clamp_and_replay_without_duplicates() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = ManagedSessionStore::open(root.path().join("managed.sqlite3")).unwrap();
        store.observe("session-1", "run-1", 1).unwrap();
        let first = store
            .append_history_event("session-1", "run-1", 1, 10, message("first"))
            .unwrap();
        assert_eq!(
            store
                .append_history_event("session-1", "run-1", 1, 10, message("first"))
                .unwrap(),
            first
        );
        store
            .append_history_event(
                "session-1",
                "run-1",
                3,
                11,
                MobileHistoryBody::ToolState {
                    state: MobileToolState::Succeeded,
                },
            )
            .unwrap();
        store
            .append_history_event(
                "session-1",
                "run-1",
                5,
                12,
                MobileHistoryBody::Unknown {
                    event_kind: MobileUnknownEventKind::new("future_event").unwrap(),
                },
            )
            .unwrap();

        let ManagedHistoryPage::Page(first_page) =
            store.history_page("session-1", None, 99, 2).unwrap()
        else {
            panic!("snapshot must be a page");
        };
        assert_eq!(first_page.requested_limit, 99);
        assert_eq!(first_page.applied_limit, 2);
        assert_eq!(first_page.exclusive_cursor.get(), 0);
        assert_eq!(first_page.terminal_cursor.get(), 3);
        assert!(first_page.has_more);
        assert_eq!(first_page.events.len(), 2);

        let ManagedHistoryPage::Page(second_page) = store
            .history_page("session-1", Some(first_page.events[1].cursor), 2, 2)
            .unwrap()
        else {
            panic!("resume must be a page");
        };
        assert_eq!(second_page.events.len(), 1);
        assert!(!second_page.has_more);
        assert!(matches!(
            second_page.events[0].body,
            MobileHistoryBody::Unknown { .. }
        ));

        let conflict = store.append_history_event("session-1", "run-1", 1, 10, message("changed"));
        assert!(conflict.is_err());
        let rewind = store.append_history_event("session-1", "run-1", 2, 10, message("rewind"));
        assert!(rewind.is_err());
    }

    #[test]
    fn history_reports_expiry_and_cursor_gap_without_partial_rows() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = ManagedSessionStore::open(root.path().join("managed.sqlite3")).unwrap();
        store.observe("session-1", "run-1", 1).unwrap();
        for sequence in 1..=MAX_MOBILE_HISTORY_EVENTS + 1 {
            store
                .append_history_event(
                    "session-1",
                    "run-1",
                    u64::try_from(sequence).unwrap(),
                    i64::try_from(sequence).unwrap(),
                    MobileHistoryBody::RunState {
                        state: MobileRunState::Running,
                    },
                )
                .unwrap();
        }
        let ManagedHistoryPage::Resync(expired) = store
            .history_page("session-1", Some(MobileHistoryCursor::new(0)), 10, 10)
            .unwrap()
        else {
            panic!("expired cursor must not receive a partial page");
        };
        assert_eq!(expired.reason, MobileHistoryResyncReason::RetentionExpired);
        assert_eq!(expired.earliest_cursor.get(), 1);
        let ManagedHistoryPage::Resync(gap) = store
            .history_page("session-1", Some(MobileHistoryCursor::new(10_000)), 10, 10)
            .unwrap()
        else {
            panic!("ahead cursor must require resync");
        };
        assert_eq!(gap.reason, MobileHistoryResyncReason::CursorGap);
    }

    #[test]
    fn history_cursor_above_javascript_safe_integer_remains_exact() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = ManagedSessionStore::open(root.path().join("managed.sqlite3")).unwrap();
        store.observe("session-1", "run-1", 1).unwrap();
        let next = 9_007_199_254_740_992_i64;
        store
            .connection
            .execute(
                "INSERT INTO managed_session_history_meta(
                   provider_session_id,next_cursor,retained_from,terminal_cursor)
                 VALUES('session-1',?1,?1,?2)",
                params![next, next - 1],
            )
            .unwrap();
        let event = store
            .append_history_event("session-1", "run-1", 1, 10, message("safe"))
            .unwrap();
        assert_eq!(event.cursor.to_string(), "9007199254740992");
        let ManagedHistoryPage::Page(page) = store
            .history_page(
                "session-1",
                Some(MobileHistoryCursor::new((next - 1) as u64)),
                1,
                1,
            )
            .unwrap()
        else {
            panic!("cursor must remain readable");
        };
        assert_eq!(page.events[0].cursor, event.cursor);
    }
}
