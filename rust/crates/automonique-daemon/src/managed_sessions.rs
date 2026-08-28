// SPDX-License-Identifier: Elastic-2.0

//! Durable bindings between normalized provider sessions and Automonique runs.
//!
//! The provider's session identifier is observed from its normalized stdout,
//! never inferred from filenames or "most recent" state.  One row names the
//! latest Automonique run for that resumable provider session.  A follow-up
//! therefore has an exact provider binding and an exact run to observe after a
//! daemon restart.
//!
//! # The binding names the run of the current turn, not of the last one
//!
//! A row is advanced twice per turn: once when the provider session is known
//! and the turn is about to start, with [`ManagedRunState::InFlight`], and once
//! when the run reaches a terminal spool state, with
//! [`ManagedRunState::Completed`].  The two phases are what make the binding
//! usable by a session-scoped control surface: a provider permission request is
//! raised *during* the run that raised it, so a binding that only advanced at
//! completion always named the previous, already-terminal run and could never
//! own a live approval or a stoppable run.
//!
//! The phase is persisted rather than inferred because the revision has to move
//! at both ends of the turn.  A settlement that could not be distinguished from
//! the turn-start observation of the same run would be a silent no-op, and an
//! attached client watching `revision` would never learn that the turn ended.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use automonique_protocol::platform::{
    IdempotencyKey, PlatformText, ReceiptOutcome, ResourceId, SessionHistoryEvent,
    SessionHistoryEvidence, SessionHistoryRole, SessionHistoryRunState, SessionHistoryText,
    SessionHistoryToolState, SessionHistoryUnknownSource,
};
use automonique_protocol::primitives::EpochMillis;
use automonique_protocol::progress_api::ProgressFrame;
use automonique_protocol::tools::RunId;
use automonique_runner::backend::{
    TERMINAL_CANCELLED, TERMINAL_COMPLETED, TERMINAL_FAILED, TERMINAL_TIMED_OUT,
};
use automonique_runner::{Authority as SpoolAuthority, Event as SpoolEvent, EventKind};
use nix::unistd::geteuid;
use rusqlite::{Connection, OpenFlags, OptionalExtension as _, TransactionBehavior, params};

const SCHEMA_VERSION: u32 = 4;
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
"#;

const SCHEMA_V2: &str = r#"
CREATE TABLE managed_session_history (
    provider_session_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    source_key TEXT NOT NULL UNIQUE,
    at_ms INTEGER NOT NULL CHECK (at_ms >= 0),
    role TEXT CHECK (role IN ('user', 'assistant')),
    text TEXT,
    truncated INTEGER CHECK (truncated IN (0, 1)),
    evidence TEXT CHECK (evidence IN ('authoritative','synthetic')),
    tool_state TEXT CHECK (tool_state IN ('pending','in_progress','completed','error')),
    unknown_source TEXT CHECK (unknown_source IN ('adapter_event','simulation_event')),
    run_state TEXT CHECK (run_state IN ('started','cancel_requested','completed','failed','cancelled','timed_out')),
    CHECK ((role IS NOT NULL AND text IS NOT NULL AND truncated IS NOT NULL AND evidence IS NOT NULL AND tool_state IS NULL AND unknown_source IS NULL AND run_state IS NULL)
        OR (role IS NULL AND truncated IS NOT NULL AND evidence IS NOT NULL AND tool_state IS NOT NULL AND unknown_source IS NULL AND run_state IS NULL)
        OR (role IS NULL AND text IS NULL AND truncated IS NULL AND evidence IS NULL AND tool_state IS NULL AND unknown_source IS NULL AND run_state IS NOT NULL)
        OR (role IS NULL AND text IS NULL AND truncated IS NULL AND evidence IS NULL AND tool_state IS NULL AND unknown_source IS NOT NULL AND run_state IS NULL)),
    PRIMARY KEY(provider_session_id, sequence)
) STRICT;
CREATE INDEX managed_session_history_page
    ON managed_session_history(provider_session_id, sequence);
"#;

/// The turn phase of the bound run.
///
/// Existing rows were only ever written at completion, so `completed` is the
/// exact history-preserving backfill for them.
const SCHEMA_V3: &str = r#"
ALTER TABLE managed_sessions ADD COLUMN run_state TEXT NOT NULL DEFAULT 'completed'
    CHECK (run_state IN ('in_flight', 'completed'));
"#;

/// Split history idempotency into database-enforced transport domains. Legacy
/// rows predate retained-review v2 and therefore migrate truthfully into the
/// platform-v1 domain. Occurrence identity remains global within each domain,
/// preserving v1's existing cross-session conflict behavior, while the added
/// domain makes identical caller-chosen v1 and server-derived v2 keys disjoint.
const SCHEMA_V4: &str = r#"
ALTER TABLE managed_session_history RENAME TO managed_session_history_v3;
DROP INDEX managed_session_history_page;
CREATE TABLE managed_session_history (
    provider_session_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    source_domain TEXT NOT NULL CHECK (source_domain IN ('platform_v1','retained_review_v2')),
    source_key TEXT NOT NULL,
    at_ms INTEGER NOT NULL CHECK (at_ms >= 0),
    role TEXT CHECK (role IN ('user', 'assistant')),
    text TEXT,
    truncated INTEGER CHECK (truncated IN (0, 1)),
    evidence TEXT CHECK (evidence IN ('authoritative','synthetic')),
    tool_state TEXT CHECK (tool_state IN ('pending','in_progress','completed','error')),
    unknown_source TEXT CHECK (unknown_source IN ('adapter_event','simulation_event')),
    run_state TEXT CHECK (run_state IN ('started','cancel_requested','completed','failed','cancelled','timed_out')),
    CHECK ((role IS NOT NULL AND text IS NOT NULL AND truncated IS NOT NULL AND evidence IS NOT NULL AND tool_state IS NULL AND unknown_source IS NULL AND run_state IS NULL)
        OR (role IS NULL AND truncated IS NOT NULL AND evidence IS NOT NULL AND tool_state IS NOT NULL AND unknown_source IS NULL AND run_state IS NULL)
        OR (role IS NULL AND text IS NULL AND truncated IS NULL AND evidence IS NULL AND tool_state IS NULL AND unknown_source IS NULL AND run_state IS NOT NULL)
        OR (role IS NULL AND text IS NULL AND truncated IS NULL AND evidence IS NULL AND tool_state IS NULL AND unknown_source IS NOT NULL AND run_state IS NULL)),
    PRIMARY KEY(provider_session_id, sequence),
    UNIQUE(source_domain, source_key)
) STRICT;
INSERT INTO managed_session_history(
    provider_session_id,sequence,source_domain,source_key,at_ms,role,text,truncated,
    evidence,tool_state,unknown_source,run_state
)
SELECT provider_session_id,sequence,'platform_v1',source_key,at_ms,role,text,truncated,
       evidence,tool_state,unknown_source,run_state
FROM managed_session_history_v3;
DROP TABLE managed_session_history_v3;
CREATE INDEX managed_session_history_page
    ON managed_session_history(provider_session_id, sequence);
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

/// Which end of a turn the bound run is at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedRunState {
    /// The turn has started and the run has not reported a terminal state.
    InFlight,
    /// The run reached a terminal spool state.
    Completed,
}

/// Database-enforced idempotency namespace for authoritative turn history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedHistorySource<'a> {
    /// Existing Platform v1 new-request and follow-up history.
    PlatformV1(&'a str),
    /// Platform v2 retained-review delivery history.
    RetainedReviewV2(&'a str),
}

impl<'a> ManagedHistorySource<'a> {
    const fn domain(self) -> &'static str {
        match self {
            Self::PlatformV1(_) => "platform_v1",
            Self::RetainedReviewV2(_) => "retained_review_v2",
        }
    }

    const fn key(self) -> &'a str {
        match self {
            Self::PlatformV1(key) | Self::RetainedReviewV2(key) => key,
        }
    }
}

impl ManagedRunState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InFlight => "in_flight",
            Self::Completed => "completed",
        }
    }

    #[must_use]
    pub const fn is_in_flight(self) -> bool {
        matches!(self, Self::InFlight)
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "in_flight" => Some(Self::InFlight),
            "completed" => Some(Self::Completed),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedSession {
    pub provider_session_id: String,
    pub run_id: String,
    pub open: bool,
    /// The turn phase [`run_id`](Self::run_id) is at.  A session whose binding
    /// is [`ManagedRunState::InFlight`] names the run that is executing right
    /// now, which is the run a live approval and a live stop belong to.
    pub run_state: ManagedRunState,
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
pub enum ManagedHistoryRead {
    Page {
        events: Vec<SessionHistoryEvent>,
        head: u64,
        has_more: bool,
    },
    Resync {
        snapshot_from: u64,
        snapshot_to: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PendingHistoryEvent {
    ToolState {
        at_ms: i64,
        evidence: SessionHistoryEvidence,
        state: SessionHistoryToolState,
        label: Option<SessionHistoryText>,
        truncated: bool,
    },
    RunState {
        at_ms: i64,
        state: SessionHistoryRunState,
    },
    Unknown {
        at_ms: i64,
        source: SessionHistoryUnknownSource,
    },
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

    /// Bind this session to the run that is about to take its turn.
    ///
    /// Called once the provider session identifier is known and before the turn
    /// is started, so everything the turn goes on to raise — a provider
    /// permission request above all — is raised against the run this session
    /// already names.  Without it the binding lags exactly one turn and a
    /// session-scoped surface can only ever address a terminal run.
    pub fn observe_active(
        &mut self,
        provider_session_id: &str,
        run_id: &str,
        now_ms: i64,
    ) -> Managed<ManagedSession> {
        self.bind(
            provider_session_id,
            run_id,
            ManagedRunState::InFlight,
            now_ms,
        )
    }

    /// Settle this session's binding on the run that has just become terminal.
    ///
    /// This is the observation that existed before turn-start binding, and it
    /// keeps its exact effect on `run_id` and `state`: it advances the binding
    /// to `run_id` and reopens a session recorded as lost.  It additionally
    /// records that the turn is over, which is what moves the revision at the
    /// end of a turn that turn-start binding already advanced.
    pub fn observe_terminal(
        &mut self,
        provider_session_id: &str,
        run_id: &str,
        now_ms: i64,
    ) -> Managed<ManagedSession> {
        self.bind(
            provider_session_id,
            run_id,
            ManagedRunState::Completed,
            now_ms,
        )
    }

    /// One durable binding write.
    ///
    /// Idempotent on the whole observation rather than on `run_id` alone: the
    /// same run observed twice in the same phase writes nothing and holds the
    /// revision still, and a phase change on the same run is a real advance.
    fn bind(
        &mut self,
        provider_session_id: &str,
        run_id: &str,
        run_state: ManagedRunState,
        now_ms: i64,
    ) -> Managed<ManagedSession> {
        validate(provider_session_id, run_id, now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = read(&transaction, provider_session_id)?;
        match existing {
            Some(existing)
                if existing.run_id == run_id
                    && existing.open
                    && existing.run_state == run_state =>
            {
                transaction.commit()?;
                return Ok(existing);
            }
            Some(existing) => {
                let revision = existing
                    .revision
                    .checked_add(1)
                    .ok_or(ManagedSessionError::InvalidField("revision"))?;
                transaction.execute(
                    "UPDATE managed_sessions SET run_id=?2,state='open',run_state=?3,revision=?4,updated_ms=?5
                     WHERE provider_session_id=?1 AND revision=?6",
                    params![
                        provider_session_id,
                        run_id,
                        run_state.as_str(),
                        to_i64(revision)?,
                        now_ms,
                        to_i64(existing.revision)?
                    ],
                )?;
            }
            None => {
                transaction.execute(
                    "INSERT INTO managed_sessions(provider_session_id,run_id,state,run_state,revision,created_ms,updated_ms)
                     VALUES(?1,?2,'open',?3,1,?4,?4)",
                    params![provider_session_id, run_id, run_state.as_str(), now_ms],
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
                "SELECT provider_session_id,run_id,state,run_state,revision,created_ms,updated_ms
                 FROM managed_sessions WHERE run_id=?1",
                [run_id],
                decode,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list(&self) -> Managed<Vec<ManagedSession>> {
        let mut statement = self.connection.prepare(
            "SELECT provider_session_id,run_id,state,run_state,revision,created_ms,updated_ms
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

    /// Atomically append the authoritative accepted prompt and final answer.
    /// `source_key` is server-produced and makes crash replay idempotent.
    pub fn record_completed_turn(
        &mut self,
        provider_session_id: &str,
        source: ManagedHistorySource<'_>,
        user_text: &str,
        assistant_text: &str,
        spool_events: &[SpoolEvent],
        at_ms: i64,
    ) -> Managed<()> {
        let source_domain = source.domain();
        let source_key = source.key();
        ResourceId::new(provider_session_id)
            .map_err(|_| ManagedSessionError::InvalidField("provider_session_id"))?;
        IdempotencyKey::new(source_key)
            .map_err(|_| ManagedSessionError::InvalidField("source_key"))?;
        if at_ms < 0 {
            return Err(ManagedSessionError::InvalidField("at_ms"));
        }
        let (user_text, user_truncated) = sanitize_history_text(user_text)?;
        let (assistant_text, assistant_truncated) = sanitize_history_text(assistant_text)?;
        let projected = project_spool_events(spool_events)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String, i64, String, i64)> = transaction
            .query_row(
                "SELECT user.provider_session_id,user.text,user.truncated,
                        assistant.text,assistant.truncated
                 FROM managed_session_history user
                 JOIN managed_session_history assistant
                   ON assistant.source_domain=?1 AND assistant.source_key=?3
                 WHERE user.source_domain=?1 AND user.source_key=?2
                   AND assistant.provider_session_id=user.provider_session_id",
                params![
                    source_domain,
                    format!("{source_key}:user"),
                    format!("{source_key}:assistant")
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        if let Some((
            stored_session,
            stored_user,
            stored_user_truncated,
            stored_assistant,
            stored_assistant_truncated,
        )) = existing
        {
            if stored_session != provider_session_id
                || stored_user != user_text.as_str()
                || stored_user_truncated != i64::from(user_truncated)
                || stored_assistant != assistant_text.as_str()
                || stored_assistant_truncated != i64::from(assistant_truncated)
            {
                return Err(ManagedSessionError::InvalidField("history_replay_conflict"));
            }
            transaction.commit()?;
            return Ok(());
        }
        let mut sequence: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(sequence),0) FROM managed_session_history WHERE provider_session_id=?1",
            [provider_session_id],
            |row| row.get(0),
        )?;
        sequence = sequence
            .checked_add(1)
            .ok_or(ManagedSessionError::InvalidField("sequence"))?;
        let user_key = format!("{source_key}:user");
        transaction.execute(
            "INSERT INTO managed_session_history(provider_session_id,sequence,source_domain,source_key,at_ms,role,text,truncated,evidence,tool_state,unknown_source,run_state)
             VALUES(?1,?2,?3,?4,?5,'user',?6,?7,'authoritative',NULL,NULL,NULL) ON CONFLICT(source_domain,source_key) DO NOTHING",
            params![provider_session_id, sequence, source_domain, user_key, at_ms, user_text.as_str(), user_truncated],
        )?;
        for (index, event) in projected.iter().enumerate() {
            sequence = sequence
                .checked_add(1)
                .ok_or(ManagedSessionError::InvalidField("sequence"))?;
            let key = format!("{source_key}:spool:{index}");
            match event {
                PendingHistoryEvent::ToolState { at_ms, evidence, state, label, truncated } => transaction.execute(
                    "INSERT INTO managed_session_history(provider_session_id,sequence,source_domain,source_key,at_ms,role,text,truncated,evidence,tool_state,unknown_source,run_state)
                     VALUES(?1,?2,?3,?4,?5,NULL,?6,?7,?8,?9,NULL,NULL) ON CONFLICT(source_domain,source_key) DO NOTHING",
                    params![provider_session_id, sequence, source_domain, key, at_ms, label.as_ref().map(SessionHistoryText::as_str), truncated, evidence.as_str(), state.as_str()],
                )?,
                PendingHistoryEvent::RunState { at_ms, state } => transaction.execute(
                    "INSERT INTO managed_session_history(provider_session_id,sequence,source_domain,source_key,at_ms,role,text,truncated,evidence,tool_state,unknown_source,run_state)
                     VALUES(?1,?2,?3,?4,?5,NULL,NULL,NULL,NULL,NULL,NULL,?6) ON CONFLICT(source_domain,source_key) DO NOTHING",
                    params![provider_session_id, sequence, source_domain, key, at_ms, state.as_str()],
                )?,
                PendingHistoryEvent::Unknown { at_ms, source } => transaction.execute(
                    "INSERT INTO managed_session_history(provider_session_id,sequence,source_domain,source_key,at_ms,role,text,truncated,evidence,tool_state,unknown_source,run_state)
                     VALUES(?1,?2,?3,?4,?5,NULL,NULL,NULL,NULL,NULL,?6,NULL) ON CONFLICT(source_domain,source_key) DO NOTHING",
                    params![provider_session_id, sequence, source_domain, key, at_ms, source.as_str()],
                )?,
            };
        }
        sequence = sequence
            .checked_add(1)
            .ok_or(ManagedSessionError::InvalidField("sequence"))?;
        transaction.execute(
            "INSERT INTO managed_session_history(provider_session_id,sequence,source_domain,source_key,at_ms,role,text,truncated,evidence,tool_state,unknown_source,run_state)
             VALUES(?1,?2,?3,?4,?5,'assistant',?6,?7,'authoritative',NULL,NULL,NULL) ON CONFLICT(source_domain,source_key) DO NOTHING",
            params![provider_session_id, sequence, source_domain, format!("{source_key}:assistant"), at_ms, assistant_text.as_str(), assistant_truncated],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn history(
        &self,
        provider_session_id: &str,
        after: u64,
        limit: u16,
    ) -> Managed<ManagedHistoryRead> {
        ResourceId::new(provider_session_id)
            .map_err(|_| ManagedSessionError::InvalidField("provider_session_id"))?;
        if limit == 0
            || usize::from(limit) > automonique_protocol::platform::MAX_SESSION_HISTORY_EVENTS
        {
            return Err(ManagedSessionError::InvalidField("limit"));
        }
        let (floor, head): (i64, i64) = self.connection.query_row(
            "SELECT COALESCE(MIN(sequence),0),COALESCE(MAX(sequence),0) FROM managed_session_history WHERE provider_session_id=?1",
            [provider_session_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let after_i64 =
            i64::try_from(after).map_err(|_| ManagedSessionError::InvalidField("after"))?;
        if after_i64 > head || (floor > 1 && after_i64 < floor - 1) {
            return Ok(ManagedHistoryRead::Resync {
                snapshot_from: u64::try_from(floor.saturating_sub(1)).unwrap_or(0),
                snapshot_to: u64::try_from(head).unwrap_or(0),
            });
        }
        let query_limit = i64::from(limit) + 1;
        let mut statement = self.connection.prepare(
            "SELECT sequence,at_ms,role,text,truncated,evidence,tool_state,unknown_source,run_state FROM managed_session_history
             WHERE provider_session_id=?1 AND sequence>?2 ORDER BY sequence LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![provider_session_id, after_i64, query_limit],
            decode_history,
        )?;
        let mut events = rows.collect::<Result<Vec<_>, _>>()?;
        let has_more = events.len() > usize::from(limit);
        if has_more {
            events.pop();
        }
        Ok(ManagedHistoryRead::Page {
            events,
            head: u64::try_from(head).map_err(|_| ManagedSessionError::InvalidField("head"))?,
            has_more,
        })
    }

    /// Start at the oldest retained event. Unlike a stale page resume, a fresh
    /// snapshot is itself the recovery operation and therefore cannot demand
    /// another snapshot when retention has advanced.
    pub fn history_snapshot(
        &self,
        provider_session_id: &str,
        limit: u16,
    ) -> Managed<ManagedHistoryRead> {
        ResourceId::new(provider_session_id)
            .map_err(|_| ManagedSessionError::InvalidField("provider_session_id"))?;
        let floor: i64 = self.connection.query_row(
            "SELECT COALESCE(MIN(sequence),0) FROM managed_session_history WHERE provider_session_id=?1",
            [provider_session_id],
            |row| row.get(0),
        )?;
        let after = u64::try_from(floor.saturating_sub(1)).unwrap_or(0);
        self.history(provider_session_id, after, limit)
    }
}

fn sanitize_history_text(value: &str) -> Managed<(SessionHistoryText, bool)> {
    let normalized: String = value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    let mut end = normalized
        .len()
        .min(automonique_protocol::platform::MAX_SESSION_HISTORY_TEXT_BYTES);
    while !normalized.is_char_boundary(end) {
        end -= 1;
    }
    let truncated = end < normalized.len();
    let text = SessionHistoryText::new(&normalized[..end])
        .map_err(|_| ManagedSessionError::InvalidField("history_text"))?;
    Ok((text, truncated))
}

fn project_spool_events(events: &[SpoolEvent]) -> Managed<Vec<PendingHistoryEvent>> {
    events
        .iter()
        .map(|event| {
            let at_ms = i64::try_from(event.at_millis())
                .map_err(|_| ManagedSessionError::InvalidField("event_at_ms"))?;
            Ok(match event.kind() {
                EventKind::Started => PendingHistoryEvent::RunState {
                    at_ms,
                    state: SessionHistoryRunState::Started,
                },
                EventKind::CancelRequested => PendingHistoryEvent::RunState {
                    at_ms,
                    state: SessionHistoryRunState::CancelRequested,
                },
                EventKind::Terminal => PendingHistoryEvent::RunState {
                    at_ms,
                    state: match event.payload() {
                        TERMINAL_COMPLETED => SessionHistoryRunState::Completed,
                        TERMINAL_FAILED => SessionHistoryRunState::Failed,
                        TERMINAL_CANCELLED => SessionHistoryRunState::Cancelled,
                        TERMINAL_TIMED_OUT => SessionHistoryRunState::TimedOut,
                        _ => return Err(ManagedSessionError::InvalidField("terminal_state")),
                    },
                },
                EventKind::SimulationEvent => PendingHistoryEvent::Unknown {
                    at_ms,
                    source: SessionHistoryUnknownSource::SimulationEvent,
                },
                EventKind::AdapterEvent => {
                    let frame = ProgressFrame::from_canonical_bytes(event.payload()).ok();
                    if let Some(frame) = frame.filter(|frame| {
                        matches!(
                            frame.kind(),
                            automonique_protocol::event::EventKind::ToolCallStarted
                                | automonique_protocol::event::EventKind::ToolCallUpdated
                                | automonique_protocol::event::EventKind::ToolCallCompleted
                        ) && frame.body().step().is_some()
                    }) {
                        let (label, truncated) =
                            frame.body().text().map_or(Ok((None, false)), |text| {
                                sanitize_history_text(text.as_str())
                                    .map(|(text, truncated)| (Some(text), truncated))
                            })?;
                        let state = match frame.body().step().expect("filtered step") {
                            automonique_protocol::event::StepStatus::Pending => {
                                SessionHistoryToolState::Pending
                            }
                            automonique_protocol::event::StepStatus::InProgress => {
                                SessionHistoryToolState::InProgress
                            }
                            automonique_protocol::event::StepStatus::Completed => {
                                SessionHistoryToolState::Completed
                            }
                            automonique_protocol::event::StepStatus::Error => {
                                SessionHistoryToolState::Error
                            }
                        };
                        PendingHistoryEvent::ToolState {
                            at_ms,
                            evidence: match event.authority() {
                                SpoolAuthority::Authoritative => {
                                    SessionHistoryEvidence::Authoritative
                                }
                                SpoolAuthority::Synthetic => SessionHistoryEvidence::Synthetic,
                            },
                            state,
                            label,
                            truncated,
                        }
                    } else {
                        PendingHistoryEvent::Unknown {
                            at_ms,
                            source: SessionHistoryUnknownSource::AdapterEvent,
                        }
                    }
                }
            })
        })
        .collect()
}

fn decode_history(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionHistoryEvent> {
    let cursor = u64::try_from(row.get::<_, i64>(0)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    let at = EpochMillis::from_millis(row.get(1)?);
    let role: Option<String> = row.get(2)?;
    if let Some(role) = role {
        let role = SessionHistoryRole::parse(&role).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let text: String = row.get(3)?;
        let text = SessionHistoryText::new(&text).map_err(|_| rusqlite::Error::InvalidQuery)?;
        return Ok(SessionHistoryEvent::Message {
            cursor,
            at,
            evidence: SessionHistoryEvidence::parse(&row.get::<_, String>(5)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            role,
            text,
            truncated: row.get(4)?,
        });
    }
    if let Some(state) = row.get::<_, Option<String>>(6)? {
        return Ok(SessionHistoryEvent::ToolState {
            cursor,
            at,
            evidence: SessionHistoryEvidence::parse(&row.get::<_, String>(5)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            state: SessionHistoryToolState::parse(&state)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            label: row
                .get::<_, Option<String>>(3)?
                .map(|label| {
                    SessionHistoryText::new(&label).map_err(|_| rusqlite::Error::InvalidQuery)
                })
                .transpose()?,
            truncated: row.get(4)?,
        });
    }
    if let Some(source) = row.get::<_, Option<String>>(7)? {
        return Ok(SessionHistoryEvent::Unknown {
            cursor,
            at,
            source: SessionHistoryUnknownSource::parse(&source)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        });
    }
    let state: String = row.get(8)?;
    Ok(SessionHistoryEvent::RunState {
        cursor,
        at,
        state: SessionHistoryRunState::parse(&state).map_err(|_| rusqlite::Error::InvalidQuery)?,
    })
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
            "SELECT provider_session_id,run_id,state,run_state,revision,created_ms,updated_ms
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

fn decode(row: &rusqlite::Row<'_>) -> rusqlite::Result<ManagedSession> {
    let revision = row.get::<_, i64>(4)?;
    let run_state = row.get::<_, String>(3)?;
    Ok(ManagedSession {
        provider_session_id: row.get(0)?,
        run_id: row.get(1)?,
        open: row.get::<_, String>(2)? == "open",
        run_state: ManagedRunState::parse(&run_state).ok_or_else(|| {
            rusqlite::Error::InvalidColumnType(
                3,
                "run_state".to_owned(),
                rusqlite::types::Type::Text,
            )
        })?,
        revision: u64::try_from(revision).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
        created_ms: row.get(5)?,
        updated_ms: row.get(6)?,
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
        transaction.execute_batch(SCHEMA_V2)?;
        transaction.execute_batch(SCHEMA_V3)?;
        transaction.execute_batch(SCHEMA_V4)?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
    } else if version == 1 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA_V2)?;
        transaction.execute_batch(SCHEMA_V3)?;
        transaction.execute_batch(SCHEMA_V4)?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
    } else if version == 2 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA_V3)?;
        transaction.execute_batch(SCHEMA_V4)?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
    } else if version == 3 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA_V4)?;
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
        let first = store.observe_terminal("session-1", "run-1", 10).unwrap();
        assert_eq!(first.revision, 1);
        assert_eq!(
            store.observe_terminal("session-1", "run-1", 11).unwrap(),
            first
        );
        let second = store.observe_terminal("session-1", "run-2", 12).unwrap();
        assert_eq!(second.revision, 2);
        assert_eq!(second.run_id, "run-2");
        assert_eq!(store.by_run("run-2").unwrap(), Some(second.clone()));
        assert_eq!(store.list().unwrap(), vec![second]);
    }

    /// The binding names the in-flight run from turn start, and settles on the
    /// same run when it ends.  Both ends move the revision: an attached client
    /// that only ever saw the turn-start observation would never learn that the
    /// turn was over.
    #[test]
    fn a_turn_binds_its_run_in_flight_and_settles_on_the_same_run() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = ManagedSessionStore::open(root.path().join("managed.sqlite3")).unwrap();

        let first = store.observe_terminal("session-1", "run-1", 10).unwrap();
        assert_eq!(first.run_state, ManagedRunState::Completed);
        assert_eq!(first.revision, 1);

        let started = store.observe_active("session-1", "run-2", 11).unwrap();
        assert_eq!(started.run_id, "run-2");
        assert!(started.run_state.is_in_flight());
        assert_eq!(started.revision, 2);
        assert_eq!(
            store.observe_active("session-1", "run-2", 12).unwrap(),
            started,
            "the same turn observed twice holds the revision still"
        );
        assert_eq!(store.by_run("run-2").unwrap(), Some(started));
        assert_eq!(
            store.by_run("run-1").unwrap(),
            None,
            "the previous run is no longer the session's binding"
        );

        let settled = store.observe_terminal("session-1", "run-2", 13).unwrap();
        assert_eq!(settled.run_id, "run-2");
        assert_eq!(settled.run_state, ManagedRunState::Completed);
        assert_eq!(settled.revision, 3);
        assert_eq!(
            store.observe_terminal("session-1", "run-2", 14).unwrap(),
            settled
        );
    }

    /// A row written by a generation that predates turn-start binding named a
    /// run at its completion, so it opens as `completed` and nothing about the
    /// existing projection changes under it.
    #[test]
    fn a_pre_turn_start_row_migrates_to_a_completed_binding() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("managed.sqlite3");
        {
            let mut store = ManagedSessionStore::open(&path).unwrap();
            store.observe_terminal("session-1", "run-1", 10).unwrap();
            store
                .connection
                .execute_batch("ALTER TABLE managed_sessions DROP COLUMN run_state;")
                .unwrap();
            store
                .connection
                .pragma_update(None, "user_version", 2_u32)
                .unwrap();
        }
        let store = ManagedSessionStore::open(&path).unwrap();
        let migrated = store.by_id("session-1").unwrap().expect("migrated row");
        assert_eq!(migrated.run_id, "run-1");
        assert_eq!(migrated.run_state, ManagedRunState::Completed);
        assert_eq!(migrated.revision, 1);
    }

    #[test]
    fn legacy_v3_history_migrates_to_v1_domain_without_changing_replay() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("managed.sqlite3");
        {
            let mut store = ManagedSessionStore::open(&path).unwrap();
            store
                .record_completed_turn(
                    "session-1",
                    ManagedHistorySource::PlatformV1("legacy-turn"),
                    "legacy prompt",
                    "legacy answer",
                    &[],
                    10,
                )
                .unwrap();
            store
                .connection
                .execute_batch(
                    "DROP INDEX managed_session_history_page;
                     ALTER TABLE managed_session_history RENAME TO managed_session_history_v4;",
                )
                .unwrap();
            store.connection.execute_batch(SCHEMA_V2).unwrap();
            store
                .connection
                .execute_batch(
                    "INSERT INTO managed_session_history(
                         provider_session_id,sequence,source_key,at_ms,role,text,truncated,
                         evidence,tool_state,unknown_source,run_state
                     )
                     SELECT provider_session_id,sequence,source_key,at_ms,role,text,truncated,
                            evidence,tool_state,unknown_source,run_state
                     FROM managed_session_history_v4;
                     DROP TABLE managed_session_history_v4;",
                )
                .unwrap();
            store
                .connection
                .pragma_update(None, "user_version", 3_u32)
                .unwrap();
        }

        let mut migrated = ManagedSessionStore::open(&path).unwrap();
        assert_eq!(
            migrated
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM managed_session_history
                     WHERE source_domain='platform_v1'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
        migrated
            .record_completed_turn(
                "session-1",
                ManagedHistorySource::PlatformV1("legacy-turn"),
                "legacy prompt",
                "legacy answer",
                &[],
                11,
            )
            .unwrap();
        migrated
            .record_completed_turn(
                "session-1",
                ManagedHistorySource::RetainedReviewV2("legacy-turn"),
                "v2 prompt",
                "v2 answer",
                &[],
                12,
            )
            .unwrap();
        let ManagedHistoryRead::Page { head, .. } = migrated.history("session-1", 0, 16).unwrap()
        else {
            panic!("migrated history page");
        };
        assert_eq!(head, 4);
    }

    #[test]
    fn history_identity_is_global_within_each_typed_source_domain() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = ManagedSessionStore::open(root.path().join("managed.sqlite3")).unwrap();
        for (session, domain, prompt) in [
            (
                "session-1",
                ManagedHistorySource::PlatformV1("chosen-key"),
                "v1 session one",
            ),
            (
                "session-1",
                ManagedHistorySource::RetainedReviewV2("chosen-key"),
                "v2 session one",
            ),
        ] {
            store
                .record_completed_turn(session, domain, prompt, "answer", &[], 10)
                .unwrap();
        }
        assert!(
            store
                .record_completed_turn(
                    "session-2",
                    ManagedHistorySource::PlatformV1("chosen-key"),
                    "must conflict",
                    "answer",
                    &[],
                    10,
                )
                .is_err(),
            "one v1 occurrence cannot be attributed to a second session"
        );
        store
            .record_completed_turn(
                "session-2",
                ManagedHistorySource::PlatformV1("session-2-key"),
                "v1 session two",
                "answer",
                &[],
                10,
            )
            .unwrap();
        for session in ["session-1", "session-2"] {
            let ManagedHistoryRead::Page { head, .. } = store.history(session, 0, 16).unwrap()
            else {
                panic!("history page");
            };
            assert_eq!(head, if session == "session-1" { 4 } else { 2 });
        }
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

    #[test]
    fn history_is_gap_free_idempotent_and_resumes_exclusively() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = ManagedSessionStore::open(root.path().join("managed.sqlite3")).unwrap();
        store
            .record_completed_turn(
                "session-1",
                ManagedHistorySource::PlatformV1("turn-1"),
                "hello",
                "world",
                &[],
                10,
            )
            .unwrap();
        assert!(
            store
                .record_completed_turn(
                    "session-1",
                    ManagedHistorySource::PlatformV1("turn-1"),
                    "changed",
                    "world",
                    &[],
                    10,
                )
                .is_err()
        );
        store
            .record_completed_turn(
                "session-1",
                ManagedHistorySource::PlatformV1("turn-1"),
                "hello",
                "world",
                &[],
                10,
            )
            .unwrap();
        let ManagedHistoryRead::Page {
            events,
            head,
            has_more,
        } = store.history("session-1", 0, 1).unwrap()
        else {
            panic!("page");
        };
        assert_eq!(
            events
                .iter()
                .map(SessionHistoryEvent::cursor)
                .collect::<Vec<_>>(),
            vec![1]
        );
        assert_eq!(head, 2);
        assert!(has_more);
        let ManagedHistoryRead::Page {
            events, has_more, ..
        } = store.history("session-1", 1, 2).unwrap()
        else {
            panic!("page");
        };
        assert_eq!(
            events
                .iter()
                .map(SessionHistoryEvent::cursor)
                .collect::<Vec<_>>(),
            vec![2]
        );
        assert!(!has_more);
    }

    #[test]
    fn retention_gap_returns_resync_without_partial_events() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = ManagedSessionStore::open(root.path().join("managed.sqlite3")).unwrap();
        store
            .record_completed_turn(
                "session-1",
                ManagedHistorySource::PlatformV1("turn-1"),
                "hello",
                "world",
                &[],
                10,
            )
            .unwrap();
        store.connection.execute(
            "DELETE FROM managed_session_history WHERE provider_session_id='session-1' AND sequence < 2",
            [],
        ).unwrap();
        assert_eq!(
            store.history("session-1", 0, 2).unwrap(),
            ManagedHistoryRead::Resync {
                snapshot_from: 1,
                snapshot_to: 2
            }
        );
        let ManagedHistoryRead::Page { events, .. } =
            store.history_snapshot("session-1", 2).unwrap()
        else {
            panic!("snapshot");
        };
        assert_eq!(
            events
                .iter()
                .map(SessionHistoryEvent::cursor)
                .collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[test]
    fn history_text_is_utf8_bounded_and_control_free() {
        let input = format!("{}\0secret", "é".repeat(300));
        let (text, truncated) = sanitize_history_text(&input).unwrap();
        assert!(truncated);
        assert!(
            text.as_str().len() <= automonique_protocol::platform::MAX_SESSION_HISTORY_TEXT_BYTES
        );
        assert!(!text.as_str().chars().any(char::is_control));
    }

    #[test]
    fn opaque_spool_payload_never_enters_the_history_serialization() {
        use automonique_protocol::codec::RequestId;
        use automonique_protocol::platform::{
            PlatformResponse, ResourceAuthority, ResourceCoordinate, ResourceKind,
            SessionHistoryPage,
        };
        use automonique_protocol::platform_api::PlatformResponseMessage;
        use automonique_runner::{Authority, EventKind, Spool};

        const FORBIDDEN: &[u8] = b"FORBIDDEN_PROVIDER_PROMPT_TOOL_CREDENTIAL_BYTES";
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut spool = Spool::open(root.path().join("spool"), "run-1", 1_000_000).unwrap();
        spool
            .append(EventKind::Started, Authority::Authoritative, FORBIDDEN)
            .unwrap();
        spool
            .append(EventKind::AdapterEvent, Authority::Authoritative, FORBIDDEN)
            .unwrap();
        spool
            .append(
                EventKind::Terminal,
                Authority::Authoritative,
                TERMINAL_COMPLETED,
            )
            .unwrap();
        drop(spool);
        let events = automonique_runner::read_events(root.path().join("spool"), "run-1").unwrap();

        let mut store = ManagedSessionStore::open(root.path().join("managed.sqlite3")).unwrap();
        store
            .record_completed_turn(
                "session-1",
                ManagedHistorySource::PlatformV1("turn-1"),
                "hello",
                "world",
                &events,
                10,
            )
            .unwrap();
        let ManagedHistoryRead::Page {
            events, has_more, ..
        } = store.history("session-1", 0, 10).unwrap()
        else {
            panic!("page");
        };
        let session = ResourceCoordinate::new(
            ResourceAuthority::Automonique,
            ResourceKind::Session,
            ResourceId::new("session-1").unwrap(),
        );
        let terminal = events.last().map_or(0, SessionHistoryEvent::cursor);
        let page = SessionHistoryPage::new(session, 10, 10, 0, terminal, has_more, events).unwrap();
        let bytes = PlatformResponseMessage::new(
            RequestId::new("history-sentinel").unwrap(),
            PlatformResponse::SessionHistory(page),
        )
        .to_message()
        .unwrap()
        .to_canonical_bytes();
        assert!(
            !bytes
                .windows(FORBIDDEN.len())
                .any(|window| window == FORBIDDEN)
        );
    }
}
