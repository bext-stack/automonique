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

    /// Atomically append the authoritative accepted prompt and final answer.
    /// `source_key` is server-produced and makes crash replay idempotent.
    pub fn record_completed_turn(
        &mut self,
        provider_session_id: &str,
        source_key: &str,
        user_text: &str,
        assistant_text: &str,
        spool_events: &[SpoolEvent],
        at_ms: i64,
    ) -> Managed<()> {
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
        let existing: Option<(String, i64, String, i64)> = transaction
            .query_row(
                "SELECT user.text,user.truncated,assistant.text,assistant.truncated
                 FROM managed_session_history user
                 JOIN managed_session_history assistant ON assistant.source_key=?3
                 WHERE user.source_key=?2 AND user.provider_session_id=?1
                   AND assistant.provider_session_id=?1",
                params![
                    provider_session_id,
                    format!("{source_key}:user"),
                    format!("{source_key}:assistant")
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if let Some((
            stored_user,
            stored_user_truncated,
            stored_assistant,
            stored_assistant_truncated,
        )) = existing
        {
            if stored_user != user_text.as_str()
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
            "INSERT INTO managed_session_history(provider_session_id,sequence,source_key,at_ms,role,text,truncated,evidence,tool_state,unknown_source,run_state)
             VALUES(?1,?2,?3,?4,'user',?5,?6,'authoritative',NULL,NULL,NULL) ON CONFLICT(source_key) DO NOTHING",
            params![provider_session_id, sequence, user_key, at_ms, user_text.as_str(), user_truncated],
        )?;
        for (index, event) in projected.iter().enumerate() {
            sequence = sequence
                .checked_add(1)
                .ok_or(ManagedSessionError::InvalidField("sequence"))?;
            let key = format!("{source_key}:spool:{index}");
            match event {
                PendingHistoryEvent::ToolState { at_ms, evidence, state, label, truncated } => transaction.execute(
                    "INSERT INTO managed_session_history(provider_session_id,sequence,source_key,at_ms,role,text,truncated,evidence,tool_state,unknown_source,run_state)
                     VALUES(?1,?2,?3,?4,NULL,?5,?6,?7,?8,NULL,NULL) ON CONFLICT(source_key) DO NOTHING",
                    params![provider_session_id, sequence, key, at_ms, label.as_ref().map(SessionHistoryText::as_str), truncated, evidence.as_str(), state.as_str()],
                )?,
                PendingHistoryEvent::RunState { at_ms, state } => transaction.execute(
                    "INSERT INTO managed_session_history(provider_session_id,sequence,source_key,at_ms,role,text,truncated,evidence,tool_state,unknown_source,run_state)
                     VALUES(?1,?2,?3,?4,NULL,NULL,NULL,NULL,NULL,NULL,?5) ON CONFLICT(source_key) DO NOTHING",
                    params![provider_session_id, sequence, key, at_ms, state.as_str()],
                )?,
                PendingHistoryEvent::Unknown { at_ms, source } => transaction.execute(
                    "INSERT INTO managed_session_history(provider_session_id,sequence,source_key,at_ms,role,text,truncated,evidence,tool_state,unknown_source,run_state)
                     VALUES(?1,?2,?3,?4,NULL,NULL,NULL,NULL,NULL,?5,NULL) ON CONFLICT(source_key) DO NOTHING",
                    params![provider_session_id, sequence, key, at_ms, source.as_str()],
                )?,
            };
        }
        sequence = sequence
            .checked_add(1)
            .ok_or(ManagedSessionError::InvalidField("sequence"))?;
        transaction.execute(
            "INSERT INTO managed_session_history(provider_session_id,sequence,source_key,at_ms,role,text,truncated,evidence,tool_state,unknown_source,run_state)
             VALUES(?1,?2,?3,?4,'assistant',?5,?6,'authoritative',NULL,NULL,NULL) ON CONFLICT(source_key) DO NOTHING",
            params![provider_session_id, sequence, format!("{source_key}:assistant"), at_ms, assistant_text.as_str(), assistant_truncated],
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
        transaction.execute_batch(SCHEMA_V2)?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
    } else if version == 1 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA_V2)?;
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

    #[test]
    fn history_is_gap_free_idempotent_and_resumes_exclusively() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = ManagedSessionStore::open(root.path().join("managed.sqlite3")).unwrap();
        store
            .record_completed_turn("session-1", "turn-1", "hello", "world", &[], 10)
            .unwrap();
        assert!(
            store
                .record_completed_turn("session-1", "turn-1", "changed", "world", &[], 10)
                .is_err()
        );
        store
            .record_completed_turn("session-1", "turn-1", "hello", "world", &[], 10)
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
            .record_completed_turn("session-1", "turn-1", "hello", "world", &[], 10)
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
            .record_completed_turn("session-1", "turn-1", "hello", "world", &events, 10)
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
