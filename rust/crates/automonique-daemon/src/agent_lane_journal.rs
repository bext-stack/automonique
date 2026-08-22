// SPDX-License-Identifier: Elastic-2.0

//! Durable, append-only run coordinates for the conversational agent harness.
//!
//! A lane is a transport-independent conversation coordinate. Each run stores
//! its intent before a provider is called, then appends provider intents,
//! transcript entries, tool intents and tool outcomes in one total order. The
//! current ambiguous provider or tool boundary is repeated on the run row so a
//! restarting owner can recover without inferring that an external effect did
//! or did not happen.
//!
//! This journal performs no provider or tool IO and grants no authority. The
//! caller must record an intent before invoking the corresponding effect. Tool
//! idempotency keys are persisted whole so the broker can safely reconcile a
//! crash between effect execution and outcome recording.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use nix::unistd::geteuid;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};

pub const AGENT_LANE_JOURNAL_SCHEMA_VERSION: u32 = 2;
pub const AGENT_LANE_JOURNAL_NAME: &str = "agent-lanes.sqlite3";

const BUSY_TIMEOUT: Duration = Duration::from_millis(2_000);
const MAX_KEY_BYTES: usize = 256;
const MAX_TOOL_NAME_BYTES: usize = 128;
const MAX_APPROVAL_SUMMARY_BYTES: usize = 16 * 1024;
const MAX_JSON_BYTES: usize = 1024 * 1024;

const SCHEMA_V2: &str = r#"
CREATE TABLE agent_lane_runs (
    run_id INTEGER PRIMARY KEY,
    lane_key TEXT NOT NULL,
    run_key TEXT NOT NULL UNIQUE,
    intent_json BLOB NOT NULL CHECK (typeof(intent_json) = 'blob'),
    status TEXT NOT NULL CHECK (
        status IN ('running', 'awaiting_approval', 'completed', 'failed')
    ),
    opened_ms INTEGER NOT NULL CHECK (opened_ms >= 0),
    finished_ms INTEGER CHECK (finished_ms IS NULL OR finished_ms >= opened_ms),
    terminal_json BLOB CHECK (terminal_json IS NULL OR typeof(terminal_json) = 'blob'),
    next_sequence INTEGER NOT NULL CHECK (next_sequence >= 2),
    provider_round INTEGER NOT NULL DEFAULT 0 CHECK (provider_round >= 0),
    pending_provider_round INTEGER CHECK (pending_provider_round >= 1),
    completed_tool_calls INTEGER NOT NULL DEFAULT 0 CHECK (completed_tool_calls >= 0),
    pending_tool_sequence INTEGER CHECK (pending_tool_sequence >= 1),
    pending_call_id TEXT,
    pending_tool_name TEXT,
    pending_idempotency_key TEXT,
    pending_arguments_json BLOB CHECK (
        pending_arguments_json IS NULL OR typeof(pending_arguments_json) = 'blob'
    ),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    CHECK (
        (status IN ('running', 'awaiting_approval')
         AND finished_ms IS NULL AND terminal_json IS NULL)
        OR
        (status IN ('completed', 'failed')
         AND finished_ms IS NOT NULL AND terminal_json IS NOT NULL)
    ),
    CHECK (
        (pending_tool_sequence IS NULL AND pending_call_id IS NULL
         AND pending_tool_name IS NULL AND pending_idempotency_key IS NULL
         AND pending_arguments_json IS NULL)
        OR
        (pending_tool_sequence IS NOT NULL AND pending_call_id IS NOT NULL
         AND pending_tool_name IS NOT NULL AND pending_idempotency_key IS NOT NULL
         AND pending_arguments_json IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX agent_lane_one_active_run
    ON agent_lane_runs(lane_key)
    WHERE status IN ('running', 'awaiting_approval');

CREATE TABLE agent_lane_events (
    event_id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES agent_lane_runs(run_id),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    kind TEXT NOT NULL CHECK (kind IN (
        'run_intent', 'provider_intent', 'provider_outcome', 'transcript', 'tool_intent',
        'tool_outcome', 'approval_pending', 'approval_decision', 'terminal'
    )),
    payload_json BLOB NOT NULL CHECK (typeof(payload_json) = 'blob'),
    recorded_ms INTEGER NOT NULL CHECK (recorded_ms >= 0),
    UNIQUE (run_id, sequence)
) STRICT;

CREATE TABLE agent_lane_approvals (
    run_id INTEGER NOT NULL REFERENCES agent_lane_runs(run_id),
    approval_key TEXT NOT NULL,
    call_id TEXT NOT NULL,
    summary TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied')),
    requested_ms INTEGER NOT NULL CHECK (requested_ms >= 0),
    decision_ref TEXT,
    decided_ms INTEGER CHECK (decided_ms IS NULL OR decided_ms >= requested_ms),
    PRIMARY KEY (run_id, approval_key),
    CHECK (
        (status = 'pending' AND decision_ref IS NULL AND decided_ms IS NULL)
        OR
        (status <> 'pending' AND decision_ref IS NOT NULL AND decided_ms IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX agent_lane_one_pending_approval
    ON agent_lane_approvals(run_id) WHERE status = 'pending';
"#;

/// Schema v1's event vocabulary did not admit `provider_outcome`. Rebuilding
/// the table is required because SQLite cannot alter a table-level CHECK.
const MIGRATE_V1_TO_V2: &str = r#"
ALTER TABLE agent_lane_events RENAME TO agent_lane_events_v1;

CREATE TABLE agent_lane_events (
    event_id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES agent_lane_runs(run_id),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    kind TEXT NOT NULL CHECK (kind IN (
        'run_intent', 'provider_intent', 'provider_outcome', 'transcript', 'tool_intent',
        'tool_outcome', 'approval_pending', 'approval_decision', 'terminal'
    )),
    payload_json BLOB NOT NULL CHECK (typeof(payload_json) = 'blob'),
    recorded_ms INTEGER NOT NULL CHECK (recorded_ms >= 0),
    UNIQUE (run_id, sequence)
) STRICT;

INSERT INTO agent_lane_events
    (event_id, run_id, sequence, kind, payload_json, recorded_ms)
SELECT event_id, run_id, sequence, kind, payload_json, recorded_ms
FROM agent_lane_events_v1
ORDER BY event_id;

DROP TABLE agent_lane_events_v1;
"#;

#[derive(Debug)]
pub enum AgentLaneJournalError {
    InsecurePath(String),
    SchemaVersion { found: u32, supported: u32 },
    InvalidField(&'static str),
    NotFound,
    Conflict(&'static str),
    Terminal,
    PendingProvider,
    PendingTool,
    PendingApproval,
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
}

impl fmt::Display for AgentLaneJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => write!(formatter, "agent lane journal path: {reason}"),
            Self::SchemaVersion { found, supported } => {
                write!(formatter, "agent lane schema {found}, expected {supported}")
            }
            Self::InvalidField(field) => write!(formatter, "invalid agent lane field: {field}"),
            Self::NotFound => formatter.write_str("agent lane run not found"),
            Self::Conflict(field) => write!(formatter, "agent lane conflict: {field}"),
            Self::Terminal => formatter.write_str("agent lane run is terminal"),
            Self::PendingProvider => formatter.write_str("agent lane provider result is pending"),
            Self::PendingTool => formatter.write_str("agent lane tool outcome is pending"),
            Self::PendingApproval => formatter.write_str("agent lane approval is pending"),
            Self::Io(error) => write!(formatter, "agent lane journal I/O: {error}"),
            Self::Sqlite(error) => write!(formatter, "agent lane journal SQLite: {error}"),
        }
    }
}

impl std::error::Error for AgentLaneJournalError {}

impl From<std::io::Error> for AgentLaneJournalError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for AgentLaneJournalError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

pub type Journalled<T> = Result<T, AgentLaneJournalError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunStatus {
    Running,
    AwaitingApproval,
    Completed,
    Failed,
}

impl RunStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Journalled<Self> {
        match value {
            "running" => Ok(Self::Running),
            "awaiting_approval" => Ok(Self::AwaitingApproval),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            _ => Err(AgentLaneJournalError::Conflict("status")),
        }
    }

    const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranscriptKind {
    User,
    Assistant,
    ToolCall,
    ToolResult,
}

impl TranscriptKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::ToolCall => "tool_call",
            Self::ToolResult => "tool_result",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    Approved,
    Denied,
}

impl ApprovalDecision {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalStatus {
    Completed,
    Failed,
}

impl TerminalStatus {
    const fn run_status(self) -> RunStatus {
        match self {
            Self::Completed => RunStatus::Completed,
            Self::Failed => RunStatus::Failed,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunCursor {
    pub run_id: i64,
    pub revision: u64,
    pub next_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunReceipt {
    pub cursor: RunCursor,
    pub duplicate: bool,
}

pub struct RunIntent<'a> {
    pub lane_key: &'a str,
    pub run_key: &'a str,
    pub intent: &'a Value,
    pub opened_ms: i64,
}

pub struct ProviderIntent<'a> {
    pub cursor: &'a RunCursor,
    pub round: u32,
    pub request: &'a Value,
    pub recorded_ms: i64,
}

pub struct ProviderOutcome<'a> {
    pub cursor: &'a RunCursor,
    pub round: u32,
    pub outcome: &'a Value,
    pub recorded_ms: i64,
}

pub struct TranscriptAppend<'a> {
    pub cursor: &'a RunCursor,
    pub kind: TranscriptKind,
    pub content: &'a Value,
    pub recorded_ms: i64,
}

pub struct ToolIntent<'a> {
    pub cursor: &'a RunCursor,
    pub call_id: &'a str,
    pub tool_name: &'a str,
    pub idempotency_key: &'a str,
    pub arguments: &'a Value,
    pub recorded_ms: i64,
}

pub struct ToolOutcome<'a> {
    pub cursor: &'a RunCursor,
    pub call_id: &'a str,
    pub outcome: &'a Value,
    pub recorded_ms: i64,
}

pub struct ApprovalPending<'a> {
    pub cursor: &'a RunCursor,
    pub approval_key: &'a str,
    pub call_id: &'a str,
    pub summary: &'a str,
    pub requested_ms: i64,
}

pub struct ApprovalResolution<'a> {
    pub cursor: &'a RunCursor,
    pub approval_key: &'a str,
    pub decision: ApprovalDecision,
    pub decision_ref: &'a str,
    pub decided_ms: i64,
}

pub struct TerminalRecord<'a> {
    pub cursor: &'a RunCursor,
    pub status: TerminalStatus,
    pub detail: &'a Value,
    pub finished_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingTool {
    pub intent_sequence: u64,
    pub call_id: String,
    pub tool_name: String,
    pub idempotency_key: String,
    pub arguments: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingApproval {
    pub approval_key: String,
    pub call_id: String,
    pub summary: String,
    pub requested_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalEvent {
    pub sequence: u64,
    pub kind: String,
    pub payload: Value,
    pub recorded_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunRecovery {
    pub cursor: RunCursor,
    pub lane_key: String,
    pub run_key: String,
    pub intent: Value,
    pub status: RunStatus,
    pub opened_ms: i64,
    pub finished_ms: Option<i64>,
    pub terminal_detail: Option<Value>,
    pub provider_round: u32,
    pub pending_provider_round: Option<u32>,
    pub completed_tool_calls: u32,
    pub pending_tool: Option<PendingTool>,
    pub pending_approval: Option<PendingApproval>,
    pub events: Vec<JournalEvent>,
}

#[derive(Debug)]
pub struct AgentLaneJournal {
    connection: Connection,
    path: PathBuf,
}

impl AgentLaneJournal {
    pub fn open(path: impl AsRef<Path>) -> Journalled<Self> {
        let path = path.as_ref();
        validate_database_path(path)?;
        if !path.exists() {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
        }
        validate_database_path(path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = Connection::open_with_flags(path, flags)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let journal: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(AgentLaneJournalError::Sqlite(rusqlite::Error::InvalidQuery));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
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

    pub fn begin_run(&mut self, intent: RunIntent<'_>) -> Journalled<RunReceipt> {
        validate_key(intent.lane_key, "lane_key")?;
        validate_key(intent.run_key, "run_key")?;
        validate_time(intent.opened_ms, "opened_ms")?;
        let intent_json = encode_json(intent.intent, "intent")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_run_by_key(&transaction, intent.run_key)? {
            if existing.lane_key != intent.lane_key
                || existing.intent_json != intent_json
                || existing.opened_ms != intent.opened_ms
            {
                return Err(AgentLaneJournalError::Conflict("run_key"));
            }
            transaction.commit()?;
            return Ok(RunReceipt {
                cursor: existing.cursor(),
                duplicate: true,
            });
        }
        let active: bool = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM agent_lane_runs
                 WHERE lane_key = ?1 AND status IN ('running', 'awaiting_approval')
             )",
            [intent.lane_key],
            |row| row.get(0),
        )?;
        if active {
            return Err(AgentLaneJournalError::Conflict("lane_active"));
        }
        transaction.execute(
            "INSERT INTO agent_lane_runs
             (lane_key, run_key, intent_json, status, opened_ms, next_sequence, revision)
             VALUES (?1, ?2, ?3, 'running', ?4, 2, 1)",
            params![
                intent.lane_key,
                intent.run_key,
                intent_json,
                intent.opened_ms
            ],
        )?;
        let run_id = transaction.last_insert_rowid();
        insert_event(
            &transaction,
            run_id,
            1,
            "run_intent",
            &intent_json,
            intent.opened_ms,
        )?;
        transaction.commit()?;
        Ok(RunReceipt {
            cursor: RunCursor {
                run_id,
                revision: 1,
                next_sequence: 2,
            },
            duplicate: false,
        })
    }

    /// Persist a provider request before performing the provider call.
    pub fn record_provider_intent(&mut self, intent: ProviderIntent<'_>) -> Journalled<RunCursor> {
        validate_time(intent.recorded_ms, "recorded_ms")?;
        if intent.round == 0 {
            return Err(AgentLaneJournalError::InvalidField("round"));
        }
        let payload = encode_json(
            &json!({"round": intent.round, "request": intent.request}),
            "provider_request",
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let run = require_cursor(&transaction, intent.cursor)?;
        require_running(&run)?;
        if run.pending_provider_round.is_some() {
            return Err(AgentLaneJournalError::PendingProvider);
        }
        if intent.round != run.provider_round.saturating_add(1) {
            return Err(AgentLaneJournalError::Conflict("provider_round"));
        }
        if run.pending_tool.is_some() {
            return Err(AgentLaneJournalError::PendingTool);
        }
        insert_event(
            &transaction,
            run.run_id,
            run.next_sequence,
            "provider_intent",
            &payload,
            intent.recorded_ms,
        )?;
        advance_run(
            &transaction,
            &run,
            "UPDATE agent_lane_runs
             SET provider_round = ?1, pending_provider_round = ?1,
                 next_sequence = next_sequence + 1, revision = revision + 1
             WHERE run_id = ?2 AND revision = ?3",
            params![i64::from(intent.round), run.run_id, to_i64(run.revision)?],
        )?;
        transaction.commit()?;
        Ok(run.advanced())
    }

    pub fn record_transcript(&mut self, append: TranscriptAppend<'_>) -> Journalled<RunCursor> {
        validate_time(append.recorded_ms, "recorded_ms")?;
        let payload = encode_json(
            &json!({"kind": append.kind.as_str(), "content": append.content}),
            "transcript",
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let run = require_cursor(&transaction, append.cursor)?;
        require_running(&run)?;
        if run.pending_provider_round.is_some()
            && matches!(
                append.kind,
                TranscriptKind::Assistant | TranscriptKind::ToolCall
            )
        {
            return Err(AgentLaneJournalError::PendingProvider);
        }
        insert_event(
            &transaction,
            run.run_id,
            run.next_sequence,
            "transcript",
            &payload,
            append.recorded_ms,
        )?;
        advance_run(
            &transaction,
            &run,
            "UPDATE agent_lane_runs
             SET next_sequence = next_sequence + 1, revision = revision + 1
             WHERE run_id = ?1 AND revision = ?2",
            params![run.run_id, to_i64(run.revision)?],
        )?;
        transaction.commit()?;
        Ok(run.advanced())
    }

    /// Persist the typed provider result (or refusal) after the provider call.
    /// A matching pending round is required, so a restart never mistakes an
    /// old response for the result of a newer request.
    pub fn record_provider_outcome(
        &mut self,
        outcome: ProviderOutcome<'_>,
    ) -> Journalled<RunCursor> {
        validate_time(outcome.recorded_ms, "recorded_ms")?;
        validate_provider_outcome(outcome.outcome)?;
        if outcome.round == 0 {
            return Err(AgentLaneJournalError::InvalidField("round"));
        }
        let payload = encode_json(
            &json!({"round": outcome.round, "outcome": outcome.outcome}),
            "provider_outcome",
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let run = require_cursor(&transaction, outcome.cursor)?;
        require_running(&run)?;
        if run.pending_provider_round != Some(outcome.round) {
            return Err(AgentLaneJournalError::Conflict("provider_round"));
        }
        insert_event(
            &transaction,
            run.run_id,
            run.next_sequence,
            "provider_outcome",
            &payload,
            outcome.recorded_ms,
        )?;
        advance_run(
            &transaction,
            &run,
            "UPDATE agent_lane_runs
             SET pending_provider_round = NULL,
                 next_sequence = next_sequence + 1, revision = revision + 1
             WHERE run_id = ?1 AND revision = ?2",
            params![run.run_id, to_i64(run.revision)?],
        )?;
        transaction.commit()?;
        Ok(run.advanced())
    }

    /// Persist an exact tool invocation before reaching the broker/executor.
    pub fn record_tool_intent(&mut self, intent: ToolIntent<'_>) -> Journalled<RunCursor> {
        validate_key(intent.call_id, "call_id")?;
        validate_tool_name(intent.tool_name)?;
        validate_key(intent.idempotency_key, "idempotency_key")?;
        validate_time(intent.recorded_ms, "recorded_ms")?;
        if !intent.arguments.is_object() {
            return Err(AgentLaneJournalError::InvalidField("arguments"));
        }
        let arguments = encode_json(intent.arguments, "arguments")?;
        let payload = encode_json(
            &json!({
                "call_id": intent.call_id,
                "tool": intent.tool_name,
                "idempotency_key": intent.idempotency_key,
                "arguments": intent.arguments
            }),
            "tool_intent",
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let run = require_cursor(&transaction, intent.cursor)?;
        require_running(&run)?;
        if run.pending_provider_round.is_some() {
            return Err(AgentLaneJournalError::PendingProvider);
        }
        if run.pending_tool.is_some() {
            return Err(AgentLaneJournalError::PendingTool);
        }
        let previous = read_event(
            &transaction,
            run.run_id,
            run.next_sequence.saturating_sub(1),
        )?
        .ok_or(AgentLaneJournalError::Conflict("tool_intent_order"))?;
        if previous.kind != "provider_outcome"
            || !provider_outcome_matches_tool(
                &previous.payload,
                run.provider_round,
                intent.call_id,
                intent.tool_name,
                intent.arguments,
            )?
        {
            return Err(AgentLaneJournalError::Conflict("tool_intent_order"));
        }
        insert_event(
            &transaction,
            run.run_id,
            run.next_sequence,
            "tool_intent",
            &payload,
            intent.recorded_ms,
        )?;
        advance_run(
            &transaction,
            &run,
            "UPDATE agent_lane_runs
             SET pending_provider_round = NULL,
                 pending_tool_sequence = ?1, pending_call_id = ?2,
                 pending_tool_name = ?3, pending_idempotency_key = ?4,
                 pending_arguments_json = ?5,
                 next_sequence = next_sequence + 1, revision = revision + 1
             WHERE run_id = ?6 AND revision = ?7",
            params![
                to_i64(run.next_sequence)?,
                intent.call_id,
                intent.tool_name,
                intent.idempotency_key,
                arguments,
                run.run_id,
                to_i64(run.revision)?
            ],
        )?;
        transaction.commit()?;
        Ok(run.advanced())
    }

    pub fn record_tool_outcome(&mut self, outcome: ToolOutcome<'_>) -> Journalled<RunCursor> {
        validate_key(outcome.call_id, "call_id")?;
        validate_time(outcome.recorded_ms, "recorded_ms")?;
        let payload = encode_json(
            &json!({"call_id": outcome.call_id, "outcome": outcome.outcome}),
            "tool_outcome",
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let run = require_cursor(&transaction, outcome.cursor)?;
        require_running(&run)?;
        let pending = run
            .pending_tool
            .as_ref()
            .ok_or(AgentLaneJournalError::Conflict("tool_outcome"))?;
        if pending.call_id != outcome.call_id {
            return Err(AgentLaneJournalError::Conflict("call_id"));
        }
        if read_pending_approval(&transaction, run.run_id)?.is_some() {
            return Err(AgentLaneJournalError::PendingApproval);
        }
        insert_event(
            &transaction,
            run.run_id,
            run.next_sequence,
            "tool_outcome",
            &payload,
            outcome.recorded_ms,
        )?;
        advance_run(
            &transaction,
            &run,
            "UPDATE agent_lane_runs
             SET completed_tool_calls = completed_tool_calls + 1,
                 pending_tool_sequence = NULL, pending_call_id = NULL,
                 pending_tool_name = NULL, pending_idempotency_key = NULL,
                 pending_arguments_json = NULL,
                 next_sequence = next_sequence + 1, revision = revision + 1
             WHERE run_id = ?1 AND revision = ?2",
            params![run.run_id, to_i64(run.revision)?],
        )?;
        transaction.commit()?;
        Ok(run.advanced())
    }

    pub fn request_approval(&mut self, pending: ApprovalPending<'_>) -> Journalled<RunCursor> {
        validate_key(pending.approval_key, "approval_key")?;
        validate_key(pending.call_id, "call_id")?;
        validate_summary(pending.summary)?;
        validate_time(pending.requested_ms, "requested_ms")?;
        let payload = encode_json(
            &json!({
                "approval_key": pending.approval_key,
                "call_id": pending.call_id,
                "summary": pending.summary
            }),
            "approval_pending",
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let run = require_cursor(&transaction, pending.cursor)?;
        require_running(&run)?;
        let tool = run
            .pending_tool
            .as_ref()
            .ok_or(AgentLaneJournalError::Conflict("approval_tool"))?;
        if tool.call_id != pending.call_id {
            return Err(AgentLaneJournalError::Conflict("call_id"));
        }
        if read_pending_approval(&transaction, run.run_id)?.is_some() {
            return Err(AgentLaneJournalError::PendingApproval);
        }
        transaction.execute(
            "INSERT INTO agent_lane_approvals
             (run_id, approval_key, call_id, summary, status, requested_ms)
             VALUES (?1, ?2, ?3, ?4, 'pending', ?5)",
            params![
                run.run_id,
                pending.approval_key,
                pending.call_id,
                pending.summary,
                pending.requested_ms
            ],
        )?;
        insert_event(
            &transaction,
            run.run_id,
            run.next_sequence,
            "approval_pending",
            &payload,
            pending.requested_ms,
        )?;
        advance_run(
            &transaction,
            &run,
            "UPDATE agent_lane_runs
             SET status = 'awaiting_approval', next_sequence = next_sequence + 1,
                 revision = revision + 1
             WHERE run_id = ?1 AND revision = ?2",
            params![run.run_id, to_i64(run.revision)?],
        )?;
        transaction.commit()?;
        Ok(run.advanced())
    }

    pub fn resolve_approval(
        &mut self,
        resolution: ApprovalResolution<'_>,
    ) -> Journalled<RunCursor> {
        validate_key(resolution.approval_key, "approval_key")?;
        validate_key(resolution.decision_ref, "decision_ref")?;
        validate_time(resolution.decided_ms, "decided_ms")?;
        let payload = encode_json(
            &json!({
                "approval_key": resolution.approval_key,
                "decision": resolution.decision.as_str(),
                "decision_ref": resolution.decision_ref
            }),
            "approval_decision",
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let run = require_cursor(&transaction, resolution.cursor)?;
        if run.status != RunStatus::AwaitingApproval {
            return Err(if run.status.is_terminal() {
                AgentLaneJournalError::Terminal
            } else {
                AgentLaneJournalError::Conflict("approval_status")
            });
        }
        let approval = read_pending_approval(&transaction, run.run_id)?
            .ok_or(AgentLaneJournalError::Conflict("approval_missing"))?;
        if approval.approval_key != resolution.approval_key {
            return Err(AgentLaneJournalError::Conflict("approval_key"));
        }
        if resolution.decided_ms < approval.requested_ms {
            return Err(AgentLaneJournalError::InvalidField("decided_ms"));
        }
        transaction.execute(
            "UPDATE agent_lane_approvals
             SET status = ?1, decision_ref = ?2, decided_ms = ?3
             WHERE run_id = ?4 AND approval_key = ?5 AND status = 'pending'",
            params![
                resolution.decision.as_str(),
                resolution.decision_ref,
                resolution.decided_ms,
                run.run_id,
                resolution.approval_key
            ],
        )?;
        insert_event(
            &transaction,
            run.run_id,
            run.next_sequence,
            "approval_decision",
            &payload,
            resolution.decided_ms,
        )?;
        advance_run(
            &transaction,
            &run,
            "UPDATE agent_lane_runs
             SET status = 'running', next_sequence = next_sequence + 1,
                 revision = revision + 1
             WHERE run_id = ?1 AND revision = ?2",
            params![run.run_id, to_i64(run.revision)?],
        )?;
        transaction.commit()?;
        Ok(run.advanced())
    }

    pub fn finish(&mut self, terminal: TerminalRecord<'_>) -> Journalled<RunCursor> {
        validate_time(terminal.finished_ms, "finished_ms")?;
        let detail = encode_json(terminal.detail, "terminal_detail")?;
        let payload = encode_json(
            &json!({
                "status": terminal.status.run_status().as_str(),
                "detail": terminal.detail
            }),
            "terminal",
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let run = require_cursor(&transaction, terminal.cursor)?;
        require_running(&run)?;
        if terminal.finished_ms < run.opened_ms {
            return Err(AgentLaneJournalError::InvalidField("finished_ms"));
        }
        if run.pending_provider_round.is_some() {
            return Err(AgentLaneJournalError::PendingProvider);
        }
        if run.pending_tool.is_some() {
            return Err(AgentLaneJournalError::PendingTool);
        }
        if read_pending_approval(&transaction, run.run_id)?.is_some() {
            return Err(AgentLaneJournalError::PendingApproval);
        }
        insert_event(
            &transaction,
            run.run_id,
            run.next_sequence,
            "terminal",
            &payload,
            terminal.finished_ms,
        )?;
        advance_run(
            &transaction,
            &run,
            "UPDATE agent_lane_runs
             SET status = ?1, finished_ms = ?2, terminal_json = ?3,
                 next_sequence = next_sequence + 1, revision = revision + 1
             WHERE run_id = ?4 AND revision = ?5",
            params![
                terminal.status.run_status().as_str(),
                terminal.finished_ms,
                detail,
                run.run_id,
                to_i64(run.revision)?
            ],
        )?;
        transaction.commit()?;
        Ok(run.advanced())
    }

    pub fn recover(&self, run_key: &str) -> Journalled<Option<RunRecovery>> {
        validate_key(run_key, "run_key")?;
        let Some(run) = read_run_by_key(&self.connection, run_key)? else {
            return Ok(None);
        };
        self.recover_run(run).map(Some)
    }

    pub fn recover_active_lane(&self, lane_key: &str) -> Journalled<Option<RunRecovery>> {
        validate_key(lane_key, "lane_key")?;
        let run = self
            .connection
            .query_row(
                &format!(
                    "{RUN_SELECT} WHERE lane_key = ?1
                     AND status IN ('running', 'awaiting_approval')"
                ),
                [lane_key],
                decode_run,
            )
            .optional()?;
        run.map(|row| self.recover_run(row)).transpose()
    }

    fn recover_run(&self, run: StoredRun) -> Journalled<RunRecovery> {
        validate_stored_run(&run)?;
        let pending_approval = read_pending_approval(&self.connection, run.run_id)?;
        if (run.status == RunStatus::AwaitingApproval) != pending_approval.is_some() {
            return Err(AgentLaneJournalError::Conflict("approval_state"));
        }
        let mut statement = self.connection.prepare(
            "SELECT sequence, kind, payload_json, recorded_ms
             FROM agent_lane_events WHERE run_id = ?1 ORDER BY sequence",
        )?;
        let rows = statement.query_map([run.run_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut events = Vec::new();
        for row in rows {
            let (sequence, kind, payload, recorded_ms) = row?;
            let sequence = from_i64(sequence, "event_sequence")?;
            if !matches!(
                kind.as_str(),
                "run_intent"
                    | "provider_intent"
                    | "provider_outcome"
                    | "transcript"
                    | "tool_intent"
                    | "tool_outcome"
                    | "approval_pending"
                    | "approval_decision"
                    | "terminal"
            ) || recorded_ms < 0
            {
                return Err(AgentLaneJournalError::Conflict("event"));
            }
            if sequence != u64::try_from(events.len()).unwrap_or(u64::MAX) + 1 {
                return Err(AgentLaneJournalError::Conflict("event_sequence"));
            }
            events.push(JournalEvent {
                sequence,
                kind,
                payload: decode_json(&payload, "event_payload")?,
                recorded_ms,
            });
        }
        if u64::try_from(events.len()).unwrap_or(u64::MAX) + 1 != run.next_sequence {
            return Err(AgentLaneJournalError::Conflict("next_sequence"));
        }
        validate_event_invariants(&run, &events)?;
        Ok(RunRecovery {
            cursor: run.cursor(),
            lane_key: run.lane_key,
            run_key: run.run_key,
            intent: decode_json(&run.intent_json, "intent")?,
            status: run.status,
            opened_ms: run.opened_ms,
            finished_ms: run.finished_ms,
            terminal_detail: run
                .terminal_json
                .as_deref()
                .map(|value| decode_json(value, "terminal_detail"))
                .transpose()?,
            provider_round: run.provider_round,
            pending_provider_round: run.pending_provider_round,
            completed_tool_calls: run.completed_tool_calls,
            pending_tool: run.pending_tool,
            pending_approval,
            events,
        })
    }
}

const RUN_SELECT: &str = "SELECT run_id, lane_key, run_key, intent_json, status,
    opened_ms, finished_ms, terminal_json, next_sequence, provider_round,
    pending_provider_round, completed_tool_calls, pending_tool_sequence,
    pending_call_id, pending_tool_name, pending_idempotency_key,
    pending_arguments_json, revision FROM agent_lane_runs";

#[derive(Clone, Debug)]
struct StoredRun {
    run_id: i64,
    lane_key: String,
    run_key: String,
    intent_json: Vec<u8>,
    status: RunStatus,
    opened_ms: i64,
    finished_ms: Option<i64>,
    terminal_json: Option<Vec<u8>>,
    next_sequence: u64,
    provider_round: u32,
    pending_provider_round: Option<u32>,
    completed_tool_calls: u32,
    pending_tool: Option<PendingTool>,
    revision: u64,
}

impl StoredRun {
    fn cursor(&self) -> RunCursor {
        RunCursor {
            run_id: self.run_id,
            revision: self.revision,
            next_sequence: self.next_sequence,
        }
    }

    fn advanced(&self) -> RunCursor {
        RunCursor {
            run_id: self.run_id,
            revision: self.revision.saturating_add(1),
            next_sequence: self.next_sequence.saturating_add(1),
        }
    }
}

fn decode_run(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredRun> {
    let status: String = row.get(4)?;
    let pending_sequence: Option<i64> = row.get(12)?;
    let pending_call_id: Option<String> = row.get(13)?;
    let pending_tool_name: Option<String> = row.get(14)?;
    let pending_idempotency_key: Option<String> = row.get(15)?;
    let pending_arguments: Option<Vec<u8>> = row.get(16)?;
    let pending_tool = match (
        pending_sequence,
        pending_call_id,
        pending_tool_name,
        pending_idempotency_key,
        pending_arguments,
    ) {
        (None, None, None, None, None) => None,
        (
            Some(sequence),
            Some(call_id),
            Some(tool_name),
            Some(idempotency_key),
            Some(arguments),
        ) => Some(PendingTool {
            intent_sequence: u64::try_from(sequence)
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(12, sequence))?,
            call_id,
            tool_name,
            idempotency_key,
            arguments: serde_json::from_slice(&arguments).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    arguments.len(),
                    rusqlite::types::Type::Blob,
                    Box::new(AgentLaneJournalError::Conflict("arguments")),
                )
            })?,
        }),
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let next_sequence: i64 = row.get(8)?;
    let provider_round: i64 = row.get(9)?;
    let pending_provider_round: Option<i64> = row.get(10)?;
    let completed_tool_calls: i64 = row.get(11)?;
    let revision: i64 = row.get(17)?;
    Ok(StoredRun {
        run_id: row.get(0)?,
        lane_key: row.get(1)?,
        run_key: row.get(2)?,
        intent_json: row.get(3)?,
        status: RunStatus::parse(&status).map_err(|_| rusqlite::Error::InvalidQuery)?,
        opened_ms: row.get(5)?,
        finished_ms: row.get(6)?,
        terminal_json: row.get(7)?,
        next_sequence: u64::try_from(next_sequence)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(8, next_sequence))?,
        provider_round: u32::try_from(provider_round)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(9, provider_round))?,
        pending_provider_round: pending_provider_round
            .map(u32::try_from)
            .transpose()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        completed_tool_calls: u32::try_from(completed_tool_calls)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(11, completed_tool_calls))?,
        pending_tool,
        revision: u64::try_from(revision)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(17, revision))?,
    })
}

fn read_run_by_key(connection: &Connection, run_key: &str) -> Journalled<Option<StoredRun>> {
    let run = connection
        .query_row(
            &format!("{RUN_SELECT} WHERE run_key = ?1"),
            [run_key],
            decode_run,
        )
        .optional()
        .map_err(AgentLaneJournalError::from)?;
    run.map(|run| {
        validate_stored_run(&run)?;
        Ok(run)
    })
    .transpose()
}

fn require_cursor(connection: &Connection, cursor: &RunCursor) -> Journalled<StoredRun> {
    if cursor.run_id <= 0 || cursor.revision == 0 || cursor.next_sequence < 2 {
        return Err(AgentLaneJournalError::InvalidField("cursor"));
    }
    let run = connection
        .query_row(
            &format!("{RUN_SELECT} WHERE run_id = ?1"),
            [cursor.run_id],
            decode_run,
        )
        .optional()?
        .ok_or(AgentLaneJournalError::NotFound)?;
    validate_stored_run(&run)?;
    if run.revision != cursor.revision || run.next_sequence != cursor.next_sequence {
        return Err(AgentLaneJournalError::Conflict("cursor"));
    }
    Ok(run)
}

fn require_running(run: &StoredRun) -> Journalled<()> {
    match run.status {
        RunStatus::Running => Ok(()),
        RunStatus::AwaitingApproval => Err(AgentLaneJournalError::PendingApproval),
        RunStatus::Completed | RunStatus::Failed => Err(AgentLaneJournalError::Terminal),
    }
}

fn read_pending_approval(
    connection: &Connection,
    run_id: i64,
) -> Journalled<Option<PendingApproval>> {
    let approval = connection
        .query_row(
            "SELECT approval_key, call_id, summary, requested_ms
             FROM agent_lane_approvals WHERE run_id = ?1 AND status = 'pending'",
            [run_id],
            |row| {
                Ok(PendingApproval {
                    approval_key: row.get(0)?,
                    call_id: row.get(1)?,
                    summary: row.get(2)?,
                    requested_ms: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(AgentLaneJournalError::from)?;
    approval
        .map(|approval| {
            validate_key(&approval.approval_key, "stored_approval_key")?;
            validate_key(&approval.call_id, "stored_approval_call_id")?;
            validate_summary(&approval.summary)?;
            validate_time(approval.requested_ms, "stored_approval_requested_ms")?;
            Ok(approval)
        })
        .transpose()
}

fn validate_stored_run(run: &StoredRun) -> Journalled<()> {
    validate_key(&run.lane_key, "stored_lane_key")?;
    validate_key(&run.run_key, "stored_run_key")?;
    validate_time(run.opened_ms, "stored_opened_ms")?;
    if run.run_id <= 0
        || run.revision == 0
        || run.next_sequence < 2
        || run
            .pending_provider_round
            .is_some_and(|round| round == 0 || round > run.provider_round)
        || run
            .finished_ms
            .is_some_and(|finished_ms| finished_ms < run.opened_ms)
        || (run.status.is_terminal() != run.finished_ms.is_some())
        || (run.status.is_terminal() != run.terminal_json.is_some())
    {
        return Err(AgentLaneJournalError::Conflict("run_row"));
    }
    decode_json(&run.intent_json, "stored_intent")?;
    if let Some(detail) = run.terminal_json.as_deref() {
        decode_json(detail, "stored_terminal_detail")?;
    }
    if let Some(tool) = run.pending_tool.as_ref() {
        if tool.intent_sequence == 0 || tool.intent_sequence >= run.next_sequence {
            return Err(AgentLaneJournalError::Conflict("pending_tool_sequence"));
        }
        validate_key(&tool.call_id, "stored_call_id")?;
        validate_tool_name(&tool.tool_name)?;
        validate_key(&tool.idempotency_key, "stored_idempotency_key")?;
        encode_json(&tool.arguments, "stored_arguments")?;
    }
    Ok(())
}

fn insert_event(
    connection: &Connection,
    run_id: i64,
    sequence: u64,
    kind: &str,
    payload: &[u8],
    recorded_ms: i64,
) -> Journalled<()> {
    connection.execute(
        "INSERT INTO agent_lane_events
         (run_id, sequence, kind, payload_json, recorded_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![run_id, to_i64(sequence)?, kind, payload, recorded_ms],
    )?;
    Ok(())
}

fn read_event(
    connection: &Connection,
    run_id: i64,
    sequence: u64,
) -> Journalled<Option<JournalEvent>> {
    let row = connection
        .query_row(
            "SELECT kind, payload_json, recorded_ms
             FROM agent_lane_events WHERE run_id = ?1 AND sequence = ?2",
            params![run_id, to_i64(sequence)?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    row.map(|(kind, payload, recorded_ms)| {
        Ok(JournalEvent {
            sequence,
            kind,
            payload: decode_json(&payload, "event_payload")?,
            recorded_ms,
        })
    })
    .transpose()
}

fn validate_provider_outcome(value: &Value) -> Journalled<()> {
    let object = value
        .as_object()
        .ok_or(AgentLaneJournalError::InvalidField("provider_outcome"))?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(AgentLaneJournalError::InvalidField("provider_outcome"))?;
    match kind {
        "final" => {
            if object.len() != 2
                || object
                    .get("answer")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
            {
                return Err(AgentLaneJournalError::InvalidField("provider_outcome"));
            }
        }
        "failure" => {
            if object.len() != 2
                || object
                    .get("failure")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
            {
                return Err(AgentLaneJournalError::InvalidField("provider_outcome"));
            }
        }
        "tool_call" => {
            if object.len() != 4 {
                return Err(AgentLaneJournalError::InvalidField("provider_outcome"));
            }
            let call_id = object
                .get("call_id")
                .and_then(Value::as_str)
                .ok_or(AgentLaneJournalError::InvalidField("provider_outcome"))?;
            let tool = object
                .get("tool")
                .and_then(Value::as_str)
                .ok_or(AgentLaneJournalError::InvalidField("provider_outcome"))?;
            let arguments = object
                .get("arguments")
                .ok_or(AgentLaneJournalError::InvalidField("provider_outcome"))?;
            validate_key(call_id, "provider_call_id")?;
            validate_tool_name(tool)?;
            if !arguments.is_object() {
                return Err(AgentLaneJournalError::InvalidField("provider_arguments"));
            }
            encode_json(arguments, "provider_arguments")?;
        }
        _ => return Err(AgentLaneJournalError::InvalidField("provider_outcome")),
    }
    Ok(())
}

fn provider_outcome_matches_tool(
    event_payload: &Value,
    expected_round: u32,
    call_id: &str,
    tool_name: &str,
    arguments: &Value,
) -> Journalled<bool> {
    let payload = event_payload
        .as_object()
        .ok_or(AgentLaneJournalError::Conflict("provider_outcome"))?;
    if payload.len() != 2
        || payload.get("round").and_then(Value::as_u64) != Some(u64::from(expected_round))
    {
        return Err(AgentLaneJournalError::Conflict("provider_outcome"));
    }
    let outcome = payload
        .get("outcome")
        .ok_or(AgentLaneJournalError::Conflict("provider_outcome"))?;
    validate_provider_outcome(outcome)
        .map_err(|_| AgentLaneJournalError::Conflict("provider_outcome"))?;
    let object = outcome
        .as_object()
        .ok_or(AgentLaneJournalError::Conflict("provider_outcome"))?;
    Ok(
        object.get("kind").and_then(Value::as_str) == Some("tool_call")
            && object.get("call_id").and_then(Value::as_str) == Some(call_id)
            && object.get("tool").and_then(Value::as_str) == Some(tool_name)
            && object.get("arguments") == Some(arguments),
    )
}

fn validate_event_invariants(run: &StoredRun, events: &[JournalEvent]) -> Journalled<()> {
    if events.first().map(|event| event.kind.as_str()) != Some("run_intent")
        || events
            .iter()
            .skip(1)
            .any(|event| event.kind == "run_intent")
    {
        return Err(AgentLaneJournalError::Conflict("run_intent_order"));
    }

    let mut pending_provider = None;
    let mut latest_round = 0_u32;
    let mut pending_tool: Option<(u64, String, String, String, Value)> = None;
    for (index, event) in events.iter().enumerate() {
        match event.kind.as_str() {
            "provider_intent" => {
                if pending_provider.is_some() {
                    return Err(AgentLaneJournalError::Conflict("provider_order"));
                }
                let round = event
                    .payload
                    .get("round")
                    .and_then(Value::as_u64)
                    .and_then(|round| u32::try_from(round).ok())
                    .ok_or(AgentLaneJournalError::Conflict("provider_round"))?;
                if round != latest_round.saturating_add(1) {
                    return Err(AgentLaneJournalError::Conflict("provider_round"));
                }
                latest_round = round;
                pending_provider = Some(round);
            }
            "provider_outcome" => {
                let round = event
                    .payload
                    .get("round")
                    .and_then(Value::as_u64)
                    .and_then(|round| u32::try_from(round).ok())
                    .ok_or(AgentLaneJournalError::Conflict("provider_round"))?;
                if pending_provider != Some(round) {
                    return Err(AgentLaneJournalError::Conflict("provider_order"));
                }
                let outcome = event
                    .payload
                    .get("outcome")
                    .ok_or(AgentLaneJournalError::Conflict("provider_outcome"))?;
                validate_provider_outcome(outcome)
                    .map_err(|_| AgentLaneJournalError::Conflict("provider_outcome"))?;
                pending_provider = None;
            }
            "tool_intent" => {
                if pending_tool.is_some() || index == 0 {
                    return Err(AgentLaneJournalError::Conflict("tool_intent_order"));
                }
                let call_id = event
                    .payload
                    .get("call_id")
                    .and_then(Value::as_str)
                    .ok_or(AgentLaneJournalError::Conflict("tool_intent"))?;
                let tool = event
                    .payload
                    .get("tool")
                    .and_then(Value::as_str)
                    .ok_or(AgentLaneJournalError::Conflict("tool_intent"))?;
                let idempotency_key = event
                    .payload
                    .get("idempotency_key")
                    .and_then(Value::as_str)
                    .ok_or(AgentLaneJournalError::Conflict("tool_intent"))?;
                let arguments = event
                    .payload
                    .get("arguments")
                    .ok_or(AgentLaneJournalError::Conflict("tool_intent"))?;
                if event.payload.as_object().map(serde_json::Map::len) != Some(4)
                    || !arguments.is_object()
                {
                    return Err(AgentLaneJournalError::Conflict("tool_intent"));
                }
                let previous = &events[index - 1];
                if previous.kind != "provider_outcome"
                    || !provider_outcome_matches_tool(
                        &previous.payload,
                        latest_round,
                        call_id,
                        tool,
                        arguments,
                    )?
                {
                    return Err(AgentLaneJournalError::Conflict("tool_intent_order"));
                }
                validate_key(call_id, "stored_call_id")?;
                validate_tool_name(tool)?;
                validate_key(idempotency_key, "stored_idempotency_key")?;
                pending_tool = Some((
                    event.sequence,
                    call_id.to_owned(),
                    tool.to_owned(),
                    idempotency_key.to_owned(),
                    arguments.clone(),
                ));
            }
            "tool_outcome" => {
                let call_id = event
                    .payload
                    .get("call_id")
                    .and_then(Value::as_str)
                    .ok_or(AgentLaneJournalError::Conflict("tool_outcome"))?;
                if pending_tool.as_ref().map(|tool| tool.1.as_str()) != Some(call_id) {
                    return Err(AgentLaneJournalError::Conflict("tool_outcome"));
                }
                pending_tool = None;
            }
            _ => {}
        }
    }
    if latest_round != run.provider_round || pending_provider != run.pending_provider_round {
        return Err(AgentLaneJournalError::Conflict("provider_coordinate"));
    }
    match (&run.pending_tool, pending_tool) {
        (None, None) => {}
        (Some(stored), Some((sequence, call_id, tool, key, arguments)))
            if stored.intent_sequence == sequence
                && stored.call_id == call_id
                && stored.tool_name == tool
                && stored.idempotency_key == key
                && stored.arguments == arguments => {}
        _ => return Err(AgentLaneJournalError::Conflict("pending_tool_coordinate")),
    }
    Ok(())
}

fn advance_run<P: rusqlite::Params>(
    connection: &Connection,
    run: &StoredRun,
    sql: &str,
    parameters: P,
) -> Journalled<()> {
    if connection.execute(sql, parameters)? != 1 {
        return Err(AgentLaneJournalError::Conflict("revision"));
    }
    if run.next_sequence == u64::MAX || run.revision == u64::MAX {
        return Err(AgentLaneJournalError::Conflict("coordinate_overflow"));
    }
    Ok(())
}

fn initialize(connection: &mut Connection) -> Journalled<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == AGENT_LANE_JOURNAL_SCHEMA_VERSION {
        return Ok(());
    }
    if version == 1 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let before: u64 =
            transaction.query_row("SELECT count(*) FROM agent_lane_events", [], |row| {
                row.get(0)
            })?;
        transaction.execute_batch(MIGRATE_V1_TO_V2)?;
        let after: u64 =
            transaction.query_row("SELECT count(*) FROM agent_lane_events", [], |row| {
                row.get(0)
            })?;
        if before != after {
            return Err(AgentLaneJournalError::Conflict("migration_event_count"));
        }
        transaction.pragma_update(None, "user_version", AGENT_LANE_JOURNAL_SCHEMA_VERSION)?;
        transaction.commit()?;
        return Ok(());
    }
    if version != 0 {
        return Err(AgentLaneJournalError::SchemaVersion {
            found: version,
            supported: AGENT_LANE_JOURNAL_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(AgentLaneJournalError::SchemaVersion {
            found: 0,
            supported: AGENT_LANE_JOURNAL_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V2)?;
    transaction.pragma_update(None, "user_version", AGENT_LANE_JOURNAL_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn encode_json(value: &Value, field: &'static str) -> Journalled<Vec<u8>> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| AgentLaneJournalError::InvalidField(field))?;
    if bytes.len() > MAX_JSON_BYTES {
        return Err(AgentLaneJournalError::InvalidField(field));
    }
    Ok(bytes)
}

fn decode_json(bytes: &[u8], field: &'static str) -> Journalled<Value> {
    if bytes.len() > MAX_JSON_BYTES {
        return Err(AgentLaneJournalError::Conflict(field));
    }
    serde_json::from_slice(bytes).map_err(|_| AgentLaneJournalError::Conflict(field))
}

fn validate_key(value: &str, field: &'static str) -> Journalled<()> {
    if value.is_empty()
        || value.len() > MAX_KEY_BYTES
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        Err(AgentLaneJournalError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_tool_name(value: &str) -> Journalled<()> {
    if value.is_empty()
        || value.len() > MAX_TOOL_NAME_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        Err(AgentLaneJournalError::InvalidField("tool_name"))
    } else {
        Ok(())
    }
}

fn validate_summary(value: &str) -> Journalled<()> {
    if value.is_empty() || value.len() > MAX_APPROVAL_SUMMARY_BYTES || value.contains('\0') {
        Err(AgentLaneJournalError::InvalidField("summary"))
    } else {
        Ok(())
    }
}

fn validate_time(value: i64, field: &'static str) -> Journalled<()> {
    if value < 0 {
        Err(AgentLaneJournalError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn to_i64(value: u64) -> Journalled<i64> {
    i64::try_from(value).map_err(|_| AgentLaneJournalError::Conflict("coordinate_overflow"))
}

fn from_i64(value: i64, field: &'static str) -> Journalled<u64> {
    u64::try_from(value).map_err(|_| AgentLaneJournalError::Conflict(field))
}

fn validate_database_path(path: &Path) -> Journalled<()> {
    if !path.is_absolute() {
        return Err(AgentLaneJournalError::InsecurePath(
            "path must be absolute".to_owned(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| AgentLaneJournalError::InsecurePath("path has no parent".to_owned()))?;
    validate_owned_private(&fs::symlink_metadata(parent)?, true, "parent")?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        validate_owned_private(&metadata, false, "database")?;
    }
    Ok(())
}

fn validate_owned_private(metadata: &fs::Metadata, directory: bool, label: &str) -> Journalled<()> {
    let expected_kind = if directory {
        metadata.file_type().is_dir()
    } else {
        metadata.file_type().is_file()
    };
    if !expected_kind || metadata.file_type().is_symlink() {
        return Err(AgentLaneJournalError::InsecurePath(format!(
            "{label} has the wrong file type"
        )));
    }
    if metadata.uid() != geteuid().as_raw() {
        return Err(AgentLaneJournalError::InsecurePath(format!(
            "{label} has a foreign owner"
        )));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(AgentLaneJournalError::InsecurePath(format!(
            "{label} permits group/other access"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    struct Fixture {
        root: TempDir,
        journal: AgentLaneJournal,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("temporary directory");
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
                .expect("private directory");
            let journal =
                AgentLaneJournal::open(root.path().join(AGENT_LANE_JOURNAL_NAME)).expect("journal");
            Self { root, journal }
        }

        fn begin(&mut self) -> RunCursor {
            self.journal
                .begin_run(RunIntent {
                    lane_key: "slack:thread-7",
                    run_key: "event-11",
                    intent: &json!({"message": "find yesterday's tickets"}),
                    opened_ms: 10,
                })
                .expect("begin")
                .cursor
        }
    }

    #[test]
    fn persists_ordered_run_and_restart_coordinates() {
        let mut fixture = Fixture::new();
        let mut cursor = fixture.begin();
        cursor = fixture
            .journal
            .record_provider_intent(ProviderIntent {
                cursor: &cursor,
                round: 1,
                request: &json!({"transcript_entries": 1}),
                recorded_ms: 11,
            })
            .expect("provider intent");
        cursor = fixture
            .journal
            .record_provider_outcome(ProviderOutcome {
                cursor: &cursor,
                round: 1,
                outcome: &json!({
                    "kind": "tool_call",
                    "call_id": "call-1",
                    "tool": "tickets.list",
                    "arguments": {"state": "closed"}
                }),
                recorded_ms: 12,
            })
            .expect("provider tool outcome");
        cursor = fixture
            .journal
            .record_tool_intent(ToolIntent {
                cursor: &cursor,
                call_id: "call-1",
                tool_name: "tickets.list",
                idempotency_key: "lane:event-11:call-1",
                arguments: &json!({"state": "closed"}),
                recorded_ms: 13,
            })
            .expect("tool intent");

        let path = fixture.journal.path().to_path_buf();
        drop(fixture.journal);
        let mut journal = AgentLaneJournal::open(&path).expect("reopen");
        let recovery = journal.recover("event-11").expect("recover").expect("run");
        assert_eq!(recovery.pending_provider_round, None);
        assert_eq!(recovery.pending_tool.as_ref().unwrap().call_id, "call-1");
        assert_eq!(recovery.cursor, cursor);
        assert_eq!(
            recovery
                .events
                .iter()
                .map(|event| event.kind.as_str())
                .collect::<Vec<_>>(),
            vec![
                "run_intent",
                "provider_intent",
                "provider_outcome",
                "tool_intent"
            ]
        );

        let mut cursor = journal
            .record_tool_outcome(ToolOutcome {
                cursor: &recovery.cursor,
                call_id: "call-1",
                outcome: &json!({"tickets": ["T-7"]}),
                recorded_ms: 14,
            })
            .expect("tool outcome");
        cursor = journal
            .record_provider_intent(ProviderIntent {
                cursor: &cursor,
                round: 2,
                request: &json!({"transcript_entries": 3}),
                recorded_ms: 15,
            })
            .expect("second provider intent");
        cursor = journal
            .record_provider_outcome(ProviderOutcome {
                cursor: &cursor,
                round: 2,
                outcome: &json!({
                    "kind": "final",
                    "answer": "T-7 was completed yesterday."
                }),
                recorded_ms: 16,
            })
            .expect("final provider outcome");
        cursor = journal
            .record_transcript(TranscriptAppend {
                cursor: &cursor,
                kind: TranscriptKind::Assistant,
                content: &json!({"text": "T-7 was completed yesterday."}),
                recorded_ms: 17,
            })
            .expect("assistant transcript");
        journal
            .finish(TerminalRecord {
                cursor: &cursor,
                status: TerminalStatus::Completed,
                detail: &json!({"answer": "T-7 was completed yesterday."}),
                finished_ms: 18,
            })
            .expect("finish");
        let recovered = journal.recover("event-11").unwrap().unwrap();
        assert_eq!(recovered.status, RunStatus::Completed);
        assert_eq!(recovered.completed_tool_calls, 1);
        assert!(recovered.pending_tool.is_none());
        assert_eq!(recovered.events.len(), 9);
    }

    #[test]
    fn pending_provider_is_explicit_after_restart() {
        let mut fixture = Fixture::new();
        let cursor = fixture.begin();
        fixture
            .journal
            .record_provider_intent(ProviderIntent {
                cursor: &cursor,
                round: 1,
                request: &json!({"digest": "request-1"}),
                recorded_ms: 11,
            })
            .unwrap();
        let recovered = fixture.journal.recover("event-11").unwrap().unwrap();
        assert_eq!(recovered.pending_provider_round, Some(1));
        assert!(matches!(
            fixture.journal.finish(TerminalRecord {
                cursor: &recovered.cursor,
                status: TerminalStatus::Failed,
                detail: &json!({"reason": "restart"}),
                finished_ms: 12,
            }),
            Err(AgentLaneJournalError::PendingProvider)
        ));
    }

    #[test]
    fn existing_v1_database_migrates_and_accepts_provider_outcomes_idempotently() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join(AGENT_LANE_JOURNAL_NAME);
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let legacy = Connection::open(&path).unwrap();
        let legacy_schema = SCHEMA_V2.replace("'provider_outcome', ", "");
        legacy.execute_batch(&legacy_schema).unwrap();
        legacy.pragma_update(None, "user_version", 1).unwrap();
        let intent = serde_json::to_vec(&json!({"message": "legacy run"})).unwrap();
        legacy
            .execute(
                "INSERT INTO agent_lane_runs
                 (lane_key, run_key, intent_json, status, opened_ms, next_sequence, revision)
                 VALUES ('legacy-lane', 'legacy-run', ?1, 'running', 10, 2, 1)",
                [&intent],
            )
            .unwrap();
        legacy
            .execute(
                "INSERT INTO agent_lane_events
                 (run_id, sequence, kind, payload_json, recorded_ms)
                 VALUES (1, 1, 'run_intent', ?1, 10)",
                [&intent],
            )
            .unwrap();
        drop(legacy);

        let mut journal = AgentLaneJournal::open(&path).expect("migrate v1");
        let version: u32 = journal
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, AGENT_LANE_JOURNAL_SCHEMA_VERSION);
        let mut cursor = journal.recover("legacy-run").unwrap().unwrap().cursor;
        cursor = journal
            .record_provider_intent(ProviderIntent {
                cursor: &cursor,
                round: 1,
                request: &json!({"transcript_entries": 1}),
                recorded_ms: 11,
            })
            .unwrap();
        journal
            .record_provider_outcome(ProviderOutcome {
                cursor: &cursor,
                round: 1,
                outcome: &json!({"kind": "final", "answer": "migrated"}),
                recorded_ms: 12,
            })
            .unwrap();
        drop(journal);

        let reopened = AgentLaneJournal::open(&path).expect("idempotent v2 reopen");
        let recovered = reopened.recover("legacy-run").unwrap().unwrap();
        assert_eq!(recovered.pending_provider_round, None);
        assert_eq!(
            recovered.events.last().map(|event| event.kind.as_str()),
            Some("provider_outcome")
        );
    }

    #[test]
    fn tool_intent_requires_immediately_preceding_matching_provider_outcome() {
        let mut fixture = Fixture::new();
        let cursor = fixture.begin();
        assert!(matches!(
            fixture.journal.record_tool_intent(ToolIntent {
                cursor: &cursor,
                call_id: "call-1",
                tool_name: "tickets.read",
                idempotency_key: "effect-1",
                arguments: &json!({"number": 7}),
                recorded_ms: 11,
            }),
            Err(AgentLaneJournalError::Conflict("tool_intent_order"))
        ));
        let mut cursor = fixture
            .journal
            .record_provider_intent(ProviderIntent {
                cursor: &cursor,
                round: 1,
                request: &json!({}),
                recorded_ms: 11,
            })
            .unwrap();
        assert!(matches!(
            fixture.journal.record_tool_intent(ToolIntent {
                cursor: &cursor,
                call_id: "call-1",
                tool_name: "tickets.read",
                idempotency_key: "effect-1",
                arguments: &json!({"number": 7}),
                recorded_ms: 12,
            }),
            Err(AgentLaneJournalError::PendingProvider)
        ));
        cursor = fixture
            .journal
            .record_provider_outcome(ProviderOutcome {
                cursor: &cursor,
                round: 1,
                outcome: &json!({
                    "kind": "tool_call",
                    "call_id": "call-1",
                    "tool": "tickets.read",
                    "arguments": {"number": 7}
                }),
                recorded_ms: 12,
            })
            .unwrap();
        assert!(matches!(
            fixture.journal.record_tool_intent(ToolIntent {
                cursor: &cursor,
                call_id: "call-1",
                tool_name: "tickets.read",
                idempotency_key: "effect-1",
                arguments: &json!({"number": 8}),
                recorded_ms: 13,
            }),
            Err(AgentLaneJournalError::Conflict("tool_intent_order"))
        ));
        cursor = fixture
            .journal
            .record_transcript(TranscriptAppend {
                cursor: &cursor,
                kind: TranscriptKind::User,
                content: &json!({"text": "unrelated steering"}),
                recorded_ms: 13,
            })
            .unwrap();
        assert!(matches!(
            fixture.journal.record_tool_intent(ToolIntent {
                cursor: &cursor,
                call_id: "call-1",
                tool_name: "tickets.read",
                idempotency_key: "effect-1",
                arguments: &json!({"number": 7}),
                recorded_ms: 14,
            }),
            Err(AgentLaneJournalError::Conflict("tool_intent_order"))
        ));
    }

    #[test]
    fn recovery_refuses_tool_intent_whose_provider_binding_was_tampered() {
        let mut fixture = Fixture::new();
        let mut cursor = fixture.begin();
        cursor = fixture
            .journal
            .record_provider_intent(ProviderIntent {
                cursor: &cursor,
                round: 1,
                request: &json!({}),
                recorded_ms: 11,
            })
            .unwrap();
        cursor = fixture
            .journal
            .record_provider_outcome(ProviderOutcome {
                cursor: &cursor,
                round: 1,
                outcome: &json!({
                    "kind": "tool_call",
                    "call_id": "call-1",
                    "tool": "tickets.read",
                    "arguments": {"number": 7}
                }),
                recorded_ms: 12,
            })
            .unwrap();
        fixture
            .journal
            .record_tool_intent(ToolIntent {
                cursor: &cursor,
                call_id: "call-1",
                tool_name: "tickets.read",
                idempotency_key: "effect-1",
                arguments: &json!({"number": 7}),
                recorded_ms: 13,
            })
            .unwrap();
        let replacement = serde_json::to_vec(&json!({
            "round": 1,
            "outcome": {"kind": "final", "answer": "tampered"}
        }))
        .unwrap();
        fixture
            .journal
            .connection
            .execute(
                "UPDATE agent_lane_events SET payload_json = ?1
                 WHERE run_id = ?2 AND kind = 'provider_outcome'",
                params![replacement, cursor.run_id],
            )
            .unwrap();
        assert!(matches!(
            fixture.journal.recover("event-11"),
            Err(AgentLaneJournalError::Conflict("tool_intent_order"))
        ));
    }

    #[test]
    fn approval_and_exact_tool_intent_survive_restart() {
        let mut fixture = Fixture::new();
        let mut cursor = fixture.begin();
        cursor = fixture
            .journal
            .record_provider_intent(ProviderIntent {
                cursor: &cursor,
                round: 1,
                request: &json!({}),
                recorded_ms: 11,
            })
            .unwrap();
        cursor = fixture
            .journal
            .record_provider_outcome(ProviderOutcome {
                cursor: &cursor,
                round: 1,
                outcome: &json!({
                    "kind": "tool_call",
                    "call_id": "call-approve",
                    "tool": "tickets.comment",
                    "arguments": {"ticket": 7, "body": "done"}
                }),
                recorded_ms: 12,
            })
            .unwrap();
        cursor = fixture
            .journal
            .record_tool_intent(ToolIntent {
                cursor: &cursor,
                call_id: "call-approve",
                tool_name: "tickets.comment",
                idempotency_key: "stable-effect-key",
                arguments: &json!({"ticket": 7, "body": "done"}),
                recorded_ms: 13,
            })
            .unwrap();
        fixture
            .journal
            .request_approval(ApprovalPending {
                cursor: &cursor,
                approval_key: "approval-7",
                call_id: "call-approve",
                summary: "Post the exact ticket comment",
                requested_ms: 14,
            })
            .unwrap();

        let recovery = fixture
            .journal
            .recover_active_lane("slack:thread-7")
            .unwrap()
            .unwrap();
        assert_eq!(recovery.status, RunStatus::AwaitingApproval);
        assert_eq!(
            recovery.pending_tool.as_ref().unwrap().idempotency_key,
            "stable-effect-key"
        );
        assert_eq!(
            recovery.pending_approval.as_ref().unwrap().approval_key,
            "approval-7"
        );

        let cursor = fixture
            .journal
            .resolve_approval(ApprovalResolution {
                cursor: &recovery.cursor,
                approval_key: "approval-7",
                decision: ApprovalDecision::Approved,
                decision_ref: "operator-decision-9",
                decided_ms: 15,
            })
            .unwrap();
        let recovery = fixture.journal.recover("event-11").unwrap().unwrap();
        assert_eq!(recovery.cursor, cursor);
        assert!(recovery.pending_approval.is_none());
        assert!(recovery.pending_tool.is_some());
        assert_eq!(recovery.status, RunStatus::Running);
    }

    #[test]
    fn stale_cursor_and_mismatched_outcome_are_refused() {
        let mut fixture = Fixture::new();
        let stale = fixture.begin();
        let cursor = fixture
            .journal
            .record_provider_intent(ProviderIntent {
                cursor: &stale,
                round: 1,
                request: &json!({}),
                recorded_ms: 11,
            })
            .unwrap();
        assert!(matches!(
            fixture.journal.record_transcript(TranscriptAppend {
                cursor: &stale,
                kind: TranscriptKind::User,
                content: &json!({"text": "late"}),
                recorded_ms: 12,
            }),
            Err(AgentLaneJournalError::Conflict("cursor"))
        ));
        let cursor = fixture
            .journal
            .record_provider_outcome(ProviderOutcome {
                cursor: &cursor,
                round: 1,
                outcome: &json!({
                    "kind": "tool_call",
                    "call_id": "expected",
                    "tool": "tickets.read",
                    "arguments": {}
                }),
                recorded_ms: 12,
            })
            .unwrap();
        let cursor = fixture
            .journal
            .record_tool_intent(ToolIntent {
                cursor: &cursor,
                call_id: "expected",
                tool_name: "tickets.read",
                idempotency_key: "read-1",
                arguments: &json!({}),
                recorded_ms: 13,
            })
            .unwrap();
        assert!(matches!(
            fixture.journal.record_tool_outcome(ToolOutcome {
                cursor: &cursor,
                call_id: "different",
                outcome: &json!({}),
                recorded_ms: 14,
            }),
            Err(AgentLaneJournalError::Conflict("call_id"))
        ));
    }

    #[test]
    fn run_key_is_idempotent_and_lane_has_one_active_run() {
        let mut fixture = Fixture::new();
        let first = fixture.begin();
        let duplicate = fixture
            .journal
            .begin_run(RunIntent {
                lane_key: "slack:thread-7",
                run_key: "event-11",
                intent: &json!({"message": "find yesterday's tickets"}),
                opened_ms: 10,
            })
            .unwrap();
        assert!(duplicate.duplicate);
        assert_eq!(duplicate.cursor, first);
        assert!(matches!(
            fixture.journal.begin_run(RunIntent {
                lane_key: "slack:thread-7",
                run_key: "event-12",
                intent: &json!({"message": "next"}),
                opened_ms: 11,
            }),
            Err(AgentLaneJournalError::Conflict("lane_active"))
        ));
        assert!(matches!(
            fixture.journal.begin_run(RunIntent {
                lane_key: "other",
                run_key: "event-11",
                intent: &json!({}),
                opened_ms: 10,
            }),
            Err(AgentLaneJournalError::Conflict("run_key"))
        ));
    }

    #[test]
    fn journal_file_is_private_and_insecure_parent_is_refused() {
        let fixture = Fixture::new();
        let metadata = fs::metadata(fixture.journal.path()).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.uid(), geteuid().as_raw());

        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            AgentLaneJournal::open(root.path().join("journal.sqlite3")),
            Err(AgentLaneJournalError::InsecurePath(_))
        ));
        assert!(fixture.root.path().exists());
    }
}
