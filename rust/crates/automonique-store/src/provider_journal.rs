// SPDX-License-Identifier: Elastic-2.0

//! Durable journal of supervisor-recorded provider bindings.
//!
//! An external provider CLI (codex, claude, jcode) is spawned as a process,
//! negotiates a session, and executes turns made of correlated requests. When a
//! supervisor restarts it must know which process attempt owned which provider
//! session, which turn was open, which requests were issued and never answered,
//! what event sequence was last durably consumed, which capability and schema
//! versions were negotiated, and which approvals were granted.
//!
//! This module stores exactly those bindings and nothing else. There is no
//! provider IO here: callers supply every identifier, digest and timestamp.
//!
//! # What this journal does not establish
//!
//! - It proves what the supervisor *recorded*, not what the provider actually
//!   did. A journalled turn may have been abandoned before the provider saw it.
//! - Digests bind content without storing it. The journal never computes a
//!   digest and cannot reproduce, verify or re-derive the bytes behind one; a
//!   digest is only a stable name a caller chose to record.
//! - A terminal process state is the supervisor's observation, not proof the
//!   operating system process is gone.
//! - A cursor records what was durably consumed, not what the provider emitted;
//!   events beyond the cursor may or may not exist.
//! - A recorded approval proves a decision was journalled, not that the
//!   provider honoured it.
//!
//! # Storage discipline
//!
//! The journal owns its own SQLite database with its own `user_version`, opened
//! under the same privacy, WAL and `synchronous = FULL` rules as [`crate::Store`].
//! Every multi-row mutation runs in one immediate transaction, every in-place
//! transition is revision-checked, and every read re-validates the row it loaded
//! rather than trusting the database.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use automonique_protocol::provenance::Provenance;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::{
    BUSY_TIMEOUT, StoreError, StoredProvenance, stored_provenance, validate_database_path,
};

/// The only provider journal schema this build can read and write.
pub const PROVIDER_JOURNAL_SCHEMA_VERSION: u32 = 3;

/// Exact character count of a lowercase hex SHA-256 digest.
pub const DIGEST_CHARS: usize = 64;

const MAX_KEY_BYTES: usize = 256;
const MAX_KIND_BYTES: usize = 64;
const MAX_VERSION_BYTES: usize = 128;
const MAX_REASON_BYTES: usize = 512;
const MAX_SETTLEMENTS: usize = 1_024;

/// Schema v1.
///
/// Digest widths and closed state vocabularies are database constraints so a
/// second writer cannot introduce them. Bounded key lengths, digest alphabet
/// and turn-ordinal contiguity are deliberately *not* database constraints:
/// they are enforced on write and re-checked on every read, so a row written
/// around this API is refused rather than believed.
const SCHEMA_V1: &str = r#"
CREATE TABLE provider_processes (
    process_id INTEGER PRIMARY KEY,
    spawn_key TEXT NOT NULL UNIQUE,
    attempt_id TEXT NOT NULL,
    provider_kind TEXT NOT NULL,
    executable_digest TEXT NOT NULL CHECK (length(executable_digest) = 64),
    state TEXT NOT NULL CHECK (state IN ('live', 'exited', 'failed', 'lost')),
    spawned_ms INTEGER NOT NULL CHECK (spawned_ms >= 0),
    exited_ms INTEGER CHECK (exited_ms IS NULL OR exited_ms >= 0),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    CHECK (
        (state = 'live' AND exited_ms IS NULL)
        OR (state <> 'live' AND exited_ms IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX provider_processes_one_live_per_attempt
    ON provider_processes(attempt_id) WHERE state = 'live';
CREATE INDEX provider_processes_by_attempt
    ON provider_processes(attempt_id, process_id);

CREATE TABLE provider_sessions (
    session_id INTEGER PRIMARY KEY,
    process_id INTEGER NOT NULL REFERENCES provider_processes(process_id),
    provider_session_key TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('open', 'closed', 'lost')),
    opened_ms INTEGER NOT NULL CHECK (opened_ms >= 0),
    closed_ms INTEGER CHECK (closed_ms IS NULL OR closed_ms >= 0),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    UNIQUE (process_id, provider_session_key),
    CHECK (
        (state = 'open' AND closed_ms IS NULL)
        OR (state <> 'open' AND closed_ms IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX provider_sessions_one_open_per_process
    ON provider_sessions(process_id) WHERE state = 'open';

CREATE TABLE provider_turns (
    turn_id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES provider_sessions(session_id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 1),
    turn_key TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('open', 'completed', 'aborted')),
    opened_ms INTEGER NOT NULL CHECK (opened_ms >= 0),
    closed_ms INTEGER CHECK (closed_ms IS NULL OR closed_ms >= 0),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    UNIQUE (session_id, ordinal),
    UNIQUE (session_id, turn_key),
    CHECK (
        (state = 'open' AND closed_ms IS NULL)
        OR (state <> 'open' AND closed_ms IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX provider_turns_one_open_per_session
    ON provider_turns(session_id) WHERE state = 'open';

CREATE TABLE provider_requests (
    request_id INTEGER PRIMARY KEY,
    turn_id INTEGER NOT NULL REFERENCES provider_turns(turn_id),
    request_key TEXT NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('to_provider', 'from_provider')),
    payload_digest TEXT NOT NULL CHECK (length(payload_digest) = 64),
    outcome TEXT NOT NULL CHECK (outcome IN ('pending', 'answered', 'failed')),
    response_digest TEXT CHECK (response_digest IS NULL OR length(response_digest) = 64),
    failure_reason TEXT,
    created_ms INTEGER NOT NULL CHECK (created_ms >= 0),
    settled_ms INTEGER CHECK (settled_ms IS NULL OR settled_ms >= 0),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    UNIQUE (turn_id, request_key),
    CHECK (
        (outcome = 'pending' AND settled_ms IS NULL
         AND response_digest IS NULL AND failure_reason IS NULL)
        OR
        (outcome = 'answered' AND settled_ms IS NOT NULL
         AND response_digest IS NOT NULL AND failure_reason IS NULL)
        OR
        (outcome = 'failed' AND settled_ms IS NOT NULL
         AND response_digest IS NULL AND failure_reason IS NOT NULL)
    )
) STRICT;

CREATE INDEX provider_requests_pending
    ON provider_requests(turn_id, request_id) WHERE outcome = 'pending';

CREATE TABLE provider_cursors (
    session_id INTEGER NOT NULL REFERENCES provider_sessions(session_id),
    stream TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    updated_ms INTEGER NOT NULL CHECK (updated_ms >= 0),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    PRIMARY KEY (session_id, stream)
) STRICT;

CREATE TABLE provider_bindings (
    session_id INTEGER NOT NULL REFERENCES provider_sessions(session_id),
    kind TEXT NOT NULL CHECK (kind IN ('capability', 'schema')),
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    value_digest TEXT NOT NULL CHECK (length(value_digest) = 64),
    bound_ms INTEGER NOT NULL CHECK (bound_ms >= 0),
    PRIMARY KEY (session_id, kind, name)
) STRICT;

CREATE TABLE provider_approvals (
    session_id INTEGER NOT NULL REFERENCES provider_sessions(session_id),
    approval_key TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('granted', 'denied')),
    deciding_actor TEXT NOT NULL,
    decided_ms INTEGER NOT NULL CHECK (decided_ms >= 0),
    PRIMARY KEY (session_id, approval_key)
) STRICT;
"#;

/// Schema v2 adds one bounded, one-to-one usage record per provider turn.
const SCHEMA_V2: &str = r#"
CREATE TABLE provider_turn_usage (
    turn_id INTEGER PRIMARY KEY REFERENCES provider_turns(turn_id),
    gen_ai_system TEXT NOT NULL,
    request_model TEXT,
    response_model TEXT,
    input_tokens INTEGER NOT NULL CHECK (input_tokens >= 0),
    cached_input_tokens INTEGER NOT NULL CHECK (cached_input_tokens >= 0),
    output_tokens INTEGER NOT NULL CHECK (output_tokens >= 0),
    finish_reason TEXT NOT NULL CHECK (finish_reason IN ('stop', 'error'))
) STRICT;
"#;

const SCHEMA_V3: &str = r#"
ALTER TABLE provider_turns ADD COLUMN trace_id TEXT;
ALTER TABLE provider_turns ADD COLUMN correlation_id TEXT;
ALTER TABLE provider_turns ADD COLUMN causation_id TEXT;
CREATE INDEX provider_turns_by_trace ON provider_turns(trace_id, turn_id);
"#;

/// A provider journal error with stable refusal categories.
#[derive(Debug)]
pub enum ProviderJournalError {
    /// The journal path or its containing directory is not private and owned.
    InsecurePath(String),
    /// The journal schema is absent from a non-empty database or unsupported.
    SchemaVersion { found: u32, supported: u32 },
    /// A caller-provided field is empty, over-long, malformed, or out of range.
    InvalidField(&'static str),
    /// A stable key was reused for different content.
    IdempotencyConflict(&'static str),
    /// The referenced durable row does not exist.
    NotFound(&'static str),
    /// The referenced parent row exists but is no longer open.
    NotOpen(&'static str),
    /// The attempt already owns a live provider process.
    ProcessLive { process_id: i64 },
    /// The process already owns an open provider session.
    SessionOpen { session_id: i64 },
    /// The session already owns an open turn.
    TurnOpen { turn_id: i64 },
    /// Turn ordinals are contiguous from one; the supplied ordinal is not next.
    TurnOrdinal { expected: u64, supplied: u64 },
    /// A durably consumed cursor may never move backward.
    CursorRegression { durable: u64, supplied: u64 },
    /// A write-once binding was rebound to a different value.
    BindingConflict(&'static str),
    /// A settled row was re-settled with different content.
    AlreadySettled,
    /// The caller's expected revision does not match the durable revision.
    RevisionMismatch { expected: u64, durable: u64 },
    /// A stored row violates an invariant this API can only have written once.
    Corrupt(&'static str),
    /// Filesystem failure while establishing the private journal.
    Io(std::io::Error),
    /// SQLite rejected an operation.
    Sqlite(rusqlite::Error),
}

impl ProviderJournalError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::IdempotencyConflict(_) => "idempotency_conflict",
            Self::NotFound(_) => "not_found",
            Self::NotOpen(_) => "not_open",
            Self::ProcessLive { .. } => "process_live",
            Self::SessionOpen { .. } => "session_open",
            Self::TurnOpen { .. } => "turn_open",
            Self::TurnOrdinal { .. } => "turn_ordinal",
            Self::CursorRegression { .. } => "cursor_regression",
            Self::BindingConflict(_) => "binding_conflict",
            Self::AlreadySettled => "already_settled",
            Self::RevisionMismatch { .. } => "revision_mismatch",
            Self::Corrupt(_) => "corrupt",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}

impl fmt::Display for ProviderJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => {
                write!(formatter, "journal path is not private: {reason}")
            }
            Self::SchemaVersion { found, supported } => write!(
                formatter,
                "provider journal schema {found} is unsupported; expected {supported}"
            ),
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::IdempotencyConflict(key) => write!(formatter, "stable key was reused: {key}"),
            Self::NotFound(row) => write!(formatter, "durable row not found: {row}"),
            Self::NotOpen(row) => write!(formatter, "durable row is not open: {row}"),
            Self::ProcessLive { process_id } => write!(
                formatter,
                "attempt already owns live provider process {process_id}"
            ),
            Self::SessionOpen { session_id } => write!(
                formatter,
                "process already owns open provider session {session_id}"
            ),
            Self::TurnOpen { turn_id } => {
                write!(formatter, "session already owns open turn {turn_id}")
            }
            Self::TurnOrdinal { expected, supplied } => write!(
                formatter,
                "turn ordinal {supplied} is not contiguous; expected {expected}"
            ),
            Self::CursorRegression { durable, supplied } => write!(
                formatter,
                "cursor {supplied} is behind durable sequence {durable}"
            ),
            Self::BindingConflict(binding) => {
                write!(formatter, "write-once binding was rebound: {binding}")
            }
            Self::AlreadySettled => {
                formatter.write_str("row is already settled with different content")
            }
            Self::RevisionMismatch { expected, durable } => write!(
                formatter,
                "expected revision {expected} but durable revision is {durable}"
            ),
            Self::Corrupt(invariant) => {
                write!(formatter, "stored row violates invariant: {invariant}")
            }
            Self::Io(error) => write!(formatter, "journal filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite error: {error}"),
        }
    }
}

impl Error for ProviderJournalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ProviderJournalError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for ProviderJournalError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// Result of one journal operation.
pub type Journalled<T> = Result<T, ProviderJournalError>;

/// Observed lifecycle state of one provider process attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessState {
    /// The supervisor has not recorded a terminal observation.
    Live,
    /// The process was observed to exit.
    Exited,
    /// The process was observed to fail.
    Failed,
    /// The supervisor lost track of the process without a terminal observation.
    Lost,
}

/// Terminal observation recorded against a live process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessTermination {
    /// Ordinary exit. Refused while the process still owns an open session.
    Exited,
    /// Observed failure. Cascades any open session to `lost`.
    Failed,
    /// Supervision was lost. Cascades any open session to `lost`.
    Lost,
}

/// Durable state of one provider session binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    Open,
    Closed,
    Lost,
}

/// Terminal observation recorded against an open session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionClosure {
    /// Orderly close. Refused while the session still owns an open turn.
    Closed,
    /// The session was lost. Cascades any open turn to `aborted`.
    Lost,
}

/// Durable state of one turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnState {
    Open,
    Completed,
    Aborted,
}

/// Terminal observation recorded against an open turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnOutcome {
    Completed,
    Aborted,
}

/// Closed `gen_ai.response.finish_reasons` vocabulary recorded for a turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinishReason {
    Stop,
    Error,
}

impl FinishReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Error => "error",
        }
    }

    fn parse(value: &str) -> Journalled<Self> {
        match value {
            "stop" => Ok(Self::Stop),
            "error" => Ok(Self::Error),
            _ => Err(ProviderJournalError::Corrupt("finish_reason")),
        }
    }
}

/// Which side issued a correlated request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestDirection {
    ToProvider,
    FromProvider,
}

/// Durable settlement state of one request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestState {
    Pending,
    Answered,
    Failed,
}

/// Which negotiated namespace a write-once binding belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingKind {
    Capability,
    Schema,
}

/// Closed decision recorded for one approval key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    Granted,
    Denied,
}

impl ProcessState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Exited => "exited",
            Self::Failed => "failed",
            Self::Lost => "lost",
        }
    }

    fn parse(value: &str) -> Journalled<Self> {
        match value {
            "live" => Ok(Self::Live),
            "exited" => Ok(Self::Exited),
            "failed" => Ok(Self::Failed),
            "lost" => Ok(Self::Lost),
            _ => Err(ProviderJournalError::Corrupt("process_state")),
        }
    }
}

impl ProcessTermination {
    const fn state(self) -> ProcessState {
        match self {
            Self::Exited => ProcessState::Exited,
            Self::Failed => ProcessState::Failed,
            Self::Lost => ProcessState::Lost,
        }
    }
}

impl SessionState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Lost => "lost",
        }
    }

    fn parse(value: &str) -> Journalled<Self> {
        match value {
            "open" => Ok(Self::Open),
            "closed" => Ok(Self::Closed),
            "lost" => Ok(Self::Lost),
            _ => Err(ProviderJournalError::Corrupt("session_state")),
        }
    }
}

impl SessionClosure {
    const fn state(self) -> SessionState {
        match self {
            Self::Closed => SessionState::Closed,
            Self::Lost => SessionState::Lost,
        }
    }
}

impl TurnState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Completed => "completed",
            Self::Aborted => "aborted",
        }
    }

    fn parse(value: &str) -> Journalled<Self> {
        match value {
            "open" => Ok(Self::Open),
            "completed" => Ok(Self::Completed),
            "aborted" => Ok(Self::Aborted),
            _ => Err(ProviderJournalError::Corrupt("turn_state")),
        }
    }
}

impl TurnOutcome {
    const fn state(self) -> TurnState {
        match self {
            Self::Completed => TurnState::Completed,
            Self::Aborted => TurnState::Aborted,
        }
    }
}

impl RequestDirection {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ToProvider => "to_provider",
            Self::FromProvider => "from_provider",
        }
    }

    fn parse(value: &str) -> Journalled<Self> {
        match value {
            "to_provider" => Ok(Self::ToProvider),
            "from_provider" => Ok(Self::FromProvider),
            _ => Err(ProviderJournalError::Corrupt("request_direction")),
        }
    }
}

impl RequestState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Answered => "answered",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Journalled<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "answered" => Ok(Self::Answered),
            "failed" => Ok(Self::Failed),
            _ => Err(ProviderJournalError::Corrupt("request_outcome")),
        }
    }
}

impl BindingKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Capability => "capability",
            Self::Schema => "schema",
        }
    }

    const fn conflict(self) -> &'static str {
        match self {
            Self::Capability => "capability_binding",
            Self::Schema => "schema_binding",
        }
    }

    fn parse(value: &str) -> Journalled<Self> {
        match value {
            "capability" => Ok(Self::Capability),
            "schema" => Ok(Self::Schema),
            _ => Err(ProviderJournalError::Corrupt("binding_kind")),
        }
    }
}

impl ApprovalDecision {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Denied => "denied",
        }
    }

    fn parse(value: &str) -> Journalled<Self> {
        match value {
            "granted" => Ok(Self::Granted),
            "denied" => Ok(Self::Denied),
            _ => Err(ProviderJournalError::Corrupt("approval_decision")),
        }
    }
}

/// One recorded provider process spawn.
pub struct ProcessSpawn<'a> {
    /// Stable retry key for this spawn attempt.
    pub spawn_key: &'a str,
    /// Opaque attempt/run identity this process was spawned for.
    pub attempt_id: &'a str,
    /// Bounded provider kind, for example `codex` or `claude`.
    pub provider_kind: &'a str,
    /// Lowercase hex SHA-256 of the executable the supervisor launched.
    pub executable_digest: &'a str,
    pub spawned_ms: i64,
}

/// A terminal observation for one live process.
pub struct ProcessExit {
    pub process_id: i64,
    pub expected_revision: u64,
    pub now_ms: i64,
    pub termination: ProcessTermination,
}

/// Durable identity of one journalled process transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessReceipt {
    pub process_id: i64,
    pub revision: u64,
    pub duplicate: bool,
}

/// One provider session bound to a live process.
pub struct SessionOpening<'a> {
    pub process_id: i64,
    /// Opaque provider-supplied session identifier.
    pub provider_session_key: &'a str,
    pub opened_ms: i64,
}

/// A terminal observation for one open session.
pub struct SessionClosing {
    pub session_id: i64,
    pub expected_revision: u64,
    pub now_ms: i64,
    pub closure: SessionClosure,
}

/// Durable identity of one journalled session transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionReceipt {
    pub session_id: i64,
    pub revision: u64,
    pub duplicate: bool,
}

/// One turn opened against an open session.
pub struct TurnOpening<'a> {
    pub session_id: i64,
    /// Contiguous from one within the session; a gap is refused.
    pub ordinal: u64,
    /// Stable retry key for this turn.
    pub turn_key: &'a str,
    pub opened_ms: i64,
    /// Explicit ancestry of the work that caused this provider turn.
    pub provenance: Option<&'a Provenance>,
}

/// Atomic close of one open turn with its settlements and cursor.
#[derive(Clone, Copy)]
pub struct TurnCompletion<'a> {
    pub turn_id: i64,
    pub expected_revision: u64,
    pub now_ms: i64,
    pub outcome: TurnOutcome,
    /// Applied before the turn closes; any refusal discards the whole commit.
    pub settlements: &'a [RequestSettlement<'a>],
    /// Applied after the settlements and before the turn closes.
    pub cursor: Option<CursorAdvance<'a>>,
    /// OTel GenAI usage committed in the same transaction as the terminal.
    pub usage: Option<TurnUsage<'a>>,
}

/// Provider-reported OpenTelemetry GenAI attributes for one turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TurnUsage<'a> {
    pub gen_ai_system: &'a str,
    pub request_model: Option<&'a str>,
    pub response_model: Option<&'a str>,
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub output_tokens: u64,
    pub finish_reason: FinishReason,
}

/// Durable identity of one journalled turn transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TurnReceipt {
    pub turn_id: i64,
    pub ordinal: u64,
    pub revision: u64,
    pub duplicate: bool,
}

/// One correlated request issued within an open turn.
pub struct RequestRecord<'a> {
    pub turn_id: i64,
    /// Unique within the turn; reuse with different content is refused.
    pub request_key: &'a str,
    pub direction: RequestDirection,
    /// Lowercase hex SHA-256 binding the payload without storing it.
    pub payload_digest: &'a str,
    pub created_ms: i64,
}

/// Closed settlement content for one pending request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettledOutcome<'a> {
    /// The response was observed; the digest binds it without storing it.
    Answered { response_digest: &'a str },
    /// The request will never be answered, for the recorded bounded reason.
    Failed { reason: &'a str },
}

/// One revision-checked request settlement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestSettlement<'a> {
    pub request_key: &'a str,
    pub expected_revision: u64,
    pub outcome: SettledOutcome<'a>,
}

/// One settlement applied outside a turn commit.
pub struct RequestOutcomeCommit<'a> {
    pub turn_id: i64,
    pub now_ms: i64,
    pub settlement: RequestSettlement<'a>,
}

/// Durable identity of one journalled request transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestReceipt {
    pub request_id: i64,
    pub revision: u64,
    pub duplicate: bool,
}

/// A monotonic advance of one durably consumed stream cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CursorAdvance<'a> {
    pub session_id: i64,
    /// Bounded stream name, for example `events` or `notifications`.
    pub stream: &'a str,
    pub sequence: u64,
    pub now_ms: i64,
}

/// Durable identity of one journalled cursor advance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CursorReceipt {
    pub sequence: u64,
    pub revision: u64,
    pub duplicate: bool,
}

/// One write-once capability or schema binding negotiated by a session.
pub struct BindingRecord<'a> {
    pub session_id: i64,
    pub name: &'a str,
    pub version: &'a str,
    /// Lowercase hex SHA-256 of whatever the version denotes.
    pub value_digest: &'a str,
    pub bound_ms: i64,
}

/// One write-once approval decision recorded against a session.
pub struct ApprovalRecord<'a> {
    pub session_id: i64,
    pub approval_key: &'a str,
    pub decision: ApprovalDecision,
    pub deciding_actor: &'a str,
    pub decided_ms: i64,
}

/// Whether a write-once record was newly written or exactly replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteOnceReceipt {
    pub duplicate: bool,
}

/// Validated `provider_processes` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessRow {
    pub process_id: i64,
    pub spawn_key: String,
    pub attempt_id: String,
    pub provider_kind: String,
    pub executable_digest: String,
    pub state: ProcessState,
    pub spawned_ms: i64,
    pub exited_ms: Option<i64>,
    pub revision: u64,
}

/// Validated `provider_sessions` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRow {
    pub session_id: i64,
    pub process_id: i64,
    pub provider_session_key: String,
    pub state: SessionState,
    pub opened_ms: i64,
    pub closed_ms: Option<i64>,
    pub revision: u64,
}

/// Validated `provider_turns` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnRow {
    pub turn_id: i64,
    pub session_id: i64,
    pub ordinal: u64,
    pub turn_key: String,
    pub state: TurnState,
    pub opened_ms: i64,
    pub closed_ms: Option<i64>,
    pub revision: u64,
    pub provenance: Option<StoredProvenance>,
}

/// Validated durable usage attached to one turn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnUsageRow {
    pub turn_id: i64,
    pub gen_ai_system: String,
    pub request_model: Option<String>,
    pub response_model: Option<String>,
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub output_tokens: u64,
    pub finish_reason: FinishReason,
}

/// Aggregate used by the local metrics exporter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UsageTotals {
    pub requests: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// Validated `provider_requests` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestRow {
    pub request_id: i64,
    pub turn_id: i64,
    pub request_key: String,
    pub direction: RequestDirection,
    pub payload_digest: String,
    pub outcome: RequestState,
    pub response_digest: Option<String>,
    pub failure_reason: Option<String>,
    pub created_ms: i64,
    pub settled_ms: Option<i64>,
    pub revision: u64,
}

/// Validated `provider_cursors` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CursorRow {
    pub session_id: i64,
    pub stream: String,
    pub sequence: u64,
    pub updated_ms: i64,
    pub revision: u64,
}

/// Validated `provider_bindings` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingRow {
    pub session_id: i64,
    pub kind: BindingKind,
    pub name: String,
    pub version: String,
    pub value_digest: String,
    pub bound_ms: i64,
}

/// Validated `provider_approvals` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRow {
    pub session_id: i64,
    pub approval_key: String,
    pub decision: ApprovalDecision,
    pub deciding_actor: String,
    pub decided_ms: i64,
}

/// One point-in-time view of everything an attempt recorded.
///
/// `process`, `session` and `turn` carry the live/open row when one exists and
/// otherwise the most recent terminal row, so a restarting supervisor sees the
/// ambiguity it must reconcile instead of an empty answer. Each row states its
/// own state; nothing here is silently downgraded to "absent".
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptRecovery {
    pub attempt_id: String,
    pub process: Option<ProcessRow>,
    pub session: Option<SessionRow>,
    pub turn: Option<TurnRow>,
    /// Requests of `turn` still lacking a durable outcome, oldest first.
    pub pending_requests: Vec<RequestRow>,
    /// Durably consumed cursors of `session`, ordered by stream name.
    pub cursors: Vec<CursorRow>,
    /// Capability bindings of `session`, ordered by name.
    pub capabilities: Vec<BindingRow>,
    /// Schema bindings of `session`, ordered by name.
    pub schemas: Vec<BindingRow>,
    /// Approval decisions of `session`, ordered by key.
    pub approvals: Vec<ApprovalRow>,
}

/// Durable provider session journal. A supervisor owns it from one actor.
#[derive(Debug)]
pub struct ProviderJournal {
    connection: Connection,
    path: PathBuf,
}

impl ProviderJournal {
    /// Open or initialize a journal inside an existing private directory.
    ///
    /// The parent must be owned by the effective user and deny all group/other
    /// access. Existing journal paths must be regular, owned, non-symlinks.
    pub fn open(path: impl AsRef<Path>) -> Journalled<Self> {
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

        let open_flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = Connection::open_with_flags(path, open_flags)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let journal: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(ProviderJournalError::Sqlite(rusqlite::Error::InvalidQuery));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        initialize_or_validate_schema(&mut connection)?;

        Ok(Self {
            connection,
            path: path.to_path_buf(),
        })
    }

    /// Exact path opened by this journal.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record one provider process spawn for an attempt.
    ///
    /// An attempt owns at most one live process. Replaying the same spawn key
    /// with identical content returns the existing process.
    pub fn record_process(&mut self, spawn: ProcessSpawn<'_>) -> Journalled<ProcessReceipt> {
        validate_key(spawn.spawn_key, "spawn_key")?;
        validate_key(spawn.attempt_id, "attempt_id")?;
        validate_bounded(spawn.provider_kind, MAX_KIND_BYTES, "provider_kind")?;
        validate_digest(spawn.executable_digest, "executable_digest")?;
        validate_time(spawn.spawned_ms, "spawned_ms")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_process_by_spawn_key(&transaction, spawn.spawn_key)? {
            if existing.attempt_id != spawn.attempt_id
                || existing.provider_kind != spawn.provider_kind
                || existing.executable_digest != spawn.executable_digest
                || existing.spawned_ms != spawn.spawned_ms
            {
                return Err(ProviderJournalError::IdempotencyConflict("spawn_key"));
            }
            transaction.commit()?;
            return Ok(ProcessReceipt {
                process_id: existing.process_id,
                revision: existing.revision,
                duplicate: true,
            });
        }
        if let Some(live) = read_live_process(&transaction, spawn.attempt_id)? {
            return Err(ProviderJournalError::ProcessLive {
                process_id: live.process_id,
            });
        }
        transaction.execute(
            "INSERT INTO provider_processes
             (spawn_key, attempt_id, provider_kind, executable_digest, state,
              spawned_ms, exited_ms, revision)
             VALUES (?1, ?2, ?3, ?4, 'live', ?5, NULL, 1)",
            params![
                spawn.spawn_key,
                spawn.attempt_id,
                spawn.provider_kind,
                spawn.executable_digest,
                spawn.spawned_ms
            ],
        )?;
        let process_id = transaction.last_insert_rowid();
        transaction.commit()?;
        Ok(ProcessReceipt {
            process_id,
            revision: 1,
            duplicate: false,
        })
    }

    /// Record a terminal observation for one live process.
    ///
    /// `Exited` is refused while the process still owns an open session, since
    /// an orderly exit and a live session cannot both be true. `Failed` and
    /// `Lost` cascade the open session to `lost` and its open turn to
    /// `aborted` in the same transaction.
    pub fn finish_process(&mut self, exit: ProcessExit) -> Journalled<ProcessReceipt> {
        validate_time(exit.now_ms, "now_ms")?;
        validate_row_id(exit.process_id, "process_id")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let process = read_process(&transaction, exit.process_id)?
            .ok_or(ProviderJournalError::NotFound("provider_process"))?;
        let terminal = exit.termination.state();
        if process.state != ProcessState::Live {
            if process.state == terminal {
                transaction.commit()?;
                return Ok(ProcessReceipt {
                    process_id: process.process_id,
                    revision: process.revision,
                    duplicate: true,
                });
            }
            return Err(ProviderJournalError::AlreadySettled);
        }
        require_revision(exit.expected_revision, process.revision)?;
        let next_revision = next_revision(process.revision)?;

        if let Some(session) = read_open_session(&transaction, process.process_id)? {
            if exit.termination == ProcessTermination::Exited {
                return Err(ProviderJournalError::SessionOpen {
                    session_id: session.session_id,
                });
            }
            close_session_rows(
                &transaction,
                &session,
                SessionClosure::Lost,
                exit.now_ms,
                TurnOutcome::Aborted,
            )?;
        }
        let changed = transaction.execute(
            "UPDATE provider_processes SET state = ?2, exited_ms = ?3, revision = ?4
             WHERE process_id = ?1 AND state = 'live' AND revision = ?5",
            params![
                process.process_id,
                terminal.as_str(),
                exit.now_ms,
                to_db_u64(next_revision, "revision")?,
                to_db_u64(process.revision, "revision")?
            ],
        )?;
        require_single_row(changed, "provider_process")?;
        transaction.commit()?;
        Ok(ProcessReceipt {
            process_id: process.process_id,
            revision: next_revision,
            duplicate: false,
        })
    }

    /// Bind one provider session to a live process.
    ///
    /// A process may record several sequential sessions but at most one open.
    pub fn open_session(&mut self, opening: SessionOpening<'_>) -> Journalled<SessionReceipt> {
        validate_key(opening.provider_session_key, "provider_session_key")?;
        validate_time(opening.opened_ms, "opened_ms")?;
        validate_row_id(opening.process_id, "process_id")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let process = read_process(&transaction, opening.process_id)?
            .ok_or(ProviderJournalError::NotFound("provider_process"))?;
        if process.state != ProcessState::Live {
            return Err(ProviderJournalError::NotOpen("provider_process"));
        }
        if let Some(existing) = read_session_by_key(
            &transaction,
            opening.process_id,
            opening.provider_session_key,
        )? {
            if existing.state == SessionState::Open && existing.opened_ms == opening.opened_ms {
                transaction.commit()?;
                return Ok(SessionReceipt {
                    session_id: existing.session_id,
                    revision: existing.revision,
                    duplicate: true,
                });
            }
            return Err(ProviderJournalError::IdempotencyConflict(
                "provider_session_key",
            ));
        }
        if let Some(open) = read_open_session(&transaction, opening.process_id)? {
            return Err(ProviderJournalError::SessionOpen {
                session_id: open.session_id,
            });
        }
        transaction.execute(
            "INSERT INTO provider_sessions
             (process_id, provider_session_key, state, opened_ms, closed_ms, revision)
             VALUES (?1, ?2, 'open', ?3, NULL, 1)",
            params![
                opening.process_id,
                opening.provider_session_key,
                opening.opened_ms
            ],
        )?;
        let session_id = transaction.last_insert_rowid();
        transaction.commit()?;
        Ok(SessionReceipt {
            session_id,
            revision: 1,
            duplicate: false,
        })
    }

    /// Record a terminal observation for one open session.
    ///
    /// `Closed` is refused while the session still owns an open turn; `Lost`
    /// aborts that turn in the same transaction.
    pub fn close_session(&mut self, closing: SessionClosing) -> Journalled<SessionReceipt> {
        validate_time(closing.now_ms, "now_ms")?;
        validate_row_id(closing.session_id, "session_id")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session = read_session(&transaction, closing.session_id)?
            .ok_or(ProviderJournalError::NotFound("provider_session"))?;
        let terminal = closing.closure.state();
        if session.state != SessionState::Open {
            if session.state == terminal {
                transaction.commit()?;
                return Ok(SessionReceipt {
                    session_id: session.session_id,
                    revision: session.revision,
                    duplicate: true,
                });
            }
            return Err(ProviderJournalError::AlreadySettled);
        }
        require_revision(closing.expected_revision, session.revision)?;
        if closing.closure == SessionClosure::Closed
            && let Some(turn) = read_open_turn(&transaction, session.session_id)?
        {
            return Err(ProviderJournalError::TurnOpen {
                turn_id: turn.turn_id,
            });
        }
        let revision = close_session_rows(
            &transaction,
            &session,
            closing.closure,
            closing.now_ms,
            TurnOutcome::Aborted,
        )?;
        transaction.commit()?;
        Ok(SessionReceipt {
            session_id: session.session_id,
            revision,
            duplicate: false,
        })
    }

    /// Open one turn against an open session.
    ///
    /// Ordinals are contiguous from one within the session and a session owns
    /// at most one open turn.
    pub fn open_turn(&mut self, opening: TurnOpening<'_>) -> Journalled<TurnReceipt> {
        validate_key(opening.turn_key, "turn_key")?;
        validate_time(opening.opened_ms, "opened_ms")?;
        validate_row_id(opening.session_id, "session_id")?;
        if opening.ordinal == 0 {
            return Err(ProviderJournalError::InvalidField("ordinal"));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session = read_session(&transaction, opening.session_id)?
            .ok_or(ProviderJournalError::NotFound("provider_session"))?;
        if session.state != SessionState::Open {
            return Err(ProviderJournalError::NotOpen("provider_session"));
        }
        if let Some(existing) =
            read_turn_by_key(&transaction, opening.session_id, opening.turn_key)?
        {
            if existing.state == TurnState::Open
                && existing.ordinal == opening.ordinal
                && existing.opened_ms == opening.opened_ms
                && same_provenance(existing.provenance.as_ref(), opening.provenance)
            {
                transaction.commit()?;
                return Ok(TurnReceipt {
                    turn_id: existing.turn_id,
                    ordinal: existing.ordinal,
                    revision: existing.revision,
                    duplicate: true,
                });
            }
            return Err(ProviderJournalError::IdempotencyConflict("turn_key"));
        }
        if let Some(open) = read_open_turn(&transaction, opening.session_id)? {
            return Err(ProviderJournalError::TurnOpen {
                turn_id: open.turn_id,
            });
        }
        let expected = next_ordinal(&transaction, opening.session_id)?;
        if expected != opening.ordinal {
            return Err(ProviderJournalError::TurnOrdinal {
                expected,
                supplied: opening.ordinal,
            });
        }
        transaction.execute(
            "INSERT INTO provider_turns
             (session_id, ordinal, turn_key, state, opened_ms, closed_ms, revision,
              trace_id, correlation_id, causation_id)
             VALUES (?1, ?2, ?3, 'open', ?4, NULL, 1, ?5, ?6, ?7)",
            params![
                opening.session_id,
                to_db_u64(opening.ordinal, "ordinal")?,
                opening.turn_key,
                opening.opened_ms,
                opening.provenance.map(|value| value.trace_id().as_str()),
                opening
                    .provenance
                    .map(|value| value.correlation_id().as_str()),
                opening
                    .provenance
                    .map(|value| value.causation_id().as_str())
            ],
        )?;
        let turn_id = transaction.last_insert_rowid();
        transaction.commit()?;
        Ok(TurnReceipt {
            turn_id,
            ordinal: opening.ordinal,
            revision: 1,
            duplicate: false,
        })
    }

    /// Atomically settle requests, advance the cursor and close one open turn.
    ///
    /// Every part commits together. A refusal anywhere — an unknown request
    /// key, a stale request revision, a backward cursor — discards the whole
    /// commit, so a crashed writer cannot leave a half-closed turn.
    pub fn complete_turn(&mut self, completion: TurnCompletion<'_>) -> Journalled<TurnReceipt> {
        validate_time(completion.now_ms, "now_ms")?;
        validate_row_id(completion.turn_id, "turn_id")?;
        if completion.settlements.len() > MAX_SETTLEMENTS {
            return Err(ProviderJournalError::InvalidField("settlements"));
        }
        for settlement in completion.settlements {
            validate_settlement(settlement)?;
        }
        if let Some(cursor) = completion.cursor.as_ref() {
            validate_cursor(cursor)?;
        }
        if let Some(usage) = completion.usage.as_ref() {
            if completion.outcome != TurnOutcome::Completed {
                return Err(ProviderJournalError::InvalidField("turn_usage"));
            }
            validate_turn_usage(usage)?;
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let turn = read_turn(&transaction, completion.turn_id)?
            .ok_or(ProviderJournalError::NotFound("provider_turn"))?;
        let terminal = completion.outcome.state();
        let replay = turn.state != TurnState::Open;
        if replay && turn.state != terminal {
            return Err(ProviderJournalError::AlreadySettled);
        }
        if !replay {
            require_revision(completion.expected_revision, turn.revision)?;
        }
        for settlement in completion.settlements {
            settle_request_row(&transaction, turn.turn_id, completion.now_ms, settlement)?;
        }
        if let Some(cursor) = completion.cursor.as_ref() {
            advance_cursor_row(&transaction, cursor)?;
        }
        if replay {
            match (
                read_turn_usage(&transaction, turn.turn_id)?,
                completion.usage.as_ref(),
            ) {
                (None, None) => {}
                (Some(recorded), Some(supplied)) if usage_matches(&recorded, supplied) => {}
                _ => return Err(ProviderJournalError::AlreadySettled),
            }
            transaction.commit()?;
            return Ok(TurnReceipt {
                turn_id: turn.turn_id,
                ordinal: turn.ordinal,
                revision: turn.revision,
                duplicate: true,
            });
        }
        let next_revision = next_revision(turn.revision)?;
        let changed = transaction.execute(
            "UPDATE provider_turns SET state = ?2, closed_ms = ?3, revision = ?4
             WHERE turn_id = ?1 AND state = 'open' AND revision = ?5",
            params![
                turn.turn_id,
                terminal.as_str(),
                completion.now_ms,
                to_db_u64(next_revision, "revision")?,
                to_db_u64(turn.revision, "revision")?
            ],
        )?;
        require_single_row(changed, "provider_turn")?;
        if let Some(usage) = completion.usage.as_ref() {
            insert_turn_usage(&transaction, turn.turn_id, usage)?;
        }
        transaction.commit()?;
        Ok(TurnReceipt {
            turn_id: turn.turn_id,
            ordinal: turn.ordinal,
            revision: next_revision,
            duplicate: false,
        })
    }

    /// Read the usage recorded for one turn.
    pub fn turn_usage(&self, turn_id: i64) -> Journalled<Option<TurnUsageRow>> {
        validate_row_id(turn_id, "turn_id")?;
        read_turn_usage(&self.connection, turn_id)
    }

    /// Aggregate all durable completed-turn usage in this journal.
    pub fn usage_totals(&self) -> Journalled<UsageTotals> {
        let (requests, input_tokens, output_tokens): (i64, i64, i64) = self.connection.query_row(
            "SELECT count(*), coalesce(sum(input_tokens), 0),
                        coalesce(sum(output_tokens), 0)
                 FROM provider_turn_usage",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        Ok(UsageTotals {
            requests: from_db_u64(requests, "usage_requests")?,
            input_tokens: from_db_u64(input_tokens, "usage_input_tokens")?,
            output_tokens: from_db_u64(output_tokens, "usage_output_tokens")?,
        })
    }

    /// Record one correlated request inside an open turn.
    ///
    /// The payload digest binds the request content; the content itself never
    /// enters this journal. Replaying the same key with the same direction and
    /// digest returns the existing request.
    pub fn record_request(&mut self, request: RequestRecord<'_>) -> Journalled<RequestReceipt> {
        validate_key(request.request_key, "request_key")?;
        validate_digest(request.payload_digest, "payload_digest")?;
        validate_time(request.created_ms, "created_ms")?;
        validate_row_id(request.turn_id, "turn_id")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let turn = read_turn(&transaction, request.turn_id)?
            .ok_or(ProviderJournalError::NotFound("provider_turn"))?;
        if turn.state != TurnState::Open {
            return Err(ProviderJournalError::NotOpen("provider_turn"));
        }
        if let Some(existing) =
            read_request_by_key(&transaction, request.turn_id, request.request_key)?
        {
            if existing.direction != request.direction
                || existing.payload_digest != request.payload_digest
                || existing.created_ms != request.created_ms
            {
                return Err(ProviderJournalError::IdempotencyConflict("request_key"));
            }
            transaction.commit()?;
            return Ok(RequestReceipt {
                request_id: existing.request_id,
                revision: existing.revision,
                duplicate: true,
            });
        }
        transaction.execute(
            "INSERT INTO provider_requests
             (turn_id, request_key, direction, payload_digest, outcome,
              response_digest, failure_reason, created_ms, settled_ms, revision)
             VALUES (?1, ?2, ?3, ?4, 'pending', NULL, NULL, ?5, NULL, 1)",
            params![
                request.turn_id,
                request.request_key,
                request.direction.as_str(),
                request.payload_digest,
                request.created_ms
            ],
        )?;
        let request_id = transaction.last_insert_rowid();
        transaction.commit()?;
        Ok(RequestReceipt {
            request_id,
            revision: 1,
            duplicate: false,
        })
    }

    /// Settle one request outside a turn commit.
    ///
    /// A settlement is accepted after the turn closed: a supervisor may only
    /// learn a pending request's fate during reconciliation.
    pub fn settle_request(
        &mut self,
        commit: RequestOutcomeCommit<'_>,
    ) -> Journalled<RequestReceipt> {
        validate_time(commit.now_ms, "now_ms")?;
        validate_row_id(commit.turn_id, "turn_id")?;
        validate_settlement(&commit.settlement)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if read_turn(&transaction, commit.turn_id)?.is_none() {
            return Err(ProviderJournalError::NotFound("provider_turn"));
        }
        let receipt = settle_request_row(
            &transaction,
            commit.turn_id,
            commit.now_ms,
            &commit.settlement,
        )?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Move one stream cursor forward for an open session.
    ///
    /// Rewriting the durable sequence is idempotent; moving backward is a
    /// refusal, never a silent rewind.
    pub fn advance_cursor(&mut self, advance: CursorAdvance<'_>) -> Journalled<CursorReceipt> {
        validate_cursor(&advance)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_open_session(&transaction, advance.session_id)?;
        let receipt = advance_cursor_row(&transaction, &advance)?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Record one write-once capability binding for an open session.
    pub fn bind_capability(&mut self, binding: BindingRecord<'_>) -> Journalled<WriteOnceReceipt> {
        self.bind(BindingKind::Capability, binding)
    }

    /// Record one write-once schema binding for an open session.
    pub fn bind_schema(&mut self, binding: BindingRecord<'_>) -> Journalled<WriteOnceReceipt> {
        self.bind(BindingKind::Schema, binding)
    }

    fn bind(
        &mut self,
        kind: BindingKind,
        binding: BindingRecord<'_>,
    ) -> Journalled<WriteOnceReceipt> {
        validate_key(binding.name, "binding_name")?;
        validate_bounded(binding.version, MAX_VERSION_BYTES, "binding_version")?;
        validate_digest(binding.value_digest, "value_digest")?;
        validate_time(binding.bound_ms, "bound_ms")?;
        validate_row_id(binding.session_id, "session_id")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_open_session(&transaction, binding.session_id)?;
        if let Some(existing) = read_binding(&transaction, binding.session_id, kind, binding.name)?
        {
            if existing.version != binding.version || existing.value_digest != binding.value_digest
            {
                return Err(ProviderJournalError::BindingConflict(kind.conflict()));
            }
            transaction.commit()?;
            return Ok(WriteOnceReceipt { duplicate: true });
        }
        transaction.execute(
            "INSERT INTO provider_bindings
             (session_id, kind, name, version, value_digest, bound_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                binding.session_id,
                kind.as_str(),
                binding.name,
                binding.version,
                binding.value_digest,
                binding.bound_ms
            ],
        )?;
        transaction.commit()?;
        Ok(WriteOnceReceipt { duplicate: false })
    }

    /// Record one write-once approval decision for an open session.
    ///
    /// This records that a decision was journalled. It does not establish that
    /// the provider observed or honoured it.
    pub fn record_approval(
        &mut self,
        approval: ApprovalRecord<'_>,
    ) -> Journalled<WriteOnceReceipt> {
        validate_key(approval.approval_key, "approval_key")?;
        validate_key(approval.deciding_actor, "deciding_actor")?;
        validate_time(approval.decided_ms, "decided_ms")?;
        validate_row_id(approval.session_id, "session_id")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_open_session(&transaction, approval.session_id)?;
        if let Some(existing) =
            read_approval(&transaction, approval.session_id, approval.approval_key)?
        {
            if existing.decision != approval.decision
                || existing.deciding_actor != approval.deciding_actor
                || existing.decided_ms != approval.decided_ms
            {
                return Err(ProviderJournalError::BindingConflict("approval_binding"));
            }
            transaction.commit()?;
            return Ok(WriteOnceReceipt { duplicate: true });
        }
        transaction.execute(
            "INSERT INTO provider_approvals
             (session_id, approval_key, decision, deciding_actor, decided_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                approval.session_id,
                approval.approval_key,
                approval.decision.as_str(),
                approval.deciding_actor,
                approval.decided_ms
            ],
        )?;
        transaction.commit()?;
        Ok(WriteOnceReceipt { duplicate: false })
    }

    /// Read one validated process row.
    pub fn process(&self, process_id: i64) -> Journalled<ProcessRow> {
        read_process(&self.connection, process_id)?
            .ok_or(ProviderJournalError::NotFound("provider_process"))
    }

    /// Read one validated session row.
    pub fn session(&self, session_id: i64) -> Journalled<SessionRow> {
        read_session(&self.connection, session_id)?
            .ok_or(ProviderJournalError::NotFound("provider_session"))
    }

    /// Read one validated turn row.
    pub fn turn(&self, turn_id: i64) -> Journalled<TurnRow> {
        read_turn(&self.connection, turn_id)?.ok_or(ProviderJournalError::NotFound("provider_turn"))
    }

    /// Read every turn of a session, ordinal order, checking contiguity.
    pub fn session_turns(&self, session_id: i64) -> Journalled<Vec<TurnRow>> {
        read_session_turns(&self.connection, session_id)
    }

    /// Read every request of a turn, oldest first.
    pub fn turn_requests(&self, turn_id: i64) -> Journalled<Vec<RequestRow>> {
        read_turn_requests(&self.connection, turn_id, false)
    }

    /// Read every durable cursor of a session, ordered by stream name.
    pub fn cursors(&self, session_id: i64) -> Journalled<Vec<CursorRow>> {
        read_cursors(&self.connection, session_id)
    }

    /// Read every binding of one kind for a session, ordered by name.
    pub fn bindings(&self, session_id: i64, kind: BindingKind) -> Journalled<Vec<BindingRow>> {
        read_bindings(&self.connection, session_id, kind)
    }

    /// Read every approval decision for a session, ordered by key.
    pub fn approvals(&self, session_id: i64) -> Journalled<Vec<ApprovalRow>> {
        read_approvals(&self.connection, session_id)
    }

    /// One transactional point-in-time recovery view for an attempt.
    ///
    /// Everything returned is read inside one transaction, so a restarting
    /// supervisor reasons from a single consistent instant rather than from
    /// rows that moved between queries.
    pub fn recover_attempt(&mut self, attempt_id: &str) -> Journalled<AttemptRecovery> {
        validate_key(attempt_id, "attempt_id")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let recovery = attempt_recovery(&transaction, attempt_id)?;
        transaction.commit()?;
        Ok(recovery)
    }
}

fn attempt_recovery(
    transaction: &Transaction<'_>,
    attempt_id: &str,
) -> Journalled<AttemptRecovery> {
    let processes = read_attempt_processes(transaction, attempt_id)?;
    if processes
        .iter()
        .filter(|process| process.state == ProcessState::Live)
        .count()
        > 1
    {
        return Err(ProviderJournalError::Corrupt("attempt_live_processes"));
    }
    let process = processes
        .iter()
        .find(|process| process.state == ProcessState::Live)
        .or_else(|| processes.last())
        .cloned();
    let Some(process) = process else {
        return Ok(AttemptRecovery {
            attempt_id: attempt_id.to_owned(),
            process: None,
            session: None,
            turn: None,
            pending_requests: Vec::new(),
            cursors: Vec::new(),
            capabilities: Vec::new(),
            schemas: Vec::new(),
            approvals: Vec::new(),
        });
    };

    let sessions = read_process_sessions(transaction, process.process_id)?;
    if sessions
        .iter()
        .filter(|session| session.state == SessionState::Open)
        .count()
        > 1
    {
        return Err(ProviderJournalError::Corrupt("process_open_sessions"));
    }
    let session = sessions
        .iter()
        .find(|session| session.state == SessionState::Open)
        .or_else(|| sessions.last())
        .cloned();
    let Some(session) = session else {
        return Ok(AttemptRecovery {
            attempt_id: attempt_id.to_owned(),
            process: Some(process),
            session: None,
            turn: None,
            pending_requests: Vec::new(),
            cursors: Vec::new(),
            capabilities: Vec::new(),
            schemas: Vec::new(),
            approvals: Vec::new(),
        });
    };

    let turns = read_session_turns(transaction, session.session_id)?;
    if turns
        .iter()
        .filter(|turn| turn.state == TurnState::Open)
        .count()
        > 1
    {
        return Err(ProviderJournalError::Corrupt("session_open_turns"));
    }
    let turn = turns
        .iter()
        .find(|turn| turn.state == TurnState::Open)
        .or_else(|| turns.last())
        .cloned();
    let pending_requests = match turn.as_ref() {
        Some(turn) => read_turn_requests(transaction, turn.turn_id, true)?,
        None => Vec::new(),
    };

    Ok(AttemptRecovery {
        attempt_id: attempt_id.to_owned(),
        cursors: read_cursors(transaction, session.session_id)?,
        capabilities: read_bindings(transaction, session.session_id, BindingKind::Capability)?,
        schemas: read_bindings(transaction, session.session_id, BindingKind::Schema)?,
        approvals: read_approvals(transaction, session.session_id)?,
        process: Some(process),
        session: Some(session),
        turn,
        pending_requests,
    })
}

/// Close one open session and, when it is lost, abort its open turn.
fn close_session_rows(
    transaction: &Transaction<'_>,
    session: &SessionRow,
    closure: SessionClosure,
    now_ms: i64,
    turn_outcome: TurnOutcome,
) -> Journalled<u64> {
    if let Some(turn) = read_open_turn(transaction, session.session_id)? {
        let turn_revision = next_revision(turn.revision)?;
        let changed = transaction.execute(
            "UPDATE provider_turns SET state = ?2, closed_ms = ?3, revision = ?4
             WHERE turn_id = ?1 AND state = 'open' AND revision = ?5",
            params![
                turn.turn_id,
                turn_outcome.state().as_str(),
                now_ms,
                to_db_u64(turn_revision, "revision")?,
                to_db_u64(turn.revision, "revision")?
            ],
        )?;
        require_single_row(changed, "provider_turn")?;
    }
    let next = next_revision(session.revision)?;
    let changed = transaction.execute(
        "UPDATE provider_sessions SET state = ?2, closed_ms = ?3, revision = ?4
         WHERE session_id = ?1 AND state = 'open' AND revision = ?5",
        params![
            session.session_id,
            closure.state().as_str(),
            now_ms,
            to_db_u64(next, "revision")?,
            to_db_u64(session.revision, "revision")?
        ],
    )?;
    require_single_row(changed, "provider_session")?;
    Ok(next)
}

fn settle_request_row(
    transaction: &Transaction<'_>,
    turn_id: i64,
    now_ms: i64,
    settlement: &RequestSettlement<'_>,
) -> Journalled<RequestReceipt> {
    let request = read_request_by_key(transaction, turn_id, settlement.request_key)?
        .ok_or(ProviderJournalError::NotFound("provider_request"))?;
    let (outcome, response_digest, failure_reason) = match settlement.outcome {
        SettledOutcome::Answered { response_digest } => {
            (RequestState::Answered, Some(response_digest), None)
        }
        SettledOutcome::Failed { reason } => (RequestState::Failed, None, Some(reason)),
    };
    if request.outcome != RequestState::Pending {
        if request.outcome == outcome
            && request.response_digest.as_deref() == response_digest
            && request.failure_reason.as_deref() == failure_reason
        {
            return Ok(RequestReceipt {
                request_id: request.request_id,
                revision: request.revision,
                duplicate: true,
            });
        }
        return Err(ProviderJournalError::AlreadySettled);
    }
    require_revision(settlement.expected_revision, request.revision)?;
    let next = next_revision(request.revision)?;
    let changed = transaction.execute(
        "UPDATE provider_requests
         SET outcome = ?2, response_digest = ?3, failure_reason = ?4,
             settled_ms = ?5, revision = ?6
         WHERE request_id = ?1 AND outcome = 'pending' AND revision = ?7",
        params![
            request.request_id,
            outcome.as_str(),
            response_digest,
            failure_reason,
            now_ms,
            to_db_u64(next, "revision")?,
            to_db_u64(request.revision, "revision")?
        ],
    )?;
    require_single_row(changed, "provider_request")?;
    Ok(RequestReceipt {
        request_id: request.request_id,
        revision: next,
        duplicate: false,
    })
}

fn advance_cursor_row(
    transaction: &Transaction<'_>,
    advance: &CursorAdvance<'_>,
) -> Journalled<CursorReceipt> {
    let existing = read_cursor(transaction, advance.session_id, advance.stream)?;
    let Some(existing) = existing else {
        transaction.execute(
            "INSERT INTO provider_cursors (session_id, stream, sequence, updated_ms, revision)
             VALUES (?1, ?2, ?3, ?4, 1)",
            params![
                advance.session_id,
                advance.stream,
                to_db_u64(advance.sequence, "sequence")?,
                advance.now_ms
            ],
        )?;
        return Ok(CursorReceipt {
            sequence: advance.sequence,
            revision: 1,
            duplicate: false,
        });
    };
    if advance.sequence < existing.sequence {
        return Err(ProviderJournalError::CursorRegression {
            durable: existing.sequence,
            supplied: advance.sequence,
        });
    }
    if advance.sequence == existing.sequence {
        return Ok(CursorReceipt {
            sequence: existing.sequence,
            revision: existing.revision,
            duplicate: true,
        });
    }
    let next = next_revision(existing.revision)?;
    let changed = transaction.execute(
        "UPDATE provider_cursors SET sequence = ?3, updated_ms = ?4, revision = ?5
         WHERE session_id = ?1 AND stream = ?2 AND revision = ?6",
        params![
            advance.session_id,
            advance.stream,
            to_db_u64(advance.sequence, "sequence")?,
            advance.now_ms,
            to_db_u64(next, "revision")?,
            to_db_u64(existing.revision, "revision")?
        ],
    )?;
    require_single_row(changed, "provider_cursor")?;
    Ok(CursorReceipt {
        sequence: advance.sequence,
        revision: next,
        duplicate: false,
    })
}

fn require_open_session(transaction: &Transaction<'_>, session_id: i64) -> Journalled<SessionRow> {
    let session = read_session(transaction, session_id)?
        .ok_or(ProviderJournalError::NotFound("provider_session"))?;
    if session.state != SessionState::Open {
        return Err(ProviderJournalError::NotOpen("provider_session"));
    }
    Ok(session)
}

fn next_ordinal(transaction: &Transaction<'_>, session_id: i64) -> Journalled<u64> {
    let highest: Option<i64> = transaction.query_row(
        "SELECT max(ordinal) FROM provider_turns WHERE session_id = ?1",
        [session_id],
        |row| row.get(0),
    )?;
    let highest = highest.map_or(Ok(0), |value| from_db_u64(value, "ordinal"))?;
    highest
        .checked_add(1)
        .ok_or(ProviderJournalError::InvalidField("ordinal"))
}

struct RawProcess {
    process_id: i64,
    spawn_key: String,
    attempt_id: String,
    provider_kind: String,
    executable_digest: String,
    state: String,
    spawned_ms: i64,
    exited_ms: Option<i64>,
    revision: i64,
}

const PROCESS_COLUMNS: &str = "process_id, spawn_key, attempt_id, provider_kind,
     executable_digest, state, spawned_ms, exited_ms, revision";

fn raw_process(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawProcess> {
    Ok(RawProcess {
        process_id: row.get(0)?,
        spawn_key: row.get(1)?,
        attempt_id: row.get(2)?,
        provider_kind: row.get(3)?,
        executable_digest: row.get(4)?,
        state: row.get(5)?,
        spawned_ms: row.get(6)?,
        exited_ms: row.get(7)?,
        revision: row.get(8)?,
    })
}

fn validated_process(raw: RawProcess) -> Journalled<ProcessRow> {
    let state = ProcessState::parse(&raw.state)?;
    let terminal = state != ProcessState::Live;
    if terminal != raw.exited_ms.is_some() {
        return Err(ProviderJournalError::Corrupt("process_exited_ms"));
    }
    Ok(ProcessRow {
        process_id: checked_row_id(raw.process_id, "process_id")?,
        spawn_key: checked_key(raw.spawn_key, "spawn_key")?,
        attempt_id: checked_key(raw.attempt_id, "attempt_id")?,
        provider_kind: checked_bounded(raw.provider_kind, MAX_KIND_BYTES, "provider_kind")?,
        executable_digest: checked_digest(raw.executable_digest, "executable_digest")?,
        state,
        spawned_ms: checked_time(raw.spawned_ms, "spawned_ms")?,
        exited_ms: raw
            .exited_ms
            .map(|value| checked_time(value, "exited_ms"))
            .transpose()?,
        revision: checked_revision(raw.revision)?,
    })
}

fn read_process(connection: &Connection, process_id: i64) -> Journalled<Option<ProcessRow>> {
    let raw = connection
        .query_row(
            &format!("SELECT {PROCESS_COLUMNS} FROM provider_processes WHERE process_id = ?1"),
            [process_id],
            raw_process,
        )
        .optional()?;
    raw.map(validated_process).transpose()
}

fn read_process_by_spawn_key(
    connection: &Connection,
    spawn_key: &str,
) -> Journalled<Option<ProcessRow>> {
    let raw = connection
        .query_row(
            &format!("SELECT {PROCESS_COLUMNS} FROM provider_processes WHERE spawn_key = ?1"),
            [spawn_key],
            raw_process,
        )
        .optional()?;
    raw.map(validated_process).transpose()
}

fn read_live_process(connection: &Connection, attempt_id: &str) -> Journalled<Option<ProcessRow>> {
    let raw = connection
        .query_row(
            &format!(
                "SELECT {PROCESS_COLUMNS} FROM provider_processes
                 WHERE attempt_id = ?1 AND state = 'live'"
            ),
            [attempt_id],
            raw_process,
        )
        .optional()?;
    raw.map(validated_process).transpose()
}

fn read_attempt_processes(
    connection: &Connection,
    attempt_id: &str,
) -> Journalled<Vec<ProcessRow>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {PROCESS_COLUMNS} FROM provider_processes
         WHERE attempt_id = ?1 ORDER BY process_id"
    ))?;
    let rows = statement.query_map([attempt_id], raw_process)?;
    let mut processes = Vec::new();
    for raw in rows {
        processes.push(validated_process(raw?)?);
    }
    Ok(processes)
}

struct RawSession {
    session_id: i64,
    process_id: i64,
    provider_session_key: String,
    state: String,
    opened_ms: i64,
    closed_ms: Option<i64>,
    revision: i64,
}

const SESSION_COLUMNS: &str = "session_id, process_id, provider_session_key, state,
     opened_ms, closed_ms, revision";

fn raw_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawSession> {
    Ok(RawSession {
        session_id: row.get(0)?,
        process_id: row.get(1)?,
        provider_session_key: row.get(2)?,
        state: row.get(3)?,
        opened_ms: row.get(4)?,
        closed_ms: row.get(5)?,
        revision: row.get(6)?,
    })
}

fn validated_session(raw: RawSession) -> Journalled<SessionRow> {
    let state = SessionState::parse(&raw.state)?;
    if (state != SessionState::Open) != raw.closed_ms.is_some() {
        return Err(ProviderJournalError::Corrupt("session_closed_ms"));
    }
    Ok(SessionRow {
        session_id: checked_row_id(raw.session_id, "session_id")?,
        process_id: checked_row_id(raw.process_id, "process_id")?,
        provider_session_key: checked_key(raw.provider_session_key, "provider_session_key")?,
        state,
        opened_ms: checked_time(raw.opened_ms, "opened_ms")?,
        closed_ms: raw
            .closed_ms
            .map(|value| checked_time(value, "closed_ms"))
            .transpose()?,
        revision: checked_revision(raw.revision)?,
    })
}

fn read_session(connection: &Connection, session_id: i64) -> Journalled<Option<SessionRow>> {
    let raw = connection
        .query_row(
            &format!("SELECT {SESSION_COLUMNS} FROM provider_sessions WHERE session_id = ?1"),
            [session_id],
            raw_session,
        )
        .optional()?;
    raw.map(validated_session).transpose()
}

fn read_session_by_key(
    connection: &Connection,
    process_id: i64,
    provider_session_key: &str,
) -> Journalled<Option<SessionRow>> {
    let raw = connection
        .query_row(
            &format!(
                "SELECT {SESSION_COLUMNS} FROM provider_sessions
                 WHERE process_id = ?1 AND provider_session_key = ?2"
            ),
            params![process_id, provider_session_key],
            raw_session,
        )
        .optional()?;
    raw.map(validated_session).transpose()
}

fn read_open_session(connection: &Connection, process_id: i64) -> Journalled<Option<SessionRow>> {
    let raw = connection
        .query_row(
            &format!(
                "SELECT {SESSION_COLUMNS} FROM provider_sessions
                 WHERE process_id = ?1 AND state = 'open'"
            ),
            [process_id],
            raw_session,
        )
        .optional()?;
    raw.map(validated_session).transpose()
}

fn read_process_sessions(connection: &Connection, process_id: i64) -> Journalled<Vec<SessionRow>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {SESSION_COLUMNS} FROM provider_sessions
         WHERE process_id = ?1 ORDER BY session_id"
    ))?;
    let rows = statement.query_map([process_id], raw_session)?;
    let mut sessions = Vec::new();
    for raw in rows {
        sessions.push(validated_session(raw?)?);
    }
    Ok(sessions)
}

struct RawTurn {
    turn_id: i64,
    session_id: i64,
    ordinal: i64,
    turn_key: String,
    state: String,
    opened_ms: i64,
    closed_ms: Option<i64>,
    revision: i64,
    trace_id: Option<String>,
    correlation_id: Option<String>,
    causation_id: Option<String>,
}

struct RawTurnUsage {
    turn_id: i64,
    gen_ai_system: String,
    request_model: Option<String>,
    response_model: Option<String>,
    input_tokens: i64,
    cached_input_tokens: i64,
    output_tokens: i64,
    finish_reason: String,
}

const TURN_COLUMNS: &str = "turn_id, session_id, ordinal, turn_key, state,
     opened_ms, closed_ms, revision, trace_id, correlation_id, causation_id";

fn raw_turn(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawTurn> {
    Ok(RawTurn {
        turn_id: row.get(0)?,
        session_id: row.get(1)?,
        ordinal: row.get(2)?,
        turn_key: row.get(3)?,
        state: row.get(4)?,
        opened_ms: row.get(5)?,
        closed_ms: row.get(6)?,
        revision: row.get(7)?,
        trace_id: row.get(8)?,
        correlation_id: row.get(9)?,
        causation_id: row.get(10)?,
    })
}

fn validated_turn(raw: RawTurn) -> Journalled<TurnRow> {
    let state = TurnState::parse(&raw.state)?;
    if (state != TurnState::Open) != raw.closed_ms.is_some() {
        return Err(ProviderJournalError::Corrupt("turn_closed_ms"));
    }
    let ordinal = from_db_u64(raw.ordinal, "ordinal")?;
    if ordinal == 0 {
        return Err(ProviderJournalError::Corrupt("turn_ordinal"));
    }
    Ok(TurnRow {
        turn_id: checked_row_id(raw.turn_id, "turn_id")?,
        session_id: checked_row_id(raw.session_id, "session_id")?,
        ordinal,
        turn_key: checked_key(raw.turn_key, "turn_key")?,
        state,
        opened_ms: checked_time(raw.opened_ms, "opened_ms")?,
        closed_ms: raw
            .closed_ms
            .map(|value| checked_time(value, "closed_ms"))
            .transpose()?,
        revision: checked_revision(raw.revision)?,
        provenance: stored_provenance(raw.trace_id, raw.correlation_id, raw.causation_id)
            .map_err(|_| ProviderJournalError::Corrupt("turn_provenance"))?,
    })
}

fn same_provenance(stored: Option<&StoredProvenance>, supplied: Option<&Provenance>) -> bool {
    match (stored, supplied) {
        (None, None) => true,
        (Some(stored), Some(supplied)) => {
            stored.trace_id == supplied.trace_id().as_str()
                && stored.correlation_id == supplied.correlation_id().as_str()
                && stored.causation_id == supplied.causation_id().as_str()
        }
        _ => false,
    }
}

fn read_turn(connection: &Connection, turn_id: i64) -> Journalled<Option<TurnRow>> {
    let raw = connection
        .query_row(
            &format!("SELECT {TURN_COLUMNS} FROM provider_turns WHERE turn_id = ?1"),
            [turn_id],
            raw_turn,
        )
        .optional()?;
    raw.map(validated_turn).transpose()
}

fn read_turn_usage(connection: &Connection, turn_id: i64) -> Journalled<Option<TurnUsageRow>> {
    let raw: Option<RawTurnUsage> = connection
        .query_row(
            "SELECT turn_id, gen_ai_system, request_model, response_model,
                        input_tokens, cached_input_tokens, output_tokens, finish_reason
                 FROM provider_turn_usage WHERE turn_id = ?1",
            [turn_id],
            |row| {
                Ok(RawTurnUsage {
                    turn_id: row.get(0)?,
                    gen_ai_system: row.get(1)?,
                    request_model: row.get(2)?,
                    response_model: row.get(3)?,
                    input_tokens: row.get(4)?,
                    cached_input_tokens: row.get(5)?,
                    output_tokens: row.get(6)?,
                    finish_reason: row.get(7)?,
                })
            },
        )
        .optional()?;
    raw.map(|raw| {
        Ok(TurnUsageRow {
            turn_id: checked_row_id(raw.turn_id, "turn_id")?,
            gen_ai_system: checked_bounded(raw.gen_ai_system, MAX_KIND_BYTES, "gen_ai_system")?,
            request_model: raw
                .request_model
                .map(|value| checked_bounded(value, MAX_VERSION_BYTES, "request_model"))
                .transpose()?,
            response_model: raw
                .response_model
                .map(|value| checked_bounded(value, MAX_VERSION_BYTES, "response_model"))
                .transpose()?,
            input_tokens: from_db_u64(raw.input_tokens, "input_tokens")?,
            cached_input_tokens: from_db_u64(raw.cached_input_tokens, "cached_input_tokens")?,
            output_tokens: from_db_u64(raw.output_tokens, "output_tokens")?,
            finish_reason: FinishReason::parse(&raw.finish_reason)?,
        })
    })
    .transpose()
}

fn insert_turn_usage(
    connection: &Connection,
    turn_id: i64,
    usage: &TurnUsage<'_>,
) -> Journalled<()> {
    let changed = connection.execute(
        "INSERT INTO provider_turn_usage
         (turn_id, gen_ai_system, request_model, response_model, input_tokens,
          cached_input_tokens, output_tokens, finish_reason)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            turn_id,
            usage.gen_ai_system,
            usage.request_model,
            usage.response_model,
            to_db_u64(usage.input_tokens, "input_tokens")?,
            to_db_u64(usage.cached_input_tokens, "cached_input_tokens")?,
            to_db_u64(usage.output_tokens, "output_tokens")?,
            usage.finish_reason.as_str(),
        ],
    )?;
    require_single_row(changed, "provider_turn_usage")
}

fn usage_matches(recorded: &TurnUsageRow, supplied: &TurnUsage<'_>) -> bool {
    recorded.gen_ai_system == supplied.gen_ai_system
        && recorded.request_model.as_deref() == supplied.request_model
        && recorded.response_model.as_deref() == supplied.response_model
        && recorded.input_tokens == supplied.input_tokens
        && recorded.cached_input_tokens == supplied.cached_input_tokens
        && recorded.output_tokens == supplied.output_tokens
        && recorded.finish_reason == supplied.finish_reason
}

fn read_turn_by_key(
    connection: &Connection,
    session_id: i64,
    turn_key: &str,
) -> Journalled<Option<TurnRow>> {
    let raw = connection
        .query_row(
            &format!(
                "SELECT {TURN_COLUMNS} FROM provider_turns
                 WHERE session_id = ?1 AND turn_key = ?2"
            ),
            params![session_id, turn_key],
            raw_turn,
        )
        .optional()?;
    raw.map(validated_turn).transpose()
}

fn read_open_turn(connection: &Connection, session_id: i64) -> Journalled<Option<TurnRow>> {
    let raw = connection
        .query_row(
            &format!(
                "SELECT {TURN_COLUMNS} FROM provider_turns
                 WHERE session_id = ?1 AND state = 'open'"
            ),
            [session_id],
            raw_turn,
        )
        .optional()?;
    raw.map(validated_turn).transpose()
}

/// Read a session's turns and refuse a non-contiguous ordinal sequence.
///
/// Contiguity is not a database constraint, so this is where a row written
/// around this API is caught instead of believed.
fn read_session_turns(connection: &Connection, session_id: i64) -> Journalled<Vec<TurnRow>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {TURN_COLUMNS} FROM provider_turns WHERE session_id = ?1 ORDER BY ordinal"
    ))?;
    let rows = statement.query_map([session_id], raw_turn)?;
    let mut turns = Vec::new();
    for raw in rows {
        turns.push(validated_turn(raw?)?);
    }
    for (index, turn) in turns.iter().enumerate() {
        let expected = u64::try_from(index)
            .map_err(|_| ProviderJournalError::Corrupt("turn_ordinal_span"))?
            .checked_add(1)
            .ok_or(ProviderJournalError::Corrupt("turn_ordinal_span"))?;
        if turn.ordinal != expected {
            return Err(ProviderJournalError::Corrupt("turn_ordinal_contiguity"));
        }
    }
    Ok(turns)
}

struct RawRequest {
    request_id: i64,
    turn_id: i64,
    request_key: String,
    direction: String,
    payload_digest: String,
    outcome: String,
    response_digest: Option<String>,
    failure_reason: Option<String>,
    created_ms: i64,
    settled_ms: Option<i64>,
    revision: i64,
}

const REQUEST_COLUMNS: &str = "request_id, turn_id, request_key, direction, payload_digest,
     outcome, response_digest, failure_reason, created_ms, settled_ms, revision";

fn raw_request(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRequest> {
    Ok(RawRequest {
        request_id: row.get(0)?,
        turn_id: row.get(1)?,
        request_key: row.get(2)?,
        direction: row.get(3)?,
        payload_digest: row.get(4)?,
        outcome: row.get(5)?,
        response_digest: row.get(6)?,
        failure_reason: row.get(7)?,
        created_ms: row.get(8)?,
        settled_ms: row.get(9)?,
        revision: row.get(10)?,
    })
}

fn validated_request(raw: RawRequest) -> Journalled<RequestRow> {
    let outcome = RequestState::parse(&raw.outcome)?;
    let settled = outcome != RequestState::Pending;
    if settled != raw.settled_ms.is_some() {
        return Err(ProviderJournalError::Corrupt("request_settled_ms"));
    }
    if (outcome == RequestState::Answered) != raw.response_digest.is_some()
        || (outcome == RequestState::Failed) != raw.failure_reason.is_some()
    {
        return Err(ProviderJournalError::Corrupt("request_outcome_content"));
    }
    Ok(RequestRow {
        request_id: checked_row_id(raw.request_id, "request_id")?,
        turn_id: checked_row_id(raw.turn_id, "turn_id")?,
        request_key: checked_key(raw.request_key, "request_key")?,
        direction: RequestDirection::parse(&raw.direction)?,
        payload_digest: checked_digest(raw.payload_digest, "payload_digest")?,
        outcome,
        response_digest: raw
            .response_digest
            .map(|value| checked_digest(value, "response_digest"))
            .transpose()?,
        failure_reason: raw
            .failure_reason
            .map(|value| checked_bounded(value, MAX_REASON_BYTES, "failure_reason"))
            .transpose()?,
        created_ms: checked_time(raw.created_ms, "created_ms")?,
        settled_ms: raw
            .settled_ms
            .map(|value| checked_time(value, "settled_ms"))
            .transpose()?,
        revision: checked_revision(raw.revision)?,
    })
}

fn read_request_by_key(
    connection: &Connection,
    turn_id: i64,
    request_key: &str,
) -> Journalled<Option<RequestRow>> {
    let raw = connection
        .query_row(
            &format!(
                "SELECT {REQUEST_COLUMNS} FROM provider_requests
                 WHERE turn_id = ?1 AND request_key = ?2"
            ),
            params![turn_id, request_key],
            raw_request,
        )
        .optional()?;
    raw.map(validated_request).transpose()
}

fn read_turn_requests(
    connection: &Connection,
    turn_id: i64,
    pending_only: bool,
) -> Journalled<Vec<RequestRow>> {
    let filter = if pending_only {
        " AND outcome = 'pending'"
    } else {
        ""
    };
    let mut statement = connection.prepare(&format!(
        "SELECT {REQUEST_COLUMNS} FROM provider_requests
         WHERE turn_id = ?1{filter} ORDER BY request_id"
    ))?;
    let rows = statement.query_map([turn_id], raw_request)?;
    let mut requests = Vec::new();
    for raw in rows {
        requests.push(validated_request(raw?)?);
    }
    Ok(requests)
}

struct RawCursor {
    session_id: i64,
    stream: String,
    sequence: i64,
    updated_ms: i64,
    revision: i64,
}

fn raw_cursor(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawCursor> {
    Ok(RawCursor {
        session_id: row.get(0)?,
        stream: row.get(1)?,
        sequence: row.get(2)?,
        updated_ms: row.get(3)?,
        revision: row.get(4)?,
    })
}

fn validated_cursor(raw: RawCursor) -> Journalled<CursorRow> {
    Ok(CursorRow {
        session_id: checked_row_id(raw.session_id, "session_id")?,
        stream: checked_key(raw.stream, "stream")?,
        sequence: from_db_u64(raw.sequence, "sequence")?,
        updated_ms: checked_time(raw.updated_ms, "updated_ms")?,
        revision: checked_revision(raw.revision)?,
    })
}

fn read_cursor(
    connection: &Connection,
    session_id: i64,
    stream: &str,
) -> Journalled<Option<CursorRow>> {
    let raw = connection
        .query_row(
            "SELECT session_id, stream, sequence, updated_ms, revision
             FROM provider_cursors WHERE session_id = ?1 AND stream = ?2",
            params![session_id, stream],
            raw_cursor,
        )
        .optional()?;
    raw.map(validated_cursor).transpose()
}

fn read_cursors(connection: &Connection, session_id: i64) -> Journalled<Vec<CursorRow>> {
    let mut statement = connection.prepare(
        "SELECT session_id, stream, sequence, updated_ms, revision
         FROM provider_cursors WHERE session_id = ?1 ORDER BY stream",
    )?;
    let rows = statement.query_map([session_id], raw_cursor)?;
    let mut cursors = Vec::new();
    for raw in rows {
        cursors.push(validated_cursor(raw?)?);
    }
    Ok(cursors)
}

struct RawBinding {
    session_id: i64,
    kind: String,
    name: String,
    version: String,
    value_digest: String,
    bound_ms: i64,
}

fn raw_binding(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawBinding> {
    Ok(RawBinding {
        session_id: row.get(0)?,
        kind: row.get(1)?,
        name: row.get(2)?,
        version: row.get(3)?,
        value_digest: row.get(4)?,
        bound_ms: row.get(5)?,
    })
}

fn validated_binding(raw: RawBinding) -> Journalled<BindingRow> {
    Ok(BindingRow {
        session_id: checked_row_id(raw.session_id, "session_id")?,
        kind: BindingKind::parse(&raw.kind)?,
        name: checked_key(raw.name, "binding_name")?,
        version: checked_bounded(raw.version, MAX_VERSION_BYTES, "binding_version")?,
        value_digest: checked_digest(raw.value_digest, "value_digest")?,
        bound_ms: checked_time(raw.bound_ms, "bound_ms")?,
    })
}

fn read_binding(
    connection: &Connection,
    session_id: i64,
    kind: BindingKind,
    name: &str,
) -> Journalled<Option<BindingRow>> {
    let raw = connection
        .query_row(
            "SELECT session_id, kind, name, version, value_digest, bound_ms
             FROM provider_bindings WHERE session_id = ?1 AND kind = ?2 AND name = ?3",
            params![session_id, kind.as_str(), name],
            raw_binding,
        )
        .optional()?;
    raw.map(validated_binding).transpose()
}

fn read_bindings(
    connection: &Connection,
    session_id: i64,
    kind: BindingKind,
) -> Journalled<Vec<BindingRow>> {
    let mut statement = connection.prepare(
        "SELECT session_id, kind, name, version, value_digest, bound_ms
         FROM provider_bindings WHERE session_id = ?1 AND kind = ?2 ORDER BY name",
    )?;
    let rows = statement.query_map(params![session_id, kind.as_str()], raw_binding)?;
    let mut bindings = Vec::new();
    for raw in rows {
        bindings.push(validated_binding(raw?)?);
    }
    Ok(bindings)
}

struct RawApproval {
    session_id: i64,
    approval_key: String,
    decision: String,
    deciding_actor: String,
    decided_ms: i64,
}

fn raw_approval(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawApproval> {
    Ok(RawApproval {
        session_id: row.get(0)?,
        approval_key: row.get(1)?,
        decision: row.get(2)?,
        deciding_actor: row.get(3)?,
        decided_ms: row.get(4)?,
    })
}

fn validated_approval(raw: RawApproval) -> Journalled<ApprovalRow> {
    Ok(ApprovalRow {
        session_id: checked_row_id(raw.session_id, "session_id")?,
        approval_key: checked_key(raw.approval_key, "approval_key")?,
        decision: ApprovalDecision::parse(&raw.decision)?,
        deciding_actor: checked_key(raw.deciding_actor, "deciding_actor")?,
        decided_ms: checked_time(raw.decided_ms, "decided_ms")?,
    })
}

fn read_approval(
    connection: &Connection,
    session_id: i64,
    approval_key: &str,
) -> Journalled<Option<ApprovalRow>> {
    let raw = connection
        .query_row(
            "SELECT session_id, approval_key, decision, deciding_actor, decided_ms
             FROM provider_approvals WHERE session_id = ?1 AND approval_key = ?2",
            params![session_id, approval_key],
            raw_approval,
        )
        .optional()?;
    raw.map(validated_approval).transpose()
}

fn read_approvals(connection: &Connection, session_id: i64) -> Journalled<Vec<ApprovalRow>> {
    let mut statement = connection.prepare(
        "SELECT session_id, approval_key, decision, deciding_actor, decided_ms
         FROM provider_approvals WHERE session_id = ?1 ORDER BY approval_key",
    )?;
    let rows = statement.query_map([session_id], raw_approval)?;
    let mut approvals = Vec::new();
    for raw in rows {
        approvals.push(validated_approval(raw?)?);
    }
    Ok(approvals)
}

fn secure_path(path: &Path) -> Journalled<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => ProviderJournalError::Io(io),
        other => ProviderJournalError::InsecurePath(other.to_string()),
    })
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Journalled<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == PROVIDER_JOURNAL_SCHEMA_VERSION {
        return Ok(());
    }
    if version == 1 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA_V2)?;
        transaction.execute_batch(SCHEMA_V3)?;
        transaction.pragma_update(None, "user_version", PROVIDER_JOURNAL_SCHEMA_VERSION)?;
        transaction.commit()?;
        return Ok(());
    }
    if version == 2 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA_V3)?;
        transaction.pragma_update(None, "user_version", PROVIDER_JOURNAL_SCHEMA_VERSION)?;
        transaction.commit()?;
        return Ok(());
    }
    if version != 0 {
        return Err(ProviderJournalError::SchemaVersion {
            found: version,
            supported: PROVIDER_JOURNAL_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(ProviderJournalError::SchemaVersion {
            found: 0,
            supported: PROVIDER_JOURNAL_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.execute_batch(SCHEMA_V2)?;
    transaction.execute_batch(SCHEMA_V3)?;
    transaction.pragma_update(None, "user_version", PROVIDER_JOURNAL_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn validate_settlement(settlement: &RequestSettlement<'_>) -> Journalled<()> {
    validate_key(settlement.request_key, "request_key")?;
    match settlement.outcome {
        SettledOutcome::Answered { response_digest } => {
            validate_digest(response_digest, "response_digest")
        }
        SettledOutcome::Failed { reason } => {
            validate_bounded(reason, MAX_REASON_BYTES, "failure_reason")
        }
    }
}

fn validate_cursor(advance: &CursorAdvance<'_>) -> Journalled<()> {
    validate_key(advance.stream, "stream")?;
    validate_time(advance.now_ms, "now_ms")?;
    validate_row_id(advance.session_id, "session_id")?;
    to_db_u64(advance.sequence, "sequence").map(|_| ())
}

fn validate_turn_usage(usage: &TurnUsage<'_>) -> Journalled<()> {
    validate_bounded(usage.gen_ai_system, MAX_KIND_BYTES, "gen_ai_system")?;
    if let Some(model) = usage.request_model {
        validate_bounded(model, MAX_VERSION_BYTES, "request_model")?;
    }
    if let Some(model) = usage.response_model {
        validate_bounded(model, MAX_VERSION_BYTES, "response_model")?;
    }
    to_db_u64(usage.input_tokens, "input_tokens")?;
    to_db_u64(usage.cached_input_tokens, "cached_input_tokens")?;
    to_db_u64(usage.output_tokens, "output_tokens")?;
    Ok(())
}

fn validate_key(value: &str, field: &'static str) -> Journalled<()> {
    validate_bounded(value, MAX_KEY_BYTES, field)
}

fn validate_bounded(value: &str, limit: usize, field: &'static str) -> Journalled<()> {
    if value.is_empty() || value.len() > limit || value.chars().any(char::is_control) {
        return Err(ProviderJournalError::InvalidField(field));
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Journalled<()> {
    if value.len() != DIGEST_CHARS
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProviderJournalError::InvalidField(field));
    }
    Ok(())
}

fn validate_time(value: i64, field: &'static str) -> Journalled<()> {
    if value < 0 {
        return Err(ProviderJournalError::InvalidField(field));
    }
    Ok(())
}

fn validate_row_id(value: i64, field: &'static str) -> Journalled<()> {
    if value <= 0 {
        return Err(ProviderJournalError::InvalidField(field));
    }
    Ok(())
}

fn checked_key(value: String, field: &'static str) -> Journalled<String> {
    checked_bounded(value, MAX_KEY_BYTES, field)
}

fn checked_bounded(value: String, limit: usize, field: &'static str) -> Journalled<String> {
    validate_bounded(&value, limit, field).map_err(|_| corrupt_field(field))?;
    Ok(value)
}

fn checked_digest(value: String, field: &'static str) -> Journalled<String> {
    validate_digest(&value, field).map_err(|_| corrupt_field(field))?;
    Ok(value)
}

fn checked_time(value: i64, field: &'static str) -> Journalled<i64> {
    validate_time(value, field).map_err(|_| corrupt_field(field))?;
    Ok(value)
}

fn checked_row_id(value: i64, field: &'static str) -> Journalled<i64> {
    validate_row_id(value, field).map_err(|_| corrupt_field(field))?;
    Ok(value)
}

fn checked_revision(value: i64) -> Journalled<u64> {
    let revision = from_db_u64(value, "revision").map_err(|_| corrupt_field("revision"))?;
    if revision == 0 {
        return Err(corrupt_field("revision"));
    }
    Ok(revision)
}

/// Map a validation field onto its stable corruption invariant name.
///
/// Read paths never reuse `InvalidField`: a bad stored row is corruption the
/// caller cannot have caused, and the two must not be confused.
fn corrupt_field(field: &'static str) -> ProviderJournalError {
    ProviderJournalError::Corrupt(field)
}

fn require_revision(expected: u64, durable: u64) -> Journalled<()> {
    if expected != durable {
        return Err(ProviderJournalError::RevisionMismatch { expected, durable });
    }
    Ok(())
}

fn next_revision(revision: u64) -> Journalled<u64> {
    revision
        .checked_add(1)
        .ok_or(ProviderJournalError::InvalidField("revision"))
}

fn require_single_row(changed: usize, row: &'static str) -> Journalled<()> {
    if changed == 1 {
        return Ok(());
    }
    Err(ProviderJournalError::Corrupt(row))
}

fn to_db_u64(value: u64, field: &'static str) -> Journalled<i64> {
    i64::try_from(value).map_err(|_| ProviderJournalError::InvalidField(field))
}

fn from_db_u64(value: i64, field: &'static str) -> Journalled<u64> {
    u64::try_from(value).map_err(|_| ProviderJournalError::InvalidField(field))
}
