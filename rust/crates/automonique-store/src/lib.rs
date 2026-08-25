// SPDX-License-Identifier: Elastic-2.0

//! Durable, single-writer product state for Automonique.
//!
//! The store owns SQLite transaction boundaries. Callers provide time and
//! stable transport/action keys so retries remain deterministic and tests do
//! not depend on an ambient clock.

#![forbid(unsafe_code)]

pub mod agent_memory;
pub mod approval_ledger;
pub mod approval_requests;
pub mod audit_chain;
pub mod automation_store;
pub mod batch_registry;
pub mod cancel_ledger;
pub mod context_memory;
pub mod durable_scheduler;
pub mod generation_audit;
pub mod improvements;
pub mod operator_members;
pub mod platform_store;
pub mod provider_deployments;
pub mod provider_journal;
pub mod run_index;
pub mod run_submissions;
pub mod shadow_comparisons;
pub mod slack_ingress;
pub mod slack_interactions;
pub mod sqlite_policy;
pub mod support_tickets;

use std::error::Error;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use automonique_protocol::provenance::{CausationId, CorrelationId, Provenance, TraceId};
use nix::unistd::geteuid;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

/// The only database schema this build can read and write.
pub const SCHEMA_VERSION: u32 = 10;
/// SQLite lock contention is bounded rather than waiting indefinitely.
pub const BUSY_TIMEOUT: Duration = sqlite_policy::AUTHORITY_BUSY_TIMEOUT;

/// Longest accepted inbox `transport_key`, in bytes.
///
/// Deliberately wider than the 256-byte bound every other identifier in this
/// store carries. That bound is the default for names the store itself mints,
/// parses or matches against a vocabulary; the inbox key is none of those. It
/// is an opaque coordinate the transport supplies, stored whole, compared whole
/// by `UNIQUE (transport, transport_key)` and never split — so its length is a
/// storage question, not a correctness one, and a wider bound admits no shape
/// the narrower one was protecting against.
///
/// It has to be wider. `automonique-transports` builds a Slack key as
/// `slack:{app}:{team}:{channel}:{ts}` from four coordinates of at most 128
/// bytes each, reaching `9 + 4 * 128 = 521` bytes, so a 256-byte inbox would
/// refuse legitimate deliveries from long-coordinate workspaces outright. This
/// matches [`slack_ingress::MAX_SOURCE_KEY_BYTES`](crate::slack_ingress::MAX_SOURCE_KEY_BYTES)
/// exactly: the inbox admits precisely the keys the ingress log can already
/// record, and nothing beyond them.
pub const MAX_TRANSPORT_KEY_BYTES: usize = 640;

const MAX_ID_BYTES: usize = 256;
const MAX_KIND_BYTES: usize = 128;
const MAX_PAYLOAD_BYTES: usize = 1_048_576;
const MAX_TELEGRAM_BATCH_UPDATES: usize = 100;
const MAX_TELEGRAM_CONTENT_BYTES: usize = 16 * 1024;

#[cfg(test)]
const SCHEMA_V1: &str = r#"
CREATE TABLE generations (
    generation_id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    state TEXT NOT NULL CHECK (state IN ('active')),
    lease_holder TEXT NOT NULL,
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch >= 1),
    lease_expires_ms INTEGER NOT NULL CHECK (lease_expires_ms >= 0)
) STRICT;

CREATE TABLE inbox (
    inbox_id INTEGER PRIMARY KEY,
    transport TEXT NOT NULL,
    transport_key TEXT NOT NULL,
    payload BLOB NOT NULL,
    received_ms INTEGER NOT NULL CHECK (received_ms >= 0),
    revision INTEGER NOT NULL CHECK (revision = 1),
    UNIQUE (transport, transport_key)
) STRICT;

CREATE TABLE runs (
    run_id INTEGER PRIMARY KEY,
    claim_key TEXT NOT NULL UNIQUE,
    inbox_id INTEGER NOT NULL REFERENCES inbox(inbox_id),
    scope TEXT NOT NULL,
    generation_id TEXT NOT NULL REFERENCES generations(generation_id),
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch >= 1),
    state TEXT NOT NULL CHECK (state IN ('running', 'succeeded', 'failed', 'abandoned')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    started_ms INTEGER NOT NULL CHECK (started_ms >= 0),
    finished_ms INTEGER,
    terminal_payload BLOB,
    outbox_intent_key TEXT
) STRICT;

CREATE TABLE work_locks (
    scope TEXT PRIMARY KEY,
    run_id INTEGER NOT NULL UNIQUE REFERENCES runs(run_id),
    generation_id TEXT NOT NULL REFERENCES generations(generation_id),
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch >= 1),
    expires_ms INTEGER NOT NULL CHECK (expires_ms >= 0)
) STRICT;

CREATE TABLE domain_events (
    event_id INTEGER PRIMARY KEY,
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    occurred_ms INTEGER NOT NULL CHECK (occurred_ms >= 0),
    kind TEXT NOT NULL,
    payload BLOB NOT NULL,
    UNIQUE (aggregate_kind, aggregate_id, revision)
) STRICT;

CREATE TABLE outbox (
    outbox_id INTEGER PRIMARY KEY,
    intent_key TEXT NOT NULL UNIQUE,
    event_id INTEGER NOT NULL REFERENCES domain_events(event_id),
    kind TEXT NOT NULL,
    payload BLOB NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'delivered')),
    created_ms INTEGER NOT NULL CHECK (created_ms >= 0)
) STRICT;
"#;

const SCHEMA_V2: &str = r#"
CREATE TABLE generations (
    generation_id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    state TEXT NOT NULL CHECK (state IN ('active')),
    lease_holder TEXT NOT NULL,
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch >= 1),
    lease_expires_ms INTEGER NOT NULL CHECK (lease_expires_ms >= 0)
) STRICT;

CREATE TABLE inbox (
    inbox_id INTEGER PRIMARY KEY,
    transport TEXT NOT NULL,
    transport_key TEXT NOT NULL,
    scope TEXT NOT NULL,
    payload BLOB NOT NULL,
    received_ms INTEGER NOT NULL CHECK (received_ms >= 0),
    state TEXT NOT NULL CHECK (state IN ('pending', 'claimed', 'completed', 'failed')),
    claimed_run_id INTEGER REFERENCES runs(run_id),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    UNIQUE (transport, transport_key)
) STRICT;

CREATE TABLE runs (
    run_id INTEGER PRIMARY KEY,
    claim_key TEXT NOT NULL UNIQUE,
    inbox_id INTEGER NOT NULL UNIQUE REFERENCES inbox(inbox_id),
    scope TEXT NOT NULL,
    generation_id TEXT NOT NULL REFERENCES generations(generation_id),
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch >= 1),
    state TEXT NOT NULL CHECK (state IN ('running', 'succeeded', 'failed', 'abandoned')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    started_ms INTEGER NOT NULL CHECK (started_ms >= 0),
    finished_ms INTEGER,
    terminal_payload BLOB,
    outbox_intent_key TEXT
) STRICT;

CREATE TABLE work_locks (
    scope TEXT PRIMARY KEY,
    run_id INTEGER NOT NULL UNIQUE REFERENCES runs(run_id),
    generation_id TEXT NOT NULL REFERENCES generations(generation_id),
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch >= 1),
    expires_ms INTEGER NOT NULL CHECK (expires_ms >= 0)
) STRICT;

CREATE TABLE domain_events (
    event_id INTEGER PRIMARY KEY,
    aggregate_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    occurred_ms INTEGER NOT NULL CHECK (occurred_ms >= 0),
    kind TEXT NOT NULL,
    payload BLOB NOT NULL,
    UNIQUE (aggregate_kind, aggregate_id, revision)
) STRICT;

CREATE TABLE outbox (
    outbox_id INTEGER PRIMARY KEY,
    intent_key TEXT NOT NULL UNIQUE,
    event_id INTEGER NOT NULL REFERENCES domain_events(event_id),
    kind TEXT NOT NULL,
    payload BLOB NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'delivered')),
    created_ms INTEGER NOT NULL CHECK (created_ms >= 0)
) STRICT;
"#;

const MIGRATE_V1_TO_V2: &str = r#"
CREATE TABLE inbox_v2 (
    inbox_id INTEGER PRIMARY KEY,
    transport TEXT NOT NULL,
    transport_key TEXT NOT NULL,
    scope TEXT NOT NULL,
    payload BLOB NOT NULL,
    received_ms INTEGER NOT NULL CHECK (received_ms >= 0),
    state TEXT NOT NULL CHECK (state IN ('pending', 'claimed', 'completed', 'failed')),
    claimed_run_id INTEGER REFERENCES runs(run_id),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    UNIQUE (transport, transport_key)
) STRICT;
INSERT INTO inbox_v2
    (inbox_id, transport, transport_key, scope, payload, received_ms, state,
     claimed_run_id, revision)
SELECT inbox_id, transport, transport_key, 'legacy:' || inbox_id, payload,
       received_ms, 'pending', NULL, revision
FROM inbox;
DROP TABLE inbox;
ALTER TABLE inbox_v2 RENAME TO inbox;
UPDATE inbox SET
    scope = (SELECT scope FROM runs WHERE runs.inbox_id = inbox.inbox_id),
    claimed_run_id = (SELECT run_id FROM runs WHERE runs.inbox_id = inbox.inbox_id),
    state = CASE (SELECT state FROM runs WHERE runs.inbox_id = inbox.inbox_id)
        WHEN 'succeeded' THEN 'completed'
        WHEN 'failed' THEN 'failed'
        ELSE 'claimed'
    END,
    revision = CASE
        WHEN (SELECT state FROM runs WHERE runs.inbox_id = inbox.inbox_id)
             IN ('succeeded', 'failed') THEN 3
        ELSE 2
    END
WHERE EXISTS (SELECT 1 FROM runs WHERE runs.inbox_id = inbox.inbox_id);
INSERT INTO domain_events
    (aggregate_kind, aggregate_id, revision, schema_version, occurred_ms, kind, payload)
SELECT 'inbox', CAST(i.inbox_id AS TEXT), 2, 1, r.started_ms,
       'inbox.claimed', CAST(r.run_id AS BLOB)
FROM inbox i JOIN runs r ON r.inbox_id = i.inbox_id;
INSERT INTO domain_events
    (aggregate_kind, aggregate_id, revision, schema_version, occurred_ms, kind, payload)
SELECT 'inbox', CAST(i.inbox_id AS TEXT), 3, 1, r.finished_ms,
       CASE r.state WHEN 'succeeded' THEN 'inbox.completed' ELSE 'inbox.failed' END,
       COALESCE(r.terminal_payload, CAST(r.state AS BLOB))
FROM inbox i JOIN runs r ON r.inbox_id = i.inbox_id
WHERE r.state IN ('succeeded', 'failed');
CREATE UNIQUE INDEX runs_one_per_inbox ON runs(inbox_id);
"#;

const MIGRATE_V2_TO_V3: &str = r#"
CREATE TABLE telegram_offsets (
    bot_id INTEGER PRIMARY KEY CHECK (bot_id > 0),
    next_offset BLOB NOT NULL CHECK (
        typeof(next_offset) = 'blob' AND length(next_offset) = 8
    ),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    updated_ms INTEGER NOT NULL CHECK (updated_ms >= 0)
) STRICT;

CREATE TABLE telegram_ingress (
    bot_id INTEGER NOT NULL REFERENCES telegram_offsets(bot_id),
    update_id BLOB NOT NULL CHECK (
        typeof(update_id) = 'blob' AND length(update_id) = 8
    ),
    source_key TEXT NOT NULL UNIQUE,
    scope TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK (
        disposition IN ('admitted', 'denied', 'ignored_unsupported')
    ),
    content BLOB,
    received_ms INTEGER NOT NULL CHECK (received_ms >= 0),
    PRIMARY KEY (bot_id, update_id),
    CHECK (
        (disposition = 'admitted' AND content IS NOT NULL
         AND length(content) > 0 AND length(content) <= 16384)
        OR
        (disposition != 'admitted' AND content IS NULL)
    )
) STRICT;

CREATE TABLE telegram_batches (
    bot_id INTEGER NOT NULL REFERENCES telegram_offsets(bot_id),
    expected_offset BLOB NOT NULL CHECK (
        typeof(expected_offset) = 'blob' AND length(expected_offset) = 8
    ),
    next_offset BLOB NOT NULL CHECK (
        typeof(next_offset) = 'blob' AND length(next_offset) = 8
    ),
    disposition_count INTEGER NOT NULL CHECK (disposition_count > 0),
    received_ms INTEGER NOT NULL CHECK (received_ms >= 0),
    PRIMARY KEY (bot_id, expected_offset),
    UNIQUE (bot_id, next_offset)
) STRICT;
"#;

const MIGRATE_V3_TO_V4: &str = r#"
ALTER TABLE outbox RENAME TO outbox_v3;
CREATE TABLE outbox (
    outbox_id INTEGER PRIMARY KEY,
    intent_key TEXT NOT NULL UNIQUE,
    event_id INTEGER NOT NULL REFERENCES domain_events(event_id),
    transport TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload BLOB NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('pending', 'in_flight', 'delivered', 'dead_lettered')
    ),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    available_ms INTEGER NOT NULL CHECK (available_ms >= 0),
    lease_token TEXT,
    lease_generation_id TEXT REFERENCES generations(generation_id),
    lease_holder TEXT,
    lease_epoch INTEGER CHECK (lease_epoch >= 1),
    lease_expires_ms INTEGER CHECK (lease_expires_ms >= 0),
    delivery_receipt_key TEXT UNIQUE,
    delivered_ms INTEGER CHECK (delivered_ms >= 0),
    last_error TEXT,
    created_ms INTEGER NOT NULL CHECK (created_ms >= 0),
    CHECK (
        (state = 'pending' AND lease_token IS NULL
         AND lease_generation_id IS NULL AND lease_holder IS NULL
         AND lease_epoch IS NULL AND lease_expires_ms IS NULL
         AND delivery_receipt_key IS NULL AND delivered_ms IS NULL)
        OR
        (state = 'in_flight' AND lease_token IS NOT NULL
         AND lease_generation_id IS NOT NULL AND lease_holder IS NOT NULL
         AND lease_epoch IS NOT NULL AND lease_expires_ms IS NOT NULL
         AND delivery_receipt_key IS NULL AND delivered_ms IS NULL)
        OR
        (state = 'delivered'
         AND delivery_receipt_key IS NOT NULL AND delivered_ms IS NOT NULL)
        OR
        (state = 'dead_lettered' AND delivery_receipt_key IS NULL
         AND delivered_ms IS NOT NULL)
    )
) STRICT;
INSERT INTO outbox
    (outbox_id, intent_key, event_id, transport, kind, payload, state,
     revision, attempts, available_ms, lease_token, lease_generation_id,
     lease_holder, lease_epoch, lease_expires_ms, delivery_receipt_key,
     delivered_ms, last_error, created_ms)
SELECT outbox_id, intent_key, event_id,
       CASE WHEN instr(kind, '.') > 1 THEN substr(kind, 1, instr(kind, '.') - 1)
            ELSE kind END,
       kind, payload, state, 1, 0, created_ms,
       NULL, NULL, NULL, NULL, NULL,
       CASE WHEN state = 'delivered' THEN 'legacy-receipt:' || outbox_id ELSE NULL END,
       CASE WHEN state = 'delivered' THEN created_ms ELSE NULL END,
       NULL, created_ms
FROM outbox_v3;
DROP TABLE outbox_v3;
CREATE INDEX outbox_ready_fifo
    ON outbox(transport, kind, created_ms, outbox_id);
"#;

const MIGRATE_V4_TO_V5: &str = r#"
CREATE TABLE telegram_poller_leases (
    bot_id INTEGER PRIMARY KEY CHECK (bot_id > 0),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    generation_id TEXT NOT NULL REFERENCES generations(generation_id),
    holder_id TEXT NOT NULL,
    authority_lease_epoch INTEGER NOT NULL CHECK (authority_lease_epoch >= 1),
    poller_epoch INTEGER NOT NULL CHECK (poller_epoch >= 1),
    expires_ms INTEGER NOT NULL CHECK (expires_ms >= 0)
) STRICT;
ALTER TABLE telegram_batches ADD COLUMN batch_digest BLOB CHECK (
    batch_digest IS NULL OR (typeof(batch_digest) = 'blob' AND length(batch_digest) = 32)
);
ALTER TABLE telegram_batches ADD COLUMN poller_generation_id TEXT;
ALTER TABLE telegram_batches ADD COLUMN poller_holder_id TEXT;
ALTER TABLE telegram_batches ADD COLUMN poller_epoch INTEGER CHECK (
    poller_epoch IS NULL OR poller_epoch >= 1
);
CREATE INDEX telegram_poller_owner
    ON telegram_poller_leases(generation_id, holder_id, poller_epoch);
"#;

/// Operator intake pauses, in the main database beside the generation they scope.
///
/// A pause is scheduler state: it decides whether the very next intake write in
/// this database is admitted. Putting it in a sibling log the way run
/// submissions are stored would make the gate and the thing it gates commit
/// separately, so the row lives here and is fenced by the same generation lease
/// as every other mutation.
///
/// Rows are never deleted. A resumed pause keeps its actor, reason and both
/// timestamps, which is the whole point of writing it down: the history of who
/// closed intake and why survives the resume that reopened it. The partial
/// unique index is what makes "paused" a question with one answer — at most one
/// unresumed row per generation — while still admitting an unbounded sequence
/// of closed pause episodes for the same generation over time.
const MIGRATE_V5_TO_V6: &str = r#"
CREATE TABLE intake_pauses (
    pause_id INTEGER PRIMARY KEY,
    generation_id TEXT NOT NULL REFERENCES generations(generation_id),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    paused_at_ms INTEGER NOT NULL CHECK (paused_at_ms >= 0),
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    resumed_at_ms INTEGER CHECK (resumed_at_ms IS NULL OR resumed_at_ms >= 0),
    resume_actor TEXT,
    CHECK (
        (resumed_at_ms IS NULL AND resume_actor IS NULL)
        OR (resumed_at_ms IS NOT NULL AND resume_actor IS NOT NULL)
    )
) STRICT;
CREATE UNIQUE INDEX intake_pauses_one_live_per_generation
    ON intake_pauses(generation_id) WHERE resumed_at_ms IS NULL;
"#;

/// Transport pauses a remote peer imposed, in the database the transport's own
/// offsets and outbox already live in.
///
/// # Why this is durable at all
///
/// Because a `429` is about the *bot*, not about the request that met it. A
/// pause held only in memory would be forgotten by the next restart, and the
/// first thing a restarted daemon does is poll — straight back into the rate
/// limit it was told to wait out, from a peer that has by then started counting
/// the offence again.
///
/// # One row per (transport, scope), updated in place
///
/// Unlike [`intake_pauses`](MIGRATE_V5_TO_V6), which keeps an episode per pause
/// because *who closed intake and why* is history worth having, a transport
/// pause is a deadline and nothing else. There is exactly one answer to "may
/// this bot call Telegram right now", so there is exactly one row, and a second
/// `429` moves its deadline rather than opening a second episode. The revision
/// counts the moves, which is what makes the domain event chain over it total.
///
/// `resume_after_ms` is an instant on the same clock the offsets and leases use.
/// A row whose deadline has passed is simply not live; nothing sweeps it,
/// because a stale deadline answers the question correctly on its own.
const MIGRATE_V6_TO_V7: &str = r#"
CREATE TABLE transport_pauses (
    transport TEXT NOT NULL,
    scope TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    paused_at_ms INTEGER NOT NULL CHECK (paused_at_ms >= 0),
    resume_after_ms INTEGER NOT NULL CHECK (resume_after_ms >= 0),
    reason TEXT NOT NULL,
    PRIMARY KEY (transport, scope),
    CHECK (resume_after_ms >= paused_at_ms)
) STRICT;
"#;

/// Expand-only provenance columns. Historical rows remain explicitly unknown.
const MIGRATE_V7_TO_V8: &str = r#"
ALTER TABLE inbox ADD COLUMN trace_id TEXT;
ALTER TABLE inbox ADD COLUMN correlation_id TEXT;
ALTER TABLE inbox ADD COLUMN causation_id TEXT;
ALTER TABLE runs ADD COLUMN trace_id TEXT;
ALTER TABLE runs ADD COLUMN correlation_id TEXT;
ALTER TABLE runs ADD COLUMN causation_id TEXT;
ALTER TABLE domain_events ADD COLUMN trace_id TEXT;
ALTER TABLE domain_events ADD COLUMN correlation_id TEXT;
ALTER TABLE domain_events ADD COLUMN causation_id TEXT;
ALTER TABLE outbox ADD COLUMN trace_id TEXT;
ALTER TABLE outbox ADD COLUMN correlation_id TEXT;
ALTER TABLE outbox ADD COLUMN causation_id TEXT;
ALTER TABLE telegram_ingress ADD COLUMN trace_id TEXT;
ALTER TABLE telegram_ingress ADD COLUMN correlation_id TEXT;
ALTER TABLE telegram_ingress ADD COLUMN causation_id TEXT;
CREATE INDEX domain_events_by_trace ON domain_events(trace_id, event_id);
CREATE INDEX outbox_by_trace ON outbox(trace_id, outbox_id);
"#;

/// Bind generation ownership to one kernel boot and one exact process.
///
/// Existing leases are expired during migration. Their owner identity was
/// never recorded, so carrying them forward as live would turn an absence of
/// evidence into authority. Subordinate leases remain as reconciliation
/// evidence but become expired at the same boundary.
const MIGRATE_V8_TO_V9: &str = r#"
ALTER TABLE generations ADD COLUMN boot_id TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE generations ADD COLUMN holder_pid INTEGER NOT NULL DEFAULT 0
    CHECK (holder_pid >= 0);
ALTER TABLE generations ADD COLUMN holder_starttime INTEGER NOT NULL DEFAULT 0
    CHECK (holder_starttime >= 0);
UPDATE generations SET lease_expires_ms = 0;
UPDATE work_locks SET expires_ms = 0;
UPDATE telegram_poller_leases SET expires_ms = 0;
UPDATE outbox SET lease_expires_ms = 0 WHERE state = 'in_flight';
"#;

/// Change every lease deadline from caller wall time to absolute Linux
/// `CLOCK_BOOTTIME` milliseconds. Values in the old domain are deliberately
/// not converted: no conversion can recover the sampling relationship, so
/// every outstanding lease is expired at the boundary.
const MIGRATE_V9_TO_V10: &str = r#"
UPDATE generations SET lease_expires_ms = 0;
UPDATE work_locks SET expires_ms = 0;
UPDATE telegram_poller_leases SET expires_ms = 0;
UPDATE outbox SET lease_expires_ms = 0 WHERE state = 'in_flight';
"#;

/// Source of absolute lease-authority time.
///
/// Audit timestamps remain caller-supplied Unix milliseconds. A daemon opens
/// the store with this source so lease comparisons and deadline arithmetic
/// cannot consume wall time. [`Store::open`] retains caller-supplied time for
/// deterministic fixtures and non-daemon compatibility callers.
pub trait LeaseTimeSource: Send + Sync {
    /// Current milliseconds from the boot-inclusive monotonic clock.
    fn now_boottime_ms(&self) -> Result<i64, &'static str>;
}

/// A durable store error with stable refusal categories.
#[derive(Debug)]
pub enum StoreError {
    /// The database path or its containing directory is not private and owned.
    InsecurePath(String),
    /// The database schema is absent from a non-empty database or unsupported.
    SchemaVersion { found: u32, supported: u32 },
    /// Historical rows are ambiguous and cannot be migrated safely.
    MigrationInvariant(&'static str),
    /// A caller-provided field is empty, over-long, malformed, or out of range.
    InvalidField(&'static str),
    /// A stable retry key was reused for different input.
    IdempotencyConflict(&'static str),
    /// Another live generation owns the requested lease.
    LeaseHeld,
    /// The supplied lease holder/epoch is stale or expired.
    StaleEpoch,
    /// The caller's current authority lease is no longer live.
    AuthorityLost,
    /// The boot-inclusive lease clock could not be sampled.
    LeaseClock(&'static str),
    /// Another live run holds the requested scope.
    ScopeLocked,
    /// A prior run's scope lease expired and its execution must be reconciled.
    ReconciliationRequired { run_id: i64 },
    /// An in-flight external effect expired with an ambiguous outcome.
    OutboxReconciliationRequired { outbox_id: i64 },
    /// The referenced durable row does not exist.
    NotFound(&'static str),
    /// A terminal transition was retried with different content.
    AlreadyTerminal,
    /// The outbox key already belongs to another intent.
    OutboxConflict,
    /// Intake is already paused for this generation.
    ///
    /// The live decision travels with the refusal so a second operator learns
    /// who closed intake and why, rather than only that their own request lost.
    AlreadyPaused(Box<PauseRecord>),
    /// Intake is not paused for this generation, so there is nothing to resume.
    NotPaused,
    /// Filesystem failure while establishing the private database.
    Io(std::io::Error),
    /// SQLite rejected an operation.
    Sqlite(rusqlite::Error),
}

impl StoreError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::MigrationInvariant(_) => "migration_invariant",
            Self::InvalidField(_) => "invalid_field",
            Self::IdempotencyConflict(_) => "idempotency_conflict",
            Self::LeaseHeld => "lease_held",
            Self::StaleEpoch => "stale_epoch",
            Self::AuthorityLost => "authority_lost",
            Self::LeaseClock(_) => "lease_clock",
            Self::ScopeLocked => "scope_locked",
            Self::ReconciliationRequired { .. } => "reconciliation_required",
            Self::OutboxReconciliationRequired { .. } => "outbox_reconciliation_required",
            Self::NotFound(_) => "not_found",
            Self::AlreadyTerminal => "already_terminal",
            Self::OutboxConflict => "outbox_conflict",
            Self::AlreadyPaused(_) => "intake_already_paused",
            Self::NotPaused => "intake_not_paused",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => {
                write!(formatter, "database path is not private: {reason}")
            }
            Self::SchemaVersion { found, supported } => {
                write!(
                    formatter,
                    "database schema {found} is unsupported; expected {supported}"
                )
            }
            Self::MigrationInvariant(invariant) => {
                write!(
                    formatter,
                    "database migration invariant failed: {invariant}"
                )
            }
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::IdempotencyConflict(key) => write!(formatter, "stable key was reused: {key}"),
            Self::LeaseHeld => formatter.write_str("generation lease is held"),
            Self::StaleEpoch => formatter.write_str("generation lease epoch is stale or expired"),
            Self::AuthorityLost => formatter.write_str("current generation authority was lost"),
            Self::LeaseClock(category) => write!(formatter, "lease clock failed: {category}"),
            Self::ScopeLocked => formatter.write_str("work scope is locked"),
            Self::ReconciliationRequired { run_id } => {
                write!(
                    formatter,
                    "run {run_id} requires reconciliation before scope reuse"
                )
            }
            Self::OutboxReconciliationRequired { outbox_id } => {
                write!(
                    formatter,
                    "outbox intent {outbox_id} requires reconciliation"
                )
            }
            Self::NotFound(row) => write!(formatter, "durable row not found: {row}"),
            Self::AlreadyTerminal => {
                formatter.write_str("run is already terminal with different content")
            }
            Self::OutboxConflict => formatter.write_str("outbox intent key is already in use"),
            Self::AlreadyPaused(record) => write!(
                formatter,
                "intake is already paused for generation {} since {}",
                record.generation_id, record.paused_at_ms
            ),
            Self::NotPaused => formatter.write_str("intake is not paused"),
            Self::Io(error) => write!(formatter, "database filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite error: {error}"),
        }
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// A fenced generation lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationLease {
    pub generation_id: String,
    pub holder_id: String,
    pub epoch: u64,
    /// Absolute boot-inclusive deadline when the store has a lease-time source.
    pub expires_ms: i64,
    pub boot_id: String,
    pub holder_pid: u32,
    pub holder_starttime: u64,
}

/// Kernel identity bound to one generation lease holder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseOwnerIdentity<'a> {
    pub boot_id: &'a str,
    pub pid: u32,
    pub starttime: u64,
}

/// Parameters for acquiring a new or expired generation lease.
pub struct LeaseRequest<'a> {
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    /// Unix milliseconds for audit rows. Lease arithmetic uses the store's
    /// boot-inclusive source when one was supplied at open.
    pub now_ms: i64,
    pub ttl_ms: i64,
}

/// Parameters for renewing the exact lease epoch a worker already owns.
pub struct LeaseRenewal<'a> {
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub epoch: u64,
    /// Unix audit time; never a production lease-authority input.
    pub now_ms: i64,
    pub ttl_ms: i64,
}

/// Exact generation owner a startup sweep has proved is no longer live.
pub struct LeaseExpiryRequest<'a> {
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub epoch: u64,
    pub owner: LeaseOwnerIdentity<'a>,
    pub now_ms: i64,
}

/// One live operator decision to close intake for a generation.
///
/// `observed_ms` is the instant the record was read, not a property of the
/// pause: a pause has no expiry and does not lapse. It is carried so a caller
/// that reports "intake is paused" can say when it established that, the same
/// way [`StatusSnapshot`] carries its own observation instant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseRecord {
    pub pause_id: i64,
    pub generation_id: String,
    pub revision: u64,
    pub paused_at_ms: i64,
    pub actor: String,
    pub reason: String,
    pub observed_ms: i64,
}

/// Close intake for one generation under its live authority lease.
pub struct IntakePauseRequest<'a> {
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub authority_lease_epoch: u64,
    /// Who decided. Recorded verbatim; the store does not authenticate it.
    pub actor: &'a str,
    pub reason: &'a str,
    pub now_ms: i64,
}

/// Reopen intake by closing the exact live pause a caller has already read.
pub struct IntakeResumeRequest<'a> {
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub authority_lease_epoch: u64,
    /// Who reopened it. Recorded beside, never over, the pausing actor.
    pub actor: &'a str,
    /// Revision the caller observed on the live pause row.
    pub expected_revision: u64,
    pub now_ms: i64,
}

/// Durable identity and fencing revision of one pause decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntakePauseReceipt {
    pub pause_id: i64,
    pub revision: u64,
}

/// One remote peer's live refusal to be called, for one transport and scope.
///
/// Unlike [`PauseRecord`] this has an expiry, because the peer named one. A
/// record whose `resume_after_ms` is at or before the instant it was read is not
/// returned at all: see [`Store::transport_pause`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportPause {
    pub transport: String,
    /// The transport's own name for what was paused — for Telegram, the bot id.
    pub scope: String,
    pub revision: u64,
    pub paused_at_ms: i64,
    /// The instant calls may resume. Never in the past for a returned record.
    pub resume_after_ms: i64,
    /// A closed category the caller supplies. Recorded, never interpreted.
    pub reason: String,
    /// The instant this was read, so a reporter can say when it established it.
    pub observed_ms: i64,
}

/// Record that a peer refused one transport scope until an instant.
///
/// A pause is only ever *extended*: presenting an earlier deadline than the one
/// already recorded leaves the recorded one in force and still succeeds, because
/// a shorter interval arriving second says nothing about the longer one.
pub struct TransportPauseRequest<'a> {
    pub transport: &'a str,
    pub scope: &'a str,
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub authority_lease_epoch: u64,
    /// Closed category, from the caller's own vocabulary.
    pub reason: &'a str,
    pub now_ms: i64,
    /// Instant calls may resume. Must not precede `now_ms`.
    pub resume_after_ms: i64,
}

/// One stable transport delivery.
pub struct InboxSubmission<'a> {
    pub transport: &'a str,
    /// The transport's own delivery coordinate, opaque here and bounded by
    /// [`MAX_TRANSPORT_KEY_BYTES`] so a maximal Slack key fits.
    pub transport_key: &'a str,
    pub scope: &'a str,
    pub payload: &'a [u8],
    pub received_ms: i64,
}

/// The durable result of accepting a transport delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboxReceipt {
    pub inbox_id: i64,
    pub duplicate: bool,
}

/// Provenance persisted on one durable record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredProvenance {
    pub trace_id: String,
    pub correlation_id: String,
    pub causation_id: String,
}

/// One joined causal path from an external effect back to its input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CausalChain {
    pub inbox_id: i64,
    pub inbox_transport: String,
    pub inbox_transport_key: String,
    pub run_id: i64,
    pub event_id: i64,
    pub event_kind: String,
    pub outbox_id: i64,
    pub outbox_kind: String,
    pub provenance: StoredProvenance,
    pub run_causation_id: String,
    pub event_causation_id: String,
    pub outbox_causation_id: String,
}

/// Content-bearing or content-free durable Telegram disposition.
///
/// Denied and unsupported inputs cannot carry content in this type, preventing
/// their payload from crossing the store adapter seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelegramStoreDisposition<'a> {
    /// An allowlisted text or callback payload.
    Admitted { content: &'a [u8] },
    /// A well-formed input from a principal outside the exact allowlist.
    Denied,
    /// A fresh update outside the supported input shapes.
    IgnoredUnsupported,
}

/// One parsed Telegram update prepared for durable ingestion.
pub struct TelegramStoreUpdate<'a> {
    pub update_id: u64,
    pub source_key: &'a str,
    pub scope: &'a str,
    pub disposition: TelegramStoreDisposition<'a>,
}

/// Compare-and-set ingestion of one complete parsed Telegram batch.
pub struct TelegramBatchIngestion<'a> {
    pub bot_id: i64,
    pub expected_offset: u64,
    pub next_offset: u64,
    pub received_ms: i64,
    pub updates: &'a [TelegramStoreUpdate<'a>],
}

/// Durable result of an atomic Telegram batch ingestion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelegramBatchReceipt {
    pub next_offset: u64,
    pub disposition_count: usize,
    pub duplicate: bool,
}

/// Exact durable ownership of one bot's polling cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelegramPollerLease {
    pub bot_id: i64,
    pub generation_id: String,
    pub holder_id: String,
    pub epoch: u64,
    pub expires_ms: i64,
}

/// Acquire an absent or expired bot lease under a live generation lease.
pub struct TelegramPollerLeaseRequest<'a> {
    pub bot_id: i64,
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub authority_lease_epoch: u64,
    pub now_ms: i64,
    pub ttl_ms: i64,
}

/// Renew one exact bot lease under the same live generation authority.
pub struct TelegramPollerLeaseRenewal<'a> {
    pub bot_id: i64,
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub authority_lease_epoch: u64,
    pub poller_epoch: u64,
    pub expected_expires_ms: i64,
    pub now_ms: i64,
    pub ttl_ms: i64,
}

/// Exact live bot lease coordinates used for cursor reads and release.
pub struct TelegramPollerLeaseIdentity<'a> {
    pub bot_id: i64,
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub poller_epoch: u64,
    pub expected_expires_ms: i64,
    pub now_ms: i64,
}

/// Cursor observation fenced to the exact live bot lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelegramOffsetReceipt {
    pub bot_id: i64,
    pub lease_epoch: u64,
    pub next_offset: u64,
}

/// One atomic fenced disposition and cursor commit.
pub struct TelegramPollerCommit<'a> {
    pub lease: TelegramPollerLeaseIdentity<'a>,
    pub commit_before_ms: i64,
    pub batch_digest: [u8; 32],
    pub batch: TelegramBatchIngestion<'a>,
}

/// Runtime-compatible exact acknowledgement of a fenced batch commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelegramPollerCommitReceipt {
    pub bot_id: i64,
    pub lease_epoch: u64,
    pub next_offset: u64,
    pub disposition_count: usize,
    pub batch_digest: [u8; 32],
    pub duplicate: bool,
}

/// Content-minimizing persisted Telegram disposition for inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelegramDispositionSnapshot {
    pub source_key: String,
    pub scope: String,
    pub disposition: String,
    pub content: Option<Vec<u8>>,
    pub received_ms: i64,
}

/// One request to claim serialized work for a scope.
pub struct WorkClaim<'a> {
    pub claim_key: &'a str,
    pub inbox_id: i64,
    pub scope: &'a str,
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub lease_epoch: u64,
    pub now_ms: i64,
}

/// A claimed run and whether it was returned from a stable retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunClaim {
    pub run_id: i64,
    pub duplicate: bool,
}

/// Scheduler authority for one FIFO claim attempt.
pub struct SchedulerClaim<'a> {
    pub transport: &'a str,
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub lease_epoch: u64,
    pub now_ms: i64,
}

/// One FIFO inbox item atomically bound to a new or replayed run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduledRun {
    pub run_id: i64,
    pub inbox_id: i64,
    pub scope: String,
    pub duplicate: bool,
}

/// Owned input available only to the exact live generation that claimed it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedInbox {
    pub inbox_id: i64,
    pub transport: String,
    pub transport_key: String,
    pub scope: String,
    pub payload: Vec<u8>,
    pub received_ms: i64,
}

/// Closed authority decision for one ambiguous running item.
///
/// There is deliberately no requeue decision: missing durable outcome rows do
/// not prove that an external execution did not begin before a crash. A
/// successful completion is expressible only when the caller has independent
/// durable terminal evidence and supplies the exact terminal/event intent that
/// must be committed under the new generation's reconciliation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationDecision<'a> {
    /// Record an explicit failed outcome and one fake reconciliation receipt.
    Fail { reason: &'a str },
    /// Record a proven failed outcome with a caller-owned durable effect.
    FailWithIntent {
        reason: &'a str,
        outbox_kind: &'a str,
        outbox_payload: &'a [u8],
    },
    /// Record a proven successful outcome and its external-effect intent.
    Complete {
        event_kind: &'a str,
        event_payload: &'a [u8],
        outbox_kind: &'a str,
        outbox_payload: &'a [u8],
    },
}

/// Exact observation an operator must carry into a reconciliation decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationRunState {
    Running,
    Failed,
    Abandoned,
}

/// Closed inbox state observed during reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationInboxState {
    Pending,
    Claimed,
    Completed,
    Failed,
}

/// Exact observation an operator must carry into a reconciliation decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationEvidence {
    pub run_id: i64,
    pub inbox_id: i64,
    pub transport: String,
    pub transport_key: String,
    pub scope: String,
    pub inbox_state: ReconciliationInboxState,
    pub inbox_revision: u64,
    pub claimed_run_id: Option<i64>,
    pub run_state: ReconciliationRunState,
    pub run_revision: u64,
    pub generation_id: String,
    pub lease_epoch: u64,
    pub lock_generation_id: Option<String>,
    pub lock_epoch: Option<u64>,
    pub lock_expires_ms: Option<i64>,
    pub terminal_payload_present: bool,
    pub outbox_intent_key: Option<String>,
    pub outbox_count: u64,
    pub provenance: Option<StoredProvenance>,
}

/// Compare-and-set reconciliation request.
pub struct ReconciliationRequest<'a> {
    pub run_id: i64,
    pub authority_generation_id: &'a str,
    pub authority_holder_id: &'a str,
    pub authority_lease_epoch: u64,
    pub expected_generation_id: &'a str,
    pub expected_lease_epoch: u64,
    pub expected_revision: u64,
    pub decision_key: &'a str,
    pub now_ms: i64,
    pub decision: ReconciliationDecision<'a>,
}

/// Durable identities committed by one reconciliation decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconciliationReceipt {
    pub run_event_id: i64,
    pub inbox_event_id: i64,
    pub outbox_id: i64,
    pub duplicate: bool,
}

/// Closed terminal states accepted by the durable store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalState {
    Succeeded,
    Failed,
}

impl TerminalState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

/// The event and effect intent committed with a terminal run transition.
pub struct TerminalRun<'a> {
    pub run_id: i64,
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub lease_epoch: u64,
    pub expected_revision: u64,
    pub now_ms: i64,
    pub state: TerminalState,
    pub event_kind: &'a str,
    pub event_payload: &'a [u8],
    pub outbox_intent_key: &'a str,
    pub outbox_kind: &'a str,
    pub outbox_payload: &'a [u8],
}

/// Identity of an atomically committed terminal transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalReceipt {
    pub event_id: i64,
    pub outbox_id: i64,
    pub duplicate: bool,
}

/// One independently queued external-effect intent.
///
/// Unlike [`TerminalRun`], this does not finish a run. It is for effects whose
/// source was already committed by another durable subsystem (for example, a
/// transport ingress record) and still gives them the canonical outbox's
/// idempotency, fencing, leasing, retry and reconciliation semantics.
pub struct OutboxEnqueue<'a> {
    pub intent_key: &'a str,
    pub kind: &'a str,
    pub payload: &'a [u8],
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub lease_epoch: u64,
    pub now_ms: i64,
}

/// Durable identity returned when an independent outbox intent is queued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboxEnqueueReceipt {
    pub event_id: i64,
    pub outbox_id: i64,
    pub duplicate: bool,
}

/// Minimal persisted run state used by status and recovery code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunSnapshot {
    pub state: String,
    pub revision: u64,
}

/// Minimal persisted fake/external intent state used by recovery tests and
/// operator inspection. Payload bytes remain private to the store boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxSnapshot {
    pub kind: String,
    pub state: String,
}

/// Fenced FIFO claim for one external-effect transport and kind.
pub struct OutboxClaimRequest<'a> {
    pub transport: &'a str,
    pub kind: &'a str,
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub lease_epoch: u64,
    pub now_ms: i64,
    pub ttl_ms: i64,
}

/// Durable lease identity; payload is intentionally returned separately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxLease {
    pub outbox_id: i64,
    pub intent_key: String,
    pub transport: String,
    pub kind: String,
    pub lease_token: String,
    pub attempt: u64,
    pub retry_after_ms: i64,
    pub revision: u64,
    pub duplicate: bool,
}

/// Payload disclosed only after rechecking the exact live generation lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeasedOutboxPayload {
    pub outbox_id: i64,
    pub intent_key: String,
    pub payload: Vec<u8>,
}

pub struct OutboxPayloadRequest<'a> {
    pub outbox_id: i64,
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub lease_epoch: u64,
    pub lease_token: &'a str,
    pub now_ms: i64,
}

/// Exact success receipt for an in-flight external effect.
pub struct OutboxDelivery<'a> {
    pub outbox_id: i64,
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub lease_epoch: u64,
    pub lease_token: &'a str,
    pub expected_attempt: u64,
    pub receipt_key: &'a str,
    pub now_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxDeliveryReceipt {
    pub outbox_id: i64,
    pub receipt_key: String,
    pub revision: u64,
    pub duplicate: bool,
}

/// Closed negative outcome while the delivery lease is still live.
pub enum OutboxFailureDecision<'a> {
    Retry {
        reason: &'a str,
        retry_after_ms: i64,
    },
    DeadLetter {
        reason: &'a str,
    },
}

pub struct OutboxFailure<'a> {
    pub outbox_id: i64,
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub lease_epoch: u64,
    pub lease_token: &'a str,
    pub expected_attempt: u64,
    pub now_ms: i64,
    pub decision: OutboxFailureDecision<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxOutcomeReceipt {
    pub outbox_id: i64,
    pub state: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxReconciliationReceipt {
    pub outbox_id: i64,
    pub state: String,
    pub revision: u64,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxReconciliationEvidence {
    pub outbox_id: i64,
    pub intent_key: String,
    pub transport: String,
    pub kind: String,
    pub state: String,
    pub revision: u64,
    pub attempt: u64,
    pub lease_token: Option<String>,
    pub lease_generation_id: Option<String>,
    pub lease_holder: Option<String>,
    pub lease_epoch: Option<u64>,
    pub lease_expires_ms: Option<i64>,
    pub delivery_receipt_key: Option<String>,
    pub available_ms: i64,
    pub last_error: Option<String>,
    pub provenance: Option<StoredProvenance>,
}

/// An ambiguous effect may only be closed, never automatically retried.
pub enum OutboxReconciliationDecision<'a> {
    Delivered { receipt_key: &'a str },
    DeadLetter { reason: &'a str },
}

pub struct OutboxReconciliationRequest<'a> {
    pub outbox_id: i64,
    pub authority_generation_id: &'a str,
    pub authority_holder_id: &'a str,
    pub authority_lease_epoch: u64,
    pub expected_generation_id: &'a str,
    pub expected_lease_epoch: u64,
    pub expected_lease_token: &'a str,
    pub expected_attempt: u64,
    pub expected_revision: u64,
    pub now_ms: i64,
    pub decision: OutboxReconciliationDecision<'a>,
}

/// One generation row in a consistent operator-status snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationSnapshot {
    generation_id: String,
    revision: u64,
    state: String,
    holder_id: String,
    lease_epoch: u64,
    lease_expires_ms: i64,
    boot_id: String,
    holder_pid: u32,
    holder_starttime: u64,
}

impl GenerationSnapshot {
    #[must_use]
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }
    #[must_use]
    pub fn holder_id(&self) -> &str {
        &self.holder_id
    }
    #[must_use]
    pub const fn lease_epoch(&self) -> u64 {
        self.lease_epoch
    }
    #[must_use]
    pub const fn lease_expires_ms(&self) -> i64 {
        self.lease_expires_ms
    }
    #[must_use]
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }
    #[must_use]
    pub const fn holder_pid(&self) -> u32 {
        self.holder_pid
    }
    #[must_use]
    pub const fn holder_starttime(&self) -> u64 {
        self.holder_starttime
    }
}

/// Read-only database status observed from one SQLite snapshot transaction.
///
/// Time-classified fields are meaningful only when produced by
/// [`Store::status_snapshot_at`]. The compatibility wrapper records
/// `observed_ms = 0` and is aggregate-only.
/// ```compile_fail
/// use automonique_store::StatusSnapshot;
/// // Store snapshots are issued only by Store; external code cannot invent
/// // durable measurements with a struct literal.
/// let _forged = StatusSnapshot {
///     schema_version: 1, observed_ms: 1, generation: None, event_cursor: 0,
///     inbox_pending: 0, outbox_pending: 0, runs_running: 0,
///     runs_reconciliation_pending: 0, outbox_pending_ready: 0,
///     outbox_pending_delayed: 0, outbox_in_flight_live: 0,
///     outbox_in_flight_ambiguous: 0, outbox_delivered: 0,
///     outbox_dead_lettered: 0, outbox_oldest_ready_age_ms: 0,
///     telegram_pollers_live: 0, telegram_pollers_expired: 0,
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusSnapshot {
    schema_version: u32,
    observed_ms: i64,
    lease_observed_boottime_ms: i64,
    generation: Option<GenerationSnapshot>,
    event_cursor: u64,
    inbox_pending: u64,
    outbox_pending: u64,
    runs_running: u64,
    runs_reconciliation_pending: u64,
    outbox_pending_ready: u64,
    outbox_pending_delayed: u64,
    outbox_in_flight_live: u64,
    outbox_in_flight_ambiguous: u64,
    outbox_delivered: u64,
    outbox_dead_lettered: u64,
    outbox_oldest_ready_age_ms: u64,
    telegram_pollers_live: u64,
    telegram_pollers_expired: u64,
}

impl StatusSnapshot {
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }
    #[must_use]
    pub const fn observed_ms(&self) -> i64 {
        self.observed_ms
    }
    /// Boot-inclusive authority time used for every lease classification in
    /// this exact database snapshot.
    #[must_use]
    pub const fn lease_observed_boottime_ms(&self) -> i64 {
        self.lease_observed_boottime_ms
    }
    #[must_use]
    pub const fn generation(&self) -> Option<&GenerationSnapshot> {
        self.generation.as_ref()
    }
    #[must_use]
    pub const fn event_cursor(&self) -> u64 {
        self.event_cursor
    }
    #[must_use]
    pub const fn inbox_pending(&self) -> u64 {
        self.inbox_pending
    }
    #[must_use]
    pub const fn outbox_pending(&self) -> u64 {
        self.outbox_pending
    }
    #[must_use]
    pub const fn runs_running(&self) -> u64 {
        self.runs_running
    }
    #[must_use]
    pub const fn runs_reconciliation_pending(&self) -> u64 {
        self.runs_reconciliation_pending
    }
    #[must_use]
    pub const fn outbox_pending_ready(&self) -> u64 {
        self.outbox_pending_ready
    }
    #[must_use]
    pub const fn outbox_pending_delayed(&self) -> u64 {
        self.outbox_pending_delayed
    }
    #[must_use]
    pub const fn outbox_in_flight_live(&self) -> u64 {
        self.outbox_in_flight_live
    }
    #[must_use]
    pub const fn outbox_in_flight_ambiguous(&self) -> u64 {
        self.outbox_in_flight_ambiguous
    }
    #[must_use]
    pub const fn outbox_delivered(&self) -> u64 {
        self.outbox_delivered
    }
    #[must_use]
    pub const fn outbox_dead_lettered(&self) -> u64 {
        self.outbox_dead_lettered
    }
    #[must_use]
    pub const fn outbox_oldest_ready_age_ms(&self) -> u64 {
        self.outbox_oldest_ready_age_ms
    }
    #[must_use]
    pub const fn telegram_pollers_live(&self) -> u64 {
        self.telegram_pollers_live
    }
    #[must_use]
    pub const fn telegram_pollers_expired(&self) -> u64 {
        self.telegram_pollers_expired
    }
}

/// Product SQLite store. A daemon should own it from one dedicated actor.
pub struct Store {
    connection: Connection,
    path: PathBuf,
    lease_time_source: Option<Arc<dyn LeaseTimeSource>>,
}

impl Store {
    /// Open or initialize a database inside an existing private directory.
    ///
    /// The parent must be owned by the effective user and deny all group/other
    /// access. Existing database paths must be regular, owned, non-symlinks.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_inner(path.as_ref(), None)
    }

    /// Open a daemon store whose lease authority comes only from an absolute
    /// boot-inclusive clock. Caller `now_ms` values remain audit wall time.
    pub fn open_with_lease_time_source(
        path: impl AsRef<Path>,
        source: Arc<dyn LeaseTimeSource>,
    ) -> Result<Self, StoreError> {
        Self::open_inner(path.as_ref(), Some(source))
    }

    fn open_inner(
        path: &Path,
        lease_time_source: Option<Arc<dyn LeaseTimeSource>>,
    ) -> Result<Self, StoreError> {
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

        let open_flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = Connection::open_with_flags(path, open_flags)?;
        crate::sqlite_policy::configure_authoritative(&connection)?;
        initialize_or_validate_schema(&mut connection)?;

        Ok(Self {
            connection,
            path: path.to_path_buf(),
            lease_time_source,
        })
    }

    fn lease_now_ms(&self, caller_now_ms: i64) -> Result<i64, StoreError> {
        let now_ms = self.lease_time_source.as_ref().map_or_else(
            || Ok(caller_now_ms),
            |source| source.now_boottime_ms().map_err(StoreError::LeaseClock),
        )?;
        validate_time(now_ms)?;
        Ok(now_ms)
    }

    /// Observe lease-authority time without performing a durable operation.
    ///
    /// Runtime adapters use this to compare an in-memory deadline with the
    /// same clock domain that the store will use when it fences the eventual
    /// read or commit. Audit timestamps remain caller-supplied Unix time.
    pub fn observe_lease_now_ms(&self, caller_now_ms: i64) -> Result<i64, StoreError> {
        self.lease_now_ms(caller_now_ms)
    }

    /// Exact path opened by this store.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Acquire an absent or expired generation lease, returning its fencing epoch.
    pub fn acquire_generation_lease(
        &mut self,
        request: LeaseRequest<'_>,
    ) -> Result<GenerationLease, StoreError> {
        self.acquire_generation_lease_owned(
            request,
            LeaseOwnerIdentity {
                boot_id: "untracked",
                pid: 0,
                starttime: 0,
            },
        )
    }

    /// Acquire a generation lease bound to an exact boot and process identity.
    pub fn acquire_generation_lease_owned(
        &mut self,
        request: LeaseRequest<'_>,
        owner: LeaseOwnerIdentity<'_>,
    ) -> Result<GenerationLease, StoreError> {
        validate_id(request.generation_id, "generation_id")?;
        validate_id(request.holder_id, "holder_id")?;
        validate_id(owner.boot_id, "boot_id")?;
        validate_time(request.now_ms)?;
        let lease_now_ms = self.lease_now_ms(request.now_ms)?;
        let expires_ms = checked_expiry(lease_now_ms, request.ttl_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = transaction
            .query_row(
                "SELECT lease_holder, lease_epoch, lease_expires_ms, revision,
                        boot_id, holder_pid, holder_starttime
                 FROM generations WHERE generation_id = ?1",
                [request.generation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()?;

        let (epoch, revision, changed) = match current {
            None => {
                transaction.execute(
                    "INSERT INTO generations
                     (generation_id, revision, state, lease_holder, lease_epoch,
                      lease_expires_ms, boot_id, holder_pid, holder_starttime)
                     VALUES (?1, 1, 'active', ?2, 1, ?3, ?4, ?5, ?6)",
                    params![
                        request.generation_id,
                        request.holder_id,
                        expires_ms,
                        owner.boot_id,
                        i64::from(owner.pid),
                        to_db_u64(owner.starttime, "holder_starttime")?
                    ],
                )?;
                (1_u64, 1_u64, true)
            }
            Some((
                holder,
                raw_epoch,
                old_expiry,
                raw_revision,
                old_boot_id,
                raw_pid,
                raw_starttime,
            )) => {
                let epoch = from_db_u64(raw_epoch, "lease_epoch")?;
                let revision = from_db_u64(raw_revision, "revision")?;
                if old_expiry > lease_now_ms {
                    if holder == request.holder_id
                        && old_boot_id == owner.boot_id
                        && u32::try_from(raw_pid)
                            .map_err(|_| StoreError::MigrationInvariant("holder_pid"))?
                            == owner.pid
                        && from_db_u64(raw_starttime, "holder_starttime")? == owner.starttime
                    {
                        transaction.commit()?;
                        return Ok(GenerationLease {
                            generation_id: request.generation_id.to_owned(),
                            holder_id: holder,
                            epoch,
                            expires_ms: old_expiry,
                            boot_id: old_boot_id,
                            holder_pid: owner.pid,
                            holder_starttime: owner.starttime,
                        });
                    }
                    return Err(StoreError::LeaseHeld);
                }
                let next_epoch = epoch.checked_add(1).ok_or(StoreError::StaleEpoch)?;
                let next_revision = revision
                    .checked_add(1)
                    .ok_or(StoreError::InvalidField("generation_revision"))?;
                let changed = transaction.execute(
                    "UPDATE generations SET revision = ?2, lease_holder = ?3,
                     lease_epoch = ?4, lease_expires_ms = ?5, boot_id = ?6,
                     holder_pid = ?7, holder_starttime = ?8
                     WHERE generation_id = ?1 AND lease_holder = ?9
                       AND lease_epoch = ?10 AND lease_expires_ms = ?11
                       AND boot_id = ?12 AND holder_pid = ?13
                       AND holder_starttime = ?14 AND lease_expires_ms <= ?15",
                    params![
                        request.generation_id,
                        to_db_u64(next_revision, "generation_revision")?,
                        request.holder_id,
                        to_db_u64(next_epoch, "lease_epoch")?,
                        expires_ms,
                        owner.boot_id,
                        i64::from(owner.pid),
                        to_db_u64(owner.starttime, "holder_starttime")?,
                        holder,
                        to_db_u64(epoch, "lease_epoch")?,
                        old_expiry,
                        old_boot_id,
                        raw_pid,
                        raw_starttime,
                        lease_now_ms
                    ],
                )?;
                if changed != 1 {
                    return Err(StoreError::StaleEpoch);
                }
                (next_epoch, next_revision, true)
            }
        };
        if changed {
            append_event(
                &transaction,
                "generation",
                request.generation_id,
                revision,
                request.now_ms,
                "generation.lease_acquired",
                request.holder_id.as_bytes(),
            )?;
        }
        transaction.commit()?;
        Ok(GenerationLease {
            generation_id: request.generation_id.to_owned(),
            holder_id: request.holder_id.to_owned(),
            epoch,
            expires_ms,
            boot_id: owner.boot_id.to_owned(),
            holder_pid: owner.pid,
            holder_starttime: owner.starttime,
        })
    }

    /// Renew only the exact, live lease epoch held by this generation owner.
    pub fn renew_generation_lease(
        &mut self,
        renewal: LeaseRenewal<'_>,
    ) -> Result<GenerationLease, StoreError> {
        validate_id(renewal.generation_id, "generation_id")?;
        validate_id(renewal.holder_id, "holder_id")?;
        validate_time(renewal.now_ms)?;
        let lease_now_ms = self.lease_now_ms(renewal.now_ms)?;
        let expires_ms = checked_expiry(lease_now_ms, renewal.ttl_ms)?;
        let epoch = to_db_u64(renewal.epoch, "lease_epoch")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE generations SET lease_expires_ms = ?4
             WHERE generation_id = ?1 AND lease_holder = ?2 AND lease_epoch = ?3
             AND lease_expires_ms > ?5",
            params![
                renewal.generation_id,
                renewal.holder_id,
                epoch,
                expires_ms,
                lease_now_ms
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::StaleEpoch);
        }
        let owner = transaction.query_row(
            "SELECT boot_id, holder_pid, holder_starttime FROM generations
             WHERE generation_id = ?1 AND lease_holder = ?2 AND lease_epoch = ?3",
            params![renewal.generation_id, renewal.holder_id, epoch],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?;
        transaction.execute(
            "UPDATE work_locks SET expires_ms = ?3
             WHERE generation_id = ?1 AND lease_epoch = ?2",
            params![renewal.generation_id, epoch, expires_ms],
        )?;
        transaction.commit()?;
        Ok(GenerationLease {
            generation_id: renewal.generation_id.to_owned(),
            holder_id: renewal.holder_id.to_owned(),
            epoch: renewal.epoch,
            expires_ms,
            boot_id: owner.0,
            holder_pid: u32::try_from(owner.1)
                .map_err(|_| StoreError::MigrationInvariant("holder_pid"))?,
            holder_starttime: from_db_u64(owner.2, "holder_starttime")?,
        })
    }

    /// Expire one exact owner identity after the caller proved it is dead.
    ///
    /// Every predicate is in the mutation itself. A PID-reuse race, a
    /// successor acquisition, or any changed owner coordinate therefore turns
    /// this into [`StoreError::StaleEpoch`] without writing a partial sweep.
    pub fn expire_generation_lease_owner(
        &mut self,
        request: LeaseExpiryRequest<'_>,
    ) -> Result<(), StoreError> {
        validate_id(request.generation_id, "generation_id")?;
        validate_id(request.holder_id, "holder_id")?;
        validate_id(request.owner.boot_id, "boot_id")?;
        validate_time(request.now_ms)?;
        let lease_now_ms = self.lease_now_ms(request.now_ms)?;
        let epoch = to_db_u64(request.epoch, "lease_epoch")?;
        let starttime = to_db_u64(request.owner.starttime, "holder_starttime")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revision = transaction
            .query_row(
                "SELECT revision FROM generations
                 WHERE generation_id = ?1 AND lease_holder = ?2 AND lease_epoch = ?3
                   AND boot_id = ?4 AND holder_pid = ?5 AND holder_starttime = ?6
                   AND lease_expires_ms > ?7",
                params![
                    request.generation_id,
                    request.holder_id,
                    epoch,
                    request.owner.boot_id,
                    i64::from(request.owner.pid),
                    starttime,
                    lease_now_ms
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or(StoreError::StaleEpoch)?;
        let next_revision = from_db_u64(revision, "generation_revision")?
            .checked_add(1)
            .ok_or(StoreError::InvalidField("generation_revision"))?;
        let changed = transaction.execute(
            "UPDATE generations SET revision = ?8, lease_expires_ms = ?7
             WHERE generation_id = ?1 AND lease_holder = ?2 AND lease_epoch = ?3
               AND boot_id = ?4 AND holder_pid = ?5 AND holder_starttime = ?6
               AND lease_expires_ms > ?7",
            params![
                request.generation_id,
                request.holder_id,
                epoch,
                request.owner.boot_id,
                i64::from(request.owner.pid),
                starttime,
                lease_now_ms,
                to_db_u64(next_revision, "generation_revision")?
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::StaleEpoch);
        }
        transaction.execute(
            "UPDATE work_locks SET expires_ms = ?4
             WHERE generation_id = ?1 AND lease_epoch = ?2 AND expires_ms > ?3",
            params![request.generation_id, epoch, lease_now_ms, lease_now_ms],
        )?;
        transaction.execute(
            "UPDATE telegram_poller_leases SET revision = revision + 1, expires_ms = ?5
             WHERE generation_id = ?1 AND holder_id = ?2
               AND authority_lease_epoch = ?3 AND expires_ms > ?4",
            params![
                request.generation_id,
                request.holder_id,
                epoch,
                lease_now_ms,
                lease_now_ms
            ],
        )?;
        transaction.execute(
            "UPDATE outbox SET lease_expires_ms = ?4
             WHERE state = 'in_flight' AND lease_generation_id = ?1
               AND lease_epoch = ?2 AND lease_expires_ms > ?3",
            params![request.generation_id, epoch, lease_now_ms, lease_now_ms],
        )?;
        append_event(
            &transaction,
            "generation",
            request.generation_id,
            next_revision,
            request.now_ms,
            "generation.lease_owner_dead",
            request.holder_id.as_bytes(),
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Release one exact live generation lease without abandoning active work.
    ///
    /// The durable expiry is set to `now_ms`, so another holder may acquire a
    /// new fencing epoch immediately. Matching work locks become expired but
    /// remain present and require explicit reconciliation before reuse.
    pub fn release_generation_lease(
        &mut self,
        generation_id: &str,
        holder_id: &str,
        epoch: u64,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        validate_id(generation_id, "generation_id")?;
        validate_id(holder_id, "holder_id")?;
        validate_time(now_ms)?;
        let lease_now_ms = self.lease_now_ms(now_ms)?;
        let epoch = to_db_u64(epoch, "lease_epoch")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let raw_revision = transaction
            .query_row(
                "SELECT revision FROM generations
                 WHERE generation_id = ?1 AND lease_holder = ?2 AND lease_epoch = ?3
                 AND lease_expires_ms > ?4",
                params![generation_id, holder_id, epoch, lease_now_ms],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or(StoreError::StaleEpoch)?;
        let revision = from_db_u64(raw_revision, "generation_revision")?
            .checked_add(1)
            .ok_or(StoreError::InvalidField("generation_revision"))?;
        transaction.execute(
            "UPDATE generations SET revision = ?4, lease_expires_ms = ?5
             WHERE generation_id = ?1 AND lease_holder = ?2 AND lease_epoch = ?3",
            params![
                generation_id,
                holder_id,
                epoch,
                to_db_u64(revision, "generation_revision")?,
                lease_now_ms
            ],
        )?;
        transaction.execute(
            "UPDATE work_locks SET expires_ms = ?3
             WHERE generation_id = ?1 AND lease_epoch = ?2",
            params![generation_id, epoch, lease_now_ms],
        )?;
        append_event(
            &transaction,
            "generation",
            generation_id,
            revision,
            now_ms,
            "generation.lease_released",
            holder_id.as_bytes(),
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Durably close intake for one generation, naming the deciding actor.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::StaleEpoch`] unless the caller holds the named
    /// generation's live lease at `now_ms`, and
    /// [`StoreError::AlreadyPaused`] — carrying the live decision — when this
    /// generation already has an unresumed pause.
    pub fn pause_intake(
        &mut self,
        request: IntakePauseRequest<'_>,
    ) -> Result<IntakePauseReceipt, StoreError> {
        validate_id(request.generation_id, "generation_id")?;
        validate_id(request.holder_id, "holder_id")?;
        validate_id(request.actor, "intake_pause_actor")?;
        validate_id(request.reason, "intake_pause_reason")?;
        validate_time(request.now_ms)?;
        let lease_now_ms = self.lease_now_ms(request.now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // A pause takes effect at an instant rather than holding a window
        // open, so the lease need only be live now — unlike a bot lease, which
        // must outlive the TTL it is about to be granted.
        require_generation_authority_through(
            &transaction,
            request.generation_id,
            request.holder_id,
            request.authority_lease_epoch,
            lease_now_ms,
            lease_now_ms,
        )?;
        if let Some(live) = live_intake_pause(&transaction, request.generation_id, request.now_ms)?
        {
            return Err(StoreError::AlreadyPaused(Box::new(live)));
        }
        transaction.execute(
            "INSERT INTO intake_pauses
             (generation_id, revision, paused_at_ms, actor, reason, resumed_at_ms, resume_actor)
             VALUES (?1, 1, ?2, ?3, ?4, NULL, NULL)",
            params![
                request.generation_id,
                request.now_ms,
                request.actor,
                request.reason
            ],
        )?;
        let pause_id = transaction.last_insert_rowid();
        append_event(
            &transaction,
            "intake_pause",
            &pause_id.to_string(),
            1,
            request.now_ms,
            "intake.paused",
            request.actor.as_bytes(),
        )?;
        transaction.commit()?;
        Ok(IntakePauseReceipt {
            pause_id,
            revision: 1,
        })
    }

    /// Reopen intake by closing the exact live pause the caller observed.
    ///
    /// The pause row is updated, never removed: `actor`/`reason` keep naming
    /// who closed intake, and `resume_actor` records who reopened it.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::StaleEpoch`] without live generation authority,
    /// [`StoreError::NotPaused`] when no unresumed pause exists, and
    /// [`StoreError::IdempotencyConflict`] when the live pause has moved past
    /// the revision the caller read.
    pub fn resume_intake(
        &mut self,
        request: IntakeResumeRequest<'_>,
    ) -> Result<IntakePauseReceipt, StoreError> {
        validate_id(request.generation_id, "generation_id")?;
        validate_id(request.holder_id, "holder_id")?;
        validate_id(request.actor, "intake_resume_actor")?;
        validate_time(request.now_ms)?;
        let lease_now_ms = self.lease_now_ms(request.now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_generation_authority_through(
            &transaction,
            request.generation_id,
            request.holder_id,
            request.authority_lease_epoch,
            lease_now_ms,
            lease_now_ms,
        )?;
        let Some(live) = live_intake_pause(&transaction, request.generation_id, request.now_ms)?
        else {
            return Err(StoreError::NotPaused);
        };
        if live.revision != request.expected_revision {
            return Err(StoreError::IdempotencyConflict("intake_pause_revision"));
        }
        let next_revision = live
            .revision
            .checked_add(1)
            .ok_or(StoreError::InvalidField("intake_pause_revision"))?;
        let changed = transaction.execute(
            "UPDATE intake_pauses
             SET revision = ?3, resumed_at_ms = ?4, resume_actor = ?5
             WHERE pause_id = ?1 AND revision = ?2 AND resumed_at_ms IS NULL",
            params![
                live.pause_id,
                to_db_u64(live.revision, "intake_pause_revision")?,
                to_db_u64(next_revision, "intake_pause_revision")?,
                request.now_ms,
                request.actor
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::StaleEpoch);
        }
        append_event(
            &transaction,
            "intake_pause",
            &live.pause_id.to_string(),
            next_revision,
            request.now_ms,
            "intake.resumed",
            request.actor.as_bytes(),
        )?;
        transaction.commit()?;
        Ok(IntakePauseReceipt {
            pause_id: live.pause_id,
            revision: next_revision,
        })
    }

    /// Read the live pause for one generation, if intake is closed.
    ///
    /// This is scoped to `generation_id` and nothing else: a pause outlives the
    /// lease epoch that wrote it, which is what makes it survive a restart of
    /// the same named generation. A different generation has its own answer.
    pub fn intake_paused(
        &mut self,
        generation_id: &str,
        now_ms: i64,
    ) -> Result<Option<PauseRecord>, StoreError> {
        validate_id(generation_id, "generation_id")?;
        validate_time(now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let record = live_intake_pause(&transaction, generation_id, now_ms)?;
        transaction.commit()?;
        Ok(record)
    }

    /// Durably record that a peer refused one transport scope until an instant.
    ///
    /// The deadline is the whole record. A second call whose `resume_after_ms`
    /// is earlier than the one in force is accepted and changes nothing but the
    /// revision — a peer that says "wait one second" while an earlier answer of
    /// "wait five minutes" is still standing has not withdrawn the five minutes.
    ///
    /// Fenced by the same generation authority every other mutation here is,
    /// and for the same reason: a pause is state the next process reads before
    /// it dials, so a writer who no longer holds the generation must not be able
    /// to install one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidField`] for an empty or over-long
    /// transport, scope or reason, for a negative instant, or for a deadline
    /// that precedes `now_ms`, and [`StoreError::StaleEpoch`] without live
    /// generation authority.
    pub fn pause_transport(
        &mut self,
        request: TransportPauseRequest<'_>,
    ) -> Result<TransportPause, StoreError> {
        validate_id(request.transport, "transport")?;
        validate_id(request.scope, "transport_pause_scope")?;
        validate_id(request.generation_id, "generation_id")?;
        validate_id(request.holder_id, "holder_id")?;
        validate_id(request.reason, "transport_pause_reason")?;
        validate_time(request.now_ms)?;
        validate_time(request.resume_after_ms)?;
        if request.resume_after_ms < request.now_ms {
            return Err(StoreError::InvalidField("transport_pause_resume_after_ms"));
        }
        let lease_now_ms = self.lease_now_ms(request.now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // A pause takes effect at an instant rather than holding a window open,
        // so the lease need only be live now — the same reading `pause_intake`
        // applies to its own decision.
        require_generation_authority_through(
            &transaction,
            request.generation_id,
            request.holder_id,
            request.authority_lease_epoch,
            lease_now_ms,
            lease_now_ms,
        )?;
        let existing = transport_pause_row(
            &transaction,
            request.transport,
            request.scope,
            request.now_ms,
        )?;
        let (revision, paused_at_ms, resume_after_ms) = match &existing {
            None => (1_u64, request.now_ms, request.resume_after_ms),
            Some(live) => (
                live.revision
                    .checked_add(1)
                    .ok_or(StoreError::InvalidField("transport_pause_revision"))?,
                // The first refusal of an unbroken run is when the pause began.
                live.paused_at_ms.min(request.now_ms),
                live.resume_after_ms.max(request.resume_after_ms),
            ),
        };
        transaction.execute(
            "INSERT INTO transport_pauses
             (transport, scope, revision, paused_at_ms, resume_after_ms, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(transport, scope) DO UPDATE SET
                 revision = excluded.revision,
                 paused_at_ms = excluded.paused_at_ms,
                 resume_after_ms = excluded.resume_after_ms,
                 reason = excluded.reason",
            params![
                request.transport,
                request.scope,
                to_db_u64(revision, "transport_pause_revision")?,
                paused_at_ms,
                resume_after_ms,
                request.reason
            ],
        )?;
        append_event(
            &transaction,
            "transport_pause",
            &format!("{}:{}", request.transport, request.scope),
            revision,
            request.now_ms,
            "transport.paused",
            request.reason.as_bytes(),
        )?;
        transaction.commit()?;
        Ok(TransportPause {
            transport: request.transport.to_owned(),
            scope: request.scope.to_owned(),
            revision,
            paused_at_ms,
            resume_after_ms,
            reason: request.reason.to_owned(),
            observed_ms: request.now_ms,
        })
    }

    /// The live pause for one transport scope, if a peer is still refusing it.
    ///
    /// `None` covers both "never paused" and "the deadline has passed", which
    /// are the same answer to the only question a caller asks: may this call go
    /// out now. Nothing sweeps an elapsed row, because an elapsed row already
    /// answers correctly.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidField`] for an empty or over-long transport
    /// or scope, or a negative instant.
    pub fn transport_pause(
        &mut self,
        transport: &str,
        scope: &str,
        now_ms: i64,
    ) -> Result<Option<TransportPause>, StoreError> {
        validate_id(transport, "transport")?;
        validate_id(scope, "transport_pause_scope")?;
        validate_time(now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let record = transport_pause_row(&transaction, transport, scope, now_ms)?
            .filter(|pause| pause.resume_after_ms > now_ms);
        transaction.commit()?;
        Ok(record)
    }

    /// Durably accept one transport delivery, replaying the same stable key.
    ///
    /// The key is bounded by [`MAX_TRANSPORT_KEY_BYTES`] rather than by the
    /// store's ordinary identifier width, because it is the transport's
    /// coordinate and not this store's name for anything; a maximal Slack key
    /// exceeds the ordinary width. The transport and scope beside it are the
    /// store's own vocabulary and keep the ordinary bound.
    pub fn submit_inbox(
        &mut self,
        submission: InboxSubmission<'_>,
    ) -> Result<InboxReceipt, StoreError> {
        validate_id(submission.transport, "transport")?;
        validate_bounded_id(
            submission.transport_key,
            MAX_TRANSPORT_KEY_BYTES,
            "transport_key",
        )?;
        validate_id(submission.scope, "scope")?;
        validate_payload(submission.payload, "inbox_payload")?;
        validate_time(submission.received_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((inbox_id, scope, payload)) = transaction
            .query_row(
                "SELECT inbox_id, scope, payload FROM inbox
                 WHERE transport = ?1 AND transport_key = ?2",
                params![submission.transport, submission.transport_key],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?
        {
            if scope != submission.scope || payload != submission.payload {
                return Err(StoreError::IdempotencyConflict("transport_key"));
            }
            transaction.commit()?;
            return Ok(InboxReceipt {
                inbox_id,
                duplicate: true,
            });
        }

        transaction.execute(
            "INSERT INTO inbox
             (transport, transport_key, scope, payload, received_ms, state, revision, trace_id)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 1, ?6)",
            params![
                submission.transport,
                submission.transport_key,
                submission.scope,
                submission.payload,
                submission.received_ms,
                TraceId::for_ingress(submission.transport, submission.transport_key).as_str()
            ],
        )?;
        let inbox_id = transaction.last_insert_rowid();
        let provenance = ingress_record_provenance(
            submission.transport,
            submission.transport_key,
            "inbox",
            inbox_id,
        )?;
        transaction.execute(
            "UPDATE inbox SET correlation_id = ?2, causation_id = ?3 WHERE inbox_id = ?1",
            params![
                inbox_id,
                provenance.correlation_id().as_str(),
                provenance.causation_id().as_str()
            ],
        )?;
        append_event_with_provenance(
            &transaction,
            "inbox",
            &inbox_id.to_string(),
            1,
            submission.received_ms,
            "inbox.accepted",
            submission.transport_key.as_bytes(),
            &provenance,
        )?;
        transaction.commit()?;
        Ok(InboxReceipt {
            inbox_id,
            duplicate: false,
        })
    }

    /// Acquire an absent or expired bot poller lease under live generation authority.
    pub fn acquire_telegram_poller_lease(
        &mut self,
        request: TelegramPollerLeaseRequest<'_>,
    ) -> Result<TelegramPollerLease, StoreError> {
        validate_telegram_poller_request(
            request.bot_id,
            request.generation_id,
            request.holder_id,
            request.now_ms,
        )?;
        let lease_now_ms = self.lease_now_ms(request.now_ms)?;
        let expires_ms = checked_expiry(lease_now_ms, request.ttl_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_generation_authority_through(
            &transaction,
            request.generation_id,
            request.holder_id,
            request.authority_lease_epoch,
            lease_now_ms,
            expires_ms,
        )?;
        let current = transaction
            .query_row(
                "SELECT p.generation_id, p.holder_id, p.authority_lease_epoch,
                        p.poller_epoch, p.expires_ms, p.revision,
                        EXISTS(SELECT 1 FROM generations g
                               WHERE g.generation_id = p.generation_id
                                 AND g.lease_holder = p.holder_id
                                 AND g.lease_epoch = p.authority_lease_epoch
                                 AND g.lease_expires_ms > ?2)
                 FROM telegram_poller_leases p WHERE p.bot_id = ?1",
                params![request.bot_id, lease_now_ms],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, bool>(6)?,
                    ))
                },
            )
            .optional()?;
        let poller_epoch = match current {
            None => {
                transaction.execute(
                    "INSERT INTO telegram_poller_leases
                     (bot_id, revision, generation_id, holder_id, authority_lease_epoch,
                      poller_epoch, expires_ms) VALUES (?1, 1, ?2, ?3, ?4, 1, ?5)",
                    params![
                        request.bot_id,
                        request.generation_id,
                        request.holder_id,
                        to_db_u64(request.authority_lease_epoch, "authority_lease_epoch")?,
                        expires_ms
                    ],
                )?;
                1
            }
            Some((
                generation_id,
                holder_id,
                raw_authority_epoch,
                raw_epoch,
                old_expiry,
                raw_revision,
                owner_authority_live,
            )) => {
                let epoch = from_db_u64(raw_epoch, "telegram_poller_epoch")?;
                if old_expiry > lease_now_ms && owner_authority_live {
                    if generation_id == request.generation_id
                        && holder_id == request.holder_id
                        && from_db_u64(raw_authority_epoch, "authority_lease_epoch")?
                            == request.authority_lease_epoch
                    {
                        transaction.commit()?;
                        return Ok(TelegramPollerLease {
                            bot_id: request.bot_id,
                            generation_id,
                            holder_id,
                            epoch,
                            expires_ms: old_expiry,
                        });
                    }
                    return Err(StoreError::LeaseHeld);
                }
                let next_epoch = epoch.checked_add(1).ok_or(StoreError::StaleEpoch)?;
                let next_revision = from_db_u64(raw_revision, "telegram_poller_revision")?
                    .checked_add(1)
                    .ok_or(StoreError::InvalidField("telegram_poller_revision"))?;
                let changed = transaction.execute(
                    "UPDATE telegram_poller_leases SET revision = ?2, generation_id = ?3,
                     holder_id = ?4, authority_lease_epoch = ?5, poller_epoch = ?6,
                     expires_ms = ?7 WHERE bot_id = ?1
                       AND generation_id = ?8 AND holder_id = ?9
                       AND authority_lease_epoch = ?10 AND poller_epoch = ?11
                       AND expires_ms = ?12",
                    params![
                        request.bot_id,
                        to_db_u64(next_revision, "telegram_poller_revision")?,
                        request.generation_id,
                        request.holder_id,
                        to_db_u64(request.authority_lease_epoch, "authority_lease_epoch")?,
                        to_db_u64(next_epoch, "telegram_poller_epoch")?,
                        expires_ms,
                        generation_id,
                        holder_id,
                        raw_authority_epoch,
                        raw_epoch,
                        old_expiry
                    ],
                )?;
                if changed != 1 {
                    return Err(StoreError::StaleEpoch);
                }
                next_epoch
            }
        };
        transaction.commit()?;
        Ok(TelegramPollerLease {
            bot_id: request.bot_id,
            generation_id: request.generation_id.to_owned(),
            holder_id: request.holder_id.to_owned(),
            epoch: poller_epoch,
            expires_ms,
        })
    }

    /// Renew only the exact currently live bot poller lease.
    pub fn renew_telegram_poller_lease(
        &mut self,
        renewal: TelegramPollerLeaseRenewal<'_>,
    ) -> Result<TelegramPollerLease, StoreError> {
        validate_telegram_poller_request(
            renewal.bot_id,
            renewal.generation_id,
            renewal.holder_id,
            renewal.now_ms,
        )?;
        let lease_now_ms = self.lease_now_ms(renewal.now_ms)?;
        let expires_ms = checked_expiry(lease_now_ms, renewal.ttl_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_generation_authority_through(
            &transaction,
            renewal.generation_id,
            renewal.holder_id,
            renewal.authority_lease_epoch,
            lease_now_ms,
            expires_ms,
        )?;
        let changed = transaction.execute(
            "UPDATE telegram_poller_leases SET revision = revision + 1, expires_ms = ?7
             WHERE bot_id = ?1 AND generation_id = ?2 AND holder_id = ?3
               AND authority_lease_epoch = ?4 AND poller_epoch = ?5
               AND expires_ms = ?6 AND expires_ms > ?8",
            params![
                renewal.bot_id,
                renewal.generation_id,
                renewal.holder_id,
                to_db_u64(renewal.authority_lease_epoch, "authority_lease_epoch")?,
                to_db_u64(renewal.poller_epoch, "telegram_poller_epoch")?,
                renewal.expected_expires_ms,
                expires_ms,
                lease_now_ms
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::StaleEpoch);
        }
        transaction.commit()?;
        Ok(TelegramPollerLease {
            bot_id: renewal.bot_id,
            generation_id: renewal.generation_id.to_owned(),
            holder_id: renewal.holder_id.to_owned(),
            epoch: renewal.poller_epoch,
            expires_ms,
        })
    }

    /// Release one exact live bot poller lease without deleting its fencing epoch.
    pub fn release_telegram_poller_lease(
        &mut self,
        identity: TelegramPollerLeaseIdentity<'_>,
    ) -> Result<(), StoreError> {
        validate_telegram_poller_identity(&identity)?;
        let lease_now_ms = self.lease_now_ms(identity.now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_exact_telegram_poller(&transaction, &identity, lease_now_ms)?;
        let changed = transaction.execute(
            "UPDATE telegram_poller_leases SET revision = revision + 1, expires_ms = ?6
             WHERE bot_id = ?1 AND generation_id = ?2 AND holder_id = ?3
               AND poller_epoch = ?4 AND expires_ms = ?5",
            params![
                identity.bot_id,
                identity.generation_id,
                identity.holder_id,
                to_db_u64(identity.poller_epoch, "telegram_poller_epoch")?,
                identity.expected_expires_ms,
                lease_now_ms
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::StaleEpoch);
        }
        transaction.commit()?;
        Ok(())
    }

    /// Read the cursor only while the exact bot poller lease remains live.
    pub fn read_telegram_offset(
        &mut self,
        identity: TelegramPollerLeaseIdentity<'_>,
    ) -> Result<TelegramOffsetReceipt, StoreError> {
        validate_telegram_poller_identity(&identity)?;
        let lease_now_ms = self.lease_now_ms(identity.now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_exact_telegram_poller(&transaction, &identity, lease_now_ms)?;
        let next_offset = transaction
            .query_row(
                "SELECT next_offset FROM telegram_offsets WHERE bot_id = ?1",
                [identity.bot_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|value| telegram_offset_from_bytes(&value))
            .transpose()?
            .unwrap_or(0);
        transaction.commit()?;
        Ok(TelegramOffsetReceipt {
            bot_id: identity.bot_id,
            lease_epoch: identity.poller_epoch,
            next_offset,
        })
    }

    /// Atomically persist every disposition and cursor under an exact live bot lease.
    pub fn commit_telegram_batch(
        &mut self,
        commit: TelegramPollerCommit<'_>,
    ) -> Result<TelegramPollerCommitReceipt, StoreError> {
        validate_telegram_poller_identity(&commit.lease)?;
        validate_telegram_batch(&commit.batch)?;
        if commit.batch.bot_id != commit.lease.bot_id {
            return Err(StoreError::InvalidField("telegram_bot_id"));
        }
        let lease_now_ms = self.lease_now_ms(commit.lease.now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(receipt) = exact_telegram_commit_receipt(&transaction, &commit)? {
            transaction.commit()?;
            return Ok(receipt);
        }
        if lease_now_ms >= commit.lease.expected_expires_ms {
            return Err(StoreError::StaleEpoch);
        }
        if commit.commit_before_ms <= lease_now_ms
            || commit.commit_before_ms > commit.lease.expected_expires_ms
        {
            return Err(StoreError::InvalidField("telegram_commit_deadline"));
        }
        require_exact_telegram_poller(&transaction, &commit.lease, commit.commit_before_ms - 1)?;
        let receipt = commit_fenced_telegram_batch(&transaction, &commit)?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Legacy unfenced ingestion retained for migration fixtures. Runtime code
    /// must use `commit_telegram_batch`.
    #[doc(hidden)]
    /// Atomically persist every disposition in a parsed Telegram batch and
    /// advance that bot's offset only after all rows are durable.
    pub fn ingest_telegram_batch(
        &mut self,
        batch: TelegramBatchIngestion<'_>,
    ) -> Result<TelegramBatchReceipt, StoreError> {
        validate_telegram_batch(&batch)?;
        let expected = telegram_offset_bytes(batch.expected_offset);
        let next = telegram_offset_bytes(batch.next_offset);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT next_offset FROM telegram_offsets WHERE bot_id = ?1",
                [batch.bot_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|value| telegram_offset_from_bytes(&value))
            .transpose()?;

        match existing {
            Some(current) if current == batch.next_offset => {
                verify_telegram_retry(&transaction, &batch)?;
                transaction.commit()?;
                return Ok(TelegramBatchReceipt {
                    next_offset: batch.next_offset,
                    disposition_count: batch.updates.len(),
                    duplicate: true,
                });
            }
            Some(current) if current != batch.expected_offset => {
                return Err(StoreError::IdempotencyConflict("telegram_offset"));
            }
            Some(_) => {}
            None if batch.expected_offset != 0 => {
                return Err(StoreError::IdempotencyConflict("telegram_offset"));
            }
            None => {
                transaction.execute(
                    "INSERT INTO telegram_offsets
                     (bot_id, next_offset, revision, updated_ms)
                     VALUES (?1, ?2, 1, ?3)",
                    params![batch.bot_id, &expected[..], batch.received_ms],
                )?;
            }
        }

        for update in batch.updates {
            if transaction
                .query_row(
                    "SELECT 1 FROM telegram_ingress
                     WHERE bot_id = ?1 AND update_id = ?2",
                    params![batch.bot_id, &telegram_offset_bytes(update.update_id)[..]],
                    |_| Ok(()),
                )
                .optional()?
                .is_some()
            {
                return Err(StoreError::IdempotencyConflict("telegram_update"));
            }
            if transaction
                .query_row(
                    "SELECT 1 FROM telegram_ingress WHERE source_key = ?1",
                    [update.source_key],
                    |_| Ok(()),
                )
                .optional()?
                .is_some()
            {
                return Err(StoreError::IdempotencyConflict("telegram_source_key"));
            }
            let (disposition, content) = telegram_disposition_parts(update.disposition);
            let provenance = telegram_ingress_provenance(update.source_key, update.update_id)?;
            transaction.execute(
                "INSERT INTO telegram_ingress
                 (bot_id, update_id, source_key, scope, disposition, content, received_ms,
                  trace_id, correlation_id, causation_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    batch.bot_id,
                    &telegram_offset_bytes(update.update_id)[..],
                    update.source_key,
                    update.scope,
                    disposition,
                    content,
                    batch.received_ms,
                    provenance.trace_id().as_str(),
                    provenance.correlation_id().as_str(),
                    provenance.causation_id().as_str()
                ],
            )?;
        }

        if batch.next_offset != batch.expected_offset {
            transaction.execute(
                "INSERT INTO telegram_batches
                 (bot_id, expected_offset, next_offset, disposition_count, received_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    batch.bot_id,
                    &expected[..],
                    &next[..],
                    to_db_u64(batch.updates.len() as u64, "telegram_disposition_count")?,
                    batch.received_ms
                ],
            )?;
            let changed = transaction.execute(
                "UPDATE telegram_offsets
                 SET next_offset = ?3, revision = revision + 1, updated_ms = ?4
                 WHERE bot_id = ?1 AND next_offset = ?2",
                params![batch.bot_id, &expected[..], &next[..], batch.received_ms],
            )?;
            if changed != 1 {
                return Err(StoreError::IdempotencyConflict("telegram_offset"));
            }
        }
        transaction.commit()?;
        Ok(TelegramBatchReceipt {
            next_offset: batch.next_offset,
            disposition_count: batch.updates.len(),
            duplicate: false,
        })
    }

    /// Read one bot's last atomically committed Telegram offset.
    pub fn telegram_offset(&self, bot_id: i64) -> Result<Option<u64>, StoreError> {
        if bot_id <= 0 {
            return Err(StoreError::InvalidField("telegram_bot_id"));
        }
        self.connection
            .query_row(
                "SELECT next_offset FROM telegram_offsets WHERE bot_id = ?1",
                [bot_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|value| telegram_offset_from_bytes(&value))
            .transpose()
    }

    /// Inspect one durable Telegram disposition without exposing unrelated rows.
    pub fn telegram_disposition(
        &self,
        bot_id: i64,
        update_id: u64,
    ) -> Result<TelegramDispositionSnapshot, StoreError> {
        if bot_id <= 0 {
            return Err(StoreError::InvalidField("telegram_bot_id"));
        }
        self.connection
            .query_row(
                "SELECT source_key, scope, disposition, content, received_ms
                 FROM telegram_ingress WHERE bot_id = ?1 AND update_id = ?2",
                params![bot_id, &telegram_offset_bytes(update_id)[..]],
                |row| {
                    Ok(TelegramDispositionSnapshot {
                        source_key: row.get(0)?,
                        scope: row.get(1)?,
                        disposition: row.get(2)?,
                        content: row.get(3)?,
                        received_ms: row.get(4)?,
                    })
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound("telegram_disposition"))
    }

    /// Atomically create a running run and acquire its exclusive scope lock.
    pub fn claim_work(&mut self, claim: WorkClaim<'_>) -> Result<RunClaim, StoreError> {
        validate_id(claim.claim_key, "claim_key")?;
        validate_id(claim.scope, "scope")?;
        validate_id(claim.generation_id, "generation_id")?;
        validate_id(claim.holder_id, "holder_id")?;
        validate_time(claim.now_ms)?;
        if claim.inbox_id <= 0 {
            return Err(StoreError::InvalidField("inbox_id"));
        }
        let lease_now_ms = self.lease_now_ms(claim.now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lease_expiry = require_live_lease(
            &transaction,
            claim.generation_id,
            claim.holder_id,
            claim.lease_epoch,
            lease_now_ms,
        )?;

        if let Some((run_id, inbox_id, scope, generation_id, epoch)) = transaction
            .query_row(
                "SELECT run_id, inbox_id, scope, generation_id, lease_epoch
                 FROM runs WHERE claim_key = ?1",
                [claim.claim_key],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?
        {
            if inbox_id != claim.inbox_id
                || scope != claim.scope
                || generation_id != claim.generation_id
                || from_db_u64(epoch, "lease_epoch")? != claim.lease_epoch
            {
                return Err(StoreError::IdempotencyConflict("claim_key"));
            }
            transaction.commit()?;
            return Ok(RunClaim {
                run_id,
                duplicate: true,
            });
        }

        let inbox = transaction
            .query_row(
                "SELECT scope, state FROM inbox WHERE inbox_id = ?1",
                [claim.inbox_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound("inbox"))?;
        if inbox.0 != claim.scope {
            return Err(StoreError::IdempotencyConflict("inbox_scope"));
        }
        if inbox.1 != "pending" {
            return Err(StoreError::IdempotencyConflict("inbox_state"));
        }

        if let Some((old_run_id, expires_ms)) = transaction
            .query_row(
                "SELECT run_id, expires_ms FROM work_locks WHERE scope = ?1",
                [claim.scope],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
        {
            if expires_ms > lease_now_ms {
                return Err(StoreError::ScopeLocked);
            }
            return Err(StoreError::ReconciliationRequired { run_id: old_run_id });
        }

        transaction.execute(
            "INSERT INTO runs
             (claim_key, inbox_id, scope, generation_id, lease_epoch, state, revision, started_ms,
              trace_id, causation_id)
             SELECT ?1, inbox_id, ?3, ?4, ?5, 'running', 1, ?6,
                    trace_id, 'inbox:' || inbox_id
             FROM inbox WHERE inbox_id = ?2",
            params![
                claim.claim_key,
                claim.inbox_id,
                claim.scope,
                claim.generation_id,
                to_db_u64(claim.lease_epoch, "lease_epoch")?,
                claim.now_ms
            ],
        )?;
        let run_id = transaction.last_insert_rowid();
        let provenance = run_provenance(&transaction, claim.inbox_id, run_id)?;
        mark_inbox_claimed(
            &transaction,
            claim.inbox_id,
            run_id,
            claim.now_ms,
            provenance.as_ref(),
        )?;
        transaction.execute(
            "INSERT INTO work_locks
             (scope, run_id, generation_id, lease_epoch, expires_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                claim.scope,
                run_id,
                claim.generation_id,
                to_db_u64(claim.lease_epoch, "lease_epoch")?,
                lease_expiry
            ],
        )?;
        if let Some(provenance) = &provenance {
            append_event_with_provenance(
                &transaction,
                "run",
                &run_id.to_string(),
                1,
                claim.now_ms,
                "run.claimed",
                claim.scope.as_bytes(),
                provenance,
            )?;
        } else {
            append_event(
                &transaction,
                "run",
                &run_id.to_string(),
                1,
                claim.now_ms,
                "run.claimed",
                claim.scope.as_bytes(),
            )?;
        }
        transaction.commit()?;
        Ok(RunClaim {
            run_id,
            duplicate: false,
        })
    }

    /// Atomically claim the oldest claimable pending inbox item.
    ///
    /// FIFO order is `(received_ms, inbox_id)`. An existing claimed item is
    /// replayed only to its exact live generation epoch. A scope lock blocks or
    /// requires reconciliation; the scheduler never skips, steals, or abandons
    /// older prior work.
    pub fn claim_next(
        &mut self,
        claim: SchedulerClaim<'_>,
    ) -> Result<Option<ScheduledRun>, StoreError> {
        validate_id(claim.transport, "transport")?;
        validate_id(claim.generation_id, "generation_id")?;
        validate_id(claim.holder_id, "holder_id")?;
        validate_time(claim.now_ms)?;
        let lease_now_ms = self.lease_now_ms(claim.now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lease_expiry = require_live_lease(
            &transaction,
            claim.generation_id,
            claim.holder_id,
            claim.lease_epoch,
            lease_now_ms,
        )?;

        let outstanding = transaction
            .query_row(
                "SELECT i.inbox_id, i.scope, i.state, i.claimed_run_id,
                        r.generation_id, r.lease_epoch, r.state
                 FROM inbox i
                 LEFT JOIN runs r ON r.run_id = i.claimed_run_id
                 WHERE i.transport = ?1 AND i.state IN ('pending', 'claimed')
                 ORDER BY i.received_ms, i.inbox_id LIMIT 1",
                [claim.transport],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((inbox_id, scope, state, claimed_run_id, run_generation, raw_epoch, run_state)) =
            outstanding
        else {
            transaction.commit()?;
            return Ok(None);
        };
        if state == "claimed" {
            let run_id = claimed_run_id
                .ok_or(StoreError::MigrationInvariant("claimed_inbox_without_run"))?;
            let run_epoch = raw_epoch.ok_or(StoreError::MigrationInvariant(
                "claimed_inbox_without_epoch",
            ))?;
            if run_generation.as_deref() != Some(claim.generation_id)
                || from_db_u64(run_epoch, "lease_epoch")? != claim.lease_epoch
                || run_state.as_deref() != Some("running")
            {
                return Err(StoreError::ReconciliationRequired { run_id });
            }
            transaction.commit()?;
            return Ok(Some(ScheduledRun {
                run_id,
                inbox_id,
                scope,
                duplicate: true,
            }));
        }

        if let Some((run_id, expires_ms)) = transaction
            .query_row(
                "SELECT run_id, expires_ms FROM work_locks WHERE scope = ?1",
                [&scope],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
        {
            return Err(if expires_ms > lease_now_ms {
                StoreError::ScopeLocked
            } else {
                StoreError::ReconciliationRequired { run_id }
            });
        }
        let claim_key = format!("scheduler:{inbox_id}");

        transaction.execute(
            "INSERT INTO runs
             (claim_key, inbox_id, scope, generation_id, lease_epoch, state, revision, started_ms,
              trace_id, causation_id)
             SELECT ?1, inbox_id, ?3, ?4, ?5, 'running', 1, ?6,
                    trace_id, 'inbox:' || inbox_id
             FROM inbox WHERE inbox_id = ?2",
            params![
                claim_key,
                inbox_id,
                scope,
                claim.generation_id,
                to_db_u64(claim.lease_epoch, "lease_epoch")?,
                claim.now_ms
            ],
        )?;
        let run_id = transaction.last_insert_rowid();
        let provenance = run_provenance(&transaction, inbox_id, run_id)?;
        mark_inbox_claimed(
            &transaction,
            inbox_id,
            run_id,
            claim.now_ms,
            provenance.as_ref(),
        )?;
        transaction.execute(
            "INSERT INTO work_locks
             (scope, run_id, generation_id, lease_epoch, expires_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                scope,
                run_id,
                claim.generation_id,
                to_db_u64(claim.lease_epoch, "lease_epoch")?,
                lease_expiry
            ],
        )?;
        if let Some(provenance) = &provenance {
            append_event_with_provenance(
                &transaction,
                "run",
                &run_id.to_string(),
                1,
                claim.now_ms,
                "run.claimed",
                scope.as_bytes(),
                provenance,
            )?;
        } else {
            append_event(
                &transaction,
                "run",
                &run_id.to_string(),
                1,
                claim.now_ms,
                "run.claimed",
                scope.as_bytes(),
            )?;
        }
        transaction.commit()?;
        Ok(Some(ScheduledRun {
            run_id,
            inbox_id,
            scope,
            duplicate: false,
        }))
    }

    /// Read the bounded owned payload for one exact live claimed run.
    pub fn claimed_inbox(
        &mut self,
        run_id: i64,
        generation_id: &str,
        holder_id: &str,
        lease_epoch: u64,
        now_ms: i64,
    ) -> Result<ClaimedInbox, StoreError> {
        if run_id <= 0 {
            return Err(StoreError::InvalidField("run_id"));
        }
        validate_id(generation_id, "generation_id")?;
        validate_id(holder_id, "holder_id")?;
        validate_time(now_ms)?;
        let lease_now_ms = self.lease_now_ms(now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_live_lease(
            &transaction,
            generation_id,
            holder_id,
            lease_epoch,
            lease_now_ms,
        )?;
        let claimed = transaction
            .query_row(
                "SELECT i.inbox_id, i.transport, i.transport_key, i.scope, i.payload,
                        i.received_ms
                 FROM runs r JOIN inbox i ON i.inbox_id = r.inbox_id
                 WHERE r.run_id = ?1 AND r.generation_id = ?2 AND r.lease_epoch = ?3
                   AND r.state = 'running' AND i.state = 'claimed'
                   AND i.claimed_run_id = r.run_id",
                params![
                    run_id,
                    generation_id,
                    to_db_u64(lease_epoch, "lease_epoch")?
                ],
                |row| {
                    Ok(ClaimedInbox {
                        inbox_id: row.get(0)?,
                        transport: row.get(1)?,
                        transport_key: row.get(2)?,
                        scope: row.get(3)?,
                        payload: row.get(4)?,
                        received_ms: row.get(5)?,
                    })
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound("claimed_inbox"))?;
        transaction.commit()?;
        Ok(claimed)
    }

    /// Inspect exact durable evidence for one running or reconciled item.
    pub fn inspect_reconciliation(
        &mut self,
        run_id: i64,
    ) -> Result<ReconciliationEvidence, StoreError> {
        if run_id <= 0 {
            return Err(StoreError::InvalidField("run_id"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let row = transaction
            .query_row(
                "SELECT r.run_id, i.inbox_id, i.transport, i.transport_key, r.scope,
                        i.state, i.revision, i.claimed_run_id,
                        r.state, r.revision, r.generation_id, r.lease_epoch,
                        w.generation_id, w.lease_epoch, w.expires_ms,
                        r.terminal_payload IS NOT NULL, r.outbox_intent_key,
                        (SELECT count(*) FROM outbox o
                         JOIN domain_events e ON e.event_id = o.event_id
                         WHERE e.aggregate_kind = 'run'
                           AND e.aggregate_id = CAST(r.run_id AS TEXT)),
                        r.trace_id, r.correlation_id, r.causation_id
                 FROM runs r JOIN inbox i ON i.inbox_id = r.inbox_id
                 LEFT JOIN work_locks w ON w.run_id = r.run_id
                 WHERE r.run_id = ?1",
                [run_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, i64>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, i64>(11)?,
                        row.get::<_, Option<String>>(12)?,
                        row.get::<_, Option<i64>>(13)?,
                        row.get::<_, Option<i64>>(14)?,
                        row.get::<_, bool>(15)?,
                        row.get::<_, Option<String>>(16)?,
                        row.get::<_, i64>(17)?,
                        row.get::<_, Option<String>>(18)?,
                        row.get::<_, Option<String>>(19)?,
                        row.get::<_, Option<String>>(20)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound("run"))?;
        let inbox_state = match row.5.as_str() {
            "pending" => ReconciliationInboxState::Pending,
            "claimed" => ReconciliationInboxState::Claimed,
            "completed" => ReconciliationInboxState::Completed,
            "failed" => ReconciliationInboxState::Failed,
            _ => return Err(StoreError::MigrationInvariant("unknown_inbox_state")),
        };
        let run_state = match row.8.as_str() {
            "running" => ReconciliationRunState::Running,
            "failed" => ReconciliationRunState::Failed,
            "abandoned" => ReconciliationRunState::Abandoned,
            _ => return Err(StoreError::AlreadyTerminal),
        };
        let evidence = ReconciliationEvidence {
            run_id: row.0,
            inbox_id: row.1,
            transport: row.2,
            transport_key: row.3,
            scope: row.4,
            inbox_state,
            inbox_revision: from_db_u64(row.6, "inbox_revision")?,
            claimed_run_id: row.7,
            run_state,
            run_revision: from_db_u64(row.9, "run_revision")?,
            generation_id: row.10,
            lease_epoch: from_db_u64(row.11, "lease_epoch")?,
            lock_generation_id: row.12,
            lock_epoch: row
                .13
                .map(|epoch| from_db_u64(epoch, "lock_epoch"))
                .transpose()?,
            lock_expires_ms: row.14,
            terminal_payload_present: row.15,
            outbox_intent_key: row.16,
            outbox_count: from_db_u64(row.17, "outbox_count")?,
            provenance: stored_provenance(row.18, row.19, row.20)?,
        };
        transaction.commit()?;
        Ok(evidence)
    }

    /// Resolve one exact ambiguous running item through a closed decision.
    ///
    /// The expected fields compare-and-set the old run, while the authority
    /// fields must name the current live lease in this same transaction.
    pub fn reconcile_run(
        &mut self,
        request: ReconciliationRequest<'_>,
    ) -> Result<ReconciliationReceipt, StoreError> {
        if request.run_id <= 0 {
            return Err(StoreError::InvalidField("run_id"));
        }
        validate_id(request.authority_generation_id, "authority_generation_id")?;
        validate_id(request.authority_holder_id, "authority_holder_id")?;
        validate_id(request.expected_generation_id, "expected_generation_id")?;
        validate_id(request.decision_key, "decision_key")?;
        validate_time(request.now_ms)?;
        let parts = reconciliation_parts(request.decision);
        match request.decision {
            ReconciliationDecision::Fail { reason } => {
                validate_id(reason, "reconciliation_reason")?;
            }
            ReconciliationDecision::FailWithIntent {
                reason,
                outbox_kind,
                outbox_payload,
            } => {
                validate_id(reason, "reconciliation_reason")?;
                validate_id(outbox_kind, "outbox_kind")?;
                validate_payload(outbox_payload, "outbox_payload")?;
            }
            ReconciliationDecision::Complete {
                event_kind,
                event_payload,
                outbox_kind,
                outbox_payload,
            } => {
                validate_id(event_kind, "event_kind")?;
                validate_payload(event_payload, "event_payload")?;
                validate_id(outbox_kind, "outbox_kind")?;
                validate_payload(outbox_payload, "outbox_payload")?;
            }
        }
        let lease_now_ms = self.lease_now_ms(request.now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_reconciliation_authority(
            &transaction,
            request.authority_generation_id,
            request.authority_holder_id,
            request.authority_lease_epoch,
            lease_now_ms,
        )?;
        let run = transaction
            .query_row(
                "SELECT r.state, r.revision, r.generation_id, r.lease_epoch,
                        r.terminal_payload, r.outbox_intent_key, r.inbox_id, r.scope,
                        w.generation_id, w.lease_epoch, w.expires_ms
                 FROM runs r LEFT JOIN work_locks w ON w.run_id = r.run_id
                 WHERE r.run_id = ?1",
                [request.run_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, Option<i64>>(9)?,
                        row.get::<_, Option<i64>>(10)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound("run"))?;
        let run_provenance = run_row_provenance(&transaction, request.run_id)?;
        let revision = from_db_u64(run.1, "run_revision")?;
        if run.0 != "running" {
            let receipt = reconciliation_retry_receipt(&transaction, &request, &run)?;
            transaction.commit()?;
            return Ok(receipt);
        }
        if run.2 != request.expected_generation_id
            || from_db_u64(run.3, "lease_epoch")? != request.expected_lease_epoch
            || run.8.as_deref() != Some(request.expected_generation_id)
            || run
                .9
                .map(|epoch| from_db_u64(epoch, "lock_epoch"))
                .transpose()?
                != Some(request.expected_lease_epoch)
        {
            return Err(StoreError::StaleEpoch);
        }
        if revision != request.expected_revision {
            return Err(StoreError::IdempotencyConflict("expected_revision"));
        }
        if run.10.is_none_or(|expires_ms| expires_ms > lease_now_ms) {
            return Err(StoreError::LeaseHeld);
        }
        let outcome_rows: bool = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM domain_events e
                LEFT JOIN outbox o ON o.event_id = e.event_id
                WHERE e.aggregate_kind = 'run' AND e.aggregate_id = ?1
                  AND (e.kind != 'run.claimed' OR o.outbox_id IS NOT NULL)
             )",
            [request.run_id.to_string()],
            |row| row.get(0),
        )?;
        if run.4.is_some() || run.5.is_some() || outcome_rows {
            return Err(StoreError::AlreadyTerminal);
        }
        let next_revision = revision
            .checked_add(1)
            .ok_or(StoreError::InvalidField("run_revision"))?;
        let inbox_revision: i64 = transaction
            .query_row(
                "SELECT revision FROM inbox WHERE inbox_id = ?1 AND state = 'claimed'
                 AND claimed_run_id = ?2",
                params![run.6, request.run_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::MigrationInvariant(
                "reconciliation_inbox_not_claimed",
            ))?;
        let next_inbox_revision = from_db_u64(inbox_revision, "inbox_revision")?
            .checked_add(1)
            .ok_or(StoreError::InvalidField("inbox_revision"))?;

        let run_changed = transaction.execute(
            "UPDATE runs SET state = ?2, revision = ?3, finished_ms = ?4,
             terminal_payload = ?5, outbox_intent_key = ?6
             WHERE run_id = ?1 AND generation_id = ?7 AND lease_epoch = ?8
               AND state = 'running' AND revision = ?9",
            params![
                request.run_id,
                parts.run_state,
                to_db_u64(next_revision, "run_revision")?,
                request.now_ms,
                parts.event_payload,
                request.decision_key,
                request.expected_generation_id,
                to_db_u64(request.expected_lease_epoch, "lease_epoch")?,
                to_db_u64(revision, "run_revision")?
            ],
        )?;
        if run_changed != 1 {
            return Err(StoreError::IdempotencyConflict("run_state"));
        }
        let inbox_changed = transaction.execute(
            "UPDATE inbox SET state = ?2, claimed_run_id = NULL, revision = ?3
             WHERE inbox_id = ?1 AND state = 'claimed' AND claimed_run_id = ?4",
            params![
                run.6,
                parts.inbox_state,
                to_db_u64(next_inbox_revision, "inbox_revision")?,
                request.run_id
            ],
        )?;
        if inbox_changed != 1 {
            return Err(StoreError::IdempotencyConflict("inbox_state"));
        }
        let event_provenance = run_provenance
            .as_ref()
            .map(|provenance| {
                child_provenance(
                    provenance.trace_id().as_str(),
                    provenance.correlation_id().as_str().to_owned(),
                    format!("run:{}", request.run_id),
                )
            })
            .transpose()?;
        let (run_event_id, inbox_event_id) = if let Some(provenance) = &event_provenance {
            (
                append_event_with_provenance(
                    &transaction,
                    "run",
                    &request.run_id.to_string(),
                    next_revision,
                    request.now_ms,
                    parts.run_event_kind,
                    parts.event_payload,
                    provenance,
                )?,
                append_event_with_provenance(
                    &transaction,
                    "inbox",
                    &run.6.to_string(),
                    next_inbox_revision,
                    request.now_ms,
                    parts.inbox_event_kind,
                    parts.event_payload,
                    provenance,
                )?,
            )
        } else {
            (
                append_event(
                    &transaction,
                    "run",
                    &request.run_id.to_string(),
                    next_revision,
                    request.now_ms,
                    parts.run_event_kind,
                    parts.event_payload,
                )?,
                append_event(
                    &transaction,
                    "inbox",
                    &run.6.to_string(),
                    next_inbox_revision,
                    request.now_ms,
                    parts.inbox_event_kind,
                    parts.event_payload,
                )?,
            )
        };
        let outbox_provenance = event_provenance
            .as_ref()
            .map(|provenance| {
                child_provenance(
                    provenance.trace_id().as_str(),
                    provenance.correlation_id().as_str().to_owned(),
                    format!("event:{run_event_id}"),
                )
            })
            .transpose()?;
        let insert = transaction.execute(
            "INSERT INTO outbox
             (intent_key, event_id, transport, kind, payload, state, revision,
              attempts, available_ms, created_ms, trace_id, correlation_id, causation_id)
             VALUES (?1, ?2, ?3, ?4, ?5,
                     'pending', 1, 0, ?6, ?6, ?7, ?8, ?9)",
            params![
                request.decision_key,
                run_event_id,
                outbox_transport(parts.outbox_kind),
                parts.outbox_kind,
                parts.outbox_payload,
                request.now_ms,
                outbox_provenance
                    .as_ref()
                    .map(|value| value.trace_id().as_str()),
                outbox_provenance
                    .as_ref()
                    .map(|value| value.correlation_id().as_str()),
                outbox_provenance
                    .as_ref()
                    .map(|value| value.causation_id().as_str())
            ],
        );
        if let Err(error) = insert {
            if error
                .sqlite_error()
                .is_some_and(|code| code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE)
            {
                return Err(StoreError::OutboxConflict);
            }
            return Err(StoreError::Sqlite(error));
        }
        let outbox_id = transaction.last_insert_rowid();
        let lock_deleted = transaction.execute(
            "DELETE FROM work_locks WHERE run_id = ?1
             AND generation_id = ?2 AND lease_epoch = ?3",
            params![
                request.run_id,
                request.expected_generation_id,
                to_db_u64(request.expected_lease_epoch, "lease_epoch")?
            ],
        )?;
        if lock_deleted != 1 {
            return Err(StoreError::StaleEpoch);
        }
        transaction.commit()?;
        Ok(ReconciliationReceipt {
            run_event_id,
            inbox_event_id,
            outbox_id,
            duplicate: false,
        })
    }

    /// Recover the exact committed event/outbox receipt for a terminal run.
    pub fn terminal_receipt(
        &mut self,
        run_id: i64,
        outbox_intent_key: &str,
    ) -> Result<TerminalReceipt, StoreError> {
        if run_id <= 0 {
            return Err(StoreError::InvalidField("run_id"));
        }
        validate_id(outbox_intent_key, "outbox_intent_key")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let receipt = transaction
            .query_row(
                "SELECT e.event_id, o.outbox_id
                 FROM runs r
                 JOIN domain_events e ON e.aggregate_kind = 'run'
                     AND e.aggregate_id = CAST(r.run_id AS TEXT)
                     AND e.revision = r.revision
                 JOIN outbox o ON o.event_id = e.event_id
                 WHERE r.run_id = ?1 AND r.state IN ('succeeded', 'failed')
                   AND r.outbox_intent_key = ?2 AND o.intent_key = ?2",
                params![run_id, outbox_intent_key],
                |row| {
                    Ok(TerminalReceipt {
                        event_id: row.get(0)?,
                        outbox_id: row.get(1)?,
                        duplicate: true,
                    })
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound("terminal_receipt"))?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Commit terminal state, its event, and one external-effect intent together.
    pub fn finish_run(&mut self, terminal: TerminalRun<'_>) -> Result<TerminalReceipt, StoreError> {
        validate_id(terminal.generation_id, "generation_id")?;
        validate_id(terminal.holder_id, "holder_id")?;
        validate_id(terminal.event_kind, "event_kind")?;
        validate_id(terminal.outbox_intent_key, "outbox_intent_key")?;
        validate_id(terminal.outbox_kind, "outbox_kind")?;
        validate_payload(terminal.event_payload, "event_payload")?;
        validate_payload(terminal.outbox_payload, "outbox_payload")?;
        validate_time(terminal.now_ms)?;
        if terminal.run_id <= 0 {
            return Err(StoreError::InvalidField("run_id"));
        }
        let lease_now_ms = self.lease_now_ms(terminal.now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_live_lease(
            &transaction,
            terminal.generation_id,
            terminal.holder_id,
            terminal.lease_epoch,
            lease_now_ms,
        )?;

        let run = transaction
            .query_row(
                "SELECT state, revision, generation_id, lease_epoch, terminal_payload,
                        outbox_intent_key, inbox_id
                 FROM runs WHERE run_id = ?1",
                [terminal.run_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound("run"))?;
        let provenance = run_row_provenance(&transaction, terminal.run_id)?;
        let revision = from_db_u64(run.1, "run_revision")?;
        if run.2 != terminal.generation_id
            || from_db_u64(run.3, "lease_epoch")? != terminal.lease_epoch
        {
            return Err(StoreError::StaleEpoch);
        }
        if run.0 != "running" {
            if run.0 == terminal.state.as_str()
                && run.4.as_deref() == Some(terminal.event_payload)
                && run.5.as_deref() == Some(terminal.outbox_intent_key)
            {
                let receipt = terminal_receipt(&transaction, &terminal)?;
                transaction.commit()?;
                return Ok(TerminalReceipt {
                    duplicate: true,
                    ..receipt
                });
            }
            return Err(StoreError::AlreadyTerminal);
        }
        if revision != terminal.expected_revision {
            return Err(StoreError::IdempotencyConflict("expected_revision"));
        }
        let next_revision = revision
            .checked_add(1)
            .ok_or(StoreError::InvalidField("run_revision"))?;

        let lock_matches: bool = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM work_locks WHERE run_id = ?1 AND generation_id = ?2
                AND lease_epoch = ?3
             )",
            params![
                terminal.run_id,
                terminal.generation_id,
                to_db_u64(terminal.lease_epoch, "lease_epoch")?
            ],
            |row| row.get(0),
        )?;
        if !lock_matches {
            return Err(StoreError::StaleEpoch);
        }

        let run_changed = transaction.execute(
            "UPDATE runs SET state = ?2, revision = ?3, finished_ms = ?4,
             terminal_payload = ?5, outbox_intent_key = ?6
             WHERE run_id = ?1 AND generation_id = ?7 AND lease_epoch = ?8
               AND state = 'running' AND revision = ?9",
            params![
                terminal.run_id,
                terminal.state.as_str(),
                to_db_u64(next_revision, "run_revision")?,
                terminal.now_ms,
                terminal.event_payload,
                terminal.outbox_intent_key,
                terminal.generation_id,
                to_db_u64(terminal.lease_epoch, "lease_epoch")?,
                to_db_u64(revision, "run_revision")?
            ],
        )?;
        if run_changed != 1 {
            return Err(StoreError::StaleEpoch);
        }
        let inbox_state = match terminal.state {
            TerminalState::Succeeded => "completed",
            TerminalState::Failed => "failed",
        };
        let inbox_changed = transaction.execute(
            "UPDATE inbox SET state = ?2, revision = revision + 1
             WHERE inbox_id = ?1 AND state = 'claimed' AND claimed_run_id = ?3",
            params![run.6, inbox_state, terminal.run_id],
        )?;
        if inbox_changed != 1 {
            return Err(StoreError::IdempotencyConflict("inbox_state"));
        }
        let inbox_revision: i64 = transaction.query_row(
            "SELECT revision FROM inbox WHERE inbox_id = ?1",
            [run.6],
            |row| row.get(0),
        )?;
        let inbox_kind = if terminal.state == TerminalState::Succeeded {
            "inbox.completed"
        } else {
            "inbox.failed"
        };
        let event_provenance = provenance
            .as_ref()
            .map(|provenance| {
                child_provenance(
                    provenance.trace_id().as_str(),
                    provenance.correlation_id().as_str().to_owned(),
                    format!("run:{}", terminal.run_id),
                )
            })
            .transpose()?;
        let event_id = if let Some(provenance) = &event_provenance {
            append_event_with_provenance(
                &transaction,
                "inbox",
                &run.6.to_string(),
                from_db_u64(inbox_revision, "inbox_revision")?,
                terminal.now_ms,
                inbox_kind,
                terminal.event_payload,
                provenance,
            )?;
            append_event_with_provenance(
                &transaction,
                "run",
                &terminal.run_id.to_string(),
                next_revision,
                terminal.now_ms,
                terminal.event_kind,
                terminal.event_payload,
                provenance,
            )?
        } else {
            append_event(
                &transaction,
                "inbox",
                &run.6.to_string(),
                from_db_u64(inbox_revision, "inbox_revision")?,
                terminal.now_ms,
                inbox_kind,
                terminal.event_payload,
            )?;
            append_event(
                &transaction,
                "run",
                &terminal.run_id.to_string(),
                next_revision,
                terminal.now_ms,
                terminal.event_kind,
                terminal.event_payload,
            )?
        };
        let outbox_provenance = event_provenance
            .as_ref()
            .map(|provenance| {
                child_provenance(
                    provenance.trace_id().as_str(),
                    provenance.correlation_id().as_str().to_owned(),
                    format!("event:{event_id}"),
                )
            })
            .transpose()?;
        let insert = transaction.execute(
            "INSERT INTO outbox
             (intent_key, event_id, transport, kind, payload, state, revision,
              attempts, available_ms, created_ms, trace_id, correlation_id, causation_id)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 1, 0, ?6, ?6, ?7, ?8, ?9)",
            params![
                terminal.outbox_intent_key,
                event_id,
                outbox_transport(terminal.outbox_kind),
                terminal.outbox_kind,
                terminal.outbox_payload,
                terminal.now_ms,
                outbox_provenance
                    .as_ref()
                    .map(|value| value.trace_id().as_str()),
                outbox_provenance
                    .as_ref()
                    .map(|value| value.correlation_id().as_str()),
                outbox_provenance
                    .as_ref()
                    .map(|value| value.causation_id().as_str())
            ],
        );
        if let Err(error) = insert {
            if error
                .sqlite_error()
                .is_some_and(|code| code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE)
            {
                return Err(StoreError::OutboxConflict);
            }
            return Err(StoreError::Sqlite(error));
        }
        let outbox_id = transaction.last_insert_rowid();
        let lock_deleted = transaction.execute(
            "DELETE FROM work_locks WHERE run_id = ?1
             AND generation_id = ?2 AND lease_epoch = ?3",
            params![
                terminal.run_id,
                terminal.generation_id,
                to_db_u64(terminal.lease_epoch, "lease_epoch")?
            ],
        )?;
        if lock_deleted != 1 {
            return Err(StoreError::StaleEpoch);
        }
        transaction.commit()?;
        Ok(TerminalReceipt {
            event_id,
            outbox_id,
            duplicate: false,
        })
    }

    /// Read one run for operator status or recovery.
    pub fn run_snapshot(&self, run_id: i64) -> Result<RunSnapshot, StoreError> {
        let (state, revision) = self
            .connection
            .query_row(
                "SELECT state, revision FROM runs WHERE run_id = ?1",
                [run_id],
                |row| {
                    let revision = row.get::<_, i64>(1)?;
                    Ok((row.get::<_, String>(0)?, revision))
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound("run"))?;
        Ok(RunSnapshot {
            state,
            revision: from_db_u64(revision, "run_revision")?,
        })
    }

    /// Count durable events, primarily for readiness and recovery evidence.
    pub fn event_count(&self) -> Result<u64, StoreError> {
        count_table(&self.connection, "domain_events")
    }

    /// Count pending and delivered effect intents.
    pub fn outbox_count(&self) -> Result<u64, StoreError> {
        count_table(&self.connection, "outbox")
    }

    /// Queue one external effect under the current generation fence.
    ///
    /// Replaying an identical intent is idempotent, including after restart.
    /// Reusing its key for a different kind or payload is a conflict.
    pub fn enqueue_outbox(
        &mut self,
        request: OutboxEnqueue<'_>,
    ) -> Result<OutboxEnqueueReceipt, StoreError> {
        validate_id(request.intent_key, "outbox_intent_key")?;
        validate_id(request.kind, "outbox_kind")?;
        validate_payload(request.payload, "outbox_payload")?;
        validate_id(request.generation_id, "generation_id")?;
        validate_id(request.holder_id, "holder_id")?;
        validate_time(request.now_ms)?;
        let lease_now_ms = self.lease_now_ms(request.now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_live_lease(
            &transaction,
            request.generation_id,
            request.holder_id,
            request.lease_epoch,
            lease_now_ms,
        )?;
        if let Some((outbox_id, event_id, kind, payload)) = transaction
            .query_row(
                "SELECT outbox_id, event_id, kind, payload FROM outbox
                 WHERE intent_key = ?1",
                [request.intent_key],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?
        {
            if kind == request.kind && payload == request.payload {
                transaction.commit()?;
                return Ok(OutboxEnqueueReceipt {
                    event_id,
                    outbox_id,
                    duplicate: true,
                });
            }
            return Err(StoreError::OutboxConflict);
        }
        let root_trace = TraceId::for_ingress("outbox", request.intent_key);
        let event_provenance = child_provenance(
            root_trace.as_str(),
            root_trace.as_str().to_owned(),
            provenance_coordinate("generation", request.generation_id, root_trace.as_str()),
        )?;
        let event_id = append_event_with_provenance(
            &transaction,
            "outbox_intent",
            request.intent_key,
            1,
            request.now_ms,
            "outbox.queued",
            request.payload,
            &event_provenance,
        )?;
        let outbox_provenance = child_provenance(
            root_trace.as_str(),
            root_trace.as_str().to_owned(),
            format!("event:{event_id}"),
        )?;
        let insert = transaction.execute(
            "INSERT INTO outbox
             (intent_key, event_id, transport, kind, payload, state, revision,
              attempts, available_ms, created_ms, trace_id, correlation_id, causation_id)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 1, 0, ?6, ?6, ?7, ?8, ?9)",
            params![
                request.intent_key,
                event_id,
                outbox_transport(request.kind),
                request.kind,
                request.payload,
                request.now_ms,
                outbox_provenance.trace_id().as_str(),
                outbox_provenance.correlation_id().as_str(),
                outbox_provenance.causation_id().as_str()
            ],
        );
        if let Err(error) = insert {
            if error
                .sqlite_error()
                .is_some_and(|code| code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE)
            {
                return Err(StoreError::OutboxConflict);
            }
            return Err(StoreError::Sqlite(error));
        }
        let outbox_id = transaction.last_insert_rowid();
        transaction.commit()?;
        Ok(OutboxEnqueueReceipt {
            event_id,
            outbox_id,
            duplicate: false,
        })
    }

    /// Claim the oldest matching ready effect without exposing its payload.
    pub fn claim_outbox(
        &mut self,
        request: OutboxClaimRequest<'_>,
    ) -> Result<Option<OutboxLease>, StoreError> {
        validate_id(request.transport, "outbox_transport")?;
        validate_id(request.kind, "outbox_kind")?;
        validate_id(request.generation_id, "generation_id")?;
        validate_id(request.holder_id, "holder_id")?;
        validate_time(request.now_ms)?;
        let lease_now_ms = self.lease_now_ms(request.now_ms)?;
        let requested_expiry = checked_expiry(lease_now_ms, request.ttl_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let generation_expiry = require_live_lease(
            &transaction,
            request.generation_id,
            request.holder_id,
            request.lease_epoch,
            lease_now_ms,
        )?;
        let row = transaction
            .query_row(
                "SELECT outbox_id, intent_key, transport, kind, state, revision,
                        attempts, available_ms, lease_token, lease_generation_id,
                        lease_holder, lease_epoch, lease_expires_ms
                 FROM outbox
                 WHERE transport = ?1 AND kind = ?2
                   AND (state = 'in_flight'
                        OR (state = 'pending' AND available_ms <= ?3))
                 ORDER BY created_ms, outbox_id LIMIT 1",
                params![request.transport, request.kind, request.now_ms],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, Option<String>>(9)?,
                        row.get::<_, Option<String>>(10)?,
                        row.get::<_, Option<i64>>(11)?,
                        row.get::<_, Option<i64>>(12)?,
                    ))
                },
            )
            .optional()?;
        let Some(row) = row else {
            transaction.commit()?;
            return Ok(None);
        };
        let revision = from_db_u64(row.5, "outbox_revision")?;
        let attempt = from_db_u64(row.6, "outbox_attempt")?;
        if row.4 == "in_flight" {
            let expires_ms = row.12.ok_or(StoreError::MigrationInvariant(
                "in_flight_outbox_without_expiry",
            ))?;
            if expires_ms <= lease_now_ms {
                return Err(StoreError::OutboxReconciliationRequired { outbox_id: row.0 });
            }
            if row.9.as_deref() != Some(request.generation_id)
                || row.10.as_deref() != Some(request.holder_id)
                || row
                    .11
                    .map(|epoch| from_db_u64(epoch, "outbox_lease_epoch"))
                    .transpose()?
                    != Some(request.lease_epoch)
            {
                return Err(StoreError::LeaseHeld);
            }
            let lease_token = row.8.ok_or(StoreError::MigrationInvariant(
                "in_flight_outbox_without_token",
            ))?;
            transaction.commit()?;
            return Ok(Some(OutboxLease {
                outbox_id: row.0,
                intent_key: row.1,
                transport: row.2,
                kind: row.3,
                lease_token,
                attempt,
                retry_after_ms: expires_ms,
                revision,
                duplicate: true,
            }));
        }
        let next_attempt = attempt
            .checked_add(1)
            .ok_or(StoreError::InvalidField("outbox_attempt"))?;
        let next_revision = revision
            .checked_add(1)
            .ok_or(StoreError::InvalidField("outbox_revision"))?;
        let expires_ms = requested_expiry.min(generation_expiry);
        let lease_token = format!(
            "outbox:{}:attempt:{}:epoch:{}",
            row.0, next_attempt, request.lease_epoch
        );
        let changed = transaction.execute(
            "UPDATE outbox SET state = 'in_flight', revision = ?2, attempts = ?3,
                    lease_token = ?4, lease_generation_id = ?5, lease_holder = ?6,
                    lease_epoch = ?7, lease_expires_ms = ?8, last_error = NULL
             WHERE outbox_id = ?1 AND state = 'pending' AND revision = ?9",
            params![
                row.0,
                to_db_u64(next_revision, "outbox_revision")?,
                to_db_u64(next_attempt, "outbox_attempt")?,
                lease_token,
                request.generation_id,
                request.holder_id,
                to_db_u64(request.lease_epoch, "outbox_lease_epoch")?,
                expires_ms,
                row.5
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::IdempotencyConflict("outbox_claim"));
        }
        transaction.commit()?;
        Ok(Some(OutboxLease {
            outbox_id: row.0,
            intent_key: row.1,
            transport: row.2,
            kind: row.3,
            lease_token,
            attempt: next_attempt,
            retry_after_ms: expires_ms,
            revision: next_revision,
            duplicate: false,
        }))
    }

    /// Read payload only for the exact still-live delivery lease.
    pub fn leased_outbox_payload(
        &mut self,
        request: OutboxPayloadRequest<'_>,
    ) -> Result<LeasedOutboxPayload, StoreError> {
        validate_outbox_lease_request(
            request.outbox_id,
            request.generation_id,
            request.holder_id,
            request.lease_token,
            request.now_ms,
        )?;
        let lease_now_ms = self.lease_now_ms(request.now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_live_lease(
            &transaction,
            request.generation_id,
            request.holder_id,
            request.lease_epoch,
            lease_now_ms,
        )?;
        let payload = transaction
            .query_row(
                "SELECT intent_key, payload FROM outbox
                 WHERE outbox_id = ?1 AND state = 'in_flight'
                   AND lease_generation_id = ?2 AND lease_holder = ?3
                   AND lease_epoch = ?4 AND lease_token = ?5
                   AND lease_expires_ms > ?6",
                params![
                    request.outbox_id,
                    request.generation_id,
                    request.holder_id,
                    to_db_u64(request.lease_epoch, "outbox_lease_epoch")?,
                    request.lease_token,
                    lease_now_ms
                ],
                |row| {
                    Ok(LeasedOutboxPayload {
                        outbox_id: request.outbox_id,
                        intent_key: row.get(0)?,
                        payload: row.get(1)?,
                    })
                },
            )
            .optional()?
            .ok_or(StoreError::StaleEpoch)?;
        transaction.commit()?;
        Ok(payload)
    }

    /// Commit an exact external delivery receipt idempotently.
    pub fn deliver_outbox(
        &mut self,
        delivery: OutboxDelivery<'_>,
    ) -> Result<OutboxDeliveryReceipt, StoreError> {
        validate_outbox_lease_request(
            delivery.outbox_id,
            delivery.generation_id,
            delivery.holder_id,
            delivery.lease_token,
            delivery.now_ms,
        )?;
        validate_id(delivery.receipt_key, "outbox_receipt_key")?;
        let lease_now_ms = self.lease_now_ms(delivery.now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_live_lease(
            &transaction,
            delivery.generation_id,
            delivery.holder_id,
            delivery.lease_epoch,
            lease_now_ms,
        )?;
        let row = outbox_delivery_row(&transaction, delivery.outbox_id)?;
        let revision = from_db_u64(row.1, "outbox_revision")?;
        let attempt = from_db_u64(row.2, "outbox_attempt")?;
        if row.0 == "delivered" {
            if attempt == delivery.expected_attempt
                && row.3.as_deref() == Some(delivery.lease_token)
                && row.4.as_deref() == Some(delivery.generation_id)
                && row.5.as_deref() == Some(delivery.holder_id)
                && row
                    .8
                    .map(|value| from_db_u64(value, "outbox_lease_epoch"))
                    .transpose()?
                    == Some(delivery.lease_epoch)
                && row.6.as_deref() == Some(delivery.receipt_key)
            {
                transaction.commit()?;
                return Ok(OutboxDeliveryReceipt {
                    outbox_id: delivery.outbox_id,
                    receipt_key: delivery.receipt_key.to_owned(),
                    revision,
                    duplicate: true,
                });
            }
            return Err(StoreError::AlreadyTerminal);
        }
        require_exact_outbox_lease(
            &row,
            &OutboxLeaseIdentity {
                outbox_id: delivery.outbox_id,
                generation_id: delivery.generation_id,
                holder_id: delivery.holder_id,
                lease_epoch: delivery.lease_epoch,
                lease_token: delivery.lease_token,
                expected_attempt: delivery.expected_attempt,
                now_ms: lease_now_ms,
            },
        )?;
        let next_revision = revision
            .checked_add(1)
            .ok_or(StoreError::InvalidField("outbox_revision"))?;
        let changed = transaction.execute(
            "UPDATE outbox SET state = 'delivered', revision = ?2,
                    delivery_receipt_key = ?3, delivered_ms = ?4
             WHERE outbox_id = ?1 AND state = 'in_flight' AND revision = ?5
               AND lease_generation_id = ?6 AND lease_holder = ?7
               AND lease_epoch = ?8 AND lease_token = ?9 AND attempts = ?10",
            params![
                delivery.outbox_id,
                to_db_u64(next_revision, "outbox_revision")?,
                delivery.receipt_key,
                delivery.now_ms,
                row.1,
                delivery.generation_id,
                delivery.holder_id,
                to_db_u64(delivery.lease_epoch, "outbox_lease_epoch")?,
                delivery.lease_token,
                to_db_u64(delivery.expected_attempt, "outbox_attempt")?
            ],
        );
        map_outbox_unique(changed)?;
        transaction.commit()?;
        Ok(OutboxDeliveryReceipt {
            outbox_id: delivery.outbox_id,
            receipt_key: delivery.receipt_key.to_owned(),
            revision: next_revision,
            duplicate: false,
        })
    }

    /// Record an explicit retry or dead-letter outcome while the lease is live.
    ///
    /// This transition is deliberately not presented as replayable: after an
    /// acknowledgement loss the caller must inspect durable outbox state. An
    /// identical second call refuses rather than claiming an unproven replay.
    pub fn fail_outbox(
        &mut self,
        failure: OutboxFailure<'_>,
    ) -> Result<OutboxOutcomeReceipt, StoreError> {
        validate_outbox_lease_request(
            failure.outbox_id,
            failure.generation_id,
            failure.holder_id,
            failure.lease_token,
            failure.now_ms,
        )?;
        let (state, reason, retry_after) = match failure.decision {
            OutboxFailureDecision::Retry {
                reason,
                retry_after_ms,
            } => {
                validate_time(retry_after_ms)?;
                if retry_after_ms <= failure.now_ms {
                    return Err(StoreError::InvalidField("outbox_retry_after"));
                }
                ("pending", reason, Some(retry_after_ms))
            }
            OutboxFailureDecision::DeadLetter { reason } => ("dead_lettered", reason, None),
        };
        validate_id(reason, "outbox_failure_reason")?;
        let lease_now_ms = self.lease_now_ms(failure.now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_live_lease(
            &transaction,
            failure.generation_id,
            failure.holder_id,
            failure.lease_epoch,
            lease_now_ms,
        )?;
        let row = outbox_delivery_row(&transaction, failure.outbox_id)?;
        require_exact_outbox_lease(
            &row,
            &OutboxLeaseIdentity {
                outbox_id: failure.outbox_id,
                generation_id: failure.generation_id,
                holder_id: failure.holder_id,
                lease_epoch: failure.lease_epoch,
                lease_token: failure.lease_token,
                expected_attempt: failure.expected_attempt,
                now_ms: lease_now_ms,
            },
        )?;
        let revision = from_db_u64(row.1, "outbox_revision")?;
        let next_revision = revision
            .checked_add(1)
            .ok_or(StoreError::InvalidField("outbox_revision"))?;
        let available_ms = retry_after.unwrap_or(failure.now_ms);
        let delivered_ms = (state == "dead_lettered").then_some(failure.now_ms);
        let changed = transaction.execute(
            "UPDATE outbox SET state = ?2, revision = ?3, available_ms = ?4,
                    lease_token = NULL, lease_generation_id = NULL,
                    lease_holder = NULL, lease_epoch = NULL, lease_expires_ms = NULL,
                    delivered_ms = ?5, last_error = ?6
             WHERE outbox_id = ?1 AND state = 'in_flight' AND revision = ?7
               AND lease_generation_id = ?8 AND lease_holder = ?9
               AND lease_epoch = ?10 AND lease_token = ?11 AND attempts = ?12",
            params![
                failure.outbox_id,
                state,
                to_db_u64(next_revision, "outbox_revision")?,
                available_ms,
                delivered_ms,
                reason,
                row.1,
                failure.generation_id,
                failure.holder_id,
                to_db_u64(failure.lease_epoch, "outbox_lease_epoch")?,
                failure.lease_token,
                to_db_u64(failure.expected_attempt, "outbox_attempt")?
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::IdempotencyConflict("outbox_failure"));
        }
        transaction.commit()?;
        Ok(OutboxOutcomeReceipt {
            outbox_id: failure.outbox_id,
            state: state.to_owned(),
            revision: next_revision,
        })
    }

    /// Inspect exact durable state without exposing effect payload bytes.
    pub fn inspect_outbox_reconciliation(
        &self,
        outbox_id: i64,
    ) -> Result<OutboxReconciliationEvidence, StoreError> {
        if outbox_id <= 0 {
            return Err(StoreError::InvalidField("outbox_id"));
        }
        let row = self
            .connection
            .query_row(
                "SELECT intent_key, transport, kind, state, revision, attempts,
                        lease_token, lease_generation_id, lease_holder, lease_epoch,
                        lease_expires_ms, delivery_receipt_key, available_ms,
                        last_error, trace_id, correlation_id, causation_id
                 FROM outbox WHERE outbox_id = ?1",
                [outbox_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, Option<i64>>(9)?,
                        row.get::<_, Option<i64>>(10)?,
                        row.get::<_, Option<String>>(11)?,
                        row.get::<_, i64>(12)?,
                        row.get::<_, Option<String>>(13)?,
                        row.get::<_, Option<String>>(14)?,
                        row.get::<_, Option<String>>(15)?,
                        row.get::<_, Option<String>>(16)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound("outbox"))?;
        Ok(OutboxReconciliationEvidence {
            outbox_id,
            intent_key: row.0,
            transport: row.1,
            kind: row.2,
            state: row.3,
            revision: from_db_u64(row.4, "outbox_revision")?,
            attempt: from_db_u64(row.5, "outbox_attempt")?,
            lease_token: row.6,
            lease_generation_id: row.7,
            lease_holder: row.8,
            lease_epoch: row
                .9
                .map(|value| from_db_u64(value, "outbox_lease_epoch"))
                .transpose()?,
            lease_expires_ms: row.10,
            delivery_receipt_key: row.11,
            available_ms: row.12,
            last_error: row.13,
            provenance: stored_provenance(row.14, row.15, row.16)?,
        })
    }

    /// Reconstruct one terminal effect's exact durable ancestry in one query.
    pub fn causal_chain_for_outbox(&self, outbox_id: i64) -> Result<CausalChain, StoreError> {
        if outbox_id <= 0 {
            return Err(StoreError::InvalidField("outbox_id"));
        }
        let row = self
            .connection
            .query_row(
                "SELECT i.inbox_id, i.transport, i.transport_key,
                        r.run_id, e.event_id, e.kind, o.outbox_id, o.kind,
                        o.trace_id, o.correlation_id, o.causation_id,
                        r.causation_id, e.causation_id
                 FROM outbox o
                 JOIN domain_events e ON e.event_id = o.event_id
                 JOIN runs r ON e.aggregate_kind = 'run'
                            AND e.aggregate_id = CAST(r.run_id AS TEXT)
                 JOIN inbox i ON i.inbox_id = r.inbox_id
                 WHERE o.outbox_id = ?1
                   AND i.trace_id = r.trace_id
                   AND r.trace_id = e.trace_id
                   AND e.trace_id = o.trace_id",
                [outbox_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, Option<String>>(9)?,
                        row.get::<_, Option<String>>(10)?,
                        row.get::<_, Option<String>>(11)?,
                        row.get::<_, Option<String>>(12)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound("causal_chain"))?;
        let provenance = stored_provenance(row.8, row.9, row.10)?.ok_or(
            StoreError::MigrationInvariant("causal_chain_without_provenance"),
        )?;
        let run_causation_id = row
            .11
            .ok_or(StoreError::MigrationInvariant("run_without_causation"))?;
        let event_causation_id = row
            .12
            .ok_or(StoreError::MigrationInvariant("event_without_causation"))?;
        let expected_run_cause = format!("inbox:{}", row.0);
        let expected_event_cause = format!("run:{}", row.3);
        let expected_outbox_cause = format!("event:{}", row.4);
        if run_causation_id != expected_run_cause
            || event_causation_id != expected_event_cause
            || provenance.causation_id != expected_outbox_cause
        {
            return Err(StoreError::MigrationInvariant("broken_causal_chain"));
        }
        Ok(CausalChain {
            inbox_id: row.0,
            inbox_transport: row.1,
            inbox_transport_key: row.2,
            run_id: row.3,
            event_id: row.4,
            event_kind: row.5,
            outbox_id: row.6,
            outbox_kind: row.7,
            provenance,
            run_causation_id,
            event_causation_id,
            outbox_causation_id: expected_outbox_cause,
        })
    }

    /// Close an expired ambiguous effect; reconciliation never requeues it.
    pub fn reconcile_outbox(
        &mut self,
        request: OutboxReconciliationRequest<'_>,
    ) -> Result<OutboxReconciliationReceipt, StoreError> {
        validate_outbox_lease_request(
            request.outbox_id,
            request.authority_generation_id,
            request.authority_holder_id,
            request.expected_lease_token,
            request.now_ms,
        )?;
        validate_id(request.expected_generation_id, "expected_generation_id")?;
        let (state, value) = match request.decision {
            OutboxReconciliationDecision::Delivered { receipt_key } => {
                validate_id(receipt_key, "outbox_receipt_key")?;
                ("delivered", receipt_key)
            }
            OutboxReconciliationDecision::DeadLetter { reason } => {
                validate_id(reason, "outbox_failure_reason")?;
                ("dead_lettered", reason)
            }
        };
        let lease_now_ms = self.lease_now_ms(request.now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_reconciliation_authority(
            &transaction,
            request.authority_generation_id,
            request.authority_holder_id,
            request.authority_lease_epoch,
            lease_now_ms,
        )?;
        let row = outbox_delivery_row(&transaction, request.outbox_id)?;
        let revision = from_db_u64(row.1, "outbox_revision")?;
        let attempt = from_db_u64(row.2, "outbox_attempt")?;
        if row.0 != "in_flight" {
            let exact = revision
                == request
                    .expected_revision
                    .checked_add(1)
                    .ok_or(StoreError::InvalidField("expected_revision"))?
                && attempt == request.expected_attempt
                && row.3.as_deref() == Some(request.expected_lease_token)
                && row.4.as_deref() == Some(request.expected_generation_id)
                && row
                    .8
                    .map(|epoch| from_db_u64(epoch, "outbox_lease_epoch"))
                    .transpose()?
                    == Some(request.expected_lease_epoch)
                && ((state == "delivered" && row.6.as_deref() == Some(value))
                    || (state == "dead_lettered" && row.7.as_deref() == Some(value)))
                && row.0 == state;
            if !exact {
                return Err(StoreError::AlreadyTerminal);
            }
            transaction.commit()?;
            return Ok(OutboxReconciliationReceipt {
                outbox_id: request.outbox_id,
                state: state.to_owned(),
                revision,
                duplicate: true,
            });
        }
        if revision != request.expected_revision || attempt != request.expected_attempt {
            return Err(StoreError::IdempotencyConflict(
                "outbox_reconciliation_revision",
            ));
        }
        if row.3.as_deref() != Some(request.expected_lease_token)
            || row.4.as_deref() != Some(request.expected_generation_id)
            || row
                .8
                .map(|epoch| from_db_u64(epoch, "outbox_lease_epoch"))
                .transpose()?
                != Some(request.expected_lease_epoch)
        {
            return Err(StoreError::StaleEpoch);
        }
        if row.9.is_none_or(|expires_ms| expires_ms > lease_now_ms) {
            return Err(StoreError::LeaseHeld);
        }
        let next_revision = revision
            .checked_add(1)
            .ok_or(StoreError::InvalidField("outbox_revision"))?;
        let (receipt_key, last_error) = if state == "delivered" {
            (Some(value), None)
        } else {
            (None, Some(value))
        };
        let changed = transaction.execute(
            "UPDATE outbox SET state = ?2, revision = ?3,
                    delivery_receipt_key = ?4, delivered_ms = ?5, last_error = ?6
             WHERE outbox_id = ?1 AND state = 'in_flight' AND revision = ?7
               AND lease_generation_id = ?8 AND lease_epoch = ?9
               AND lease_token = ?10 AND attempts = ?11",
            params![
                request.outbox_id,
                state,
                to_db_u64(next_revision, "outbox_revision")?,
                receipt_key,
                request.now_ms,
                last_error,
                row.1,
                request.expected_generation_id,
                to_db_u64(request.expected_lease_epoch, "outbox_lease_epoch")?,
                request.expected_lease_token,
                to_db_u64(request.expected_attempt, "outbox_attempt")?
            ],
        );
        map_outbox_unique(changed)?;
        transaction.commit()?;
        Ok(OutboxReconciliationReceipt {
            outbox_id: request.outbox_id,
            state: state.to_owned(),
            revision: next_revision,
            duplicate: false,
        })
    }

    /// Read one effect-intent classification without exposing its payload.
    pub fn outbox_snapshot(&self, outbox_id: i64) -> Result<OutboxSnapshot, StoreError> {
        if outbox_id <= 0 {
            return Err(StoreError::InvalidField("outbox_id"));
        }
        self.connection
            .query_row(
                "SELECT kind, state FROM outbox WHERE outbox_id = ?1",
                [outbox_id],
                |row| {
                    Ok(OutboxSnapshot {
                        kind: row.get(0)?,
                        state: row.get(1)?,
                    })
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound("outbox"))
    }

    /// Whether a scope lock currently exists.
    pub fn scope_is_locked(&self, scope: &str) -> Result<bool, StoreError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM work_locks WHERE scope = ?1)",
            [scope],
            |row| row.get(0),
        )?)
    }

    /// Compatibility aggregate snapshot at epoch zero.
    ///
    /// Existing callers may read generation/cursor/aggregate pending/running
    /// fields. Operational projections must use [`Self::status_snapshot_at`].
    pub fn status_snapshot(&mut self, generation_id: &str) -> Result<StatusSnapshot, StoreError> {
        self.status_snapshot_at(generation_id, 0)
    }

    /// Observe time-classified queue status from one consistent SQLite snapshot.
    /// Ready-item age clamps to zero when a stored creation timestamp is later
    /// than the explicit observation time.
    pub fn status_snapshot_at(
        &mut self,
        generation_id: &str,
        now_ms: i64,
    ) -> Result<StatusSnapshot, StoreError> {
        validate_id(generation_id, "generation_id")?;
        validate_time(now_ms)?;
        let lease_now_ms = self.lease_now_ms(now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let generation = transaction
            .query_row(
                "SELECT generation_id, revision, state, lease_holder, lease_epoch,
                        lease_expires_ms, boot_id, holder_pid, holder_starttime
                 FROM generations WHERE generation_id = ?1",
                [generation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                    ))
                },
            )
            .optional()?
            .map(|row| {
                Ok::<_, StoreError>(GenerationSnapshot {
                    generation_id: row.0,
                    revision: from_db_u64(row.1, "generation_revision")?,
                    state: row.2,
                    holder_id: row.3,
                    lease_epoch: from_db_u64(row.4, "lease_epoch")?,
                    lease_expires_ms: row.5,
                    boot_id: row.6,
                    holder_pid: u32::try_from(row.7)
                        .map_err(|_| StoreError::MigrationInvariant("holder_pid"))?,
                    holder_starttime: from_db_u64(row.8, "holder_starttime")?,
                })
            })
            .transpose()?;
        let event_cursor = query_count(
            &transaction,
            "SELECT COALESCE(MAX(event_id), 0) FROM domain_events",
        )?;
        let inbox_pending = query_count(
            &transaction,
            "SELECT count(*) FROM inbox WHERE state = 'pending'",
        )?;
        let outbox_pending = query_count(
            &transaction,
            "SELECT count(*) FROM outbox WHERE state = 'pending'",
        )?;
        let runs_running = query_count(
            &transaction,
            "SELECT count(*) FROM runs WHERE state = 'running'",
        )?;
        let runs_reconciliation_pending: i64 = transaction.query_row(
            "SELECT count(DISTINCT r.run_id) FROM runs r
             JOIN work_locks w ON w.run_id = r.run_id
             WHERE r.state = 'running' AND w.expires_ms <= ?1",
            [lease_now_ms],
            |row| row.get(0),
        )?;
        let outbox_counts: (i64, i64, i64, i64, i64, i64, Option<i64>) =
            transaction.query_row(
                "SELECT
                    COALESCE(sum(CASE WHEN state = 'pending' AND available_ms <= ?1 THEN 1 ELSE 0 END), 0),
                    COALESCE(sum(CASE WHEN state = 'pending' AND available_ms > ?1 THEN 1 ELSE 0 END), 0),
                    COALESCE(sum(CASE WHEN state = 'in_flight' AND lease_expires_ms > ?2 THEN 1 ELSE 0 END), 0),
                    COALESCE(sum(CASE WHEN state = 'in_flight' AND lease_expires_ms <= ?2 THEN 1 ELSE 0 END), 0),
                    COALESCE(sum(CASE WHEN state = 'delivered' THEN 1 ELSE 0 END), 0),
                    COALESCE(sum(CASE WHEN state = 'dead_lettered' THEN 1 ELSE 0 END), 0),
                    min(CASE WHEN state = 'pending' AND available_ms <= ?1 THEN created_ms END)
                 FROM outbox",
                params![now_ms, lease_now_ms],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )?;
        let poller_counts: (i64, i64) = transaction.query_row(
            "SELECT
                COALESCE(sum(CASE WHEN p.expires_ms > ?1 AND g.lease_holder = p.holder_id
                              AND g.lease_epoch = p.authority_lease_epoch
                              AND g.lease_expires_ms > ?1 THEN 1 ELSE 0 END), 0),
                COALESCE(sum(CASE WHEN NOT (p.expires_ms > ?1 AND g.lease_holder = p.holder_id
                                  AND g.lease_epoch = p.authority_lease_epoch
                                  AND g.lease_expires_ms > ?1) THEN 1 ELSE 0 END), 0)
             FROM telegram_poller_leases p
             JOIN generations g ON g.generation_id = p.generation_id
             WHERE p.generation_id = ?2",
            params![lease_now_ms, generation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        transaction.commit()?;
        Ok(StatusSnapshot {
            schema_version: SCHEMA_VERSION,
            observed_ms: now_ms,
            lease_observed_boottime_ms: lease_now_ms,
            generation,
            event_cursor,
            inbox_pending,
            outbox_pending,
            runs_running,
            runs_reconciliation_pending: from_db_u64(
                runs_reconciliation_pending,
                "runs_reconciliation_pending",
            )?,
            outbox_pending_ready: from_db_u64(outbox_counts.0, "outbox_pending_ready")?,
            outbox_pending_delayed: from_db_u64(outbox_counts.1, "outbox_pending_delayed")?,
            outbox_in_flight_live: from_db_u64(outbox_counts.2, "outbox_in_flight_live")?,
            outbox_in_flight_ambiguous: from_db_u64(outbox_counts.3, "outbox_in_flight_ambiguous")?,
            outbox_delivered: from_db_u64(outbox_counts.4, "outbox_delivered")?,
            outbox_dead_lettered: from_db_u64(outbox_counts.5, "outbox_dead_lettered")?,
            outbox_oldest_ready_age_ms: outbox_counts
                .6
                .map_or(0, |created_ms| now_ms.saturating_sub(created_ms))
                .try_into()
                .map_err(|_| StoreError::MigrationInvariant("outbox_ready_age"))?,
            telegram_pollers_live: from_db_u64(poller_counts.0, "telegram_pollers_live")?,
            telegram_pollers_expired: from_db_u64(poller_counts.1, "telegram_pollers_expired")?,
        })
    }
}

fn validate_database_path(path: &Path) -> Result<(), StoreError> {
    if !path.is_absolute() {
        return Err(StoreError::InsecurePath("path must be absolute".to_owned()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::InsecurePath("path has no parent".to_owned()))?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    validate_owned_private(&parent_metadata, true, "parent")?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        validate_owned_private(&metadata, false, "database")?;
    }
    Ok(())
}

fn validate_owned_private(
    metadata: &fs::Metadata,
    directory: bool,
    label: &str,
) -> Result<(), StoreError> {
    let expected_kind = if directory {
        metadata.file_type().is_dir()
    } else {
        metadata.file_type().is_file()
    };
    if !expected_kind || metadata.file_type().is_symlink() {
        return Err(StoreError::InsecurePath(format!(
            "{label} has the wrong file type"
        )));
    }
    if metadata.uid() != geteuid().as_raw() {
        return Err(StoreError::InsecurePath(format!(
            "{label} has a foreign owner"
        )));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(StoreError::InsecurePath(format!(
            "{label} permits group/other access"
        )));
    }
    Ok(())
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Result<(), StoreError> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    if version == 1 {
        let duplicate_inbox: bool = connection.query_row(
            "SELECT EXISTS(
                SELECT inbox_id FROM runs GROUP BY inbox_id HAVING count(*) > 1
             )",
            [],
            |row| row.get(0),
        )?;
        if duplicate_inbox {
            return Err(StoreError::MigrationInvariant("duplicate_runs_for_inbox"));
        }
        connection.pragma_update(None, "foreign_keys", "OFF")?;
        let migration = (|| -> Result<(), StoreError> {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(MIGRATE_V1_TO_V2)?;
            transaction.pragma_update(None, "user_version", 2)?;
            transaction.commit()?;
            Ok(())
        })();
        connection.pragma_update(None, "foreign_keys", "ON")?;
        migration?;
        let foreign_key_violation: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
            [],
            |row| row.get(0),
        )?;
        if foreign_key_violation {
            return Err(StoreError::MigrationInvariant("foreign_key_check"));
        }
        migrate_v2_to_v3(connection)?;
        migrate_v3_to_v4(connection)?;
        migrate_v4_to_v5(connection)?;
        migrate_v5_to_v6(connection)?;
        migrate_v6_to_v7(connection)?;
        migrate_v7_to_v8(connection)?;
        migrate_v8_to_v9(connection)?;
        return migrate_v9_to_v10(connection);
    }
    if version == 2 {
        migrate_v2_to_v3(connection)?;
        migrate_v3_to_v4(connection)?;
        migrate_v4_to_v5(connection)?;
        migrate_v5_to_v6(connection)?;
        migrate_v6_to_v7(connection)?;
        migrate_v7_to_v8(connection)?;
        migrate_v8_to_v9(connection)?;
        return migrate_v9_to_v10(connection);
    }
    if version == 3 {
        migrate_v3_to_v4(connection)?;
        migrate_v4_to_v5(connection)?;
        migrate_v5_to_v6(connection)?;
        migrate_v6_to_v7(connection)?;
        migrate_v7_to_v8(connection)?;
        migrate_v8_to_v9(connection)?;
        return migrate_v9_to_v10(connection);
    }
    if version == 4 {
        migrate_v4_to_v5(connection)?;
        migrate_v5_to_v6(connection)?;
        migrate_v6_to_v7(connection)?;
        migrate_v7_to_v8(connection)?;
        migrate_v8_to_v9(connection)?;
        return migrate_v9_to_v10(connection);
    }
    if version == 5 {
        migrate_v5_to_v6(connection)?;
        migrate_v6_to_v7(connection)?;
        migrate_v7_to_v8(connection)?;
        migrate_v8_to_v9(connection)?;
        return migrate_v9_to_v10(connection);
    }
    if version == 6 {
        migrate_v6_to_v7(connection)?;
        migrate_v7_to_v8(connection)?;
        migrate_v8_to_v9(connection)?;
        return migrate_v9_to_v10(connection);
    }
    if version == 7 {
        migrate_v7_to_v8(connection)?;
        migrate_v8_to_v9(connection)?;
        return migrate_v9_to_v10(connection);
    }
    if version == 8 {
        migrate_v8_to_v9(connection)?;
        return migrate_v9_to_v10(connection);
    }
    if version == 9 {
        return migrate_v9_to_v10(connection);
    }
    if version != 0 {
        return Err(StoreError::SchemaVersion {
            found: version,
            supported: SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(StoreError::SchemaVersion {
            found: 0,
            supported: SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V2)?;
    transaction.execute_batch(MIGRATE_V2_TO_V3)?;
    transaction.execute_batch(MIGRATE_V3_TO_V4)?;
    transaction.execute_batch(MIGRATE_V4_TO_V5)?;
    transaction.execute_batch(MIGRATE_V5_TO_V6)?;
    transaction.execute_batch(MIGRATE_V6_TO_V7)?;
    transaction.execute_batch(MIGRATE_V7_TO_V8)?;
    transaction.execute_batch(MIGRATE_V8_TO_V9)?;
    transaction.execute_batch(MIGRATE_V9_TO_V10)?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v2_to_v3(connection: &mut Connection) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(MIGRATE_V2_TO_V3)?;
    transaction.pragma_update(None, "user_version", 3)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v3_to_v4(connection: &mut Connection) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(MIGRATE_V3_TO_V4)?;
    transaction.pragma_update(None, "user_version", 4)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v4_to_v5(connection: &mut Connection) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(MIGRATE_V4_TO_V5)?;
    transaction.pragma_update(None, "user_version", 5)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v5_to_v6(connection: &mut Connection) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(MIGRATE_V5_TO_V6)?;
    transaction.pragma_update(None, "user_version", 6)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v6_to_v7(connection: &mut Connection) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(MIGRATE_V6_TO_V7)?;
    transaction.pragma_update(None, "user_version", 7)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v7_to_v8(connection: &mut Connection) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(MIGRATE_V7_TO_V8)?;
    transaction.pragma_update(None, "user_version", 8)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v8_to_v9(connection: &mut Connection) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(MIGRATE_V8_TO_V9)?;
    transaction.pragma_update(None, "user_version", 9)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v9_to_v10(connection: &mut Connection) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(MIGRATE_V9_TO_V10)?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn validate_telegram_poller_request(
    bot_id: i64,
    generation_id: &str,
    holder_id: &str,
    now_ms: i64,
) -> Result<(), StoreError> {
    if bot_id <= 0 {
        return Err(StoreError::InvalidField("telegram_bot_id"));
    }
    validate_id(generation_id, "generation_id")?;
    validate_id(holder_id, "holder_id")?;
    validate_time(now_ms)
}

fn validate_telegram_poller_identity(
    identity: &TelegramPollerLeaseIdentity<'_>,
) -> Result<(), StoreError> {
    validate_telegram_poller_request(
        identity.bot_id,
        identity.generation_id,
        identity.holder_id,
        identity.now_ms,
    )?;
    if identity.poller_epoch == 0 || identity.expected_expires_ms < 0 {
        return Err(StoreError::InvalidField("telegram_poller_lease"));
    }
    Ok(())
}

fn require_generation_authority_through(
    transaction: &Transaction<'_>,
    generation_id: &str,
    holder_id: &str,
    authority_lease_epoch: u64,
    now_ms: i64,
    required_through_ms: i64,
) -> Result<(), StoreError> {
    let valid: bool = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM generations
            WHERE generation_id = ?1 AND lease_holder = ?2 AND lease_epoch = ?3
              AND lease_expires_ms > ?4 AND lease_expires_ms >= ?5
         )",
        params![
            generation_id,
            holder_id,
            to_db_u64(authority_lease_epoch, "authority_lease_epoch")?,
            now_ms,
            required_through_ms
        ],
        |row| row.get(0),
    )?;
    if valid {
        Ok(())
    } else {
        Err(StoreError::StaleEpoch)
    }
}

/// The one unresumed pause for a generation, read inside a caller's transaction.
///
/// The partial unique index is what makes `query_row` the right shape here:
/// two live pauses for one generation are unrepresentable, so this cannot be
/// silently reading the first of several.
fn live_intake_pause(
    transaction: &Transaction<'_>,
    generation_id: &str,
    observed_ms: i64,
) -> Result<Option<PauseRecord>, StoreError> {
    transaction
        .query_row(
            "SELECT pause_id, revision, paused_at_ms, actor, reason
             FROM intake_pauses
             WHERE generation_id = ?1 AND resumed_at_ms IS NULL",
            [generation_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
        .map(|(pause_id, raw_revision, paused_at_ms, actor, reason)| {
            Ok(PauseRecord {
                pause_id,
                generation_id: generation_id.to_owned(),
                revision: from_db_u64(raw_revision, "intake_pause_revision")?,
                paused_at_ms,
                actor,
                reason,
                observed_ms,
            })
        })
        .transpose()
}

/// One transport's pause row, live or elapsed, read inside a caller's
/// transaction.
///
/// The primary key is what makes `query_row` the right shape: there is one row
/// per transport and scope, so this cannot be reading the first of several.
fn transport_pause_row(
    transaction: &Transaction<'_>,
    transport: &str,
    scope: &str,
    observed_ms: i64,
) -> Result<Option<TransportPause>, StoreError> {
    transaction
        .query_row(
            "SELECT revision, paused_at_ms, resume_after_ms, reason
             FROM transport_pauses
             WHERE transport = ?1 AND scope = ?2",
            params![transport, scope],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?
        .map(|(raw_revision, paused_at_ms, resume_after_ms, reason)| {
            Ok(TransportPause {
                transport: transport.to_owned(),
                scope: scope.to_owned(),
                revision: from_db_u64(raw_revision, "transport_pause_revision")?,
                paused_at_ms,
                resume_after_ms,
                reason,
                observed_ms,
            })
        })
        .transpose()
}

fn require_exact_telegram_poller(
    transaction: &Transaction<'_>,
    identity: &TelegramPollerLeaseIdentity<'_>,
    live_at_ms: i64,
) -> Result<(), StoreError> {
    let valid: bool = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM telegram_poller_leases p
            JOIN generations g ON g.generation_id = p.generation_id
            WHERE p.bot_id = ?1 AND p.generation_id = ?2 AND p.holder_id = ?3
              AND p.poller_epoch = ?4 AND p.expires_ms = ?5 AND p.expires_ms > ?6
              AND g.lease_holder = p.holder_id
              AND g.lease_epoch = p.authority_lease_epoch
              AND g.lease_expires_ms > ?6
         )",
        params![
            identity.bot_id,
            identity.generation_id,
            identity.holder_id,
            to_db_u64(identity.poller_epoch, "telegram_poller_epoch")?,
            identity.expected_expires_ms,
            live_at_ms
        ],
        |row| row.get(0),
    )?;
    if valid {
        Ok(())
    } else {
        Err(StoreError::StaleEpoch)
    }
}

fn commit_fenced_telegram_batch(
    transaction: &Transaction<'_>,
    commit: &TelegramPollerCommit<'_>,
) -> Result<TelegramPollerCommitReceipt, StoreError> {
    let batch = &commit.batch;
    if batch.updates.is_empty() {
        return Ok(TelegramPollerCommitReceipt {
            bot_id: batch.bot_id,
            lease_epoch: commit.lease.poller_epoch,
            next_offset: batch.next_offset,
            disposition_count: 0,
            batch_digest: commit.batch_digest,
            duplicate: false,
        });
    }
    let expected = telegram_offset_bytes(batch.expected_offset);
    let next = telegram_offset_bytes(batch.next_offset);
    let existing = transaction
        .query_row(
            "SELECT next_offset FROM telegram_offsets WHERE bot_id = ?1",
            [batch.bot_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .map(|value| telegram_offset_from_bytes(&value))
        .transpose()?;
    match existing {
        Some(current) if current == batch.next_offset => {
            return Err(StoreError::IdempotencyConflict("telegram_batch_lease"));
        }
        Some(current) if current != batch.expected_offset => {
            return Err(StoreError::IdempotencyConflict("telegram_offset"));
        }
        Some(_) => {}
        None if batch.expected_offset != 0 => {
            return Err(StoreError::IdempotencyConflict("telegram_offset"));
        }
        None => {
            transaction.execute(
                "INSERT INTO telegram_offsets
                 (bot_id, next_offset, revision, updated_ms) VALUES (?1, ?2, 1, ?3)",
                params![batch.bot_id, &expected[..], batch.received_ms],
            )?;
        }
    }
    for update in batch.updates {
        if transaction
            .query_row(
                "SELECT 1 FROM telegram_ingress WHERE bot_id = ?1 AND update_id = ?2",
                params![batch.bot_id, &telegram_offset_bytes(update.update_id)[..]],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(StoreError::IdempotencyConflict("telegram_update"));
        }
        if transaction
            .query_row(
                "SELECT 1 FROM telegram_ingress WHERE source_key = ?1",
                [update.source_key],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(StoreError::IdempotencyConflict("telegram_source_key"));
        }
        let (disposition, content) = telegram_disposition_parts(update.disposition);
        let provenance = telegram_ingress_provenance(update.source_key, update.update_id)?;
        transaction.execute(
            "INSERT INTO telegram_ingress
             (bot_id, update_id, source_key, scope, disposition, content, received_ms,
              trace_id, correlation_id, causation_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                batch.bot_id,
                &telegram_offset_bytes(update.update_id)[..],
                update.source_key,
                update.scope,
                disposition,
                content,
                batch.received_ms,
                provenance.trace_id().as_str(),
                provenance.correlation_id().as_str(),
                provenance.causation_id().as_str()
            ],
        )?;
    }
    if batch.next_offset != batch.expected_offset {
        transaction.execute(
            "INSERT INTO telegram_batches
             (bot_id, expected_offset, next_offset, disposition_count, received_ms,
              batch_digest, poller_generation_id, poller_holder_id, poller_epoch)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                batch.bot_id,
                &expected[..],
                &next[..],
                to_db_u64(batch.updates.len() as u64, "telegram_disposition_count")?,
                batch.received_ms,
                &commit.batch_digest[..],
                commit.lease.generation_id,
                commit.lease.holder_id,
                to_db_u64(commit.lease.poller_epoch, "telegram_poller_epoch")?
            ],
        )?;
        let changed = transaction.execute(
            "UPDATE telegram_offsets SET next_offset = ?3, revision = revision + 1,
             updated_ms = ?4 WHERE bot_id = ?1 AND next_offset = ?2",
            params![batch.bot_id, &expected[..], &next[..], batch.received_ms],
        )?;
        if changed != 1 {
            return Err(StoreError::IdempotencyConflict("telegram_offset"));
        }
    }
    Ok(TelegramPollerCommitReceipt {
        bot_id: batch.bot_id,
        lease_epoch: commit.lease.poller_epoch,
        next_offset: batch.next_offset,
        disposition_count: batch.updates.len(),
        batch_digest: commit.batch_digest,
        duplicate: false,
    })
}

fn exact_telegram_commit_receipt(
    transaction: &Transaction<'_>,
    commit: &TelegramPollerCommit<'_>,
) -> Result<Option<TelegramPollerCommitReceipt>, StoreError> {
    if commit.batch.updates.is_empty() {
        return Ok(None);
    }
    let current = transaction
        .query_row(
            "SELECT next_offset FROM telegram_offsets WHERE bot_id = ?1",
            [commit.batch.bot_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .map(|value| telegram_offset_from_bytes(&value))
        .transpose()?;
    if current != Some(commit.batch.next_offset) {
        return Ok(None);
    }
    verify_telegram_retry(transaction, &commit.batch)?;
    let exact: bool = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM telegram_batches
            WHERE bot_id = ?1 AND expected_offset = ?2 AND next_offset = ?3
              AND batch_digest = ?4 AND poller_generation_id = ?5
              AND poller_holder_id = ?6 AND poller_epoch = ?7
         )",
        params![
            commit.batch.bot_id,
            &telegram_offset_bytes(commit.batch.expected_offset)[..],
            &telegram_offset_bytes(commit.batch.next_offset)[..],
            &commit.batch_digest[..],
            commit.lease.generation_id,
            commit.lease.holder_id,
            to_db_u64(commit.lease.poller_epoch, "telegram_poller_epoch")?
        ],
        |row| row.get(0),
    )?;
    if !exact {
        return Err(StoreError::IdempotencyConflict("telegram_batch_lease"));
    }
    Ok(Some(TelegramPollerCommitReceipt {
        bot_id: commit.batch.bot_id,
        lease_epoch: commit.lease.poller_epoch,
        next_offset: commit.batch.next_offset,
        disposition_count: commit.batch.updates.len(),
        batch_digest: commit.batch_digest,
        duplicate: true,
    }))
}

fn validate_telegram_batch(batch: &TelegramBatchIngestion<'_>) -> Result<(), StoreError> {
    if batch.bot_id <= 0 {
        return Err(StoreError::InvalidField("telegram_bot_id"));
    }
    validate_time(batch.received_ms)?;
    if batch.updates.len() > MAX_TELEGRAM_BATCH_UPDATES || batch.next_offset < batch.expected_offset
    {
        return Err(StoreError::InvalidField("telegram_batch"));
    }
    if batch.updates.is_empty() {
        if batch.next_offset != batch.expected_offset {
            return Err(StoreError::InvalidField("telegram_batch"));
        }
        return Ok(());
    }
    let mut previous = None;
    for update in batch.updates {
        validate_id(update.source_key, "telegram_source_key")?;
        validate_id(update.scope, "telegram_scope")?;
        if update.source_key != format!("telegram:{}:update:{}", batch.bot_id, update.update_id)
            || !update
                .scope
                .starts_with(&format!("telegram:{}:", batch.bot_id))
        {
            return Err(StoreError::InvalidField("telegram_binding"));
        }
        if update.update_id < batch.expected_offset
            || update.update_id >= batch.next_offset
            || previous.is_some_and(|prior| update.update_id <= prior)
        {
            return Err(StoreError::InvalidField("telegram_update_id"));
        }
        if let TelegramStoreDisposition::Admitted { content } = update.disposition
            && (content.is_empty() || content.len() > MAX_TELEGRAM_CONTENT_BYTES)
        {
            return Err(StoreError::InvalidField("telegram_content"));
        }
        previous = Some(update.update_id);
    }
    if previous.and_then(|value| value.checked_add(1)) != Some(batch.next_offset) {
        return Err(StoreError::InvalidField("telegram_next_offset"));
    }
    Ok(())
}

fn verify_telegram_retry(
    transaction: &Transaction<'_>,
    batch: &TelegramBatchIngestion<'_>,
) -> Result<(), StoreError> {
    if batch.updates.is_empty() {
        if batch.expected_offset == batch.next_offset {
            return Ok(());
        }
        return Err(StoreError::IdempotencyConflict("telegram_batch"));
    }
    let metadata_matches: bool = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM telegram_batches
            WHERE bot_id = ?1 AND expected_offset = ?2 AND next_offset = ?3
              AND disposition_count = ?4 AND received_ms = ?5
         )",
        params![
            batch.bot_id,
            &telegram_offset_bytes(batch.expected_offset)[..],
            &telegram_offset_bytes(batch.next_offset)[..],
            to_db_u64(batch.updates.len() as u64, "telegram_disposition_count")?,
            batch.received_ms
        ],
        |row| row.get(0),
    )?;
    if !metadata_matches {
        return Err(StoreError::IdempotencyConflict("telegram_batch"));
    }
    let count: i64 = transaction.query_row(
        "SELECT count(*) FROM telegram_ingress
         WHERE bot_id = ?1 AND update_id >= ?2 AND update_id < ?3",
        params![
            batch.bot_id,
            &telegram_offset_bytes(batch.expected_offset)[..],
            &telegram_offset_bytes(batch.next_offset)[..]
        ],
        |row| row.get(0),
    )?;
    if from_db_u64(count, "telegram_disposition_count")? != batch.updates.len() as u64 {
        return Err(StoreError::IdempotencyConflict("telegram_batch"));
    }
    for update in batch.updates {
        let stored = transaction
            .query_row(
                "SELECT source_key, scope, disposition, content, received_ms
                 FROM telegram_ingress WHERE bot_id = ?1 AND update_id = ?2",
                params![batch.bot_id, &telegram_offset_bytes(update.update_id)[..]],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::IdempotencyConflict("telegram_batch"))?;
        let (disposition, content) = telegram_disposition_parts(update.disposition);
        if stored.0 != update.source_key
            || stored.1 != update.scope
            || stored.2 != disposition
            || stored.3.as_deref() != content
            || stored.4 != batch.received_ms
        {
            return Err(StoreError::IdempotencyConflict("telegram_batch"));
        }
    }
    Ok(())
}

const fn telegram_disposition_parts(
    disposition: TelegramStoreDisposition<'_>,
) -> (&'static str, Option<&[u8]>) {
    match disposition {
        TelegramStoreDisposition::Admitted { content } => ("admitted", Some(content)),
        TelegramStoreDisposition::Denied => ("denied", None),
        TelegramStoreDisposition::IgnoredUnsupported => ("ignored_unsupported", None),
    }
}

const fn telegram_offset_bytes(offset: u64) -> [u8; 8] {
    offset.to_be_bytes()
}

fn telegram_offset_from_bytes(bytes: &[u8]) -> Result<u64, StoreError> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| StoreError::MigrationInvariant("telegram_offset_width"))?;
    Ok(u64::from_be_bytes(bytes))
}

fn validate_id(value: &str, field: &'static str) -> Result<(), StoreError> {
    validate_bounded_id(value, MAX_ID_BYTES, field)
}

/// The identifier grammar at a caller-chosen width.
///
/// Only the length ceiling varies. Empty and control-bearing values stay
/// refused at every width, so a wider bound buys length and nothing else.
fn validate_bounded_id(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidField(field));
    }
    Ok(())
}

fn validate_payload(value: &[u8], field: &'static str) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > MAX_PAYLOAD_BYTES {
        return Err(StoreError::InvalidField(field));
    }
    Ok(())
}

fn outbox_transport(kind: &str) -> &str {
    kind.split_once('.')
        .map_or(kind, |(transport, _)| transport)
}

fn validate_outbox_lease_request(
    outbox_id: i64,
    generation_id: &str,
    holder_id: &str,
    lease_token: &str,
    now_ms: i64,
) -> Result<(), StoreError> {
    if outbox_id <= 0 {
        return Err(StoreError::InvalidField("outbox_id"));
    }
    validate_id(generation_id, "generation_id")?;
    validate_id(holder_id, "holder_id")?;
    validate_id(lease_token, "outbox_lease_token")?;
    validate_time(now_ms)
}

type OutboxDeliveryRow = (
    String,
    i64,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
);

fn outbox_delivery_row(
    transaction: &Transaction<'_>,
    outbox_id: i64,
) -> Result<OutboxDeliveryRow, StoreError> {
    transaction
        .query_row(
            "SELECT state, revision, attempts, lease_token, lease_generation_id,
                    lease_holder, delivery_receipt_key, last_error, lease_epoch,
                    lease_expires_ms
             FROM outbox WHERE outbox_id = ?1",
            [outbox_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::NotFound("outbox"))
}

struct OutboxLeaseIdentity<'a> {
    outbox_id: i64,
    generation_id: &'a str,
    holder_id: &'a str,
    lease_epoch: u64,
    lease_token: &'a str,
    expected_attempt: u64,
    now_ms: i64,
}

fn require_exact_outbox_lease(
    row: &OutboxDeliveryRow,
    identity: &OutboxLeaseIdentity<'_>,
) -> Result<(), StoreError> {
    if row.0 != "in_flight"
        || row.3.as_deref() != Some(identity.lease_token)
        || row.4.as_deref() != Some(identity.generation_id)
        || row.5.as_deref() != Some(identity.holder_id)
        || row
            .8
            .map(|value| from_db_u64(value, "outbox_lease_epoch"))
            .transpose()?
            != Some(identity.lease_epoch)
        || from_db_u64(row.2, "outbox_attempt")? != identity.expected_attempt
    {
        return Err(StoreError::StaleEpoch);
    }
    if row.9.is_none_or(|expires_ms| expires_ms <= identity.now_ms) {
        return Err(StoreError::OutboxReconciliationRequired {
            outbox_id: identity.outbox_id,
        });
    }
    Ok(())
}

fn map_outbox_unique(result: Result<usize, rusqlite::Error>) -> Result<(), StoreError> {
    match result {
        Ok(1) => Ok(()),
        Ok(_) => Err(StoreError::IdempotencyConflict("outbox_state")),
        Err(error)
            if error.sqlite_error().is_some_and(|code| {
                code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
            }) =>
        {
            Err(StoreError::OutboxConflict)
        }
        Err(error) => Err(StoreError::Sqlite(error)),
    }
}

fn validate_time(value: i64) -> Result<(), StoreError> {
    if value < 0 {
        return Err(StoreError::InvalidField("time_ms"));
    }
    Ok(())
}

fn checked_expiry(now_ms: i64, ttl_ms: i64) -> Result<i64, StoreError> {
    validate_time(now_ms)?;
    if ttl_ms <= 0 {
        return Err(StoreError::InvalidField("ttl_ms"));
    }
    now_ms
        .checked_add(ttl_ms)
        .ok_or(StoreError::InvalidField("lease_expires_ms"))
}

fn to_db_u64(value: u64, field: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::InvalidField(field))
}

fn from_db_u64(value: i64, field: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::InvalidField(field))
}

fn require_live_lease(
    transaction: &Transaction<'_>,
    generation_id: &str,
    holder_id: &str,
    epoch: u64,
    now_ms: i64,
) -> Result<i64, StoreError> {
    let expiry = transaction
        .query_row(
            "SELECT lease_expires_ms FROM generations
             WHERE generation_id = ?1 AND lease_holder = ?2 AND lease_epoch = ?3
             AND lease_expires_ms > ?4",
            params![
                generation_id,
                holder_id,
                to_db_u64(epoch, "lease_epoch")?,
                now_ms
            ],
            |row| row.get(0),
        )
        .optional()?;
    expiry.ok_or(StoreError::StaleEpoch)
}

fn require_reconciliation_authority(
    transaction: &Transaction<'_>,
    generation_id: &str,
    holder_id: &str,
    epoch: u64,
    now_ms: i64,
) -> Result<i64, StoreError> {
    require_live_lease(transaction, generation_id, holder_id, epoch, now_ms).map_err(|error| {
        if matches!(error, StoreError::StaleEpoch) {
            StoreError::AuthorityLost
        } else {
            error
        }
    })
}

fn append_event(
    transaction: &Transaction<'_>,
    aggregate_kind: &str,
    aggregate_id: &str,
    revision: u64,
    occurred_ms: i64,
    kind: &str,
    payload: &[u8],
) -> Result<i64, StoreError> {
    let trace_id = TraceId::for_ingress(aggregate_kind, aggregate_id);
    let correlation_id = CorrelationId::new(trace_id.as_str().to_owned())
        .map_err(|_| StoreError::InvalidField("correlation_id"))?;
    let causation_id = CausationId::new(format!("{aggregate_kind}:{aggregate_id}"))
        .or_else(|_| CausationId::new(trace_id.as_str().to_owned()))
        .map_err(|_| StoreError::InvalidField("causation_id"))?;
    append_event_with_provenance(
        transaction,
        aggregate_kind,
        aggregate_id,
        revision,
        occurred_ms,
        kind,
        payload,
        &Provenance::new(trace_id, correlation_id, causation_id),
    )
}

#[allow(clippy::too_many_arguments)]
fn append_event_with_provenance(
    transaction: &Transaction<'_>,
    aggregate_kind: &str,
    aggregate_id: &str,
    revision: u64,
    occurred_ms: i64,
    kind: &str,
    payload: &[u8],
    provenance: &Provenance,
) -> Result<i64, StoreError> {
    validate_id(aggregate_kind, "aggregate_kind")?;
    validate_id(aggregate_id, "aggregate_id")?;
    if kind.is_empty() || kind.len() > MAX_KIND_BYTES || kind.chars().any(char::is_control) {
        return Err(StoreError::InvalidField("event_kind"));
    }
    validate_payload(payload, "event_payload")?;
    transaction.execute(
        "INSERT INTO domain_events
         (aggregate_kind, aggregate_id, revision, schema_version, occurred_ms, kind, payload,
          trace_id, correlation_id, causation_id)
         VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            aggregate_kind,
            aggregate_id,
            to_db_u64(revision, "event_revision")?,
            occurred_ms,
            kind,
            payload,
            provenance.trace_id().as_str(),
            provenance.correlation_id().as_str(),
            provenance.causation_id().as_str()
        ],
    )?;
    Ok(transaction.last_insert_rowid())
}

fn ingress_record_provenance(
    transport: &str,
    transport_key: &str,
    record_kind: &str,
    record_id: i64,
) -> Result<Provenance, StoreError> {
    let trace_id = TraceId::for_ingress(transport, transport_key);
    let correlation_id = CorrelationId::new(format!("{record_kind}:{record_id}"))
        .map_err(|_| StoreError::InvalidField("correlation_id"))?;
    let causation_id = CausationId::new(format!("ingress:{}", trace_id.as_str()))
        .map_err(|_| StoreError::InvalidField("causation_id"))?;
    Ok(Provenance::new(trace_id, correlation_id, causation_id))
}

fn telegram_ingress_provenance(source_key: &str, update_id: u64) -> Result<Provenance, StoreError> {
    let trace_id = TraceId::for_ingress("telegram", source_key);
    child_provenance(
        trace_id.as_str(),
        format!("telegram:{update_id}"),
        format!("ingress:{}", trace_id.as_str()),
    )
}

fn child_provenance(
    trace_id: &str,
    correlation_id: String,
    causation_id: String,
) -> Result<Provenance, StoreError> {
    Ok(Provenance::new(
        TraceId::new(trace_id.to_owned()).map_err(|_| StoreError::InvalidField("trace_id"))?,
        CorrelationId::new(correlation_id)
            .map_err(|_| StoreError::InvalidField("correlation_id"))?,
        CausationId::new(causation_id).map_err(|_| StoreError::InvalidField("causation_id"))?,
    ))
}

fn provenance_coordinate(prefix: &str, value: &str, fallback: &str) -> String {
    let coordinate = format!("{prefix}:{value}");
    if CausationId::new(coordinate.clone()).is_ok() {
        coordinate
    } else {
        fallback.to_owned()
    }
}

fn run_row_provenance(
    transaction: &Transaction<'_>,
    run_id: i64,
) -> Result<Option<Provenance>, StoreError> {
    let row = transaction.query_row(
        "SELECT trace_id, correlation_id, causation_id FROM runs WHERE run_id = ?1",
        [run_id],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        },
    )?;
    match row {
        (None, None, None) => Ok(None),
        (Some(trace_id), Some(correlation_id), Some(causation_id)) => Ok(Some(child_provenance(
            &trace_id,
            correlation_id,
            causation_id,
        )?)),
        _ => Err(StoreError::MigrationInvariant("partial_provenance")),
    }
}

fn stored_provenance(
    trace_id: Option<String>,
    correlation_id: Option<String>,
    causation_id: Option<String>,
) -> Result<Option<StoredProvenance>, StoreError> {
    match (trace_id, correlation_id, causation_id) {
        (None, None, None) => Ok(None),
        (Some(trace_id), Some(correlation_id), Some(causation_id)) => {
            child_provenance(&trace_id, correlation_id.clone(), causation_id.clone())?;
            Ok(Some(StoredProvenance {
                trace_id,
                correlation_id,
                causation_id,
            }))
        }
        _ => Err(StoreError::MigrationInvariant("partial_provenance")),
    }
}

fn mark_inbox_claimed(
    transaction: &Transaction<'_>,
    inbox_id: i64,
    run_id: i64,
    occurred_ms: i64,
    provenance: Option<&Provenance>,
) -> Result<(), StoreError> {
    let changed = transaction.execute(
        "UPDATE inbox SET state = 'claimed', claimed_run_id = ?2, revision = revision + 1
         WHERE inbox_id = ?1 AND state = 'pending' AND claimed_run_id IS NULL",
        params![inbox_id, run_id],
    )?;
    if changed != 1 {
        return Err(StoreError::IdempotencyConflict("inbox_state"));
    }
    let revision: i64 = transaction.query_row(
        "SELECT revision FROM inbox WHERE inbox_id = ?1",
        [inbox_id],
        |row| row.get(0),
    )?;
    if let Some(provenance) = provenance {
        append_event_with_provenance(
            transaction,
            "inbox",
            &inbox_id.to_string(),
            from_db_u64(revision, "inbox_revision")?,
            occurred_ms,
            "inbox.claimed",
            &run_id.to_be_bytes(),
            provenance,
        )?;
    } else {
        append_event(
            transaction,
            "inbox",
            &inbox_id.to_string(),
            from_db_u64(revision, "inbox_revision")?,
            occurred_ms,
            "inbox.claimed",
            &run_id.to_be_bytes(),
        )?;
    }
    Ok(())
}

fn run_provenance(
    transaction: &Transaction<'_>,
    inbox_id: i64,
    run_id: i64,
) -> Result<Option<Provenance>, StoreError> {
    let trace_id = transaction.query_row(
        "SELECT trace_id FROM inbox WHERE inbox_id = ?1",
        [inbox_id],
        |row| row.get::<_, Option<String>>(0),
    )?;
    let Some(trace_id) = trace_id else {
        return Ok(None);
    };
    let provenance = child_provenance(
        &trace_id,
        format!("run:{run_id}"),
        format!("inbox:{inbox_id}"),
    )?;
    transaction.execute(
        "UPDATE runs SET correlation_id = ?2, causation_id = ?3 WHERE run_id = ?1",
        params![
            run_id,
            provenance.correlation_id().as_str(),
            provenance.causation_id().as_str()
        ],
    )?;
    Ok(Some(provenance))
}

fn terminal_receipt(
    transaction: &Transaction<'_>,
    terminal: &TerminalRun<'_>,
) -> Result<TerminalReceipt, StoreError> {
    transaction
        .query_row(
            "SELECT e.event_id, o.outbox_id
             FROM runs r
             JOIN domain_events e ON e.aggregate_kind = 'run'
                 AND e.aggregate_id = CAST(r.run_id AS TEXT) AND e.revision = r.revision
             JOIN outbox o ON o.event_id = e.event_id
             WHERE r.run_id = ?1 AND e.kind = ?2 AND e.payload = ?3
               AND o.intent_key = ?4 AND o.kind = ?5 AND o.payload = ?6",
            params![
                terminal.run_id,
                terminal.event_kind,
                terminal.event_payload,
                terminal.outbox_intent_key,
                terminal.outbox_kind,
                terminal.outbox_payload
            ],
            |row| {
                Ok(TerminalReceipt {
                    event_id: row.get(0)?,
                    outbox_id: row.get(1)?,
                    duplicate: false,
                })
            },
        )
        .optional()?
        .ok_or(StoreError::AlreadyTerminal)
}

type ReconciliationRunRow = (
    String,
    i64,
    String,
    i64,
    Option<Vec<u8>>,
    Option<String>,
    i64,
    String,
    Option<String>,
    Option<i64>,
    Option<i64>,
);

fn reconciliation_retry_receipt(
    transaction: &Transaction<'_>,
    request: &ReconciliationRequest<'_>,
    run: &ReconciliationRunRow,
) -> Result<ReconciliationReceipt, StoreError> {
    if run.2 != request.expected_generation_id
        || from_db_u64(run.3, "lease_epoch")? != request.expected_lease_epoch
    {
        return Err(StoreError::StaleEpoch);
    }
    let revision = from_db_u64(run.1, "run_revision")?;
    let expected_revision = request
        .expected_revision
        .checked_add(1)
        .ok_or(StoreError::InvalidField("expected_revision"))?;
    if revision != expected_revision || run.5.as_deref() != Some(request.decision_key) {
        return Err(StoreError::AlreadyTerminal);
    }
    let parts = reconciliation_parts(request.decision);
    if run.0 != parts.run_state || run.4.as_deref() != Some(parts.event_payload) {
        return Err(StoreError::AlreadyTerminal);
    }
    let run_event_id: i64 = transaction.query_row(
        "SELECT event_id FROM domain_events WHERE aggregate_kind = 'run'
         AND aggregate_id = ?1 AND revision = ?2 AND kind = ?3 AND payload = ?4",
        params![
            request.run_id.to_string(),
            to_db_u64(revision, "run_revision")?,
            parts.run_event_kind,
            parts.event_payload
        ],
        |row| row.get(0),
    )?;
    let outbox_id = transaction.query_row(
        "SELECT outbox_id FROM outbox WHERE event_id = ?1 AND intent_key = ?2
         AND kind = ?3 AND payload = ?4",
        params![
            run_event_id,
            request.decision_key,
            parts.outbox_kind,
            parts.outbox_payload
        ],
        |row| row.get(0),
    )?;
    let inbox_event_id = transaction.query_row(
        "SELECT e.event_id FROM inbox i JOIN domain_events e
           ON e.aggregate_kind = 'inbox'
          AND e.aggregate_id = CAST(i.inbox_id AS TEXT)
          AND e.revision = i.revision
         WHERE i.inbox_id = ?1 AND i.state = ?2 AND i.claimed_run_id IS NULL
           AND e.kind = ?3 AND e.payload = ?4",
        params![
            run.6,
            parts.inbox_state,
            parts.inbox_event_kind,
            parts.event_payload
        ],
        |row| row.get(0),
    )?;
    Ok(ReconciliationReceipt {
        run_event_id,
        inbox_event_id,
        outbox_id,
        duplicate: true,
    })
}

struct ReconciliationParts<'a> {
    run_state: &'static str,
    inbox_state: &'static str,
    run_event_kind: &'a str,
    inbox_event_kind: &'static str,
    event_payload: &'a [u8],
    outbox_kind: &'a str,
    outbox_payload: &'a [u8],
}

fn reconciliation_parts(decision: ReconciliationDecision<'_>) -> ReconciliationParts<'_> {
    match decision {
        ReconciliationDecision::Fail { reason } => ReconciliationParts {
            run_state: "failed",
            inbox_state: "failed",
            run_event_kind: "run.reconciliation_failed",
            inbox_event_kind: "inbox.reconciliation_failed",
            event_payload: reason.as_bytes(),
            outbox_kind: "fake.reconciliation.receipt",
            outbox_payload: reason.as_bytes(),
        },
        ReconciliationDecision::FailWithIntent {
            reason,
            outbox_kind,
            outbox_payload,
        } => ReconciliationParts {
            run_state: "failed",
            inbox_state: "failed",
            run_event_kind: "run.reconciliation_failed",
            inbox_event_kind: "inbox.reconciliation_failed",
            event_payload: reason.as_bytes(),
            outbox_kind,
            outbox_payload,
        },
        ReconciliationDecision::Complete {
            event_kind,
            event_payload,
            outbox_kind,
            outbox_payload,
        } => ReconciliationParts {
            run_state: "succeeded",
            inbox_state: "completed",
            run_event_kind: event_kind,
            inbox_event_kind: "inbox.reconciliation_completed",
            event_payload,
            outbox_kind,
            outbox_payload,
        },
    }
}

fn count_table(connection: &Connection, table: &'static str) -> Result<u64, StoreError> {
    let sql = match table {
        "domain_events" => "SELECT count(*) FROM domain_events",
        "outbox" => "SELECT count(*) FROM outbox",
        _ => return Err(StoreError::InvalidField("table")),
    };
    let count: i64 = connection.query_row(sql, [], |row| row.get(0))?;
    from_db_u64(count, "count")
}

fn query_count(transaction: &Transaction<'_>, sql: &str) -> Result<u64, StoreError> {
    let count: i64 = transaction.query_row(sql, [], |row| row.get(0))?;
    from_db_u64(count, "count")
}

#[cfg(test)]
mod migration_tests {
    use super::*;

    #[test]
    fn a_causal_coordinate_does_not_narrow_an_existing_identifier_bound() {
        let maximum = "g".repeat(MAX_ID_BYTES);
        assert_eq!(
            provenance_coordinate("generation", &maximum, "fallback"),
            "fallback"
        );
        assert_eq!(
            provenance_coordinate("generation", "foreground", "fallback"),
            "generation:foreground"
        );
    }

    #[derive(Debug, Eq, PartialEq)]
    struct LegacyTelegramBatch {
        disposition_count: i64,
        batch_digest: Option<Vec<u8>>,
        generation_id: Option<String>,
        holder_id: Option<String>,
        poller_epoch: Option<i64>,
    }

    /// Build the exact canonical v5 shape through the migration path that
    /// produces it, rather than restating the schema as a literal here.
    fn canonical_v5(connection: &mut Connection) {
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("foreign keys");
        connection.execute_batch(SCHEMA_V2).expect("v2 base");
        connection
            .execute_batch(MIGRATE_V2_TO_V3)
            .expect("v3 schema");
        connection
            .execute_batch(MIGRATE_V3_TO_V4)
            .expect("v4 schema");
        connection
            .execute_batch(MIGRATE_V4_TO_V5)
            .expect("canonical v5 schema");
        connection
            .pragma_update(None, "user_version", 5)
            .expect("v5 marker");
    }

    /// The canonical v6 shape, reached the same way: through the migrations
    /// that produce it rather than a literal restating them.
    fn canonical_v6(connection: &mut Connection) {
        canonical_v5(connection);
        connection
            .execute_batch(MIGRATE_V5_TO_V6)
            .expect("canonical v6 schema");
        connection
            .pragma_update(None, "user_version", 6)
            .expect("v6 marker");
    }

    fn canonical_v8(connection: &mut Connection) {
        canonical_v6(connection);
        connection
            .execute_batch(MIGRATE_V6_TO_V7)
            .expect("canonical v7 schema");
        connection
            .execute_batch(MIGRATE_V7_TO_V8)
            .expect("canonical v8 schema");
        connection
            .pragma_update(None, "user_version", 8)
            .expect("v8 marker");
    }

    fn canonical_v9(connection: &mut Connection) {
        canonical_v8(connection);
        connection
            .execute_batch(MIGRATE_V8_TO_V9)
            .expect("canonical v9 schema");
        connection
            .pragma_update(None, "user_version", 9)
            .expect("v9 marker");
    }

    #[test]
    fn v8_ownerless_leases_migrate_expired_with_explicit_legacy_identity() {
        let mut connection = Connection::open_in_memory().expect("memory database");
        canonical_v8(&mut connection);
        connection
            .execute(
                "INSERT INTO generations
                 (generation_id, revision, state, lease_holder, lease_epoch, lease_expires_ms)
                 VALUES ('foreground', 4, 'active', 'old-holder', 7, 900)",
                [],
            )
            .expect("v8 lease");

        initialize_or_validate_schema(&mut connection).expect("current migration");
        let row: (i64, String, i64, i64) = connection
            .query_row(
                "SELECT lease_expires_ms, boot_id, holder_pid, holder_starttime
                 FROM generations WHERE generation_id = 'foreground'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("migrated identity");
        assert_eq!(row, (0, "legacy".to_owned(), 0, 0));
    }

    #[test]
    fn v9_wall_time_lease_is_expired_at_the_boottime_domain_boundary() {
        let mut connection = Connection::open_in_memory().expect("memory database");
        canonical_v9(&mut connection);
        connection
            .execute(
                "INSERT INTO generations
                 (generation_id, revision, state, lease_holder, lease_epoch, lease_expires_ms,
                  boot_id, holder_pid, holder_starttime)
                 VALUES ('foreground', 4, 'active', 'old-holder', 7, 900,
                         'boot-a', 42, 99)",
                [],
            )
            .expect("v9 wall-time lease");

        initialize_or_validate_schema(&mut connection).expect("v10 time-domain migration");
        let row: (u32, i64, String) = connection
            .query_row(
                "SELECT (SELECT user_version FROM pragma_user_version),
                        lease_expires_ms, boot_id
                 FROM generations WHERE generation_id = 'foreground'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("migrated lease");
        assert_eq!(row, (SCHEMA_VERSION, 0, "boot-a".to_owned()));
    }

    #[test]
    fn fresh_database_initializes_at_the_pause_bearing_version() {
        let mut connection = Connection::open_in_memory().expect("memory database");
        initialize_or_validate_schema(&mut connection).expect("fresh initialization");
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("version");
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(version, 10);
        let transport_pauses: i64 = connection
            .query_row("SELECT count(*) FROM transport_pauses", [], |row| {
                row.get(0)
            })
            .expect("transport pause table exists");
        assert_eq!(transport_pauses, 0);
        let pauses: i64 = connection
            .query_row("SELECT count(*) FROM intake_pauses", [], |row| row.get(0))
            .expect("pause table exists");
        assert_eq!(pauses, 0);
        // The partial index is the invariant, not decoration: without it two
        // live pauses for one generation would be representable and
        // `live_intake_pause` would be reading the first of several.
        let index: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE name = 'intake_pauses_one_live_per_generation'",
                [],
                |row| row.get(0),
            )
            .expect("partial unique index");
        assert!(index.contains("UNIQUE"), "{index}");
        assert!(index.contains("WHERE resumed_at_ms IS NULL"), "{index}");
    }

    /// Widening the `transport_key` bound needed no migration, and this is the
    /// evidence rather than the assertion. Every inbox table this build can
    /// reach — created fresh, or arrived at from v1, v2 or v5 — stores a
    /// maximal key, refuses a second row carrying it, and still separates two
    /// keys that differ only in their final byte. The column is TEXT with no
    /// length constraint on any of those paths and the unique index compares
    /// the key whole, so the bound lives in `validate_bounded_id` alone and an
    /// existing database accepts Slack-length keys without being rewritten.
    #[test]
    fn every_inbox_schema_path_stores_and_dedupes_a_maximal_transport_key() {
        const INSERT: &str = "INSERT INTO inbox
             (transport, transport_key, scope, payload, received_ms, state, revision)
             VALUES ('slack', ?1, 'scope:maximal', X'01', 1, 'pending', 1)";
        let maximal = "k".repeat(MAX_TRANSPORT_KEY_BYTES);
        let mut sibling = maximal.clone();
        sibling.pop();
        sibling.push('z');

        let mut fresh = Connection::open_in_memory().expect("memory database");
        initialize_or_validate_schema(&mut fresh).expect("fresh initialization");
        let mut from_v1 = Connection::open_in_memory().expect("memory database");
        from_v1
            .pragma_update(None, "foreign_keys", "ON")
            .expect("foreign keys");
        from_v1.execute_batch(SCHEMA_V1).expect("v1 base");
        from_v1
            .pragma_update(None, "user_version", 1)
            .expect("v1 marker");
        initialize_or_validate_schema(&mut from_v1).expect("v1 migration");
        let mut from_v2 = Connection::open_in_memory().expect("memory database");
        from_v2
            .pragma_update(None, "foreign_keys", "ON")
            .expect("foreign keys");
        from_v2.execute_batch(SCHEMA_V2).expect("v2 base");
        from_v2
            .pragma_update(None, "user_version", 2)
            .expect("v2 marker");
        initialize_or_validate_schema(&mut from_v2).expect("v2 migration");
        let mut from_v5 = Connection::open_in_memory().expect("memory database");
        canonical_v5(&mut from_v5);
        initialize_or_validate_schema(&mut from_v5).expect("v5 migration");

        for (label, connection) in [
            ("fresh", &fresh),
            ("from_v1", &from_v1),
            ("from_v2", &from_v2),
            ("from_v5", &from_v5),
        ] {
            connection
                .execute(INSERT, params![maximal])
                .unwrap_or_else(|error| panic!("{label} stores a maximal key: {error}"));
            let stored: String = connection
                .query_row(
                    "SELECT transport_key FROM inbox WHERE transport = 'slack'",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or_else(|error| panic!("{label} reads the maximal key back: {error}"));
            assert_eq!(stored, maximal, "{label} truncated a maximal key");
            assert!(
                connection.execute(INSERT, params![maximal]).is_err(),
                "{label} admitted a duplicate maximal key"
            );
            connection
                .execute(INSERT, params![sibling])
                .unwrap_or_else(|error| {
                    panic!("{label} treats a key differing in its last byte as taken: {error}")
                });
        }
    }

    #[test]
    fn populated_canonical_v5_migrates_to_empty_pause_state_preserving_every_row() {
        let mut connection = Connection::open_in_memory().expect("memory database");
        canonical_v5(&mut connection);
        connection
            .execute(
                "INSERT INTO generations
                 VALUES ('foreground', 3, 'active', 'holder-v5', 4, 900)",
                [],
            )
            .expect("v5 generation");
        connection
            .execute(
                "INSERT INTO inbox
                 (transport, transport_key, scope, payload, received_ms, state, revision)
                 VALUES ('local.synthetic', 'preserved-v5', 'scope:v5', X'01', 7, 'pending', 1)",
                [],
            )
            .expect("v5 inbox");
        connection
            .execute(
                "INSERT INTO domain_events
                 (aggregate_kind, aggregate_id, revision, schema_version,
                  occurred_ms, kind, payload)
                 VALUES ('generation', 'foreground', 3, 1, 7,
                         'generation.lease_acquired', X'02')",
                [],
            )
            .expect("v5 event");
        connection
            .execute(
                "INSERT INTO telegram_poller_leases
                 (bot_id, revision, generation_id, holder_id, authority_lease_epoch,
                  poller_epoch, expires_ms)
                 VALUES (7, 2, 'foreground', 'holder-v5', 4, 3, 800)",
                [],
            )
            .expect("v5 poller lease");

        initialize_or_validate_schema(&mut connection).expect("v6 migration");
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("version");
        assert_eq!(version, SCHEMA_VERSION);

        // Every table the v5 database carried keeps its rows: this migration
        // adds state and rewrites none.
        for (table, expected) in [
            ("generations", 1),
            ("inbox", 1),
            ("domain_events", 1),
            ("telegram_poller_leases", 1),
            ("intake_pauses", 0),
            ("transport_pauses", 0),
        ] {
            let rows: i64 = connection
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap_or_else(|error| panic!("count {table}: {error}"));
            assert_eq!(rows, expected, "{table} row count changed across v5 -> v7");
        }
        let inbox: (String, String, i64) = connection
            .query_row(
                "SELECT transport_key, scope, revision FROM inbox",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("preserved inbox row");
        assert_eq!(inbox, ("preserved-v5".to_owned(), "scope:v5".to_owned(), 1));
        let generation: (i64, String, i64, i64) = connection
            .query_row(
                "SELECT revision, lease_holder, lease_epoch, lease_expires_ms
                 FROM generations WHERE generation_id = 'foreground'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("preserved generation");
        assert_eq!(
            generation,
            (3, "holder-v5".to_owned(), 4, 0),
            "a lease with no process identity must migrate expired"
        );
        let poller: (i64, String, i64) = connection
            .query_row(
                "SELECT revision, holder_id, poller_epoch FROM telegram_poller_leases
                 WHERE bot_id = 7",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("preserved poller lease");
        assert_eq!(poller, (2, "holder-v5".to_owned(), 3));

        // The migrated database is writable as v6, and the new table's
        // foreign key resolves against the generation that survived.
        connection
            .execute(
                "INSERT INTO intake_pauses
                 (generation_id, revision, paused_at_ms, actor, reason,
                  resumed_at_ms, resume_actor)
                 VALUES ('foreground', 1, 10, 'operator:a', 'draining', NULL, NULL)",
                [],
            )
            .expect("pause writable after migration");
        let orphan = connection.execute(
            "INSERT INTO intake_pauses
             (generation_id, revision, paused_at_ms, actor, reason,
              resumed_at_ms, resume_actor)
             VALUES ('absent', 1, 10, 'operator:a', 'draining', NULL, NULL)",
            [],
        );
        assert!(
            orphan.is_err(),
            "a pause must not name a generation that does not exist"
        );
    }

    /// The v6 → v7 replay. A database carrying the intake pause this ladder step
    /// arrives on top of keeps every row it had, gains an empty transport pause
    /// table, and the new table's own shape is what the daemon relies on: one
    /// row per (transport, scope), and no deadline before the pause began.
    #[test]
    fn populated_canonical_v6_migrates_to_empty_transport_pause_state() {
        let mut connection = Connection::open_in_memory().expect("memory database");
        canonical_v6(&mut connection);
        connection
            .execute(
                "INSERT INTO generations
                 VALUES ('foreground', 3, 'active', 'holder-v6', 4, 900)",
                [],
            )
            .expect("v6 generation");
        connection
            .execute(
                "INSERT INTO intake_pauses
                 (generation_id, revision, paused_at_ms, actor, reason,
                  resumed_at_ms, resume_actor)
                 VALUES ('foreground', 1, 10, 'operator:a', 'draining', NULL, NULL)",
                [],
            )
            .expect("v6 intake pause");
        connection
            .execute(
                "INSERT INTO inbox
                 (transport, transport_key, scope, payload, received_ms, state, revision)
                 VALUES ('local.synthetic', 'preserved-v6', 'scope:v6', X'01', 7, 'pending', 1)",
                [],
            )
            .expect("v6 inbox");

        initialize_or_validate_schema(&mut connection).expect("v7 migration");
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("version");
        assert_eq!(version, SCHEMA_VERSION);
        for (table, expected) in [
            ("generations", 1),
            ("inbox", 1),
            ("intake_pauses", 1),
            ("transport_pauses", 0),
        ] {
            let rows: i64 = connection
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap_or_else(|error| panic!("count {table}: {error}"));
            assert_eq!(rows, expected, "{table} row count changed across v6 -> v7");
        }
        let intake: (String, String) = connection
            .query_row(
                "SELECT actor, reason FROM intake_pauses WHERE generation_id = 'foreground'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("preserved intake pause");
        assert_eq!(intake, ("operator:a".to_owned(), "draining".to_owned()));

        // The migrated database is writable as v7, and the invariants that make
        // "may this bot call out" a question with one answer are in the schema.
        const INSERT: &str = "INSERT INTO transport_pauses
             (transport, scope, revision, paused_at_ms, resume_after_ms, reason)
             VALUES ('telegram', '123456', 1, 10, 20, 'rate_limited')";
        connection.execute(INSERT, []).expect("pause writable");
        assert!(
            connection.execute(INSERT, []).is_err(),
            "a transport and scope must not carry two pause rows"
        );
        assert!(
            connection
                .execute(
                    "INSERT INTO transport_pauses
                     (transport, scope, revision, paused_at_ms, resume_after_ms, reason)
                     VALUES ('telegram', '999', 1, 30, 20, 'rate_limited')",
                    [],
                )
                .is_err(),
            "a pause must not end before it began"
        );
        assert!(
            connection
                .execute(
                    "INSERT INTO transport_pauses
                     (transport, scope, revision, paused_at_ms, resume_after_ms, reason)
                     VALUES ('telegram', '998', 0, 10, 20, 'rate_limited')",
                    [],
                )
                .is_err(),
            "a pause revision starts at one"
        );
    }

    /// Every schema path this build can reach carries the transport pause table,
    /// which is what makes a restart on an inherited database honour a 429.
    #[test]
    fn every_schema_path_reaches_the_transport_pause_table() {
        let mut fresh = Connection::open_in_memory().expect("memory database");
        initialize_or_validate_schema(&mut fresh).expect("fresh initialization");
        let mut from_v1 = Connection::open_in_memory().expect("memory database");
        from_v1
            .pragma_update(None, "foreign_keys", "ON")
            .expect("foreign keys");
        from_v1.execute_batch(SCHEMA_V1).expect("v1 base");
        from_v1
            .pragma_update(None, "user_version", 1)
            .expect("v1 marker");
        initialize_or_validate_schema(&mut from_v1).expect("v1 migration");
        let mut from_v5 = Connection::open_in_memory().expect("memory database");
        canonical_v5(&mut from_v5);
        initialize_or_validate_schema(&mut from_v5).expect("v5 migration");
        let mut from_v6 = Connection::open_in_memory().expect("memory database");
        canonical_v6(&mut from_v6);
        initialize_or_validate_schema(&mut from_v6).expect("v6 migration");

        for (label, connection) in [
            ("fresh", &fresh),
            ("from_v1", &from_v1),
            ("from_v5", &from_v5),
            ("from_v6", &from_v6),
        ] {
            let version: u32 = connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap_or_else(|error| panic!("{label} version: {error}"));
            assert_eq!(version, SCHEMA_VERSION, "{label} stopped short of v9");
            connection
                .execute(
                    "INSERT INTO transport_pauses
                     (transport, scope, revision, paused_at_ms, resume_after_ms, reason)
                     VALUES ('telegram', '123456', 1, 10, 20, 'rate_limited')",
                    [],
                )
                .unwrap_or_else(|error| panic!("{label} stores a transport pause: {error}"));
        }
    }

    #[test]
    fn populated_canonical_v4_preserves_telegram_rows_and_adds_null_provenance() {
        let mut connection = Connection::open_in_memory().expect("memory database");
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("foreign keys");
        connection.execute_batch(SCHEMA_V2).expect("v2 base");
        connection
            .execute_batch(MIGRATE_V2_TO_V3)
            .expect("v3 schema");
        connection
            .execute_batch(MIGRATE_V3_TO_V4)
            .expect("canonical v4 schema");
        connection
            .pragma_update(None, "user_version", 4)
            .expect("v4 marker");
        let update_id = u64::MAX - 1;
        connection
            .execute(
                "INSERT INTO telegram_offsets
                 (bot_id, next_offset, revision, updated_ms) VALUES (?1, ?2, 2, 9)",
                params![7, &telegram_offset_bytes(u64::MAX)[..]],
            )
            .expect("populated offset");
        connection
            .execute(
                "INSERT INTO telegram_ingress
                 (bot_id, update_id, source_key, scope, disposition, content, received_ms)
                 VALUES (?1, ?2, ?3, 'telegram:7:chat', 'denied', NULL, 9)",
                params![
                    7,
                    &telegram_offset_bytes(update_id)[..],
                    format!("telegram:7:update:{update_id}")
                ],
            )
            .expect("populated disposition");
        connection
            .execute(
                "INSERT INTO telegram_batches
                 (bot_id, expected_offset, next_offset, disposition_count, received_ms)
                 VALUES (?1, ?2, ?3, 1, 9)",
                params![
                    7,
                    &telegram_offset_bytes(0)[..],
                    &telegram_offset_bytes(u64::MAX)[..]
                ],
            )
            .expect("populated batch");

        initialize_or_validate_schema(&mut connection).expect("v5 migration");
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("version");
        assert_eq!(version, SCHEMA_VERSION);
        let offset: Vec<u8> = connection
            .query_row(
                "SELECT next_offset FROM telegram_offsets WHERE bot_id = 7",
                [],
                |row| row.get(0),
            )
            .expect("preserved offset");
        assert_eq!(
            telegram_offset_from_bytes(&offset).expect("offset"),
            u64::MAX
        );
        let disposition: (String, String, Option<Vec<u8>>) = connection
            .query_row(
                "SELECT source_key, disposition, content FROM telegram_ingress
                 WHERE bot_id = 7 AND update_id = ?1",
                [&telegram_offset_bytes(update_id)[..]],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("preserved disposition");
        assert_eq!(
            disposition,
            (
                format!("telegram:7:update:{update_id}"),
                "denied".to_owned(),
                None
            )
        );
        let provenance: (Option<String>, Option<String>, Option<String>) = connection
            .query_row(
                "SELECT trace_id, correlation_id, causation_id FROM telegram_ingress
                 WHERE bot_id = 7 AND update_id = ?1",
                [&telegram_offset_bytes(update_id)[..]],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("historical provenance");
        assert_eq!(provenance, (None, None, None));
        let batch: LegacyTelegramBatch = connection
            .query_row(
                "SELECT disposition_count, batch_digest, poller_generation_id,
                            poller_holder_id, poller_epoch
                     FROM telegram_batches WHERE bot_id = 7 AND expected_offset = ?1",
                [&telegram_offset_bytes(0)[..]],
                |row| {
                    Ok(LegacyTelegramBatch {
                        disposition_count: row.get(0)?,
                        batch_digest: row.get(1)?,
                        generation_id: row.get(2)?,
                        holder_id: row.get(3)?,
                        poller_epoch: row.get(4)?,
                    })
                },
            )
            .expect("preserved batch");
        assert_eq!(
            batch,
            LegacyTelegramBatch {
                disposition_count: 1,
                batch_digest: None,
                generation_id: None,
                holder_id: None,
                poller_epoch: None,
            }
        );
        let poller_rows: i64 = connection
            .query_row("SELECT count(*) FROM telegram_poller_leases", [], |row| {
                row.get(0)
            })
            .expect("empty ownership table");
        assert_eq!(poller_rows, 0);
    }

    #[test]
    fn canonical_v3_outbox_migrates_without_making_delivered_work_ready() {
        let mut connection = Connection::open_in_memory().expect("memory database");
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("foreign keys");
        connection.execute_batch(SCHEMA_V2).expect("v2 base");
        connection
            .execute_batch(MIGRATE_V2_TO_V3)
            .expect("v3 schema");
        connection
            .pragma_update(None, "user_version", 3)
            .expect("v3 marker");
        connection
            .execute(
                "INSERT INTO domain_events
                 (aggregate_kind, aggregate_id, revision, schema_version,
                  occurred_ms, kind, payload)
                 VALUES ('run', '1', 1, 1, 1, 'run.succeeded', X'01'),
                        ('run', '2', 1, 1, 2, 'run.succeeded', X'02')",
                [],
            )
            .expect("events");
        connection
            .execute(
                "INSERT INTO outbox
                 (intent_key, event_id, kind, payload, state, created_ms)
                 VALUES ('pending', 1, 'telegram.reply', X'01', 'pending', 1),
                        ('done', 2, 'telegram.reply', X'02', 'delivered', 2)",
                [],
            )
            .expect("v3 outbox rows");

        initialize_or_validate_schema(&mut connection).expect("v4 migration");
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("version");
        assert_eq!(version, SCHEMA_VERSION);
        let pending: (String, String, i64, i64) = connection
            .query_row(
                "SELECT transport, state, revision, attempts FROM outbox
                 WHERE intent_key = 'pending'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("pending migrated");
        assert_eq!(pending, ("telegram".to_owned(), "pending".to_owned(), 1, 0));
        let delivered: (String, Option<String>) = connection
            .query_row(
                "SELECT state, delivery_receipt_key FROM outbox WHERE intent_key = 'done'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("delivered migrated");
        assert_eq!(
            delivered,
            ("delivered".to_owned(), Some("legacy-receipt:2".to_owned()))
        );
    }

    #[test]
    fn canonical_v2_migrates_to_empty_telegram_state_without_changing_existing_rows() {
        let mut connection = Connection::open_in_memory().expect("memory database");
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("foreign keys");
        connection
            .execute_batch(SCHEMA_V2)
            .expect("canonical v2 schema");
        connection
            .pragma_update(None, "user_version", 2)
            .expect("v2 marker");
        connection
            .execute(
                "INSERT INTO inbox
                 (transport, transport_key, scope, payload, received_ms, state, revision)
                 VALUES ('test', 'preserved', 'scope:test', X'01', 1, 'pending', 1)",
                [],
            )
            .expect("existing v2 row");

        initialize_or_validate_schema(&mut connection).expect("v3 migration");
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("version");
        assert_eq!(version, SCHEMA_VERSION);
        let preserved: String = connection
            .query_row("SELECT transport_key FROM inbox", [], |row| row.get(0))
            .expect("preserved row");
        assert_eq!(preserved, "preserved");
        let telegram_rows: i64 = connection
            .query_row("SELECT count(*) FROM telegram_offsets", [], |row| {
                row.get(0)
            })
            .expect("telegram table");
        assert_eq!(telegram_rows, 0);
    }

    #[test]
    fn canonical_v1_schema_migrates_pending_and_claimed_rows() {
        let mut connection = Connection::open_in_memory().expect("memory database");
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("foreign keys");
        connection
            .execute_batch(SCHEMA_V1)
            .expect("canonical v1 schema");
        connection
            .pragma_update(None, "user_version", 1)
            .expect("v1 marker");
        connection
            .execute(
                "INSERT INTO generations VALUES ('generation-a', 1, 'active', 'holder-a', 1, 100)",
                [],
            )
            .expect("generation");
        connection
            .execute(
                "INSERT INTO inbox
                 (inbox_id, transport, transport_key, payload, received_ms, revision)
                 VALUES (1, 'test', 'pending', X'01', 1, 1),
                        (2, 'test', 'claimed', X'02', 2, 1)",
                [],
            )
            .expect("v1 inbox");
        connection
            .execute(
                "INSERT INTO runs
                 (run_id, claim_key, inbox_id, scope, generation_id, lease_epoch,
                  state, revision, started_ms)
                 VALUES (1, 'claim-v1', 2, 'scope:v1', 'generation-a', 1,
                         'running', 1, 3)",
                [],
            )
            .expect("v1 run");
        connection
            .execute(
                "INSERT INTO domain_events
                 (event_id, aggregate_kind, aggregate_id, revision, schema_version,
                  occurred_ms, kind, payload)
                 VALUES (1, 'inbox', '1', 1, 1, 1, 'inbox.accepted', X'01'),
                        (2, 'inbox', '2', 1, 1, 2, 'inbox.accepted', X'02'),
                        (3, 'run', '1', 1, 1, 3, 'run.claimed', X'03')",
                [],
            )
            .expect("v1 events");

        initialize_or_validate_schema(&mut connection).expect("migration");
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("version");
        assert_eq!(version, SCHEMA_VERSION);
        let pending: (String, String, Option<i64>, i64) = connection
            .query_row(
                "SELECT scope, state, claimed_run_id, revision FROM inbox WHERE inbox_id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("pending row");
        assert_eq!(
            pending,
            ("legacy:1".to_owned(), "pending".to_owned(), None, 1)
        );
        let claimed: (String, String, Option<i64>, i64) = connection
            .query_row(
                "SELECT scope, state, claimed_run_id, revision FROM inbox WHERE inbox_id = 2",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("claimed row");
        assert_eq!(
            claimed,
            ("scope:v1".to_owned(), "claimed".to_owned(), Some(1), 2)
        );
        let migrated_event: String = connection
            .query_row(
                "SELECT kind FROM domain_events
                 WHERE aggregate_kind = 'inbox' AND aggregate_id = '2' AND revision = 2",
                [],
                |row| row.get(0),
            )
            .expect("migration event");
        assert_eq!(migrated_event, "inbox.claimed");
    }

    #[test]
    fn v1_duplicate_runs_for_one_inbox_refuse_migration() {
        let mut connection = Connection::open_in_memory().expect("memory database");
        connection
            .execute_batch(SCHEMA_V1)
            .expect("canonical v1 schema");
        connection
            .pragma_update(None, "user_version", 1)
            .expect("v1 marker");
        connection
            .execute(
                "INSERT INTO generations VALUES ('generation-a', 1, 'active', 'holder-a', 1, 100)",
                [],
            )
            .expect("generation");
        connection
            .execute(
                "INSERT INTO inbox VALUES (1, 'test', 'duplicate', X'01', 1, 1)",
                [],
            )
            .expect("inbox");
        connection
            .execute(
                "INSERT INTO runs
                 (run_id, claim_key, inbox_id, scope, generation_id, lease_epoch,
                  state, revision, started_ms)
                 VALUES (1, 'claim-a', 1, 'scope:a', 'generation-a', 1, 'running', 1, 2),
                        (2, 'claim-b', 1, 'scope:b', 'generation-a', 1, 'running', 1, 3)",
                [],
            )
            .expect("ambiguous v1 runs");
        let error = initialize_or_validate_schema(&mut connection)
            .expect_err("ambiguous history must not be guessed");
        assert_eq!(error.category(), "migration_invariant");
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("version remains v1");
        assert_eq!(version, 1);
    }
}
