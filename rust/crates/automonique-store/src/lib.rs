// SPDX-License-Identifier: Elastic-2.0

//! Durable, single-writer product state for Automonique.
//!
//! The store owns SQLite transaction boundaries. Callers provide time and
//! stable transport/action keys so retries remain deterministic and tests do
//! not depend on an ambient clock.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use nix::unistd::geteuid;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

/// The only database schema this build can read and write.
pub const SCHEMA_VERSION: u32 = 1;
/// SQLite lock contention is bounded rather than waiting indefinitely.
pub const BUSY_TIMEOUT: Duration = Duration::from_millis(2_000);

const MAX_ID_BYTES: usize = 256;
const MAX_KIND_BYTES: usize = 128;
const MAX_PAYLOAD_BYTES: usize = 1_048_576;

const SCHEMA: &str = r#"
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

/// A durable store error with stable refusal categories.
#[derive(Debug)]
pub enum StoreError {
    /// The database path or its containing directory is not private and owned.
    InsecurePath(String),
    /// The database schema is absent from a non-empty database or unsupported.
    SchemaVersion { found: u32, supported: u32 },
    /// A caller-provided field is empty, over-long, malformed, or out of range.
    InvalidField(&'static str),
    /// A stable retry key was reused for different input.
    IdempotencyConflict(&'static str),
    /// Another live generation owns the requested lease.
    LeaseHeld,
    /// The supplied lease holder/epoch is stale or expired.
    StaleEpoch,
    /// Another live run holds the requested scope.
    ScopeLocked,
    /// A prior run's scope lease expired and its execution must be reconciled.
    ReconciliationRequired { run_id: i64 },
    /// The referenced durable row does not exist.
    NotFound(&'static str),
    /// A terminal transition was retried with different content.
    AlreadyTerminal,
    /// The outbox key already belongs to another intent.
    OutboxConflict,
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
            Self::InvalidField(_) => "invalid_field",
            Self::IdempotencyConflict(_) => "idempotency_conflict",
            Self::LeaseHeld => "lease_held",
            Self::StaleEpoch => "stale_epoch",
            Self::ScopeLocked => "scope_locked",
            Self::ReconciliationRequired { .. } => "reconciliation_required",
            Self::NotFound(_) => "not_found",
            Self::AlreadyTerminal => "already_terminal",
            Self::OutboxConflict => "outbox_conflict",
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
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::IdempotencyConflict(key) => write!(formatter, "stable key was reused: {key}"),
            Self::LeaseHeld => formatter.write_str("generation lease is held"),
            Self::StaleEpoch => formatter.write_str("generation lease epoch is stale or expired"),
            Self::ScopeLocked => formatter.write_str("work scope is locked"),
            Self::ReconciliationRequired { run_id } => {
                write!(
                    formatter,
                    "run {run_id} requires reconciliation before scope reuse"
                )
            }
            Self::NotFound(row) => write!(formatter, "durable row not found: {row}"),
            Self::AlreadyTerminal => {
                formatter.write_str("run is already terminal with different content")
            }
            Self::OutboxConflict => formatter.write_str("outbox intent key is already in use"),
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
    pub expires_ms: i64,
}

/// Parameters for acquiring a new or expired generation lease.
pub struct LeaseRequest<'a> {
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub now_ms: i64,
    pub ttl_ms: i64,
}

/// Parameters for renewing the exact lease epoch a worker already owns.
pub struct LeaseRenewal<'a> {
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub epoch: u64,
    pub now_ms: i64,
    pub ttl_ms: i64,
}

/// One stable transport delivery.
pub struct InboxSubmission<'a> {
    pub transport: &'a str,
    pub transport_key: &'a str,
    pub payload: &'a [u8],
    pub received_ms: i64,
}

/// The durable result of accepting a transport delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboxReceipt {
    pub inbox_id: i64,
    pub duplicate: bool,
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

/// Minimal persisted run state used by status and recovery code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunSnapshot {
    pub state: String,
    pub revision: u64,
}

/// One generation row in a consistent operator-status snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationSnapshot {
    pub generation_id: String,
    pub revision: u64,
    pub state: String,
    pub holder_id: String,
    pub lease_epoch: u64,
    pub lease_expires_ms: i64,
}

/// Read-only database status observed from one SQLite snapshot transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusSnapshot {
    pub schema_version: u32,
    pub generation: Option<GenerationSnapshot>,
    pub event_cursor: u64,
    pub inbox_pending: u64,
    pub outbox_pending: u64,
    pub runs_running: u64,
}

/// Product SQLite store. A daemon should own it from one dedicated actor.
pub struct Store {
    connection: Connection,
    path: PathBuf,
}

impl Store {
    /// Open or initialize a database inside an existing private directory.
    ///
    /// The parent must be owned by the effective user and deny all group/other
    /// access. Existing database paths must be regular, owned, non-symlinks.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
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
            return Err(StoreError::Sqlite(rusqlite::Error::InvalidQuery));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        initialize_or_validate_schema(&mut connection)?;

        Ok(Self {
            connection,
            path: path.to_path_buf(),
        })
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
        validate_id(request.generation_id, "generation_id")?;
        validate_id(request.holder_id, "holder_id")?;
        let expires_ms = checked_expiry(request.now_ms, request.ttl_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = transaction
            .query_row(
                "SELECT lease_holder, lease_epoch, lease_expires_ms, revision
                 FROM generations WHERE generation_id = ?1",
                [request.generation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;

        let (epoch, revision, changed) = match current {
            None => {
                transaction.execute(
                    "INSERT INTO generations
                     (generation_id, revision, state, lease_holder, lease_epoch, lease_expires_ms)
                     VALUES (?1, 1, 'active', ?2, 1, ?3)",
                    params![request.generation_id, request.holder_id, expires_ms],
                )?;
                (1_u64, 1_u64, true)
            }
            Some((holder, raw_epoch, old_expiry, raw_revision)) => {
                let epoch = from_db_u64(raw_epoch, "lease_epoch")?;
                let revision = from_db_u64(raw_revision, "revision")?;
                if old_expiry > request.now_ms {
                    if holder == request.holder_id {
                        transaction.commit()?;
                        return Ok(GenerationLease {
                            generation_id: request.generation_id.to_owned(),
                            holder_id: holder,
                            epoch,
                            expires_ms: old_expiry,
                        });
                    }
                    return Err(StoreError::LeaseHeld);
                }
                let next_epoch = epoch.checked_add(1).ok_or(StoreError::StaleEpoch)?;
                let next_revision = revision
                    .checked_add(1)
                    .ok_or(StoreError::InvalidField("generation_revision"))?;
                transaction.execute(
                    "UPDATE generations SET revision = ?2, lease_holder = ?3,
                     lease_epoch = ?4, lease_expires_ms = ?5 WHERE generation_id = ?1",
                    params![
                        request.generation_id,
                        to_db_u64(next_revision, "generation_revision")?,
                        request.holder_id,
                        to_db_u64(next_epoch, "lease_epoch")?,
                        expires_ms
                    ],
                )?;
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
        })
    }

    /// Renew only the exact, live lease epoch held by this generation owner.
    pub fn renew_generation_lease(
        &mut self,
        renewal: LeaseRenewal<'_>,
    ) -> Result<GenerationLease, StoreError> {
        validate_id(renewal.generation_id, "generation_id")?;
        validate_id(renewal.holder_id, "holder_id")?;
        let expires_ms = checked_expiry(renewal.now_ms, renewal.ttl_ms)?;
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
                renewal.now_ms
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::StaleEpoch);
        }
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
        })
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
        let epoch = to_db_u64(epoch, "lease_epoch")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let raw_revision = transaction
            .query_row(
                "SELECT revision FROM generations
                 WHERE generation_id = ?1 AND lease_holder = ?2 AND lease_epoch = ?3
                 AND lease_expires_ms > ?4",
                params![generation_id, holder_id, epoch, now_ms],
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
                now_ms
            ],
        )?;
        transaction.execute(
            "UPDATE work_locks SET expires_ms = ?3
             WHERE generation_id = ?1 AND lease_epoch = ?2",
            params![generation_id, epoch, now_ms],
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

    /// Durably accept one transport delivery, replaying the same stable key.
    pub fn submit_inbox(
        &mut self,
        submission: InboxSubmission<'_>,
    ) -> Result<InboxReceipt, StoreError> {
        validate_id(submission.transport, "transport")?;
        validate_id(submission.transport_key, "transport_key")?;
        validate_payload(submission.payload, "inbox_payload")?;
        validate_time(submission.received_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((inbox_id, payload)) = transaction
            .query_row(
                "SELECT inbox_id, payload FROM inbox WHERE transport = ?1 AND transport_key = ?2",
                params![submission.transport, submission.transport_key],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
        {
            if payload != submission.payload {
                return Err(StoreError::IdempotencyConflict("transport_key"));
            }
            transaction.commit()?;
            return Ok(InboxReceipt {
                inbox_id,
                duplicate: true,
            });
        }

        transaction.execute(
            "INSERT INTO inbox (transport, transport_key, payload, received_ms, revision)
             VALUES (?1, ?2, ?3, ?4, 1)",
            params![
                submission.transport,
                submission.transport_key,
                submission.payload,
                submission.received_ms
            ],
        )?;
        let inbox_id = transaction.last_insert_rowid();
        append_event(
            &transaction,
            "inbox",
            &inbox_id.to_string(),
            1,
            submission.received_ms,
            "inbox.accepted",
            submission.transport_key.as_bytes(),
        )?;
        transaction.commit()?;
        Ok(InboxReceipt {
            inbox_id,
            duplicate: false,
        })
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
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lease_expiry = require_live_lease(
            &transaction,
            claim.generation_id,
            claim.holder_id,
            claim.lease_epoch,
            claim.now_ms,
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

        let inbox_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM inbox WHERE inbox_id = ?1)",
            [claim.inbox_id],
            |row| row.get(0),
        )?;
        if !inbox_exists {
            return Err(StoreError::NotFound("inbox"));
        }

        if let Some((old_run_id, expires_ms)) = transaction
            .query_row(
                "SELECT run_id, expires_ms FROM work_locks WHERE scope = ?1",
                [claim.scope],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
        {
            if expires_ms > claim.now_ms {
                return Err(StoreError::ScopeLocked);
            }
            return Err(StoreError::ReconciliationRequired { run_id: old_run_id });
        }

        transaction.execute(
            "INSERT INTO runs
             (claim_key, inbox_id, scope, generation_id, lease_epoch, state, revision, started_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, 'running', 1, ?6)",
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
        append_event(
            &transaction,
            "run",
            &run_id.to_string(),
            1,
            claim.now_ms,
            "run.claimed",
            claim.scope.as_bytes(),
        )?;
        transaction.commit()?;
        Ok(RunClaim {
            run_id,
            duplicate: false,
        })
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
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_live_lease(
            &transaction,
            terminal.generation_id,
            terminal.holder_id,
            terminal.lease_epoch,
            terminal.now_ms,
        )?;

        let run = transaction
            .query_row(
                "SELECT state, revision, generation_id, lease_epoch, terminal_payload,
                        outbox_intent_key
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
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound("run"))?;
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

        transaction.execute(
            "UPDATE runs SET state = ?2, revision = ?3, finished_ms = ?4,
             terminal_payload = ?5, outbox_intent_key = ?6 WHERE run_id = ?1",
            params![
                terminal.run_id,
                terminal.state.as_str(),
                to_db_u64(next_revision, "run_revision")?,
                terminal.now_ms,
                terminal.event_payload,
                terminal.outbox_intent_key
            ],
        )?;
        let event_id = append_event(
            &transaction,
            "run",
            &terminal.run_id.to_string(),
            next_revision,
            terminal.now_ms,
            terminal.event_kind,
            terminal.event_payload,
        )?;
        let insert = transaction.execute(
            "INSERT INTO outbox (intent_key, event_id, kind, payload, state, created_ms)
             VALUES (?1, ?2, ?3, ?4, 'pending', ?5)",
            params![
                terminal.outbox_intent_key,
                event_id,
                terminal.outbox_kind,
                terminal.outbox_payload,
                terminal.now_ms
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
        transaction.execute(
            "DELETE FROM work_locks WHERE run_id = ?1",
            [terminal.run_id],
        )?;
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

    /// Whether a scope lock currently exists.
    pub fn scope_is_locked(&self, scope: &str) -> Result<bool, StoreError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM work_locks WHERE scope = ?1)",
            [scope],
            |row| row.get(0),
        )?)
    }

    /// Observe daemon-facing status from one explicit, consistent read transaction.
    pub fn status_snapshot(&mut self, generation_id: &str) -> Result<StatusSnapshot, StoreError> {
        validate_id(generation_id, "generation_id")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let generation = transaction
            .query_row(
                "SELECT generation_id, revision, state, lease_holder, lease_epoch,
                        lease_expires_ms
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
                })
            })
            .transpose()?;
        let event_cursor = query_count(
            &transaction,
            "SELECT COALESCE(MAX(event_id), 0) FROM domain_events",
        )?;
        let inbox_pending = query_count(
            &transaction,
            "SELECT count(*) FROM inbox i
             WHERE NOT EXISTS (
                 SELECT 1 FROM runs r
                 WHERE r.inbox_id = i.inbox_id AND r.state != 'abandoned'
             )",
        )?;
        let outbox_pending = query_count(
            &transaction,
            "SELECT count(*) FROM outbox WHERE state = 'pending'",
        )?;
        let runs_running = query_count(
            &transaction,
            "SELECT count(*) FROM runs WHERE state = 'running'",
        )?;
        transaction.commit()?;
        Ok(StatusSnapshot {
            schema_version: SCHEMA_VERSION,
            generation,
            event_cursor,
            inbox_pending,
            outbox_pending,
            runs_running,
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
    transaction.execute_batch(SCHEMA)?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn validate_id(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES || value.chars().any(char::is_control) {
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

fn append_event(
    transaction: &Transaction<'_>,
    aggregate_kind: &str,
    aggregate_id: &str,
    revision: u64,
    occurred_ms: i64,
    kind: &str,
    payload: &[u8],
) -> Result<i64, StoreError> {
    validate_id(aggregate_kind, "aggregate_kind")?;
    validate_id(aggregate_id, "aggregate_id")?;
    if kind.is_empty() || kind.len() > MAX_KIND_BYTES || kind.chars().any(char::is_control) {
        return Err(StoreError::InvalidField("event_kind"));
    }
    validate_payload(payload, "event_payload")?;
    transaction.execute(
        "INSERT INTO domain_events
         (aggregate_kind, aggregate_id, revision, schema_version, occurred_ms, kind, payload)
         VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6)",
        params![
            aggregate_kind,
            aggregate_id,
            to_db_u64(revision, "event_revision")?,
            occurred_ms,
            kind,
            payload
        ],
    )?;
    Ok(transaction.last_insert_rowid())
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
