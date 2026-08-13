// SPDX-License-Identifier: Elastic-2.0

//! Durable host-wide ledger of recorded cancellation requests.
//!
//! A control endpoint accepts a cancellation request naming an attempt, a
//! caller-chosen `request_ref` and the event sequence the requester had
//! observed when it asked. The endpoint must answer the same way for a retry as
//! for the original — a client that loses the answer retries, and a second
//! delivery of the same reference is a bug, not a second cancellation. Keeping
//! that decision in process memory makes it neither durable nor host-wide:
//! `automonique-runner`'s control socket says so in its own divergence notes.
//!
//! This module is the durable, host-wide replacement. It records exactly the
//! binding
//!
//! ```text
//! request_ref -> (attempt_id, observed_sequence, requested_at_ms)
//! ```
//!
//! and answers three ways and only three ways:
//!
//! - the reference is new: the binding is recorded, [`CancelDisposition::Delivered`];
//! - the reference is present with the *same* attempt and sequence: it is an
//!   exact replay, [`CancelDisposition::AlreadyDelivered`], and not one byte of
//!   the durable row changes;
//! - the reference is present with a different attempt or a different observed
//!   sequence: [`CancelLedgerError::Conflict`], and nothing is written.
//!
//! There is no cancellation IO here. Callers supply every identifier, sequence
//! and timestamp, so retries stay deterministic and tests do not depend on an
//! ambient clock.
//!
//! # What a ledger row does not establish
//!
//! - A row proves a cancellation request was **recorded**, not that any process
//!   died. It does not establish that the process exited, that descendants were
//!   reaped, or that a run reached a terminal state; those remain separate
//!   observations elsewhere.
//! - It does not establish that any cancellation sink ever saw the request. A
//!   caller that records first and delivers second may crash in between; a
//!   caller that delivers first and records second may deliver twice. Which
//!   order to use is the caller's decision, and this module states the choice
//!   rather than hiding it: recording is the cheap, replay-safe half.
//! - `observed_sequence` is the requester's claim about what it had seen. The
//!   ledger stores and compares it; it never checks it against a spool, and a
//!   sequence ahead of reality is recorded, not detected.
//! - A [`Retention::terminal_attempts`] entry is the caller's declaration that
//!   an attempt is finished. The ledger cannot verify terminality and does not
//!   try.
//!
//! # Deletion
//!
//! Ordinary operation never deletes. [`CancelLedger::prune`] is the only
//! deletion path in this module, and its cost is stated plainly in that
//! method's documentation: a pruned reference is *forgotten*, so presenting it
//! again is answered `Delivered` a second time.
//!
//! # Storage discipline
//!
//! The ledger owns its own SQLite database with its own `user_version`, opened
//! under the same privacy, WAL and `synchronous = FULL` rules as [`crate::Store`].
//! Recording one request is one immediate transaction, so a reader after a
//! crash sees the whole entry or no entry. Every read re-validates the row it
//! loaded rather than trusting the database.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::{BUSY_TIMEOUT, StoreError, validate_database_path};

/// The only cancel ledger schema this build can read and write.
pub const CANCEL_LEDGER_SCHEMA_VERSION: u32 = 1;

/// Largest number of live entries any ledger will hold.
pub const MAX_LEDGER_ENTRIES: usize = 65_536;

/// Longest accepted `request_ref` or `attempt_id`, in bytes.
///
/// The same identifier grammar [`crate::Store`] uses: non-empty, at most this
/// many bytes, no control characters.
pub const MAX_IDENTIFIER_BYTES: usize = 256;

/// Largest batch [`CancelLedger::record_all`] will accept.
pub const MAX_BATCH_REQUESTS: usize = 1_024;

/// Largest terminal-attempt list [`CancelLedger::prune`] will accept.
pub const MAX_TERMINAL_ATTEMPTS: usize = 1_024;

/// Schema v1.
///
/// Uniqueness of `request_ref` and the non-negative ranges are database
/// constraints so a second writer cannot introduce a duplicate binding. The
/// identifier grammar and length bound are deliberately *not* database
/// constraints: they are enforced on write and re-checked on every read, so a
/// row written around this API is refused rather than believed.
const SCHEMA_V1: &str = r#"
CREATE TABLE cancel_requests (
    entry_id INTEGER PRIMARY KEY,
    request_ref TEXT NOT NULL UNIQUE,
    attempt_id TEXT NOT NULL,
    observed_sequence INTEGER NOT NULL CHECK (observed_sequence >= 0),
    requested_at_ms INTEGER NOT NULL CHECK (requested_at_ms >= 0)
) STRICT;

CREATE INDEX cancel_requests_by_attempt
    ON cancel_requests(attempt_id, entry_id);
"#;

/// A cancel ledger error with stable refusal categories.
#[derive(Debug)]
pub enum CancelLedgerError {
    /// The ledger path or its containing directory is not private and owned.
    InsecurePath(String),
    /// The ledger schema is absent from a non-empty database or unsupported.
    SchemaVersion { found: u32, supported: u32 },
    /// A caller-provided field is empty, over-long, malformed, or out of range.
    InvalidField(&'static str),
    /// A recorded `request_ref` was presented with a different binding.
    ///
    /// Nothing was written. The recorded coordinates are reported so a caller
    /// can tell a stale retry from a reused reference without a second read.
    Conflict {
        /// First bound coordinate that differs: `attempt_id` or
        /// `observed_sequence`.
        field: &'static str,
        /// Attempt the durable entry binds.
        recorded_attempt_id: String,
        /// Observed sequence the durable entry binds.
        recorded_observed_sequence: u64,
    },
    /// The ledger holds its full capacity of live entries.
    ///
    /// Recording is refused *before* delivery, because a delivery this ledger
    /// cannot record would lose idempotency for every later replay.
    LedgerFull { capacity: usize },
    /// A stored row violates an invariant this API can only have written once.
    Corrupt(&'static str),
    /// Filesystem failure while establishing the private ledger.
    Io(std::io::Error),
    /// SQLite rejected an operation.
    Sqlite(rusqlite::Error),
}

impl CancelLedgerError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::Conflict { .. } => "conflict",
            Self::LedgerFull { .. } => "ledger_full",
            Self::Corrupt(_) => "corrupt",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}

impl fmt::Display for CancelLedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => {
                write!(formatter, "ledger path is not private: {reason}")
            }
            Self::SchemaVersion { found, supported } => write!(
                formatter,
                "cancel ledger schema {found} is unsupported; expected {supported}"
            ),
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::Conflict {
                field,
                recorded_attempt_id,
                recorded_observed_sequence,
            } => write!(
                formatter,
                "request_ref is already bound to attempt {recorded_attempt_id} \
                 at observed sequence {recorded_observed_sequence}; {field} differs"
            ),
            Self::LedgerFull { capacity } => {
                write!(formatter, "cancel ledger holds its capacity of {capacity}")
            }
            Self::Corrupt(invariant) => {
                write!(formatter, "stored row violates invariant: {invariant}")
            }
            Self::Io(error) => write!(formatter, "ledger filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite error: {error}"),
        }
    }
}

impl Error for CancelLedgerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CancelLedgerError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for CancelLedgerError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// Result of one ledger operation.
pub type Ledgered<T> = Result<T, CancelLedgerError>;

/// One cancellation request presented for durable recording.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelRequest<'a> {
    /// Bounded opaque reference chosen by the requester. The unique key.
    pub request_ref: &'a str,
    /// Attempt this reference cancels.
    pub attempt_id: &'a str,
    /// Event sequence the requester had observed when it asked.
    pub observed_sequence: u64,
    /// When the requester asked, in caller-supplied milliseconds.
    ///
    /// Not part of the binding: a retry naturally carries a later clock, so a
    /// differing timestamp is an exact replay, not a conflict, and never
    /// rewrites the recorded one.
    pub requested_at_ms: i64,
}

/// How the ledger answered one recording.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelDisposition {
    /// The binding was new and is now durable.
    Delivered,
    /// The exact binding was already durable. Nothing changed.
    AlreadyDelivered,
}

impl CancelDisposition {
    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::AlreadyDelivered => "already_delivered",
        }
    }
}

/// Durable identity of one recorded or replayed cancellation request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelReceipt {
    /// Row identity of the durable entry.
    pub entry_id: i64,
    pub disposition: CancelDisposition,
}

/// Validated `cancel_requests` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelEntry {
    pub entry_id: i64,
    pub request_ref: String,
    pub attempt_id: String,
    pub observed_sequence: u64,
    /// When the *first* delivery of this reference was recorded.
    pub requested_at_ms: i64,
}

/// Bounded retention window for [`CancelLedger::prune`].
///
/// Both conditions must hold for an entry to be eligible; neither alone is
/// enough. There is no "prune everything" spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Retention<'a> {
    /// Entries recorded strictly before this instant are old enough.
    pub older_than_ms: i64,
    /// Attempts the caller declares terminal. Only their entries are eligible.
    ///
    /// The ledger cannot verify terminality; this is the caller's assertion.
    pub terminal_attempts: &'a [&'a str],
}

/// What one prune removed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PruneOutcome {
    /// Entries deleted by this prune.
    pub removed: usize,
    /// Entries still live afterwards.
    pub remaining: usize,
}

/// Durable host-wide cancellation request ledger.
#[derive(Debug)]
pub struct CancelLedger {
    connection: Connection,
    path: PathBuf,
    capacity: usize,
}

impl CancelLedger {
    /// Open or initialize a ledger inside an existing private directory.
    ///
    /// The parent must be owned by the effective user and deny all group/other
    /// access. Existing ledger paths must be regular, owned, non-symlinks.
    /// Capacity is [`MAX_LEDGER_ENTRIES`].
    pub fn open(path: impl AsRef<Path>) -> Ledgered<Self> {
        Self::open_with_capacity(path, MAX_LEDGER_ENTRIES)
    }

    /// Open a ledger with a lowered live-entry capacity.
    ///
    /// `capacity` must be between one and [`MAX_LEDGER_ENTRIES`]. It is a
    /// property of this handle, not of the database: opening an existing ledger
    /// under a capacity below its current entry count refuses further
    /// recordings with [`CancelLedgerError::LedgerFull`] while exact replays
    /// and reads keep working, because a replay writes nothing.
    pub fn open_with_capacity(path: impl AsRef<Path>, capacity: usize) -> Ledgered<Self> {
        if capacity == 0 || capacity > MAX_LEDGER_ENTRIES {
            return Err(CancelLedgerError::InvalidField("capacity"));
        }
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
            return Err(CancelLedgerError::Sqlite(rusqlite::Error::InvalidQuery));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        initialize_or_validate_schema(&mut connection)?;

        Ok(Self {
            connection,
            path: path.to_path_buf(),
            capacity,
        })
    }

    /// Exact path opened by this ledger.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Live-entry capacity of this handle.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Record one cancellation request.
    ///
    /// One immediate transaction: after a crash a reader sees the whole entry
    /// or no entry, never half of one.
    ///
    /// Lookup precedes the capacity check, so an exact replay is still answered
    /// [`CancelDisposition::AlreadyDelivered`] in a full ledger — a replay
    /// writes nothing and must never degrade into a refusal. A conflicting
    /// reuse is likewise a [`CancelLedgerError::Conflict`] rather than
    /// [`CancelLedgerError::LedgerFull`], because the reuse is a client bug
    /// regardless of how full the ledger is.
    pub fn record(&mut self, request: CancelRequest<'_>) -> Ledgered<CancelReceipt> {
        validate_request(&request)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut live = count_entries(&transaction)?;
        let receipt = record_row(&transaction, &request, self.capacity, &mut live)?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Record a batch of cancellation requests atomically.
    ///
    /// Every request commits together. A refusal anywhere — a malformed field,
    /// a conflicting reference, the capacity boundary reached part-way —
    /// discards the whole batch, so the earlier rows of a refused batch are
    /// absent afterwards rather than half-applied.
    ///
    /// Within a batch, a repeated reference sees the row the batch itself just
    /// inserted: an exact repeat is [`CancelDisposition::AlreadyDelivered`] and
    /// an altered repeat conflicts, exactly as it would across two calls.
    pub fn record_all(&mut self, requests: &[CancelRequest<'_>]) -> Ledgered<Vec<CancelReceipt>> {
        if requests.len() > MAX_BATCH_REQUESTS {
            return Err(CancelLedgerError::InvalidField("batch_length"));
        }
        for request in requests {
            validate_request(request)?;
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut live = count_entries(&transaction)?;
        let mut receipts = Vec::with_capacity(requests.len());
        for request in requests {
            receipts.push(record_row(&transaction, request, self.capacity, &mut live)?);
        }
        transaction.commit()?;
        Ok(receipts)
    }

    /// Read the validated entry one reference binds, if any.
    pub fn entry(&self, request_ref: &str) -> Ledgered<Option<CancelEntry>> {
        validate_identifier(request_ref, "request_ref")?;
        read_entry_by_ref(&self.connection, request_ref)
    }

    /// List every cancellation request recorded against one attempt.
    ///
    /// This is the recovery view: a supervisor that restarted asks which
    /// references it has already answered for an attempt, oldest first. An
    /// empty answer means nothing was recorded — never that nothing was asked.
    pub fn attempt_requests(&self, attempt_id: &str) -> Ledgered<Vec<CancelEntry>> {
        validate_identifier(attempt_id, "attempt_id")?;
        read_attempt_entries(&self.connection, attempt_id)
    }

    /// Count live entries.
    pub fn entry_count(&self) -> Ledgered<usize> {
        count_entries(&self.connection)
    }

    /// Delete entries that are both old enough and belong to terminal attempts.
    ///
    /// This is the only deletion in this module, and it costs exactly one
    /// thing, stated here rather than buried: **a pruned reference is
    /// forgotten.** If the same `request_ref` is presented again after its
    /// entry is pruned, the ledger has no memory of it and answers
    /// [`CancelDisposition::Delivered`] a second time. Idempotency therefore
    /// holds for as long as an entry is live and no longer. A caller that
    /// prunes an attempt must not replay references that belonged to it; that
    /// is what declaring the attempt terminal is meant to promise.
    ///
    /// Both conditions are required: an entry of a live attempt survives no
    /// matter how old, and a recent entry of a terminal attempt survives until
    /// the horizon passes it. The whole prune is one transaction.
    ///
    /// The removed references are not returned. A caller that needs them must
    /// read [`CancelLedger::attempt_requests`] before pruning; returning them
    /// would make the answer grow with the ledger.
    pub fn prune(&mut self, retention: Retention<'_>) -> Ledgered<PruneOutcome> {
        validate_time(retention.older_than_ms, "older_than_ms")?;
        if retention.terminal_attempts.len() > MAX_TERMINAL_ATTEMPTS {
            return Err(CancelLedgerError::InvalidField("terminal_attempts"));
        }
        for attempt_id in retention.terminal_attempts {
            validate_identifier(attempt_id, "attempt_id")?;
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut removed = 0usize;
        for attempt_id in retention.terminal_attempts {
            let deleted = transaction.execute(
                "DELETE FROM cancel_requests
                 WHERE attempt_id = ?1 AND requested_at_ms < ?2",
                params![attempt_id, retention.older_than_ms],
            )?;
            removed = removed
                .checked_add(deleted)
                .ok_or(CancelLedgerError::InvalidField("terminal_attempts"))?;
        }
        let remaining = count_entries(&transaction)?;
        transaction.commit()?;
        Ok(PruneOutcome { removed, remaining })
    }
}

/// Record one request inside an open transaction.
///
/// `live` is the entry count as of the start of the transaction, advanced here
/// for every row this transaction inserts. The transaction is immediate, so no
/// other writer can move the count underneath it.
fn record_row(
    transaction: &Transaction<'_>,
    request: &CancelRequest<'_>,
    capacity: usize,
    live: &mut usize,
) -> Ledgered<CancelReceipt> {
    if let Some(recorded) = read_entry_by_ref(transaction, request.request_ref)? {
        if recorded.attempt_id != request.attempt_id {
            return Err(CancelLedgerError::Conflict {
                field: "attempt_id",
                recorded_attempt_id: recorded.attempt_id,
                recorded_observed_sequence: recorded.observed_sequence,
            });
        }
        if recorded.observed_sequence != request.observed_sequence {
            return Err(CancelLedgerError::Conflict {
                field: "observed_sequence",
                recorded_attempt_id: recorded.attempt_id,
                recorded_observed_sequence: recorded.observed_sequence,
            });
        }
        // Exact replay. `requested_at_ms` stays at the first delivery's value.
        return Ok(CancelReceipt {
            entry_id: recorded.entry_id,
            disposition: CancelDisposition::AlreadyDelivered,
        });
    }
    if *live >= capacity {
        return Err(CancelLedgerError::LedgerFull { capacity });
    }
    transaction.execute(
        "INSERT INTO cancel_requests
         (request_ref, attempt_id, observed_sequence, requested_at_ms)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            request.request_ref,
            request.attempt_id,
            to_db_u64(request.observed_sequence, "observed_sequence")?,
            request.requested_at_ms
        ],
    )?;
    *live = live
        .checked_add(1)
        .ok_or(CancelLedgerError::InvalidField("batch_length"))?;
    Ok(CancelReceipt {
        entry_id: transaction.last_insert_rowid(),
        disposition: CancelDisposition::Delivered,
    })
}

struct RawEntry {
    entry_id: i64,
    request_ref: String,
    attempt_id: String,
    observed_sequence: i64,
    requested_at_ms: i64,
}

const ENTRY_COLUMNS: &str = "entry_id, request_ref, attempt_id, observed_sequence, requested_at_ms";

fn raw_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawEntry> {
    Ok(RawEntry {
        entry_id: row.get(0)?,
        request_ref: row.get(1)?,
        attempt_id: row.get(2)?,
        observed_sequence: row.get(3)?,
        requested_at_ms: row.get(4)?,
    })
}

fn validated_entry(raw: RawEntry) -> Ledgered<CancelEntry> {
    Ok(CancelEntry {
        entry_id: checked_row_id(raw.entry_id, "entry_id")?,
        request_ref: checked_identifier(raw.request_ref, "request_ref")?,
        attempt_id: checked_identifier(raw.attempt_id, "attempt_id")?,
        observed_sequence: from_db_u64(raw.observed_sequence, "observed_sequence")
            .map_err(|_| corrupt_field("observed_sequence"))?,
        requested_at_ms: checked_time(raw.requested_at_ms, "requested_at_ms")?,
    })
}

fn read_entry_by_ref(connection: &Connection, request_ref: &str) -> Ledgered<Option<CancelEntry>> {
    let raw = connection
        .query_row(
            &format!("SELECT {ENTRY_COLUMNS} FROM cancel_requests WHERE request_ref = ?1"),
            [request_ref],
            raw_entry,
        )
        .optional()?;
    raw.map(validated_entry).transpose()
}

fn read_attempt_entries(connection: &Connection, attempt_id: &str) -> Ledgered<Vec<CancelEntry>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {ENTRY_COLUMNS} FROM cancel_requests
         WHERE attempt_id = ?1 ORDER BY entry_id"
    ))?;
    let rows = statement.query_map([attempt_id], raw_entry)?;
    let mut entries = Vec::new();
    for raw in rows {
        entries.push(validated_entry(raw?)?);
    }
    Ok(entries)
}

fn count_entries(connection: &Connection) -> Ledgered<usize> {
    let count: i64 =
        connection.query_row("SELECT count(*) FROM cancel_requests", [], |row| row.get(0))?;
    usize::try_from(count).map_err(|_| corrupt_field("entry_count"))
}

fn secure_path(path: &Path) -> Ledgered<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => CancelLedgerError::Io(io),
        other => CancelLedgerError::InsecurePath(other.to_string()),
    })
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Ledgered<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == CANCEL_LEDGER_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(CancelLedgerError::SchemaVersion {
            found: version,
            supported: CANCEL_LEDGER_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(CancelLedgerError::SchemaVersion {
            found: 0,
            supported: CANCEL_LEDGER_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", CANCEL_LEDGER_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn validate_request(request: &CancelRequest<'_>) -> Ledgered<()> {
    validate_identifier(request.request_ref, "request_ref")?;
    validate_identifier(request.attempt_id, "attempt_id")?;
    validate_time(request.requested_at_ms, "requested_at_ms")?;
    to_db_u64(request.observed_sequence, "observed_sequence").map(|_| ())
}

fn validate_identifier(value: &str, field: &'static str) -> Ledgered<()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(CancelLedgerError::InvalidField(field));
    }
    Ok(())
}

fn validate_time(value: i64, field: &'static str) -> Ledgered<()> {
    if value < 0 {
        return Err(CancelLedgerError::InvalidField(field));
    }
    Ok(())
}

fn validate_row_id(value: i64, field: &'static str) -> Ledgered<()> {
    if value <= 0 {
        return Err(CancelLedgerError::InvalidField(field));
    }
    Ok(())
}

fn checked_identifier(value: String, field: &'static str) -> Ledgered<String> {
    validate_identifier(&value, field).map_err(|_| corrupt_field(field))?;
    Ok(value)
}

fn checked_time(value: i64, field: &'static str) -> Ledgered<i64> {
    validate_time(value, field).map_err(|_| corrupt_field(field))?;
    Ok(value)
}

fn checked_row_id(value: i64, field: &'static str) -> Ledgered<i64> {
    validate_row_id(value, field).map_err(|_| corrupt_field(field))?;
    Ok(value)
}

/// Map a validation field onto its stable corruption invariant name.
///
/// Read paths never reuse `InvalidField`: a bad stored row is corruption the
/// caller cannot have caused, and the two must not be confused.
fn corrupt_field(field: &'static str) -> CancelLedgerError {
    CancelLedgerError::Corrupt(field)
}

fn to_db_u64(value: u64, field: &'static str) -> Ledgered<i64> {
    i64::try_from(value).map_err(|_| CancelLedgerError::InvalidField(field))
}

fn from_db_u64(value: i64, field: &'static str) -> Ledgered<u64> {
    u64::try_from(value).map_err(|_| CancelLedgerError::InvalidField(field))
}
