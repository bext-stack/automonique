// SPDX-License-Identifier: Elastic-2.0

//! Durable custody of submitted canonical run specification documents.
//!
//! A local administrator submits one canonical RunSpec document under a
//! caller-chosen `idempotency_key`. The endpoint must answer a retry the same
//! way it answered the original — a submitter that loses the answer retries,
//! and a second acceptance of the same key would be a second custody record for
//! one intent. This module is that durable half. It records exactly the binding
//!
//! ```text
//! idempotency_key -> (run_id, spec_digest, document, accepted_at_ms)
//! ```
//!
//! and answers three ways and only three ways:
//!
//! - the key is new: the row is written, [`RunSubmissionDisposition::Accepted`];
//! - the key is present with the *same* run, digest and document bytes: it is an
//!   exact replay, [`RunSubmissionDisposition::AlreadyAccepted`], and not one
//!   byte of the durable row changes;
//! - the key is present with a different run, digest or document:
//!   [`RunSubmissionError::Conflict`], and nothing is written. A retry must not
//!   rewrite what was accepted.
//!
//! There is no execution here, and no clock: callers supply every identifier,
//! digest and timestamp, so retries stay deterministic and tests do not depend
//! on an ambient clock.
//!
//! # Custody, and the document itself
//!
//! Unlike [`crate::provider_journal`] and [`crate::slack_ingress`], which record
//! a digest and never the bytes, **this table is the document.** It holds the
//! canonical bytes verbatim, because a custody record that cannot reproduce
//! what was accepted is not custody. The digest beside them is the name the
//! caller declared; this module computes no hash and therefore cannot check
//! that the name fits the bytes. What it can promise is that both were written
//! in one transaction and neither is ever rewritten, so a reader that recomputes
//! SHA-256 over `document` can check the binding this module recorded — which is
//! exactly the check the daemon performs before it ever calls
//! [`RunSubmissionLog::record`].
//!
//! # What a row does not establish
//!
//! - **A row is not execution authority.** [`RunSubmissionState`] has one
//!   variant, `accepted`, and this release defines no other. There is no
//!   `executing` and no `completed` spelling here, because nothing in this
//!   product can yet reach those states: adding the words before the behaviour
//!   would be a durable lie in the schema. Accepting a document establishes
//!   custody of it and nothing else — no admission decision, no launch, no
//!   sandbox, no scheduler reservation.
//! - **A row does not establish that the document is a valid RunSpec.** This
//!   crate has no decoder and does not parse the bytes. A caller that records
//!   an unvalidated document gets a durable unvalidated document.
//! - **`accepted_at_ms` is the caller's clock**, recorded at the *first*
//!   acceptance. A replay carries a later clock and never rewrites it, so the
//!   column states when custody began, not when it was last confirmed.
//!
//! # Storage discipline, and what a separate database costs
//!
//! The log owns its own SQLite database with its own `user_version`, opened
//! under the same privacy, WAL and `synchronous = FULL` rules as
//! [`crate::Store`], exactly as [`crate::cancel_ledger`] and
//! [`crate::slack_ingress`] do. Recording one submission is one immediate
//! transaction, so a reader after a crash sees the whole row or no row. Every
//! read re-validates the row it loaded rather than trusting the database.
//!
//! That separation has a cost, stated here rather than buried: **a caller's
//! generation fence lives in another database, and there is no transaction
//! spanning the two.** A daemon that checks it still holds its lease and then
//! records here can lose that lease in between and still write the row. This
//! module accepts that race rather than pretending to close it, on one specific
//! ground: a custody row claims no exclusive resource and schedules no work, so
//! a row written by a generation that has just been fenced out costs a
//! superseded record, not a double execution. A lane that ever *does* execute
//! from these rows must not inherit that reasoning.
//!
//! # Deletion
//!
//! There is none. This module has no prune and no delete: forgetting a key
//! would answer a later retry of it as a fresh acceptance, and forgetting a
//! document would destroy the only copy of what was accepted. Capacity is a
//! refusal ([`RunSubmissionError::LogFull`]), never an eviction.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::{BUSY_TIMEOUT, StoreError, validate_database_path};

/// The only run submission schema this build can read and write.
pub const RUN_SUBMISSIONS_SCHEMA_VERSION: u32 = 1;

/// Largest number of submissions any log will hold.
///
/// Nothing deletes from this table, so this is a hard ceiling on the lifetime
/// of one database file rather than a high-water mark.
pub const MAX_RUN_SUBMISSIONS: usize = 65_536;

/// Longest accepted `idempotency_key` or `run_id`, in bytes.
///
/// The same identifier grammar [`crate::Store`] uses: non-empty, at most this
/// many bytes, no control characters.
pub const MAX_IDENTIFIER_BYTES: usize = 256;

/// Longest accepted canonical document, in bytes.
///
/// This is the store's own bound, deliberately not a mirror of any caller's.
/// The admin lane admits a far smaller document — its hex encoding has to fit
/// one 64 KiB administration frame — so this ceiling is not the operative one
/// for that submitter. It exists so custody never depends on a caller having
/// bounded its input first.
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// Exact length of a `spec_digest`: SHA-256 as 64 lowercase hexadecimal digits.
///
/// The algorithm is named by this documentation and by the column's grammar
/// rather than by a prefix in the value, so the stored column is fixed-width.
pub const SPEC_DIGEST_HEX_BYTES: usize = 64;

/// Schema v1.
///
/// Uniqueness of `idempotency_key`, the digest width, the non-empty document
/// and the closed `state` vocabulary are database constraints, so a second
/// writer cannot introduce a duplicate binding or a state this build does not
/// define. The identifier grammar, the digest's lowercase-hex spelling and the
/// document ceiling are deliberately *not* database constraints: they are
/// enforced on write and re-checked on every read, so a row written around this
/// API is refused rather than believed.
const SCHEMA_V1: &str = r#"
CREATE TABLE run_submissions (
    submission_id INTEGER PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL,
    spec_digest TEXT NOT NULL CHECK (length(spec_digest) = 64),
    document BLOB NOT NULL CHECK (length(document) > 0),
    accepted_at_ms INTEGER NOT NULL CHECK (accepted_at_ms >= 0),
    state TEXT NOT NULL CHECK (state IN ('accepted'))
) STRICT;

CREATE INDEX run_submissions_by_run
    ON run_submissions(run_id, submission_id);
"#;

/// A run submission error with stable refusal categories.
#[derive(Debug)]
pub enum RunSubmissionError {
    /// The log path or its containing directory is not private and owned.
    InsecurePath(String),
    /// The schema is absent from a non-empty database, or unsupported.
    SchemaVersion {
        /// Version found in the database.
        found: u32,
        /// Version this build implements.
        supported: u32,
    },
    /// A caller-provided field is empty, over-long, malformed, or out of range.
    InvalidField(&'static str),
    /// A recorded key was presented with a different submission.
    ///
    /// Nothing was written. The recorded coordinates are reported so a caller
    /// can tell a stale retry from a reused key without a second read. The
    /// recorded *document* is deliberately not reported: a refusal must not
    /// hand back bytes the retrying caller did not already have.
    Conflict {
        /// First bound coordinate that differs: `run_id`, `spec_digest` or
        /// `document`.
        field: &'static str,
        /// Row the key already binds.
        recorded_submission_id: i64,
        /// Digest the durable row binds.
        recorded_spec_digest: String,
    },
    /// The log holds its full capacity of submissions.
    ///
    /// Acceptance is refused *before* a row is written. Nothing here evicts.
    LogFull {
        /// Capacity of the handle that refused.
        capacity: usize,
    },
    /// A stored row violates an invariant this API can only have written once.
    Corrupt(&'static str),
    /// Filesystem failure while establishing the private log.
    Io(std::io::Error),
    /// SQLite rejected an operation.
    Sqlite(rusqlite::Error),
}

impl RunSubmissionError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::Conflict { .. } => "conflict",
            Self::LogFull { .. } => "log_full",
            Self::Corrupt(_) => "corrupt",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}

impl fmt::Display for RunSubmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => {
                write!(formatter, "submission log path is not private: {reason}")
            }
            Self::SchemaVersion { found, supported } => write!(
                formatter,
                "run submission schema {found} is unsupported; expected {supported}"
            ),
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::Conflict {
                field,
                recorded_submission_id,
                recorded_spec_digest,
            } => write!(
                formatter,
                "idempotency_key is already bound to submission {recorded_submission_id} \
                 at digest {recorded_spec_digest}; {field} differs"
            ),
            Self::LogFull { capacity } => {
                write!(
                    formatter,
                    "run submission log holds its capacity of {capacity}"
                )
            }
            Self::Corrupt(invariant) => {
                write!(formatter, "stored row violates invariant: {invariant}")
            }
            Self::Io(error) => write!(formatter, "submission log filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite error: {error}"),
        }
    }
}

impl Error for RunSubmissionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for RunSubmissionError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for RunSubmissionError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// Result of one submission-log operation.
pub type Submitted<T> = Result<T, RunSubmissionError>;

/// The durable state of one submission.
///
/// One variant, on purpose. This release accepts documents and does nothing
/// else with them, so `accepted` is the whole vocabulary; a lane that executes
/// a submitted run will have to add both a spelling and the behaviour that
/// earns it, in the same change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunSubmissionState {
    /// The document is durably held. Nothing has run.
    Accepted,
}

impl RunSubmissionState {
    /// Stable machine-oriented spelling, and the only value the column admits.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
        }
    }

    /// Map a stored spelling onto a state this build defines.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        match value {
            "accepted" => Some(Self::Accepted),
            _ => None,
        }
    }
}

/// One canonical document presented for durable custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunSubmission<'a> {
    /// Bounded key chosen by the submitter. The unique key.
    pub idempotency_key: &'a str,
    /// Run identity the submitter read out of the document.
    ///
    /// This module does not parse the document and cannot confirm the two
    /// agree; it records the claim.
    pub run_id: &'a str,
    /// SHA-256 of `document` as 64 lowercase hexadecimal digits, as declared by
    /// the caller.
    pub spec_digest: &'a str,
    /// The canonical document bytes, stored verbatim.
    pub document: &'a [u8],
    /// When the submitter accepted it, in caller-supplied milliseconds.
    ///
    /// Not part of the binding: a retry naturally carries a later clock, so a
    /// differing timestamp is an exact replay, not a conflict.
    pub accepted_at_ms: i64,
}

/// How the log answered one submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunSubmissionDisposition {
    /// The submission was new and is now durable.
    Accepted,
    /// The exact submission was already durable. Nothing changed.
    AlreadyAccepted,
}

impl RunSubmissionDisposition {
    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::AlreadyAccepted => "already_accepted",
        }
    }

    /// Whether this answer replayed an existing row rather than writing one.
    #[must_use]
    pub const fn is_replay(self) -> bool {
        matches!(self, Self::AlreadyAccepted)
    }
}

/// Durable identity of one accepted or replayed submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunSubmissionReceipt {
    /// Row identity of the durable submission.
    pub submission_id: i64,
    /// Whether this call wrote the row or replayed it.
    pub disposition: RunSubmissionDisposition,
}

/// Validated `run_submissions` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunSubmissionEntry {
    /// Row identity, monotonic in acceptance order.
    pub submission_id: i64,
    /// The unique key this row is bound to.
    pub idempotency_key: String,
    /// Run identity the first acceptance claimed.
    pub run_id: String,
    /// Digest the first acceptance declared, as 64 lowercase hex digits.
    pub spec_digest: String,
    /// The canonical document bytes, exactly as accepted.
    pub document: Vec<u8>,
    /// When the *first* acceptance of this key was recorded.
    pub accepted_at_ms: i64,
    /// Durable state. Always [`RunSubmissionState::Accepted`] in this release.
    pub state: RunSubmissionState,
}

/// Durable log of accepted run specification documents.
#[derive(Debug)]
pub struct RunSubmissionLog {
    connection: Connection,
    path: PathBuf,
    capacity: usize,
}

impl RunSubmissionLog {
    /// Open or initialize a log inside an existing private directory.
    ///
    /// The parent must be owned by the effective user and deny all group and
    /// other access. Existing paths must be regular, owned, non-symlinks.
    /// Capacity is [`MAX_RUN_SUBMISSIONS`].
    ///
    /// # Errors
    ///
    /// Returns [`RunSubmissionError::InsecurePath`] for an unsafe path,
    /// [`RunSubmissionError::SchemaVersion`] for a foreign or future database,
    /// and the underlying I/O or SQLite failure otherwise.
    pub fn open(path: impl AsRef<Path>) -> Submitted<Self> {
        Self::open_with_capacity(path, MAX_RUN_SUBMISSIONS)
    }

    /// Open a log with a lowered capacity.
    ///
    /// `capacity` must be between one and [`MAX_RUN_SUBMISSIONS`]. It is a
    /// property of this handle, not of the database: opening an existing log
    /// under a capacity below its row count refuses further acceptances with
    /// [`RunSubmissionError::LogFull`] while exact replays and reads keep
    /// working, because a replay writes nothing.
    ///
    /// # Errors
    ///
    /// As [`RunSubmissionLog::open`], plus
    /// [`RunSubmissionError::InvalidField`] for a capacity outside the range.
    pub fn open_with_capacity(path: impl AsRef<Path>, capacity: usize) -> Submitted<Self> {
        if capacity == 0 || capacity > MAX_RUN_SUBMISSIONS {
            return Err(RunSubmissionError::InvalidField("capacity"));
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
            return Err(RunSubmissionError::Sqlite(rusqlite::Error::InvalidQuery));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        initialize_or_validate_schema(&mut connection)?;

        Ok(Self {
            connection,
            path: path.to_path_buf(),
            capacity,
        })
    }

    /// Exact path opened by this log.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Submission capacity of this handle.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Take durable custody of one document, or replay an exact resubmission.
    ///
    /// One immediate transaction: after a crash a reader sees the whole row or
    /// no row, never a document without its digest.
    ///
    /// Lookup precedes the capacity check, so an exact replay is still answered
    /// [`RunSubmissionDisposition::AlreadyAccepted`] in a full log — a replay
    /// writes nothing and must never degrade into a refusal. A conflicting
    /// reuse is likewise a [`RunSubmissionError::Conflict`] rather than
    /// [`RunSubmissionError::LogFull`], because the reuse is a submitter bug
    /// regardless of how full the log is.
    ///
    /// # Errors
    ///
    /// Returns [`RunSubmissionError::InvalidField`] for a malformed field,
    /// [`RunSubmissionError::Conflict`] for a reused key,
    /// [`RunSubmissionError::LogFull`] at capacity, and
    /// [`RunSubmissionError::Corrupt`] when the existing row it must compare
    /// against is not one this API could have written.
    pub fn record(&mut self, submission: RunSubmission<'_>) -> Submitted<RunSubmissionReceipt> {
        validate_submission(&submission)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut live = count_submissions(&transaction)?;
        let receipt = record_row(&transaction, &submission, self.capacity, &mut live)?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Read the validated row one key binds, if any.
    ///
    /// # Errors
    ///
    /// Returns [`RunSubmissionError::InvalidField`] for a malformed key and
    /// [`RunSubmissionError::Corrupt`] when the stored row is not one this API
    /// could have written.
    pub fn submission(&self, idempotency_key: &str) -> Submitted<Option<RunSubmissionEntry>> {
        validate_identifier(idempotency_key, "idempotency_key")?;
        read_by_key(&self.connection, idempotency_key)
    }

    /// List every submission recorded against one run identity, oldest first.
    ///
    /// This is the custody view: an operator asks which documents were accepted
    /// for a run. An empty answer means nothing was accepted — never that
    /// nothing was submitted.
    ///
    /// # Errors
    ///
    /// As [`RunSubmissionLog::submission`].
    pub fn run_submissions(&self, run_id: &str) -> Submitted<Vec<RunSubmissionEntry>> {
        validate_identifier(run_id, "run_id")?;
        read_by_run(&self.connection, run_id)
    }

    /// Count durable submissions.
    ///
    /// # Errors
    ///
    /// Returns the SQLite failure, or [`RunSubmissionError::Corrupt`] for a
    /// count outside the representable range.
    pub fn submission_count(&self) -> Submitted<usize> {
        count_submissions(&self.connection)
    }
}

/// Record one submission inside an open transaction.
///
/// `live` is the row count as of the start of the transaction, advanced for
/// every row this transaction inserts. The transaction is immediate, so no
/// other writer can move the count underneath it.
fn record_row(
    transaction: &Transaction<'_>,
    submission: &RunSubmission<'_>,
    capacity: usize,
    live: &mut usize,
) -> Submitted<RunSubmissionReceipt> {
    if let Some(recorded) = read_by_key(transaction, submission.idempotency_key)? {
        // The binding is compared field by field, and the first difference is
        // named. Comparing the document as well as its digest costs one memcmp
        // and means a caller that declares a stale digest for fresh bytes is
        // told so rather than silently replaying the old custody row.
        let conflict = |field: &'static str| RunSubmissionError::Conflict {
            field,
            recorded_submission_id: recorded.submission_id,
            recorded_spec_digest: recorded.spec_digest.clone(),
        };
        if recorded.run_id != submission.run_id {
            return Err(conflict("run_id"));
        }
        if recorded.spec_digest != submission.spec_digest {
            return Err(conflict("spec_digest"));
        }
        if recorded.document != submission.document {
            return Err(conflict("document"));
        }
        // Exact replay. `accepted_at_ms` stays at the first acceptance's value.
        return Ok(RunSubmissionReceipt {
            submission_id: recorded.submission_id,
            disposition: RunSubmissionDisposition::AlreadyAccepted,
        });
    }
    if *live >= capacity {
        return Err(RunSubmissionError::LogFull { capacity });
    }
    transaction.execute(
        "INSERT INTO run_submissions
         (idempotency_key, run_id, spec_digest, document, accepted_at_ms, state)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            submission.idempotency_key,
            submission.run_id,
            submission.spec_digest,
            submission.document,
            submission.accepted_at_ms,
            RunSubmissionState::Accepted.as_str(),
        ],
    )?;
    *live = live
        .checked_add(1)
        .ok_or(RunSubmissionError::InvalidField("submission_count"))?;
    Ok(RunSubmissionReceipt {
        submission_id: transaction.last_insert_rowid(),
        disposition: RunSubmissionDisposition::Accepted,
    })
}

struct RawEntry {
    submission_id: i64,
    idempotency_key: String,
    run_id: String,
    spec_digest: String,
    document: Vec<u8>,
    accepted_at_ms: i64,
    state: String,
}

const ENTRY_COLUMNS: &str =
    "submission_id, idempotency_key, run_id, spec_digest, document, accepted_at_ms, state";

fn raw_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawEntry> {
    Ok(RawEntry {
        submission_id: row.get(0)?,
        idempotency_key: row.get(1)?,
        run_id: row.get(2)?,
        spec_digest: row.get(3)?,
        document: row.get(4)?,
        accepted_at_ms: row.get(5)?,
        state: row.get(6)?,
    })
}

/// Re-validate a loaded row against every rule the write path enforced.
///
/// A row that fails here was written around this API. It is corruption the
/// caller cannot have caused, and it is never reported as an invalid argument.
fn validated_entry(raw: RawEntry) -> Submitted<RunSubmissionEntry> {
    if raw.submission_id <= 0 {
        return Err(RunSubmissionError::Corrupt("submission_id"));
    }
    validate_identifier(&raw.idempotency_key, "idempotency_key")
        .map_err(|_| RunSubmissionError::Corrupt("idempotency_key"))?;
    validate_identifier(&raw.run_id, "run_id")
        .map_err(|_| RunSubmissionError::Corrupt("run_id"))?;
    validate_digest(&raw.spec_digest).map_err(|_| RunSubmissionError::Corrupt("spec_digest"))?;
    validate_document(&raw.document).map_err(|_| RunSubmissionError::Corrupt("document"))?;
    if raw.accepted_at_ms < 0 {
        return Err(RunSubmissionError::Corrupt("accepted_at_ms"));
    }
    Ok(RunSubmissionEntry {
        submission_id: raw.submission_id,
        idempotency_key: raw.idempotency_key,
        run_id: raw.run_id,
        spec_digest: raw.spec_digest,
        document: raw.document,
        accepted_at_ms: raw.accepted_at_ms,
        state: RunSubmissionState::from_spelling(&raw.state)
            .ok_or(RunSubmissionError::Corrupt("state"))?,
    })
}

fn read_by_key(
    connection: &Connection,
    idempotency_key: &str,
) -> Submitted<Option<RunSubmissionEntry>> {
    let raw = connection
        .query_row(
            &format!("SELECT {ENTRY_COLUMNS} FROM run_submissions WHERE idempotency_key = ?1"),
            [idempotency_key],
            raw_entry,
        )
        .optional()?;
    raw.map(validated_entry).transpose()
}

fn read_by_run(connection: &Connection, run_id: &str) -> Submitted<Vec<RunSubmissionEntry>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {ENTRY_COLUMNS} FROM run_submissions
         WHERE run_id = ?1 ORDER BY submission_id"
    ))?;
    let rows = statement.query_map([run_id], raw_entry)?;
    let mut entries = Vec::new();
    for raw in rows {
        entries.push(validated_entry(raw?)?);
    }
    Ok(entries)
}

fn count_submissions(connection: &Connection) -> Submitted<usize> {
    let count: i64 =
        connection.query_row("SELECT count(*) FROM run_submissions", [], |row| row.get(0))?;
    usize::try_from(count).map_err(|_| RunSubmissionError::Corrupt("submission_count"))
}

fn secure_path(path: &Path) -> Submitted<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => RunSubmissionError::Io(io),
        other => RunSubmissionError::InsecurePath(other.to_string()),
    })
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Submitted<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == RUN_SUBMISSIONS_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(RunSubmissionError::SchemaVersion {
            found: version,
            supported: RUN_SUBMISSIONS_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(RunSubmissionError::SchemaVersion {
            found: 0,
            supported: RUN_SUBMISSIONS_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", RUN_SUBMISSIONS_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn validate_submission(submission: &RunSubmission<'_>) -> Submitted<()> {
    validate_identifier(submission.idempotency_key, "idempotency_key")?;
    validate_identifier(submission.run_id, "run_id")?;
    validate_digest(submission.spec_digest)?;
    validate_document(submission.document)?;
    if submission.accepted_at_ms < 0 {
        return Err(RunSubmissionError::InvalidField("accepted_at_ms"));
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Submitted<()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(RunSubmissionError::InvalidField(field));
    }
    Ok(())
}

/// Exactly 64 lowercase hexadecimal digits.
///
/// Uppercase is refused rather than folded, so one digest has exactly one
/// stored spelling and a byte comparison of two rows means what it looks like.
fn validate_digest(value: &str) -> Submitted<()> {
    if value.len() != SPEC_DIGEST_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RunSubmissionError::InvalidField("spec_digest"));
    }
    Ok(())
}

fn validate_document(document: &[u8]) -> Submitted<()> {
    if document.is_empty() || document.len() > MAX_DOCUMENT_BYTES {
        return Err(RunSubmissionError::InvalidField("document"));
    }
    Ok(())
}
