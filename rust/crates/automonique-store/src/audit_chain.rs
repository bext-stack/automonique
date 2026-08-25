// SPDX-License-Identifier: Elastic-2.0

//! Durable append-only audit chain.
//!
//! An audit record says that a named actor, on a named surface, did a named
//! thing to a named subject, and that it came out one of five ways. This module
//! is where those records live. Every record carries the hash of the record
//! before it, so a reader holding only the newest hash can tell whether any
//! earlier record was altered, reordered or removed.
//!
//! The chain is exactly this binding
//!
//! ```text
//! seq -> (record_id, body, prev_hash, record_hash)
//! ```
//!
//! and one append answers three ways and only three ways:
//!
//! - the record is new and links to the current head: it is appended,
//!   [`AuditDisposition::Recorded`];
//! - the record's identifier is already present with the *same* body, hashes
//!   and position: it is an exact replay, [`AuditDisposition::AlreadyRecorded`],
//!   and not one byte of the durable row changes;
//! - the identifier is present with a different body, hash or position:
//!   [`AuditChainError::Conflict`], and nothing is written.
//!
//! A record whose `prev_hash` is not the head's `record_hash` is a fourth
//! answer, [`AuditChainError::ChainBroken`], and it is an error rather than a
//! disposition because it is not a statement about this record at all — it says
//! the caller built against a head that has since moved.
//!
//! There is no hashing here, no canonical JSON, no clock and no identifier
//! minting. Callers supply every one of those, so retries stay deterministic
//! and tests do not depend on an ambient clock.
//!
//! # Why the cryptography is not in this module
//!
//! `record_hash` is SHA-256 over `body`, and `body` is canonical JSON. Both are
//! `automonique_protocol`'s — its `digest` module is a from-scratch FIPS 180-4
//! implementation and its `wire` module is the canonical encoder — and its
//! `audit` module composes them into the typed record this table stores. The
//! library modules of this crate take no protocol dependency, so putting the
//! hashing here would mean a second SHA-256 in the tree with the chain's
//! integrity resting on the two agreeing.
//!
//! So this module holds the durable structure and checks it structurally: that
//! `seq` is contiguous from one, that each `prev_hash` is the previous row's
//! `record_hash`, that the genesis row's `prev_hash` is 64 zeros, and that both
//! hash columns are 64 lowercase hexadecimal digits. **What it cannot check is
//! whether `record_hash` is actually the hash of `body`** — that requires the
//! hash, and it is `automonique_protocol::audit::verify_chain`'s job, reached
//! by `automonique audit verify`. Structure without arithmetic catches a
//! deletion and a reordering; only the verifier catches an edited body. A
//! reader must run both, and the CLI verb does.
//!
//! # Single-writer, and why the head is uncontended
//!
//! One daemon holds the generation lease, so one process appends. That is the
//! same argument the attempt host makes for one cancellation dispatcher per
//! host, and it is what makes the append safe: the head is read and the
//! successor inserted inside one `BEGIN IMMEDIATE` transaction, so even a
//! second writer that ignored the lease cannot interleave — it serializes
//! behind the transaction and then finds its `prev_hash` stale, which is
//! [`AuditChainError::ChainBroken`] rather than a fork.
//!
//! # Write order against the thing being audited
//!
//! An audit record and the event it describes are separate databases and no
//! transaction spans them, exactly the seam [`crate::approval_ledger`]
//! documents against the provider journal. The order this module's callers use
//! is **the event first, the audit record second**, and the reason is which
//! failure it buys:
//!
//! - Event first: a crash in between leaves an event with no audit record. That
//!   is a *detectable gap* — the chain is contiguous by `seq`, so reconciling
//!   events against records finds it, and the missing record can be appended.
//! - Record first: a crash in between leaves an audit record for an event that
//!   never happened. That is a *false claim*, and nothing can detect it, because
//!   a record that says a thing happened is exactly what a record of a thing
//!   that happened looks like.
//!
//! A detectable gap is recoverable and a false claim is not, so the gap is the
//! one to buy. Callers are not free to choose the other order.
//!
//! # What a row does not establish
//!
//! - A row proves a record was **written**, not that its contents are true. An
//!   actor who records a falsehood records it as durably as a truth.
//! - The chain does not detect **truncation from the end**. A holder of the
//!   file can delete a suffix and the remainder verifies, because it is a valid
//!   chain — a shorter one. Only an external witness to the head hash closes
//!   that, and this module does not provide one.
//! - `recorded_at` is the caller's claim about when. It is stored and compared;
//!   it is never checked against a clock.
//! - A row is not authorization and not a decision. Nothing in this product
//!   gates on an audit record.
//!
//! # Deletion
//!
//! Ordinary operation never deletes, and unlike every sibling ledger this
//! module offers no prune. A chain with a hole does not verify, so a pruning
//! path would be a supported way to break the one property the table exists
//! for. A chain that has reached [`MAX_AUDIT_RECORDS`] refuses further appends
//! with [`AuditChainError::ChainFull`] and stays readable and verifiable.
//!
//! # Storage discipline
//!
//! The chain owns its own SQLite database with its own `user_version`, opened
//! under the same privacy, WAL and `synchronous = FULL` rules as
//! [`crate::Store`], exactly as [`crate::cancel_ledger`],
//! [`crate::approval_ledger`] and [`crate::run_index`] do. Appending one record
//! is one immediate transaction, so a reader after a crash sees the whole
//! record or no record. Every read re-validates the row it loaded rather than
//! trusting the database.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::{StoreError, validate_database_path};

/// Schema version this module implements.
pub const AUDIT_CHAIN_SCHEMA_VERSION: u32 = 1;

/// Maximum records one chain holds.
pub const MAX_AUDIT_RECORDS: usize = 1_000_000;

/// Maximum UTF-8 byte length of `record_id`, `recorded_at`, `actor`, `surface`
/// and `subject`.
///
/// Pinned by literal from `automonique_protocol::audit::MAX_AUDIT_FIELD_BYTES`,
/// which is the bound the records are built under. This crate's library modules
/// name protocol constants rather than importing them; a value written around
/// that API is refused here rather than believed.
pub const MAX_IDENTIFIER_BYTES: usize = 256;

/// Hexadecimal digits in one chain hash.
///
/// Pinned by literal from `automonique_protocol::audit::HASH_HEX_BYTES`.
pub const CHAIN_HASH_HEX_BYTES: usize = 64;

/// The `prev_hash` of the first record in a chain.
///
/// Pinned by literal from `automonique_protocol::audit::GENESIS_PREV_HASH`.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Maximum records one page returns.
pub const MAX_AUDIT_PAGE: usize = 256;

/// Maximum stored body size.
///
/// A record body is nine fixed keys over bounded fields, so a legal one is well
/// under a kilobyte. The ceiling is here so a row written around this API
/// cannot make a reader allocate without bound.
pub const MAX_BODY_BYTES: usize = 8 * 1024;

/// Schema v1.
///
/// `seq` is the row identity and the chain position at once, which is what lets
/// contiguity be checked by arithmetic rather than by a join. `revision = 1`
/// makes append-only a property of the table: there is no second revision to
/// update a row into, so an `UPDATE` that changes anything else still has to
/// leave `revision` alone and a writer that tries to version a row is refused
/// by the column.
///
/// The two hash columns carry their width and their alphabet as constraints so
/// a second writer cannot introduce a hash that is not one, and `record_hash`
/// is `UNIQUE` because two rows with one hash would make the chain ambiguous.
/// The identifier grammar and the length bounds on the text columns are
/// deliberately *not* database constraints: they are enforced on write and
/// re-checked on every read, so a row written around this API is refused rather
/// than believed.
const SCHEMA_V1: &str = r#"
CREATE TABLE audit_records (
    seq INTEGER PRIMARY KEY CHECK (seq >= 1),
    record_id TEXT NOT NULL UNIQUE,
    recorded_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    surface TEXT NOT NULL,
    category TEXT NOT NULL CHECK (
        category IN ('approval', 'action', 'override', 'cancellation', 'policy', 'escalation')),
    subject TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (
        outcome IN ('success', 'failure', 'timeout', 'denied', 'escalated')),
    body BLOB NOT NULL CHECK (length(body) > 0),
    prev_hash TEXT NOT NULL
        CHECK (length(prev_hash) = 64 AND prev_hash NOT GLOB '*[^0-9a-f]*'),
    record_hash TEXT NOT NULL UNIQUE
        CHECK (length(record_hash) = 64 AND record_hash NOT GLOB '*[^0-9a-f]*'),
    revision INTEGER NOT NULL CHECK (revision = 1)
) STRICT;

CREATE INDEX audit_records_by_subject ON audit_records(subject, seq);
"#;

/// An audit chain error with stable refusal categories.
#[derive(Debug)]
pub enum AuditChainError {
    /// The chain path or its containing directory is not private and owned.
    InsecurePath(String),
    /// The chain schema is absent from a non-empty database or unsupported.
    SchemaVersion {
        /// Version found in the database.
        found: u32,
        /// Version this build implements.
        supported: u32,
    },
    /// A caller-provided field is empty, over-long, malformed, or out of range.
    InvalidField(&'static str),
    /// The presented `prev_hash` is not the chain head's `record_hash`.
    ///
    /// Nothing was written. The caller built against a head that has since
    /// moved, or against no head at all; both recorded coordinates are reported
    /// so it can rebuild without a second read.
    ChainBroken {
        /// `record_hash` of the row this chain actually ends at, or the genesis
        /// value for an empty chain.
        head_hash: String,
        /// `seq` the next record must occupy.
        expected_seq: u64,
        /// The `prev_hash` the caller presented.
        presented_prev_hash: String,
    },
    /// A recorded `record_id` was presented with a different record.
    ///
    /// Nothing was written. Because the identifier is derived from the record's
    /// own hash, this is either a caller that minted an identifier some other
    /// way or a genuine collision, and both are bugs rather than retries.
    Conflict {
        /// First bound coordinate that differs.
        field: &'static str,
        /// Position the durable row occupies.
        recorded_seq: u64,
        /// Hash the durable row carries.
        recorded_record_hash: String,
    },
    /// A page cursor is past the highest retained record.
    CursorOutOfRange {
        /// Cursor the caller supplied.
        supplied: u64,
        /// Highest `seq` this chain retains.
        retained_last: u64,
    },
    /// The chain holds its full capacity of records.
    ///
    /// Appending is refused rather than pruning, because a chain with a hole
    /// does not verify and a prune would be a supported way to break it.
    ChainFull {
        /// Capacity this handle enforces.
        capacity: usize,
    },
    /// A stored row violates an invariant this API can only have written once.
    Corrupt(&'static str),
    /// Filesystem failure while establishing the private chain.
    Io(std::io::Error),
    /// SQLite rejected an operation.
    Sqlite(rusqlite::Error),
}

impl AuditChainError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::ChainBroken { .. } => "chain_broken",
            Self::Conflict { .. } => "conflict",
            Self::CursorOutOfRange { .. } => "cursor_out_of_range",
            Self::ChainFull { .. } => "chain_full",
            Self::Corrupt(_) => "corrupt",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}

impl fmt::Display for AuditChainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => {
                write!(formatter, "audit chain path is not private: {reason}")
            }
            Self::SchemaVersion { found, supported } => write!(
                formatter,
                "audit chain schema {found} is unsupported; expected {supported}"
            ),
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::ChainBroken {
                head_hash,
                expected_seq,
                presented_prev_hash,
            } => write!(
                formatter,
                "audit chain head is {head_hash} at seq {expected_seq}; \
                 prev_hash {presented_prev_hash} does not continue it"
            ),
            Self::Conflict {
                field,
                recorded_seq,
                recorded_record_hash,
            } => write!(
                formatter,
                "record_id is already bound to seq {recorded_seq} \
                 with record_hash {recorded_record_hash}; {field} differs"
            ),
            Self::CursorOutOfRange {
                supplied,
                retained_last,
            } => write!(
                formatter,
                "cursor {supplied} is past the last retained record {retained_last}"
            ),
            Self::ChainFull { capacity } => {
                write!(formatter, "audit chain holds its capacity of {capacity}")
            }
            Self::Corrupt(invariant) => {
                write!(formatter, "stored row violates invariant: {invariant}")
            }
            Self::Io(error) => write!(formatter, "audit chain filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite error: {error}"),
        }
    }
}

impl Error for AuditChainError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for AuditChainError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for AuditChainError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// Result of one chain operation.
pub type Chained<T> = Result<T, AuditChainError>;

/// How the chain answered one append.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditDisposition {
    /// The record was new and is now durable.
    Recorded,
    /// The exact record was already durable. Nothing changed.
    AlreadyRecorded,
}

impl AuditDisposition {
    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::AlreadyRecorded => "already_recorded",
        }
    }
}

impl fmt::Display for AuditDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One record presented for appending.
///
/// The caller has already built the body, hashed it and derived the identifier;
/// this module writes exactly what it is given and checks that it links.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditAppend<'a> {
    /// Identifier derived from `record_hash`. The unique key.
    pub record_id: &'a str,
    /// Caller-supplied RFC 3339 UTC timestamp.
    pub recorded_at: &'a str,
    /// Who did the thing.
    pub actor: &'a str,
    /// Where they did it.
    pub surface: &'a str,
    /// One of the six spellings the column admits.
    pub category: &'a str,
    /// What it was done to.
    pub subject: &'a str,
    /// One of the five spellings the column admits.
    pub outcome: &'a str,
    /// The record's canonical bytes, which `record_hash` is over.
    pub body: &'a [u8],
    /// The head's `record_hash` this record continues, or [`GENESIS_PREV_HASH`].
    pub prev_hash: &'a str,
    /// The record's own hash.
    pub record_hash: &'a str,
}

/// Durable identity of one appended or replayed record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditReceipt {
    /// Position the record occupies.
    pub seq: u64,
    /// How the chain answered.
    pub disposition: AuditDisposition,
}

/// Where a chain currently ends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditHead {
    /// `seq` of the last record.
    pub seq: u64,
    /// `record_hash` of the last record, which the next record's `prev_hash`
    /// must equal.
    pub record_hash: String,
}

/// Validated `audit_records` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEntry {
    /// Position in the chain.
    pub seq: u64,
    /// Derived identifier.
    pub record_id: String,
    /// Caller-supplied RFC 3339 UTC timestamp.
    pub recorded_at: String,
    /// Who did the thing.
    pub actor: String,
    /// Where they did it.
    pub surface: String,
    /// What kind of event it was.
    pub category: String,
    /// What it was done to.
    pub subject: String,
    /// How it came out.
    pub outcome: String,
    /// The record's canonical bytes.
    pub body: Vec<u8>,
    /// Link to the predecessor.
    pub prev_hash: String,
    /// The record's own hash.
    pub record_hash: String,
}

/// One bounded page of records, oldest first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditPage {
    /// The records on this page.
    pub entries: Vec<AuditEntry>,
    /// Cursor for the next page, or `None` when this page is the last.
    pub next_cursor: Option<u64>,
}

/// Durable append-only audit chain.
#[derive(Debug)]
pub struct AuditChain {
    connection: Connection,
    path: PathBuf,
    capacity: usize,
}

impl AuditChain {
    /// Open or initialize a chain inside an existing private directory.
    ///
    /// The parent must be owned by the effective user and deny all group/other
    /// access. Existing chain paths must be regular, owned, non-symlinks.
    /// Capacity is [`MAX_AUDIT_RECORDS`].
    ///
    /// # Errors
    ///
    /// Returns [`AuditChainError::InsecurePath`] for an unsafe path,
    /// [`AuditChainError::SchemaVersion`] for a foreign or future database, and
    /// the underlying I/O or SQLite failure otherwise.
    pub fn open(path: impl AsRef<Path>) -> Chained<Self> {
        Self::open_with_capacity(path, MAX_AUDIT_RECORDS)
    }

    /// Open a chain with a lowered record capacity.
    ///
    /// `capacity` must be between one and [`MAX_AUDIT_RECORDS`]. It is a
    /// property of this handle, not of the database: opening an existing chain
    /// under a capacity below its current length refuses further appends with
    /// [`AuditChainError::ChainFull`] while exact replays and reads keep
    /// working, because a replay writes nothing.
    ///
    /// # Errors
    ///
    /// As [`AuditChain::open`], plus [`AuditChainError::InvalidField`] for a
    /// capacity outside its range.
    pub fn open_with_capacity(path: impl AsRef<Path>, capacity: usize) -> Chained<Self> {
        if capacity == 0 || capacity > MAX_AUDIT_RECORDS {
            return Err(AuditChainError::InvalidField("capacity"));
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
        crate::sqlite_policy::configure_authoritative(&connection)?;
        initialize_or_validate_schema(&mut connection)?;

        Ok(Self {
            connection,
            path: path.to_path_buf(),
            capacity,
        })
    }

    /// Exact path opened by this chain.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record capacity of this handle.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Where the chain currently ends, or `None` for an empty chain.
    ///
    /// A caller builds the next record against this: `seq` is `head.seq + 1`,
    /// or 1, and `prev_hash` is `head.record_hash`, or [`GENESIS_PREV_HASH`].
    /// The value can move between this read and the append that follows it,
    /// which is what [`AuditChainError::ChainBroken`] reports.
    ///
    /// # Errors
    ///
    /// Returns [`AuditChainError::Corrupt`] for a head row this API would not
    /// have written, or the underlying SQLite failure.
    pub fn head(&self) -> Chained<Option<AuditHead>> {
        read_head(&self.connection)
    }

    /// Append one record to the chain.
    ///
    /// One immediate transaction: the head is read and the successor inserted
    /// inside it, so after a crash a reader sees the whole record or no record,
    /// and a second writer cannot slot a record between the two.
    ///
    /// Identifier lookup precedes the link check, so an exact replay is still
    /// answered [`AuditDisposition::AlreadyRecorded`] after the head has moved
    /// past it — a replay writes nothing and must never degrade into a refusal.
    /// It also precedes the capacity check, for the same reason.
    ///
    /// # Errors
    ///
    /// Returns [`AuditChainError::InvalidField`] for a malformed field,
    /// [`AuditChainError::Conflict`] for an identifier already bound to a
    /// different record, [`AuditChainError::ChainBroken`] when `prev_hash` is
    /// not the head's `record_hash`, and [`AuditChainError::ChainFull`] at
    /// capacity.
    pub fn append(&mut self, record: AuditAppend<'_>) -> Chained<AuditReceipt> {
        validate_append(&record)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(durable) = read_entry_by_record_id(&transaction, record.record_id)? {
            let receipt = replay_or_conflict(&durable, &record)?;
            transaction.rollback()?;
            return Ok(receipt);
        }

        let head = read_head(&transaction)?;
        let (expected_seq, head_hash) = head.map_or_else(
            || (1, GENESIS_PREV_HASH.to_owned()),
            |head| (head.seq.saturating_add(1), head.record_hash),
        );
        if record.prev_hash != head_hash {
            return Err(AuditChainError::ChainBroken {
                head_hash,
                expected_seq,
                presented_prev_hash: record.prev_hash.to_owned(),
            });
        }
        let live = count_records(&transaction)?;
        if live >= self.capacity {
            return Err(AuditChainError::ChainFull {
                capacity: self.capacity,
            });
        }
        transaction.execute(
            "INSERT INTO audit_records
             (seq, record_id, recorded_at, actor, surface, category, subject, outcome,
              body, prev_hash, record_hash, revision)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 1)",
            params![
                to_db_u64(expected_seq, "seq")?,
                record.record_id,
                record.recorded_at,
                record.actor,
                record.surface,
                record.category,
                record.subject,
                record.outcome,
                record.body,
                record.prev_hash,
                record.record_hash,
            ],
        )?;
        transaction.commit()?;
        Ok(AuditReceipt {
            seq: expected_seq,
            disposition: AuditDisposition::Recorded,
        })
    }

    /// Read the validated record at one position, if any.
    ///
    /// # Errors
    ///
    /// Returns [`AuditChainError::InvalidField`] for a zero `seq`,
    /// [`AuditChainError::Corrupt`] for a row this API would not have written,
    /// or the underlying SQLite failure.
    pub fn entry(&self, seq: u64) -> Chained<Option<AuditEntry>> {
        if seq == 0 {
            return Err(AuditChainError::InvalidField("seq"));
        }
        read_entry_by_seq(&self.connection, to_db_u64(seq, "seq")?)
    }

    /// Read the validated record one identifier names, if any.
    ///
    /// # Errors
    ///
    /// As [`AuditChain::entry`], with the identifier judged instead of `seq`.
    pub fn record(&self, record_id: &str) -> Chained<Option<AuditEntry>> {
        validate_identifier(record_id, "record_id")?;
        read_entry_by_record_id(&self.connection, record_id)
    }

    /// Read one bounded page of records, oldest first.
    ///
    /// The page is read inside one transaction together with the bound the
    /// cursor is judged against, so a concurrent append cannot make the cursor
    /// look out of range for a page that was about to be served.
    ///
    /// # Errors
    ///
    /// Returns [`AuditChainError::InvalidField`] for a limit outside
    /// 1..=[`MAX_AUDIT_PAGE`], [`AuditChainError::CursorOutOfRange`] for a
    /// cursor past the end, [`AuditChainError::Corrupt`] for a row this API
    /// would not have written, or the underlying SQLite failure.
    pub fn page(&self, cursor: u64, limit: usize) -> Chained<AuditPage> {
        if limit == 0 || limit > MAX_AUDIT_PAGE {
            return Err(AuditChainError::InvalidField("limit"));
        }
        let after = to_db_u64(cursor, "cursor")?;
        let page = i64::try_from(limit).map_err(|_| AuditChainError::InvalidField("limit"))?;
        let lookahead = page
            .checked_add(1)
            .ok_or(AuditChainError::InvalidField("limit"))?;

        let transaction = self.connection.unchecked_transaction()?;
        let highest: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM audit_records",
            [],
            |row| row.get(0),
        )?;
        let retained_last = from_db_u64(highest, "seq").map_err(|_| corrupt("seq"))?;
        if cursor > retained_last {
            return Err(AuditChainError::CursorOutOfRange {
                supplied: cursor,
                retained_last,
            });
        }

        let mut statement = transaction.prepare(&format!(
            "SELECT {ENTRY_COLUMNS} FROM audit_records
             WHERE seq > ?1 ORDER BY seq LIMIT ?2"
        ))?;
        let mut entries = Vec::new();
        {
            let rows = statement.query_map(params![after, lookahead], raw_entry)?;
            for raw in rows {
                entries.push(validated_entry(raw?)?);
            }
        }
        drop(statement);
        transaction.rollback()?;

        let next_cursor = if entries.len() > limit {
            entries.truncate(limit);
            Some(entries.last().ok_or_else(|| corrupt("seq"))?.seq)
        } else {
            None
        };
        Ok(AuditPage {
            entries,
            next_cursor,
        })
    }

    /// How many records the chain holds.
    ///
    /// # Errors
    ///
    /// Returns [`AuditChainError::Corrupt`] for a count outside `usize`, or the
    /// underlying SQLite failure.
    pub fn record_count(&self) -> Chained<usize> {
        count_records(&self.connection)
    }

    /// Check the chain's structure without recomputing a hash.
    ///
    /// Walks every record in `seq` order and verifies that positions are
    /// contiguous from one, that the genesis record's `prev_hash` is
    /// [`GENESIS_PREV_HASH`], and that each later record's `prev_hash` is its
    /// predecessor's `record_hash`. Returns the number of records checked.
    ///
    /// **This is half a verification.** It catches a deleted record, a
    /// reordering and a cut link, because those are structural. It cannot catch
    /// an edited body, because deciding whether `record_hash` is the hash of
    /// `body` requires the hash, and the hash lives in `automonique-protocol`.
    /// `automonique_protocol::audit::verify_chain` is the other half and
    /// `automonique audit verify` runs both. Passing this alone is not evidence
    /// the chain is intact.
    ///
    /// # Errors
    ///
    /// Returns [`AuditChainError::Corrupt`] naming the first structural fault,
    /// or the underlying SQLite failure. The invariant name carries the `seq`
    /// it was found at.
    pub fn verify_structure(&self) -> Chained<u64> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {ENTRY_COLUMNS} FROM audit_records ORDER BY seq"
        ))?;
        let rows = statement.query_map([], raw_entry)?;
        let mut expected_seq = 1_u64;
        let mut expected_prev = GENESIS_PREV_HASH.to_owned();
        let mut checked = 0_u64;
        for raw in rows {
            let entry = validated_entry(raw?)?;
            if entry.seq != expected_seq {
                return Err(corrupt("seq_not_contiguous"));
            }
            if entry.prev_hash != expected_prev {
                return Err(corrupt(if expected_seq == 1 {
                    "genesis_prev_hash"
                } else {
                    "prev_hash_link"
                }));
            }
            expected_prev = entry.record_hash;
            expected_seq = expected_seq.saturating_add(1);
            checked = checked.saturating_add(1);
        }
        Ok(checked)
    }
}

/// Answer an identifier that is already recorded: exact replay, or the first
/// field that differs.
///
/// `seq` and `record_hash` are compared before the body, so the cheap
/// coordinate that identifies the row is named before the expensive one that
/// explains it.
fn replay_or_conflict(durable: &AuditEntry, presented: &AuditAppend<'_>) -> Chained<AuditReceipt> {
    let differing = if durable.record_hash != presented.record_hash {
        Some("record_hash")
    } else if durable.prev_hash != presented.prev_hash {
        Some("prev_hash")
    } else if durable.body != presented.body {
        Some("body")
    } else if durable.recorded_at != presented.recorded_at {
        Some("recorded_at")
    } else if durable.actor != presented.actor {
        Some("actor")
    } else if durable.surface != presented.surface {
        Some("surface")
    } else if durable.category != presented.category {
        Some("category")
    } else if durable.subject != presented.subject {
        Some("subject")
    } else if durable.outcome != presented.outcome {
        Some("outcome")
    } else {
        None
    };
    if let Some(field) = differing {
        return Err(AuditChainError::Conflict {
            field,
            recorded_seq: durable.seq,
            recorded_record_hash: durable.record_hash.clone(),
        });
    }
    Ok(AuditReceipt {
        seq: durable.seq,
        disposition: AuditDisposition::AlreadyRecorded,
    })
}

struct RawEntry {
    seq: i64,
    record_id: String,
    recorded_at: String,
    actor: String,
    surface: String,
    category: String,
    subject: String,
    outcome: String,
    body: Vec<u8>,
    prev_hash: String,
    record_hash: String,
}

const ENTRY_COLUMNS: &str = "seq, record_id, recorded_at, actor, surface, category, \
                             subject, outcome, body, prev_hash, record_hash";

fn raw_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawEntry> {
    Ok(RawEntry {
        seq: row.get(0)?,
        record_id: row.get(1)?,
        recorded_at: row.get(2)?,
        actor: row.get(3)?,
        surface: row.get(4)?,
        category: row.get(5)?,
        subject: row.get(6)?,
        outcome: row.get(7)?,
        body: row.get(8)?,
        prev_hash: row.get(9)?,
        record_hash: row.get(10)?,
    })
}

fn validated_entry(raw: RawEntry) -> Chained<AuditEntry> {
    let seq = from_db_u64(raw.seq, "seq").map_err(|_| corrupt("seq"))?;
    if seq == 0 {
        return Err(corrupt("seq"));
    }
    if raw.body.is_empty() || raw.body.len() > MAX_BODY_BYTES {
        return Err(corrupt("body"));
    }
    Ok(AuditEntry {
        seq,
        record_id: checked_identifier(raw.record_id, "record_id")?,
        recorded_at: checked_identifier(raw.recorded_at, "recorded_at")?,
        actor: checked_identifier(raw.actor, "actor")?,
        surface: checked_identifier(raw.surface, "surface")?,
        category: checked_vocabulary(raw.category, &CATEGORIES, "category")?,
        subject: checked_identifier(raw.subject, "subject")?,
        outcome: checked_vocabulary(raw.outcome, &OUTCOMES, "outcome")?,
        body: raw.body,
        prev_hash: checked_hash(raw.prev_hash, "prev_hash")?,
        record_hash: checked_hash(raw.record_hash, "record_hash")?,
    })
}

fn read_entry_by_seq(connection: &Connection, seq: i64) -> Chained<Option<AuditEntry>> {
    let raw = connection
        .query_row(
            &format!("SELECT {ENTRY_COLUMNS} FROM audit_records WHERE seq = ?1"),
            [seq],
            raw_entry,
        )
        .optional()?;
    raw.map(validated_entry).transpose()
}

fn read_entry_by_record_id(
    connection: &Connection,
    record_id: &str,
) -> Chained<Option<AuditEntry>> {
    let raw = connection
        .query_row(
            &format!("SELECT {ENTRY_COLUMNS} FROM audit_records WHERE record_id = ?1"),
            [record_id],
            raw_entry,
        )
        .optional()?;
    raw.map(validated_entry).transpose()
}

fn read_head(connection: &Connection) -> Chained<Option<AuditHead>> {
    let raw = connection
        .query_row(
            &format!("SELECT {ENTRY_COLUMNS} FROM audit_records ORDER BY seq DESC LIMIT 1"),
            [],
            raw_entry,
        )
        .optional()?;
    raw.map(validated_entry).transpose().map(|entry| {
        entry.map(|entry| AuditHead {
            seq: entry.seq,
            record_hash: entry.record_hash,
        })
    })
}

fn count_records(connection: &Connection) -> Chained<usize> {
    let count: i64 =
        connection.query_row("SELECT count(*) FROM audit_records", [], |row| row.get(0))?;
    usize::try_from(count).map_err(|_| corrupt("record_count"))
}

/// Every category spelling the column admits.
///
/// Pinned by literal from `automonique_protocol::audit::AuditCategory`, and
/// duplicated in `SCHEMA_V1`'s CHECK for the reason every vocabulary in this
/// crate is: the CHECK protects the database from a second writer, and this
/// list protects callers from a row that got in anyway.
const CATEGORIES: [&str; 6] = [
    "approval",
    "action",
    "override",
    "cancellation",
    "policy",
    "escalation",
];

/// Every outcome spelling the column admits.
///
/// Pinned by literal from `automonique_protocol::audit::AuditOutcome`.
const OUTCOMES: [&str; 5] = ["success", "failure", "timeout", "denied", "escalated"];

fn validate_append(record: &AuditAppend<'_>) -> Chained<()> {
    validate_identifier(record.record_id, "record_id")?;
    validate_identifier(record.recorded_at, "recorded_at")?;
    validate_identifier(record.actor, "actor")?;
    validate_identifier(record.surface, "surface")?;
    validate_identifier(record.subject, "subject")?;
    validate_vocabulary(record.category, &CATEGORIES, "category")?;
    validate_vocabulary(record.outcome, &OUTCOMES, "outcome")?;
    validate_hash(record.prev_hash, "prev_hash")?;
    validate_hash(record.record_hash, "record_hash")?;
    if record.body.is_empty() || record.body.len() > MAX_BODY_BYTES {
        return Err(AuditChainError::InvalidField("body"));
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Chained<()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(AuditChainError::InvalidField(field));
    }
    Ok(())
}

/// Exactly 64 lowercase hexadecimal digits.
///
/// Uppercase is refused rather than folded, so one hash has exactly one stored
/// spelling and a byte comparison of two rows means what it looks like.
fn validate_hash(value: &str, field: &'static str) -> Chained<()> {
    if value.len() != CHAIN_HASH_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AuditChainError::InvalidField(field));
    }
    Ok(())
}

/// Exactly one of a closed set of spellings.
///
/// An unrecognized value is refused rather than folded into a neighbour: "we
/// could not tell what this record was" and "this record was an action" are
/// different answers, and only one of them is true.
fn validate_vocabulary(value: &str, allowed: &[&str], field: &'static str) -> Chained<()> {
    if allowed.contains(&value) {
        return Ok(());
    }
    Err(AuditChainError::InvalidField(field))
}

fn checked_identifier(value: String, field: &'static str) -> Chained<String> {
    validate_identifier(&value, field).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_hash(value: String, field: &'static str) -> Chained<String> {
    validate_hash(&value, field).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_vocabulary(value: String, allowed: &[&str], field: &'static str) -> Chained<String> {
    validate_vocabulary(&value, allowed, field).map_err(|_| corrupt(field))?;
    Ok(value)
}

/// Map a validation field onto its stable corruption invariant name.
///
/// Read paths never reuse `InvalidField`: a bad stored row is corruption the
/// caller cannot have caused, and the two must not be confused.
const fn corrupt(field: &'static str) -> AuditChainError {
    AuditChainError::Corrupt(field)
}

fn to_db_u64(value: u64, field: &'static str) -> Chained<i64> {
    i64::try_from(value).map_err(|_| AuditChainError::InvalidField(field))
}

fn from_db_u64(value: i64, field: &'static str) -> Chained<u64> {
    u64::try_from(value).map_err(|_| AuditChainError::InvalidField(field))
}

fn secure_path(path: &Path) -> Chained<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => AuditChainError::Io(io),
        other => AuditChainError::InsecurePath(other.to_string()),
    })
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Chained<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == AUDIT_CHAIN_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(AuditChainError::SchemaVersion {
            found: version,
            supported: AUDIT_CHAIN_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(AuditChainError::SchemaVersion {
            found: 0,
            supported: AUDIT_CHAIN_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", AUDIT_CHAIN_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}
