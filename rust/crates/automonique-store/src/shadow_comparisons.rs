// SPDX-License-Identifier: Elastic-2.0

//! Durable custody of intended-action envelopes, their comparisons, and the
//! gate decisions taken on them.
//!
//! The parity harness records, per source event, what each engine *decided to
//! do*. This module is where those decisions become durable, and it holds three
//! things:
//!
//! - `intended_actions` — one row per (scope, source key, engine, sequence),
//!   carrying the canonical envelope bytes and the digest the caller declared
//!   for them. Record-once, three ways and only three ways: the coordinate is
//!   new and the row is written ([`ShadowDisposition::Recorded`]); the exact
//!   same envelope is presented again and nothing changes
//!   ([`ShadowDisposition::AlreadyRecorded`]); or the coordinate is bound to
//!   different bytes and nothing is written ([`ShadowError::Conflict`], naming
//!   the first differing field);
//! - `comparisons` — one row per compared position, carrying the verdict, the
//!   canonical diff bytes, the classification and, for a known deviation, the
//!   registry entry that explains it;
//! - `gate_decisions` — one immutable row per go/no-go, pinning the score, the
//!   band, the per-category counts, and the **digest of the deviation registry
//!   the decision was taken against**. That last column is the point: a later
//!   edit to the registry cannot retroactively rewrite what was known when a
//!   scope was promoted.
//!
//! # A sibling database, and why
//!
//! Every store in this crate owns its own SQLite file. The main [`crate::Store`]
//! is reserved for scheduler state and for anything that must commit in the same
//! transaction as the thing it gates. A parity record is *derived observation*:
//! it claims no exclusive resource, releases no work and gates nothing at write
//! time, so it needs no such atomicity — and a sibling avoids bumping the main
//! schema version and re-pinning its whole migration ladder for a table that
//! nothing in the scheduler reads.
//!
//! `gate_decisions` is in the version-one schema rather than migrated in later,
//! for the reason the M2 plan names: sibling stores in this crate almost never
//! migrate, and the one that did needed a full rename-and-copy rebuild because
//! `ALTER TABLE ADD COLUMN` cannot add a cross-column `CHECK` — which is exactly
//! the shape a gate-decision row needs.
//!
//! # This module parses no JSON
//!
//! Envelope and diff bodies are opaque bytes here. The digest beside them is the
//! name the caller declared; this module checks its *spelling* — 64 lowercase
//! hexadecimal digits, at the DDL level as well as in Rust — and never computes
//! a hash. Canonicalization and hashing belong to the caller, which is the rule
//! the rest of this crate already follows.
//!
//! # Retention is a refusal
//!
//! Nothing here evicts. [`Retention`] states a ceiling per table and a write
//! above it is [`ShadowError::LogFull`], because a parity corpus that silently
//! forgot its oldest evidence would let a scope's score improve by nothing more
//! than the passage of time.
//!
//! # There is no clock
//!
//! Callers supply every timestamp, exactly as they do everywhere else in this
//! crate, so a replay is deterministic and a test carries no ambient clock.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::{BUSY_TIMEOUT, MAX_TRANSPORT_KEY_BYTES, StoreError, validate_database_path};

/// The only shadow-comparison schema this build can read and write.
pub const SHADOW_COMPARISONS_SCHEMA_VERSION: u32 = 1;

/// Largest number of intended-action envelopes any database will hold.
pub const MAX_INTENDED_ACTIONS: usize = 262_144;

/// Largest number of comparisons any database will hold.
pub const MAX_COMPARISONS: usize = 262_144;

/// Largest number of gate decisions any database will hold.
pub const MAX_GATE_DECISIONS: usize = 4_096;

/// Longest accepted scope, engine, verdict, classification or decider value.
pub const MAX_IDENTIFIER_BYTES: usize = 256;

/// Longest accepted source key, in bytes.
///
/// The durable transport-key bound, so an envelope keyed by a source key any
/// other durable surface admits is one this table admits too.
pub const MAX_SOURCE_KEY_BYTES: usize = MAX_TRANSPORT_KEY_BYTES;

/// Longest accepted canonical envelope or diff body, in bytes.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Exact length of a declared digest: SHA-256 as 64 lowercase hexadecimal
/// digits.
pub const DIGEST_HEX_BYTES: usize = 64;

/// Highest score a gate decision may record.
pub const MAX_SCORE: i64 = 100;

/// Schema v1.
///
/// The closed vocabularies (`engine`, `verdict`, `classification`, `band`), the
/// digest widths and hex alphabets, the non-empty bodies and the coordinate
/// uniqueness are *database* constraints, so a second writer cannot introduce a
/// value this build does not define. The identifier grammar and the body
/// ceilings are enforced on write and re-checked on every read, so a row written
/// around this API is refused rather than believed.
const SCHEMA_V1: &str = r#"
CREATE TABLE intended_actions (
    action_id INTEGER PRIMARY KEY,
    scope TEXT NOT NULL,
    source_key TEXT NOT NULL,
    engine TEXT NOT NULL CHECK (engine IN ('shadow-candidate', 'legacy-observed')),
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    envelope BLOB NOT NULL CHECK (length(envelope) > 0),
    envelope_digest TEXT NOT NULL
        CHECK (length(envelope_digest) = 64 AND envelope_digest NOT GLOB '*[^0-9a-f]*'),
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0),
    UNIQUE (scope, source_key, engine, sequence)
) STRICT;

CREATE INDEX intended_actions_by_source
    ON intended_actions(scope, source_key, sequence, engine);

CREATE TABLE comparisons (
    comparison_id INTEGER PRIMARY KEY,
    scope TEXT NOT NULL,
    source_key TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    verdict TEXT NOT NULL
        CHECK (verdict IN ('match', 'mismatch', 'shadow_only', 'legacy_only')),
    classification TEXT NOT NULL
        CHECK (classification IN ('parity', 'known_deviation', 'regression')),
    deviation_id TEXT
        CHECK ((classification = 'known_deviation') = (deviation_id IS NOT NULL)),
    category TEXT NOT NULL
        CHECK (category IN ('happy', 'error', 'edge', 'variety', 'production-representative')),
    diff BLOB NOT NULL CHECK (length(diff) > 0),
    diff_digest TEXT NOT NULL
        CHECK (length(diff_digest) = 64 AND diff_digest NOT GLOB '*[^0-9a-f]*'),
    compared_at_ms INTEGER NOT NULL CHECK (compared_at_ms >= 0),
    UNIQUE (scope, source_key, sequence)
) STRICT;

CREATE INDEX comparisons_by_scope
    ON comparisons(scope, classification, comparison_id);

CREATE TABLE gate_decisions (
    decision_id INTEGER PRIMARY KEY,
    decision_key TEXT NOT NULL UNIQUE,
    scope TEXT NOT NULL,
    score INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
    band TEXT NOT NULL
        CHECK (band IN ('block', 'caution', 'shadow-ready', 'cutover-ready')),
    happy_total INTEGER NOT NULL CHECK (happy_total >= 0),
    happy_accounted INTEGER NOT NULL
        CHECK (happy_accounted >= 0 AND happy_accounted <= happy_total),
    error_total INTEGER NOT NULL CHECK (error_total >= 0),
    error_accounted INTEGER NOT NULL
        CHECK (error_accounted >= 0 AND error_accounted <= error_total),
    edge_total INTEGER NOT NULL CHECK (edge_total >= 0),
    edge_accounted INTEGER NOT NULL
        CHECK (edge_accounted >= 0 AND edge_accounted <= edge_total),
    variety_total INTEGER NOT NULL CHECK (variety_total >= 0),
    variety_accounted INTEGER NOT NULL
        CHECK (variety_accounted >= 0 AND variety_accounted <= variety_total),
    production_total INTEGER NOT NULL CHECK (production_total >= 0),
    production_accounted INTEGER NOT NULL
        CHECK (production_accounted >= 0 AND production_accounted <= production_total),
    registry_digest TEXT NOT NULL
        CHECK (length(registry_digest) = 64 AND registry_digest NOT GLOB '*[^0-9a-f]*'),
    evidence_digest TEXT NOT NULL
        CHECK (length(evidence_digest) = 64 AND evidence_digest NOT GLOB '*[^0-9a-f]*'),
    decided_at_ms INTEGER NOT NULL CHECK (decided_at_ms >= 0),
    decider TEXT NOT NULL
) STRICT;

CREATE INDEX gate_decisions_by_scope
    ON gate_decisions(scope, decision_id);
"#;

/// A shadow-comparison error with stable refusal categories.
#[derive(Debug)]
pub enum ShadowError {
    /// The database path or its containing directory is not private and owned.
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
    /// A recorded coordinate was presented with different content.
    ///
    /// Nothing was written. The recorded digest is reported so a caller can tell
    /// a stale retry from a reused coordinate without a second read; the
    /// recorded *body* is deliberately not reported, because a refusal must not
    /// hand back bytes the retrying caller did not already have.
    Conflict {
        /// First bound coordinate that differs.
        field: &'static str,
        /// Row the coordinate already binds.
        recorded_id: i64,
        /// Digest the durable row binds.
        recorded_digest: String,
    },
    /// The table holds its full capacity of rows.
    ///
    /// Refused *before* a row is written. Nothing here evicts.
    LogFull {
        /// Capacity of the table that refused.
        capacity: usize,
        /// Table that refused.
        table: &'static str,
    },
    /// A stored row violates an invariant this API can only have written once.
    Corrupt(&'static str),
    /// Filesystem failure while establishing the private database.
    Io(std::io::Error),
    /// SQLite rejected an operation.
    Sqlite(rusqlite::Error),
}

impl ShadowError {
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

impl fmt::Display for ShadowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => {
                write!(formatter, "shadow database path is not private: {reason}")
            }
            Self::SchemaVersion { found, supported } => write!(
                formatter,
                "shadow comparison schema {found} is unsupported; expected {supported}"
            ),
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::Conflict {
                field,
                recorded_id,
                recorded_digest,
            } => write!(
                formatter,
                "coordinate is already bound to row {recorded_id} at digest \
                 {recorded_digest}; {field} differs"
            ),
            Self::LogFull { capacity, table } => write!(
                formatter,
                "shadow table {table} holds its capacity of {capacity}"
            ),
            Self::Corrupt(invariant) => {
                write!(formatter, "stored row violates invariant: {invariant}")
            }
            Self::Io(error) => write!(formatter, "shadow database filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite error: {error}"),
        }
    }
}

impl Error for ShadowError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ShadowError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for ShadowError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// Result of one shadow-comparison operation.
pub type Shadowed<T> = Result<T, ShadowError>;

/// The stated ceiling on what one shadow database retains.
///
/// A bound from day one, and a refusing one: a corpus that evicted its oldest
/// evidence would let a scope's score improve without a line of code changing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Retention {
    /// Ceiling on `intended_actions`.
    pub intended_actions: usize,
    /// Ceiling on `comparisons`.
    pub comparisons: usize,
    /// Ceiling on `gate_decisions`.
    pub gate_decisions: usize,
}

impl Retention {
    /// The whole-file ceilings this build ships.
    #[must_use]
    pub const fn full() -> Self {
        Self {
            intended_actions: MAX_INTENDED_ACTIONS,
            comparisons: MAX_COMPARISONS,
            gate_decisions: MAX_GATE_DECISIONS,
        }
    }

    fn validate(self) -> Shadowed<()> {
        if self.intended_actions == 0 || self.intended_actions > MAX_INTENDED_ACTIONS {
            return Err(ShadowError::InvalidField("retention.intended_actions"));
        }
        if self.comparisons == 0 || self.comparisons > MAX_COMPARISONS {
            return Err(ShadowError::InvalidField("retention.comparisons"));
        }
        if self.gate_decisions == 0 || self.gate_decisions > MAX_GATE_DECISIONS {
            return Err(ShadowError::InvalidField("retention.gate_decisions"));
        }
        Ok(())
    }
}

impl Default for Retention {
    fn default() -> Self {
        Self::full()
    }
}

/// How a record-once write was answered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShadowDisposition {
    /// The coordinate was new and the row is now durable.
    Recorded,
    /// The exact row was already durable. Nothing changed.
    AlreadyRecorded,
}

impl ShadowDisposition {
    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::AlreadyRecorded => "already_recorded",
        }
    }

    /// Whether this answer replayed an existing row rather than writing one.
    #[must_use]
    pub const fn is_replay(self) -> bool {
        matches!(self, Self::AlreadyRecorded)
    }
}

/// Durable identity of one recorded or replayed row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShadowReceipt {
    /// Row identity.
    pub row_id: i64,
    /// Whether this call wrote the row or replayed it.
    pub disposition: ShadowDisposition,
}

/// One intended-action envelope presented for durable custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntendedActionRecord<'a> {
    /// Parity scope the decision belongs to.
    pub scope: &'a str,
    /// Durable source key of the event that provoked the decision.
    pub source_key: &'a str,
    /// Which engine decided. `shadow-candidate` or `legacy-observed`.
    pub engine: &'a str,
    /// Position in this engine's decision stream for this source key.
    pub sequence: i64,
    /// Canonical envelope bytes, stored verbatim.
    pub envelope: &'a [u8],
    /// SHA-256 of `envelope` as 64 lowercase hexadecimal digits, as declared by
    /// the caller. This module computes no hash.
    pub envelope_digest: &'a str,
    /// When the caller observed the decision, in caller-supplied milliseconds.
    ///
    /// Not part of the binding: a replay naturally carries a later clock, so a
    /// differing timestamp is an exact replay rather than a conflict.
    pub observed_at_ms: i64,
}

/// A validated `intended_actions` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntendedActionEntry {
    /// Row identity, monotonic in record order.
    pub action_id: i64,
    /// Parity scope.
    pub scope: String,
    /// Durable source key.
    pub source_key: String,
    /// Recording engine.
    pub engine: String,
    /// Position in the engine's stream.
    pub sequence: i64,
    /// Canonical envelope bytes, exactly as recorded.
    pub envelope: Vec<u8>,
    /// Digest the first record declared.
    pub envelope_digest: String,
    /// When the *first* record of this coordinate was written.
    pub observed_at_ms: i64,
}

/// One comparison presented for durable custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComparisonRecord<'a> {
    /// Parity scope.
    pub scope: &'a str,
    /// Durable source key.
    pub source_key: &'a str,
    /// Position compared.
    pub sequence: i64,
    /// `match`, `mismatch`, `shadow_only` or `legacy_only`.
    pub verdict: &'a str,
    /// `parity`, `known_deviation` or `regression`.
    pub classification: &'a str,
    /// The registry entry that explains a known deviation.
    ///
    /// Required exactly when `classification` is `known_deviation`, and refused
    /// otherwise — at the DDL level, so the two columns cannot disagree.
    pub deviation_id: Option<&'a str>,
    /// How representative the comparison is, for the weighted score.
    pub category: &'a str,
    /// Canonical diff bytes, stored verbatim.
    pub diff: &'a [u8],
    /// SHA-256 of `diff` as 64 lowercase hexadecimal digits.
    pub diff_digest: &'a str,
    /// When the comparison was taken, in caller-supplied milliseconds.
    pub compared_at_ms: i64,
}

/// A validated `comparisons` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComparisonEntry {
    /// Row identity.
    pub comparison_id: i64,
    /// Parity scope.
    pub scope: String,
    /// Durable source key.
    pub source_key: String,
    /// Position compared.
    pub sequence: i64,
    /// The verdict.
    pub verdict: String,
    /// The classification.
    pub classification: String,
    /// The registry entry explaining a known deviation.
    pub deviation_id: Option<String>,
    /// The category.
    pub category: String,
    /// Canonical diff bytes.
    pub diff: Vec<u8>,
    /// Digest of the diff.
    pub diff_digest: String,
    /// When the comparison was taken.
    pub compared_at_ms: i64,
}

/// Per-category counts recorded beside one gate decision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GateCounts {
    /// Comparisons scored in a category.
    pub total: i64,
    /// Of those, the ones that classified parity or known-deviation.
    pub accounted: i64,
}

/// One go/no-go decision presented for durable custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GateDecisionRecord<'a> {
    /// The caller's stable identity for this decision. The unique key.
    ///
    /// Re-deciding a scope needs a *new* key: the row is immutable, so a second
    /// decision under the first decision's key is a conflict rather than an
    /// update.
    pub decision_key: &'a str,
    /// Parity scope decided.
    pub scope: &'a str,
    /// The weighted score, 0 to [`MAX_SCORE`].
    pub score: i64,
    /// `block`, `caution`, `shadow-ready` or `cutover-ready`.
    pub band: &'a str,
    /// Counts for the happy category.
    pub happy: GateCounts,
    /// Counts for the error category.
    pub error: GateCounts,
    /// Counts for the edge category.
    pub edge: GateCounts,
    /// Counts for the variety category.
    pub variety: GateCounts,
    /// Counts for the production-representative category.
    pub production: GateCounts,
    /// Digest of the deviation registry this decision was taken against.
    pub registry_digest: &'a str,
    /// Digest of the evidence the score was computed over.
    pub evidence_digest: &'a str,
    /// When the decision was taken, in caller-supplied milliseconds.
    pub decided_at_ms: i64,
    /// Who took it.
    pub decider: &'a str,
}

/// A validated `gate_decisions` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateDecisionEntry {
    /// Row identity.
    pub decision_id: i64,
    /// The unique key this row is bound to.
    pub decision_key: String,
    /// Parity scope decided.
    pub scope: String,
    /// The weighted score.
    pub score: i64,
    /// The band.
    pub band: String,
    /// Counts for the happy category.
    pub happy: GateCounts,
    /// Counts for the error category.
    pub error: GateCounts,
    /// Counts for the edge category.
    pub edge: GateCounts,
    /// Counts for the variety category.
    pub variety: GateCounts,
    /// Counts for the production-representative category.
    pub production: GateCounts,
    /// Registry digest the decision pinned.
    pub registry_digest: String,
    /// Evidence digest the decision pinned.
    pub evidence_digest: String,
    /// When the decision was taken.
    pub decided_at_ms: i64,
    /// Who took it.
    pub decider: String,
}

/// Durable custody of one scope's shadow-comparison evidence.
#[derive(Debug)]
pub struct ShadowComparisonStore {
    connection: Connection,
    path: PathBuf,
    retention: Retention,
}

impl ShadowComparisonStore {
    /// Open or initialize a database inside an existing private directory.
    ///
    /// The parent must be owned by the effective user and deny all group and
    /// other access. Existing paths must be regular, owned, non-symlinks.
    ///
    /// # Errors
    ///
    /// Returns [`ShadowError::InsecurePath`] for an unsafe path,
    /// [`ShadowError::SchemaVersion`] for a foreign or future database, and the
    /// underlying I/O or SQLite failure otherwise.
    pub fn open(path: impl AsRef<Path>) -> Shadowed<Self> {
        Self::open_with_retention(path, Retention::full())
    }

    /// Open a database under a lowered retention ceiling.
    ///
    /// The ceiling is a property of this handle, not of the database: opening an
    /// existing database under a ceiling below its row count refuses further
    /// writes with [`ShadowError::LogFull`] while exact replays and reads keep
    /// working, because a replay writes nothing.
    ///
    /// # Errors
    ///
    /// As [`Self::open`], plus [`ShadowError::InvalidField`] for a ceiling
    /// outside its range.
    pub fn open_with_retention(path: impl AsRef<Path>, retention: Retention) -> Shadowed<Self> {
        retention.validate()?;
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
            return Err(ShadowError::Sqlite(rusqlite::Error::InvalidQuery));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        migrate(&mut connection)?;

        Ok(Self {
            connection,
            path: path.to_path_buf(),
            retention,
        })
    }

    /// Exact path opened by this database.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The retention ceiling of this handle.
    #[must_use]
    pub const fn retention(&self) -> Retention {
        self.retention
    }

    /// Take durable custody of one intended-action envelope.
    ///
    /// One immediate transaction: after a crash a reader sees the whole row or
    /// no row, never an envelope without its digest.
    ///
    /// Lookup precedes the capacity check, so an exact replay is still answered
    /// [`ShadowDisposition::AlreadyRecorded`] in a full database — a replay
    /// writes nothing and must never degrade into a refusal.
    ///
    /// # Errors
    ///
    /// Returns [`ShadowError::InvalidField`] for a malformed field,
    /// [`ShadowError::Conflict`] for a coordinate already bound to different
    /// content, [`ShadowError::LogFull`] at capacity, and
    /// [`ShadowError::Corrupt`] when the existing row it must compare against is
    /// not one this API could have written.
    pub fn record_intended_action(
        &mut self,
        record: IntendedActionRecord<'_>,
    ) -> Shadowed<ShadowReceipt> {
        validate_identifier(record.scope, MAX_IDENTIFIER_BYTES, "scope")?;
        validate_identifier(record.source_key, MAX_SOURCE_KEY_BYTES, "source_key")?;
        validate_identifier(record.engine, MAX_IDENTIFIER_BYTES, "engine")?;
        validate_sequence(record.sequence)?;
        validate_body(record.envelope, "envelope")?;
        validate_digest(record.envelope_digest, "envelope_digest")?;
        if record.observed_at_ms < 0 {
            return Err(ShadowError::InvalidField("observed_at_ms"));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let receipt =
            insert_intended_action(&transaction, &record, self.retention.intended_actions)?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Take durable custody of one comparison.
    ///
    /// # Errors
    ///
    /// As [`Self::record_intended_action`].
    pub fn record_comparison(&mut self, record: ComparisonRecord<'_>) -> Shadowed<ShadowReceipt> {
        validate_identifier(record.scope, MAX_IDENTIFIER_BYTES, "scope")?;
        validate_identifier(record.source_key, MAX_SOURCE_KEY_BYTES, "source_key")?;
        validate_sequence(record.sequence)?;
        validate_identifier(record.verdict, MAX_IDENTIFIER_BYTES, "verdict")?;
        validate_identifier(
            record.classification,
            MAX_IDENTIFIER_BYTES,
            "classification",
        )?;
        validate_identifier(record.category, MAX_IDENTIFIER_BYTES, "category")?;
        if let Some(deviation_id) = record.deviation_id {
            validate_identifier(deviation_id, MAX_IDENTIFIER_BYTES, "deviation_id")?;
        }
        validate_body(record.diff, "diff")?;
        validate_digest(record.diff_digest, "diff_digest")?;
        if record.compared_at_ms < 0 {
            return Err(ShadowError::InvalidField("compared_at_ms"));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let receipt = insert_comparison(&transaction, &record, self.retention.comparisons)?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Record one immutable gate decision.
    ///
    /// Immutable means what it says: a second decision under the same
    /// `decision_key` with identical content replays, and one with any differing
    /// field is [`ShadowError::Conflict`]. Re-deciding a scope takes a new key.
    ///
    /// # Errors
    ///
    /// As [`Self::record_intended_action`].
    pub fn record_gate_decision(
        &mut self,
        record: GateDecisionRecord<'_>,
    ) -> Shadowed<ShadowReceipt> {
        validate_identifier(record.decision_key, MAX_IDENTIFIER_BYTES, "decision_key")?;
        validate_identifier(record.scope, MAX_IDENTIFIER_BYTES, "scope")?;
        validate_identifier(record.band, MAX_IDENTIFIER_BYTES, "band")?;
        validate_identifier(record.decider, MAX_IDENTIFIER_BYTES, "decider")?;
        validate_digest(record.registry_digest, "registry_digest")?;
        validate_digest(record.evidence_digest, "evidence_digest")?;
        if record.score < 0 || record.score > MAX_SCORE {
            return Err(ShadowError::InvalidField("score"));
        }
        for (counts, field) in [
            (record.happy, "happy"),
            (record.error, "error"),
            (record.edge, "edge"),
            (record.variety, "variety"),
            (record.production, "production"),
        ] {
            if counts.total < 0 || counts.accounted < 0 || counts.accounted > counts.total {
                return Err(ShadowError::InvalidField(field));
            }
        }
        if record.decided_at_ms < 0 {
            return Err(ShadowError::InvalidField("decided_at_ms"));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let receipt = insert_gate_decision(&transaction, &record, self.retention.gate_decisions)?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Read every envelope one engine recorded for one source key, in order.
    ///
    /// # Errors
    ///
    /// Returns [`ShadowError::InvalidField`] for a malformed coordinate and
    /// [`ShadowError::Corrupt`] when a stored row is not one this API could have
    /// written.
    pub fn intended_actions(
        &self,
        scope: &str,
        source_key: &str,
        engine: &str,
    ) -> Shadowed<Vec<IntendedActionEntry>> {
        validate_identifier(scope, MAX_IDENTIFIER_BYTES, "scope")?;
        validate_identifier(source_key, MAX_SOURCE_KEY_BYTES, "source_key")?;
        validate_identifier(engine, MAX_IDENTIFIER_BYTES, "engine")?;
        let mut statement = self.connection.prepare(&format!(
            "SELECT {ACTION_COLUMNS} FROM intended_actions
             WHERE scope = ?1 AND source_key = ?2 AND engine = ?3
             ORDER BY sequence"
        ))?;
        let rows = statement.query_map(params![scope, source_key, engine], raw_action)?;
        let mut entries = Vec::new();
        for raw in rows {
            entries.push(validated_action(raw?)?);
        }
        Ok(entries)
    }

    /// Read every source key one scope recorded an envelope for, in first-record
    /// order.
    ///
    /// # Errors
    ///
    /// As [`Self::intended_actions`].
    pub fn source_keys(&self, scope: &str) -> Shadowed<Vec<String>> {
        validate_identifier(scope, MAX_IDENTIFIER_BYTES, "scope")?;
        let mut statement = self.connection.prepare(
            "SELECT source_key FROM intended_actions
             WHERE scope = ?1
             GROUP BY source_key
             ORDER BY min(action_id)",
        )?;
        let rows = statement.query_map([scope], |row| row.get::<_, String>(0))?;
        let mut keys = Vec::new();
        for key in rows {
            let key = key?;
            validate_identifier(&key, MAX_SOURCE_KEY_BYTES, "source_key")
                .map_err(|_| ShadowError::Corrupt("source_key"))?;
            keys.push(key);
        }
        Ok(keys)
    }

    /// Read every comparison recorded for one scope, oldest first.
    ///
    /// # Errors
    ///
    /// As [`Self::intended_actions`].
    pub fn comparisons(&self, scope: &str) -> Shadowed<Vec<ComparisonEntry>> {
        validate_identifier(scope, MAX_IDENTIFIER_BYTES, "scope")?;
        let mut statement = self.connection.prepare(&format!(
            "SELECT {COMPARISON_COLUMNS} FROM comparisons WHERE scope = ?1 ORDER BY comparison_id"
        ))?;
        let rows = statement.query_map([scope], raw_comparison)?;
        let mut entries = Vec::new();
        for raw in rows {
            entries.push(validated_comparison(raw?)?);
        }
        Ok(entries)
    }

    /// Read every gate decision recorded for one scope, oldest first.
    ///
    /// # Errors
    ///
    /// As [`Self::intended_actions`].
    pub fn gate_decisions(&self, scope: &str) -> Shadowed<Vec<GateDecisionEntry>> {
        validate_identifier(scope, MAX_IDENTIFIER_BYTES, "scope")?;
        let mut statement = self.connection.prepare(&format!(
            "SELECT {DECISION_COLUMNS} FROM gate_decisions WHERE scope = ?1 ORDER BY decision_id"
        ))?;
        let rows = statement.query_map([scope], raw_decision)?;
        let mut entries = Vec::new();
        for raw in rows {
            entries.push(validated_decision(raw?)?);
        }
        Ok(entries)
    }

    /// Count durable rows in one table.
    ///
    /// # Errors
    ///
    /// Returns the SQLite failure, or [`ShadowError::Corrupt`] for a count
    /// outside the representable range.
    pub fn intended_action_count(&self) -> Shadowed<usize> {
        count(&self.connection, "intended_actions")
    }

    /// Count durable comparisons.
    ///
    /// # Errors
    ///
    /// As [`Self::intended_action_count`].
    pub fn comparison_count(&self) -> Shadowed<usize> {
        count(&self.connection, "comparisons")
    }

    /// Count durable gate decisions.
    ///
    /// # Errors
    ///
    /// As [`Self::intended_action_count`].
    pub fn gate_decision_count(&self) -> Shadowed<usize> {
        count(&self.connection, "gate_decisions")
    }
}

fn insert_intended_action(
    transaction: &Transaction<'_>,
    record: &IntendedActionRecord<'_>,
    capacity: usize,
) -> Shadowed<ShadowReceipt> {
    let recorded = transaction
        .query_row(
            &format!(
                "SELECT {ACTION_COLUMNS} FROM intended_actions
                 WHERE scope = ?1 AND source_key = ?2 AND engine = ?3 AND sequence = ?4"
            ),
            params![
                record.scope,
                record.source_key,
                record.engine,
                record.sequence
            ],
            raw_action,
        )
        .optional()?;
    if let Some(recorded) = recorded {
        let recorded = validated_action(recorded)?;
        let conflict = |field: &'static str| ShadowError::Conflict {
            field,
            recorded_id: recorded.action_id,
            recorded_digest: recorded.envelope_digest.clone(),
        };
        if recorded.envelope_digest != record.envelope_digest {
            return Err(conflict("envelope_digest"));
        }
        if recorded.envelope != record.envelope {
            return Err(conflict("envelope"));
        }
        return Ok(ShadowReceipt {
            row_id: recorded.action_id,
            disposition: ShadowDisposition::AlreadyRecorded,
        });
    }
    admit(transaction, "intended_actions", capacity)?;
    transaction.execute(
        "INSERT INTO intended_actions
         (scope, source_key, engine, sequence, envelope, envelope_digest, observed_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            record.scope,
            record.source_key,
            record.engine,
            record.sequence,
            record.envelope,
            record.envelope_digest,
            record.observed_at_ms,
        ],
    )?;
    Ok(ShadowReceipt {
        row_id: transaction.last_insert_rowid(),
        disposition: ShadowDisposition::Recorded,
    })
}

fn insert_comparison(
    transaction: &Transaction<'_>,
    record: &ComparisonRecord<'_>,
    capacity: usize,
) -> Shadowed<ShadowReceipt> {
    let recorded = transaction
        .query_row(
            &format!(
                "SELECT {COMPARISON_COLUMNS} FROM comparisons
                 WHERE scope = ?1 AND source_key = ?2 AND sequence = ?3"
            ),
            params![record.scope, record.source_key, record.sequence],
            raw_comparison,
        )
        .optional()?;
    if let Some(recorded) = recorded {
        let recorded = validated_comparison(recorded)?;
        let conflict = |field: &'static str| ShadowError::Conflict {
            field,
            recorded_id: recorded.comparison_id,
            recorded_digest: recorded.diff_digest.clone(),
        };
        if recorded.verdict != record.verdict {
            return Err(conflict("verdict"));
        }
        if recorded.classification != record.classification {
            return Err(conflict("classification"));
        }
        if recorded.deviation_id.as_deref() != record.deviation_id {
            return Err(conflict("deviation_id"));
        }
        if recorded.category != record.category {
            return Err(conflict("category"));
        }
        if recorded.diff_digest != record.diff_digest {
            return Err(conflict("diff_digest"));
        }
        if recorded.diff != record.diff {
            return Err(conflict("diff"));
        }
        return Ok(ShadowReceipt {
            row_id: recorded.comparison_id,
            disposition: ShadowDisposition::AlreadyRecorded,
        });
    }
    admit(transaction, "comparisons", capacity)?;
    transaction.execute(
        "INSERT INTO comparisons
         (scope, source_key, sequence, verdict, classification, deviation_id, category,
          diff, diff_digest, compared_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            record.scope,
            record.source_key,
            record.sequence,
            record.verdict,
            record.classification,
            record.deviation_id,
            record.category,
            record.diff,
            record.diff_digest,
            record.compared_at_ms,
        ],
    )?;
    Ok(ShadowReceipt {
        row_id: transaction.last_insert_rowid(),
        disposition: ShadowDisposition::Recorded,
    })
}

fn insert_gate_decision(
    transaction: &Transaction<'_>,
    record: &GateDecisionRecord<'_>,
    capacity: usize,
) -> Shadowed<ShadowReceipt> {
    let recorded = transaction
        .query_row(
            &format!("SELECT {DECISION_COLUMNS} FROM gate_decisions WHERE decision_key = ?1"),
            [record.decision_key],
            raw_decision,
        )
        .optional()?;
    if let Some(recorded) = recorded {
        let recorded = validated_decision(recorded)?;
        let conflict = |field: &'static str| ShadowError::Conflict {
            field,
            recorded_id: recorded.decision_id,
            recorded_digest: recorded.evidence_digest.clone(),
        };
        if recorded.scope != record.scope {
            return Err(conflict("scope"));
        }
        if recorded.score != record.score {
            return Err(conflict("score"));
        }
        if recorded.band != record.band {
            return Err(conflict("band"));
        }
        for (stored, presented, field) in [
            (recorded.happy, record.happy, "happy"),
            (recorded.error, record.error, "error"),
            (recorded.edge, record.edge, "edge"),
            (recorded.variety, record.variety, "variety"),
            (recorded.production, record.production, "production"),
        ] {
            if stored != presented {
                return Err(conflict(field));
            }
        }
        if recorded.registry_digest != record.registry_digest {
            return Err(conflict("registry_digest"));
        }
        if recorded.evidence_digest != record.evidence_digest {
            return Err(conflict("evidence_digest"));
        }
        if recorded.decider != record.decider {
            return Err(conflict("decider"));
        }
        return Ok(ShadowReceipt {
            row_id: recorded.decision_id,
            disposition: ShadowDisposition::AlreadyRecorded,
        });
    }
    admit(transaction, "gate_decisions", capacity)?;
    transaction.execute(
        "INSERT INTO gate_decisions
         (decision_key, scope, score, band,
          happy_total, happy_accounted, error_total, error_accounted,
          edge_total, edge_accounted, variety_total, variety_accounted,
          production_total, production_accounted,
          registry_digest, evidence_digest, decided_at_ms, decider)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
        params![
            record.decision_key,
            record.scope,
            record.score,
            record.band,
            record.happy.total,
            record.happy.accounted,
            record.error.total,
            record.error.accounted,
            record.edge.total,
            record.edge.accounted,
            record.variety.total,
            record.variety.accounted,
            record.production.total,
            record.production.accounted,
            record.registry_digest,
            record.evidence_digest,
            record.decided_at_ms,
            record.decider,
        ],
    )?;
    Ok(ShadowReceipt {
        row_id: transaction.last_insert_rowid(),
        disposition: ShadowDisposition::Recorded,
    })
}

/// Refuse a write that would take a table past its stated ceiling.
fn admit(transaction: &Transaction<'_>, table: &'static str, capacity: usize) -> Shadowed<()> {
    if count(transaction, table)? >= capacity {
        return Err(ShadowError::LogFull { capacity, table });
    }
    Ok(())
}

const ACTION_COLUMNS: &str =
    "action_id, scope, source_key, engine, sequence, envelope, envelope_digest, observed_at_ms";

const COMPARISON_COLUMNS: &str = "comparison_id, scope, source_key, sequence, verdict, \
     classification, deviation_id, category, diff, diff_digest, compared_at_ms";

const DECISION_COLUMNS: &str = "decision_id, decision_key, scope, score, band, \
     happy_total, happy_accounted, error_total, error_accounted, \
     edge_total, edge_accounted, variety_total, variety_accounted, \
     production_total, production_accounted, \
     registry_digest, evidence_digest, decided_at_ms, decider";

fn raw_action(row: &rusqlite::Row<'_>) -> rusqlite::Result<IntendedActionEntry> {
    Ok(IntendedActionEntry {
        action_id: row.get(0)?,
        scope: row.get(1)?,
        source_key: row.get(2)?,
        engine: row.get(3)?,
        sequence: row.get(4)?,
        envelope: row.get(5)?,
        envelope_digest: row.get(6)?,
        observed_at_ms: row.get(7)?,
    })
}

fn raw_comparison(row: &rusqlite::Row<'_>) -> rusqlite::Result<ComparisonEntry> {
    Ok(ComparisonEntry {
        comparison_id: row.get(0)?,
        scope: row.get(1)?,
        source_key: row.get(2)?,
        sequence: row.get(3)?,
        verdict: row.get(4)?,
        classification: row.get(5)?,
        deviation_id: row.get(6)?,
        category: row.get(7)?,
        diff: row.get(8)?,
        diff_digest: row.get(9)?,
        compared_at_ms: row.get(10)?,
    })
}

fn raw_decision(row: &rusqlite::Row<'_>) -> rusqlite::Result<GateDecisionEntry> {
    Ok(GateDecisionEntry {
        decision_id: row.get(0)?,
        decision_key: row.get(1)?,
        scope: row.get(2)?,
        score: row.get(3)?,
        band: row.get(4)?,
        happy: GateCounts {
            total: row.get(5)?,
            accounted: row.get(6)?,
        },
        error: GateCounts {
            total: row.get(7)?,
            accounted: row.get(8)?,
        },
        edge: GateCounts {
            total: row.get(9)?,
            accounted: row.get(10)?,
        },
        variety: GateCounts {
            total: row.get(11)?,
            accounted: row.get(12)?,
        },
        production: GateCounts {
            total: row.get(13)?,
            accounted: row.get(14)?,
        },
        registry_digest: row.get(15)?,
        evidence_digest: row.get(16)?,
        decided_at_ms: row.get(17)?,
        decider: row.get(18)?,
    })
}

/// Re-validate a loaded row against every rule the write path enforced.
///
/// A row that fails here was written around this API. It is corruption the
/// caller cannot have caused, and it is never reported as an invalid argument.
fn validated_action(entry: IntendedActionEntry) -> Shadowed<IntendedActionEntry> {
    if entry.action_id <= 0 {
        return Err(ShadowError::Corrupt("action_id"));
    }
    corrupt_if(
        validate_identifier(&entry.scope, MAX_IDENTIFIER_BYTES, "scope"),
        "scope",
    )?;
    corrupt_if(
        validate_identifier(&entry.source_key, MAX_SOURCE_KEY_BYTES, "source_key"),
        "source_key",
    )?;
    corrupt_if(
        validate_identifier(&entry.engine, MAX_IDENTIFIER_BYTES, "engine"),
        "engine",
    )?;
    corrupt_if(validate_sequence(entry.sequence), "sequence")?;
    corrupt_if(validate_body(&entry.envelope, "envelope"), "envelope")?;
    corrupt_if(
        validate_digest(&entry.envelope_digest, "envelope_digest"),
        "envelope_digest",
    )?;
    if entry.observed_at_ms < 0 {
        return Err(ShadowError::Corrupt("observed_at_ms"));
    }
    Ok(entry)
}

fn validated_comparison(entry: ComparisonEntry) -> Shadowed<ComparisonEntry> {
    if entry.comparison_id <= 0 {
        return Err(ShadowError::Corrupt("comparison_id"));
    }
    corrupt_if(
        validate_identifier(&entry.scope, MAX_IDENTIFIER_BYTES, "scope"),
        "scope",
    )?;
    corrupt_if(
        validate_identifier(&entry.source_key, MAX_SOURCE_KEY_BYTES, "source_key"),
        "source_key",
    )?;
    corrupt_if(validate_sequence(entry.sequence), "sequence")?;
    corrupt_if(
        validate_identifier(&entry.verdict, MAX_IDENTIFIER_BYTES, "verdict"),
        "verdict",
    )?;
    corrupt_if(
        validate_identifier(
            &entry.classification,
            MAX_IDENTIFIER_BYTES,
            "classification",
        ),
        "classification",
    )?;
    corrupt_if(
        validate_identifier(&entry.category, MAX_IDENTIFIER_BYTES, "category"),
        "category",
    )?;
    if let Some(deviation_id) = &entry.deviation_id {
        corrupt_if(
            validate_identifier(deviation_id, MAX_IDENTIFIER_BYTES, "deviation_id"),
            "deviation_id",
        )?;
    }
    corrupt_if(validate_body(&entry.diff, "diff"), "diff")?;
    corrupt_if(
        validate_digest(&entry.diff_digest, "diff_digest"),
        "diff_digest",
    )?;
    if entry.compared_at_ms < 0 {
        return Err(ShadowError::Corrupt("compared_at_ms"));
    }
    Ok(entry)
}

fn validated_decision(entry: GateDecisionEntry) -> Shadowed<GateDecisionEntry> {
    if entry.decision_id <= 0 {
        return Err(ShadowError::Corrupt("decision_id"));
    }
    corrupt_if(
        validate_identifier(&entry.decision_key, MAX_IDENTIFIER_BYTES, "decision_key"),
        "decision_key",
    )?;
    corrupt_if(
        validate_identifier(&entry.scope, MAX_IDENTIFIER_BYTES, "scope"),
        "scope",
    )?;
    corrupt_if(
        validate_identifier(&entry.band, MAX_IDENTIFIER_BYTES, "band"),
        "band",
    )?;
    corrupt_if(
        validate_identifier(&entry.decider, MAX_IDENTIFIER_BYTES, "decider"),
        "decider",
    )?;
    corrupt_if(
        validate_digest(&entry.registry_digest, "registry_digest"),
        "registry_digest",
    )?;
    corrupt_if(
        validate_digest(&entry.evidence_digest, "evidence_digest"),
        "evidence_digest",
    )?;
    if entry.score < 0 || entry.score > MAX_SCORE {
        return Err(ShadowError::Corrupt("score"));
    }
    for (counts, field) in [
        (entry.happy, "happy"),
        (entry.error, "error"),
        (entry.edge, "edge"),
        (entry.variety, "variety"),
        (entry.production, "production"),
    ] {
        if counts.total < 0 || counts.accounted < 0 || counts.accounted > counts.total {
            return Err(ShadowError::Corrupt(field));
        }
    }
    if entry.decided_at_ms < 0 {
        return Err(ShadowError::Corrupt("decided_at_ms"));
    }
    Ok(entry)
}

fn corrupt_if(result: Shadowed<()>, invariant: &'static str) -> Shadowed<()> {
    result.map_err(|_| ShadowError::Corrupt(invariant))
}

fn count(connection: &Connection, table: &'static str) -> Shadowed<usize> {
    let total: i64 = connection.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
        row.get(0)
    })?;
    usize::try_from(total).map_err(|_| ShadowError::Corrupt("row_count"))
}

fn secure_path(path: &Path) -> Shadowed<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => ShadowError::Io(io),
        other => ShadowError::InsecurePath(other.to_string()),
    })
}

/// Walk the `user_version` ladder to [`SHADOW_COMPARISONS_SCHEMA_VERSION`].
///
/// One rung today. It is written as a ladder rather than as a single-version
/// check so a future rung is an addition rather than a rewrite, and so the
/// replay test in `tests/shadow_comparisons.rs` has something to replay: a
/// database opened twice must land on the same version and the same objects.
fn migrate(connection: &mut Connection) -> Shadowed<()> {
    let mut version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > SHADOW_COMPARISONS_SCHEMA_VERSION {
        return Err(ShadowError::SchemaVersion {
            found: version,
            supported: SHADOW_COMPARISONS_SCHEMA_VERSION,
        });
    }
    if version == 0 {
        let objects: u32 = connection.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        if objects != 0 {
            // A database with objects and no version is some other product's.
            return Err(ShadowError::SchemaVersion {
                found: 0,
                supported: SHADOW_COMPARISONS_SCHEMA_VERSION,
            });
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA_V1)?;
        transaction.pragma_update(None, "user_version", 1_u32)?;
        transaction.commit()?;
        version = 1;
    }
    if version != SHADOW_COMPARISONS_SCHEMA_VERSION {
        return Err(ShadowError::SchemaVersion {
            found: version,
            supported: SHADOW_COMPARISONS_SCHEMA_VERSION,
        });
    }
    Ok(())
}

fn validate_identifier(value: &str, max_bytes: usize, field: &'static str) -> Shadowed<()> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(ShadowError::InvalidField(field));
    }
    Ok(())
}

fn validate_sequence(sequence: i64) -> Shadowed<()> {
    if sequence < 0 || sequence > i64::from(u32::MAX) {
        return Err(ShadowError::InvalidField("sequence"));
    }
    Ok(())
}

fn validate_body(body: &[u8], field: &'static str) -> Shadowed<()> {
    if body.is_empty() || body.len() > MAX_BODY_BYTES {
        return Err(ShadowError::InvalidField(field));
    }
    Ok(())
}

/// Exactly 64 lowercase hexadecimal digits.
///
/// Uppercase is refused rather than folded, so one digest has exactly one stored
/// spelling and a byte comparison of two rows means what it looks like.
fn validate_digest(value: &str, field: &'static str) -> Shadowed<()> {
    if value.len() != DIGEST_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ShadowError::InvalidField(field));
    }
    Ok(())
}
