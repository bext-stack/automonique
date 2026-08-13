// SPDX-License-Identifier: Elastic-2.0

//! Durable registry of which submissions a batch declared, and where each of
//! them was last reported to have got to.
//!
//! `automonique_protocol::batch_runner` models a batch as a `BatchPlan` — an
//! identity, an optional label, an ordered set of member keys and a
//! `ConcurrencyPolicy` — and a reading of one as a `BatchProgress`, which is a
//! `MemberProgress` per member plus a `BatchState` that `roll_up` derives from
//! them. Those are values in memory. Nothing in this product wrote them down.
//! Restart the daemon and the membership an operator declared is gone, which
//! makes "resume by stable record identity" impossible: there is no durable
//! record of which identities the batch had. This module is the durable half.
//! One row per batch, and one row per member of one:
//!
//! ```text
//! batch_id  -> (label, concurrency, created_at_ms, revision)
//! (batch_id, member_key) -> (ordinal, progress, last_sequence, updated_at_ms, revision)
//! ```
//!
//! There is no execution here, no fan-out, no clock and no protocol dependency.
//! Callers supply every identifier, sequence and timestamp, so restarts stay
//! deterministic and tests do not depend on an ambient clock.
//!
//! # What these rows are, and what they are not
//!
//! **A batch row records a declared membership.** That is the whole of it.
//!
//! - **It does not submit.** Registering a batch accepts no RunSpec document,
//!   writes nothing to [`crate::run_submissions`] and reserves nothing. A member
//!   at `unsubmitted` means nobody has *told this table* a submission exists,
//!   never that one does not.
//! - **It does not schedule, and it does not enforce its own concurrency.**
//!   [`ConcurrencyPolicy`] is stored because the plan declared it. Nothing here
//!   counts what is in flight, and no executor reads this column in this
//!   release. A `bounded_parallel` ceiling is a recorded intention, not a
//!   throttle.
//! - **A member's progress is a writer's claim, not a reading.** This module
//!   never opens a spool and never joins [`crate::run_index`]. The run index is
//!   the true binding from a submission to the state its run reached; a member
//!   row is whatever the writer that read that index then reported here. It
//!   enforces that the reports form a legal sequence and that the sequence
//!   numbers never go backwards; it cannot enforce that any of them were true.
//! - **It does not store the rolled-up batch state.** See below.
//!
//! # The rolled-up state is not a column
//!
//! `automonique_protocol::batch_runner::roll_up` is a total function of the
//! member states, and `BatchProgress` derives the batch state from it rather
//! than carrying one — its decoder refuses a document whose claimed state
//! contradicts its own members. A column here would be the same field with the
//! same contradiction available and no decoder to catch it: every accepted
//! [`BatchRegistry::advance_member`] would have to rewrite it, and any writer
//! that reached the table around this API would leave a batch claiming
//! `completed` over members that say otherwise.
//!
//! So [`BatchRegistry::batch`] returns the members in ordinal order and the
//! caller rolls up. The one durable copy of that answer is the members
//! themselves, which is the only arrangement in which the answer cannot drift
//! from what it summarizes.
//!
//! # The member lattice
//!
//! [`MemberProgress`] is `automonique_protocol::batch_runner::MemberProgress`:
//! the six run states plus the one a run vocabulary cannot express. The six are
//! [`crate::run_index::RunSpoolState`], reused rather than re-spelled, so this
//! module and the index it mirrors cannot disagree about a word.
//!
//! | from | to | why |
//! |---|---|---|
//! | `unsubmitted` | `ready` | a submission was recorded for the member |
//! | `ready` | `running` | the first event was appended |
//! | `running` | `running` | further events; only `last_sequence` moved |
//! | `running` | `completed` / `failed` / `cancelled` / `timed_out` | the single terminal event |
//!
//! Everything else is [`BatchRegistryError::IllegalTransition`]. Nothing returns
//! to `unsubmitted` or to `ready`, no terminal state is left, and no state
//! transitions to itself except `running`, whose repeat is a writer observing a
//! run that has moved without ending. The `ready -> terminal` jump
//! [`crate::run_index`] refuses is refused here for the reason given there.
//!
//! `unsubmitted -> ready` is the only edge this lattice adds to the index's, and
//! it is the edge that makes a batch member's life expressible: a member exists
//! before its submission does.
//!
//! ## `last_sequence` is bound to the progress
//!
//! `unsubmitted` and `ready` both mean zero spool events — the first because no
//! submission was recorded, the second because none has produced an event yet —
//! so both carry a zero `last_sequence`; every other progress means at least one
//! event, so it carries at least one. That is a database constraint, re-checked
//! on every read, and the exact analogue of the index's `ready`/zero binding
//! extended over the one state the index has no word for. Coupling only
//! `unsubmitted` would admit a member `ready` at sequence seven, which describes
//! a run index row that cannot exist.
//!
//! The coupling is judged against the *request* before the durable row is read,
//! as [`crate::automation_store`] judges its cause coupling, so a caller that
//! reports `ready` at a non-zero sequence learns that whatever revision the row
//! is at ([`BatchRegistryError::SequenceCoupling`]). Beyond it:
//!
//! - a state *change* requires a strictly greater sequence, because the event
//!   that changed the state is itself a new event;
//! - a re-report of the same state admits an equal sequence, because a writer
//!   may observe a run that has not moved; and
//! - `unsubmitted -> ready` is the one change no event causes, so it carries the
//!   same zero sequence on both sides.
//!
//! A backward sequence is [`BatchRegistryError::SequenceRegression`].
//!
//! # Ordinals
//!
//! A member's `ordinal` is its position in the order the batch declared, from
//! zero and contiguous. The order is durable because
//! `ConcurrencyPolicy::Sequential` *names* it — "one member at a time, in the
//! order the plan declares" — so a registry that stored an unordered set would
//! lose the only thing that distinguishes sequential from
//! `BoundedParallel { max_in_flight: 1 }`.
//!
//! Registration is the only writer of ordinals and writes `0..n`, `UNIQUE
//! (batch_id, ordinal)` stops a second writer repeating one, and
//! [`BatchRegistry::batch`] re-checks contiguity on every read: a gap is
//! [`BatchRegistryError::Corrupt`], because a batch missing its third member is
//! a membership nobody declared.
//!
//! # Spellings this module pins by literal
//!
//! This crate depends on `nix` and `rusqlite` and nothing else, so it cannot
//! import the protocol vocabulary it stores. `automonique_protocol::batch_runner`
//! is the authority for all of it, and these are copies:
//!
//! - the two [`ConcurrencyKind`] spellings, `sequential` and `bounded_parallel`,
//!   and the rule that exactly one of them carries a ceiling;
//! - the `unsubmitted` spelling and its seven-word progress vocabulary; and
//! - [`MAX_BATCH_MEMBERS`], [`MAX_BATCH_ID_BYTES`], [`MAX_BATCH_LABEL_BYTES`]
//!   and [`MAX_MEMBER_KEY_BYTES`].
//!
//! `tests/batch_registry.rs` pins every one of them again by literal, so a
//! rename in the protocol crate has to break both this module and that suite —
//! the honest-gap technique [`crate::run_index`] and [`crate::automation_store`]
//! use for the vocabularies they mirror.
//!
//! # Pagination
//!
//! `entry_id` is monotonic in registration order and is the pagination key. A
//! cursor above the highest recorded `entry_id` is
//! [`BatchRegistryError::CursorOutOfRange`] rather than an empty page, because
//! those are different answers: one means "your cursor is gone", the other means
//! "there is nothing to show".
//!
//! A page carries batch rows and not their members: a maximal page of maximal
//! batches would be 512 × 256 member rows, which is a listing that would have to
//! be paged again. A caller that needs one batch's members asks
//! [`BatchRegistry::batch`] for it.
//!
//! `entry_id` is an explicit `INTEGER PRIMARY KEY` rather than the implicit rowid
//! of a `batch_id TEXT PRIMARY KEY` table, for the reason
//! [`crate::automation_store`] gives: SQLite may renumber the rowids of a table
//! with no such alias when it is `VACUUM`ed, and a renumbered rowid is a
//! silently broken cursor.
//!
//! # Storage discipline
//!
//! The registry owns its own SQLite database with its own `user_version`, opened
//! under the same privacy, WAL and `synchronous = FULL` rules as
//! [`crate::Store`], exactly as [`crate::cancel_ledger`], [`crate::run_index`]
//! and [`crate::automation_store`] do. Every mutation is one immediate
//! transaction, revision-checked in the `UPDATE` itself. Every read re-validates
//! the row it loaded rather than trusting the database.
//!
//! Registration writes a batch and all of its members in that one transaction,
//! so a reader after a crash sees the whole membership or no batch at all. A
//! member row that cannot be written discards the batch row with it; there is no
//! state in which a batch exists with part of what it declared, because a
//! partial membership is a batch that would silently under-run.
//!
//! That separation from the rest of the store has a cost, stated here rather
//! than buried: **the run index a member's progress mirrors lives in another
//! database, and there is no transaction spanning the two.** A `member_key`
//! recorded here is not proved to name an accepted submission, and this module
//! cannot check it. The failure that buys is bounded — a batch naming a
//! submission nobody accepted sits at `unsubmitted` forever, which is a batch
//! that never finishes rather than one that finishes wrongly.
//!
//! # Deletion
//!
//! There is none, and no prune. Forgetting a batch would strand the only durable
//! record of what it declared, and a member row outliving its batch would name a
//! membership nothing can reconstruct. Capacity is
//! [`BatchRegistryError::RegistryFull`], never an eviction.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::run_index::RunSpoolState;
use crate::{BUSY_TIMEOUT, StoreError, validate_database_path};

/// The only batch registry schema this build can read and write.
pub const BATCH_REGISTRY_SCHEMA_VERSION: u32 = 1;

/// Largest number of batches any registry will hold.
///
/// Nothing deletes from these tables, so this is a hard ceiling on the lifetime
/// of one database file rather than a high-water mark. It matches
/// [`crate::run_index::MAX_RUN_INDEX_ENTRIES`] in shape and reasoning, not in
/// arithmetic: a batch is not a submission, and one batch may name up to
/// [`MAX_BATCH_MEMBERS`] of them.
pub const MAX_BATCHES: usize = 65_536;

/// Most members one batch may declare.
///
/// Pinned by literal from `automonique_protocol::batch_runner::MAX_BATCH_MEMBERS`,
/// which this crate cannot import. A ceiling on one batch, not on a dataset: a
/// larger dataset is not a larger batch here, it is not representable, which is
/// what "Automonique never accepts unbounded work it cannot retain" prefers to a
/// membership that grows without limit.
pub const MAX_BATCH_MEMBERS: usize = 256;

/// Longest accepted `batch_id`, in bytes.
///
/// Pinned by literal from `automonique_protocol::batch_runner::MAX_BATCH_ID_BYTES`.
pub const MAX_BATCH_ID_BYTES: usize = 128;

/// Longest accepted batch label, in bytes.
///
/// Pinned by literal from `automonique_protocol::batch_runner::MAX_BATCH_LABEL_BYTES`.
pub const MAX_BATCH_LABEL_BYTES: usize = 128;

/// Longest accepted `member_key`, in bytes.
///
/// Pinned by literal from
/// `automonique_protocol::batch_runner::MAX_BATCH_MEMBER_KEY_BYTES`, which is
/// defined there *as* `admin::MAX_RUN_SUBMISSION_KEY_BYTES` rather than as a
/// second number that happens to match it. A member key is the idempotency key
/// of the submission it names, so a key this registry admitted and the admin
/// lane refused would be a batch that could never be submitted.
pub const MAX_MEMBER_KEY_BYTES: usize = 128;

/// Largest page [`BatchRegistry::page`] will return.
pub const MAX_BATCH_PAGE: usize = 512;

/// The grammar all three bounded fields share: non-empty, within their ceiling,
/// no control characters. Identical to the protocol crate's `validate_bounded`,
/// so a value `BatchId`, `BatchLabel` or `BatchMemberKey` accepts is a value
/// this registry stores.
const _: () = assert!(
    MAX_BATCH_ID_BYTES > 0 && MAX_BATCH_LABEL_BYTES > 0 && MAX_MEMBER_KEY_BYTES > 0,
    "a zero ceiling would admit no value at all"
);

/// Schema v1.
///
/// The invariants a second writer must not be able to break are database
/// constraints: one row per `batch_id`, one member per `(batch_id, member_key)`,
/// one member per `(batch_id, ordinal)`, positive revisions, the two closed
/// vocabularies, non-negative sequences and timestamps, the coupling between a
/// concurrency kind and its ceiling, and the coupling between a not-started
/// progress and a zero sequence.
///
/// The identifier grammar, the length bounds, the transition lattice, ordinal
/// contiguity and the agreement between `unsubmitted` and `revision = 1` are
/// deliberately *not* database constraints: they are enforced on write and
/// re-checked on every read, so a row written around this API is refused rather
/// than believed.
///
/// The member foreign key references `batches(batch_id)` rather than
/// `batches(entry_id)`, so a member names its batch by the identity a caller
/// knows; `foreign_keys` is `ON`, and `batch_id` is `UNIQUE`, which is what
/// makes it a legal parent key.
///
/// The concurrency coupling spells `concurrency_max IS NOT NULL` before the
/// range comparisons rather than leaning on them, because SQLite treats a CHECK
/// that evaluates to `NULL` as *satisfied*: `NULL >= 1` is `NULL`, so a
/// `bounded_parallel` row with no ceiling would otherwise pass the very
/// constraint written to refuse it. `tests/batch_registry.rs` drives both halves
/// of the coupling through the raw connection, which is how that hole was found.
const SCHEMA_V1: &str = r#"
CREATE TABLE batches (
    entry_id INTEGER PRIMARY KEY,
    batch_id TEXT NOT NULL UNIQUE,
    label TEXT,
    concurrency TEXT NOT NULL CHECK (
        concurrency IN ('sequential', 'bounded_parallel')
    ),
    concurrency_max INTEGER,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    CHECK (
        (concurrency = 'sequential' AND concurrency_max IS NULL)
        OR (concurrency = 'bounded_parallel'
            AND concurrency_max IS NOT NULL
            AND concurrency_max >= 1 AND concurrency_max <= 256)
    )
) STRICT;

CREATE TABLE batch_members (
    member_entry_id INTEGER PRIMARY KEY,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    member_key TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 256),
    progress TEXT NOT NULL CHECK (
        progress IN (
            'unsubmitted', 'ready', 'running',
            'completed', 'failed', 'cancelled', 'timed_out'
        )
    ),
    last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    UNIQUE (batch_id, member_key),
    UNIQUE (batch_id, ordinal),
    CHECK ((progress IN ('unsubmitted', 'ready')) = (last_sequence = 0))
) STRICT;
"#;

/// A batch registry error with stable refusal categories.
#[derive(Debug)]
pub enum BatchRegistryError {
    /// The registry path or its containing directory is not private and owned.
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
    /// The batch identity is already registered.
    ///
    /// A batch is registered exactly once. Nothing was written, and the recorded
    /// coordinates travel with the refusal so a caller learns what it collided
    /// with without a second read.
    AlreadyRegistered {
        /// Row the batch already occupies.
        entry_id: i64,
        /// Members that batch already declared.
        member_count: usize,
    },
    /// A batch named no member, which is a unit with nothing in it.
    EmptyBatch,
    /// A batch named more members than [`MAX_BATCH_MEMBERS`].
    TooManyMembers {
        /// Most members one batch tracks.
        max_members: usize,
        /// Members the caller supplied.
        actual_members: usize,
    },
    /// A batch named one member key twice.
    ///
    /// Refused, never collapsed: a caller that named a submission twice believes
    /// it asked for something it did not.
    DuplicateMember {
        /// The repeated key.
        key: String,
    },
    /// A concurrency ceiling was zero, which admits no work at all.
    ConcurrencyCeilingZero,
    /// A concurrency ceiling was above what a batch could ever place in flight.
    ///
    /// A ceiling that can never bind is an unbounded policy with a number
    /// written on it.
    ConcurrencyCeilingUnreachable {
        /// Most members one batch tracks.
        max_members: usize,
        /// Ceiling the caller asked for.
        requested: u32,
    },
    /// The referenced durable row does not exist.
    NotFound(&'static str),
    /// The reported progress does not follow the durable one along the lattice.
    IllegalTransition {
        /// Progress the durable row records.
        from: MemberProgress,
        /// Progress the writer reported.
        to: MemberProgress,
    },
    /// A reported sequence disagrees with the progress it accompanies.
    ///
    /// `unsubmitted` and `ready` mean zero spool events and carry a zero
    /// sequence; every other progress carries at least one. A property of the
    /// request alone, so it is judged before the durable row is read.
    SequenceCoupling {
        /// Progress the writer reported.
        progress: MemberProgress,
        /// Sequence the writer reported beside it.
        last_sequence: u64,
    },
    /// The caller's expected revision does not match the durable revision.
    RevisionMismatch {
        /// Revision the caller believed it was advancing.
        expected: u64,
        /// Revision the durable row carries.
        durable: u64,
    },
    /// The reported sequence does not advance past the durable one.
    SequenceRegression {
        /// Sequence the durable row records.
        durable: u64,
        /// Sequence the writer reported.
        supplied: u64,
    },
    /// A page was requested from a cursor above everything recorded.
    ///
    /// An empty page is a different answer and is never reported this way.
    CursorOutOfRange {
        /// Cursor the caller presented.
        supplied: u64,
        /// Highest `entry_id` recorded, or zero when the registry is empty.
        retained_last: u64,
    },
    /// The registry holds its full capacity of batches.
    ///
    /// Registration is refused *before* a row is written. Nothing here evicts.
    RegistryFull {
        /// Capacity of the handle that refused.
        capacity: usize,
    },
    /// A stored row violates an invariant this API can only have written once.
    Corrupt(&'static str),
    /// Filesystem failure while establishing the private registry.
    Io(std::io::Error),
    /// SQLite rejected an operation.
    Sqlite(rusqlite::Error),
}

impl BatchRegistryError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::AlreadyRegistered { .. } => "already_registered",
            Self::EmptyBatch => "empty_batch",
            Self::TooManyMembers { .. } => "too_many_members",
            Self::DuplicateMember { .. } => "duplicate_member",
            Self::ConcurrencyCeilingZero => "concurrency_ceiling_zero",
            Self::ConcurrencyCeilingUnreachable { .. } => "concurrency_ceiling_unreachable",
            Self::NotFound(_) => "not_found",
            Self::IllegalTransition { .. } => "illegal_transition",
            Self::SequenceCoupling { .. } => "sequence_coupling",
            Self::RevisionMismatch { .. } => "revision_mismatch",
            Self::SequenceRegression { .. } => "sequence_regression",
            Self::CursorOutOfRange { .. } => "cursor_out_of_range",
            Self::RegistryFull { .. } => "registry_full",
            Self::Corrupt(_) => "corrupt",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}

impl fmt::Display for BatchRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => {
                write!(formatter, "batch registry path is not private: {reason}")
            }
            Self::SchemaVersion { found, supported } => write!(
                formatter,
                "batch registry schema {found} is unsupported; expected {supported}"
            ),
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::AlreadyRegistered {
                entry_id,
                member_count,
            } => write!(
                formatter,
                "batch is already registered at row {entry_id} with {member_count} members"
            ),
            Self::EmptyBatch => formatter.write_str("a batch names no member"),
            Self::TooManyMembers {
                max_members,
                actual_members,
            } => write!(
                formatter,
                "batch names {actual_members} members; maximum is {max_members}"
            ),
            Self::DuplicateMember { key } => write!(formatter, "batch names member {key} twice"),
            Self::ConcurrencyCeilingZero => {
                formatter.write_str("a concurrency ceiling admits at least one member in flight")
            }
            Self::ConcurrencyCeilingUnreachable {
                max_members,
                requested,
            } => write!(
                formatter,
                "concurrency ceiling {requested} is above the {max_members} members a batch can hold"
            ),
            Self::NotFound(entity) => write!(formatter, "no such {entity}"),
            Self::IllegalTransition { from, to } => write!(
                formatter,
                "member progress {} may not advance to {}",
                from.as_str(),
                to.as_str()
            ),
            Self::SequenceCoupling {
                progress,
                last_sequence,
            } => write!(
                formatter,
                "member progress {} does not admit last_sequence {last_sequence}",
                progress.as_str()
            ),
            Self::RevisionMismatch { expected, durable } => write!(
                formatter,
                "expected revision {expected} but durable revision is {durable}"
            ),
            Self::SequenceRegression { durable, supplied } => write!(
                formatter,
                "last_sequence {supplied} does not advance past the durable {durable}"
            ),
            Self::CursorOutOfRange {
                supplied,
                retained_last,
            } => write!(
                formatter,
                "cursor {supplied} is above the retained entry_id {retained_last}"
            ),
            Self::RegistryFull { capacity } => {
                write!(formatter, "batch registry holds its capacity of {capacity}")
            }
            Self::Corrupt(invariant) => {
                write!(formatter, "stored row violates invariant: {invariant}")
            }
            Self::Io(error) => write!(formatter, "batch registry filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite error: {error}"),
        }
    }
}

impl Error for BatchRegistryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for BatchRegistryError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for BatchRegistryError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// Result of one batch registry operation.
pub type Batched<T> = Result<T, BatchRegistryError>;

/// Which concurrency policy a batch declared.
///
/// Two variants, two spellings, mirroring
/// `automonique_protocol::batch_runner::ConcurrencyKind` — the authority. Held
/// apart from [`ConcurrencyPolicy`] so the stored vocabulary is two closed words
/// and the ceiling sits in its own column rather than inside the word.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConcurrencyKind {
    /// One member at a time, in the order the batch declares.
    Sequential,
    /// Up to a declared ceiling at a time, in no declared order.
    BoundedParallel,
}

impl ConcurrencyKind {
    /// Every kind, in the protocol's declaration order.
    pub const ALL: [Self; 2] = [Self::Sequential, Self::BoundedParallel];

    /// Stable machine-oriented spelling, and the exact stored text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sequential => "sequential",
            Self::BoundedParallel => "bounded_parallel",
        }
    }

    /// Parse the exact stored text, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }

    /// Whether a batch of this kind declares a ceiling.
    ///
    /// Exactly one of the two does, which is the coupling the schema enforces
    /// and every read re-checks.
    #[must_use]
    pub const fn declares_ceiling(self) -> bool {
        matches!(self, Self::BoundedParallel)
    }
}

impl fmt::Display for ConcurrencyKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How many members of a batch may be in flight, and in what order.
///
/// `automonique_protocol::batch_runner::ConcurrencyPolicy`, stored. There is
/// deliberately no variant meaning "unbounded": the only variant admitting more
/// than one member in flight carries a declared ceiling, a zero ceiling is
/// refused rather than read as "no limit", and a ceiling above
/// [`MAX_BATCH_MEMBERS`] is refused because no batch could reach it.
///
/// [`Self::Sequential`] and `BoundedParallel { max_in_flight: 1 }` are not two
/// spellings of one policy: sequential also fixes the order to the batch's,
/// bounded-parallel declares none. They are stored distinctly for that reason.
///
/// The variant is publicly constructible, exactly as the protocol's is, so
/// [`BatchRegistry::register`] re-validates the ceiling rather than trusting
/// that [`Self::bounded_parallel`] produced it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConcurrencyPolicy {
    /// One member at a time, in the order the batch declares.
    Sequential,
    /// Up to `max_in_flight` members at a time, in no declared order.
    BoundedParallel {
        /// How many members may be in flight together.
        max_in_flight: u32,
    },
}

impl ConcurrencyPolicy {
    /// A bounded parallelism.
    ///
    /// # Errors
    ///
    /// Returns [`BatchRegistryError::ConcurrencyCeilingZero`] for a zero
    /// ceiling, which would be a batch that never starts rather than a batch
    /// without limit, and
    /// [`BatchRegistryError::ConcurrencyCeilingUnreachable`] above
    /// [`MAX_BATCH_MEMBERS`].
    pub const fn bounded_parallel(max_in_flight: u32) -> Batched<Self> {
        if max_in_flight == 0 {
            return Err(BatchRegistryError::ConcurrencyCeilingZero);
        }
        if max_in_flight as usize > MAX_BATCH_MEMBERS {
            return Err(BatchRegistryError::ConcurrencyCeilingUnreachable {
                max_members: MAX_BATCH_MEMBERS,
                requested: max_in_flight,
            });
        }
        Ok(Self::BoundedParallel { max_in_flight })
    }

    /// Which kind this is.
    #[must_use]
    pub const fn kind(self) -> ConcurrencyKind {
        match self {
            Self::Sequential => ConcurrencyKind::Sequential,
            Self::BoundedParallel { .. } => ConcurrencyKind::BoundedParallel,
        }
    }

    /// The declared ceiling, when the policy declares one.
    #[must_use]
    pub const fn declared_ceiling(self) -> Option<u32> {
        match self {
            Self::Sequential => None,
            Self::BoundedParallel { max_in_flight } => Some(max_in_flight),
        }
    }

    /// Re-check the ceiling this value carries.
    ///
    /// The kind and the ceiling must agree, which is a property of the value
    /// alone. A value built by [`Self::bounded_parallel`] always passes; one
    /// built by a struct literal may not.
    fn validated(self) -> Batched<Self> {
        match self {
            Self::Sequential => Ok(self),
            Self::BoundedParallel { max_in_flight } => {
                Self::bounded_parallel(max_in_flight).map(|_| self)
            }
        }
    }
}

impl fmt::Display for ConcurrencyPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.declared_ceiling() {
            Some(ceiling) => write!(formatter, "{}({ceiling})", self.kind().as_str()),
            None => formatter.write_str(self.kind().as_str()),
        }
    }
}

/// The spelling for a member no submission has been recorded for.
///
/// Pinned by literal from `automonique_protocol::batch_runner`'s `UNSUBMITTED`,
/// and held apart from the six [`RunSpoolState`] spellings this module reuses.
/// [`MemberProgress::from_spelling`] would silently prefer this word over a run
/// state of the same name, so the assertion below proves there is none.
const UNSUBMITTED: &str = "unsubmitted";

const _: () = {
    let mut index = 0;
    while index < RunSpoolState::ALL.len() {
        // `str` equality is not const, so the bytes are compared by hand. Only
        // equal-length words can collide, and none of the six has this length.
        assert!(
            RunSpoolState::ALL[index].as_str().len() != UNSUBMITTED.len(),
            "the unsubmitted spelling must collide with no run state spelling"
        );
        index += 1;
    }
};

/// Where one member of a batch has got to, as last reported to this registry.
///
/// Seven values: the six [`RunSpoolState`]s, reused rather than re-spelled, plus
/// the one state a run vocabulary cannot express — a member the batch names for
/// which no submission has been recorded at all.
/// [`RunSpoolState::Ready`] is not that state: `ready` means a submission exists
/// and no event has arrived, which presumes a submission happened.
///
/// This is `automonique_protocol::batch_runner::MemberProgress`, shape and all:
/// that type is `Unsubmitted` beside a `Run(RunState)`, and so is this. The six
/// spellings come from [`crate::run_index`], which pins the runner's spool
/// vocabulary for this crate, so a member's progress and the index row it
/// mirrors cannot disagree about a word.
///
/// A value of this type is a claim, recorded by whoever read the durable run
/// index. It is not a reading, and this module has no way to check one.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MemberProgress {
    /// No submission has been recorded for this member.
    Unsubmitted,
    /// A writer reported this state for the member's run.
    Run(RunSpoolState),
}

impl MemberProgress {
    /// Every value, unsubmitted first and then [`RunSpoolState::ALL`] in order.
    pub const ALL: [Self; 7] = [
        Self::Unsubmitted,
        Self::Run(RunSpoolState::Ready),
        Self::Run(RunSpoolState::Running),
        Self::Run(RunSpoolState::Completed),
        Self::Run(RunSpoolState::Failed),
        Self::Run(RunSpoolState::Cancelled),
        Self::Run(RunSpoolState::TimedOut),
    ];

    /// Stable machine-oriented spelling, and the exact stored text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsubmitted => UNSUBMITTED,
            Self::Run(state) => state.as_str(),
        }
    }

    /// Parse the exact stored text, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        if value == UNSUBMITTED {
            return Some(Self::Unsubmitted);
        }
        RunSpoolState::from_spelling(value).map(Self::Run)
    }

    /// The run state, when a submission was recorded.
    #[must_use]
    pub const fn run_state(self) -> Option<RunSpoolState> {
        match self {
            Self::Unsubmitted => None,
            Self::Run(state) => Some(state),
        }
    }

    /// Whether this member has ended.
    ///
    /// `unsubmitted` is not terminal: a member that was never submitted has not
    /// finished, it has not begun.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        match self {
            Self::Unsubmitted => false,
            Self::Run(state) => state.is_terminal(),
        }
    }

    /// Whether this member has yet to produce a spool event.
    ///
    /// `unsubmitted` and `ready` are the two values carrying no evidence any
    /// work started, and are exactly the two that carry a zero `last_sequence`.
    #[must_use]
    pub const fn has_not_started(self) -> bool {
        matches!(self, Self::Unsubmitted | Self::Run(RunSpoolState::Ready))
    }

    /// Whether a member at this progress may next be reported at `next`.
    ///
    /// The whole lattice, in one place: `unsubmitted -> ready` when a submission
    /// is recorded, and then exactly [`RunSpoolState::may_advance_to`]. Nothing
    /// returns to `unsubmitted`, and no terminal state is left.
    #[must_use]
    pub const fn may_advance_to(self, next: Self) -> bool {
        match (self, next) {
            (Self::Unsubmitted, Self::Run(RunSpoolState::Ready)) => true,
            (Self::Unsubmitted, _) | (Self::Run(_), Self::Unsubmitted) => false,
            (Self::Run(from), Self::Run(to)) => from.may_advance_to(to),
        }
    }
}

impl fmt::Display for MemberProgress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One batch presented for registration.
///
/// The initial progress is not a field: registration always writes every member
/// at `unsubmitted` with a zero sequence, because a batch that has just been
/// declared has submitted nothing. A caller that has already submitted a member
/// registers first and advances second.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchRegistration<'a> {
    /// Durable batch identity. The unique key.
    pub batch_id: &'a str,
    /// Operator-supplied name, when there is one. Recorded verbatim.
    pub label: Option<&'a str>,
    /// The declared concurrency policy. Recorded, never enforced here.
    pub concurrency: ConcurrencyPolicy,
    /// Member keys in declaration order, which becomes their ordinals.
    ///
    /// Non-empty, at most [`MAX_BATCH_MEMBERS`], and free of repeats. The order
    /// is kept because [`ConcurrencyPolicy::Sequential`] names it.
    pub members: &'a [&'a str],
    /// When the batch was declared, in caller-supplied milliseconds.
    pub now_ms: i64,
}

/// One writer's report that a member has moved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberAdvance<'a> {
    /// Batch the member belongs to.
    pub batch_id: &'a str,
    /// Member whose row is being advanced. Scoped to `batch_id`: the same key
    /// in another batch is another row and is left alone.
    pub member_key: &'a str,
    /// Durable revision the caller believes it is advancing. `1` at
    /// registration, and one higher after every accepted advance.
    pub expected_revision: u64,
    /// Progress the writer observed. Must follow the durable progress along the
    /// lattice; see [`MemberProgress::may_advance_to`].
    pub new_progress: MemberProgress,
    /// Highest spool sequence the writer observed. Zero exactly when the
    /// progress has not started.
    pub last_sequence: u64,
    /// When the writer observed it, in caller-supplied milliseconds.
    pub now_ms: i64,
}

/// Durable identity of one registered batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchReceipt {
    /// Row identity, monotonic in registration order. The pagination key.
    pub entry_id: i64,
    /// Members written, all at `unsubmitted`, at ordinals `0..member_count`.
    pub member_count: usize,
    /// Revision the batch row now carries.
    pub revision: u64,
    /// Instant the batch row records.
    pub created_at_ms: i64,
}

/// Durable identity and fencing revision of one advanced member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberReceipt {
    /// Member row identity.
    pub member_entry_id: i64,
    /// Position of the member in its batch's declaration order.
    pub ordinal: u32,
    /// Progress the row now records.
    pub progress: MemberProgress,
    /// Sequence the row now records.
    pub last_sequence: u64,
    /// Revision the row now carries. The next advance must expect this.
    pub revision: u64,
    /// Instant the row now records.
    pub updated_at_ms: i64,
}

/// Validated `batches` row.
///
/// There is no rolled-up batch state here, and deliberately so: it is derived
/// from the members by `automonique_protocol::batch_runner::roll_up`, and a
/// column would be a second copy of an answer that can drift from what it
/// summarizes. [`BatchView::members`] is what the caller rolls up.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchRecord {
    /// Row identity, monotonic in registration order.
    pub entry_id: i64,
    /// Durable batch identity.
    pub batch_id: String,
    /// The operator-supplied label, when the batch was given one.
    pub label: Option<String>,
    /// The declared concurrency policy.
    pub concurrency: ConcurrencyPolicy,
    /// When the batch was registered.
    pub created_at_ms: i64,
    /// `1` for every row this release writes; see the module documentation.
    pub revision: u64,
}

/// Validated `batch_members` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberRecord {
    /// Member row identity.
    pub member_entry_id: i64,
    /// Batch this member belongs to.
    pub batch_id: String,
    /// Submission idempotency key this member names.
    pub member_key: String,
    /// Position in the batch's declaration order, from zero.
    pub ordinal: u32,
    /// The last progress a writer reported. Never a reading of a run.
    pub progress: MemberProgress,
    /// The last sequence a writer reported. Zero exactly when the progress has
    /// not started.
    pub last_sequence: u64,
    /// When the last report was recorded.
    pub updated_at_ms: i64,
    /// `1` at registration, and one higher after every accepted advance.
    pub revision: u64,
}

/// One batch and the whole membership it declared.
///
/// The members are in ordinal order, contiguous from zero, and complete: this
/// type is never produced from a partial read, because a partial membership
/// would roll up to a batch state nobody could act on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchView {
    /// The batch row.
    pub batch: BatchRecord,
    /// Its members, ordinal `0..n`, oldest position first.
    pub members: Vec<MemberRecord>,
}

impl BatchView {
    /// The members' progresses, in ordinal order.
    ///
    /// The exact slice `automonique_protocol::batch_runner::roll_up` consumes.
    /// This module deliberately does not call it — see the module documentation
    /// on why the rolled-up state is the protocol's to compute and not a column
    /// here — but it hands a caller the argument without a second walk.
    #[must_use]
    pub fn progresses(&self) -> Vec<MemberProgress> {
        self.members.iter().map(|member| member.progress).collect()
    }
}

/// One bounded page of batch rows, ordered by `entry_id`.
///
/// Members are not carried; see the module documentation on why a page of
/// batches is not a page of memberships.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchPage {
    /// Rows above the requested cursor, oldest first.
    pub entries: Vec<BatchRecord>,
    /// Cursor to present for the next page, or `None` when this page is the end
    /// of the query.
    ///
    /// Set only when a further row was seen, so an exhausted listing is
    /// distinguishable from one that merely filled its page.
    pub next_cursor: Option<u64>,
}

/// The window of `entry_id` values this registry still holds.
///
/// `first` is `1` in this release because nothing deletes. It is reported rather
/// than assumed so a caller keeps saying something true if that ever changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedBatchRange {
    /// Lowest `entry_id` still recorded.
    pub first: u64,
    /// Highest `entry_id` recorded.
    pub last: u64,
}

/// Durable registry of batches and their members.
#[derive(Debug)]
pub struct BatchRegistry {
    connection: Connection,
    path: PathBuf,
    capacity: usize,
}

impl BatchRegistry {
    /// Open or initialize a registry inside an existing private directory.
    ///
    /// The parent must be owned by the effective user and deny all group and
    /// other access. Existing paths must be regular, owned, non-symlinks.
    /// Capacity is [`MAX_BATCHES`].
    ///
    /// # Errors
    ///
    /// Returns [`BatchRegistryError::InsecurePath`] for an unsafe path,
    /// [`BatchRegistryError::SchemaVersion`] for a foreign or future database,
    /// and the underlying I/O or SQLite failure otherwise.
    pub fn open(path: impl AsRef<Path>) -> Batched<Self> {
        Self::open_with_capacity(path, MAX_BATCHES)
    }

    /// Open a registry with a lowered capacity.
    ///
    /// `capacity` counts batches, not members. It must be between one and
    /// [`MAX_BATCHES`], and it is a property of this handle rather than of the
    /// database: opening an existing registry under a capacity below its batch
    /// count refuses further registrations with
    /// [`BatchRegistryError::RegistryFull`] while advances and reads keep
    /// working, because neither adds a batch.
    ///
    /// # Errors
    ///
    /// As [`BatchRegistry::open`], plus [`BatchRegistryError::InvalidField`] for
    /// a capacity outside the range.
    pub fn open_with_capacity(path: impl AsRef<Path>, capacity: usize) -> Batched<Self> {
        if capacity == 0 || capacity > MAX_BATCHES {
            return Err(BatchRegistryError::InvalidField("capacity"));
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
            return Err(BatchRegistryError::Sqlite(rusqlite::Error::InvalidQuery));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        initialize_or_validate_schema(&mut connection)?;

        Ok(Self {
            connection,
            path: path.to_path_buf(),
            capacity,
        })
    }

    /// Exact path opened by this registry.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Batch capacity of this handle.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Record a batch and its whole declared membership, every member
    /// `unsubmitted`.
    ///
    /// One immediate transaction writes the batch row and all `n` member rows,
    /// so a reader after a crash sees the whole membership or no batch at all.
    /// A member row that cannot be written takes the batch row down with it:
    /// there is no state in which a batch exists holding part of what it
    /// declared.
    ///
    /// Every refusal that is a property of the request alone — the field
    /// grammar, the ceiling, the member count, a repeated key — is made before
    /// the transaction opens, so those callers learn what is wrong with their
    /// request regardless of what the registry holds.
    ///
    /// A batch is registered exactly once. A second registration is
    /// [`BatchRegistryError::AlreadyRegistered`] and writes nothing — not even
    /// when it names the same members, because a re-registration would reset
    /// rows a writer may already have advanced, and silently discarding a
    /// batch's recorded progress is the one thing these tables exist to prevent.
    ///
    /// # Errors
    ///
    /// Returns [`BatchRegistryError::InvalidField`] for a malformed field,
    /// [`BatchRegistryError::EmptyBatch`] for a batch with no member,
    /// [`BatchRegistryError::TooManyMembers`] above [`MAX_BATCH_MEMBERS`],
    /// [`BatchRegistryError::DuplicateMember`] for a repeated key,
    /// [`BatchRegistryError::ConcurrencyCeilingZero`] or
    /// [`BatchRegistryError::ConcurrencyCeilingUnreachable`] for an incoherent
    /// policy, [`BatchRegistryError::AlreadyRegistered`] for a duplicate
    /// identity, [`BatchRegistryError::RegistryFull`] at capacity, and
    /// [`BatchRegistryError::Corrupt`] when the existing row it must compare
    /// against is not one this API could have written.
    pub fn register(&mut self, registration: BatchRegistration<'_>) -> Batched<BatchReceipt> {
        validate_bounded(registration.batch_id, "batch_id", MAX_BATCH_ID_BYTES)?;
        if let Some(label) = registration.label {
            validate_bounded(label, "label", MAX_BATCH_LABEL_BYTES)?;
        }
        validate_time(registration.now_ms, "now_ms")?;
        let concurrency = registration.concurrency.validated()?;

        let members = registration.members;
        if members.is_empty() {
            return Err(BatchRegistryError::EmptyBatch);
        }
        if members.len() > MAX_BATCH_MEMBERS {
            return Err(BatchRegistryError::TooManyMembers {
                max_members: MAX_BATCH_MEMBERS,
                actual_members: members.len(),
            });
        }
        for key in members {
            validate_bounded(key, "member_key", MAX_MEMBER_KEY_BYTES)?;
        }
        // Sorted-window scan rather than a nested loop, and a refusal rather
        // than a collapse: a caller that named a submission twice believes it
        // asked for something it did not. The database `UNIQUE (batch_id,
        // member_key)` is the backstop for a writer that reaches the table
        // around this API, not the primary guard.
        let mut ordered: Vec<&str> = members.to_vec();
        ordered.sort_unstable();
        if let Some(pair) = ordered.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(BatchRegistryError::DuplicateMember {
                key: pair[0].to_owned(),
            });
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(recorded) = read_batch_row(&transaction, registration.batch_id)? {
            return Err(BatchRegistryError::AlreadyRegistered {
                entry_id: recorded.entry_id,
                member_count: count_members(&transaction, registration.batch_id)?,
            });
        }
        let live = count_batches(&transaction)?;
        if live >= self.capacity {
            return Err(BatchRegistryError::RegistryFull {
                capacity: self.capacity,
            });
        }
        transaction.execute(
            "INSERT INTO batches
             (batch_id, label, concurrency, concurrency_max, created_at_ms, revision)
             VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            params![
                registration.batch_id,
                registration.label,
                concurrency.kind().as_str(),
                concurrency.declared_ceiling(),
                registration.now_ms,
            ],
        )?;
        let entry_id = transaction.last_insert_rowid();
        for (ordinal, key) in members.iter().enumerate() {
            let ordinal =
                i64::try_from(ordinal).map_err(|_| BatchRegistryError::InvalidField("ordinal"))?;
            transaction.execute(
                "INSERT INTO batch_members
                 (batch_id, member_key, ordinal, progress, last_sequence, updated_at_ms, revision)
                 VALUES (?1, ?2, ?3, ?4, 0, ?5, 1)",
                params![
                    registration.batch_id,
                    key,
                    ordinal,
                    MemberProgress::Unsubmitted.as_str(),
                    registration.now_ms,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(BatchReceipt {
            entry_id,
            member_count: members.len(),
            revision: 1,
            created_at_ms: registration.now_ms,
        })
    }

    /// Record that a writer observed one member at a new progress.
    ///
    /// Revision-checked and lattice-checked in one immediate transaction. The
    /// guard is repeated in the `UPDATE` itself, so a row that moved between the
    /// read and the write cannot be overwritten even if a caller reached here
    /// with a revision that happened to match.
    ///
    /// Member-scoped in both directions: only the named member's row is touched,
    /// and only within the named batch. Its siblings keep their progress, their
    /// sequence and their revision, and a member of the same key in another
    /// batch is a different row entirely.
    ///
    /// What this call establishes is that a writer *said* the member is at
    /// `new_progress` at `last_sequence`. It does not establish that the run
    /// index agrees; this module never reads one.
    ///
    /// # Errors
    ///
    /// Returns [`BatchRegistryError::InvalidField`] for a malformed field,
    /// [`BatchRegistryError::SequenceCoupling`] for a sequence that disagrees
    /// with the progress beside it, [`BatchRegistryError::NotFound`] for an
    /// unregistered batch or member,
    /// [`BatchRegistryError::RevisionMismatch`] for a stale expected revision,
    /// [`BatchRegistryError::IllegalTransition`] for a progress that does not
    /// follow the durable one, [`BatchRegistryError::SequenceRegression`] for a
    /// sequence that does not advance, and [`BatchRegistryError::Corrupt`] when
    /// the stored row is not one this API could have written.
    pub fn advance_member(&mut self, advance: MemberAdvance<'_>) -> Batched<MemberReceipt> {
        validate_bounded(advance.batch_id, "batch_id", MAX_BATCH_ID_BYTES)?;
        validate_bounded(advance.member_key, "member_key", MAX_MEMBER_KEY_BYTES)?;
        validate_time(advance.now_ms, "now_ms")?;
        if advance.expected_revision == 0 {
            return Err(BatchRegistryError::InvalidField("expected_revision"));
        }
        // A property of the request alone, judged before the durable row is
        // read, as `automation_store` judges its cause coupling: a caller that
        // reports `ready` at a non-zero sequence learns that whatever revision
        // the row is at.
        if advance.new_progress.has_not_started() != (advance.last_sequence == 0) {
            return Err(BatchRegistryError::SequenceCoupling {
                progress: advance.new_progress,
                last_sequence: advance.last_sequence,
            });
        }
        let next_sequence = to_db_u64(advance.last_sequence, "last_sequence")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // The batch is looked up first so a caller that mistyped an identity
        // learns which of the two it got wrong.
        if read_batch_row(&transaction, advance.batch_id)?.is_none() {
            return Err(BatchRegistryError::NotFound("batch"));
        }
        let record = read_member_row(&transaction, advance.batch_id, advance.member_key)?
            .ok_or(BatchRegistryError::NotFound("batch member"))?;
        if record.revision != advance.expected_revision {
            return Err(BatchRegistryError::RevisionMismatch {
                expected: advance.expected_revision,
                durable: record.revision,
            });
        }
        if !record.progress.may_advance_to(advance.new_progress) {
            return Err(BatchRegistryError::IllegalTransition {
                from: record.progress,
                to: advance.new_progress,
            });
        }
        // A state change is caused by an event, so it carries a strictly greater
        // sequence, and a re-report of `running` admits an equal one because a
        // writer may observe a run that has not moved. `unsubmitted -> ready` is
        // the one change no event causes — a submission was recorded, nothing
        // ran — so it carries the same zero sequence on both sides, which the
        // coupling above has already pinned.
        let advanced = if record.progress == advance.new_progress {
            advance.last_sequence >= record.last_sequence
        } else if advance.new_progress.has_not_started() {
            advance.last_sequence == record.last_sequence
        } else {
            advance.last_sequence > record.last_sequence
        };
        if !advanced {
            return Err(BatchRegistryError::SequenceRegression {
                durable: record.last_sequence,
                supplied: advance.last_sequence,
            });
        }
        let next_revision = record
            .revision
            .checked_add(1)
            .ok_or(BatchRegistryError::InvalidField("revision"))?;
        let changed = transaction.execute(
            "UPDATE batch_members
             SET progress = ?3, last_sequence = ?4, updated_at_ms = ?5, revision = ?6
             WHERE member_entry_id = ?1 AND revision = ?2",
            params![
                record.member_entry_id,
                to_db_u64(record.revision, "revision")?,
                advance.new_progress.as_str(),
                next_sequence,
                advance.now_ms,
                to_db_u64(next_revision, "revision")?,
            ],
        )?;
        if changed != 1 {
            // The row was read inside this immediate transaction, so nothing
            // else can have moved it; a disagreement means the stored row is not
            // what this API writes.
            return Err(BatchRegistryError::Corrupt("member_advance"));
        }
        transaction.commit()?;
        Ok(MemberReceipt {
            member_entry_id: record.member_entry_id,
            ordinal: record.ordinal,
            progress: advance.new_progress,
            last_sequence: advance.last_sequence,
            revision: next_revision,
            updated_at_ms: advance.now_ms,
        })
    }

    /// One batch and its whole membership, in ordinal order.
    ///
    /// The batch row and its members are read in one transaction, so an advance
    /// committed between the two cannot produce a view of a membership that
    /// never existed.
    ///
    /// The rolled-up batch state is not returned because it is not stored:
    /// [`BatchView::progresses`] is the argument
    /// `automonique_protocol::batch_runner::roll_up` takes, and the caller rolls
    /// up. See the module documentation.
    ///
    /// # Errors
    ///
    /// Returns [`BatchRegistryError::InvalidField`] for a malformed identity and
    /// [`BatchRegistryError::Corrupt`] for a row this API could not have
    /// written, including a membership that is empty or whose ordinals are not
    /// contiguous from zero.
    pub fn batch(&self, batch_id: &str) -> Batched<Option<BatchView>> {
        validate_bounded(batch_id, "batch_id", MAX_BATCH_ID_BYTES)?;
        let transaction = self.connection.unchecked_transaction()?;
        let Some(batch) = read_batch_row(&transaction, batch_id)? else {
            transaction.rollback()?;
            return Ok(None);
        };
        let mut statement = transaction.prepare(&format!(
            "SELECT {MEMBER_COLUMNS} FROM batch_members
             WHERE batch_id = ?1 ORDER BY ordinal"
        ))?;
        let rows = statement.query_map([batch_id], raw_member)?;
        let mut members = Vec::new();
        for raw in rows {
            members.push(validated_member(raw?)?);
        }
        drop(statement);
        transaction.rollback()?;

        // Registration is the only writer of a membership and writes `0..n`, so
        // anything else is a row this API could not have produced. A batch that
        // lost its third member is a membership nobody declared, and a caller
        // that rolled it up would report a batch state over the wrong set.
        if members.is_empty() {
            return Err(corrupt("batch_members"));
        }
        if members.len() > MAX_BATCH_MEMBERS {
            return Err(corrupt("batch_members"));
        }
        for (position, member) in members.iter().enumerate() {
            let expected =
                u32::try_from(position).map_err(|_| BatchRegistryError::Corrupt("ordinal"))?;
            if member.ordinal != expected {
                return Err(corrupt("ordinal"));
            }
        }
        Ok(Some(BatchView { batch, members }))
    }

    /// The validated row one member of one batch holds, if any.
    ///
    /// Answers `None` both for a member no batch declared and for a batch that
    /// does not exist: this is a lookup, and a caller that needs to tell the two
    /// apart asks [`BatchRegistry::batch`].
    ///
    /// # Errors
    ///
    /// Returns [`BatchRegistryError::InvalidField`] for a malformed identity and
    /// [`BatchRegistryError::Corrupt`] for a row this API could not have
    /// written.
    pub fn member(&self, batch_id: &str, member_key: &str) -> Batched<Option<MemberRecord>> {
        validate_bounded(batch_id, "batch_id", MAX_BATCH_ID_BYTES)?;
        validate_bounded(member_key, "member_key", MAX_MEMBER_KEY_BYTES)?;
        read_member_row(&self.connection, batch_id, member_key)
    }

    /// One bounded page of every batch, ordered by `entry_id`, oldest first.
    ///
    /// `cursor` names the row to resume *after*; pass `0` to start at the
    /// beginning, and to advance, pass [`BatchPage::next_cursor`]. `limit` must
    /// be between one and [`MAX_BATCH_PAGE`].
    ///
    /// The page is read inside one transaction together with the bound the
    /// cursor is judged against, so a concurrent registration cannot make the
    /// cursor look out of range for a page that was about to be served.
    ///
    /// # Errors
    ///
    /// Returns [`BatchRegistryError::InvalidField`] for a limit outside its
    /// range, [`BatchRegistryError::CursorOutOfRange`] for a cursor above
    /// everything recorded, and [`BatchRegistryError::Corrupt`] for a row this
    /// API could not have written.
    pub fn page(&self, cursor: u64, limit: usize) -> Batched<BatchPage> {
        if limit == 0 || limit > MAX_BATCH_PAGE {
            return Err(BatchRegistryError::InvalidField("limit"));
        }
        let after = to_db_u64(cursor, "cursor")?;
        let page = i64::try_from(limit).map_err(|_| BatchRegistryError::InvalidField("limit"))?;
        let lookahead = page
            .checked_add(1)
            .ok_or(BatchRegistryError::InvalidField("limit"))?;

        let transaction = self.connection.unchecked_transaction()?;
        let highest: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(entry_id), 0) FROM batches",
            [],
            |row| row.get(0),
        )?;
        let retained_last = from_db_u64(highest, "entry_id").map_err(|_| corrupt("entry_id"))?;
        if cursor > retained_last {
            return Err(BatchRegistryError::CursorOutOfRange {
                supplied: cursor,
                retained_last,
            });
        }
        let mut statement = transaction.prepare(&format!(
            "SELECT {BATCH_COLUMNS} FROM batches
             WHERE entry_id > ?1 ORDER BY entry_id LIMIT ?2"
        ))?;
        let rows = statement.query_map(params![after, lookahead], raw_batch)?;
        let mut entries = Vec::new();
        for raw in rows {
            entries.push(validated_batch(raw?)?);
        }
        drop(statement);
        transaction.rollback()?;

        let next_cursor = if entries.len() > limit {
            entries.truncate(limit);
            let last = entries.last().ok_or(corrupt("entry_id"))?.entry_id;
            Some(from_db_u64(last, "entry_id").map_err(|_| corrupt("entry_id"))?)
        } else {
            None
        };
        Ok(BatchPage {
            entries,
            next_cursor,
        })
    }

    /// The window of `entry_id` values this registry holds, or `None` when
    /// empty.
    ///
    /// An empty registry has no retained window, and reporting `(0, 0)` would
    /// name a row no writer produced.
    ///
    /// # Errors
    ///
    /// Returns [`BatchRegistryError::Corrupt`] for a stored bound outside the
    /// representable range.
    pub fn retained_range(&self) -> Batched<Option<RetainedBatchRange>> {
        let bounds: (Option<i64>, Option<i64>) = self.connection.query_row(
            "SELECT MIN(entry_id), MAX(entry_id) FROM batches",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        match bounds {
            (Some(first), Some(last)) => {
                let first = checked_row_id(first, "entry_id")?;
                let last = checked_row_id(last, "entry_id")?;
                if last < first {
                    return Err(corrupt("entry_id"));
                }
                Ok(Some(RetainedBatchRange {
                    first: from_db_u64(first, "entry_id").map_err(|_| corrupt("entry_id"))?,
                    last: from_db_u64(last, "entry_id").map_err(|_| corrupt("entry_id"))?,
                }))
            }
            (None, None) => Ok(None),
            _ => Err(corrupt("entry_id")),
        }
    }

    /// Count durable batches.
    ///
    /// # Errors
    ///
    /// Returns the SQLite failure, or [`BatchRegistryError::Corrupt`] for a
    /// count outside the representable range.
    pub fn batch_count(&self) -> Batched<usize> {
        count_batches(&self.connection)
    }
}

struct RawBatch {
    entry_id: i64,
    batch_id: String,
    label: Option<String>,
    concurrency: String,
    concurrency_max: Option<i64>,
    created_at_ms: i64,
    revision: i64,
}

const BATCH_COLUMNS: &str = "entry_id, batch_id, label, concurrency, \
                             concurrency_max, created_at_ms, revision";

fn raw_batch(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawBatch> {
    Ok(RawBatch {
        entry_id: row.get(0)?,
        batch_id: row.get(1)?,
        label: row.get(2)?,
        concurrency: row.get(3)?,
        concurrency_max: row.get(4)?,
        created_at_ms: row.get(5)?,
        revision: row.get(6)?,
    })
}

struct RawMember {
    member_entry_id: i64,
    batch_id: String,
    member_key: String,
    ordinal: i64,
    progress: String,
    last_sequence: i64,
    updated_at_ms: i64,
    revision: i64,
}

const MEMBER_COLUMNS: &str = "member_entry_id, batch_id, member_key, ordinal, \
                              progress, last_sequence, updated_at_ms, revision";

fn raw_member(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawMember> {
    Ok(RawMember {
        member_entry_id: row.get(0)?,
        batch_id: row.get(1)?,
        member_key: row.get(2)?,
        ordinal: row.get(3)?,
        progress: row.get(4)?,
        last_sequence: row.get(5)?,
        updated_at_ms: row.get(6)?,
        revision: row.get(7)?,
    })
}

/// Re-derive a [`BatchRecord`] from a stored row, refusing anything this API
/// could not have written.
///
/// Two cross-column invariants are checked here as well as the per-column ones,
/// because a database CHECK protects the table from a second writer while this
/// function protects callers from a row that got in anyway:
///
/// - a concurrency kind and a stored ceiling imply each other, and the ceiling
///   is within the range a batch could reach; and
/// - the revision is exactly one, because registration is the only writer of a
///   batch row in this release and no operation moves it. When a batch-level
///   transition lands it raises [`BATCH_REGISTRY_SCHEMA_VERSION`] and relaxes
///   this; until then a higher revision is a row nothing here produced.
fn validated_batch(raw: RawBatch) -> Batched<BatchRecord> {
    let kind = ConcurrencyKind::from_spelling(&raw.concurrency).ok_or(corrupt("concurrency"))?;
    let concurrency = match (kind.declares_ceiling(), raw.concurrency_max) {
        (false, None) => ConcurrencyPolicy::Sequential,
        (true, Some(ceiling)) => {
            let ceiling = u32::try_from(ceiling).map_err(|_| corrupt("concurrency_max"))?;
            ConcurrencyPolicy::bounded_parallel(ceiling).map_err(|_| corrupt("concurrency_max"))?
        }
        _ => return Err(corrupt("concurrency_max")),
    };
    let label = match raw.label {
        Some(label) => Some(checked_bounded(label, "label", MAX_BATCH_LABEL_BYTES)?),
        None => None,
    };
    let revision = from_db_u64(raw.revision, "revision").map_err(|_| corrupt("revision"))?;
    if revision != 1 {
        return Err(corrupt("revision"));
    }
    Ok(BatchRecord {
        entry_id: checked_row_id(raw.entry_id, "entry_id")?,
        batch_id: checked_bounded(raw.batch_id, "batch_id", MAX_BATCH_ID_BYTES)?,
        label,
        concurrency,
        created_at_ms: checked_time(raw.created_at_ms, "created_at_ms")?,
        revision,
    })
}

/// Re-derive a [`MemberRecord`] from a stored row, refusing anything this API
/// could not have written.
///
/// Three cross-column invariants are checked here as well as the per-column
/// ones:
///
/// - a progress that has not started and a zero `last_sequence` imply each
///   other;
/// - `unsubmitted` implies `revision = 1`, because registration is the only
///   writer of `unsubmitted` and no transition returns to it; and
/// - the ordinal is within the membership ceiling. Its contiguity is a property
///   of the whole membership rather than of one row, so it is checked where the
///   membership is assembled, in [`BatchRegistry::batch`].
fn validated_member(raw: RawMember) -> Batched<MemberRecord> {
    let progress = MemberProgress::from_spelling(&raw.progress).ok_or(corrupt("progress"))?;
    let last_sequence =
        from_db_u64(raw.last_sequence, "last_sequence").map_err(|_| corrupt("last_sequence"))?;
    if progress.has_not_started() != (last_sequence == 0) {
        return Err(corrupt("last_sequence"));
    }
    let revision = from_db_u64(raw.revision, "revision").map_err(|_| corrupt("revision"))?;
    if revision == 0 {
        return Err(corrupt("revision"));
    }
    if progress == MemberProgress::Unsubmitted && revision != 1 {
        return Err(corrupt("revision"));
    }
    let ordinal = u32::try_from(raw.ordinal).map_err(|_| corrupt("ordinal"))?;
    if ordinal as usize >= MAX_BATCH_MEMBERS {
        return Err(corrupt("ordinal"));
    }
    Ok(MemberRecord {
        member_entry_id: checked_row_id(raw.member_entry_id, "member_entry_id")?,
        batch_id: checked_bounded(raw.batch_id, "batch_id", MAX_BATCH_ID_BYTES)?,
        member_key: checked_bounded(raw.member_key, "member_key", MAX_MEMBER_KEY_BYTES)?,
        ordinal,
        progress,
        last_sequence,
        updated_at_ms: checked_time(raw.updated_at_ms, "updated_at_ms")?,
        revision,
    })
}

fn read_batch_row(connection: &Connection, batch_id: &str) -> Batched<Option<BatchRecord>> {
    let raw = connection
        .query_row(
            &format!("SELECT {BATCH_COLUMNS} FROM batches WHERE batch_id = ?1"),
            [batch_id],
            raw_batch,
        )
        .optional()?;
    raw.map(validated_batch).transpose()
}

fn read_member_row(
    connection: &Connection,
    batch_id: &str,
    member_key: &str,
) -> Batched<Option<MemberRecord>> {
    let raw = connection
        .query_row(
            &format!(
                "SELECT {MEMBER_COLUMNS} FROM batch_members
                 WHERE batch_id = ?1 AND member_key = ?2"
            ),
            [batch_id, member_key],
            raw_member,
        )
        .optional()?;
    raw.map(validated_member).transpose()
}

fn count_batches(connection: &Connection) -> Batched<usize> {
    let count: i64 = connection.query_row("SELECT count(*) FROM batches", [], |row| row.get(0))?;
    usize::try_from(count).map_err(|_| corrupt("batch_count"))
}

fn count_members(connection: &Connection, batch_id: &str) -> Batched<usize> {
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM batch_members WHERE batch_id = ?1",
        [batch_id],
        |row| row.get(0),
    )?;
    usize::try_from(count).map_err(|_| corrupt("member_count"))
}

fn secure_path(path: &Path) -> Batched<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => BatchRegistryError::Io(io),
        other => BatchRegistryError::InsecurePath(other.to_string()),
    })
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Batched<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == BATCH_REGISTRY_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(BatchRegistryError::SchemaVersion {
            found: version,
            supported: BATCH_REGISTRY_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(BatchRegistryError::SchemaVersion {
            found: 0,
            supported: BATCH_REGISTRY_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", BATCH_REGISTRY_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

/// The grammar `automonique_protocol::primitives`' `validate_bounded` applies to
/// a batch identity, a label and a member key alike: non-empty, within its own
/// ceiling, no control characters.
fn validate_bounded(value: &str, field: &'static str, max_bytes: usize) -> Batched<()> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(BatchRegistryError::InvalidField(field));
    }
    Ok(())
}

fn validate_time(value: i64, field: &'static str) -> Batched<()> {
    if value < 0 {
        return Err(BatchRegistryError::InvalidField(field));
    }
    Ok(())
}

fn checked_bounded(value: String, field: &'static str, max_bytes: usize) -> Batched<String> {
    validate_bounded(&value, field, max_bytes).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_time(value: i64, field: &'static str) -> Batched<i64> {
    validate_time(value, field).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_row_id(value: i64, field: &'static str) -> Batched<i64> {
    if value <= 0 {
        return Err(corrupt(field));
    }
    Ok(value)
}

/// Map a validation field onto its stable corruption invariant name.
///
/// Read paths never reuse `InvalidField`: a bad stored row is corruption the
/// caller cannot have caused, and the two must not be confused.
const fn corrupt(field: &'static str) -> BatchRegistryError {
    BatchRegistryError::Corrupt(field)
}

fn to_db_u64(value: u64, field: &'static str) -> Batched<i64> {
    i64::try_from(value).map_err(|_| BatchRegistryError::InvalidField(field))
}

fn from_db_u64(value: i64, field: &'static str) -> Batched<u64> {
    u64::try_from(value).map_err(|_| BatchRegistryError::InvalidField(field))
}
