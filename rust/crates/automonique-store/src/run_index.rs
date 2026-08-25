// SPDX-License-Identifier: Elastic-2.0

//! Durable index from an accepted submission to its run and the last run state
//! a writer reported for it.
//!
//! [`crate::run_submissions`] takes custody of a RunSpec document under an
//! idempotency key and records `submission_id -> (run_id, spec_digest,
//! document, accepted_at_ms)`. Its `state` column has the closed vocabulary
//! `('accepted')` and always will while nothing executes: that column is
//! *custody*, not progress. Ask it "what is run X doing?" and it cannot answer,
//! because it never knew.
//!
//! The run's own state lives in the runner's durable spool as
//! `automonique_runner::spool::RunState`, one directory per run, on a machine
//! that a listing query has no business walking. This module is the durable
//! join between the two. One row per submission:
//!
//! ```text
//! submission_id -> (run_id, spool_state, last_sequence, updated_at_ms, revision)
//! ```
//!
//! `automonique_protocol::runs_api` names exactly this gap under "The seam this
//! leaves open": a handler for `ListRuns` needs "the submission log's real
//! retained window", "a join from `run_submissions` to the runner spool that
//! produces [`RunSummary::state`]", and an ordering it can page over. The first
//! is [`RunIndex::retained_range`], the second is [`RunIndexRecord::spool_state`],
//! and the third is `index_id`.
//!
//! There is no execution here, no spool IO, and no clock: callers supply every
//! identifier, sequence and timestamp, so restarts stay deterministic and tests
//! do not depend on an ambient clock.
//!
//! # What a row is, and what it is not
//!
//! **A row records the last state a writer reported. It is not an observation
//! of the spool.** This module never opens a spool, never reads an event, and
//! cannot recompute `state_from_events`. It enforces that the reported states
//! form a legal sequence and that the reported sequence numbers never go
//! backwards; it cannot enforce that any of them were true. Binding the report
//! to the spool is the writer's duty, and the writer is the daemon's execution
//! lane.
//!
//! **That lane does not exist in this release.** Nothing in this product
//! appends to a spool on behalf of a submitted run, so nothing calls
//! [`RunIndex::advance_state`] in production and every durable row sits at
//! `ready` forever. The lattice below is enforced from the first release rather
//! than added with the lane, so the lane cannot quietly introduce a transition
//! the spool cannot produce — but until it lands, a `ready` row means "a
//! submission was registered", not "a run is waiting to start".
//!
//! **A row is not authority.** Registering an index entry admits nothing,
//! reserves nothing and schedules nothing. It is a lookup table.
//!
//! # The state lattice
//!
//! [`RunSpoolState`] carries the six spellings `automonique_runner::spool::RunState`
//! defines, and the transitions this module admits are the ones that crate's
//! `state_from_events` can produce as a spool grows:
//!
//! | from | to | why |
//! |---|---|---|
//! | `ready` | `running` | the first event was appended |
//! | `running` | `running` | further events; only `last_sequence` moved |
//! | `running` | `completed` / `failed` / `cancelled` / `timed_out` | the single terminal event, discriminated by its payload |
//!
//! Everything else is [`RunIndexError::IllegalTransition`]. In particular a
//! terminal state is terminal: the spool refuses any append after its terminal
//! event (`SpoolError::AlreadyTerminal`), so a row that has ended can never
//! honestly be told it is running again, and `ready` is only ever written by
//! [`RunIndex::register`] — no transition returns to it.
//!
//! ## The one jump the spool admits and this index refuses
//!
//! `state_from_events` reads a spool whose *only* event is terminal as terminal
//! directly, without ever having been `running`. `Spool::append` does not
//! require a `Started` event first, so the type admits that history. Both lanes
//! that actually write runner spools append `Started` before anything else —
//! `automonique_runner::backend` records it with the pid it observed before it
//! begins waiting, and `automonique_runner::supervise` opens its view spool
//! with it — so `ready -> terminal` is not a history the product produces.
//!
//! This module refuses it anyway, and the cost is stated rather than hidden: a
//! writer that polls a spool infrequently enough to miss the `running` phase
//! must report the intervening `running` step before the terminal one, and
//! `last_sequence` makes that report checkable rather than free. If a lane is
//! ever built that appends a bare terminal event, this refusal is what will
//! stop it, and the schema version is where that decision gets revisited.
//!
//! ## `last_sequence` is bound to the state
//!
//! `ready` means zero events, so `last_sequence` is zero; every other state
//! means at least one event, so `last_sequence` is at least one. That is a
//! database constraint, re-checked on every read. Beyond it:
//!
//! - a state *change* requires a strictly greater sequence, because the event
//!   that changed the state is itself a new event; and
//! - a re-report of the same state admits an equal sequence, because a writer
//!   may observe a run that has not moved.
//!
//! A backward sequence is [`RunIndexError::SequenceRegression`] in both cases.
//!
//! # Pagination, and the retained window
//!
//! `index_id` is monotonic in registration order, and a page is a bounded run
//! of rows above a cursor. A cursor above the highest recorded `index_id` is
//! [`RunIndexError::CursorOutOfRange`] rather than an empty page, because those
//! are different answers: `automonique_protocol::runs_api` maps the first onto
//! `resync_required` and the second onto an empty listing, and a store that
//! blurred them would let a UI mistake "your cursor is gone" for "there is
//! nothing to show". This module does not model resync; it reports the range it
//! holds and lets the handler decide.
//!
//! [`RunIndex::retained_range`] answers what is retained, and today its floor is
//! always `1` because **nothing here deletes**. It is a function rather than a
//! constant so a handler that builds
//! `automonique_protocol::journal::RetainedRange` from it does not hard-code a
//! fact a later retention policy would falsify.
//!
//! # Storage discipline
//!
//! The index owns its own SQLite database with its own `user_version`, opened
//! under the same privacy, WAL and `synchronous = FULL` rules as
//! [`crate::Store`], exactly as [`crate::cancel_ledger`],
//! [`crate::run_submissions`] and [`crate::generation_audit`] do. Every mutation
//! is one immediate transaction. Every read re-validates the row it loaded
//! rather than trusting the database.
//!
//! That separation has a cost, stated here rather than buried: **the submission
//! this row binds lives in another database, and there is no transaction
//! spanning the two.** A `submission_id` recorded here is not proved to exist in
//! [`crate::run_submissions`], and this module cannot check it; a foreign key is
//! not available across files. Registering after the submission commits is the
//! caller's ordering duty. The failure it buys is a bounded one — an index row
//! naming a submission nobody accepted lists a run whose document cannot be
//! read, which is a broken listing rather than a lost document.
//!
//! # Deletion
//!
//! There is none, and no prune. Forgetting a row would strand the only durable
//! binding from a submission to the run it became, and a listing that silently
//! dropped rows would answer `ListRuns` with a lie rather than a refusal.
//! Capacity is [`RunIndexError::IndexFull`], never an eviction.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::{StoreError, validate_database_path};

/// The only run index schema this build can read and write.
pub const RUN_INDEX_SCHEMA_VERSION: u32 = 1;

/// Largest number of entries any index will hold.
///
/// Nothing deletes from this table, so this is a hard ceiling on the lifetime of
/// one database file rather than a high-water mark. It matches
/// [`crate::run_submissions::MAX_RUN_SUBMISSIONS`], because one submission
/// registers at most one entry.
pub const MAX_RUN_INDEX_ENTRIES: usize = 65_536;

/// Longest accepted `run_id`, in bytes.
///
/// The same identifier grammar [`crate::Store`] and [`crate::run_submissions`]
/// use: non-empty, at most this many bytes, no control characters.
pub const MAX_IDENTIFIER_BYTES: usize = 256;

/// Largest page [`RunIndex::page`] and [`RunIndex::page_in_states`] will return.
pub const MAX_INDEX_PAGE: usize = 512;

/// Schema v1.
///
/// The invariants a second writer must not be able to break are database
/// constraints: one row per submission, a positive submission identity, the
/// closed six-word state vocabulary, a non-negative sequence, and the binding
/// between `ready` and a zero sequence.
///
/// The identifier grammar, the length bound, the transition lattice and the
/// agreement between `ready` and `revision = 1` are deliberately *not* database
/// constraints: they are enforced on write and re-checked on every read, so a
/// row written around this API is refused rather than believed.
const SCHEMA_V1: &str = r#"
CREATE TABLE run_index (
    index_id INTEGER PRIMARY KEY,
    submission_id INTEGER NOT NULL UNIQUE CHECK (submission_id >= 1),
    run_id TEXT NOT NULL,
    spool_state TEXT NOT NULL CHECK (
        spool_state IN ('ready', 'running', 'completed', 'failed', 'cancelled', 'timed_out')
    ),
    last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    CHECK ((spool_state = 'ready') = (last_sequence = 0))
) STRICT;

CREATE INDEX run_index_by_run ON run_index(run_id, index_id);

CREATE INDEX run_index_by_state ON run_index(spool_state, index_id);
"#;

/// A run index error with stable refusal categories.
#[derive(Debug)]
pub enum RunIndexError {
    /// The index path or its containing directory is not private and owned.
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
    /// The submission already has an index entry.
    ///
    /// A submission is registered exactly once. Nothing was written, and the
    /// recorded coordinates travel with the refusal so a caller learns which
    /// run the submission is already bound to without a second read.
    AlreadyRegistered {
        /// Row the submission already occupies.
        index_id: i64,
        /// Run identity that row binds.
        run_id: String,
    },
    /// The referenced durable row does not exist.
    NotFound(&'static str),
    /// The reported state does not follow the durable one along the lattice.
    IllegalTransition {
        /// State the durable row records.
        from: RunSpoolState,
        /// State the writer reported.
        to: RunSpoolState,
    },
    /// The caller's expected revision does not match the durable revision.
    RevisionMismatch {
        /// Revision the caller believed it was advancing.
        expected: u64,
        /// Revision the durable row carries.
        durable: u64,
    },
    /// The reported sequence does not advance past the durable one.
    ///
    /// A state change requires a strictly greater sequence; a re-report of the
    /// same state admits an equal one. Neither admits a backward sequence.
    SequenceRegression {
        /// Sequence the durable row records.
        durable: u64,
        /// Sequence the writer reported.
        supplied: u64,
    },
    /// A page was requested from a cursor above everything recorded.
    ///
    /// This is the refusal `automonique_protocol::runs_api` maps onto
    /// `resync_required`. An empty page is a different answer and is never
    /// reported this way.
    CursorOutOfRange {
        /// Cursor the caller presented.
        supplied: u64,
        /// Highest `index_id` recorded, or zero when the index is empty.
        retained_last: u64,
    },
    /// The index holds its full capacity of entries.
    ///
    /// Registration is refused *before* a row is written. Nothing here evicts.
    IndexFull {
        /// Capacity of the handle that refused.
        capacity: usize,
    },
    /// A stored row violates an invariant this API can only have written once.
    Corrupt(&'static str),
    /// Filesystem failure while establishing the private index.
    Io(std::io::Error),
    /// SQLite rejected an operation.
    Sqlite(rusqlite::Error),
}

impl RunIndexError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::AlreadyRegistered { .. } => "already_registered",
            Self::NotFound(_) => "not_found",
            Self::IllegalTransition { .. } => "illegal_transition",
            Self::RevisionMismatch { .. } => "revision_mismatch",
            Self::SequenceRegression { .. } => "sequence_regression",
            Self::CursorOutOfRange { .. } => "cursor_out_of_range",
            Self::IndexFull { .. } => "index_full",
            Self::Corrupt(_) => "corrupt",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}

impl fmt::Display for RunIndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => {
                write!(formatter, "run index path is not private: {reason}")
            }
            Self::SchemaVersion { found, supported } => write!(
                formatter,
                "run index schema {found} is unsupported; expected {supported}"
            ),
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::AlreadyRegistered { index_id, run_id } => write!(
                formatter,
                "submission is already indexed at row {index_id} for run {run_id}"
            ),
            Self::NotFound(entity) => write!(formatter, "no such {entity}"),
            Self::IllegalTransition { from, to } => write!(
                formatter,
                "run state {} may not advance to {}",
                from.as_str(),
                to.as_str()
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
                "cursor {supplied} is above the retained index_id {retained_last}"
            ),
            Self::IndexFull { capacity } => {
                write!(formatter, "run index holds its capacity of {capacity}")
            }
            Self::Corrupt(invariant) => {
                write!(formatter, "stored row violates invariant: {invariant}")
            }
            Self::Io(error) => write!(formatter, "run index filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite error: {error}"),
        }
    }
}

impl Error for RunIndexError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for RunIndexError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for RunIndexError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// Result of one run index operation.
pub type Indexed<T> = Result<T, RunIndexError>;

/// The state one run is in, as last reported to this index.
///
/// Six variants, six spellings, mirroring `automonique_runner::spool::RunState`
/// — the authority for both the vocabulary and the terminal discrimination its
/// `state_from_events` performs. This crate does not depend on the runner, so
/// the spellings are pinned by literal here and again in `tests/run_index.rs`.
/// `automonique_protocol::runs_api::RunState` pins the same six on the wire
/// side; the two pins are independent on purpose, so a rename has to break both.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RunSpoolState {
    /// Accepted, with no event recorded yet.
    Ready,
    /// At least one event recorded and no terminal event.
    Running,
    /// Ended with a terminal event reporting completion.
    Completed,
    /// Ended with a terminal event this build reads as failure.
    Failed,
    /// Ended with a terminal event reporting cancellation.
    Cancelled,
    /// Ended with a terminal event reporting a deadline.
    TimedOut,
}

impl RunSpoolState {
    /// Every state, in the spool's declaration order.
    pub const ALL: [Self; 6] = [
        Self::Ready,
        Self::Running,
        Self::Completed,
        Self::Failed,
        Self::Cancelled,
        Self::TimedOut,
    ];

    /// Stable machine-oriented spelling, and the exact stored text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
        }
    }

    /// Parse the exact stored text, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == value)
    }

    /// Whether the run has ended.
    ///
    /// The spool reaches exactly one terminal event and refuses every append
    /// after it, so these four states are the ones a row can never leave.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::TimedOut
        )
    }

    /// Whether a spool in this state can next be observed in `next`.
    ///
    /// The whole lattice, in one place: `ready -> running`, `running -> running`
    /// as events accumulate, and `running -> ` any terminal state. Nothing
    /// returns to `ready`, no terminal state is left, and `ready` never jumps
    /// straight to a terminal state — see this module's documentation for the
    /// one spool history that admits that jump and why it is refused here.
    #[must_use]
    pub const fn may_advance_to(self, next: Self) -> bool {
        match self {
            Self::Ready => matches!(next, Self::Running),
            Self::Running => next.is_terminal() || matches!(next, Self::Running),
            Self::Completed | Self::Failed | Self::Cancelled | Self::TimedOut => false,
        }
    }
}

impl fmt::Display for RunSpoolState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One accepted submission presented for indexing.
///
/// The initial state is not a field: registration always writes `ready` at
/// sequence zero, because a submission that has not been executed has no
/// events. A writer that has already observed progress registers first and
/// advances second.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunIndexEntry<'a> {
    /// Durable identity of the [`crate::run_submissions`] row this binds.
    ///
    /// Monotonic in acceptance order there, and the unique key here. This
    /// module cannot verify the row exists; see the module documentation.
    pub submission_id: i64,
    /// Run identity the accepted document claimed.
    ///
    /// Recorded as the submitter declared it. Not unique: nothing stops two
    /// submissions naming one run, exactly as in [`crate::run_submissions`].
    pub run_id: &'a str,
    /// When the entry was registered, in caller-supplied milliseconds.
    pub registered_at_ms: i64,
}

/// One writer's report that a run has moved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateAdvance {
    /// Submission whose row is being advanced.
    pub submission_id: i64,
    /// Durable revision the caller believes it is advancing. `1` at
    /// registration, and one higher after every accepted advance.
    pub expected_revision: u64,
    /// State the writer observed. Must follow the durable state along the
    /// lattice; see [`RunSpoolState::may_advance_to`].
    pub new_state: RunSpoolState,
    /// Highest spool sequence the writer observed.
    pub last_sequence: u64,
    /// When the writer observed it, in caller-supplied milliseconds.
    pub now_ms: i64,
}

/// Durable identity and fencing revision of one registered or advanced entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunIndexReceipt {
    /// Row identity, monotonic in registration order. The pagination key.
    pub index_id: i64,
    /// Submission this row binds.
    pub submission_id: i64,
    /// State the row now records.
    pub spool_state: RunSpoolState,
    /// Sequence the row now records.
    pub last_sequence: u64,
    /// Revision the row now carries. The next advance must expect this.
    pub revision: u64,
    /// Instant the row now records.
    pub updated_at_ms: i64,
}

/// Validated `run_index` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunIndexRecord {
    /// Row identity, monotonic in registration order.
    pub index_id: i64,
    /// Submission this row binds.
    pub submission_id: i64,
    /// Run identity the submission claimed.
    pub run_id: String,
    /// The last state a writer reported. Never an observation of the spool.
    pub spool_state: RunSpoolState,
    /// The last sequence a writer reported. Zero exactly when `ready`.
    pub last_sequence: u64,
    /// When the last report was recorded.
    pub updated_at_ms: i64,
    /// `1` at registration, and one higher after every accepted advance.
    pub revision: u64,
}

/// One bounded page of index rows, ordered by `index_id`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunIndexPage {
    /// Rows above the requested cursor, oldest first.
    pub entries: Vec<RunIndexRecord>,
    /// Cursor to present for the next page, or `None` when this page is the
    /// end of the query.
    ///
    /// Set only when a further matching row was seen, so an exhausted listing
    /// is distinguishable from one that merely filled its page.
    pub next_cursor: Option<u64>,
}

/// The window of `index_id` values this index still holds.
///
/// `first` is `1` in this release because nothing deletes. It is reported
/// rather than assumed so a caller that builds
/// `automonique_protocol::journal::RetainedRange` from it keeps saying
/// something true if that ever changes. Both fields are `u64` because both are
/// at least one, which makes the conversion from SQLite's signed rowid total.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedIndexRange {
    /// Lowest `index_id` still recorded.
    pub first: u64,
    /// Highest `index_id` recorded.
    pub last: u64,
}

/// Durable index from submission to run and last reported state.
#[derive(Debug)]
pub struct RunIndex {
    connection: Connection,
    path: PathBuf,
    capacity: usize,
}

impl RunIndex {
    /// Open or initialize an index inside an existing private directory.
    ///
    /// The parent must be owned by the effective user and deny all group and
    /// other access. Existing paths must be regular, owned, non-symlinks.
    /// Capacity is [`MAX_RUN_INDEX_ENTRIES`].
    ///
    /// # Errors
    ///
    /// Returns [`RunIndexError::InsecurePath`] for an unsafe path,
    /// [`RunIndexError::SchemaVersion`] for a foreign or future database, and
    /// the underlying I/O or SQLite failure otherwise.
    pub fn open(path: impl AsRef<Path>) -> Indexed<Self> {
        Self::open_with_capacity(path, MAX_RUN_INDEX_ENTRIES)
    }

    /// Open an index with a lowered capacity.
    ///
    /// `capacity` must be between one and [`MAX_RUN_INDEX_ENTRIES`]. It is a
    /// property of this handle, not of the database: opening an existing index
    /// under a capacity below its row count refuses further registrations with
    /// [`RunIndexError::IndexFull`] while advances and reads keep working,
    /// because neither adds a row.
    ///
    /// # Errors
    ///
    /// As [`RunIndex::open`], plus [`RunIndexError::InvalidField`] for a
    /// capacity outside the range.
    pub fn open_with_capacity(path: impl AsRef<Path>, capacity: usize) -> Indexed<Self> {
        if capacity == 0 || capacity > MAX_RUN_INDEX_ENTRIES {
            return Err(RunIndexError::InvalidField("capacity"));
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

    /// Exact path opened by this index.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Entry capacity of this handle.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Bind one accepted submission to its run, at `ready`.
    ///
    /// One immediate transaction, so a reader after a crash sees the whole row
    /// or no row.
    ///
    /// A submission is registered exactly once. A second registration is
    /// [`RunIndexError::AlreadyRegistered`] and writes nothing — not even when
    /// it names the same run, because a re-registration would reset a row a
    /// writer may already have advanced, and silently discarding a run's
    /// recorded progress is the one thing this table exists to prevent.
    ///
    /// # Errors
    ///
    /// Returns [`RunIndexError::InvalidField`] for a malformed field,
    /// [`RunIndexError::AlreadyRegistered`] for a duplicate submission,
    /// [`RunIndexError::IndexFull`] at capacity, and
    /// [`RunIndexError::Corrupt`] when the existing row it must compare against
    /// is not one this API could have written.
    pub fn register(&mut self, entry: RunIndexEntry<'_>) -> Indexed<RunIndexReceipt> {
        validate_submission_id(entry.submission_id)?;
        validate_identifier(entry.run_id, "run_id")?;
        validate_time(entry.registered_at_ms, "registered_at_ms")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(recorded) = read_by_submission(&transaction, entry.submission_id)? {
            return Err(RunIndexError::AlreadyRegistered {
                index_id: recorded.index_id,
                run_id: recorded.run_id,
            });
        }
        let live = count_entries(&transaction)?;
        if live >= self.capacity {
            return Err(RunIndexError::IndexFull {
                capacity: self.capacity,
            });
        }
        transaction.execute(
            "INSERT INTO run_index
             (submission_id, run_id, spool_state, last_sequence, updated_at_ms, revision)
             VALUES (?1, ?2, ?3, 0, ?4, 1)",
            params![
                entry.submission_id,
                entry.run_id,
                RunSpoolState::Ready.as_str(),
                entry.registered_at_ms,
            ],
        )?;
        let index_id = transaction.last_insert_rowid();
        transaction.commit()?;
        Ok(RunIndexReceipt {
            index_id,
            submission_id: entry.submission_id,
            spool_state: RunSpoolState::Ready,
            last_sequence: 0,
            revision: 1,
            updated_at_ms: entry.registered_at_ms,
        })
    }

    /// Record that a writer observed the run in a new state.
    ///
    /// Revision-checked and lattice-checked in one immediate transaction. The
    /// guard is repeated in the `UPDATE` itself, so a row that moved between
    /// the read and the write cannot be overwritten even if a caller reached
    /// here with a revision that happened to match.
    ///
    /// What this call establishes is that a writer *said* the run is in
    /// `new_state` at `last_sequence`. It does not establish that the spool
    /// agrees; this module never reads one.
    ///
    /// # Errors
    ///
    /// Returns [`RunIndexError::NotFound`] for an unregistered submission,
    /// [`RunIndexError::RevisionMismatch`] for a stale expected revision,
    /// [`RunIndexError::IllegalTransition`] for a state that does not follow
    /// the durable one, [`RunIndexError::SequenceRegression`] for a sequence
    /// that does not advance, [`RunIndexError::InvalidField`] for a malformed
    /// field, and [`RunIndexError::Corrupt`] when the stored row is not one
    /// this API could have written.
    pub fn advance_state(&mut self, advance: StateAdvance) -> Indexed<RunIndexReceipt> {
        validate_submission_id(advance.submission_id)?;
        validate_time(advance.now_ms, "now_ms")?;
        if advance.expected_revision == 0 {
            return Err(RunIndexError::InvalidField("expected_revision"));
        }
        let next_sequence = to_db_u64(advance.last_sequence, "last_sequence")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = read_by_submission(&transaction, advance.submission_id)?
            .ok_or(RunIndexError::NotFound("run index entry"))?;
        if record.revision != advance.expected_revision {
            return Err(RunIndexError::RevisionMismatch {
                expected: advance.expected_revision,
                durable: record.revision,
            });
        }
        if !record.spool_state.may_advance_to(advance.new_state) {
            return Err(RunIndexError::IllegalTransition {
                from: record.spool_state,
                to: advance.new_state,
            });
        }
        // A state change is caused by an event, so it carries a strictly
        // greater sequence. A re-report of `running` may carry an equal one: a
        // writer is allowed to observe a run that has not moved.
        //
        // A zero sequence needs no separate refusal. Only a `ready` row carries
        // one, `ready` is the lattice's only source, and every destination is a
        // change, so the strict rule below already refuses it — which is why
        // the stored `ready`/zero binding can be a database CHECK rather than a
        // second write-path rule that could drift from this one.
        let advanced = if record.spool_state == advance.new_state {
            advance.last_sequence >= record.last_sequence
        } else {
            advance.last_sequence > record.last_sequence
        };
        if !advanced {
            return Err(RunIndexError::SequenceRegression {
                durable: record.last_sequence,
                supplied: advance.last_sequence,
            });
        }
        let next_revision = record
            .revision
            .checked_add(1)
            .ok_or(RunIndexError::InvalidField("revision"))?;
        let changed = transaction.execute(
            "UPDATE run_index
             SET spool_state = ?3, last_sequence = ?4, updated_at_ms = ?5, revision = ?6
             WHERE index_id = ?1 AND revision = ?2",
            params![
                record.index_id,
                to_db_u64(record.revision, "revision")?,
                advance.new_state.as_str(),
                next_sequence,
                advance.now_ms,
                to_db_u64(next_revision, "revision")?,
            ],
        )?;
        if changed != 1 {
            // The row was read inside this immediate transaction, so nothing
            // else can have moved it; a disagreement means the stored row is
            // not what this API writes.
            return Err(RunIndexError::Corrupt("state_advance"));
        }
        transaction.commit()?;
        Ok(RunIndexReceipt {
            index_id: record.index_id,
            submission_id: record.submission_id,
            spool_state: advance.new_state,
            last_sequence: advance.last_sequence,
            revision: next_revision,
            updated_at_ms: advance.now_ms,
        })
    }

    /// The validated row one submission binds, if any.
    ///
    /// # Errors
    ///
    /// Returns [`RunIndexError::InvalidField`] for a malformed submission
    /// identity and [`RunIndexError::Corrupt`] for a row this API could not
    /// have written.
    pub fn entry(&self, submission_id: i64) -> Indexed<Option<RunIndexRecord>> {
        validate_submission_id(submission_id)?;
        read_by_submission(&self.connection, submission_id)
    }

    /// Every entry recorded against one run identity, oldest first.
    ///
    /// A list rather than a single row: `run_id` is not unique here, because it
    /// is not unique in [`crate::run_submissions`] either. Two submissions may
    /// name one run, and answering with only one of them would hide the other.
    ///
    /// # Errors
    ///
    /// As [`RunIndex::entry`], for the identifier.
    pub fn by_run_id(&self, run_id: &str) -> Indexed<Vec<RunIndexRecord>> {
        validate_identifier(run_id, "run_id")?;
        let mut statement = self.connection.prepare(&format!(
            "SELECT {RECORD_COLUMNS} FROM run_index WHERE run_id = ?1 ORDER BY index_id"
        ))?;
        let rows = statement.query_map([run_id], raw_record)?;
        let mut records = Vec::new();
        for raw in rows {
            records.push(validated_record(raw?)?);
        }
        Ok(records)
    }

    /// One bounded page of every entry, ordered by `index_id`, oldest first.
    ///
    /// `cursor` names the row to resume *after*; pass `0` to start at the
    /// beginning, and to advance, pass [`RunIndexPage::next_cursor`]. `limit`
    /// must be between one and [`MAX_INDEX_PAGE`].
    ///
    /// # Errors
    ///
    /// Returns [`RunIndexError::InvalidField`] for a limit outside its range,
    /// [`RunIndexError::CursorOutOfRange`] for a cursor above everything
    /// recorded, and [`RunIndexError::Corrupt`] for a row this API could not
    /// have written.
    pub fn page(&self, cursor: u64, limit: usize) -> Indexed<RunIndexPage> {
        self.read_page(cursor, limit, None)
    }

    /// One bounded page restricted to a set of states.
    ///
    /// This is the `ListRuns` state filter. `states` must be non-empty and free
    /// of repeats — the two conditions
    /// `automonique_protocol::runs_api::RunsApiError` calls `StateFilterEmpty`
    /// and `StateFilterRepeats` — because a filter that admits nothing is a
    /// query with no answer, and a repeated state is a caller mistake this
    /// module refuses rather than silently folds.
    ///
    /// The cursor is judged against the whole index, not against the filtered
    /// subset: a cursor is a position in the listing order, and a filter that
    /// excluded the row it names must not turn a resumable cursor into a
    /// refusal.
    ///
    /// A filter selects rows; it never hides one. A stored state outside the
    /// six-word vocabulary matches no filter, so such a row is selected anyway
    /// and refused as [`RunIndexError::Corrupt`] — a filtered listing and an
    /// unfiltered one answer a corrupt table identically.
    ///
    /// # Errors
    ///
    /// As [`RunIndex::page`], plus [`RunIndexError::InvalidField`] for an empty
    /// or repeating state filter.
    pub fn page_in_states(
        &self,
        cursor: u64,
        limit: usize,
        states: &[RunSpoolState],
    ) -> Indexed<RunIndexPage> {
        if states.is_empty() {
            return Err(RunIndexError::InvalidField("states"));
        }
        for (position, state) in states.iter().enumerate() {
            if states[..position].contains(state) {
                return Err(RunIndexError::InvalidField("states"));
            }
        }
        self.read_page(cursor, limit, Some(states))
    }

    /// The window of `index_id` values this index holds, or `None` when empty.
    ///
    /// An empty index has no retained window, and reporting `(0, 0)` would name
    /// a row no writer produced. A caller building a protocol retained range
    /// for an empty index is answering a different question — there is nothing
    /// to resume within — and this type makes it decide.
    ///
    /// # Errors
    ///
    /// Returns [`RunIndexError::Corrupt`] for a stored bound outside the
    /// representable range.
    pub fn retained_range(&self) -> Indexed<Option<RetainedIndexRange>> {
        let bounds: (Option<i64>, Option<i64>) = self.connection.query_row(
            "SELECT MIN(index_id), MAX(index_id) FROM run_index",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        match bounds {
            (Some(first), Some(last)) => {
                let first = checked_row_id(first, "index_id")?;
                let last = checked_row_id(last, "index_id")?;
                if last < first {
                    return Err(RunIndexError::Corrupt("index_id"));
                }
                Ok(Some(RetainedIndexRange {
                    first: from_db_u64(first, "index_id")
                        .map_err(|_| RunIndexError::Corrupt("index_id"))?,
                    last: from_db_u64(last, "index_id")
                        .map_err(|_| RunIndexError::Corrupt("index_id"))?,
                }))
            }
            (None, None) => Ok(None),
            _ => Err(RunIndexError::Corrupt("index_id")),
        }
    }

    /// Count durable entries.
    ///
    /// # Errors
    ///
    /// Returns the SQLite failure, or [`RunIndexError::Corrupt`] for a count
    /// outside the representable range.
    pub fn entry_count(&self) -> Indexed<usize> {
        count_entries(&self.connection)
    }

    /// Read one page, optionally restricted to a set of states.
    ///
    /// The page is read inside one transaction together with the bound the
    /// cursor is judged against, so a concurrent registration cannot make the
    /// cursor look out of range for a page that was about to be served.
    fn read_page(
        &self,
        cursor: u64,
        limit: usize,
        states: Option<&[RunSpoolState]>,
    ) -> Indexed<RunIndexPage> {
        if limit == 0 || limit > MAX_INDEX_PAGE {
            return Err(RunIndexError::InvalidField("limit"));
        }
        let after = to_db_u64(cursor, "cursor")?;
        let page = i64::try_from(limit).map_err(|_| RunIndexError::InvalidField("limit"))?;
        let lookahead = page
            .checked_add(1)
            .ok_or(RunIndexError::InvalidField("limit"))?;

        let transaction = self.connection.unchecked_transaction()?;
        let highest: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(index_id), 0) FROM run_index",
            [],
            |row| row.get(0),
        )?;
        let retained_last =
            from_db_u64(highest, "index_id").map_err(|_| RunIndexError::Corrupt("index_id"))?;
        if cursor > retained_last {
            return Err(RunIndexError::CursorOutOfRange {
                supplied: cursor,
                retained_last,
            });
        }

        // The filter is rendered as SQL literals rather than bound parameters
        // because its members are a closed enum whose spellings are fixed
        // lowercase ASCII words from `RunSpoolState::as_str`; there is no
        // caller-controlled text on this path.
        //
        // The second disjunct is what stops a filter from *hiding* a row: a
        // stored state outside the whole vocabulary matches no filter, so a
        // `WHERE spool_state IN (...)` alone would drop a corrupt row from a
        // filtered listing while the unfiltered listing refused it. Selecting
        // those rows too means `validated_record` sees them and every listing
        // answers a corrupt table the same way.
        let filter = states.map_or_else(String::new, |states| {
            format!(
                " AND (spool_state IN ({}) OR spool_state NOT IN ({}))",
                state_literals(states),
                state_literals(&RunSpoolState::ALL)
            )
        });
        let mut statement = transaction.prepare(&format!(
            "SELECT {RECORD_COLUMNS} FROM run_index
             WHERE index_id > ?1{filter}
             ORDER BY index_id LIMIT ?2"
        ))?;
        let rows = statement.query_map(params![after, lookahead], raw_record)?;
        let mut entries = Vec::new();
        for raw in rows {
            entries.push(validated_record(raw?)?);
        }
        drop(statement);
        transaction.rollback()?;

        let next_cursor = if entries.len() > limit {
            entries.truncate(limit);
            let last = entries
                .last()
                .ok_or(RunIndexError::Corrupt("index_id"))?
                .index_id;
            Some(from_db_u64(last, "index_id").map_err(|_| RunIndexError::Corrupt("index_id"))?)
        } else {
            None
        };
        Ok(RunIndexPage {
            entries,
            next_cursor,
        })
    }
}

/// Render a set of states as a comma-separated SQL literal list.
///
/// Safe by construction: every spelling comes from [`RunSpoolState::as_str`],
/// which returns one of six fixed lowercase ASCII words.
fn state_literals(states: &[RunSpoolState]) -> String {
    states
        .iter()
        .map(|state| format!("'{}'", state.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

struct RawRecord {
    index_id: i64,
    submission_id: i64,
    run_id: String,
    spool_state: String,
    last_sequence: i64,
    updated_at_ms: i64,
    revision: i64,
}

const RECORD_COLUMNS: &str =
    "index_id, submission_id, run_id, spool_state, last_sequence, updated_at_ms, revision";

fn raw_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRecord> {
    Ok(RawRecord {
        index_id: row.get(0)?,
        submission_id: row.get(1)?,
        run_id: row.get(2)?,
        spool_state: row.get(3)?,
        last_sequence: row.get(4)?,
        updated_at_ms: row.get(5)?,
        revision: row.get(6)?,
    })
}

/// Re-derive a [`RunIndexRecord`] from a stored row, refusing anything this API
/// could not have written.
///
/// Three cross-column invariants are checked here as well as the per-column
/// ones, because a database CHECK protects the table from a second writer while
/// this function protects callers from a row that got in anyway:
///
/// - `ready` and a zero `last_sequence` imply each other;
/// - `ready` implies `revision = 1`, because registration is the only writer of
///   `ready` and no transition returns to it; and
/// - `index_id` and `submission_id` are positive, because durable identities
///   start at one.
fn validated_record(raw: RawRecord) -> Indexed<RunIndexRecord> {
    let spool_state = RunSpoolState::from_spelling(&raw.spool_state)
        .ok_or(RunIndexError::Corrupt("spool_state"))?;
    let last_sequence =
        from_db_u64(raw.last_sequence, "last_sequence").map_err(|_| corrupt("last_sequence"))?;
    if (spool_state == RunSpoolState::Ready) != (last_sequence == 0) {
        return Err(corrupt("last_sequence"));
    }
    let revision = from_db_u64(raw.revision, "revision").map_err(|_| corrupt("revision"))?;
    if revision == 0 {
        return Err(corrupt("revision"));
    }
    if spool_state == RunSpoolState::Ready && revision != 1 {
        return Err(corrupt("revision"));
    }
    Ok(RunIndexRecord {
        index_id: checked_row_id(raw.index_id, "index_id")?,
        submission_id: checked_row_id(raw.submission_id, "submission_id")?,
        run_id: checked_identifier(raw.run_id, "run_id")?,
        spool_state,
        last_sequence,
        updated_at_ms: checked_time(raw.updated_at_ms, "updated_at_ms")?,
        revision,
    })
}

fn read_by_submission(
    connection: &Connection,
    submission_id: i64,
) -> Indexed<Option<RunIndexRecord>> {
    let raw = connection
        .query_row(
            &format!("SELECT {RECORD_COLUMNS} FROM run_index WHERE submission_id = ?1"),
            [submission_id],
            raw_record,
        )
        .optional()?;
    raw.map(validated_record).transpose()
}

fn count_entries(connection: &Connection) -> Indexed<usize> {
    let count: i64 =
        connection.query_row("SELECT count(*) FROM run_index", [], |row| row.get(0))?;
    usize::try_from(count).map_err(|_| corrupt("entry_count"))
}

fn secure_path(path: &Path) -> Indexed<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => RunIndexError::Io(io),
        other => RunIndexError::InsecurePath(other.to_string()),
    })
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Indexed<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == RUN_INDEX_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(RunIndexError::SchemaVersion {
            found: version,
            supported: RUN_INDEX_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(RunIndexError::SchemaVersion {
            found: 0,
            supported: RUN_INDEX_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", RUN_INDEX_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

/// Durable identities start at one, so a zero or negative one names no row.
fn validate_submission_id(value: i64) -> Indexed<()> {
    if value <= 0 {
        return Err(RunIndexError::InvalidField("submission_id"));
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Indexed<()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(RunIndexError::InvalidField(field));
    }
    Ok(())
}

fn validate_time(value: i64, field: &'static str) -> Indexed<()> {
    if value < 0 {
        return Err(RunIndexError::InvalidField(field));
    }
    Ok(())
}

fn checked_identifier(value: String, field: &'static str) -> Indexed<String> {
    validate_identifier(&value, field).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_time(value: i64, field: &'static str) -> Indexed<i64> {
    validate_time(value, field).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_row_id(value: i64, field: &'static str) -> Indexed<i64> {
    if value <= 0 {
        return Err(corrupt(field));
    }
    Ok(value)
}

/// Map a validation field onto its stable corruption invariant name.
///
/// Read paths never reuse `InvalidField`: a bad stored row is corruption the
/// caller cannot have caused, and the two must not be confused.
const fn corrupt(field: &'static str) -> RunIndexError {
    RunIndexError::Corrupt(field)
}

fn to_db_u64(value: u64, field: &'static str) -> Indexed<i64> {
    i64::try_from(value).map_err(|_| RunIndexError::InvalidField(field))
}

fn from_db_u64(value: i64, field: &'static str) -> Indexed<u64> {
    u64::try_from(value).map_err(|_| RunIndexError::InvalidField(field))
}
