// SPDX-License-Identifier: Elastic-2.0

//! Durable append-only audit of generation hand-offs.
//!
//! [`crate::Store`] already fences daemon generations: `generations` holds one
//! row per `generation_id` with a `lease_holder`, a monotonic `lease_epoch` and
//! an expiry, and [`crate::Store::acquire_generation_lease`] hands out a *new*
//! epoch only when the recorded lease has lapsed. That fence answers "who may
//! act right now". It answers nothing about the past: the row is overwritten in
//! place, so the moment a successor takes over, every trace of who held the
//! generation before it, when, and how that tenure ended is gone.
//!
//! This module is the durable record of that history. It stores two kinds of
//! row, both append-only:
//!
//! - a **tenure** — one holder's period of authority over one `generation_id`
//!   at one `lease_epoch`: `(generation_id, holder_id, lease_epoch,
//!   started_at_ms)`, later closed exactly once with `(ended_at_ms, end_kind)`;
//! - a **handoff** — the successor's written observation of the predecessor it
//!   displaced: `(predecessor_epoch, successor_epoch, predecessor_end_kind,
//!   observed_at_ms)`.
//!
//! There is no daemon IO here and no clock. Callers supply every identifier,
//! epoch and timestamp, so restarts stay deterministic and tests do not depend
//! on an ambient clock.
//!
//! # The end-kind vocabulary is closed, and partitioned by who may write it
//!
//! `end_kind` is one of exactly three values, and *which* process may write
//! each one is part of the contract rather than a convention:
//!
//! | `end_kind` | written by | means |
//! |---|---|---|
//! | `released` | the holder itself, [`GenerationAudit::end_tenure`] | "I released my lease and am standing down" |
//! | `expired` | the holder itself, [`GenerationAudit::end_tenure`] | "I observed that my own authority had lapsed" |
//! | `superseded` | the **successor**, [`GenerationAudit::succeed_tenure`] | "I acquired this generation and found the predecessor's tenure still open" |
//!
//! [`SelfEndKind`] makes the partition unrepresentable rather than merely
//! refused: the only end kinds a holder can name for itself are `Released` and
//! `Expired`. `Superseded` has no spelling in that type, because a process
//! never supersedes itself — a predecessor that crashed never wrote its own
//! end, and the successor's opening transaction writes it instead.
//!
//! ## There is deliberately no "seized" or "preempted"
//!
//! [`crate::Store::acquire_generation_lease`] refuses a lease that is live and
//! held by somebody else: it returns [`crate::StoreError::LeaseHeld`] and
//! writes nothing. **A live generation lease cannot be taken away.** Every
//! successor's acquisition therefore implies the predecessor's lease had
//! already been released or had already lapsed. Representing a forcible seizure
//! here would be representing a transition the main store cannot produce, so
//! this module does not offer one.
//!
//! By the same reasoning `superseded` is a statement about the *audit log*, not
//! an accusation about the predecessor: it means only that the predecessor's
//! tenure row was still open when the successor wrote its own. A predecessor
//! that released cleanly and then crashed before closing its row is recorded
//! `superseded` too, and that is the honest reading.
//!
//! # What these rows do not establish
//!
//! - A tenure row proves a claim was **recorded**, never that a process held,
//!   or stopped holding, any authority. Authority lives in the main database's
//!   `generations` row and nowhere else; a reader deciding who may act now must
//!   read that row, not this log.
//! - `superseded` does not establish that the predecessor stopped. Only the
//!   lease fence establishes that, by refusing the predecessor's next
//!   epoch-checked write.
//! - `expired` is the holder's own claim that it observed
//!   [`crate::StoreError::StaleEpoch`] or [`crate::StoreError::AuthorityLost`].
//!   This module cannot re-derive an expiry: it never reads the main database.
//! - A handoff row records what the successor **found in this log**. It is not
//!   evidence of a cooperative hand-off protocol having run, and nothing here
//!   is bound to a reload epoch, a release manifest or a readiness proof.
//!
//! # Crash windows, named rather than hidden
//!
//! This log is a separate SQLite database from [`crate::Store`], so a lease
//! write and its audit row cannot commit together. Four windows follow, and the
//! schema is shaped around them:
//!
//! 1. **Lease acquired, tenure row never written.** The successor crashes
//!    between `acquire_generation_lease` and [`GenerationAudit::open_tenure`] or
//!    [`GenerationAudit::succeed_tenure`]. A tenure that really happened has no
//!    row, and the *next* successor's epoch is then more than one above the last
//!    recorded epoch. This is why epochs are only ever required to be **strictly
//!    increasing** and never contiguous: demanding `predecessor_epoch + 1` would
//!    make an unrecorded tenure permanently unrecordable.
//! 2. **Tenure row written, lease never held.** A caller that records first and
//!    acquires second leaves a row for a tenure that never had authority. The
//!    ordering duty is the caller's and is stated here rather than hidden:
//!    acquire the lease first, record second.
//! 3. **Lease released, tenure row never closed.** The holder crashes between
//!    `release_generation_lease` and [`GenerationAudit::end_tenure`]. The row
//!    stays open and the eventual successor closes it `superseded`, so a clean
//!    exit can be recorded as `superseded`; see above.
//! 4. **Tenure row closed, lease still live.** The holder closes its row and
//!    crashes before releasing. The log says the tenure ended while the main
//!    database still fences writes to it until the lease expires. The main
//!    database wins.
//!
//! # Divergences from the reload protocol as planned
//!
//! `docs/product-plan/requirements/reload-protocol.md` says every transition is
//! written to "the generation/reload audit tables", and
//! `requirements/verification-and-rollout.md` lists a bounded reload success
//! report. Most of that report cannot be recorded honestly yet, and the gaps
//! are recorded here instead of being invented:
//!
//! - **No reload epoch, and no source/target generation pair.** The plan's
//!   handoff runs between two distinct generations N and N+1 joined by a reload
//!   epoch E. The store cannot produce that transition: its lease is keyed by
//!   `generation_id`, and the epoch it increments is *within* one
//!   `generation_id`. The only handoff this store can produce, and therefore
//!   the only one recorded here, is between two tenures of a single
//!   `generation_id`. When a cross-generation primitive exists, it needs its own
//!   table and its own schema version.
//! - **No generation state machine.** The plan's `legacy_generations` carries
//!   `starting`/`ready`/`active`/`quiescing`/`draining`/`retired`/`failed`. The
//!   store's `generations.state` admits the single value `active`, so there are
//!   no state transitions to audit. `end_kind` has no `failed` for the same
//!   reason: a candidate that fails warm-up never acquires a lease and so never
//!   opens a tenure here.
//! - **No release, timing or adoption evidence.** Release checksums, phase
//!   timings, leases transferred, adopted hosts/attempts/workspaces, cursor
//!   counts and drain results are not durable state anywhere in this crate. A
//!   column holding them would hold an unverifiable claim, so there is none.
//! - **No `pid`, `version` or `heartbeat_at`.** Liveness is the main database's
//!   `lease_expires_ms`, and duplicating it here would create a second, staler
//!   answer to a question that already has one.
//!
//! # Storage discipline
//!
//! The audit owns its own SQLite database with its own `user_version`, opened
//! under the same privacy, WAL and `synchronous = FULL` rules as
//! [`crate::Store`], exactly as [`crate::cancel_ledger`] and
//! [`crate::slack_ingress`] do. Every mutation is one immediate transaction, so
//! a reader after a crash sees the whole hand-off or none of it. Every read
//! re-validates the rows it loaded rather than trusting the database.
//!
//! # Append-only
//!
//! There is **no deletion path in this module at all** — no `prune`, no
//! retention window, no compaction. That is the difference between an audit and
//! a ledger: [`crate::cancel_ledger`] prunes because a forgotten cancellation
//! reference only costs a duplicate answer, whereas a forgotten tenure erases
//! the only record that a generation ever changed hands. Bounded growth is
//! achieved by refusing new tenures at capacity instead
//! ([`GenerationAuditError::AuditFull`]).
//!
//! The single in-place update anywhere in this module is closing a tenure, and
//! it happens exactly once per row: `revision` is `1` while a tenure is open and
//! `2` once it is terminal, the close is revision-checked, and the `end_kind IS
//! NULL` guard in the same statement makes a second close write nothing.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::{StoreError, validate_database_path};

/// The only generation audit schema this build can read and write.
pub const GENERATION_AUDIT_SCHEMA_VERSION: u32 = 1;

/// Largest number of tenure rows any audit will hold.
///
/// Handoff rows are not counted separately: `UNIQUE (successor_tenure_id)`
/// admits at most one handoff per tenure, so bounding tenures bounds both
/// tables.
pub const MAX_TENURE_RECORDS: usize = 65_536;

/// Longest accepted `generation_id` or `holder_id`, in bytes.
///
/// The same identifier grammar [`crate::Store`] uses for these exact fields:
/// non-empty, at most this many bytes, no control characters.
pub const MAX_IDENTIFIER_BYTES: usize = 256;

/// Largest page [`GenerationAudit::history`] will return, per table.
pub const MAX_HISTORY_PAGE: usize = 512;

/// Schema v1.
///
/// The invariants a second writer must not be able to break are database
/// constraints: one open tenure per generation, one tenure per
/// `(generation_id, lease_epoch)`, one handoff per successor, a closed
/// `end_kind` vocabulary, `ended_at_ms` and `end_kind` present together or not
/// at all, an end that does not precede its own start, and a successor epoch
/// above the predecessor's.
///
/// The identifier grammar, the length bound, the `1`/`2` revision pair and the
/// agreement between a handoff's `predecessor_end_kind` and the tenure it names
/// are deliberately *not* database constraints: they are enforced on write and
/// re-checked on every read, so a row written around this API is refused rather
/// than believed.
const SCHEMA_V1: &str = r#"
CREATE TABLE generation_tenures (
    tenure_id INTEGER PRIMARY KEY,
    generation_id TEXT NOT NULL,
    holder_id TEXT NOT NULL,
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch >= 1),
    started_at_ms INTEGER NOT NULL CHECK (started_at_ms >= 0),
    ended_at_ms INTEGER CHECK (ended_at_ms IS NULL OR ended_at_ms >= 0),
    end_kind TEXT CHECK (end_kind IN ('released', 'expired', 'superseded')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    UNIQUE (generation_id, lease_epoch),
    CHECK ((ended_at_ms IS NULL) = (end_kind IS NULL)),
    CHECK (ended_at_ms IS NULL OR ended_at_ms >= started_at_ms)
) STRICT;

CREATE UNIQUE INDEX generation_tenures_one_open
    ON generation_tenures(generation_id) WHERE end_kind IS NULL;

CREATE TABLE generation_handoffs (
    handoff_id INTEGER PRIMARY KEY,
    generation_id TEXT NOT NULL,
    predecessor_tenure_id INTEGER NOT NULL
        REFERENCES generation_tenures(tenure_id),
    successor_tenure_id INTEGER NOT NULL UNIQUE
        REFERENCES generation_tenures(tenure_id),
    predecessor_epoch INTEGER NOT NULL CHECK (predecessor_epoch >= 1),
    successor_epoch INTEGER NOT NULL CHECK (successor_epoch >= 1),
    predecessor_end_kind TEXT NOT NULL
        CHECK (predecessor_end_kind IN ('released', 'expired', 'superseded')),
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0),
    CHECK (successor_epoch > predecessor_epoch)
) STRICT;

CREATE INDEX generation_handoffs_by_generation
    ON generation_handoffs(generation_id, successor_epoch);
"#;

/// A generation audit error with stable refusal categories.
#[derive(Debug)]
pub enum GenerationAuditError {
    /// The audit path or its containing directory is not private and owned.
    InsecurePath(String),
    /// The audit schema is absent from a non-empty database or unsupported.
    SchemaVersion { found: u32, supported: u32 },
    /// A caller-provided field is empty, over-long, malformed, or out of range.
    InvalidField(&'static str),
    /// The referenced durable row does not exist.
    NotFound(&'static str),
    /// The generation already has an open tenure.
    ///
    /// [`GenerationAudit::open_tenure`] never closes somebody else's row.
    /// A successor takes over through [`GenerationAudit::succeed_tenure`].
    TenureOpen {
        tenure_id: i64,
        holder_id: String,
        lease_epoch: u64,
    },
    /// The generation already has recorded tenures, all of them terminal.
    ///
    /// A successor must record its observation of the predecessor, so it uses
    /// [`GenerationAudit::succeed_tenure`]. [`GenerationAudit::open_tenure`] is
    /// only ever the first tenure of a generation, which has no predecessor to
    /// observe; there is no path that silently omits a handoff row.
    PredecessorRecorded { tenure_id: i64, lease_epoch: u64 },
    /// A tenure was offered at an epoch not above every recorded epoch.
    ///
    /// Epochs must increase but need not be contiguous; see this module's crash
    /// window 1.
    EpochRegression { durable: u64, supplied: u64 },
    /// The tenure is recorded against a different holder.
    HolderMismatch { recorded_holder_id: String },
    /// The tenure is already terminal, and a terminal tenure is never rewritten.
    AlreadyEnded { end_kind: EndKind, ended_at_ms: i64 },
    /// The caller's expected revision does not match the durable revision.
    RevisionMismatch { expected: u64, durable: u64 },
    /// A tenure would end before it started.
    EndBeforeStart {
        started_at_ms: i64,
        ended_at_ms: i64,
    },
    /// The audit holds its full capacity of tenures.
    ///
    /// There is no deletion path in this module, so this is a hard boundary and
    /// not a prompt to compact.
    AuditFull { capacity: usize },
    /// A stored row violates an invariant this API can only have written once.
    Corrupt(&'static str),
    /// Filesystem failure while establishing the private audit.
    Io(std::io::Error),
    /// SQLite rejected an operation.
    Sqlite(rusqlite::Error),
}

impl GenerationAuditError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::NotFound(_) => "not_found",
            Self::TenureOpen { .. } => "tenure_open",
            Self::PredecessorRecorded { .. } => "predecessor_recorded",
            Self::EpochRegression { .. } => "epoch_regression",
            Self::HolderMismatch { .. } => "holder_mismatch",
            Self::AlreadyEnded { .. } => "already_ended",
            Self::RevisionMismatch { .. } => "revision_mismatch",
            Self::EndBeforeStart { .. } => "end_before_start",
            Self::AuditFull { .. } => "audit_full",
            Self::Corrupt(_) => "corrupt",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}

impl fmt::Display for GenerationAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => {
                write!(formatter, "audit path is not private: {reason}")
            }
            Self::SchemaVersion { found, supported } => write!(
                formatter,
                "generation audit schema {found} is unsupported; expected {supported}"
            ),
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::NotFound(entity) => write!(formatter, "no such {entity}"),
            Self::TenureOpen {
                tenure_id,
                holder_id,
                lease_epoch,
            } => write!(
                formatter,
                "generation already has open tenure {tenure_id} \
                 held by {holder_id} at epoch {lease_epoch}"
            ),
            Self::PredecessorRecorded {
                tenure_id,
                lease_epoch,
            } => write!(
                formatter,
                "generation already recorded tenure {tenure_id} at epoch \
                 {lease_epoch}; a successor must record a handoff"
            ),
            Self::EpochRegression { durable, supplied } => write!(
                formatter,
                "lease epoch {supplied} is not above the recorded epoch {durable}"
            ),
            Self::HolderMismatch { recorded_holder_id } => write!(
                formatter,
                "tenure is recorded against holder {recorded_holder_id}"
            ),
            Self::AlreadyEnded {
                end_kind,
                ended_at_ms,
            } => write!(
                formatter,
                "tenure already ended {} at {ended_at_ms}",
                end_kind.as_str()
            ),
            Self::RevisionMismatch { expected, durable } => write!(
                formatter,
                "expected revision {expected} but durable revision is {durable}"
            ),
            Self::EndBeforeStart {
                started_at_ms,
                ended_at_ms,
            } => write!(
                formatter,
                "tenure end {ended_at_ms} precedes its start {started_at_ms}"
            ),
            Self::AuditFull { capacity } => {
                write!(
                    formatter,
                    "generation audit holds its capacity of {capacity}"
                )
            }
            Self::Corrupt(invariant) => {
                write!(formatter, "stored row violates invariant: {invariant}")
            }
            Self::Io(error) => write!(formatter, "audit filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite error: {error}"),
        }
    }
}

impl Error for GenerationAuditError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for GenerationAuditError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for GenerationAuditError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// Result of one generation audit operation.
pub type Audited<T> = Result<T, GenerationAuditError>;

/// How a recorded tenure ended.
///
/// The whole vocabulary. A stored value outside it is corruption, not an
/// extension point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndKind {
    /// The holder released its lease and stood down. Written by the holder.
    Released,
    /// The holder observed that its own authority had lapsed. Written by the
    /// holder.
    Expired,
    /// A successor acquired the generation and found this tenure still open.
    /// Written by the successor, never by the holder.
    Superseded,
}

impl EndKind {
    /// Stable machine-oriented spelling, and the exact stored text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Superseded => "superseded",
        }
    }

    /// Parse the exact stored text.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "released" => Some(Self::Released),
            "expired" => Some(Self::Expired),
            "superseded" => Some(Self::Superseded),
            _ => None,
        }
    }
}

/// The end kinds a holder may write for its *own* tenure.
///
/// [`EndKind::Superseded`] is absent by construction: a holder never supersedes
/// itself, and a successor writes that value through
/// [`GenerationAudit::succeed_tenure`] instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelfEndKind {
    /// The holder released its lease.
    Released,
    /// The holder observed its own authority had lapsed.
    Expired,
}

impl SelfEndKind {
    /// The recorded [`EndKind`] this self-claim writes.
    #[must_use]
    pub const fn kind(self) -> EndKind {
        match self {
            Self::Released => EndKind::Released,
            Self::Expired => EndKind::Expired,
        }
    }
}

impl From<SelfEndKind> for EndKind {
    fn from(value: SelfEndKind) -> Self {
        value.kind()
    }
}

/// One tenure a process is claiming to have begun.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenureOpening<'a> {
    /// Generation whose lease the holder acquired.
    pub generation_id: &'a str,
    /// Process that acquired it.
    pub holder_id: &'a str,
    /// Fencing epoch [`crate::Store::acquire_generation_lease`] returned.
    pub lease_epoch: u64,
    /// When the holder acquired it, in caller-supplied milliseconds.
    pub started_at_ms: i64,
}

/// One successor taking over a generation that already has recorded tenures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Succession<'a> {
    /// The successor's own tenure.
    pub opening: TenureOpening<'a>,
    /// When the successor read the predecessor's state out of this log.
    ///
    /// Must be at or after [`TenureOpening::started_at_ms`]: the successor
    /// acquires its lease first and records second. When the predecessor's
    /// tenure is still open this is also the `ended_at_ms` written for it,
    /// because it is the first instant at which anything durably knew that
    /// tenure was over.
    pub observed_at_ms: i64,
}

/// One holder closing its own tenure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenureEnding<'a> {
    pub generation_id: &'a str,
    /// Must match the recorded holder: a process never closes another's tenure.
    pub holder_id: &'a str,
    pub lease_epoch: u64,
    /// Durable revision the caller believes it is closing. `1` while open.
    pub expected_revision: u64,
    pub ended_at_ms: i64,
    pub end_kind: SelfEndKind,
}

/// Validated `generation_tenures` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenureRecord {
    pub tenure_id: i64,
    pub generation_id: String,
    pub holder_id: String,
    pub lease_epoch: u64,
    pub started_at_ms: i64,
    /// `None` while the tenure is open, and set exactly once.
    pub ended_at_ms: Option<i64>,
    /// `None` while the tenure is open, and set exactly once.
    pub end_kind: Option<EndKind>,
    /// `1` while open, `2` once terminal.
    pub revision: u64,
}

impl TenureRecord {
    /// Whether this tenure is still open.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.end_kind.is_none()
    }
}

/// Validated `generation_handoffs` row: a successor's recorded observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffRecord {
    pub handoff_id: i64,
    pub generation_id: String,
    pub predecessor_tenure_id: i64,
    pub successor_tenure_id: i64,
    pub predecessor_epoch: u64,
    pub successor_epoch: u64,
    /// The end kind the predecessor's tenure carried once this handoff
    /// committed. Always equal to that tenure's `end_kind`, and re-checked
    /// against it on every read.
    pub predecessor_end_kind: EndKind,
    pub observed_at_ms: i64,
}

/// What one succession durably wrote.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Succeeded {
    /// The successor's new open tenure.
    pub tenure: TenureRecord,
    /// The observation it recorded about its predecessor.
    pub handoff: HandoffRecord,
    /// The predecessor as it stands after this succession, always terminal.
    pub predecessor: TenureRecord,
}

/// One bounded page of a generation's recorded history, oldest first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationHistory {
    /// Tenures ordered by `lease_epoch`.
    pub tenures: Vec<TenureRecord>,
    /// Handoffs ordered by `successor_epoch`.
    pub handoffs: Vec<HandoffRecord>,
}

/// Durable append-only audit of generation hand-offs.
#[derive(Debug)]
pub struct GenerationAudit {
    connection: Connection,
    path: PathBuf,
    capacity: usize,
}

impl GenerationAudit {
    /// Open or initialize an audit inside an existing private directory.
    ///
    /// The parent must be owned by the effective user and deny all group/other
    /// access. Existing audit paths must be regular, owned, non-symlinks.
    /// Capacity is [`MAX_TENURE_RECORDS`].
    pub fn open(path: impl AsRef<Path>) -> Audited<Self> {
        Self::open_with_capacity(path, MAX_TENURE_RECORDS)
    }

    /// Open an audit with a lowered tenure capacity.
    ///
    /// `capacity` must be between one and [`MAX_TENURE_RECORDS`]. It is a
    /// property of this handle, not of the database: opening an existing audit
    /// under a capacity below its current row count refuses further tenures
    /// with [`GenerationAuditError::AuditFull`] while closing an open tenure
    /// and every read keep working, because neither adds a row.
    pub fn open_with_capacity(path: impl AsRef<Path>, capacity: usize) -> Audited<Self> {
        if capacity == 0 || capacity > MAX_TENURE_RECORDS {
            return Err(GenerationAuditError::InvalidField("capacity"));
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

    /// Exact path opened by this audit.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Tenure capacity of this handle.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Record the **first** tenure of a generation.
    ///
    /// One immediate transaction: after a crash a reader sees the whole row or
    /// no row.
    ///
    /// This entry point is deliberately narrow. It refuses
    /// [`GenerationAuditError::TenureOpen`] when the generation still has an
    /// open tenure — nothing here ever closes a row this caller did not write —
    /// and [`GenerationAuditError::PredecessorRecorded`] when the generation has
    /// only terminal tenures, because a successor owes the log an observation of
    /// what it displaced. Together those refusals mean a generation's recorded
    /// history has no un-linked tenures after the first.
    pub fn open_tenure(&mut self, opening: TenureOpening<'_>) -> Audited<TenureRecord> {
        validate_opening(&opening)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(latest) = read_latest_tenure(&transaction, opening.generation_id)? {
            return Err(if latest.is_open() {
                GenerationAuditError::TenureOpen {
                    tenure_id: latest.tenure_id,
                    holder_id: latest.holder_id,
                    lease_epoch: latest.lease_epoch,
                }
            } else {
                GenerationAuditError::PredecessorRecorded {
                    tenure_id: latest.tenure_id,
                    lease_epoch: latest.lease_epoch,
                }
            });
        }
        let mut live = count_tenures(&transaction)?;
        let record = insert_tenure(&transaction, &opening, self.capacity, &mut live)?;
        transaction.commit()?;
        Ok(record)
    }

    /// Record a successor taking over a generation, in one transaction.
    ///
    /// The successor does not get to say how its predecessor ended; this module
    /// reads that out of the log and reports it back:
    ///
    /// - the predecessor's tenure is already terminal, because that holder
    ///   closed it itself: nothing about it changes, and the handoff row records
    ///   the `released` or `expired` it found;
    /// - the predecessor's tenure is still open, because that holder never got
    ///   to close it: this transaction closes it [`EndKind::Superseded`] at
    ///   `observed_at_ms` **and** opens the successor's tenure **and** writes the
    ///   handoff row. Either all three land or none does, so the log can never
    ///   hold a superseded predecessor with no successor, nor two open tenures.
    ///
    /// The successor's epoch must be above every epoch recorded for the
    /// generation, but need not be the next one; see this module's crash
    /// window 1.
    ///
    /// Refuses [`GenerationAuditError::NotFound`] when the generation has no
    /// recorded tenure at all: the first tenure has no predecessor to observe
    /// and belongs to [`GenerationAudit::open_tenure`].
    pub fn succeed_tenure(&mut self, succession: Succession<'_>) -> Audited<Succeeded> {
        let opening = succession.opening;
        validate_opening(&opening)?;
        validate_time(succession.observed_at_ms, "observed_at_ms")?;
        if succession.observed_at_ms < opening.started_at_ms {
            return Err(GenerationAuditError::InvalidField("observed_at_ms"));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut predecessor = read_latest_tenure(&transaction, opening.generation_id)?
            .ok_or(GenerationAuditError::NotFound("predecessor_tenure"))?;
        if opening.lease_epoch <= predecessor.lease_epoch {
            return Err(GenerationAuditError::EpochRegression {
                durable: predecessor.lease_epoch,
                supplied: opening.lease_epoch,
            });
        }

        let predecessor_end_kind = match predecessor.end_kind {
            Some(kind) => kind,
            None => {
                if succession.observed_at_ms < predecessor.started_at_ms {
                    return Err(GenerationAuditError::EndBeforeStart {
                        started_at_ms: predecessor.started_at_ms,
                        ended_at_ms: succession.observed_at_ms,
                    });
                }
                let revision = close_tenure(
                    &transaction,
                    predecessor.tenure_id,
                    predecessor.revision,
                    succession.observed_at_ms,
                    EndKind::Superseded,
                )?;
                predecessor.ended_at_ms = Some(succession.observed_at_ms);
                predecessor.end_kind = Some(EndKind::Superseded);
                predecessor.revision = revision;
                EndKind::Superseded
            }
        };

        // The successor's row is the second write of this transaction, and it
        // can still refuse: capacity is a property of inserting a tenure. A
        // refusal here discards the predecessor's close as well, which is the
        // whole reason succession is one transaction and not two calls.
        let mut live = count_tenures(&transaction)?;
        let tenure = insert_tenure(&transaction, &opening, self.capacity, &mut live)?;
        let handoff = insert_handoff(
            &transaction,
            &predecessor,
            &tenure,
            predecessor_end_kind,
            succession.observed_at_ms,
        )?;
        transaction.commit()?;
        Ok(Succeeded {
            tenure,
            handoff,
            predecessor,
        })
    }

    /// Close one's own tenure, exactly once.
    ///
    /// The tenure is named by the coordinates its holder already has from the
    /// lease it took — `(generation_id, lease_epoch)` — so a process that
    /// restarted its own bookkeeping does not need a row id it never kept.
    ///
    /// Refuses [`GenerationAuditError::HolderMismatch`] for another holder's
    /// tenure, [`GenerationAuditError::AlreadyEnded`] for a terminal one, and
    /// [`GenerationAuditError::RevisionMismatch`] when the caller's expected
    /// revision is not the durable one. A terminal tenure is never rewritten,
    /// not even to the same `end_kind`: the first close is the record.
    pub fn end_tenure(&mut self, ending: TenureEnding<'_>) -> Audited<TenureRecord> {
        validate_identifier(ending.generation_id, "generation_id")?;
        validate_identifier(ending.holder_id, "holder_id")?;
        validate_epoch(ending.lease_epoch)?;
        validate_time(ending.ended_at_ms, "ended_at_ms")?;
        if ending.expected_revision == 0 {
            return Err(GenerationAuditError::InvalidField("expected_revision"));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = read_tenure(&transaction, ending.generation_id, ending.lease_epoch)?
            .ok_or(GenerationAuditError::NotFound("tenure"))?;
        if record.holder_id != ending.holder_id {
            return Err(GenerationAuditError::HolderMismatch {
                recorded_holder_id: record.holder_id,
            });
        }
        if let Some(end_kind) = record.end_kind {
            return Err(GenerationAuditError::AlreadyEnded {
                end_kind,
                ended_at_ms: record
                    .ended_at_ms
                    .ok_or_else(|| corrupt_field("ended_at_ms"))?,
            });
        }
        if record.revision != ending.expected_revision {
            return Err(GenerationAuditError::RevisionMismatch {
                expected: ending.expected_revision,
                durable: record.revision,
            });
        }
        if ending.ended_at_ms < record.started_at_ms {
            return Err(GenerationAuditError::EndBeforeStart {
                started_at_ms: record.started_at_ms,
                ended_at_ms: ending.ended_at_ms,
            });
        }

        let kind = ending.end_kind.kind();
        let revision = close_tenure(
            &transaction,
            record.tenure_id,
            record.revision,
            ending.ended_at_ms,
            kind,
        )?;
        transaction.commit()?;
        record.ended_at_ms = Some(ending.ended_at_ms);
        record.end_kind = Some(kind);
        record.revision = revision;
        Ok(record)
    }

    /// The generation's open tenure, if it has one.
    ///
    /// This is the recovery question a starting daemon asks first: did anybody
    /// leave a tenure open here? An answer of `None` means no *record* is open,
    /// never that no process is running — only the main database's lease says
    /// that.
    pub fn latest_open(&self, generation_id: &str) -> Audited<Option<TenureRecord>> {
        validate_identifier(generation_id, "generation_id")?;
        Ok(read_latest_tenure(&self.connection, generation_id)?.filter(TenureRecord::is_open))
    }

    /// The tenure recorded at one exact `(generation_id, lease_epoch)`.
    pub fn tenure(&self, generation_id: &str, lease_epoch: u64) -> Audited<Option<TenureRecord>> {
        validate_identifier(generation_id, "generation_id")?;
        validate_epoch(lease_epoch)?;
        read_tenure(&self.connection, generation_id, lease_epoch)
    }

    /// One bounded page of a generation's history, oldest first.
    ///
    /// Both lists cover epochs strictly above `since_epoch`; pass `0` to start
    /// at the beginning, and to advance, pass the `lease_epoch` of the last
    /// tenure read. `limit` must be between one and [`MAX_HISTORY_PAGE`] and
    /// bounds each list independently, though there can never be more handoffs
    /// than tenures.
    ///
    /// The page is read inside one transaction, so the tenures and the handoffs
    /// that reference them come from a single snapshot rather than from either
    /// side of a concurrent succession.
    ///
    /// An empty answer means nothing was recorded in that window — never that
    /// the generation never changed hands.
    pub fn history(
        &self,
        generation_id: &str,
        since_epoch: u64,
        limit: usize,
    ) -> Audited<GenerationHistory> {
        validate_identifier(generation_id, "generation_id")?;
        if limit == 0 || limit > MAX_HISTORY_PAGE {
            return Err(GenerationAuditError::InvalidField("limit"));
        }
        let since = to_db_u64(since_epoch, "since_epoch")?;
        let page = i64::try_from(limit).map_err(|_| GenerationAuditError::InvalidField("limit"))?;

        let transaction = self.connection.unchecked_transaction()?;
        let tenures = read_tenure_page(&transaction, generation_id, since, page)?;
        let handoffs = read_handoff_page(&transaction, generation_id, since, page)?;
        transaction.rollback()?;
        Ok(GenerationHistory { tenures, handoffs })
    }

    /// Count recorded tenures across every generation.
    pub fn tenure_count(&self) -> Audited<usize> {
        count_tenures(&self.connection)
    }

    /// Count recorded handoffs across every generation.
    pub fn handoff_count(&self) -> Audited<usize> {
        let count: i64 =
            self.connection
                .query_row("SELECT count(*) FROM generation_handoffs", [], |row| {
                    row.get(0)
                })?;
        usize::try_from(count).map_err(|_| corrupt_field("handoff_count"))
    }
}

/// Insert one open tenure inside an open transaction.
///
/// `live` is the tenure count as of the start of the transaction, advanced here
/// for every row this transaction inserts. The transaction is immediate, so no
/// other writer can move the count underneath it.
fn insert_tenure(
    transaction: &Transaction<'_>,
    opening: &TenureOpening<'_>,
    capacity: usize,
    live: &mut usize,
) -> Audited<TenureRecord> {
    if *live >= capacity {
        return Err(GenerationAuditError::AuditFull { capacity });
    }
    transaction.execute(
        "INSERT INTO generation_tenures
         (generation_id, holder_id, lease_epoch, started_at_ms,
          ended_at_ms, end_kind, revision)
         VALUES (?1, ?2, ?3, ?4, NULL, NULL, 1)",
        params![
            opening.generation_id,
            opening.holder_id,
            to_db_u64(opening.lease_epoch, "lease_epoch")?,
            opening.started_at_ms
        ],
    )?;
    *live = live
        .checked_add(1)
        .ok_or(GenerationAuditError::InvalidField("lease_epoch"))?;
    Ok(TenureRecord {
        tenure_id: transaction.last_insert_rowid(),
        generation_id: opening.generation_id.to_owned(),
        holder_id: opening.holder_id.to_owned(),
        lease_epoch: opening.lease_epoch,
        started_at_ms: opening.started_at_ms,
        ended_at_ms: None,
        end_kind: None,
        revision: 1,
    })
}

/// Close one open tenure, revision-checked, returning the new revision.
///
/// `end_kind IS NULL` in the guard makes a second close write nothing even if a
/// caller reached here with a stale revision that happened to match.
fn close_tenure(
    transaction: &Transaction<'_>,
    tenure_id: i64,
    expected_revision: u64,
    ended_at_ms: i64,
    end_kind: EndKind,
) -> Audited<u64> {
    let next_revision = expected_revision
        .checked_add(1)
        .ok_or(GenerationAuditError::InvalidField("revision"))?;
    let changed = transaction.execute(
        "UPDATE generation_tenures
         SET ended_at_ms = ?3, end_kind = ?4, revision = ?5
         WHERE tenure_id = ?1 AND revision = ?2 AND end_kind IS NULL",
        params![
            tenure_id,
            to_db_u64(expected_revision, "revision")?,
            ended_at_ms,
            end_kind.as_str(),
            to_db_u64(next_revision, "revision")?
        ],
    )?;
    if changed != 1 {
        // The row was read inside this immediate transaction, so nothing else
        // can have moved it; a disagreement means the stored row is not what
        // this API writes.
        return Err(corrupt_field("tenure_close"));
    }
    Ok(next_revision)
}

fn insert_handoff(
    transaction: &Transaction<'_>,
    predecessor: &TenureRecord,
    successor: &TenureRecord,
    predecessor_end_kind: EndKind,
    observed_at_ms: i64,
) -> Audited<HandoffRecord> {
    transaction.execute(
        "INSERT INTO generation_handoffs
         (generation_id, predecessor_tenure_id, successor_tenure_id,
          predecessor_epoch, successor_epoch, predecessor_end_kind, observed_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            successor.generation_id,
            predecessor.tenure_id,
            successor.tenure_id,
            to_db_u64(predecessor.lease_epoch, "predecessor_epoch")?,
            to_db_u64(successor.lease_epoch, "successor_epoch")?,
            predecessor_end_kind.as_str(),
            observed_at_ms
        ],
    )?;
    Ok(HandoffRecord {
        handoff_id: transaction.last_insert_rowid(),
        generation_id: successor.generation_id.clone(),
        predecessor_tenure_id: predecessor.tenure_id,
        successor_tenure_id: successor.tenure_id,
        predecessor_epoch: predecessor.lease_epoch,
        successor_epoch: successor.lease_epoch,
        predecessor_end_kind,
        observed_at_ms,
    })
}

struct RawTenure {
    tenure_id: i64,
    generation_id: String,
    holder_id: String,
    lease_epoch: i64,
    started_at_ms: i64,
    ended_at_ms: Option<i64>,
    end_kind: Option<String>,
    revision: i64,
}

const TENURE_COLUMNS: &str = "tenure_id, generation_id, holder_id, lease_epoch, \
                              started_at_ms, ended_at_ms, end_kind, revision";

fn raw_tenure(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawTenure> {
    Ok(RawTenure {
        tenure_id: row.get(0)?,
        generation_id: row.get(1)?,
        holder_id: row.get(2)?,
        lease_epoch: row.get(3)?,
        started_at_ms: row.get(4)?,
        ended_at_ms: row.get(5)?,
        end_kind: row.get(6)?,
        revision: row.get(7)?,
    })
}

/// Re-derive a [`TenureRecord`] from a stored row, refusing anything this API
/// could not have written.
///
/// `revision` is checked against the terminal state rather than merely against
/// zero: this module performs exactly one update per row, so `1` means open and
/// `2` means terminal and nothing else is reachable.
fn validated_tenure(raw: RawTenure) -> Audited<TenureRecord> {
    let end_kind = match raw.end_kind {
        None => None,
        Some(text) => Some(EndKind::parse(&text).ok_or_else(|| corrupt_field("end_kind"))?),
    };
    match (end_kind, raw.ended_at_ms) {
        (None, None) | (Some(_), Some(_)) => {}
        _ => return Err(corrupt_field("tenure_terminality")),
    }
    let started_at_ms = checked_time(raw.started_at_ms, "started_at_ms")?;
    if let Some(ended_at_ms) = raw.ended_at_ms {
        checked_time(ended_at_ms, "ended_at_ms")?;
        if ended_at_ms < started_at_ms {
            return Err(corrupt_field("ended_at_ms"));
        }
    }
    let revision = from_db_u64(raw.revision, "revision").map_err(|_| corrupt_field("revision"))?;
    let expected_revision = if end_kind.is_some() { 2 } else { 1 };
    if revision != expected_revision {
        return Err(corrupt_field("revision"));
    }
    Ok(TenureRecord {
        tenure_id: checked_row_id(raw.tenure_id, "tenure_id")?,
        generation_id: checked_identifier(raw.generation_id, "generation_id")?,
        holder_id: checked_identifier(raw.holder_id, "holder_id")?,
        lease_epoch: checked_epoch(raw.lease_epoch, "lease_epoch")?,
        started_at_ms,
        ended_at_ms: raw.ended_at_ms,
        end_kind,
        revision,
    })
}

/// The generation's highest-epoch tenure, whether open or terminal.
///
/// Also enforces the one invariant that spans rows on the read side: an open
/// tenure is always the latest one. The partial unique index admits at most one
/// open tenure per generation and this API only ever opens above the recorded
/// maximum, so an open tenure below a terminal one is a row somebody else wrote.
fn read_latest_tenure(
    connection: &Connection,
    generation_id: &str,
) -> Audited<Option<TenureRecord>> {
    let raw = connection
        .query_row(
            &format!(
                "SELECT {TENURE_COLUMNS} FROM generation_tenures
                 WHERE generation_id = ?1 ORDER BY lease_epoch DESC LIMIT 1"
            ),
            [generation_id],
            raw_tenure,
        )
        .optional()?;
    let Some(record) = raw.map(validated_tenure).transpose()? else {
        return Ok(None);
    };
    if !record.is_open() {
        let stranded: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM generation_tenures
             WHERE generation_id = ?1 AND end_kind IS NULL)",
            [generation_id],
            |row| row.get(0),
        )?;
        if stranded {
            return Err(corrupt_field("open_tenure_not_latest"));
        }
    }
    Ok(Some(record))
}

fn read_tenure(
    connection: &Connection,
    generation_id: &str,
    lease_epoch: u64,
) -> Audited<Option<TenureRecord>> {
    let raw = connection
        .query_row(
            &format!(
                "SELECT {TENURE_COLUMNS} FROM generation_tenures
                 WHERE generation_id = ?1 AND lease_epoch = ?2"
            ),
            params![generation_id, to_db_u64(lease_epoch, "lease_epoch")?],
            raw_tenure,
        )
        .optional()?;
    raw.map(validated_tenure).transpose()
}

fn read_tenure_page(
    connection: &Connection,
    generation_id: &str,
    since_epoch: i64,
    limit: i64,
) -> Audited<Vec<TenureRecord>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {TENURE_COLUMNS} FROM generation_tenures
         WHERE generation_id = ?1 AND lease_epoch > ?2
         ORDER BY lease_epoch LIMIT ?3"
    ))?;
    let rows = statement.query_map(params![generation_id, since_epoch, limit], raw_tenure)?;
    let mut records = Vec::new();
    for raw in rows {
        records.push(validated_tenure(raw?)?);
    }
    Ok(records)
}

struct RawHandoff {
    handoff_id: i64,
    generation_id: String,
    predecessor_tenure_id: i64,
    successor_tenure_id: i64,
    predecessor_epoch: i64,
    successor_epoch: i64,
    predecessor_end_kind: String,
    observed_at_ms: i64,
    /// The predecessor tenure's own `end_kind`, joined in for cross-checking.
    recorded_end_kind: Option<String>,
    /// The predecessor tenure's own `generation_id`, joined in likewise.
    recorded_generation_id: Option<String>,
    /// The predecessor tenure's own `lease_epoch`, joined in likewise.
    recorded_epoch: Option<i64>,
}

fn raw_handoff(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawHandoff> {
    Ok(RawHandoff {
        handoff_id: row.get(0)?,
        generation_id: row.get(1)?,
        predecessor_tenure_id: row.get(2)?,
        successor_tenure_id: row.get(3)?,
        predecessor_epoch: row.get(4)?,
        successor_epoch: row.get(5)?,
        predecessor_end_kind: row.get(6)?,
        observed_at_ms: row.get(7)?,
        recorded_end_kind: row.get(8)?,
        recorded_generation_id: row.get(9)?,
        recorded_epoch: row.get(10)?,
    })
}

/// Re-derive a [`HandoffRecord`], refusing a row that disagrees with the tenure
/// it names.
///
/// A handoff always references a predecessor this same transaction left
/// terminal, so a `NULL` or differing `end_kind` on the joined tenure — or a
/// missing tenure at all — is a row this API did not write.
fn validated_handoff(raw: RawHandoff) -> Audited<HandoffRecord> {
    let predecessor_end_kind = EndKind::parse(&raw.predecessor_end_kind)
        .ok_or_else(|| corrupt_field("predecessor_end_kind"))?;
    let recorded = raw
        .recorded_end_kind
        .as_deref()
        .and_then(EndKind::parse)
        .ok_or_else(|| corrupt_field("predecessor_end_kind"))?;
    if recorded != predecessor_end_kind {
        return Err(corrupt_field("predecessor_end_kind"));
    }
    let generation_id = checked_identifier(raw.generation_id, "generation_id")?;
    if raw.recorded_generation_id.as_deref() != Some(generation_id.as_str()) {
        return Err(corrupt_field("handoff_generation_id"));
    }
    let predecessor_epoch = checked_epoch(raw.predecessor_epoch, "predecessor_epoch")?;
    if raw.recorded_epoch != Some(raw.predecessor_epoch) {
        return Err(corrupt_field("predecessor_epoch"));
    }
    let successor_epoch = checked_epoch(raw.successor_epoch, "successor_epoch")?;
    if successor_epoch <= predecessor_epoch {
        return Err(corrupt_field("successor_epoch"));
    }
    Ok(HandoffRecord {
        handoff_id: checked_row_id(raw.handoff_id, "handoff_id")?,
        generation_id,
        predecessor_tenure_id: checked_row_id(raw.predecessor_tenure_id, "predecessor_tenure_id")?,
        successor_tenure_id: checked_row_id(raw.successor_tenure_id, "successor_tenure_id")?,
        predecessor_epoch,
        successor_epoch,
        predecessor_end_kind,
        observed_at_ms: checked_time(raw.observed_at_ms, "observed_at_ms")?,
    })
}

fn read_handoff_page(
    connection: &Connection,
    generation_id: &str,
    since_epoch: i64,
    limit: i64,
) -> Audited<Vec<HandoffRecord>> {
    let mut statement = connection.prepare(
        "SELECT h.handoff_id, h.generation_id, h.predecessor_tenure_id,
                h.successor_tenure_id, h.predecessor_epoch, h.successor_epoch,
                h.predecessor_end_kind, h.observed_at_ms,
                t.end_kind, t.generation_id, t.lease_epoch
         FROM generation_handoffs h
         LEFT JOIN generation_tenures t ON t.tenure_id = h.predecessor_tenure_id
         WHERE h.generation_id = ?1 AND h.successor_epoch > ?2
         ORDER BY h.successor_epoch LIMIT ?3",
    )?;
    let rows = statement.query_map(params![generation_id, since_epoch, limit], raw_handoff)?;
    let mut records = Vec::new();
    for raw in rows {
        records.push(validated_handoff(raw?)?);
    }
    Ok(records)
}

fn count_tenures(connection: &Connection) -> Audited<usize> {
    let count: i64 =
        connection.query_row("SELECT count(*) FROM generation_tenures", [], |row| {
            row.get(0)
        })?;
    usize::try_from(count).map_err(|_| corrupt_field("tenure_count"))
}

fn secure_path(path: &Path) -> Audited<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => GenerationAuditError::Io(io),
        other => GenerationAuditError::InsecurePath(other.to_string()),
    })
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Audited<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == GENERATION_AUDIT_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(GenerationAuditError::SchemaVersion {
            found: version,
            supported: GENERATION_AUDIT_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(GenerationAuditError::SchemaVersion {
            found: 0,
            supported: GENERATION_AUDIT_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", GENERATION_AUDIT_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn validate_opening(opening: &TenureOpening<'_>) -> Audited<()> {
    validate_identifier(opening.generation_id, "generation_id")?;
    validate_identifier(opening.holder_id, "holder_id")?;
    validate_epoch(opening.lease_epoch)?;
    validate_time(opening.started_at_ms, "started_at_ms")
}

fn validate_identifier(value: &str, field: &'static str) -> Audited<()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(GenerationAuditError::InvalidField(field));
    }
    Ok(())
}

/// Epochs start at one, exactly as [`crate::Store`]'s `lease_epoch >= 1`.
fn validate_epoch(value: u64) -> Audited<()> {
    if value == 0 {
        return Err(GenerationAuditError::InvalidField("lease_epoch"));
    }
    to_db_u64(value, "lease_epoch").map(|_| ())
}

fn validate_time(value: i64, field: &'static str) -> Audited<()> {
    if value < 0 {
        return Err(GenerationAuditError::InvalidField(field));
    }
    Ok(())
}

fn validate_row_id(value: i64, field: &'static str) -> Audited<()> {
    if value <= 0 {
        return Err(GenerationAuditError::InvalidField(field));
    }
    Ok(())
}

fn checked_identifier(value: String, field: &'static str) -> Audited<String> {
    validate_identifier(&value, field).map_err(|_| corrupt_field(field))?;
    Ok(value)
}

fn checked_time(value: i64, field: &'static str) -> Audited<i64> {
    validate_time(value, field).map_err(|_| corrupt_field(field))?;
    Ok(value)
}

fn checked_row_id(value: i64, field: &'static str) -> Audited<i64> {
    validate_row_id(value, field).map_err(|_| corrupt_field(field))?;
    Ok(value)
}

fn checked_epoch(value: i64, field: &'static str) -> Audited<u64> {
    let epoch = from_db_u64(value, field).map_err(|_| corrupt_field(field))?;
    if epoch == 0 {
        return Err(corrupt_field(field));
    }
    Ok(epoch)
}

/// Map a validation field onto its stable corruption invariant name.
///
/// Read paths never reuse `InvalidField`: a bad stored row is corruption the
/// caller cannot have caused, and the two must not be confused.
fn corrupt_field(field: &'static str) -> GenerationAuditError {
    GenerationAuditError::Corrupt(field)
}

fn to_db_u64(value: u64, field: &'static str) -> Audited<i64> {
    i64::try_from(value).map_err(|_| GenerationAuditError::InvalidField(field))
}

fn from_db_u64(value: i64, field: &'static str) -> Audited<u64> {
    u64::try_from(value).map_err(|_| GenerationAuditError::InvalidField(field))
}
