// SPDX-License-Identifier: Elastic-2.0

//! Durable registry of which automations are in service, and who withdrew the
//! ones that are not.
//!
//! `automonique_protocol::automation` models an automation as an immutable
//! `AutomationRevision`: a schedule, a set of pre-approved effects, an overlap
//! policy and an `AutomationEnablement` that is `Enabled`, `Paused` or
//! `Archived`. Every lifecycle move there produces a *new* revision value, and
//! the pause and archive shapes carry a `PauseCause` — an actor and a reason —
//! because a withdrawal with no stated cause is the one an operator cannot
//! safely resume from.
//!
//! Those are values in memory. Nothing in this product wrote them down. Restart
//! the daemon and every pause an operator entered is gone, which makes a pause
//! a suggestion rather than a decision. This module is the durable half. One row
//! per automation:
//!
//! ```text
//! automation_id -> (revision, enablement, actor, cause, created_at_ms, updated_at_ms)
//! ```
//!
//! There is no scheduling here, no clock, and no protocol dependency. Callers
//! supply every identifier and timestamp, so restarts stay deterministic and
//! tests do not depend on an ambient clock.
//!
//! # What a row is, and what it is not
//!
//! **A row records an operator's decision about whether an automation is in
//! service.** That is the whole of it.
//!
//! - **It does not schedule.** Nothing here evaluates a `CanonicalSchedule`,
//!   computes a next occurrence, or holds a timer. An `enabled` row means
//!   somebody said this automation may fire, not that anything will fire it.
//! - **It does not evaluate a trigger or fire an action.** `TriggerSpec`,
//!   `FilterExpression` and `AutomationAction` live in the protocol crate and
//!   are not stored here at all; the executor that would consume them does not
//!   exist in this release. A `paused` row therefore suppresses nothing today,
//!   because there is nothing running to suppress. It is written now so that the
//!   scheduler, when it lands, reads its enablement out of a durable record
//!   rather than inventing one.
//! - **It does not verify the actor.** [`AutomationRegistration::actor`] and
//!   [`EnablementTransition::actor`] are recorded exactly as supplied. This
//!   module cannot tell an operator from a runbook from a typo; authenticating
//!   the peer is the daemon's `SO_PEERCRED` check, and the protocol's
//!   `AutomationActor` says the same of itself — it names who asked, and is not
//!   a capability.
//! - **It does not store the automation.** The schedule, the approved-effect
//!   scope, the trigger, the action and the overlap policy are not columns here.
//!   Persisting the protocol's whole type graph would mean persisting a
//!   canonical rendering this module cannot re-validate without depending on the
//!   crate that defines it. What is durable is the spine an operator acts on:
//!   identity, revision, enablement, and attribution. An approved-effect scope
//!   recorded here would be an authority claim nothing checks, so there is none.
//!
//! # The enablement lattice
//!
//! [`EnablementState`] carries the three spellings
//! `automonique_protocol::automation::EnablementState` defines, and the
//! transitions this module admits are exactly the ordered pairs that crate's
//! `AutomationRevision::permits` admits:
//!
//! | from | to | why |
//! |---|---|---|
//! | `enabled` | `paused` | withdrawn from service, resumably |
//! | `paused` | `enabled` | put back, naming who reopened it |
//! | `enabled` / `paused` | `archived` | withdrawn permanently |
//!
//! Everything else is [`AutomationStoreError::IllegalTransition`]. Two cases are
//! worth naming because they look harmless:
//!
//! - **`archived` is terminal.** Nothing leaves it, not even to `archived`
//!   again. The protocol calls archiving permanent, and a store that let a row
//!   out of it would make the protocol's word untrue at the only layer that
//!   outlives a process.
//! - **A state never transitions to itself.** Pausing an already-paused
//!   automation is refused rather than accepted, for the reason the protocol
//!   gives: accepting it would overwrite the cause of the pause an operator
//!   still has to resume from. The same reasoning refuses `enabled -> enabled`,
//!   which would credit a resume to somebody who resumed nothing.
//!
//! # The cause is coupled to the state
//!
//! `paused` and `archived` require a non-empty cause; `enabled` requires its
//! absence. Both halves are refused
//! ([`AutomationStoreError::CauseRequired`] and
//! [`AutomationStoreError::CauseForbidden`]), the coupling is a database CHECK
//! so a second writer cannot break it, and it is re-checked on every read.
//!
//! This is the protocol's `AutomationEnablement` shape written into a table:
//! `Paused { cause }` and `Archived { cause }` have no causeless spelling, and
//! `Enabled { resumed_by }` has no cause field to put one in.
//!
//! ## Attribution, and how `resumed_by` survives the flattening
//!
//! `actor` is the last actor to change enablement, and it is written on every
//! transition, so a pause and the resume that follows it name different people
//! in the same column at different revisions. The protocol distinguishes an
//! automation that was never paused (`Enabled { resumed_by: None }`) from one
//! that was put back (`Enabled { resumed_by: Some(actor) }`), and one flat
//! column looks like it loses that. It does not: registration is the only writer
//! of `enabled` at revision `1`, and the only other way into `enabled` is
//! `paused -> enabled`. So an `enabled` row above revision `1` was resumed, and
//! [`AutomationRecord::resumed_by`] reports the actor for exactly those rows.
//!
//! What is genuinely not kept is *history*: this table holds one row per
//! automation, overwritten in place, so the actor and cause of a pause are lost
//! when it is resumed. The row answers "who withdrew this, and why" for the
//! withdrawal in force now, and nothing about earlier ones. An audit of every
//! transition is a second, append-only table — the shape
//! [`crate::generation_audit`] has — and it is not this one.
//!
//! # Pagination
//!
//! `entry_id` is monotonic in registration order and is the pagination key. A
//! cursor above the highest recorded `entry_id` is
//! [`AutomationStoreError::CursorOutOfRange`] rather than an empty page, because
//! those are different answers: one means "your cursor is gone", the other means
//! "there is nothing to show", and a listing that blurred them would let a UI
//! mistake the first for the second.
//!
//! `entry_id` is an explicit `INTEGER PRIMARY KEY` rather than the implicit
//! rowid of an `automation_id TEXT PRIMARY KEY` table, for one concrete reason:
//! SQLite may renumber the rowids of a table that has no `INTEGER PRIMARY KEY`
//! alias when it is `VACUUM`ed, and a renumbered rowid is a silently broken
//! cursor. `automation_id` remains a `UNIQUE NOT NULL` key, so there is still
//! exactly one row per automation.
//!
//! # Time
//!
//! Both timestamps are the caller's. This module does not require
//! `updated_at_ms` to be at or after `created_at_ms` and does not police clock
//! monotonicity, because it has no clock to police it against: a transition
//! arriving after an NTP step backwards is still a decision an operator made,
//! and refusing to record it would lose the decision to keep a timestamp tidy.
//! A reader that needs ordering has `revision`, which this module does enforce.
//!
//! # Storage discipline
//!
//! The registry owns its own SQLite database with its own `user_version`, opened
//! under the same privacy, WAL and `synchronous = FULL` rules as
//! [`crate::Store`], exactly as [`crate::cancel_ledger`], [`crate::run_index`]
//! and [`crate::generation_audit`] do. Every mutation is one immediate
//! transaction, revision-checked in the `UPDATE` itself. Every read re-validates
//! the row it loaded rather than trusting the database.
//!
//! # Deletion
//!
//! There is none, and no prune. `archived` is how an automation leaves service,
//! and it leaves the row behind on purpose: forgetting it would let the same
//! `automation_id` be registered again as a fresh `enabled` automation, quietly
//! undoing the archival. Capacity is [`AutomationStoreError::RegistryFull`],
//! never an eviction.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::{BUSY_TIMEOUT, StoreError, validate_database_path};

/// The only automation registry schema this build can read and write.
pub const AUTOMATION_STORE_SCHEMA_VERSION: u32 = 1;

/// Largest number of automations any registry will hold.
///
/// Nothing deletes from this table, so this is a hard ceiling on the lifetime of
/// one database file rather than a high-water mark. Archiving an automation
/// frees no room, which is the honest consequence of keeping the archival.
pub const MAX_AUTOMATIONS: usize = 65_536;

/// Longest accepted `automation_id`, `actor` or `cause`, in bytes.
///
/// The same identifier grammar [`crate::Store`] and [`crate::run_index`] use:
/// non-empty, at most this many bytes, no control characters. It is also the
/// grammar and the bound `automonique_protocol::automation`'s `bounded` applies
/// to these exact three fields under `MAX_AUTOMATION_FIELD_BYTES`, so a value
/// that crate accepts is a value this one stores.
pub const MAX_IDENTIFIER_BYTES: usize = 256;

/// Largest page [`AutomationStore::page`] and
/// [`AutomationStore::page_in_states`] will return.
pub const MAX_AUTOMATION_PAGE: usize = 512;

/// Schema v1.
///
/// The invariants a second writer must not be able to break are database
/// constraints: one row per `automation_id`, a positive revision, the closed
/// three-word enablement vocabulary, non-negative timestamps, and the coupling
/// between `enabled` and an absent cause.
///
/// The identifier grammar, the length bound, the transition lattice and the
/// agreement between a withdrawn state and a revision above one are deliberately
/// *not* database constraints: they are enforced on write and re-checked on
/// every read, so a row written around this API is refused rather than believed.
const SCHEMA_V1: &str = r#"
CREATE TABLE automations (
    entry_id INTEGER PRIMARY KEY,
    automation_id TEXT NOT NULL UNIQUE,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    enablement TEXT NOT NULL CHECK (
        enablement IN ('enabled', 'paused', 'archived')
    ),
    actor TEXT NOT NULL,
    cause TEXT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    CHECK ((enablement = 'enabled') = (cause IS NULL))
) STRICT;

CREATE INDEX automations_by_enablement ON automations(enablement, entry_id);
"#;

/// An automation registry error with stable refusal categories.
#[derive(Debug)]
pub enum AutomationStoreError {
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
    /// The automation identity is already registered.
    ///
    /// An automation is registered exactly once. Nothing was written, and the
    /// durable state travels with the refusal so a caller learns what it
    /// collided with without a second read — in particular that it may have
    /// collided with an `archived` automation, which is the collision a
    /// re-registration must not quietly resolve.
    AlreadyRegistered {
        /// Row the automation already occupies.
        entry_id: i64,
        /// Enablement that row records.
        enablement: EnablementState,
    },
    /// The referenced durable row does not exist.
    NotFound(&'static str),
    /// The requested enablement does not follow the durable one along the
    /// lattice.
    IllegalTransition {
        /// State the durable row records.
        from: EnablementState,
        /// State the caller asked for.
        to: EnablementState,
    },
    /// A withdrawal was requested with no stated cause.
    ///
    /// `paused` and `archived` both require one; see this module's
    /// documentation for why a causeless withdrawal is refused rather than
    /// recorded.
    CauseRequired {
        /// State that requires a cause.
        state: EnablementState,
    },
    /// A cause was supplied for a state that does not carry one.
    ///
    /// Only `enabled` refuses a cause. The pairing is incoherent rather than
    /// merely redundant: the protocol's `Enabled` shape has no field to hold it,
    /// so a stored cause on an `enabled` row would be a reason for a withdrawal
    /// that is not in force.
    CauseForbidden {
        /// State that admits no cause.
        state: EnablementState,
    },
    /// The caller's expected revision does not match the durable revision.
    RevisionMismatch {
        /// Revision the caller believed it was transitioning.
        expected: u64,
        /// Revision the durable row carries.
        durable: u64,
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
    /// The registry holds its full capacity of automations.
    ///
    /// Registration is refused *before* a row is written. Nothing here evicts,
    /// and archiving frees no room.
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

impl AutomationStoreError {
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
            Self::CauseRequired { .. } => "cause_required",
            Self::CauseForbidden { .. } => "cause_forbidden",
            Self::RevisionMismatch { .. } => "revision_mismatch",
            Self::CursorOutOfRange { .. } => "cursor_out_of_range",
            Self::RegistryFull { .. } => "registry_full",
            Self::Corrupt(_) => "corrupt",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}

impl fmt::Display for AutomationStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => {
                write!(
                    formatter,
                    "automation registry path is not private: {reason}"
                )
            }
            Self::SchemaVersion { found, supported } => write!(
                formatter,
                "automation registry schema {found} is unsupported; expected {supported}"
            ),
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::AlreadyRegistered {
                entry_id,
                enablement,
            } => write!(
                formatter,
                "automation is already registered at row {entry_id}, {}",
                enablement.as_str()
            ),
            Self::NotFound(entity) => write!(formatter, "no such {entity}"),
            Self::IllegalTransition { from, to } => write!(
                formatter,
                "automation enablement {} may not become {}",
                from.as_str(),
                to.as_str()
            ),
            Self::CauseRequired { state } => write!(
                formatter,
                "enablement {} requires a stated cause",
                state.as_str()
            ),
            Self::CauseForbidden { state } => {
                write!(formatter, "enablement {} admits no cause", state.as_str())
            }
            Self::RevisionMismatch { expected, durable } => write!(
                formatter,
                "expected revision {expected} but durable revision is {durable}"
            ),
            Self::CursorOutOfRange {
                supplied,
                retained_last,
            } => write!(
                formatter,
                "cursor {supplied} is above the retained entry_id {retained_last}"
            ),
            Self::RegistryFull { capacity } => write!(
                formatter,
                "automation registry holds its capacity of {capacity}"
            ),
            Self::Corrupt(invariant) => {
                write!(formatter, "stored row violates invariant: {invariant}")
            }
            Self::Io(error) => write!(formatter, "automation registry filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite error: {error}"),
        }
    }
}

impl Error for AutomationStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for AutomationStoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for AutomationStoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// Result of one automation registry operation.
pub type Registered<T> = Result<T, AutomationStoreError>;

/// Which of the three lifecycle states an automation is durably in.
///
/// Three variants, three spellings, mirroring
/// `automonique_protocol::automation::EnablementState` — the authority for both
/// this vocabulary and the lattice [`Self::may_transition_to`] admits, which is
/// that type's `AutomationRevision::permits` written out. This crate does not
/// depend on the protocol crate, so the spellings are pinned by literal here and
/// again in `tests/automation_store.rs`; a rename has to break both.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EnablementState {
    /// In service. Fires, once something exists that fires automations.
    Enabled,
    /// Withdrawn from service, resumable. Carries who withdrew it and why.
    Paused,
    /// Withdrawn permanently. Terminal, and carries who archived it and why.
    Archived,
}

impl EnablementState {
    /// Every state, in the protocol's declaration order. The set is closed:
    /// there is no fourth.
    pub const ALL: [Self; 3] = [Self::Enabled, Self::Paused, Self::Archived];

    /// Stable machine-oriented spelling, and the exact stored text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Paused => "paused",
            Self::Archived => "archived",
        }
    }

    /// Parse the exact stored text, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == value)
    }

    /// Whether an automation in this state may fire.
    ///
    /// Named after the protocol's `admits_occurrence`, and just as weak a claim:
    /// it says the operator has not withdrawn this automation, never that
    /// anything will run it.
    #[must_use]
    pub const fn admits_occurrence(self) -> bool {
        matches!(self, Self::Enabled)
    }

    /// Whether a row in this state must carry a stated cause.
    ///
    /// True for exactly the two withdrawn states, because those are the two the
    /// protocol gives a `PauseCause` and the one it does not.
    #[must_use]
    pub const fn requires_cause(self) -> bool {
        matches!(self, Self::Paused | Self::Archived)
    }

    /// Whether an automation in this state may next be moved to `next`.
    ///
    /// The whole lattice, in one place: `enabled <-> paused` both ways, either
    /// of them to `archived`, and nothing at all out of `archived`. No state
    /// transitions to itself; see this module's documentation for why a repeated
    /// pause is refused rather than absorbed.
    #[must_use]
    pub const fn may_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Enabled, Self::Paused)
                | (Self::Paused, Self::Enabled)
                | (Self::Enabled | Self::Paused, Self::Archived)
        )
    }
}

impl fmt::Display for EnablementState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One automation presented for registration.
///
/// The initial enablement is not a field: registration always writes `enabled`
/// at revision one with no cause, because that is the protocol's
/// `AutomationEnablement::newly_declared`. An operator that wants a paused
/// automation registers it and pauses it, and the pause then carries the cause
/// it owes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AutomationRegistration<'a> {
    /// Durable automation identity. The unique key.
    pub automation_id: &'a str,
    /// Who declared it. Recorded, never verified; see the module documentation.
    pub actor: &'a str,
    /// When it was declared, in caller-supplied milliseconds.
    pub now_ms: i64,
}

/// One requested move along the enablement lattice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnablementTransition<'a> {
    /// Automation whose row is being moved.
    pub automation_id: &'a str,
    /// Durable revision the caller believes it is moving. `1` at registration,
    /// and one higher after every accepted transition.
    pub expected_revision: u64,
    /// State to move to. Must follow the durable state along the lattice; see
    /// [`EnablementState::may_transition_to`].
    pub new_enablement: EnablementState,
    /// Who asked. Recorded on every transition, so a resume names whoever
    /// reopened the automation rather than whoever paused it.
    pub actor: &'a str,
    /// Why, for a withdrawal. Required for `paused` and `archived`, and refused
    /// for `enabled`.
    pub cause: Option<&'a str>,
    /// When, in caller-supplied milliseconds.
    pub now_ms: i64,
}

/// Durable identity and fencing revision of one registered or moved automation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AutomationReceipt {
    /// Row identity, monotonic in registration order. The pagination key.
    pub entry_id: i64,
    /// Enablement the row now records.
    pub enablement: EnablementState,
    /// Revision the row now carries. The next transition must expect this.
    pub revision: u64,
    /// Instant the row now records as its last change.
    pub updated_at_ms: i64,
}

/// Validated `automations` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationRecord {
    /// Row identity, monotonic in registration order.
    pub entry_id: i64,
    /// Durable automation identity.
    pub automation_id: String,
    /// `1` at registration, and one higher after every accepted transition.
    pub revision: u64,
    /// Whether the automation is in service.
    pub enablement: EnablementState,
    /// The last actor to change enablement, or the registrant while the row is
    /// still at revision one.
    pub actor: String,
    /// Why it was withdrawn. `Some` exactly when the state is withdrawn.
    pub cause: Option<String>,
    /// When the automation was registered.
    pub created_at_ms: i64,
    /// When its enablement last changed. Equal to `created_at_ms` at revision
    /// one.
    pub updated_at_ms: i64,
}

impl AutomationRecord {
    /// Whether the automation is in service.
    #[must_use]
    pub const fn admits_occurrence(&self) -> bool {
        self.enablement.admits_occurrence()
    }

    /// Who put this automation back in service, if anybody did.
    ///
    /// The protocol's `AutomationEnablement::Enabled { resumed_by }`, recovered
    /// from the flat columns: registration is the only writer of `enabled` at
    /// revision one, and `paused -> enabled` is the only other way in, so an
    /// `enabled` row above revision one was resumed and its `actor` is whoever
    /// reopened it. A never-paused automation answers `None`, exactly as
    /// `newly_declared` does.
    #[must_use]
    pub fn resumed_by(&self) -> Option<&str> {
        (self.enablement == EnablementState::Enabled && self.revision > 1)
            .then_some(self.actor.as_str())
    }
}

/// One bounded page of automation rows, ordered by `entry_id`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationPage {
    /// Rows above the requested cursor, oldest first.
    pub entries: Vec<AutomationRecord>,
    /// Cursor to present for the next page, or `None` when this page is the end
    /// of the query.
    ///
    /// Set only when a further matching row was seen, so an exhausted listing is
    /// distinguishable from one that merely filled its page.
    pub next_cursor: Option<u64>,
}

/// The window of `entry_id` values this registry still holds.
///
/// `first` is `1` in this release because nothing deletes. It is reported rather
/// than assumed so a caller keeps saying something true if that ever changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedAutomationRange {
    /// Lowest `entry_id` still recorded.
    pub first: u64,
    /// Highest `entry_id` recorded.
    pub last: u64,
}

/// Durable registry of automation enablement.
#[derive(Debug)]
pub struct AutomationStore {
    connection: Connection,
    path: PathBuf,
    capacity: usize,
}

impl AutomationStore {
    /// Open or initialize a registry inside an existing private directory.
    ///
    /// The parent must be owned by the effective user and deny all group and
    /// other access. Existing paths must be regular, owned, non-symlinks.
    /// Capacity is [`MAX_AUTOMATIONS`].
    ///
    /// # Errors
    ///
    /// Returns [`AutomationStoreError::InsecurePath`] for an unsafe path,
    /// [`AutomationStoreError::SchemaVersion`] for a foreign or future database,
    /// and the underlying I/O or SQLite failure otherwise.
    pub fn open(path: impl AsRef<Path>) -> Registered<Self> {
        Self::open_with_capacity(path, MAX_AUTOMATIONS)
    }

    /// Open a registry with a lowered capacity.
    ///
    /// `capacity` must be between one and [`MAX_AUTOMATIONS`]. It is a property
    /// of this handle, not of the database: opening an existing registry under a
    /// capacity below its row count refuses further registrations with
    /// [`AutomationStoreError::RegistryFull`] while transitions and reads keep
    /// working, because neither adds a row.
    ///
    /// # Errors
    ///
    /// As [`AutomationStore::open`], plus
    /// [`AutomationStoreError::InvalidField`] for a capacity outside the range.
    pub fn open_with_capacity(path: impl AsRef<Path>, capacity: usize) -> Registered<Self> {
        if capacity == 0 || capacity > MAX_AUTOMATIONS {
            return Err(AutomationStoreError::InvalidField("capacity"));
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
            return Err(AutomationStoreError::Sqlite(rusqlite::Error::InvalidQuery));
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

    /// Automation capacity of this handle.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Record a new automation, enabled, at revision one.
    ///
    /// One immediate transaction, so a reader after a crash sees the whole row
    /// or no row.
    ///
    /// An automation is registered exactly once. A second registration is
    /// [`AutomationStoreError::AlreadyRegistered`] and writes nothing, whatever
    /// state the recorded row is in — most pointedly when it is `archived`,
    /// where a re-registration that reset the row to `enabled` would be a way
    /// out of a terminal state that the lattice refuses to offer directly.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationStoreError::InvalidField`] for a malformed field,
    /// [`AutomationStoreError::AlreadyRegistered`] for a duplicate identity,
    /// [`AutomationStoreError::RegistryFull`] at capacity, and
    /// [`AutomationStoreError::Corrupt`] when the existing row it must compare
    /// against is not one this API could have written.
    pub fn register(
        &mut self,
        registration: AutomationRegistration<'_>,
    ) -> Registered<AutomationReceipt> {
        validate_identifier(registration.automation_id, "automation_id")?;
        validate_identifier(registration.actor, "actor")?;
        validate_time(registration.now_ms, "now_ms")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(recorded) = read_by_id(&transaction, registration.automation_id)? {
            return Err(AutomationStoreError::AlreadyRegistered {
                entry_id: recorded.entry_id,
                enablement: recorded.enablement,
            });
        }
        let live = count_automations(&transaction)?;
        if live >= self.capacity {
            return Err(AutomationStoreError::RegistryFull {
                capacity: self.capacity,
            });
        }
        transaction.execute(
            "INSERT INTO automations
             (automation_id, revision, enablement, actor, cause, created_at_ms, updated_at_ms)
             VALUES (?1, 1, ?2, ?3, NULL, ?4, ?4)",
            params![
                registration.automation_id,
                EnablementState::Enabled.as_str(),
                registration.actor,
                registration.now_ms,
            ],
        )?;
        let entry_id = transaction.last_insert_rowid();
        transaction.commit()?;
        Ok(AutomationReceipt {
            entry_id,
            enablement: EnablementState::Enabled,
            revision: 1,
            updated_at_ms: registration.now_ms,
        })
    }

    /// Move one automation along the enablement lattice.
    ///
    /// Revision-checked and lattice-checked in one immediate transaction. The
    /// guard is repeated in the `UPDATE` itself, so a row that moved between the
    /// read and the write cannot be overwritten even if a caller reached here
    /// with a revision that happened to match.
    ///
    /// The cause coupling is judged *before* the durable row is read, because it
    /// is a property of the request alone: a caller that asks to pause without
    /// stating why learns that regardless of what revision the row is at.
    ///
    /// What this call establishes is that somebody claiming to be `actor` asked
    /// for this move. It does not establish that they were entitled to; see the
    /// module documentation.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationStoreError::InvalidField`] for a malformed field,
    /// [`AutomationStoreError::CauseRequired`] or
    /// [`AutomationStoreError::CauseForbidden`] for an incoherent state and
    /// cause pairing, [`AutomationStoreError::NotFound`] for an unregistered
    /// automation, [`AutomationStoreError::RevisionMismatch`] for a stale
    /// expected revision, [`AutomationStoreError::IllegalTransition`] for a
    /// state that does not follow the durable one, and
    /// [`AutomationStoreError::Corrupt`] when the stored row is not one this API
    /// could have written.
    pub fn transition(
        &mut self,
        transition: EnablementTransition<'_>,
    ) -> Registered<AutomationReceipt> {
        validate_identifier(transition.automation_id, "automation_id")?;
        validate_identifier(transition.actor, "actor")?;
        validate_time(transition.now_ms, "now_ms")?;
        if transition.expected_revision == 0 {
            return Err(AutomationStoreError::InvalidField("expected_revision"));
        }
        let cause = match (transition.new_enablement.requires_cause(), transition.cause) {
            (true, Some(cause)) => {
                validate_identifier(cause, "cause")?;
                Some(cause)
            }
            (true, None) => {
                return Err(AutomationStoreError::CauseRequired {
                    state: transition.new_enablement,
                });
            }
            (false, Some(_)) => {
                return Err(AutomationStoreError::CauseForbidden {
                    state: transition.new_enablement,
                });
            }
            (false, None) => None,
        };

        let sql_transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = read_by_id(&sql_transaction, transition.automation_id)?
            .ok_or(AutomationStoreError::NotFound("automation"))?;
        if record.revision != transition.expected_revision {
            return Err(AutomationStoreError::RevisionMismatch {
                expected: transition.expected_revision,
                durable: record.revision,
            });
        }
        if !record
            .enablement
            .may_transition_to(transition.new_enablement)
        {
            return Err(AutomationStoreError::IllegalTransition {
                from: record.enablement,
                to: transition.new_enablement,
            });
        }
        let next_revision = record
            .revision
            .checked_add(1)
            .ok_or(AutomationStoreError::InvalidField("revision"))?;
        let changed = sql_transaction.execute(
            "UPDATE automations
             SET revision = ?3, enablement = ?4, actor = ?5, cause = ?6, updated_at_ms = ?7
             WHERE entry_id = ?1 AND revision = ?2",
            params![
                record.entry_id,
                to_db_u64(record.revision, "revision")?,
                to_db_u64(next_revision, "revision")?,
                transition.new_enablement.as_str(),
                transition.actor,
                cause,
                transition.now_ms,
            ],
        )?;
        if changed != 1 {
            // The row was read inside this immediate transaction, so nothing
            // else can have moved it; a disagreement means the stored row is not
            // what this API writes.
            return Err(AutomationStoreError::Corrupt("enablement_transition"));
        }
        sql_transaction.commit()?;
        Ok(AutomationReceipt {
            entry_id: record.entry_id,
            enablement: transition.new_enablement,
            revision: next_revision,
            updated_at_ms: transition.now_ms,
        })
    }

    /// The validated row one automation identity holds, if any.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationStoreError::InvalidField`] for a malformed identity
    /// and [`AutomationStoreError::Corrupt`] for a row this API could not have
    /// written.
    pub fn entry(&self, automation_id: &str) -> Registered<Option<AutomationRecord>> {
        validate_identifier(automation_id, "automation_id")?;
        read_by_id(&self.connection, automation_id)
    }

    /// One bounded page of every automation, ordered by `entry_id`, oldest
    /// first.
    ///
    /// `cursor` names the row to resume *after*; pass `0` to start at the
    /// beginning, and to advance, pass [`AutomationPage::next_cursor`]. `limit`
    /// must be between one and [`MAX_AUTOMATION_PAGE`].
    ///
    /// # Errors
    ///
    /// Returns [`AutomationStoreError::InvalidField`] for a limit outside its
    /// range, [`AutomationStoreError::CursorOutOfRange`] for a cursor above
    /// everything recorded, and [`AutomationStoreError::Corrupt`] for a row this
    /// API could not have written.
    pub fn page(&self, cursor: u64, limit: usize) -> Registered<AutomationPage> {
        self.read_page(cursor, limit, None)
    }

    /// One bounded page restricted to a set of enablement states.
    ///
    /// This is the listing an operator console asks for — "show me what is
    /// paused". `states` must be non-empty and free of repeats, because a filter
    /// that admits nothing is a query with no answer and a repeated state is a
    /// caller mistake this module refuses rather than silently folds.
    ///
    /// The cursor is judged against the whole registry, not against the filtered
    /// subset: a cursor is a position in the listing order, and a filter that
    /// excluded the row it names must not turn a resumable cursor into a
    /// refusal.
    ///
    /// A filter selects rows; it never hides one. A stored state outside the
    /// three-word vocabulary matches no filter, so such a row is selected anyway
    /// and refused as [`AutomationStoreError::Corrupt`] — a filtered listing and
    /// an unfiltered one answer a corrupt table identically.
    ///
    /// # Errors
    ///
    /// As [`AutomationStore::page`], plus
    /// [`AutomationStoreError::InvalidField`] for an empty or repeating state
    /// filter.
    pub fn page_in_states(
        &self,
        cursor: u64,
        limit: usize,
        states: &[EnablementState],
    ) -> Registered<AutomationPage> {
        if states.is_empty() {
            return Err(AutomationStoreError::InvalidField("states"));
        }
        for (position, state) in states.iter().enumerate() {
            if states[..position].contains(state) {
                return Err(AutomationStoreError::InvalidField("states"));
            }
        }
        self.read_page(cursor, limit, Some(states))
    }

    /// The window of `entry_id` values this registry holds, or `None` when
    /// empty.
    ///
    /// An empty registry has no retained window, and reporting `(0, 0)` would
    /// name a row no writer produced.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationStoreError::Corrupt`] for a stored bound outside the
    /// representable range.
    pub fn retained_range(&self) -> Registered<Option<RetainedAutomationRange>> {
        let bounds: (Option<i64>, Option<i64>) = self.connection.query_row(
            "SELECT MIN(entry_id), MAX(entry_id) FROM automations",
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
                Ok(Some(RetainedAutomationRange {
                    first: from_db_u64(first, "entry_id").map_err(|_| corrupt("entry_id"))?,
                    last: from_db_u64(last, "entry_id").map_err(|_| corrupt("entry_id"))?,
                }))
            }
            (None, None) => Ok(None),
            _ => Err(corrupt("entry_id")),
        }
    }

    /// Count durable automations.
    ///
    /// # Errors
    ///
    /// Returns the SQLite failure, or [`AutomationStoreError::Corrupt`] for a
    /// count outside the representable range.
    pub fn automation_count(&self) -> Registered<usize> {
        count_automations(&self.connection)
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
        states: Option<&[EnablementState]>,
    ) -> Registered<AutomationPage> {
        if limit == 0 || limit > MAX_AUTOMATION_PAGE {
            return Err(AutomationStoreError::InvalidField("limit"));
        }
        let after = to_db_u64(cursor, "cursor")?;
        let page = i64::try_from(limit).map_err(|_| AutomationStoreError::InvalidField("limit"))?;
        let lookahead = page
            .checked_add(1)
            .ok_or(AutomationStoreError::InvalidField("limit"))?;

        let transaction = self.connection.unchecked_transaction()?;
        let highest: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(entry_id), 0) FROM automations",
            [],
            |row| row.get(0),
        )?;
        let retained_last = from_db_u64(highest, "entry_id").map_err(|_| corrupt("entry_id"))?;
        if cursor > retained_last {
            return Err(AutomationStoreError::CursorOutOfRange {
                supplied: cursor,
                retained_last,
            });
        }

        // The filter is rendered as SQL literals rather than bound parameters
        // because its members are a closed enum whose spellings are fixed
        // lowercase ASCII words from `EnablementState::as_str`; there is no
        // caller-controlled text on this path.
        //
        // The second disjunct is what stops a filter from *hiding* a row: a
        // stored state outside the whole vocabulary matches no filter, so a
        // `WHERE enablement IN (...)` alone would drop a corrupt row from a
        // filtered listing while the unfiltered listing refused it. Selecting
        // those rows too means `validated_record` sees them and every listing
        // answers a corrupt table the same way.
        let filter = states.map_or_else(String::new, |states| {
            format!(
                " AND (enablement IN ({}) OR enablement NOT IN ({}))",
                state_literals(states),
                state_literals(&EnablementState::ALL)
            )
        });
        let mut statement = transaction.prepare(&format!(
            "SELECT {RECORD_COLUMNS} FROM automations
             WHERE entry_id > ?1{filter}
             ORDER BY entry_id LIMIT ?2"
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
            let last = entries.last().ok_or(corrupt("entry_id"))?.entry_id;
            Some(from_db_u64(last, "entry_id").map_err(|_| corrupt("entry_id"))?)
        } else {
            None
        };
        Ok(AutomationPage {
            entries,
            next_cursor,
        })
    }
}

/// Render a set of states as a comma-separated SQL literal list.
///
/// Safe by construction: every spelling comes from
/// [`EnablementState::as_str`], which returns one of three fixed lowercase ASCII
/// words.
fn state_literals(states: &[EnablementState]) -> String {
    states
        .iter()
        .map(|state| format!("'{}'", state.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

struct RawRecord {
    entry_id: i64,
    automation_id: String,
    revision: i64,
    enablement: String,
    actor: String,
    cause: Option<String>,
    created_at_ms: i64,
    updated_at_ms: i64,
}

const RECORD_COLUMNS: &str = "entry_id, automation_id, revision, enablement, \
                              actor, cause, created_at_ms, updated_at_ms";

fn raw_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRecord> {
    Ok(RawRecord {
        entry_id: row.get(0)?,
        automation_id: row.get(1)?,
        revision: row.get(2)?,
        enablement: row.get(3)?,
        actor: row.get(4)?,
        cause: row.get(5)?,
        created_at_ms: row.get(6)?,
        updated_at_ms: row.get(7)?,
    })
}

/// Re-derive an [`AutomationRecord`] from a stored row, refusing anything this
/// API could not have written.
///
/// Two cross-column invariants are checked here as well as the per-column ones,
/// because a database CHECK protects the table from a second writer while this
/// function protects callers from a row that got in anyway:
///
/// - a withdrawn state and a stated cause imply each other; and
/// - a withdrawn state implies `revision >= 2`, because registration is the only
///   writer of revision one and it always writes `enabled`.
///
/// The converse of the second is deliberately *not* checked: an `enabled` row
/// above revision one is a resumed automation, which is legal and is exactly
/// what [`AutomationRecord::resumed_by`] reports.
fn validated_record(raw: RawRecord) -> Registered<AutomationRecord> {
    let enablement =
        EnablementState::from_spelling(&raw.enablement).ok_or(corrupt("enablement"))?;
    let cause = match raw.cause {
        Some(cause) => Some(checked_identifier(cause, "cause")?),
        None => None,
    };
    if enablement.requires_cause() != cause.is_some() {
        return Err(corrupt("cause"));
    }
    let revision = from_db_u64(raw.revision, "revision").map_err(|_| corrupt("revision"))?;
    if revision == 0 {
        return Err(corrupt("revision"));
    }
    if enablement.requires_cause() && revision < 2 {
        return Err(corrupt("revision"));
    }
    Ok(AutomationRecord {
        entry_id: checked_row_id(raw.entry_id, "entry_id")?,
        automation_id: checked_identifier(raw.automation_id, "automation_id")?,
        revision,
        enablement,
        actor: checked_identifier(raw.actor, "actor")?,
        cause,
        created_at_ms: checked_time(raw.created_at_ms, "created_at_ms")?,
        updated_at_ms: checked_time(raw.updated_at_ms, "updated_at_ms")?,
    })
}

fn read_by_id(
    connection: &Connection,
    automation_id: &str,
) -> Registered<Option<AutomationRecord>> {
    let raw = connection
        .query_row(
            &format!("SELECT {RECORD_COLUMNS} FROM automations WHERE automation_id = ?1"),
            [automation_id],
            raw_record,
        )
        .optional()?;
    raw.map(validated_record).transpose()
}

fn count_automations(connection: &Connection) -> Registered<usize> {
    let count: i64 =
        connection.query_row("SELECT count(*) FROM automations", [], |row| row.get(0))?;
    usize::try_from(count).map_err(|_| corrupt("automation_count"))
}

fn secure_path(path: &Path) -> Registered<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => AutomationStoreError::Io(io),
        other => AutomationStoreError::InsecurePath(other.to_string()),
    })
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Registered<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == AUTOMATION_STORE_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(AutomationStoreError::SchemaVersion {
            found: version,
            supported: AUTOMATION_STORE_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(AutomationStoreError::SchemaVersion {
            found: 0,
            supported: AUTOMATION_STORE_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", AUTOMATION_STORE_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

/// The grammar `automonique_protocol::automation`'s `bounded` applies to an
/// automation identity, an actor and a pause reason alike.
fn validate_identifier(value: &str, field: &'static str) -> Registered<()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(AutomationStoreError::InvalidField(field));
    }
    Ok(())
}

fn validate_time(value: i64, field: &'static str) -> Registered<()> {
    if value < 0 {
        return Err(AutomationStoreError::InvalidField(field));
    }
    Ok(())
}

fn checked_identifier(value: String, field: &'static str) -> Registered<String> {
    validate_identifier(&value, field).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_time(value: i64, field: &'static str) -> Registered<i64> {
    validate_time(value, field).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_row_id(value: i64, field: &'static str) -> Registered<i64> {
    if value <= 0 {
        return Err(corrupt(field));
    }
    Ok(value)
}

/// Map a validation field onto its stable corruption invariant name.
///
/// Read paths never reuse `InvalidField`: a bad stored row is corruption the
/// caller cannot have caused, and the two must not be confused.
const fn corrupt(field: &'static str) -> AutomationStoreError {
    AutomationStoreError::Corrupt(field)
}

fn to_db_u64(value: u64, field: &'static str) -> Registered<i64> {
    i64::try_from(value).map_err(|_| AutomationStoreError::InvalidField(field))
}

fn from_db_u64(value: i64, field: &'static str) -> Registered<u64> {
    u64::try_from(value).map_err(|_| AutomationStoreError::InvalidField(field))
}
