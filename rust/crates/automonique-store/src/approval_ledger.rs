// SPDX-License-Identifier: Elastic-2.0

//! Durable, write-once custody of approval decisions: what was approved, by
//! whom, and when it was decided.
//!
//! Approvals are referenced all over this product and, until this module, were
//! written down in exactly one place and only there.
//! `automonique_protocol::command_registry` gives ten admin commands an
//! `ApprovalPolicy` and says plainly that
//! `ApprovalPolicy::OperatorConfirmation` is a *client-side* obligation the
//! daemon cannot observe, adding that "a named-approver policy — a second,
//! identified party recorded durably — is not represented, because there is no
//! approver identity in this product to name".
//! `automonique_protocol::automation` answers an unattended effect with
//! `UnattendedDecision::RequiresApproval`, and `automonique_protocol::connector`
//! refuses with `ApprovalRequired`. Every one of those is a value in memory:
//! restart the process and no record survives that anybody decided anything.
//!
//! This module is the durable half. One row per decision:
//!
//! ```text
//! approval_key -> (subject, decision, decider, decided_at_ms)
//! ```
//!
//! and it answers three ways and only three ways:
//!
//! - the key is new: the decision is recorded, [`ApprovalDisposition::Recorded`];
//! - the key is present with the *same* subject, decision and decider: it is an
//!   exact replay, [`ApprovalDisposition::AlreadyRecorded`], and not one byte of
//!   the durable row changes;
//! - the key is present with any of those three differing:
//!   [`ApprovalLedgerError::Conflict`] naming the first field that differs, and
//!   nothing is written.
//!
//! There is no approval IO here, no clock and no protocol dependency. Callers
//! supply every identifier and timestamp, so retries stay deterministic and
//! tests do not depend on an ambient clock.
//!
//! # What a row establishes, and what it does not
//!
//! **A row is evidence that a decision was recorded, and that somebody
//! identifying themselves as `decider` was named as having made it.** That is
//! the whole of it. In particular:
//!
//! - **It does not enforce the decision.** Nothing in *this module* gates
//!   anything: it stores rows and answers questions about them.
//!
//!   What a row means to a reader now depends on its key, and the difference is
//!   worth stating plainly because this comment used to say the opposite. A row
//!   under an `apr-` key answers a durable proposal in
//!   [`crate::approval_requests`], and the daemon reads it **in front of** the
//!   launch it is about: a `granted` row there admits a run and a `denied` row
//!   refuses one. A row under any other key is written beside an action rather
//!   than in front of it, because there is no proposal for it to answer and no
//!   launch bound to it, and for those a reader must still not treat the
//!   presence of a row as proof that anything was allowed or blocked.
//!
//!   Neither reading is this module's to make. It records; the gate is
//!   `automonique-daemon`'s, and it is the only thing that turns a row into a
//!   permission.
//! - **It does not verify the decider's authority.** `decider` is recorded
//!   exactly as supplied; this module cannot tell an operator from a runbook
//!   from a typo. Authenticating the local peer is the daemon's `SO_PEERCRED`
//!   check, and `automonique_protocol::command_registry` already says its
//!   `AuthorizationRequirement` has only that check behind it. Recording an
//!   approver's name does not turn the protocol's client-side obligation into a
//!   server-side one, and this module does not claim otherwise.
//! - **It does not bind the decision to a live provider session.** That is
//!   [`crate::provider_journal`]'s `provider_approvals` binding; see below.
//! - **It does not decide which of several decisions governs.** A subject may
//!   carry a grant and, later, a denial. [`ApprovalLedger::by_subject`] returns
//!   them in the order they were recorded and stops there. Nothing here knows
//!   whether a later grant supersedes an earlier denial or whether two rows
//!   sharing a subject string described different scopes, so "the decision in
//!   force" is the caller's policy and is deliberately not a method.
//!
//! # Relationship to [`crate::provider_journal`]
//!
//! That module already records approvals, and the overlap is real and worth
//! naming rather than glossing. Its `provider_approvals` table holds
//! `(session_id, approval_key) -> (decision, deciding_actor, decided_ms)`,
//! keyed on the pair, foreign-keyed to `provider_sessions`, and written only
//! through `record_approval`, which refuses unless that session is still open.
//! The columns are nearly this table's columns.
//!
//! They are not the same record, because the identity is not the same:
//!
//! | | `provider_journal` | this module |
//! |---|---|---|
//! | key | `(session_id, approval_key)` | `approval_key`, host-wide unique |
//! | question answered | which approvals did *this provider session* run under | was this approval decided, for what, by whom |
//! | precondition | the session exists and is open | none |
//! | what was approved | not stored; the key is the only description | `subject`, stored beside the key |
//! | lifetime | the session's, in the journal's database | its own database, until the file is removed |
//!
//! The consequences are concrete. The journal cannot record a decision that has
//! no provider session — an operator confirming an admin command, an automation
//! effect approved out of band, a decision made before any provider is spawned
//! — because there is no open `session_id` to hang it on. It also, correctly for
//! its purpose, lets the *same* `approval_key` carry different decisions under
//! two different sessions; a store of decision custody must not, because then a
//! key would have no single answer. This module is the cross-cutting decision
//! record; the journal's row is the per-session binding that says a particular
//! provider session ran under it.
//!
//! So both exist, and a decision that gates a provider turn belongs in both.
//! The cost of that is stated rather than buried: **the two live in separate
//! databases and no transaction spans them**, exactly the seam
//! [`crate::run_index`] documents against [`crate::run_submissions`]. A caller
//! that writes only the journal has a session binding with no durable custody
//! of who decided; a caller that writes only this ledger has custody of a
//! decision no session is bound to. Ordering the two writes is the caller's
//! duty, and the failure it buys is a bounded one — a disagreement between two
//! records, not a lost decision.
//!
//! # Write-once, and why a reversal is a new key
//!
//! There is no update path. Not a revision-fenced one, not a
//! same-actor-may-amend one: [`ApprovalLedger::record`] is the only writer and
//! it either inserts a new row or touches nothing at all. A decision is never
//! silently overwritten, because an approval that can be edited in place is not
//! evidence of anything — a `denied` row that a later call could turn into
//! `granted` would let the record of a refusal disappear into the record of a
//! permission, leaving no trace that the refusal ever happened.
//!
//! Reversing a decision is therefore a **new** row: a new `approval_key`, which
//! is what makes it a new decision rather than an edit of the old one, naming
//! the same subject if that is what was reconsidered. Both rows survive, and
//! [`ApprovalLedger::by_subject`] shows the sequence. What the ledger will not
//! do is tell you which one won; see above.
//!
//! The `revision` column exists and is pinned to `1` by a database CHECK. Every
//! other durable module in this crate uses `revision` as a fencing token for an
//! in-place update; here there are no in-place updates, so the column is
//! constant, and the constraint is what makes "write-once" a property of the
//! table rather than a promise of this file. A stored row above revision one is
//! [`ApprovalLedgerError::Corrupt`].
//!
//! # The decision vocabulary
//!
//! [`ApprovalDecision`] is two-valued and closed: `granted` and `denied`.
//!
//! The spellings are pinned by literal here and again in
//! `tests/approval_ledger.rs`, and the pin has an honest gap in it. This crate
//! does not depend on `automonique-protocol` — its dependencies are `nix` and
//! `rusqlite` — so no compile-time link to the protocol exists, and any
//! agreement has to be asserted rather than derived. Worse, the protocol has no
//! approval *decision* type to derive from: its approval vocabulary is a
//! policy (`command_registry::ApprovalPolicy::{None, OperatorConfirmation}`) and
//! a pair of two-valued outcomes (`automation::UnattendedDecision::{PreApproved,
//! RequiresApproval}`, `automation::ActionBinding::{Bound, RequiresApproval}`)
//! that name whether an approval is *needed*, never what a human answered.
//!
//! So the authority for these two words is stated exactly:
//!
//! - **`denied` is the protocol's own spelling for a refusal**, rendered by
//!   `automonique_protocol::sandbox::NetworkAccess::Denied` and
//!   `automonique_protocol::connector_conformance::DispositionOutcome::Denied`;
//! - **`granted`/`denied` together are the pair
//!   [`crate::provider_journal`]'s `ApprovalDecision` already writes** into the
//!   `provider_approvals` column, under the identical
//!   `CHECK (decision IN ('granted', 'denied'))`. Since the daemon writes both
//!   tables for the same human answer, a disagreement between the two columns
//!   would be a bug that only showed up as an unreadable row much later.
//!
//! This module does not reuse that enum: the journal's renderer and parser are
//! module-private, and the two tables carry their own schema versions and must
//! be able to move independently. `tests/approval_ledger.rs` pins the agreement
//! from the other side, so a rename in either module fails a test rather than
//! landing.
//!
//! # Bounds
//!
//! `approval_key`, `subject` and `decider` share the identifier grammar
//! [`crate::Store`] uses: non-empty, at most [`MAX_IDENTIFIER_BYTES`] bytes, no
//! control characters. `subject` is therefore a bounded *name* for what was
//! approved — a command id, an effect name, a digest — and not the thing
//! itself. Anything larger has to be named by a digest recorded elsewhere,
//! which is the same trade [`crate::provider_journal`] makes for values it
//! binds without storing.
//!
//! # Capacity, and the absence of a prune
//!
//! Capacity is [`ApprovalLedgerError::LedgerFull`], never an eviction, and
//! there is **no prune at all** — no retention window, no horizon, no
//! caller-declared terminal set. [`crate::cancel_ledger`] has a prune and
//! states its cost (a pruned reference is forgotten, so it is delivered a second
//! time). Here that cost is not payable: forgetting a `denied` row would let the
//! denied thing be presented again as a fresh, undecided request and approved
//! without anyone knowing it had already been refused. A denial that expires by
//! garbage collection is not a denial.
//!
//! What that buys is stated plainly: [`MAX_APPROVAL_DECISIONS`] is a hard
//! ceiling on the lifetime of one database file, not a high-water mark. A full
//! ledger refuses new decisions while still replaying and reading every decision
//! it holds, because a replay writes nothing.
//!
//! # Storage discipline
//!
//! The ledger owns its own SQLite database with its own `user_version`, opened
//! under the same privacy, WAL and `synchronous = FULL` rules as
//! [`crate::Store`], exactly as [`crate::cancel_ledger`],
//! [`crate::automation_store`] and [`crate::run_index`] do. Recording one
//! decision is one immediate transaction, so a reader after a crash sees the
//! whole row or no row. Every read re-validates the row it loaded rather than
//! trusting the database.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::{StoreError, validate_database_path};

/// The only approval ledger schema this build can read and write.
pub const APPROVAL_LEDGER_SCHEMA_VERSION: u32 = 1;

/// Largest number of decisions any ledger will hold.
///
/// Nothing deletes from this table and there is no prune, so this is a hard
/// ceiling on the lifetime of one database file rather than a high-water mark.
/// That is the honest consequence of keeping every decision; see the module
/// documentation for why forgetting one is worse.
pub const MAX_APPROVAL_DECISIONS: usize = 65_536;

/// Longest accepted `approval_key`, `subject` or `decider`, in bytes.
///
/// The same identifier grammar [`crate::Store`], [`crate::cancel_ledger`] and
/// [`crate::automation_store`] use: non-empty, at most this many bytes, no
/// control characters.
pub const MAX_IDENTIFIER_BYTES: usize = 256;

/// Largest page [`ApprovalLedger::page`] and [`ApprovalLedger::by_subject`]
/// will return.
pub const MAX_APPROVAL_PAGE: usize = 512;

/// Schema v1.
///
/// The invariants a second writer must not be able to break are database
/// constraints: one row per `approval_key`, the closed two-word decision
/// vocabulary, a non-negative decision instant, and `revision = 1` — which is
/// how write-once becomes a property of the table rather than of this file.
///
/// The identifier grammar and the length bound are deliberately *not* database
/// constraints: they are enforced on write and re-checked on every read, so a
/// row written around this API is refused rather than believed.
const SCHEMA_V1: &str = r#"
CREATE TABLE approval_decisions (
    entry_id INTEGER PRIMARY KEY,
    approval_key TEXT NOT NULL UNIQUE,
    subject TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('granted', 'denied')),
    decider TEXT NOT NULL,
    decided_at_ms INTEGER NOT NULL CHECK (decided_at_ms >= 0),
    revision INTEGER NOT NULL CHECK (revision = 1)
) STRICT;

CREATE INDEX approval_decisions_by_subject
    ON approval_decisions(subject, entry_id);
"#;

/// An approval ledger error with stable refusal categories.
#[derive(Debug)]
pub enum ApprovalLedgerError {
    /// The ledger path or its containing directory is not private and owned.
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
    /// A recorded `approval_key` was presented with a different decision.
    ///
    /// Nothing was written, and nothing ever will be for this key: there is no
    /// update path, and a decision that has genuinely changed is a new key. The
    /// recorded decision travels with the refusal so a caller learns what it
    /// collided with without a second read.
    Conflict {
        /// First field that differs: `subject`, `decision` or `decider`.
        field: &'static str,
        /// Row the durable decision occupies.
        entry_id: i64,
        /// Subject the durable row records.
        recorded_subject: String,
        /// Decision the durable row records.
        recorded_decision: ApprovalDecision,
        /// Decider the durable row records.
        recorded_decider: String,
    },
    /// A page was requested from a cursor above everything recorded.
    ///
    /// An empty page is a different answer and is never reported this way.
    CursorOutOfRange {
        /// Cursor the caller presented.
        supplied: u64,
        /// Highest `entry_id` recorded, or zero when the ledger is empty.
        retained_last: u64,
    },
    /// The ledger holds its full capacity of decisions.
    ///
    /// Recording is refused rather than evicting an older decision, and there
    /// is no prune to make room. An exact replay is unaffected, because a
    /// replay writes nothing.
    LedgerFull {
        /// Capacity of the handle that refused.
        capacity: usize,
    },
    /// A stored row violates an invariant this API can only have written once.
    Corrupt(&'static str),
    /// Filesystem failure while establishing the private ledger.
    Io(std::io::Error),
    /// SQLite rejected an operation.
    Sqlite(rusqlite::Error),
}

impl ApprovalLedgerError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::Conflict { .. } => "conflict",
            Self::CursorOutOfRange { .. } => "cursor_out_of_range",
            Self::LedgerFull { .. } => "ledger_full",
            Self::Corrupt(_) => "corrupt",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}

impl fmt::Display for ApprovalLedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => {
                write!(formatter, "approval ledger path is not private: {reason}")
            }
            Self::SchemaVersion { found, supported } => write!(
                formatter,
                "approval ledger schema {found} is unsupported; expected {supported}"
            ),
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::Conflict {
                field,
                entry_id,
                recorded_subject,
                recorded_decision,
                recorded_decider,
            } => write!(
                formatter,
                "approval_key is already recorded at row {entry_id}: {} for subject \
                 {recorded_subject} by {recorded_decider}; {field} differs",
                recorded_decision.as_str()
            ),
            Self::CursorOutOfRange {
                supplied,
                retained_last,
            } => write!(
                formatter,
                "cursor {supplied} is above the retained entry_id {retained_last}"
            ),
            Self::LedgerFull { capacity } => {
                write!(
                    formatter,
                    "approval ledger holds its capacity of {capacity}"
                )
            }
            Self::Corrupt(invariant) => {
                write!(formatter, "stored row violates invariant: {invariant}")
            }
            Self::Io(error) => write!(formatter, "approval ledger filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite error: {error}"),
        }
    }
}

impl Error for ApprovalLedgerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ApprovalLedgerError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for ApprovalLedgerError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// Result of one approval ledger operation.
pub type Recorded<T> = Result<T, ApprovalLedgerError>;

/// What a decider answered.
///
/// Two variants, two spellings, and the set is closed: there is no "pending"
/// and no "expired". A decision that was never made has no row, and a decision
/// that was reconsidered is a second row under a new key — see the module
/// documentation for both.
///
/// Where the question itself lives is [`crate::approval_requests`], which does
/// have a pending state and an expired one. That split is deliberate: an
/// expiry is the *absence* of an answer, and giving this enum a third variant
/// for it would let a sweeper write a decision nobody made.
///
/// The spellings are the ones [`crate::provider_journal`]'s `ApprovalDecision`
/// already writes, and `denied` is the protocol's own spelling for a refusal.
/// The module documentation states exactly how far that authority reaches and
/// where the pin has to be a literal one.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ApprovalDecision {
    /// The subject was approved.
    Granted,
    /// The subject was refused.
    Denied,
}

impl ApprovalDecision {
    /// Both decisions. The set is closed: there is no third.
    pub const ALL: [Self; 2] = [Self::Granted, Self::Denied];

    /// Stable machine-oriented spelling, and the exact stored text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Denied => "denied",
        }
    }

    /// Parse the exact stored text, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|decision| decision.as_str() == value)
    }

    /// Whether this decision was an approval.
    ///
    /// As weak a claim as the row it comes from: it says somebody was recorded
    /// as approving the subject, never that the subject was permitted to
    /// happen. This module enforces nothing.
    #[must_use]
    pub const fn grants(self) -> bool {
        matches!(self, Self::Granted)
    }
}

impl fmt::Display for ApprovalDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One approval decision presented for durable recording.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalDecisionRecord<'a> {
    /// Bounded opaque idempotency identity chosen by the caller. The unique
    /// key, host-wide.
    pub approval_key: &'a str,
    /// Bounded opaque name for what was decided. Part of the replay identity:
    /// the same key describing a different subject is a conflict, not a
    /// correction.
    pub subject: &'a str,
    /// What was answered.
    pub decision: ApprovalDecision,
    /// Who answered. Recorded, never verified; see the module documentation.
    pub decider: &'a str,
    /// When, in caller-supplied milliseconds.
    ///
    /// Not part of the replay identity: a retry naturally carries a later
    /// clock, so a differing timestamp is an exact replay and never rewrites
    /// the recorded one. [`crate::provider_journal`] decides this the other
    /// way for its per-session binding, where a differing `decided_ms`
    /// conflicts; the divergence is deliberate. A caller that lost the answer
    /// to its first `record` and retries it should get the first answer back,
    /// not a refusal reporting a clock it never controlled.
    pub decided_at_ms: i64,
}

/// How the ledger answered one recording.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDisposition {
    /// The decision was new and is now durable.
    Recorded,
    /// The exact decision was already durable. Nothing changed.
    AlreadyRecorded,
}

impl ApprovalDisposition {
    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::AlreadyRecorded => "already_recorded",
        }
    }
}

impl fmt::Display for ApprovalDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Durable identity of one recorded or replayed approval decision.
///
/// There is no `revision` here, and its absence is deliberate: a caller has
/// nothing to fence against, because no second write to this row exists. The
/// stored column is reported on [`ApprovalEntry`], where a reader can see that
/// it is one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalReceipt {
    /// Row identity of the durable decision. The pagination key.
    pub entry_id: i64,
    /// Whether this call wrote the row or found it.
    pub disposition: ApprovalDisposition,
    /// The instant the durable row records.
    ///
    /// On an [`ApprovalDisposition::AlreadyRecorded`] answer this is the
    /// *first* recording's instant, not the one this call supplied.
    pub decided_at_ms: i64,
}

/// Validated `approval_decisions` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalEntry {
    /// Row identity, monotonic in recording order.
    pub entry_id: i64,
    /// Durable idempotency identity.
    pub approval_key: String,
    /// What was decided.
    pub subject: String,
    /// What was answered.
    pub decision: ApprovalDecision,
    /// Who was recorded as answering.
    pub decider: String,
    /// When the decision was recorded as made.
    pub decided_at_ms: i64,
    /// Always `1`. Write-once rows have no second revision; the column is a
    /// database CHECK, and anything else is corruption.
    pub revision: u64,
}

impl ApprovalEntry {
    /// Whether the recorded decision was an approval.
    ///
    /// See [`ApprovalDecision::grants`] for how little that establishes.
    #[must_use]
    pub const fn grants(&self) -> bool {
        self.decision.grants()
    }
}

/// One bounded page of decisions, ordered by `entry_id`, oldest first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalPage {
    /// Rows above the requested cursor, oldest first.
    pub entries: Vec<ApprovalEntry>,
    /// Cursor to present for the next page, or `None` when this page is the end
    /// of the query.
    ///
    /// Set only when a further matching row was seen, so an exhausted listing
    /// is distinguishable from one that merely filled its page.
    pub next_cursor: Option<u64>,
}

/// The window of `entry_id` values this ledger still holds.
///
/// `first` is `1` in this release and in every release that keeps the no-prune
/// rule. It is reported rather than assumed so a caller keeps saying something
/// true if that ever changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedApprovalRange {
    /// Lowest `entry_id` still recorded.
    pub first: u64,
    /// Highest `entry_id` recorded.
    pub last: u64,
}

/// Durable, write-once ledger of approval decisions.
#[derive(Debug)]
pub struct ApprovalLedger {
    connection: Connection,
    path: PathBuf,
    capacity: usize,
}

impl ApprovalLedger {
    /// Open or initialize a ledger inside an existing private directory.
    ///
    /// The parent must be owned by the effective user and deny all group and
    /// other access. Existing paths must be regular, owned, non-symlinks.
    /// Capacity is [`MAX_APPROVAL_DECISIONS`].
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalLedgerError::InsecurePath`] for an unsafe path,
    /// [`ApprovalLedgerError::SchemaVersion`] for a foreign or future database,
    /// and the underlying I/O or SQLite failure otherwise.
    pub fn open(path: impl AsRef<Path>) -> Recorded<Self> {
        Self::open_with_capacity(path, MAX_APPROVAL_DECISIONS)
    }

    /// Open a ledger with a lowered capacity.
    ///
    /// `capacity` must be between one and [`MAX_APPROVAL_DECISIONS`]. It is a
    /// property of this handle, not of the database: opening an existing ledger
    /// under a capacity below its row count refuses further recordings with
    /// [`ApprovalLedgerError::LedgerFull`] while exact replays and reads keep
    /// working, because a replay writes nothing.
    ///
    /// # Errors
    ///
    /// As [`ApprovalLedger::open`], plus
    /// [`ApprovalLedgerError::InvalidField`] for a capacity outside the range.
    pub fn open_with_capacity(path: impl AsRef<Path>, capacity: usize) -> Recorded<Self> {
        if capacity == 0 || capacity > MAX_APPROVAL_DECISIONS {
            return Err(ApprovalLedgerError::InvalidField("capacity"));
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

    /// Exact path opened by this ledger.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Decision capacity of this handle.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Record one approval decision, write-once.
    ///
    /// One immediate transaction: after a crash a reader sees the whole row or
    /// no row, never half of one.
    ///
    /// The lookup precedes the capacity check, so an exact replay is still
    /// answered [`ApprovalDisposition::AlreadyRecorded`] in a full ledger — a
    /// replay writes nothing and must never degrade into a refusal. A
    /// conflicting reuse is likewise [`ApprovalLedgerError::Conflict`] rather
    /// than [`ApprovalLedgerError::LedgerFull`], because the reuse is a caller
    /// bug regardless of how full the ledger is.
    ///
    /// The three identity fields are compared in declaration order and the
    /// first difference is the one reported, so a conflict names one field
    /// rather than a set.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalLedgerError::InvalidField`] for a malformed field,
    /// [`ApprovalLedgerError::Conflict`] for a key presented with a different
    /// decision, [`ApprovalLedgerError::LedgerFull`] at capacity, and
    /// [`ApprovalLedgerError::Corrupt`] when the existing row it must compare
    /// against is not one this API could have written.
    pub fn record(&mut self, record: ApprovalDecisionRecord<'_>) -> Recorded<ApprovalReceipt> {
        validate_identifier(record.approval_key, "approval_key")?;
        validate_identifier(record.subject, "subject")?;
        validate_identifier(record.decider, "decider")?;
        validate_time(record.decided_at_ms, "decided_at_ms")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(durable) = read_by_key(&transaction, record.approval_key)? {
            return replay_or_conflict(&durable, &record);
        }
        let live = count_decisions(&transaction)?;
        if live >= self.capacity {
            return Err(ApprovalLedgerError::LedgerFull {
                capacity: self.capacity,
            });
        }
        transaction.execute(
            "INSERT INTO approval_decisions
             (approval_key, subject, decision, decider, decided_at_ms, revision)
             VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            params![
                record.approval_key,
                record.subject,
                record.decision.as_str(),
                record.decider,
                record.decided_at_ms,
            ],
        )?;
        let entry_id = transaction.last_insert_rowid();
        transaction.commit()?;
        Ok(ApprovalReceipt {
            entry_id,
            disposition: ApprovalDisposition::Recorded,
            decided_at_ms: record.decided_at_ms,
        })
    }

    /// The validated decision one key records, if any.
    ///
    /// `None` means nothing was recorded under this key — never that the
    /// subject behind it was refused. An unrecorded decision and a `denied` one
    /// are different answers.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalLedgerError::InvalidField`] for a malformed key and
    /// [`ApprovalLedgerError::Corrupt`] for a row this API could not have
    /// written.
    pub fn entry(&self, approval_key: &str) -> Recorded<Option<ApprovalEntry>> {
        validate_identifier(approval_key, "approval_key")?;
        read_by_key(&self.connection, approval_key)
    }

    /// One bounded page of every decision, ordered by `entry_id`, oldest first.
    ///
    /// `cursor` names the row to resume *after*; pass `0` to start at the
    /// beginning, and to advance, pass [`ApprovalPage::next_cursor`]. `limit`
    /// must be between one and [`MAX_APPROVAL_PAGE`].
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalLedgerError::InvalidField`] for a limit outside its
    /// range, [`ApprovalLedgerError::CursorOutOfRange`] for a cursor above
    /// everything recorded, and [`ApprovalLedgerError::Corrupt`] for a row this
    /// API could not have written.
    pub fn page(&self, cursor: u64, limit: usize) -> Recorded<ApprovalPage> {
        self.read_page(cursor, limit, None)
    }

    /// One bounded page of the decisions recorded against one subject, oldest
    /// first.
    ///
    /// This is the decision history of a subject: a grant and the later denial
    /// that reconsidered it are two rows here, in the order they were recorded.
    /// Which of them governs is not this module's answer; see the module
    /// documentation.
    ///
    /// The cursor is judged against the whole ledger, not against the matching
    /// subset: a cursor is a position in the listing order, and a filter that
    /// excluded the row it names must not turn a resumable cursor into a
    /// refusal.
    ///
    /// The filter is an equality on an opaque column rather than a membership
    /// test over a closed vocabulary, so — unlike
    /// [`crate::automation_store::AutomationStore::page_in_states`] — there is
    /// no spelling a corrupt row could fall outside of to be silently dropped
    /// from a listing. A row this subject selects is validated like any other
    /// and refused as [`ApprovalLedgerError::Corrupt`] if it is not one this
    /// API wrote; a row another subject selects was never this query's answer.
    /// [`ApprovalLedger::page`] is the listing that sees every row.
    ///
    /// # Errors
    ///
    /// As [`ApprovalLedger::page`], plus
    /// [`ApprovalLedgerError::InvalidField`] for a malformed subject.
    pub fn by_subject(&self, subject: &str, cursor: u64, limit: usize) -> Recorded<ApprovalPage> {
        validate_identifier(subject, "subject")?;
        self.read_page(cursor, limit, Some(subject))
    }

    /// The window of `entry_id` values this ledger holds, or `None` when empty.
    ///
    /// An empty ledger has no retained window, and reporting `(0, 0)` would
    /// name a row no writer produced.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalLedgerError::Corrupt`] for a stored bound outside the
    /// representable range.
    pub fn retained_range(&self) -> Recorded<Option<RetainedApprovalRange>> {
        let bounds: (Option<i64>, Option<i64>) = self.connection.query_row(
            "SELECT MIN(entry_id), MAX(entry_id) FROM approval_decisions",
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
                Ok(Some(RetainedApprovalRange {
                    first: from_db_u64(first, "entry_id").map_err(|_| corrupt("entry_id"))?,
                    last: from_db_u64(last, "entry_id").map_err(|_| corrupt("entry_id"))?,
                }))
            }
            (None, None) => Ok(None),
            _ => Err(corrupt("entry_id")),
        }
    }

    /// Count durable decisions.
    ///
    /// # Errors
    ///
    /// Returns the SQLite failure, or [`ApprovalLedgerError::Corrupt`] for a
    /// count outside the representable range.
    pub fn decision_count(&self) -> Recorded<usize> {
        count_decisions(&self.connection)
    }

    /// Read one page, optionally restricted to a subject.
    ///
    /// The page is read inside one transaction together with the bound the
    /// cursor is judged against, so a concurrent recording cannot make the
    /// cursor look out of range for a page that was about to be served.
    fn read_page(
        &self,
        cursor: u64,
        limit: usize,
        subject: Option<&str>,
    ) -> Recorded<ApprovalPage> {
        if limit == 0 || limit > MAX_APPROVAL_PAGE {
            return Err(ApprovalLedgerError::InvalidField("limit"));
        }
        let after = to_db_u64(cursor, "cursor")?;
        let page = i64::try_from(limit).map_err(|_| ApprovalLedgerError::InvalidField("limit"))?;
        let lookahead = page
            .checked_add(1)
            .ok_or(ApprovalLedgerError::InvalidField("limit"))?;

        let transaction = self.connection.unchecked_transaction()?;
        let highest: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(entry_id), 0) FROM approval_decisions",
            [],
            |row| row.get(0),
        )?;
        let retained_last = from_db_u64(highest, "entry_id").map_err(|_| corrupt("entry_id"))?;
        if cursor > retained_last {
            return Err(ApprovalLedgerError::CursorOutOfRange {
                supplied: cursor,
                retained_last,
            });
        }

        let filter = if subject.is_some() {
            " AND subject = ?3"
        } else {
            ""
        };
        let mut statement = transaction.prepare(&format!(
            "SELECT {ENTRY_COLUMNS} FROM approval_decisions
             WHERE entry_id > ?1{filter}
             ORDER BY entry_id LIMIT ?2"
        ))?;
        let mut entries = Vec::new();
        {
            let rows = match subject {
                Some(subject) => {
                    statement.query_map(params![after, lookahead, subject], raw_entry)?
                }
                None => statement.query_map(params![after, lookahead], raw_entry)?,
            };
            for raw in rows {
                entries.push(validated_entry(raw?)?);
            }
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
        Ok(ApprovalPage {
            entries,
            next_cursor,
        })
    }
}

/// Answer a key that is already recorded: exact replay, or the first field that
/// differs.
///
/// `decided_at_ms` is not compared; see [`ApprovalDecisionRecord::decided_at_ms`]
/// for why a later clock on a retry is a replay rather than a conflict.
fn replay_or_conflict(
    durable: &ApprovalEntry,
    presented: &ApprovalDecisionRecord<'_>,
) -> Recorded<ApprovalReceipt> {
    let differing = if durable.subject != presented.subject {
        Some("subject")
    } else if durable.decision != presented.decision {
        Some("decision")
    } else if durable.decider != presented.decider {
        Some("decider")
    } else {
        None
    };
    if let Some(field) = differing {
        return Err(ApprovalLedgerError::Conflict {
            field,
            entry_id: durable.entry_id,
            recorded_subject: durable.subject.clone(),
            recorded_decision: durable.decision,
            recorded_decider: durable.decider.clone(),
        });
    }
    Ok(ApprovalReceipt {
        entry_id: durable.entry_id,
        disposition: ApprovalDisposition::AlreadyRecorded,
        decided_at_ms: durable.decided_at_ms,
    })
}

struct RawEntry {
    entry_id: i64,
    approval_key: String,
    subject: String,
    decision: String,
    decider: String,
    decided_at_ms: i64,
    revision: i64,
}

const ENTRY_COLUMNS: &str = "entry_id, approval_key, subject, decision, \
                             decider, decided_at_ms, revision";

fn raw_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawEntry> {
    Ok(RawEntry {
        entry_id: row.get(0)?,
        approval_key: row.get(1)?,
        subject: row.get(2)?,
        decision: row.get(3)?,
        decider: row.get(4)?,
        decided_at_ms: row.get(5)?,
        revision: row.get(6)?,
    })
}

/// Re-derive an [`ApprovalEntry`] from a stored row, refusing anything this API
/// could not have written.
///
/// The decision vocabulary is closed here as well as in the column CHECK,
/// because a CHECK protects the table from a second writer while this function
/// protects callers from a row that got in anyway. The same goes for
/// `revision`: this API writes `1` and only `1`, so anything else is a row a
/// second writer produced and a reader must not silently accept it as an
/// amended decision.
fn validated_entry(raw: RawEntry) -> Recorded<ApprovalEntry> {
    let decision = ApprovalDecision::from_spelling(&raw.decision).ok_or(corrupt("decision"))?;
    let revision = from_db_u64(raw.revision, "revision").map_err(|_| corrupt("revision"))?;
    if revision != 1 {
        return Err(corrupt("revision"));
    }
    Ok(ApprovalEntry {
        entry_id: checked_row_id(raw.entry_id, "entry_id")?,
        approval_key: checked_identifier(raw.approval_key, "approval_key")?,
        subject: checked_identifier(raw.subject, "subject")?,
        decision,
        decider: checked_identifier(raw.decider, "decider")?,
        decided_at_ms: checked_time(raw.decided_at_ms, "decided_at_ms")?,
        revision,
    })
}

fn read_by_key(connection: &Connection, approval_key: &str) -> Recorded<Option<ApprovalEntry>> {
    let raw = connection
        .query_row(
            &format!("SELECT {ENTRY_COLUMNS} FROM approval_decisions WHERE approval_key = ?1"),
            [approval_key],
            raw_entry,
        )
        .optional()?;
    raw.map(validated_entry).transpose()
}

fn count_decisions(connection: &Connection) -> Recorded<usize> {
    let count: i64 =
        connection.query_row("SELECT count(*) FROM approval_decisions", [], |row| {
            row.get(0)
        })?;
    usize::try_from(count).map_err(|_| corrupt("decision_count"))
}

fn secure_path(path: &Path) -> Recorded<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => ApprovalLedgerError::Io(io),
        other => ApprovalLedgerError::InsecurePath(other.to_string()),
    })
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Recorded<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == APPROVAL_LEDGER_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(ApprovalLedgerError::SchemaVersion {
            found: version,
            supported: APPROVAL_LEDGER_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(ApprovalLedgerError::SchemaVersion {
            found: 0,
            supported: APPROVAL_LEDGER_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", APPROVAL_LEDGER_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

/// The identifier grammar an approval key, a subject and a decider share.
fn validate_identifier(value: &str, field: &'static str) -> Recorded<()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(ApprovalLedgerError::InvalidField(field));
    }
    Ok(())
}

fn validate_time(value: i64, field: &'static str) -> Recorded<()> {
    if value < 0 {
        return Err(ApprovalLedgerError::InvalidField(field));
    }
    Ok(())
}

fn checked_identifier(value: String, field: &'static str) -> Recorded<String> {
    validate_identifier(&value, field).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_time(value: i64, field: &'static str) -> Recorded<i64> {
    validate_time(value, field).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_row_id(value: i64, field: &'static str) -> Recorded<i64> {
    if value <= 0 {
        return Err(corrupt(field));
    }
    Ok(value)
}

/// Map a validation field onto its stable corruption invariant name.
///
/// Read paths never reuse `InvalidField`: a bad stored row is corruption the
/// caller cannot have caused, and the two must not be confused.
const fn corrupt(field: &'static str) -> ApprovalLedgerError {
    ApprovalLedgerError::Corrupt(field)
}

fn to_db_u64(value: u64, field: &'static str) -> Recorded<i64> {
    i64::try_from(value).map_err(|_| ApprovalLedgerError::InvalidField(field))
}

fn from_db_u64(value: i64, field: &'static str) -> Recorded<u64> {
    u64::try_from(value).map_err(|_| ApprovalLedgerError::InvalidField(field))
}
