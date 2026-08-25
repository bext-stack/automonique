// SPDX-License-Identifier: Elastic-2.0

//! Durable record of what is waiting for an operator decision.
//!
//! [`crate::approval_ledger`] holds *decisions*, write-once, and it is explicit
//! that it has no pending state: "there is no 'pending' and no 'expired'. A
//! decision that was never made has no row." That is the right shape for an
//! answer and the wrong shape for a question, so an approval *lane* needs a
//! second table beside it. This is that table.
//!
//! One row is one proposal:
//!
//! ```text
//! request_key -> (subject, run_id, bound context, requester, expiry, state)
//! ```
//!
//! and it moves at most once, out of `pending` and into exactly one of
//! `granted`, `denied` or `expired`. There is no transition back, no second
//! decision, and no update path that revisits a terminal row — which is what
//! makes a re-proposal a new row with a new key rather than a revival.
//!
//! # Proposing answers three ways and only three ways
//!
//! - the key is new: the proposal is recorded, [`ProposalDisposition::Proposed`];
//! - the key is present with the *same* binding: it is an exact replay,
//!   [`ProposalDisposition::AlreadyProposed`], and not one byte of the durable
//!   row changes;
//! - the key is present with a different subject, run, context or expiry:
//!   [`ApprovalRequestError::Conflict`], and nothing is written.
//!
//! Deciding is a single fenced `UPDATE … WHERE request_key = ? AND revision = ?
//! AND state = 'pending'`, so two surfaces racing to answer the same proposal
//! resolve exactly one way and the loser learns it lost —
//! [`ApprovalRequestError::StaleRevision`] — rather than overwriting an answer.
//!
//! There is no clock here, no identifier minting and no decision-making.
//! Callers supply every timestamp and every key, so retries stay deterministic
//! and tests do not depend on an ambient clock.
//!
//! # The two-database seam, and the order that repairs it
//!
//! A decision touches two databases — this one and the decision ledger — and no
//! transaction spans them. That is the same seam
//! [`crate::approval_ledger`] names against the provider journal and
//! [`crate::run_index`] against [`crate::run_submissions`], and the house
//! practice is to state the order and the bounded failure it buys rather than
//! hide it.
//!
//! **The ledger row is written first, and this row is transitioned second.**
//! The reason is which failure each order buys:
//!
//! - Ledger first: a crash in between leaves a durable decision whose proposal
//!   still reads `pending`. The next reader of that proposal finds a ledger row
//!   under the same key, re-presents it — [`crate::approval_ledger`] answers
//!   `AlreadyRecorded` and changes nothing — and transitions this row. The gap
//!   *heals on replay*, and the healing is idempotent because both halves are.
//! - This row first: a crash in between leaves a proposal that reads `granted`
//!   with no decision anywhere. Nothing can reconstruct who decided or when,
//!   because the only record of it was the one that was never written, and the
//!   row now claims an authority no ledger backs.
//!
//! A gap that heals is worth more than a claim that cannot be checked, so
//! callers are not free to choose the other order. [`ApprovalRequestRecord::approval_key`]
//! is what makes the repair possible: it is the ledger key this row's decision
//! was recorded under, and it is set in the same statement as the transition.
//!
//! # What the bound context closes, and what it does not
//!
//! Five columns record the launch context a decision was made about: the
//! document's canonical digest, the program's path, the digest of the bytes
//! behind that path, the digest of the prompt, and the working-directory token.
//! They are denormalized onto the row rather than re-derived from the document
//! because a refusal has to be able to **name the field that drifted**, and a
//! comparison against a document is only ever "these differ somewhere".
//!
//! A consumer that re-observes all five before acting closes **approval →
//! admission** drift: an approval granted for one launch cannot be spent on a
//! different one. It does not close **admission → exec** drift, because a
//! runner that hashes a path and then executes that path can still be handed
//! different bytes in between. This module makes no claim about that window,
//! and a reader should not infer one from the presence of a digest column.
//!
//! # What a row does not establish
//!
//! - A `pending` row proves a decision was **asked for**, never that anyone saw
//!   the question. Whether an operator surface could carry it is
//!   `automonique_policy::approval`'s to decide, before a row is written.
//! - A terminal row proves a transition was **recorded**. It does not establish
//!   that the approved thing then happened, or that the denied thing did not.
//! - `expires_at_ms` is the caller's deadline. Nothing here expires a row on
//!   its own; a sweeper reads [`ApprovalRequests::expiring_before`] and asks.
//! - An `expired` row is deliberately **not** a denial. It is the absence of an
//!   answer, and forging a denial nobody made would put a decider's name on a
//!   silence.
//!
//! # Deletion
//!
//! Ordinary operation never deletes. [`ApprovalRequests::prune`] is the only
//! deletion path, it removes terminal rows only, and its cost is stated on the
//! method: a pruned key is forgotten, so the uniqueness that makes revival
//! impossible is only as durable as the row.
//!
//! # Storage discipline
//!
//! This module owns its own SQLite database with its own `user_version`, opened
//! under the same privacy, WAL and `synchronous = FULL` rules as
//! [`crate::Store`], exactly as [`crate::cancel_ledger`],
//! [`crate::approval_ledger`] and [`crate::audit_chain`] do. Every write is one
//! immediate transaction, so a reader after a crash sees the whole change or
//! none of it. Every read re-validates the row it loaded rather than trusting
//! the database.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::{StoreError, validate_database_path};

/// The only approval request schema this build can read and write.
pub const APPROVAL_REQUEST_SCHEMA_VERSION: u32 = 1;

/// Largest number of rows any request table will hold.
pub const MAX_APPROVAL_REQUESTS: usize = 65_536;

/// Longest accepted identifier, in bytes.
///
/// The same grammar [`crate::Store`] uses: non-empty, at most this many bytes,
/// no control characters.
pub const MAX_IDENTIFIER_BYTES: usize = 256;

/// Prefix every request key carries.
///
/// It is the grammar that keeps this lane's keys apart from the ticket
/// references an operator also types at `/approve`, so a surface can tell which
/// lane a reference belongs to before it resolves anything.
pub const REQUEST_KEY_PREFIX: &str = "apr-";

/// Hexadecimal digits following [`REQUEST_KEY_PREFIX`].
pub const REQUEST_KEY_HEX_BYTES: usize = 32;

/// Exact byte length of a well-formed request key.
pub const REQUEST_KEY_BYTES: usize = REQUEST_KEY_PREFIX.len() + REQUEST_KEY_HEX_BYTES;

/// Hexadecimal digits in one bound digest.
pub const DIGEST_HEX_BYTES: usize = 64;

/// Largest page any read returns.
pub const MAX_APPROVAL_REQUEST_PAGE: usize = 256;

/// Schema v1.
///
/// The state vocabulary is a database constraint because a fourth state would
/// silently escape every match in this module. The two paired `CHECK`s are the
/// row's own consistency: a pending row has decided nothing and links to no
/// ledger row, and exactly the two states that carry a decision carry the key
/// it was recorded under. An `expired` row is terminal *and* has no
/// `approval_key`, which is the table saying in SQL that an expiry is not a
/// decision.
///
/// The identifier grammar and the length bounds are deliberately *not* database
/// constraints: they are enforced on write and re-checked on every read, so a
/// row written around this API is refused rather than believed.
const SCHEMA_V1: &str = r#"
CREATE TABLE approval_requests (
    request_entry_id INTEGER PRIMARY KEY,
    request_key TEXT NOT NULL UNIQUE,
    subject TEXT NOT NULL,
    run_id TEXT NOT NULL,
    spec_digest TEXT NOT NULL
        CHECK (length(spec_digest) = 64 AND spec_digest NOT GLOB '*[^0-9a-f]*'),
    program_path TEXT NOT NULL,
    program_sha256 TEXT NOT NULL
        CHECK (length(program_sha256) = 64 AND program_sha256 NOT GLOB '*[^0-9a-f]*'),
    prompt_sha256 TEXT NOT NULL
        CHECK (length(prompt_sha256) = 64 AND prompt_sha256 NOT GLOB '*[^0-9a-f]*'),
    cwd_token TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    requested_at_ms INTEGER NOT NULL CHECK (requested_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > requested_at_ms),
    state TEXT NOT NULL CHECK (state IN ('pending', 'granted', 'denied', 'expired')),
    approval_key TEXT,
    decided_at_ms INTEGER CHECK (decided_at_ms >= 0),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    CHECK ((state = 'pending') = (decided_at_ms IS NULL)),
    CHECK ((state IN ('granted', 'denied')) = (approval_key IS NOT NULL))
) STRICT;

CREATE INDEX approval_requests_by_subject
    ON approval_requests(subject, request_entry_id);

CREATE INDEX approval_requests_by_state
    ON approval_requests(state, expires_at_ms);
"#;

/// An approval request error with stable refusal categories.
#[derive(Debug)]
pub enum ApprovalRequestError {
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
    /// A recorded `request_key` was presented with a different binding.
    ///
    /// Nothing was written. A proposal binds a subject to an exact launch
    /// context, and a key that meant one thing must never come to mean another;
    /// a genuinely different proposal is a new key.
    Conflict {
        /// First bound field that differs.
        field: &'static str,
        /// Row the durable proposal occupies.
        request_entry_id: i64,
    },
    /// No row is recorded under that key.
    UnknownRequest,
    /// The row was not `pending` at the revision the caller fenced on.
    ///
    /// Either somebody else answered first, or the caller read the row, lost a
    /// race, and is about to overwrite an answer. Both are the same refusal
    /// because both must write nothing.
    StaleRevision,
    /// The table holds its full capacity of rows.
    ///
    /// Proposing is refused rather than evicting an older proposal: forgetting
    /// a pending question would let it be asked again as if it were fresh, and
    /// forgetting a terminal one would let a decided thing be re-proposed.
    TableFull {
        /// Capacity of the handle that refused.
        capacity: usize,
    },
    /// A stored row violates an invariant this API can only have written once.
    Corrupt(&'static str),
    /// Filesystem failure while establishing the private database.
    Io(std::io::Error),
    /// SQLite rejected an operation.
    Sqlite(rusqlite::Error),
}

impl ApprovalRequestError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::Conflict { .. } => "conflict",
            Self::UnknownRequest => "unknown_request",
            Self::StaleRevision => "stale_revision",
            Self::TableFull { .. } => "table_full",
            Self::Corrupt(_) => "corrupt",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}

impl fmt::Display for ApprovalRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => {
                write!(formatter, "approval request path is not private: {reason}")
            }
            Self::SchemaVersion { found, supported } => write!(
                formatter,
                "approval request schema {found} is unsupported; expected {supported}"
            ),
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::Conflict {
                field,
                request_entry_id,
            } => write!(
                formatter,
                "request_key is already bound by row {request_entry_id}; {field} differs"
            ),
            Self::UnknownRequest => formatter.write_str("no approval request under that key"),
            Self::StaleRevision => {
                formatter.write_str("the approval request is no longer pending at that revision")
            }
            Self::TableFull { capacity } => write!(
                formatter,
                "approval requests hold their capacity of {capacity}"
            ),
            Self::Corrupt(invariant) => {
                write!(formatter, "stored row violates invariant: {invariant}")
            }
            Self::Io(error) => write!(formatter, "approval request filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite error: {error}"),
        }
    }
}

impl Error for ApprovalRequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ApprovalRequestError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for ApprovalRequestError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// Result of one approval request operation.
pub type Requested<T> = Result<T, ApprovalRequestError>;

/// Where one proposal has got to.
///
/// Closed at four, and the fourth is not a decision: an [`ApprovalState::Expired`]
/// row records that nobody answered, which is a different fact from
/// [`ApprovalState::Denied`] and must never be reported as one.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ApprovalState {
    /// Awaiting an operator.
    Pending,
    /// An operator permitted it.
    Granted,
    /// An operator refused it.
    Denied,
    /// The deadline passed with no answer.
    Expired,
}

impl ApprovalState {
    /// Every state, in canonical order.
    pub const ALL: [Self; 4] = [Self::Pending, Self::Granted, Self::Denied, Self::Expired];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Granted => "granted",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == value)
    }

    /// Whether a row in this state can still move.
    #[must_use]
    pub const fn is_pending(self) -> bool {
        matches!(self, Self::Pending)
    }
}

impl fmt::Display for ApprovalState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The terminal state one decision moves a proposal into.
///
/// Deliberately narrower than [`ApprovalState`]: a decision is granted or
/// denied, and there is no spelling here for an expiry, so the decide path
/// cannot be used to record one.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ApprovalOutcome {
    /// Permit it.
    Granted,
    /// Refuse it.
    Denied,
}

impl ApprovalOutcome {
    /// Every outcome, in canonical order.
    pub const ALL: [Self; 2] = [Self::Granted, Self::Denied];

    /// Stable lowercase spelling, shared with [`ApprovalState`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Denied => "denied",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|outcome| outcome.as_str() == value)
    }

    /// The state a proposal reaches when this outcome is recorded.
    #[must_use]
    pub const fn state(self) -> ApprovalState {
        match self {
            Self::Granted => ApprovalState::Granted,
            Self::Denied => ApprovalState::Denied,
        }
    }

    /// Whether this outcome permits the thing it is about.
    #[must_use]
    pub const fn grants(self) -> bool {
        matches!(self, Self::Granted)
    }
}

impl fmt::Display for ApprovalOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The launch context one approval is bound to.
///
/// Denormalized onto the proposal on purpose. The custodied document holds the
/// same facts, but a refusal has to be able to *name the field that drifted*,
/// and a comparison against a document is only ever "these differ somewhere".
/// Five fields, five names.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ApprovalContext<'a> {
    /// Canonical digest of the RunSpec document in custody, 64 hex digits.
    pub spec_digest: &'a str,
    /// Absolute path of the program the document pins.
    pub program_path: &'a str,
    /// Digest of the bytes behind that path at proposal time, 64 hex digits.
    pub program_sha256: &'a str,
    /// Digest of the prompt the launch would carry, 64 hex digits.
    pub prompt_sha256: &'a str,
    /// Opaque token standing for the working directory.
    pub cwd_token: &'a str,
}

/// Validated launch context read back off a row.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct StoredApprovalContext {
    /// Canonical digest of the RunSpec document in custody.
    pub spec_digest: String,
    /// Absolute path of the program the document pins.
    pub program_path: String,
    /// Digest of the bytes behind that path at proposal time.
    pub program_sha256: String,
    /// Digest of the prompt the launch would carry.
    pub prompt_sha256: String,
    /// Opaque token standing for the working directory.
    pub cwd_token: String,
}

/// One proposal presented for durable recording.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalProposal<'a> {
    /// Opaque key this proposal is addressed by. The unique key.
    pub request_key: &'a str,
    /// What is being approved, as a stable subject spelling.
    pub subject: &'a str,
    /// Run the proposal was raised for.
    pub run_id: &'a str,
    /// The launch context the approval binds.
    pub context: ApprovalContext<'a>,
    /// Who raised it.
    pub requested_by: &'a str,
    /// When it was raised, in caller-supplied milliseconds.
    pub requested_at_ms: i64,
    /// When it stops being answerable. Strictly after `requested_at_ms`, so a
    /// proposal with no lifetime cannot be expressed.
    pub expires_at_ms: i64,
}

/// How the table answered one proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalDisposition {
    /// The proposal was new and is now durable.
    Proposed,
    /// The exact proposal was already durable. Nothing changed.
    AlreadyProposed,
}

impl ProposalDisposition {
    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::AlreadyProposed => "already_proposed",
        }
    }
}

impl fmt::Display for ProposalDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Durable identity of one recorded or replayed proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProposalReceipt {
    /// Row identity of the durable proposal.
    pub request_entry_id: i64,
    /// Whether this call wrote the row or found it.
    pub disposition: ProposalDisposition,
    /// Revision to fence the next transition on.
    pub revision: u64,
}

/// Validated `approval_requests` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRequestRecord {
    /// Row identity, monotonic in proposal order. The pagination key.
    pub request_entry_id: i64,
    /// Opaque key this proposal is addressed by.
    pub request_key: String,
    /// What is being approved.
    pub subject: String,
    /// Run the proposal was raised for.
    pub run_id: String,
    /// The launch context the approval binds.
    pub context: StoredApprovalContext,
    /// Who raised it.
    pub requested_by: String,
    /// When the *first* recording of this key was made.
    pub requested_at_ms: i64,
    /// When it stops being answerable.
    pub expires_at_ms: i64,
    /// Where it has got to.
    pub state: ApprovalState,
    /// Ledger key this row's decision was recorded under.
    ///
    /// Present exactly when the state is granted or denied. An expiry is not a
    /// decision and links to nothing.
    pub approval_key: Option<String>,
    /// When it left `pending`.
    pub decided_at_ms: Option<i64>,
    /// Optimistic fence. One for a fresh proposal, two after its transition.
    pub revision: u64,
}

impl ApprovalRequestRecord {
    /// Whether this row is still answerable at a given instant.
    ///
    /// Expiry is inclusive of the deadline: `now_ms == expires_at_ms` is
    /// expired. That is the same direction
    /// [`crate::improvements`] compares its challenge lifetimes in, and the two
    /// agree deliberately — one product should not hold two expiry semantics.
    #[must_use]
    pub const fn is_answerable_at(&self, now_ms: i64) -> bool {
        self.state.is_pending() && now_ms < self.expires_at_ms
    }
}

/// One bounded page of proposals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRequestPage {
    /// Rows, oldest first.
    pub records: Vec<ApprovalRequestRecord>,
    /// Cursor for the next page, or `None` when the page is the last one.
    pub next_cursor: Option<u64>,
}

/// Durable table of proposals awaiting, or having received, a decision.
#[derive(Debug)]
pub struct ApprovalRequests {
    connection: Connection,
    path: PathBuf,
    capacity: usize,
}

impl ApprovalRequests {
    /// Open or initialize the table inside an existing private directory.
    ///
    /// The parent must be owned by the effective user and deny all group/other
    /// access. Capacity is [`MAX_APPROVAL_REQUESTS`].
    ///
    /// # Errors
    ///
    /// [`ApprovalRequestError`] naming the refused rule.
    pub fn open(path: impl AsRef<Path>) -> Requested<Self> {
        Self::open_with_capacity(path, MAX_APPROVAL_REQUESTS)
    }

    /// Open with a lowered row capacity.
    ///
    /// `capacity` is a property of this handle, not of the database: opening an
    /// existing table under a capacity below its row count refuses further
    /// proposals with [`ApprovalRequestError::TableFull`] while exact replays,
    /// decisions and reads keep working — a replay and a transition both write
    /// no new row.
    ///
    /// # Errors
    ///
    /// [`ApprovalRequestError`] naming the refused rule.
    pub fn open_with_capacity(path: impl AsRef<Path>, capacity: usize) -> Requested<Self> {
        if capacity == 0 || capacity > MAX_APPROVAL_REQUESTS {
            return Err(ApprovalRequestError::InvalidField("capacity"));
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

    /// Exact path opened by this handle.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Row capacity of this handle.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Record one proposal.
    ///
    /// One immediate transaction: after a crash a reader sees the whole row or
    /// no row, never half of one.
    ///
    /// Lookup precedes the capacity check, so an exact replay is still answered
    /// [`ProposalDisposition::AlreadyProposed`] in a full table — a replay
    /// writes nothing and must never degrade into a refusal.
    ///
    /// # Errors
    ///
    /// [`ApprovalRequestError::Conflict`] for a key rebound to different
    /// coordinates, [`ApprovalRequestError::TableFull`] at the ceiling, and
    /// [`ApprovalRequestError::InvalidField`] for anything outside the grammar.
    pub fn propose(&mut self, proposal: ApprovalProposal<'_>) -> Requested<ProposalReceipt> {
        validate_proposal(&proposal)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let receipt = propose_row(&transaction, &proposal, self.capacity)?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Move one pending proposal to a decision, under the caller's fence.
    ///
    /// The `UPDATE` names the revision *and* the state, so a row somebody else
    /// answered a microsecond earlier fails the fence rather than being
    /// overwritten: exactly one of two racing surfaces wins and the other is
    /// told it lost.
    ///
    /// `approval_key` is the ledger key the decision was recorded under, and it
    /// is written in the same statement as the transition. Callers must have
    /// recorded that ledger row **first** — see this module's header for the
    /// failure each order buys.
    ///
    /// # Errors
    ///
    /// [`ApprovalRequestError::UnknownRequest`] when no row carries the key,
    /// and [`ApprovalRequestError::StaleRevision`] when the row is not pending
    /// at that revision.
    pub fn decide(
        &mut self,
        request_key: &str,
        expected_revision: u64,
        outcome: ApprovalOutcome,
        approval_key: &str,
        decided_at_ms: i64,
    ) -> Requested<ApprovalRequestRecord> {
        validate_request_key(request_key)?;
        validate_identifier(approval_key, "approval_key")?;
        validate_time(decided_at_ms, "decided_at_ms")?;
        let revision = to_db_u64(expected_revision, "revision")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if read_by_key(&transaction, request_key)?.is_none() {
            return Err(ApprovalRequestError::UnknownRequest);
        }
        let changed = transaction.execute(
            "UPDATE approval_requests
             SET state = ?1, approval_key = ?2, decided_at_ms = ?3, revision = revision + 1
             WHERE request_key = ?4 AND revision = ?5 AND state = 'pending'",
            params![
                outcome.state().as_str(),
                approval_key,
                decided_at_ms,
                request_key,
                revision
            ],
        )?;
        if changed != 1 {
            return Err(ApprovalRequestError::StaleRevision);
        }
        let record = read_by_key(&transaction, request_key)?
            .ok_or(ApprovalRequestError::Corrupt("request_key"))?;
        transaction.commit()?;
        Ok(record)
    }

    /// Move one pending proposal to `expired`, under the caller's fence.
    ///
    /// Deliberately a separate method from [`ApprovalRequests::decide`] and
    /// deliberately unable to write an `approval_key`: an expiry is the absence
    /// of an answer, and a path that could record one as a decision would let a
    /// sweeper put a decider's name on a silence.
    ///
    /// # Errors
    ///
    /// [`ApprovalRequestError::UnknownRequest`] when no row carries the key,
    /// and [`ApprovalRequestError::StaleRevision`] when the row is not pending
    /// at that revision — which is what makes a second sweep of the same row a
    /// no-op rather than a second expiry.
    pub fn expire(
        &mut self,
        request_key: &str,
        expected_revision: u64,
        expired_at_ms: i64,
    ) -> Requested<ApprovalRequestRecord> {
        validate_request_key(request_key)?;
        validate_time(expired_at_ms, "expired_at_ms")?;
        let revision = to_db_u64(expected_revision, "revision")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if read_by_key(&transaction, request_key)?.is_none() {
            return Err(ApprovalRequestError::UnknownRequest);
        }
        let changed = transaction.execute(
            "UPDATE approval_requests
             SET state = 'expired', decided_at_ms = ?1, revision = revision + 1
             WHERE request_key = ?2 AND revision = ?3 AND state = 'pending'",
            params![expired_at_ms, request_key, revision],
        )?;
        if changed != 1 {
            return Err(ApprovalRequestError::StaleRevision);
        }
        let record = read_by_key(&transaction, request_key)?
            .ok_or(ApprovalRequestError::Corrupt("request_key"))?;
        transaction.commit()?;
        Ok(record)
    }

    /// Read the validated row one key addresses, if any.
    ///
    /// # Errors
    ///
    /// [`ApprovalRequestError`] for a malformed key or an unreadable row.
    pub fn entry(&self, request_key: &str) -> Requested<Option<ApprovalRequestRecord>> {
        validate_request_key(request_key)?;
        read_by_key(&self.connection, request_key)
    }

    /// Every row for one subject, oldest first.
    ///
    /// This is the lane's own lookup: a launch asks what has already been
    /// decided about the document it would run, and the answer is the whole
    /// history rather than the newest row, because a re-proposal after an
    /// expiry leaves both.
    ///
    /// # Errors
    ///
    /// [`ApprovalRequestError`] for a malformed subject or an unreadable row.
    pub fn by_subject(&self, subject: &str) -> Requested<Vec<ApprovalRequestRecord>> {
        validate_identifier(subject, "subject")?;
        let mut statement = self.connection.prepare(&format!(
            "SELECT {RECORD_COLUMNS} FROM approval_requests
             WHERE subject = ?1 ORDER BY request_entry_id"
        ))?;
        let rows = statement.query_map([subject], raw_record)?;
        let mut records = Vec::new();
        for raw in rows {
            records.push(validated_record(raw?)?);
        }
        Ok(records)
    }

    /// Pending rows whose deadline has arrived, oldest first.
    ///
    /// Inclusive of the deadline, matching
    /// [`ApprovalRequestRecord::is_answerable_at`], so the sweeper and the
    /// answerability check cannot disagree about a row at the exact boundary.
    ///
    /// # Errors
    ///
    /// [`ApprovalRequestError::InvalidField`] for a negative instant or a limit
    /// above [`MAX_APPROVAL_REQUEST_PAGE`].
    pub fn expiring_before(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Requested<Vec<ApprovalRequestRecord>> {
        validate_time(now_ms, "now_ms")?;
        if limit == 0 || limit > MAX_APPROVAL_REQUEST_PAGE {
            return Err(ApprovalRequestError::InvalidField("limit"));
        }
        let mut statement = self.connection.prepare(&format!(
            "SELECT {RECORD_COLUMNS} FROM approval_requests
             WHERE state = 'pending' AND expires_at_ms <= ?1
             ORDER BY request_entry_id LIMIT ?2"
        ))?;
        let rows = statement.query_map(params![now_ms, to_db_usize(limit)?], raw_record)?;
        let mut records = Vec::new();
        for raw in rows {
            records.push(validated_record(raw?)?);
        }
        Ok(records)
    }

    /// Pending rows, oldest first.
    ///
    /// The backlog view: what is in front of an operator right now. A sweeper
    /// that reminds reads this and computes its own milestones, which is why
    /// there is no "due for a reminder" query — the ladder is a policy the
    /// caller owns, and baking one into a `WHERE` clause would put it in two
    /// places.
    ///
    /// # Errors
    ///
    /// [`ApprovalRequestError::InvalidField`] for a limit outside
    /// `1..=MAX_APPROVAL_REQUEST_PAGE`.
    pub fn pending(&self, limit: usize) -> Requested<Vec<ApprovalRequestRecord>> {
        if limit == 0 || limit > MAX_APPROVAL_REQUEST_PAGE {
            return Err(ApprovalRequestError::InvalidField("limit"));
        }
        let mut statement = self.connection.prepare(&format!(
            "SELECT {RECORD_COLUMNS} FROM approval_requests
             WHERE state = 'pending' ORDER BY request_entry_id LIMIT ?1"
        ))?;
        let rows = statement.query_map([to_db_usize(limit)?], raw_record)?;
        let mut records = Vec::new();
        for raw in rows {
            records.push(validated_record(raw?)?);
        }
        Ok(records)
    }

    /// One bounded page of every row, oldest first.
    ///
    /// # Errors
    ///
    /// [`ApprovalRequestError::InvalidField`] for a limit outside
    /// `1..=MAX_APPROVAL_REQUEST_PAGE`.
    pub fn page(&self, cursor: u64, limit: usize) -> Requested<ApprovalRequestPage> {
        if limit == 0 || limit > MAX_APPROVAL_REQUEST_PAGE {
            return Err(ApprovalRequestError::InvalidField("limit"));
        }
        let after = to_db_u64(cursor, "cursor")?;
        let mut statement = self.connection.prepare(&format!(
            "SELECT {RECORD_COLUMNS} FROM approval_requests
             WHERE request_entry_id > ?1 ORDER BY request_entry_id LIMIT ?2"
        ))?;
        let rows = statement.query_map(params![after, to_db_usize(limit)?], raw_record)?;
        let mut records = Vec::new();
        for raw in rows {
            records.push(validated_record(raw?)?);
        }
        let next_cursor = if records.len() == limit {
            records
                .last()
                .map(|record| from_db_u64(record.request_entry_id, "request_entry_id"))
                .transpose()?
        } else {
            None
        };
        Ok(ApprovalRequestPage {
            records,
            next_cursor,
        })
    }

    /// Count rows.
    ///
    /// # Errors
    ///
    /// [`ApprovalRequestError`] when the count cannot be read.
    pub fn request_count(&self) -> Requested<usize> {
        count_rows(&self.connection)
    }

    /// Count rows in one state.
    ///
    /// The operational metric this lane needs: a growing `pending` count is a
    /// backlog of unanswered questions, which is exactly the thing an approval
    /// lane can fail at silently.
    ///
    /// # Errors
    ///
    /// [`ApprovalRequestError`] when the count cannot be read.
    pub fn state_count(&self, state: ApprovalState) -> Requested<usize> {
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM approval_requests WHERE state = ?1",
            [state.as_str()],
            |row| row.get(0),
        )?;
        usize::try_from(count).map_err(|_| corrupt_field("state_count"))
    }

    /// Delete terminal rows recorded before an instant.
    ///
    /// The only deletion in this module, and it costs exactly one thing, stated
    /// here rather than buried: **a pruned key is forgotten.** Uniqueness of
    /// `request_key` is what makes a terminal row impossible to revive, so a
    /// pruned key could be proposed again as if it were fresh. A caller that
    /// prunes must not replay keys that belonged to the pruned window.
    ///
    /// Pending rows are never eligible, whatever their age: a question nobody
    /// answered is not garbage, and deleting one would turn a backlog into an
    /// empty table.
    ///
    /// # Errors
    ///
    /// [`ApprovalRequestError::InvalidField`] for a negative instant.
    pub fn prune(&mut self, older_than_ms: i64) -> Requested<usize> {
        validate_time(older_than_ms, "older_than_ms")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let removed = transaction.execute(
            "DELETE FROM approval_requests
             WHERE state != 'pending' AND decided_at_ms < ?1",
            [older_than_ms],
        )?;
        transaction.commit()?;
        Ok(removed)
    }
}

/// Record one proposal inside an open transaction.
fn propose_row(
    transaction: &Transaction<'_>,
    proposal: &ApprovalProposal<'_>,
    capacity: usize,
) -> Requested<ProposalReceipt> {
    if let Some(recorded) = read_by_key(transaction, proposal.request_key)? {
        // Every bound field is compared, in a fixed order, so a refusal names
        // the first real difference rather than an arbitrary one.
        for (field, differs) in [
            ("subject", recorded.subject != proposal.subject),
            ("run_id", recorded.run_id != proposal.run_id),
            (
                "spec_digest",
                recorded.context.spec_digest != proposal.context.spec_digest,
            ),
            (
                "program_path",
                recorded.context.program_path != proposal.context.program_path,
            ),
            (
                "program_sha256",
                recorded.context.program_sha256 != proposal.context.program_sha256,
            ),
            (
                "prompt_sha256",
                recorded.context.prompt_sha256 != proposal.context.prompt_sha256,
            ),
            (
                "cwd_token",
                recorded.context.cwd_token != proposal.context.cwd_token,
            ),
            (
                "requested_by",
                recorded.requested_by != proposal.requested_by,
            ),
            (
                "expires_at_ms",
                recorded.expires_at_ms != proposal.expires_at_ms,
            ),
        ] {
            if differs {
                return Err(ApprovalRequestError::Conflict {
                    field,
                    request_entry_id: recorded.request_entry_id,
                });
            }
        }
        // Exact replay. `requested_at_ms` keeps the first proposal's instant, so
        // a retry does not extend or move the window it was raised in.
        return Ok(ProposalReceipt {
            request_entry_id: recorded.request_entry_id,
            disposition: ProposalDisposition::AlreadyProposed,
            revision: recorded.revision,
        });
    }
    if count_rows(transaction)? >= capacity {
        return Err(ApprovalRequestError::TableFull { capacity });
    }
    transaction.execute(
        "INSERT INTO approval_requests
         (request_key, subject, run_id, spec_digest, program_path, program_sha256,
          prompt_sha256, cwd_token, requested_by, requested_at_ms, expires_at_ms,
          state, approval_key, decided_at_ms, revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'pending', NULL, NULL, 1)",
        params![
            proposal.request_key,
            proposal.subject,
            proposal.run_id,
            proposal.context.spec_digest,
            proposal.context.program_path,
            proposal.context.program_sha256,
            proposal.context.prompt_sha256,
            proposal.context.cwd_token,
            proposal.requested_by,
            proposal.requested_at_ms,
            proposal.expires_at_ms,
        ],
    )?;
    Ok(ProposalReceipt {
        request_entry_id: transaction.last_insert_rowid(),
        disposition: ProposalDisposition::Proposed,
        revision: 1,
    })
}

struct RawRecord {
    request_entry_id: i64,
    request_key: String,
    subject: String,
    run_id: String,
    spec_digest: String,
    program_path: String,
    program_sha256: String,
    prompt_sha256: String,
    cwd_token: String,
    requested_by: String,
    requested_at_ms: i64,
    expires_at_ms: i64,
    state: String,
    approval_key: Option<String>,
    decided_at_ms: Option<i64>,
    revision: i64,
}

const RECORD_COLUMNS: &str = "request_entry_id, request_key, subject, run_id, spec_digest, \
     program_path, program_sha256, prompt_sha256, cwd_token, requested_by, requested_at_ms, \
     expires_at_ms, state, approval_key, decided_at_ms, revision";

fn raw_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRecord> {
    Ok(RawRecord {
        request_entry_id: row.get(0)?,
        request_key: row.get(1)?,
        subject: row.get(2)?,
        run_id: row.get(3)?,
        spec_digest: row.get(4)?,
        program_path: row.get(5)?,
        program_sha256: row.get(6)?,
        prompt_sha256: row.get(7)?,
        cwd_token: row.get(8)?,
        requested_by: row.get(9)?,
        requested_at_ms: row.get(10)?,
        expires_at_ms: row.get(11)?,
        state: row.get(12)?,
        approval_key: row.get(13)?,
        decided_at_ms: row.get(14)?,
        revision: row.get(15)?,
    })
}

fn validated_record(raw: RawRecord) -> Requested<ApprovalRequestRecord> {
    let state = ApprovalState::from_spelling(&raw.state).ok_or_else(|| corrupt_field("state"))?;
    let approval_key = match raw.approval_key {
        Some(key) => Some(checked_identifier(key, "approval_key")?),
        None => None,
    };
    let decided_at_ms = match raw.decided_at_ms {
        Some(instant) => Some(checked_time(instant, "decided_at_ms")?),
        None => None,
    };
    // The pairing the schema states in SQL, re-checked here: a row written
    // around this API is refused rather than believed.
    if state.is_pending() != decided_at_ms.is_none()
        || matches!(state, ApprovalState::Granted | ApprovalState::Denied) != approval_key.is_some()
    {
        return Err(corrupt_field("state"));
    }
    let expires_at_ms = checked_time(raw.expires_at_ms, "expires_at_ms")?;
    let requested_at_ms = checked_time(raw.requested_at_ms, "requested_at_ms")?;
    if expires_at_ms <= requested_at_ms {
        return Err(corrupt_field("expires_at_ms"));
    }
    Ok(ApprovalRequestRecord {
        request_entry_id: checked_row_id(raw.request_entry_id, "request_entry_id")?,
        request_key: checked_request_key(raw.request_key)?,
        subject: checked_identifier(raw.subject, "subject")?,
        run_id: checked_identifier(raw.run_id, "run_id")?,
        context: StoredApprovalContext {
            spec_digest: checked_digest(raw.spec_digest, "spec_digest")?,
            program_path: checked_identifier(raw.program_path, "program_path")?,
            program_sha256: checked_digest(raw.program_sha256, "program_sha256")?,
            prompt_sha256: checked_digest(raw.prompt_sha256, "prompt_sha256")?,
            cwd_token: checked_identifier(raw.cwd_token, "cwd_token")?,
        },
        requested_by: checked_identifier(raw.requested_by, "requested_by")?,
        requested_at_ms,
        expires_at_ms,
        state,
        approval_key,
        decided_at_ms,
        revision: from_db_u64(raw.revision, "revision").map_err(|_| corrupt_field("revision"))?,
    })
}

fn read_by_key(
    connection: &Connection,
    request_key: &str,
) -> Requested<Option<ApprovalRequestRecord>> {
    let raw = connection
        .query_row(
            &format!("SELECT {RECORD_COLUMNS} FROM approval_requests WHERE request_key = ?1"),
            [request_key],
            raw_record,
        )
        .optional()?;
    raw.map(validated_record).transpose()
}

fn count_rows(connection: &Connection) -> Requested<usize> {
    let count: i64 = connection.query_row("SELECT count(*) FROM approval_requests", [], |row| {
        row.get(0)
    })?;
    usize::try_from(count).map_err(|_| corrupt_field("request_count"))
}

fn secure_path(path: &Path) -> Requested<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => ApprovalRequestError::Io(io),
        other => ApprovalRequestError::InsecurePath(other.to_string()),
    })
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Requested<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == APPROVAL_REQUEST_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(ApprovalRequestError::SchemaVersion {
            found: version,
            supported: APPROVAL_REQUEST_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(ApprovalRequestError::SchemaVersion {
            found: 0,
            supported: APPROVAL_REQUEST_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", APPROVAL_REQUEST_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn validate_proposal(proposal: &ApprovalProposal<'_>) -> Requested<()> {
    validate_request_key(proposal.request_key)?;
    validate_identifier(proposal.subject, "subject")?;
    validate_identifier(proposal.run_id, "run_id")?;
    validate_digest(proposal.context.spec_digest, "spec_digest")?;
    validate_identifier(proposal.context.program_path, "program_path")?;
    validate_digest(proposal.context.program_sha256, "program_sha256")?;
    validate_digest(proposal.context.prompt_sha256, "prompt_sha256")?;
    validate_identifier(proposal.context.cwd_token, "cwd_token")?;
    validate_identifier(proposal.requested_by, "requested_by")?;
    validate_time(proposal.requested_at_ms, "requested_at_ms")?;
    validate_time(proposal.expires_at_ms, "expires_at_ms")?;
    // A proposal with no lifetime would be a question that can never time out,
    // which the TTL sweep could never reach. It is refused rather than defaulted.
    if proposal.expires_at_ms <= proposal.requested_at_ms {
        return Err(ApprovalRequestError::InvalidField("expires_at_ms"));
    }
    Ok(())
}

/// The `apr-` grammar, checked on every write and on every read.
///
/// Lowercase hexadecimal after a fixed prefix, at an exact length. The shape is
/// what lets an operator surface tell this lane's references apart from the
/// ticket references typed at the same verb, without resolving either.
fn validate_request_key(value: &str) -> Requested<()> {
    if value.len() != REQUEST_KEY_BYTES
        || !value.starts_with(REQUEST_KEY_PREFIX)
        || !value[REQUEST_KEY_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApprovalRequestError::InvalidField("request_key"));
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Requested<()> {
    if value.len() != DIGEST_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApprovalRequestError::InvalidField(field));
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Requested<()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(ApprovalRequestError::InvalidField(field));
    }
    Ok(())
}

fn validate_time(value: i64, field: &'static str) -> Requested<()> {
    if value < 0 {
        return Err(ApprovalRequestError::InvalidField(field));
    }
    Ok(())
}

fn checked_identifier(value: String, field: &'static str) -> Requested<String> {
    validate_identifier(&value, field).map_err(|_| corrupt_field(field))?;
    Ok(value)
}

fn checked_digest(value: String, field: &'static str) -> Requested<String> {
    validate_digest(&value, field).map_err(|_| corrupt_field(field))?;
    Ok(value)
}

fn checked_request_key(value: String) -> Requested<String> {
    validate_request_key(&value).map_err(|_| corrupt_field("request_key"))?;
    Ok(value)
}

fn checked_time(value: i64, field: &'static str) -> Requested<i64> {
    validate_time(value, field).map_err(|_| corrupt_field(field))?;
    Ok(value)
}

fn checked_row_id(value: i64, field: &'static str) -> Requested<i64> {
    if value <= 0 {
        return Err(corrupt_field(field));
    }
    Ok(value)
}

/// Map a validation field onto its stable corruption invariant name.
///
/// Read paths never reuse `InvalidField`: a bad stored row is corruption the
/// caller cannot have caused, and the two must not be confused.
const fn corrupt_field(field: &'static str) -> ApprovalRequestError {
    ApprovalRequestError::Corrupt(field)
}

fn to_db_u64(value: u64, field: &'static str) -> Requested<i64> {
    i64::try_from(value).map_err(|_| ApprovalRequestError::InvalidField(field))
}

fn to_db_usize(value: usize) -> Requested<i64> {
    i64::try_from(value).map_err(|_| ApprovalRequestError::InvalidField("limit"))
}

fn from_db_u64(value: i64, field: &'static str) -> Requested<u64> {
    u64::try_from(value).map_err(|_| ApprovalRequestError::InvalidField(field))
}
