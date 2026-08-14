// SPDX-License-Identifier: Elastic-2.0

//! Durable record of the support tickets this host has seen on the fleet board.
//!
//! `automonique-support-connector` reads one page of the Support fleet board
//! and hands back typed `SupportIssue` rows. That read is a *snapshot*: ask
//! twice and you get two answers, ask after a restart and you get no history at
//! all. This module is where a snapshot becomes a record. One row per fleet
//! issue:
//!
//! ```text
//! fleet_issue_id -> (the fleet's fields, verbatim)
//!                 + (first_seen_ms, last_synced_ms)
//!                 + (lifecycle, revision)
//! ```
//!
//! There is no fleet IO here, no HTTP, no clock and no parsing: callers supply
//! every field and every timestamp, so a re-poll is deterministic and tests do
//! not depend on an ambient clock. The connector proves the fields are the
//! contract; this module proves they are still the contract after a round trip
//! through SQLite.
//!
//! # Two owners, one row
//!
//! Every column is owned by exactly one writer, and the split is the whole
//! design:
//!
//! - **The fleet owns its own fields.** `title`, `tenant_name`, `site_label`,
//!   `fleet_status`, `priority`, `source`, `requested_by`, `comment_count`,
//!   `created_at` and `updated_at` are recorded verbatim and overwritten by
//!   every [`SupportTicketStore::record`]. This store never repairs, defaults or
//!   normalizes one — the connector already refused anything outside the
//!   contract, and re-deriving here would put two opinions on one field.
//! - **This host owns [`TicketLifecycle`].** It is *not* the fleet's status. It
//!   records what Automonique has done about the ticket, which the fleet has no
//!   way of knowing, and it moves only through [`SupportTicketStore::transition`].
//!
//! `first_seen_ms` and `last_synced_ms` belong to this host too: the first is
//! written once and never again, the second on every observation. Together they
//! answer "how long have we known about this?" — a question the fleet's own
//! `created_at` cannot answer, because a ticket may have existed for a week
//! before this host first looked at the board.
//!
//! `draft_answer` belongs to this host as well, and belongs to it completely: it
//! is what *Automonique* wrote about the ticket, never anything the fleet said.
//! It is written once, by [`SupportTicketStore::record_draft`], and no re-poll
//! touches it.
//!
//! # The draft is a local record, not a reply
//!
//! Storing a draft sends nothing to anybody. This module has no fleet IO at all,
//! and the column is a row in a private SQLite file on this host — an operator
//! reads it, decides, and posts it (or does not) through a surface that does not
//! exist yet. `answered` therefore means *this host has produced an answer*,
//! which is the same thing every other lifecycle word means: what Automonique
//! did, not what the requester received.
//!
//! # Upsert, and why it is not an insert
//!
//! A poller re-reads the whole open board on every cadence, so the *same* issue
//! arrives again and again. [`SupportTicketStore::record`] is therefore an
//! upsert keyed on `fleet_issue_id`, and a second sighting updates the row it
//! already has. It never inserts a second one — `UNIQUE` says so in the schema,
//! and [`TicketReceipt::inserted`] says so to the caller, which is how a poller
//! can report "three new tickets" without counting the ones it has seen forty
//! times already.
//!
//! `revision` counts changes to *what the row says*, not to when it was last
//! looked at. A re-poll that finds nothing moved writes `last_synced_ms` and
//! leaves `revision` alone, so a caller holding a revision from an earlier read
//! is not made stale by the mere passage of polls. That matters because
//! `revision` is the compare-and-set token [`SupportTicketStore::transition`]
//! demands: a poller bumping it every minute would make an operator's transition
//! fail for no reason anybody could act on.
//!
//! # The lifecycle lattice
//!
//! | from | to | why |
//! |---|---|---|
//! | `new` | `acknowledged` | somebody has looked at it |
//! | `acknowledged` | `working` | work has started |
//! | `working` | `answered` | the requester was replied to |
//! | `answered` | `closed` | the ordinary end |
//! | any non-terminal | `closed` | the fleet may close a ticket at any point |
//!
//! Everything else is [`SupportTicketError::IllegalTransition`]: nothing goes
//! backwards, nothing skips forward except straight to `closed`, nothing leaves
//! `closed`, and a re-report of the state a row already carries is refused
//! rather than silently accepted — a caller asking for it is acting on a stale
//! read, and answering "fine" would hide that.
//!
//! [`SupportTicketStore::record_draft`] is the one caller that moves *more than
//! one* step, because recording an answer for a ticket at `acknowledged` means
//! work started and finished. It walks the same lattice one step at a time and
//! refuses exactly what [`TicketLifecycle::may_advance_to`] refuses at every
//! step, so the path it takes is one [`SupportTicketStore::transition`] could
//! have taken; what it does not do is charge three revisions for one thing that
//! happened. See [`TicketLifecycle::may_reach`].
//!
//! `closed` is reachable from everywhere for one concrete reason: the fleet can
//! mark an issue `done` while this host still has it at `new`, and a store that
//! could not record that would either have to invent the intervening steps or
//! keep claiming a finished ticket is untouched. Both are lies; the shortcut is
//! not.
//!
//! # Storage discipline
//!
//! Its own SQLite database with its own `user_version`, opened under the same
//! privacy, WAL and `synchronous = FULL` rules as [`crate::Store`], exactly as
//! [`crate::run_index`], [`crate::cancel_ledger`] and [`crate::generation_audit`]
//! do. Every mutation is one immediate transaction. Every read re-validates the
//! row it loaded rather than trusting the database.
//!
//! The field ceilings below are re-declared here rather than imported, because
//! this crate does not depend on the connector and must not: a store that
//! compiled against an HTTP client would drag one into every process that opens
//! a database. The duplication is the point — the two bounds are pinned
//! independently, so a widened ceiling on one side has to be a deliberate change
//! on both.
//!
//! # Deletion
//!
//! There is none, and no prune. A ticket that left the fleet's open board did
//! not stop having happened, and a store that forgot it would answer "have we
//! seen this before?" with a fresh `new` row the next time the requester
//! reopened it. Capacity is [`SupportTicketError::StoreFull`], never an
//! eviction.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::{BUSY_TIMEOUT, StoreError, validate_database_path};

/// The only support ticket schema this build can read and write.
pub const SUPPORT_TICKETS_SCHEMA_VERSION: u32 = 2;

/// Largest number of tickets any store will hold.
///
/// Nothing deletes from this table, so this is a hard ceiling on the lifetime of
/// one database file rather than a high-water mark.
pub const MAX_SUPPORT_TICKETS: usize = 65_536;

/// Largest page [`SupportTicketStore::page`] and
/// [`SupportTicketStore::page_in_lifecycles`] will return.
pub const MAX_TICKET_PAGE: usize = 512;

/// Longest accepted fleet issue id, in bytes.
pub const MAX_FLEET_ISSUE_ID_BYTES: usize = 120;
/// Longest accepted ticket title, in bytes.
pub const MAX_TICKET_TITLE_BYTES: usize = 240;
/// Longest accepted tenant name, in bytes.
pub const MAX_TENANT_NAME_BYTES: usize = 160;
/// Longest accepted site label, in bytes.
pub const MAX_SITE_LABEL_BYTES: usize = 200;
/// Longest accepted status, priority or source token, in bytes.
pub const MAX_TICKET_TOKEN_BYTES: usize = 40;
/// Longest accepted requester name, in bytes.
pub const MAX_REQUESTED_BY_BYTES: usize = 160;
/// Highest accepted comment count.
pub const MAX_COMMENT_COUNT: u32 = 10_000;
/// Longest draft answer one ticket may carry, in bytes.
///
/// A draft is something this host wrote rather than a field the fleet owns, so
/// it is bounded far above the fleet's own ceilings and far below anything
/// unbounded. 32 KiB is more than a support reply is and less than any one
/// message a chat transport carries, so a draft at this ceiling is one an
/// operator reads in pieces, never one this store could not hold.
pub const MAX_DRAFT_ANSWER_BYTES: usize = 32 * 1024;

/// The schema spells this ceiling as a literal, because a CHECK cannot read a
/// Rust constant. This is the one place the two are held together.
const _: () = assert!(MAX_DRAFT_ANSWER_BYTES == 32_768);

/// Longest accepted fleet timestamp, in bytes.
///
/// Retained verbatim and never parsed. The connector documents why: the fleet's
/// timestamps are validated upstream by a JavaScript `Date.parse` that accepts
/// far more than one format, so guessing at RFC 3339 here would refuse a
/// timestamp the fleet legitimately sends.
pub const MAX_TIMESTAMP_BYTES: usize = 60;

/// Schema v2, the table.
///
/// The invariants a second writer must not be able to break are database
/// constraints: one row per fleet issue, the closed five-word lifecycle
/// vocabulary, a comment count inside its range, non-negative observation
/// instants that do not travel backwards, a positive revision, the binding that
/// an absent site label is `NULL` rather than an empty string, and the three
/// facts about a draft — that its text and its instant are present or absent
/// together, that a present one is non-empty and inside its ceiling, and that a
/// row carrying one has reached `answered` or gone past it.
///
/// The identifier grammar, the length bounds and the transition lattice are
/// deliberately *not* database constraints: they are enforced on write and
/// re-checked on every read, so a row written around this API is refused rather
/// than believed.
///
/// Every CHECK that touches a nullable column spells `IS NOT NULL` explicitly on
/// the branch that reads it. A bare `length(site_label) > 0` would evaluate to
/// `NULL` for an absent label, and SQLite admits a `NULL` CHECK — so the
/// constraint would silently stop constraining exactly the rows it was written
/// for. The draft's ceiling is measured on `CAST(... AS BLOB)` because
/// `length()` of TEXT counts characters, and a bound stated in bytes has to be
/// checked in bytes or a multi-byte draft passes a check it exceeds.
const TABLE_V2: &str = r#"
CREATE TABLE support_tickets (
    ticket_id INTEGER PRIMARY KEY,
    fleet_issue_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    tenant_name TEXT NOT NULL,
    site_label TEXT,
    fleet_status TEXT NOT NULL,
    priority TEXT NOT NULL,
    source TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    comment_count INTEGER NOT NULL CHECK (
        comment_count >= 0 AND comment_count <= 10000
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    first_seen_ms INTEGER NOT NULL CHECK (first_seen_ms >= 0),
    last_synced_ms INTEGER NOT NULL CHECK (last_synced_ms >= 0),
    lifecycle TEXT NOT NULL CHECK (
        lifecycle IN ('new', 'acknowledged', 'working', 'answered', 'closed')
    ),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    draft_answer TEXT,
    draft_answer_at_ms INTEGER,
    CHECK (last_synced_ms >= first_seen_ms),
    CHECK (
        site_label IS NULL
        OR (site_label IS NOT NULL
            AND length(site_label) > 0
            AND length(site_label) <= 200)
    ),
    CHECK (
        (draft_answer IS NULL AND draft_answer_at_ms IS NULL)
        OR (draft_answer IS NOT NULL
            AND draft_answer_at_ms IS NOT NULL
            AND length(draft_answer) > 0
            AND length(CAST(draft_answer AS BLOB)) <= 32768
            AND draft_answer_at_ms >= 0
            AND lifecycle IN ('answered', 'closed'))
    )
) STRICT;
"#;

/// Schema v2, the indexes. Applied after the table, on a fresh store and after a
/// migration alike, so the two are the same schema and not merely similar.
const INDEXES_V2: &str = r#"
CREATE INDEX support_tickets_by_lifecycle ON support_tickets(lifecycle, ticket_id);

CREATE INDEX support_tickets_by_sync ON support_tickets(last_synced_ms, ticket_id);
"#;

/// v1 to v2: the two draft columns, added by rebuilding the table.
///
/// A rebuild rather than two `ALTER TABLE ADD COLUMN`s, because the invariant
/// being added is a *cross-column* CHECK — text and instant present together, a
/// draft only on a row that reached `answered` — and `ADD COLUMN` cannot add a
/// table constraint. A migrated database that carried the columns without the
/// CHECK would be a different schema wearing the same `user_version`.
///
/// Every v1 row migrates to a row with no draft, which is exactly true: nothing
/// in v1 could record one.
const MIGRATE_V1_RENAME: &str = "ALTER TABLE support_tickets RENAME TO support_tickets_v1;";

/// The copy, and the disposal of the old table — which takes v1's indexes with
/// it, freeing their names for [`INDEXES_V2`].
const MIGRATE_V1_COPY: &str = r#"
INSERT INTO support_tickets
    (ticket_id, fleet_issue_id, title, tenant_name, site_label, fleet_status,
     priority, source, requested_by, comment_count, created_at, updated_at,
     first_seen_ms, last_synced_ms, lifecycle, revision,
     draft_answer, draft_answer_at_ms)
SELECT
    ticket_id, fleet_issue_id, title, tenant_name, site_label, fleet_status,
    priority, source, requested_by, comment_count, created_at, updated_at,
    first_seen_ms, last_synced_ms, lifecycle, revision,
    NULL, NULL
FROM support_tickets_v1;

DROP TABLE support_tickets_v1;
"#;

/// A support ticket store error with stable refusal categories.
#[derive(Debug)]
pub enum SupportTicketError {
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
    /// The referenced durable row does not exist.
    NotFound(&'static str),
    /// The requested lifecycle does not follow the durable one along the
    /// lattice.
    IllegalTransition {
        /// Lifecycle the durable row records.
        from: TicketLifecycle,
        /// Lifecycle the caller asked for.
        to: TicketLifecycle,
    },
    /// The caller's expected revision does not match the durable revision.
    RevisionMismatch {
        /// Revision the caller believed it was moving.
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
        /// Highest `ticket_id` recorded, or zero when the store is empty.
        retained_last: u64,
    },
    /// The store holds its full capacity of tickets.
    ///
    /// A *new* ticket is refused before a row is written. An update to a ticket
    /// already recorded is not growth and is still admitted, because refusing it
    /// would freeze the board's newest rows at whatever they said when the
    /// ceiling was reached. Nothing here evicts.
    StoreFull {
        /// Capacity of the handle that refused.
        capacity: usize,
    },
    /// A stored row violates an invariant this API can only have written once.
    Corrupt(&'static str),
    /// Filesystem failure while establishing the private store.
    Io(std::io::Error),
    /// SQLite rejected an operation.
    Sqlite(rusqlite::Error),
}

impl SupportTicketError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::NotFound(_) => "not_found",
            Self::IllegalTransition { .. } => "illegal_transition",
            Self::RevisionMismatch { .. } => "revision_mismatch",
            Self::CursorOutOfRange { .. } => "cursor_out_of_range",
            Self::StoreFull { .. } => "store_full",
            Self::Corrupt(_) => "corrupt",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}

impl fmt::Display for SupportTicketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => {
                write!(formatter, "support ticket path is not private: {reason}")
            }
            Self::SchemaVersion { found, supported } => write!(
                formatter,
                "support ticket schema {found} is unsupported; expected {supported}"
            ),
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::NotFound(entity) => write!(formatter, "no such {entity}"),
            Self::IllegalTransition { from, to } => write!(
                formatter,
                "ticket lifecycle {} may not advance to {}",
                from.as_str(),
                to.as_str()
            ),
            Self::RevisionMismatch { expected, durable } => write!(
                formatter,
                "expected revision {expected} but durable revision is {durable}"
            ),
            Self::CursorOutOfRange {
                supplied,
                retained_last,
            } => write!(
                formatter,
                "cursor {supplied} is above the retained ticket_id {retained_last}"
            ),
            Self::StoreFull { capacity } => {
                write!(
                    formatter,
                    "support ticket store holds its capacity of {capacity}"
                )
            }
            Self::Corrupt(invariant) => {
                write!(formatter, "stored row violates invariant: {invariant}")
            }
            Self::Io(error) => write!(formatter, "support ticket filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite error: {error}"),
        }
    }
}

impl Error for SupportTicketError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SupportTicketError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for SupportTicketError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// Result of one support ticket operation.
pub type Ticketed<T> = Result<T, SupportTicketError>;

/// What this host has done about one ticket.
///
/// Deliberately *not* the fleet's `status`, which is recorded verbatim beside it
/// in its own column. The fleet knows whether its own board says `triaging`; it
/// does not know whether Automonique has read the ticket, started on it, or
/// replied. These five words are that second question, and they are this host's
/// to answer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TicketLifecycle {
    /// Recorded from the board. Nobody here has acted on it.
    New,
    /// Somebody here has read it.
    Acknowledged,
    /// Work on it has started.
    Working,
    /// The requester has been replied to.
    Answered,
    /// Finished. Terminal.
    Closed,
}

impl TicketLifecycle {
    /// Every lifecycle, in advancing order.
    pub const ALL: [Self; 5] = [
        Self::New,
        Self::Acknowledged,
        Self::Working,
        Self::Answered,
        Self::Closed,
    ];

    /// Stable machine-oriented spelling, and the exact stored text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Acknowledged => "acknowledged",
            Self::Working => "working",
            Self::Answered => "answered",
            Self::Closed => "closed",
        }
    }

    /// Parse the exact stored text, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == value)
    }

    /// Position along the lattice, `0` at [`Self::New`].
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::New => 0,
            Self::Acknowledged => 1,
            Self::Working => 2,
            Self::Answered => 3,
            Self::Closed => 4,
        }
    }

    /// Whether the ticket has ended.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Whether a ticket in this lifecycle may next be moved to `next`.
    ///
    /// The whole lattice, in one place: one step forward, or straight to
    /// `closed` from anywhere that is not already there. Nothing goes backwards,
    /// nothing skips an intermediate step on the way to `answered`, nothing
    /// leaves `closed`, and nothing re-reports the state it already holds — see
    /// this module's documentation for why the shortcut to `closed` exists and
    /// the others do not.
    #[must_use]
    pub const fn may_advance_to(self, next: Self) -> bool {
        if self.is_terminal() {
            return false;
        }
        next.is_terminal() || next.rank() == self.rank() + 1
    }

    /// Whether a ticket here could still be walked forward to `next`, in one
    /// step or several.
    ///
    /// The transitive closure of [`Self::may_advance_to`], and nothing more:
    /// every pair this admits is joined by a chain of single steps that lattice
    /// allows, and every pair it refuses has no such chain. It exists because
    /// [`SupportTicketStore::record_draft`] has to answer "can this ticket still
    /// become `answered`?" *before* spending a run on it, and asking
    /// `may_advance_to` would answer no for a ticket at `new` that has two
    /// perfectly legal steps left.
    #[must_use]
    pub const fn may_reach(self, next: Self) -> bool {
        if self.is_terminal() {
            return false;
        }
        next.is_terminal() || next.rank() > self.rank()
    }
}

impl fmt::Display for TicketLifecycle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One support issue as the fleet described it, presented for recording.
///
/// The lifecycle is not a field: a first sighting always writes
/// [`TicketLifecycle::New`], because a ticket this host has only just read is
/// one nobody here has acted on. A caller that already knows better records
/// first and transitions second.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FleetTicket<'a> {
    /// Fleet identifier for the request. The dedup key.
    pub fleet_issue_id: &'a str,
    /// Human title, verbatim.
    pub title: &'a str,
    /// Tenant the request belongs to, verbatim. May be empty.
    pub tenant_name: &'a str,
    /// Site the request concerns, when the fleet names one.
    ///
    /// `None` and `Some("")` are not the same value and the second is refused:
    /// the connector already collapses an empty label onto absence, so an empty
    /// string arriving here means a caller built the value some other way.
    pub site_label: Option<&'a str>,
    /// The fleet's own workflow status, verbatim. Never interpreted here.
    pub fleet_status: &'a str,
    /// Priority, verbatim.
    pub priority: &'a str,
    /// Origin channel, verbatim. May be empty.
    pub source: &'a str,
    /// Who filed it, verbatim. May be empty.
    pub requested_by: &'a str,
    /// Comments on the thread.
    pub comment_count: u32,
    /// The fleet's creation timestamp, verbatim and unparsed.
    pub created_at: &'a str,
    /// The fleet's last-update timestamp, verbatim and unparsed.
    pub updated_at: &'a str,
    /// When this host observed the row, in caller-supplied milliseconds.
    pub observed_at_ms: i64,
}

/// One caller's request to move a ticket's lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TicketTransition<'a> {
    /// Fleet issue whose row is being moved.
    pub fleet_issue_id: &'a str,
    /// Durable revision the caller believes it is moving. `1` at first
    /// recording, and one higher after every accepted change.
    pub expected_revision: u64,
    /// Lifecycle to move to. Must follow the durable one along the lattice.
    pub lifecycle: TicketLifecycle,
    /// When the caller decided, in caller-supplied milliseconds.
    pub now_ms: i64,
}

/// Durable identity and fencing revision after one recording or transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TicketReceipt {
    /// Row identity, monotonic in first-sighting order. The pagination key.
    pub ticket_id: i64,
    /// Lifecycle the row now records.
    pub lifecycle: TicketLifecycle,
    /// Revision the row now carries. The next transition must expect this.
    pub revision: u64,
    /// Whether this call created the row.
    ///
    /// The dedup signal: a re-poll of a ticket already recorded reports `false`,
    /// which is how a poller counts new tickets rather than sightings.
    pub inserted: bool,
    /// Whether a field the fleet owns moved.
    ///
    /// `true` on a first sighting. On a re-poll it is `true` only when the fleet
    /// actually said something different, which is also exactly when `revision`
    /// advanced.
    pub changed: bool,
}

/// Validated `support_tickets` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketRecord {
    /// Row identity, monotonic in first-sighting order.
    pub ticket_id: i64,
    /// Fleet identifier for the request.
    pub fleet_issue_id: String,
    /// Human title, as the fleet last described it.
    pub title: String,
    /// Tenant the request belongs to.
    pub tenant_name: String,
    /// Site the request concerns, when the fleet names one.
    pub site_label: Option<String>,
    /// The fleet's own workflow status, verbatim.
    pub fleet_status: String,
    /// Priority, verbatim.
    pub priority: String,
    /// Origin channel, verbatim.
    pub source: String,
    /// Who filed it.
    pub requested_by: String,
    /// Comments on the thread.
    pub comment_count: u32,
    /// The fleet's creation timestamp, verbatim.
    pub created_at: String,
    /// The fleet's last-update timestamp, verbatim.
    pub updated_at: String,
    /// When this host first recorded the ticket. Written once.
    pub first_seen_ms: i64,
    /// When this host last observed the ticket on the board.
    pub last_synced_ms: i64,
    /// What this host has done about it.
    pub lifecycle: TicketLifecycle,
    /// `1` at first recording, and one higher after every accepted change.
    pub revision: u64,
    /// Size of the draft answer this host recorded, in bytes, or `None` when
    /// there is none.
    ///
    /// The size and not the text, deliberately. A listing renders many rows and
    /// a detail view renders one, and neither has any use for 32 KiB of draft;
    /// a caller that wants the text asks [`SupportTicketStore::draft`] for that
    /// one ticket. Loading every draft into memory to report that one exists
    /// would be paying the whole cost of the column for a boolean.
    pub draft_answer_bytes: Option<usize>,
    /// When the draft was recorded, or `None` when there is none.
    ///
    /// Present exactly when [`Self::draft_answer_bytes`] is; the schema will not
    /// hold a row where one is set and the other is not.
    pub draft_answer_at_ms: Option<i64>,
}

impl TicketRecord {
    /// Whether the fleet's own fields differ from the ones presented.
    ///
    /// Compares exactly the columns the fleet owns, and none of the ones this
    /// host does: an observation instant that moved is not the fleet saying
    /// something new.
    #[must_use]
    fn diverges_from(&self, ticket: &FleetTicket<'_>) -> bool {
        self.title != ticket.title
            || self.tenant_name != ticket.tenant_name
            || self.site_label.as_deref() != ticket.site_label
            || self.fleet_status != ticket.fleet_status
            || self.priority != ticket.priority
            || self.source != ticket.source
            || self.requested_by != ticket.requested_by
            || self.comment_count != ticket.comment_count
            || self.created_at != ticket.created_at
            || self.updated_at != ticket.updated_at
    }
}

/// The draft answer one ticket carries, and when this host wrote it.
///
/// Read by [`SupportTicketStore::draft`], which is the only way the text leaves
/// this store. Nothing sends it anywhere: it is what an operator reads before
/// deciding whether the requester should receive anything at all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketDraft {
    /// The draft text, exactly as it was recorded.
    pub text: String,
    /// When this host recorded it, in the caller-supplied milliseconds of the
    /// call that did.
    pub recorded_at_ms: i64,
    /// The lifecycle the row carries now, which is `answered` unless the ticket
    /// has since been closed.
    pub lifecycle: TicketLifecycle,
}

/// One bounded page of ticket rows, ordered by `ticket_id`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketPage {
    /// Rows above the requested cursor, oldest first.
    pub tickets: Vec<TicketRecord>,
    /// Cursor to present for the next page, or `None` when this page is the end
    /// of the query.
    ///
    /// Set only when a further matching row was seen, so an exhausted listing is
    /// distinguishable from one that merely filled its page.
    pub next_cursor: Option<u64>,
}

/// The window of `ticket_id` values this store still holds.
///
/// `first` is `1` in this release because nothing deletes. It is reported rather
/// than assumed so a caller keeps saying something true if that ever changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedTicketRange {
    /// Lowest `ticket_id` still recorded.
    pub first: u64,
    /// Highest `ticket_id` recorded.
    pub last: u64,
}

/// Durable record of the support tickets this host has seen.
#[derive(Debug)]
pub struct SupportTicketStore {
    connection: Connection,
    path: PathBuf,
    capacity: usize,
}

impl SupportTicketStore {
    /// Open or initialize a store inside an existing private directory.
    ///
    /// The parent must be owned by the effective user and deny all group and
    /// other access. Existing paths must be regular, owned, non-symlinks.
    /// Capacity is [`MAX_SUPPORT_TICKETS`].
    ///
    /// # Errors
    ///
    /// Returns [`SupportTicketError::InsecurePath`] for an unsafe path,
    /// [`SupportTicketError::SchemaVersion`] for a foreign or future database,
    /// and the underlying I/O or SQLite failure otherwise.
    pub fn open(path: impl AsRef<Path>) -> Ticketed<Self> {
        Self::open_with_capacity(path, MAX_SUPPORT_TICKETS)
    }

    /// Open a store with a lowered capacity.
    ///
    /// `capacity` must be between one and [`MAX_SUPPORT_TICKETS`]. It is a
    /// property of this handle, not of the database: opening an existing store
    /// under a capacity below its row count refuses further *first sightings*
    /// with [`SupportTicketError::StoreFull`] while updates, transitions and
    /// reads keep working, because none of those adds a row.
    ///
    /// # Errors
    ///
    /// As [`SupportTicketStore::open`], plus
    /// [`SupportTicketError::InvalidField`] for a capacity outside the range.
    pub fn open_with_capacity(path: impl AsRef<Path>, capacity: usize) -> Ticketed<Self> {
        if capacity == 0 || capacity > MAX_SUPPORT_TICKETS {
            return Err(SupportTicketError::InvalidField("capacity"));
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
            return Err(SupportTicketError::Sqlite(rusqlite::Error::InvalidQuery));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        initialize_or_validate_schema(&mut connection)?;

        Ok(Self {
            connection,
            path: path.to_path_buf(),
            capacity,
        })
    }

    /// Exact path opened by this store.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Ticket capacity of this handle.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Record one sighting of a fleet issue, inserting it or updating the row it
    /// already has.
    ///
    /// One immediate transaction, so a reader after a crash sees the whole row
    /// or no row. The row is keyed on `fleet_issue_id`: a re-poll of a ticket
    /// already recorded **updates** it and never inserts a second row, which is
    /// what [`TicketReceipt::inserted`] reports.
    ///
    /// A first sighting writes [`TicketLifecycle::New`] at revision `1`, with
    /// `first_seen_ms` and `last_synced_ms` both at `observed_at_ms`. A later
    /// sighting leaves `first_seen_ms` and the lifecycle exactly where they
    /// were — this call is the *fleet's* writer, and neither column is the
    /// fleet's — advances `last_synced_ms`, and bumps `revision` only when a
    /// field the fleet owns actually moved.
    ///
    /// # Errors
    ///
    /// Returns [`SupportTicketError::InvalidField`] for a malformed field,
    /// [`SupportTicketError::StoreFull`] when a *new* ticket would exceed
    /// capacity, and [`SupportTicketError::Corrupt`] when the existing row it
    /// must compare against is not one this API could have written.
    pub fn record(&mut self, ticket: &FleetTicket<'_>) -> Ticketed<TicketReceipt> {
        validate_ticket(ticket)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(recorded) = read_by_fleet_id(&transaction, ticket.fleet_issue_id)? else {
            let live = count_tickets(&transaction)?;
            if live >= self.capacity {
                return Err(SupportTicketError::StoreFull {
                    capacity: self.capacity,
                });
            }
            transaction.execute(
                "INSERT INTO support_tickets
                 (fleet_issue_id, title, tenant_name, site_label, fleet_status, priority,
                  source, requested_by, comment_count, created_at, updated_at,
                  first_seen_ms, last_synced_ms, lifecycle, revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12, ?13, 1)",
                params![
                    ticket.fleet_issue_id,
                    ticket.title,
                    ticket.tenant_name,
                    ticket.site_label,
                    ticket.fleet_status,
                    ticket.priority,
                    ticket.source,
                    ticket.requested_by,
                    ticket.comment_count,
                    ticket.created_at,
                    ticket.updated_at,
                    ticket.observed_at_ms,
                    TicketLifecycle::New.as_str(),
                ],
            )?;
            let ticket_id = transaction.last_insert_rowid();
            transaction.commit()?;
            return Ok(TicketReceipt {
                ticket_id,
                lifecycle: TicketLifecycle::New,
                revision: 1,
                inserted: true,
                changed: true,
            });
        };

        // An observation may not travel backwards in time. The column CHECK
        // states the same thing about the pair it can see; this is the caller's
        // half, and it refuses rather than silently keeping the later value,
        // because a poller supplying a stale clock is a fact worth surfacing.
        if ticket.observed_at_ms < recorded.last_synced_ms {
            return Err(SupportTicketError::InvalidField("observed_at_ms"));
        }
        let changed = recorded.diverges_from(ticket);
        let next_revision = if changed {
            recorded
                .revision
                .checked_add(1)
                .ok_or(SupportTicketError::InvalidField("revision"))?
        } else {
            recorded.revision
        };
        let updated = transaction.execute(
            "UPDATE support_tickets
             SET title = ?3, tenant_name = ?4, site_label = ?5, fleet_status = ?6,
                 priority = ?7, source = ?8, requested_by = ?9, comment_count = ?10,
                 created_at = ?11, updated_at = ?12, last_synced_ms = ?13, revision = ?14
             WHERE ticket_id = ?1 AND revision = ?2",
            params![
                recorded.ticket_id,
                to_db_u64(recorded.revision, "revision")?,
                ticket.title,
                ticket.tenant_name,
                ticket.site_label,
                ticket.fleet_status,
                ticket.priority,
                ticket.source,
                ticket.requested_by,
                ticket.comment_count,
                ticket.created_at,
                ticket.updated_at,
                ticket.observed_at_ms,
                to_db_u64(next_revision, "revision")?,
            ],
        )?;
        if updated != 1 {
            // The row was read inside this immediate transaction, so nothing
            // else can have moved it; a disagreement means the stored row is not
            // what this API writes.
            return Err(SupportTicketError::Corrupt("ticket_update"));
        }
        transaction.commit()?;
        Ok(TicketReceipt {
            ticket_id: recorded.ticket_id,
            lifecycle: recorded.lifecycle,
            revision: next_revision,
            inserted: false,
            changed,
        })
    }

    /// Move one ticket's lifecycle along the lattice.
    ///
    /// Revision-checked and lattice-checked in one immediate transaction. The
    /// guard is repeated in the `UPDATE` itself, so a row that moved between the
    /// read and the write cannot be overwritten even if a caller reached here
    /// with a revision that happened to match.
    ///
    /// This touches no column the fleet owns. A transition records what *this
    /// host* did; it does not claim the board changed.
    ///
    /// # Errors
    ///
    /// Returns [`SupportTicketError::NotFound`] for an unrecorded fleet issue,
    /// [`SupportTicketError::RevisionMismatch`] for a stale expected revision,
    /// [`SupportTicketError::IllegalTransition`] for a lifecycle that does not
    /// follow the durable one, [`SupportTicketError::InvalidField`] for a
    /// malformed field, and [`SupportTicketError::Corrupt`] when the stored row
    /// is not one this API could have written.
    pub fn transition(&mut self, transition: TicketTransition<'_>) -> Ticketed<TicketReceipt> {
        validate_identifier(
            transition.fleet_issue_id,
            "fleet_issue_id",
            MAX_FLEET_ISSUE_ID_BYTES,
        )?;
        validate_time(transition.now_ms, "now_ms")?;
        if transition.expected_revision == 0 {
            return Err(SupportTicketError::InvalidField("expected_revision"));
        }

        let sqlite = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = read_by_fleet_id(&sqlite, transition.fleet_issue_id)?
            .ok_or(SupportTicketError::NotFound("support ticket"))?;
        if record.revision != transition.expected_revision {
            return Err(SupportTicketError::RevisionMismatch {
                expected: transition.expected_revision,
                durable: record.revision,
            });
        }
        if !record.lifecycle.may_advance_to(transition.lifecycle) {
            return Err(SupportTicketError::IllegalTransition {
                from: record.lifecycle,
                to: transition.lifecycle,
            });
        }
        if transition.now_ms < record.last_synced_ms {
            return Err(SupportTicketError::InvalidField("now_ms"));
        }
        let next_revision = record
            .revision
            .checked_add(1)
            .ok_or(SupportTicketError::InvalidField("revision"))?;
        let changed = sqlite.execute(
            "UPDATE support_tickets
             SET lifecycle = ?3, last_synced_ms = ?4, revision = ?5
             WHERE ticket_id = ?1 AND revision = ?2",
            params![
                record.ticket_id,
                to_db_u64(record.revision, "revision")?,
                transition.lifecycle.as_str(),
                transition.now_ms,
                to_db_u64(next_revision, "revision")?,
            ],
        )?;
        if changed != 1 {
            return Err(SupportTicketError::Corrupt("ticket_transition"));
        }
        sqlite.commit()?;
        Ok(TicketReceipt {
            ticket_id: record.ticket_id,
            lifecycle: transition.lifecycle,
            revision: next_revision,
            inserted: false,
            changed: true,
        })
    }

    /// Record the draft answer this host produced for one ticket, and advance
    /// its lifecycle to [`TicketLifecycle::Answered`].
    ///
    /// One call, one immediate transaction, one revision: the draft and the
    /// lifecycle move together or neither moves, because a row carrying an
    /// answer that does not say it has been answered — or the reverse — is a row
    /// no reader could act on. The schema states the same binding, so a second
    /// writer cannot produce that row either.
    ///
    /// # Why this takes no expected revision
    ///
    /// Every other mutation here is compare-and-set. This one is not, and the
    /// reason is the shape of the work: the caller read the ticket, then spent
    /// minutes running a sandboxed agent against it, and the poller may well
    /// have re-synced the row in the meantime. A revision from before the run is
    /// a token about a *fleet field* that has nothing to do with whether the
    /// answer is still wanted, and refusing on it would throw away a completed
    /// run because a comment count moved.
    ///
    /// What guards this instead is the lattice and the lifecycle it lands on. A
    /// ticket that has already been answered, or has been closed, has no step
    /// left to `answered` and is refused — so a second draft can never overwrite
    /// a first, and a ticket somebody closed during the run does not silently
    /// acquire an answer.
    ///
    /// # Errors
    ///
    /// Returns [`SupportTicketError::NotFound`] for an unrecorded fleet issue,
    /// [`SupportTicketError::IllegalTransition`] when the ticket can no longer
    /// reach `answered`, [`SupportTicketError::InvalidField`] for a draft that is
    /// empty, over [`MAX_DRAFT_ANSWER_BYTES`], or carries a control character
    /// other than newline or tab, for a negative instant, or for one earlier
    /// than the row's last observation, and [`SupportTicketError::Corrupt`] when
    /// the stored row is not one this API could have written.
    pub fn record_draft(
        &mut self,
        fleet_issue_id: &str,
        draft_answer: &str,
        now_ms: i64,
    ) -> Ticketed<TicketReceipt> {
        validate_identifier(fleet_issue_id, "fleet_issue_id", MAX_FLEET_ISSUE_ID_BYTES)?;
        validate_draft(draft_answer)?;
        validate_time(now_ms, "now_ms")?;

        let answered = TicketLifecycle::Answered;
        let sqlite = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = read_by_fleet_id(&sqlite, fleet_issue_id)?
            .ok_or(SupportTicketError::NotFound("support ticket"))?;
        if !record.lifecycle.may_reach(answered) {
            return Err(SupportTicketError::IllegalTransition {
                from: record.lifecycle,
                to: answered,
            });
        }
        if now_ms < record.last_synced_ms {
            return Err(SupportTicketError::InvalidField("now_ms"));
        }
        let next_revision = record
            .revision
            .checked_add(1)
            .ok_or(SupportTicketError::InvalidField("revision"))?;
        let changed = sqlite.execute(
            "UPDATE support_tickets
             SET lifecycle = ?3, draft_answer = ?4, draft_answer_at_ms = ?5,
                 last_synced_ms = ?5, revision = ?6
             WHERE ticket_id = ?1 AND revision = ?2",
            params![
                record.ticket_id,
                to_db_u64(record.revision, "revision")?,
                answered.as_str(),
                draft_answer,
                now_ms,
                to_db_u64(next_revision, "revision")?,
            ],
        )?;
        if changed != 1 {
            // Read inside this immediate transaction, so nothing else moved it.
            return Err(SupportTicketError::Corrupt("ticket_draft"));
        }
        sqlite.commit()?;
        Ok(TicketReceipt {
            ticket_id: record.ticket_id,
            lifecycle: answered,
            revision: next_revision,
            inserted: false,
            changed: true,
        })
    }

    /// The draft answer one ticket carries, if it carries one.
    ///
    /// `Ok(None)` is a ticket nobody has drafted an answer for.
    /// [`SupportTicketError::NotFound`] is a ticket nobody recorded at all —
    /// which is a different fact, and one a caller asking about a reference has
    /// to be able to tell apart.
    ///
    /// # Errors
    ///
    /// Returns [`SupportTicketError::InvalidField`] for a malformed identifier,
    /// [`SupportTicketError::NotFound`] for an unrecorded fleet issue, and
    /// [`SupportTicketError::Corrupt`] for a stored draft this API could not
    /// have written.
    pub fn draft(&self, fleet_issue_id: &str) -> Ticketed<Option<TicketDraft>> {
        validate_identifier(fleet_issue_id, "fleet_issue_id", MAX_FLEET_ISSUE_ID_BYTES)?;
        let row: Option<(Option<String>, Option<i64>, String)> = self
            .connection
            .query_row(
                "SELECT draft_answer, draft_answer_at_ms, lifecycle
                 FROM support_tickets WHERE fleet_issue_id = ?1",
                [fleet_issue_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (text, recorded_at_ms, lifecycle) =
            row.ok_or(SupportTicketError::NotFound("support ticket"))?;
        let lifecycle = TicketLifecycle::from_spelling(&lifecycle)
            .ok_or(SupportTicketError::Corrupt("lifecycle"))?;
        match (text, recorded_at_ms) {
            (None, None) => Ok(None),
            (Some(text), Some(recorded_at_ms)) => {
                validate_draft(&text).map_err(|_| corrupt("draft_answer"))?;
                Ok(Some(TicketDraft {
                    text,
                    recorded_at_ms: checked_time(recorded_at_ms, "draft_answer_at_ms")?,
                    lifecycle,
                }))
            }
            // The schema binds the pair, so a half-written draft is a row that
            // got in around this API.
            _ => Err(corrupt("draft_answer")),
        }
    }

    /// The validated row one fleet issue holds, if any.
    ///
    /// # Errors
    ///
    /// Returns [`SupportTicketError::InvalidField`] for a malformed identifier
    /// and [`SupportTicketError::Corrupt`] for a row this API could not have
    /// written.
    pub fn ticket(&self, fleet_issue_id: &str) -> Ticketed<Option<TicketRecord>> {
        validate_identifier(fleet_issue_id, "fleet_issue_id", MAX_FLEET_ISSUE_ID_BYTES)?;
        read_by_fleet_id(&self.connection, fleet_issue_id)
    }

    /// One bounded page of every ticket, ordered by `ticket_id`, oldest first.
    ///
    /// `cursor` names the row to resume *after*; pass `0` to start at the
    /// beginning, and to advance, pass [`TicketPage::next_cursor`]. `limit` must
    /// be between one and [`MAX_TICKET_PAGE`].
    ///
    /// # Errors
    ///
    /// Returns [`SupportTicketError::InvalidField`] for a limit outside its
    /// range, [`SupportTicketError::CursorOutOfRange`] for a cursor above
    /// everything recorded, and [`SupportTicketError::Corrupt`] for a row this
    /// API could not have written.
    pub fn page(&self, cursor: u64, limit: usize) -> Ticketed<TicketPage> {
        self.read_page(cursor, limit, None)
    }

    /// One bounded page restricted to a set of lifecycles.
    ///
    /// `lifecycles` must be non-empty and free of repeats, because a filter that
    /// admits nothing is a query with no answer and a repeated member is a
    /// caller mistake this module refuses rather than silently folds.
    ///
    /// The cursor is judged against the whole store, not against the filtered
    /// subset: a cursor is a position in the listing order, and a filter that
    /// excluded the row it names must not turn a resumable cursor into a
    /// refusal.
    ///
    /// A filter selects rows; it never hides one. A stored lifecycle outside the
    /// five-word vocabulary matches no filter, so such a row is selected anyway
    /// and refused as [`SupportTicketError::Corrupt`] — a filtered listing and
    /// an unfiltered one answer a corrupt table identically.
    ///
    /// # Errors
    ///
    /// As [`SupportTicketStore::page`], plus
    /// [`SupportTicketError::InvalidField`] for an empty or repeating filter.
    pub fn page_in_lifecycles(
        &self,
        cursor: u64,
        limit: usize,
        lifecycles: &[TicketLifecycle],
    ) -> Ticketed<TicketPage> {
        if lifecycles.is_empty() {
            return Err(SupportTicketError::InvalidField("lifecycles"));
        }
        for (position, lifecycle) in lifecycles.iter().enumerate() {
            if lifecycles[..position].contains(lifecycle) {
                return Err(SupportTicketError::InvalidField("lifecycles"));
            }
        }
        self.read_page(cursor, limit, Some(lifecycles))
    }

    /// The window of `ticket_id` values this store holds, or `None` when empty.
    ///
    /// An empty store has no retained window, and reporting `(0, 0)` would name
    /// a row no writer produced.
    ///
    /// # Errors
    ///
    /// Returns [`SupportTicketError::Corrupt`] for a stored bound outside the
    /// representable range.
    pub fn retained_range(&self) -> Ticketed<Option<RetainedTicketRange>> {
        let bounds: (Option<i64>, Option<i64>) = self.connection.query_row(
            "SELECT MIN(ticket_id), MAX(ticket_id) FROM support_tickets",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        match bounds {
            (Some(first), Some(last)) => {
                let first = checked_row_id(first, "ticket_id")?;
                let last = checked_row_id(last, "ticket_id")?;
                if last < first {
                    return Err(SupportTicketError::Corrupt("ticket_id"));
                }
                Ok(Some(RetainedTicketRange {
                    first: from_db_u64(first, "ticket_id")
                        .map_err(|_| SupportTicketError::Corrupt("ticket_id"))?,
                    last: from_db_u64(last, "ticket_id")
                        .map_err(|_| SupportTicketError::Corrupt("ticket_id"))?,
                }))
            }
            (None, None) => Ok(None),
            _ => Err(SupportTicketError::Corrupt("ticket_id")),
        }
    }

    /// Count durable tickets.
    ///
    /// # Errors
    ///
    /// Returns the SQLite failure, or [`SupportTicketError::Corrupt`] for a
    /// count outside the representable range.
    pub fn ticket_count(&self) -> Ticketed<usize> {
        count_tickets(&self.connection)
    }

    /// Read one page, optionally restricted to a set of lifecycles.
    ///
    /// The page is read inside one transaction together with the bound the
    /// cursor is judged against, so a concurrent recording cannot make the
    /// cursor look out of range for a page that was about to be served.
    fn read_page(
        &self,
        cursor: u64,
        limit: usize,
        lifecycles: Option<&[TicketLifecycle]>,
    ) -> Ticketed<TicketPage> {
        if limit == 0 || limit > MAX_TICKET_PAGE {
            return Err(SupportTicketError::InvalidField("limit"));
        }
        let after = to_db_u64(cursor, "cursor")?;
        let page = i64::try_from(limit).map_err(|_| SupportTicketError::InvalidField("limit"))?;
        let lookahead = page
            .checked_add(1)
            .ok_or(SupportTicketError::InvalidField("limit"))?;

        let transaction = self.connection.unchecked_transaction()?;
        let highest: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(ticket_id), 0) FROM support_tickets",
            [],
            |row| row.get(0),
        )?;
        let retained_last = from_db_u64(highest, "ticket_id")
            .map_err(|_| SupportTicketError::Corrupt("ticket_id"))?;
        if cursor > retained_last {
            return Err(SupportTicketError::CursorOutOfRange {
                supplied: cursor,
                retained_last,
            });
        }

        // The filter is rendered as SQL literals rather than bound parameters
        // because its members are a closed enum whose spellings are fixed
        // lowercase ASCII words from `TicketLifecycle::as_str`; there is no
        // caller-controlled text on this path.
        //
        // The second disjunct is what stops a filter from *hiding* a row: a
        // stored lifecycle outside the whole vocabulary matches no filter, so a
        // bare `WHERE lifecycle IN (...)` would drop a corrupt row from a
        // filtered listing while the unfiltered listing refused it.
        let filter = lifecycles.map_or_else(String::new, |lifecycles| {
            format!(
                " AND (lifecycle IN ({}) OR lifecycle NOT IN ({}))",
                lifecycle_literals(lifecycles),
                lifecycle_literals(&TicketLifecycle::ALL)
            )
        });
        let mut statement = transaction.prepare(&format!(
            "SELECT {RECORD_COLUMNS} FROM support_tickets
             WHERE ticket_id > ?1{filter}
             ORDER BY ticket_id LIMIT ?2"
        ))?;
        let rows = statement.query_map(params![after, lookahead], raw_record)?;
        let mut tickets = Vec::new();
        for raw in rows {
            tickets.push(validated_record(raw?)?);
        }
        drop(statement);
        transaction.rollback()?;

        let next_cursor = if tickets.len() > limit {
            tickets.truncate(limit);
            let last = tickets
                .last()
                .ok_or(SupportTicketError::Corrupt("ticket_id"))?
                .ticket_id;
            Some(
                from_db_u64(last, "ticket_id")
                    .map_err(|_| SupportTicketError::Corrupt("ticket_id"))?,
            )
        } else {
            None
        };
        Ok(TicketPage {
            tickets,
            next_cursor,
        })
    }
}

/// Render a set of lifecycles as a comma-separated SQL literal list.
///
/// Safe by construction: every spelling comes from [`TicketLifecycle::as_str`],
/// which returns one of five fixed lowercase ASCII words.
fn lifecycle_literals(lifecycles: &[TicketLifecycle]) -> String {
    lifecycles
        .iter()
        .map(|lifecycle| format!("'{}'", lifecycle.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

struct RawRecord {
    ticket_id: i64,
    fleet_issue_id: String,
    title: String,
    tenant_name: String,
    site_label: Option<String>,
    fleet_status: String,
    priority: String,
    source: String,
    requested_by: String,
    comment_count: i64,
    created_at: String,
    updated_at: String,
    first_seen_ms: i64,
    last_synced_ms: i64,
    lifecycle: String,
    revision: i64,
    draft_answer_bytes: Option<i64>,
    draft_answer_at_ms: Option<i64>,
}

/// The draft's *size* is selected, never its text.
///
/// `CAST(... AS BLOB)` because the ceiling is stated in bytes and `length()` of
/// TEXT counts characters. `octet_length()` says the same thing and needs a
/// newer SQLite than this workspace pins.
const RECORD_COLUMNS: &str = "ticket_id, fleet_issue_id, title, tenant_name, site_label, \
     fleet_status, priority, source, requested_by, comment_count, created_at, updated_at, \
     first_seen_ms, last_synced_ms, lifecycle, revision, \
     length(CAST(draft_answer AS BLOB)), draft_answer_at_ms";

fn raw_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRecord> {
    Ok(RawRecord {
        ticket_id: row.get(0)?,
        fleet_issue_id: row.get(1)?,
        title: row.get(2)?,
        tenant_name: row.get(3)?,
        site_label: row.get(4)?,
        fleet_status: row.get(5)?,
        priority: row.get(6)?,
        source: row.get(7)?,
        requested_by: row.get(8)?,
        comment_count: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
        first_seen_ms: row.get(12)?,
        last_synced_ms: row.get(13)?,
        lifecycle: row.get(14)?,
        revision: row.get(15)?,
        draft_answer_bytes: row.get(16)?,
        draft_answer_at_ms: row.get(17)?,
    })
}

/// Re-derive a [`TicketRecord`] from a stored row, refusing anything this API
/// could not have written.
///
/// The cross-column invariants are checked here as well as the per-column ones,
/// because a database CHECK protects the table from a second writer while this
/// function protects callers from a row that got in anyway.
fn validated_record(raw: RawRecord) -> Ticketed<TicketRecord> {
    let lifecycle = TicketLifecycle::from_spelling(&raw.lifecycle)
        .ok_or(SupportTicketError::Corrupt("lifecycle"))?;
    let revision = from_db_u64(raw.revision, "revision").map_err(|_| corrupt("revision"))?;
    if revision == 0 {
        return Err(corrupt("revision"));
    }
    let comment_count = u32::try_from(raw.comment_count).map_err(|_| corrupt("comment_count"))?;
    if comment_count > MAX_COMMENT_COUNT {
        return Err(corrupt("comment_count"));
    }
    let first_seen_ms = checked_time(raw.first_seen_ms, "first_seen_ms")?;
    let last_synced_ms = checked_time(raw.last_synced_ms, "last_synced_ms")?;
    if last_synced_ms < first_seen_ms {
        return Err(corrupt("last_synced_ms"));
    }
    let site_label = match raw.site_label {
        None => None,
        Some(label) => Some(checked_identifier(
            label,
            "site_label",
            MAX_SITE_LABEL_BYTES,
        )?),
    };
    // The pair, the ceiling and the lifecycle binding are all schema CHECKs.
    // They are re-derived here for the same reason every other invariant is: a
    // constraint protects the table from a second writer, and this protects a
    // caller from a row that got in anyway.
    let (draft_answer_bytes, draft_answer_at_ms) =
        match (raw.draft_answer_bytes, raw.draft_answer_at_ms) {
            (None, None) => (None, None),
            (Some(bytes), Some(recorded_at_ms)) => {
                let bytes = usize::try_from(bytes).map_err(|_| corrupt("draft_answer"))?;
                if bytes == 0 || bytes > MAX_DRAFT_ANSWER_BYTES {
                    return Err(corrupt("draft_answer"));
                }
                if !matches!(
                    lifecycle,
                    TicketLifecycle::Answered | TicketLifecycle::Closed
                ) {
                    return Err(corrupt("draft_answer"));
                }
                (
                    Some(bytes),
                    Some(checked_time(recorded_at_ms, "draft_answer_at_ms")?),
                )
            }
            _ => return Err(corrupt("draft_answer")),
        };
    Ok(TicketRecord {
        ticket_id: checked_row_id(raw.ticket_id, "ticket_id")?,
        fleet_issue_id: checked_identifier(
            raw.fleet_issue_id,
            "fleet_issue_id",
            MAX_FLEET_ISSUE_ID_BYTES,
        )?,
        title: checked_identifier(raw.title, "title", MAX_TICKET_TITLE_BYTES)?,
        tenant_name: checked_text(raw.tenant_name, "tenant_name", MAX_TENANT_NAME_BYTES)?,
        site_label,
        fleet_status: checked_identifier(raw.fleet_status, "fleet_status", MAX_TICKET_TOKEN_BYTES)?,
        priority: checked_identifier(raw.priority, "priority", MAX_TICKET_TOKEN_BYTES)?,
        source: checked_text(raw.source, "source", MAX_TICKET_TOKEN_BYTES)?,
        requested_by: checked_text(raw.requested_by, "requested_by", MAX_REQUESTED_BY_BYTES)?,
        comment_count,
        created_at: checked_timestamp(raw.created_at, "created_at")?,
        updated_at: checked_timestamp(raw.updated_at, "updated_at")?,
        first_seen_ms,
        last_synced_ms,
        lifecycle,
        revision,
        draft_answer_bytes,
        draft_answer_at_ms,
    })
}

fn read_by_fleet_id(
    connection: &Connection,
    fleet_issue_id: &str,
) -> Ticketed<Option<TicketRecord>> {
    let raw = connection
        .query_row(
            &format!("SELECT {RECORD_COLUMNS} FROM support_tickets WHERE fleet_issue_id = ?1"),
            [fleet_issue_id],
            raw_record,
        )
        .optional()?;
    raw.map(validated_record).transpose()
}

fn count_tickets(connection: &Connection) -> Ticketed<usize> {
    let count: i64 =
        connection.query_row("SELECT count(*) FROM support_tickets", [], |row| row.get(0))?;
    usize::try_from(count).map_err(|_| corrupt("ticket_count"))
}

fn secure_path(path: &Path) -> Ticketed<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => SupportTicketError::Io(io),
        other => SupportTicketError::InsecurePath(other.to_string()),
    })
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Ticketed<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == SUPPORT_TICKETS_SCHEMA_VERSION {
        return Ok(());
    }
    if version == 1 {
        return migrate_v1_to_v2(connection);
    }
    if version != 0 {
        return Err(SupportTicketError::SchemaVersion {
            found: version,
            supported: SUPPORT_TICKETS_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(SupportTicketError::SchemaVersion {
            found: 0,
            supported: SUPPORT_TICKETS_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(TABLE_V2)?;
    transaction.execute_batch(INDEXES_V2)?;
    transaction.pragma_update(None, "user_version", SUPPORT_TICKETS_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

/// Rebuild a v1 table as a v2 one, in one immediate transaction.
///
/// A crash part-way leaves the v1 database exactly as it was: the rename, the
/// copy and the version bump are one atomic unit, so there is no state in which
/// a reader finds `user_version` at 2 and a table without the draft columns, or
/// a `support_tickets_v1` nobody will ever read again.
fn migrate_v1_to_v2(connection: &mut Connection) -> Ticketed<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(MIGRATE_V1_RENAME)?;
    transaction.execute_batch(TABLE_V2)?;
    transaction.execute_batch(MIGRATE_V1_COPY)?;
    transaction.execute_batch(INDEXES_V2)?;
    transaction.pragma_update(None, "user_version", SUPPORT_TICKETS_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

/// Check every field of one presented sighting.
///
/// Which fields may be empty is not a preference: it mirrors the connector's own
/// decoder exactly. `id`, `title`, `status` and `priority` are required to be
/// non-empty there, while `tenant_name`, `source` and `requested_by` are
/// admitted empty because the fleet legitimately sends them that way.
fn validate_ticket(ticket: &FleetTicket<'_>) -> Ticketed<()> {
    validate_identifier(
        ticket.fleet_issue_id,
        "fleet_issue_id",
        MAX_FLEET_ISSUE_ID_BYTES,
    )?;
    validate_identifier(ticket.title, "title", MAX_TICKET_TITLE_BYTES)?;
    validate_text(ticket.tenant_name, "tenant_name", MAX_TENANT_NAME_BYTES)?;
    if let Some(label) = ticket.site_label {
        validate_identifier(label, "site_label", MAX_SITE_LABEL_BYTES)?;
    }
    validate_identifier(ticket.fleet_status, "fleet_status", MAX_TICKET_TOKEN_BYTES)?;
    validate_identifier(ticket.priority, "priority", MAX_TICKET_TOKEN_BYTES)?;
    validate_text(ticket.source, "source", MAX_TICKET_TOKEN_BYTES)?;
    validate_text(ticket.requested_by, "requested_by", MAX_REQUESTED_BY_BYTES)?;
    if ticket.comment_count > MAX_COMMENT_COUNT {
        return Err(SupportTicketError::InvalidField("comment_count"));
    }
    validate_timestamp(ticket.created_at, "created_at")?;
    validate_timestamp(ticket.updated_at, "updated_at")?;
    validate_time(ticket.observed_at_ms, "observed_at_ms")
}

/// A bounded, control-free field that may be empty.
fn validate_text(value: &str, field: &'static str, max_bytes: usize) -> Ticketed<()> {
    if value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(SupportTicketError::InvalidField(field));
    }
    Ok(())
}

/// A bounded, control-free field that may not be empty.
fn validate_identifier(value: &str, field: &'static str, max_bytes: usize) -> Ticketed<()> {
    validate_text(value, field, max_bytes)?;
    if value.is_empty() {
        return Err(SupportTicketError::InvalidField(field));
    }
    Ok(())
}

/// A bounded, non-empty draft answer.
///
/// The one text field here that may hold newlines and tabs, because it is a
/// written answer rather than one of the fleet's single-line fields. Every other
/// control character is refused: a draft is read by an operator in a chat and
/// written back into a support thread, and an escape sequence in either is a
/// rendering nobody asked for.
///
/// The bound is bytes, matching the schema's own `CAST(... AS BLOB)` ceiling.
fn validate_draft(value: &str) -> Ticketed<()> {
    if value.is_empty()
        || value.len() > MAX_DRAFT_ANSWER_BYTES
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(SupportTicketError::InvalidField("draft_answer"));
    }
    Ok(())
}

/// A bounded, non-empty, printable-ASCII timestamp, retained verbatim.
fn validate_timestamp(value: &str, field: &'static str) -> Ticketed<()> {
    if value.is_empty()
        || value.len() > MAX_TIMESTAMP_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(SupportTicketError::InvalidField(field));
    }
    Ok(())
}

fn validate_time(value: i64, field: &'static str) -> Ticketed<()> {
    if value < 0 {
        return Err(SupportTicketError::InvalidField(field));
    }
    Ok(())
}

fn checked_text(value: String, field: &'static str, max_bytes: usize) -> Ticketed<String> {
    validate_text(&value, field, max_bytes).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_identifier(value: String, field: &'static str, max_bytes: usize) -> Ticketed<String> {
    validate_identifier(&value, field, max_bytes).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_timestamp(value: String, field: &'static str) -> Ticketed<String> {
    validate_timestamp(&value, field).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_time(value: i64, field: &'static str) -> Ticketed<i64> {
    validate_time(value, field).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_row_id(value: i64, field: &'static str) -> Ticketed<i64> {
    if value <= 0 {
        return Err(corrupt(field));
    }
    Ok(value)
}

/// Map a validation field onto its stable corruption invariant name.
///
/// Read paths never reuse `InvalidField`: a bad stored row is corruption the
/// caller cannot have caused, and the two must not be confused.
const fn corrupt(field: &'static str) -> SupportTicketError {
    SupportTicketError::Corrupt(field)
}

fn to_db_u64(value: u64, field: &'static str) -> Ticketed<i64> {
    i64::try_from(value).map_err(|_| SupportTicketError::InvalidField(field))
}

fn from_db_u64(value: i64, field: &'static str) -> Ticketed<u64> {
    u64::try_from(value).map_err(|_| SupportTicketError::InvalidField(field))
}
