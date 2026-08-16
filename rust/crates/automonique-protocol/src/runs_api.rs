// SPDX-License-Identifier: Elastic-2.0

//! The Automonique-native Runs API, read half: list a run, read one run, turn a
//! page.
//!
//! `docs/product-plan/requirements/public-agent-protocols.md` § Automonique-native
//! Runs API makes this surface the complete one — "The TypeScript SDK's native
//! API remains the complete surface for cursor-based events, exact revisions,
//! attachments, artifacts, work graphs, sandboxes and reload" — and
//! `docs/product-plan/reference/work-breakdown.md` R11-01 names the resources:
//! "native HTTP runs/events/stop/approval/session/job resources over canonical
//! receipts and cursors".
//!
//! Two rules from `docs/product-plan/requirements/state-and-protocols.md`
//! § Operator client protocol govern every type here:
//!
//! - "A cursor outside retention receives `resync_required`, never a silent
//!   partial stream" (line 431's neighbourhood, the subscription rule this
//!   module applies to a *page* rather than a stream); and
//! - "Responses distinguish `accepted`, `completed`, `rejected`, `conflict`,
//!   `unknown` and `resync_required` so a UI cannot mistake transport failure
//!   for operation failure" — [`crate::journal::ActionOutcome`], reused rather
//!   than restated, with [`RunsResponse::outcome`] saying which three of the six
//!   a read can produce and [`OUTCOMES_A_READ_NEVER_PRODUCES`] saying which
//!   three it cannot.
//!
//! # What this slice is
//!
//! Values. Nothing here queries a store, opens a socket, reads a spool or
//! decides authorization:
//!
//! - a [`RunSummary`] is a caller's claim about a row, recorded with the
//!   coordinates that make it checkable elsewhere, not a row that was read;
//! - [`ListRuns::resume_within`] decides *where a listing may resume* from a
//!   retained window a caller supplies. It does not know what is retained;
//! - [`RunsResponse::listing`] refuses an answer that contradicts the decision
//!   it was built from, which is the whole of this module's enforcement.
//!
//! The daemon handler and the store query are a later slice. What that slice
//! still needs is recorded under "The seam this leaves open" below.
//!
//! # The two states a run has, and why both are carried
//!
//! `automonique_store::run_submissions` holds a submission row whose `state`
//! column has the closed vocabulary `('accepted')` — one value in this release.
//! That is the *custody* state: the daemon holds a RunSpec document. It is not
//! the run's state, and reading `state` out of that table would answer a
//! different question than the one a run list asks.
//!
//! The run's own state lives in the runner's durable spool as
//! `automonique_runner::spool::RunState`. [`RunSummary`] therefore carries both:
//! [`RunSummary::state`] is the spool's, [`RunSummary::submission_state`] is the
//! store's. A reader that sees `state: "completed"` cannot mistake it for a
//! column of `run_submissions`, because the column is beside it and says
//! `accepted`.
//!
//! # Cross-crate spellings this crate cannot import
//!
//! `automonique-protocol` is dependency-free by design, so two vocabularies
//! defined elsewhere are carried here rather than imported:
//!
//! - [`RunState`] against `automonique_runner::spool::RunState`, whose wire
//!   spellings `automonique_runner::control::state_word` renders on the control
//!   socket; and
//! - [`SpoolEventKind`] against `automonique_runner::spool::EventKind`, whose
//!   wire spellings `automonique_runner::control::kind_word` renders.
//!
//! Both are pinned twice by `tests/runs_api.rs`: by literal, and by reading the
//! sibling crate's source and comparing the match arms it declares. The literal
//! pin states the wire contract; the source cross-check names the authority and
//! fails when either side is renamed. This is the honest-gap technique
//! [`crate::provider_catalog`] uses for `ProviderKind` and `RunnerEventDialect`,
//! with the gap narrowed from "a test in the owning crate would catch it" to "a
//! test here reads the owning crate".
//!
//! [`crate::event::Authority`] is *not* carried: the spool's `Authority` and
//! this crate's are the same two words, so [`LIFECYCLE_AUTHORITIES`] reuses the
//! existing type and derives its parser from `Authority::as_str` rather than
//! writing a second spelling down.
//!
//! # Divergences from the plan's Runs API
//!
//! Named rather than silently approximated:
//!
//! - **This is the read half only.** R11-01 names `stop`, `approval`, `session`
//!   and `job` resources too. None is representable here; there is no mutation
//!   in this module and no field through which one could be requested.
//! - **HTTP is absent.** The plan says "native HTTP". These are protocol values
//!   framed by [`crate::codec`] on the same canonical-JSON envelope
//!   [`crate::admin`] uses, under a separate protocol name so the admin lane's
//!   closed kind set stays closed. An HTTP projection is a transport concern
//!   and would carry these bodies unchanged.
//! - **`RunDetailView` carries no event payloads and no chain digest.** The
//!   spool's `Event` exposes payload bytes and the control socket's `subscribe`
//!   serves them hex-encoded; its per-event chain digest has no public accessor
//!   at all. A detail view carries the lifecycle *skeleton* — sequence, time,
//!   kind, authority — and [`LifecycleCoverage`] says whether that skeleton is
//!   the whole log. Payload retrieval stays on the subscribe lane.
//! - **The normalized 23-kind event vocabulary is not used here.**
//!   [`crate::event::EventKind`] is what `automonique-agents` normalizes
//!   provider records *into*; [`SpoolEventKind`] is what the runner's spool
//!   durably holds. Mapping one onto the other is that crate's business, and
//!   doing it here would invent a projection nothing has agreed to.
//! - **Authorization filtering has no representation.** The plan requires
//!   "Attachable-session discovery is authorization-filtered". This module
//!   models no actor, so it cannot filter by one; [`RunsRefusal`] has no
//!   `not_authorized` variant because a refusal this slice cannot decide is a
//!   refusal it must not claim.
//! - **Lease.** `plan/work-graph.toml` gives R11-01 the paths
//!   `rust/crates/automonique-compat-api/`, which does not exist. These values
//!   sit in `automonique-protocol` beside [`crate::admin`], whose custody
//!   vocabulary they read against.
//!
//! # The seam this leaves open
//!
//! A daemon handler for these requests needs three things this module
//! deliberately does not have: the submission log's real retained window (to
//! build the [`crate::journal::RetainedRange`] [`ListRuns::resume_within`]
//! judges against), a join from `run_submissions` to the runner spool that
//! produces [`RunSummary::state`], and the actor that would make
//! [`RunsRefusal`] grow. Until then, every value here is constructible and
//! nothing here is reachable from a socket.

use core::fmt;
use std::error::Error;

use crate::codec::{
    CodecError, Envelope, MajorVersion, MessageKind, ProtocolName, RequestId,
    SecuritySensitiveEnum, SupportedProtocol, VersionRange, decode_security_enum,
};
use crate::digest::Sha256Digest;
use crate::event::Authority;
use crate::journal::{ActionOutcome, CursorResume, JournalCursor, RetainedRange};
use crate::primitives::{EpochMillis, ValueError};
use crate::provenance::{CausationId, CorrelationId, Provenance, TraceId};
use crate::tools::{MAX_TOOL_FIELD_BYTES, RunId};
use crate::wire::{JsonValue, Message};

/// Stable protocol name for the native Runs API.
pub const RUNS_PROTOCOL: &str = "automonique.runs";

/// Stable schema identifier for the version-one read surface.
pub const RUNS_API_SCHEMA_V1: &str = "automonique.runs/v1";

/// Maximum canonical message bytes this protocol will assemble or admit.
pub const MAX_RUNS_CANONICAL_BYTES: usize = 64 * 1024;

/// Maximum summaries one listing page may carry.
///
/// A page bound is not a paging hint. [`RunListPage::new`] refuses a longer
/// vector rather than truncating it, because a truncated page that still
/// answers `complete` is exactly the silent drop the retention rule forbids.
pub const MAX_RUN_PAGE_ITEMS: usize = 64;

/// Maximum lifecycle events one detail view may carry.
pub const MAX_LIFECYCLE_EVENTS: usize = 128;

/// Every authority [`crate::event`] defines, in canonical order.
///
/// The spool's `Authority` and this crate's carry the same two words, so this
/// is a reuse rather than a carried spelling: [`decode_authority`] finds a
/// value by comparing `Authority::as_str`, and no second spelling is written
/// down here.
pub const LIFECYCLE_AUTHORITIES: [Authority; 2] = [Authority::Authoritative, Authority::Synthetic];

/// The three outcomes a read on this protocol can never report.
///
/// `accepted` names a mutation whose completion follows, `conflict` names a
/// failed expected-revision check and `unknown` names a transport failure — and
/// a transport failure is the *absence* of a message, so no message can carry
/// it. A reader that receives one of these on this protocol is reading a
/// response this build did not write.
pub const OUTCOMES_A_READ_NEVER_PRODUCES: [ActionOutcome; 3] = [
    ActionOutcome::Accepted,
    ActionOutcome::Conflict,
    ActionOutcome::Unknown,
];

/// Consumer coordinate the listing cursor delegates under.
const CURSOR_CONSUMER: &str = "automonique.runs";

/// Topic the listing cursor delegates under: the durable submission log.
const CURSOR_TOPIC: &str = "run_submissions";

/// Worst-case canonical bytes of one summary, excluding its run identifier.
///
/// Key names, the quoted 71-byte `sha256:`-spelled digest, the longest state and
/// submission-state spellings, two 20-digit integers and the punctuation.
const RUN_SUMMARY_OVERHEAD_BYTES: usize = 200;

/// Worst-case canonical bytes of one lifecycle event.
const LIFECYCLE_EVENT_BYTES: usize = 176;

/// Worst-case canonical bytes of a page or view scaffold, excluding its items.
const BODY_SCAFFOLD_BYTES: usize = 256;

/// Worst-case canonical bytes of the envelope wrapped around one body.
///
/// The `kind`, `protocol` and `version` members plus a maximal 128-byte
/// `request_id`, budgeted at its JSON-escaped worst case.
const ENVELOPE_OVERHEAD_BYTES: usize = 472;

/// A run identifier costs at most two canonical bytes per source byte, because
/// a quote or a backslash escapes to two.
const RUN_ID_ENCODED_BYTES: usize = 2 * MAX_TOOL_FIELD_BYTES;

const _: () = assert!(
    MAX_RUN_PAGE_ITEMS * (RUN_ID_ENCODED_BYTES + RUN_SUMMARY_OVERHEAD_BYTES)
        + BODY_SCAFFOLD_BYTES
        + ENVELOPE_OVERHEAD_BYTES
        <= MAX_RUNS_CANONICAL_BYTES,
    "a maximal run listing page must fit one runs frame"
);

const _: () = assert!(
    MAX_LIFECYCLE_EVENTS * LIFECYCLE_EVENT_BYTES
        + RUN_ID_ENCODED_BYTES
        + RUN_SUMMARY_OVERHEAD_BYTES
        + BODY_SCAFFOLD_BYTES
        + ENVELOPE_OVERHEAD_BYTES
        <= MAX_RUNS_CANONICAL_BYTES,
    "a maximal run detail view must fit one runs frame"
);

/// Position of an authority in [`LIFECYCLE_AUTHORITIES`].
///
/// The match is exhaustive, so a variant added to [`crate::event::Authority`]
/// fails to compile here rather than dropping out of the array unnoticed and
/// becoming a spelling this lane silently refuses.
const fn authority_slot(authority: Authority) -> usize {
    match authority {
        Authority::Authoritative => 0,
        Authority::Synthetic => 1,
    }
}

const _: () = assert!(
    authority_slot(LIFECYCLE_AUTHORITIES[0]) == 0 && authority_slot(LIFECYCLE_AUTHORITIES[1]) == 1,
    "the authority array and the exhaustive match must agree"
);

/// A refusal while constructing, encoding or decoding a Runs API value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunsApiError {
    /// The shared envelope or canonical JSON codec refused the message.
    ///
    /// Includes [`CodecError::UnknownEnumValue`] for a state, event kind,
    /// authority or submission state this build does not define. Those fail
    /// closed rather than decoding to a default.
    Codec(CodecError),
    /// The message kind is not part of this closed protocol version.
    UnknownKind,
    /// A body was not the exact shape defined for its kind.
    InvalidBody,
    /// A counter cannot be represented by the integer-only wire codec.
    CounterOutOfRange {
        /// Field that was outside the wire range.
        field: &'static str,
    },
    /// A bounded identifier was empty, over-long or control-bearing.
    Field {
        /// Field that was refused.
        field: &'static str,
        /// Why it was refused.
        error: ValueError,
    },
    /// A requested page size was zero or above [`MAX_RUN_PAGE_ITEMS`].
    PageSizeOutOfRange {
        /// Largest page this protocol serves.
        max_items: usize,
        /// Size the caller asked for.
        requested: usize,
    },
    /// A page carried more summaries than [`MAX_RUN_PAGE_ITEMS`].
    PageTooLarge {
        /// Largest page this protocol serves.
        max_items: usize,
        /// Summaries the caller supplied.
        actual_items: usize,
    },
    /// A page carried more summaries than the query it answers asked for.
    PageAboveRequestedSize {
        /// Size the query asked for.
        requested: usize,
        /// Summaries the page carried.
        actual_items: usize,
    },
    /// A view carried more lifecycle events than [`MAX_LIFECYCLE_EVENTS`].
    LifecycleTooLong {
        /// Most events one view carries.
        max_events: usize,
        /// Events the caller supplied.
        actual_events: usize,
    },
    /// A durable row identity was zero, which is a row that was never written.
    UnwrittenRow {
        /// Field that claimed the unwritten identity.
        field: &'static str,
    },
    /// A durable timestamp was before the epoch, which the store cannot hold.
    TimeBeforeEpoch {
        /// Field that carried the impossible instant.
        field: &'static str,
    },
    /// A state filter admitted nothing, which no listing could ever answer.
    StateFilterEmpty,
    /// A state filter named one state twice.
    StateFilterRepeats {
        /// The repeated state.
        state: RunState,
    },
    /// Lifecycle sequences did not strictly increase, or began below one.
    LifecycleOutOfOrder,
    /// A lifecycle event claimed a sequence above the run's last.
    LifecycleAboveLastSequence,
    /// A terminal event was carried with events after it.
    TerminalEventNotLast,
    /// A terminal event was carried for a run whose state is not terminal.
    TerminalEventContradictsState,
    /// The declared coverage contradicts the events and state carried with it.
    CoverageIncoherent,
    /// A page claimed rows follow without a cursor, or a cursor without rows
    /// following.
    ContinuationIncoherent,
    /// A continuation cursor did not advance past the last row on the page.
    ContinuationRewinds,
    /// Page summaries did not strictly increase by submission identity.
    PageOutOfOrder,
    /// A page began before the position its retention decision allowed.
    PageBeforeCursor,
    /// A page carried a summary the query's state filter excludes.
    PageOutsideFilter,
    /// A `resync_required` answer was handed rows, which it must never carry.
    ResyncCarriesRows,
    /// A live retention decision was not given the page it admits.
    PageMissing,
}

impl RunsApiError {
    /// Stable category suitable for logs and refusal metrics.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Codec(error) => error.category(),
            Self::UnknownKind => "runs_unknown_kind",
            Self::InvalidBody => "runs_invalid_body",
            Self::CounterOutOfRange { .. } => "runs_counter_out_of_range",
            Self::Field { .. } => "runs_invalid_field",
            Self::PageSizeOutOfRange { .. } => "runs_page_size_out_of_range",
            Self::PageTooLarge { .. } => "runs_page_too_large",
            Self::PageAboveRequestedSize { .. } => "runs_page_above_requested_size",
            Self::LifecycleTooLong { .. } => "runs_lifecycle_too_long",
            Self::UnwrittenRow { .. } => "runs_unwritten_row",
            Self::TimeBeforeEpoch { .. } => "runs_time_before_epoch",
            Self::StateFilterEmpty => "runs_state_filter_empty",
            Self::StateFilterRepeats { .. } => "runs_state_filter_repeats",
            Self::LifecycleOutOfOrder => "runs_lifecycle_out_of_order",
            Self::LifecycleAboveLastSequence => "runs_lifecycle_above_last_sequence",
            Self::TerminalEventNotLast => "runs_terminal_event_not_last",
            Self::TerminalEventContradictsState => "runs_terminal_event_contradicts_state",
            Self::CoverageIncoherent => "runs_coverage_incoherent",
            Self::ContinuationIncoherent => "runs_continuation_incoherent",
            Self::ContinuationRewinds => "runs_continuation_rewinds",
            Self::PageOutOfOrder => "runs_page_out_of_order",
            Self::PageBeforeCursor => "runs_page_before_cursor",
            Self::PageOutsideFilter => "runs_page_outside_filter",
            Self::ResyncCarriesRows => "runs_resync_carries_rows",
            Self::PageMissing => "runs_page_missing",
        }
    }
}

impl fmt::Display for RunsApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "runs codec refused message: {error}"),
            Self::UnknownKind => formatter.write_str("runs message kind is not defined"),
            Self::InvalidBody => formatter.write_str("runs message body is invalid"),
            Self::CounterOutOfRange { field } => {
                write!(formatter, "runs counter {field} is outside the wire range")
            }
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
            Self::PageSizeOutOfRange {
                max_items,
                requested,
            } => write!(
                formatter,
                "page size {requested} is outside 1..={max_items}"
            ),
            Self::PageTooLarge {
                max_items,
                actual_items,
            } => write!(
                formatter,
                "page carries {actual_items} runs; maximum is {max_items}"
            ),
            Self::PageAboveRequestedSize {
                requested,
                actual_items,
            } => write!(
                formatter,
                "page carries {actual_items} runs; the query asked for {requested}"
            ),
            Self::LifecycleTooLong {
                max_events,
                actual_events,
            } => write!(
                formatter,
                "view carries {actual_events} events; maximum is {max_events}"
            ),
            Self::UnwrittenRow { field } => {
                write!(formatter, "{field} is zero, which names an unwritten row")
            }
            Self::TimeBeforeEpoch { field } => {
                write!(formatter, "{field} is before the epoch")
            }
            Self::StateFilterEmpty => formatter.write_str("a state filter admits no state"),
            Self::StateFilterRepeats { state } => {
                write!(formatter, "state filter names {state} twice")
            }
            Self::LifecycleOutOfOrder => {
                formatter.write_str("lifecycle sequences do not strictly increase from one")
            }
            Self::LifecycleAboveLastSequence => {
                formatter.write_str("a lifecycle event is above the run's last sequence")
            }
            Self::TerminalEventNotLast => {
                formatter.write_str("a terminal event is followed by another event")
            }
            Self::TerminalEventContradictsState => {
                formatter.write_str("a terminal event was carried for a non-terminal run")
            }
            Self::CoverageIncoherent => {
                formatter.write_str("declared lifecycle coverage contradicts what is carried")
            }
            Self::ContinuationIncoherent => {
                formatter.write_str("a page's continuation marker and cursor disagree")
            }
            Self::ContinuationRewinds => {
                formatter.write_str("a continuation cursor does not advance past the page")
            }
            Self::PageOutOfOrder => {
                formatter.write_str("page summaries do not strictly increase by submission")
            }
            Self::PageBeforeCursor => {
                formatter.write_str("a page begins before its retention decision allows")
            }
            Self::PageOutsideFilter => {
                formatter.write_str("a page carries a run the query's state filter excludes")
            }
            Self::ResyncCarriesRows => {
                formatter.write_str("a resync_required answer cannot carry rows")
            }
            Self::PageMissing => formatter.write_str("a live retention decision was given no page"),
        }
    }
}

impl Error for RunsApiError {}

impl From<CodecError> for RunsApiError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

/// The state one run is in, carried from the runner's durable spool.
///
/// Mirrors `automonique_runner::spool::RunState`, which this dependency-free
/// crate cannot import. Six variants, six spellings, pinned by literal *and*
/// against the sibling crate's source in `tests/runs_api.rs`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RunState {
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

impl RunState {
    /// Every state, in the spool's declaration order.
    pub const ALL: [Self; 6] = [
        Self::Ready,
        Self::Running,
        Self::Completed,
        Self::Failed,
        Self::Cancelled,
        Self::TimedOut,
    ];

    /// Stable lowercase wire spelling.
    ///
    /// Identical to `automonique_runner::control::state_word`, which renders
    /// the same states on the control socket.
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

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == value)
    }

    /// Whether the run has ended.
    ///
    /// The spool reaches exactly one terminal event, and the four states below
    /// are what its payload discriminates into. `ready` and `running` are the
    /// two a run can still leave.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::TimedOut
        )
    }
}

impl fmt::Display for RunState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for RunState {
    const FIELD: &'static str = "state";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// The durable custody state of one submission row.
///
/// Mirrors the closed `CHECK (state IN ('accepted'))` vocabulary of
/// `automonique_store::run_submissions`. One variant, because the store defines
/// one value: custody is the only thing that release durably records about a
/// submission. This is the same deliberate single-variant shape
/// [`crate::provider_catalog::ProviderKind`] carries, and it grows when the
/// store's constraint does — not before.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SubmissionState {
    /// The daemon durably holds the RunSpec document.
    Accepted,
}

impl SubmissionState {
    /// Every state the store defines, in canonical order.
    pub const ALL: [Self; 1] = [Self::Accepted];

    /// Stable lowercase wire spelling, identical to the stored column value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == value)
    }
}

impl fmt::Display for SubmissionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for SubmissionState {
    const FIELD: &'static str = "submission_state";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// The kind of one durable spool event.
///
/// Mirrors `automonique_runner::spool::EventKind`, whose wire spellings
/// `automonique_runner::control::kind_word` renders on the control socket.
///
/// This is deliberately *not* [`crate::event::EventKind`]. That enum is the
/// normalized 23-kind vocabulary `automonique-agents` produces from provider
/// records; this one is the five kinds the runner durably appends. A read
/// surface that silently substituted one for the other would be inventing a
/// projection nothing has agreed to.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SpoolEventKind {
    /// The run began.
    Started,
    /// A normalized record from the provider adapter.
    AdapterEvent,
    /// A record from the simulation backend.
    SimulationEvent,
    /// A cancellation was requested against the run.
    CancelRequested,
    /// The single terminal event.
    Terminal,
}

impl SpoolEventKind {
    /// Every kind, in the spool's declaration order.
    pub const ALL: [Self; 5] = [
        Self::Started,
        Self::AdapterEvent,
        Self::SimulationEvent,
        Self::CancelRequested,
        Self::Terminal,
    ];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::AdapterEvent => "adapter_event",
            Self::SimulationEvent => "simulation_event",
            Self::CancelRequested => "cancel_requested",
            Self::Terminal => "terminal",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }

    /// Whether this kind ends a run.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal)
    }
}

impl fmt::Display for SpoolEventKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for SpoolEventKind {
    const FIELD: &'static str = "kind";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// Decode an authority spelling, failing closed on an unknown one.
///
/// Derived from `Authority::as_str` rather than from a second spelling table,
/// so this module cannot disagree with [`crate::event`] about a word.
///
/// # Errors
///
/// Returns [`CodecError::UnknownEnumValue`] for a spelling this build does not
/// define.
pub fn decode_authority(value: &str) -> Result<Authority, RunsApiError> {
    LIFECYCLE_AUTHORITIES
        .into_iter()
        .find(|candidate| candidate.as_str() == value)
        .ok_or(RunsApiError::Codec(CodecError::UnknownEnumValue {
            field: "authority",
        }))
}

/// A durable listing position: the next submission identity a caller receives.
///
/// The run listing is ordered by `run_submissions.submission_id`, which is
/// monotonic in acceptance order, so a cursor is one of those identities. It is
/// a journal cursor on the submission topic and is judged as one — see
/// [`RunCursor::resume_within`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunCursor(u64);

impl RunCursor {
    /// Name a listing position.
    #[must_use]
    pub const fn new(position: u64) -> Self {
        Self(position)
    }

    /// The next submission identity this cursor will receive.
    #[must_use]
    pub const fn position(self) -> u64 {
        self.0
    }

    /// Where a listing holding this cursor may resume.
    ///
    /// Delegates to [`JournalCursor::resume_within`]. The resumable set is
    /// `first ..= caught_up`, which is one larger than the retained window, and
    /// re-deriving that off-by-one here — recorded as amendment A2 of
    /// `plan/contracts/R1-12.md` — is exactly the drift the house forbids. A
    /// cursor outside the set answers [`CursorResume::ResyncRequired`], never a
    /// position that would skip rows.
    ///
    /// The journal's coordinates are compile-time literals inside its field
    /// bound, so the constructor cannot refuse them; `tests/runs_api.rs` pins
    /// that. The branch is nonetheless classified rather than unwrapped, and it
    /// fails closed to a resync: a panic in a read path, or a live answer built
    /// from a decision that was never made, are both worse than asking a client
    /// to snapshot.
    #[must_use]
    pub fn resume_within(self, retained: RetainedRange) -> CursorResume {
        match JournalCursor::new(CURSOR_CONSUMER, CURSOR_TOPIC, self.0) {
            Ok(cursor) => cursor.resume_within(retained),
            Err(_) => CursorResume::ResyncRequired {
                snapshot_from: retained.first(),
                snapshot_to: retained.last(),
            },
        }
    }
}

/// How many summaries one listing asks for.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PageSize(usize);

impl PageSize {
    /// The largest page this protocol serves.
    pub const MAX: Self = Self(MAX_RUN_PAGE_ITEMS);

    /// Ask for a bounded number of summaries.
    ///
    /// # Errors
    ///
    /// Returns [`RunsApiError::PageSizeOutOfRange`] for zero — a page that
    /// admits nothing cannot make progress — or for a size above
    /// [`MAX_RUN_PAGE_ITEMS`].
    pub const fn new(items: usize) -> Result<Self, RunsApiError> {
        if items == 0 || items > MAX_RUN_PAGE_ITEMS {
            return Err(RunsApiError::PageSizeOutOfRange {
                max_items: MAX_RUN_PAGE_ITEMS,
                requested: items,
            });
        }
        Ok(Self(items))
    }

    /// The requested size.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

/// Which states a listing admits.
///
/// [`RunStateFilter::any`] is the absence of a filter, which is different from
/// a filter naming all six states only in what a later release would mean by
/// it. Both are representable; neither is an empty list, which
/// [`RunStateFilter::only`] refuses.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RunStateFilter(Option<Vec<RunState>>);

impl RunStateFilter {
    /// Admit every state.
    #[must_use]
    pub const fn any() -> Self {
        Self(None)
    }

    /// Admit exactly the named states.
    ///
    /// The set is sorted into [`RunState::ALL`] order so a filter built in any
    /// order encodes identically.
    ///
    /// # Errors
    ///
    /// Returns [`RunsApiError::StateFilterEmpty`] for an empty set and
    /// [`RunsApiError::StateFilterRepeats`] for a repeated state, because a
    /// repeat is a caller that believes it asked for something it did not.
    pub fn only(states: impl IntoIterator<Item = RunState>) -> Result<Self, RunsApiError> {
        let mut ordered: Vec<RunState> = states.into_iter().collect();
        if ordered.is_empty() {
            return Err(RunsApiError::StateFilterEmpty);
        }
        ordered.sort_unstable();
        if let Some(pair) = ordered.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(RunsApiError::StateFilterRepeats { state: pair[0] });
        }
        Ok(Self(Some(ordered)))
    }

    /// Whether this filter admits a state.
    #[must_use]
    pub fn admits(&self, state: RunState) -> bool {
        self.0.as_ref().is_none_or(|states| states.contains(&state))
    }

    /// The named states, when the filter names any.
    #[must_use]
    pub fn states(&self) -> Option<&[RunState]> {
        self.0.as_deref()
    }
}

/// A bounded request to list runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListRuns {
    states: RunStateFilter,
    since: Option<RunCursor>,
    page_size: PageSize,
}

impl ListRuns {
    /// Ask for one page of runs.
    #[must_use]
    pub const fn new(
        states: RunStateFilter,
        since: Option<RunCursor>,
        page_size: PageSize,
    ) -> Self {
        Self {
            states,
            since,
            page_size,
        }
    }

    /// Which states this listing admits.
    #[must_use]
    pub const fn states(&self) -> &RunStateFilter {
        &self.states
    }

    /// Where this listing resumes, when it resumes.
    #[must_use]
    pub const fn since(&self) -> Option<RunCursor> {
        self.since
    }

    /// How many summaries this listing asks for.
    #[must_use]
    pub const fn page_size(&self) -> PageSize {
        self.page_size
    }

    /// Where this listing may be answered from, given what the log retains.
    ///
    /// A listing without a cursor starts at the oldest position still retained,
    /// never at position one: claiming to have started at the beginning of a log
    /// whose beginning was pruned is the same silent drop as serving an
    /// out-of-retention cursor.
    ///
    /// A listing with a cursor is judged by [`RunCursor::resume_within`], so a
    /// cursor outside retention yields [`CursorResume::ResyncRequired`] — and
    /// [`RunsResponse::listing`] refuses to build a page from that decision.
    #[must_use]
    pub fn resume_within(&self, retained: RetainedRange) -> CursorResume {
        match self.since {
            Some(cursor) => cursor.resume_within(retained),
            None => CursorResume::Live {
                from: retained.first(),
            },
        }
    }

    fn to_body(&self) -> Result<JsonValue, RunsApiError> {
        Ok(JsonValue::Object(vec![
            (
                "page_size".to_owned(),
                integer("page_size", self.page_size.get() as u64)?,
            ),
            (
                "since".to_owned(),
                match self.since {
                    Some(cursor) => integer("since", cursor.position())?,
                    None => JsonValue::Null,
                },
            ),
            (
                "states".to_owned(),
                match self.states.states() {
                    Some(states) => JsonValue::Array(
                        states
                            .iter()
                            .map(|state| JsonValue::String(state.as_str().to_owned()))
                            .collect(),
                    ),
                    None => JsonValue::Null,
                },
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, RunsApiError> {
        exact_fields(body, &["page_size", "since", "states"])?;
        let page_size =
            PageSize::new(usize::try_from(unsigned(body, "page_size")?).map_err(|_| {
                RunsApiError::PageSizeOutOfRange {
                    max_items: MAX_RUN_PAGE_ITEMS,
                    requested: MAX_RUN_PAGE_ITEMS.saturating_add(1),
                }
            })?)?;
        let since = match body.get("since") {
            Some(JsonValue::Null) => None,
            Some(JsonValue::Integer(_)) => Some(RunCursor::new(unsigned(body, "since")?)),
            _ => return Err(RunsApiError::InvalidBody),
        };
        let states = match body.get("states") {
            Some(JsonValue::Null) => RunStateFilter::any(),
            Some(JsonValue::Array(items)) => {
                let mut states = Vec::with_capacity(items.len());
                for item in items {
                    let spelling = item.as_str().ok_or(RunsApiError::InvalidBody)?;
                    states.push(decode_security_enum::<RunState>(spelling)?);
                }
                RunStateFilter::only(states)?
            }
            _ => return Err(RunsApiError::InvalidBody),
        };
        Ok(Self::new(states, since, page_size))
    }
}

/// One run, as a listing reports it.
///
/// [`RunSummary::state`] comes from the runner's spool and
/// [`RunSummary::submission_state`] from the store's `run_submissions` row; see
/// the module note on why both travel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunSummary {
    run_id: RunId,
    submission_id: u64,
    spec_digest: Sha256Digest,
    state: RunState,
    submission_state: SubmissionState,
    accepted_at: EpochMillis,
}

impl RunSummary {
    /// Record one run.
    ///
    /// # Errors
    ///
    /// Returns [`RunsApiError::UnwrittenRow`] for a zero `submission_id`, which
    /// names a row no writer produced — durable identities start at one — and
    /// [`RunsApiError::TimeBeforeEpoch`] for an acceptance instant the store's
    /// `accepted_at_ms >= 0` constraint cannot hold.
    pub fn new(
        run_id: RunId,
        submission_id: u64,
        spec_digest: Sha256Digest,
        state: RunState,
        submission_state: SubmissionState,
        accepted_at: EpochMillis,
    ) -> Result<Self, RunsApiError> {
        if submission_id == 0 {
            return Err(RunsApiError::UnwrittenRow {
                field: "submission_id",
            });
        }
        if accepted_at.as_millis() < 0 {
            return Err(RunsApiError::TimeBeforeEpoch {
                field: "accepted_at_ms",
            });
        }
        Ok(Self {
            run_id,
            submission_id,
            spec_digest,
            state,
            submission_state,
            accepted_at,
        })
    }

    /// Run identity the accepted document claimed.
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Durable identity of the submission row, monotonic in acceptance order.
    #[must_use]
    pub const fn submission_id(&self) -> u64 {
        self.submission_id
    }

    /// SHA-256 the daemon verified over the accepted document bytes.
    #[must_use]
    pub const fn spec_digest(&self) -> &Sha256Digest {
        &self.spec_digest
    }

    /// The run's state, from the runner's durable spool.
    #[must_use]
    pub const fn state(&self) -> RunState {
        self.state
    }

    /// The submission's custody state, from the store.
    #[must_use]
    pub const fn submission_state(&self) -> SubmissionState {
        self.submission_state
    }

    /// When the first acceptance of this submission was recorded.
    #[must_use]
    pub const fn accepted_at(&self) -> EpochMillis {
        self.accepted_at
    }

    fn to_body(&self) -> Result<JsonValue, RunsApiError> {
        Ok(JsonValue::Object(vec![
            (
                "accepted_at_ms".to_owned(),
                JsonValue::Integer(self.accepted_at.as_millis()),
            ),
            (
                "run_id".to_owned(),
                JsonValue::String(self.run_id.as_str().to_owned()),
            ),
            (
                "spec_digest".to_owned(),
                JsonValue::String(self.spec_digest.to_string()),
            ),
            (
                "state".to_owned(),
                JsonValue::String(self.state.as_str().to_owned()),
            ),
            (
                "submission_id".to_owned(),
                integer("submission_id", self.submission_id)?,
            ),
            (
                "submission_state".to_owned(),
                JsonValue::String(self.submission_state.as_str().to_owned()),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, RunsApiError> {
        exact_fields(
            body,
            &[
                "accepted_at_ms",
                "run_id",
                "spec_digest",
                "state",
                "submission_id",
                "submission_state",
            ],
        )?;
        let accepted_at_ms = body
            .get("accepted_at_ms")
            .and_then(JsonValue::as_integer)
            .ok_or(RunsApiError::InvalidBody)?;
        Self::new(
            RunId::new(required_string(body, "run_id")?).map_err(|error| RunsApiError::Field {
                field: "run_id",
                error,
            })?,
            unsigned(body, "submission_id")?,
            required_string(body, "spec_digest")?
                .parse()
                .map_err(|_| RunsApiError::InvalidBody)?,
            decode_security_enum::<RunState>(&required_string(body, "state")?)?,
            decode_security_enum::<SubmissionState>(&required_string(body, "submission_state")?)?,
            EpochMillis::from_millis(accepted_at_ms),
        )
    }
}

/// One durable lifecycle event, as the runner's spool exposes it.
///
/// The payload bytes and the chained digest are deliberately absent; see the
/// module's divergence note.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunLifecycleEvent {
    sequence: u64,
    at: EpochMillis,
    kind: SpoolEventKind,
    authority: Authority,
}

impl RunLifecycleEvent {
    /// Record one lifecycle event.
    ///
    /// # Errors
    ///
    /// Returns [`RunsApiError::LifecycleOutOfOrder`] for sequence zero — spool
    /// sequences begin at one, and zero is the value the spool's status reports
    /// when there are *no* events — and [`RunsApiError::TimeBeforeEpoch`] for an
    /// instant the spool's unsigned millisecond field cannot hold.
    pub const fn new(
        sequence: u64,
        at: EpochMillis,
        kind: SpoolEventKind,
        authority: Authority,
    ) -> Result<Self, RunsApiError> {
        if sequence == 0 {
            return Err(RunsApiError::LifecycleOutOfOrder);
        }
        if at.as_millis() < 0 {
            return Err(RunsApiError::TimeBeforeEpoch { field: "at_ms" });
        }
        Ok(Self {
            sequence,
            at,
            kind,
            authority,
        })
    }

    /// Position in the run's spool, beginning at one.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// When the runner recorded it.
    #[must_use]
    pub const fn at(self) -> EpochMillis {
        self.at
    }

    /// What kind of event it is.
    #[must_use]
    pub const fn kind(self) -> SpoolEventKind {
        self.kind
    }

    /// How much it may be relied upon.
    #[must_use]
    pub const fn authority(self) -> Authority {
        self.authority
    }

    fn to_body(self) -> Result<JsonValue, RunsApiError> {
        Ok(JsonValue::Object(vec![
            ("at_ms".to_owned(), JsonValue::Integer(self.at.as_millis())),
            (
                "authority".to_owned(),
                JsonValue::String(self.authority.as_str().to_owned()),
            ),
            (
                "kind".to_owned(),
                JsonValue::String(self.kind.as_str().to_owned()),
            ),
            ("sequence".to_owned(), integer("sequence", self.sequence)?),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, RunsApiError> {
        exact_fields(body, &["at_ms", "authority", "kind", "sequence"])?;
        let at_ms = body
            .get("at_ms")
            .and_then(JsonValue::as_integer)
            .ok_or(RunsApiError::InvalidBody)?;
        Self::new(
            unsigned(body, "sequence")?,
            EpochMillis::from_millis(at_ms),
            decode_security_enum::<SpoolEventKind>(&required_string(body, "kind")?)?,
            decode_authority(&required_string(body, "authority")?)?,
        )
    }
}

/// Whether a detail view's lifecycle is the whole log.
///
/// Closed, and required on every view. A bounded list of events with no
/// statement about what it omits is a partial stream presented as a whole one,
/// which is the failure the retention rule exists to prevent — at a different
/// scale, but the same failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LifecycleCoverage {
    /// Every event the spool holds for this run is carried.
    Complete,
    /// A bounded tail is carried; the rest is on the subscribe lane, resuming
    /// from [`RunDetailView::resume_cursor`].
    Truncated,
}

impl LifecycleCoverage {
    /// Every coverage, in canonical order.
    pub const ALL: [Self; 2] = [Self::Complete, Self::Truncated];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Truncated => "truncated",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|coverage| coverage.as_str() == value)
    }
}

impl fmt::Display for LifecycleCoverage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for LifecycleCoverage {
    const FIELD: &'static str = "coverage";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// One run, in full: its summary and its lifecycle skeleton.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunDetailView {
    summary: RunSummary,
    last_sequence: u64,
    lifecycle: Vec<RunLifecycleEvent>,
    coverage: LifecycleCoverage,
    provenance: Option<Provenance>,
}

impl RunDetailView {
    /// Assemble a view, refusing every incoherent combination.
    ///
    /// The spool's own rules are enforced here rather than assumed:
    ///
    /// - sequences strictly increase, so a view cannot repeat or reorder;
    /// - no carried sequence exceeds `last_sequence`, which is what the spool's
    ///   status reports and what `inspect` renders;
    /// - there is at most one terminal event and nothing follows it;
    /// - a terminal event is carried only for a terminal state; and
    /// - [`LifecycleCoverage::Complete`] means what it says: an empty lifecycle
    ///   is `ready` at sequence zero, a non-empty one ends exactly at
    ///   `last_sequence`, and its final event is terminal if and only if the
    ///   state is. [`LifecycleCoverage::Truncated`] must carry at least one
    ///   event and must stop below `last_sequence`, or it is not truncated.
    ///
    /// # Errors
    ///
    /// Returns [`RunsApiError::LifecycleTooLong`],
    /// [`RunsApiError::LifecycleOutOfOrder`],
    /// [`RunsApiError::LifecycleAboveLastSequence`],
    /// [`RunsApiError::TerminalEventNotLast`],
    /// [`RunsApiError::TerminalEventContradictsState`] or
    /// [`RunsApiError::CoverageIncoherent`].
    pub fn new(
        summary: RunSummary,
        last_sequence: u64,
        lifecycle: Vec<RunLifecycleEvent>,
        coverage: LifecycleCoverage,
    ) -> Result<Self, RunsApiError> {
        if lifecycle.len() > MAX_LIFECYCLE_EVENTS {
            return Err(RunsApiError::LifecycleTooLong {
                max_events: MAX_LIFECYCLE_EVENTS,
                actual_events: lifecycle.len(),
            });
        }
        if lifecycle
            .windows(2)
            .any(|pair| pair[1].sequence() <= pair[0].sequence())
        {
            return Err(RunsApiError::LifecycleOutOfOrder);
        }
        if lifecycle
            .iter()
            .any(|event| event.sequence() > last_sequence)
        {
            return Err(RunsApiError::LifecycleAboveLastSequence);
        }
        if lifecycle
            .iter()
            .rev()
            .skip(1)
            .any(|event| event.kind().is_terminal())
        {
            return Err(RunsApiError::TerminalEventNotLast);
        }
        let ends_terminal = lifecycle
            .last()
            .is_some_and(|event| event.kind().is_terminal());
        if ends_terminal && !summary.state().is_terminal() {
            return Err(RunsApiError::TerminalEventContradictsState);
        }
        let coherent = match (coverage, lifecycle.last()) {
            (LifecycleCoverage::Complete, None) => {
                summary.state() == RunState::Ready && last_sequence == 0
            }
            (LifecycleCoverage::Complete, Some(last)) => {
                last.sequence() == last_sequence && ends_terminal == summary.state().is_terminal()
            }
            (LifecycleCoverage::Truncated, None) => false,
            (LifecycleCoverage::Truncated, Some(last)) => last.sequence() < last_sequence,
        };
        if !coherent {
            return Err(RunsApiError::CoverageIncoherent);
        }
        Ok(Self {
            summary,
            last_sequence,
            lifecycle,
            coverage,
            provenance: None,
        })
    }

    /// Attach the durable ancestry for this run and its attempt events.
    #[must_use]
    pub fn with_provenance(mut self, provenance: Provenance) -> Self {
        self.provenance = Some(provenance);
        self
    }

    /// The listing summary for this run.
    #[must_use]
    pub const fn summary(&self) -> &RunSummary {
        &self.summary
    }

    /// Highest sequence the run's spool holds; zero when it holds none.
    #[must_use]
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// The carried lifecycle, in sequence order.
    #[must_use]
    pub fn lifecycle(&self) -> &[RunLifecycleEvent] {
        &self.lifecycle
    }

    /// Whether the carried lifecycle is the whole log.
    #[must_use]
    pub const fn coverage(&self) -> LifecycleCoverage {
        self.coverage
    }

    #[must_use]
    pub const fn provenance(&self) -> Option<&Provenance> {
        self.provenance.as_ref()
    }

    /// The cursor a subscriber resumes from to receive what this view omits.
    ///
    /// `None` when the view is complete: there is nothing to resume. Otherwise
    /// the last carried sequence, which the control socket's `subscribe` treats
    /// as exclusive, so the next event delivered is the first one omitted here.
    #[must_use]
    pub fn resume_cursor(&self) -> Option<u64> {
        match self.coverage {
            LifecycleCoverage::Complete => None,
            LifecycleCoverage::Truncated => self.lifecycle.last().map(|event| event.sequence()),
        }
    }

    fn to_body(&self) -> Result<JsonValue, RunsApiError> {
        let mut lifecycle = Vec::with_capacity(self.lifecycle.len());
        for event in &self.lifecycle {
            lifecycle.push(event.to_body()?);
        }
        Ok(JsonValue::Object(vec![
            (
                "causation_id".to_owned(),
                self.provenance.as_ref().map_or(JsonValue::Null, |value| {
                    JsonValue::String(value.causation_id().as_str().to_owned())
                }),
            ),
            (
                "correlation_id".to_owned(),
                self.provenance.as_ref().map_or(JsonValue::Null, |value| {
                    JsonValue::String(value.correlation_id().as_str().to_owned())
                }),
            ),
            (
                "coverage".to_owned(),
                JsonValue::String(self.coverage.as_str().to_owned()),
            ),
            (
                "last_sequence".to_owned(),
                integer("last_sequence", self.last_sequence)?,
            ),
            ("lifecycle".to_owned(), JsonValue::Array(lifecycle)),
            ("summary".to_owned(), self.summary.to_body()?),
            (
                "trace_id".to_owned(),
                self.provenance.as_ref().map_or(JsonValue::Null, |value| {
                    JsonValue::String(value.trace_id().as_str().to_owned())
                }),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, RunsApiError> {
        exact_fields(
            body,
            &[
                "causation_id",
                "correlation_id",
                "coverage",
                "last_sequence",
                "lifecycle",
                "summary",
                "trace_id",
            ],
        )?;
        let JsonValue::Array(items) = body.get("lifecycle").ok_or(RunsApiError::InvalidBody)?
        else {
            return Err(RunsApiError::InvalidBody);
        };
        if items.len() > MAX_LIFECYCLE_EVENTS {
            return Err(RunsApiError::LifecycleTooLong {
                max_events: MAX_LIFECYCLE_EVENTS,
                actual_events: items.len(),
            });
        }
        let mut lifecycle = Vec::with_capacity(items.len());
        for item in items {
            lifecycle.push(RunLifecycleEvent::from_body(item)?);
        }
        let view = Self::new(
            RunSummary::from_body(body.get("summary").ok_or(RunsApiError::InvalidBody)?)?,
            unsigned(body, "last_sequence")?,
            lifecycle,
            decode_security_enum::<LifecycleCoverage>(&required_string(body, "coverage")?)?,
        )?;
        match (
            optional_provenance_string(body, "trace_id")?,
            optional_provenance_string(body, "correlation_id")?,
            optional_provenance_string(body, "causation_id")?,
        ) {
            (None, None, None) => Ok(view),
            (Some(trace_id), Some(correlation_id), Some(causation_id)) => {
                Ok(view.with_provenance(Provenance::new(
                    TraceId::new(trace_id).map_err(|_| RunsApiError::InvalidBody)?,
                    CorrelationId::new(correlation_id).map_err(|_| RunsApiError::InvalidBody)?,
                    CausationId::new(causation_id).map_err(|_| RunsApiError::InvalidBody)?,
                )))
            }
            _ => Err(RunsApiError::InvalidBody),
        }
    }
}

/// Whether a page is the end of the listing.
///
/// Closed, and carried explicitly rather than inferred from `runs.len() <
/// page_size`. A short page is not the same statement as a last page: a state
/// filter can exclude every row in a scanned window and still leave rows behind
/// it, and a client that inferred "done" from a short page would stop early.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Continuation {
    /// More rows may follow; resume from this cursor.
    More(RunCursor),
    /// The listing reached the end of the retained log.
    Complete,
}

impl Continuation {
    /// The cursor to resume from, when there is one.
    #[must_use]
    pub const fn cursor(self) -> Option<RunCursor> {
        match self {
            Self::More(cursor) => Some(cursor),
            Self::Complete => None,
        }
    }

    /// Whether more rows may follow.
    #[must_use]
    pub const fn has_more(self) -> bool {
        matches!(self, Self::More(_))
    }
}

/// One bounded page of run summaries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunListPage {
    runs: Vec<RunSummary>,
    continuation: Continuation,
}

impl RunListPage {
    /// Assemble a page.
    ///
    /// # Errors
    ///
    /// Returns [`RunsApiError::PageTooLarge`] above [`MAX_RUN_PAGE_ITEMS`],
    /// [`RunsApiError::PageOutOfOrder`] when summaries do not strictly increase
    /// by submission identity — a listing is ordered by that identity, and a
    /// repeat or a step backwards means the next page would re-serve or skip —
    /// and [`RunsApiError::ContinuationRewinds`] when a continuation cursor does
    /// not point past the last row on the page.
    ///
    /// An empty page carrying [`Continuation::More`] is accepted: a state filter
    /// may exclude every row in one scanned window while rows remain behind it.
    pub fn new(runs: Vec<RunSummary>, continuation: Continuation) -> Result<Self, RunsApiError> {
        if runs.len() > MAX_RUN_PAGE_ITEMS {
            return Err(RunsApiError::PageTooLarge {
                max_items: MAX_RUN_PAGE_ITEMS,
                actual_items: runs.len(),
            });
        }
        if runs
            .windows(2)
            .any(|pair| pair[1].submission_id() <= pair[0].submission_id())
        {
            return Err(RunsApiError::PageOutOfOrder);
        }
        if let (Some(cursor), Some(last)) = (continuation.cursor(), runs.last())
            && cursor.position() <= last.submission_id()
        {
            return Err(RunsApiError::ContinuationRewinds);
        }
        Ok(Self { runs, continuation })
    }

    /// The summaries, in submission order.
    #[must_use]
    pub fn runs(&self) -> &[RunSummary] {
        &self.runs
    }

    /// Whether more rows may follow, and where.
    #[must_use]
    pub const fn continuation(&self) -> Continuation {
        self.continuation
    }

    fn to_body(&self) -> Result<JsonValue, RunsApiError> {
        let mut runs = Vec::with_capacity(self.runs.len());
        for summary in &self.runs {
            runs.push(summary.to_body()?);
        }
        Ok(JsonValue::Object(vec![
            (
                "more".to_owned(),
                JsonValue::Bool(self.continuation.has_more()),
            ),
            (
                "next_cursor".to_owned(),
                match self.continuation.cursor() {
                    Some(cursor) => integer("next_cursor", cursor.position())?,
                    None => JsonValue::Null,
                },
            ),
            ("runs".to_owned(), JsonValue::Array(runs)),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, RunsApiError> {
        exact_fields(body, &["more", "next_cursor", "runs"])?;
        let more = match body.get("more") {
            Some(JsonValue::Bool(value)) => *value,
            _ => return Err(RunsApiError::InvalidBody),
        };
        let continuation = match (more, body.get("next_cursor")) {
            (true, Some(JsonValue::Integer(_))) => {
                Continuation::More(RunCursor::new(unsigned(body, "next_cursor")?))
            }
            (false, Some(JsonValue::Null)) => Continuation::Complete,
            (true, Some(JsonValue::Null)) | (false, Some(JsonValue::Integer(_))) => {
                return Err(RunsApiError::ContinuationIncoherent);
            }
            _ => return Err(RunsApiError::InvalidBody),
        };
        let JsonValue::Array(items) = body.get("runs").ok_or(RunsApiError::InvalidBody)? else {
            return Err(RunsApiError::InvalidBody);
        };
        if items.len() > MAX_RUN_PAGE_ITEMS {
            return Err(RunsApiError::PageTooLarge {
                max_items: MAX_RUN_PAGE_ITEMS,
                actual_items: items.len(),
            });
        }
        let mut runs = Vec::with_capacity(items.len());
        for item in items {
            runs.push(RunSummary::from_body(item)?);
        }
        Self::new(runs, continuation)
    }
}

/// Why a Runs query was refused.
///
/// Closed, and deliberately small. A refusal this slice cannot decide is a
/// refusal it must not name: there is no `not_authorized`, because no actor is
/// modelled, and no `retention_unavailable`, because retention is answered by
/// [`ActionOutcome::ResyncRequired`] rather than by a refusal.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RunsRefusal {
    /// No run with that identity is known to this daemon.
    UnknownRun,
}

impl RunsRefusal {
    /// Every refusal, in canonical order.
    pub const ALL: [Self; 1] = [Self::UnknownRun];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownRun => "unknown_run",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|refusal| refusal.as_str() == value)
    }
}

impl fmt::Display for RunsRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for RunsRefusal {
    const FIELD: &'static str = "refusal";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// A correlated read request on the Runs API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunsRequest {
    /// One bounded page of runs.
    ListRuns {
        /// Correlation identifier.
        request_id: RequestId,
        /// Filters, cursor and page size.
        query: ListRuns,
    },
    /// One run in full.
    RunDetail {
        /// Correlation identifier.
        request_id: RequestId,
        /// Run to read.
        run_id: RunId,
    },
}

impl RunsRequest {
    /// Correlation identifier.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        match self {
            Self::ListRuns { request_id, .. } | Self::RunDetail { request_id, .. } => request_id,
        }
    }

    /// Encode the request as a canonical message.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal if a counter or a compile-time envelope literal
    /// is outside the protocol bounds.
    pub fn to_message(&self) -> Result<Message, RunsApiError> {
        match self {
            Self::ListRuns { request_id, query } => Ok(Message::new(
                envelope(request_id.clone(), "list_runs")?,
                query.to_body()?,
            )),
            Self::RunDetail { request_id, run_id } => Ok(Message::new(
                envelope(request_id.clone(), "run_detail")?,
                JsonValue::Object(vec![(
                    "run_id".to_owned(),
                    JsonValue::String(run_id.as_str().to_owned()),
                )]),
            )),
        }
    }

    /// Decode and admit a request against the exact first protocol version.
    ///
    /// # Errors
    ///
    /// Refuses unknown kinds and bodies that are not exact.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, RunsApiError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let request_id = message.envelope().request_id().clone();
        match message.envelope().kind().as_str() {
            "list_runs" => Ok(Self::ListRuns {
                request_id,
                query: ListRuns::from_body(message.body())?,
            }),
            "run_detail" => {
                exact_fields(message.body(), &["run_id"])?;
                Ok(Self::RunDetail {
                    request_id,
                    run_id: RunId::new(required_string(message.body(), "run_id")?).map_err(
                        |error| RunsApiError::Field {
                            field: "run_id",
                            error,
                        },
                    )?,
                })
            }
            _ => Err(RunsApiError::UnknownKind),
        }
    }
}

/// A correlated answer on the Runs API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunsResponse {
    /// One page of runs.
    RunList {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// The page.
        page: RunListPage,
    },
    /// One run in full.
    RunDetail {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// The view.
        view: RunDetailView,
    },
    /// The caller's cursor is outside retention.
    ///
    /// Carries the window a bounded snapshot must cover. It never carries rows:
    /// [`RunsResponse::listing`] refuses to build this variant with a page.
    Resync {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// Lowest position still retained.
        snapshot_from: u64,
        /// Highest position still retained.
        snapshot_to: u64,
    },
    /// The query was refused. Nothing was read.
    Refused {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// Why.
        refusal: RunsRefusal,
    },
}

impl RunsResponse {
    /// Correlation identifier from the request.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        match self {
            Self::RunList { request_id, .. }
            | Self::RunDetail { request_id, .. }
            | Self::Resync { request_id, .. }
            | Self::Refused { request_id, .. } => request_id,
        }
    }

    /// Which of the six terminal outcomes this answer reports.
    ///
    /// A delivered read is `completed`, not `accepted`: there is no later
    /// completion to wait for. See [`OUTCOMES_A_READ_NEVER_PRODUCES`] for the
    /// three this protocol cannot produce and why.
    #[must_use]
    pub const fn outcome(&self) -> ActionOutcome {
        match self {
            Self::RunList { .. } | Self::RunDetail { .. } => ActionOutcome::Completed,
            Self::Resync { .. } => ActionOutcome::ResyncRequired,
            Self::Refused { .. } => ActionOutcome::Rejected,
        }
    }

    /// Build the answer to a listing from the retention decision and the rows a
    /// store produced.
    ///
    /// This is the enforcement the module exists for. The decision comes from
    /// [`ListRuns::resume_within`], and it cannot be talked out of:
    ///
    /// - a [`CursorResume::ResyncRequired`] decision handed rows is
    ///   [`RunsApiError::ResyncCarriesRows`], not a page trimmed to fit. The
    ///   rows are refused rather than served, so "a cursor outside retention
    ///   receives `resync_required`, never a silent partial stream" holds by
    ///   construction rather than by convention;
    /// - a [`CursorResume::Live`] decision handed nothing is
    ///   [`RunsApiError::PageMissing`], so an empty success cannot stand in for
    ///   an answer that was never computed;
    /// - a page longer than the query asked for, beginning before the decision's
    ///   position, or carrying a run the filter excludes, is refused.
    ///
    /// # Errors
    ///
    /// Returns [`RunsApiError::ResyncCarriesRows`],
    /// [`RunsApiError::PageMissing`],
    /// [`RunsApiError::PageAboveRequestedSize`],
    /// [`RunsApiError::PageBeforeCursor`] or
    /// [`RunsApiError::PageOutsideFilter`].
    pub fn listing(
        request_id: RequestId,
        query: &ListRuns,
        decision: CursorResume,
        page: Option<RunListPage>,
    ) -> Result<Self, RunsApiError> {
        match (decision, page) {
            (
                CursorResume::ResyncRequired {
                    snapshot_from,
                    snapshot_to,
                },
                None,
            ) => Ok(Self::Resync {
                request_id,
                snapshot_from,
                snapshot_to,
            }),
            (CursorResume::ResyncRequired { .. }, Some(_)) => Err(RunsApiError::ResyncCarriesRows),
            (CursorResume::Live { .. }, None) => Err(RunsApiError::PageMissing),
            (CursorResume::Live { from }, Some(page)) => {
                if page.runs().len() > query.page_size().get() {
                    return Err(RunsApiError::PageAboveRequestedSize {
                        requested: query.page_size().get(),
                        actual_items: page.runs().len(),
                    });
                }
                if page
                    .runs()
                    .iter()
                    .any(|summary| summary.submission_id() < from)
                {
                    return Err(RunsApiError::PageBeforeCursor);
                }
                if page
                    .runs()
                    .iter()
                    .any(|summary| !query.states().admits(summary.state()))
                {
                    return Err(RunsApiError::PageOutsideFilter);
                }
                Ok(Self::RunList { request_id, page })
            }
        }
    }

    /// Encode the response as a canonical message.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal if a counter or a compile-time envelope literal
    /// is outside the protocol bounds.
    pub fn to_message(&self) -> Result<Message, RunsApiError> {
        match self {
            Self::RunList { request_id, page } => Ok(Message::new(
                envelope(request_id.clone(), "run_list_result")?,
                page.to_body()?,
            )),
            Self::RunDetail { request_id, view } => Ok(Message::new(
                envelope(request_id.clone(), "run_detail_result")?,
                view.to_body()?,
            )),
            Self::Resync {
                request_id,
                snapshot_from,
                snapshot_to,
            } => Ok(Message::new(
                envelope(request_id.clone(), "resync_required")?,
                JsonValue::Object(vec![
                    (
                        "snapshot_from".to_owned(),
                        integer("snapshot_from", *snapshot_from)?,
                    ),
                    (
                        "snapshot_to".to_owned(),
                        integer("snapshot_to", *snapshot_to)?,
                    ),
                ]),
            )),
            Self::Refused {
                request_id,
                refusal,
            } => Ok(Message::new(
                envelope(request_id.clone(), "refused")?,
                JsonValue::Object(vec![(
                    "refusal".to_owned(),
                    JsonValue::String(refusal.as_str().to_owned()),
                )]),
            )),
        }
    }

    /// Decode and admit a response against the exact first protocol version.
    ///
    /// # Errors
    ///
    /// Refuses unknown kinds and bodies that are not exact.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, RunsApiError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let request_id = message.envelope().request_id().clone();
        match message.envelope().kind().as_str() {
            "run_list_result" => Ok(Self::RunList {
                request_id,
                page: RunListPage::from_body(message.body())?,
            }),
            "run_detail_result" => Ok(Self::RunDetail {
                request_id,
                view: RunDetailView::from_body(message.body())?,
            }),
            "resync_required" => {
                exact_fields(message.body(), &["snapshot_from", "snapshot_to"])?;
                let snapshot_from = unsigned(message.body(), "snapshot_from")?;
                let snapshot_to = unsigned(message.body(), "snapshot_to")?;
                if snapshot_to < snapshot_from {
                    return Err(RunsApiError::InvalidBody);
                }
                Ok(Self::Resync {
                    request_id,
                    snapshot_from,
                    snapshot_to,
                })
            }
            "refused" => {
                exact_fields(message.body(), &["refusal"])?;
                Ok(Self::Refused {
                    request_id,
                    refusal: decode_security_enum::<RunsRefusal>(&required_string(
                        message.body(),
                        "refusal",
                    )?)?,
                })
            }
            _ => Err(RunsApiError::UnknownKind),
        }
    }
}

fn envelope(request_id: RequestId, kind: &str) -> Result<Envelope, RunsApiError> {
    Ok(Envelope::new(
        ProtocolName::new(RUNS_PROTOCOL)?,
        MajorVersion::FIRST,
        request_id,
        MessageKind::new(kind)?,
    ))
}

fn supported_protocol() -> Result<SupportedProtocol, RunsApiError> {
    Ok(SupportedProtocol::new(
        ProtocolName::new(RUNS_PROTOCOL)?,
        VersionRange::new(MajorVersion::FIRST, MajorVersion::FIRST)?,
    ))
}

fn integer(field: &'static str, value: u64) -> Result<JsonValue, RunsApiError> {
    i64::try_from(value)
        .map(JsonValue::Integer)
        .map_err(|_| RunsApiError::CounterOutOfRange { field })
}

fn unsigned(body: &JsonValue, field: &'static str) -> Result<u64, RunsApiError> {
    let value = body
        .get(field)
        .and_then(JsonValue::as_integer)
        .ok_or(RunsApiError::InvalidBody)?;
    u64::try_from(value).map_err(|_| RunsApiError::InvalidBody)
}

fn required_string(body: &JsonValue, field: &'static str) -> Result<String, RunsApiError> {
    body.get(field)
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
        .ok_or(RunsApiError::InvalidBody)
}

fn optional_provenance_string(
    body: &JsonValue,
    field: &'static str,
) -> Result<Option<String>, RunsApiError> {
    match body.get(field) {
        Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::String(value)) => Ok(Some(value.clone())),
        _ => Err(RunsApiError::InvalidBody),
    }
}

fn exact_fields(body: &JsonValue, fields: &[&str]) -> Result<(), RunsApiError> {
    let JsonValue::Object(entries) = body else {
        return Err(RunsApiError::InvalidBody);
    };
    if entries.len() != fields.len()
        || !fields
            .iter()
            .all(|field| entries.iter().any(|(name, _)| name == field))
    {
        return Err(RunsApiError::InvalidBody);
    }
    Ok(())
}
