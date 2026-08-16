// SPDX-License-Identifier: Elastic-2.0

//! The Automonique-native Automation control API: register an automation, move
//! it along the enablement lattice, and read back what an operator decided.
//!
//! `docs/product-plan/requirements/state-and-protocols.md` § Operator client
//! protocol is the rule every response here obeys — "Responses distinguish
//! `accepted`, `completed`, `rejected`, `conflict`, `unknown` and
//! `resync_required` so a UI cannot mistake transport failure for operation
//! failure" — reused from [`crate::journal::ActionOutcome`] rather than
//! restated, with [`AutomationResponse::outcome`] saying which four of the six
//! this protocol produces and [`OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES`] saying
//! which two it cannot.
//!
//! # What this surface does, stated before what it looks like
//!
//! **It records an operator's decision about whether an automation is in
//! service, durably, and serves those decisions back.** That is the whole of
//! it, and the honesty of the whole slice depends on saying so:
//!
//! - **Nothing here schedules.** No [`crate::automation::CanonicalSchedule`]
//!   is carried, evaluated or stored; no next occurrence is computed; no timer
//!   exists anywhere in this build.
//! - **Nothing here fires an action.** The executor that would consume a
//!   trigger and an action does not exist in this release, so **a `paused`
//!   automation suppresses nothing today.** It is written now so that the
//!   scheduler, when it lands, reads enablement out of a durable record rather
//!   than inventing one.
//! - **Nothing here authenticates.** [`RegisterAutomation::actor`] and
//!   [`SetEnablement::actor`] name who asked and are recorded verbatim. The
//!   daemon's `SO_PEERCRED` check is the authentication; this string is not a
//!   capability, exactly as [`crate::automation::AutomationActor`] says of
//!   itself and as [`crate::admin::IntakePause`] says of the intake switch.
//!
//! # The vocabulary is borrowed, not re-spelled
//!
//! [`crate::automation::EnablementState`], [`crate::automation::AutomationActor`]
//! and [`crate::automation::PauseCause`] already define this product's
//! enablement words, so this module *uses* them rather than writing a second
//! set down. Only two bounded types are new — [`AutomationId`] and
//! [`PauseReason`] — because the rich model spells a withdrawal as one
//! `PauseCause` value carrying both halves, while `automonique_store`'s
//! `automations` table stores the actor and the reason in separate columns and
//! writes an actor on *every* transition including a resume. The wire follows
//! the table, and [`AutomationRecordView::enablement`] reassembles the rich
//! value so a reader can have either shape without this module choosing for
//! them.
//!
//! [`AutomationId`] deliberately does **not** reuse
//! [`crate::automation::DurableId`], whose grammar additionally forbids
//! whitespace. The durable registry accepts any non-empty, bounded,
//! control-free identifier, and a wire type stricter than the table would make
//! a stored row unreadable through the only surface that serves it.
//!
//! # Where the cause coupling is enforced, and why twice
//!
//! `paused` and `archived` require a stated cause; `enabled` refuses one. That
//! is a property of the *request alone*, so [`SetEnablement::new`] decides it
//! before a socket is opened and [`AutomationApiError::CauseRequired`] /
//! [`AutomationApiError::CauseForbidden`] are constructor refusals rather than
//! daemon answers. The durable store checks it again, in a database `CHECK` as
//! well as in its own API, because a second writer is not obliged to come
//! through here.
//!
//! Two checks that cannot disagree are worth more than one: this one refuses a
//! malformed request without spending a frame, and that one refuses a malformed
//! row without trusting us.
//!
//! # Divergences from the plan's automation surface
//!
//! Named rather than silently approximated:
//!
//! - **Only enablement is controlled.** `plan` gives an automation a schedule,
//!   a trigger, an action, an overlap policy and a pre-approved effect scope.
//!   None is representable in [`RegisterAutomation`], because none is durable:
//!   the registry stores identity, revision, enablement and attribution and
//!   nothing else. A field here that the store drops would be a promise the
//!   next read breaks.
//! - **There is no history.** The registry holds one row per automation,
//!   overwritten in place, so a resume erases the cause of the pause it
//!   resumed. [`AutomationRecordView`] answers "who withdrew this, and why" for
//!   the withdrawal in force *now*, and nothing about earlier ones. An audit of
//!   every transition is a second, append-only table and is not this one.
//! - **`resync_required` is unreachable.** Nothing deletes from the registry,
//!   so no cursor can fall out of retention; a cursor above everything recorded
//!   is [`AutomationRefusal::CursorOutOfRange`] — "your cursor names a row that
//!   was never written" — which is a different statement from "the rows you
//!   wanted are gone", and this protocol only ever makes the true one.
//! - **HTTP is absent.** These are protocol values framed by [`crate::codec`]
//!   on the same canonical-JSON envelope [`crate::admin`] uses, under a
//!   separate protocol name so the admin lane's closed kind set stays closed.

use core::fmt;
use std::error::Error;

use crate::automation::{
    AutomationActor, AutomationEnablement, AutomationError, EnablementState, PauseCause,
};
use crate::codec::{
    CodecError, Envelope, MajorVersion, MessageKind, ProtocolName, RequestId,
    SecuritySensitiveEnum, SupportedProtocol, VersionRange, decode_security_enum,
};
use crate::journal::ActionOutcome;
use crate::primitives::{EpochMillis, ValueError};
use crate::wire::{JsonValue, Message};

/// Stable protocol name for the native Automation control API.
pub const AUTOMATION_PROTOCOL: &str = "automonique.automation";

/// Stable schema identifier for the version-one control surface.
pub const AUTOMATION_API_SCHEMA_V1: &str = "automonique.automation/v1";

/// Maximum canonical message bytes this protocol will assemble or admit.
pub const MAX_AUTOMATION_CANONICAL_BYTES: usize = 64 * 1024;

/// Maximum UTF-8 byte length of an automation identity, actor or cause.
///
/// The same bound [`crate::automation::MAX_AUTOMATION_FIELD_BYTES`] applies to
/// these exact three fields, and the same bound
/// `automonique_store::automation_store::MAX_IDENTIFIER_BYTES` stores them
/// under. A value this protocol admits is a value that store holds.
pub const MAX_AUTOMATION_API_FIELD_BYTES: usize = crate::automation::MAX_AUTOMATION_FIELD_BYTES;

/// Maximum automations one listing page may carry.
///
/// Thirty-two rather than the sixty-four [`crate::runs_api`] serves, because an
/// automation row carries *three* maximal identifiers where a run summary
/// carries one. The number is derived from the frame arithmetic below and not
/// chosen: see [`RECORD_OVERHEAD_BYTES`].
///
/// A page bound is not a paging hint. [`AutomationListPage::new`] refuses a
/// longer vector rather than truncating it, because a truncated page that still
/// answers `complete` is a silent drop.
pub const MAX_AUTOMATION_PAGE_ITEMS: usize = 32;

/// The two outcomes this protocol can never report.
///
/// `unknown` names a transport failure, and a transport failure is the
/// *absence* of a message, so no message can carry it. `resync_required` names
/// a cursor outside retention, and nothing is ever removed from the automation
/// registry — an unrecorded cursor is [`AutomationRefusal::CursorOutOfRange`]
/// instead, which says something true. A reader that receives one of these on
/// this protocol is reading a response this build did not write.
pub const OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES: [ActionOutcome; 2] =
    [ActionOutcome::Unknown, ActionOutcome::ResyncRequired];

/// Worst-case canonical bytes of one record, excluding its three identifiers.
///
/// The eight quoted key names and their punctuation (108), four twenty-digit
/// integers (80), the longest quoted enablement spelling (10), and the quote
/// pairs around the three string members (6), rounded up.
const RECORD_OVERHEAD_BYTES: usize = 224;

/// Worst-case canonical bytes of a page scaffold, excluding its items.
const BODY_SCAFFOLD_BYTES: usize = 256;

/// Worst-case canonical bytes of the envelope wrapped around one body.
///
/// The `kind`, `protocol` and `version` members plus a maximal 128-byte
/// `request_id`, budgeted at its JSON-escaped worst case.
const ENVELOPE_OVERHEAD_BYTES: usize = 480;

/// A bounded field costs at most two canonical bytes per source byte, because a
/// quote or a backslash escapes to two.
const FIELD_ENCODED_BYTES: usize = 2 * MAX_AUTOMATION_API_FIELD_BYTES;

/// One record carries three of them: the identity, the actor, and the cause.
const RECORD_FIELDS: usize = 3;

const _: () = assert!(
    MAX_AUTOMATION_PAGE_ITEMS * (RECORD_FIELDS * FIELD_ENCODED_BYTES + RECORD_OVERHEAD_BYTES)
        + BODY_SCAFFOLD_BYTES
        + ENVELOPE_OVERHEAD_BYTES
        <= MAX_AUTOMATION_CANONICAL_BYTES,
    "a maximal automation listing page must fit one automation frame"
);

const _: () = assert!(
    RECORD_FIELDS * FIELD_ENCODED_BYTES
        + RECORD_OVERHEAD_BYTES
        + BODY_SCAFFOLD_BYTES
        + ENVELOPE_OVERHEAD_BYTES
        <= MAX_AUTOMATION_CANONICAL_BYTES,
    "a maximal automation detail view must fit one automation frame"
);

/// Position of a state in [`ENABLEMENT_STATES`].
///
/// The match is exhaustive, so a variant added to
/// [`crate::automation::EnablementState`] fails to compile here rather than
/// dropping out of the array unnoticed and becoming a spelling this lane
/// silently refuses.
const fn state_slot(state: EnablementState) -> usize {
    match state {
        EnablementState::Enabled => 0,
        EnablementState::Paused => 1,
        EnablementState::Archived => 2,
    }
}

/// Every enablement state, in the automation model's declaration order.
///
/// A reuse rather than a carried spelling: [`decode_enablement`] finds a value
/// by comparing `EnablementState::as_str`, so this module cannot disagree with
/// [`crate::automation`] about a word.
pub const ENABLEMENT_STATES: [EnablementState; 3] = EnablementState::ALL;

const _: () = assert!(
    state_slot(ENABLEMENT_STATES[0]) == 0
        && state_slot(ENABLEMENT_STATES[1]) == 1
        && state_slot(ENABLEMENT_STATES[2]) == 2,
    "the enablement array and the exhaustive match must agree"
);

/// Whether a row in this state must carry a stated cause.
///
/// True for exactly the two withdrawn states, because those are the two
/// [`crate::automation::AutomationEnablement`] gives a
/// [`crate::automation::PauseCause`] and the one it does not. Written as an
/// exhaustive match so a fourth state could not default into "no cause
/// required", which is the direction that loses evidence.
#[must_use]
pub const fn requires_cause(state: EnablementState) -> bool {
    match state {
        EnablementState::Enabled => false,
        EnablementState::Paused | EnablementState::Archived => true,
    }
}

/// Whether an automation in `from` may next be moved to `to`.
///
/// The whole lattice, in one place, and the same one
/// `AutomationRevision::permits` admits: `enabled <-> paused` both ways, either
/// of them to `archived`, and nothing at all out of `archived`. No state
/// transitions to itself.
///
/// This is a *client-side* courtesy, not the enforcement: the durable store
/// decides, and [`AutomationRefusal::IllegalTransition`] is what a caller that
/// ignored this receives.
#[must_use]
pub const fn permits_transition(from: EnablementState, to: EnablementState) -> bool {
    matches!(
        (from, to),
        (EnablementState::Enabled, EnablementState::Paused)
            | (EnablementState::Paused, EnablementState::Enabled)
            | (
                EnablementState::Enabled | EnablementState::Paused,
                EnablementState::Archived
            )
    )
}

/// Decode an enablement spelling, failing closed on an unknown one.
///
/// # Errors
///
/// Returns [`CodecError::UnknownEnumValue`] for a spelling this build does not
/// define.
pub fn decode_enablement(value: &str) -> Result<EnablementState, AutomationApiError> {
    ENABLEMENT_STATES
        .into_iter()
        .find(|candidate| candidate.as_str() == value)
        .ok_or(AutomationApiError::Codec(CodecError::UnknownEnumValue {
            field: "enablement",
        }))
}

/// A refusal while constructing, encoding or decoding an Automation API value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AutomationApiError {
    /// The shared envelope or canonical JSON codec refused the message.
    ///
    /// Includes [`CodecError::UnknownEnumValue`] for an enablement or refusal
    /// word this build does not define. Those fail closed rather than decoding
    /// to a default.
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
    /// A requested page size was zero or above [`MAX_AUTOMATION_PAGE_ITEMS`].
    PageSizeOutOfRange {
        /// Largest page this protocol serves.
        max_items: usize,
        /// Size the caller asked for.
        requested: usize,
    },
    /// A page carried more records than [`MAX_AUTOMATION_PAGE_ITEMS`].
    PageTooLarge {
        /// Largest page this protocol serves.
        max_items: usize,
        /// Records the caller supplied.
        actual_items: usize,
    },
    /// A page carried more records than the query it answers asked for.
    PageAboveRequestedSize {
        /// Size the query asked for.
        requested: usize,
        /// Records the page carried.
        actual_items: usize,
    },
    /// A withdrawal was requested with no stated cause.
    CauseRequired {
        /// State that requires a cause.
        state: EnablementState,
    },
    /// A cause was supplied for a state that does not carry one.
    CauseForbidden {
        /// State that admits no cause.
        state: EnablementState,
    },
    /// A durable row identity was zero, which is a row that was never written.
    UnwrittenRow {
        /// Field that claimed the unwritten identity.
        field: &'static str,
    },
    /// A revision was zero, which is a row no writer produced.
    ///
    /// Registration writes revision one, and every accepted transition writes
    /// one higher, so zero names nothing.
    UnwrittenRevision,
    /// A withdrawn row claimed revision one.
    ///
    /// Registration is the only writer of revision one and it always writes
    /// `enabled`, so a `paused` or `archived` row below revision two is a row
    /// no writer produced.
    WithdrawnAtFirstRevision,
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
        state: EnablementState,
    },
    /// A page claimed rows follow without a cursor, or a cursor without rows
    /// following.
    ContinuationIncoherent,
    /// A continuation cursor did not reach the last row on the page.
    ContinuationRewinds,
    /// Page records did not strictly increase by durable row identity.
    PageOutOfOrder,
    /// A page carried a record the query's state filter excludes.
    PageOutsideFilter,
    /// A conflict named a durable revision equal to the expected one, which is
    /// agreement rather than a conflict.
    ConflictWithoutDisagreement,
}

impl AutomationApiError {
    /// Stable category suitable for logs and refusal metrics.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Codec(error) => error.category(),
            Self::UnknownKind => "automation_unknown_kind",
            Self::InvalidBody => "automation_invalid_body",
            Self::CounterOutOfRange { .. } => "automation_counter_out_of_range",
            Self::Field { .. } => "automation_invalid_field",
            Self::PageSizeOutOfRange { .. } => "automation_page_size_out_of_range",
            Self::PageTooLarge { .. } => "automation_page_too_large",
            Self::PageAboveRequestedSize { .. } => "automation_page_above_requested_size",
            Self::CauseRequired { .. } => "automation_cause_required",
            Self::CauseForbidden { .. } => "automation_cause_forbidden",
            Self::UnwrittenRow { .. } => "automation_unwritten_row",
            Self::UnwrittenRevision => "automation_unwritten_revision",
            Self::WithdrawnAtFirstRevision => "automation_withdrawn_at_first_revision",
            Self::TimeBeforeEpoch { .. } => "automation_time_before_epoch",
            Self::StateFilterEmpty => "automation_state_filter_empty",
            Self::StateFilterRepeats { .. } => "automation_state_filter_repeats",
            Self::ContinuationIncoherent => "automation_continuation_incoherent",
            Self::ContinuationRewinds => "automation_continuation_rewinds",
            Self::PageOutOfOrder => "automation_page_out_of_order",
            Self::PageOutsideFilter => "automation_page_outside_filter",
            Self::ConflictWithoutDisagreement => "automation_conflict_without_disagreement",
        }
    }
}

impl fmt::Display for AutomationApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "automation codec refused message: {error}"),
            Self::UnknownKind => formatter.write_str("automation message kind is not defined"),
            Self::InvalidBody => formatter.write_str("automation message body is invalid"),
            Self::CounterOutOfRange { field } => write!(
                formatter,
                "automation counter {field} is outside the wire range"
            ),
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
                "page carries {actual_items} automations; maximum is {max_items}"
            ),
            Self::PageAboveRequestedSize {
                requested,
                actual_items,
            } => write!(
                formatter,
                "page carries {actual_items} automations; the query asked for {requested}"
            ),
            Self::CauseRequired { state } => {
                write!(
                    formatter,
                    "enablement {} requires a stated cause",
                    state.as_str()
                )
            }
            Self::CauseForbidden { state } => {
                write!(formatter, "enablement {} admits no cause", state.as_str())
            }
            Self::UnwrittenRow { field } => {
                write!(formatter, "{field} is zero, which names an unwritten row")
            }
            Self::UnwrittenRevision => {
                formatter.write_str("revision zero names a row no writer produced")
            }
            Self::WithdrawnAtFirstRevision => {
                formatter.write_str("a withdrawn automation cannot be at revision one")
            }
            Self::TimeBeforeEpoch { field } => write!(formatter, "{field} is before the epoch"),
            Self::StateFilterEmpty => formatter.write_str("an enablement filter admits no state"),
            Self::StateFilterRepeats { state } => {
                write!(
                    formatter,
                    "enablement filter names {} twice",
                    state.as_str()
                )
            }
            Self::ContinuationIncoherent => {
                formatter.write_str("a page's continuation marker and cursor disagree")
            }
            Self::ContinuationRewinds => {
                formatter.write_str("a continuation cursor does not reach the end of its page")
            }
            Self::PageOutOfOrder => {
                formatter.write_str("page records do not strictly increase by entry")
            }
            Self::PageOutsideFilter => {
                formatter.write_str("a page carries an automation the query's filter excludes")
            }
            Self::ConflictWithoutDisagreement => {
                formatter.write_str("a revision conflict named the revision the caller expected")
            }
        }
    }
}

impl Error for AutomationApiError {}

impl From<CodecError> for AutomationApiError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

/// Translate an [`crate::automation`] field refusal into this lane's.
///
/// Only the field arm can arise from the constructors this module calls, and
/// every other arm is folded onto [`AutomationApiError::InvalidBody`] rather
/// than being invented into a field name that was not refused.
fn from_automation_error(error: &AutomationError, field: &'static str) -> AutomationApiError {
    match error {
        AutomationError::Field { error, .. } => AutomationApiError::Field {
            field,
            error: *error,
        },
        _ => AutomationApiError::InvalidBody,
    }
}

/// The durable identity of one automation.
///
/// Non-empty, at most [`MAX_AUTOMATION_API_FIELD_BYTES`], and control-free:
/// exactly the grammar `automonique_store::automation_store` stores under, so
/// this type admits every identity that registry can hold and no more. See the
/// module note on why [`crate::automation::DurableId`] is deliberately not
/// reused.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AutomationId(String);

impl AutomationId {
    /// Longest identity this protocol carries.
    pub const MAX_BYTES: usize = MAX_AUTOMATION_API_FIELD_BYTES;

    /// Validate and construct an identity.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::Field`] for an empty, over-long or
    /// control-bearing value.
    pub fn new(value: impl AsRef<str>) -> Result<Self, AutomationApiError> {
        let value = value.as_ref();
        bounded(value, "automation_id")?;
        Ok(Self(value.to_owned()))
    }

    /// The validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AutomationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Why an automation was withdrawn from service.
///
/// The reason half of [`crate::automation::PauseCause`], carried separately
/// because the durable registry stores the actor and the reason in separate
/// columns and writes an actor on every transition — including a resume, which
/// has no cause at all.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PauseReason(String);

impl PauseReason {
    /// Longest reason this protocol carries.
    pub const MAX_BYTES: usize = MAX_AUTOMATION_API_FIELD_BYTES;

    /// Validate and construct a reason.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::Field`] for an empty, over-long or
    /// control-bearing value. Empty is refused rather than read as "no reason
    /// given": a withdrawal an operator cannot safely resume from is the one
    /// this product does not offer a spelling for.
    pub fn new(value: impl AsRef<str>) -> Result<Self, AutomationApiError> {
        let value = value.as_ref();
        bounded(value, "cause")?;
        Ok(Self(value.to_owned()))
    }

    /// The validated reason.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PauseReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A durable listing position: the entry a listing resumes *after*.
///
/// Zero starts at the beginning. This is the store's own exclusive cursor
/// rather than a translated one — the registry pages by `entry_id` and reports
/// the last one it served — so no coordinate is converted between the wire and
/// the table and there is no off-by-one to re-derive.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AutomationCursor(u64);

impl AutomationCursor {
    /// The beginning of the listing.
    pub const START: Self = Self(0);

    /// Name a listing position.
    #[must_use]
    pub const fn new(position: u64) -> Self {
        Self(position)
    }

    /// The entry this cursor resumes after.
    #[must_use]
    pub const fn position(self) -> u64 {
        self.0
    }
}

/// How many records one listing asks for.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AutomationPageSize(usize);

impl AutomationPageSize {
    /// The largest page this protocol serves.
    pub const MAX: Self = Self(MAX_AUTOMATION_PAGE_ITEMS);

    /// Ask for a bounded number of records.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::PageSizeOutOfRange`] for zero — a page
    /// that admits nothing cannot make progress — or for a size above
    /// [`MAX_AUTOMATION_PAGE_ITEMS`].
    pub const fn new(items: usize) -> Result<Self, AutomationApiError> {
        if items == 0 || items > MAX_AUTOMATION_PAGE_ITEMS {
            return Err(AutomationApiError::PageSizeOutOfRange {
                max_items: MAX_AUTOMATION_PAGE_ITEMS,
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

/// Which enablement states a listing admits.
///
/// [`AutomationStateFilter::any`] is the absence of a filter, which differs
/// from a filter naming all three states only in what a later release would
/// mean by it. Neither is an empty list, which
/// [`AutomationStateFilter::only`] refuses.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AutomationStateFilter(Option<Vec<EnablementState>>);

impl AutomationStateFilter {
    /// Admit every state.
    #[must_use]
    pub const fn any() -> Self {
        Self(None)
    }

    /// Admit exactly the named states.
    ///
    /// The set is sorted into [`ENABLEMENT_STATES`] order so a filter built in
    /// any order encodes identically.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::StateFilterEmpty`] for an empty set and
    /// [`AutomationApiError::StateFilterRepeats`] for a repeated state, because
    /// a repeat is a caller that believes it asked for something it did not.
    pub fn only(
        states: impl IntoIterator<Item = EnablementState>,
    ) -> Result<Self, AutomationApiError> {
        let mut ordered: Vec<EnablementState> = states.into_iter().collect();
        if ordered.is_empty() {
            return Err(AutomationApiError::StateFilterEmpty);
        }
        ordered.sort_unstable();
        if let Some(pair) = ordered.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(AutomationApiError::StateFilterRepeats { state: pair[0] });
        }
        Ok(Self(Some(ordered)))
    }

    /// Whether this filter admits a state.
    #[must_use]
    pub fn admits(&self, state: EnablementState) -> bool {
        self.0.as_ref().is_none_or(|states| states.contains(&state))
    }

    /// The named states, when the filter names any.
    #[must_use]
    pub fn states(&self) -> Option<&[EnablementState]> {
        self.0.as_deref()
    }
}

/// One automation presented for registration.
///
/// The initial enablement is not a field: registration always writes `enabled`
/// at revision one with no cause, which is
/// [`crate::automation::AutomationEnablement::newly_declared`]. An operator who
/// wants a paused automation registers it and pauses it, and the pause then
/// carries the cause it owes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterAutomation {
    automation_id: AutomationId,
    actor: AutomationActor,
}

impl RegisterAutomation {
    /// Declare one automation.
    #[must_use]
    pub const fn new(automation_id: AutomationId, actor: AutomationActor) -> Self {
        Self {
            automation_id,
            actor,
        }
    }

    /// Identity to register.
    #[must_use]
    pub const fn automation_id(&self) -> &AutomationId {
        &self.automation_id
    }

    /// Who declared it. Recorded, never verified.
    #[must_use]
    pub const fn actor(&self) -> &AutomationActor {
        &self.actor
    }

    fn to_body(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "actor".to_owned(),
                JsonValue::String(self.actor.as_str().to_owned()),
            ),
            (
                "automation_id".to_owned(),
                JsonValue::String(self.automation_id.as_str().to_owned()),
            ),
        ])
    }

    fn from_body(body: &JsonValue) -> Result<Self, AutomationApiError> {
        exact_fields(body, &["actor", "automation_id"])?;
        Ok(Self::new(
            AutomationId::new(required_string(body, "automation_id")?)?,
            actor(&required_string(body, "actor")?)?,
        ))
    }
}

/// One requested move along the enablement lattice.
///
/// The cause coupling is decided here, before a frame is spent: see the module
/// note on why it is enforced at this layer as well as in the store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetEnablement {
    automation_id: AutomationId,
    expected_revision: u64,
    target: EnablementState,
    actor: AutomationActor,
    cause: Option<PauseReason>,
}

impl SetEnablement {
    /// Ask for one move.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::UnwrittenRevision`] for a zero expected
    /// revision, [`AutomationApiError::CauseRequired`] when a withdrawal states
    /// no cause, and [`AutomationApiError::CauseForbidden`] when a resume
    /// states one.
    pub fn new(
        automation_id: AutomationId,
        expected_revision: u64,
        target: EnablementState,
        actor: AutomationActor,
        cause: Option<PauseReason>,
    ) -> Result<Self, AutomationApiError> {
        if expected_revision == 0 {
            return Err(AutomationApiError::UnwrittenRevision);
        }
        match (requires_cause(target), cause.is_some()) {
            (true, false) => return Err(AutomationApiError::CauseRequired { state: target }),
            (false, true) => return Err(AutomationApiError::CauseForbidden { state: target }),
            (true, true) | (false, false) => {}
        }
        Ok(Self {
            automation_id,
            expected_revision,
            target,
            actor,
            cause,
        })
    }

    /// Automation whose row is being moved.
    #[must_use]
    pub const fn automation_id(&self) -> &AutomationId {
        &self.automation_id
    }

    /// Durable revision the caller believes it is moving.
    #[must_use]
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    /// State to move to.
    #[must_use]
    pub const fn target(&self) -> EnablementState {
        self.target
    }

    /// Who asked. Recorded on every transition, so a resume names whoever
    /// reopened the automation rather than whoever paused it.
    #[must_use]
    pub const fn actor(&self) -> &AutomationActor {
        &self.actor
    }

    /// Why, for a withdrawal. `Some` exactly when the target requires one.
    #[must_use]
    pub const fn cause(&self) -> Option<&PauseReason> {
        self.cause.as_ref()
    }

    fn to_body(&self) -> Result<JsonValue, AutomationApiError> {
        Ok(JsonValue::Object(vec![
            (
                "actor".to_owned(),
                JsonValue::String(self.actor.as_str().to_owned()),
            ),
            (
                "automation_id".to_owned(),
                JsonValue::String(self.automation_id.as_str().to_owned()),
            ),
            (
                "cause".to_owned(),
                match &self.cause {
                    Some(cause) => JsonValue::String(cause.as_str().to_owned()),
                    None => JsonValue::Null,
                },
            ),
            (
                "expected_revision".to_owned(),
                integer("expected_revision", self.expected_revision)?,
            ),
            (
                "target".to_owned(),
                JsonValue::String(self.target.as_str().to_owned()),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AutomationApiError> {
        exact_fields(
            body,
            &[
                "actor",
                "automation_id",
                "cause",
                "expected_revision",
                "target",
            ],
        )?;
        let cause = match body.get("cause") {
            Some(JsonValue::Null) => None,
            Some(JsonValue::String(_)) => Some(PauseReason::new(required_string(body, "cause")?)?),
            _ => return Err(AutomationApiError::InvalidBody),
        };
        Self::new(
            AutomationId::new(required_string(body, "automation_id")?)?,
            unsigned(body, "expected_revision")?,
            decode_enablement(&required_string(body, "target")?)?,
            actor(&required_string(body, "actor")?)?,
            cause,
        )
    }
}

/// A bounded request to list automations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListAutomations {
    states: AutomationStateFilter,
    since: AutomationCursor,
    page_size: AutomationPageSize,
}

impl ListAutomations {
    /// Ask for one page of automations.
    #[must_use]
    pub const fn new(
        states: AutomationStateFilter,
        since: AutomationCursor,
        page_size: AutomationPageSize,
    ) -> Self {
        Self {
            states,
            since,
            page_size,
        }
    }

    /// Which states this listing admits.
    #[must_use]
    pub const fn states(&self) -> &AutomationStateFilter {
        &self.states
    }

    /// The entry this listing resumes after.
    #[must_use]
    pub const fn since(&self) -> AutomationCursor {
        self.since
    }

    /// How many records this listing asks for.
    #[must_use]
    pub const fn page_size(&self) -> AutomationPageSize {
        self.page_size
    }

    fn to_body(&self) -> Result<JsonValue, AutomationApiError> {
        Ok(JsonValue::Object(vec![
            (
                "page_size".to_owned(),
                integer("page_size", self.page_size.get() as u64)?,
            ),
            ("since".to_owned(), integer("since", self.since.position())?),
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

    fn from_body(body: &JsonValue) -> Result<Self, AutomationApiError> {
        exact_fields(body, &["page_size", "since", "states"])?;
        let page_size =
            AutomationPageSize::new(usize::try_from(unsigned(body, "page_size")?).map_err(
                |_| AutomationApiError::PageSizeOutOfRange {
                    max_items: MAX_AUTOMATION_PAGE_ITEMS,
                    requested: MAX_AUTOMATION_PAGE_ITEMS.saturating_add(1),
                },
            )?)?;
        let states = match body.get("states") {
            Some(JsonValue::Null) => AutomationStateFilter::any(),
            Some(JsonValue::Array(items)) => {
                let mut states = Vec::with_capacity(items.len());
                for item in items {
                    let spelling = item.as_str().ok_or(AutomationApiError::InvalidBody)?;
                    states.push(decode_enablement(spelling)?);
                }
                AutomationStateFilter::only(states)?
            }
            _ => return Err(AutomationApiError::InvalidBody),
        };
        Ok(Self::new(
            states,
            AutomationCursor::new(unsigned(body, "since")?),
            page_size,
        ))
    }
}

/// Durable identity and fencing revision of one registered or moved automation.
///
/// This is `automonique_store::automation_store::AutomationReceipt` on the
/// wire, plus the identity it is about — the store's receipt omits it because
/// its caller supplied it, and a correlated answer travelling on its own cannot
/// rely on that.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationReceiptView {
    entry_id: u64,
    automation_id: AutomationId,
    enablement: EnablementState,
    revision: u64,
    updated_at: EpochMillis,
}

impl AutomationReceiptView {
    /// Record what one accepted write established.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::UnwrittenRow`] for a zero `entry_id`,
    /// [`AutomationApiError::UnwrittenRevision`] for a zero revision,
    /// [`AutomationApiError::WithdrawnAtFirstRevision`] for a withdrawn state
    /// at revision one, and [`AutomationApiError::TimeBeforeEpoch`] for an
    /// instant the store's `updated_at_ms >= 0` constraint cannot hold.
    pub fn new(
        entry_id: u64,
        automation_id: AutomationId,
        enablement: EnablementState,
        revision: u64,
        updated_at: EpochMillis,
    ) -> Result<Self, AutomationApiError> {
        if entry_id == 0 {
            return Err(AutomationApiError::UnwrittenRow { field: "entry_id" });
        }
        if revision == 0 {
            return Err(AutomationApiError::UnwrittenRevision);
        }
        if requires_cause(enablement) && revision < 2 {
            return Err(AutomationApiError::WithdrawnAtFirstRevision);
        }
        if updated_at.as_millis() < 0 {
            return Err(AutomationApiError::TimeBeforeEpoch {
                field: "updated_at_ms",
            });
        }
        Ok(Self {
            entry_id,
            automation_id,
            enablement,
            revision,
            updated_at,
        })
    }

    /// Row identity, monotonic in registration order. The pagination key.
    #[must_use]
    pub const fn entry_id(&self) -> u64 {
        self.entry_id
    }

    /// Automation this receipt is about.
    #[must_use]
    pub const fn automation_id(&self) -> &AutomationId {
        &self.automation_id
    }

    /// Enablement the row now records.
    #[must_use]
    pub const fn enablement(&self) -> EnablementState {
        self.enablement
    }

    /// Revision the row now carries. The next transition must expect this.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Instant the row now records as its last change.
    #[must_use]
    pub const fn updated_at(&self) -> EpochMillis {
        self.updated_at
    }

    fn to_body(&self) -> Result<JsonValue, AutomationApiError> {
        Ok(JsonValue::Object(vec![
            (
                "automation_id".to_owned(),
                JsonValue::String(self.automation_id.as_str().to_owned()),
            ),
            (
                "enablement".to_owned(),
                JsonValue::String(self.enablement.as_str().to_owned()),
            ),
            ("entry_id".to_owned(), integer("entry_id", self.entry_id)?),
            ("revision".to_owned(), integer("revision", self.revision)?),
            (
                "updated_at_ms".to_owned(),
                JsonValue::Integer(self.updated_at.as_millis()),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AutomationApiError> {
        exact_fields(
            body,
            &[
                "automation_id",
                "enablement",
                "entry_id",
                "revision",
                "updated_at_ms",
            ],
        )?;
        Self::new(
            unsigned(body, "entry_id")?,
            AutomationId::new(required_string(body, "automation_id")?)?,
            decode_enablement(&required_string(body, "enablement")?)?,
            unsigned(body, "revision")?,
            EpochMillis::from_millis(signed(body, "updated_at_ms")?),
        )
    }
}

/// One validated `automations` row, as a listing or a detail read reports it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationRecordView {
    entry_id: u64,
    automation_id: AutomationId,
    revision: u64,
    enablement: EnablementState,
    actor: AutomationActor,
    cause: Option<PauseReason>,
    created_at: EpochMillis,
    updated_at: EpochMillis,
}

impl AutomationRecordView {
    /// Record one automation, refusing every row this product could not have
    /// written.
    ///
    /// The same three cross-column invariants the store re-derives on every
    /// read are re-derived here, because a wire value is read by clients the
    /// store never sees:
    ///
    /// - a withdrawn state and a stated cause imply each other;
    /// - a withdrawn state implies revision two or above, because registration
    ///   is the only writer of revision one and it always writes `enabled`; and
    /// - both timestamps are at or after the epoch.
    ///
    /// The converse of the second is deliberately not checked: an `enabled` row
    /// above revision one is a *resumed* automation, which is legal and is
    /// exactly what [`AutomationRecordView::resumed_by`] reports.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::UnwrittenRow`],
    /// [`AutomationApiError::UnwrittenRevision`],
    /// [`AutomationApiError::CauseRequired`],
    /// [`AutomationApiError::CauseForbidden`],
    /// [`AutomationApiError::WithdrawnAtFirstRevision`] or
    /// [`AutomationApiError::TimeBeforeEpoch`].
    pub fn new(parts: AutomationRecordParts) -> Result<Self, AutomationApiError> {
        let AutomationRecordParts {
            entry_id,
            automation_id,
            revision,
            enablement,
            actor,
            cause,
            created_at,
            updated_at,
        } = parts;
        if entry_id == 0 {
            return Err(AutomationApiError::UnwrittenRow { field: "entry_id" });
        }
        if revision == 0 {
            return Err(AutomationApiError::UnwrittenRevision);
        }
        match (requires_cause(enablement), cause.is_some()) {
            (true, false) => return Err(AutomationApiError::CauseRequired { state: enablement }),
            (false, true) => return Err(AutomationApiError::CauseForbidden { state: enablement }),
            (true, true) | (false, false) => {}
        }
        if requires_cause(enablement) && revision < 2 {
            return Err(AutomationApiError::WithdrawnAtFirstRevision);
        }
        if created_at.as_millis() < 0 {
            return Err(AutomationApiError::TimeBeforeEpoch {
                field: "created_at_ms",
            });
        }
        if updated_at.as_millis() < 0 {
            return Err(AutomationApiError::TimeBeforeEpoch {
                field: "updated_at_ms",
            });
        }
        Ok(Self {
            entry_id,
            automation_id,
            revision,
            enablement,
            actor,
            cause,
            created_at,
            updated_at,
        })
    }

    /// Row identity, monotonic in registration order.
    #[must_use]
    pub const fn entry_id(&self) -> u64 {
        self.entry_id
    }

    /// Durable automation identity.
    #[must_use]
    pub const fn automation_id(&self) -> &AutomationId {
        &self.automation_id
    }

    /// `1` at registration, one higher after every accepted transition.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Whether the automation is in service.
    #[must_use]
    pub const fn enablement(&self) -> EnablementState {
        self.enablement
    }

    /// The last actor to change enablement, or the registrant while the row is
    /// still at revision one.
    #[must_use]
    pub const fn actor(&self) -> &AutomationActor {
        &self.actor
    }

    /// Why it was withdrawn. `Some` exactly when the state is withdrawn.
    #[must_use]
    pub const fn cause(&self) -> Option<&PauseReason> {
        self.cause.as_ref()
    }

    /// When the automation was registered.
    #[must_use]
    pub const fn created_at(&self) -> EpochMillis {
        self.created_at
    }

    /// When its enablement last changed.
    #[must_use]
    pub const fn updated_at(&self) -> EpochMillis {
        self.updated_at
    }

    /// Whether the automation may fire.
    ///
    /// As weak a claim as [`crate::automation::EnablementState::admits_occurrence`]:
    /// it says the operator has not withdrawn this automation, never that
    /// anything will run it. Nothing in this build runs one.
    #[must_use]
    pub const fn admits_occurrence(&self) -> bool {
        self.enablement.admits_occurrence()
    }

    /// Who put this automation back in service, if anybody did.
    ///
    /// Recovered from the flat columns exactly as the store recovers it:
    /// registration is the only writer of `enabled` at revision one, and
    /// `paused -> enabled` is the only other way in, so an `enabled` row above
    /// revision one was resumed and its actor is whoever reopened it. A
    /// never-paused automation answers `None`, as
    /// [`crate::automation::AutomationEnablement::newly_declared`] does.
    #[must_use]
    pub fn resumed_by(&self) -> Option<&AutomationActor> {
        (self.enablement == EnablementState::Enabled && self.revision > 1).then_some(&self.actor)
    }

    /// This row as the rich model's [`crate::automation::AutomationEnablement`].
    ///
    /// The flat columns reassembled into the shape
    /// [`crate::automation`] defines, so a caller can have either without this
    /// module choosing for them. It cannot fail: both halves of a cause were
    /// validated against the same grammar `PauseCause` applies, and the
    /// constructor above already refused every incoherent state/cause pairing.
    /// A cause that somehow failed to reassemble would be a bug here rather
    /// than a caller's, so it is reported as one — `None` — instead of being
    /// papered over with a fabricated reason.
    #[must_use]
    pub fn enablement_value(&self) -> Option<AutomationEnablement> {
        match (self.enablement, &self.cause) {
            (EnablementState::Enabled, _) => Some(AutomationEnablement::Enabled {
                resumed_by: self.resumed_by().cloned(),
            }),
            (EnablementState::Paused, Some(reason)) => {
                PauseCause::new(self.actor.as_str(), reason.as_str())
                    .ok()
                    .map(|cause| AutomationEnablement::Paused { cause })
            }
            (EnablementState::Archived, Some(reason)) => {
                PauseCause::new(self.actor.as_str(), reason.as_str())
                    .ok()
                    .map(|cause| AutomationEnablement::Archived { cause })
            }
            (EnablementState::Paused | EnablementState::Archived, None) => None,
        }
    }

    fn to_body(&self) -> Result<JsonValue, AutomationApiError> {
        Ok(JsonValue::Object(vec![
            (
                "actor".to_owned(),
                JsonValue::String(self.actor.as_str().to_owned()),
            ),
            (
                "automation_id".to_owned(),
                JsonValue::String(self.automation_id.as_str().to_owned()),
            ),
            (
                "cause".to_owned(),
                match &self.cause {
                    Some(cause) => JsonValue::String(cause.as_str().to_owned()),
                    None => JsonValue::Null,
                },
            ),
            (
                "created_at_ms".to_owned(),
                JsonValue::Integer(self.created_at.as_millis()),
            ),
            (
                "enablement".to_owned(),
                JsonValue::String(self.enablement.as_str().to_owned()),
            ),
            ("entry_id".to_owned(), integer("entry_id", self.entry_id)?),
            ("revision".to_owned(), integer("revision", self.revision)?),
            (
                "updated_at_ms".to_owned(),
                JsonValue::Integer(self.updated_at.as_millis()),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AutomationApiError> {
        exact_fields(
            body,
            &[
                "actor",
                "automation_id",
                "cause",
                "created_at_ms",
                "enablement",
                "entry_id",
                "revision",
                "updated_at_ms",
            ],
        )?;
        let cause = match body.get("cause") {
            Some(JsonValue::Null) => None,
            Some(JsonValue::String(_)) => Some(PauseReason::new(required_string(body, "cause")?)?),
            _ => return Err(AutomationApiError::InvalidBody),
        };
        Self::new(AutomationRecordParts {
            entry_id: unsigned(body, "entry_id")?,
            automation_id: AutomationId::new(required_string(body, "automation_id")?)?,
            revision: unsigned(body, "revision")?,
            enablement: decode_enablement(&required_string(body, "enablement")?)?,
            actor: actor(&required_string(body, "actor")?)?,
            cause,
            created_at: EpochMillis::from_millis(signed(body, "created_at_ms")?),
            updated_at: EpochMillis::from_millis(signed(body, "updated_at_ms")?),
        })
    }
}

/// The eight columns one automation row carries.
///
/// A parameter object rather than eight positional arguments: two `u64`
/// revisions and two `EpochMillis` instants sit beside one another, and a
/// transposed pair would type-check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationRecordParts {
    /// Row identity, monotonic in registration order.
    pub entry_id: u64,
    /// Durable automation identity.
    pub automation_id: AutomationId,
    /// `1` at registration, one higher after every accepted transition.
    pub revision: u64,
    /// Whether the automation is in service.
    pub enablement: EnablementState,
    /// The last actor to change enablement.
    pub actor: AutomationActor,
    /// Why it was withdrawn. `Some` exactly when the state is withdrawn.
    pub cause: Option<PauseReason>,
    /// When the automation was registered.
    pub created_at: EpochMillis,
    /// When its enablement last changed.
    pub updated_at: EpochMillis,
}

/// Whether a page is the end of the listing.
///
/// Closed, and carried explicitly rather than inferred from `entries.len() <
/// page_size`. A short page is not the same statement as a last page: a state
/// filter can exclude every row in a scanned window and still leave rows behind
/// it, and a client that inferred "done" from a short page would stop early.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AutomationContinuation {
    /// More rows may follow; resume after this cursor.
    More(AutomationCursor),
    /// The listing reached the end of the registry.
    Complete,
}

impl AutomationContinuation {
    /// The cursor to resume after, when there is one.
    #[must_use]
    pub const fn cursor(self) -> Option<AutomationCursor> {
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

/// One bounded page of automation records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationListPage {
    entries: Vec<AutomationRecordView>,
    continuation: AutomationContinuation,
}

impl AutomationListPage {
    /// Assemble a page.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::PageTooLarge`] above
    /// [`MAX_AUTOMATION_PAGE_ITEMS`], [`AutomationApiError::PageOutOfOrder`]
    /// when records do not strictly increase by `entry_id` — a listing is
    /// ordered by that identity, and a repeat or a step backwards means the
    /// next page would re-serve or skip — and
    /// [`AutomationApiError::ContinuationRewinds`] when a continuation cursor
    /// does not reach the last row on the page.
    ///
    /// An empty page carrying [`AutomationContinuation::More`] is accepted: a
    /// state filter may exclude every row in one scanned window while rows
    /// remain behind it.
    pub fn new(
        entries: Vec<AutomationRecordView>,
        continuation: AutomationContinuation,
    ) -> Result<Self, AutomationApiError> {
        if entries.len() > MAX_AUTOMATION_PAGE_ITEMS {
            return Err(AutomationApiError::PageTooLarge {
                max_items: MAX_AUTOMATION_PAGE_ITEMS,
                actual_items: entries.len(),
            });
        }
        if entries
            .windows(2)
            .any(|pair| pair[1].entry_id() <= pair[0].entry_id())
        {
            return Err(AutomationApiError::PageOutOfOrder);
        }
        if let (Some(cursor), Some(last)) = (continuation.cursor(), entries.last())
            && cursor.position() < last.entry_id()
        {
            return Err(AutomationApiError::ContinuationRewinds);
        }
        Ok(Self {
            entries,
            continuation,
        })
    }

    /// The records, in registration order.
    #[must_use]
    pub fn entries(&self) -> &[AutomationRecordView] {
        &self.entries
    }

    /// Whether more rows may follow, and from where.
    #[must_use]
    pub const fn continuation(&self) -> AutomationContinuation {
        self.continuation
    }

    fn to_body(&self) -> Result<JsonValue, AutomationApiError> {
        let mut entries = Vec::with_capacity(self.entries.len());
        for record in &self.entries {
            entries.push(record.to_body()?);
        }
        Ok(JsonValue::Object(vec![
            ("automations".to_owned(), JsonValue::Array(entries)),
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
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AutomationApiError> {
        exact_fields(body, &["automations", "more", "next_cursor"])?;
        let more = match body.get("more") {
            Some(JsonValue::Bool(value)) => *value,
            _ => return Err(AutomationApiError::InvalidBody),
        };
        let continuation = match (more, body.get("next_cursor")) {
            (true, Some(JsonValue::Integer(_))) => {
                AutomationContinuation::More(AutomationCursor::new(unsigned(body, "next_cursor")?))
            }
            (false, Some(JsonValue::Null)) => AutomationContinuation::Complete,
            (true, Some(JsonValue::Null)) | (false, Some(JsonValue::Integer(_))) => {
                return Err(AutomationApiError::ContinuationIncoherent);
            }
            _ => return Err(AutomationApiError::InvalidBody),
        };
        let JsonValue::Array(items) = body
            .get("automations")
            .ok_or(AutomationApiError::InvalidBody)?
        else {
            return Err(AutomationApiError::InvalidBody);
        };
        if items.len() > MAX_AUTOMATION_PAGE_ITEMS {
            return Err(AutomationApiError::PageTooLarge {
                max_items: MAX_AUTOMATION_PAGE_ITEMS,
                actual_items: items.len(),
            });
        }
        let mut entries = Vec::with_capacity(items.len());
        for item in items {
            entries.push(AutomationRecordView::from_body(item)?);
        }
        Self::new(entries, continuation)
    }
}

/// Why an automation control operation was refused.
///
/// Closed, and every variant is one word. A refusal carries no field name, no
/// stored text and no echo of the caller's payload: a refusal category is a
/// metric label and an operator-facing word, not a diagnostic channel for the
/// bytes that were sent.
///
/// A stale expected revision is deliberately *not* here. It is
/// [`AutomationResponse::Conflict`], which the plan's vocabulary distinguishes
/// from a rejection precisely because a caller retries the two differently.
///
/// # Two of these are unreachable from a conforming client, and stay anyway
///
/// [`Self::CauseRequired`] and [`Self::CauseForbidden`] cannot be earned by a
/// request that came through [`SetEnablement::new`] or its decoder: both refuse
/// an incoherent state and cause pairing before a frame is sent, and the frame
/// that carried one would not have decoded. They are here because
/// `automonique_store` can produce both — its API and its database `CHECK`
/// decide the coupling independently of ours — and a daemon that met one would
/// otherwise have no word for it and would have to report the operator's own
/// mistake as our storage failing. An unreachable refusal with a real condition
/// behind it is defence in depth; an unreachable refusal with *nothing* behind
/// it would be an invented vocabulary, and there are none of those here.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AutomationRefusal {
    /// No automation with that identity is registered.
    UnknownAutomation,
    /// The identity is already registered, whatever state its row is in.
    AlreadyRegistered,
    /// The requested state does not follow the durable one along the lattice.
    IllegalTransition,
    /// A withdrawal was requested with no stated cause.
    CauseRequired,
    /// A cause was supplied for a state that admits none.
    CauseForbidden,
    /// A page was requested from a cursor above everything recorded.
    CursorOutOfRange,
    /// The registry holds its full capacity of automations.
    RegistryFull,
    /// A supplied field was outside the durable registry's grammar.
    InvalidField,
}

impl AutomationRefusal {
    /// Every refusal, in canonical order.
    pub const ALL: [Self; 8] = [
        Self::UnknownAutomation,
        Self::AlreadyRegistered,
        Self::IllegalTransition,
        Self::CauseRequired,
        Self::CauseForbidden,
        Self::CursorOutOfRange,
        Self::RegistryFull,
        Self::InvalidField,
    ];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownAutomation => "unknown_automation",
            Self::AlreadyRegistered => "already_registered",
            Self::IllegalTransition => "illegal_transition",
            Self::CauseRequired => "cause_required",
            Self::CauseForbidden => "cause_forbidden",
            Self::CursorOutOfRange => "cursor_out_of_range",
            Self::RegistryFull => "registry_full",
            Self::InvalidField => "invalid_field",
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

impl fmt::Display for AutomationRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for AutomationRefusal {
    const FIELD: &'static str = "refusal";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// A correlated request on the Automation control API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AutomationRequest {
    /// Declare one automation, enabled, at revision one.
    RegisterAutomation {
        /// Correlation identifier.
        request_id: RequestId,
        /// What to register.
        registration: RegisterAutomation,
    },
    /// Move one automation along the enablement lattice.
    SetEnablement {
        /// Correlation identifier.
        request_id: RequestId,
        /// The requested move.
        transition: SetEnablement,
    },
    /// One bounded page of automations.
    ListAutomations {
        /// Correlation identifier.
        request_id: RequestId,
        /// Filter, cursor and page size.
        query: ListAutomations,
    },
    /// One automation in full.
    AutomationDetail {
        /// Correlation identifier.
        request_id: RequestId,
        /// Automation to read.
        automation_id: AutomationId,
    },
}

impl AutomationRequest {
    /// Correlation identifier.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        match self {
            Self::RegisterAutomation { request_id, .. }
            | Self::SetEnablement { request_id, .. }
            | Self::ListAutomations { request_id, .. }
            | Self::AutomationDetail { request_id, .. } => request_id,
        }
    }

    /// Whether this request would change durable state.
    ///
    /// Reads and writes travel the same lane, and the daemon fences both the
    /// same way, so this exists for callers that log or meter the difference
    /// rather than for anything that decides it.
    #[must_use]
    pub const fn is_mutation(&self) -> bool {
        matches!(
            self,
            Self::RegisterAutomation { .. } | Self::SetEnablement { .. }
        )
    }

    /// Encode the request as a canonical message.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal if a counter or a compile-time envelope literal
    /// is outside the protocol bounds.
    pub fn to_message(&self) -> Result<Message, AutomationApiError> {
        match self {
            Self::RegisterAutomation {
                request_id,
                registration,
            } => Ok(Message::new(
                envelope(request_id.clone(), "register_automation")?,
                registration.to_body(),
            )),
            Self::SetEnablement {
                request_id,
                transition,
            } => Ok(Message::new(
                envelope(request_id.clone(), "set_enablement")?,
                transition.to_body()?,
            )),
            Self::ListAutomations { request_id, query } => Ok(Message::new(
                envelope(request_id.clone(), "list_automations")?,
                query.to_body()?,
            )),
            Self::AutomationDetail {
                request_id,
                automation_id,
            } => Ok(Message::new(
                envelope(request_id.clone(), "automation_detail")?,
                JsonValue::Object(vec![(
                    "automation_id".to_owned(),
                    JsonValue::String(automation_id.as_str().to_owned()),
                )]),
            )),
        }
    }

    /// Decode and admit a request against the exact first protocol version.
    ///
    /// # Errors
    ///
    /// Refuses unknown kinds and bodies that are not exact.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, AutomationApiError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let request_id = message.envelope().request_id().clone();
        match message.envelope().kind().as_str() {
            "register_automation" => Ok(Self::RegisterAutomation {
                request_id,
                registration: RegisterAutomation::from_body(message.body())?,
            }),
            "set_enablement" => Ok(Self::SetEnablement {
                request_id,
                transition: SetEnablement::from_body(message.body())?,
            }),
            "list_automations" => Ok(Self::ListAutomations {
                request_id,
                query: ListAutomations::from_body(message.body())?,
            }),
            "automation_detail" => {
                exact_fields(message.body(), &["automation_id"])?;
                Ok(Self::AutomationDetail {
                    request_id,
                    automation_id: AutomationId::new(required_string(
                        message.body(),
                        "automation_id",
                    )?)?,
                })
            }
            _ => Err(AutomationApiError::UnknownKind),
        }
    }
}

/// A correlated answer on the Automation control API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AutomationResponse {
    /// One durable write landed.
    Accepted {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// What the write established.
        receipt: AutomationReceiptView,
    },
    /// One page of automations.
    AutomationList {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// The page.
        page: AutomationListPage,
    },
    /// One automation in full.
    AutomationDetail {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// The record.
        record: AutomationRecordView,
    },
    /// The caller's expected revision did not match the durable one. Nothing
    /// was written.
    Conflict {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// Revision the caller believed it was moving.
        expected_revision: u64,
        /// Revision the durable row carries. Retry against this one.
        durable_revision: u64,
    },
    /// The operation was refused. Nothing was written and nothing was read.
    Refused {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// Why.
        refusal: AutomationRefusal,
    },
}

impl AutomationResponse {
    /// Correlation identifier from the request.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        match self {
            Self::Accepted { request_id, .. }
            | Self::AutomationList { request_id, .. }
            | Self::AutomationDetail { request_id, .. }
            | Self::Conflict { request_id, .. }
            | Self::Refused { request_id, .. } => request_id,
        }
    }

    /// Which of the six terminal outcomes this answer reports.
    ///
    /// A delivered read is `completed`: there is no later completion to wait
    /// for. A landed write is `accepted` rather than `completed`, and the
    /// distinction is the honest one — the durable row *is* committed, but what
    /// the row authorizes has not happened and cannot: no scheduler reads it
    /// and no executor exists. `accepted` says "recorded"; `completed` would
    /// say the decision took effect, which would be a claim about a component
    /// this release does not contain.
    ///
    /// See [`OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES`] for the two this protocol
    /// cannot produce and why.
    #[must_use]
    pub const fn outcome(&self) -> ActionOutcome {
        match self {
            Self::Accepted { .. } => ActionOutcome::Accepted,
            Self::AutomationList { .. } | Self::AutomationDetail { .. } => ActionOutcome::Completed,
            Self::Conflict { .. } => ActionOutcome::Conflict,
            Self::Refused { .. } => ActionOutcome::Rejected,
        }
    }

    /// Build the answer to a listing from the rows a store produced.
    ///
    /// This is the enforcement the module exists for: a page longer than the
    /// query asked for, or carrying an automation the filter excludes, is
    /// refused here rather than served. Both are answers that would look
    /// perfectly well-formed to a client and would silently contradict the
    /// question it asked.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::PageAboveRequestedSize`] or
    /// [`AutomationApiError::PageOutsideFilter`].
    pub fn listing(
        request_id: RequestId,
        query: &ListAutomations,
        page: AutomationListPage,
    ) -> Result<Self, AutomationApiError> {
        if page.entries().len() > query.page_size().get() {
            return Err(AutomationApiError::PageAboveRequestedSize {
                requested: query.page_size().get(),
                actual_items: page.entries().len(),
            });
        }
        if page
            .entries()
            .iter()
            .any(|record| !query.states().admits(record.enablement()))
        {
            return Err(AutomationApiError::PageOutsideFilter);
        }
        Ok(Self::AutomationList { request_id, page })
    }

    /// Report a stale expected revision.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::UnwrittenRevision`] for a zero on either
    /// side, and [`AutomationApiError::ConflictWithoutDisagreement`] when the
    /// two revisions agree — which is not a conflict, and answering one would
    /// tell a caller to retry with the revision it already used.
    pub fn conflict(
        request_id: RequestId,
        expected_revision: u64,
        durable_revision: u64,
    ) -> Result<Self, AutomationApiError> {
        if expected_revision == 0 || durable_revision == 0 {
            return Err(AutomationApiError::UnwrittenRevision);
        }
        if expected_revision == durable_revision {
            return Err(AutomationApiError::ConflictWithoutDisagreement);
        }
        Ok(Self::Conflict {
            request_id,
            expected_revision,
            durable_revision,
        })
    }

    /// Encode the response as a canonical message.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal if a counter or a compile-time envelope literal
    /// is outside the protocol bounds.
    pub fn to_message(&self) -> Result<Message, AutomationApiError> {
        match self {
            Self::Accepted {
                request_id,
                receipt,
            } => Ok(Message::new(
                envelope(request_id.clone(), "automation_accepted")?,
                receipt.to_body()?,
            )),
            Self::AutomationList { request_id, page } => Ok(Message::new(
                envelope(request_id.clone(), "automation_list_result")?,
                page.to_body()?,
            )),
            Self::AutomationDetail { request_id, record } => Ok(Message::new(
                envelope(request_id.clone(), "automation_detail_result")?,
                record.to_body()?,
            )),
            Self::Conflict {
                request_id,
                expected_revision,
                durable_revision,
            } => Ok(Message::new(
                envelope(request_id.clone(), "revision_conflict")?,
                JsonValue::Object(vec![
                    (
                        "durable_revision".to_owned(),
                        integer("durable_revision", *durable_revision)?,
                    ),
                    (
                        "expected_revision".to_owned(),
                        integer("expected_revision", *expected_revision)?,
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
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, AutomationApiError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let request_id = message.envelope().request_id().clone();
        match message.envelope().kind().as_str() {
            "automation_accepted" => Ok(Self::Accepted {
                request_id,
                receipt: AutomationReceiptView::from_body(message.body())?,
            }),
            "automation_list_result" => Ok(Self::AutomationList {
                request_id,
                page: AutomationListPage::from_body(message.body())?,
            }),
            "automation_detail_result" => Ok(Self::AutomationDetail {
                request_id,
                record: AutomationRecordView::from_body(message.body())?,
            }),
            "revision_conflict" => {
                exact_fields(message.body(), &["durable_revision", "expected_revision"])?;
                Self::conflict(
                    request_id,
                    unsigned(message.body(), "expected_revision")?,
                    unsigned(message.body(), "durable_revision")?,
                )
            }
            "refused" => {
                exact_fields(message.body(), &["refusal"])?;
                Ok(Self::Refused {
                    request_id,
                    refusal: decode_security_enum::<AutomationRefusal>(&required_string(
                        message.body(),
                        "refusal",
                    )?)?,
                })
            }
            _ => Err(AutomationApiError::UnknownKind),
        }
    }
}

fn envelope(request_id: RequestId, kind: &str) -> Result<Envelope, AutomationApiError> {
    Ok(Envelope::new(
        ProtocolName::new(AUTOMATION_PROTOCOL)?,
        MajorVersion::FIRST,
        request_id,
        MessageKind::new(kind)?,
    ))
}

fn supported_protocol() -> Result<SupportedProtocol, AutomationApiError> {
    Ok(SupportedProtocol::new(
        ProtocolName::new(AUTOMATION_PROTOCOL)?,
        VersionRange::new(MajorVersion::FIRST, MajorVersion::FIRST)?,
    ))
}

fn actor(value: &str) -> Result<AutomationActor, AutomationApiError> {
    AutomationActor::new(value).map_err(|error| from_automation_error(&error, "actor"))
}

fn bounded(value: &str, field: &'static str) -> Result<(), AutomationApiError> {
    crate::primitives::bounded_value(value, MAX_AUTOMATION_API_FIELD_BYTES)
        .map_err(|error| AutomationApiError::Field { field, error })
}

fn integer(field: &'static str, value: u64) -> Result<JsonValue, AutomationApiError> {
    i64::try_from(value)
        .map(JsonValue::Integer)
        .map_err(|_| AutomationApiError::CounterOutOfRange { field })
}

fn unsigned(body: &JsonValue, field: &'static str) -> Result<u64, AutomationApiError> {
    let value = body
        .get(field)
        .and_then(JsonValue::as_integer)
        .ok_or(AutomationApiError::InvalidBody)?;
    u64::try_from(value).map_err(|_| AutomationApiError::InvalidBody)
}

fn signed(body: &JsonValue, field: &'static str) -> Result<i64, AutomationApiError> {
    body.get(field)
        .and_then(JsonValue::as_integer)
        .ok_or(AutomationApiError::InvalidBody)
}

fn required_string(body: &JsonValue, field: &'static str) -> Result<String, AutomationApiError> {
    body.get(field)
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
        .ok_or(AutomationApiError::InvalidBody)
}

fn exact_fields(body: &JsonValue, fields: &[&str]) -> Result<(), AutomationApiError> {
    let JsonValue::Object(entries) = body else {
        return Err(AutomationApiError::InvalidBody);
    };
    if entries.len() != fields.len()
        || !fields
            .iter()
            .all(|field| entries.iter().any(|(name, _)| name == field))
    {
        return Err(AutomationApiError::InvalidBody);
    }
    Ok(())
}
