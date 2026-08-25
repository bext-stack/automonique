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
//! **It registers an automation job — a canonical schedule, a serialization
//! scope and a bounded prompt — records an operator's decisions about whether
//! that job is in service, durably, and serves those decisions and the job's
//! last and next execution back.** What consumes the record is the daemon's
//! automation scheduler worker, which derives one occurrence per due instant,
//! admits it through the durable scheduler core under the generation fence,
//! and submits it as a normal run on the durable synthetic lane under the
//! idempotency key [`AutomationOccurrenceKey`] derives. Two things this
//! surface still does not do:
//!
//! - **It carries no cron.** [`AutomationSchedule`] admits the one-shot and
//!   fixed-interval forms of [`crate::automation::CanonicalSchedule`] and
//!   refuses the five-field cron form with the typed
//!   [`AutomationApiError::UnsupportedSchedule`], because no dependency-free
//!   cron evaluator with a timezone database ships in this build and a schedule
//!   that cannot be evaluated must not be accepted as if it could.
//! - **Nothing here authenticates.** [`RegisterAutomation::actor`] and
//!   [`SetEnablement::actor`] name who asked and are recorded verbatim. The
//!   daemon's `SO_PEERCRED` check is the authentication; this string is not a
//!   capability, exactly as [`crate::automation::AutomationActor`] says of
//!   itself and as [`crate::admin::IntakePause`] says of the intake switch.
//!
//! # The bounds are the durable submit lane's
//!
//! An occurrence is submitted exactly as `automonique submit` submits synthetic
//! work, so the job's three fields carry that lane's bounds rather than new
//! ones: [`AutomationScope`] is bounded by
//! [`crate::admin::MAX_SYNTHETIC_SCOPE_BYTES`], [`AutomationPrompt`] by
//! [`crate::admin::MAX_SYNTHETIC_TASK_BYTES`] under the same no-NUL rule, and
//! the occurrence key `automation:<automation_id>:<occurrence_instant>` by
//! [`crate::admin::MAX_SYNTHETIC_KEY_BYTES`] — which is why an identity
//! registered *with a schedule* is bounded by
//! [`MAX_SCHEDULED_AUTOMATION_ID_BYTES`], derived from that key bound, while
//! [`AutomationId`] itself keeps the registry's wider grammar so a row written
//! before schedules existed is still readable.
//!
//! # The vocabulary is borrowed, not re-spelled
//!
//! [`crate::automation::EnablementState`], [`crate::automation::AutomationActor`]
//! and [`crate::automation::PauseCause`] already define this product's
//! enablement words, so this module *uses* them rather than writing a second
//! set down. The bounded types that are new — [`AutomationId`],
//! [`PauseReason`], [`AutomationScope`] and [`AutomationPrompt`] — exist
//! because the rich model spells a withdrawal as one `PauseCause` value
//! carrying both halves, while `automonique_store`'s `automations` table stores
//! the actor and the reason in separate columns and writes an actor on *every*
//! transition including a resume. The wire follows the table, and
//! [`AutomationRecordView::enablement`] reassembles the rich value so a reader
//! can have either shape without this module choosing for them.
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
//! - **A job is a schedule, a scope and a prompt.** `plan` also gives an
//!   automation a trigger, an overlap policy, delivery targets and a
//!   pre-approved effect scope. None of those is representable in
//!   [`RegisterAutomation`], because none is durable: the registry stores the
//!   three job fields beside identity, revision, enablement and attribution
//!   and nothing else. The overlap policy is fixed rather than chosen — one
//!   occurrence per automation is admitted at a time, and a fixed interval
//!   that falls behind fires its oldest due instant once and skips the rest —
//!   and an occurrence's only effect is the synthetic lane's, so no approved
//!   effect set is recorded because nothing here spends one.
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
    AutomationActor, AutomationEnablement, AutomationError, CanonicalSchedule, EnablementState,
    FixedInterval, PauseCause,
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

/// Maximum UTF-8 byte length of an automation's serialization scope.
///
/// An occurrence is serialized under this scope twice: admitted by the
/// scheduler core in `automonique-core`, whose identifier ceiling is 160
/// bytes, and then run on the durable submit lane, whose scope bound is
/// [`crate::admin::MAX_SYNTHETIC_SCOPE_BYTES`]. The scope has to be admitted
/// by both, so this is the narrower of the two — spelled here as a literal
/// because this crate does not depend on the core, and pinned against the
/// core's source in `tests/automation_api.rs`.
pub const MAX_AUTOMATION_SCOPE_BYTES: usize = 160;

const _: () = assert!(
    MAX_AUTOMATION_SCOPE_BYTES <= crate::admin::MAX_SYNTHETIC_SCOPE_BYTES,
    "a scope the scheduler core admits must also be one the durable submit lane admits"
);

/// Maximum UTF-8 byte length of the prompt one occurrence submits.
///
/// The durable submit lane's own task bound,
/// [`crate::admin::MAX_SYNTHETIC_TASK_BYTES`], under the same rule: non-empty,
/// no NUL, and otherwise free text — a prompt may carry newlines.
pub const MAX_AUTOMATION_PROMPT_BYTES: usize = crate::admin::MAX_SYNTHETIC_TASK_BYTES;

/// Maximum UTF-8 byte length of an occurrence key.
///
/// The durable submit lane's own idempotency-key bound,
/// [`crate::admin::MAX_SYNTHETIC_KEY_BYTES`]. That lane derives bounded receipt
/// keys from the coordinate it is handed, and an occurrence key travels the
/// same path, so it fits the same bound.
pub const MAX_OCCURRENCE_KEY_BYTES: usize = crate::admin::MAX_SYNTHETIC_KEY_BYTES;

/// The namespace every occurrence key opens with.
///
/// `automation:<automation_id>:<occurrence_instant>`, where the instant is the
/// canonical decimal rendering of the scheduled Unix millisecond. Derived from
/// the automation and its instant and nothing else, so a replayed tick, a
/// restarted daemon or a re-elected generation derives the same key and the
/// lane's own idempotency dedupes the firing.
pub const OCCURRENCE_KEY_PREFIX: &str = "automation:";

/// Longest canonical decimal rendering of a non-negative `i64` instant.
const MAX_INSTANT_DIGITS: usize = 19;

/// Longest automation identity that may be registered with a schedule.
///
/// Derived, not chosen: the occurrence key is the prefix, the identity, one
/// colon and an instant of at most [`MAX_INSTANT_DIGITS`] digits, and the whole
/// must fit [`MAX_OCCURRENCE_KEY_BYTES`]. [`AutomationId`] keeps the wider
/// registry grammar so a row registered before schedules existed stays
/// readable; [`RegisterAutomation::new`] applies this narrower bound.
pub const MAX_SCHEDULED_AUTOMATION_ID_BYTES: usize =
    MAX_OCCURRENCE_KEY_BYTES - OCCURRENCE_KEY_PREFIX.len() - 1 - MAX_INSTANT_DIGITS;

/// Longest canonical rendering of a schedule this lane carries.
///
/// `every@` followed by at most [`MAX_INSTANT_DIGITS`] digits. A cron
/// rendering is longer and is refused before its length matters.
pub const MAX_AUTOMATION_SCHEDULE_BYTES: usize = "every@".len() + MAX_INSTANT_DIGITS;

/// Maximum automations one listing page may carry.
///
/// Twenty-four rather than the sixty-four [`crate::runs_api`] serves, because an
/// automation row carries *four* maximal bounded strings — the identity, the
/// actor, the cause and the scope — where a run summary carries one. The number
/// is derived from the frame arithmetic below and not chosen: see
/// [`RECORD_OVERHEAD_BYTES`].
///
/// A page bound is not a paging hint. [`AutomationListPage::new`] refuses a
/// longer vector rather than truncating it, because a truncated page that still
/// answers `complete` is a silent drop.
pub const MAX_AUTOMATION_PAGE_ITEMS: usize = 24;

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

/// Worst-case canonical bytes of one record, excluding its four bounded
/// strings.
///
/// The twelve quoted key names and their punctuation (168), six twenty-digit
/// integers (120), the longest quoted enablement spelling (10), the longest
/// quoted schedule rendering (27), and the quote pairs around the four string
/// members (8), rounded up.
const RECORD_OVERHEAD_BYTES: usize = 352;

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

/// One record carries four of them: the identity, the actor, the cause and the
/// scope, whose bound is the same number of bytes.
const RECORD_FIELDS: usize = 4;

/// The prompt a detail read carries beside its record, at its escaped worst
/// case plus its quoted key.
const PROMPT_ENCODED_BYTES: usize = 2 * MAX_AUTOMATION_PROMPT_BYTES + 16;

const _: () = assert!(
    MAX_AUTOMATION_SCOPE_BYTES <= MAX_AUTOMATION_API_FIELD_BYTES,
    "the record arithmetic budgets the scope as one more identifier-sized field"
);

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
        + PROMPT_ENCODED_BYTES
        + BODY_SCAFFOLD_BYTES
        + ENVELOPE_OVERHEAD_BYTES
        <= MAX_AUTOMATION_CANONICAL_BYTES,
    "a maximal automation detail view must fit one automation frame"
);

const _: () = assert!(
    OCCURRENCE_KEY_PREFIX.len() + MAX_SCHEDULED_AUTOMATION_ID_BYTES + 1 + MAX_INSTANT_DIGITS
        <= MAX_OCCURRENCE_KEY_BYTES,
    "a maximal occurrence key must fit the durable submit lane's key bound"
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
    /// A canonical schedule form this lane cannot evaluate was presented.
    ///
    /// Typed rather than folded into an invalid body: the schedule *is*
    /// canonical, and the refusal names the form the daemon has no evaluator
    /// for, so an operator learns that cron is not yet supported rather than
    /// that their expression was malformed.
    UnsupportedSchedule {
        /// The canonical form that was refused.
        kind: &'static str,
    },
    /// A schedule expression did not resolve to one canonical schedule.
    InvalidSchedule,
    /// A record's job fields disagreed with one another.
    ///
    /// A schedule and a scope imply each other, and a next or last execution
    /// implies a schedule: a row with one half of the job is a row no writer
    /// produced.
    JobIncoherent,
    /// An occurrence key would exceed the durable submit lane's key bound.
    OccurrenceKeyTooLong {
        /// Largest key that lane admits.
        max_bytes: usize,
    },
    /// An occurrence key did not have the shape this lane derives.
    OccurrenceKeyMalformed,
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
            Self::UnsupportedSchedule { .. } => "automation_unsupported_schedule",
            Self::InvalidSchedule => "automation_invalid_schedule",
            Self::JobIncoherent => "automation_job_incoherent",
            Self::OccurrenceKeyTooLong { .. } => "automation_occurrence_key_too_long",
            Self::OccurrenceKeyMalformed => "automation_occurrence_key_malformed",
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
            Self::UnsupportedSchedule { kind } => {
                write!(formatter, "the {kind} schedule form is not supported")
            }
            Self::InvalidSchedule => {
                formatter.write_str("the expression is not one canonical schedule")
            }
            Self::JobIncoherent => {
                formatter.write_str("a record's schedule, scope and execution fields disagree")
            }
            Self::OccurrenceKeyTooLong { max_bytes } => {
                write!(formatter, "the occurrence key exceeds {max_bytes} bytes")
            }
            Self::OccurrenceKeyMalformed => {
                formatter.write_str("the occurrence key is not automation:<id>:<instant>")
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

/// The serialization scope every occurrence of one automation is submitted
/// under.
///
/// What a scope *is* — a workspace, a conversation, a tenant — is a deployment
/// decision; what this type fixes is that two occurrences sharing one never
/// overlap, because the durable scheduler core serializes per scope and the
/// synthetic lane locks the scope again for the run. The grammar is the
/// durable submit lane's: non-empty, at most [`MAX_AUTOMATION_SCOPE_BYTES`],
/// control-free.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AutomationScope(String);

impl AutomationScope {
    /// Longest scope this protocol carries.
    pub const MAX_BYTES: usize = MAX_AUTOMATION_SCOPE_BYTES;

    /// Validate and construct a scope.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::Field`] for an empty, over-long or
    /// control-bearing value.
    pub fn new(value: impl AsRef<str>) -> Result<Self, AutomationApiError> {
        let value = value.as_ref();
        crate::primitives::bounded_value(value, MAX_AUTOMATION_SCOPE_BYTES).map_err(|error| {
            AutomationApiError::Field {
                field: "scope",
                error,
            }
        })?;
        Ok(Self(value.to_owned()))
    }

    /// The validated scope.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AutomationScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The prompt one occurrence submits as its task.
///
/// Free text under the durable submit lane's task rule: non-empty, at most
/// [`MAX_AUTOMATION_PROMPT_BYTES`], and free of NUL. Newlines are admitted —
/// a prompt is prose, not an identifier — which is why this does not share
/// [`AutomationId`]'s control-free grammar.
///
/// It grants no provider or external-effect authority. It is the payload the
/// synthetic lane's run receives, exactly as `automonique submit` hands one
/// over.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AutomationPrompt(String);

impl AutomationPrompt {
    /// Longest prompt this protocol carries.
    pub const MAX_BYTES: usize = MAX_AUTOMATION_PROMPT_BYTES;

    /// Validate and construct a prompt.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::Field`] for an empty or over-long value,
    /// or one carrying a NUL.
    pub fn new(value: impl AsRef<str>) -> Result<Self, AutomationApiError> {
        let value = value.as_ref();
        let refused = |error| AutomationApiError::Field {
            field: "prompt",
            error,
        };
        if value.is_empty() {
            return Err(refused(ValueError::Empty));
        }
        if value.len() > MAX_AUTOMATION_PROMPT_BYTES {
            return Err(refused(ValueError::TooLong {
                max_bytes: MAX_AUTOMATION_PROMPT_BYTES,
                actual_bytes: value.len(),
            }));
        }
        if value.contains('\0') {
            return Err(refused(ValueError::ControlCharacter));
        }
        Ok(Self(value.to_owned()))
    }

    /// The validated prompt.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The schedule forms this lane carries and the daemon evaluates.
///
/// A projection of [`crate::automation::CanonicalSchedule`] onto the two forms
/// that need no timezone database: an exact instant, and a fixed interval. The
/// cron form is refused by [`AutomationSchedule::from_canonical`] with the
/// typed [`AutomationApiError::UnsupportedSchedule`] rather than accepted and
/// never fired. The wire spelling is the canonical rendering itself —
/// `once@<ms>` or `every@<ms>` — so what an operator previews is what is
/// stored and what fires.
///
/// The occurrence arithmetic lives here rather than in the store or the
/// daemon so that both derive the same instants:
///
/// - [`Self::first_occurrence`] is the instant a fresh registration fires at:
///   the instant itself for a one-shot, one interval after registration for a
///   fixed interval.
/// - [`Self::next_after`] is the instant that follows a firing. A one-shot has
///   none. A fixed interval that has fallen behind — the daemon was down, or
///   the automation was paused across several instants — advances to the first
///   instant *after* `now` and skips the ones between: the oldest due instant
///   fires once, and a burst of catch-up firings is never produced.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AutomationSchedule {
    /// Once, at an exact instant.
    Once {
        /// When.
        at: EpochMillis,
    },
    /// Every fixed interval, starting one interval after registration.
    Every {
        /// The interval.
        interval: FixedInterval,
    },
}

impl AutomationSchedule {
    /// The canonical spelling of the one-shot form.
    pub const ONCE: &'static str = "once";

    /// The canonical spelling of the fixed-interval form.
    pub const EVERY: &'static str = "every";

    /// The canonical spelling of the form this lane refuses.
    pub const CRON: &'static str = "cron";

    /// A one-shot schedule.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::TimeBeforeEpoch`] for an instant the
    /// registry's `next_fire_at_ms >= 0` constraint cannot hold.
    pub fn once(at: EpochMillis) -> Result<Self, AutomationApiError> {
        if at.as_millis() < 0 {
            return Err(AutomationApiError::TimeBeforeEpoch { field: "schedule" });
        }
        Ok(Self::Once { at })
    }

    /// A fixed-interval schedule.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::InvalidSchedule`] for a non-positive
    /// interval.
    pub fn every(interval_ms: i64) -> Result<Self, AutomationApiError> {
        Ok(Self::Every {
            interval: FixedInterval::new(interval_ms)
                .map_err(|_| AutomationApiError::InvalidSchedule)?,
        })
    }

    /// Project a canonical schedule onto the forms this lane carries.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::UnsupportedSchedule`] for the cron form
    /// and [`AutomationApiError::TimeBeforeEpoch`] for a one-shot before the
    /// epoch.
    pub fn from_canonical(schedule: CanonicalSchedule) -> Result<Self, AutomationApiError> {
        match schedule {
            CanonicalSchedule::Once { at } => Self::once(at),
            CanonicalSchedule::Every { interval } => Ok(Self::Every { interval }),
            CanonicalSchedule::Cron { .. } => {
                Err(AutomationApiError::UnsupportedSchedule { kind: Self::CRON })
            }
        }
    }

    /// Parse an operator's expression.
    ///
    /// Accepts what [`CanonicalSchedule::parse`] accepts — a canonical
    /// rendering or one of the recognized natural-language phrases — and then
    /// projects it. A phrase that resolves to cron (`daily`) is therefore a
    /// typed [`AutomationApiError::UnsupportedSchedule`], not an ambiguity.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::InvalidSchedule`] for anything that does
    /// not resolve to exactly one canonical schedule, and the projection's own
    /// refusals.
    pub fn parse(expression: &str) -> Result<Self, AutomationApiError> {
        let canonical = CanonicalSchedule::parse(expression)
            .map_err(|_| AutomationApiError::InvalidSchedule)?;
        Self::from_canonical(canonical)
    }

    /// Read a canonical rendering back.
    ///
    /// This is what the wire decoder uses: it accepts exactly what
    /// [`Self::render`] writes, so an operator's prose has no way onto the wire.
    ///
    /// # Errors
    ///
    /// As [`Self::parse`], for a rendering rather than an expression.
    pub fn from_rendering(rendered: &str) -> Result<Self, AutomationApiError> {
        let canonical = CanonicalSchedule::from_rendering(rendered)
            .map_err(|_| AutomationApiError::InvalidSchedule)?;
        Self::from_canonical(canonical)
    }

    /// This schedule in the rich model's own type.
    #[must_use]
    pub fn canonical(&self) -> CanonicalSchedule {
        match self {
            Self::Once { at } => CanonicalSchedule::Once { at: *at },
            Self::Every { interval } => CanonicalSchedule::Every {
                interval: *interval,
            },
        }
    }

    /// The canonical rendering, which is also the wire spelling.
    #[must_use]
    pub fn render(&self) -> String {
        self.canonical().render()
    }

    /// The canonical spelling of this schedule's form.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Once { .. } => Self::ONCE,
            Self::Every { .. } => Self::EVERY,
        }
    }

    /// The instant a registration at `registered_at` first fires at.
    ///
    /// `None` when a fixed interval would carry the instant past the end of
    /// representable time, which is a schedule that never fires rather than
    /// one that fires at a wrapped instant.
    #[must_use]
    pub fn first_occurrence(&self, registered_at: EpochMillis) -> Option<EpochMillis> {
        match self {
            Self::Once { at } => Some(*at),
            Self::Every { interval } => registered_at
                .as_millis()
                .checked_add(interval.as_millis())
                .map(EpochMillis::from_millis),
        }
    }

    /// The instant that follows a firing at `fired_at`, as judged at `now`.
    ///
    /// A one-shot has no successor. A fixed interval's successor is the first
    /// multiple of the interval after `fired_at` that is *later than* `now`:
    /// when the lane has kept up that is simply the next instant, and when it
    /// has fallen behind the instants in between are skipped rather than
    /// fired in a burst.
    #[must_use]
    pub fn next_after(&self, fired_at: EpochMillis, now: EpochMillis) -> Option<EpochMillis> {
        let Self::Every { interval } = self else {
            return None;
        };
        let interval = interval.as_millis();
        let mut next = fired_at.as_millis().checked_add(interval)?;
        if next <= now.as_millis() {
            let behind = now.as_millis() - next;
            let skipped = (behind / interval).checked_add(1)?;
            next = next.checked_add(skipped.checked_mul(interval)?)?;
        }
        Some(EpochMillis::from_millis(next))
    }
}

impl fmt::Display for AutomationSchedule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.render())
    }
}

/// The identity of one firing: `automation:<automation_id>:<instant>`.
///
/// This is the idempotency key the occurrence is submitted under on the
/// durable synthetic lane, and the work identity it is admitted under in the
/// durable scheduler core. Both dedupe on it, which is what makes "an
/// occurrence fires at most once" true across a replayed tick, a daemon
/// restart and a re-elected generation: whoever derives it derives the same
/// bytes.
///
/// The rich model's [`crate::automation::OccurrenceKey`] spells the same fact
/// as `<id>@<ms>`; this lane's spelling is the one the durable submit lane's
/// key grammar and namespace discipline call for, and the two are not mixed.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AutomationOccurrenceKey(String);

impl AutomationOccurrenceKey {
    /// Derive the key for one automation at one instant.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::TimeBeforeEpoch`] for an instant before
    /// the epoch and [`AutomationApiError::OccurrenceKeyTooLong`] when the
    /// derived key would not fit the durable submit lane's key bound — which
    /// [`RegisterAutomation::new`] already rules out for a scheduled identity.
    pub fn derive(
        automation_id: &AutomationId,
        at: EpochMillis,
    ) -> Result<Self, AutomationApiError> {
        if at.as_millis() < 0 {
            return Err(AutomationApiError::TimeBeforeEpoch {
                field: "occurrence_instant",
            });
        }
        let key = format!(
            "{OCCURRENCE_KEY_PREFIX}{}:{}",
            automation_id.as_str(),
            at.as_millis()
        );
        if key.len() > MAX_OCCURRENCE_KEY_BYTES {
            return Err(AutomationApiError::OccurrenceKeyTooLong {
                max_bytes: MAX_OCCURRENCE_KEY_BYTES,
            });
        }
        Ok(Self(key))
    }

    /// Read a key back into the automation and instant it names.
    ///
    /// The instant is the trailing canonical decimal, so an identity carrying
    /// a colon reads back whole: the split is from the right, and an identity
    /// cannot end in the digits-only tail because a colon separates them.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::OccurrenceKeyMalformed`] for anything
    /// [`Self::derive`] could not have produced.
    pub fn parse(key: &str) -> Result<(AutomationId, EpochMillis), AutomationApiError> {
        const MALFORMED: AutomationApiError = AutomationApiError::OccurrenceKeyMalformed;
        if key.len() > MAX_OCCURRENCE_KEY_BYTES {
            return Err(MALFORMED);
        }
        let rest = key.strip_prefix(OCCURRENCE_KEY_PREFIX).ok_or(MALFORMED)?;
        let (identity, instant) = rest.rsplit_once(':').ok_or(MALFORMED)?;
        let millis = instant.parse::<i64>().map_err(|_| MALFORMED)?;
        if millis < 0 || millis.to_string() != instant {
            return Err(MALFORMED);
        }
        let automation_id = AutomationId::new(identity).map_err(|_| MALFORMED)?;
        Ok((automation_id, EpochMillis::from_millis(millis)))
    }

    /// The derived key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AutomationOccurrenceKey {
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

/// One automation job presented for registration.
///
/// The initial enablement is not a field: registration always writes `enabled`
/// at revision one with no cause, which is
/// [`crate::automation::AutomationEnablement::newly_declared`]. An operator who
/// wants a paused automation registers it and pauses it, and the pause then
/// carries the cause it owes.
///
/// The job is the schedule, the scope and the prompt, all three required: a
/// registration that fires nothing is not a shape this lane offers. Rows
/// registered before the job existed are still served — see
/// [`AutomationRecordView::schedule`] — but no new one is written without one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterAutomation {
    automation_id: AutomationId,
    actor: AutomationActor,
    schedule: AutomationSchedule,
    scope: AutomationScope,
    prompt: AutomationPrompt,
}

impl RegisterAutomation {
    /// Declare one automation job.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::Field`] for `automation_id` when the
    /// identity is longer than [`MAX_SCHEDULED_AUTOMATION_ID_BYTES`]: the
    /// occurrence key derived from it must fit the durable submit lane's key
    /// bound, and an identity that cannot fire is refused before a frame is
    /// spent rather than registered and never fired.
    pub fn new(
        automation_id: AutomationId,
        actor: AutomationActor,
        schedule: AutomationSchedule,
        scope: AutomationScope,
        prompt: AutomationPrompt,
    ) -> Result<Self, AutomationApiError> {
        if automation_id.as_str().len() > MAX_SCHEDULED_AUTOMATION_ID_BYTES {
            return Err(AutomationApiError::Field {
                field: "automation_id",
                error: ValueError::TooLong {
                    max_bytes: MAX_SCHEDULED_AUTOMATION_ID_BYTES,
                    actual_bytes: automation_id.as_str().len(),
                },
            });
        }
        Ok(Self {
            automation_id,
            actor,
            schedule,
            scope,
            prompt,
        })
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

    /// When occurrences fire.
    #[must_use]
    pub const fn schedule(&self) -> &AutomationSchedule {
        &self.schedule
    }

    /// The scope every occurrence is serialized under.
    #[must_use]
    pub const fn scope(&self) -> &AutomationScope {
        &self.scope
    }

    /// The task every occurrence submits.
    #[must_use]
    pub const fn prompt(&self) -> &AutomationPrompt {
        &self.prompt
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
            (
                "prompt".to_owned(),
                JsonValue::String(self.prompt.as_str().to_owned()),
            ),
            (
                "schedule".to_owned(),
                JsonValue::String(self.schedule.render()),
            ),
            (
                "scope".to_owned(),
                JsonValue::String(self.scope.as_str().to_owned()),
            ),
        ])
    }

    fn from_body(body: &JsonValue) -> Result<Self, AutomationApiError> {
        exact_fields(
            body,
            &["actor", "automation_id", "prompt", "schedule", "scope"],
        )?;
        Self::new(
            AutomationId::new(required_string(body, "automation_id")?)?,
            actor(&required_string(body, "actor")?)?,
            AutomationSchedule::from_rendering(&required_string(body, "schedule")?)?,
            AutomationScope::new(required_string(body, "scope")?)?,
            AutomationPrompt::new(required_string(body, "prompt")?)?,
        )
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
///
/// The prompt is deliberately not a column here: at its bound it is thirty
/// times the size of every other field together, and a listing that carried
/// it would hold three rows per frame. A detail read carries it beside the
/// record — see [`AutomationResponse::AutomationDetail`].
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
    schedule: Option<AutomationSchedule>,
    scope: Option<AutomationScope>,
    next_fire_at: Option<EpochMillis>,
    last_fired_at: Option<EpochMillis>,
}

impl AutomationRecordView {
    /// Record one automation, refusing every row this product could not have
    /// written.
    ///
    /// The same cross-column invariants the store re-derives on every read are
    /// re-derived here, because a wire value is read by clients the store
    /// never sees:
    ///
    /// - a withdrawn state and a stated cause imply each other;
    /// - a withdrawn state implies revision two or above, because registration
    ///   is the only writer of revision one and it always writes `enabled`;
    /// - every timestamp is at or after the epoch; and
    /// - a schedule and a scope imply each other, and a next or last execution
    ///   implies a schedule. A row with neither is a registration from before
    ///   jobs existed: served, listed, and never fired.
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
    /// [`AutomationApiError::WithdrawnAtFirstRevision`],
    /// [`AutomationApiError::TimeBeforeEpoch`] or
    /// [`AutomationApiError::JobIncoherent`].
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
            schedule,
            scope,
            next_fire_at,
            last_fired_at,
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
        for (field, instant) in [
            ("created_at_ms", Some(created_at)),
            ("updated_at_ms", Some(updated_at)),
            ("next_fire_at_ms", next_fire_at),
            ("last_fired_at_ms", last_fired_at),
        ] {
            if instant.is_some_and(|instant| instant.as_millis() < 0) {
                return Err(AutomationApiError::TimeBeforeEpoch { field });
            }
        }
        if schedule.is_some() != scope.is_some()
            || (schedule.is_none() && (next_fire_at.is_some() || last_fired_at.is_some()))
        {
            return Err(AutomationApiError::JobIncoherent);
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
            schedule,
            scope,
            next_fire_at,
            last_fired_at,
        })
    }

    /// When occurrences fire, or `None` for a row registered before jobs
    /// existed — which is listed truthfully and fires nothing.
    #[must_use]
    pub const fn schedule(&self) -> Option<&AutomationSchedule> {
        self.schedule.as_ref()
    }

    /// The scope occurrences are serialized under. `Some` exactly when
    /// [`Self::schedule`] is.
    #[must_use]
    pub const fn scope(&self) -> Option<&AutomationScope> {
        self.scope.as_ref()
    }

    /// The instant the next occurrence is due, or `None` when nothing further
    /// is scheduled: a one-shot that has fired, or a row with no job.
    #[must_use]
    pub const fn next_fire_at(&self) -> Option<EpochMillis> {
        self.next_fire_at
    }

    /// The scheduled instant of the last occurrence the daemon submitted, or
    /// `None` when none has been.
    #[must_use]
    pub const fn last_fired_at(&self) -> Option<EpochMillis> {
        self.last_fired_at
    }

    /// Whether this row carries a job at all.
    #[must_use]
    pub const fn is_scheduled(&self) -> bool {
        self.schedule.is_some()
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
    /// The enablement half of the question, exactly as
    /// [`crate::automation::EnablementState::admits_occurrence`] answers it: the
    /// operator has not withdrawn this automation. Whether anything is *due*
    /// is [`Self::next_fire_at`], and a row with no job admits an occurrence
    /// it will never have.
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

    /// The record's members, in canonical key order.
    ///
    /// One list for both the page item and the detail body, so the two cannot
    /// disagree about a column; the detail body appends its prompt to this.
    fn body_members(&self) -> Result<Vec<(String, JsonValue)>, AutomationApiError> {
        Ok(vec![
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
            (
                "last_fired_at_ms".to_owned(),
                optional_instant(self.last_fired_at),
            ),
            (
                "next_fire_at_ms".to_owned(),
                optional_instant(self.next_fire_at),
            ),
            ("revision".to_owned(), integer("revision", self.revision)?),
            (
                "schedule".to_owned(),
                self.schedule.as_ref().map_or(JsonValue::Null, |schedule| {
                    JsonValue::String(schedule.render())
                }),
            ),
            (
                "scope".to_owned(),
                self.scope.as_ref().map_or(JsonValue::Null, |scope| {
                    JsonValue::String(scope.as_str().to_owned())
                }),
            ),
            (
                "updated_at_ms".to_owned(),
                JsonValue::Integer(self.updated_at.as_millis()),
            ),
        ])
    }

    /// The exact key set a record body carries.
    const FIELDS: [&'static str; 12] = [
        "actor",
        "automation_id",
        "cause",
        "created_at_ms",
        "enablement",
        "entry_id",
        "last_fired_at_ms",
        "next_fire_at_ms",
        "revision",
        "schedule",
        "scope",
        "updated_at_ms",
    ];

    fn to_body(&self) -> Result<JsonValue, AutomationApiError> {
        Ok(JsonValue::Object(self.body_members()?))
    }

    /// Read the record members out of a body that may carry more than them.
    ///
    /// The caller has already judged the exact key set, so this reads by name
    /// and never by position.
    fn from_members(body: &JsonValue) -> Result<Self, AutomationApiError> {
        let cause = match body.get("cause") {
            Some(JsonValue::Null) => None,
            Some(JsonValue::String(_)) => Some(PauseReason::new(required_string(body, "cause")?)?),
            _ => return Err(AutomationApiError::InvalidBody),
        };
        let schedule = match body.get("schedule") {
            Some(JsonValue::Null) => None,
            Some(JsonValue::String(rendered)) => {
                Some(AutomationSchedule::from_rendering(rendered)?)
            }
            _ => return Err(AutomationApiError::InvalidBody),
        };
        let scope = match body.get("scope") {
            Some(JsonValue::Null) => None,
            Some(JsonValue::String(_)) => {
                Some(AutomationScope::new(required_string(body, "scope")?)?)
            }
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
            schedule,
            scope,
            next_fire_at: optional_signed(body, "next_fire_at_ms")?.map(EpochMillis::from_millis),
            last_fired_at: optional_signed(body, "last_fired_at_ms")?.map(EpochMillis::from_millis),
        })
    }

    fn from_body(body: &JsonValue) -> Result<Self, AutomationApiError> {
        exact_fields(body, &Self::FIELDS)?;
        Self::from_members(body)
    }
}

/// The twelve columns one automation row carries.
///
/// A parameter object rather than twelve positional arguments: two `u64`
/// revisions and four `EpochMillis` instants sit beside one another, and a
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
    /// When occurrences fire. `None` for a row registered before jobs existed.
    pub schedule: Option<AutomationSchedule>,
    /// The scope occurrences are serialized under. `Some` exactly when
    /// `schedule` is.
    pub scope: Option<AutomationScope>,
    /// The instant the next occurrence is due, when one is.
    pub next_fire_at: Option<EpochMillis>,
    /// The scheduled instant of the last submitted occurrence, when one was.
    pub last_fired_at: Option<EpochMillis>,
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
    ///
    /// The prompt travels here and only here: a listing omits it because at
    /// its bound it dwarfs every other column, and a detail read is the one
    /// answer an operator asks for one row at a time. `Some` exactly when the
    /// record carries a job; [`AutomationResponse::detail`] refuses the other
    /// pairings and the decoder re-decides them.
    AutomationDetail {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// The record.
        record: AutomationRecordView,
        /// The task every occurrence submits, when the record has a job.
        prompt: Option<AutomationPrompt>,
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
    /// distinction is the honest one — the durable row *is* committed, and what
    /// it authorizes happens later and elsewhere: the scheduler worker reads
    /// the row on its next tick, and an occurrence it derives is a run with
    /// its own durable outcome. `accepted` says "recorded"; `completed` would
    /// say the decision took effect, which no write on this lane can know at
    /// the moment it answers.
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

    /// Answer a detail read.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationApiError::JobIncoherent`] when the prompt and the
    /// record's job disagree about whether there is one: a scheduled row with
    /// no prompt would be a job that submits nothing, and a prompt on a row
    /// with no schedule would be a task nothing ever fires.
    pub fn detail(
        request_id: RequestId,
        record: AutomationRecordView,
        prompt: Option<AutomationPrompt>,
    ) -> Result<Self, AutomationApiError> {
        if record.is_scheduled() != prompt.is_some() {
            return Err(AutomationApiError::JobIncoherent);
        }
        Ok(Self::AutomationDetail {
            request_id,
            record,
            prompt,
        })
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
            Self::AutomationDetail {
                request_id,
                record,
                prompt,
            } => {
                let mut members = record.body_members()?;
                // Canonical key order: `prompt` sorts between `next_fire_at_ms`
                // and `revision`, and the codec insists on the sorted order.
                let position = members
                    .iter()
                    .position(|(name, _)| name.as_str() > "prompt")
                    .unwrap_or(members.len());
                members.insert(
                    position,
                    (
                        "prompt".to_owned(),
                        prompt.as_ref().map_or(JsonValue::Null, |prompt| {
                            JsonValue::String(prompt.as_str().to_owned())
                        }),
                    ),
                );
                Ok(Message::new(
                    envelope(request_id.clone(), "automation_detail_result")?,
                    JsonValue::Object(members),
                ))
            }
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
            "automation_detail_result" => {
                let mut fields: Vec<&str> = AutomationRecordView::FIELDS.to_vec();
                fields.push("prompt");
                exact_fields(message.body(), &fields)?;
                let prompt = match message.body().get("prompt") {
                    Some(JsonValue::Null) => None,
                    Some(JsonValue::String(_)) => Some(AutomationPrompt::new(required_string(
                        message.body(),
                        "prompt",
                    )?)?),
                    _ => return Err(AutomationApiError::InvalidBody),
                };
                Self::detail(
                    request_id,
                    AutomationRecordView::from_members(message.body())?,
                    prompt,
                )
            }
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

/// A member that is always present and is either an integer or `null`.
fn optional_signed(
    body: &JsonValue,
    field: &'static str,
) -> Result<Option<i64>, AutomationApiError> {
    match body.get(field) {
        Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::Integer(value)) => Ok(Some(*value)),
        _ => Err(AutomationApiError::InvalidBody),
    }
}

fn optional_instant(instant: Option<EpochMillis>) -> JsonValue {
    instant.map_or(JsonValue::Null, |instant| {
        JsonValue::Integer(instant.as_millis())
    })
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
