// SPDX-License-Identifier: Elastic-2.0

//! Canonical schedules, occurrence keys, goals, jobs and inbound triggers.
//!
//! Work that starts without a person present has to be reconstructible. A
//! schedule is stored only in canonical form, an occurrence key makes duplicate
//! firing detectable without coordination, and a goal's completion cannot rest
//! on prose when its contract demanded artifacts.
//!
//! Nothing here runs a scheduler, fires anything, holds a lease, verifies a
//! webhook signature or calls a model. In particular no timezone database is
//! consulted and no wall-clock arithmetic is performed: a canonical schedule
//! *records* a zone and a DST policy, and this module round-trips that record.
//!
//! Each compile-fail proof below is paired with a passing case differing only
//! in the rejected thing, so an unrelated compilation failure cannot be
//! mistaken for the property under test.
//!
//! # A completion cannot be built from evidence the contract did not name
//!
//! A goal that demands an artifact is completed with an artifact:
//!
//! ```
//! use automonique_protocol::automation::{ArtifactEvidence, Goal, GoalVerdict};
//! let goal: Goal<ArtifactEvidence> = Goal::declare("g-1").unwrap();
//! let verdict = goal.complete_with(ArtifactEvidence::new("sha256:bundle", "built the bundle").unwrap());
//! assert!(matches!(verdict, GoalVerdict::Complete { .. }));
//! ```
//!
//! and cannot be completed with prose instead:
//!
//! ```compile_fail
//! use automonique_protocol::automation::{ArtifactEvidence, Goal, NarrativeEvidence};
//! let goal: Goal<ArtifactEvidence> = Goal::declare("g-1").unwrap();
//! let verdict = goal.complete_with(NarrativeEvidence::new("it looks done").unwrap());
//! ```
//!
//! The verdict is not a way around that either. A `Complete` verdict carries no
//! free-text field — its paired passing case is the example above, which builds
//! the same variant through the goal:
//!
//! ```compile_fail
//! use automonique_protocol::automation::GoalVerdict;
//! let verdict = GoalVerdict::Complete { evidence: String::from("it looks done") };
//! ```
//!
//! That one is refused by the field name. What `Complete` does carry is a
//! [`CompletionRecord`], and every field of it is private, so the record has to
//! come out of the goal rather than be assembled beside it. Read back through
//! its accessors,
//!
//! ```
//! use automonique_protocol::automation::{
//!     ArtifactEvidence, CompletionEvidenceKind, Goal, GoalVerdict,
//! };
//! let goal: Goal<ArtifactEvidence> = Goal::declare("g-1").unwrap();
//! let verdict = goal.complete_with(ArtifactEvidence::new("sha256:bundle", "built it").unwrap());
//! let GoalVerdict::Complete { record } = verdict else { panic!("a completed goal") };
//! assert_eq!(record.goal_id(), "g-1");
//! assert_eq!(record.kind(), CompletionEvidenceKind::Artifact);
//! assert_eq!(record.reference(), Some("sha256:bundle"));
//! assert_eq!(record.statement().as_str(), "built it");
//! ```
//!
//! and the same four values written directly into the record they came from:
//!
//! ```compile_fail
//! use automonique_protocol::automation::{
//!     CompletionEvidenceKind, CompletionRecord, GoalVerdict, VerdictEvidence,
//! };
//! let record = CompletionRecord {
//!     goal_id: String::from("g-1"),
//!     kind: CompletionEvidenceKind::Artifact,
//!     reference: Some(String::from("sha256:never-built")),
//!     statement: VerdictEvidence::new("it looks done").unwrap(),
//! };
//! let verdict = GoalVerdict::Complete { record };
//! ```
//!
//! What that does not say, because it would not be true: the binding between a
//! goal identity and its completion contract lives in the [`Goal`] value's type
//! parameter, and nothing here registers it. A second `Goal<NarrativeEvidence>`
//! declared with the same identity is constructible and closes on prose. The
//! record names the goal it closed and the kind that closed it, so a consumer
//! holding the real contract for that identity can detect such a completion —
//! this slice makes it *detectable*, not impossible. See [`CompletionRecord`].
//!
//! # An out-of-scope effect cannot become a completed effect
//!
//! A pre-approved effect yields a token that records a completion:
//!
//! ```
//! use automonique_protocol::automation::{
//!     AutomationRevision, CanonicalSchedule, CompletedEffect, UnattendedDecision,
//! };
//! use automonique_protocol::primitives::Revision;
//! let automation = AutomationRevision::new(
//!     "auto-1",
//!     Revision::FIRST,
//!     CanonicalSchedule::every(60_000).unwrap(),
//!     &["notify:slack"],
//! )
//! .unwrap();
//! let UnattendedDecision::PreApproved(approved) = automation.decide_unattended("notify:slack") else {
//!     panic!("declared effect");
//! };
//! let done = CompletedEffect::record(approved, "outbox:receipt-1").unwrap();
//! assert_eq!(done.effect(), "notify:slack");
//! ```
//!
//! An effect outside the declared scope produces an approval request, and an
//! approval request is not spendable as authority:
//!
//! ```compile_fail
//! use automonique_protocol::automation::{
//!     AutomationRevision, CanonicalSchedule, CompletedEffect, UnattendedDecision,
//! };
//! use automonique_protocol::primitives::Revision;
//! let automation = AutomationRevision::new(
//!     "auto-1",
//!     Revision::FIRST,
//!     CanonicalSchedule::every(60_000).unwrap(),
//!     &["notify:slack"],
//! )
//! .unwrap();
//! let UnattendedDecision::RequiresApproval(request) = automation.decide_unattended("deploy:production") else {
//!     panic!("undeclared effect");
//! };
//! let done = CompletedEffect::record(request, "outbox:receipt-1").unwrap();
//! ```
//!
//! # A wake resolves a context, never a label
//!
//! ```
//! use automonique_protocol::automation::{DurableId, Wake, WaitCondition, WakeContext};
//! let wake = Wake::resolve(
//!     WakeContext::Goal(DurableId::new("g-1").unwrap()),
//!     WaitCondition::Run { run_id: DurableId::new("run-1").unwrap() },
//! );
//! assert_eq!(wake.context_id(), "g-1");
//! ```
//!
//! ```compile_fail
//! use automonique_protocol::automation::{DurableId, Wake, WaitCondition};
//! let wake = Wake::resolve(
//!     "the goal about the build",
//!     WaitCondition::Run { run_id: DurableId::new("run-1").unwrap() },
//! );
//! ```
//!
//! # A label is not a tenancy control
//!
//! ```
//! use automonique_protocol::automation::{
//!     BoardClaim, BoardClaimParts, ClaimLabel, FailureLedger, Tenancy,
//! };
//! let claim = BoardClaim::claim(BoardClaimParts {
//!     task: "task-1",
//!     worker: "worker-1",
//!     tenant: Tenancy::new("acme").unwrap(),
//!     epoch: 7,
//!     labels: vec![ClaimLabel::new("tenant:globex").unwrap()],
//!     failures: FailureLedger::declare(3).unwrap(),
//! })
//! .unwrap();
//! assert!(!claim.authorizes(&Tenancy::new("globex").unwrap(), 7));
//! ```
//!
//! ```compile_fail
//! use automonique_protocol::automation::{
//!     BoardClaim, BoardClaimParts, ClaimLabel, FailureLedger,
//! };
//! let claim = BoardClaim::claim(BoardClaimParts {
//!     task: "task-1",
//!     worker: "worker-1",
//!     tenant: ClaimLabel::new("tenant:acme").unwrap(),
//!     epoch: 7,
//!     labels: Vec::new(),
//!     failures: FailureLedger::declare(3).unwrap(),
//! })
//! .unwrap();
//! ```
//!
//! # A job that skips the model has no cheaper constructor
//!
//! ```
//! use automonique_protocol::automation::{
//!     AuthorizedDestination, AutomationJob, JobKind, JobObligations, OutboxObligation, Tenancy,
//! };
//! let obligations = JobObligations::new(
//!     "auto-1",
//!     Tenancy::new("acme").unwrap(),
//!     "workspace-offline",
//!     OutboxObligation::new(
//!         AuthorizedDestination::new("slack:C1", "grant:slack-post").unwrap(),
//!         "outbox:auto-1",
//!     )
//!     .unwrap(),
//! )
//! .unwrap();
//! let job = AutomationJob::declare(JobKind::Script, obligations);
//! assert_eq!(job.kind(), JobKind::Script);
//! ```
//!
//! ```compile_fail
//! use automonique_protocol::automation::{AutomationJob, JobKind};
//! let job = AutomationJob::declare(JobKind::Script);
//! ```
//!
//! # A condition is a vocabulary, not an expression language
//!
//! A pattern predicate takes a [`BoundedPattern`], which refuses an unbounded
//! quantifier before the value exists:
//!
//! ```
//! use automonique_protocol::automation::{BoundedPattern, FilterExpression, FilterPredicate};
//! let pattern = BoundedPattern::new("build-[a-z]{1,8}").unwrap();
//! let condition =
//!     FilterExpression::field("event.name", FilterPredicate::Matches { pattern }).unwrap();
//! assert_eq!(condition.render(), "matches(event.name,16:build-[a-z]{1,8})");
//! assert!(BoundedPattern::new("build-[a-z]+").is_err());
//! ```
//!
//! and there is no way to hand it text instead, so a filter cannot be widened
//! into something that has to be evaluated:
//!
//! ```compile_fail
//! use automonique_protocol::automation::{FilterExpression, FilterPredicate};
//! let condition = FilterExpression::field(
//!     "event.name",
//!     FilterPredicate::Matches { pattern: String::from("build-[a-z]+") },
//! )
//! .unwrap();
//! ```
//!
//! # A trigger fires an action only inside declared scope
//!
//! ```
//! use automonique_protocol::automation::{
//!     ActionBinding, AutomationAction, AutomationRevision, CanonicalSchedule, CompletedEffect,
//!     TriggerSpec,
//! };
//! use automonique_protocol::primitives::Revision;
//! let automation = AutomationRevision::new(
//!     "auto-1",
//!     Revision::FIRST,
//!     CanonicalSchedule::every(60_000).unwrap(),
//!     &["command:pause_intake"],
//! )
//! .unwrap();
//! let trigger = TriggerSpec::manual("ada").unwrap();
//! let action = AutomationAction::command("pause_intake").unwrap();
//! let ActionBinding::Bound(bound) = automation.bind(&trigger, action).unwrap() else {
//!     panic!("declared effect");
//! };
//! let done = CompletedEffect::record(bound.into_approved(), "outbox:receipt-1").unwrap();
//! assert_eq!(done.effect(), "command:pause_intake");
//! ```
//!
//! [`BoundAction`]'s fields are private and it has no constructor, so the
//! binding cannot be assembled beside the automation that refused it:
//!
//! ```compile_fail
//! use automonique_protocol::automation::{
//!     ActionBinding, AutomationAction, BoundAction, TriggerSpec,
//! };
//! let binding = ActionBinding::Bound(BoundAction {
//!     automation_id: String::from("auto-1"),
//!     trigger: TriggerSpec::manual("ada").unwrap(),
//!     action: AutomationAction::command("deploy").unwrap(),
//! });
//! ```

use core::fmt;
use core::marker::PhantomData;
use std::error::Error;

use crate::command_registry::CommandId;
use crate::primitives::{EpochMillis, Revision, ValueError};

/// Maximum UTF-8 byte length of an automation field.
pub const MAX_AUTOMATION_FIELD_BYTES: usize = 256;

/// Why an automation or goal operation was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AutomationError {
    /// A natural-language expression did not resolve to one schedule.
    AmbiguousExpression {
        /// The reason it could not be resolved.
        reason: &'static str,
    },
    /// A value was not in the canonical form its position requires.
    NotCanonical {
        /// The field that was not canonical.
        field: &'static str,
        /// What canonical form requires.
        reason: &'static str,
    },
    /// An edit carried the wrong expected revision.
    RevisionConflict {
        /// The current revision.
        expected: u64,
        /// The revision the caller asserted.
        offered: u64,
    },
    /// An effect fell outside the automation's pre-approved scope.
    OutsideApprovedScope {
        /// The effect that was refused.
        effect: String,
    },
    /// An approval request was presented to a different automation.
    ApprovalMismatch {
        /// The automation the request was raised by.
        automation_id: String,
    },
    /// A completion claimed evidence its contract required and did not supply.
    CompletionEvidenceMissing {
        /// The evidence kind that was required.
        required: &'static str,
    },
    /// A name was offered that a closed vocabulary does not contain.
    ///
    /// Refused rather than defaulted: a stored trigger, action or predicate
    /// this build does not know is not silently read as a no-op.
    UnknownVocabulary {
        /// Which vocabulary was consulted.
        vocabulary: &'static str,
        /// The name that is not in it.
        requested: String,
    },
    /// An operation required an automation that was enabled.
    NotEnabled {
        /// The state the automation was actually in.
        state: &'static str,
    },
    /// A lifecycle transition the state machine does not permit.
    InvalidTransition {
        /// The state the automation was in.
        from: &'static str,
        /// The state the caller asked for.
        to: &'static str,
    },
    /// A bounded collection, nesting depth or repetition ceiling was exceeded.
    TooLarge {
        /// The field that was too large.
        field: &'static str,
        /// The declared ceiling.
        max: usize,
        /// What was supplied.
        actual: usize,
    },
    /// A bounded field was rejected.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
}

impl AutomationError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::AmbiguousExpression { .. } => "ambiguous_expression",
            Self::NotCanonical { .. } => "not_canonical",
            Self::RevisionConflict { .. } => "revision_conflict",
            Self::OutsideApprovedScope { .. } => "outside_approved_scope",
            Self::ApprovalMismatch { .. } => "approval_mismatch",
            Self::CompletionEvidenceMissing { .. } => "completion_evidence_missing",
            Self::UnknownVocabulary { .. } => "unknown_vocabulary",
            Self::NotEnabled { .. } => "not_enabled",
            Self::InvalidTransition { .. } => "invalid_transition",
            Self::TooLarge { .. } => "too_large",
            Self::Field { .. } => "field_invalid",
        }
    }
}

impl fmt::Display for AutomationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmbiguousExpression { reason } => {
                write!(formatter, "expression is ambiguous: {reason}")
            }
            Self::NotCanonical { field, reason } => {
                write!(formatter, "field {field} is not canonical: {reason}")
            }
            Self::RevisionConflict { expected, offered } => write!(
                formatter,
                "automation is at revision {expected}; the edit asserted {offered}"
            ),
            Self::OutsideApprovedScope { effect } => write!(
                formatter,
                "effect {effect} is outside the automation's pre-approved scope"
            ),
            Self::ApprovalMismatch { automation_id } => write!(
                formatter,
                "approval request belongs to automation {automation_id}"
            ),
            Self::CompletionEvidenceMissing { required } => write!(
                formatter,
                "completion requires {required} evidence, which was not supplied"
            ),
            Self::UnknownVocabulary {
                vocabulary,
                requested,
            } => write!(
                formatter,
                "{requested} is not a declared {vocabulary}; this build knows no such value"
            ),
            Self::NotEnabled { state } => write!(
                formatter,
                "the automation is {state}, so it admits no occurrence and binds no action"
            ),
            Self::InvalidTransition { from, to } => {
                write!(formatter, "an automation cannot go from {from} to {to}")
            }
            Self::TooLarge { field, max, actual } => write!(
                formatter,
                "field {field} admits at most {max}; {actual} were supplied"
            ),
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
        }
    }
}

impl Error for AutomationError {}

const fn not_canonical(field: &'static str, reason: &'static str) -> AutomationError {
    AutomationError::NotCanonical { field, reason }
}

const fn too_large(field: &'static str, max: usize, actual: usize) -> AutomationError {
    AutomationError::TooLarge { field, max, actual }
}

fn unknown_vocabulary(vocabulary: &'static str, requested: &str) -> AutomationError {
    AutomationError::UnknownVocabulary {
        vocabulary,
        requested: requested.to_owned(),
    }
}

/// The identity of something durable: a run, an event source, a monitor, a
/// goal, a job or a session.
///
/// Non-empty, bounded, control-free and free of whitespace, so a sentence
/// cannot occupy an identity position. This is what makes "resuming from a
/// free-text label" unrepresentable rather than merely discouraged.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DurableId(String);

impl DurableId {
    /// Validate and construct an identity.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an empty, over-long or control
    /// value and [`AutomationError::NotCanonical`] for anything containing
    /// whitespace.
    pub fn new(value: &str) -> Result<Self, AutomationError> {
        bounded(value, "durable_id")?;
        if value.chars().any(char::is_whitespace) {
            return Err(not_canonical(
                "durable_id",
                "an identity carries no whitespace, so prose cannot occupy one",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    /// The validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DurableId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A tenancy control.
///
/// A distinct type from [`ClaimLabel`]: an authorization decision accepts this
/// and nothing else, so a label cannot be passed where tenancy is required.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Tenancy(String);

impl Tenancy {
    /// Validate and construct a tenancy.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid value.
    pub fn new(tenant: &str) -> Result<Self, AutomationError> {
        bounded(tenant, "tenant")?;
        Ok(Self(tenant.to_owned()))
    }

    /// The tenant.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A free-form annotation on a board claim.
///
/// Carries no authority. There is no conversion from a label to a [`Tenancy`]
/// and no accessor on a claim that consults labels when authorizing.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClaimLabel(String);

impl ClaimLabel {
    /// Validate and construct a label.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid value.
    pub fn new(label: &str) -> Result<Self, AutomationError> {
        bounded(label, "claim_label")?;
        Ok(Self(label.to_owned()))
    }

    /// The label text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How a wall-clock schedule resolves a daylight-saving transition.
///
/// A canonical cron schedule always carries one. A zone without transitions
/// makes the choice inert, but never absent, so two operators reading the same
/// stored schedule read the same rule.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DstPolicy {
    /// A wall-clock time that does not exist is skipped; a repeated one fires
    /// on its first occurrence only.
    SkipMissingFireFirst,
    /// A wall-clock time that does not exist fires at the next existing
    /// instant; a repeated one fires on its second occurrence only.
    ShiftMissingFireSecond,
}

impl DstPolicy {
    /// Every policy, for coverage checks.
    pub const ALL: [Self; 2] = [Self::SkipMissingFireFirst, Self::ShiftMissingFireSecond];

    /// Stable spelling, used in the canonical rendering.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SkipMissingFireFirst => "skip_missing_fire_first",
            Self::ShiftMissingFireSecond => "shift_missing_fire_second",
        }
    }

    fn from_rendering(rendered: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|policy| policy.as_str() == rendered)
    }
}

/// A strictly positive repetition interval in milliseconds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FixedInterval(i64);

impl FixedInterval {
    /// Declare an interval.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::NotCanonical`] for a non-positive interval,
    /// which would fire without advancing.
    pub const fn new(interval_ms: i64) -> Result<Self, AutomationError> {
        if interval_ms <= 0 {
            return Err(not_canonical(
                "interval_ms",
                "a repetition interval is strictly positive",
            ));
        }
        Ok(Self(interval_ms))
    }

    /// The interval in milliseconds.
    #[must_use]
    pub const fn as_millis(self) -> i64 {
        self.0
    }
}

/// Month and weekday names a cron field may use in place of a number.
const CRON_NAMES: [&str; 19] = [
    "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC", "SUN",
    "MON", "TUE", "WED", "THU", "FRI", "SAT",
];

/// A five-field cron expression.
///
/// Grammar only: five space-separated fields, each a comma-separated list of
/// `*`, `?`, a number, a name, or a range, optionally with a `/step`. This
/// slice computes no occurrence, so a number is not checked against the range
/// of the field it appears in; what is checked is that the value is a cron
/// expression rather than a sentence.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CronExpression(String);

impl CronExpression {
    /// Validate and construct an expression.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid value and
    /// [`AutomationError::NotCanonical`] when the value is not five cron
    /// fields.
    pub fn new(expression: &str) -> Result<Self, AutomationError> {
        bounded(expression, "cron_expression")?;
        let mut fields = 0_usize;
        for field in expression.split(' ') {
            fields += 1;
            if !is_cron_field(field) {
                return Err(not_canonical(
                    "cron_expression",
                    "a field is a comma-separated list of *, ?, numbers, names, ranges and steps",
                ));
            }
        }
        if fields != 5 {
            return Err(not_canonical(
                "cron_expression",
                "a canonical cron expression has exactly five fields",
            ));
        }
        Ok(Self(expression.to_owned()))
    }

    /// The validated expression.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_cron_field(field: &str) -> bool {
    !field.is_empty() && field.split(',').all(is_cron_item)
}

fn is_cron_item(item: &str) -> bool {
    let (range, step) = match item.split_once('/') {
        Some((range, step)) => (range, Some(step)),
        None => (item, None),
    };
    if let Some(step) = step
        && (step.is_empty() || !step.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    if range == "*" || range == "?" {
        return true;
    }
    match range.split_once('-') {
        Some((low, high)) => is_cron_value(low) && is_cron_value(high),
        None => is_cron_value(range),
    }
}

fn is_cron_value(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    value.bytes().all(|byte| byte.is_ascii_digit())
        || CRON_NAMES
            .iter()
            .any(|name| value.eq_ignore_ascii_case(name))
}

/// An IANA timezone name.
///
/// Syntactic only: no timezone database is consulted and no offset is derived.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Timezone(String);

impl Timezone {
    /// Validate and construct a timezone name.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid value and
    /// [`AutomationError::NotCanonical`] when the name is not slash-separated
    /// alphanumeric segments.
    pub fn new(name: &str) -> Result<Self, AutomationError> {
        bounded(name, "timezone")?;
        let mut segments = 0_usize;
        for segment in name.split('/') {
            segments += 1;
            if segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'+'))
            {
                return Err(not_canonical(
                    "timezone",
                    "an IANA name is one to three slash-separated alphanumeric segments",
                ));
            }
        }
        if segments > 3 {
            return Err(not_canonical(
                "timezone",
                "an IANA name is one to three slash-separated alphanumeric segments",
            ));
        }
        Ok(Self(name.to_owned()))
    }

    /// The validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A schedule in canonical form.
///
/// Prose is not a variant. A natural-language expression is parsed into one of
/// these or refused; it is never stored as written. Every component is a
/// validated type, so a schedule that could not be rendered and read back is
/// not constructible.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CanonicalSchedule {
    /// Once, at an exact instant.
    Once {
        /// When.
        at: EpochMillis,
    },
    /// Every fixed interval.
    Every {
        /// The interval.
        interval: FixedInterval,
    },
    /// A five-field cron expression in an explicit zone with an explicit DST
    /// policy.
    Cron {
        /// The canonical five-field expression.
        expression: CronExpression,
        /// The IANA timezone.
        timezone: Timezone,
        /// How a daylight-saving transition resolves.
        dst_policy: DstPolicy,
    },
}

impl CanonicalSchedule {
    /// A one-shot schedule.
    #[must_use]
    pub const fn once(at: EpochMillis) -> Self {
        Self::Once { at }
    }

    /// A fixed-interval schedule.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::NotCanonical`] for a non-positive interval.
    pub fn every(interval_ms: i64) -> Result<Self, AutomationError> {
        Ok(Self::Every {
            interval: FixedInterval::new(interval_ms)?,
        })
    }

    /// A cron schedule.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::NotCanonical`] for an expression or zone that
    /// is not canonical.
    pub fn cron(
        expression: &str,
        timezone: &str,
        dst_policy: DstPolicy,
    ) -> Result<Self, AutomationError> {
        Ok(Self::Cron {
            expression: CronExpression::new(expression)?,
            timezone: Timezone::new(timezone)?,
            dst_policy,
        })
    }

    /// Parse an expression into canonical form.
    ///
    /// Accepts a canonical rendering — the output of [`Self::render`] — and the
    /// recognized natural-language expressions. Everything else is refused.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::NotCanonical`] when the expression opens with
    /// a canonical prefix but is malformed, and
    /// [`AutomationError::AmbiguousExpression`] for anything that does not
    /// resolve to exactly one schedule. A best guess is not an outcome.
    pub fn parse(expression: &str) -> Result<Self, AutomationError> {
        bounded(expression, "expression")?;
        let trimmed = expression.trim();
        if trimmed.starts_with("once@")
            || trimmed.starts_with("every@")
            || trimmed.starts_with("cron@")
        {
            return Self::from_rendering(trimmed);
        }
        match trimmed.to_lowercase().as_str() {
            "every hour" | "hourly" => Self::every(60 * 60 * 1_000),
            "every day" | "daily" => {
                Self::cron("0 0 * * *", "UTC", DstPolicy::SkipMissingFireFirst)
            }
            _ => Err(AutomationError::AmbiguousExpression {
                reason: "no single canonical schedule matches",
            }),
        }
    }

    /// Read a canonical rendering back.
    ///
    /// This is the reader storage uses: it accepts exactly what [`Self::render`]
    /// writes and nothing else, so prose has no way into stored state.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::NotCanonical`] for anything that is not a
    /// canonical rendering.
    pub fn from_rendering(rendered: &str) -> Result<Self, AutomationError> {
        if let Some(rest) = rendered.strip_prefix("once@") {
            return Ok(Self::Once {
                at: EpochMillis::from_millis(canonical_decimal(rest, "once")?),
            });
        }
        if let Some(rest) = rendered.strip_prefix("every@") {
            return Ok(Self::Every {
                interval: FixedInterval::new(canonical_decimal(rest, "every")?)?,
            });
        }
        let Some(rest) = rendered.strip_prefix("cron@") else {
            return Err(not_canonical(
                "schedule",
                "a canonical rendering opens with once@, every@ or cron@",
            ));
        };
        let mut parts = rest.split('@');
        let (Some(expression), Some(timezone), Some(policy), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(not_canonical(
                "schedule",
                "a canonical cron rendering is cron@expression@timezone@dst_policy",
            ));
        };
        let Some(dst_policy) = DstPolicy::from_rendering(policy) else {
            return Err(not_canonical(
                "dst_policy",
                "a canonical rendering names a declared DST policy",
            ));
        };
        Ok(Self::Cron {
            expression: CronExpression::new(expression)?,
            timezone: Timezone::new(timezone)?,
            dst_policy,
        })
    }

    /// Render the canonical form.
    ///
    /// Round-trips: [`Self::from_rendering`] reads this back into an identical
    /// schedule, and equal schedules render identically, so the preview shown
    /// to an operator is the schedule that will run.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Once { at } => format!("once@{}", at.as_millis()),
            Self::Every { interval } => format!("every@{}", interval.as_millis()),
            Self::Cron {
                expression,
                timezone,
                dst_policy,
            } => format!(
                "cron@{}@{}@{}",
                expression.as_str(),
                timezone.as_str(),
                dst_policy.as_str()
            ),
        }
    }
}

/// Accept exactly the canonical decimal spelling of an `i64`.
///
/// A leading `+`, a leading zero or surrounding space would render differently
/// than it was read, so the reader refuses them rather than normalizing.
fn canonical_decimal(value: &str, field: &'static str) -> Result<i64, AutomationError> {
    match value.parse::<i64>() {
        Ok(number) if number.to_string() == value => Ok(number),
        _ => Err(not_canonical(
            field,
            "an instant is a canonical decimal integer",
        )),
    }
}

/// The identity of one firing.
///
/// Derived from the automation and the canonical instant and nothing else, so
/// failover, clock recovery or a replayed tick cannot enqueue duplicate work.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OccurrenceKey(String);

impl OccurrenceKey {
    /// Derive an occurrence key.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid automation id.
    pub fn derive(automation_id: &str, fire_at: EpochMillis) -> Result<Self, AutomationError> {
        bounded(automation_id, "automation_id")?;
        Ok(Self(format!("{automation_id}@{}", fire_at.as_millis())))
    }

    /// The derived key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An immutable automation revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationRevision {
    id: String,
    revision: Revision,
    schedule: CanonicalSchedule,
    approved_effects: Vec<String>,
    enablement: AutomationEnablement,
    overlap: OverlapPolicy,
}

impl AutomationRevision {
    /// Declare a revision.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid component.
    pub fn new(
        id: &str,
        revision: Revision,
        schedule: CanonicalSchedule,
        approved_effects: &[&str],
    ) -> Result<Self, AutomationError> {
        bounded(id, "automation_id")?;
        for effect in approved_effects {
            bounded(effect, "approved_effect")?;
        }
        Ok(Self {
            id: id.to_owned(),
            revision,
            schedule,
            approved_effects: approved_effects.iter().map(|e| (*e).to_owned()).collect(),
            enablement: AutomationEnablement::newly_declared(),
            overlap: OverlapPolicy::Skip,
        })
    }

    /// The automation identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The canonical schedule.
    #[must_use]
    pub const fn schedule(&self) -> &CanonicalSchedule {
        &self.schedule
    }

    /// The current revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// The declared pre-approved effects.
    #[must_use]
    pub fn approved_effects(&self) -> &[String] {
        &self.approved_effects
    }

    /// Produce the next revision, requiring the caller's expectation to match.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::RevisionConflict`], so a concurrent edit
    /// conflicts rather than overwriting.
    pub fn edited(
        &self,
        expected: Revision,
        schedule: CanonicalSchedule,
    ) -> Result<Self, AutomationError> {
        let mut next = self.successor(expected)?;
        next.schedule = schedule;
        Ok(next)
    }

    /// Produce the next revision with an approval request's effect declared.
    ///
    /// This is the only way an [`ApprovalRequest`] becomes authority: a new
    /// immutable revision that names the effect, not a mutation of the one that
    /// refused it and not a value derived from the request itself. It is not a
    /// claim about authority in general — whoever can call [`Self::new`] can
    /// declare any effect on a fresh revision, which is what declaring an
    /// automation *is*.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::RevisionConflict`] for a stale expectation
    /// and [`AutomationError::ApprovalMismatch`] when the request was raised by
    /// a different automation.
    pub fn approving(
        &self,
        expected: Revision,
        request: &ApprovalRequest,
    ) -> Result<Self, AutomationError> {
        if request.automation_id() != self.id {
            return Err(AutomationError::ApprovalMismatch {
                automation_id: request.automation_id().to_owned(),
            });
        }
        let mut next = self.successor(expected)?;
        next.approved_effects.push(request.effect().to_owned());
        Ok(next)
    }

    fn successor(&self, expected: Revision) -> Result<Self, AutomationError> {
        if expected != self.revision {
            return Err(AutomationError::RevisionConflict {
                expected: self.revision.get(),
                offered: expected.get(),
            });
        }
        let mut next = self.clone();
        next.revision = self
            .revision
            .checked_next()
            .map_err(|_| not_canonical("revision", "the revision successor is representable"))?;
        Ok(next)
    }

    /// Decide what may happen to an unattended effect.
    ///
    /// Total and two-valued: an effect is either pre-approved, yielding the
    /// token a completion needs, or it is an approval request. There is no
    /// third outcome, so creating a schedule is never blanket authority for
    /// future arbitrary effects.
    ///
    /// Membership in the declared scope is exact equality, never a prefix or a
    /// substring: an automation that declared `notify:slack` does not
    /// pre-approve `notify:slack && rm -rf /`, ` notify:slack`, `notify:` or
    /// `NOTIFY:SLACK`. Each of those is an approval request like any other
    /// undeclared effect.
    #[must_use]
    pub fn decide_unattended(&self, effect: &str) -> UnattendedDecision {
        if self
            .approved_effects
            .iter()
            .any(|allowed| allowed == effect)
        {
            UnattendedDecision::PreApproved(ApprovedEffect {
                automation_id: self.id.clone(),
                effect: effect.to_owned(),
            })
        } else {
            UnattendedDecision::RequiresApproval(ApprovalRequest {
                automation_id: self.id.clone(),
                effect: effect.to_owned(),
            })
        }
    }

    /// Decide whether an unattended effect is pre-approved.
    ///
    /// The same decision as [`Self::decide_unattended`], reported as a refusal
    /// for callers that only need the yes-or-no.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::OutsideApprovedScope`].
    pub fn permit_unattended(&self, effect: &str) -> Result<(), AutomationError> {
        match self.decide_unattended(effect) {
            UnattendedDecision::PreApproved(_) => Ok(()),
            UnattendedDecision::RequiresApproval(request) => Err(request.refusal()),
        }
    }

    /// Whether the automation is in service, and what took it out.
    #[must_use]
    pub const fn enablement(&self) -> &AutomationEnablement {
        &self.enablement
    }

    /// What happens when an occurrence fires while one is still running.
    #[must_use]
    pub const fn overlap(&self) -> OverlapPolicy {
        self.overlap
    }

    /// Produce the next revision with a different overlap policy.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::RevisionConflict`] for a stale expectation.
    pub fn with_overlap(
        &self,
        expected: Revision,
        overlap: OverlapPolicy,
    ) -> Result<Self, AutomationError> {
        let mut next = self.successor(expected)?;
        next.overlap = overlap;
        Ok(next)
    }

    /// Produce the next revision, paused.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::RevisionConflict`] for a stale expectation
    /// and [`AutomationError::InvalidTransition`] from any state but
    /// [`EnablementState::Enabled`]. Pausing an already-paused automation is
    /// refused rather than accepted, because accepting it would overwrite the
    /// cause of the pause an operator still has to resume from.
    pub fn paused(&self, expected: Revision, cause: PauseCause) -> Result<Self, AutomationError> {
        self.transition(expected, EnablementState::Paused, || {
            AutomationEnablement::Paused { cause }
        })
    }

    /// Produce the next revision, back in service and naming who reopened it.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::RevisionConflict`] for a stale expectation,
    /// [`AutomationError::InvalidTransition`] from any state but
    /// [`EnablementState::Paused`], and [`AutomationError::Field`] for an
    /// invalid actor.
    pub fn resumed(&self, expected: Revision, actor: &str) -> Result<Self, AutomationError> {
        let actor = AutomationActor::new(actor)?;
        self.transition(expected, EnablementState::Enabled, || {
            AutomationEnablement::Enabled {
                resumed_by: Some(actor),
            }
        })
    }

    /// Produce the next revision, archived.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::RevisionConflict`] for a stale expectation
    /// and [`AutomationError::InvalidTransition`] from
    /// [`EnablementState::Archived`], which is terminal.
    pub fn archived(&self, expected: Revision, cause: PauseCause) -> Result<Self, AutomationError> {
        self.transition(expected, EnablementState::Archived, || {
            AutomationEnablement::Archived { cause }
        })
    }

    /// The closed lifecycle. Every other ordered pair is refused.
    const fn permits(from: EnablementState, to: EnablementState) -> bool {
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

    fn transition(
        &self,
        expected: Revision,
        to: EnablementState,
        build: impl FnOnce() -> AutomationEnablement,
    ) -> Result<Self, AutomationError> {
        let from = self.enablement.state();
        if !Self::permits(from, to) {
            return Err(AutomationError::InvalidTransition {
                from: from.as_str(),
                to: to.as_str(),
            });
        }
        let mut next = self.successor(expected)?;
        next.enablement = build();
        Ok(next)
    }

    /// Derive the occurrence key for a firing of this automation.
    ///
    /// The gate a pause exists for: a withdrawn automation produces no
    /// occurrence key, so a scheduler that kept a stale tick has nothing to
    /// enqueue it under. [`OccurrenceKey::derive`] remains available for
    /// callers reconstructing a key for an occurrence that already happened.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::NotEnabled`] unless the automation is
    /// enabled.
    pub fn occurrence_at(&self, fire_at: EpochMillis) -> Result<OccurrenceKey, AutomationError> {
        self.require_enabled()?;
        OccurrenceKey::derive(&self.id, fire_at)
    }

    /// Bind a trigger to the action it fires.
    ///
    /// Total over the two outcomes that exist once the automation is in
    /// service: the action's required effect is either inside the declared
    /// scope, yielding a [`BoundAction`], or it is an approval request. The
    /// trigger's kind does not change that decision — a manual run-now is not a
    /// way around the scope an automation declared, because if it were, "ask a
    /// person to press the button" would be a privilege escalation.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::NotEnabled`] for a paused or archived
    /// automation, which fires nothing whoever asks.
    pub fn bind(
        &self,
        trigger: &TriggerSpec,
        action: AutomationAction,
    ) -> Result<ActionBinding, AutomationError> {
        self.require_enabled()?;
        Ok(match self.decide_unattended(&action.required_effect()) {
            UnattendedDecision::PreApproved(approved) => ActionBinding::Bound(BoundAction {
                automation_id: self.id.clone(),
                trigger: trigger.clone(),
                action,
                approved,
            }),
            UnattendedDecision::RequiresApproval(request) => {
                ActionBinding::RequiresApproval(request)
            }
        })
    }

    fn require_enabled(&self) -> Result<(), AutomationError> {
        if self.enablement.admits_occurrence() {
            Ok(())
        } else {
            Err(AutomationError::NotEnabled {
                state: self.enablement.state().as_str(),
            })
        }
    }
}

/// Proof that a named effect was inside an automation's declared scope.
///
/// The only constructor is the pre-approved branch of
/// [`AutomationRevision::decide_unattended`], so this token cannot be
/// manufactured for an effect an automation never declared.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedEffect {
    automation_id: String,
    effect: String,
}

impl ApprovedEffect {
    /// The automation that declared the effect.
    #[must_use]
    pub fn automation_id(&self) -> &str {
        &self.automation_id
    }

    /// The approved effect.
    #[must_use]
    pub fn effect(&self) -> &str {
        &self.effect
    }
}

/// A request for authority an automation does not have.
///
/// There is no accessor returning an [`ApprovedEffect`] and no constructor for
/// one, so a request cannot be spent as authority. It becomes authority only
/// through [`AutomationRevision::approving`], which produces a new revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRequest {
    automation_id: String,
    effect: String,
}

impl ApprovalRequest {
    /// The automation that raised the request.
    #[must_use]
    pub fn automation_id(&self) -> &str {
        &self.automation_id
    }

    /// The effect being asked for.
    #[must_use]
    pub fn effect(&self) -> &str {
        &self.effect
    }

    /// The refusal this request corresponds to.
    #[must_use]
    pub fn refusal(&self) -> AutomationError {
        AutomationError::OutsideApprovedScope {
            effect: self.effect.clone(),
        }
    }
}

/// What may happen to an unattended effect.
///
/// Deliberately two-valued. There is no "completed" variant to reach without
/// the token in [`Self::PreApproved`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnattendedDecision {
    /// The effect was declared in advance.
    PreApproved(ApprovedEffect),
    /// The effect was not declared and can only be asked for.
    RequiresApproval(ApprovalRequest),
}

/// An unattended effect that was carried out and recorded.
///
/// Constructed only from an [`ApprovedEffect`], so there is no path from an
/// out-of-scope effect to a completed one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedEffect {
    automation_id: String,
    effect: String,
    receipt: String,
}

impl CompletedEffect {
    /// Record a completed effect against its approval.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid receipt.
    pub fn record(approved: ApprovedEffect, receipt: &str) -> Result<Self, AutomationError> {
        bounded(receipt, "receipt")?;
        Ok(Self {
            automation_id: approved.automation_id,
            effect: approved.effect,
            receipt: receipt.to_owned(),
        })
    }

    /// The automation the effect ran for.
    #[must_use]
    pub fn automation_id(&self) -> &str {
        &self.automation_id
    }

    /// The effect that ran.
    #[must_use]
    pub fn effect(&self) -> &str {
        &self.effect
    }

    /// The outbox receipt.
    #[must_use]
    pub fn receipt(&self) -> &str {
        &self.receipt
    }
}

/// A delivery target together with the grant that permits it.
///
/// There is no destination value without an authorization, so "deliver
/// somewhere unauthorized" is not expressible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedDestination {
    target: String,
    authorization: String,
}

impl AuthorizedDestination {
    /// Declare a destination and the grant authorizing it.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid component.
    pub fn new(target: &str, authorization: &str) -> Result<Self, AutomationError> {
        bounded(target, "destination_target")?;
        bounded(authorization, "destination_authorization")?;
        Ok(Self {
            target: target.to_owned(),
            authorization: authorization.to_owned(),
        })
    }

    /// Where the effect is delivered.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The grant that authorizes the delivery.
    #[must_use]
    pub fn authorization(&self) -> &str {
        &self.authorization
    }
}

/// The obligation to deliver only to an authorized destination and to record a
/// receipt for every delivery.
///
/// There is no variant meaning "no receipt". Jobs and trigger routes carry this
/// same type, so neither can be given a weaker obligation than the other.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxObligation {
    destination: AuthorizedDestination,
    receipt_log: String,
}

impl OutboxObligation {
    /// Declare the obligation.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid receipt log.
    pub fn new(
        destination: AuthorizedDestination,
        receipt_log: &str,
    ) -> Result<Self, AutomationError> {
        bounded(receipt_log, "receipt_log")?;
        Ok(Self {
            destination,
            receipt_log: receipt_log.to_owned(),
        })
    }

    /// The authorized destination.
    #[must_use]
    pub const fn destination(&self) -> &AuthorizedDestination {
        &self.destination
    }

    /// Where receipts are recorded.
    #[must_use]
    pub fn receipt_log(&self) -> &str {
        &self.receipt_log
    }
}

/// Whether a job runs a script or drives a model.
///
/// This is the only difference between the two. Every obligation lives in
/// [`JobObligations`], which both kinds supply through the same constructor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum JobKind {
    /// A no-agent script job.
    Script,
    /// A job that drives a model.
    Agent,
}

impl JobKind {
    /// Every kind, for coverage checks.
    pub const ALL: [Self; 2] = [Self::Script, Self::Agent];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Script => "script",
            Self::Agent => "agent",
        }
    }
}

/// What a job owes regardless of whether a model is involved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobObligations {
    automation_id: String,
    tenant: Tenancy,
    sandbox_profile: String,
    outbox: OutboxObligation,
}

impl JobObligations {
    /// Declare the obligations.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid component.
    pub fn new(
        automation_id: &str,
        tenant: Tenancy,
        sandbox_profile: &str,
        outbox: OutboxObligation,
    ) -> Result<Self, AutomationError> {
        bounded(automation_id, "automation_id")?;
        bounded(sandbox_profile, "sandbox_profile")?;
        Ok(Self {
            automation_id: automation_id.to_owned(),
            tenant,
            sandbox_profile: sandbox_profile.to_owned(),
            outbox,
        })
    }

    /// The automation the job belongs to.
    #[must_use]
    pub fn automation_id(&self) -> &str {
        &self.automation_id
    }

    /// The owning tenant.
    #[must_use]
    pub const fn tenant(&self) -> &Tenancy {
        &self.tenant
    }

    /// The sandbox profile the job must run under.
    #[must_use]
    pub fn sandbox_profile(&self) -> &str {
        &self.sandbox_profile
    }

    /// The outbox obligation.
    #[must_use]
    pub const fn outbox(&self) -> &OutboxObligation {
        &self.outbox
    }
}

/// A unit of unattended work.
///
/// [`Self::declare`] is the only constructor and it takes the same
/// [`JobObligations`] for either kind, so the one that skips the model has no
/// cheaper path: identity, sandbox and outbox are supplied by the same type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationJob {
    kind: JobKind,
    obligations: JobObligations,
}

impl AutomationJob {
    /// Declare a job of either kind.
    #[must_use]
    pub fn declare(kind: JobKind, obligations: JobObligations) -> Self {
        Self { kind, obligations }
    }

    /// Whether this job drives a model.
    #[must_use]
    pub const fn kind(&self) -> JobKind {
        self.kind
    }

    /// The obligations, which do not vary by kind.
    #[must_use]
    pub const fn obligations(&self) -> &JobObligations {
        &self.obligations
    }
}

/// Non-empty, bounded evidence text.
///
/// Every verdict carries one, and it cannot be empty, so a verdict without
/// evidence is unrepresentable rather than merely discouraged.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VerdictEvidence(String);

impl VerdictEvidence {
    /// Validate and construct evidence text.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an empty, over-long or control
    /// value.
    pub fn new(statement: &str) -> Result<Self, AutomationError> {
        bounded(statement, "evidence")?;
        Ok(Self(statement.to_owned()))
    }

    /// The evidence text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What kind of evidence a completion contract demands.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CompletionEvidenceKind {
    /// Prose is sufficient.
    Narrative,
    /// A passing test run is required.
    Tests,
    /// A produced artifact is required.
    Artifact,
    /// An action receipt is required.
    Receipt,
}

impl CompletionEvidenceKind {
    /// Every kind, for coverage checks.
    pub const ALL: [Self; 4] = [Self::Narrative, Self::Tests, Self::Artifact, Self::Receipt];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Narrative => "narrative",
            Self::Tests => "tests",
            Self::Artifact => "artifact",
            Self::Receipt => "receipt",
        }
    }
}

mod sealed {
    /// Prevents completion evidence being implemented outside this module.
    pub trait Sealed {}
}

/// Evidence a completion contract can demand, as a type.
///
/// A [`Goal`] names its contract by its type parameter, so supplying the wrong
/// kind is a compilation error rather than a runtime refusal.
pub trait CompletionEvidence: sealed::Sealed {
    /// Which kind this evidence is.
    const KIND: CompletionEvidenceKind;

    /// The statement accompanying the evidence.
    fn statement(&self) -> &VerdictEvidence;

    /// The durable reference the evidence points at, when its kind has one.
    fn reference(&self) -> Option<&str>;
}

/// Prose. Sufficient only for a goal whose contract demands nothing durable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NarrativeEvidence {
    statement: VerdictEvidence,
}

impl NarrativeEvidence {
    /// Record prose.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for empty or invalid text.
    pub fn new(statement: &str) -> Result<Self, AutomationError> {
        Ok(Self {
            statement: VerdictEvidence::new(statement)?,
        })
    }
}

impl sealed::Sealed for NarrativeEvidence {}

impl CompletionEvidence for NarrativeEvidence {
    const KIND: CompletionEvidenceKind = CompletionEvidenceKind::Narrative;

    fn statement(&self) -> &VerdictEvidence {
        &self.statement
    }

    fn reference(&self) -> Option<&str> {
        None
    }
}

/// A passing test run, named by its run identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestEvidence {
    run_id: DurableId,
    statement: VerdictEvidence,
}

impl TestEvidence {
    /// Record a test run.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] or [`AutomationError::NotCanonical`]
    /// for an invalid run identity or statement.
    pub fn new(run_id: &str, statement: &str) -> Result<Self, AutomationError> {
        Ok(Self {
            run_id: DurableId::new(run_id)?,
            statement: VerdictEvidence::new(statement)?,
        })
    }
}

impl sealed::Sealed for TestEvidence {}

impl CompletionEvidence for TestEvidence {
    const KIND: CompletionEvidenceKind = CompletionEvidenceKind::Tests;

    fn statement(&self) -> &VerdictEvidence {
        &self.statement
    }

    fn reference(&self) -> Option<&str> {
        Some(self.run_id.as_str())
    }
}

/// A produced artifact, named by its digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactEvidence {
    digest: DurableId,
    statement: VerdictEvidence,
}

impl ArtifactEvidence {
    /// Record an artifact.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] or [`AutomationError::NotCanonical`]
    /// for an invalid digest or statement.
    pub fn new(digest: &str, statement: &str) -> Result<Self, AutomationError> {
        Ok(Self {
            digest: DurableId::new(digest)?,
            statement: VerdictEvidence::new(statement)?,
        })
    }
}

impl sealed::Sealed for ArtifactEvidence {}

impl CompletionEvidence for ArtifactEvidence {
    const KIND: CompletionEvidenceKind = CompletionEvidenceKind::Artifact;

    fn statement(&self) -> &VerdictEvidence {
        &self.statement
    }

    fn reference(&self) -> Option<&str> {
        Some(self.digest.as_str())
    }
}

/// An action receipt, named by its receipt identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptEvidence {
    receipt_id: DurableId,
    statement: VerdictEvidence,
}

impl ReceiptEvidence {
    /// Record a receipt.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] or [`AutomationError::NotCanonical`]
    /// for an invalid receipt identity or statement.
    pub fn new(receipt_id: &str, statement: &str) -> Result<Self, AutomationError> {
        Ok(Self {
            receipt_id: DurableId::new(receipt_id)?,
            statement: VerdictEvidence::new(statement)?,
        })
    }
}

impl sealed::Sealed for ReceiptEvidence {}

impl CompletionEvidence for ReceiptEvidence {
    const KIND: CompletionEvidenceKind = CompletionEvidenceKind::Receipt;

    fn statement(&self) -> &VerdictEvidence {
        &self.statement
    }

    fn reference(&self) -> Option<&str> {
        Some(self.receipt_id.as_str())
    }
}

/// Completion evidence whose kind is known only at runtime.
///
/// Used when evidence is read back from storage rather than named statically.
/// The kind still has to match the goal's contract; see
/// [`Goal::complete_from`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnyCompletionEvidence {
    /// Prose.
    Narrative(NarrativeEvidence),
    /// A test run.
    Tests(TestEvidence),
    /// An artifact.
    Artifact(ArtifactEvidence),
    /// A receipt.
    Receipt(ReceiptEvidence),
}

impl AnyCompletionEvidence {
    /// Which kind this is.
    #[must_use]
    pub const fn kind(&self) -> CompletionEvidenceKind {
        match self {
            Self::Narrative(_) => CompletionEvidenceKind::Narrative,
            Self::Tests(_) => CompletionEvidenceKind::Tests,
            Self::Artifact(_) => CompletionEvidenceKind::Artifact,
            Self::Receipt(_) => CompletionEvidenceKind::Receipt,
        }
    }

    fn into_record(self, goal_id: &str) -> CompletionRecord {
        match self {
            Self::Narrative(evidence) => CompletionRecord::of(goal_id, &evidence),
            Self::Tests(evidence) => CompletionRecord::of(goal_id, &evidence),
            Self::Artifact(evidence) => CompletionRecord::of(goal_id, &evidence),
            Self::Receipt(evidence) => CompletionRecord::of(goal_id, &evidence),
        }
    }
}

/// What a `complete` verdict carries.
///
/// Every field is private, so the record cannot be assembled from a literal
/// outside this module; it is produced by [`Goal::complete_with`] or
/// [`Goal::complete_from`], both of which require the evidence kind the goal's
/// contract names, and it carries the identity of the goal it closed.
///
/// Two limits, stated because the tests measure exactly this much and no more:
///
/// * The type-level binding holds at the call site. `Goal<ArtifactEvidence>`
///   cannot be handed prose — but this slice has no registry from a goal
///   identity to its contract, so a second `Goal<NarrativeEvidence>` declared
///   with the same identity is constructible and closes on prose. Because the
///   record names both [`Self::goal_id`] and [`Self::kind`], a consumer holding
///   the contract for that identity can detect that completion. It is not
///   prevented here.
/// * That no *other* constructor for this type is public is a property of this
///   `impl` block, established by reading it rather than by a test. A
///   compile-fail proof can show a literal is refused; it cannot show the
///   absence of a function that was never written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionRecord {
    goal_id: String,
    kind: CompletionEvidenceKind,
    reference: Option<String>,
    statement: VerdictEvidence,
}

impl CompletionRecord {
    fn of<E: CompletionEvidence>(goal_id: &str, evidence: &E) -> Self {
        Self {
            goal_id: goal_id.to_owned(),
            kind: E::KIND,
            reference: evidence.reference().map(ToOwned::to_owned),
            statement: evidence.statement().clone(),
        }
    }

    /// The goal this record closed.
    #[must_use]
    pub fn goal_id(&self) -> &str {
        &self.goal_id
    }

    /// The evidence kind that closed the goal.
    #[must_use]
    pub const fn kind(&self) -> CompletionEvidenceKind {
        self.kind
    }

    /// The durable reference, when the kind has one.
    #[must_use]
    pub fn reference(&self) -> Option<&str> {
        self.reference.as_deref()
    }

    /// The accompanying statement.
    #[must_use]
    pub const fn statement(&self) -> &VerdictEvidence {
        &self.statement
    }
}

/// A durable objective whose completion contract is its type parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Goal<E: CompletionEvidence> {
    id: String,
    contract: PhantomData<fn() -> E>,
}

impl<E: CompletionEvidence> Goal<E> {
    /// Declare a goal whose completion requires `E`.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid identifier.
    pub fn declare(id: &str) -> Result<Self, AutomationError> {
        bounded(id, "goal_id")?;
        Ok(Self {
            id: id.to_owned(),
            contract: PhantomData,
        })
    }

    /// The goal identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// What completion requires.
    #[must_use]
    pub const fn required_evidence(&self) -> CompletionEvidenceKind {
        E::KIND
    }

    /// Complete the goal.
    ///
    /// Infallible, because the argument type *is* the contract: evidence of
    /// another kind does not typecheck. The record names this goal, so the
    /// verdict says which goal it closed rather than relying on the caller to
    /// keep the pairing.
    #[must_use]
    pub fn complete_with(&self, evidence: E) -> GoalVerdict {
        GoalVerdict::Complete {
            record: CompletionRecord::of(&self.id, &evidence),
        }
    }

    /// Complete the goal from evidence whose kind was not known statically.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::CompletionEvidenceMissing`] when the supplied
    /// kind is not the kind this goal's contract names.
    pub fn complete_from(
        &self,
        supplied: AnyCompletionEvidence,
    ) -> Result<GoalVerdict, AutomationError> {
        if supplied.kind() != E::KIND {
            return Err(AutomationError::CompletionEvidenceMissing {
                required: E::KIND.as_str(),
            });
        }
        Ok(GoalVerdict::Complete {
            record: supplied.into_record(&self.id),
        })
    }
}

/// The closed set of goal outcomes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GoalOutcome {
    /// Keep going.
    Continue,
    /// Finished.
    Complete,
    /// Waiting on a durable condition.
    Wait,
    /// Cannot proceed.
    Blocked,
    /// Out of budget.
    BudgetExhausted,
}

impl GoalOutcome {
    /// Every outcome. The set is closed: there is no other.
    pub const ALL: [Self; 5] = [
        Self::Continue,
        Self::Complete,
        Self::Wait,
        Self::Blocked,
        Self::BudgetExhausted,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::Complete => "complete",
            Self::Wait => "wait",
            Self::Blocked => "blocked",
            Self::BudgetExhausted => "budget_exhausted",
        }
    }
}

/// What a goal should do next.
///
/// Exactly one of five outcomes, each carrying its evidence. `Complete` carries
/// a [`CompletionRecord`] rather than free text, so it cannot be assembled
/// outside the completion contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GoalVerdict {
    /// Keep going.
    Continue {
        /// Why.
        evidence: VerdictEvidence,
    },
    /// Finished, with the record its contract required.
    Complete {
        /// What closed the goal.
        record: CompletionRecord,
    },
    /// Waiting on a durable condition.
    Wait {
        /// What is being waited on.
        condition: WaitCondition,
        /// Why the wait was chosen.
        evidence: VerdictEvidence,
    },
    /// Cannot proceed.
    Blocked {
        /// Why.
        evidence: VerdictEvidence,
    },
    /// Out of budget.
    BudgetExhausted {
        /// Why.
        evidence: VerdictEvidence,
    },
}

impl GoalVerdict {
    /// Which outcome this is.
    #[must_use]
    pub const fn outcome(&self) -> GoalOutcome {
        match self {
            Self::Continue { .. } => GoalOutcome::Continue,
            Self::Complete { .. } => GoalOutcome::Complete,
            Self::Wait { .. } => GoalOutcome::Wait,
            Self::Blocked { .. } => GoalOutcome::Blocked,
            Self::BudgetExhausted { .. } => GoalOutcome::BudgetExhausted,
        }
    }

    /// The evidence this verdict carries. Every outcome has one.
    #[must_use]
    pub const fn evidence(&self) -> &VerdictEvidence {
        match self {
            Self::Continue { evidence }
            | Self::Wait { evidence, .. }
            | Self::Blocked { evidence }
            | Self::BudgetExhausted { evidence } => evidence,
            Self::Complete { record } => record.statement(),
        }
    }
}

/// What a goal waits on.
///
/// Every variant names something durable and every payload is a
/// [`DurableId`] or an instant, so a free-text label cannot be waited on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WaitCondition {
    /// A durable timer.
    Timer {
        /// When it fires.
        until: EpochMillis,
    },
    /// A run reaching a terminal state.
    Run {
        /// The run identity.
        run_id: DurableId,
    },
    /// A connector event.
    ConnectorEvent {
        /// The source key expected.
        source_key: DurableId,
    },
    /// A registered monitor observing its pattern.
    MonitoredPattern {
        /// The monitor identity.
        monitor_id: DurableId,
    },
}

/// What a wake resumes.
///
/// An exact goal, job or session. There is no variant carrying prose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WakeContext {
    /// A goal.
    Goal(DurableId),
    /// A job.
    Job(DurableId),
    /// A session.
    Session(DurableId),
}

impl WakeContext {
    /// The resumed identity.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Goal(id) | Self::Job(id) | Self::Session(id) => id.as_str(),
        }
    }
}

/// The resumption of a wait.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Wake {
    context: WakeContext,
    condition: WaitCondition,
}

impl Wake {
    /// Resolve a wait against an exact context.
    #[must_use]
    pub const fn resolve(context: WakeContext, condition: WaitCondition) -> Self {
        Self { context, condition }
    }

    /// What is being resumed.
    #[must_use]
    pub const fn context(&self) -> &WakeContext {
        &self.context
    }

    /// The identity being resumed.
    #[must_use]
    pub fn context_id(&self) -> &str {
        self.context.id()
    }

    /// The condition that was waited on.
    #[must_use]
    pub const fn condition(&self) -> &WaitCondition {
        &self.condition
    }
}

/// Where a claim stands against its declared failure threshold.
///
/// There is deliberately no variant meaning "keep retrying regardless".
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ClaimState {
    /// Attempts remain.
    Retry {
        /// How many attempts are left before the threshold.
        remaining: u32,
    },
    /// The threshold was reached; the claim is blocked for a person.
    Blocked {
        /// How many failures were counted.
        failures: u32,
    },
}

/// A declared failure threshold and the failures counted against it.
///
/// Once the threshold is reached the state is [`ClaimState::Blocked`] and
/// further failures keep it there, so a claim cannot retry unboundedly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailureLedger {
    threshold: u32,
    failures: u32,
}

impl FailureLedger {
    /// Declare a threshold.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::NotCanonical`] for a zero threshold, which
    /// would permit no attempt at all.
    pub const fn declare(threshold: u32) -> Result<Self, AutomationError> {
        if threshold == 0 {
            return Err(not_canonical(
                "failure_threshold",
                "a threshold permits at least one attempt",
            ));
        }
        Ok(Self {
            threshold,
            failures: 0,
        })
    }

    /// The declared threshold.
    #[must_use]
    pub const fn threshold(self) -> u32 {
        self.threshold
    }

    /// Failures counted so far.
    #[must_use]
    pub const fn failures(self) -> u32 {
        self.failures
    }

    /// Count one more failure.
    #[must_use]
    pub const fn after_failure(self) -> Self {
        Self {
            threshold: self.threshold,
            failures: self.failures.saturating_add(1),
        }
    }

    /// Where the ledger stands.
    #[must_use]
    pub const fn state(self) -> ClaimState {
        if self.failures >= self.threshold {
            ClaimState::Blocked {
                failures: self.failures,
            }
        } else {
            ClaimState::Retry {
                remaining: self.threshold - self.failures,
            }
        }
    }
}

/// Every component of a [`BoardClaim`], named at the call site.
///
/// A struct rather than a positional list: tenancy and labels are both
/// string-shaped, and transposing them is exactly the mistake that would turn a
/// label into a tenancy control. Naming them removes the hazard, and the two
/// fields have different types so the transposition does not compile.
#[derive(Clone, Debug)]
pub struct BoardClaimParts<'a> {
    /// The claimed task.
    pub task: &'a str,
    /// The claiming worker.
    pub worker: &'a str,
    /// The owning tenant. Only this field carries authority.
    pub tenant: Tenancy,
    /// The fencing epoch.
    pub epoch: u64,
    /// Annotations, which carry no authority.
    pub labels: Vec<ClaimLabel>,
    /// The declared failure threshold.
    pub failures: FailureLedger,
}

/// A fenced board claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoardClaim {
    task: String,
    worker: String,
    tenant: Tenancy,
    epoch: u64,
    labels: Vec<ClaimLabel>,
    failures: FailureLedger,
}

impl BoardClaim {
    /// Claim a task at an epoch.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid component.
    pub fn claim(parts: BoardClaimParts<'_>) -> Result<Self, AutomationError> {
        bounded(parts.task, "task")?;
        bounded(parts.worker, "worker")?;
        Ok(Self {
            task: parts.task.to_owned(),
            worker: parts.worker.to_owned(),
            tenant: parts.tenant,
            epoch: parts.epoch,
            labels: parts.labels,
            failures: parts.failures,
        })
    }

    /// The fencing epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Whether this claim is still current against an observed epoch.
    #[must_use]
    pub const fn is_current(&self, observed_epoch: u64) -> bool {
        self.epoch >= observed_epoch
    }

    /// The claiming worker.
    #[must_use]
    pub fn worker(&self) -> &str {
        &self.worker
    }

    /// The claimed task.
    #[must_use]
    pub fn task(&self) -> &str {
        &self.task
    }

    /// The owning tenant.
    #[must_use]
    pub const fn tenant(&self) -> &Tenancy {
        &self.tenant
    }

    /// The annotations, which carry no authority.
    #[must_use]
    pub fn labels(&self) -> &[ClaimLabel] {
        &self.labels
    }

    /// Whether this claim authorizes work for `tenant` at `observed_epoch`.
    ///
    /// Labels are not consulted. A claim is a hard authorization boundary made
    /// of exactly two things: the tenancy and the fencing epoch.
    #[must_use]
    pub fn authorizes(&self, tenant: &Tenancy, observed_epoch: u64) -> bool {
        self.tenant == *tenant && self.is_current(observed_epoch)
    }

    /// The failure ledger.
    #[must_use]
    pub const fn failures(&self) -> FailureLedger {
        self.failures
    }

    /// Where the claim stands against its threshold.
    #[must_use]
    pub const fn state(&self) -> ClaimState {
        self.failures.state()
    }

    /// The same claim with one more failure counted.
    #[must_use]
    pub fn after_failure(&self) -> Self {
        let mut next = self.clone();
        next.failures = self.failures.after_failure();
        next
    }
}

/// How an inbound request is authenticated.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum VerificationMethod {
    /// Shared-secret HMAC.
    Hmac,
    /// Public-key signature.
    PublicKey,
    /// Mutual TLS.
    MutualTls,
}

impl VerificationMethod {
    /// Every method, for coverage checks.
    pub const ALL: [Self; 3] = [Self::Hmac, Self::PublicKey, Self::MutualTls];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hmac => "hmac",
            Self::PublicKey => "public_key",
            Self::MutualTls => "mutual_tls",
        }
    }
}

/// One declarative equality filter on an inbound event.
///
/// The shorthand for the common case. Its components are the same validated
/// types [`FilterExpression`] uses, so it is the same vocabulary written
/// shorter rather than a second one — see [`EventFilters::canonical_expression`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventFilter {
    field: FilterField,
    equals: FilterValue,
}

impl EventFilter {
    /// Require a field to equal a value.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid component and
    /// [`AutomationError::NotCanonical`] for a field outside the dotted-path
    /// grammar.
    pub fn requiring(field: &str, equals: &str) -> Result<Self, AutomationError> {
        Ok(Self {
            field: FilterField::new(field)?,
            equals: FilterValue::new(equals)?,
        })
    }

    /// The filtered field.
    #[must_use]
    pub fn field(&self) -> &str {
        self.field.as_str()
    }

    /// The required value.
    #[must_use]
    pub fn equals(&self) -> &str {
        self.equals.as_str()
    }

    fn to_expression(&self) -> FilterExpression {
        FilterExpression::Field {
            field: self.field.clone(),
            predicate: FilterPredicate::Equals {
                value: self.equals.clone(),
            },
        }
    }
}

/// The declarative filters a route applies.
///
/// Accepting every allowed event type is a named decision rather than an
/// omitted field, so a route never silently lacks filtering.
///
/// Two ways to write filtering, one meaning: the equality shorthand and a full
/// [`FilterExpression`] both reduce to the same canonical expression through
/// [`Self::canonical_expression`], so a route declared either way filters
/// identically and renders identically. There is no third way, and neither way
/// admits source text to evaluate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventFilters {
    filters: Vec<EventFilter>,
    expression: Option<FilterExpression>,
}

impl EventFilters {
    /// Accept every event of an allowed type.
    #[must_use]
    pub const fn accept_all_allowed_types() -> Self {
        Self {
            filters: Vec::new(),
            expression: None,
        }
    }

    /// Require every listed equality filter to match.
    #[must_use]
    pub const fn requiring_all(filters: Vec<EventFilter>) -> Self {
        Self {
            filters,
            expression: None,
        }
    }

    /// Require a full declarative condition to hold.
    #[must_use]
    pub const fn matching(expression: FilterExpression) -> Self {
        Self {
            filters: Vec::new(),
            expression: Some(expression),
        }
    }

    /// The declared equality filters, empty when a condition was declared
    /// instead.
    #[must_use]
    pub fn as_slice(&self) -> &[EventFilter] {
        &self.filters
    }

    /// The declared condition, when one was declared rather than a shorthand.
    #[must_use]
    pub const fn expression(&self) -> Option<&FilterExpression> {
        self.expression.as_ref()
    }

    /// The one condition this route filters by, whichever way it was declared.
    ///
    /// `Ok(None)` means "accept every allowed event type" — a named decision,
    /// not a missing filter.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::TooLarge`] when lowering the shorthand would
    /// exceed [`MAX_FILTER_NODES`] or [`MAX_FILTER_DEPTH`]. An over-long filter
    /// list is refused here rather than silently truncated to the part that
    /// fits, which would filter less than the operator asked for.
    pub fn canonical_expression(&self) -> Result<Option<FilterExpression>, AutomationError> {
        if let Some(expression) = &self.expression {
            return Ok(Some(expression.clone()));
        }
        if self.filters.is_empty() {
            return Ok(None);
        }
        let operands = self
            .filters
            .iter()
            .map(EventFilter::to_expression)
            .collect();
        FilterExpression::all(operands).map(Some)
    }
}

/// What a route does to a payload before dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteTransform {
    /// The payload is passed through unchanged.
    PassThrough,
    /// A transform evaluated inside a named sandbox profile.
    Sandboxed {
        /// The sandbox profile the transform runs under.
        profile: DurableId,
    },
    /// A typed template.
    Template {
        /// The template identity.
        template_id: DurableId,
    },
}

/// Where a route extracts the idempotency key of an inbound delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdempotencySource {
    /// A request header.
    Header {
        /// The header name.
        name: DurableId,
    },
    /// A field of the payload.
    BodyField {
        /// The pointer to the field.
        pointer: DurableId,
    },
    /// The transport delivery identity.
    DeliveryId,
}

/// Whether an inbound event reaches a model.
///
/// Both modes are carried by the same route type with the same obligations, so
/// bypassing the model does not bypass destination authorization or receipts.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DeliveryMode {
    /// The event is handed to a model.
    ThroughModel,
    /// The event is delivered directly.
    Direct,
}

impl DeliveryMode {
    /// Every mode, for coverage checks.
    pub const ALL: [Self; 2] = [Self::ThroughModel, Self::Direct];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ThroughModel => "through_model",
            Self::Direct => "direct",
        }
    }
}

/// Every component of a [`TriggerRoute`], named at the call site.
///
/// Each field is required. A literal that omits one does not compile, which is
/// what makes "a route without a destination or an idempotency source is not
/// constructible" a property of the type rather than of a validator.
#[derive(Clone, Debug)]
pub struct TriggerRouteParts<'a> {
    /// The stable route identity.
    pub id: &'a str,
    /// The inbound path.
    pub path: &'a str,
    /// The owning tenant.
    pub tenant: Tenancy,
    /// The service actor the route runs as.
    pub service_actor: &'a str,
    /// The event types the route accepts.
    pub allowed_event_types: &'a [&'a str],
    /// How an inbound request is authenticated.
    pub verification: VerificationMethod,
    /// How far back a verified request may be replayed.
    pub replay_window_ms: i64,
    /// Payload ceiling.
    pub max_body_bytes: u64,
    /// Header ceiling.
    pub max_header_bytes: u64,
    /// Declarative filters.
    pub filters: EventFilters,
    /// The sandboxed transform or typed template.
    pub transform: RouteTransform,
    /// The authorized destination and its receipt obligation.
    pub outbox: OutboxObligation,
    /// Where the idempotency key comes from.
    pub idempotency: IdempotencySource,
    /// Whether the event reaches a model.
    pub delivery: DeliveryMode,
}

/// An inbound trigger route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerRoute {
    id: String,
    path: String,
    tenant: Tenancy,
    service_actor: String,
    allowed_event_types: Vec<String>,
    verification: VerificationMethod,
    replay_window_ms: i64,
    max_body_bytes: u64,
    max_header_bytes: u64,
    filters: EventFilters,
    transform: RouteTransform,
    outbox: OutboxObligation,
    idempotency: IdempotencySource,
    delivery: DeliveryMode,
}

impl TriggerRoute {
    /// Declare a route.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid component and
    /// [`AutomationError::NotCanonical`] for a path that is not absolute, an
    /// empty allowed-type list, or a non-positive window or ceiling.
    pub fn declare(parts: TriggerRouteParts<'_>) -> Result<Self, AutomationError> {
        bounded(parts.id, "route_id")?;
        bounded(parts.path, "route_path")?;
        bounded(parts.service_actor, "service_actor")?;
        if !parts.path.starts_with('/') || parts.path.chars().any(char::is_whitespace) {
            return Err(not_canonical(
                "route_path",
                "a route path is absolute and free of whitespace",
            ));
        }
        if parts.allowed_event_types.is_empty() {
            return Err(not_canonical(
                "allowed_event_types",
                "a route names at least one accepted event type",
            ));
        }
        for event_type in parts.allowed_event_types {
            bounded(event_type, "allowed_event_type")?;
        }
        if parts.replay_window_ms <= 0 {
            return Err(not_canonical(
                "replay_window_ms",
                "a replay window is strictly positive",
            ));
        }
        if parts.max_body_bytes == 0 {
            return Err(not_canonical(
                "max_body_bytes",
                "a payload ceiling admits at least one byte",
            ));
        }
        if parts.max_header_bytes == 0 {
            return Err(not_canonical(
                "max_header_bytes",
                "a header ceiling admits at least one byte",
            ));
        }
        Ok(Self {
            id: parts.id.to_owned(),
            path: parts.path.to_owned(),
            tenant: parts.tenant,
            service_actor: parts.service_actor.to_owned(),
            allowed_event_types: parts
                .allowed_event_types
                .iter()
                .map(|event_type| (*event_type).to_owned())
                .collect(),
            verification: parts.verification,
            replay_window_ms: parts.replay_window_ms,
            max_body_bytes: parts.max_body_bytes,
            max_header_bytes: parts.max_header_bytes,
            filters: parts.filters,
            transform: parts.transform,
            outbox: parts.outbox,
            idempotency: parts.idempotency,
            delivery: parts.delivery,
        })
    }

    /// The stable route identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The inbound path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The owning tenant.
    #[must_use]
    pub const fn tenant(&self) -> &Tenancy {
        &self.tenant
    }

    /// The service actor the route runs as.
    #[must_use]
    pub fn service_actor(&self) -> &str {
        &self.service_actor
    }

    /// The accepted event types.
    #[must_use]
    pub fn allowed_event_types(&self) -> &[String] {
        &self.allowed_event_types
    }

    /// The verification method.
    #[must_use]
    pub const fn verification(&self) -> VerificationMethod {
        self.verification
    }

    /// The replay window.
    #[must_use]
    pub const fn replay_window_ms(&self) -> i64 {
        self.replay_window_ms
    }

    /// The payload ceiling.
    #[must_use]
    pub const fn max_body_bytes(&self) -> u64 {
        self.max_body_bytes
    }

    /// The header ceiling.
    #[must_use]
    pub const fn max_header_bytes(&self) -> u64 {
        self.max_header_bytes
    }

    /// The declarative filters.
    #[must_use]
    pub const fn filters(&self) -> &EventFilters {
        &self.filters
    }

    /// The sandboxed transform or typed template.
    #[must_use]
    pub const fn transform(&self) -> &RouteTransform {
        &self.transform
    }

    /// The authorized destination and its receipt obligation.
    ///
    /// Present for both delivery modes: bypassing the model does not bypass
    /// destination authorization, outbox receipts or content limits.
    #[must_use]
    pub const fn outbox(&self) -> &OutboxObligation {
        &self.outbox
    }

    /// Where the idempotency key comes from.
    #[must_use]
    pub const fn idempotency(&self) -> &IdempotencySource {
        &self.idempotency
    }

    /// Whether the event reaches a model.
    #[must_use]
    pub const fn delivery(&self) -> DeliveryMode {
        self.delivery
    }

    /// Whether delivery bypasses the model.
    #[must_use]
    pub const fn delivers_directly(&self) -> bool {
        matches!(self.delivery, DeliveryMode::Direct)
    }
}

/// Maximum number of nodes in one filter expression.
pub const MAX_FILTER_NODES: usize = 32;

/// Maximum nesting depth of one filter expression.
pub const MAX_FILTER_DEPTH: usize = 4;

/// Maximum number of values a membership predicate may list.
pub const MAX_MEMBERSHIP_VALUES: usize = 16;

/// Maximum number of dotted segments in a filter field path.
pub const MAX_FILTER_FIELD_SEGMENTS: usize = 8;

/// Maximum UTF-8 byte length of a bounded pattern.
pub const MAX_PATTERN_BYTES: usize = 128;

/// Maximum UTF-8 byte length of a filter expression's canonical rendering.
///
/// Checked at construction as well as when reading, so every constructible
/// expression renders inside the bound the reader accepts: [`render`] cannot
/// produce a value [`from_rendering`] would refuse.
///
/// [`render`]: FilterExpression::render
/// [`from_rendering`]: FilterExpression::from_rendering
pub const MAX_FILTER_RENDERING_BYTES: usize = 8_192;

/// Maximum total repetition a bounded pattern may request.
///
/// The bound is on the *product* of every repetition ceiling in the pattern,
/// which over-approximates the work a matcher can be made to do. A pattern
/// whose product exceeds this is refused rather than truncated.
pub const MAX_PATTERN_EXPANSION: u32 = 1_024;

/// A person or runbook named on a lifecycle transition.
///
/// Not authenticated, and not a capability. It says who asked, which is worth
/// recording for exactly that reason and no stronger one — the same discipline
/// [`crate::admin::IntakePause`] applies to the daemon's intake switch.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AutomationActor(String);

impl AutomationActor {
    /// Validate and construct an actor.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an empty, over-long or control
    /// value.
    pub fn new(actor: &str) -> Result<Self, AutomationError> {
        bounded(actor, "actor")?;
        Ok(Self(actor.to_owned()))
    }

    /// The actor.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Who took an automation out of service, and why.
///
/// A reason is required. A pause with no stated cause is the one an operator
/// cannot safely resume, so the type does not offer that shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseCause {
    actor: AutomationActor,
    reason: String,
}

impl PauseCause {
    /// Record who paused an automation and why.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid actor or reason.
    pub fn new(actor: &str, reason: &str) -> Result<Self, AutomationError> {
        bounded(reason, "pause_reason")?;
        Ok(Self {
            actor: AutomationActor::new(actor)?,
            reason: reason.to_owned(),
        })
    }

    /// Who paused it.
    #[must_use]
    pub const fn actor(&self) -> &AutomationActor {
        &self.actor
    }

    /// Why.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Which of the three lifecycle states an automation is in.
///
/// Reported separately from [`AutomationEnablement`] so a caller can compare or
/// render the state without inspecting its payload.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EnablementState {
    /// Firing.
    Enabled,
    /// Withdrawn from firing, resumable.
    Paused,
    /// Withdrawn permanently. Terminal.
    Archived,
}

impl EnablementState {
    /// Every state. The set is closed: there is no fourth.
    pub const ALL: [Self; 3] = [Self::Enabled, Self::Paused, Self::Archived];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Paused => "paused",
            Self::Archived => "archived",
        }
    }

    /// Whether an automation in this state fires.
    #[must_use]
    pub const fn admits_occurrence(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

/// Whether an automation is in service, and what took it out.
///
/// There is no state meaning "paused but still firing", and no way to reach
/// [`Self::Paused`] or [`Self::Archived`] without a [`PauseCause`], so the
/// record always says who withdrew it and why.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AutomationEnablement {
    /// Firing. `resumed_by` names whoever last put it back, and is absent on an
    /// automation that was never paused.
    Enabled {
        /// Who reopened it, when it had been paused.
        resumed_by: Option<AutomationActor>,
    },
    /// Withdrawn from firing, resumable.
    Paused {
        /// Who withdrew it, and why.
        cause: PauseCause,
    },
    /// Withdrawn permanently. Terminal: nothing transitions out of it.
    Archived {
        /// Who archived it, and why.
        cause: PauseCause,
    },
}

impl AutomationEnablement {
    /// The state a freshly declared automation is in.
    #[must_use]
    pub const fn newly_declared() -> Self {
        Self::Enabled { resumed_by: None }
    }

    /// Which state this is.
    #[must_use]
    pub const fn state(&self) -> EnablementState {
        match self {
            Self::Enabled { .. } => EnablementState::Enabled,
            Self::Paused { .. } => EnablementState::Paused,
            Self::Archived { .. } => EnablementState::Archived,
        }
    }

    /// Whether an automation in this state fires.
    #[must_use]
    pub const fn admits_occurrence(&self) -> bool {
        self.state().admits_occurrence()
    }

    /// Why it was withdrawn, when it was.
    #[must_use]
    pub const fn cause(&self) -> Option<&PauseCause> {
        match self {
            Self::Enabled { .. } => None,
            Self::Paused { cause } | Self::Archived { cause } => Some(cause),
        }
    }
}

/// Which overlap policy an automation declares.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OverlapKind {
    /// Drop the new occurrence.
    Skip,
    /// Hold the new occurrence behind the running one.
    Queue,
    /// Cancel the running occurrence and start the new one.
    CancelPrevious,
    /// Run both, up to a declared ceiling.
    Concurrent,
}

impl OverlapKind {
    /// Every kind. The set is closed.
    pub const ALL: [Self; 4] = [
        Self::Skip,
        Self::Queue,
        Self::CancelPrevious,
        Self::Concurrent,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::Queue => "queue",
            Self::CancelPrevious => "cancel_previous",
            Self::Concurrent => "concurrent",
        }
    }
}

/// What happens when an occurrence fires while the previous one still runs.
///
/// There is deliberately no variant meaning "unbounded": both variants that
/// admit more than one live occurrence carry a declared ceiling, and a ceiling
/// of zero is refused rather than read as "no limit".
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OverlapPolicy {
    /// The new occurrence is dropped while one is running.
    Skip,
    /// The new occurrence waits, up to a bounded queue.
    Queue {
        /// How many occurrences may wait.
        max_queued: u32,
    },
    /// The running occurrence is cancelled and the new one starts.
    CancelPrevious,
    /// Occurrences run together, up to a bounded count.
    Concurrent {
        /// How many may run together.
        max_concurrent: u32,
    },
}

impl OverlapPolicy {
    /// A bounded queue.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::NotCanonical`] for a zero ceiling, which
    /// would be a queue that holds nothing rather than a queue without limit.
    pub const fn queue(max_queued: u32) -> Result<Self, AutomationError> {
        if max_queued == 0 {
            return Err(not_canonical(
                "max_queued",
                "a queue ceiling admits at least one waiting occurrence",
            ));
        }
        Ok(Self::Queue { max_queued })
    }

    /// A bounded concurrency.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::NotCanonical`] for a zero ceiling.
    pub const fn concurrent(max_concurrent: u32) -> Result<Self, AutomationError> {
        if max_concurrent == 0 {
            return Err(not_canonical(
                "max_concurrent",
                "a concurrency ceiling admits at least one running occurrence",
            ));
        }
        Ok(Self::Concurrent { max_concurrent })
    }

    /// Which kind this is.
    #[must_use]
    pub const fn kind(self) -> OverlapKind {
        match self {
            Self::Skip => OverlapKind::Skip,
            Self::Queue { .. } => OverlapKind::Queue,
            Self::CancelPrevious => OverlapKind::CancelPrevious,
            Self::Concurrent { .. } => OverlapKind::Concurrent,
        }
    }

    /// How many occurrences may be live at once under this policy.
    ///
    /// Always a number. No policy answers "as many as arrive".
    #[must_use]
    pub const fn live_ceiling(self) -> u32 {
        match self {
            Self::Skip | Self::CancelPrevious => 1,
            Self::Queue { max_queued } => max_queued.saturating_add(1),
            Self::Concurrent { max_concurrent } => max_concurrent,
        }
    }
}

/// The external sources a watcher may be registered against.
///
/// Exactly the sources the product requirement names. A source outside the list
/// is refused by [`Self::from_str`] rather than admitted as an opaque string,
/// so an unrecognized watcher cannot be stored and later read as something this
/// build silently accepts.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WatchedSource {
    /// Repository events.
    GitHub,
    /// Continuous-integration events.
    ContinuousIntegration,
    /// Monitoring and alerting events.
    Monitoring,
    /// Filesystem events.
    Filesystem,
    /// Feed events.
    Rss,
    /// Calendar events.
    Calendar,
    /// Mailbox events.
    Email,
    /// Events raised by the product itself.
    Platform,
}

impl WatchedSource {
    /// Every source. The set is closed.
    pub const ALL: [Self; 8] = [
        Self::GitHub,
        Self::ContinuousIntegration,
        Self::Monitoring,
        Self::Filesystem,
        Self::Rss,
        Self::Calendar,
        Self::Email,
        Self::Platform,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::ContinuousIntegration => "ci",
            Self::Monitoring => "monitoring",
            Self::Filesystem => "filesystem",
            Self::Rss => "rss",
            Self::Calendar => "calendar",
            Self::Email => "email",
            Self::Platform => "platform",
        }
    }

    /// Resolve a stored spelling.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::UnknownVocabulary`] for anything else. There
    /// is no fallback source and no case folding: the spelling is exact.
    pub fn from_name(name: &str) -> Result<Self, AutomationError> {
        Self::ALL
            .into_iter()
            .find(|source| source.as_str() == name)
            .ok_or_else(|| unknown_vocabulary("watched_source", name))
    }
}

/// Which of the four ways an automation can be started.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TriggerKind {
    /// A canonical schedule.
    Schedule,
    /// An inbound trigger route.
    Inbound,
    /// A registered watcher.
    Watch,
    /// A person asking for it now.
    Manual,
}

impl TriggerKind {
    /// Every kind. The set is closed.
    pub const ALL: [Self; 4] = [Self::Schedule, Self::Inbound, Self::Watch, Self::Manual];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Schedule => "schedule",
            Self::Inbound => "inbound",
            Self::Watch => "watch",
            Self::Manual => "manual",
        }
    }

    /// Whether a trigger of this kind starts work with nobody present.
    #[must_use]
    pub const fn is_unattended(self) -> bool {
        !matches!(self, Self::Manual)
    }

    /// Resolve a stored spelling.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::UnknownVocabulary`] for anything else.
    pub fn from_name(name: &str) -> Result<Self, AutomationError> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.as_str() == name)
            .ok_or_else(|| unknown_vocabulary("trigger_kind", name))
    }
}

/// What starts an automation.
///
/// Closed and total: a trigger is a canonical schedule, a declared inbound
/// route, a registered watcher, or a person. Every payload is a validated type,
/// so no variant carries prose and none carries an opaque escape hatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TriggerSpec {
    /// A canonical schedule.
    Schedule {
        /// When it fires.
        schedule: CanonicalSchedule,
    },
    /// A declared inbound trigger route.
    Inbound {
        /// The route identity, which must be a declared [`TriggerRoute`].
        route: DurableId,
    },
    /// A registered watcher on an external source.
    Watch {
        /// Which source.
        source: WatchedSource,
        /// The watcher identity.
        watcher: DurableId,
    },
    /// A person asking for a run now.
    Manual {
        /// Who asked.
        actor: AutomationActor,
    },
}

impl TriggerSpec {
    /// A schedule trigger.
    #[must_use]
    pub const fn schedule(schedule: CanonicalSchedule) -> Self {
        Self::Schedule { schedule }
    }

    /// An inbound route trigger.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] or [`AutomationError::NotCanonical`]
    /// for an invalid route identity.
    pub fn inbound(route: &str) -> Result<Self, AutomationError> {
        Ok(Self::Inbound {
            route: DurableId::new(route)?,
        })
    }

    /// A watcher trigger.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] or [`AutomationError::NotCanonical`]
    /// for an invalid watcher identity.
    pub fn watch(source: WatchedSource, watcher: &str) -> Result<Self, AutomationError> {
        Ok(Self::Watch {
            source,
            watcher: DurableId::new(watcher)?,
        })
    }

    /// A run-now trigger.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid actor. A manual run
    /// names the person who asked for it; there is no anonymous variant.
    pub fn manual(actor: &str) -> Result<Self, AutomationError> {
        Ok(Self::Manual {
            actor: AutomationActor::new(actor)?,
        })
    }

    /// Which kind this is.
    #[must_use]
    pub const fn kind(&self) -> TriggerKind {
        match self {
            Self::Schedule { .. } => TriggerKind::Schedule,
            Self::Inbound { .. } => TriggerKind::Inbound,
            Self::Watch { .. } => TriggerKind::Watch,
            Self::Manual { .. } => TriggerKind::Manual,
        }
    }

    /// Whether this trigger starts work with nobody present.
    #[must_use]
    pub const fn is_unattended(&self) -> bool {
        self.kind().is_unattended()
    }

    /// Render the canonical form.
    ///
    /// Round-trips through [`Self::from_rendering`]. The kind is written first
    /// and every variable-length component is written last, so the reading is
    /// unambiguous without escaping.
    #[must_use]
    pub fn render(&self) -> String {
        let kind = self.kind().as_str();
        match self {
            Self::Schedule { schedule } => format!("{kind}:{}", schedule.render()),
            Self::Inbound { route } => format!("{kind}:{route}"),
            Self::Watch { source, watcher } => format!("{kind}:{}:{watcher}", source.as_str()),
            Self::Manual { actor } => format!("{kind}:{}", actor.as_str()),
        }
    }

    /// Read a canonical rendering back.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::UnknownVocabulary`] for a kind or watched
    /// source this build does not declare and
    /// [`AutomationError::NotCanonical`] for a rendering that is not
    /// `kind:payload`.
    pub fn from_rendering(rendered: &str) -> Result<Self, AutomationError> {
        bounded(rendered, "trigger")?;
        let Some((kind, rest)) = rendered.split_once(':') else {
            return Err(not_canonical(
                "trigger",
                "a canonical trigger rendering is kind:payload",
            ));
        };
        match TriggerKind::from_name(kind)? {
            TriggerKind::Schedule => Ok(Self::Schedule {
                schedule: CanonicalSchedule::from_rendering(rest)?,
            }),
            TriggerKind::Inbound => Self::inbound(rest),
            TriggerKind::Watch => {
                let Some((source, watcher)) = rest.split_once(':') else {
                    return Err(not_canonical(
                        "trigger",
                        "a canonical watch rendering is watch:source:watcher",
                    ));
                };
                Self::watch(WatchedSource::from_name(source)?, watcher)
            }
            TriggerKind::Manual => Self::manual(rest),
        }
    }
}

/// Which of the four things an automation can do when it fires.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ActionKind {
    /// Start a fresh agent turn.
    AgentTurn,
    /// Run a reviewed no-agent script or workflow.
    Script,
    /// Invoke a command from the command registry.
    Command,
    /// Deliver a notification with no model call.
    Notify,
}

impl ActionKind {
    /// Every kind. The set is closed.
    pub const ALL: [Self; 4] = [Self::AgentTurn, Self::Script, Self::Command, Self::Notify];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentTurn => "agent_turn",
            Self::Script => "script",
            Self::Command => "command",
            Self::Notify => "notify",
        }
    }

    /// Whether an action of this kind reaches a model.
    #[must_use]
    pub const fn reaches_model(self) -> bool {
        matches!(self, Self::AgentTurn)
    }

    /// The job kind an action of this kind runs as.
    ///
    /// A notification-only action is a script job, so it carries the same
    /// identity, sandbox and outbox obligations as one that drives a model —
    /// skipping the model does not buy a weaker [`JobObligations`].
    #[must_use]
    pub const fn job_kind(self) -> JobKind {
        if self.reaches_model() {
            JobKind::Agent
        } else {
            JobKind::Script
        }
    }

    /// Resolve a stored spelling.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::UnknownVocabulary`] for anything else. An
    /// action this build cannot perform is refused here rather than dropped:
    /// there is no "unknown action" variant that reads as a no-op.
    pub fn from_name(name: &str) -> Result<Self, AutomationError> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.as_str() == name)
            .ok_or_else(|| unknown_vocabulary("action_kind", name))
    }
}

/// What an automation does when it fires.
///
/// Every variant names something durable — a prompt or workflow reference, a
/// registry command identifier, an authorized destination — rather than prose
/// to interpret. The set is closed, so an action the product cannot perform is
/// not constructible and cannot be stored for a later build to guess at.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AutomationAction {
    /// Start a fresh agent turn from a stored prompt.
    AgentTurn {
        /// The prompt reference.
        prompt: DurableId,
    },
    /// Run a reviewed no-agent script or workflow.
    Script {
        /// The workflow reference.
        workflow: DurableId,
    },
    /// Invoke a command from the command registry.
    Command {
        /// The command identifier, resolved against
        /// [`crate::command_registry::CommandRegistry`].
        command: CommandId,
    },
    /// Deliver a notification with zero model call.
    Notify {
        /// Where, and the grant that permits it.
        destination: AuthorizedDestination,
    },
}

impl AutomationAction {
    /// An agent-turn action.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] or [`AutomationError::NotCanonical`]
    /// for an invalid prompt reference.
    pub fn agent_turn(prompt: &str) -> Result<Self, AutomationError> {
        Ok(Self::AgentTurn {
            prompt: DurableId::new(prompt)?,
        })
    }

    /// A no-agent script action.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] or [`AutomationError::NotCanonical`]
    /// for an invalid workflow reference.
    pub fn script(workflow: &str) -> Result<Self, AutomationError> {
        Ok(Self::Script {
            workflow: DurableId::new(workflow)?,
        })
    }

    /// A registry-command action.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::UnknownVocabulary`] when the identifier is
    /// not a command identifier the registry grammar admits. A command name
    /// this build cannot spell is refused here, not carried forward as text.
    pub fn command(command_id: &str) -> Result<Self, AutomationError> {
        let command =
            CommandId::new(command_id).map_err(|_| unknown_vocabulary("command_id", command_id))?;
        Ok(Self::Command { command })
    }

    /// A notification-only action.
    #[must_use]
    pub const fn notify(destination: AuthorizedDestination) -> Self {
        Self::Notify { destination }
    }

    /// Which kind this is.
    #[must_use]
    pub const fn kind(&self) -> ActionKind {
        match self {
            Self::AgentTurn { .. } => ActionKind::AgentTurn,
            Self::Script { .. } => ActionKind::Script,
            Self::Command { .. } => ActionKind::Command,
            Self::Notify { .. } => ActionKind::Notify,
        }
    }

    /// Whether this action reaches a model.
    #[must_use]
    pub const fn reaches_model(&self) -> bool {
        self.kind().reaches_model()
    }

    /// The effect name this action requires in the automation's declared scope.
    ///
    /// Deterministic and exact: the string produced here is compared for
    /// equality against [`AutomationRevision::approved_effects`], so declaring
    /// `command:pause_intake` pre-approves exactly that command and no other,
    /// and no prefix of it.
    #[must_use]
    pub fn required_effect(&self) -> String {
        let kind = self.kind().as_str();
        match self {
            Self::AgentTurn { prompt } => format!("{kind}:{prompt}"),
            Self::Script { workflow } => format!("{kind}:{workflow}"),
            Self::Command { command } => format!("{kind}:{command}"),
            Self::Notify { destination } => format!("{kind}:{}", destination.target()),
        }
    }
}

/// A trigger bound to the action it fires, with the authority to run it.
///
/// Every field is private and there is no public constructor: the only way to
/// obtain one is [`AutomationRevision::bind`] on an enabled automation whose
/// declared scope already contains the action's required effect. So a bound
/// action is proof, not a request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundAction {
    automation_id: String,
    trigger: TriggerSpec,
    action: AutomationAction,
    approved: ApprovedEffect,
}

impl BoundAction {
    /// The automation this binding belongs to.
    #[must_use]
    pub fn automation_id(&self) -> &str {
        &self.automation_id
    }

    /// What fired.
    #[must_use]
    pub const fn trigger(&self) -> &TriggerSpec {
        &self.trigger
    }

    /// What runs.
    #[must_use]
    pub const fn action(&self) -> &AutomationAction {
        &self.action
    }

    /// The job kind this binding runs as.
    #[must_use]
    pub const fn job_kind(&self) -> JobKind {
        self.action.kind().job_kind()
    }

    /// Spend the binding as the approval a [`CompletedEffect`] requires.
    ///
    /// This is the whole chain in one line: a trigger fires, an action is bound
    /// only inside declared scope, and only a bound action yields the token
    /// that records the effect as done.
    #[must_use]
    pub fn into_approved(self) -> ApprovedEffect {
        self.approved
    }
}

/// What may happen to a triggered action.
///
/// Two-valued for the same reason [`UnattendedDecision`] is: there is no third
/// outcome that runs the action without the scope check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionBinding {
    /// The action was inside the automation's declared scope.
    Bound(BoundAction),
    /// It was not, and can only be asked for.
    RequiresApproval(ApprovalRequest),
}

/// A field path into an inbound event payload.
///
/// Dotted segments of ASCII alphanumerics, `_` and `-`. Deliberately narrower
/// than a bounded string: a field path carries no separator the canonical
/// rendering uses, so an expression renders and reads back without escaping.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FilterField(String);

impl FilterField {
    /// Validate and construct a field path.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an empty, over-long or control
    /// value, [`AutomationError::NotCanonical`] for a segment outside the
    /// grammar, and [`AutomationError::TooLarge`] above
    /// [`MAX_FILTER_FIELD_SEGMENTS`].
    pub fn new(path: &str) -> Result<Self, AutomationError> {
        bounded(path, "filter_field")?;
        let mut segments = 0_usize;
        for segment in path.split('.') {
            segments += 1;
            if segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            {
                return Err(not_canonical(
                    "filter_field",
                    "a field path is dotted segments of alphanumerics, underscore and hyphen",
                ));
            }
        }
        if segments > MAX_FILTER_FIELD_SEGMENTS {
            return Err(too_large(
                "filter_field",
                MAX_FILTER_FIELD_SEGMENTS,
                segments,
            ));
        }
        Ok(Self(path.to_owned()))
    }

    /// The validated path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FilterField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A literal a predicate compares against.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FilterValue(String);

impl FilterValue {
    /// Validate and construct a literal.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an empty, over-long or control
    /// value.
    pub fn new(value: &str) -> Result<Self, AutomationError> {
        bounded(value, "filter_value")?;
        Ok(Self(value.to_owned()))
    }

    /// The literal.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A pattern whose total repetition is bounded by construction.
///
/// The product requirement asks for "bounded regex". What is bounded here is
/// the pattern's own repetition: `*`, `+` and an open-ended `{m,}` are refused,
/// every `{m,n}` must name a finite `n`, and the product of every ceiling in
/// the pattern must not exceed [`MAX_PATTERN_EXPANSION`]. Backreferences and
/// lookaround — the two constructs that make matching cost unbounded in the
/// pattern's length — are refused outright.
///
/// This type compiles nothing and matches nothing. It establishes that a stored
/// pattern is bounded, so the engine that eventually runs it is given a bounded
/// input rather than trusted to survive an unbounded one.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedPattern(String);

impl BoundedPattern {
    /// Validate and construct a bounded pattern.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an empty, over-long or control
    /// value, [`AutomationError::NotCanonical`] for an unbounded quantifier,
    /// an unbalanced group or class, a backreference or a lookaround, and
    /// [`AutomationError::TooLarge`] when the product of the repetition
    /// ceilings exceeds [`MAX_PATTERN_EXPANSION`].
    pub fn new(pattern: &str) -> Result<Self, AutomationError> {
        bounded(pattern, "pattern")?;
        if pattern.len() > MAX_PATTERN_BYTES {
            return Err(too_large("pattern", MAX_PATTERN_BYTES, pattern.len()));
        }
        validate_bounded_pattern(pattern)?;
        Ok(Self(pattern.to_owned()))
    }

    /// The validated pattern.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Reject any pattern whose matching cost is not bounded by its own text.
fn validate_bounded_pattern(pattern: &str) -> Result<(), AutomationError> {
    let bytes = pattern.as_bytes();
    let mut index = 0_usize;
    let mut group_depth = 0_i32;
    let mut expansion = 1_u32;
    let mut quantifiable = false;
    while index < bytes.len() {
        match bytes[index] {
            b'*' | b'+' => {
                return Err(not_canonical(
                    "pattern",
                    "a repetition is bounded: * and + name no ceiling",
                ));
            }
            b'\\' => {
                let Some(&escaped) = bytes.get(index + 1) else {
                    return Err(not_canonical(
                        "pattern",
                        "a trailing backslash escapes nothing",
                    ));
                };
                if escaped.is_ascii_digit() {
                    return Err(not_canonical(
                        "pattern",
                        "a backreference makes matching cost unbounded",
                    ));
                }
                index += 2;
                quantifiable = true;
                continue;
            }
            b'(' => {
                if matches!(bytes.get(index + 1), Some(b'?')) {
                    return Err(not_canonical(
                        "pattern",
                        "lookaround and inline flags are not part of the bounded grammar",
                    ));
                }
                group_depth += 1;
                quantifiable = false;
            }
            b')' => {
                group_depth -= 1;
                if group_depth < 0 {
                    return Err(not_canonical("pattern", "a group closes before it opens"));
                }
                quantifiable = true;
            }
            b'[' => {
                let Some(close) = find_class_end(bytes, index) else {
                    return Err(not_canonical("pattern", "a character class never closes"));
                };
                index = close + 1;
                quantifiable = true;
                continue;
            }
            b']' => return Err(not_canonical("pattern", "a class closes before it opens")),
            b'{' => {
                if !quantifiable {
                    return Err(not_canonical(
                        "pattern",
                        "a repetition follows something to repeat",
                    ));
                }
                let (ceiling, next) = read_repetition(bytes, index)?;
                expansion = expansion.saturating_mul(ceiling);
                if expansion > MAX_PATTERN_EXPANSION {
                    return Err(too_large(
                        "pattern_expansion",
                        MAX_PATTERN_EXPANSION as usize,
                        expansion as usize,
                    ));
                }
                index = next;
                quantifiable = false;
                continue;
            }
            b'?' => {
                if !quantifiable {
                    return Err(not_canonical(
                        "pattern",
                        "a repetition follows something to repeat",
                    ));
                }
                quantifiable = false;
            }
            b'|' | b'^' | b'$' => quantifiable = false,
            _ => quantifiable = true,
        }
        index += 1;
    }
    if group_depth != 0 {
        return Err(not_canonical("pattern", "a group never closes"));
    }
    Ok(())
}

/// The index of the `]` closing the class opened at `open`, honouring escapes.
fn find_class_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut index = open + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b']' if index > open + 1 => return Some(index),
            _ => index += 1,
        }
    }
    None
}

/// Read `{m}` or `{m,n}` at `open`, returning the ceiling and the next index.
fn read_repetition(bytes: &[u8], open: usize) -> Result<(u32, usize), AutomationError> {
    let malformed = not_canonical(
        "pattern",
        "a repetition is {m} or {m,n} with a finite decimal ceiling",
    );
    let mut index = open + 1;
    let low_start = index;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    if index == low_start {
        return Err(malformed.clone());
    }
    let low = decimal_bound(&bytes[low_start..index]).ok_or_else(|| malformed.clone())?;
    let high = if matches!(bytes.get(index), Some(b',')) {
        index += 1;
        let high_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == high_start {
            return Err(not_canonical(
                "pattern",
                "an open-ended repetition {m,} names no ceiling",
            ));
        }
        decimal_bound(&bytes[high_start..index]).ok_or_else(|| malformed.clone())?
    } else {
        low
    };
    if !matches!(bytes.get(index), Some(b'}')) {
        return Err(malformed);
    }
    if high < low {
        return Err(not_canonical(
            "pattern",
            "a repetition ceiling is at least its floor",
        ));
    }
    Ok((high.max(1), index + 1))
}

/// Parse ASCII decimal digits, refusing anything that would not fit a `u32`.
fn decimal_bound(digits: &[u8]) -> Option<u32> {
    core::str::from_utf8(digits).ok()?.parse::<u32>().ok()
}

/// Which of the five comparisons a predicate makes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PredicateKind {
    /// Exact equality.
    Equals,
    /// Substring containment.
    Contains,
    /// Presence of the field.
    Exists,
    /// Membership in a bounded set.
    MemberOf,
    /// A bounded pattern match.
    Matches,
}

impl PredicateKind {
    /// Every comparison. The set is closed: this is the whole condition
    /// language, and there is no variant carrying source text to evaluate.
    pub const ALL: [Self; 5] = [
        Self::Equals,
        Self::Contains,
        Self::Exists,
        Self::MemberOf,
        Self::Matches,
    ];

    /// Stable spelling, used in the canonical rendering.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Equals => "eq",
            Self::Contains => "contains",
            Self::Exists => "exists",
            Self::MemberOf => "in",
            Self::Matches => "matches",
        }
    }

    /// Resolve a stored spelling.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::UnknownVocabulary`] for anything else.
    pub fn from_name(name: &str) -> Result<Self, AutomationError> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.as_str() == name)
            .ok_or_else(|| unknown_vocabulary("predicate_kind", name))
    }
}

/// One comparison against one field.
///
/// The whole condition vocabulary. There is no `Script`, no `Expression` and no
/// variant holding source text, so a filter cannot become a program: what a
/// route can ask about an inbound event is fixed by this enum at compile time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FilterPredicate {
    /// The field equals the value exactly.
    Equals {
        /// The required value.
        value: FilterValue,
    },
    /// The field contains the substring.
    Contains {
        /// The required substring.
        substring: FilterValue,
    },
    /// The field is present, whatever it holds.
    Exists,
    /// The field is one of a bounded set of values.
    MemberOf {
        /// The permitted values, sorted and deduplicated.
        values: Vec<FilterValue>,
    },
    /// The field matches a bounded pattern.
    Matches {
        /// The bounded pattern.
        pattern: BoundedPattern,
    },
}

impl FilterPredicate {
    /// Require exact equality.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid value.
    pub fn equals(value: &str) -> Result<Self, AutomationError> {
        Ok(Self::Equals {
            value: FilterValue::new(value)?,
        })
    }

    /// Require containment.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid substring.
    pub fn contains(substring: &str) -> Result<Self, AutomationError> {
        Ok(Self::Contains {
            substring: FilterValue::new(substring)?,
        })
    }

    /// Require membership in a bounded set.
    ///
    /// The values are sorted and deduplicated, so a set is a set: two
    /// declarations listing the same values in different orders are equal and
    /// render identically.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid value,
    /// [`AutomationError::NotCanonical`] for an empty set — which would admit
    /// nothing and is more likely a mistake than an intent — and
    /// [`AutomationError::TooLarge`] above [`MAX_MEMBERSHIP_VALUES`].
    pub fn member_of(values: &[&str]) -> Result<Self, AutomationError> {
        if values.is_empty() {
            return Err(not_canonical(
                "membership_values",
                "a membership set names at least one value",
            ));
        }
        if values.len() > MAX_MEMBERSHIP_VALUES {
            return Err(too_large(
                "membership_values",
                MAX_MEMBERSHIP_VALUES,
                values.len(),
            ));
        }
        let mut parsed = values
            .iter()
            .map(|value| FilterValue::new(value))
            .collect::<Result<Vec<_>, _>>()?;
        parsed.sort();
        parsed.dedup();
        Ok(Self::MemberOf { values: parsed })
    }

    /// Require a bounded pattern match.
    ///
    /// # Errors
    ///
    /// Returns whatever [`BoundedPattern::new`] refuses the pattern with.
    pub fn matches(pattern: &str) -> Result<Self, AutomationError> {
        Ok(Self::Matches {
            pattern: BoundedPattern::new(pattern)?,
        })
    }

    /// Which comparison this is.
    #[must_use]
    pub const fn kind(&self) -> PredicateKind {
        match self {
            Self::Equals { .. } => PredicateKind::Equals,
            Self::Contains { .. } => PredicateKind::Contains,
            Self::Exists => PredicateKind::Exists,
            Self::MemberOf { .. } => PredicateKind::MemberOf,
            Self::Matches { .. } => PredicateKind::Matches,
        }
    }
}

/// A declarative condition over an inbound event.
///
/// A tree of the closed [`FilterPredicate`] vocabulary under `all`, `any` and
/// `not`. Depth and node count are bounded at construction, so a condition
/// cannot be grown into a denial-of-service against whatever evaluates it, and
/// there is no variant carrying source text, so it cannot be grown into a
/// program either.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FilterExpression {
    /// One comparison against one field.
    Field {
        /// The field path.
        field: FilterField,
        /// The comparison.
        predicate: FilterPredicate,
    },
    /// Every operand must hold.
    All {
        /// The operands, in declared order.
        operands: Vec<FilterExpression>,
    },
    /// At least one operand must hold.
    Any {
        /// The operands, in declared order.
        operands: Vec<FilterExpression>,
    },
    /// The operand must not hold.
    Not {
        /// The negated operand.
        operand: Box<FilterExpression>,
    },
}

impl FilterExpression {
    /// One comparison against one field.
    ///
    /// # Errors
    ///
    /// Returns whatever [`FilterField::new`] refuses the path with, and
    /// [`AutomationError::TooLarge`] when the node's canonical rendering would
    /// exceed [`MAX_FILTER_RENDERING_BYTES`].
    pub fn field(field: &str, predicate: FilterPredicate) -> Result<Self, AutomationError> {
        Self::Field {
            field: FilterField::new(field)?,
            predicate,
        }
        .within_bounds()
    }

    /// Require every operand.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::NotCanonical`] for no operands and
    /// [`AutomationError::TooLarge`] beyond [`MAX_FILTER_DEPTH`] or
    /// [`MAX_FILTER_NODES`].
    pub fn all(operands: Vec<Self>) -> Result<Self, AutomationError> {
        Self::combined(operands, true)
    }

    /// Require at least one operand.
    ///
    /// # Errors
    ///
    /// The same refusals as [`Self::all`].
    pub fn any(operands: Vec<Self>) -> Result<Self, AutomationError> {
        Self::combined(operands, false)
    }

    fn combined(operands: Vec<Self>, conjunction: bool) -> Result<Self, AutomationError> {
        if operands.is_empty() {
            return Err(not_canonical(
                "filter_operands",
                "a combinator names at least one operand",
            ));
        }
        let combined = if conjunction {
            Self::All { operands }
        } else {
            Self::Any { operands }
        };
        combined.within_bounds()
    }

    /// Negate an expression.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::TooLarge`] beyond [`MAX_FILTER_DEPTH`] or
    /// [`MAX_FILTER_NODES`].
    pub fn negating(operand: Self) -> Result<Self, AutomationError> {
        Self::Not {
            operand: Box::new(operand),
        }
        .within_bounds()
    }

    fn within_bounds(self) -> Result<Self, AutomationError> {
        let depth = self.depth();
        if depth > MAX_FILTER_DEPTH {
            return Err(too_large("filter_depth", MAX_FILTER_DEPTH, depth));
        }
        let nodes = self.nodes();
        if nodes > MAX_FILTER_NODES {
            return Err(too_large("filter_nodes", MAX_FILTER_NODES, nodes));
        }
        let rendered = self.render().len();
        if rendered > MAX_FILTER_RENDERING_BYTES {
            return Err(too_large(
                "filter_rendering",
                MAX_FILTER_RENDERING_BYTES,
                rendered,
            ));
        }
        Ok(self)
    }

    /// How deeply this expression nests. A single comparison is depth one.
    #[must_use]
    pub fn depth(&self) -> usize {
        match self {
            Self::Field { .. } => 1,
            Self::All { operands } | Self::Any { operands } => {
                1 + operands.iter().map(Self::depth).max().unwrap_or(0)
            }
            Self::Not { operand } => 1 + operand.depth(),
        }
    }

    /// How many nodes this expression holds.
    #[must_use]
    pub fn nodes(&self) -> usize {
        match self {
            Self::Field { .. } => 1,
            Self::All { operands } | Self::Any { operands } => {
                1 + operands.iter().map(Self::nodes).sum::<usize>()
            }
            Self::Not { operand } => 1 + operand.nodes(),
        }
    }

    /// Render the canonical form.
    ///
    /// Round-trips through [`Self::from_rendering`]. Every free-text leaf is
    /// written length-prefixed as `<bytes>:<text>`, so a value holding a comma
    /// or a bracket cannot be read as structure and no escaping is involved.
    ///
    /// Operand order is preserved and is part of the value: `all(a,b)` and
    /// `all(b,a)` are distinct expressions that render distinctly. Membership
    /// values are not, because [`FilterPredicate::member_of`] already sorted
    /// them into a set.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.render_into(&mut out);
        out
    }

    fn render_into(&self, out: &mut String) {
        match self {
            Self::Field { field, predicate } => {
                out.push_str(predicate.kind().as_str());
                out.push('(');
                out.push_str(field.as_str());
                match predicate {
                    FilterPredicate::Exists => {}
                    FilterPredicate::Equals { value }
                    | FilterPredicate::Contains { substring: value } => {
                        out.push(',');
                        push_counted(out, value.as_str());
                    }
                    FilterPredicate::MemberOf { values } => {
                        for value in values {
                            out.push(',');
                            push_counted(out, value.as_str());
                        }
                    }
                    FilterPredicate::Matches { pattern } => {
                        out.push(',');
                        push_counted(out, pattern.as_str());
                    }
                }
                out.push(')');
            }
            Self::All { operands } | Self::Any { operands } => {
                out.push_str(if matches!(self, Self::All { .. }) {
                    "all"
                } else {
                    "any"
                });
                out.push('(');
                for (position, operand) in operands.iter().enumerate() {
                    if position > 0 {
                        out.push(',');
                    }
                    operand.render_into(out);
                }
                out.push(')');
            }
            Self::Not { operand } => {
                out.push_str("not(");
                operand.render_into(out);
                out.push(')');
            }
        }
    }

    /// Read a canonical rendering back.
    ///
    /// This is the reader storage uses. It accepts exactly what
    /// [`Self::render`] writes: a trailing byte, a wrong length prefix or an
    /// unknown keyword is refused rather than tolerated.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::UnknownVocabulary`] for a keyword outside the
    /// closed vocabulary and [`AutomationError::NotCanonical`] for a rendering
    /// that is malformed or has trailing input.
    pub fn from_rendering(rendered: &str) -> Result<Self, AutomationError> {
        bounded_within(rendered, "filter_expression", MAX_FILTER_RENDERING_BYTES)?;
        let (expression, rest) = Self::read(rendered)?;
        if !rest.is_empty() {
            return Err(not_canonical(
                "filter_expression",
                "a canonical rendering ends where its outermost node does",
            ));
        }
        expression.within_bounds()
    }

    fn read(input: &str) -> Result<(Self, &str), AutomationError> {
        let Some(open) = input.find('(') else {
            return Err(not_canonical(
                "filter_expression",
                "every node opens with a keyword and a parenthesis",
            ));
        };
        let keyword = &input[..open];
        let rest = &input[open + 1..];
        match keyword {
            "all" | "any" => {
                let (operands, rest) = read_operands(rest)?;
                let combined = if keyword == "all" {
                    Self::All { operands }
                } else {
                    Self::Any { operands }
                };
                Ok((combined, rest))
            }
            "not" => {
                let (operand, rest) = Self::read(rest)?;
                let rest = expect(rest, b')')?;
                Ok((
                    Self::Not {
                        operand: Box::new(operand),
                    },
                    rest,
                ))
            }
            _ => {
                let kind = PredicateKind::from_name(keyword)?;
                read_field_node(kind, rest)
            }
        }
    }
}

/// Read one or more comma-separated operands, then the closing parenthesis.
fn read_operands(mut input: &str) -> Result<(Vec<FilterExpression>, &str), AutomationError> {
    let mut operands = Vec::new();
    loop {
        let (operand, rest) = FilterExpression::read(input)?;
        operands.push(operand);
        match rest.as_bytes().first() {
            Some(b',') => input = &rest[1..],
            Some(b')') => return Ok((operands, &rest[1..])),
            _ => {
                return Err(not_canonical(
                    "filter_expression",
                    "operands are comma separated and the list closes",
                ));
            }
        }
    }
}

/// Read the field, the predicate payload and the closing parenthesis.
fn read_field_node(
    kind: PredicateKind,
    input: &str,
) -> Result<(FilterExpression, &str), AutomationError> {
    let malformed = not_canonical(
        "filter_expression",
        "a comparison is keyword(field) or keyword(field,<bytes>:<text>)",
    );
    let terminator = input
        .bytes()
        .position(|byte| matches!(byte, b',' | b')'))
        .ok_or_else(|| malformed.clone())?;
    let field = &input[..terminator];
    let mut rest = &input[terminator..];
    let predicate = match kind {
        PredicateKind::Exists => FilterPredicate::Exists,
        PredicateKind::Equals | PredicateKind::Contains | PredicateKind::Matches => {
            rest = expect(rest, b',')?;
            let (value, tail) = read_counted(rest)?;
            rest = tail;
            match kind {
                PredicateKind::Equals => FilterPredicate::equals(value)?,
                PredicateKind::Contains => FilterPredicate::contains(value)?,
                _ => FilterPredicate::matches(value)?,
            }
        }
        PredicateKind::MemberOf => {
            let mut values = Vec::new();
            loop {
                rest = expect(rest, b',')?;
                let (value, tail) = read_counted(rest)?;
                values.push(value);
                rest = tail;
                if !matches!(rest.as_bytes().first(), Some(b',')) {
                    break;
                }
            }
            FilterPredicate::member_of(&values)?
        }
    };
    let rest = expect(rest, b')')?;
    Ok((FilterExpression::field(field, predicate)?, rest))
}

/// Write `<bytes>:<text>`.
fn push_counted(out: &mut String, text: &str) {
    out.push_str(&text.len().to_string());
    out.push(':');
    out.push_str(text);
}

/// Read `<bytes>:<text>`, refusing a length that is not exactly the text's.
fn read_counted(input: &str) -> Result<(&str, &str), AutomationError> {
    let malformed = not_canonical(
        "filter_expression",
        "a literal is written <bytes>:<text> with an exact byte count",
    );
    let separator = input.find(':').ok_or_else(|| malformed.clone())?;
    let digits = &input[..separator];
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(malformed.clone());
    }
    let Ok(length) = digits.parse::<usize>() else {
        return Err(not_canonical(
            "filter_expression",
            "a literal is written <bytes>:<text> with an exact byte count",
        ));
    };
    let body = &input[separator + 1..];
    let value = body.get(..length).ok_or(malformed)?;
    Ok((value, &body[length..]))
}

/// Consume one expected byte.
fn expect(input: &str, byte: u8) -> Result<&str, AutomationError> {
    if input.as_bytes().first() == Some(&byte) {
        Ok(&input[1..])
    } else {
        Err(not_canonical(
            "filter_expression",
            "a canonical rendering places its separators exactly",
        ))
    }
}

fn bounded(value: &str, field: &'static str) -> Result<(), AutomationError> {
    bounded_within(value, field, MAX_AUTOMATION_FIELD_BYTES)
}

fn bounded_within(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), AutomationError> {
    let error = if value.is_empty() {
        Some(ValueError::Empty)
    } else if value.len() > max_bytes {
        Some(ValueError::TooLong {
            max_bytes,
            actual_bytes: value.len(),
        })
    } else if value.chars().any(char::is_control) {
        Some(ValueError::ControlCharacter)
    } else {
        None
    };
    match error {
        Some(error) => Err(AutomationError::Field { field, error }),
        None => Ok(()),
    }
}
