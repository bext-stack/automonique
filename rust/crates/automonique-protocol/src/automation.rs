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

use core::fmt;
use core::marker::PhantomData;
use std::error::Error;

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
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
        }
    }
}

impl Error for AutomationError {}

const fn not_canonical(field: &'static str, reason: &'static str) -> AutomationError {
    AutomationError::NotCanonical { field, reason }
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

/// One declarative filter on an inbound event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventFilter {
    field: String,
    equals: String,
}

impl EventFilter {
    /// Require a field to equal a value.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid component.
    pub fn requiring(field: &str, equals: &str) -> Result<Self, AutomationError> {
        bounded(field, "filter_field")?;
        bounded(equals, "filter_value")?;
        Ok(Self {
            field: field.to_owned(),
            equals: equals.to_owned(),
        })
    }

    /// The filtered field.
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }

    /// The required value.
    #[must_use]
    pub fn equals(&self) -> &str {
        &self.equals
    }
}

/// The declarative filters a route applies.
///
/// Accepting every allowed event type is a named decision rather than an
/// omitted field, so a route never silently lacks filtering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventFilters(Vec<EventFilter>);

impl EventFilters {
    /// Accept every event of an allowed type.
    #[must_use]
    pub const fn accept_all_allowed_types() -> Self {
        Self(Vec::new())
    }

    /// Require every listed filter to match.
    #[must_use]
    pub const fn requiring_all(filters: Vec<EventFilter>) -> Self {
        Self(filters)
    }

    /// The declared filters.
    #[must_use]
    pub fn as_slice(&self) -> &[EventFilter] {
        &self.0
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

fn bounded(value: &str, field: &'static str) -> Result<(), AutomationError> {
    let error = if value.is_empty() {
        Some(ValueError::Empty)
    } else if value.len() > MAX_AUTOMATION_FIELD_BYTES {
        Some(ValueError::TooLong {
            max_bytes: MAX_AUTOMATION_FIELD_BYTES,
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
