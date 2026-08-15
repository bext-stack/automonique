// SPDX-License-Identifier: Elastic-2.0

//! What a scheduler has to do before it is allowed to run anything real.
//!
//! The property, from `docs/product-plan/requirements/scheduler-core.md`:
//! **bounded parallelism**, **per-scope serialization**, and **pause/cancel**
//! semantics that do not lose or duplicate work. `docs/product-plan/reference/
//! feature-parity.md:90` calls this "the scheduler core is entirely unpinned —
//! the largest single gap", which is why the spec and this suite exist before
//! the scheduler does.
//!
//! This is the fourth of the four safety properties
//! `automonique_protocol::safety_conformance` re-specifies. It lives here rather
//! than beside the other three because it judges *this* crate's substrate: a
//! tick is admitted under a [`SchedulerFence`], and restating that vocabulary in
//! a crate that cannot see this one would create the second authority the
//! protocol crate's conformance modules spend their headers warning about.
//!
//! # The three properties, and why each is a safety property
//!
//! **Bounded parallelism** is a resource bound. An unbounded scheduler does not
//! fail by running too much; it fails by running exactly as much as the host can
//! stand and then a little more, at which point every lease in flight is at risk
//! rather than the one that was over budget.
//!
//! **Per-scope serialization** is a correctness bound. Two agents editing one
//! workspace at once is not slow, it is wrong, and no amount of retrying fixes
//! an interleaved edit.
//!
//! **Pause and cancel** are the operator's stop button, and a stop button that
//! silently drops work is worse than none: the operator believes the work is
//! stopped and the system believes it never existed. So cancelling *queued* work
//! removes it and says so, while cancelling *running* work is a **request** —
//! custody stays with the scheduler until the terminal commit lands, which is
//! the same discipline [`crate::DurableScheduler`] applies to a claim.
//!
//! # Honest present
//!
//! Nothing here schedules anything. [`ReferenceScheduler`] holds rows in
//! vectors, has no lease timer, no store, and no executor, and it exists to
//! prove [`verify_scheduler_core`] is satisfiable. The durable scheduler that
//! must pass this suite is
//! `docs/improvement-plan/implementation/M8-scheduler-reload-isolation.md` #45.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use crate::{CoordinateError, SchedulerFence, validate_id};

/// The largest parallelism limit this suite treats as bounded.
///
/// A limit above this is not a limit; it is a number chosen so that the check
/// passes. **Owner-confirmable** — the ceiling exists to refuse "unbounded
/// spelled as a big integer", not to recommend any particular width.
pub const MAX_PARALLELISM_LIMIT: u32 = 1_024;

/// The smallest parallelism limit a conforming scheduler may declare.
///
/// One is a valid *operational* setting and a useless *conformance* subject: a
/// scheduler that never runs two things at once satisfies every parallelism
/// bound by accident, so the suite could not tell a correct implementation from
/// a serial one. A subject is asked to present itself with room for at least
/// two.
pub const MIN_PARALLELISM_LIMIT: u32 = 2;

/// Durable identity of one unit of schedulable work.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkId(String);

impl WorkId {
    /// Validate and construct a work identity.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinateError::InvalidField`] when the value is empty, over
    /// the crate's identifier ceiling, or carries a control character.
    pub fn new(value: impl Into<String>) -> Result<Self, CoordinateError> {
        let value = value.into();
        validate_id(&value, "work_id")?;
        Ok(Self(value))
    }

    /// The validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WorkId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The serialization domain a unit of work belongs to.
///
/// One scope runs one item at a time. What a scope *is* — a workspace, a
/// conversation thread, a tenant — is the deployment's decision and not this
/// module's; the property is that whatever it is, two of its items never
/// overlap.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScopeId(String);

impl ScopeId {
    /// Validate and construct a scope identity.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinateError::InvalidField`] when the value is empty, over
    /// the crate's identifier ceiling, or carries a control character.
    pub fn new(value: impl Into<String>) -> Result<Self, CoordinateError> {
        let value = value.into();
        validate_id(&value, "scope_id")?;
        Ok(Self(value))
    }

    /// The validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ScopeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One submitted unit of work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuedWork {
    work_id: WorkId,
    scope: ScopeId,
}

impl QueuedWork {
    /// Submit `work_id` into `scope`.
    #[must_use]
    pub const fn new(work_id: WorkId, scope: ScopeId) -> Self {
        Self { work_id, scope }
    }

    /// Durable work identity.
    #[must_use]
    pub const fn work_id(&self) -> &WorkId {
        &self.work_id
    }

    /// The scope that serializes it.
    #[must_use]
    pub const fn scope(&self) -> &ScopeId {
        &self.scope
    }
}

/// Where a unit of work has got to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkState {
    /// Admitted, not started.
    Queued,
    /// Started, holding one parallelism slot.
    Running,
    /// Started, and an operator has asked it to stop. Still holds its slot.
    StopRequested,
    /// Terminal: it ran to completion.
    Completed,
    /// Terminal: it never ran, or it stopped on request.
    Cancelled,
}

impl WorkState {
    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::StopRequested => "stop_requested",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Whether no further transition is possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }

    /// Whether this state holds a parallelism slot.
    #[must_use]
    pub const fn holds_a_slot(self) -> bool {
        matches!(self, Self::Running | Self::StopRequested)
    }
}

/// What cancelling one unit of work achieved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelDisposition {
    /// It was queued; it is now terminal and will never run.
    NeverStarted,
    /// It is running; a stop was requested and custody stays with the
    /// scheduler until the terminal commit.
    StopRequested,
}

impl CancelDisposition {
    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NeverStarted => "never_started",
            Self::StopRequested => "stop_requested",
        }
    }
}

/// Why a scheduler verb was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerRefusal {
    /// The presented fence is not the authority this scheduler holds.
    StaleFence,
    /// No such work.
    UnknownWork,
    /// That work identity is already admitted.
    DuplicateWork,
    /// The verb needs work that is not in a terminal state.
    AlreadyTerminal,
    /// The verb needs running work and this work is not running.
    NotRunning,
}

impl SchedulerRefusal {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::StaleFence => "stale_fence",
            Self::UnknownWork => "unknown_work",
            Self::DuplicateWork => "duplicate_work",
            Self::AlreadyTerminal => "already_terminal",
            Self::NotRunning => "not_running",
        }
    }
}

/// A scheduler that bounds parallelism, serializes scopes, and can be stopped.
///
/// Every start goes through [`SchedulerCore::tick`] under an explicit fence, so
/// "who was allowed to start this" is a parameter rather than ambient state.
pub trait SchedulerCore {
    /// The most work this scheduler will run at once.
    fn parallelism_limit(&self) -> u32;

    /// The fence this scheduler currently holds.
    fn fence(&self) -> SchedulerFence;

    /// Admit one unit of work.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerRefusal::DuplicateWork`] when the identity is already
    /// admitted. Admission never starts anything: starting is
    /// [`SchedulerCore::tick`]'s job, and keeping them separate is what makes
    /// the parallelism bound checkable.
    fn submit(&mut self, work: &QueuedWork) -> Result<(), SchedulerRefusal>;

    /// Start as much work as policy allows, and report what started.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerRefusal::StaleFence`] when `fence` is not this
    /// scheduler's authority. A stale tick starts nothing at all — it is not a
    /// partial tick.
    fn tick(&mut self, fence: &SchedulerFence) -> Result<Vec<WorkId>, SchedulerRefusal>;

    /// Commit the terminal transition for running work, freeing its slot.
    ///
    /// Work that was asked to stop commits as [`WorkState::Cancelled`]; work
    /// that was not commits as [`WorkState::Completed`].
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerRefusal::NotRunning`] for work that holds no slot and
    /// [`SchedulerRefusal::UnknownWork`] for an identity never admitted.
    fn complete(&mut self, work_id: &WorkId) -> Result<WorkState, SchedulerRefusal>;

    /// Stop admitting new work from `scope`. Running work is unaffected.
    ///
    /// Pause is a desired state, not an event: pausing a paused scope is not an
    /// error, because an operator who pauses twice meant it both times.
    fn pause(&mut self, scope: &ScopeId);

    /// Admit work from `scope` again.
    fn resume(&mut self, scope: &ScopeId);

    /// Cancel one unit of work.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerRefusal::UnknownWork`] for an identity never
    /// admitted and [`SchedulerRefusal::AlreadyTerminal`] for work that has
    /// already finished.
    fn cancel(&mut self, work_id: &WorkId) -> Result<CancelDisposition, SchedulerRefusal>;

    /// Every work identity currently holding a parallelism slot.
    fn running(&self) -> Vec<WorkId>;

    /// The state of one admitted work identity.
    fn state(&self, work_id: &WorkId) -> Option<WorkState>;
}

/// A candidate failed one named case of the scheduler suite.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchedulerViolation {
    case: &'static str,
    detail: String,
}

impl SchedulerViolation {
    /// Record a failure of one named case.
    #[must_use]
    pub fn new(case: &'static str, detail: impl Into<String>) -> Self {
        Self {
            case,
            detail: detail.into(),
        }
    }

    /// The stable name of the case that failed.
    #[must_use]
    pub const fn case(&self) -> &'static str {
        self.case
    }

    /// Human-readable detail. Not a stable interface.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for SchedulerViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "case {} failed: {}", self.case, self.detail)
    }
}

impl Error for SchedulerViolation {}

/// What one suite run covered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchedulerReport {
    cases: Vec<&'static str>,
}

impl SchedulerReport {
    /// Every case that ran, in execution order.
    #[must_use]
    pub fn cases(&self) -> &[&'static str] {
        &self.cases
    }
}

/// Case names this suite runs, in order.
pub const CASES: [&str; 10] = [
    CASE_LIMIT_IS_BOUNDED,
    CASE_PARALLELISM_NEVER_EXCEEDS_THE_LIMIT,
    CASE_ONE_ITEM_PER_SCOPE,
    CASE_SCOPE_ADMITS_IN_SUBMISSION_ORDER,
    CASE_PAUSE_STARTS_NOTHING_NEW,
    CASE_PAUSE_DOES_NOT_STOP_RUNNING_WORK,
    CASE_RESUME_LOSES_AND_DUPLICATES_NOTHING,
    CASE_CANCELLED_QUEUED_WORK_NEVER_RUNS,
    CASE_CANCELLED_RUNNING_WORK_KEEPS_ITS_SLOT,
    CASE_A_STALE_FENCE_STARTS_NOTHING,
];

/// The declared limit is a limit.
pub const CASE_LIMIT_IS_BOUNDED: &str = "the_declared_parallelism_limit_is_bounded";
/// Never more than the limit runs at once.
pub const CASE_PARALLELISM_NEVER_EXCEEDS_THE_LIMIT: &str =
    "parallelism_never_exceeds_the_declared_limit";
/// One scope, one running item.
pub const CASE_ONE_ITEM_PER_SCOPE: &str = "one_scope_runs_one_item_at_a_time";
/// A scope's items start in the order they were submitted.
pub const CASE_SCOPE_ADMITS_IN_SUBMISSION_ORDER: &str = "a_scope_admits_in_submission_order";
/// A paused scope starts nothing.
pub const CASE_PAUSE_STARTS_NOTHING_NEW: &str = "a_paused_scope_starts_nothing_new";
/// A pause is not a cancel.
pub const CASE_PAUSE_DOES_NOT_STOP_RUNNING_WORK: &str = "a_pause_does_not_stop_running_work";
/// Resume picks up exactly where the pause left off.
pub const CASE_RESUME_LOSES_AND_DUPLICATES_NOTHING: &str =
    "resume_loses_no_work_and_duplicates_none";
/// Cancelling queued work means it never runs.
pub const CASE_CANCELLED_QUEUED_WORK_NEVER_RUNS: &str = "cancelled_queued_work_never_runs";
/// Cancelling running work is a request, and the slot stays held.
pub const CASE_CANCELLED_RUNNING_WORK_KEEPS_ITS_SLOT: &str =
    "cancelled_running_work_keeps_its_slot_until_terminal";
/// A tick under the wrong authority starts nothing.
pub const CASE_A_STALE_FENCE_STARTS_NOTHING: &str = "a_stale_fence_starts_nothing";

/// Run the scheduler-core suite, building a fresh subject for every case.
///
/// The suite takes a factory rather than one subject because pause state and
/// occupied slots are scheduler-wide: a case that left a scope paused would
/// silently change the meaning of every case after it, and the resulting suite
/// would be an ordering puzzle rather than a specification.
///
/// # Errors
///
/// Returns the first [`SchedulerViolation`] a subject produces.
pub fn verify_scheduler_core<S, F>(new_subject: F) -> Result<SchedulerReport, SchedulerViolation>
where
    S: SchedulerCore,
    F: Fn() -> S,
{
    let mut cases = Vec::new();

    // A limit that is not a limit makes every later case vacuous, so it is
    // checked first and the run stops here if it fails.
    let limit = new_subject().parallelism_limit();
    require(
        CASE_LIMIT_IS_BOUNDED,
        (MIN_PARALLELISM_LIMIT..=MAX_PARALLELISM_LIMIT).contains(&limit),
        format!(
            "the subject declared a limit of {limit}; the suite needs {MIN_PARALLELISM_LIMIT}..={MAX_PARALLELISM_LIMIT}"
        ),
    )?;
    cases.push(CASE_LIMIT_IS_BOUNDED);
    let limit = limit as usize;

    parallelism_is_bounded(&new_subject, limit)?;
    cases.push(CASE_PARALLELISM_NEVER_EXCEEDS_THE_LIMIT);

    scopes_serialize(&new_subject)?;
    cases.push(CASE_ONE_ITEM_PER_SCOPE);
    cases.push(CASE_SCOPE_ADMITS_IN_SUBMISSION_ORDER);

    pause_and_resume(&new_subject)?;
    cases.push(CASE_PAUSE_STARTS_NOTHING_NEW);
    cases.push(CASE_PAUSE_DOES_NOT_STOP_RUNNING_WORK);
    cases.push(CASE_RESUME_LOSES_AND_DUPLICATES_NOTHING);

    cancellation(&new_subject, limit)?;
    cases.push(CASE_CANCELLED_QUEUED_WORK_NEVER_RUNS);
    cases.push(CASE_CANCELLED_RUNNING_WORK_KEEPS_ITS_SLOT);

    stale_fence(&new_subject)?;
    cases.push(CASE_A_STALE_FENCE_STARTS_NOTHING);

    Ok(SchedulerReport { cases })
}

/// More ready work than slots, each item in its own scope, so the only thing
/// that can hold anything back is the limit itself.
fn parallelism_is_bounded<S: SchedulerCore, F: Fn() -> S>(
    new_subject: &F,
    limit: usize,
) -> Result<(), SchedulerViolation> {
    const CASE: &str = CASE_PARALLELISM_NEVER_EXCEEDS_THE_LIMIT;
    let mut subject = new_subject();
    let fence = subject.fence();
    let total = limit + 2;
    for index in 0..total {
        submit(
            CASE,
            &mut subject,
            &format!("work-{index}"),
            &format!("scope-{index}"),
        )?;
    }

    let started = subject.tick(&fence).map_err(|refusal| {
        SchedulerViolation::new(
            CASE,
            format!("a valid tick refused with {}", refusal.category()),
        )
    })?;
    require(
        CASE,
        started.len() == limit,
        format!(
            "a first tick started {} items with {limit} slots",
            started.len()
        ),
    )?;
    require(
        CASE,
        subject.running().len() == limit,
        format!(
            "{} items are running with {limit} slots",
            subject.running().len()
        ),
    )?;

    let again = subject.tick(&fence).map_err(|refusal| {
        SchedulerViolation::new(
            CASE,
            format!("a second tick refused with {}", refusal.category()),
        )
    })?;
    require(
        CASE,
        again.is_empty(),
        format!("a full scheduler started {} more items", again.len()),
    )?;

    // Freeing exactly one slot admits exactly one more item.
    let first = started
        .first()
        .cloned()
        .ok_or_else(|| SchedulerViolation::new(CASE, "the first tick started nothing"))?;
    subject.complete(&first).map_err(|refusal| {
        SchedulerViolation::new(
            CASE,
            format!(
                "completing running work refused with {}",
                refusal.category()
            ),
        )
    })?;
    let third = subject.tick(&fence).map_err(|refusal| {
        SchedulerViolation::new(CASE, format!("a tick refused with {}", refusal.category()))
    })?;
    require(
        CASE,
        third.len() == 1 && subject.running().len() == limit,
        format!(
            "freeing one slot started {} items, leaving {} running",
            third.len(),
            subject.running().len()
        ),
    )?;
    no_duplicate_starts(CASE, [started, again, third].concat())
}

/// Three items in one scope. The scope, not the limit, is what holds them.
fn scopes_serialize<S: SchedulerCore, F: Fn() -> S>(
    new_subject: &F,
) -> Result<(), SchedulerViolation> {
    const CASE: &str = CASE_ONE_ITEM_PER_SCOPE;
    const ORDER: &str = CASE_SCOPE_ADMITS_IN_SUBMISSION_ORDER;
    let mut subject = new_subject();
    let fence = subject.fence();
    let ids = ["serial-1", "serial-2", "serial-3"];
    for id in ids {
        submit(CASE, &mut subject, id, "one-scope")?;
    }

    let started = tick(CASE, &mut subject, &fence)?;
    require(
        CASE,
        started.len() == 1,
        format!(
            "one scope started {} items at once with a limit of two or more",
            started.len()
        ),
    )?;
    require(
        ORDER,
        started[0].as_str() == ids[0],
        format!(
            "the scope started {} first; submissions were {ids:?}",
            started[0]
        ),
    )?;

    // Each completion admits the next one, and only the next one.
    let mut order = vec![started[0].clone()];
    for expected in &ids[1..] {
        let running = order
            .last()
            .cloned()
            .ok_or_else(|| SchedulerViolation::new(CASE, "no work was running"))?;
        subject.complete(&running).map_err(|refusal| {
            SchedulerViolation::new(
                CASE,
                format!(
                    "completing running work refused with {}",
                    refusal.category()
                ),
            )
        })?;
        let next = tick(CASE, &mut subject, &fence)?;
        require(
            CASE,
            next.len() == 1,
            format!("one scope started {} items after a completion", next.len()),
        )?;
        require(
            ORDER,
            next[0].as_str() == *expected,
            format!(
                "the scope started {} where {expected} was next in line",
                next[0]
            ),
        )?;
        order.push(next[0].clone());
    }
    no_duplicate_starts(CASE, order)
}

/// Pause holds back starts and nothing else; resume gives the queue back whole.
fn pause_and_resume<S: SchedulerCore, F: Fn() -> S>(
    new_subject: &F,
) -> Result<(), SchedulerViolation> {
    const CASE: &str = CASE_PAUSE_STARTS_NOTHING_NEW;
    const RUNNING: &str = CASE_PAUSE_DOES_NOT_STOP_RUNNING_WORK;
    const RESUME: &str = CASE_RESUME_LOSES_AND_DUPLICATES_NOTHING;
    let mut subject = new_subject();
    let fence = subject.fence();
    let scope = scope_id(CASE, "paused-scope")?;
    for id in ["paused-1", "paused-2", "paused-3"] {
        submit(CASE, &mut subject, id, "paused-scope")?;
    }

    let started = tick(CASE, &mut subject, &fence)?;
    require(
        CASE,
        started.len() == 1,
        "the scope did not start its first item",
    )?;
    let running = started[0].clone();

    subject.pause(&scope);
    require(
        RUNNING,
        subject.state(&running) == Some(WorkState::Running),
        "pausing a scope stopped the work that was already running",
    )?;
    require(
        RUNNING,
        subject.running().contains(&running),
        "pausing a scope dropped the running item out of the running set",
    )?;

    // Free the slot. A paused scope must still not start anything.
    subject.complete(&running).map_err(|refusal| {
        SchedulerViolation::new(
            RUNNING,
            format!(
                "running work in a paused scope could not complete: {}",
                refusal.category()
            ),
        )
    })?;
    let while_paused = tick(CASE, &mut subject, &fence)?;
    require(
        CASE,
        while_paused.is_empty(),
        format!("a paused scope started {} items", while_paused.len()),
    )?;

    // Pausing twice is not an error, and does not deepen anything.
    subject.pause(&scope);
    let still_paused = tick(CASE, &mut subject, &fence)?;
    require(
        CASE,
        still_paused.is_empty(),
        "a twice-paused scope started work",
    )?;

    subject.resume(&scope);
    let after = tick(RESUME, &mut subject, &fence)?;
    require(
        RESUME,
        after.len() == 1 && after[0].as_str() == "paused-2",
        format!("resume started {after:?}; paused-2 was next in line"),
    )?;
    require(
        RESUME,
        subject.state(&work_id(RESUME, "paused-3")?) == Some(WorkState::Queued),
        "the third item did not survive the pause as queued work",
    )?;
    no_duplicate_starts(
        RESUME,
        [started, while_paused, still_paused, after].concat(),
    )
}

/// Cancelling queued work erases it; cancelling running work asks it to stop.
fn cancellation<S: SchedulerCore, F: Fn() -> S>(
    new_subject: &F,
    limit: usize,
) -> Result<(), SchedulerViolation> {
    const QUEUED: &str = CASE_CANCELLED_QUEUED_WORK_NEVER_RUNS;
    const RUNNING: &str = CASE_CANCELLED_RUNNING_WORK_KEEPS_ITS_SLOT;
    let mut subject = new_subject();
    let fence = subject.fence();

    // Two items in one scope: the second is queued behind the first.
    submit(QUEUED, &mut subject, "cancel-running", "cancel-scope")?;
    submit(QUEUED, &mut subject, "cancel-queued", "cancel-scope")?;
    // Enough other work to fill every remaining slot, so a freed slot is
    // observable as something else starting.
    for index in 0..limit {
        submit(
            RUNNING,
            &mut subject,
            &format!("filler-{index}"),
            &format!("filler-scope-{index}"),
        )?;
    }

    let started = tick(QUEUED, &mut subject, &fence)?;
    require(
        RUNNING,
        subject.running().len() == limit,
        "the scheduler did not fill its slots",
    )?;

    let queued = work_id(QUEUED, "cancel-queued")?;
    let disposition = subject.cancel(&queued).map_err(|refusal| {
        SchedulerViolation::new(
            QUEUED,
            format!("cancelling queued work refused with {}", refusal.category()),
        )
    })?;
    require(
        QUEUED,
        disposition == CancelDisposition::NeverStarted,
        format!("cancelling queued work reported {}", disposition.as_str()),
    )?;
    require(
        QUEUED,
        subject.state(&queued) == Some(WorkState::Cancelled),
        "cancelled queued work is not terminal",
    )?;

    let running = work_id(RUNNING, "cancel-running")?;
    let disposition = subject.cancel(&running).map_err(|refusal| {
        SchedulerViolation::new(
            RUNNING,
            format!(
                "cancelling running work refused with {}",
                refusal.category()
            ),
        )
    })?;
    require(
        RUNNING,
        disposition == CancelDisposition::StopRequested,
        format!(
            "cancelling running work reported {}; a running cancel is a request",
            disposition.as_str()
        ),
    )?;
    require(
        RUNNING,
        subject.running().contains(&running),
        "cancelling running work dropped it out of custody before its terminal commit",
    )?;
    let while_stopping = tick(RUNNING, &mut subject, &fence)?;
    require(
        RUNNING,
        while_stopping.is_empty(),
        "a stop request freed a parallelism slot before the terminal commit",
    )?;

    let terminal = subject.complete(&running).map_err(|refusal| {
        SchedulerViolation::new(
            RUNNING,
            format!(
                "committing a stopped item refused with {}",
                refusal.category()
            ),
        )
    })?;
    require(
        RUNNING,
        terminal == WorkState::Cancelled,
        format!("a stopped item committed as {}", terminal.as_str()),
    )?;
    let after = tick(RUNNING, &mut subject, &fence)?;
    require(
        RUNNING,
        !after.contains(&queued),
        "cancelled queued work started after the slot was freed",
    )?;
    no_duplicate_starts(RUNNING, [started, while_stopping, after].concat())
}

/// Authority is a parameter, and the wrong one starts nothing.
fn stale_fence<S: SchedulerCore, F: Fn() -> S>(new_subject: &F) -> Result<(), SchedulerViolation> {
    const CASE: &str = CASE_A_STALE_FENCE_STARTS_NOTHING;
    let mut subject = new_subject();
    let held = subject.fence();
    submit(CASE, &mut subject, "fenced-1", "fenced-scope")?;

    let stale = SchedulerFence::new(
        held.generation_id(),
        held.holder_id(),
        held.epoch().saturating_add(1),
    )
    .map_err(|error| {
        SchedulerViolation::new(CASE, format!("the suite's own fence is invalid: {error}"))
    })?;

    match subject.tick(&stale) {
        Ok(started) => {
            return Err(SchedulerViolation::new(
                CASE,
                format!("a tick under a stale fence started {started:?}"),
            ));
        }
        Err(refusal) => require(
            CASE,
            refusal == SchedulerRefusal::StaleFence,
            format!("a stale fence refused with {}", refusal.category()),
        )?,
    }
    require(
        CASE,
        subject.running().is_empty(),
        "a refused tick started work anyway",
    )
}

fn require(
    case: &'static str,
    condition: bool,
    detail: impl Into<String>,
) -> Result<(), SchedulerViolation> {
    if condition {
        Ok(())
    } else {
        Err(SchedulerViolation::new(case, detail))
    }
}

fn work_id(case: &'static str, value: &str) -> Result<WorkId, SchedulerViolation> {
    WorkId::new(value)
        .map_err(|error| SchedulerViolation::new(case, format!("invalid suite fixture: {error}")))
}

fn scope_id(case: &'static str, value: &str) -> Result<ScopeId, SchedulerViolation> {
    ScopeId::new(value)
        .map_err(|error| SchedulerViolation::new(case, format!("invalid suite fixture: {error}")))
}

fn submit<S: SchedulerCore>(
    case: &'static str,
    subject: &mut S,
    work: &str,
    scope: &str,
) -> Result<(), SchedulerViolation> {
    let queued = QueuedWork::new(work_id(case, work)?, scope_id(case, scope)?);
    subject.submit(&queued).map_err(|refusal| {
        SchedulerViolation::new(
            case,
            format!("submitting {work} refused with {}", refusal.category()),
        )
    })
}

fn tick<S: SchedulerCore>(
    case: &'static str,
    subject: &mut S,
    fence: &SchedulerFence,
) -> Result<Vec<WorkId>, SchedulerViolation> {
    subject.tick(fence).map_err(|refusal| {
        SchedulerViolation::new(
            case,
            format!("a valid tick refused with {}", refusal.category()),
        )
    })
}

/// Exactly-once starting, checked over every start a case observed.
///
/// A scheduler that restarts work after a pause or a stop request has not lost
/// anything a caller can see; it has run the same side effects twice, which is
/// the failure this whole property exists to prevent.
fn no_duplicate_starts(case: &'static str, started: Vec<WorkId>) -> Result<(), SchedulerViolation> {
    let mut seen = BTreeSet::new();
    for id in started {
        if !seen.insert(id.clone()) {
            return Err(SchedulerViolation::new(
                case,
                format!("{id} started twice in one case"),
            ));
        }
    }
    Ok(())
}

/// An in-memory scheduler that satisfies [`verify_scheduler_core`].
///
/// It runs nothing: "starting" is a state transition. It exists to prove the
/// suite is satisfiable and to state the intended admission policy in code —
/// global submission order, filtered by the scope and pause rules, bounded by
/// the slot count.
#[derive(Clone, Debug)]
pub struct ReferenceScheduler {
    limit: u32,
    fence: SchedulerFence,
    order: Vec<QueuedWork>,
    states: BTreeMap<WorkId, WorkState>,
    paused: BTreeSet<ScopeId>,
}

impl ReferenceScheduler {
    /// Build a scheduler with `limit` slots under `fence`.
    #[must_use]
    pub fn new(limit: u32, fence: SchedulerFence) -> Self {
        Self {
            limit,
            fence,
            order: Vec::new(),
            states: BTreeMap::new(),
            paused: BTreeSet::new(),
        }
    }

    /// A scheduler with a fixture fence and the smallest conforming limit.
    ///
    /// # Panics
    ///
    /// Panics if this crate's own identifier bounds reject the fixture fence,
    /// which would mean the crate no longer accepts its own literals.
    #[must_use]
    pub fn fixture() -> Self {
        let fence = SchedulerFence::new("generation-1", "holder-1", 1)
            .expect("the reference model's own fence coordinates are valid");
        Self::new(MIN_PARALLELISM_LIMIT, fence)
    }

    fn occupied(&self) -> usize {
        self.states
            .values()
            .filter(|state| state.holds_a_slot())
            .count()
    }

    /// The scope one admitted work identity belongs to, if it is admitted.
    #[must_use]
    pub fn scope(&self, work_id: &WorkId) -> Option<&ScopeId> {
        self.order
            .iter()
            .find(|queued| queued.work_id() == work_id)
            .map(QueuedWork::scope)
    }

    fn scope_is_busy(&self, scope: &ScopeId) -> bool {
        self.order.iter().any(|queued| {
            queued.scope() == scope
                && self
                    .states
                    .get(queued.work_id())
                    .is_some_and(|state| state.holds_a_slot())
        })
    }
}

impl SchedulerCore for ReferenceScheduler {
    fn parallelism_limit(&self) -> u32 {
        self.limit
    }

    fn fence(&self) -> SchedulerFence {
        self.fence.clone()
    }

    fn submit(&mut self, work: &QueuedWork) -> Result<(), SchedulerRefusal> {
        if self.states.contains_key(work.work_id()) {
            return Err(SchedulerRefusal::DuplicateWork);
        }
        self.states
            .insert(work.work_id().clone(), WorkState::Queued);
        self.order.push(work.clone());
        Ok(())
    }

    fn tick(&mut self, fence: &SchedulerFence) -> Result<Vec<WorkId>, SchedulerRefusal> {
        if fence != &self.fence {
            return Err(SchedulerRefusal::StaleFence);
        }
        let mut started = Vec::new();
        // One pass in submission order, re-reading the scope and slot state
        // after every start so a second item of a scope started in this same
        // tick is still held back.
        for index in 0..self.order.len() {
            if self.occupied() >= self.limit as usize {
                break;
            }
            let queued = self.order[index].clone();
            if self.states.get(queued.work_id()) != Some(&WorkState::Queued)
                || self.paused.contains(queued.scope())
                || self.scope_is_busy(queued.scope())
            {
                continue;
            }
            self.states
                .insert(queued.work_id().clone(), WorkState::Running);
            started.push(queued.work_id().clone());
        }
        Ok(started)
    }

    fn complete(&mut self, work_id: &WorkId) -> Result<WorkState, SchedulerRefusal> {
        let state = *self
            .states
            .get(work_id)
            .ok_or(SchedulerRefusal::UnknownWork)?;
        let terminal = match state {
            WorkState::Running => WorkState::Completed,
            WorkState::StopRequested => WorkState::Cancelled,
            _ => return Err(SchedulerRefusal::NotRunning),
        };
        self.states.insert(work_id.clone(), terminal);
        Ok(terminal)
    }

    fn pause(&mut self, scope: &ScopeId) {
        self.paused.insert(scope.clone());
    }

    fn resume(&mut self, scope: &ScopeId) {
        self.paused.remove(scope);
    }

    fn cancel(&mut self, work_id: &WorkId) -> Result<CancelDisposition, SchedulerRefusal> {
        let state = *self
            .states
            .get(work_id)
            .ok_or(SchedulerRefusal::UnknownWork)?;
        match state {
            WorkState::Queued => {
                self.states.insert(work_id.clone(), WorkState::Cancelled);
                Ok(CancelDisposition::NeverStarted)
            }
            WorkState::Running | WorkState::StopRequested => {
                self.states
                    .insert(work_id.clone(), WorkState::StopRequested);
                Ok(CancelDisposition::StopRequested)
            }
            WorkState::Completed | WorkState::Cancelled => Err(SchedulerRefusal::AlreadyTerminal),
        }
    }

    fn running(&self) -> Vec<WorkId> {
        self.order
            .iter()
            .map(QueuedWork::work_id)
            .filter(|work_id| {
                self.states
                    .get(*work_id)
                    .is_some_and(|state| state.holds_a_slot())
            })
            .cloned()
            .collect()
    }

    fn state(&self, work_id: &WorkId) -> Option<WorkState> {
        self.states.get(work_id).copied()
    }
}
