// SPDX-License-Identifier: Elastic-2.0

//! Say exactly what you are about to change, durably, and leave time to stop it.
//!
//! The property, from
//! `docs/product-plan/requirements/mutation-announcement.md`: before any
//! externally visible mutation, the system writes a **durable announcement that
//! names the exact target**, and then waits out a **stop-check window** during
//! which an operator can stop it. A mutation with no announcement, with someone
//! else's announcement, inside the window, or after a stop, does not happen.
//!
//! Three things make this more than a log line.
//!
//! **Durable, not sent.** The announcement is a record, written before the
//! window opens. A message posted to a channel is a side effect that can be
//! lost, delivered late, or delivered after the mutation it was supposed to
//! precede. The suite reads [`AnnouncedMutations::journal`], not an outbox.
//!
//! **Exact, not descriptive.** [`MutationTarget::exact`] refuses a target that
//! names a class rather than a thing — a wildcard, or a word like `all`. An
//! announcement a reader cannot use to decide whether to stop is not a
//! stop-check, and "about to update the sites" is not a target.
//!
//! **One announcement, one mutation.** An announcement is consumed by the
//! mutation it authorizes. Without that, the first announcement of a target
//! becomes a standing permission for every later change to it, which is how a
//! stop-check quietly turns into a formality.
//!
//! ```
//! use automonique_protocol::safety_conformance::mutation_announcement::MutationTarget;
//! let refused = MutationTarget::exact("workspace", "*");
//! assert_eq!(refused.unwrap_err().category(), "target_not_exact");
//! ```

use crate::primitives::{BoundedString, EpochMillis, ValueError};
use crate::safety_conformance::{CaseLog, SafetyProperty, SafetyReport, SafetyViolation};

/// Maximum UTF-8 byte length of either half of a target.
pub const MAX_TARGET_COMPONENT_BYTES: usize = 192;

/// One half of a target coordinate.
pub type TargetComponent = BoundedString<MAX_TARGET_COMPONENT_BYTES>;

/// Words that name a class of things rather than a thing.
///
/// Compared case-insensitively, and only against a whole component: a resource
/// legitimately called `smallest` is not a wildcard because it contains `all`.
pub const WILDCARD_WORDS: [&str; 5] = ["all", "any", "each", "every", "everything"];

/// Characters that make a component a pattern rather than a name.
pub const WILDCARD_CHARACTERS: [char; 3] = ['*', '?', '%'];

/// The shortest stop-check window this module will accept as a window.
///
/// **Owner-confirmable.** Thirty seconds is the smallest interval in which a
/// human who is already looking at the announcement can act on it; it is not a
/// claim that thirty seconds is enough notice for any particular mutation. An
/// owner raising this constant tightens every subject at once, and a subject may
/// always declare a longer window than the floor. A subject declaring less does
/// not conform, because a window nobody can act inside is a delay, not a check.
pub const MIN_STOP_CHECK_WINDOW_MILLIS: i64 = 30_000;

/// Why a target was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetError {
    /// A component was empty, over its ceiling, or carried a control character.
    Component {
        /// Which half was rejected.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
    /// A component named a class of things rather than one thing.
    NotExact {
        /// Which half was rejected.
        field: &'static str,
    },
}

impl TargetError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Component { .. } => "target_component_invalid",
            Self::NotExact { .. } => "target_not_exact",
        }
    }
}

/// The exact thing a mutation will change.
///
/// Two components rather than one free-text string, because a scope and a
/// resource are what an operator compares against when deciding to stop, and a
/// single string invites a sentence.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MutationTarget {
    scope: TargetComponent,
    resource: TargetComponent,
}

impl MutationTarget {
    /// Name one exact target.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Component`] when a half is empty, too long, or
    /// carries a control character, and [`TargetError::NotExact`] when a half is
    /// a pattern or a class word.
    pub fn exact(
        scope: impl Into<String>,
        resource: impl Into<String>,
    ) -> Result<Self, TargetError> {
        Ok(Self {
            scope: component(scope.into(), "scope")?,
            resource: component(resource.into(), "resource")?,
        })
    }

    /// The bounded scope this target sits in.
    #[must_use]
    pub const fn scope(&self) -> &TargetComponent {
        &self.scope
    }

    /// The exact resource inside that scope.
    #[must_use]
    pub const fn resource(&self) -> &TargetComponent {
        &self.resource
    }
}

fn component(value: String, field: &'static str) -> Result<TargetComponent, TargetError> {
    let lowered = value.to_lowercase();
    if WILDCARD_WORDS.contains(&lowered.as_str())
        || value.chars().any(|c| WILDCARD_CHARACTERS.contains(&c))
    {
        return Err(TargetError::NotExact { field });
    }
    TargetComponent::new(value).map_err(|error| TargetError::Component { field, error })
}

/// A subject-minted identifier for one announcement.
///
/// Opaque on purpose: a caller cannot construct one it was not given, so
/// "mutate under announcement 7" is not a thing an implementation can be talked
/// into by a caller that guessed.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AnnouncementId(u64);

impl AnnouncementId {
    /// Mint an identifier. Only an implementation of
    /// [`AnnouncedMutations`] has cause to call this.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The underlying value, for journalling and comparison.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// How long a stop-check window stays open.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StopCheckWindow(i64);

impl StopCheckWindow {
    /// Declare a window of `millis`.
    ///
    /// # Errors
    ///
    /// Returns [`WindowError::BelowFloor`] when the window is shorter than
    /// [`MIN_STOP_CHECK_WINDOW_MILLIS`].
    pub const fn new(millis: i64) -> Result<Self, WindowError> {
        if millis < MIN_STOP_CHECK_WINDOW_MILLIS {
            return Err(WindowError::BelowFloor {
                floor_millis: MIN_STOP_CHECK_WINDOW_MILLIS,
                declared_millis: millis,
            });
        }
        Ok(Self(millis))
    }

    /// The window's length in milliseconds.
    #[must_use]
    pub const fn millis(self) -> i64 {
        self.0
    }
}

/// Why a declared window was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowError {
    /// The window was shorter than the module's floor.
    BelowFloor {
        /// The shortest accepted window.
        floor_millis: i64,
        /// What was declared.
        declared_millis: i64,
    },
}

/// A durable announcement, as returned to its announcer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Announcement {
    id: AnnouncementId,
    target: MutationTarget,
    announced_at: EpochMillis,
    window_closes_at: EpochMillis,
}

impl Announcement {
    /// Record one announcement.
    #[must_use]
    pub const fn new(
        id: AnnouncementId,
        target: MutationTarget,
        announced_at: EpochMillis,
        window_closes_at: EpochMillis,
    ) -> Self {
        Self {
            id,
            target,
            announced_at,
            window_closes_at,
        }
    }

    /// This announcement's identifier.
    #[must_use]
    pub const fn id(&self) -> AnnouncementId {
        self.id
    }

    /// The exact target it named.
    #[must_use]
    pub const fn target(&self) -> &MutationTarget {
        &self.target
    }

    /// When it was written.
    #[must_use]
    pub const fn announced_at(&self) -> EpochMillis {
        self.announced_at
    }

    /// The first instant at which the mutation may proceed.
    #[must_use]
    pub const fn window_closes_at(&self) -> EpochMillis {
        self.window_closes_at
    }
}

/// Where an announcement has got to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnouncementState {
    /// Written, and no mutation has consumed or stopped it.
    Open,
    /// An operator stopped it. Terminal: a stop is never lifted by waiting.
    Stopped,
    /// Its one mutation happened.
    Consumed,
}

impl AnnouncementState {
    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Stopped => "stopped",
            Self::Consumed => "consumed",
        }
    }
}

/// One durable announcement row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnouncementRecord {
    announcement: Announcement,
    state: AnnouncementState,
}

impl AnnouncementRecord {
    /// Record an announcement in `state`.
    #[must_use]
    pub const fn new(announcement: Announcement, state: AnnouncementState) -> Self {
        Self {
            announcement,
            state,
        }
    }

    /// The announcement this row carries.
    #[must_use]
    pub const fn announcement(&self) -> &Announcement {
        &self.announcement
    }

    /// Where it has got to.
    #[must_use]
    pub const fn state(&self) -> AnnouncementState {
        self.state
    }
}

/// A request to mutate one target.
///
/// The announcement is an [`Option`] so that "no announcement at all" is a
/// request an implementation must refuse, rather than one a caller cannot make.
/// The unannounced mutation is the case that has to be tested.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationRequest {
    target: MutationTarget,
    announcement: Option<AnnouncementId>,
}

impl MutationRequest {
    /// Request a mutation authorized by `announcement`.
    #[must_use]
    pub const fn announced(target: MutationTarget, announcement: AnnouncementId) -> Self {
        Self {
            target,
            announcement: Some(announcement),
        }
    }

    /// Request a mutation with no announcement behind it.
    #[must_use]
    pub const fn unannounced(target: MutationTarget) -> Self {
        Self {
            target,
            announcement: None,
        }
    }

    /// The target to be changed.
    #[must_use]
    pub const fn target(&self) -> &MutationTarget {
        &self.target
    }

    /// The announcement cited, if any.
    #[must_use]
    pub const fn announcement(&self) -> Option<AnnouncementId> {
        self.announcement
    }
}

/// Proof that one announced mutation happened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationReceipt {
    announcement: AnnouncementId,
    target: MutationTarget,
}

impl MutationReceipt {
    /// Record a completed mutation against the announcement that authorized it.
    #[must_use]
    pub const fn new(announcement: AnnouncementId, target: MutationTarget) -> Self {
        Self {
            announcement,
            target,
        }
    }

    /// The announcement consumed.
    #[must_use]
    pub const fn announcement(&self) -> AnnouncementId {
        self.announcement
    }

    /// The target changed.
    #[must_use]
    pub const fn target(&self) -> &MutationTarget {
        &self.target
    }
}

/// Why an announcement could not be written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnouncementRefusal {
    /// The announcement could not be made durable, so no mutation may follow.
    NotDurable,
    /// An open announcement for this exact target already exists.
    AlreadyOpen {
        /// The announcement already covering the target.
        announcement: AnnouncementId,
    },
}

impl AnnouncementRefusal {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::NotDurable => "announcement_not_durable",
            Self::AlreadyOpen { .. } => "announcement_already_open",
        }
    }
}

/// Why a stop request was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopRefusal {
    /// No announcement has that identifier.
    UnknownAnnouncement,
    /// The window has closed; the mutation may already be under way.
    WindowClosed,
    /// The mutation already happened.
    AlreadyConsumed,
    /// It was already stopped.
    AlreadyStopped,
}

impl StopRefusal {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::UnknownAnnouncement => "unknown_announcement",
            Self::WindowClosed => "window_closed",
            Self::AlreadyConsumed => "already_consumed",
            Self::AlreadyStopped => "already_stopped",
        }
    }
}

/// Why a mutation did not happen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationRefusal {
    /// The request cited no announcement.
    NotAnnounced,
    /// The cited announcement does not exist.
    UnknownAnnouncement,
    /// The cited announcement named a different target.
    TargetMismatch,
    /// The stop-check window is still open.
    StopCheckWindowOpen {
        /// Milliseconds left before the mutation may proceed.
        remaining_millis: i64,
    },
    /// An operator stopped this announcement.
    Stopped,
    /// This announcement already authorized its one mutation.
    AlreadyConsumed,
}

impl MutationRefusal {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::NotAnnounced => "not_announced",
            Self::UnknownAnnouncement => "unknown_announcement",
            Self::TargetMismatch => "target_mismatch",
            Self::StopCheckWindowOpen { .. } => "stop_check_window_open",
            Self::Stopped => "stopped",
            Self::AlreadyConsumed => "already_consumed",
        }
    }
}

/// A subject that announces before it mutates.
pub trait AnnouncedMutations {
    /// How long this subject holds a stop-check window open.
    fn stop_check_window(&self) -> StopCheckWindow;

    /// The subject's current instant.
    fn now(&self) -> EpochMillis;

    /// Move the subject's clock forward by `millis`.
    ///
    /// A test seam, and the reason the suite never sleeps. A daemon binds this
    /// to the same controllable clock its other durable timers use; it is not a
    /// production verb, and an implementation may leave it a no-op outside test
    /// configuration provided the suite is then run against a subject whose
    /// clock the suite can move.
    fn advance_clock(&mut self, millis: i64);

    /// Durably announce that `target` is about to change.
    ///
    /// # Errors
    ///
    /// Returns [`AnnouncementRefusal`] when the announcement cannot be made
    /// durable or the target already has an open announcement. Refusing here
    /// means no mutation follows: there is no unannounced path.
    fn announce(&mut self, target: &MutationTarget) -> Result<Announcement, AnnouncementRefusal>;

    /// Stop the mutation an open announcement authorizes.
    ///
    /// # Errors
    ///
    /// Returns [`StopRefusal`] when the announcement is unknown, already
    /// stopped, already consumed, or its window has closed.
    fn stop(&mut self, announcement: AnnouncementId) -> Result<(), StopRefusal>;

    /// Perform one externally visible mutation.
    ///
    /// # Errors
    ///
    /// Returns [`MutationRefusal`] for every request that is not an exact,
    /// unstopped, unconsumed announcement whose window has closed.
    fn mutate(&mut self, request: &MutationRequest) -> Result<MutationReceipt, MutationRefusal>;

    /// Every announcement row, oldest first.
    fn journal(&self) -> Vec<AnnouncementRecord>;
}

/// Case names this suite runs, in order.
pub const CASES: [&str; 10] = [
    CASE_FRESH_SUBJECT,
    CASE_WINDOW_MEETS_THE_FLOOR,
    CASE_UNANNOUNCED_MUTATION_REFUSED,
    CASE_ANNOUNCEMENT_IS_DURABLE_FIRST,
    CASE_MUTATION_INSIDE_THE_WINDOW_REFUSED,
    CASE_ANNOUNCED_MUTATION_PROCEEDS,
    CASE_ONE_ANNOUNCEMENT_ONE_MUTATION,
    CASE_ANNOUNCEMENT_BINDS_ITS_EXACT_TARGET,
    CASE_STOPPED_ANNOUNCEMENT_NEVER_AUTHORIZES,
    CASE_UNKNOWN_ANNOUNCEMENT_AUTHORIZES_NOTHING,
];

/// The suite requires a subject with an empty journal.
pub const CASE_FRESH_SUBJECT: &str = "the_subject_starts_with_an_empty_journal";
/// The declared window is at least the module's floor.
pub const CASE_WINDOW_MEETS_THE_FLOOR: &str = "the_stop_check_window_meets_the_floor";
/// A mutation citing no announcement is refused.
pub const CASE_UNANNOUNCED_MUTATION_REFUSED: &str = "an_unannounced_mutation_is_refused";
/// The announcement is durable, with its exact target, before anything mutates.
pub const CASE_ANNOUNCEMENT_IS_DURABLE_FIRST: &str =
    "the_announcement_is_durable_before_the_mutation";
/// The window is a wait, not a formality.
pub const CASE_MUTATION_INSIDE_THE_WINDOW_REFUSED: &str =
    "a_mutation_inside_the_stop_check_window_is_refused";
/// After the window, the announced mutation proceeds.
pub const CASE_ANNOUNCED_MUTATION_PROCEEDS: &str =
    "an_announced_mutation_proceeds_after_the_window";
/// An announcement is consumed by the mutation it authorized.
pub const CASE_ONE_ANNOUNCEMENT_ONE_MUTATION: &str =
    "an_announcement_authorizes_exactly_one_mutation";
/// An announcement authorizes its own target and no other.
pub const CASE_ANNOUNCEMENT_BINDS_ITS_EXACT_TARGET: &str =
    "an_announcement_authorizes_only_its_exact_target";
/// A stop is terminal, including after the window would have closed.
pub const CASE_STOPPED_ANNOUNCEMENT_NEVER_AUTHORIZES: &str =
    "a_stopped_announcement_never_authorizes_a_mutation";
/// An identifier the subject never minted authorizes nothing.
pub const CASE_UNKNOWN_ANNOUNCEMENT_AUTHORIZES_NOTHING: &str =
    "an_unknown_announcement_authorizes_nothing";

/// Run the announce-before-mutation suite against `subject`.
///
/// The subject must be freshly constructed. The suite moves the subject's clock
/// itself and never sleeps.
///
/// # Errors
///
/// Returns the first [`SafetyViolation`] the subject produces.
pub fn verify_mutation_announcement<S: AnnouncedMutations + ?Sized>(
    subject: &mut S,
) -> Result<SafetyReport, SafetyViolation> {
    let mut log = CaseLog::new(SafetyProperty::MutationAnnouncement);

    log.require(
        CASE_FRESH_SUBJECT,
        subject.journal().is_empty(),
        "the subject already had announcements; the suite needs a freshly constructed subject",
    )?;
    log.passed(CASE_FRESH_SUBJECT);

    let window = subject.stop_check_window().millis();
    log.require(
        CASE_WINDOW_MEETS_THE_FLOOR,
        window >= MIN_STOP_CHECK_WINDOW_MILLIS,
        format!("the subject declared a {window}ms window; the floor is {MIN_STOP_CHECK_WINDOW_MILLIS}ms"),
    )?;
    log.passed(CASE_WINDOW_MEETS_THE_FLOOR);

    let first = target(
        &log,
        CASE_UNANNOUNCED_MUTATION_REFUSED,
        "workspace-a",
        "site-1",
    )?;
    match subject.mutate(&MutationRequest::unannounced(first.clone())) {
        Ok(_) => {
            return Err(log.failed(
                CASE_UNANNOUNCED_MUTATION_REFUSED,
                "an unannounced mutation succeeded",
            ));
        }
        Err(refusal) => log.require(
            CASE_UNANNOUNCED_MUTATION_REFUSED,
            refusal == MutationRefusal::NotAnnounced,
            format!(
                "an unannounced mutation refused with {}; it must refuse as not announced",
                refusal.category()
            ),
        )?,
    }
    log.passed(CASE_UNANNOUNCED_MUTATION_REFUSED);

    // The announcement is durable, and names the target, before anything else.
    let announced_at = subject.now();
    let announcement = subject.announce(&first).map_err(|refusal| {
        log.failed(
            CASE_ANNOUNCEMENT_IS_DURABLE_FIRST,
            format!(
                "announcing a valid target refused with {}",
                refusal.category()
            ),
        )
    })?;
    let recorded = find(&subject.journal(), announcement.id()).ok_or_else(|| {
        log.failed(
            CASE_ANNOUNCEMENT_IS_DURABLE_FIRST,
            "the announcement was returned but not written to the journal",
        )
    })?;
    log.require(
        CASE_ANNOUNCEMENT_IS_DURABLE_FIRST,
        recorded.announcement().target() == &first,
        "the recorded announcement named a different target than the one announced",
    )?;
    log.require(
        CASE_ANNOUNCEMENT_IS_DURABLE_FIRST,
        recorded.state() == AnnouncementState::Open,
        format!(
            "a fresh announcement was recorded as {}",
            recorded.state().as_str()
        ),
    )?;
    log.require(
        CASE_ANNOUNCEMENT_IS_DURABLE_FIRST,
        announcement.window_closes_at().as_millis()
            >= announced_at.as_millis().saturating_add(window),
        "the window closes before a full window has elapsed",
    )?;
    log.passed(CASE_ANNOUNCEMENT_IS_DURABLE_FIRST);

    // Inside the window, the mutation waits.
    subject.advance_clock(window / 2);
    match subject.mutate(&MutationRequest::announced(
        first.clone(),
        announcement.id(),
    )) {
        Ok(_) => {
            return Err(log.failed(
                CASE_MUTATION_INSIDE_THE_WINDOW_REFUSED,
                "a mutation proceeded inside its stop-check window",
            ));
        }
        Err(MutationRefusal::StopCheckWindowOpen { remaining_millis }) => log.require(
            CASE_MUTATION_INSIDE_THE_WINDOW_REFUSED,
            remaining_millis > 0,
            format!("the window was reported open with {remaining_millis}ms remaining"),
        )?,
        Err(refusal) => {
            return Err(log.failed(
                CASE_MUTATION_INSIDE_THE_WINDOW_REFUSED,
                format!(
                    "a mutation inside the window refused with {}; it must name the open window",
                    refusal.category()
                ),
            ));
        }
    }
    log.passed(CASE_MUTATION_INSIDE_THE_WINDOW_REFUSED);

    // After the window, it proceeds.
    subject.advance_clock(window);
    let receipt = subject
        .mutate(&MutationRequest::announced(
            first.clone(),
            announcement.id(),
        ))
        .map_err(|refusal| {
            log.failed(
                CASE_ANNOUNCED_MUTATION_PROCEEDS,
                format!(
                    "an announced mutation past its window refused with {}",
                    refusal.category()
                ),
            )
        })?;
    log.require(
        CASE_ANNOUNCED_MUTATION_PROCEEDS,
        receipt.announcement() == announcement.id() && receipt.target() == &first,
        "the receipt did not cite the announcement and target it acted on",
    )?;
    let consumed = find(&subject.journal(), announcement.id()).ok_or_else(|| {
        log.failed(
            CASE_ANNOUNCED_MUTATION_PROCEEDS,
            "the announcement disappeared from the journal after its mutation",
        )
    })?;
    log.require(
        CASE_ANNOUNCED_MUTATION_PROCEEDS,
        consumed.state() == AnnouncementState::Consumed,
        format!(
            "after its mutation the announcement is {}",
            consumed.state().as_str()
        ),
    )?;
    log.passed(CASE_ANNOUNCED_MUTATION_PROCEEDS);

    // The same announcement does not authorize a second mutation.
    match subject.mutate(&MutationRequest::announced(
        first.clone(),
        announcement.id(),
    )) {
        Ok(_) => {
            return Err(log.failed(
                CASE_ONE_ANNOUNCEMENT_ONE_MUTATION,
                "a consumed announcement authorized a second mutation",
            ));
        }
        Err(refusal) => log.require(
            CASE_ONE_ANNOUNCEMENT_ONE_MUTATION,
            refusal == MutationRefusal::AlreadyConsumed,
            format!(
                "a replayed announcement refused with {}; it must refuse as already consumed",
                refusal.category()
            ),
        )?,
    }
    log.passed(CASE_ONE_ANNOUNCEMENT_ONE_MUTATION);

    // An announcement for one target does not cover its neighbour.
    let second = target(
        &log,
        CASE_ANNOUNCEMENT_BINDS_ITS_EXACT_TARGET,
        "workspace-a",
        "site-2",
    )?;
    let for_second = subject.announce(&second).map_err(|refusal| {
        log.failed(
            CASE_ANNOUNCEMENT_BINDS_ITS_EXACT_TARGET,
            format!(
                "announcing a second target refused with {}",
                refusal.category()
            ),
        )
    })?;
    subject.advance_clock(window * 2);
    let third = target(
        &log,
        CASE_ANNOUNCEMENT_BINDS_ITS_EXACT_TARGET,
        "workspace-a",
        "site-3",
    )?;
    match subject.mutate(&MutationRequest::announced(third, for_second.id())) {
        Ok(_) => {
            return Err(log.failed(
                CASE_ANNOUNCEMENT_BINDS_ITS_EXACT_TARGET,
                "an announcement for one target authorized a mutation of another",
            ));
        }
        Err(refusal) => log.require(
            CASE_ANNOUNCEMENT_BINDS_ITS_EXACT_TARGET,
            refusal == MutationRefusal::TargetMismatch,
            format!(
                "a mismatched target refused with {}; it must refuse as a target mismatch",
                refusal.category()
            ),
        )?,
    }
    let untouched = find(&subject.journal(), for_second.id()).ok_or_else(|| {
        log.failed(
            CASE_ANNOUNCEMENT_BINDS_ITS_EXACT_TARGET,
            "the second announcement left the journal",
        )
    })?;
    log.require(
        CASE_ANNOUNCEMENT_BINDS_ITS_EXACT_TARGET,
        untouched.state() == AnnouncementState::Open,
        "a refused mutation consumed the announcement it misused",
    )?;
    log.passed(CASE_ANNOUNCEMENT_BINDS_ITS_EXACT_TARGET);

    // A stop is terminal, and waiting does not undo it.
    let fourth = target(
        &log,
        CASE_STOPPED_ANNOUNCEMENT_NEVER_AUTHORIZES,
        "workspace-b",
        "site-4",
    )?;
    let stoppable = subject.announce(&fourth).map_err(|refusal| {
        log.failed(
            CASE_STOPPED_ANNOUNCEMENT_NEVER_AUTHORIZES,
            format!("announcing refused with {}", refusal.category()),
        )
    })?;
    subject.stop(stoppable.id()).map_err(|refusal| {
        log.failed(
            CASE_STOPPED_ANNOUNCEMENT_NEVER_AUTHORIZES,
            format!(
                "stopping inside the window refused with {}",
                refusal.category()
            ),
        )
    })?;
    subject.advance_clock(window * 2);
    match subject.mutate(&MutationRequest::announced(fourth, stoppable.id())) {
        Ok(_) => {
            return Err(log.failed(
                CASE_STOPPED_ANNOUNCEMENT_NEVER_AUTHORIZES,
                "a stopped announcement authorized a mutation once its window elapsed",
            ));
        }
        Err(refusal) => log.require(
            CASE_STOPPED_ANNOUNCEMENT_NEVER_AUTHORIZES,
            refusal == MutationRefusal::Stopped,
            format!(
                "a stopped announcement refused with {}; it must refuse as stopped",
                refusal.category()
            ),
        )?,
    }
    let stopped = find(&subject.journal(), stoppable.id()).ok_or_else(|| {
        log.failed(
            CASE_STOPPED_ANNOUNCEMENT_NEVER_AUTHORIZES,
            "the stopped announcement left the journal",
        )
    })?;
    log.require(
        CASE_STOPPED_ANNOUNCEMENT_NEVER_AUTHORIZES,
        stopped.state() == AnnouncementState::Stopped,
        format!(
            "a stopped announcement is recorded as {}",
            stopped.state().as_str()
        ),
    )?;
    log.passed(CASE_STOPPED_ANNOUNCEMENT_NEVER_AUTHORIZES);

    // An identifier the subject never minted.
    let fifth = target(
        &log,
        CASE_UNKNOWN_ANNOUNCEMENT_AUTHORIZES_NOTHING,
        "workspace-b",
        "site-5",
    )?;
    let unknown = AnnouncementId::new(u64::MAX);
    match subject.mutate(&MutationRequest::announced(fifth, unknown)) {
        Ok(_) => {
            return Err(log.failed(
                CASE_UNKNOWN_ANNOUNCEMENT_AUTHORIZES_NOTHING,
                "an announcement identifier the subject never minted authorized a mutation",
            ));
        }
        Err(refusal) => log.require(
            CASE_UNKNOWN_ANNOUNCEMENT_AUTHORIZES_NOTHING,
            refusal == MutationRefusal::UnknownAnnouncement,
            format!(
                "an unknown announcement refused with {}",
                refusal.category()
            ),
        )?,
    }
    log.passed(CASE_UNKNOWN_ANNOUNCEMENT_AUTHORIZES_NOTHING);

    Ok(log.finish())
}

fn target(
    log: &CaseLog,
    case: &'static str,
    scope: &str,
    resource: &str,
) -> Result<MutationTarget, SafetyViolation> {
    MutationTarget::exact(scope, resource).map_err(|error| {
        log.failed(
            case,
            format!("the suite's own fixture is invalid: {}", error.category()),
        )
    })
}

fn find(journal: &[AnnouncementRecord], id: AnnouncementId) -> Option<AnnouncementRecord> {
    journal
        .iter()
        .find(|record| record.announcement().id() == id)
        .cloned()
}

/// An in-memory implementation that satisfies [`verify_mutation_announcement`].
///
/// It mutates nothing: a "mutation" is a state transition on a row. Its clock is
/// a counter, so the suite's waits are exact rather than approximately long
/// enough.
#[derive(Clone, Debug)]
pub struct ReferenceAnnouncer {
    window: StopCheckWindow,
    now: EpochMillis,
    next_id: u64,
    journal: Vec<AnnouncementRecord>,
}

impl Default for ReferenceAnnouncer {
    fn default() -> Self {
        Self::new(StopCheckWindow(MIN_STOP_CHECK_WINDOW_MILLIS))
    }
}

impl ReferenceAnnouncer {
    /// Build a reference announcer with an explicit window.
    #[must_use]
    pub const fn new(window: StopCheckWindow) -> Self {
        Self {
            window,
            now: EpochMillis::EPOCH,
            next_id: 1,
            journal: Vec::new(),
        }
    }

    fn position(&self, id: AnnouncementId) -> Option<usize> {
        self.journal
            .iter()
            .position(|record| record.announcement().id() == id)
    }
}

impl AnnouncedMutations for ReferenceAnnouncer {
    fn stop_check_window(&self) -> StopCheckWindow {
        self.window
    }

    fn now(&self) -> EpochMillis {
        self.now
    }

    fn advance_clock(&mut self, millis: i64) {
        self.now = self
            .now
            .checked_add_millis(millis)
            .unwrap_or_else(|_| EpochMillis::from_millis(i64::MAX));
    }

    fn announce(&mut self, target: &MutationTarget) -> Result<Announcement, AnnouncementRefusal> {
        if let Some(open) = self.journal.iter().find(|record| {
            record.state() == AnnouncementState::Open && record.announcement().target() == target
        }) {
            return Err(AnnouncementRefusal::AlreadyOpen {
                announcement: open.announcement().id(),
            });
        }
        let id = AnnouncementId::new(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        let closes_at = self
            .now
            .checked_add_millis(self.window.millis())
            .map_err(|_| AnnouncementRefusal::NotDurable)?;
        let announcement = Announcement::new(id, target.clone(), self.now, closes_at);
        self.journal.push(AnnouncementRecord::new(
            announcement.clone(),
            AnnouncementState::Open,
        ));
        Ok(announcement)
    }

    fn stop(&mut self, announcement: AnnouncementId) -> Result<(), StopRefusal> {
        let index = self
            .position(announcement)
            .ok_or(StopRefusal::UnknownAnnouncement)?;
        let record = self.journal[index].clone();
        match record.state() {
            AnnouncementState::Stopped => return Err(StopRefusal::AlreadyStopped),
            AnnouncementState::Consumed => return Err(StopRefusal::AlreadyConsumed),
            AnnouncementState::Open => {}
        }
        if self.now >= record.announcement().window_closes_at() {
            return Err(StopRefusal::WindowClosed);
        }
        self.journal[index] =
            AnnouncementRecord::new(record.announcement().clone(), AnnouncementState::Stopped);
        Ok(())
    }

    fn mutate(&mut self, request: &MutationRequest) -> Result<MutationReceipt, MutationRefusal> {
        let id = request
            .announcement()
            .ok_or(MutationRefusal::NotAnnounced)?;
        let index = self
            .position(id)
            .ok_or(MutationRefusal::UnknownAnnouncement)?;
        let record = self.journal[index].clone();
        match record.state() {
            AnnouncementState::Stopped => return Err(MutationRefusal::Stopped),
            AnnouncementState::Consumed => return Err(MutationRefusal::AlreadyConsumed),
            AnnouncementState::Open => {}
        }
        if record.announcement().target() != request.target() {
            return Err(MutationRefusal::TargetMismatch);
        }
        let closes_at = record.announcement().window_closes_at();
        if self.now < closes_at {
            return Err(MutationRefusal::StopCheckWindowOpen {
                remaining_millis: closes_at
                    .checked_difference_millis(self.now)
                    .unwrap_or(i64::MAX),
            });
        }
        self.journal[index] =
            AnnouncementRecord::new(record.announcement().clone(), AnnouncementState::Consumed);
        Ok(MutationReceipt::new(id, request.target().clone()))
    }

    fn journal(&self) -> Vec<AnnouncementRecord> {
        self.journal.clone()
    }
}
