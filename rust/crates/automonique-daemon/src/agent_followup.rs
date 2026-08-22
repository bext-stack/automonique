// SPDX-License-Identifier: Elastic-2.0

//! Transport-independent resolution of referential conversational input.
//!
//! A short message such as "do it" has no safe meaning by itself. This module
//! deliberately contains no phrase list. A semantic interpreter decides
//! whether the input refers to existing lane work, while trusted lane state
//! decides what that reference is allowed to do. The interpreter cannot grant
//! steering authority, approve an effect, or make an old mutation replayable.

use std::fmt;

pub const MAX_LANE_COORDINATE_BYTES: usize = 512;
pub const MAX_TURN_COORDINATE_BYTES: usize = 512;
pub const MAX_ACTOR_COORDINATE_BYTES: usize = 256;
pub const MAX_LANE_TURNS: usize = 64;
pub const MAX_LANE_CONTEXT_BYTES: usize = 64 * 1024;
pub const MAX_TURN_TEXT_BYTES: usize = 16 * 1024;
pub const MAX_CURRENT_TEXT_BYTES: usize = 4 * 1024;

/// Whether a completed user request may be repeated without acquiring new
/// authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PriorRequestKind {
    /// A typed, side-effect-free request whose original text can be replayed.
    ReplayableReadOnly,
    /// Conversation with no independently replayable operation.
    Conversation,
    /// A request that proposed, performed, or authorized an external effect.
    Effectful,
}

/// One bounded transcript entry supplied by the lane owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LaneTurn {
    User {
        source_key: String,
        actor_key: String,
        text: String,
        request_kind: PriorRequestKind,
    },
    Assistant {
        source_key: String,
        text: String,
    },
}

impl LaneTurn {
    pub fn user(
        source_key: impl Into<String>,
        actor_key: impl Into<String>,
        text: impl Into<String>,
        request_kind: PriorRequestKind,
    ) -> Result<Self, FollowUpBuildError> {
        let source_key = source_key.into();
        let actor_key = actor_key.into();
        let text = text.into();
        validate_coordinate(&source_key, MAX_TURN_COORDINATE_BYTES)
            .map_err(|_| FollowUpBuildError::InvalidTurn)?;
        validate_coordinate(&actor_key, MAX_ACTOR_COORDINATE_BYTES)
            .map_err(|_| FollowUpBuildError::InvalidTurn)?;
        validate_text(&text, MAX_TURN_TEXT_BYTES).map_err(|_| FollowUpBuildError::InvalidTurn)?;
        Ok(Self::User {
            source_key,
            actor_key,
            text,
            request_kind,
        })
    }

    pub fn assistant(
        source_key: impl Into<String>,
        text: impl Into<String>,
    ) -> Result<Self, FollowUpBuildError> {
        let source_key = source_key.into();
        let text = text.into();
        validate_coordinate(&source_key, MAX_TURN_COORDINATE_BYTES)
            .map_err(|_| FollowUpBuildError::InvalidTurn)?;
        validate_text(&text, MAX_TURN_TEXT_BYTES).map_err(|_| FollowUpBuildError::InvalidTurn)?;
        Ok(Self::Assistant { source_key, text })
    }

    #[must_use]
    pub fn source_key(&self) -> &str {
        match self {
            Self::User { source_key, .. } | Self::Assistant { source_key, .. } => source_key,
        }
    }

    #[must_use]
    pub fn text(&self) -> &str {
        match self {
            Self::User { text, .. } | Self::Assistant { text, .. } => text,
        }
    }
}

/// Input delivery supported by the currently active operation. The lane
/// owner derives this from authenticated runtime capability, never from text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveInputMode {
    /// The caller may redirect the active turn immediately.
    Steer,
    /// The caller may append input only after the current turn settles.
    FollowUp,
    /// The caller has no control capability for the active operation.
    ObserveOnly,
}

/// Trusted execution state for the exact conversation lane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LaneActivity {
    Idle,
    Running {
        operation_id: String,
        input_mode: ActiveInputMode,
    },
    /// An approval must still use its dedicated, exact decision contract.
    AwaitingApproval {
        operation_id: String,
    },
}

impl LaneActivity {
    pub fn running(
        operation_id: impl Into<String>,
        input_mode: ActiveInputMode,
    ) -> Result<Self, FollowUpBuildError> {
        let operation_id = operation_id.into();
        validate_coordinate(&operation_id, MAX_TURN_COORDINATE_BYTES)
            .map_err(|_| FollowUpBuildError::InvalidActivity)?;
        Ok(Self::Running {
            operation_id,
            input_mode,
        })
    }

    pub fn awaiting_approval(operation_id: impl Into<String>) -> Result<Self, FollowUpBuildError> {
        let operation_id = operation_id.into();
        validate_coordinate(&operation_id, MAX_TURN_COORDINATE_BYTES)
            .map_err(|_| FollowUpBuildError::InvalidActivity)?;
        Ok(Self::AwaitingApproval { operation_id })
    }
}

/// A bounded, already-authenticated view of one conversation lane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationLane {
    lane_key: String,
    activity: LaneActivity,
    turns: Vec<LaneTurn>,
}

impl ConversationLane {
    pub fn new(
        lane_key: impl Into<String>,
        activity: LaneActivity,
        turns: Vec<LaneTurn>,
    ) -> Result<Self, FollowUpBuildError> {
        let lane_key = lane_key.into();
        validate_coordinate(&lane_key, MAX_LANE_COORDINATE_BYTES)
            .map_err(|_| FollowUpBuildError::InvalidLane)?;
        if turns.len() > MAX_LANE_TURNS {
            return Err(FollowUpBuildError::ContextTooLarge);
        }
        let context_bytes = turns
            .iter()
            .try_fold(0usize, |total, turn| total.checked_add(turn.text().len()));
        if context_bytes.is_none_or(|bytes| bytes > MAX_LANE_CONTEXT_BYTES) {
            return Err(FollowUpBuildError::ContextTooLarge);
        }
        Ok(Self {
            lane_key,
            activity,
            turns,
        })
    }

    #[must_use]
    pub fn lane_key(&self) -> &str {
        &self.lane_key
    }

    #[must_use]
    pub const fn activity(&self) -> &LaneActivity {
        &self.activity
    }

    #[must_use]
    pub fn turns(&self) -> &[LaneTurn] {
        &self.turns
    }
}

/// Current transport input. The source key permits resolution after an ingress
/// path has already appended this same message to the transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FollowUpInput {
    source_key: String,
    actor_key: String,
    text: String,
}

impl FollowUpInput {
    pub fn new(
        source_key: impl Into<String>,
        actor_key: impl Into<String>,
        text: impl Into<String>,
    ) -> Result<Self, FollowUpBuildError> {
        let source_key = source_key.into();
        let actor_key = actor_key.into();
        let text = text.into();
        validate_coordinate(&source_key, MAX_TURN_COORDINATE_BYTES)
            .map_err(|_| FollowUpBuildError::InvalidInput)?;
        validate_coordinate(&actor_key, MAX_ACTOR_COORDINATE_BYTES)
            .map_err(|_| FollowUpBuildError::InvalidInput)?;
        validate_text(&text, MAX_CURRENT_TEXT_BYTES)
            .map_err(|_| FollowUpBuildError::InvalidInput)?;
        Ok(Self {
            source_key,
            actor_key,
            text,
        })
    }

    #[must_use]
    pub fn source_key(&self) -> &str {
        &self.source_key
    }

    #[must_use]
    pub fn actor_key(&self) -> &str {
        &self.actor_key
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// Semantic interpretation only. This signal has no authority attached to it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FollowUpReference {
    NewRequest,
    RefersToLaneWork,
    Unclear,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterpreterFailure {
    Unavailable,
    TimedOut,
    MalformedOutput,
}

/// Bounded input presented to a model or another semantic interpreter.
pub struct FollowUpInterpretationRequest<'a> {
    input: &'a FollowUpInput,
    lane: &'a ConversationLane,
    prior_user_turn: Option<&'a LaneTurn>,
}

impl<'a> FollowUpInterpretationRequest<'a> {
    #[must_use]
    pub const fn input(&self) -> &'a FollowUpInput {
        self.input
    }

    #[must_use]
    pub const fn lane(&self) -> &'a ConversationLane {
        self.lane
    }

    #[must_use]
    pub const fn prior_user_turn(&self) -> Option<&'a LaneTurn> {
        self.prior_user_turn
    }
}

/// Adapter seam for model-led reference resolution. Implementations should
/// return a typed value and fail closed on malformed provider output.
pub trait FollowUpInterpreter {
    fn interpret(
        &mut self,
        request: FollowUpInterpretationRequest<'_>,
    ) -> Result<FollowUpReference, InterpreterFailure>;
}

/// A deliberately small, product-independent grammar for terse references.
///
/// This is not a table of complete phrases or business intents. It recognizes
/// only a short composition of grammatical roles (action, reference,
/// affirmation and politeness). Every other message remains a normal model
/// turn. In particular, domain verbs such as `close`, `publish`, `fix` and
/// `approve` are absent, so this adapter cannot reinterpret a new effect as a
/// replay request.
#[derive(Default)]
pub struct ConservativeTerseInterpreter;

impl FollowUpInterpreter for ConservativeTerseInterpreter {
    fn interpret(
        &mut self,
        request: FollowUpInterpretationRequest<'_>,
    ) -> Result<FollowUpReference, InterpreterFailure> {
        let text = request.input().text();
        if text.contains('?') || text.contains('\n') || text.contains('\r') {
            return Ok(FollowUpReference::NewRequest);
        }
        let tokens = text
            .to_lowercase()
            .split(|character: char| !character.is_alphanumeric())
            .filter(|token| !token.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if tokens.is_empty() || tokens.len() > 5 || tokens.iter().any(|token| !terse_token(token)) {
            return Ok(FollowUpReference::NewRequest);
        }
        let has_action = tokens.iter().any(|token| action_token(token));
        let has_reference = tokens.iter().any(|token| reference_token(token));
        let has_affirmation = tokens.iter().any(|token| affirmation_token(token));
        let has_politeness = tokens.iter().any(|token| politeness_token(token));
        let has_continuation = tokens.iter().any(|token| continuation_token(token));
        let refers = (has_action && (has_reference || has_continuation || has_politeness))
            || (has_affirmation && (has_reference || has_action || has_politeness));
        Ok(if refers {
            FollowUpReference::RefersToLaneWork
        } else {
            FollowUpReference::NewRequest
        })
    }
}

fn terse_token(token: &str) -> bool {
    action_token(token)
        || reference_token(token)
        || affirmation_token(token)
        || politeness_token(token)
        || continuation_token(token)
}

fn action_token(token: &str) -> bool {
    matches!(
        token,
        "do" | "go" | "continue" | "proceed" | "fais" | "vas" | "continuez"
    )
}

fn reference_token(token: &str) -> bool {
    matches!(
        token,
        "it" | "that" | "this" | "them" | "so" | "le" | "la" | "les" | "ça" | "cela"
    )
}

fn affirmation_token(token: &str) -> bool {
    matches!(token, "yes" | "yep" | "sure" | "oui")
}

fn politeness_token(token: &str) -> bool {
    matches!(token, "please" | "pls" | "svp")
}

fn continuation_token(token: &str) -> bool {
    matches!(token, "ahead" | "on" | "y")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnresolvedReason {
    InterpreterUnavailable,
    UnclearReference,
    NoPriorRequest,
    DifferentActor,
    PriorRequestNotReplayable,
    NoControlCapability,
}

/// A route chosen from semantic reference plus trusted lane capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FollowUpResolution {
    /// Preserve the input as an ordinary new conversational turn.
    NewTurn,
    /// Repeat the exact prior read-only request, preserving its source identity.
    ReplayReadOnly {
        prior_source_key: String,
        request: String,
    },
    /// Redirect the exact active operation using the new input, not old prose.
    Steer { operation_id: String, input: String },
    /// Append the new input after the exact active operation settles.
    QueueFollowUp { operation_id: String, input: String },
    /// Never convert referential prose into an approval decision.
    RequiresExplicitApproval { operation_id: String },
    /// Let the caller continue through its normal contextual model path or ask
    /// for clarification; this component emits no canned fallback reply.
    Unresolved(UnresolvedReason),
}

/// Resolve one message without interpreting phrases in code.
pub fn resolve_follow_up(
    lane: &ConversationLane,
    input: &FollowUpInput,
    interpreter: &mut dyn FollowUpInterpreter,
) -> FollowUpResolution {
    let prior = latest_prior_user_turn(lane.turns(), input.source_key());
    let reference = match interpreter.interpret(FollowUpInterpretationRequest {
        input,
        lane,
        prior_user_turn: prior,
    }) {
        Ok(reference) => reference,
        Err(_) => {
            return FollowUpResolution::Unresolved(UnresolvedReason::InterpreterUnavailable);
        }
    };
    match reference {
        FollowUpReference::NewRequest => FollowUpResolution::NewTurn,
        FollowUpReference::Unclear => {
            FollowUpResolution::Unresolved(UnresolvedReason::UnclearReference)
        }
        FollowUpReference::RefersToLaneWork => resolve_lane_reference(lane, input, prior),
    }
}

fn resolve_lane_reference(
    lane: &ConversationLane,
    input: &FollowUpInput,
    prior: Option<&LaneTurn>,
) -> FollowUpResolution {
    match lane.activity() {
        LaneActivity::Running {
            operation_id,
            input_mode: ActiveInputMode::Steer,
        } => FollowUpResolution::Steer {
            operation_id: operation_id.clone(),
            input: input.text().to_owned(),
        },
        LaneActivity::Running {
            operation_id,
            input_mode: ActiveInputMode::FollowUp,
        } => FollowUpResolution::QueueFollowUp {
            operation_id: operation_id.clone(),
            input: input.text().to_owned(),
        },
        LaneActivity::Running {
            input_mode: ActiveInputMode::ObserveOnly,
            ..
        } => FollowUpResolution::Unresolved(UnresolvedReason::NoControlCapability),
        LaneActivity::AwaitingApproval { operation_id } => {
            FollowUpResolution::RequiresExplicitApproval {
                operation_id: operation_id.clone(),
            }
        }
        LaneActivity::Idle => replay_prior_read_only(input, prior),
    }
}

fn replay_prior_read_only(input: &FollowUpInput, prior: Option<&LaneTurn>) -> FollowUpResolution {
    let Some(LaneTurn::User {
        source_key,
        actor_key,
        text,
        request_kind,
    }) = prior
    else {
        return FollowUpResolution::Unresolved(UnresolvedReason::NoPriorRequest);
    };
    if actor_key != input.actor_key() {
        return FollowUpResolution::Unresolved(UnresolvedReason::DifferentActor);
    }
    if *request_kind != PriorRequestKind::ReplayableReadOnly {
        return FollowUpResolution::Unresolved(UnresolvedReason::PriorRequestNotReplayable);
    }
    FollowUpResolution::ReplayReadOnly {
        prior_source_key: source_key.clone(),
        request: text.clone(),
    }
}

fn latest_prior_user_turn<'a>(turns: &'a [LaneTurn], current_source: &str) -> Option<&'a LaneTurn> {
    turns
        .iter()
        .rev()
        .find(|turn| matches!(turn, LaneTurn::User { .. }) && turn.source_key() != current_source)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FollowUpBuildError {
    InvalidLane,
    InvalidActivity,
    InvalidTurn,
    InvalidInput,
    ContextTooLarge,
}

impl fmt::Display for FollowUpBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLane => formatter.write_str("invalid conversation lane"),
            Self::InvalidActivity => formatter.write_str("invalid lane activity"),
            Self::InvalidTurn => formatter.write_str("invalid lane turn"),
            Self::InvalidInput => formatter.write_str("invalid follow-up input"),
            Self::ContextTooLarge => formatter.write_str("conversation lane context is too large"),
        }
    }
}

impl std::error::Error for FollowUpBuildError {}

fn validate_coordinate(value: &str, maximum: usize) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > maximum
        || value.chars().any(char::is_whitespace)
        || value.chars().any(|character| character == '\0')
    {
        return Err(());
    }
    Ok(())
}

fn validate_text(value: &str, maximum: usize) -> Result<(), ()> {
    if value.trim().is_empty()
        || value.len() > maximum
        || value.chars().any(|character| character == '\0')
    {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedInterpreter(Result<FollowUpReference, InterpreterFailure>);

    impl FollowUpInterpreter for FixedInterpreter {
        fn interpret(
            &mut self,
            _request: FollowUpInterpretationRequest<'_>,
        ) -> Result<FollowUpReference, InterpreterFailure> {
            self.0
        }
    }

    fn input(text: &str) -> FollowUpInput {
        FollowUpInput::new("event-current", "actor-a", text).expect("valid input")
    }

    fn user(source: &str, actor: &str, text: &str, request_kind: PriorRequestKind) -> LaneTurn {
        LaneTurn::user(source, actor, text, request_kind).expect("valid user turn")
    }

    fn assistant(source: &str, text: &str) -> LaneTurn {
        LaneTurn::assistant(source, text).expect("valid assistant turn")
    }

    fn lane(activity: LaneActivity, turns: Vec<LaneTurn>) -> ConversationLane {
        ConversationLane::new("slack:installation:channel:thread", activity, turns)
            .expect("valid lane")
    }

    fn resolve(
        lane: &ConversationLane,
        input: &FollowUpInput,
        reference: FollowUpReference,
    ) -> FollowUpResolution {
        resolve_follow_up(lane, input, &mut FixedInterpreter(Ok(reference)))
    }

    #[test]
    fn referential_input_replays_only_the_immediately_prior_read_only_request() {
        let current = input("do it");
        let lane = lane(
            LaneActivity::Idle,
            vec![
                user(
                    "event-prior",
                    "actor-a",
                    "What work finished yesterday?",
                    PriorRequestKind::ReplayableReadOnly,
                ),
                assistant("reply-prior", "I need to query the source."),
                user(
                    "event-current",
                    "actor-a",
                    "do it",
                    PriorRequestKind::Conversation,
                ),
            ],
        );
        assert_eq!(
            resolve(&lane, &current, FollowUpReference::RefersToLaneWork),
            FollowUpResolution::ReplayReadOnly {
                prior_source_key: String::from("event-prior"),
                request: String::from("What work finished yesterday?"),
            }
        );
    }

    #[test]
    fn semantic_new_request_is_never_rewritten_from_lane_history() {
        let current = input("Build a new report");
        let lane = lane(
            LaneActivity::Idle,
            vec![user(
                "event-prior",
                "actor-a",
                "Show yesterday's work",
                PriorRequestKind::ReplayableReadOnly,
            )],
        );
        assert_eq!(
            resolve(&lane, &current, FollowUpReference::NewRequest),
            FollowUpResolution::NewTurn
        );
    }

    #[test]
    fn active_lane_capability_selects_steer_or_follow_up_without_replaying_text() {
        let current = input("do it");
        let steering = lane(
            LaneActivity::running("operation-1", ActiveInputMode::Steer).expect("activity"),
            Vec::new(),
        );
        assert_eq!(
            resolve(&steering, &current, FollowUpReference::RefersToLaneWork),
            FollowUpResolution::Steer {
                operation_id: String::from("operation-1"),
                input: String::from("do it"),
            }
        );

        let queued = lane(
            LaneActivity::running("operation-2", ActiveInputMode::FollowUp).expect("activity"),
            Vec::new(),
        );
        assert_eq!(
            resolve(&queued, &current, FollowUpReference::RefersToLaneWork),
            FollowUpResolution::QueueFollowUp {
                operation_id: String::from("operation-2"),
                input: String::from("do it"),
            }
        );
    }

    #[test]
    fn referential_text_never_acts_as_approval_or_control_authority() {
        let current = input("do it");
        let approval = lane(
            LaneActivity::awaiting_approval("operation-approval").expect("activity"),
            Vec::new(),
        );
        assert_eq!(
            resolve(&approval, &current, FollowUpReference::RefersToLaneWork),
            FollowUpResolution::RequiresExplicitApproval {
                operation_id: String::from("operation-approval"),
            }
        );

        let observer = lane(
            LaneActivity::running("operation-observed", ActiveInputMode::ObserveOnly)
                .expect("activity"),
            Vec::new(),
        );
        assert_eq!(
            resolve(&observer, &current, FollowUpReference::RefersToLaneWork),
            FollowUpResolution::Unresolved(UnresolvedReason::NoControlCapability)
        );
    }

    #[test]
    fn latest_non_replayable_request_blocks_fallback_to_older_safe_text() {
        let current = input("do it");
        let lane = lane(
            LaneActivity::Idle,
            vec![
                user(
                    "event-old",
                    "actor-a",
                    "Show yesterday's work",
                    PriorRequestKind::ReplayableReadOnly,
                ),
                user(
                    "event-near",
                    "actor-a",
                    "Publish the report",
                    PriorRequestKind::Effectful,
                ),
            ],
        );
        assert_eq!(
            resolve(&lane, &current, FollowUpReference::RefersToLaneWork),
            FollowUpResolution::Unresolved(UnresolvedReason::PriorRequestNotReplayable)
        );
    }

    #[test]
    fn idle_replay_does_not_borrow_another_actor_request() {
        let current = input("do it");
        let lane = lane(
            LaneActivity::Idle,
            vec![user(
                "event-prior",
                "actor-b",
                "Show yesterday's work",
                PriorRequestKind::ReplayableReadOnly,
            )],
        );
        assert_eq!(
            resolve(&lane, &current, FollowUpReference::RefersToLaneWork),
            FollowUpResolution::Unresolved(UnresolvedReason::DifferentActor)
        );
    }

    #[test]
    fn interpreter_failures_and_uncertainty_do_not_trigger_fallback_actions() {
        let current = input("do it");
        let lane = lane(LaneActivity::Idle, Vec::new());
        assert_eq!(
            resolve_follow_up(
                &lane,
                &current,
                &mut FixedInterpreter(Err(InterpreterFailure::MalformedOutput))
            ),
            FollowUpResolution::Unresolved(UnresolvedReason::InterpreterUnavailable)
        );
        assert_eq!(
            resolve(&lane, &current, FollowUpReference::Unclear),
            FollowUpResolution::Unresolved(UnresolvedReason::UnclearReference)
        );
    }

    #[test]
    fn conservative_interpreter_recognizes_grammar_without_domain_phrase_rules() {
        let lane = lane(LaneActivity::Idle, Vec::new());
        let mut interpreter = ConservativeTerseInterpreter;
        for text in [
            "do it",
            "please do it",
            "go ahead",
            "yes please",
            "fais-le",
            "vas-y",
        ] {
            let current = input(text);
            assert_eq!(
                interpreter
                    .interpret(FollowUpInterpretationRequest {
                        input: &current,
                        lane: &lane,
                        prior_user_turn: None,
                    })
                    .expect("deterministic interpreter"),
                FollowUpReference::RefersToLaneWork,
                "{text:?}"
            );
        }
        for text in [
            "what is it?",
            "fix it",
            "approve it",
            "go to production",
            "build a report",
        ] {
            let current = input(text);
            assert_eq!(
                interpreter
                    .interpret(FollowUpInterpretationRequest {
                        input: &current,
                        lane: &lane,
                        prior_user_turn: None,
                    })
                    .expect("deterministic interpreter"),
                FollowUpReference::NewRequest,
                "{text:?}"
            );
        }
    }

    #[test]
    fn lane_and_input_bounds_are_enforced_before_interpretation() {
        assert_eq!(
            FollowUpInput::new("event", "actor", "x".repeat(MAX_CURRENT_TEXT_BYTES + 1)),
            Err(FollowUpBuildError::InvalidInput)
        );
        let turns = (0..=MAX_LANE_TURNS)
            .map(|index| {
                user(
                    &format!("event-{index}"),
                    "actor-a",
                    "safe read",
                    PriorRequestKind::ReplayableReadOnly,
                )
            })
            .collect();
        assert_eq!(
            ConversationLane::new("lane", LaneActivity::Idle, turns),
            Err(FollowUpBuildError::ContextTooLarge)
        );
    }
}
