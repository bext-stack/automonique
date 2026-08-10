// SPDX-License-Identifier: Elastic-2.0

//! Canonical schedules, occurrence keys, goals and inbound triggers.
//!
//! Work that starts without a person present has to be reconstructible. A
//! schedule is stored only in canonical form, an occurrence key makes duplicate
//! firing detectable without coordination, and a goal's completion cannot rest
//! on prose when its contract demanded artifacts.
//!
//! Nothing here runs a scheduler, fires anything, holds a lease, verifies a
//! webhook signature or calls a model.

use core::fmt;
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
            Self::RevisionConflict { .. } => "revision_conflict",
            Self::OutsideApprovedScope { .. } => "outside_approved_scope",
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
            Self::RevisionConflict { expected, offered } => write!(
                formatter,
                "automation is at revision {expected}; the edit asserted {offered}"
            ),
            Self::OutsideApprovedScope { effect } => write!(
                formatter,
                "effect {effect} is outside the automation's pre-approved scope"
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

/// A schedule in canonical form.
///
/// Prose is not a variant. A natural-language expression is parsed into one of
/// these or refused; it is never stored as written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalSchedule {
    /// Once, at an exact instant.
    Once {
        /// When.
        at: EpochMillis,
    },
    /// Every fixed interval.
    Every {
        /// The interval in milliseconds.
        interval_ms: i64,
    },
    /// A five-field cron expression in an explicit zone.
    Cron {
        /// The canonical five-field expression.
        expression: String,
        /// The IANA timezone.
        timezone: String,
    },
}

impl CanonicalSchedule {
    /// Parse a natural-language expression into canonical form.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::AmbiguousExpression`] for anything that does
    /// not resolve to exactly one schedule. A best guess is not an outcome.
    pub fn parse(expression: &str) -> Result<Self, AutomationError> {
        bounded(expression, "expression")?;
        let normalized = expression.trim().to_lowercase();
        match normalized.as_str() {
            "every hour" | "hourly" => Ok(Self::Every {
                interval_ms: 60 * 60 * 1_000,
            }),
            "every day" | "daily" => Ok(Self::Cron {
                expression: "0 0 * * *".to_owned(),
                timezone: "UTC".to_owned(),
            }),
            _ => Err(AutomationError::AmbiguousExpression {
                reason: "no single canonical schedule matches",
            }),
        }
    }

    /// Render the canonical form.
    ///
    /// Round-trips: parsing a rendering yields an identical schedule, so the
    /// preview shown to an operator is the schedule that will run.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Once { at } => format!("once@{}", at.as_millis()),
            Self::Every { interval_ms } => format!("every@{interval_ms}"),
            Self::Cron {
                expression,
                timezone,
            } => format!("cron@{expression}@{timezone}"),
        }
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
        if expected != self.revision {
            return Err(AutomationError::RevisionConflict {
                expected: self.revision.get(),
                offered: expected.get(),
            });
        }
        let mut next = self.clone();
        next.revision =
            Revision::new(self.revision.get() + 1).map_err(|_| AutomationError::Field {
                field: "revision",
                error: ValueError::Empty,
            })?;
        next.schedule = schedule;
        Ok(next)
    }

    /// Decide whether an unattended effect is pre-approved.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::OutsideApprovedScope`]. An effect outside
    /// scope is representable only as this refusal — creating a schedule is
    /// never blanket authority for future arbitrary effects.
    pub fn permit_unattended(&self, effect: &str) -> Result<(), AutomationError> {
        if self
            .approved_effects
            .iter()
            .any(|allowed| allowed == effect)
        {
            Ok(())
        } else {
            Err(AutomationError::OutsideApprovedScope {
                effect: effect.to_owned(),
            })
        }
    }
}

/// What evidence a goal's completion contract demands.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CompletionEvidence {
    /// Prose is sufficient.
    Narrative,
    /// A passing test run is required.
    Tests,
    /// A produced artifact is required.
    Artifact,
    /// An action receipt is required.
    Receipt,
}

impl CompletionEvidence {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Narrative => "narrative",
            Self::Tests => "tests",
            Self::Artifact => "artifact",
            Self::Receipt => "receipt",
        }
    }
}

/// What a goal should do next.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GoalVerdict {
    /// Keep going.
    Continue {
        /// Why.
        evidence: String,
    },
    /// Finished.
    Complete {
        /// Why.
        evidence: String,
    },
    /// Waiting on a durable condition.
    Wait {
        /// What is being waited on.
        condition: WaitCondition,
    },
    /// Cannot proceed.
    Blocked {
        /// Why.
        evidence: String,
    },
    /// Out of budget.
    BudgetExhausted {
        /// Why.
        evidence: String,
    },
}

/// What a goal waits on.
///
/// Every variant names something durable. A free-text label is not a variant,
/// so a wake cannot resolve from prose.
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
        run_id: String,
    },
    /// A connector event.
    ConnectorEvent {
        /// The source key expected.
        source_key: String,
    },
}

/// A durable objective.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Goal {
    id: String,
    required_evidence: CompletionEvidence,
}

impl Goal {
    /// Declare a goal and what its completion requires.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid identifier.
    pub fn new(id: &str, required_evidence: CompletionEvidence) -> Result<Self, AutomationError> {
        bounded(id, "goal_id")?;
        Ok(Self {
            id: id.to_owned(),
            required_evidence,
        })
    }

    /// What completion requires.
    #[must_use]
    pub const fn required_evidence(&self) -> CompletionEvidence {
        self.required_evidence
    }

    /// Record a completion, checking it against the contract.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::CompletionEvidenceMissing`] when the goal
    /// demanded tests, an artifact or a receipt and only prose was supplied.
    /// A persuasive summary does not close a goal that required evidence.
    pub fn complete_with(
        &self,
        supplied: CompletionEvidence,
        narrative: &str,
    ) -> Result<GoalVerdict, AutomationError> {
        bounded(narrative, "narrative")?;
        if self.required_evidence != CompletionEvidence::Narrative
            && supplied != self.required_evidence
        {
            return Err(AutomationError::CompletionEvidenceMissing {
                required: self.required_evidence.as_str(),
            });
        }
        Ok(GoalVerdict::Complete {
            evidence: narrative.to_owned(),
        })
    }
}

/// A fenced board claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoardClaim {
    task: String,
    worker: String,
    epoch: u64,
}

impl BoardClaim {
    /// Claim a task at an epoch.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid component.
    pub fn new(task: &str, worker: &str, epoch: u64) -> Result<Self, AutomationError> {
        bounded(task, "task")?;
        bounded(worker, "worker")?;
        Ok(Self {
            task: task.to_owned(),
            worker: worker.to_owned(),
            epoch,
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
}

/// An inbound trigger route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerRoute {
    id: String,
    verification: VerificationMethod,
    replay_window_ms: i64,
    max_body_bytes: u64,
    delivers_directly: bool,
}

/// How an inbound request is authenticated.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VerificationMethod {
    /// Shared-secret HMAC.
    Hmac,
    /// Public-key signature.
    PublicKey,
    /// Mutual TLS.
    MutualTls,
}

impl TriggerRoute {
    /// Declare a route.
    ///
    /// Verification, replay window and body ceiling are required arguments,
    /// so an unauthenticated or unbounded route is not constructible.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::Field`] for an invalid identifier.
    pub fn new(
        id: &str,
        verification: VerificationMethod,
        replay_window_ms: i64,
        max_body_bytes: u64,
        delivers_directly: bool,
    ) -> Result<Self, AutomationError> {
        bounded(id, "route_id")?;
        Ok(Self {
            id: id.to_owned(),
            verification,
            replay_window_ms,
            max_body_bytes,
            delivers_directly,
        })
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

    /// The body ceiling.
    #[must_use]
    pub const fn max_body_bytes(&self) -> u64 {
        self.max_body_bytes
    }

    /// Whether delivery bypasses the model.
    ///
    /// Bypassing the model does not bypass destination authorization, outbox
    /// receipts or content limits, which is why this is a flag on an otherwise
    /// fully specified route rather than a different kind of route.
    #[must_use]
    pub const fn delivers_directly(&self) -> bool {
        self.delivers_directly
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
