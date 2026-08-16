// SPDX-License-Identifier: Elastic-2.0

//! Execution-host lifecycle: identities, states, expiry and restart recovery.
//!
//! Five identities stay distinct — work, attempt, host, provider session and
//! turn — so a retry appends evidence instead of overwriting it:
//!
//! ```compile_fail
//! use automonique_protocol::host::{AttemptId, HostId};
//! let attempt = AttemptId::new("a-1").unwrap();
//! // An attempt is not a host.
//! let host: HostId = attempt;
//! ```
//!
//! The rule this module exists to hold is that a missing local process is
//! never called "running". Classification is total and lands on
//! [`RestartClassification::ReconciliationRequired`] whenever the evidence
//! does not say otherwise.
//!
//! Nothing here spawns a process, allocates a unit, opens a socket, reads
//! `/proc` or starts a timer. Expiry is a pure function of instants a caller
//! supplies.

use core::fmt;
use std::error::Error;

use crate::primitives::{EpochMillis, OpaqueId, ValueError};

/// Maximum UTF-8 byte length of a host identifier.
pub const MAX_HOST_ID_BYTES: usize = 128;

macro_rules! host_domain {
    ($domain:ident, $alias:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $domain;

        impl crate::primitives::IdDomain for $domain {}

        #[doc = $doc]
        pub type $alias = OpaqueId<$domain, MAX_HOST_ID_BYTES>;
    };
}

host_domain!(WorkDomain, WorkId, "An approved unit of business work.");
host_domain!(AttemptDomain, AttemptId, "One attempt at a work item.");
host_domain!(HostDomain, HostId, "One supervised execution-host unit.");

/// How long a host lives.
///
/// Fixed at construction: a host that changes lifetime mid-life has no
/// meaningful boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HostLifetime {
    /// Bounds one attempt's process boundary.
    Attempt,
    /// Serializes multiple turns.
    Session,
}

impl HostLifetime {
    /// Every lifetime, for closed-codec coverage.
    pub const ALL: [Self; 2] = [Self::Attempt, Self::Session];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attempt => "attempt",
            Self::Session => "session",
        }
    }

    /// Parse the exact stable spelling.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|lifetime| lifetime.as_str() == value)
    }
}

/// Why a host operation was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostError {
    /// A host lifetime was changed after construction.
    LifetimeIsImmutable {
        /// The lifetime that may not change.
        lifetime: HostLifetime,
    },
    /// A session attach crossed a boundary component.
    BoundaryMismatch {
        /// The differing component.
        component: &'static str,
    },
    /// A state transition is not in the legal table.
    IllegalTransition {
        /// The state departed from.
        from: HostState,
        /// The state attempted.
        to: HostState,
    },
    /// A serialization claim was released without terminal state or verified
    /// loss.
    ClaimStillActive {
        /// The work still holding it.
        work: String,
    },
    /// A bounded identifier was rejected.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
}

impl HostError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::LifetimeIsImmutable { .. } => "lifetime_is_immutable",
            Self::BoundaryMismatch { .. } => "boundary_mismatch",
            Self::IllegalTransition { .. } => "illegal_transition",
            Self::ClaimStillActive { .. } => "claim_still_active",
            Self::Field { .. } => "field_invalid",
        }
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LifetimeIsImmutable { lifetime } => write!(
                formatter,
                "host lifetime {} is fixed at construction",
                lifetime_name(*lifetime)
            ),
            Self::BoundaryMismatch { component } => {
                write!(formatter, "host boundary differs in {component}")
            }
            Self::IllegalTransition { from, to } => write!(
                formatter,
                "{} cannot transition to {}",
                from.as_str(),
                to.as_str()
            ),
            Self::ClaimStillActive { work } => write!(
                formatter,
                "claim is still held by {work}; release needs terminal state or verified loss"
            ),
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
        }
    }
}

impl Error for HostError {}

const fn lifetime_name(lifetime: HostLifetime) -> &'static str {
    lifetime.as_str()
}

/// The supervised state of a host.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HostState {
    /// Launching.
    Starting,
    /// Launched and idle-capable.
    Ready,
    /// Executing a turn.
    Busy,
    /// Alive with no work.
    Idle,
    /// Suspended, resumable.
    Hibernated,
    /// Draining.
    Stopping,
    /// Terminal: stopped cleanly.
    Stopped,
    /// Terminal: stopped with a fault.
    Failed,
    /// Terminal: contact lost and not reconcilable.
    Lost,
}

impl HostState {
    /// Every state, for coverage checks.
    pub const ALL: [Self; 9] = [
        Self::Starting,
        Self::Ready,
        Self::Busy,
        Self::Idle,
        Self::Hibernated,
        Self::Stopping,
        Self::Stopped,
        Self::Failed,
        Self::Lost,
    ];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Busy => "busy",
            Self::Idle => "idle",
            Self::Hibernated => "hibernated",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Lost => "lost",
        }
    }

    /// Whether the state is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed | Self::Lost)
    }

    /// The legal transitions out of this state.
    ///
    /// Declared exhaustively; anything absent is refused rather than allowed by
    /// a permissive default. Terminal states have no successors.
    #[must_use]
    pub const fn legal_successors(self) -> &'static [Self] {
        match self {
            Self::Starting => &[Self::Ready, Self::Failed, Self::Lost],
            Self::Ready => &[
                Self::Busy,
                Self::Idle,
                Self::Stopping,
                Self::Failed,
                Self::Lost,
            ],
            Self::Busy => &[
                Self::Ready,
                Self::Idle,
                Self::Stopping,
                Self::Failed,
                Self::Lost,
            ],
            Self::Idle => &[
                Self::Busy,
                Self::Hibernated,
                Self::Stopping,
                Self::Failed,
                Self::Lost,
            ],
            Self::Hibernated => &[Self::Ready, Self::Stopping, Self::Failed, Self::Lost],
            Self::Stopping => &[Self::Stopped, Self::Failed, Self::Lost],
            Self::Stopped | Self::Failed | Self::Lost => &[],
        }
    }

    /// Whether a transition is declared legal.
    #[must_use]
    pub fn may_transition_to(self, next: Self) -> bool {
        self.legal_successors().contains(&next)
    }

    /// Apply a transition.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::IllegalTransition`] for anything not declared.
    pub fn transition_to(self, next: Self) -> Result<Self, HostError> {
        if self.may_transition_to(next) {
            Ok(next)
        } else {
            Err(HostError::IllegalTransition {
                from: self,
                to: next,
            })
        }
    }
}

/// The security boundary a host was created under.
///
/// A resumable session may attach only through an identical boundary. Every
/// component participates, so a resume cannot cross a tenant by accident.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HostBoundary {
    tenant: String,
    provider_account: String,
    workspace_context: String,
    boot_id: String,
}

impl HostBoundary {
    /// Record the boundary a host runs within.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Field`] for an invalid component.
    pub fn new(
        tenant: &str,
        provider_account: &str,
        workspace_context: &str,
        boot_id: &str,
    ) -> Result<Self, HostError> {
        bounded(tenant, "tenant")?;
        bounded(provider_account, "provider_account")?;
        bounded(workspace_context, "workspace_context")?;
        bounded(boot_id, "boot_id")?;
        Ok(Self {
            tenant: tenant.to_owned(),
            provider_account: provider_account.to_owned(),
            workspace_context: workspace_context.to_owned(),
            boot_id: boot_id.to_owned(),
        })
    }

    /// Confirm another boundary is the same one.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::BoundaryMismatch`] naming the first differing
    /// component. A weaker or merely different boundary is a refusal, not a
    /// partial match.
    pub fn confirm_same(&self, other: &Self) -> Result<(), HostError> {
        for (component, left, right) in [
            ("tenant", &self.tenant, &other.tenant),
            (
                "provider_account",
                &self.provider_account,
                &other.provider_account,
            ),
            (
                "workspace_context",
                &self.workspace_context,
                &other.workspace_context,
            ),
            ("boot_id", &self.boot_id, &other.boot_id),
        ] {
            if left != right {
                return Err(HostError::BoundaryMismatch { component });
            }
        }
        Ok(())
    }
}

/// A supervised execution host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionHost {
    id: HostId,
    lifetime: HostLifetime,
    boundary: HostBoundary,
    state: HostState,
}

impl ExecutionHost {
    /// Create a host with a fixed lifetime.
    #[must_use]
    pub const fn new(id: HostId, lifetime: HostLifetime, boundary: HostBoundary) -> Self {
        Self {
            id,
            lifetime,
            boundary,
            state: HostState::Starting,
        }
    }

    /// The host identity.
    #[must_use]
    pub const fn id(&self) -> &HostId {
        &self.id
    }

    /// The fixed lifetime.
    #[must_use]
    pub const fn lifetime(&self) -> HostLifetime {
        self.lifetime
    }

    /// The current state.
    #[must_use]
    pub const fn state(&self) -> HostState {
        self.state
    }

    /// Refuse a lifetime change.
    ///
    /// # Errors
    ///
    /// Always returns [`HostError::LifetimeIsImmutable`]. A host with a
    /// different lifetime is a different host.
    pub const fn set_lifetime(&self, _lifetime: HostLifetime) -> Result<(), HostError> {
        Err(HostError::LifetimeIsImmutable {
            lifetime: self.lifetime,
        })
    }

    /// Move to a new state.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::IllegalTransition`] for an undeclared transition.
    pub fn transition_to(&self, next: HostState) -> Result<Self, HostError> {
        let state = self.state.transition_to(next)?;
        let mut moved = self.clone();
        moved.state = state;
        Ok(moved)
    }

    /// Attach a resumable session, requiring an identical boundary.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::BoundaryMismatch`] naming the differing component.
    pub fn attach_within(&self, boundary: &HostBoundary) -> Result<(), HostError> {
        self.boundary.confirm_same(boundary)
    }
}

/// Where a run sits relative to a host.
///
/// A run in `Running` always carries a host, so "starting with no host
/// assigned" is not a representable state. The host arrives with the
/// transition, not after it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunPlacement {
    /// Queued; no host yet.
    Pending,
    /// Refused admission; no host yet.
    AdmissionBlocked,
    /// Cancelled before launch; no host, and none is coming.
    PreLaunchCancelled,
    /// Assigned to a host.
    Running {
        /// The assigned host.
        host: HostId,
    },
}

impl RunPlacement {
    /// Assign a host, which is the only way to reach [`RunPlacement::Running`].
    #[must_use]
    pub const fn start_on(host: HostId) -> Self {
        Self::Running { host }
    }

    /// The assigned host, if any.
    #[must_use]
    pub const fn host(&self) -> Option<&HostId> {
        match self {
            Self::Running { host } => Some(host),
            Self::Pending | Self::AdmissionBlocked | Self::PreLaunchCancelled => None,
        }
    }
}

/// One attempt at a work item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attempt {
    id: AttemptId,
    work: WorkId,
    number: u32,
    retry_of: Option<AttemptId>,
}

impl Attempt {
    /// The attempt identity.
    #[must_use]
    pub const fn id(&self) -> &AttemptId {
        &self.id
    }

    /// The attempt number, starting at one.
    #[must_use]
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// The attempt this one retries, if any.
    #[must_use]
    pub const fn retry_of(&self) -> Option<&AttemptId> {
        self.retry_of.as_ref()
    }

    /// The owning work item.
    #[must_use]
    pub const fn work(&self) -> &WorkId {
        &self.work
    }
}

/// Every attempt at one work item, in order.
///
/// A retry appends. There is no method that replaces an attempt, so earlier
/// evidence stays addressable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptLog {
    work: WorkId,
    attempts: Vec<Attempt>,
}

impl AttemptLog {
    /// Start a log with its first attempt.
    #[must_use]
    pub fn new(work: WorkId, first: AttemptId) -> Self {
        Self {
            attempts: vec![Attempt {
                id: first,
                work: work.clone(),
                number: 1,
                retry_of: None,
            }],
            work,
        }
    }

    /// Append a retry of the latest attempt.
    #[must_use]
    pub fn retry(&self, id: AttemptId) -> Self {
        let previous = self.latest();
        let mut next = self.clone();
        next.attempts.push(Attempt {
            id,
            work: self.work.clone(),
            number: previous.number + 1,
            retry_of: Some(previous.id.clone()),
        });
        next
    }

    /// Every attempt, oldest first.
    #[must_use]
    pub fn attempts(&self) -> &[Attempt] {
        &self.attempts
    }

    /// The most recent attempt.
    #[must_use]
    pub fn latest(&self) -> &Attempt {
        self.attempts.last().expect("a log always has one attempt")
    }
}

/// An idle deadline, evaluated against a supplied instant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdleDeadline {
    last_active: EpochMillis,
    ttl_ms: i64,
}

impl IdleDeadline {
    /// Declare an idle window.
    #[must_use]
    pub const fn new(last_active: EpochMillis, ttl_ms: i64) -> Self {
        Self {
            last_active,
            ttl_ms,
        }
    }

    /// Whether the window has elapsed at `now`.
    ///
    /// A pure function of the two instants: no clock is read here, so the same
    /// inputs always classify the same way.
    #[must_use]
    pub const fn is_expired_at(self, now: EpochMillis) -> bool {
        now.as_millis().saturating_sub(self.last_active.as_millis()) >= self.ttl_ms
    }
}

/// What is known about a host after a restart.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RestartClassification {
    /// The provider session can be resumed.
    Resumable,
    /// The host was suspended and can be woken.
    Hibernated,
    /// The work ended and cannot continue.
    TerminallyInterrupted,
    /// The evidence does not say; a human or a reconciler must decide.
    ReconciliationRequired,
}

impl RestartClassification {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resumable => "resumable",
            Self::Hibernated => "hibernated",
            Self::TerminallyInterrupted => "terminally_interrupted",
            Self::ReconciliationRequired => "reconciliation_required",
        }
    }
}

/// What a restart found.
///
/// Deliberately does not include "a local process is present". Presence of a
/// process is not evidence that a session survived, and its absence is not
/// evidence that one did not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartEvidence {
    /// The last durably recorded state.
    pub recorded_state: Option<HostState>,
    /// Whether the provider authoritatively reports the session as resumable.
    pub provider_reports_resumable: Option<bool>,
}

/// Classify a host after a restart.
///
/// Total over the evidence and lands on
/// [`RestartClassification::ReconciliationRequired`] whenever the evidence is
/// absent or ambiguous. No input yields `Resumable` without an authoritative
/// provider answer, and none yields a running host from a missing process,
/// because process presence is not an input.
#[must_use]
pub fn classify_restart(evidence: RestartEvidence) -> RestartClassification {
    match (evidence.recorded_state, evidence.provider_reports_resumable) {
        (Some(state), _) if state.is_terminal() => RestartClassification::TerminallyInterrupted,
        (Some(HostState::Hibernated), Some(true)) => RestartClassification::Hibernated,
        (Some(_), Some(true)) => RestartClassification::Resumable,
        (Some(_), Some(false)) => RestartClassification::TerminallyInterrupted,
        // No recorded state, or the provider cannot say.
        (None, _) | (Some(_), None) => RestartClassification::ReconciliationRequired,
    }
}

/// Serialization claims held by work items.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClaimRegistry {
    claims: Vec<(String, String, bool)>,
}

impl ClaimRegistry {
    /// Start an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self { claims: Vec::new() }
    }

    /// Claim a serialization key for a work item.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ClaimStillActive`] when another work item holds it.
    pub fn claim(&mut self, key: &str, work: &str) -> Result<(), HostError> {
        bounded(key, "claim_key")?;
        bounded(work, "work")?;
        if let Some((_, holder, _)) = self.claims.iter().find(|(existing, _, _)| existing == key) {
            return Err(HostError::ClaimStillActive {
                work: holder.clone(),
            });
        }
        self.claims.push((key.to_owned(), work.to_owned(), false));
        Ok(())
    }

    /// Mark a claim's work terminal, or its host verifiably lost.
    pub fn mark_releasable(&mut self, key: &str) {
        for claim in &mut self.claims {
            if claim.0 == key {
                claim.2 = true;
            }
        }
    }

    /// Release a claim.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ClaimStillActive`] unless the work reached a
    /// terminal state or its host loss was verified.
    pub fn release(&mut self, key: &str) -> Result<(), HostError> {
        let Some(index) = self
            .claims
            .iter()
            .position(|(existing, _, _)| existing == key)
        else {
            return Ok(());
        };
        if !self.claims[index].2 {
            return Err(HostError::ClaimStillActive {
                work: self.claims[index].1.clone(),
            });
        }
        self.claims.remove(index);
        Ok(())
    }

    /// Transfer ownership of every claim to a new generation.
    ///
    /// A reload transfers claims; it does not delete them, so a paused old
    /// generation cannot act after expiry by finding the key free.
    pub fn transfer_ownership(&mut self, to_generation: &str) {
        for claim in &mut self.claims {
            claim.1 = format!("{}@{to_generation}", claim.1);
        }
    }

    /// Who holds a claim.
    #[must_use]
    pub fn holder_of(&self, key: &str) -> Option<&str> {
        self.claims
            .iter()
            .find(|(existing, _, _)| existing == key)
            .map(|(_, holder, _)| holder.as_str())
    }
}

fn bounded(value: &str, field: &'static str) -> Result<(), HostError> {
    crate::primitives::bounded_value(value, MAX_HOST_ID_BYTES)
        .map_err(|error| HostError::Field { field, error })
}
