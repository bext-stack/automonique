// SPDX-License-Identifier: Elastic-2.0

//! Tighten-only composition of approval requirements, and the fail-closed
//! answer for a host with nobody to ask.
//!
//! Three independent sources say how much ceremony one action needs: the
//! operator's configuration, the host the daemon measured itself onto, and the
//! call itself. This module folds them into one requirement and decides what a
//! caller may do, and it is a total function over caller-supplied observations:
//! no file is read, no socket is opened, no clock is consulted.
//!
//! # The one property that makes composition safe
//!
//! [`ApprovalRequirement`] is a three-value total order
//!
//! ```text
//! Allowed  <  ApprovalRequired  <  Forbidden
//! ```
//!
//! and [`ApprovalRequirement::tighten`] is its join — the maximum. A join on a
//! total order is commutative, associative and idempotent, so the composed
//! requirement does not depend on the order the sources are folded in, and
//! **no source can produce a result looser than itself**. That is the whole
//! guarantee: a configuration that says `Allowed` cannot unlock a host that
//! says `Forbidden`, and adding a source can only tighten. The property is
//! asserted by exhaustive enumeration of every triple rather than argued,
//! because a three-valued lattice has twenty-seven of them and a proof that
//! runs is worth more than a proof that reads well.
//!
//! # Where an approval fits, and where it deliberately does not
//!
//! An approval is evidence, not a policy source. It is consulted only after
//! composition, and only when the composed requirement is
//! [`ApprovalRequirement::ApprovalRequired`]:
//!
//! - composed [`ApprovalRequirement::Forbidden`] refuses **whatever the
//!   evidence says**, so a granted decision cannot reach a forbidden action;
//! - composed [`ApprovalRequirement::Allowed`] proceeds without consulting
//!   evidence at all, so an unapproved action that never needed approval is not
//!   gated by a lane it does not belong to.
//!
//! This is what "monotone by construction" means here: evidence has exactly one
//! reachable effect, promoting `ApprovalRequired` to
//! [`ApprovalGate::Proceed`], and there is no path on which it lowers a
//! requirement.
//!
//! # Fail-closed when nobody can answer
//!
//! An action that requires an operator decision on a host where no operator
//! decision surface is live has three possible answers, and two of them are
//! wrong. Proceeding is the requirement quietly discarded. Waiting is a
//! proposal nobody will ever see, held open until it expires — an outage
//! rendered as a stall. So the answer is
//! [`ApprovalPolicyRefusal::ApprovalUnreachable`]: refuse now, say why, and
//! write nothing that a later reader would have to reconcile.
//!
//! Reachability is **evidence, not configuration**. A configured Telegram bot
//! whose poller is not running is not a decision surface, and
//! [`OperatorSurfaces`] cannot be told otherwise: each of its constructors
//! names a thing that is live, and the peer constructor takes an
//! [`Admission`], which is obtainable only from [`PeerPolicy::evaluate`].
//!
//! [`PeerPolicy`]: crate::peer::PeerPolicy
//! [`PeerPolicy::evaluate`]: crate::peer::PeerPolicy::evaluate

use std::fmt;

use crate::peer::Admission;

/// How much ceremony one action needs, as a three-value total order.
///
/// The declaration order **is** the order: variants ascend from the loosest to
/// the strictest, so a derived [`Ord`] and [`ApprovalRequirement::rank`] agree
/// by construction rather than by two lists staying in step.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ApprovalRequirement {
    /// The action may proceed with no operator decision.
    Allowed,
    /// A live operator must decide before the action may proceed.
    ApprovalRequired,
    /// The action may not proceed, and no decision can change that.
    Forbidden,
}

impl ApprovalRequirement {
    /// Every requirement, loosest first.
    pub const ALL: [Self; 3] = [Self::Allowed, Self::ApprovalRequired, Self::Forbidden];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::ApprovalRequired => "approval_required",
            Self::Forbidden => "forbidden",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    ///
    /// Fail-closed on decode: an unrecognized spelling is refused rather than
    /// folded into the loosest neighbour.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|requirement| requirement.as_str() == value)
    }

    /// Position in the total order. Higher is stricter.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Allowed => 0,
            Self::ApprovalRequired => 1,
            Self::Forbidden => 2,
        }
    }

    /// The stricter of two requirements: the join of the total order.
    ///
    /// Commutative, associative and idempotent, and never looser than either
    /// input. Those four properties are what make
    /// [`ApprovalSources::compose`] order-independent and tighten-only.
    #[must_use]
    pub const fn tighten(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }

    /// The requirement a measured host imposes on its own.
    ///
    /// A host that cannot enforce the composed sandbox is already
    /// [`ApprovalRequirement::Forbidden`], and no approval reduces that: an
    /// operator cannot consent to an isolation the kernel will not apply. A
    /// host that can enforce it imposes nothing of its own and leaves the
    /// requirement to the other two sources.
    ///
    /// The argument is the daemon's *measurement*, never its configuration.
    #[must_use]
    pub const fn for_measured_host(sandbox_enforceable: bool) -> Self {
        if sandbox_enforceable {
            Self::Allowed
        } else {
            Self::Forbidden
        }
    }
}

impl fmt::Display for ApprovalRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The three independent requirement sources, before composition.
///
/// Named rather than positional so a caller cannot silently swap the host's
/// measurement for the configuration's claim, which is the one substitution
/// that would turn a measured refusal into a settable one.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ApprovalSources {
    config: ApprovalRequirement,
    host: ApprovalRequirement,
    per_call: ApprovalRequirement,
}

impl ApprovalSources {
    /// Record what each source asks for.
    #[must_use]
    pub const fn new(
        config: ApprovalRequirement,
        host: ApprovalRequirement,
        per_call: ApprovalRequirement,
    ) -> Self {
        Self {
            config,
            host,
            per_call,
        }
    }

    /// What the operator's durable configuration asks for.
    #[must_use]
    pub const fn config(self) -> ApprovalRequirement {
        self.config
    }

    /// What this host's own measurement imposes.
    #[must_use]
    pub const fn host(self) -> ApprovalRequirement {
        self.host
    }

    /// What this call asks for on top of the standing policy.
    #[must_use]
    pub const fn per_call(self) -> ApprovalRequirement {
        self.per_call
    }

    /// The strictest of the three.
    #[must_use]
    pub const fn compose(self) -> ApprovalRequirement {
        self.config.tighten(self.host).tighten(self.per_call)
    }
}

/// Which operator decision surfaces are **live** on this host.
///
/// Every constructor names a thing that is running, not a thing that is
/// configured, and there is no `Default` and no all-true constructor: a value
/// of this type is assembled from evidence a caller holds, one surface at a
/// time.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OperatorSurfaces {
    telegram_poller: bool,
    slack_approvals: bool,
    admitted_peer: bool,
}

impl OperatorSurfaces {
    /// No surface is live. The fail-closed starting point.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            telegram_poller: false,
            slack_approvals: false,
            admitted_peer: false,
        }
    }

    /// Record that a Telegram poller is running and delivering updates.
    ///
    /// A configured bot token is not this. The caller must hold a live poller.
    #[must_use]
    pub const fn with_telegram_poller(mut self) -> Self {
        self.telegram_poller = true;
        self
    }

    /// Record that Slack interactive decisions are enabled *and* the approvals
    /// capability is present.
    ///
    /// Both halves are required because a half-configured approval surface
    /// renders buttons nobody can act on.
    #[must_use]
    pub const fn with_slack_approvals(mut self) -> Self {
        self.slack_approvals = true;
        self
    }

    /// Record that an administrative peer is connected right now.
    ///
    /// Takes the [`Admission`] rather than a boolean, so this surface cannot be
    /// asserted by a caller that never admitted anybody: an `Admission` is
    /// obtainable only from [`PeerPolicy::evaluate`].
    ///
    /// [`PeerPolicy::evaluate`]: crate::peer::PeerPolicy::evaluate
    #[must_use]
    pub const fn with_admitted_peer(mut self, admission: Admission) -> Self {
        let _ = admission;
        self.admitted_peer = true;
        self
    }

    /// Whether a Telegram poller is live.
    #[must_use]
    pub const fn telegram_poller(self) -> bool {
        self.telegram_poller
    }

    /// Whether Slack can carry an approval decision.
    #[must_use]
    pub const fn slack_approvals(self) -> bool {
        self.slack_approvals
    }

    /// Whether an administrative peer is connected.
    #[must_use]
    pub const fn admitted_peer(self) -> bool {
        self.admitted_peer
    }

    /// Whether any surface could carry a decision back.
    #[must_use]
    pub const fn any_reachable(self) -> bool {
        self.telegram_poller || self.slack_approvals || self.admitted_peer
    }
}

/// What the durable approval lane already knows about this action.
///
/// Deliberately three-valued. "Nobody has decided" covers an absent proposal,
/// a pending one and one that expired without an answer, because all three
/// mean the same thing to this module: there is no decision to act on.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ApprovalEvidence {
    /// No decision is recorded.
    Undecided,
    /// A decision is recorded and it permits the action.
    Granted,
    /// A decision is recorded and it refuses the action.
    Denied,
}

impl ApprovalEvidence {
    /// Every evidence value, in canonical order.
    pub const ALL: [Self; 3] = [Self::Undecided, Self::Granted, Self::Denied];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Undecided => "undecided",
            Self::Granted => "granted",
            Self::Denied => "denied",
        }
    }
}

impl fmt::Display for ApprovalEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Why the composed policy refused.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ApprovalPolicyRefusal {
    /// Some source forbade the action outright. No decision changes this.
    Forbidden,
    /// An operator decided against it.
    ApprovalDenied,
    /// A decision is required and no live surface could carry one back.
    ApprovalUnreachable,
}

impl ApprovalPolicyRefusal {
    /// Every refusal, in canonical order.
    pub const ALL: [Self; 3] = [
        Self::Forbidden,
        Self::ApprovalDenied,
        Self::ApprovalUnreachable,
    ];

    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Forbidden => "forbidden",
            Self::ApprovalDenied => "approval_denied",
            Self::ApprovalUnreachable => "approval_unreachable",
        }
    }
}

impl fmt::Display for ApprovalPolicyRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.category())
    }
}

impl std::error::Error for ApprovalPolicyRefusal {}

/// What a caller holding a composed policy may do.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ApprovalGate {
    /// Start the action.
    Proceed,
    /// Do not start. Put the action in front of an operator and wait.
    Propose,
    /// Do not start, and do not ask.
    Refuse(ApprovalPolicyRefusal),
}

impl ApprovalGate {
    /// Whether this answer permits the action to start.
    #[must_use]
    pub const fn proceeds(self) -> bool {
        matches!(self, Self::Proceed)
    }
}

/// Decide what one action may do under composed policy and known evidence.
///
/// The order of the arms is the guarantee, and it is worth reading as one:
///
/// 1. [`ApprovalRequirement::Forbidden`] refuses before evidence is looked at,
///    so no decision can reach a forbidden action;
/// 2. [`ApprovalRequirement::Allowed`] proceeds before evidence is looked at,
///    so context binding never becomes a second admission gate for work that
///    never required approval;
/// 3. only [`ApprovalRequirement::ApprovalRequired`] consults evidence, and an
///    undecided action needs a live surface before it is worth proposing.
#[must_use]
pub const fn decide(
    sources: ApprovalSources,
    surfaces: OperatorSurfaces,
    evidence: ApprovalEvidence,
) -> ApprovalGate {
    match sources.compose() {
        ApprovalRequirement::Forbidden => ApprovalGate::Refuse(ApprovalPolicyRefusal::Forbidden),
        ApprovalRequirement::Allowed => ApprovalGate::Proceed,
        ApprovalRequirement::ApprovalRequired => match evidence {
            ApprovalEvidence::Granted => ApprovalGate::Proceed,
            ApprovalEvidence::Denied => ApprovalGate::Refuse(ApprovalPolicyRefusal::ApprovalDenied),
            ApprovalEvidence::Undecided => {
                if surfaces.any_reachable() {
                    ApprovalGate::Propose
                } else {
                    ApprovalGate::Refuse(ApprovalPolicyRefusal::ApprovalUnreachable)
                }
            }
        },
    }
}
