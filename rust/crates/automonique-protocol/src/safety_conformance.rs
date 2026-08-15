// SPDX-License-Identifier: Elastic-2.0

//! The four legacy safety properties, as suites rather than as prose.
//!
//! `docs/product-plan/reference/feature-parity.md` reclassified nineteen rows
//! `replace` on 2026-08-09 because no fixture pinned them. Four of the nineteen
//! are safety properties, and the ledger says in as many words that they must be
//! **re-specified deliberately** rather than inferred from an implementation
//! nobody is allowed to read. This module is that re-specification's executable
//! half: one small trait per property, one generic suite over that trait, and
//! one in-memory reference implementation the suite passes today.
//!
//! | Property | Suite | Requirement document |
//! |---|---|---|
//! | fail-closed deploy route | [`deploy_route`] | `requirements/deploy-notifications.md` |
//! | announce target before mutation | [`mutation_announcement`] | `requirements/mutation-announcement.md` |
//! | separately-authorized deletion | [`deletion_authority`] | `requirements/deletion-authority.md` |
//! | scheduler core | `automonique_core::scheduler_conformance` | `requirements/scheduler-core.md` |
//!
//! The fourth suite lives in `automonique-core` rather than here, because the
//! property it judges is about that crate's lease substrate and reuses its
//! `SchedulerFence`. Restating a fence vocabulary here would create the second
//! authority [`crate::connector_conformance`] spends its header warning about.
//! [`SafetyProperty`] still names all four, so the roster is one list.
//!
//! # What a suite is for
//!
//! A suite is not a test of the reference model. It is the gate a real
//! implementation will be held to, written before that implementation exists so
//! it cannot be written to match it. Each suite therefore returns a
//! [`SafetyViolation`] rather than panicking: a caller can run it against a
//! candidate, get a machine-readable case name back, and record the verdict.
//! The reference model exists to prove the suite is satisfiable at all — a gate
//! nothing can pass is indistinguishable from a gate nothing has tried.
//!
//! Every suite's negative cases matter more than its positive one. The positive
//! case says the happy path works, which an implementation will get right by
//! accident. The negative cases say what must happen when the world is broken:
//! an unreachable deploy route refuses and never falls back to ticket intake, an
//! unannounced mutation is refused, an ordinary credential's delete verb
//! refuses. Those are the behaviours that were never written down.
//!
//! # Honest present
//!
//! No suite in this module is bound to a daemon. Nothing here opens a socket,
//! holds a credential, or observes a real deployment, and passing a suite is not
//! evidence that the product has the property — it is evidence that a specific
//! implementation of a specific trait has it. [`PENDING_BINDINGS`] names the
//! surface each property is still waiting for and where that work is tracked, so
//! the gap is data in the build rather than a sentence in a document.
//!
//! # Owner confirmation
//!
//! `docs/product-plan/launch-roadmap.md` calls these "four decisions that cannot
//! be inferred", which makes their exact semantics an owner's to confirm. They
//! are drafted here rather than deferred, because a property with no spec cannot
//! be reviewed and an unreviewed property ships by accident. Each requirement
//! document states which of its constants an owner is expected to confirm or
//! change; changing one means changing a constant and re-running a suite, not
//! rewriting it.

pub mod deletion_authority;
pub mod deploy_route;
pub mod mutation_announcement;

use core::fmt;
use std::error::Error;

/// Stable schema identifier for a rendered safety-conformance verdict.
pub const SAFETY_CONFORMANCE_SCHEMA_V1: &str = "automonique.safety-conformance/v1";

/// One of the four safety properties the parity ledger left unpinned.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SafetyProperty {
    /// Deployment notices reach a dedicated route or refuse; never intake.
    DeployRoute,
    /// Every externally visible mutation is announced, by exact target, first.
    MutationAnnouncement,
    /// Deletion is a distinct approval class under a separately held credential.
    DeletionAuthority,
    /// Bounded parallelism, per-scope serialization, pause and cancel.
    SchedulerCore,
}

impl SafetyProperty {
    /// Every property, in the order the parity ledger lists them.
    pub const ALL: [Self; 4] = [
        Self::DeployRoute,
        Self::MutationAnnouncement,
        Self::DeletionAuthority,
        Self::SchedulerCore,
    ];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeployRoute => "deploy_route",
            Self::MutationAnnouncement => "mutation_announcement",
            Self::DeletionAuthority => "deletion_authority",
            Self::SchedulerCore => "scheduler_core",
        }
    }

    /// Repository-relative path of the requirement document that owns this
    /// property's semantics.
    #[must_use]
    pub const fn requirement_path(self) -> &'static str {
        match self {
            Self::DeployRoute => "docs/product-plan/requirements/deploy-notifications.md",
            Self::MutationAnnouncement => "docs/product-plan/requirements/mutation-announcement.md",
            Self::DeletionAuthority => "docs/product-plan/requirements/deletion-authority.md",
            Self::SchedulerCore => "docs/product-plan/requirements/scheduler-core.md",
        }
    }

    /// Resolve a wire spelling.
    #[must_use]
    pub fn from_spelling(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == name)
    }
}

impl fmt::Display for SafetyProperty {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A surface one of these properties still has to be bound to.
///
/// A suite passing against a reference model proves the property is
/// well-specified and satisfiable. It does not prove any shipped code has it.
/// This is the difference, named rather than left for a reader to infer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingBinding {
    /// The property whose suite is not yet bound to a real implementation.
    pub property: SafetyProperty,
    /// The surface that has to implement the property's trait.
    pub surface: &'static str,
    /// Where the binding work is tracked.
    pub tracked_at: &'static str,
}

/// Every property's outstanding binding, so the gap is checkable data.
///
/// The three chat-surface properties are built by the launch roadmap's
/// Increment 4 (`docs/product-plan/launch-roadmap.md` § Increment 4), which is
/// the first increment that sends anything outbound; the scheduler is
/// `docs/improvement-plan/implementation/M8-scheduler-reload-isolation.md`
/// issue #45, whose spec is `requirements/scheduler-core.md` — the same document
/// this module's fourth suite judges.
pub const PENDING_BINDINGS: [PendingBinding; 4] = [
    PendingBinding {
        property: SafetyProperty::DeployRoute,
        surface: "the typed deploy outbox in automonique-daemon",
        tracked_at: "docs/product-plan/launch-roadmap.md § Increment 4",
    },
    PendingBinding {
        property: SafetyProperty::MutationAnnouncement,
        surface: "the work-event announcer in automonique-daemon",
        tracked_at: "docs/product-plan/launch-roadmap.md § Increment 4",
    },
    PendingBinding {
        property: SafetyProperty::DeletionAuthority,
        surface: "the chat-surface delete verb in automonique-daemon",
        tracked_at: "docs/product-plan/launch-roadmap.md § Increment 4",
    },
    PendingBinding {
        property: SafetyProperty::SchedulerCore,
        surface: "the durable scheduler in automonique-core",
        tracked_at: "docs/improvement-plan/implementation/M8-scheduler-reload-isolation.md #45",
    },
];

/// A candidate failed one named case of one property's suite.
///
/// The case name is stable and machine-readable; the detail is for a human
/// reading a failure report and is never parsed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafetyViolation {
    property: SafetyProperty,
    case: &'static str,
    detail: String,
}

impl SafetyViolation {
    /// Record a failure of one named case.
    #[must_use]
    pub fn new(property: SafetyProperty, case: &'static str, detail: impl Into<String>) -> Self {
        Self {
            property,
            case,
            detail: detail.into(),
        }
    }

    /// The property whose suite refused the candidate.
    #[must_use]
    pub const fn property(&self) -> SafetyProperty {
        self.property
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

impl fmt::Display for SafetyViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: case {} failed: {}",
            self.property, self.case, self.detail
        )
    }
}

impl Error for SafetyViolation {}

/// What one suite run covered.
///
/// A suite reports the cases it ran rather than only that it finished, so a
/// suite that stopped exercising something is a changed report rather than a
/// silent pass. Callers pin the list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafetyReport {
    property: SafetyProperty,
    cases: Vec<&'static str>,
}

impl SafetyReport {
    /// Record a completed run over `cases`.
    #[must_use]
    pub fn new(property: SafetyProperty, cases: Vec<&'static str>) -> Self {
        Self { property, cases }
    }

    /// The property this run judged.
    #[must_use]
    pub const fn property(&self) -> SafetyProperty {
        self.property
    }

    /// Every case that ran, in execution order.
    #[must_use]
    pub fn cases(&self) -> &[&'static str] {
        &self.cases
    }
}

/// Accumulates case names as a suite runs, so a report cannot claim a case the
/// suite never reached.
#[derive(Debug)]
pub(crate) struct CaseLog {
    property: SafetyProperty,
    cases: Vec<&'static str>,
}

impl CaseLog {
    pub(crate) const fn new(property: SafetyProperty) -> Self {
        Self {
            property,
            cases: Vec::new(),
        }
    }

    /// Record that `case` passed.
    pub(crate) fn passed(&mut self, case: &'static str) {
        self.cases.push(case);
    }

    /// Record that `case` failed, and stop the run.
    pub(crate) fn failed(&self, case: &'static str, detail: impl Into<String>) -> SafetyViolation {
        SafetyViolation::new(self.property, case, detail)
    }

    /// Fail `case` unless `condition` holds.
    pub(crate) fn require(
        &self,
        case: &'static str,
        condition: bool,
        detail: impl Into<String>,
    ) -> Result<(), SafetyViolation> {
        if condition {
            Ok(())
        } else {
            Err(self.failed(case, detail))
        }
    }

    pub(crate) fn finish(self) -> SafetyReport {
        SafetyReport::new(self.property, self.cases)
    }
}
