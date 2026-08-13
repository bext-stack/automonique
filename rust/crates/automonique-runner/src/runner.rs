// SPDX-License-Identifier: Elastic-2.0

use crate::{BoundaryRequirement, RunContainment, RunSpec, SpoolError};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Cross-thread cancellation signal retained for the future enforced runner.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Honest classification of a runner's process containment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainmentEvidence {
    /// A process group is insufficient because descendants can leave it.
    ProcessGroupOnly,
    /// Kernel cgroup v2 membership with an atomic descendant kill. Membership
    /// is inherited across `fork` and is unaffected by `setsid`/`setpgid`, so
    /// no descendant can place itself outside the boundary.
    CgroupV2Descendant,
}

impl ContainmentEvidence {
    /// Whether this evidence covers every descendant of the launched process.
    #[must_use]
    pub const fn is_descendant_complete(self) -> bool {
        match self {
            Self::ProcessGroupOnly => false,
            Self::CgroupV2Descendant => true,
        }
    }
}

/// Why public execution is unavailable in this slice.
#[derive(Debug)]
pub enum RunnerError {
    Spool(SpoolError),
    /// No descendant-complete kernel containment evidence exists.
    ContainmentUnenforced(ContainmentEvidence),
    /// Containment is enforced, but launching a provider still requires the
    /// listed boundary requirements, and none of them is installed yet.
    BoundaryUnenforced(Vec<BoundaryRequirement>),
}

impl fmt::Display for RunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spool(error) => write!(formatter, "{error}"),
            Self::ContainmentUnenforced(evidence) => {
                write!(
                    formatter,
                    "runner execution refused: {evidence:?} is not descendant-complete containment"
                )
            }
            Self::BoundaryUnenforced(requirements) => {
                let names = requirements
                    .iter()
                    .map(|requirement| requirement.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(
                    formatter,
                    "runner execution refused: containment is enforced but {names} remain unenforced"
                )
            }
        }
    }
}

impl std::error::Error for RunnerError {}

impl From<SpoolError> for RunnerError {
    fn from(value: SpoolError) -> Self {
        Self::Spool(value)
    }
}

/// Provider-neutral runner gate.
///
/// Wave 1 intentionally cannot launch an arbitrary executable. Process-group
/// cleanup is not descendant-complete because a workload may call `setsid` or
/// `setpgid`. A later slice may add execution only alongside a verified cgroup
/// or equivalent kernel boundary that the workload cannot escape.
#[derive(Clone, Copy, Debug, Default)]
pub struct Runner;

impl Runner {
    /// Requirements that remain unenforced even once containment is installed.
    ///
    /// [`BoundaryRequirement::DescendantCompleteContainment`] and
    /// [`BoundaryRequirement::CompleteCleanup`] are absent because a
    /// [`RunContainment`] establishes both: cgroup membership covers every
    /// descendant, and disposal kills the tree and removes the cgroup.
    pub const REMAINING_REQUIREMENTS: [BoundaryRequirement; 3] = [
        BoundaryRequirement::DescriptorClosure,
        BoundaryRequirement::FilesystemIsolation,
        BoundaryRequirement::NetworkDenial,
    ];

    /// Refuse execution: a bare runner has installed no containment.
    ///
    /// A process group is not a boundary, so this refusal does not depend on
    /// what the host kernel happens to offer.
    pub fn run(
        &self,
        _spec: RunSpec,
        _cancellation: &CancellationToken,
    ) -> Result<(), RunnerError> {
        Err(RunnerError::ContainmentUnenforced(
            ContainmentEvidence::ProcessGroupOnly,
        ))
    }

    /// Containment evidence held by a runner given `containment`.
    ///
    /// Taking a live [`RunContainment`] means the evidence describes an
    /// installed boundary rather than an observed kernel interface.
    #[must_use]
    pub const fn containment_evidence(_containment: &RunContainment) -> ContainmentEvidence {
        ContainmentEvidence::CgroupV2Descendant
    }

    /// Refuse execution with the exact requirements that remain unenforced
    /// once descendant-complete containment is installed.
    ///
    /// This is still a refusal. Containment alone does not make an arbitrary
    /// provider launch safe: the workload would keep every inherited
    /// descriptor, see the whole filesystem, and reach the network. It reports
    /// a narrower and truthful reason than [`Self::run`] so that the remaining
    /// work is visible rather than hidden behind a containment claim that is
    /// no longer the blocker.
    pub fn run_contained(
        &self,
        _spec: RunSpec,
        _cancellation: &CancellationToken,
        containment: &RunContainment,
    ) -> Result<(), RunnerError> {
        debug_assert!(Self::containment_evidence(containment).is_descendant_complete());
        Err(RunnerError::BoundaryUnenforced(
            Self::REMAINING_REQUIREMENTS.to_vec(),
        ))
    }
}
