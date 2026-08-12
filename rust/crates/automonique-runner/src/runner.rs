// SPDX-License-Identifier: Elastic-2.0

use crate::{RunSpec, SpoolError};
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

/// Honest classification of this slice's process containment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainmentEvidence {
    /// A process group is insufficient because descendants can leave it.
    ProcessGroupOnly,
}

/// Why public execution is unavailable in this slice.
#[derive(Debug)]
pub enum RunnerError {
    Spool(SpoolError),
    /// No descendant-complete kernel containment evidence exists.
    ContainmentUnenforced(ContainmentEvidence),
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
    /// Refuse execution until descendant-complete containment is enforced.
    pub fn run(
        &self,
        _spec: RunSpec,
        _cancellation: &CancellationToken,
    ) -> Result<(), RunnerError> {
        Err(RunnerError::ContainmentUnenforced(
            ContainmentEvidence::ProcessGroupOnly,
        ))
    }
}
