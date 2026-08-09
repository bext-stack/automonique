// SPDX-License-Identifier: Elastic-2.0

//! Recovery entry point for interrupted proposal-only Git operations.

use crate::git::{CandidateId, CandidateOutcome, GitBroker, GitError, LeaseProof};

pub struct CandidateRecovery<'a> {
    broker: &'a GitBroker,
}

impl<'a> CandidateRecovery<'a> {
    pub const fn new(broker: &'a GitBroker) -> Self {
        Self { broker }
    }

    /// Reconcile a durable intent against its exact proposal ref and receipt.
    ///
    /// No local branch, remote, tag, worktree, stash, or checkout is changed.
    pub fn reconcile(
        &self,
        candidate_id: &CandidateId,
        lease_proof: &LeaseProof,
    ) -> Result<CandidateOutcome, GitError> {
        self.broker.reconcile(candidate_id, lease_proof)
    }
}
