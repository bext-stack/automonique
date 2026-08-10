// SPDX-License-Identifier: Elastic-2.0

//! Proposal-only development harness primitives.

pub mod build;
pub mod canonical_json;
pub mod controller;
pub mod framing;
pub mod git;
pub mod harness_claim;
pub mod harness_status;
pub mod program;
pub mod protocol;
pub mod provider;
pub mod recovery;
pub mod server;
pub mod state;
pub mod workspace_lease;
pub mod worktree;

#[cfg(test)]
mod git_tests;
#[cfg(test)]
mod state_tests;
