// SPDX-License-Identifier: Elastic-2.0

//! Proposal-only development harness primitives.

pub mod build;
pub mod canonical_json;
pub mod controller;
pub mod framing;
pub mod git;
pub mod protocol;
pub mod recovery;
pub mod server;
pub mod state;
pub mod workspace_lease;

#[cfg(test)]
mod git_tests;
#[cfg(test)]
mod state_tests;
