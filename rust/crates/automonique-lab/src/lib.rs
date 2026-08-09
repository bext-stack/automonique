// SPDX-License-Identifier: Elastic-2.0

//! Proposal-only development harness primitives.

pub mod canonical_json;
pub mod framing;
pub mod protocol;
pub mod state;
pub mod workspace_lease;

#[cfg(test)]
mod state_tests;
