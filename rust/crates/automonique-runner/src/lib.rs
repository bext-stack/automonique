// SPDX-License-Identifier: Elastic-2.0

//! Provider-neutral execution-host primitives.
//!
//! This crate deliberately has no provider or network client. It validates a
//! bounded execution request, delivers prompt bytes through standard input,
//! owns a process group, and records a resumable local event spool.

mod runner;
mod spec;
mod spool;

pub use runner::{CancellationToken, ContainmentEvidence, Runner, RunnerError};
pub use spec::{
    MAX_ARG_BYTES, MAX_ARG_COUNT, MAX_ENV_COUNT, MAX_FIELD_BYTES, MAX_PROMPT_BYTES,
    MAX_TOTAL_ARG_BYTES, PromptDelivery, RunSpec, RunSpecError, RunSpecParts,
};
pub use spool::{Authority, Event, EventKind, RunState, Spool, SpoolError, Status};
