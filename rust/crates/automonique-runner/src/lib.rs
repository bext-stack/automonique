// SPDX-License-Identifier: Elastic-2.0

//! Provider-neutral runner primitives.
//!
//! This crate deliberately has no provider or network client. Arbitrary
//! execution remains fail-closed until descendant-complete containment exists.
//! A separately named in-process simulation API records deterministic events
//! without presenting itself as provider execution or sandbox enforcement.

mod boundary;
mod runner;
mod simulation;
mod spec;
mod spool;

pub use boundary::{
    BoundaryProbeError, BoundaryRequirement, BoundaryStatus, BoundarySubject,
    ExecutionBoundaryAssessment, LaunchBlocker, LaunchRefusal, LinuxPrimitive,
};
pub use runner::{CancellationToken, ContainmentEvidence, Runner, RunnerError};
pub use simulation::{
    MAX_SIMULATION_ID_BYTES, MAX_SIMULATION_RESULT_BYTES, MAX_SIMULATION_STEP_BYTES,
    MAX_SIMULATION_STEPS, MAX_TOTAL_SIMULATION_BYTES, SimulationError, SimulationOutcome,
    SimulationReceipt, SimulationResult, SimulationRunner, SimulationSpec, SimulationSpecError,
    SimulationSpecParts, SimulationStep,
};
pub use spec::{
    MAX_ARG_BYTES, MAX_ARG_COUNT, MAX_ENV_COUNT, MAX_FIELD_BYTES, MAX_PROMPT_BYTES,
    MAX_TOTAL_ARG_BYTES, PromptDelivery, RunSpec, RunSpecError, RunSpecParts,
};
pub use spool::{Authority, Event, EventKind, RunState, Spool, SpoolError, Status};
