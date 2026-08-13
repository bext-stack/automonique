// SPDX-License-Identifier: Elastic-2.0

//! Provider-neutral runner primitives.
//!
//! This crate deliberately has no provider or network client. Arbitrary
//! execution remains fail-closed until descendant-complete containment exists.
//! A separately named in-process simulation API records deterministic events
//! without presenting itself as provider execution or sandbox enforcement.

mod boundary;
pub mod capability;
mod containment;
pub mod descriptors;
pub mod filesystem;
mod landlock_abi;
mod launch;
pub mod network;
mod runner;
mod simulation;
mod spec;
mod spec_decode;
mod spec_encode;
mod spec_fields;
mod spool;

pub use boundary::{
    BoundaryProbeError, BoundaryRequirement, BoundaryStatus, BoundarySubject,
    ExecutionBoundaryAssessment, LaunchBlocker, LaunchRefusal, LinuxPrimitive,
    descriptor_closure_helper_main,
};
pub use containment::{
    CGROUP_DIR_ENV, ContainmentDomain, ContainmentError, ContainmentLimits, Controller,
    HELPER_REFUSED_EXIT, MAX_RUN_ID_BYTES, RunContainment, containment_entry_helper_main,
    domain_is_owned, process_is_live,
};
pub use launch::{
    FRAME_HEADER, FRAME_TERMINATOR, LaunchError, LaunchPlan, LaunchPlanError, MAX_FRAME_BYTES,
    MAX_LAUNCH_ARG_BYTES, MAX_LAUNCH_ARGS, launch_entry_helper_main, spawn_sandboxed,
};
pub use runner::{CancellationToken, ContainmentEvidence, Runner, RunnerError};
pub use simulation::{
    MAX_SIMULATION_ID_BYTES, MAX_SIMULATION_RESULT_BYTES, MAX_SIMULATION_STEP_BYTES,
    MAX_SIMULATION_STEPS, MAX_TOTAL_SIMULATION_BYTES, SimulationError, SimulationOutcome,
    SimulationReceipt, SimulationResult, SimulationRunner, SimulationSpec, SimulationSpecError,
    SimulationSpecParts, SimulationStep,
};
pub use spec::{
    BackendPromptSession, CwdToken, MAX_ARG_BYTES, MAX_ARG_COUNT, MAX_ENV_COUNT, MAX_FIELD_BYTES,
    MAX_PATH_BYTES, MAX_RUN_SPEC_BYTES, MAX_TOTAL_ARG_BYTES, MAX_TOTAL_ENV_BYTES,
    PromptDeliveryPlan, ProtectedPromptReference, RunCoordinates, RunSpec, RunSpecError,
    RunSpecParts, WorkspaceRegistryId,
};
pub use spec_decode::RunSpecDecodeError;
pub use spec_encode::{RunSpecDigest, RunSpecEncodeError};
pub use spec_fields::{
    AdmissionFields, AdmissionFieldsParts, ArtifactGrantBinding, ArtifactGrantBindings,
    ArtifactGrantDigest, ArtifactGrantId, CredentialBinding, ExecutionPlanDigest,
    ExtensionSetDigest, FallbackEligibility, IntegrationMode, IoReservation,
    MAX_ARTIFACT_GRANT_BINDINGS, MAX_FALLBACK_MODES, MAX_ORIGIN_CAUSES, MAX_RESERVATION_BYTES,
    ModelRoutingDigest, NonInteractiveOrigin, OriginCoordinate, PersonaDigest, PortabilityPolicy,
    ProfileDigest, RemoteAttestationPolicy, RequiredCapabilities, RunOrigin, RunOriginSource,
    RunnerEventDialect, SchedulerDecisionDigest, SchedulerReservationBinding,
    SchedulerReservationId, SkillsetDigest, ToolsetDigest, WorkspaceReservation,
};
pub use spool::{Authority, Event, EventKind, RunState, Spool, SpoolError, Status};
