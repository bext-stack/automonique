// SPDX-License-Identifier: Elastic-2.0

//! Provider launch planning and provider output normalization.
//!
//! This crate prepares provider process launches and interprets provider
//! bytes. It does neither of the two things that would make it a provider
//! client: it never starts a process, and it never speaks to a provider
//! service. Concretely, it can
//!
//! - inspect executable metadata without executing it ([`ExecutableInspection`]);
//! - describe the exact intended argv ([`CodexInvocationPlan`]);
//! - build the exact sandboxed [`automonique_runner::LaunchPlan`] a provider
//!   process would run under ([`spawn_plan`]);
//! - normalize captured provider output, whole ([`normalize_jsonl`]) or
//!   incrementally as it arrives ([`ProviderEventStream`]).
//!
//! # Where execution authority lives
//!
//! Not here. A [`ProviderLaunchPlan`] is data: it grants nothing, enforces
//! nothing, and starts nothing. Only the runner's backend can launch it, and
//! only inside a delegated containment domain with the entry helper that
//! installs the plan's Landlock and seccomp policies. [`CodexAdapter`]
//! therefore still refuses every call — this crate's ability to *plan* a launch
//! deliberately did not become an ability to *perform* one.
//!
//! The remaining half is release trust, and it is unbuilt. [`spawn_plan`]
//! verifies that an executable's bytes match a caller-supplied digest and the
//! runner executes a sealed descriptor containing those verified bytes. This
//! still says nothing about whether that digest is the legitimate one; closing
//! that needs the reviewed release manifest described in [`spawn_plan`].

mod codex;
mod normalize;
pub mod spawn_plan;
mod stream;
mod types;

pub use codex::{CodexAdapter, CodexInvocationPlan, ExecutableInspection, normalize_jsonl};
pub use spawn_plan::{
    MAX_LOADER_GRANTS, PromptDelivery, ProviderExecutable, ProviderKind, ProviderLaunchPlan,
    ProviderNetwork, ProviderSpawnRequest, SHA256_HEX_BYTES, SpawnPlanError,
};
pub use stream::{MAX_STREAM_EVENTS, ProviderEventStream, StreamPolicy};
pub use types::{
    AdapterEnvironment, AdapterError, CancellationToken, CoordinateError, ExecutionMode,
    MAX_ENV_VALUE_BYTES, MAX_EVENT_KIND_BYTES, MAX_JSONL_LINE_BYTES, MAX_JSONL_TOTAL_BYTES,
    MAX_PROMPT_BYTES, NormalizedEvent, NormalizedTranscript, ProviderDisposition, ProviderItemKind,
    ProviderUsage, RecordedEvent, RecordedKind, ResumeBinding, RunCoordinates, RunRequest,
    SessionScope, StreamAuthority, UnknownEventKind,
};
