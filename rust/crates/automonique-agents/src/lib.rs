// SPDX-License-Identifier: Elastic-2.0

//! Observation-only provider planning and transcript normalization.
//!
//! This crate does not start or probe provider processes. It can inspect
//! executable metadata without execution, describe the exact intended argv,
//! and strictly normalize captured JSONL fixture bytes. Execution remains a
//! typed refusal until another component supplies unforgeable OS-enforcement
//! authority and a reviewed executable/configuration pin.

mod codex;
mod normalize;
mod types;

pub use codex::{CodexAdapter, CodexInvocationPlan, ExecutableInspection, normalize_jsonl};
pub use types::{
    AdapterEnvironment, AdapterError, CancellationToken, CoordinateError, ExecutionMode,
    MAX_ENV_VALUE_BYTES, MAX_PROMPT_BYTES, NormalizedEvent, NormalizedTranscript,
    ProviderDisposition, RecordedEvent, RecordedKind, ResumeBinding, RunCoordinates, RunRequest,
    SessionScope, StreamAuthority,
};
