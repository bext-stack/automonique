// SPDX-License-Identifier: Elastic-2.0

//! Runtime adapter from the conversational harness to the policy tool broker.
//!
//! The provider supplies a correlation call id, a granted tool name, and JSON
//! arguments. The transport supplies the trusted replay namespace. The replay
//! key is derived from that namespace plus the canonical tool/argument value;
//! changing only a model-generated call id therefore cannot execute an effect
//! twice after redelivery.

use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;

use sha2::{Digest as _, Sha256};

use automonique_protocol::tools::{ApprovalRequirement, SideEffectClass};

use crate::agent_harness::{
    AgentHarness, AgentProvider, ApprovalPause, CatalogError, HarnessFailure, HarnessLimits,
    HarnessOutcome, ProviderDecision, ProviderFailure, ProviderTurn, ToolApproval, ToolBroker,
    ToolBrokerFailure, ToolBrokerOutcome, ToolCall, ToolDefinition, ToolResultPayload,
    TranscriptInput, TranscriptRole,
};
use crate::agent_lane_journal::{
    AgentLaneJournal, AgentLaneJournalError, ApprovalPending, ProviderIntent, ProviderOutcome,
    RunCursor, RunIntent, RunRecovery, TerminalRecord, TerminalStatus, ToolIntent, ToolOutcome,
    TranscriptAppend, TranscriptKind,
};
use crate::agent_tool_broker::{
    AgentToolBroker, AgentToolExecutor, BrokerOutcome, GrantedToolCatalog, LocalToolDescriptor,
    ReplayPolicy, ToolDenial, ToolExecutionRequest, ToolInvocation,
};

const MAX_REPLAY_NAMESPACE_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentRuntimeError {
    InvalidReplayNamespace,
    InvalidCatalog,
}

/// One provider step admitted through the same harness and broker contracts as
/// a full multi-round agent turn.
///
/// Live transports use this while tool execution still belongs to their
/// existing continuation workers. A selected tool is therefore returned as a
/// typed, schema-checked call; no executor runs in this adapter. This is a
/// migration seam, not a second authority path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentRuntimeStep {
    Final(String),
    ToolCall(ToolCall),
}

/// Stable lane/run identity supplied by an authenticated transport adapter.
pub struct DurableAgentRunIdentity<'a> {
    pub lane_key: &'a str,
    pub run_key: &'a str,
    pub opened_ms: i64,
}

pub struct DurableAgentRunRequest<'a> {
    pub identity: DurableAgentRunIdentity<'a>,
    pub persona: &'a str,
    pub policy: &'a str,
    pub transcript: Vec<TranscriptInput>,
    pub limits: HarnessLimits,
}

/// Injected audit clock. Runtime persistence never reads ambient wall time.
pub trait AgentJournalClock {
    fn now_ms(&mut self) -> i64;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableAgentRunOutcome {
    Complete(String),
    AwaitingApproval(ApprovalPause),
    /// The run key already exists. No provider or tool is replayed
    /// automatically; the caller must reconcile this durable snapshot.
    Recovered(Box<RunRecovery>),
}

#[derive(Debug)]
pub enum DurableAgentRuntimeError {
    Journal(AgentLaneJournalError),
    Harness(HarnessFailure),
}

impl fmt::Display for DurableAgentRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => write!(formatter, "durable agent journal: {error}"),
            Self::Harness(error) => write!(formatter, "durable agent harness: {error}"),
        }
    }
}

impl std::error::Error for DurableAgentRuntimeError {}

impl From<AgentLaneJournalError> for DurableAgentRuntimeError {
    fn from(value: AgentLaneJournalError) -> Self {
        Self::Journal(value)
    }
}

/// Drive one fully brokered harness run with durable effect boundaries.
///
/// The run intent is committed before the catalog or provider is reached. A
/// provider wrapper records request/result boundaries, and a broker wrapper
/// records the exact downstream idempotency key before invoking a tool.
/// Duplicate run keys return recovery state without repeating either effect.
pub fn drive_durable_agent_run(
    journal: &mut AgentLaneJournal,
    request: DurableAgentRunRequest<'_>,
    provider: &mut dyn AgentProvider,
    runtime: &mut AgentRuntimeBroker<'_>,
    clock: &mut dyn AgentJournalClock,
) -> Result<DurableAgentRunOutcome, DurableAgentRuntimeError> {
    let mut harness = AgentHarness::new(
        request.persona,
        request.policy,
        request.transcript.clone(),
        request.limits,
    )
    .map_err(|_| {
        DurableAgentRuntimeError::Harness(HarnessFailure::Provider(ProviderFailure::Refused))
    })?;
    let run_intent = run_intent_value(
        request.persona,
        request.policy,
        &request.transcript,
        request.limits,
    );
    let receipt = journal.begin_run(RunIntent {
        lane_key: request.identity.lane_key,
        run_key: request.identity.run_key,
        intent: &run_intent,
        opened_ms: request.identity.opened_ms,
    })?;
    if receipt.duplicate {
        let recovery = journal
            .recover(request.identity.run_key)?
            .ok_or(AgentLaneJournalError::NotFound)?;
        return Ok(DurableAgentRunOutcome::Recovered(Box::new(recovery)));
    }

    let state = Rc::new(RefCell::new(DurableRunContext {
        journal,
        clock,
        cursor: receipt.cursor,
        failure: None,
    }));
    let mut durable_provider = JournaledProvider {
        inner: provider,
        state: Rc::clone(&state),
    };
    let mut durable_broker = JournaledRuntimeBroker {
        inner: runtime,
        state: Rc::clone(&state),
    };
    let outcome = harness.drive(&mut durable_provider, &mut durable_broker);
    drop(durable_provider);
    drop(durable_broker);

    let mut context = state.borrow_mut();
    if let Some(error) = context.failure.take() {
        return Err(DurableAgentRuntimeError::Journal(error));
    }
    match outcome {
        Ok(HarnessOutcome::Complete(answer)) => {
            context.append_transcript(
                TranscriptKind::Assistant,
                &serde_json::json!({"text": answer.as_str()}),
            )?;
            context.finish(
                TerminalStatus::Completed,
                &serde_json::json!({"answer": answer.as_str()}),
            )?;
            Ok(DurableAgentRunOutcome::Complete(answer.as_str().to_owned()))
        }
        Ok(HarnessOutcome::AwaitingApproval(pause)) => {
            Ok(DurableAgentRunOutcome::AwaitingApproval(pause))
        }
        Err(failure) => {
            context.finish(
                TerminalStatus::Failed,
                &serde_json::json!({"failure": harness_failure_code(&failure)}),
            )?;
            Err(DurableAgentRuntimeError::Harness(failure))
        }
    }
}

struct DurableRunContext<'a> {
    journal: &'a mut AgentLaneJournal,
    clock: &'a mut dyn AgentJournalClock,
    cursor: RunCursor,
    failure: Option<AgentLaneJournalError>,
}

impl DurableRunContext<'_> {
    fn now_ms(&mut self) -> i64 {
        self.clock.now_ms()
    }

    fn append_transcript(
        &mut self,
        kind: TranscriptKind,
        content: &serde_json::Value,
    ) -> Result<(), AgentLaneJournalError> {
        let now_ms = self.now_ms();
        self.cursor = self.journal.record_transcript(TranscriptAppend {
            cursor: &self.cursor,
            kind,
            content,
            recorded_ms: now_ms,
        })?;
        Ok(())
    }

    fn finish(
        &mut self,
        status: TerminalStatus,
        detail: &serde_json::Value,
    ) -> Result<(), AgentLaneJournalError> {
        let now_ms = self.now_ms();
        self.cursor = self.journal.finish(TerminalRecord {
            cursor: &self.cursor,
            status,
            detail,
            finished_ms: now_ms,
        })?;
        Ok(())
    }

    fn fail(&mut self, error: AgentLaneJournalError) {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
    }
}

struct JournaledProvider<'a, 'state> {
    inner: &'a mut dyn AgentProvider,
    state: Rc<RefCell<DurableRunContext<'state>>>,
}

impl AgentProvider for JournaledProvider<'_, '_> {
    fn decide(&mut self, turn: ProviderTurn<'_>) -> Result<ProviderDecision, ProviderFailure> {
        let round = u32::from(turn.round());
        let request = provider_turn_value(&turn);
        {
            let mut context = self.state.borrow_mut();
            let now_ms = context.now_ms();
            let cursor = context.cursor.clone();
            match context.journal.record_provider_intent(ProviderIntent {
                cursor: &cursor,
                round,
                request: &request,
                recorded_ms: now_ms,
            }) {
                Ok(cursor) => context.cursor = cursor,
                Err(error) => {
                    context.fail(error);
                    return Err(ProviderFailure::Unavailable);
                }
            }
        }

        let result = self.inner.decide(turn);
        let outcome = match &result {
            Ok(ProviderDecision::Final(answer)) => {
                serde_json::json!({"kind": "final", "answer": answer.as_str()})
            }
            Ok(ProviderDecision::ToolCall(call)) => serde_json::json!({
                "kind": "tool_call",
                "call_id": call.call_id(),
                "tool": call.tool(),
                "arguments": call.arguments()
            }),
            Err(failure) => serde_json::json!({
                "kind": "failure",
                "failure": provider_failure_code(*failure)
            }),
        };
        let mut context = self.state.borrow_mut();
        let now_ms = context.now_ms();
        let cursor = context.cursor.clone();
        match context.journal.record_provider_outcome(ProviderOutcome {
            cursor: &cursor,
            round,
            outcome: &outcome,
            recorded_ms: now_ms,
        }) {
            Ok(cursor) => context.cursor = cursor,
            Err(error) => {
                context.fail(error);
                return Err(ProviderFailure::Unavailable);
            }
        }
        result
    }
}

struct JournaledRuntimeBroker<'a, 'broker, 'state> {
    inner: &'a mut AgentRuntimeBroker<'broker>,
    state: Rc<RefCell<DurableRunContext<'state>>>,
}

impl ToolBroker for JournaledRuntimeBroker<'_, '_, '_> {
    fn catalog(&mut self) -> Result<Vec<ToolDefinition>, CatalogError> {
        self.inner.catalog()
    }

    fn invoke(&mut self, call: &ToolCall) -> Result<ToolBrokerOutcome, ToolBrokerFailure> {
        let idempotency_key = self.inner.planned_idempotency_key(call)?;
        {
            let mut context = self.state.borrow_mut();
            let now_ms = context.now_ms();
            let cursor = context.cursor.clone();
            match context.journal.record_tool_intent(ToolIntent {
                cursor: &cursor,
                call_id: call.call_id(),
                tool_name: call.tool(),
                idempotency_key: &idempotency_key,
                arguments: call.arguments(),
                recorded_ms: now_ms,
            }) {
                Ok(cursor) => context.cursor = cursor,
                Err(error) => {
                    context.fail(error);
                    return Err(ToolBrokerFailure::Failed);
                }
            }
        }

        let result = self.inner.invoke(call);
        let mut context = self.state.borrow_mut();
        let now_ms = context.now_ms();
        let cursor = context.cursor.clone();
        let journal_result = match &result {
            Ok(ToolBrokerOutcome::Complete(payload)) => {
                let outcome = serde_json::json!({
                    "kind": "complete",
                    "is_error": payload.is_error(),
                    "value": payload.value()
                });
                context.journal.record_tool_outcome(ToolOutcome {
                    cursor: &cursor,
                    call_id: call.call_id(),
                    outcome: &outcome,
                    recorded_ms: now_ms,
                })
            }
            Ok(ToolBrokerOutcome::ApprovalRequired(approval)) => {
                context.journal.request_approval(ApprovalPending {
                    cursor: &cursor,
                    approval_key: approval.key(),
                    call_id: call.call_id(),
                    summary: approval.summary(),
                    requested_ms: now_ms,
                })
            }
            Err(failure) => {
                let outcome = serde_json::json!({
                    "kind": "failure",
                    "failure": tool_failure_code(*failure)
                });
                context.journal.record_tool_outcome(ToolOutcome {
                    cursor: &cursor,
                    call_id: call.call_id(),
                    outcome: &outcome,
                    recorded_ms: now_ms,
                })
            }
        };
        match journal_result {
            Ok(cursor) => context.cursor = cursor,
            Err(error) => {
                context.fail(error);
                return Err(ToolBrokerFailure::Failed);
            }
        }
        result
    }
}

fn run_intent_value(
    persona: &str,
    policy: &str,
    transcript: &[TranscriptInput],
    limits: HarnessLimits,
) -> serde_json::Value {
    serde_json::json!({
        "persona": persona,
        "policy": policy,
        "transcript": transcript.iter().map(transcript_value).collect::<Vec<_>>(),
        "limits": {
            "max_rounds": limits.max_rounds(),
            "max_tool_calls": limits.max_tool_calls(),
            "max_calls_per_tool": limits.max_calls_per_tool(),
            "max_identical_calls": limits.max_identical_calls(),
            "max_tool_result_bytes": limits.max_tool_result_bytes()
        }
    })
}

fn provider_turn_value(turn: &ProviderTurn<'_>) -> serde_json::Value {
    serde_json::json!({
        "persona": turn.persona(),
        "policy": turn.policy(),
        "transcript": turn.transcript().iter().map(transcript_value).collect::<Vec<_>>(),
        "tools": turn.tools().iter().map(|tool| serde_json::json!({
            "id": tool.id(),
            "description": tool.description(),
            "input_schema": tool.input_schema()
        })).collect::<Vec<_>>(),
        "round": turn.round(),
        "remaining_tool_calls": turn.remaining_tool_calls()
    })
}

fn transcript_value(input: &TranscriptInput) -> serde_json::Value {
    match input {
        TranscriptInput::Message { role, text } => serde_json::json!({
            "kind": "message",
            "role": match role {
                TranscriptRole::User => "user",
                TranscriptRole::Assistant => "assistant",
            },
            "text": text
        }),
        TranscriptInput::ToolCall(call) => serde_json::json!({
            "kind": "tool_call",
            "call_id": call.call_id(),
            "tool": call.tool(),
            "arguments": call.arguments()
        }),
        TranscriptInput::ToolResult(result) => serde_json::json!({
            "kind": "tool_result",
            "call_id": result.call_id(),
            "tool": result.tool(),
            "is_error": result.payload().is_error(),
            "value": result.payload().value()
        }),
    }
}

const fn provider_failure_code(failure: ProviderFailure) -> &'static str {
    match failure {
        ProviderFailure::Unavailable => "unavailable",
        ProviderFailure::TimedOut => "timed_out",
        ProviderFailure::Refused => "refused",
        ProviderFailure::MalformedOutput => "malformed_output",
    }
}

const fn tool_failure_code(failure: ToolBrokerFailure) -> &'static str {
    match failure {
        ToolBrokerFailure::InvalidArguments => "invalid_arguments",
        ToolBrokerFailure::InvalidApproval => "invalid_approval",
        ToolBrokerFailure::Unauthorized => "unauthorized",
        ToolBrokerFailure::Unavailable => "unavailable",
        ToolBrokerFailure::TimedOut => "timed_out",
        ToolBrokerFailure::Failed => "failed",
    }
}

fn harness_failure_code(failure: &HarnessFailure) -> &'static str {
    match failure {
        HarnessFailure::Catalog(_) => "catalog",
        HarnessFailure::Provider(_) => "provider",
        HarnessFailure::Tool(_) => "tool",
        HarnessFailure::BudgetExceeded(_) => "budget_exceeded",
        HarnessFailure::UnknownTool => "unknown_tool",
        HarnessFailure::DuplicateCallId => "duplicate_call_id",
        HarnessFailure::ToolResultTooLarge { .. } => "tool_result_too_large",
        HarnessFailure::TranscriptFull => "transcript_full",
        HarnessFailure::ApprovalResultMismatch => "approval_result_mismatch",
        HarnessFailure::AlreadyCompleted => "already_completed",
        HarnessFailure::AlreadyFailed => "already_failed",
    }
}

/// Validate one raw provider response against a revision-pinned tool catalog.
///
/// The temporary broker marks every catalog entry as approval-bound so its
/// executor is unreachable. That lets [`AgentHarness`] apply its closed wire
/// decoder, catalog checks, argument schema validation and budgets before the
/// transport maps the call to its established read/effect custodian.
pub fn validate_provider_step(
    provider_bytes: &[u8],
    persona: &str,
    policy: &str,
    transcript: Vec<TranscriptInput>,
    definitions: &[ToolDefinition],
    replay_namespace: &str,
) -> Result<AgentRuntimeStep, HarnessFailure> {
    let mut local = AgentToolBroker::new(1);
    for definition in definitions {
        let descriptor = LocalToolDescriptor::new(
            definition.id(),
            definition.description(),
            definition.input_schema().clone(),
            SideEffectClass::ExternalEffect,
            ApprovalRequirement::PerInvocation,
            ReplayPolicy::AtMostOnce,
        )
        .map_err(|_| HarnessFailure::Catalog(CatalogError::InvalidTool))?;
        local
            .register(descriptor, Box::new(UnreachableExecutor))
            .map_err(|_| HarnessFailure::Catalog(CatalogError::DuplicateTool))?;
    }
    let names = definitions
        .iter()
        .map(ToolDefinition::id)
        .collect::<Vec<_>>();
    let granted = local
        .granted_catalog(&names)
        .map_err(|_| HarnessFailure::Catalog(CatalogError::InvalidTool))?;
    let mut broker = AgentRuntimeBroker::new(&mut local, granted, replay_namespace)
        .map_err(|_| HarnessFailure::Catalog(CatalogError::InvalidTool))?;
    let mut provider = OneStepProvider {
        bytes: Some(provider_bytes),
    };
    let mut harness =
        AgentHarness::new(persona, policy, transcript, HarnessLimits::conversational())
            .map_err(|_| HarnessFailure::Provider(ProviderFailure::Refused))?;
    match harness.drive(&mut provider, &mut broker)? {
        HarnessOutcome::Complete(answer) => Ok(AgentRuntimeStep::Final(answer.as_str().to_owned())),
        HarnessOutcome::AwaitingApproval(pause) => {
            Ok(AgentRuntimeStep::ToolCall(pause.call().clone()))
        }
    }
}

struct OneStepProvider<'a> {
    bytes: Option<&'a [u8]>,
}

impl AgentProvider for OneStepProvider<'_> {
    fn decide(&mut self, _turn: ProviderTurn<'_>) -> Result<ProviderDecision, ProviderFailure> {
        let bytes = self.bytes.take().ok_or(ProviderFailure::Refused)?;
        crate::agent_harness::decode_provider_decision(bytes)
    }
}

struct UnreachableExecutor;

impl AgentToolExecutor for UnreachableExecutor {
    fn execute(
        &mut self,
        _request: ToolExecutionRequest<'_>,
    ) -> Result<serde_json::Value, &'static str> {
        Err("approval-bound planner tool cannot execute in validation adapter")
    }
}

/// One revision-pinned granted catalog attached to the harness broker seam.
pub struct AgentRuntimeBroker<'a> {
    broker: &'a mut AgentToolBroker,
    granted: GrantedToolCatalog,
    definitions: Vec<ToolDefinition>,
    replay_namespace: String,
}

impl<'a> AgentRuntimeBroker<'a> {
    pub fn new(
        broker: &'a mut AgentToolBroker,
        granted: GrantedToolCatalog,
        replay_namespace: impl Into<String>,
    ) -> Result<Self, AgentRuntimeError> {
        let replay_namespace = replay_namespace.into();
        if !valid_replay_namespace(&replay_namespace) {
            return Err(AgentRuntimeError::InvalidReplayNamespace);
        }
        let definitions = granted
            .descriptors()
            .into_iter()
            .map(|descriptor| {
                ToolDefinition::new(
                    descriptor.name(),
                    descriptor.description(),
                    descriptor.input_schema().clone(),
                )
                .map_err(|_| AgentRuntimeError::InvalidCatalog)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            broker,
            granted,
            definitions,
            replay_namespace,
        })
    }

    #[must_use]
    pub const fn granted_catalog(&self) -> &GrantedToolCatalog {
        &self.granted
    }

    fn replay_key(&self, call: &ToolCall) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"automonique-agent-runtime-replay-v1\0");
        hasher.update(self.replay_namespace.as_bytes());
        hasher.update(b"\0");
        hasher.update(call.tool().as_bytes());
        hasher.update(b"\0");
        write_canonical_json(call.arguments(), &mut hasher);
        format!("ahr-{:x}", hasher.finalize())
    }

    fn invocation(&self, call: &ToolCall) -> Result<ToolInvocation, ToolBrokerFailure> {
        ToolInvocation::new(
            call.call_id(),
            &self.replay_key(call),
            call.tool(),
            call.arguments().clone(),
        )
        .map_err(|_| ToolBrokerFailure::InvalidArguments)
    }

    fn planned_idempotency_key(&self, call: &ToolCall) -> Result<String, ToolBrokerFailure> {
        let invocation = self.invocation(call)?;
        self.broker
            .planned_idempotency_key(&self.granted, &invocation)
            .map_err(map_denial)
    }
}

impl ToolBroker for AgentRuntimeBroker<'_> {
    fn catalog(&mut self) -> Result<Vec<ToolDefinition>, CatalogError> {
        Ok(self.definitions.clone())
    }

    fn invoke(&mut self, call: &ToolCall) -> Result<ToolBrokerOutcome, ToolBrokerFailure> {
        let invocation = self.invocation(call)?;
        match self.broker.invoke(&self.granted, invocation) {
            BrokerOutcome::Complete {
                tool_name, value, ..
            } => {
                // A confirmed replay legitimately carries the original
                // invocation id. The broker already matched the trusted replay
                // key and fingerprint; only the semantic tool binding must
                // still agree here.
                if tool_name != call.tool() {
                    return Err(ToolBrokerFailure::Failed);
                }
                Ok(ToolBrokerOutcome::Complete(ToolResultPayload::complete(
                    value,
                )))
            }
            BrokerOutcome::ApprovalRequired(frozen) => {
                // As above, a replay of a still-pending request retains the
                // original correlation id while this harness pause is bound to
                // the current provider call id.
                if frozen.tool_name() != call.tool() || frozen.arguments() != call.arguments() {
                    return Err(ToolBrokerFailure::Failed);
                }
                let approval = ToolApproval::new(
                    frozen.approval_key(),
                    format!("Approve the exact `{}` tool request", frozen.tool_name()),
                )?;
                Ok(ToolBrokerOutcome::ApprovalRequired(approval))
            }
            BrokerOutcome::Denied { reason, .. } => Err(map_denial(reason)),
        }
    }
}

fn map_denial(reason: ToolDenial) -> ToolBrokerFailure {
    match reason {
        ToolDenial::InvalidArguments => ToolBrokerFailure::InvalidArguments,
        ToolDenial::CatalogStale
        | ToolDenial::NotGranted
        | ToolDenial::ApprovalUnknown
        | ToolDenial::ApprovalDenied
        | ToolDenial::DescriptorChanged => ToolBrokerFailure::Unauthorized,
        ToolDenial::Unavailable => ToolBrokerFailure::Unavailable,
        ToolDenial::CallLimit
        | ToolDenial::InvocationConflict
        | ToolDenial::ReplayConflict
        | ToolDenial::ExecutionFailed => ToolBrokerFailure::Failed,
    }
}

fn valid_replay_namespace(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REPLAY_NAMESPACE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

/// Feed canonical JSON bytes directly into the replay digest.
fn write_canonical_json(value: &serde_json::Value, digest: &mut Sha256) {
    match value {
        serde_json::Value::Null => digest.update(b"null"),
        serde_json::Value::Bool(value) => {
            if *value {
                digest.update(b"true");
            } else {
                digest.update(b"false");
            }
        }
        serde_json::Value::Number(value) => digest.update(value.to_string().as_bytes()),
        serde_json::Value::String(value) => digest.update(
            serde_json::to_string(value)
                .expect("a Rust string always serializes as JSON")
                .as_bytes(),
        ),
        serde_json::Value::Array(values) => {
            digest.update(b"[");
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    digest.update(b",");
                }
                write_canonical_json(value, digest);
            }
            digest.update(b"]");
        }
        serde_json::Value::Object(values) => {
            digest.update(b"{");
            let mut fields: Vec<_> = values.iter().collect();
            fields.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (index, (key, value)) in fields.into_iter().enumerate() {
                if index != 0 {
                    digest.update(b",");
                }
                digest.update(
                    serde_json::to_string(key)
                        .expect("a Rust string always serializes as JSON")
                        .as_bytes(),
                );
                digest.update(b":");
                write_canonical_json(value, digest);
            }
            digest.update(b"}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use automonique_protocol::tools::{ApprovalRequirement, SideEffectClass};
    use serde_json::{Value, json};

    use super::*;
    use crate::agent_tool_broker::{
        AgentToolExecutor, LocalToolDescriptor, ReplayPolicy, ToolExecutionRequest,
    };

    struct StepClock(i64);

    impl AgentJournalClock for StepClock {
        fn now_ms(&mut self) -> i64 {
            self.0 = self.0.saturating_add(1);
            self.0
        }
    }

    struct InspectingProvider {
        journal_path: PathBuf,
        run_key: String,
        decisions: VecDeque<Result<ProviderDecision, ProviderFailure>>,
    }

    impl AgentProvider for InspectingProvider {
        fn decide(&mut self, turn: ProviderTurn<'_>) -> Result<ProviderDecision, ProviderFailure> {
            let journal = AgentLaneJournal::open(&self.journal_path).expect("open observer");
            let recovery = journal
                .recover(&self.run_key)
                .expect("recover before provider")
                .expect("run before provider");
            assert_eq!(
                recovery.pending_provider_round,
                Some(u32::from(turn.round()))
            );
            self.decisions
                .pop_front()
                .unwrap_or(Err(ProviderFailure::Refused))
        }
    }

    struct InspectingExecutor {
        journal_path: PathBuf,
        run_key: String,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl AgentToolExecutor for InspectingExecutor {
        fn execute(&mut self, request: ToolExecutionRequest<'_>) -> Result<Value, &'static str> {
            let journal = AgentLaneJournal::open(&self.journal_path).expect("open observer");
            let recovery = journal
                .recover(&self.run_key)
                .expect("recover before tool")
                .expect("run before tool");
            let pending = recovery.pending_tool.expect("tool intent before effect");
            assert_eq!(pending.idempotency_key, request.idempotency_key());
            self.calls
                .lock()
                .unwrap()
                .push(request.idempotency_key().to_owned());
            Ok(json!({"title": "Done yesterday"}))
        }
    }

    fn journal_fixture() -> (tempfile::TempDir, AgentLaneJournal, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root
            .path()
            .join(crate::agent_lane_journal::AGENT_LANE_JOURNAL_NAME);
        let journal = AgentLaneJournal::open(&path).unwrap();
        (root, journal, path)
    }

    struct FixtureExecutor {
        calls: Arc<Mutex<Vec<String>>>,
        value: Value,
    }

    impl AgentToolExecutor for FixtureExecutor {
        fn execute(&mut self, request: ToolExecutionRequest<'_>) -> Result<Value, &'static str> {
            self.calls
                .lock()
                .unwrap()
                .push(request.idempotency_key().to_owned());
            Ok(self.value.clone())
        }
    }

    fn schema() -> Value {
        json!({
            "type": "object",
            "properties": {"number": {"type": "integer"}},
            "required": ["number"],
            "additionalProperties": false
        })
    }

    fn registered_broker(
        side_effect: SideEffectClass,
        approval: ApprovalRequirement,
    ) -> (AgentToolBroker, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut broker = AgentToolBroker::new(8);
        broker
            .register(
                LocalToolDescriptor::new(
                    "tickets.read",
                    "Read one support ticket",
                    schema(),
                    side_effect,
                    approval,
                    if side_effect == SideEffectClass::ReadOnly {
                        ReplayPolicy::ReplaySafe
                    } else {
                        ReplayPolicy::AtMostOnce
                    },
                )
                .unwrap(),
                Box::new(FixtureExecutor {
                    calls: Arc::clone(&calls),
                    value: json!({"title":"Done yesterday"}),
                }),
            )
            .unwrap();
        (broker, calls)
    }

    fn transcript() -> Vec<TranscriptInput> {
        vec![
            TranscriptInput::message(
                crate::agent_harness::TranscriptRole::User,
                "show yesterday's tickets",
            )
            .unwrap(),
        ]
    }

    fn definition() -> ToolDefinition {
        ToolDefinition::new("tickets.read", "Read tickets", schema()).unwrap()
    }

    #[test]
    fn live_step_adapter_admits_final_answers_through_the_harness() {
        let step = validate_provider_step(
            br#"{"kind":"final","answer":"Three tickets were completed."}"#,
            "Monique",
            "Use tools for current facts.",
            transcript(),
            &[definition()],
            "telegram:turn-7",
        )
        .unwrap();
        assert_eq!(
            step,
            AgentRuntimeStep::Final(String::from("Three tickets were completed."))
        );
    }

    #[test]
    fn live_step_adapter_returns_a_schema_checked_tool_call_without_execution() {
        let step = validate_provider_step(
            br#"{"kind":"tool_call","call_id":"call-1","tool":"tickets.read","arguments":{"number":7}}"#,
            "Monique",
            "Use tools for current facts.",
            transcript(),
            &[definition()],
            "slack:turn-9",
        )
        .unwrap();
        assert!(matches!(
            step,
            AgentRuntimeStep::ToolCall(call)
                if call.tool() == "tickets.read" && call.arguments() == &json!({"number": 7})
        ));
    }

    #[test]
    fn live_step_adapter_fails_closed_on_unknown_tools_and_bad_arguments() {
        for bytes in [
            br#"{"kind":"tool_call","call_id":"call-1","tool":"shell.run","arguments":{"number":7}}"#.as_slice(),
            br#"{"kind":"tool_call","call_id":"call-1","tool":"tickets.read","arguments":{"number":"seven"}}"#.as_slice(),
        ] {
            assert!(validate_provider_step(
                bytes,
                "Monique",
                "Use tools for current facts.",
                transcript(),
                &[definition()],
                "telegram:turn-7",
            )
            .is_err());
        }
    }

    #[test]
    fn granted_read_result_crosses_the_harness_broker_seam() {
        let (mut broker, calls) =
            registered_broker(SideEffectClass::ReadOnly, ApprovalRequirement::None);
        let granted = broker.granted_catalog(&["tickets.read"]).unwrap();
        let mut runtime =
            AgentRuntimeBroker::new(&mut broker, granted, "telegram:chat-7:message-11").unwrap();
        let catalog = runtime.catalog().unwrap();
        assert_eq!(catalog.len(), 1);
        assert_eq!(catalog[0].id(), "tickets.read");

        let call = ToolCall::new("call-1", "tickets.read", json!({"number":7})).unwrap();
        let ToolBrokerOutcome::Complete(result) = runtime.invoke(&call).unwrap() else {
            panic!("read must complete without approval");
        };
        assert_eq!(result.value(), &json!({"title":"Done yesterday"}));
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn effect_is_returned_as_an_approval_pause_without_execution() {
        let (mut broker, calls) = registered_broker(
            SideEffectClass::ExternalEffect,
            ApprovalRequirement::PerInvocation,
        );
        let granted = broker.granted_catalog(&["tickets.read"]).unwrap();
        let mut runtime =
            AgentRuntimeBroker::new(&mut broker, granted, "slack:C1:thread:100.2").unwrap();
        let call = ToolCall::new("call-1", "tickets.read", json!({"number":7})).unwrap();

        let ToolBrokerOutcome::ApprovalRequired(approval) = runtime.invoke(&call).unwrap() else {
            panic!("effect must pause for approval");
        };
        assert!(approval.key().starts_with("atp-"));
        assert!(approval.summary().contains("tickets.read"));
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn replay_key_ignores_call_id_and_reuses_confirmed_read() {
        let (mut broker, calls) =
            registered_broker(SideEffectClass::ReadOnly, ApprovalRequirement::None);
        let granted = broker.granted_catalog(&["tickets.read"]).unwrap();
        let mut runtime =
            AgentRuntimeBroker::new(&mut broker, granted, "telegram:chat-7:message-11").unwrap();
        let first = ToolCall::new("call-1", "tickets.read", json!({"number":7})).unwrap();
        let replay = ToolCall::new("call-2", "tickets.read", json!({"number":7})).unwrap();

        assert!(matches!(
            runtime.invoke(&first),
            Ok(ToolBrokerOutcome::Complete(_))
        ));
        assert!(matches!(
            runtime.invoke(&replay),
            Ok(ToolBrokerOutcome::Complete(_))
        ));
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn durable_runtime_records_provider_boundary_and_terminal_answer() {
        let (_root, mut journal, path) = journal_fixture();
        let mut provider = InspectingProvider {
            journal_path: path,
            run_key: String::from("event-final"),
            decisions: vec![Ok(ProviderDecision::Final(
                crate::agent_harness::FinalAnswer::new("Three tickets were completed.").unwrap(),
            ))]
            .into(),
        };
        let (mut broker, calls) =
            registered_broker(SideEffectClass::ReadOnly, ApprovalRequirement::None);
        let granted = broker.granted_catalog(&["tickets.read"]).unwrap();
        let mut runtime =
            AgentRuntimeBroker::new(&mut broker, granted, "slack:event-final").unwrap();
        let mut clock = StepClock(100);

        let outcome = drive_durable_agent_run(
            &mut journal,
            DurableAgentRunRequest {
                identity: DurableAgentRunIdentity {
                    lane_key: "slack:thread-final",
                    run_key: "event-final",
                    opened_ms: 100,
                },
                persona: "Monique",
                policy: "Use tools for current facts.",
                transcript: transcript(),
                limits: HarnessLimits::conversational(),
            },
            &mut provider,
            &mut runtime,
            &mut clock,
        )
        .unwrap();

        assert_eq!(
            outcome,
            DurableAgentRunOutcome::Complete(String::from("Three tickets were completed."))
        );
        assert!(calls.lock().unwrap().is_empty());
        let recovery = journal.recover("event-final").unwrap().unwrap();
        assert_eq!(
            recovery.status,
            crate::agent_lane_journal::RunStatus::Completed
        );
        assert_eq!(recovery.pending_provider_round, None);
        assert_eq!(
            recovery
                .events
                .iter()
                .map(|event| event.kind.as_str())
                .collect::<Vec<_>>(),
            vec![
                "run_intent",
                "provider_intent",
                "provider_outcome",
                "transcript",
                "terminal"
            ]
        );
    }

    #[test]
    fn durable_runtime_persists_exact_tool_key_before_effect_and_never_auto_replays() {
        let (_root, mut journal, path) = journal_fixture();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut broker = AgentToolBroker::new(8);
        broker
            .register(
                LocalToolDescriptor::new(
                    "tickets.read",
                    "Read one support ticket",
                    schema(),
                    SideEffectClass::ReadOnly,
                    ApprovalRequirement::None,
                    ReplayPolicy::ReplaySafe,
                )
                .unwrap(),
                Box::new(InspectingExecutor {
                    journal_path: path.clone(),
                    run_key: String::from("event-tools"),
                    calls: Arc::clone(&calls),
                }),
            )
            .unwrap();
        let granted = broker.granted_catalog(&["tickets.read"]).unwrap();
        let mut runtime =
            AgentRuntimeBroker::new(&mut broker, granted, "slack:event-tools").unwrap();
        let mut provider = InspectingProvider {
            journal_path: path,
            run_key: String::from("event-tools"),
            decisions: vec![
                Ok(ProviderDecision::ToolCall(
                    ToolCall::new("call-1", "tickets.read", json!({"number": 7})).unwrap(),
                )),
                Ok(ProviderDecision::Final(
                    crate::agent_harness::FinalAnswer::new("Ticket 7 was completed.").unwrap(),
                )),
            ]
            .into(),
        };
        let mut clock = StepClock(200);

        let outcome = drive_durable_agent_run(
            &mut journal,
            DurableAgentRunRequest {
                identity: DurableAgentRunIdentity {
                    lane_key: "slack:thread-tools",
                    run_key: "event-tools",
                    opened_ms: 200,
                },
                persona: "Monique",
                policy: "Use tools for current facts.",
                transcript: transcript(),
                limits: HarnessLimits::conversational(),
            },
            &mut provider,
            &mut runtime,
            &mut clock,
        )
        .unwrap();
        assert!(matches!(outcome, DurableAgentRunOutcome::Complete(_)));
        assert_eq!(calls.lock().unwrap().len(), 1);

        let recovery = journal.recover("event-tools").unwrap().unwrap();
        let tool_intent = recovery
            .events
            .iter()
            .find(|event| event.kind == "tool_intent")
            .unwrap();
        assert_eq!(
            tool_intent.payload["idempotency_key"],
            calls.lock().unwrap()[0]
        );
        let intent_sequence = tool_intent.sequence;
        let outcome_sequence = recovery
            .events
            .iter()
            .find(|event| event.kind == "tool_outcome")
            .unwrap()
            .sequence;
        assert!(intent_sequence < outcome_sequence);

        let mut provider_must_not_run = InspectingProvider {
            journal_path: journal.path().to_path_buf(),
            run_key: String::from("event-tools"),
            decisions: vec![Err(ProviderFailure::Refused)].into(),
        };
        let duplicate = drive_durable_agent_run(
            &mut journal,
            DurableAgentRunRequest {
                identity: DurableAgentRunIdentity {
                    lane_key: "slack:thread-tools",
                    run_key: "event-tools",
                    opened_ms: 200,
                },
                persona: "Monique",
                policy: "Use tools for current facts.",
                transcript: transcript(),
                limits: HarnessLimits::conversational(),
            },
            &mut provider_must_not_run,
            &mut runtime,
            &mut clock,
        )
        .unwrap();
        assert!(matches!(duplicate, DurableAgentRunOutcome::Recovered(_)));
        assert_eq!(provider_must_not_run.decisions.len(), 1);
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn durable_runtime_keeps_approval_and_tool_intent_recoverable() {
        let (_root, mut journal, path) = journal_fixture();
        let mut provider = InspectingProvider {
            journal_path: path,
            run_key: String::from("event-approval"),
            decisions: vec![Ok(ProviderDecision::ToolCall(
                ToolCall::new("call-approve", "tickets.read", json!({"number": 7})).unwrap(),
            ))]
            .into(),
        };
        let (mut broker, calls) = registered_broker(
            SideEffectClass::ExternalEffect,
            ApprovalRequirement::PerInvocation,
        );
        let granted = broker.granted_catalog(&["tickets.read"]).unwrap();
        let mut runtime =
            AgentRuntimeBroker::new(&mut broker, granted, "slack:event-approval").unwrap();
        let mut clock = StepClock(300);

        let outcome = drive_durable_agent_run(
            &mut journal,
            DurableAgentRunRequest {
                identity: DurableAgentRunIdentity {
                    lane_key: "slack:thread-approval",
                    run_key: "event-approval",
                    opened_ms: 300,
                },
                persona: "Monique",
                policy: "Ask for approval before effects.",
                transcript: transcript(),
                limits: HarnessLimits::conversational(),
            },
            &mut provider,
            &mut runtime,
            &mut clock,
        )
        .unwrap();
        assert!(matches!(
            outcome,
            DurableAgentRunOutcome::AwaitingApproval(_)
        ));
        assert!(calls.lock().unwrap().is_empty());
        let recovery = journal.recover("event-approval").unwrap().unwrap();
        assert_eq!(
            recovery.status,
            crate::agent_lane_journal::RunStatus::AwaitingApproval
        );
        assert!(recovery.pending_tool.is_some());
        assert!(recovery.pending_approval.is_some());
    }
}
