// SPDX-License-Identifier: Elastic-2.0

//! Bounded, transport-independent conversational agent orchestration.
//!
//! The harness owns only the model/tool loop. It does not authenticate an
//! actor, decide an approval, open a provider connection, or execute a tool.
//! Those authorities stay behind [`AgentProvider`] and [`ToolBroker`]. A model
//! may select an ordered, bounded batch of tools from the catalog it is shown;
//! the broker remains the component that validates each call and either
//! returns a bounded result or pauses the loop for approval. Batches execute
//! sequentially so every result is returned before the next provider round.
//!
//! Persona and policy are separate inputs. Persona may shape Monique's voice,
//! but it cannot alter the catalog, budgets, approval custody, or broker.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

pub const MAX_PERSONA_BYTES: usize = 64 * 1024;
pub const MAX_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_TRANSCRIPT_ENTRIES: usize = 512;
pub const MAX_TRANSCRIPT_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_FINAL_ANSWER_BYTES: usize = 64 * 1024;
pub const MAX_TOOL_CATALOG_ENTRIES: usize = 256;
pub const MAX_TOOL_ID_BYTES: usize = 128;
pub const MAX_CALL_ID_BYTES: usize = 160;
pub const MAX_TOOL_DESCRIPTION_BYTES: usize = 2 * 1024;
pub const MAX_TOOL_SCHEMA_BYTES: usize = 64 * 1024;
pub const MAX_TOOL_ARGUMENT_BYTES: usize = 64 * 1024;
pub const MAX_PROVIDER_DECISION_BYTES: usize = 128 * 1024;
pub const MAX_PROVIDER_TOOL_CALLS_PER_BATCH: usize = MAX_TOOL_CALLS_CEILING as usize;

pub const MAX_ROUNDS_CEILING: u16 = 32;
pub const MAX_TOOL_CALLS_CEILING: u16 = 64;
pub const MAX_CALLS_PER_TOOL_CEILING: u16 = 16;
pub const MAX_IDENTICAL_CALLS_CEILING: u16 = 4;
/// Leaves room for the durable journal's tool-outcome envelope below 1 MiB.
pub const MAX_TOOL_RESULT_BYTES_CEILING: usize = 1024 * 1024 - 4 * 1024;

/// All loop ceilings. Zero is never a useful bound and is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HarnessLimits {
    max_rounds: u16,
    max_tool_calls: u16,
    max_calls_per_tool: u16,
    max_identical_calls: u16,
    max_tool_result_bytes: usize,
}

impl HarnessLimits {
    pub fn new(
        max_rounds: u16,
        max_tool_calls: u16,
        max_calls_per_tool: u16,
        max_identical_calls: u16,
        max_tool_result_bytes: usize,
    ) -> Result<Self, HarnessBuildError> {
        bounded_nonzero(max_rounds, MAX_ROUNDS_CEILING, "max_rounds")?;
        bounded_nonzero(max_tool_calls, MAX_TOOL_CALLS_CEILING, "max_tool_calls")?;
        bounded_nonzero(
            max_calls_per_tool,
            MAX_CALLS_PER_TOOL_CEILING,
            "max_calls_per_tool",
        )?;
        bounded_nonzero(
            max_identical_calls,
            MAX_IDENTICAL_CALLS_CEILING,
            "max_identical_calls",
        )?;
        if max_tool_result_bytes == 0 || max_tool_result_bytes > MAX_TOOL_RESULT_BYTES_CEILING {
            return Err(HarnessBuildError::InvalidLimit("max_tool_result_bytes"));
        }
        Ok(Self {
            max_rounds,
            max_tool_calls,
            max_calls_per_tool,
            max_identical_calls,
            max_tool_result_bytes,
        })
    }

    #[must_use]
    pub const fn conversational() -> Self {
        Self {
            max_rounds: 4,
            max_tool_calls: 6,
            max_calls_per_tool: 2,
            max_identical_calls: 1,
            max_tool_result_bytes: 64 * 1024,
        }
    }

    #[must_use]
    pub const fn max_rounds(self) -> u16 {
        self.max_rounds
    }

    #[must_use]
    pub const fn max_tool_calls(self) -> u16 {
        self.max_tool_calls
    }

    #[must_use]
    pub const fn max_calls_per_tool(self) -> u16 {
        self.max_calls_per_tool
    }

    #[must_use]
    pub const fn max_identical_calls(self) -> u16 {
        self.max_identical_calls
    }

    #[must_use]
    pub const fn max_tool_result_bytes(self) -> usize {
        self.max_tool_result_bytes
    }
}

fn bounded_nonzero(value: u16, maximum: u16, field: &'static str) -> Result<(), HarnessBuildError> {
    if value == 0 || value > maximum {
        Err(HarnessBuildError::InvalidLimit(field))
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarnessBuildError {
    InvalidLimit(&'static str),
    InvalidPersona,
    InvalidPolicy,
    InvalidTranscript,
}

impl fmt::Display for HarnessBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit(field) => write!(formatter, "invalid harness limit: {field}"),
            Self::InvalidPersona => formatter.write_str("invalid harness persona"),
            Self::InvalidPolicy => formatter.write_str("invalid harness policy"),
            Self::InvalidTranscript => formatter.write_str("invalid harness transcript"),
        }
    }
}

impl std::error::Error for HarnessBuildError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranscriptRole {
    User,
    Assistant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TranscriptInput {
    Message { role: TranscriptRole, text: String },
    ToolCall(ToolCall),
    ToolResult(ToolResultInput),
}

impl TranscriptInput {
    pub fn message(role: TranscriptRole, text: impl Into<String>) -> Result<Self, DecisionError> {
        let text = text.into();
        validate_text(&text, MAX_TRANSCRIPT_TEXT_BYTES).map_err(|_| DecisionError::InvalidText)?;
        Ok(Self::Message { role, text })
    }
}

/// One provider-visible tool, with the exact input schema shown to the model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolDefinition {
    id: String,
    description: String,
    input_schema: Value,
}

impl ToolDefinition {
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        input_schema: Value,
    ) -> Result<Self, CatalogError> {
        let id = id.into();
        let description = description.into();
        if !valid_identifier(&id, MAX_TOOL_ID_BYTES) {
            return Err(CatalogError::InvalidTool);
        }
        if description.len() > MAX_TOOL_DESCRIPTION_BYTES
            || description.chars().any(|character| character == '\0')
            || !input_schema.is_object()
            || canonical_json_bytes(&input_schema).len() > MAX_TOOL_SCHEMA_BYTES
        {
            return Err(CatalogError::InvalidTool);
        }
        Ok(Self {
            id,
            description,
            input_schema,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    #[must_use]
    pub const fn input_schema(&self) -> &Value {
        &self.input_schema
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogError {
    InvalidTool,
    DuplicateTool,
    TooManyTools,
    Unavailable,
}

/// A typed provider request. The model gets no broker or authority handle.
pub struct ProviderTurn<'a> {
    persona: &'a str,
    policy: &'a str,
    transcript: &'a [TranscriptInput],
    tools: &'a [ToolDefinition],
    round: u16,
    remaining_tool_calls: u16,
}

impl<'a> ProviderTurn<'a> {
    #[must_use]
    pub const fn persona(&self) -> &'a str {
        self.persona
    }

    #[must_use]
    pub const fn policy(&self) -> &'a str {
        self.policy
    }

    #[must_use]
    pub const fn transcript(&self) -> &'a [TranscriptInput] {
        self.transcript
    }

    #[must_use]
    pub const fn tools(&self) -> &'a [ToolDefinition] {
        self.tools
    }

    #[must_use]
    pub const fn round(&self) -> u16 {
        self.round
    }

    #[must_use]
    pub const fn remaining_tool_calls(&self) -> u16 {
        self.remaining_tool_calls
    }
}

pub trait AgentProvider {
    fn decide(&mut self, turn: ProviderTurn<'_>) -> Result<ProviderDecision, ProviderFailure>;
}

/// Closed failures: provider bytes never become a fallback answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFailure {
    Unavailable,
    TimedOut,
    Refused,
    MalformedOutput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalAnswer(String);

impl FinalAnswer {
    pub fn new(value: impl Into<String>) -> Result<Self, DecisionError> {
        let value = value.into();
        validate_text(&value, MAX_FINAL_ANSWER_BYTES).map_err(|_| DecisionError::InvalidText)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolCall {
    call_id: String,
    tool: String,
    arguments: Value,
}

impl ToolCall {
    pub fn new(
        call_id: impl Into<String>,
        tool: impl Into<String>,
        arguments: Value,
    ) -> Result<Self, DecisionError> {
        let call_id = call_id.into();
        let tool = tool.into();
        if !valid_identifier(&call_id, MAX_CALL_ID_BYTES)
            || !valid_identifier(&tool, MAX_TOOL_ID_BYTES)
        {
            return Err(DecisionError::InvalidIdentifier);
        }
        if !arguments.is_object()
            || canonical_json_bytes(&arguments).len() > MAX_TOOL_ARGUMENT_BYTES
        {
            return Err(DecisionError::InvalidArguments);
        }
        Ok(Self {
            call_id,
            tool,
            arguments,
        })
    }

    #[must_use]
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    #[must_use]
    pub const fn arguments(&self) -> &Value {
        &self.arguments
    }

    fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"automonique.agent-tool-call.v1\0");
        hasher.update(self.tool.as_bytes());
        hasher.update(b"\0");
        hasher.update(canonical_json_bytes(&self.arguments));
        hasher.finalize().into()
    }
}

/// A non-empty provider-ordered batch of tool calls.
///
/// Construction applies a hard process ceiling. A harness applies its smaller
/// per-turn budgets atomically before any call in the batch reaches a broker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolCallBatch(Vec<ToolCall>);

impl ToolCallBatch {
    pub fn new(calls: Vec<ToolCall>) -> Result<Self, DecisionError> {
        if calls.is_empty()
            || calls.len() > MAX_PROVIDER_TOOL_CALLS_PER_BATCH
            || encoded_tool_call_batch_size(&calls) > MAX_PROVIDER_DECISION_BYTES
        {
            return Err(DecisionError::InvalidBatch);
        }
        Ok(Self(calls))
    }

    #[must_use]
    pub fn calls(&self) -> &[ToolCall] {
        &self.0
    }

    fn into_calls(self) -> Vec<ToolCall> {
        self.0
    }
}

fn encoded_tool_call_batch_size(calls: &[ToolCall]) -> usize {
    let calls = calls
        .iter()
        .map(|call| {
            serde_json::json!({
                "call_id": call.call_id(),
                "tool": call.tool(),
                "arguments": call.arguments()
            })
        })
        .collect::<Vec<_>>();
    canonical_json_bytes(&serde_json::json!({
        "kind": "tool_calls",
        "calls": calls
    }))
    .len()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderDecision {
    Final(FinalAnswer),
    /// Compatibility form for providers that select exactly one tool.
    ToolCall(ToolCall),
    ToolCalls(ToolCallBatch),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionError {
    InvalidIdentifier,
    InvalidArguments,
    InvalidBatch,
    InvalidText,
}

/// Decode the deliberately small provider wire subset.
///
/// Unknown fields, trailing prose, oversized output, invalid identifiers and
/// non-object arguments all become one closed failure category. Callers must
/// never display the rejected bytes as an answer.
pub fn decode_provider_decision(bytes: &[u8]) -> Result<ProviderDecision, ProviderFailure> {
    if bytes.is_empty() || bytes.len() > MAX_PROVIDER_DECISION_BYTES {
        return Err(ProviderFailure::MalformedOutput);
    }
    let wire: ProviderDecisionWire =
        serde_json::from_slice(bytes).map_err(|_| ProviderFailure::MalformedOutput)?;
    match wire {
        ProviderDecisionWire::Final { answer } => FinalAnswer::new(answer)
            .map(ProviderDecision::Final)
            .map_err(|_| ProviderFailure::MalformedOutput),
        ProviderDecisionWire::ToolCall {
            call_id,
            tool,
            arguments,
        } => ToolCall::new(call_id, tool, arguments)
            .map(ProviderDecision::ToolCall)
            .map_err(|_| ProviderFailure::MalformedOutput),
        ProviderDecisionWire::ToolCalls { calls } => calls
            .into_iter()
            .map(|call| ToolCall::new(call.call_id, call.tool, call.arguments))
            .collect::<Result<Vec<_>, _>>()
            .and_then(ToolCallBatch::new)
            .map(ProviderDecision::ToolCalls)
            .map_err(|_| ProviderFailure::MalformedOutput),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolCallWire {
    call_id: String,
    tool: String,
    arguments: Value,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ProviderDecisionWire {
    Final {
        answer: String,
    },
    ToolCall {
        call_id: String,
        tool: String,
        arguments: Value,
    },
    ToolCalls {
        calls: Vec<ToolCallWire>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolResultPayload {
    value: Value,
    is_error: bool,
}

impl ToolResultPayload {
    #[must_use]
    pub const fn complete(value: Value) -> Self {
        Self {
            value,
            is_error: false,
        }
    }

    #[must_use]
    pub const fn error(value: Value) -> Self {
        Self {
            value,
            is_error: true,
        }
    }

    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.value
    }

    #[must_use]
    pub const fn is_error(&self) -> bool {
        self.is_error
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolResultInput {
    call_id: String,
    tool: String,
    payload: ToolResultPayload,
}

impl ToolResultInput {
    #[must_use]
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    #[must_use]
    pub const fn payload(&self) -> &ToolResultPayload {
        &self.payload
    }
}

/// Broker-owned approval metadata. Its key is opaque to the model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolApproval {
    key: String,
    summary: String,
}

impl ToolApproval {
    pub fn new(
        key: impl Into<String>,
        summary: impl Into<String>,
    ) -> Result<Self, ToolBrokerFailure> {
        let key = key.into();
        let summary = summary.into();
        if !valid_identifier(&key, MAX_CALL_ID_BYTES)
            || validate_text(&summary, MAX_TRANSCRIPT_TEXT_BYTES).is_err()
        {
            return Err(ToolBrokerFailure::InvalidApproval);
        }
        Ok(Self { key, summary })
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolBrokerOutcome {
    Complete(ToolResultPayload),
    ApprovalRequired(ToolApproval),
}

/// Execution and argument validation live here, outside model custody.
pub trait ToolBroker {
    fn catalog(&mut self) -> Result<Vec<ToolDefinition>, CatalogError>;

    /// Atomically validate and reserve an ordered batch against the pinned
    /// broker catalog without executing, freezing, or journaling.
    ///
    /// Failure must commit no reservation or replay/invocation state. Success
    /// reserves capacity and conflict coordinates for the whole batch;
    /// [`Self::invoke`] then consumes that reservation in provider order while
    /// repeating authority-sensitive validation.
    fn admit_batch(&mut self, calls: &[ToolCall]) -> Result<(), ToolBrokerFailure>;

    /// Release only the unconsumed tail of the current admitted batch.
    /// Completed calls and their legitimate replay receipts remain intact.
    fn abort_batch(&mut self);

    fn invoke(&mut self, call: &ToolCall) -> Result<ToolBrokerOutcome, ToolBrokerFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolBrokerFailure {
    InvalidArguments,
    InvalidApproval,
    Unauthorized,
    Unavailable,
    TimedOut,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalPause {
    approval: ToolApproval,
    call: ToolCall,
}

impl ApprovalPause {
    #[must_use]
    pub const fn approval(&self) -> &ToolApproval {
        &self.approval
    }

    #[must_use]
    pub const fn call(&self) -> &ToolCall {
        &self.call
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HarnessOutcome {
    Complete(FinalAnswer),
    AwaitingApproval(ApprovalPause),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetKind {
    Rounds,
    ToolCalls,
    CallsPerTool,
    IdenticalCall,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HarnessFailure {
    Catalog(CatalogError),
    Provider(ProviderFailure),
    Tool(ToolBrokerFailure),
    BudgetExceeded(BudgetKind),
    UnknownTool,
    DuplicateCallId,
    ToolResultTooLarge { maximum: usize, actual: usize },
    TranscriptFull,
    ApprovalResultMismatch,
    AlreadyCompleted,
    AlreadyFailed,
}

impl fmt::Display for HarnessFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalog(_) => formatter.write_str("agent tool catalog refused"),
            Self::Provider(failure) => write!(formatter, "agent provider refused: {failure:?}"),
            Self::Tool(failure) => write!(formatter, "agent tool refused: {failure:?}"),
            Self::BudgetExceeded(kind) => write!(formatter, "agent budget exceeded: {kind:?}"),
            Self::UnknownTool => formatter.write_str("agent selected an unknown tool"),
            Self::DuplicateCallId => formatter.write_str("agent repeated a tool call identity"),
            Self::ToolResultTooLarge { maximum, actual } => write!(
                formatter,
                "agent tool result has {actual} bytes; maximum is {maximum}"
            ),
            Self::TranscriptFull => formatter.write_str("agent transcript is full"),
            Self::ApprovalResultMismatch => {
                formatter.write_str("approval result does not match the paused tool call")
            }
            Self::AlreadyCompleted => formatter.write_str("agent turn already completed"),
            Self::AlreadyFailed => formatter.write_str("agent turn already failed"),
        }
    }
}

impl std::error::Error for HarnessFailure {}

#[derive(Clone, Debug)]
enum HarnessState {
    Ready,
    AwaitingApproval(ApprovalPause),
    Completed,
    Failed,
}

/// One bounded conversational turn, reusable by any transport.
pub struct AgentHarness {
    persona: String,
    policy: String,
    transcript: Vec<TranscriptInput>,
    limits: HarnessLimits,
    catalog: Option<Vec<ToolDefinition>>,
    rounds: u16,
    tool_calls: u16,
    calls_per_tool: BTreeMap<String, u16>,
    identical_calls: BTreeMap<[u8; 32], u16>,
    call_ids: BTreeSet<String>,
    pending_calls: VecDeque<ToolCall>,
    state: HarnessState,
}

impl AgentHarness {
    pub fn new(
        persona: impl Into<String>,
        policy: impl Into<String>,
        transcript: Vec<TranscriptInput>,
        limits: HarnessLimits,
    ) -> Result<Self, HarnessBuildError> {
        let persona = persona.into();
        let policy = policy.into();
        if validate_text(&persona, MAX_PERSONA_BYTES).is_err() {
            return Err(HarnessBuildError::InvalidPersona);
        }
        if validate_text(&policy, MAX_POLICY_BYTES).is_err() {
            return Err(HarnessBuildError::InvalidPolicy);
        }
        if transcript.is_empty()
            || transcript.len() > MAX_TRANSCRIPT_ENTRIES
            || transcript.iter().any(|entry| match entry {
                TranscriptInput::Message { text, .. } => {
                    validate_text(text, MAX_TRANSCRIPT_TEXT_BYTES).is_err()
                }
                TranscriptInput::ToolCall(_) => false,
                TranscriptInput::ToolResult(result) => {
                    canonical_json_bytes(result.payload.value()).len()
                        > limits.max_tool_result_bytes
                }
            })
        {
            return Err(HarnessBuildError::InvalidTranscript);
        }
        Ok(Self {
            persona,
            policy,
            transcript,
            limits,
            catalog: None,
            rounds: 0,
            tool_calls: 0,
            calls_per_tool: BTreeMap::new(),
            identical_calls: BTreeMap::new(),
            call_ids: BTreeSet::new(),
            pending_calls: VecDeque::new(),
            state: HarnessState::Ready,
        })
    }

    #[must_use]
    pub fn transcript(&self) -> &[TranscriptInput] {
        &self.transcript
    }

    #[must_use]
    pub const fn rounds(&self) -> u16 {
        self.rounds
    }

    #[must_use]
    pub const fn tool_calls(&self) -> u16 {
        self.tool_calls
    }

    /// Drive until a final answer, an approval boundary, or a typed refusal.
    pub fn drive(
        &mut self,
        provider: &mut dyn AgentProvider,
        broker: &mut dyn ToolBroker,
    ) -> Result<HarnessOutcome, HarnessFailure> {
        match &self.state {
            HarnessState::AwaitingApproval(pause) => {
                return Ok(HarnessOutcome::AwaitingApproval(pause.clone()));
            }
            HarnessState::Completed => return Err(HarnessFailure::AlreadyCompleted),
            HarnessState::Failed => return Err(HarnessFailure::AlreadyFailed),
            HarnessState::Ready => {}
        }
        if self.catalog.is_none() {
            let catalog = match broker.catalog() {
                Ok(catalog) => catalog,
                Err(error) => return self.fail(HarnessFailure::Catalog(error)),
            };
            if let Err(error) = validate_catalog(&catalog) {
                return self.fail(HarnessFailure::Catalog(error));
            }
            self.catalog = Some(catalog);
        }

        loop {
            // A provider batch is drained completely, in provider order,
            // before another provider round is allowed to observe results.
            if let Some(call) = self.pending_calls.pop_front() {
                self.transcript
                    .push(TranscriptInput::ToolCall(call.clone()));
                match broker.invoke(&call) {
                    Ok(ToolBrokerOutcome::Complete(payload)) => {
                        if let Err(error) = self.append_tool_result(&call, payload) {
                            broker.abort_batch();
                            return self.fail(error);
                        }
                    }
                    Ok(ToolBrokerOutcome::ApprovalRequired(approval)) => {
                        let pause = ApprovalPause { approval, call };
                        self.state = HarnessState::AwaitingApproval(pause.clone());
                        return Ok(HarnessOutcome::AwaitingApproval(pause));
                    }
                    Err(error) => {
                        broker.abort_batch();
                        return self.fail(HarnessFailure::Tool(error));
                    }
                }
                continue;
            }

            if self.rounds >= self.limits.max_rounds {
                return self.fail(HarnessFailure::BudgetExceeded(BudgetKind::Rounds));
            }
            self.rounds = self.rounds.saturating_add(1);
            let decision = {
                let catalog = self.catalog.as_deref().unwrap_or(&[]);
                let turn = ProviderTurn {
                    persona: &self.persona,
                    policy: &self.policy,
                    transcript: &self.transcript,
                    tools: catalog,
                    round: self.rounds,
                    remaining_tool_calls: self
                        .limits
                        .max_tool_calls
                        .saturating_sub(self.tool_calls),
                };
                match provider.decide(turn) {
                    Ok(decision) => decision,
                    Err(error) => return self.fail(HarnessFailure::Provider(error)),
                }
            };
            match decision {
                ProviderDecision::Final(answer) => {
                    if self.transcript.len() >= MAX_TRANSCRIPT_ENTRIES {
                        return self.fail(HarnessFailure::TranscriptFull);
                    }
                    self.transcript.push(TranscriptInput::Message {
                        role: TranscriptRole::Assistant,
                        text: answer.as_str().to_owned(),
                    });
                    self.state = HarnessState::Completed;
                    return Ok(HarnessOutcome::Complete(answer));
                }
                ProviderDecision::ToolCall(call) => {
                    if let Err(error) = self.admit_tool_calls(broker, vec![call]) {
                        return self.fail(error);
                    }
                }
                ProviderDecision::ToolCalls(batch) => {
                    if let Err(error) = self.admit_tool_calls(broker, batch.into_calls()) {
                        return self.fail(error);
                    }
                }
            }
        }
    }

    /// Continue after the external approval custodian settled and executed the
    /// exact paused call. This method validates binding and result size; it does
    /// not interpret approval evidence or execute the tool itself. The broker
    /// handle is used only to release the remaining batch if result admission
    /// fails.
    pub fn resume_with_tool_result(
        &mut self,
        broker: &mut dyn ToolBroker,
        call_id: &str,
        payload: ToolResultPayload,
    ) -> Result<(), HarnessFailure> {
        let HarnessState::AwaitingApproval(pause) = &self.state else {
            return Err(HarnessFailure::ApprovalResultMismatch);
        };
        if pause.call.call_id != call_id {
            return Err(HarnessFailure::ApprovalResultMismatch);
        }
        let call = pause.call.clone();
        if let Err(error) = self.append_tool_result(&call, payload) {
            broker.abort_batch();
            self.state = HarnessState::Failed;
            return Err(error);
        }
        self.state = HarnessState::Ready;
        Ok(())
    }

    /// Validate and reserve an entire provider batch before any member can
    /// execute. This prevents a bad later call from leaving partial effects.
    fn admit_tool_calls(
        &mut self,
        broker: &mut dyn ToolBroker,
        calls: Vec<ToolCall>,
    ) -> Result<(), HarnessFailure> {
        debug_assert!(!calls.is_empty());
        debug_assert!(self.pending_calls.is_empty());

        if self
            .transcript
            .len()
            .saturating_add(calls.len().saturating_mul(2))
            > MAX_TRANSCRIPT_ENTRIES
        {
            return Err(HarnessFailure::TranscriptFull);
        }
        let batch_count = u16::try_from(calls.len())
            .map_err(|_| HarnessFailure::BudgetExceeded(BudgetKind::ToolCalls))?;
        if self.tool_calls.saturating_add(batch_count) > self.limits.max_tool_calls {
            return Err(HarnessFailure::BudgetExceeded(BudgetKind::ToolCalls));
        }

        let catalog = self.catalog.as_deref().unwrap_or(&[]);
        let mut call_ids = self.call_ids.clone();
        let mut calls_per_tool = self.calls_per_tool.clone();
        let mut identical_calls = self.identical_calls.clone();
        for call in &calls {
            if !catalog.iter().any(|tool| tool.id == call.tool) {
                return Err(HarnessFailure::UnknownTool);
            }
            if !call_ids.insert(call.call_id.clone()) {
                return Err(HarnessFailure::DuplicateCallId);
            }

            let per_tool = calls_per_tool.entry(call.tool.clone()).or_default();
            *per_tool = per_tool.saturating_add(1);
            if *per_tool > self.limits.max_calls_per_tool {
                return Err(HarnessFailure::BudgetExceeded(BudgetKind::CallsPerTool));
            }

            let identical = identical_calls.entry(call.digest()).or_default();
            *identical = identical.saturating_add(1);
            if *identical > self.limits.max_identical_calls {
                return Err(HarnessFailure::BudgetExceeded(BudgetKind::IdenticalCall));
            }
        }

        // Broker schemas, capacity, replay and invocation fences are
        // authoritative. Reserve the whole batch atomically before any member
        // reaches `invoke`.
        broker.admit_batch(&calls).map_err(HarnessFailure::Tool)?;

        self.tool_calls = self.tool_calls.saturating_add(batch_count);
        self.call_ids = call_ids;
        self.calls_per_tool = calls_per_tool;
        self.identical_calls = identical_calls;
        self.pending_calls.extend(calls);
        Ok(())
    }

    fn append_tool_result(
        &mut self,
        call: &ToolCall,
        payload: ToolResultPayload,
    ) -> Result<(), HarnessFailure> {
        let actual = canonical_json_bytes(payload.value()).len();
        if actual > self.limits.max_tool_result_bytes {
            return Err(HarnessFailure::ToolResultTooLarge {
                maximum: self.limits.max_tool_result_bytes,
                actual,
            });
        }
        self.transcript
            .push(TranscriptInput::ToolResult(ToolResultInput {
                call_id: call.call_id.clone(),
                tool: call.tool.clone(),
                payload,
            }));
        Ok(())
    }

    fn fail<T>(&mut self, failure: HarnessFailure) -> Result<T, HarnessFailure> {
        self.state = HarnessState::Failed;
        Err(failure)
    }
}

fn validate_catalog(catalog: &[ToolDefinition]) -> Result<(), CatalogError> {
    if catalog.len() > MAX_TOOL_CATALOG_ENTRIES {
        return Err(CatalogError::TooManyTools);
    }
    let mut seen = BTreeSet::new();
    if catalog.iter().any(|tool| !seen.insert(tool.id.as_str())) {
        return Err(CatalogError::DuplicateTool);
    }
    Ok(())
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn validate_text(value: &str, maximum: usize) -> Result<(), ()> {
    if value.trim().is_empty() || value.len() > maximum || value.contains('\0') {
        Err(())
    } else {
        Ok(())
    }
}

/// Stable JSON rendering for call digests and byte accounting.
pub(crate) fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    let mut output = Vec::new();
    write_canonical_json(value, &mut output);
    output
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .expect("a Rust string always serializes as JSON")
                .as_bytes(),
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output);
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut fields: Vec<_> = values.iter().collect();
            fields.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (index, (key, value)) in fields.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .expect("a Rust string always serializes as JSON")
                        .as_bytes(),
                );
                output.push(b':');
                write_canonical_json(value, output);
            }
            output.push(b'}');
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use serde_json::json;

    use super::*;

    struct ScriptedProvider {
        decisions: VecDeque<Result<ProviderDecision, ProviderFailure>>,
        observed_rounds: Vec<u16>,
        observed_transcript_lengths: Vec<usize>,
    }

    impl ScriptedProvider {
        fn new(decisions: Vec<Result<ProviderDecision, ProviderFailure>>) -> Self {
            Self {
                decisions: decisions.into(),
                observed_rounds: Vec::new(),
                observed_transcript_lengths: Vec::new(),
            }
        }
    }

    impl AgentProvider for ScriptedProvider {
        fn decide(&mut self, turn: ProviderTurn<'_>) -> Result<ProviderDecision, ProviderFailure> {
            self.observed_rounds.push(turn.round());
            self.observed_transcript_lengths
                .push(turn.transcript().len());
            self.decisions
                .pop_front()
                .unwrap_or(Err(ProviderFailure::MalformedOutput))
        }
    }

    #[derive(Default)]
    struct FixtureBroker {
        catalog: Vec<ToolDefinition>,
        admission_outcomes: VecDeque<Result<(), ToolBrokerFailure>>,
        admitted_batches: Vec<Vec<ToolCall>>,
        outcomes: VecDeque<Result<ToolBrokerOutcome, ToolBrokerFailure>>,
        calls: Vec<ToolCall>,
        catalog_reads: usize,
        aborts: usize,
    }

    impl ToolBroker for FixtureBroker {
        fn catalog(&mut self) -> Result<Vec<ToolDefinition>, CatalogError> {
            self.catalog_reads += 1;
            Ok(self.catalog.clone())
        }

        fn admit_batch(&mut self, calls: &[ToolCall]) -> Result<(), ToolBrokerFailure> {
            self.admitted_batches.push(calls.to_vec());
            self.admission_outcomes.pop_front().unwrap_or(Ok(()))
        }

        fn abort_batch(&mut self) {
            self.aborts += 1;
        }

        fn invoke(&mut self, call: &ToolCall) -> Result<ToolBrokerOutcome, ToolBrokerFailure> {
            self.calls.push(call.clone());
            self.outcomes
                .pop_front()
                .unwrap_or(Err(ToolBrokerFailure::Unavailable))
        }
    }

    fn tool(id: &str) -> ToolDefinition {
        ToolDefinition::new(
            id,
            format!("Call {id}"),
            json!({"type":"object","additionalProperties":false}),
        )
        .unwrap()
    }

    fn call(id: &str, tool: &str, arguments: Value) -> ProviderDecision {
        ProviderDecision::ToolCall(ToolCall::new(id, tool, arguments).unwrap())
    }

    fn raw_call(id: &str, tool: &str, arguments: Value) -> ToolCall {
        ToolCall::new(id, tool, arguments).unwrap()
    }

    fn batch(calls: Vec<ToolCall>) -> ProviderDecision {
        ProviderDecision::ToolCalls(ToolCallBatch::new(calls).unwrap())
    }

    fn final_answer(text: &str) -> ProviderDecision {
        ProviderDecision::Final(FinalAnswer::new(text).unwrap())
    }

    fn harness(limits: HarnessLimits) -> AgentHarness {
        AgentHarness::new(
            "You are Monique.",
            "Tools are selected by the model and authorized by the broker.",
            vec![TranscriptInput::message(TranscriptRole::User, "hello").unwrap()],
            limits,
        )
        .unwrap()
    }

    #[test]
    fn zero_tool_turn_finishes_in_one_round() {
        let mut provider = ScriptedProvider::new(vec![Ok(final_answer("Hi."))]);
        let mut broker = FixtureBroker::default();
        let mut harness = harness(HarnessLimits::conversational());

        assert_eq!(
            harness.drive(&mut provider, &mut broker),
            Ok(HarnessOutcome::Complete(FinalAnswer::new("Hi.").unwrap()))
        );
        assert_eq!(harness.rounds(), 1);
        assert_eq!(harness.tool_calls(), 0);
        assert!(broker.calls.is_empty());
    }

    #[test]
    fn one_tool_result_returns_to_the_provider() {
        let mut provider = ScriptedProvider::new(vec![
            Ok(call("call-1", "tickets.read", json!({"day":"yesterday"}))),
            Ok(final_answer("Two tickets were completed.")),
        ]);
        let mut broker = FixtureBroker {
            catalog: vec![tool("tickets.read")],
            outcomes: vec![Ok(ToolBrokerOutcome::Complete(
                ToolResultPayload::complete(json!({"count":2})),
            ))]
            .into(),
            ..FixtureBroker::default()
        };
        let mut harness = harness(HarnessLimits::conversational());

        assert!(matches!(
            harness.drive(&mut provider, &mut broker),
            Ok(HarnessOutcome::Complete(_))
        ));
        assert_eq!(provider.observed_rounds, [1, 2]);
        assert_eq!(provider.observed_transcript_lengths, [1, 3]);
        assert_eq!(broker.calls.len(), 1);
        assert!(matches!(
            harness.transcript().get(2),
            Some(TranscriptInput::ToolResult(result))
                if result.call_id() == "call-1" && !result.payload().is_error()
        ));
    }

    #[test]
    fn chained_tool_calls_share_one_bounded_transcript() {
        let mut provider = ScriptedProvider::new(vec![
            Ok(call("call-1", "tickets.read", json!({"state":"closed"}))),
            Ok(call("call-2", "issues.read", json!({"number":7}))),
            Ok(final_answer("Ticket 7 was deployed.")),
        ]);
        let mut broker = FixtureBroker {
            catalog: vec![tool("tickets.read"), tool("issues.read")],
            outcomes: vec![
                Ok(ToolBrokerOutcome::Complete(ToolResultPayload::complete(
                    json!([7]),
                ))),
                Ok(ToolBrokerOutcome::Complete(ToolResultPayload::complete(
                    json!({"number":7,"verified":true}),
                ))),
            ]
            .into(),
            ..FixtureBroker::default()
        };
        let mut harness = harness(HarnessLimits::conversational());

        assert!(matches!(
            harness.drive(&mut provider, &mut broker),
            Ok(HarnessOutcome::Complete(_))
        ));
        assert_eq!(harness.rounds(), 3);
        assert_eq!(harness.tool_calls(), 2);
        assert_eq!(provider.observed_transcript_lengths, [1, 3, 5]);
        assert_eq!(broker.catalog_reads, 1);
        assert_eq!(broker.calls.len(), 2);
    }

    #[test]
    fn provider_batch_decodes_and_preserves_order() {
        let decision = decode_provider_decision(
            br#"{"kind":"tool_calls","calls":[{"call_id":"call-1","tool":"tickets.read","arguments":{"page":1}},{"call_id":"call-2","tool":"issues.read","arguments":{"number":7}}]}"#,
        )
        .unwrap();
        let ProviderDecision::ToolCalls(batch) = decision else {
            panic!("expected a tool batch");
        };
        assert_eq!(
            batch
                .calls()
                .iter()
                .map(ToolCall::call_id)
                .collect::<Vec<_>>(),
            ["call-1", "call-2"]
        );
        assert_eq!(
            decode_provider_decision(br#"{"kind":"tool_calls","calls":[]}"#),
            Err(ProviderFailure::MalformedOutput)
        );
        assert_eq!(
            decode_provider_decision(
                br#"{"kind":"tool_calls","calls":[{"call_id":"call-1","tool":"tickets.read","arguments":{},"unexpected":true}]}"#
            ),
            Err(ProviderFailure::MalformedOutput)
        );

        let over_ceiling = (0..=MAX_PROVIDER_TOOL_CALLS_PER_BATCH)
            .map(|index| {
                raw_call(
                    &format!("call-{index}"),
                    "tickets.read",
                    json!({"index":index}),
                )
            })
            .collect();
        assert_eq!(
            ToolCallBatch::new(over_ceiling),
            Err(DecisionError::InvalidBatch)
        );

        let large_payload = "x".repeat(MAX_TOOL_ARGUMENT_BYTES - 32);
        let aggregate_too_large = vec![
            raw_call(
                "call-large-1",
                "tickets.read",
                json!({"payload":large_payload}),
            ),
            raw_call(
                "call-large-2",
                "tickets.read",
                json!({"payload":large_payload}),
            ),
        ];
        assert_eq!(
            ToolCallBatch::new(aggregate_too_large),
            Err(DecisionError::InvalidBatch)
        );
        assert_eq!(
            HarnessLimits::new(1, 1, 1, 1, MAX_TOOL_RESULT_BYTES_CEILING + 1),
            Err(HarnessBuildError::InvalidLimit("max_tool_result_bytes"))
        );
    }

    #[test]
    fn ordered_batch_runs_sequentially_before_next_provider_round() {
        let mut provider = ScriptedProvider::new(vec![
            Ok(batch(vec![
                raw_call("call-1", "tickets.read", json!({"page":1})),
                raw_call("call-2", "issues.read", json!({"number":7})),
                raw_call("call-3", "deployments.read", json!({"name":"web"})),
            ])),
            Ok(final_answer("All three reads completed.")),
        ]);
        let mut broker = FixtureBroker {
            catalog: vec![
                tool("tickets.read"),
                tool("issues.read"),
                tool("deployments.read"),
            ],
            outcomes: vec![
                Ok(ToolBrokerOutcome::Complete(ToolResultPayload::complete(
                    json!({"page":1}),
                ))),
                Ok(ToolBrokerOutcome::Complete(ToolResultPayload::complete(
                    json!({"number":7}),
                ))),
                Ok(ToolBrokerOutcome::Complete(ToolResultPayload::complete(
                    json!({"online":true}),
                ))),
            ]
            .into(),
            ..FixtureBroker::default()
        };
        let mut harness = harness(HarnessLimits::conversational());

        assert!(matches!(
            harness.drive(&mut provider, &mut broker),
            Ok(HarnessOutcome::Complete(_))
        ));
        assert_eq!(provider.observed_rounds, [1, 2]);
        assert_eq!(provider.observed_transcript_lengths, [1, 7]);
        assert_eq!(
            broker
                .calls
                .iter()
                .map(ToolCall::call_id)
                .collect::<Vec<_>>(),
            ["call-1", "call-2", "call-3"]
        );
        for (offset, call_id) in ["call-1", "call-2", "call-3"].iter().enumerate() {
            let call_index = 1 + offset * 2;
            assert!(matches!(
                harness.transcript().get(call_index),
                Some(TranscriptInput::ToolCall(call)) if call.call_id() == *call_id
            ));
            assert!(matches!(
                harness.transcript().get(call_index + 1),
                Some(TranscriptInput::ToolResult(result)) if result.call_id() == *call_id
            ));
        }
    }

    #[test]
    fn whole_batch_is_refused_before_execution_when_a_later_call_is_invalid() {
        let mut provider = ScriptedProvider::new(vec![Ok(batch(vec![
            raw_call("call-1", "tickets.read", json!({"page":1})),
            raw_call("call-2", "shell.exec", json!({"command":"no"})),
        ]))]);
        let mut broker = FixtureBroker {
            catalog: vec![tool("tickets.read")],
            ..FixtureBroker::default()
        };
        let mut invalid_harness = harness(HarnessLimits::conversational());

        assert_eq!(
            invalid_harness.drive(&mut provider, &mut broker),
            Err(HarnessFailure::UnknownTool)
        );
        assert!(broker.calls.is_empty());
        assert_eq!(invalid_harness.tool_calls(), 0);
        assert_eq!(invalid_harness.transcript().len(), 1);

        let limits = HarnessLimits::new(4, 1, 1, 1, 1024).unwrap();
        let mut provider = ScriptedProvider::new(vec![Ok(batch(vec![
            raw_call("call-1", "tickets.read", json!({"page":1})),
            raw_call("call-2", "issues.read", json!({"number":7})),
        ]))]);
        let mut broker = FixtureBroker {
            catalog: vec![tool("tickets.read"), tool("issues.read")],
            ..FixtureBroker::default()
        };
        let mut harness = harness(limits);
        assert_eq!(
            harness.drive(&mut provider, &mut broker),
            Err(HarnessFailure::BudgetExceeded(BudgetKind::ToolCalls))
        );
        assert!(broker.calls.is_empty());
        assert_eq!(harness.tool_calls(), 0);
    }

    #[test]
    fn schema_invalid_later_batch_member_prevents_every_execution() {
        let mut provider = ScriptedProvider::new(vec![Ok(batch(vec![
            raw_call("call-valid", "tickets.read", json!({"number":7})),
            raw_call("call-invalid", "tickets.read", json!({"number":"eight"})),
        ]))]);
        let mut broker = FixtureBroker {
            catalog: vec![tool("tickets.read")],
            admission_outcomes: vec![Err(ToolBrokerFailure::InvalidArguments)].into(),
            ..FixtureBroker::default()
        };
        let mut harness = harness(HarnessLimits::conversational());

        assert_eq!(
            harness.drive(&mut provider, &mut broker),
            Err(HarnessFailure::Tool(ToolBrokerFailure::InvalidArguments))
        );
        assert_eq!(
            broker
                .admitted_batches
                .first()
                .unwrap()
                .iter()
                .map(ToolCall::call_id)
                .collect::<Vec<_>>(),
            ["call-valid", "call-invalid"]
        );
        assert!(broker.calls.is_empty());
        assert_eq!(harness.tool_calls(), 0);
        assert_eq!(harness.transcript().len(), 1);
    }

    #[test]
    fn invoke_failure_aborts_batch_tail_and_same_broker_accepts_fresh_run() {
        let mut failed_provider = ScriptedProvider::new(vec![Ok(batch(vec![
            raw_call("call-fails", "tickets.read", json!({"number":7})),
            raw_call("call-tail", "tickets.read", json!({"number":8})),
        ]))]);
        let mut broker = FixtureBroker {
            catalog: vec![tool("tickets.read")],
            outcomes: vec![
                Err(ToolBrokerFailure::Failed),
                Ok(ToolBrokerOutcome::Complete(ToolResultPayload::complete(
                    json!({"number":9}),
                ))),
            ]
            .into(),
            ..FixtureBroker::default()
        };
        let mut failed_harness = harness(HarnessLimits::conversational());

        assert_eq!(
            failed_harness.drive(&mut failed_provider, &mut broker),
            Err(HarnessFailure::Tool(ToolBrokerFailure::Failed))
        );
        assert_eq!(broker.aborts, 1);
        assert_eq!(broker.calls.len(), 1);

        let mut fresh_provider = ScriptedProvider::new(vec![
            Ok(call("call-fresh", "tickets.read", json!({"number":9}))),
            Ok(final_answer("Fresh call completed.")),
        ]);
        let mut fresh_harness = harness(HarnessLimits::conversational());
        assert!(matches!(
            fresh_harness.drive(&mut fresh_provider, &mut broker),
            Ok(HarnessOutcome::Complete(_))
        ));
        assert_eq!(broker.aborts, 1);
        assert_eq!(
            broker
                .calls
                .iter()
                .map(ToolCall::call_id)
                .collect::<Vec<_>>(),
            ["call-fails", "call-fresh"]
        );
    }

    #[test]
    fn unknown_tool_is_refused_before_broker_execution() {
        let mut provider = ScriptedProvider::new(vec![Ok(call("call-1", "shell.exec", json!({})))]);
        let mut broker = FixtureBroker {
            catalog: vec![tool("tickets.read")],
            ..FixtureBroker::default()
        };
        let mut harness = harness(HarnessLimits::conversational());

        assert_eq!(
            harness.drive(&mut provider, &mut broker),
            Err(HarnessFailure::UnknownTool)
        );
        assert!(broker.calls.is_empty());
    }

    #[test]
    fn invalid_arguments_and_malformed_provider_bytes_are_typed_failures() {
        assert_eq!(
            decode_provider_decision(
                br#"{"kind":"tool_call","call_id":"c-1","tool":"tickets.read","arguments":[]}"#
            ),
            Err(ProviderFailure::MalformedOutput)
        );
        assert_eq!(
            decode_provider_decision(br#"answer outside the closed schema"#),
            Err(ProviderFailure::MalformedOutput)
        );

        let mut provider = ScriptedProvider::new(vec![Ok(call(
            "call-1",
            "tickets.read",
            json!({"bad":true}),
        ))]);
        let mut broker = FixtureBroker {
            catalog: vec![tool("tickets.read")],
            outcomes: vec![Err(ToolBrokerFailure::InvalidArguments)].into(),
            ..FixtureBroker::default()
        };
        let mut harness = harness(HarnessLimits::conversational());
        assert_eq!(
            harness.drive(&mut provider, &mut broker),
            Err(HarnessFailure::Tool(ToolBrokerFailure::InvalidArguments))
        );
    }

    #[test]
    fn identical_call_digest_ignores_provider_call_id() {
        let mut provider = ScriptedProvider::new(vec![
            Ok(call("call-1", "tickets.read", json!({"state":"open"}))),
            Ok(call("call-2", "tickets.read", json!({"state":"open"}))),
        ]);
        let mut broker = FixtureBroker {
            catalog: vec![tool("tickets.read")],
            outcomes: vec![Ok(ToolBrokerOutcome::Complete(
                ToolResultPayload::complete(json!([])),
            ))]
            .into(),
            ..FixtureBroker::default()
        };
        let mut harness = harness(HarnessLimits::conversational());

        assert_eq!(
            harness.drive(&mut provider, &mut broker),
            Err(HarnessFailure::BudgetExceeded(BudgetKind::IdenticalCall))
        );
        assert_eq!(broker.calls.len(), 1);
    }

    #[test]
    fn round_call_per_tool_and_result_bounds_fail_closed() {
        let rounds = HarnessLimits::new(1, 4, 4, 2, 1024).unwrap();
        let mut provider =
            ScriptedProvider::new(vec![Ok(call("call-1", "tickets.read", json!({})))]);
        let mut broker = FixtureBroker {
            catalog: vec![tool("tickets.read")],
            outcomes: vec![Ok(ToolBrokerOutcome::Complete(
                ToolResultPayload::complete(json!({})),
            ))]
            .into(),
            ..FixtureBroker::default()
        };
        assert_eq!(
            harness(rounds).drive(&mut provider, &mut broker),
            Err(HarnessFailure::BudgetExceeded(BudgetKind::Rounds))
        );

        let calls = HarnessLimits::new(4, 1, 4, 2, 1024).unwrap();
        let mut provider = ScriptedProvider::new(vec![
            Ok(call("call-1", "tickets.read", json!({"page":1}))),
            Ok(call("call-2", "tickets.read", json!({"page":2}))),
        ]);
        let mut broker = FixtureBroker {
            catalog: vec![tool("tickets.read")],
            outcomes: vec![Ok(ToolBrokerOutcome::Complete(
                ToolResultPayload::complete(json!({})),
            ))]
            .into(),
            ..FixtureBroker::default()
        };
        assert_eq!(
            harness(calls).drive(&mut provider, &mut broker),
            Err(HarnessFailure::BudgetExceeded(BudgetKind::ToolCalls))
        );

        let per_tool = HarnessLimits::new(4, 4, 1, 2, 1024).unwrap();
        let mut provider = ScriptedProvider::new(vec![
            Ok(call("call-1", "tickets.read", json!({"page":1}))),
            Ok(call("call-2", "tickets.read", json!({"page":2}))),
        ]);
        let mut broker = FixtureBroker {
            catalog: vec![tool("tickets.read")],
            outcomes: vec![Ok(ToolBrokerOutcome::Complete(
                ToolResultPayload::complete(json!({})),
            ))]
            .into(),
            ..FixtureBroker::default()
        };
        assert_eq!(
            harness(per_tool).drive(&mut provider, &mut broker),
            Err(HarnessFailure::BudgetExceeded(BudgetKind::CallsPerTool))
        );

        let result = HarnessLimits::new(4, 4, 4, 2, 8).unwrap();
        let mut provider =
            ScriptedProvider::new(vec![Ok(call("call-1", "tickets.read", json!({})))]);
        let mut broker = FixtureBroker {
            catalog: vec![tool("tickets.read")],
            outcomes: vec![Ok(ToolBrokerOutcome::Complete(
                ToolResultPayload::complete(json!({"long":"0123456789"})),
            ))]
            .into(),
            ..FixtureBroker::default()
        };
        let mut result_harness = harness(result);
        assert!(matches!(
            result_harness.drive(&mut provider, &mut broker),
            Err(HarnessFailure::ToolResultTooLarge {
                maximum: 8,
                actual: _
            })
        ));
        assert_eq!(broker.aborts, 1);
    }

    #[test]
    fn approval_pauses_without_reinvoking_and_resumes_with_bound_result() {
        let mut provider = ScriptedProvider::new(vec![
            Ok(call("call-1", "slack.post", json!({"text":"hello"}))),
            Ok(final_answer("Posted after approval.")),
        ]);
        let mut broker = FixtureBroker {
            catalog: vec![tool("slack.post")],
            outcomes: vec![Ok(ToolBrokerOutcome::ApprovalRequired(
                ToolApproval::new("approval-1", "Post hello to the configured channel").unwrap(),
            ))]
            .into(),
            ..FixtureBroker::default()
        };
        let mut harness = harness(HarnessLimits::conversational());

        let first = harness.drive(&mut provider, &mut broker).unwrap();
        let HarnessOutcome::AwaitingApproval(pause) = first else {
            panic!("expected approval pause");
        };
        assert_eq!(pause.call().call_id(), "call-1");
        assert_eq!(broker.calls.len(), 1);
        assert!(matches!(
            harness.drive(&mut provider, &mut broker),
            Ok(HarnessOutcome::AwaitingApproval(_))
        ));
        assert_eq!(broker.calls.len(), 1);
        assert_eq!(
            harness.resume_with_tool_result(
                &mut broker,
                "wrong-call",
                ToolResultPayload::complete(json!({}))
            ),
            Err(HarnessFailure::ApprovalResultMismatch)
        );
        harness
            .resume_with_tool_result(
                &mut broker,
                "call-1",
                ToolResultPayload::complete(json!({"posted":true})),
            )
            .unwrap();
        assert!(matches!(
            harness.drive(&mut provider, &mut broker),
            Ok(HarnessOutcome::Complete(_))
        ));
    }

    #[test]
    fn oversized_resumed_result_aborts_the_retained_batch_tail() {
        let limits = HarnessLimits::new(4, 4, 4, 2, 8).unwrap();
        let mut provider = ScriptedProvider::new(vec![Ok(batch(vec![
            raw_call("call-effect", "slack.post", json!({"text":"hello"})),
            raw_call("call-tail", "tickets.read", json!({"number":7})),
        ]))]);
        let mut broker = FixtureBroker {
            catalog: vec![tool("slack.post"), tool("tickets.read")],
            outcomes: vec![Ok(ToolBrokerOutcome::ApprovalRequired(
                ToolApproval::new("approval-1", "Post hello").unwrap(),
            ))]
            .into(),
            ..FixtureBroker::default()
        };
        let mut harness = harness(limits);
        assert!(matches!(
            harness.drive(&mut provider, &mut broker),
            Ok(HarnessOutcome::AwaitingApproval(_))
        ));
        assert_eq!(broker.aborts, 0);

        assert!(matches!(
            harness.resume_with_tool_result(
                &mut broker,
                "call-effect",
                ToolResultPayload::complete(json!({"long":"0123456789"}))
            ),
            Err(HarnessFailure::ToolResultTooLarge {
                maximum: 8,
                actual: _
            })
        ));
        assert_eq!(broker.aborts, 1);
    }

    #[test]
    fn approval_in_a_batch_gates_later_calls_and_the_next_provider_round() {
        let mut provider = ScriptedProvider::new(vec![
            Ok(batch(vec![
                raw_call("call-read-1", "tickets.read", json!({"page":1})),
                raw_call("call-effect", "slack.post", json!({"text":"hello"})),
                raw_call("call-read-2", "issues.read", json!({"number":7})),
            ])),
            Ok(final_answer("Read, posted, and verified.")),
        ]);
        let mut broker = FixtureBroker {
            catalog: vec![
                tool("tickets.read"),
                tool("slack.post"),
                tool("issues.read"),
            ],
            outcomes: vec![
                Ok(ToolBrokerOutcome::Complete(ToolResultPayload::complete(
                    json!({"tickets":[]}),
                ))),
                Ok(ToolBrokerOutcome::ApprovalRequired(
                    ToolApproval::new("approval-1", "Post hello to the configured channel")
                        .unwrap(),
                )),
                Ok(ToolBrokerOutcome::Complete(ToolResultPayload::complete(
                    json!({"number":7}),
                ))),
            ]
            .into(),
            ..FixtureBroker::default()
        };
        let mut harness = harness(HarnessLimits::conversational());

        let HarnessOutcome::AwaitingApproval(pause) =
            harness.drive(&mut provider, &mut broker).unwrap()
        else {
            panic!("expected effect call to pause the batch");
        };
        assert_eq!(pause.call().call_id(), "call-effect");
        assert_eq!(harness.tool_calls(), 3);
        assert_eq!(provider.observed_rounds, [1]);
        assert_eq!(
            broker
                .calls
                .iter()
                .map(ToolCall::call_id)
                .collect::<Vec<_>>(),
            ["call-read-1", "call-effect"]
        );
        assert_eq!(harness.transcript().len(), 4);

        harness
            .resume_with_tool_result(
                &mut broker,
                "call-effect",
                ToolResultPayload::complete(json!({"posted":true})),
            )
            .unwrap();
        assert!(matches!(
            harness.drive(&mut provider, &mut broker),
            Ok(HarnessOutcome::Complete(_))
        ));
        assert_eq!(provider.observed_rounds, [1, 2]);
        assert_eq!(provider.observed_transcript_lengths, [1, 7]);
        assert_eq!(
            broker
                .calls
                .iter()
                .map(ToolCall::call_id)
                .collect::<Vec<_>>(),
            ["call-read-1", "call-effect", "call-read-2"]
        );
    }

    #[test]
    fn duplicate_catalog_and_duplicate_call_id_fail_closed() {
        let duplicate = tool("tickets.read");
        let mut provider = ScriptedProvider::new(vec![Ok(final_answer("unused"))]);
        let mut broker = FixtureBroker {
            catalog: vec![duplicate.clone(), duplicate],
            ..FixtureBroker::default()
        };
        assert_eq!(
            harness(HarnessLimits::conversational()).drive(&mut provider, &mut broker),
            Err(HarnessFailure::Catalog(CatalogError::DuplicateTool))
        );

        let limits = HarnessLimits::new(4, 4, 4, 2, 1024).unwrap();
        let mut provider = ScriptedProvider::new(vec![
            Ok(call("call-1", "tickets.read", json!({"page":1}))),
            Ok(call("call-1", "tickets.read", json!({"page":2}))),
        ]);
        let mut broker = FixtureBroker {
            catalog: vec![tool("tickets.read")],
            outcomes: vec![Ok(ToolBrokerOutcome::Complete(
                ToolResultPayload::complete(json!({})),
            ))]
            .into(),
            ..FixtureBroker::default()
        };
        assert_eq!(
            harness(limits).drive(&mut provider, &mut broker),
            Err(HarnessFailure::DuplicateCallId)
        );
        assert_eq!(broker.calls.len(), 1);
    }

    #[test]
    fn direct_enum_construction_cannot_bypass_transcript_bounds() {
        let invalid = TranscriptInput::Message {
            role: TranscriptRole::User,
            text: String::new(),
        };
        assert!(matches!(
            AgentHarness::new(
                "You are Monique.",
                "Policy remains outside persona.",
                vec![invalid],
                HarnessLimits::conversational(),
            ),
            Err(HarnessBuildError::InvalidTranscript)
        ));
    }
}
