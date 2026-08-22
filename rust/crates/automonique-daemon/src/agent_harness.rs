// SPDX-License-Identifier: Elastic-2.0

//! Bounded, transport-independent conversational agent orchestration.
//!
//! The harness owns only the model/tool loop. It does not authenticate an
//! actor, decide an approval, open a provider connection, or execute a tool.
//! Those authorities stay behind [`AgentProvider`] and [`ToolBroker`]. A model
//! may select one tool from the catalog it is shown; the broker remains the
//! component that validates arguments and either returns a bounded result or
//! pauses the loop for approval.
//!
//! Persona and policy are separate inputs. Persona may shape Monique's voice,
//! but it cannot alter the catalog, budgets, approval custody, or broker.

use std::collections::{BTreeMap, BTreeSet};
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

pub const MAX_ROUNDS_CEILING: u16 = 32;
pub const MAX_TOOL_CALLS_CEILING: u16 = 64;
pub const MAX_CALLS_PER_TOOL_CEILING: u16 = 16;
pub const MAX_IDENTICAL_CALLS_CEILING: u16 = 4;
pub const MAX_TOOL_RESULT_BYTES_CEILING: usize = 1024 * 1024;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderDecision {
    Final(FinalAnswer),
    ToolCall(ToolCall),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionError {
    InvalidIdentifier,
    InvalidArguments,
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
    }
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
                    // Reserve both the call and its eventual result before the
                    // broker is reached. A tool must not execute if its result
                    // cannot be represented in the bounded transcript.
                    if self.transcript.len().saturating_add(2) > MAX_TRANSCRIPT_ENTRIES {
                        return self.fail(HarnessFailure::TranscriptFull);
                    }
                    if !self
                        .catalog
                        .as_deref()
                        .unwrap_or(&[])
                        .iter()
                        .any(|tool| tool.id == call.tool)
                    {
                        return self.fail(HarnessFailure::UnknownTool);
                    }
                    if !self.call_ids.insert(call.call_id.clone()) {
                        return self.fail(HarnessFailure::DuplicateCallId);
                    }
                    if self.tool_calls >= self.limits.max_tool_calls {
                        return self.fail(HarnessFailure::BudgetExceeded(BudgetKind::ToolCalls));
                    }
                    let per_tool = self.calls_per_tool.get(&call.tool).copied().unwrap_or(0);
                    if per_tool >= self.limits.max_calls_per_tool {
                        return self.fail(HarnessFailure::BudgetExceeded(BudgetKind::CallsPerTool));
                    }
                    let digest = call.digest();
                    let identical = self.identical_calls.get(&digest).copied().unwrap_or(0);
                    if identical >= self.limits.max_identical_calls {
                        return self
                            .fail(HarnessFailure::BudgetExceeded(BudgetKind::IdenticalCall));
                    }

                    self.tool_calls = self.tool_calls.saturating_add(1);
                    self.calls_per_tool
                        .insert(call.tool.clone(), per_tool.saturating_add(1));
                    self.identical_calls
                        .insert(digest, identical.saturating_add(1));
                    self.transcript
                        .push(TranscriptInput::ToolCall(call.clone()));

                    match broker.invoke(&call) {
                        Ok(ToolBrokerOutcome::Complete(payload)) => {
                            if let Err(error) = self.append_tool_result(&call, payload) {
                                return self.fail(error);
                            }
                        }
                        Ok(ToolBrokerOutcome::ApprovalRequired(approval)) => {
                            let pause = ApprovalPause { approval, call };
                            self.state = HarnessState::AwaitingApproval(pause.clone());
                            return Ok(HarnessOutcome::AwaitingApproval(pause));
                        }
                        Err(error) => return self.fail(HarnessFailure::Tool(error)),
                    }
                }
            }
        }
    }

    /// Continue after the external approval custodian settled and executed the
    /// exact paused call. This method validates binding and result size; it does
    /// not interpret approval evidence or execute the tool itself.
    pub fn resume_with_tool_result(
        &mut self,
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
            self.state = HarnessState::Failed;
            return Err(error);
        }
        self.state = HarnessState::Ready;
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
fn canonical_json_bytes(value: &Value) -> Vec<u8> {
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
        outcomes: VecDeque<Result<ToolBrokerOutcome, ToolBrokerFailure>>,
        calls: Vec<ToolCall>,
        catalog_reads: usize,
    }

    impl ToolBroker for FixtureBroker {
        fn catalog(&mut self) -> Result<Vec<ToolDefinition>, CatalogError> {
            self.catalog_reads += 1;
            Ok(self.catalog.clone())
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
        assert!(matches!(
            harness(result).drive(&mut provider, &mut broker),
            Err(HarnessFailure::ToolResultTooLarge {
                maximum: 8,
                actual: _
            })
        ));
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
            harness.resume_with_tool_result("wrong-call", ToolResultPayload::complete(json!({}))),
            Err(HarnessFailure::ApprovalResultMismatch)
        );
        harness
            .resume_with_tool_result(
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
