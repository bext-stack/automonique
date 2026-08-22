// SPDX-License-Identifier: Elastic-2.0

//! Conservative in-process custody for model-selected agent tools.
//!
//! The broker separates the model-facing invocation from trusted grant,
//! approval and replay state. A model may name only a tool and JSON arguments;
//! the caller supplies stable invocation coordinates and a catalog granted for
//! the current actor and conversation. Only an explicitly read-only tool whose
//! local descriptor requires no approval can execute immediately. Every other
//! invocation is frozen behind an opaque approval reference.

use std::collections::{BTreeMap, BTreeSet};

use automonique_protocol::tools::{ApprovalRequirement, SideEffectClass};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const MAX_TOOL_NAME_BYTES: usize = 100;
const MAX_DESCRIPTION_BYTES: usize = 500;
const MAX_INVOCATION_FIELD_BYTES: usize = 256;
const MAX_SCHEMA_BYTES: usize = 16 * 1024;
const MAX_ARGUMENT_BYTES: usize = 64 * 1024;
const MAX_SCHEMA_DEPTH: usize = 8;
const MAX_PROPERTIES: usize = 64;

/// How replayed calls to a tool are handled.
///
/// Both policies are fenced by the broker. `ReplaySafe` documents that the
/// implementation itself is safe to repeat, while `AtMostOnce` is mandatory
/// for effects and causes the broker-owned idempotency key to travel into the
/// executor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReplayPolicy {
    /// The operation is intrinsically safe to repeat, although an exact replay
    /// within this broker still receives its cached outcome.
    ReplaySafe,
    /// The operation may run at most once for one stable replay key.
    AtMostOnce,
}

impl ReplayPolicy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ReplaySafe => "replay_safe",
            Self::AtMostOnce => "at_most_once",
        }
    }
}

/// A locally declared tool contract safe to expose in a granted catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalToolDescriptor {
    name: String,
    description: String,
    input_schema: Value,
    side_effect: SideEffectClass,
    approval: ApprovalRequirement,
    replay: ReplayPolicy,
}

impl LocalToolDescriptor {
    /// Declare one tool. Schemas outside the broker's deliberately small JSON
    /// Schema subset are refused rather than partially interpreted.
    pub fn new(
        name: &str,
        description: &str,
        input_schema: Value,
        side_effect: SideEffectClass,
        approval: ApprovalRequirement,
        replay: ReplayPolicy,
    ) -> Result<Self, DescriptorError> {
        if !valid_tool_name(name) {
            return Err(DescriptorError::Name);
        }
        if description.trim().is_empty() || description.len() > MAX_DESCRIPTION_BYTES {
            return Err(DescriptorError::Description);
        }
        if serde_json::to_vec(&input_schema)
            .map_err(|_| DescriptorError::Schema)?
            .len()
            > MAX_SCHEMA_BYTES
            || input_schema.get("type").and_then(Value::as_str) != Some("object")
            || validate_schema(&input_schema, 0).is_err()
        {
            return Err(DescriptorError::Schema);
        }
        if side_effect != SideEffectClass::ReadOnly && replay != ReplayPolicy::AtMostOnce {
            return Err(DescriptorError::ReplayPolicy);
        }
        Ok(Self {
            name: name.to_owned(),
            description: description.to_owned(),
            input_schema: canonical_json(&input_schema),
            side_effect,
            approval,
            replay,
        })
    }

    /// Exact registry-facing name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Bounded description shown to the selecting model.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Pinned input schema.
    #[must_use]
    pub const fn input_schema(&self) -> &Value {
        &self.input_schema
    }

    /// Locally assigned effect class. Remote annotations cannot alter it.
    #[must_use]
    pub const fn side_effect(&self) -> SideEffectClass {
        self.side_effect
    }

    /// Locally assigned approval requirement.
    #[must_use]
    pub const fn approval(&self) -> ApprovalRequirement {
        self.approval
    }

    /// Locally assigned replay policy.
    #[must_use]
    pub const fn replay(&self) -> ReplayPolicy {
        self.replay
    }

    fn digest(&self) -> String {
        digest_fields(&[
            "automonique-agent-tool-descriptor-v1",
            &self.name,
            &canonical_json_text(&self.input_schema),
            self.side_effect.as_str(),
            self.approval.as_str(),
            self.replay.as_str(),
        ])
    }
}

/// Why a local descriptor was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorError {
    /// The tool name was empty, oversized, or outside the closed identifier
    /// grammar.
    Name,
    /// The model-facing description was empty or oversized.
    Description,
    /// The input contract was not in the supported strict subset.
    Schema,
    /// An effect was incorrectly declared safe to replay.
    ReplayPolicy,
}

/// One exact granted view of the registry.
///
/// Catalogs are revision-bound. Registering another tool makes every older
/// catalog stale, preventing a selection made under one capability view from
/// running under another.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantedToolCatalog {
    revision: u64,
    descriptors: BTreeMap<String, LocalToolDescriptor>,
}

impl GrantedToolCatalog {
    /// Registry revision this catalog was minted against.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Granted descriptors, sorted by exact name.
    #[must_use]
    pub fn descriptors(&self) -> Vec<&LocalToolDescriptor> {
        self.descriptors.values().collect()
    }

    /// Whether an exact, case-sensitive name is granted.
    #[must_use]
    pub fn permits(&self, name: &str) -> bool {
        self.descriptors.contains_key(name)
    }
}

/// Stable trusted coordinates attached to one model-selected invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolInvocation {
    invocation_id: String,
    replay_key: String,
    tool_name: String,
    arguments: Value,
}

impl ToolInvocation {
    /// Construct an invocation. The identifier is a correlation coordinate;
    /// the replay key must remain identical across transport redelivery.
    pub fn new(
        invocation_id: &str,
        replay_key: &str,
        tool_name: &str,
        arguments: Value,
    ) -> Result<Self, InvocationError> {
        if !valid_coordinate(invocation_id) {
            return Err(InvocationError::InvocationId);
        }
        if !valid_coordinate(replay_key) {
            return Err(InvocationError::ReplayKey);
        }
        if !valid_tool_name(tool_name) {
            return Err(InvocationError::ToolName);
        }
        if serde_json::to_vec(&arguments)
            .map_err(|_| InvocationError::Arguments)?
            .len()
            > MAX_ARGUMENT_BYTES
        {
            return Err(InvocationError::Arguments);
        }
        Ok(Self {
            invocation_id: invocation_id.to_owned(),
            replay_key: replay_key.to_owned(),
            tool_name: tool_name.to_owned(),
            arguments: canonical_json(&arguments),
        })
    }

    /// Correlation identifier for this planned call.
    #[must_use]
    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }

    /// Stable replay coordinate supplied by trusted transport state.
    #[must_use]
    pub fn replay_key(&self) -> &str {
        &self.replay_key
    }

    /// Exact selected tool name.
    #[must_use]
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    /// Canonicalized model-supplied arguments.
    #[must_use]
    pub const fn arguments(&self) -> &Value {
        &self.arguments
    }
}

/// Why an invocation could not be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvocationError {
    /// Invalid correlation identifier.
    InvocationId,
    /// Invalid trusted replay key.
    ReplayKey,
    /// Invalid tool name.
    ToolName,
    /// Arguments were oversized or could not be encoded.
    Arguments,
}

/// Request passed to one in-process executor after broker checks.
pub struct ToolExecutionRequest<'a> {
    invocation_id: &'a str,
    tool_name: &'a str,
    arguments: &'a Value,
    idempotency_key: &'a str,
}

impl<'a> ToolExecutionRequest<'a> {
    /// Invocation correlation identifier.
    #[must_use]
    pub const fn invocation_id(&self) -> &'a str {
        self.invocation_id
    }

    /// Exact local tool name.
    #[must_use]
    pub const fn tool_name(&self) -> &'a str {
        self.tool_name
    }

    /// Validated canonical arguments.
    #[must_use]
    pub const fn arguments(&self) -> &'a Value {
        self.arguments
    }

    /// Broker-owned stable key for downstream idempotency.
    #[must_use]
    pub const fn idempotency_key(&self) -> &'a str {
        self.idempotency_key
    }
}

/// Narrow adapter implemented by an existing typed surface.
pub trait AgentToolExecutor: Send {
    /// Execute one already admitted request. Errors must be content-free stable
    /// categories safe to expose to the broker.
    fn execute(&mut self, request: ToolExecutionRequest<'_>) -> Result<Value, &'static str>;
}

/// One exact effect request retained behind approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenToolRequest {
    invocation_id: String,
    tool_name: String,
    arguments: Value,
    approval_key: String,
    idempotency_key: String,
    digest: String,
}

impl FrozenToolRequest {
    /// Invocation correlation identifier.
    #[must_use]
    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }

    /// Exact tool selected before approval.
    #[must_use]
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    /// Canonical arguments frozen before approval.
    #[must_use]
    pub const fn arguments(&self) -> &Value {
        &self.arguments
    }

    /// Opaque approval reference suitable for a transport button.
    #[must_use]
    pub fn approval_key(&self) -> &str {
        &self.approval_key
    }

    /// Stable downstream idempotency key.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Digest covering replay coordinate, tool contract, and arguments.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Human decision applied to one frozen request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolApprovalDecision {
    /// Permit the exact frozen request to execute once.
    Approve,
    /// Reject it without calling the executor.
    Deny,
}

/// Closed reasons for refusing or failing one call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolDenial {
    /// The catalog was minted before the current registry revision.
    CatalogStale,
    /// The selected name was not present in the granted catalog.
    NotGranted,
    /// The granted name no longer maps to a registered executor.
    Unavailable,
    /// Arguments did not match the local schema.
    InvalidArguments,
    /// The unique-call budget was exhausted.
    CallLimit,
    /// An invocation identifier was reused with another replay coordinate.
    InvocationConflict,
    /// A replay key was reused for another request.
    ReplayConflict,
    /// No pending frozen request has this approval reference.
    ApprovalUnknown,
    /// The human denied the exact frozen request.
    ApprovalDenied,
    /// The descriptor changed after the request was frozen.
    DescriptorChanged,
    /// The typed executor refused or failed the admitted request.
    ExecutionFailed,
}

/// Complete broker disposition. No fourth state is implicit: effects either
/// wait behind approval or are denied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerOutcome {
    /// The executor returned a confirmed structured result.
    Complete {
        /// Original invocation identifier.
        invocation_id: String,
        /// Exact tool name.
        tool_name: String,
        /// Broker-owned downstream idempotency key.
        idempotency_key: String,
        /// Structured tool result.
        value: Value,
    },
    /// An effect is frozen and no executor has run yet.
    ApprovalRequired(FrozenToolRequest),
    /// Nothing ran, or an admitted executor failed without a confirmed result.
    Denied {
        /// Invocation identifier when one was available.
        invocation_id: Option<String>,
        /// Stable content-free refusal category.
        reason: ToolDenial,
    },
}

struct RegisteredTool {
    descriptor: LocalToolDescriptor,
    executor: Box<dyn AgentToolExecutor>,
}

#[derive(Clone)]
struct ReplayRecord {
    fingerprint: String,
    outcome: BrokerOutcome,
}

struct PendingApproval {
    frozen: FrozenToolRequest,
    replay_key: String,
    fingerprint: String,
    descriptor_digest: String,
}

/// In-process registry, grant boundary, approval custodian, and replay fence.
pub struct AgentToolBroker {
    tools: BTreeMap<String, RegisteredTool>,
    revision: u64,
    max_calls: usize,
    calls_used: usize,
    invocation_ids: BTreeMap<String, String>,
    replays: BTreeMap<String, ReplayRecord>,
    pending: BTreeMap<String, PendingApproval>,
    decisions: BTreeMap<String, BrokerOutcome>,
}

impl AgentToolBroker {
    /// Create an empty broker with a positive unique-call budget.
    #[must_use]
    pub fn new(max_calls: usize) -> Self {
        Self {
            tools: BTreeMap::new(),
            revision: 1,
            max_calls: max_calls.max(1),
            calls_used: 0,
            invocation_ids: BTreeMap::new(),
            replays: BTreeMap::new(),
            pending: BTreeMap::new(),
            decisions: BTreeMap::new(),
        }
    }

    /// Register one exact descriptor/executor pair. Duplicate names are
    /// refused and never replace a live implementation.
    pub fn register(
        &mut self,
        descriptor: LocalToolDescriptor,
        executor: Box<dyn AgentToolExecutor>,
    ) -> Result<(), RegisterError> {
        if self.tools.contains_key(descriptor.name()) {
            return Err(RegisterError::Duplicate);
        }
        self.tools.insert(
            descriptor.name.clone(),
            RegisteredTool {
                descriptor,
                executor,
            },
        );
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    /// Mint an exact granted catalog. Unknown names make the whole grant fail;
    /// silently dropping one would give the caller a capability view different
    /// from the one it intended to authorize.
    pub fn granted_catalog(&self, names: &[&str]) -> Result<GrantedToolCatalog, GrantError> {
        let mut unique = BTreeSet::new();
        let mut descriptors = BTreeMap::new();
        for name in names {
            if !unique.insert(*name) {
                continue;
            }
            let descriptor = self
                .tools
                .get(*name)
                .map(|registered| registered.descriptor.clone())
                .ok_or(GrantError::UnknownTool)?;
            descriptors.insert((*name).to_owned(), descriptor);
        }
        Ok(GrantedToolCatalog {
            revision: self.revision,
            descriptors,
        })
    }

    /// Number of unique admitted calls charged to this broker instance.
    #[must_use]
    pub const fn calls_used(&self) -> usize {
        self.calls_used
    }

    /// Validate, fence, and either execute or freeze one invocation.
    pub fn invoke(
        &mut self,
        catalog: &GrantedToolCatalog,
        invocation: ToolInvocation,
    ) -> BrokerOutcome {
        let denied = |reason| BrokerOutcome::Denied {
            invocation_id: Some(invocation.invocation_id.clone()),
            reason,
        };
        if catalog.revision != self.revision {
            return denied(ToolDenial::CatalogStale);
        }
        let Some(granted) = catalog.descriptors.get(&invocation.tool_name) else {
            return denied(ToolDenial::NotGranted);
        };
        let Some(registered) = self.tools.get(&invocation.tool_name) else {
            return denied(ToolDenial::Unavailable);
        };
        if registered.descriptor != *granted {
            return denied(ToolDenial::CatalogStale);
        }
        if validate_value(&granted.input_schema, &invocation.arguments, 0).is_err() {
            return denied(ToolDenial::InvalidArguments);
        }

        let fingerprint = invocation_fingerprint(&invocation, granted);
        if let Some(existing_key) = self.invocation_ids.get(&invocation.invocation_id)
            && existing_key != &invocation.replay_key
        {
            return denied(ToolDenial::InvocationConflict);
        }
        if let Some(existing) = self.replays.get(&invocation.replay_key) {
            if existing.fingerprint != fingerprint {
                return denied(ToolDenial::ReplayConflict);
            }
            let outcome = existing.outcome.clone();
            self.invocation_ids.insert(
                invocation.invocation_id.clone(),
                invocation.replay_key.clone(),
            );
            return outcome;
        }
        if self.calls_used >= self.max_calls {
            return denied(ToolDenial::CallLimit);
        }
        self.calls_used += 1;
        self.invocation_ids.insert(
            invocation.invocation_id.clone(),
            invocation.replay_key.clone(),
        );

        let digest = effect_digest(&invocation, granted);
        let idempotency_key = format!("atk-{digest}");
        let auto_run = granted.side_effect == SideEffectClass::ReadOnly
            && granted.approval == ApprovalRequirement::None;
        if auto_run {
            let outcome = self.execute(
                &invocation.invocation_id,
                &invocation.tool_name,
                &invocation.arguments,
                &idempotency_key,
            );
            self.replays.insert(
                invocation.replay_key,
                ReplayRecord {
                    fingerprint,
                    outcome: outcome.clone(),
                },
            );
            return outcome;
        }

        let approval_key = format!("atp-{}", &digest[..32]);
        let frozen = FrozenToolRequest {
            invocation_id: invocation.invocation_id,
            tool_name: invocation.tool_name,
            arguments: invocation.arguments,
            approval_key: approval_key.clone(),
            idempotency_key,
            digest,
        };
        let outcome = BrokerOutcome::ApprovalRequired(frozen.clone());
        self.replays.insert(
            invocation.replay_key.clone(),
            ReplayRecord {
                fingerprint: fingerprint.clone(),
                outcome: outcome.clone(),
            },
        );
        self.pending.insert(
            approval_key,
            PendingApproval {
                frozen,
                replay_key: invocation.replay_key,
                fingerprint,
                descriptor_digest: granted.digest(),
            },
        );
        outcome
    }

    /// Apply one human decision to the exact frozen request. Repeated decisions
    /// return the already recorded outcome and never call an executor twice.
    pub fn decide(
        &mut self,
        catalog: &GrantedToolCatalog,
        approval_key: &str,
        decision: ToolApprovalDecision,
    ) -> BrokerOutcome {
        if let Some(outcome) = self.decisions.get(approval_key) {
            return outcome.clone();
        }
        let Some(pending) = self.pending.remove(approval_key) else {
            return BrokerOutcome::Denied {
                invocation_id: None,
                reason: ToolDenial::ApprovalUnknown,
            };
        };
        let invocation_id = pending.frozen.invocation_id.clone();
        if decision == ToolApprovalDecision::Deny {
            let outcome = BrokerOutcome::Denied {
                invocation_id: Some(invocation_id),
                reason: ToolDenial::ApprovalDenied,
            };
            self.finish_decision(approval_key, pending, outcome.clone());
            return outcome;
        }
        if catalog.revision != self.revision {
            let outcome = BrokerOutcome::Denied {
                invocation_id: Some(invocation_id),
                reason: ToolDenial::CatalogStale,
            };
            self.finish_decision(approval_key, pending, outcome.clone());
            return outcome;
        }
        let descriptor = catalog
            .descriptors
            .get(&pending.frozen.tool_name)
            .filter(|descriptor| descriptor.digest() == pending.descriptor_digest);
        let Some(descriptor) = descriptor else {
            let outcome = BrokerOutcome::Denied {
                invocation_id: Some(invocation_id),
                reason: ToolDenial::DescriptorChanged,
            };
            self.finish_decision(approval_key, pending, outcome.clone());
            return outcome;
        };
        if validate_value(descriptor.input_schema(), &pending.frozen.arguments, 0).is_err() {
            let outcome = BrokerOutcome::Denied {
                invocation_id: Some(invocation_id),
                reason: ToolDenial::InvalidArguments,
            };
            self.finish_decision(approval_key, pending, outcome.clone());
            return outcome;
        }
        let outcome = self.execute(
            &pending.frozen.invocation_id,
            &pending.frozen.tool_name,
            &pending.frozen.arguments,
            &pending.frozen.idempotency_key,
        );
        self.finish_decision(approval_key, pending, outcome.clone());
        outcome
    }

    fn execute(
        &mut self,
        invocation_id: &str,
        tool_name: &str,
        arguments: &Value,
        idempotency_key: &str,
    ) -> BrokerOutcome {
        let Some(registered) = self.tools.get_mut(tool_name) else {
            return BrokerOutcome::Denied {
                invocation_id: Some(invocation_id.to_owned()),
                reason: ToolDenial::Unavailable,
            };
        };
        let request = ToolExecutionRequest {
            invocation_id,
            tool_name,
            arguments,
            idempotency_key,
        };
        match registered.executor.execute(request) {
            Ok(value) => BrokerOutcome::Complete {
                invocation_id: invocation_id.to_owned(),
                tool_name: tool_name.to_owned(),
                idempotency_key: idempotency_key.to_owned(),
                value,
            },
            Err(_) => BrokerOutcome::Denied {
                invocation_id: Some(invocation_id.to_owned()),
                reason: ToolDenial::ExecutionFailed,
            },
        }
    }

    fn finish_decision(
        &mut self,
        approval_key: &str,
        pending: PendingApproval,
        outcome: BrokerOutcome,
    ) {
        self.replays.insert(
            pending.replay_key,
            ReplayRecord {
                fingerprint: pending.fingerprint,
                outcome: outcome.clone(),
            },
        );
        self.decisions.insert(approval_key.to_owned(), outcome);
    }
}

/// Why registration failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisterError {
    /// Another executor already owns this exact name.
    Duplicate,
}

/// Why a catalog grant could not be minted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantError {
    /// At least one requested exact name is not registered.
    UnknownTool,
}

fn valid_tool_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOOL_NAME_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

fn valid_coordinate(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_INVOCATION_FIELD_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\\' && byte != b'\"')
}

fn validate_schema(schema: &Value, depth: usize) -> Result<(), ()> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(());
    }
    let object = schema.as_object().ok_or(())?;
    let kind = object.get("type").and_then(Value::as_str).ok_or(())?;
    match kind {
        "object" => {
            if !object.keys().all(|key| {
                matches!(
                    key.as_str(),
                    "type" | "properties" | "required" | "additionalProperties"
                )
            }) || object.get("additionalProperties").and_then(Value::as_bool) != Some(false)
            {
                return Err(());
            }
            let properties = object
                .get("properties")
                .and_then(Value::as_object)
                .ok_or(())?;
            if properties.len() > MAX_PROPERTIES
                || properties.iter().any(|(name, child)| {
                    !valid_property_name(name) || validate_schema(child, depth + 1).is_err()
                })
            {
                return Err(());
            }
            let mut required = BTreeSet::new();
            for name in required_fields(object)? {
                let name = name.as_str().ok_or(())?;
                if !properties.contains_key(name) || !required.insert(name) {
                    return Err(());
                }
            }
            Ok(())
        }
        "array" => {
            if !object
                .keys()
                .all(|key| matches!(key.as_str(), "type" | "items"))
            {
                return Err(());
            }
            validate_schema(object.get("items").ok_or(())?, depth + 1)
        }
        "string" | "number" | "integer" | "boolean" | "null" => object
            .keys()
            .all(|key| key == "type")
            .then_some(())
            .ok_or(()),
        _ => Err(()),
    }
}

fn validate_value(schema: &Value, value: &Value, depth: usize) -> Result<(), ()> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(());
    }
    let schema = schema.as_object().ok_or(())?;
    match schema.get("type").and_then(Value::as_str).ok_or(())? {
        "object" => {
            let value = value.as_object().ok_or(())?;
            let properties = schema
                .get("properties")
                .and_then(Value::as_object)
                .ok_or(())?;
            if value.keys().any(|name| !properties.contains_key(name)) {
                return Err(());
            }
            for name in required_fields(schema)? {
                if !value.contains_key(name.as_str().ok_or(())?) {
                    return Err(());
                }
            }
            for (name, child) in value {
                validate_value(properties.get(name).ok_or(())?, child, depth + 1)?;
            }
            Ok(())
        }
        "array" => {
            let values = value.as_array().ok_or(())?;
            let items = schema.get("items").ok_or(())?;
            values
                .iter()
                .try_for_each(|value| validate_value(items, value, depth + 1))
        }
        "string" if value.is_string() => Ok(()),
        "number" if value.is_number() => Ok(()),
        "integer" if value.as_i64().is_some() || value.as_u64().is_some() => Ok(()),
        "boolean" if value.is_boolean() => Ok(()),
        "null" if value.is_null() => Ok(()),
        _ => Err(()),
    }
}

fn valid_property_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOOL_NAME_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn required_fields(object: &serde_json::Map<String, Value>) -> Result<&[Value], ()> {
    match object.get("required") {
        None => Ok(&[]),
        Some(value) => value.as_array().map(Vec::as_slice).ok_or(()),
    }
}

fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), canonical_json(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(canonical_json).collect()),
        _ => value.clone(),
    }
}

fn canonical_json_text(value: &Value) -> String {
    serde_json::to_string(&canonical_json(value)).expect("JSON value always serializes")
}

fn invocation_fingerprint(invocation: &ToolInvocation, descriptor: &LocalToolDescriptor) -> String {
    digest_fields(&[
        "automonique-agent-tool-invocation-v1",
        &invocation.replay_key,
        &invocation.tool_name,
        &canonical_json_text(&invocation.arguments),
        &descriptor.digest(),
    ])
}

fn effect_digest(invocation: &ToolInvocation, descriptor: &LocalToolDescriptor) -> String {
    digest_fields(&[
        "automonique-agent-tool-effect-v1",
        &invocation.replay_key,
        &invocation.tool_name,
        &canonical_json_text(&invocation.arguments),
        &descriptor.digest(),
    ])
}

fn digest_fields(fields: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for field in fields {
        let length = u64::try_from(field.len()).expect("bounded broker field length fits u64");
        hasher.update(length.to_be_bytes());
        hasher.update(field.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use serde_json::json;

    use super::*;

    #[derive(Clone)]
    struct RecordingExecutor {
        calls: Arc<Mutex<Vec<(String, Value, String)>>>,
    }

    impl AgentToolExecutor for RecordingExecutor {
        fn execute(&mut self, request: ToolExecutionRequest<'_>) -> Result<Value, &'static str> {
            self.calls.lock().unwrap().push((
                request.tool_name().to_owned(),
                request.arguments().clone(),
                request.idempotency_key().to_owned(),
            ));
            Ok(json!({"observed": request.arguments()}))
        }
    }

    fn schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "ticket": {"type": "integer"},
                "detail": {"type": "string"}
            },
            "required": ["ticket"],
            "additionalProperties": false
        })
    }

    fn descriptor(
        name: &str,
        side_effect: SideEffectClass,
        approval: ApprovalRequirement,
    ) -> LocalToolDescriptor {
        LocalToolDescriptor::new(
            name,
            "A bounded test capability.",
            schema(),
            side_effect,
            approval,
            if side_effect == SideEffectClass::ReadOnly {
                ReplayPolicy::ReplaySafe
            } else {
                ReplayPolicy::AtMostOnce
            },
        )
        .unwrap()
    }

    fn invocation(id: &str, key: &str, name: &str, arguments: Value) -> ToolInvocation {
        ToolInvocation::new(id, key, name, arguments).unwrap()
    }

    #[test]
    fn only_exactly_granted_read_without_approval_runs_automatically() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut broker = AgentToolBroker::new(4);
        broker
            .register(
                descriptor(
                    "tickets.read",
                    SideEffectClass::ReadOnly,
                    ApprovalRequirement::None,
                ),
                Box::new(RecordingExecutor {
                    calls: calls.clone(),
                }),
            )
            .unwrap();
        let catalog = broker.granted_catalog(&["tickets.read"]).unwrap();

        let result = broker.invoke(
            &catalog,
            invocation(
                "call-1",
                "event-1:call-1",
                "tickets.read",
                json!({"ticket": 7}),
            ),
        );
        assert!(matches!(result, BrokerOutcome::Complete { .. }));
        assert_eq!(calls.lock().unwrap().len(), 1);

        let refused = broker.invoke(
            &catalog,
            invocation(
                "call-2",
                "event-1:call-2",
                "tickets.write",
                json!({"ticket": 7}),
            ),
        );
        assert!(matches!(
            refused,
            BrokerOutcome::Denied {
                reason: ToolDenial::NotGranted,
                ..
            }
        ));
        assert_eq!(
            ToolInvocation::new(
                "call-3",
                "event-1:call-3",
                "Tickets.read",
                json!({"ticket": 7})
            ),
            Err(InvocationError::ToolName)
        );
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn local_schema_rejects_missing_extra_and_wrong_typed_arguments() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut broker = AgentToolBroker::new(8);
        broker
            .register(
                descriptor(
                    "tickets.read",
                    SideEffectClass::ReadOnly,
                    ApprovalRequirement::None,
                ),
                Box::new(RecordingExecutor {
                    calls: calls.clone(),
                }),
            )
            .unwrap();
        let catalog = broker.granted_catalog(&["tickets.read"]).unwrap();
        for (index, arguments) in [
            json!({}),
            json!({"ticket": 1, "unknown": true}),
            json!({"ticket": "one"}),
        ]
        .into_iter()
        .enumerate()
        {
            let result = broker.invoke(
                &catalog,
                invocation(
                    &format!("call-{index}"),
                    &format!("event:{index}"),
                    "tickets.read",
                    arguments,
                ),
            );
            assert!(matches!(
                result,
                BrokerOutcome::Denied {
                    reason: ToolDenial::InvalidArguments,
                    ..
                }
            ));
        }
        assert!(calls.lock().unwrap().is_empty());
        assert_eq!(broker.calls_used(), 0);
    }

    #[test]
    fn every_effect_is_frozen_even_when_descriptor_says_no_approval() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut broker = AgentToolBroker::new(4);
        broker
            .register(
                descriptor(
                    "slack.post",
                    SideEffectClass::ExternalEffect,
                    ApprovalRequirement::None,
                ),
                Box::new(RecordingExecutor {
                    calls: calls.clone(),
                }),
            )
            .unwrap();
        let catalog = broker.granted_catalog(&["slack.post"]).unwrap();
        let call = invocation(
            "call-1",
            "slack:event-9:call-1",
            "slack.post",
            json!({"ticket": 9, "detail": "hello"}),
        );

        let first = broker.invoke(&catalog, call.clone());
        let replay = broker.invoke(&catalog, call);
        let BrokerOutcome::ApprovalRequired(frozen) = first else {
            panic!("effect must wait for approval");
        };
        assert_eq!(replay, BrokerOutcome::ApprovalRequired(frozen.clone()));
        assert!(frozen.idempotency_key().starts_with("atk-"));
        assert!(calls.lock().unwrap().is_empty());
        assert_eq!(broker.calls_used(), 1);
    }

    #[test]
    fn approval_executes_frozen_effect_once_and_replays_receipt() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut broker = AgentToolBroker::new(4);
        broker
            .register(
                descriptor(
                    "github.reply",
                    SideEffectClass::ExternalEffect,
                    ApprovalRequirement::PerInvocation,
                ),
                Box::new(RecordingExecutor {
                    calls: calls.clone(),
                }),
            )
            .unwrap();
        let catalog = broker.granted_catalog(&["github.reply"]).unwrap();
        let call = invocation(
            "call-1",
            "telegram:update-4:call-1",
            "github.reply",
            json!({"ticket": 4, "detail": "done"}),
        );
        let BrokerOutcome::ApprovalRequired(frozen) = broker.invoke(&catalog, call.clone()) else {
            panic!("effect must wait");
        };

        let completed = broker.decide(
            &catalog,
            frozen.approval_key(),
            ToolApprovalDecision::Approve,
        );
        assert!(matches!(completed, BrokerOutcome::Complete { .. }));
        assert_eq!(
            broker.decide(
                &catalog,
                frozen.approval_key(),
                ToolApprovalDecision::Approve
            ),
            completed
        );
        assert_eq!(broker.invoke(&catalog, call), completed);
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn denial_is_final_and_never_calls_the_executor() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut broker = AgentToolBroker::new(2);
        broker
            .register(
                descriptor(
                    "memory.forget",
                    SideEffectClass::WorkspaceWrite,
                    ApprovalRequirement::PerInvocation,
                ),
                Box::new(RecordingExecutor {
                    calls: calls.clone(),
                }),
            )
            .unwrap();
        let catalog = broker.granted_catalog(&["memory.forget"]).unwrap();
        let BrokerOutcome::ApprovalRequired(frozen) = broker.invoke(
            &catalog,
            invocation(
                "call-1",
                "event-1:call-1",
                "memory.forget",
                json!({"ticket": 1}),
            ),
        ) else {
            panic!("effect must wait");
        };
        let denied = broker.decide(&catalog, frozen.approval_key(), ToolApprovalDecision::Deny);
        assert!(matches!(
            denied,
            BrokerOutcome::Denied {
                reason: ToolDenial::ApprovalDenied,
                ..
            }
        ));
        assert_eq!(
            broker.decide(
                &catalog,
                frozen.approval_key(),
                ToolApprovalDecision::Approve
            ),
            denied
        );
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn replay_and_invocation_collisions_fail_closed() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut broker = AgentToolBroker::new(4);
        broker
            .register(
                descriptor(
                    "tickets.read",
                    SideEffectClass::ReadOnly,
                    ApprovalRequirement::None,
                ),
                Box::new(RecordingExecutor {
                    calls: calls.clone(),
                }),
            )
            .unwrap();
        let catalog = broker.granted_catalog(&["tickets.read"]).unwrap();
        let _ = broker.invoke(
            &catalog,
            invocation("call-1", "replay-1", "tickets.read", json!({"ticket": 1})),
        );
        let exact_alias = broker.invoke(
            &catalog,
            invocation("call-2", "replay-1", "tickets.read", json!({"ticket": 1})),
        );
        assert!(matches!(exact_alias, BrokerOutcome::Complete { .. }));
        let replay_conflict = broker.invoke(
            &catalog,
            invocation("call-3", "replay-1", "tickets.read", json!({"ticket": 2})),
        );
        assert!(matches!(
            replay_conflict,
            BrokerOutcome::Denied {
                reason: ToolDenial::ReplayConflict,
                ..
            }
        ));
        let invocation_conflict = broker.invoke(
            &catalog,
            invocation("call-2", "replay-2", "tickets.read", json!({"ticket": 1})),
        );
        assert!(matches!(
            invocation_conflict,
            BrokerOutcome::Denied {
                reason: ToolDenial::InvocationConflict,
                ..
            }
        ));
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn exact_replays_do_not_spend_the_call_budget_twice() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut broker = AgentToolBroker::new(1);
        broker
            .register(
                descriptor(
                    "tickets.read",
                    SideEffectClass::ReadOnly,
                    ApprovalRequirement::None,
                ),
                Box::new(RecordingExecutor {
                    calls: calls.clone(),
                }),
            )
            .unwrap();
        let catalog = broker.granted_catalog(&["tickets.read"]).unwrap();
        let first = invocation("call-1", "key-1", "tickets.read", json!({"ticket": 1}));
        let result = broker.invoke(&catalog, first.clone());
        assert_eq!(broker.invoke(&catalog, first), result);
        let exhausted = broker.invoke(
            &catalog,
            invocation("call-2", "key-2", "tickets.read", json!({"ticket": 2})),
        );
        assert!(matches!(
            exhausted,
            BrokerOutcome::Denied {
                reason: ToolDenial::CallLimit,
                ..
            }
        ));
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn catalog_revision_and_effect_replay_policy_are_fail_closed() {
        assert_eq!(
            LocalToolDescriptor::new(
                "bad.write",
                "Bad replay declaration.",
                schema(),
                SideEffectClass::ExternalEffect,
                ApprovalRequirement::None,
                ReplayPolicy::ReplaySafe,
            ),
            Err(DescriptorError::ReplayPolicy)
        );

        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut broker = AgentToolBroker::new(4);
        broker
            .register(
                descriptor(
                    "tickets.read",
                    SideEffectClass::ReadOnly,
                    ApprovalRequirement::None,
                ),
                Box::new(RecordingExecutor {
                    calls: calls.clone(),
                }),
            )
            .unwrap();
        let stale = broker.granted_catalog(&["tickets.read"]).unwrap();
        broker
            .register(
                descriptor(
                    "status.read",
                    SideEffectClass::ReadOnly,
                    ApprovalRequirement::None,
                ),
                Box::new(RecordingExecutor {
                    calls: calls.clone(),
                }),
            )
            .unwrap();
        let result = broker.invoke(
            &stale,
            invocation("call-1", "key-1", "tickets.read", json!({"ticket": 1})),
        );
        assert!(matches!(
            result,
            BrokerOutcome::Denied {
                reason: ToolDenial::CatalogStale,
                ..
            }
        ));
        assert!(calls.lock().unwrap().is_empty());
    }
}
