// SPDX-License-Identifier: Elastic-2.0

//! Runtime adapter from the conversational harness to the policy tool broker.
//!
//! The provider supplies a correlation call id, a granted tool name, and JSON
//! arguments. The transport supplies the trusted replay namespace. The replay
//! key is derived from that namespace plus the canonical tool/argument value;
//! changing only a model-generated call id therefore cannot execute an effect
//! twice after redelivery.

use sha2::{Digest as _, Sha256};

use automonique_protocol::tools::{ApprovalRequirement, SideEffectClass};

use crate::agent_harness::{
    AgentHarness, AgentProvider, CatalogError, HarnessFailure, HarnessLimits, HarnessOutcome,
    ProviderDecision, ProviderFailure, ProviderTurn, ToolApproval, ToolBroker, ToolBrokerFailure,
    ToolBrokerOutcome, ToolCall, ToolDefinition, ToolResultPayload, TranscriptInput,
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
}

impl ToolBroker for AgentRuntimeBroker<'_> {
    fn catalog(&mut self) -> Result<Vec<ToolDefinition>, CatalogError> {
        Ok(self.definitions.clone())
    }

    fn invoke(&mut self, call: &ToolCall) -> Result<ToolBrokerOutcome, ToolBrokerFailure> {
        let invocation = ToolInvocation::new(
            call.call_id(),
            &self.replay_key(call),
            call.tool(),
            call.arguments().clone(),
        )
        .map_err(|_| ToolBrokerFailure::InvalidArguments)?;
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
    use std::sync::{Arc, Mutex};

    use automonique_protocol::tools::{ApprovalRequirement, SideEffectClass};
    use serde_json::{Value, json};

    use super::*;
    use crate::agent_tool_broker::{
        AgentToolExecutor, LocalToolDescriptor, ReplayPolicy, ToolExecutionRequest,
    };

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
}
