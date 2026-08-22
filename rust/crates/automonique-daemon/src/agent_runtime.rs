// SPDX-License-Identifier: Elastic-2.0

//! Runtime adapter from the conversational harness to the policy tool broker.
//!
//! The provider supplies a correlation call id, a granted tool name, and JSON
//! arguments. The transport supplies the trusted replay namespace. The replay
//! key is derived from that namespace plus the canonical tool/argument value;
//! changing only a model-generated call id therefore cannot execute an effect
//! twice after redelivery.

use sha2::{Digest as _, Sha256};

use crate::agent_harness::{
    CatalogError, ToolApproval, ToolBroker, ToolBrokerFailure, ToolBrokerOutcome, ToolCall,
    ToolDefinition, ToolResultPayload,
};
use crate::agent_tool_broker::{
    AgentToolBroker, BrokerOutcome, GrantedToolCatalog, ToolDenial, ToolInvocation,
};

const MAX_REPLAY_NAMESPACE_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentRuntimeError {
    InvalidReplayNamespace,
    InvalidCatalog,
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
