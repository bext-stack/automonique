// SPDX-License-Identifier: Elastic-2.0

//! Canonical, encode-only RunSpec v1 projection.

use crate::{MAX_RUN_SPEC_BYTES, RunOrigin, RunSpec};
use automonique_protocol::context::{PolicyComponent, SuppliedComponent};
use automonique_protocol::identity::Actor;
use automonique_protocol::sandbox::{Budgets, SandboxSpec};
use automonique_protocol::wire::JsonValue;
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::os::unix::ffi::OsStrExt;

const DIGEST_DOMAIN: &[u8] = b"automonique.run-spec/v1\0";

/// A static, value-redacted RunSpec encoding refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunSpecEncodeError {
    /// The complete canonical document exceeds [`MAX_RUN_SPEC_BYTES`].
    DocumentTooLarge,
}

impl fmt::Display for RunSpecEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("canonical RunSpec document exceeds the byte limit")
    }
}

impl std::error::Error for RunSpecEncodeError {}

/// Domain-separated SHA-256 of canonical RunSpec v1 bytes.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunSpecDigest(String);

impl RunSpecDigest {
    /// Canonical lowercase `sha256:` spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RunSpecDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RunSpecDigest(<sha256>)")
    }
}

impl fmt::Display for RunSpecDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn string(value: impl Into<String>) -> JsonValue {
    JsonValue::String(value.into())
}

fn unsigned(value: u64) -> JsonValue {
    string(value.to_string())
}

fn optional(value: Option<&str>) -> JsonValue {
    value.map_or(JsonValue::Null, string)
}

fn object(entries: Vec<(&str, JsonValue)>) -> JsonValue {
    JsonValue::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn strings<'a>(values: impl IntoIterator<Item = &'a str>) -> JsonValue {
    JsonValue::Array(values.into_iter().map(string).collect())
}

fn hex(bytes: &[u8]) -> JsonValue {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    string(encoded)
}

pub(crate) fn encode(spec: &RunSpec) -> Result<Vec<u8>, RunSpecEncodeError> {
    let admission = spec.admission();
    let document = object(vec![
        (
            "argv_hex",
            JsonValue::Array(spec.arguments().iter().map(|v| hex(v.as_bytes())).collect()),
        ),
        (
            "artifact_grants",
            JsonValue::Array(
                admission
                    .artifact_grants()
                    .iter()
                    .map(encode_artifact)
                    .collect(),
            ),
        ),
        ("attempt_id", string(spec.attempt_id().as_str())),
        ("backend_id", string(spec.backend_id().as_str())),
        (
            "context_manifest",
            encode_context(admission.context_manifest()),
        ),
        (
            "credential_bindings",
            JsonValue::Array(
                admission
                    .credential_bindings()
                    .iter()
                    .map(encode_credential_binding)
                    .collect(),
            ),
        ),
        ("cwd_token", string(spec.cwd_token().as_str())),
        (
            "environment_hex",
            JsonValue::Array(
                spec.environment()
                    .iter()
                    .map(|(key, value)| {
                        object(vec![
                            ("key_hex", hex(key.as_bytes())),
                            ("value_hex", hex(value.as_bytes())),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("event_dialect", string(admission.event_dialect().as_str())),
        (
            "executable_path_hex",
            hex(spec.executable().as_os_str().as_bytes()),
        ),
        (
            "execution_plan_digest",
            string(admission.execution_plan_digest().digest().to_string()),
        ),
        (
            "executor_class",
            encode_executor(admission.executor_class()),
        ),
        (
            "extension_set_digest",
            string(admission.extension_set_digest().digest().to_string()),
        ),
        (
            "fallback_eligibility",
            strings(
                admission
                    .fallback_eligibility()
                    .iter()
                    .map(|mode| mode.as_str()),
            ),
        ),
        ("host_id", string(spec.host_id().as_str())),
        ("host_lifetime", string(spec.host_lifetime().as_str())),
        (
            "integration_mode",
            string(admission.integration_mode().as_str()),
        ),
        (
            "io_reservation",
            object(vec![
                (
                    "read_bytes",
                    unsigned(admission.io_reservation().read_bytes()),
                ),
                (
                    "write_bytes",
                    unsigned(admission.io_reservation().write_bytes()),
                ),
            ]),
        ),
        (
            "model_routing_digest",
            string(admission.model_routing_digest().digest().to_string()),
        ),
        ("origin", encode_origin(admission.origin())),
        (
            "persona_digest",
            string(admission.persona_digest().digest().to_string()),
        ),
        (
            "portability_policy",
            encode_portability(admission.portability_policy()),
        ),
        (
            "profile_digest",
            string(admission.profile_digest().digest().to_string()),
        ),
        ("prompt_delivery", encode_prompt(spec.prompt_delivery())),
        ("provider_binary", encode_binary(spec.provider_binary())),
        (
            "remote_attestation_policy",
            string(admission.remote_attestation_policy().as_str()),
        ),
        (
            "required_capabilities",
            JsonValue::Array(
                admission
                    .required_capabilities()
                    .iter()
                    .map(|capability| {
                        object(vec![
                            ("group", string(capability.group().as_str())),
                            ("name", string(capability.name())),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("run_id", string(spec.run_id().as_str())),
        ("sandbox_spec", encode_sandbox(spec.sandbox())),
        (
            "scheduler_reservation",
            encode_scheduler(admission.scheduler_reservation()),
        ),
        ("schema", string("automonique.run-spec/v1")),
        (
            "session_binding",
            admission
                .session_binding()
                .map_or(JsonValue::Null, encode_session),
        ),
        (
            "skillset_digest",
            string(admission.skillset_digest().digest().to_string()),
        ),
        (
            "toolset_digest",
            string(admission.toolset_digest().digest().to_string()),
        ),
        ("work_id", string(spec.work_id().as_str())),
        ("workspace", encode_workspace(spec.workspace())),
        (
            "workspace_registry_id",
            string(spec.workspace_registry_id().as_str()),
        ),
        (
            "workspace_reservation",
            unsigned(admission.workspace_reservation().bytes()),
        ),
    ]);
    let bytes = document.to_canonical_bytes();
    if bytes.len() > MAX_RUN_SPEC_BYTES {
        return Err(RunSpecEncodeError::DocumentTooLarge);
    }
    Ok(bytes)
}

pub(crate) fn digest(spec: &RunSpec) -> Result<RunSpecDigest, RunSpecEncodeError> {
    let bytes = encode(spec)?;
    let mut hash = Sha256::new();
    hash.update(DIGEST_DOMAIN);
    hash.update(bytes);
    Ok(RunSpecDigest(format!("sha256:{:x}", hash.finalize())))
}

fn encode_prompt(prompt: &crate::PromptDeliveryPlan) -> JsonValue {
    use crate::PromptDeliveryPlan::{BackendSession, ProtectedReference, Stdin};
    let (backend, protected) = match prompt {
        Stdin => (None, None),
        ProtectedReference(reference) => (None, Some(reference.as_str())),
        BackendSession(session) => (Some(session.as_str()), None),
    };
    object(vec![
        ("backend_session", optional(backend)),
        ("mode", string(prompt.as_str())),
        ("protected_reference", optional(protected)),
    ])
}

fn encode_binary(binary: &automonique_protocol::provider::BinaryProvenance) -> JsonValue {
    object(vec![
        ("digest", string(binary.digest())),
        ("schema_digest", optional(binary.schema_digest())),
        ("version", string(binary.version())),
    ])
}

fn encode_workspace(
    workspace: &automonique_protocol::workspace::WorkspaceRegistration,
) -> JsonValue {
    object(vec![
        ("base_revision", unsigned(workspace.base_revision().get())),
        ("canonical_source", string(workspace.canonical_source())),
        ("isolation", string(workspace.isolation().as_str())),
        ("snapshot", string(workspace.snapshot())),
        ("tenant", string(workspace.tenant())),
        ("token", string(workspace.token().as_str())),
    ])
}

fn encode_session(session: &automonique_protocol::provider::SessionBinding) -> JsonValue {
    object(vec![
        ("backend", string(session.backend())),
        ("provider_account", string(session.provider_account())),
        ("provider_namespace", string(session.provider_namespace())),
        ("session", string(session.session().as_str())),
        ("tenant", string(session.tenant())),
    ])
}

fn encode_context(context: &automonique_protocol::context::ContextManifest) -> JsonValue {
    object(vec![
        (
            "policy",
            JsonValue::Array(context.policy().iter().map(encode_policy).collect()),
        ),
        ("policy_revision", unsigned(context.policy_revision().get())),
        (
            "supplied",
            JsonValue::Array(context.supplied().iter().map(encode_supplied).collect()),
        ),
        (
            "token_budget",
            unsigned(context.token_budget().total_tokens()),
        ),
    ])
}

fn caps(caps: automonique_protocol::context::ComponentCaps) -> JsonValue {
    object(vec![
        ("byte_cap", unsigned(caps.byte_cap())),
        ("token_cap", unsigned(caps.token_cap())),
    ])
}

fn encode_policy(component: &PolicyComponent) -> JsonValue {
    object(vec![
        ("caps", caps(component.caps())),
        ("digest", string(component.digest())),
        ("redaction", string(component.redaction().as_str())),
        ("revision", unsigned(component.revision().get())),
        ("source", string(component.source())),
    ])
}

fn encode_supplied(component: &SuppliedComponent) -> JsonValue {
    object(vec![
        ("caps", caps(component.caps())),
        ("class", string(component.class().as_str())),
        ("digest", string(component.digest())),
        ("redaction", string(component.redaction().as_str())),
        ("source", string(component.source())),
        ("trust", string(component.trust().as_str())),
    ])
}

fn encode_origin(origin: &RunOrigin) -> JsonValue {
    let Some(details) = origin.non_interactive_details() else {
        return object(vec![
            ("automation_id", JsonValue::Null),
            ("causal_events", JsonValue::Array(vec![])),
            ("cause", JsonValue::Null),
            ("event_id", JsonValue::Null),
            ("goal_id", JsonValue::Null),
            ("source", string("interactive")),
            ("trigger_id", JsonValue::Null),
        ]);
    };
    object(vec![
        (
            "automation_id",
            optional(details.automation().map(|id| id.as_str())),
        ),
        (
            "causal_events",
            strings(details.causal_events().iter().map(|id| id.as_str())),
        ),
        ("cause", encode_cause(details.cause())),
        ("event_id", string(details.event_id().as_str())),
        ("goal_id", optional(details.goal().map(|id| id.as_str()))),
        ("source", string(details.source().as_str())),
        (
            "trigger_id",
            optional(details.trigger().map(|id| id.as_str())),
        ),
    ])
}

fn encode_actor(actor: &Actor) -> JsonValue {
    object(vec![
        ("id", string(actor.id())),
        ("tenant", string(actor.tenant())),
    ])
}

fn encode_cause(cause: &automonique_protocol::tools::NestedCause) -> JsonValue {
    object(vec![
        ("actor", encode_actor(cause.actor())),
        ("causation_id", string(cause.causation().as_str())),
        ("parent_id", optional(cause.parent().map(|id| id.as_str()))),
        ("run_id", string(cause.run().as_str())),
    ])
}

fn encode_executor(executor: &automonique_protocol::models::ExecutorClass) -> JsonValue {
    let coordinate = executor
        .coordinate()
        .map(|coordinate| {
            object(vec![
                ("resource_id", string(coordinate.resource_id())),
                ("vendor", string(coordinate.vendor())),
            ])
        })
        .unwrap_or(JsonValue::Null);
    object(vec![
        ("kind", string(executor.as_str())),
        ("remote_coordinate", coordinate),
    ])
}

fn encode_portability(policy: crate::PortabilityPolicy) -> JsonValue {
    object(vec![
        (
            "artifact_transfer",
            policy
                .artifact_transfer()
                .map(|mode| string(mode.as_str()))
                .unwrap_or(JsonValue::Null),
        ),
        ("kind", string(policy.as_str())),
        (
            "workspace_transfer",
            policy
                .workspace_transfer()
                .map(|mode| string(mode.as_str()))
                .unwrap_or(JsonValue::Null),
        ),
    ])
}

fn encode_scheduler(binding: &crate::SchedulerReservationBinding) -> JsonValue {
    object(vec![
        (
            "decision_digest",
            string(binding.decision_digest().digest().to_string()),
        ),
        ("id", string(binding.id().as_str())),
        ("revision", unsigned(binding.revision().get())),
    ])
}

fn encode_artifact(binding: &crate::ArtifactGrantBinding) -> JsonValue {
    object(vec![
        (
            "grant_digest",
            string(binding.grant_digest().digest().to_string()),
        ),
        ("id", string(binding.id().as_str())),
        ("revision", unsigned(binding.revision().get())),
    ])
}

fn encode_credential_binding(binding: &crate::CredentialBinding) -> JsonValue {
    object(vec![
        (
            "audiences",
            strings(binding.audiences().audiences().iter().map(String::as_str)),
        ),
        ("name", string(binding.name())),
        ("version", unsigned(binding.version().get())),
    ])
}

fn encode_sandbox(sandbox: &SandboxSpec) -> JsonValue {
    let profile = sandbox.profile();
    let nested = sandbox.nested_isolation();
    object(vec![
        ("actor", encode_actor(sandbox.actor())),
        (
            "allowlists",
            JsonValue::Array(
                sandbox
                    .allowlists()
                    .as_slice()
                    .iter()
                    .map(|entry| {
                        object(vec![
                            ("class", string(entry.class().as_str())),
                            ("name", string(entry.name())),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "approval_revision",
            unsigned(sandbox.approval_revision().get()),
        ),
        ("base_revision", unsigned(sandbox.base_revision().get())),
        ("budgets", encode_budgets(sandbox.budgets())),
        (
            "credentials",
            JsonValue::Array(
                sandbox
                    .credential_descriptors()
                    .iter()
                    .map(|descriptor| {
                        object(vec![
                            ("name", string(descriptor.name())),
                            ("recipient", string(descriptor.recipient().as_str())),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "nested_isolation",
            object(vec![
                ("extensions", string(nested.extensions().as_str())),
                ("nested_tools", string(nested.nested_tools().as_str())),
            ]),
        ),
        (
            "path_grants",
            JsonValue::Array(
                sandbox
                    .path_grants()
                    .as_slice()
                    .iter()
                    .map(|grant| {
                        object(vec![
                            ("access", string(grant.access().as_str())),
                            ("path", string(grant.path().as_str())),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("policy_digest", string(sandbox.policy_digest().to_string())),
        (
            "profile",
            object(vec![
                ("filesystem", string(profile.filesystem().as_str())),
                ("id", string(profile.id())),
                (
                    "tool_network",
                    string(profile.tool_network().access().as_str()),
                ),
                ("version", unsigned(u64::from(profile.version()))),
            ]),
        ),
        (
            "prohibited_capabilities",
            strings(
                sandbox
                    .prohibited_capabilities()
                    .iter()
                    .map(|name| name.as_str()),
            ),
        ),
        (
            "provider_account",
            string(sandbox.provider_account().as_str()),
        ),
        (
            "provider_control_egress",
            string(sandbox.provider_control_egress().access().as_str()),
        ),
        (
            "required_features",
            JsonValue::Array(
                sandbox
                    .required_features()
                    .iter()
                    .map(|feature| {
                        object(vec![
                            (
                                "accepted_implementations",
                                strings(
                                    feature
                                        .accepted_implementations()
                                        .iter()
                                        .map(ToString::to_string)
                                        .collect::<Vec<_>>()
                                        .iter()
                                        .map(String::as_str),
                                ),
                            ),
                            ("name", string(feature.name())),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "tool_workload_egress",
            string(sandbox.tool_workload_egress().access().as_str()),
        ),
        (
            "workspace_context",
            string(sandbox.workspace_context().to_string()),
        ),
    ])
}

fn encode_budgets(budgets: &Budgets) -> JsonValue {
    object(vec![
        ("artifact_bytes", unsigned(budgets.artifact().quantity())),
        (
            "cgroup_cpu_millicores",
            unsigned(budgets.cgroup_cpu().quantity()),
        ),
        (
            "cgroup_memory_bytes",
            unsigned(budgets.cgroup_memory().quantity()),
        ),
        (
            "rlimit_descriptors",
            unsigned(budgets.rlimit_descriptors().quantity()),
        ),
        (
            "rlimit_processes",
            unsigned(budgets.rlimit_processes().quantity()),
        ),
        ("spool_bytes", unsigned(budgets.spool().quantity())),
        (
            "temporary_storage_bytes",
            unsigned(budgets.temporary_storage().quantity()),
        ),
        ("timeout_millis", unsigned(budgets.timeout().quantity())),
    ])
}
