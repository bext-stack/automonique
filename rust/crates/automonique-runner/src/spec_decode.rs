// SPDX-License-Identifier: Elastic-2.0

//! Strict canonical RunSpec v1 decoding.

use crate::{
    AdmissionFields, AdmissionFieldsParts, ArtifactGrantBinding, ArtifactGrantBindings,
    ArtifactGrantDigest, ArtifactGrantId, BackendPromptSession, CredentialBinding, CwdToken,
    ExecutionPlanDigest, ExtensionSetDigest, FallbackEligibility, IntegrationMode, IoReservation,
    MAX_ARTIFACT_GRANT_BINDINGS, MAX_FALLBACK_MODES, MAX_ORIGIN_CAUSES, MAX_RUN_SPEC_BYTES,
    ModelRoutingDigest, OriginCoordinate, PersonaDigest, PortabilityPolicy, ProfileDigest,
    PromptDeliveryPlan, ProtectedPromptReference, RemoteAttestationPolicy, RequiredCapabilities,
    RunCoordinates, RunOrigin, RunOriginSource, RunSpec, RunSpecParts, RunnerEventDialect,
    SchedulerDecisionDigest, SchedulerReservationBinding, SchedulerReservationId, SkillsetDigest,
    ToolsetDigest, WorkspaceRegistryId, WorkspaceReservation,
};
use automonique_protocol::automation::DurableId;
use automonique_protocol::context::{
    ComponentCaps, ContextManifest, PolicyComponent, RedactionOutcome, SuppliedClass,
    SuppliedComponent, TokenBudget, TrustClass,
};
use automonique_protocol::host::{AttemptId, HostId, HostLifetime, WorkId};
use automonique_protocol::identity::Actor;
use automonique_protocol::models::{
    ArtifactTransfer, ExecutorClass, ProviderAccountId, RemoteCoordinate, WorkspaceTransfer,
};
use automonique_protocol::primitives::Revision;
use automonique_protocol::provider::{
    BinaryProvenance, Capability, CapabilityGroup, ProviderSessionId, SessionBinding,
};
use automonique_protocol::sandbox::{
    AllowlistClass, AllowlistEntry, BudgetQuantities, Budgets, CredentialDescriptor,
    CredentialDescriptors, Digest, DigestAlgorithm, ExecutionAllowlists, ExecutionBackendId,
    FilesystemAccess, ImplementationDigest, IsolationRequirement, MAX_SANDBOX_ENTRIES,
    NestedIsolation, NetworkAccess, PathAccess, PathGrant, PathGrants, PolicyDigest, ProcessClass,
    ProhibitedCapabilities, ProviderControlEgress, RequiredFeature, RequiredFeatures,
    SandboxProfile, SandboxSpec, SandboxSpecParts, ToolWorkloadEgress, WorkspaceContextHash,
};
use automonique_protocol::tools::{CausationId, CredentialAudiences, NestedCause, RunId};
use automonique_protocol::wire::{self, JsonValue, MAX_JSON_ENTRIES};
use automonique_protocol::workspace::{IsolationKind, WorkspaceRegistration, WorkspaceToken};
use std::ffi::OsString;
use std::fmt;
use std::num::NonZeroU64;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

/// A static, input-redacted RunSpec v1 decoding refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunSpecDecodeError {
    /// Input exceeded the whole-document limit before parsing.
    DocumentTooLarge,
    /// Input was not strict canonical JSON.
    InvalidCanonicalJson,
    /// An object did not have its one exact closed key set.
    ObjectShape(&'static str),
    /// A scalar, enum, null, hex, decimal, digest, or array rule failed.
    Field(&'static str),
    /// A domain constructor or cross-field admission invariant refused.
    Domain(&'static str),
    /// Typed reconstruction did not encode to the identical input bytes.
    NonCanonicalRoundTrip,
}

impl fmt::Display for RunSpecDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DocumentTooLarge => {
                formatter.write_str("RunSpec document exceeds the byte limit")
            }
            Self::InvalidCanonicalJson => {
                formatter.write_str("RunSpec document is not canonical JSON")
            }
            Self::ObjectShape(name) => write!(formatter, "RunSpec {name} object shape is invalid"),
            Self::Field(name) => write!(formatter, "RunSpec {name} field is invalid"),
            Self::Domain(name) => write!(formatter, "RunSpec {name} domain invariant failed"),
            Self::NonCanonicalRoundTrip => {
                formatter.write_str("RunSpec typed round trip changed canonical bytes")
            }
        }
    }
}

impl std::error::Error for RunSpecDecodeError {}

type Entries<'a> = &'a [(String, JsonValue)];

fn exact<'a>(
    value: &'a JsonValue,
    name: &'static str,
    keys: &[&str],
) -> Result<Entries<'a>, RunSpecDecodeError> {
    let JsonValue::Object(entries) = value else {
        return Err(RunSpecDecodeError::ObjectShape(name));
    };
    if entries.len() != keys.len()
        || entries
            .iter()
            .zip(keys)
            .any(|((actual, _), expected)| actual != expected)
    {
        return Err(RunSpecDecodeError::ObjectShape(name));
    }
    Ok(entries)
}

fn value<'a>(entries: Entries<'a>, key: &'static str) -> Result<&'a JsonValue, RunSpecDecodeError> {
    entries
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
        .ok_or(RunSpecDecodeError::Field(key))
}

fn text<'a>(value: &'a JsonValue, field: &'static str) -> Result<&'a str, RunSpecDecodeError> {
    value.as_str().ok_or(RunSpecDecodeError::Field(field))
}

fn array<'a>(
    value: &'a JsonValue,
    field: &'static str,
    max: usize,
) -> Result<&'a [JsonValue], RunSpecDecodeError> {
    let JsonValue::Array(items) = value else {
        return Err(RunSpecDecodeError::Field(field));
    };
    if items.len() > max {
        return Err(RunSpecDecodeError::Field(field));
    }
    Ok(items)
}

fn optional_text<'a>(
    value: &'a JsonValue,
    field: &'static str,
) -> Result<Option<&'a str>, RunSpecDecodeError> {
    match value {
        JsonValue::Null => Ok(None),
        JsonValue::String(value) => Ok(Some(value)),
        _ => Err(RunSpecDecodeError::Field(field)),
    }
}

fn unsigned(value: &JsonValue, field: &'static str) -> Result<u64, RunSpecDecodeError> {
    let value = text(value, field)?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(RunSpecDecodeError::Field(field));
    }
    value.parse().map_err(|_| RunSpecDecodeError::Field(field))
}

fn revision(value: &JsonValue, field: &'static str) -> Result<Revision, RunSpecDecodeError> {
    Revision::new(unsigned(value, field)?).map_err(|_| RunSpecDecodeError::Field(field))
}

fn nonzero(value: &JsonValue, field: &'static str) -> Result<NonZeroU64, RunSpecDecodeError> {
    NonZeroU64::new(unsigned(value, field)?).ok_or(RunSpecDecodeError::Field(field))
}

fn hex_len(
    value: &JsonValue,
    field: &'static str,
    max_decoded: usize,
) -> Result<usize, RunSpecDecodeError> {
    let encoded = text(value, field)?;
    let max_encoded = max_decoded
        .checked_mul(2)
        .ok_or(RunSpecDecodeError::Field(field))?;
    if encoded.len() > max_encoded
        || encoded.len() % 2 != 0
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RunSpecDecodeError::Field(field));
    }
    Ok(encoded.len() / 2)
}

fn hex(
    value: &JsonValue,
    field: &'static str,
    max_decoded: usize,
) -> Result<Vec<u8>, RunSpecDecodeError> {
    let decoded_len = hex_len(value, field, max_decoded)?;
    let encoded = text(value, field)?;
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(decoded_len)
        .map_err(|_| RunSpecDecodeError::Field(field))?;
    for pair in encoded.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(pair).map_err(|_| RunSpecDecodeError::Field(field))?;
        decoded.push(u8::from_str_radix(pair, 16).map_err(|_| RunSpecDecodeError::Field(field))?);
    }
    Ok(decoded)
}

fn sha256<'a>(value: &'a JsonValue, field: &'static str) -> Result<&'a str, RunSpecDecodeError> {
    let value = text(value, field)?;
    let digest = Digest::parse(value).map_err(|_| RunSpecDecodeError::Field(field))?;
    if digest.algorithm() != DigestAlgorithm::Sha256 {
        return Err(RunSpecDecodeError::Field(field));
    }
    Ok(value)
}

fn strings(
    value: &JsonValue,
    field: &'static str,
    max: usize,
) -> Result<Vec<String>, RunSpecDecodeError> {
    array(value, field, max)?
        .iter()
        .map(|item| text(item, field).map(str::to_owned))
        .collect()
}

pub(crate) fn decode(bytes: &[u8]) -> Result<RunSpec, RunSpecDecodeError> {
    if bytes.len() > MAX_RUN_SPEC_BYTES {
        return Err(RunSpecDecodeError::DocumentTooLarge);
    }
    let document =
        wire::parse_canonical(bytes).map_err(|_| RunSpecDecodeError::InvalidCanonicalJson)?;
    let e = exact(
        &document,
        "run_spec",
        &[
            "argv_hex",
            "artifact_grants",
            "attempt_id",
            "backend_id",
            "context_manifest",
            "credential_bindings",
            "cwd_token",
            "environment_hex",
            "event_dialect",
            "executable_path_hex",
            "execution_plan_digest",
            "executor_class",
            "extension_set_digest",
            "fallback_eligibility",
            "host_id",
            "host_lifetime",
            "integration_mode",
            "io_reservation",
            "model_routing_digest",
            "origin",
            "persona_digest",
            "portability_policy",
            "profile_digest",
            "prompt_delivery",
            "provider_binary",
            "remote_attestation_policy",
            "required_capabilities",
            "run_id",
            "sandbox_spec",
            "scheduler_reservation",
            "schema",
            "session_binding",
            "skillset_digest",
            "toolset_digest",
            "work_id",
            "workspace",
            "workspace_registry_id",
            "workspace_reservation",
        ],
    )?;
    if text(value(e, "schema")?, "schema")? != "automonique.run-spec/v1" {
        return Err(RunSpecDecodeError::Field("schema"));
    }

    let argv_items = array(value(e, "argv_hex")?, "argv_hex", crate::MAX_ARG_COUNT)?;
    let mut argv_total = 0_usize;
    for item in argv_items {
        argv_total = argv_total
            .checked_add(hex_len(item, "argv_hex", crate::MAX_ARG_BYTES)?)
            .ok_or(RunSpecDecodeError::Field("argv_hex"))?;
        if argv_total > crate::MAX_TOTAL_ARG_BYTES {
            return Err(RunSpecDecodeError::Field("argv_hex"));
        }
    }
    let arguments = argv_items
        .iter()
        .map(|item| hex(item, "argv_hex", crate::MAX_ARG_BYTES).map(OsString::from_vec))
        .collect::<Result<Vec<_>, _>>()?;
    let environment_items = array(
        value(e, "environment_hex")?,
        "environment_hex",
        crate::MAX_ENV_COUNT,
    )?;
    let mut environment_total = 0_usize;
    for item in environment_items {
        let entry = exact(item, "environment_entry", &["key_hex", "value_hex"])?;
        let key_len = hex_len(value(entry, "key_hex")?, "key_hex", crate::MAX_FIELD_BYTES)?;
        let value_len = hex_len(
            value(entry, "value_hex")?,
            "value_hex",
            crate::MAX_ARG_BYTES,
        )?;
        environment_total = environment_total
            .checked_add(key_len)
            .and_then(|total| total.checked_add(value_len))
            .ok_or(RunSpecDecodeError::Field("environment_hex"))?;
        if environment_total > crate::MAX_TOTAL_ENV_BYTES {
            return Err(RunSpecDecodeError::Field("environment_hex"));
        }
    }
    let environment = environment_items
        .iter()
        .map(decode_environment)
        .collect::<Result<Vec<_>, _>>()?;
    let integration_mode =
        IntegrationMode::new(text(value(e, "integration_mode")?, "integration_mode")?)
            .map_err(|_| RunSpecDecodeError::Domain("integration_mode"))?;
    let fallback_values = strings(
        value(e, "fallback_eligibility")?,
        "fallback_eligibility",
        MAX_FALLBACK_MODES,
    )?;
    let fallbacks = fallback_values
        .iter()
        .map(|mode| {
            IntegrationMode::new(mode)
                .map_err(|_| RunSpecDecodeError::Domain("fallback_eligibility"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fallback_eligibility = FallbackEligibility::declare(&integration_mode, fallbacks)
        .map_err(|_| RunSpecDecodeError::Domain("fallback_eligibility"))?;
    let sandbox = decode_sandbox(value(e, "sandbox_spec")?)?;
    let prompt = decode_prompt(value(e, "prompt_delivery")?)?;
    let coordinates = RunCoordinates::new(
        WorkId::new(text(value(e, "work_id")?, "work_id")?)
            .map_err(|_| RunSpecDecodeError::Domain("work_id"))?,
        RunId::new(text(value(e, "run_id")?, "run_id")?)
            .map_err(|_| RunSpecDecodeError::Domain("run_id"))?,
        AttemptId::new(text(value(e, "attempt_id")?, "attempt_id")?)
            .map_err(|_| RunSpecDecodeError::Domain("attempt_id"))?,
        HostId::new(text(value(e, "host_id")?, "host_id")?)
            .map_err(|_| RunSpecDecodeError::Domain("host_id"))?,
        HostLifetime::from_spelling(text(value(e, "host_lifetime")?, "host_lifetime")?)
            .ok_or(RunSpecDecodeError::Field("host_lifetime"))?,
        ExecutionBackendId::new(text(value(e, "backend_id")?, "backend_id")?)
            .map_err(|_| RunSpecDecodeError::Domain("backend_id"))?,
    );
    let io = exact(
        value(e, "io_reservation")?,
        "io_reservation",
        &["read_bytes", "write_bytes"],
    )?;
    let admission = AdmissionFields::new(AdmissionFieldsParts {
        io_reservation: IoReservation::new(
            unsigned(value(io, "read_bytes")?, "read_bytes")?,
            unsigned(value(io, "write_bytes")?, "write_bytes")?,
        )
        .map_err(|_| RunSpecDecodeError::Domain("io_reservation"))?,
        workspace_reservation: WorkspaceReservation::new(unsigned(
            value(e, "workspace_reservation")?,
            "workspace_reservation",
        )?)
        .map_err(|_| RunSpecDecodeError::Domain("workspace_reservation"))?,
        session_binding: decode_optional_session(value(e, "session_binding")?)?,
        integration_mode,
        fallback_eligibility,
        required_capabilities: decode_capabilities(value(e, "required_capabilities")?)?,
        context_manifest: decode_context(value(e, "context_manifest")?)?,
        profile_digest: ProfileDigest::parse(sha256(
            value(e, "profile_digest")?,
            "profile_digest",
        )?)
        .map_err(|_| RunSpecDecodeError::Domain("profile_digest"))?,
        model_routing_digest: ModelRoutingDigest::parse(sha256(
            value(e, "model_routing_digest")?,
            "model_routing_digest",
        )?)
        .map_err(|_| RunSpecDecodeError::Domain("model_routing_digest"))?,
        toolset_digest: ToolsetDigest::parse(sha256(
            value(e, "toolset_digest")?,
            "toolset_digest",
        )?)
        .map_err(|_| RunSpecDecodeError::Domain("toolset_digest"))?,
        skillset_digest: SkillsetDigest::parse(sha256(
            value(e, "skillset_digest")?,
            "skillset_digest",
        )?)
        .map_err(|_| RunSpecDecodeError::Domain("skillset_digest"))?,
        extension_set_digest: ExtensionSetDigest::parse(sha256(
            value(e, "extension_set_digest")?,
            "extension_set_digest",
        )?)
        .map_err(|_| RunSpecDecodeError::Domain("extension_set_digest"))?,
        origin: decode_origin(value(e, "origin")?)?,
        executor_class: decode_executor(value(e, "executor_class")?)?,
        portability_policy: decode_portability(value(e, "portability_policy")?)?,
        remote_attestation_policy: RemoteAttestationPolicy::from_spelling(text(
            value(e, "remote_attestation_policy")?,
            "remote_attestation_policy",
        )?)
        .ok_or(RunSpecDecodeError::Field("remote_attestation_policy"))?,
        persona_digest: PersonaDigest::parse(sha256(
            value(e, "persona_digest")?,
            "persona_digest",
        )?)
        .map_err(|_| RunSpecDecodeError::Domain("persona_digest"))?,
        execution_plan_digest: ExecutionPlanDigest::parse(sha256(
            value(e, "execution_plan_digest")?,
            "execution_plan_digest",
        )?)
        .map_err(|_| RunSpecDecodeError::Domain("execution_plan_digest"))?,
        scheduler_reservation: decode_scheduler(value(e, "scheduler_reservation")?)?,
        artifact_grants: decode_artifacts(value(e, "artifact_grants")?)?,
        credential_bindings: decode_credential_bindings(value(e, "credential_bindings")?)?,
        event_dialect: RunnerEventDialect::from_spelling(text(
            value(e, "event_dialect")?,
            "event_dialect",
        )?)
        .ok_or(RunSpecDecodeError::Field("event_dialect"))?,
    });
    let spec = RunSpec::new(RunSpecParts {
        protocol_version: 1,
        coordinates,
        executable: PathBuf::from(OsString::from_vec(hex(
            value(e, "executable_path_hex")?,
            "executable_path_hex",
            crate::MAX_PATH_BYTES,
        )?)),
        arguments,
        cwd_token: CwdToken::new(text(value(e, "cwd_token")?, "cwd_token")?)
            .map_err(|_| RunSpecDecodeError::Domain("cwd_token"))?,
        environment,
        prompt,
        workspace_registry_id: WorkspaceRegistryId::new(text(
            value(e, "workspace_registry_id")?,
            "workspace_registry_id",
        )?)
        .map_err(|_| RunSpecDecodeError::Domain("workspace_registry_id"))?,
        workspace: decode_workspace(value(e, "workspace")?)?,
        provider_binary: decode_binary(value(e, "provider_binary")?)?,
        sandbox,
        admission,
    })
    .map_err(|_| RunSpecDecodeError::Domain("run_spec"))?;
    if spec
        .to_canonical_bytes()
        .map_err(|_| RunSpecDecodeError::DocumentTooLarge)?
        != bytes
    {
        return Err(RunSpecDecodeError::NonCanonicalRoundTrip);
    }
    Ok(spec)
}

fn decode_environment(value_: &JsonValue) -> Result<(OsString, OsString), RunSpecDecodeError> {
    let e = exact(value_, "environment_entry", &["key_hex", "value_hex"])?;
    Ok((
        OsString::from_vec(hex(
            value(e, "key_hex")?,
            "key_hex",
            crate::MAX_FIELD_BYTES,
        )?),
        OsString::from_vec(hex(
            value(e, "value_hex")?,
            "value_hex",
            crate::MAX_ARG_BYTES,
        )?),
    ))
}

fn decode_prompt(value_: &JsonValue) -> Result<PromptDeliveryPlan, RunSpecDecodeError> {
    let e = exact(
        value_,
        "prompt_delivery",
        &["backend_session", "mode", "protected_reference"],
    )?;
    let backend = optional_text(value(e, "backend_session")?, "backend_session")?;
    let protected = optional_text(value(e, "protected_reference")?, "protected_reference")?;
    let protected = protected
        .map(|v| {
            ProtectedPromptReference::new(v)
                .map_err(|_| RunSpecDecodeError::Domain("protected_reference"))
        })
        .transpose()?;
    let backend = backend
        .map(|v| {
            BackendPromptSession::new(v).map_err(|_| RunSpecDecodeError::Domain("backend_session"))
        })
        .transpose()?;
    PromptDeliveryPlan::from_spelling(text(value(e, "mode")?, "prompt_mode")?, protected, backend)
        .ok_or(RunSpecDecodeError::Field("prompt_delivery"))
}

fn decode_binary(value_: &JsonValue) -> Result<BinaryProvenance, RunSpecDecodeError> {
    let e = exact(
        value_,
        "provider_binary",
        &["digest", "schema_digest", "version"],
    )?;
    let digest = sha256(value(e, "digest")?, "binary_digest")?;
    let schema = optional_text(value(e, "schema_digest")?, "schema_digest")?;
    if let Some(schema) = schema {
        Digest::parse(schema)
            .ok()
            .filter(|d| d.algorithm() == DigestAlgorithm::Sha256)
            .ok_or(RunSpecDecodeError::Field("schema_digest"))?;
    }
    BinaryProvenance::new(
        text(value(e, "version")?, "binary_version")?,
        digest,
        schema,
    )
    .map_err(|_| RunSpecDecodeError::Domain("provider_binary"))
}

fn decode_workspace(value_: &JsonValue) -> Result<WorkspaceRegistration, RunSpecDecodeError> {
    let e = exact(
        value_,
        "workspace",
        &[
            "base_revision",
            "canonical_source",
            "isolation",
            "snapshot",
            "tenant",
            "token",
        ],
    )?;
    WorkspaceRegistration::new(
        text(value(e, "tenant")?, "workspace_tenant")?,
        text(value(e, "canonical_source")?, "canonical_source")?,
        revision(value(e, "base_revision")?, "workspace_base_revision")?,
        text(value(e, "snapshot")?, "snapshot")?,
        IsolationKind::from_spelling(text(value(e, "isolation")?, "workspace_isolation")?)
            .ok_or(RunSpecDecodeError::Field("workspace_isolation"))?,
        WorkspaceToken::new(text(value(e, "token")?, "workspace_token")?)
            .map_err(|_| RunSpecDecodeError::Domain("workspace_token"))?,
    )
    .map_err(|_| RunSpecDecodeError::Domain("workspace"))
}

fn decode_optional_session(
    value_: &JsonValue,
) -> Result<Option<SessionBinding>, RunSpecDecodeError> {
    if matches!(value_, JsonValue::Null) {
        return Ok(None);
    }
    let e = exact(
        value_,
        "session_binding",
        &[
            "backend",
            "provider_account",
            "provider_namespace",
            "session",
            "tenant",
        ],
    )?;
    SessionBinding::new(
        text(value(e, "tenant")?, "session_tenant")?,
        text(value(e, "backend")?, "session_backend")?,
        text(value(e, "provider_account")?, "session_provider_account")?,
        text(value(e, "provider_namespace")?, "provider_namespace")?,
        ProviderSessionId::new(text(value(e, "session")?, "session")?)
            .map_err(|_| RunSpecDecodeError::Domain("session"))?,
    )
    .map(Some)
    .map_err(|_| RunSpecDecodeError::Domain("session_binding"))
}

fn decode_capabilities(value_: &JsonValue) -> Result<RequiredCapabilities, RunSpecDecodeError> {
    let items = array(
        value_,
        "required_capabilities",
        automonique_protocol::provider::MAX_CAPABILITIES,
    )?;
    let mut decoded = Vec::with_capacity(items.len());
    for item in items {
        let e = exact(item, "capability", &["group", "name"])?;
        let group = CapabilityGroup::from_spelling(text(value(e, "group")?, "capability_group")?)
            .ok_or(RunSpecDecodeError::Field("capability_group"))?;
        decoded.push(
            Capability::new(group, text(value(e, "name")?, "capability_name")?)
                .map_err(|_| RunSpecDecodeError::Domain("capability"))?,
        );
    }
    RequiredCapabilities::declare(decoded)
        .map_err(|_| RunSpecDecodeError::Domain("required_capabilities"))
}

fn decode_caps(value_: &JsonValue) -> Result<ComponentCaps, RunSpecDecodeError> {
    let e = exact(value_, "component_caps", &["byte_cap", "token_cap"])?;
    ComponentCaps::new(
        unsigned(value(e, "byte_cap")?, "byte_cap")?,
        unsigned(value(e, "token_cap")?, "token_cap")?,
    )
    .map_err(|_| RunSpecDecodeError::Domain("component_caps"))
}

fn decode_context(value_: &JsonValue) -> Result<ContextManifest, RunSpecDecodeError> {
    let e = exact(
        value_,
        "context_manifest",
        &["policy", "policy_revision", "supplied", "token_budget"],
    )?;
    let policy_items = array(value(e, "policy")?, "context_policy", MAX_JSON_ENTRIES)?;
    let supplied_items = array(value(e, "supplied")?, "context_supplied", MAX_JSON_ENTRIES)?;
    let mut policy = Vec::with_capacity(policy_items.len());
    for item in policy_items {
        let p = exact(
            item,
            "policy_component",
            &["caps", "digest", "redaction", "revision", "source"],
        )?;
        policy.push(
            PolicyComponent::new(
                text(value(p, "source")?, "policy_source")?,
                revision(value(p, "revision")?, "policy_component_revision")?,
                text(value(p, "digest")?, "policy_component_digest")?,
                decode_caps(value(p, "caps")?)?,
                RedactionOutcome::from_spelling(text(value(p, "redaction")?, "policy_redaction")?)
                    .ok_or(RunSpecDecodeError::Field("policy_redaction"))?,
            )
            .map_err(|_| RunSpecDecodeError::Domain("policy_component"))?,
        );
    }
    let mut supplied = Vec::with_capacity(supplied_items.len());
    for item in supplied_items {
        let s = exact(
            item,
            "supplied_component",
            &["caps", "class", "digest", "redaction", "source", "trust"],
        )?;
        let trust = TrustClass::from_spelling(text(value(s, "trust")?, "supplied_trust")?)
            .ok_or(RunSpecDecodeError::Field("supplied_trust"))?;
        if trust == TrustClass::Policy {
            return Err(RunSpecDecodeError::Field("supplied_trust"));
        }
        supplied.push(
            SuppliedComponent::new(
                text(value(s, "source")?, "supplied_source")?,
                SuppliedClass::from_spelling(text(value(s, "class")?, "supplied_class")?)
                    .ok_or(RunSpecDecodeError::Field("supplied_class"))?,
                trust,
                text(value(s, "digest")?, "supplied_digest")?,
                decode_caps(value(s, "caps")?)?,
                RedactionOutcome::from_spelling(text(
                    value(s, "redaction")?,
                    "supplied_redaction",
                )?)
                .ok_or(RunSpecDecodeError::Field("supplied_redaction"))?,
            )
            .map_err(|_| RunSpecDecodeError::Domain("supplied_component"))?,
        );
    }
    Ok(ContextManifest::new(
        revision(value(e, "policy_revision")?, "policy_revision")?,
        TokenBudget::new(unsigned(value(e, "token_budget")?, "token_budget")?),
        policy,
        supplied,
    ))
}

fn decode_actor(value_: &JsonValue) -> Result<Actor, RunSpecDecodeError> {
    let e = exact(value_, "actor", &["id", "tenant"])?;
    Actor::new(
        text(value(e, "tenant")?, "actor_tenant")?,
        text(value(e, "id")?, "actor_id")?,
    )
    .map_err(|_| RunSpecDecodeError::Domain("actor"))
}

fn decode_cause(value_: &JsonValue) -> Result<NestedCause, RunSpecDecodeError> {
    let e = exact(
        value_,
        "nested_cause",
        &["actor", "causation_id", "parent_id", "run_id"],
    )?;
    let root_id = optional_text(value(e, "parent_id")?, "parent_id")?;
    let causation = CausationId::new(text(value(e, "causation_id")?, "causation_id")?)
        .map_err(|_| RunSpecDecodeError::Domain("causation_id"))?;
    let actor = decode_actor(value(e, "actor")?)?;
    let run = RunId::new(text(value(e, "run_id")?, "cause_run_id")?)
        .map_err(|_| RunSpecDecodeError::Domain("cause_run_id"))?;
    match root_id {
        None => Ok(NestedCause::root(actor, run, causation)),
        Some(parent) => Ok(NestedCause::root(
            actor,
            run,
            CausationId::new(parent).map_err(|_| RunSpecDecodeError::Domain("parent_id"))?,
        )
        .caused(causation)),
    }
}

fn durable_optional(
    value_: &JsonValue,
    field: &'static str,
) -> Result<Option<DurableId>, RunSpecDecodeError> {
    optional_text(value_, field)?
        .map(|v| DurableId::new(v).map_err(|_| RunSpecDecodeError::Domain(field)))
        .transpose()
}

fn decode_origin(value_: &JsonValue) -> Result<RunOrigin, RunSpecDecodeError> {
    let e = exact(
        value_,
        "origin",
        &[
            "automation_id",
            "causal_events",
            "cause",
            "event_id",
            "goal_id",
            "source",
            "trigger_id",
        ],
    )?;
    let source = RunOriginSource::from_spelling(text(value(e, "source")?, "origin_source")?)
        .ok_or(RunSpecDecodeError::Field("origin_source"))?;
    let automation = durable_optional(value(e, "automation_id")?, "automation_id")?;
    let goal = durable_optional(value(e, "goal_id")?, "goal_id")?;
    let trigger = durable_optional(value(e, "trigger_id")?, "trigger_id")?;
    let event = durable_optional(value(e, "event_id")?, "event_id")?;
    let causal_values = strings(
        value(e, "causal_events")?,
        "causal_events",
        MAX_ORIGIN_CAUSES,
    )?;
    let causals = causal_values
        .iter()
        .map(|v| DurableId::new(v).map_err(|_| RunSpecDecodeError::Domain("causal_events")))
        .collect::<Result<Vec<_>, _>>()?;
    if source == RunOriginSource::Interactive {
        if automation.is_some()
            || goal.is_some()
            || trigger.is_some()
            || event.is_some()
            || !causals.is_empty()
            || !matches!(value(e, "cause")?, JsonValue::Null)
        {
            return Err(RunSpecDecodeError::Field("origin"));
        }
        return Ok(RunOrigin::Interactive);
    }
    let coordinate = match (source, automation, goal, trigger) {
        (RunOriginSource::Automation, Some(id), None, None) => OriginCoordinate::Automation(id),
        (RunOriginSource::Goal, None, Some(id), None) => OriginCoordinate::Goal(id),
        (RunOriginSource::Trigger, None, None, Some(id)) => OriginCoordinate::Trigger(id),
        (
            RunOriginSource::Schedule
            | RunOriginSource::Recovery
            | RunOriginSource::GraphChild
            | RunOriginSource::BackgroundCuration
            | RunOriginSource::Media
            | RunOriginSource::RemoteWakeup
            | RunOriginSource::Batch
            | RunOriginSource::Evaluation,
            None,
            None,
            None,
        ) => OriginCoordinate::None,
        _ => return Err(RunSpecDecodeError::Field("origin")),
    };
    let cause_value = value(e, "cause")?;
    if matches!(cause_value, JsonValue::Null) {
        return Err(RunSpecDecodeError::Field("cause"));
    }
    RunOrigin::non_interactive(
        source,
        event.ok_or(RunSpecDecodeError::Field("event_id"))?,
        coordinate,
        causals,
        decode_cause(cause_value)?,
    )
    .map_err(|_| RunSpecDecodeError::Domain("origin"))
}

fn decode_executor(value_: &JsonValue) -> Result<ExecutorClass, RunSpecDecodeError> {
    let e = exact(value_, "executor_class", &["kind", "remote_coordinate"])?;
    let coordinate = match value(e, "remote_coordinate")? {
        JsonValue::Null => None,
        value_ => {
            let r = exact(value_, "remote_coordinate", &["resource_id", "vendor"])?;
            Some(
                RemoteCoordinate::new(
                    text(value(r, "vendor")?, "remote_vendor")?,
                    text(value(r, "resource_id")?, "remote_resource_id")?,
                )
                .map_err(|_| RunSpecDecodeError::Domain("remote_coordinate"))?,
            )
        }
    };
    ExecutorClass::from_spelling(text(value(e, "kind")?, "executor_kind")?, coordinate)
        .ok_or(RunSpecDecodeError::Field("executor_class"))
}

fn decode_portability(value_: &JsonValue) -> Result<PortabilityPolicy, RunSpecDecodeError> {
    let e = exact(
        value_,
        "portability_policy",
        &["artifact_transfer", "kind", "workspace_transfer"],
    )?;
    let artifact = optional_text(value(e, "artifact_transfer")?, "artifact_transfer")?
        .map(|v| {
            ArtifactTransfer::from_spelling(v).ok_or(RunSpecDecodeError::Field("artifact_transfer"))
        })
        .transpose()?;
    let workspace = optional_text(value(e, "workspace_transfer")?, "workspace_transfer")?
        .map(|v| {
            WorkspaceTransfer::from_spelling(v)
                .ok_or(RunSpecDecodeError::Field("workspace_transfer"))
        })
        .transpose()?;
    PortabilityPolicy::from_spelling(
        text(value(e, "kind")?, "portability_kind")?,
        workspace,
        artifact,
    )
    .ok_or(RunSpecDecodeError::Field("portability_policy"))
}

fn decode_scheduler(value_: &JsonValue) -> Result<SchedulerReservationBinding, RunSpecDecodeError> {
    let e = exact(
        value_,
        "scheduler_reservation",
        &["decision_digest", "id", "revision"],
    )?;
    Ok(SchedulerReservationBinding::new(
        SchedulerReservationId::new(text(value(e, "id")?, "scheduler_id")?)
            .map_err(|_| RunSpecDecodeError::Domain("scheduler_id"))?,
        revision(value(e, "revision")?, "scheduler_revision")?,
        SchedulerDecisionDigest::parse(sha256(value(e, "decision_digest")?, "scheduler_digest")?)
            .map_err(|_| RunSpecDecodeError::Domain("scheduler_digest"))?,
    ))
}

fn decode_artifacts(value_: &JsonValue) -> Result<ArtifactGrantBindings, RunSpecDecodeError> {
    let items = array(value_, "artifact_grants", MAX_ARTIFACT_GRANT_BINDINGS)?;
    let mut decoded = Vec::with_capacity(items.len());
    for item in items {
        let e = exact(item, "artifact_grant", &["grant_digest", "id", "revision"])?;
        decoded.push(ArtifactGrantBinding::new(
            ArtifactGrantId::new(text(value(e, "id")?, "artifact_grant_id")?)
                .map_err(|_| RunSpecDecodeError::Domain("artifact_grant_id"))?,
            revision(value(e, "revision")?, "artifact_grant_revision")?,
            ArtifactGrantDigest::parse(sha256(value(e, "grant_digest")?, "artifact_grant_digest")?)
                .map_err(|_| RunSpecDecodeError::Domain("artifact_grant_digest"))?,
        ));
    }
    ArtifactGrantBindings::declare(decoded)
        .map_err(|_| RunSpecDecodeError::Domain("artifact_grants"))
}

fn decode_credential_bindings(
    value_: &JsonValue,
) -> Result<Vec<CredentialBinding>, RunSpecDecodeError> {
    let items = array(value_, "credential_bindings", MAX_SANDBOX_ENTRIES)?;
    let mut decoded = Vec::with_capacity(items.len());
    for item in items {
        let e = exact(
            item,
            "credential_binding",
            &["audiences", "name", "version"],
        )?;
        let audiences = strings(
            value(e, "audiences")?,
            "credential_audiences",
            MAX_SANDBOX_ENTRIES,
        )?;
        if audiences
            .windows(2)
            .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err(RunSpecDecodeError::Field("credential_audiences"));
        }
        let refs = audiences.iter().map(String::as_str).collect::<Vec<_>>();
        decoded.push(
            CredentialBinding::new(
                text(value(e, "name")?, "credential_name")?,
                nonzero(value(e, "version")?, "credential_version")?,
                CredentialAudiences::exactly(&refs)
                    .map_err(|_| RunSpecDecodeError::Domain("credential_audiences"))?,
            )
            .map_err(|_| RunSpecDecodeError::Domain("credential_binding"))?,
        );
    }
    Ok(decoded)
}

fn decode_budgets(value_: &JsonValue) -> Result<Budgets, RunSpecDecodeError> {
    let e = exact(
        value_,
        "budgets",
        &[
            "artifact_bytes",
            "cgroup_cpu_millicores",
            "cgroup_memory_bytes",
            "rlimit_descriptors",
            "rlimit_processes",
            "spool_bytes",
            "temporary_storage_bytes",
            "timeout_millis",
        ],
    )?;
    Budgets::declare(BudgetQuantities {
        artifact_bytes: unsigned(value(e, "artifact_bytes")?, "artifact_bytes")?,
        cgroup_cpu_millicores: unsigned(
            value(e, "cgroup_cpu_millicores")?,
            "cgroup_cpu_millicores",
        )?,
        cgroup_memory_bytes: unsigned(value(e, "cgroup_memory_bytes")?, "cgroup_memory_bytes")?,
        rlimit_descriptors: unsigned(value(e, "rlimit_descriptors")?, "rlimit_descriptors")?,
        rlimit_processes: unsigned(value(e, "rlimit_processes")?, "rlimit_processes")?,
        spool_bytes: unsigned(value(e, "spool_bytes")?, "spool_bytes")?,
        temporary_storage_bytes: unsigned(
            value(e, "temporary_storage_bytes")?,
            "temporary_storage_bytes",
        )?,
        timeout_millis: unsigned(value(e, "timeout_millis")?, "timeout_millis")?,
    })
    .map_err(|_| RunSpecDecodeError::Domain("budgets"))
}

fn decode_sandbox(value_: &JsonValue) -> Result<SandboxSpec, RunSpecDecodeError> {
    let e = exact(
        value_,
        "sandbox_spec",
        &[
            "actor",
            "allowlists",
            "approval_revision",
            "base_revision",
            "budgets",
            "credentials",
            "nested_isolation",
            "path_grants",
            "policy_digest",
            "profile",
            "prohibited_capabilities",
            "provider_account",
            "provider_control_egress",
            "required_features",
            "tool_workload_egress",
            "workspace_context",
        ],
    )?;
    let profile_e = exact(
        value(e, "profile")?,
        "sandbox_profile",
        &["filesystem", "id", "tool_network", "version"],
    )?;
    let tool_network = NetworkAccess::from_spelling(text(
        value(profile_e, "tool_network")?,
        "profile_tool_network",
    )?)
    .ok_or(RunSpecDecodeError::Field("profile_tool_network"))?;
    let profile = SandboxProfile::new(
        text(value(profile_e, "id")?, "profile_id")?,
        u32::try_from(unsigned(value(profile_e, "version")?, "profile_version")?)
            .map_err(|_| RunSpecDecodeError::Field("profile_version"))?,
        FilesystemAccess::from_spelling(text(
            value(profile_e, "filesystem")?,
            "profile_filesystem",
        )?)
        .ok_or(RunSpecDecodeError::Field("profile_filesystem"))?,
        ToolWorkloadEgress::brokered(tool_network),
    )
    .map_err(|_| RunSpecDecodeError::Domain("sandbox_profile"))?;

    let path_items = array(value(e, "path_grants")?, "path_grants", MAX_SANDBOX_ENTRIES)?;
    let mut paths = Vec::with_capacity(path_items.len());
    for item in path_items {
        let p = exact(item, "path_grant", &["access", "path"])?;
        paths.push(
            PathGrant::new(
                text(value(p, "path")?, "path_grant_path")?,
                PathAccess::from_spelling(text(value(p, "access")?, "path_grant_access")?)
                    .ok_or(RunSpecDecodeError::Field("path_grant_access"))?,
            )
            .map_err(|_| RunSpecDecodeError::Domain("path_grant"))?,
        );
    }
    let allowlist_items = array(value(e, "allowlists")?, "allowlists", MAX_SANDBOX_ENTRIES)?;
    let mut allowlists = Vec::with_capacity(allowlist_items.len());
    for item in allowlist_items {
        let a = exact(item, "allowlist_entry", &["class", "name"])?;
        allowlists.push(
            AllowlistEntry::new(
                AllowlistClass::from_spelling(text(value(a, "class")?, "allowlist_class")?)
                    .ok_or(RunSpecDecodeError::Field("allowlist_class"))?,
                text(value(a, "name")?, "allowlist_name")?,
            )
            .map_err(|_| RunSpecDecodeError::Domain("allowlist_entry"))?,
        );
    }
    let credential_items = array(value(e, "credentials")?, "credentials", MAX_SANDBOX_ENTRIES)?;
    let mut credentials = Vec::with_capacity(credential_items.len());
    for item in credential_items {
        let c = exact(item, "credential_descriptor", &["name", "recipient"])?;
        credentials.push(
            CredentialDescriptor::new(
                text(value(c, "name")?, "credential_descriptor_name")?,
                ProcessClass::from_spelling(text(value(c, "recipient")?, "credential_recipient")?)
                    .ok_or(RunSpecDecodeError::Field("credential_recipient"))?,
            )
            .map_err(|_| RunSpecDecodeError::Domain("credential_descriptor"))?,
        );
    }
    let feature_items = array(
        value(e, "required_features")?,
        "required_features",
        MAX_SANDBOX_ENTRIES,
    )?;
    if feature_items.is_empty() {
        return Err(RunSpecDecodeError::Field("required_features"));
    }
    let mut features = Vec::with_capacity(feature_items.len());
    for item in feature_items {
        let f = exact(
            item,
            "required_feature",
            &["accepted_implementations", "name"],
        )?;
        let implementation_values = strings(
            value(f, "accepted_implementations")?,
            "accepted_implementations",
            MAX_SANDBOX_ENTRIES,
        )?;
        if implementation_values.is_empty() {
            return Err(RunSpecDecodeError::Field("accepted_implementations"));
        }
        let implementations = implementation_values
            .iter()
            .map(|v| {
                ImplementationDigest::parse(v)
                    .map_err(|_| RunSpecDecodeError::Field("accepted_implementations"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        features.push(
            RequiredFeature::new(
                text(value(f, "name")?, "required_feature_name")?,
                &implementations,
            )
            .map_err(|_| RunSpecDecodeError::Domain("required_feature"))?,
        );
    }
    let nested_e = exact(
        value(e, "nested_isolation")?,
        "nested_isolation",
        &["extensions", "nested_tools"],
    )?;
    let prohibited_values = strings(
        value(e, "prohibited_capabilities")?,
        "prohibited_capabilities",
        MAX_SANDBOX_ENTRIES,
    )?;
    let prohibited_refs = prohibited_values
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let policy = text(value(e, "policy_digest")?, "policy_digest")?;
    Digest::parse(policy).map_err(|_| RunSpecDecodeError::Field("policy_digest"))?;
    let workspace_context = text(value(e, "workspace_context")?, "workspace_context")?;
    Digest::parse(workspace_context).map_err(|_| RunSpecDecodeError::Field("workspace_context"))?;
    SandboxSpec::compile(SandboxSpecParts {
        profile,
        policy_digest: PolicyDigest::parse(policy)
            .map_err(|_| RunSpecDecodeError::Domain("policy_digest"))?,
        actor: decode_actor(value(e, "actor")?)?,
        provider_account: ProviderAccountId::new(text(
            value(e, "provider_account")?,
            "provider_account",
        )?)
        .map_err(|_| RunSpecDecodeError::Domain("provider_account"))?,
        workspace_context: WorkspaceContextHash::parse(workspace_context)
            .map_err(|_| RunSpecDecodeError::Domain("workspace_context"))?,
        base_revision: revision(value(e, "base_revision")?, "sandbox_base_revision")?,
        path_grants: PathGrants::declare(&paths)
            .map_err(|_| RunSpecDecodeError::Domain("path_grants"))?,
        allowlists: ExecutionAllowlists::declare(&allowlists)
            .map_err(|_| RunSpecDecodeError::Domain("allowlists"))?,
        provider_control_egress: ProviderControlEgress::brokered(
            NetworkAccess::from_spelling(text(
                value(e, "provider_control_egress")?,
                "provider_control_egress",
            )?)
            .ok_or(RunSpecDecodeError::Field("provider_control_egress"))?,
        ),
        tool_workload_egress: ToolWorkloadEgress::brokered(
            NetworkAccess::from_spelling(text(
                value(e, "tool_workload_egress")?,
                "tool_workload_egress",
            )?)
            .ok_or(RunSpecDecodeError::Field("tool_workload_egress"))?,
        ),
        credentials: CredentialDescriptors::declare(&credentials)
            .map_err(|_| RunSpecDecodeError::Domain("credentials"))?,
        budgets: decode_budgets(value(e, "budgets")?)?,
        required_features: RequiredFeatures::declare(&features)
            .map_err(|_| RunSpecDecodeError::Domain("required_features"))?,
        nested_isolation: NestedIsolation::new(
            IsolationRequirement::from_spelling(text(
                value(nested_e, "nested_tools")?,
                "nested_tools",
            )?)
            .ok_or(RunSpecDecodeError::Field("nested_tools"))?,
            IsolationRequirement::from_spelling(text(
                value(nested_e, "extensions")?,
                "extensions",
            )?)
            .ok_or(RunSpecDecodeError::Field("extensions"))?,
        ),
        approval_revision: revision(value(e, "approval_revision")?, "approval_revision")?,
        prohibited_capabilities: ProhibitedCapabilities::declare(&prohibited_refs)
            .map_err(|_| RunSpecDecodeError::Domain("prohibited_capabilities"))?,
    })
    .map_err(|_| RunSpecDecodeError::Domain("sandbox_spec"))
}
