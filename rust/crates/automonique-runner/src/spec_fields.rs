// SPDX-License-Identifier: Elastic-2.0

//! Runner-owned, admission-only RunSpec fields with no protocol equivalent.

use crate::{PromptDeliveryPlan, RunCoordinates, RunSpecError};
use automonique_protocol::automation::DurableId;
use automonique_protocol::context::ContextManifest;
use automonique_protocol::models::ExecutorClass;
use automonique_protocol::models::{ArtifactTransfer, WorkspaceTransfer};
use automonique_protocol::provider::{Capability, MAX_CAPABILITIES, SessionBinding};
use automonique_protocol::sandbox::{Digest, DigestAlgorithm, SandboxSpec};
use automonique_protocol::tools::{ApprovalRequirement, CredentialAudiences, NestedCause};
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::num::NonZeroU64;

pub const MAX_FALLBACK_MODES: usize = 16;
pub const MAX_ORIGIN_CAUSES: usize = 64;
pub const MAX_RESERVATION_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_LOCAL_FIELD_BYTES: usize = 256;

fn bounded(value: &str, field: &'static str) -> Result<(), RunSpecError> {
    if value.is_empty()
        || value.len() > MAX_LOCAL_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        Err(RunSpecError::FieldInvalid(field))
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoReservation {
    read_bytes: u64,
    write_bytes: u64,
}

impl IoReservation {
    pub fn new(read_bytes: u64, write_bytes: u64) -> Result<Self, RunSpecError> {
        if read_bytes > MAX_RESERVATION_BYTES || write_bytes > MAX_RESERVATION_BYTES {
            return Err(RunSpecError::FieldInvalid("io_reservation"));
        }
        read_bytes
            .checked_add(write_bytes)
            .ok_or(RunSpecError::FieldInvalid("io_reservation"))?;
        Ok(Self {
            read_bytes,
            write_bytes,
        })
    }
    pub const fn read_bytes(self) -> u64 {
        self.read_bytes
    }
    pub const fn write_bytes(self) -> u64 {
        self.write_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkspaceReservation(u64);

impl WorkspaceReservation {
    pub fn new(bytes: u64) -> Result<Self, RunSpecError> {
        if bytes > MAX_RESERVATION_BYTES {
            return Err(RunSpecError::FieldInvalid("workspace_reservation"));
        }
        Ok(Self(bytes))
    }
    pub const fn bytes(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IntegrationMode(String);

impl IntegrationMode {
    pub fn new(value: &str) -> Result<Self, RunSpecError> {
        bounded(value, "integration_mode")?;
        if value.contains('/')
            || value.contains('\\')
            || value.contains("..")
            || value.contains(':')
        {
            return Err(RunSpecError::FieldInvalid("integration_mode"));
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackEligibility(Vec<IntegrationMode>);

impl FallbackEligibility {
    pub fn declare(
        selected: &IntegrationMode,
        fallbacks: Vec<IntegrationMode>,
    ) -> Result<Self, RunSpecError> {
        if fallbacks.len() > MAX_FALLBACK_MODES {
            return Err(RunSpecError::FieldInvalid("fallback_eligibility"));
        }
        let mut seen = BTreeSet::new();
        for fallback in &fallbacks {
            if fallback == selected || !seen.insert(fallback.clone()) {
                return Err(RunSpecError::FieldInvalid("fallback_eligibility"));
            }
        }
        Ok(Self(fallbacks))
    }
    pub fn as_slice(&self) -> &[IntegrationMode] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequiredCapabilities(Vec<Capability>);

impl RequiredCapabilities {
    pub fn declare(capabilities: Vec<Capability>) -> Result<Self, RunSpecError> {
        if capabilities.len() > MAX_CAPABILITIES {
            return Err(RunSpecError::FieldInvalid("required_capabilities"));
        }
        let mut seen = BTreeSet::new();
        for capability in &capabilities {
            if !seen.insert(capability.clone()) {
                return Err(RunSpecError::FieldInvalid("required_capabilities"));
            }
        }
        Ok(Self(capabilities))
    }
    pub fn as_slice(&self) -> &[Capability] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProfileDomain;
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelRoutingDomain;
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ToolsetDomain;
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SkillsetDomain;
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExtensionSetDomain;
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PersonaDomain;
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExecutionPlanDomain;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SpecDigest<D> {
    digest: Digest,
    domain: PhantomData<D>,
}

impl<D> SpecDigest<D> {
    pub fn parse(value: &str, field: &'static str) -> Result<Self, RunSpecError> {
        let digest = Digest::parse(value).map_err(|_| RunSpecError::FieldInvalid(field))?;
        if digest.algorithm() != DigestAlgorithm::Sha256 {
            return Err(RunSpecError::FieldInvalid(field));
        }
        Ok(Self {
            digest,
            domain: PhantomData,
        })
    }
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }
}

macro_rules! digest_type {
    ($name:ident, $domain:ident, $field:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(SpecDigest<$domain>);
        impl $name {
            pub fn parse(value: &str) -> Result<Self, RunSpecError> {
                SpecDigest::parse(value, $field).map(Self)
            }
            pub const fn digest(&self) -> &Digest {
                self.0.digest()
            }
        }
    };
}

digest_type!(ProfileDigest, ProfileDomain, "profile_digest");
digest_type!(
    ModelRoutingDigest,
    ModelRoutingDomain,
    "model_routing_digest"
);
digest_type!(ToolsetDigest, ToolsetDomain, "toolset_digest");
digest_type!(SkillsetDigest, SkillsetDomain, "skillset_digest");
digest_type!(
    ExtensionSetDigest,
    ExtensionSetDomain,
    "extension_set_digest"
);
digest_type!(PersonaDigest, PersonaDomain, "persona_digest");
digest_type!(
    ExecutionPlanDigest,
    ExecutionPlanDomain,
    "execution_plan_digest"
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunOrigin {
    Interactive,
    NonInteractive(Box<NonInteractiveOrigin>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonInteractiveOrigin {
    automation: Option<DurableId>,
    goal: Option<DurableId>,
    trigger: Option<DurableId>,
    causal_events: Vec<DurableId>,
    cause: NestedCause,
}

impl RunOrigin {
    pub fn non_interactive(
        automation: Option<DurableId>,
        goal: Option<DurableId>,
        trigger: Option<DurableId>,
        causal_events: Vec<DurableId>,
        cause: NestedCause,
    ) -> Result<Self, RunSpecError> {
        if automation.is_none() && goal.is_none() && trigger.is_none() {
            return Err(RunSpecError::FieldInvalid("origin"));
        }
        if causal_events.is_empty() || causal_events.len() > MAX_ORIGIN_CAUSES {
            return Err(RunSpecError::FieldInvalid("causal_events"));
        }
        let mut seen = BTreeSet::new();
        if causal_events
            .iter()
            .any(|event| !seen.insert(event.as_str().to_owned()))
        {
            return Err(RunSpecError::FieldInvalid("causal_events"));
        }
        Ok(Self::NonInteractive(Box::new(NonInteractiveOrigin {
            automation,
            goal,
            trigger,
            causal_events,
            cause,
        })))
    }
}

impl NonInteractiveOrigin {
    #[must_use]
    pub const fn automation(&self) -> Option<&DurableId> {
        self.automation.as_ref()
    }

    #[must_use]
    pub const fn goal(&self) -> Option<&DurableId> {
        self.goal.as_ref()
    }

    #[must_use]
    pub const fn trigger(&self) -> Option<&DurableId> {
        self.trigger.as_ref()
    }

    #[must_use]
    pub fn causal_events(&self) -> &[DurableId] {
        &self.causal_events
    }

    #[must_use]
    pub const fn cause(&self) -> &NestedCause {
        &self.cause
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortabilityPolicy {
    Pinned,
    Portable {
        workspace_transfer: WorkspaceTransfer,
        artifact_transfer: ArtifactTransfer,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteAttestationPolicy {
    NotRequired,
    Signed,
    MutuallyAuthenticated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialBinding {
    name: String,
    version: NonZeroU64,
    audiences: CredentialAudiences,
}

impl CredentialBinding {
    pub fn new(
        name: &str,
        version: NonZeroU64,
        audiences: CredentialAudiences,
    ) -> Result<Self, RunSpecError> {
        bounded(name, "credential_name")?;
        if audiences.is_empty() {
            return Err(RunSpecError::FieldInvalid("credential_audiences"));
        }
        Ok(Self {
            name: name.to_owned(),
            version,
            audiences,
        })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub const fn version(&self) -> NonZeroU64 {
        self.version
    }
    pub const fn audiences(&self) -> &CredentialAudiences {
        &self.audiences
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerEventDialect {
    AutomoniqueRunnerV1,
}

#[derive(Clone, Debug)]
pub struct AdmissionFieldsParts {
    pub io_reservation: IoReservation,
    pub workspace_reservation: WorkspaceReservation,
    pub session_binding: Option<SessionBinding>,
    pub integration_mode: IntegrationMode,
    pub fallback_eligibility: FallbackEligibility,
    pub required_capabilities: RequiredCapabilities,
    pub context_manifest: ContextManifest,
    pub profile_digest: ProfileDigest,
    pub model_routing_digest: ModelRoutingDigest,
    pub toolset_digest: ToolsetDigest,
    pub skillset_digest: SkillsetDigest,
    pub extension_set_digest: ExtensionSetDigest,
    pub origin: RunOrigin,
    pub executor_class: ExecutorClass,
    pub portability_policy: PortabilityPolicy,
    pub remote_attestation_policy: RemoteAttestationPolicy,
    pub persona_digest: PersonaDigest,
    pub execution_plan_digest: ExecutionPlanDigest,
    pub credential_bindings: Vec<CredentialBinding>,
    pub event_dialect: RunnerEventDialect,
    pub approval_requirement: ApprovalRequirement,
}

#[derive(Clone)]
pub struct AdmissionFields(AdmissionFieldsParts);

impl core::fmt::Debug for AdmissionFields {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AdmissionFields(<redacted bindings>)")
    }
}

impl AdmissionFields {
    #[must_use]
    pub const fn new(parts: AdmissionFieldsParts) -> Self {
        Self(parts)
    }
    pub const fn io_reservation(&self) -> IoReservation {
        self.0.io_reservation
    }
    pub const fn workspace_reservation(&self) -> WorkspaceReservation {
        self.0.workspace_reservation
    }
    pub const fn session_binding(&self) -> Option<&SessionBinding> {
        self.0.session_binding.as_ref()
    }
    pub const fn integration_mode(&self) -> &IntegrationMode {
        &self.0.integration_mode
    }
    pub fn fallback_eligibility(&self) -> &[IntegrationMode] {
        self.0.fallback_eligibility.as_slice()
    }
    pub fn required_capabilities(&self) -> &[Capability] {
        self.0.required_capabilities.as_slice()
    }
    pub const fn context_manifest(&self) -> &ContextManifest {
        &self.0.context_manifest
    }
    pub const fn profile_digest(&self) -> &ProfileDigest {
        &self.0.profile_digest
    }
    pub const fn model_routing_digest(&self) -> &ModelRoutingDigest {
        &self.0.model_routing_digest
    }
    pub const fn toolset_digest(&self) -> &ToolsetDigest {
        &self.0.toolset_digest
    }
    pub const fn skillset_digest(&self) -> &SkillsetDigest {
        &self.0.skillset_digest
    }
    pub const fn extension_set_digest(&self) -> &ExtensionSetDigest {
        &self.0.extension_set_digest
    }
    pub const fn origin(&self) -> &RunOrigin {
        &self.0.origin
    }
    pub const fn executor_class(&self) -> &ExecutorClass {
        &self.0.executor_class
    }
    pub const fn portability_policy(&self) -> PortabilityPolicy {
        self.0.portability_policy
    }
    pub const fn remote_attestation_policy(&self) -> RemoteAttestationPolicy {
        self.0.remote_attestation_policy
    }
    pub const fn persona_digest(&self) -> &PersonaDigest {
        &self.0.persona_digest
    }
    pub const fn execution_plan_digest(&self) -> &ExecutionPlanDigest {
        &self.0.execution_plan_digest
    }
    pub fn credential_bindings(&self) -> &[CredentialBinding] {
        &self.0.credential_bindings
    }
    pub const fn event_dialect(&self) -> RunnerEventDialect {
        self.0.event_dialect
    }
    pub const fn approval_requirement(&self) -> ApprovalRequirement {
        self.0.approval_requirement
    }

    pub(crate) fn validate_against(
        &self,
        coordinates: &RunCoordinates,
        prompt: &PromptDeliveryPlan,
        sandbox: &SandboxSpec,
    ) -> Result<(), RunSpecError> {
        self.validate_session(coordinates, prompt, sandbox)?;
        if !self.context_manifest().within_budget() {
            return Err(RunSpecError::FieldInvalid("context_manifest"));
        }
        if self
            .fallback_eligibility()
            .contains(self.integration_mode())
        {
            return Err(RunSpecError::FieldInvalid("fallback_eligibility"));
        }
        if let RunOrigin::NonInteractive(origin) = self.origin()
            && (origin.cause.actor() != sandbox.actor()
                || origin.cause.run() != coordinates.run_id())
        {
            return Err(RunSpecError::FieldInvalid("origin"));
        }
        if matches!(
            self.executor_class(),
            ExecutorClass::Ssh
                | ExecutorClass::Batch
                | ExecutorClass::Cluster
                | ExecutorClass::MicroVm
                | ExecutorClass::Remote(_)
        ) && self.remote_attestation_policy() == RemoteAttestationPolicy::NotRequired
        {
            return Err(RunSpecError::FieldInvalid("remote_attestation_policy"));
        }
        let descriptors = sandbox.credential_descriptors();
        if self.credential_bindings().len() != descriptors.len()
            || descriptors.iter().any(|descriptor| {
                self.credential_bindings()
                    .iter()
                    .filter(|binding| binding.name() == descriptor.name())
                    .count()
                    != 1
            })
        {
            return Err(RunSpecError::FieldInvalid("credential_bindings"));
        }
        Ok(())
    }

    fn validate_session(
        &self,
        coordinates: &RunCoordinates,
        prompt: &PromptDeliveryPlan,
        sandbox: &SandboxSpec,
    ) -> Result<(), RunSpecError> {
        if let Some(binding) = self.session_binding()
            && (binding.tenant() != sandbox.tenant()
                || binding.backend() != coordinates.backend().as_str()
                || binding.provider_account() != sandbox.provider_account().as_str())
        {
            return Err(RunSpecError::FieldInvalid("session_binding"));
        }
        if let PromptDeliveryPlan::BackendSession(session) = prompt {
            let Some(binding) = self.session_binding() else {
                return Err(RunSpecError::FieldInvalid("backend_prompt_session"));
            };
            if session.as_str() != binding.session().as_str() {
                return Err(RunSpecError::FieldInvalid("backend_prompt_session"));
            }
        }
        Ok(())
    }
}
