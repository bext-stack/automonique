// SPDX-License-Identifier: Elastic-2.0

//! Runner-owned, admission-only RunSpec fields with no protocol equivalent.
//!
//! Binding IDs and digests are domain-distinct:
//!
//! ```compile_fail
//! use automonique_runner::{ArtifactGrantDigest, SchedulerDecisionDigest};
//! let scheduler = SchedulerDecisionDigest::parse(
//!     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
//! ).unwrap();
//! let artifact: ArtifactGrantDigest = scheduler;
//! ```

use crate::{PromptDeliveryPlan, RunCoordinates, RunSpecError};
use automonique_protocol::automation::DurableId;
use automonique_protocol::context::ContextManifest;
use automonique_protocol::models::ExecutorClass;
use automonique_protocol::models::{ArtifactTransfer, WorkspaceTransfer};
use automonique_protocol::primitives::Revision;
use automonique_protocol::provider::{Capability, MAX_CAPABILITIES, SessionBinding};
use automonique_protocol::sandbox::{Digest, DigestAlgorithm, SandboxSpec};
use automonique_protocol::tools::{CredentialAudiences, NestedCause};
use automonique_protocol::wire::MAX_JSON_ENTRIES;
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::num::NonZeroU64;

pub const MAX_FALLBACK_MODES: usize = 16;
pub const MAX_ORIGIN_CAUSES: usize = 64;
pub const MAX_ARTIFACT_GRANT_BINDINGS: usize = 128;
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

fn opaque_ascii(value: &str, field: &'static str) -> Result<(), RunSpecError> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(RunSpecError::FieldInvalid(field));
    };
    if value.len() > MAX_LOCAL_FIELD_BYTES
        || !first.is_ascii_alphanumeric()
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || matches!(value, "." | "..")
    {
        return Err(RunSpecError::FieldInvalid(field));
    }
    Ok(())
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
pub struct SchedulerDecisionDomain;
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArtifactGrantDomain;

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
digest_type!(
    SchedulerDecisionDigest,
    SchedulerDecisionDomain,
    "scheduler_decision_digest"
);
digest_type!(
    ArtifactGrantDigest,
    ArtifactGrantDomain,
    "artifact_grant_digest"
);

macro_rules! opaque_id_type {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: &str) -> Result<Self, RunSpecError> {
                opaque_ascii(value, $field)?;
                Ok(Self(value.to_owned()))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<opaque>)"))
            }
        }
    };
}

opaque_id_type!(
    /// Opaque scheduler record coordinate, distinct from artifact grant IDs.
    ///
    /// ```compile_fail
    /// use automonique_runner::{ArtifactGrantId, SchedulerReservationId};
    /// let scheduler = SchedulerReservationId::new("reservation-1").unwrap();
    /// let artifact: ArtifactGrantId = scheduler;
    /// ```
    SchedulerReservationId,
    "scheduler_reservation_id"
);
opaque_id_type!(ArtifactGrantId, "artifact_grant_id");

#[derive(Clone, Eq, PartialEq)]
pub struct SchedulerReservationBinding {
    id: SchedulerReservationId,
    revision: Revision,
    decision_digest: SchedulerDecisionDigest,
}

impl SchedulerReservationBinding {
    #[must_use]
    pub const fn new(
        id: SchedulerReservationId,
        revision: Revision,
        decision_digest: SchedulerDecisionDigest,
    ) -> Self {
        Self {
            id,
            revision,
            decision_digest,
        }
    }

    #[must_use]
    pub const fn id(&self) -> &SchedulerReservationId {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn decision_digest(&self) -> &SchedulerDecisionDigest {
        &self.decision_digest
    }
}

impl core::fmt::Debug for SchedulerReservationBinding {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SchedulerReservationBinding(<non-authorizing>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ArtifactGrantBinding {
    id: ArtifactGrantId,
    revision: Revision,
    grant_digest: ArtifactGrantDigest,
}

impl ArtifactGrantBinding {
    #[must_use]
    pub const fn new(
        id: ArtifactGrantId,
        revision: Revision,
        grant_digest: ArtifactGrantDigest,
    ) -> Self {
        Self {
            id,
            revision,
            grant_digest,
        }
    }

    #[must_use]
    pub const fn id(&self) -> &ArtifactGrantId {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn grant_digest(&self) -> &ArtifactGrantDigest {
        &self.grant_digest
    }
}

impl core::fmt::Debug for ArtifactGrantBinding {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ArtifactGrantBinding(<non-authorizing>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ArtifactGrantBindings(Vec<ArtifactGrantBinding>);

impl ArtifactGrantBindings {
    pub fn declare(bindings: Vec<ArtifactGrantBinding>) -> Result<Self, RunSpecError> {
        if bindings.len() > MAX_ARTIFACT_GRANT_BINDINGS {
            return Err(RunSpecError::FieldInvalid("artifact_grants"));
        }
        let mut ids = BTreeSet::new();
        if bindings
            .iter()
            .any(|binding| !ids.insert(binding.id().as_str()))
        {
            return Err(RunSpecError::FieldInvalid("artifact_grants"));
        }
        Ok(Self(bindings))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[ArtifactGrantBinding] {
        &self.0
    }
}

impl core::fmt::Debug for ArtifactGrantBindings {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "ArtifactGrantBindings(<{} references>)",
            self.0.len()
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunOrigin {
    Interactive,
    NonInteractive(Box<NonInteractiveOrigin>),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RunOriginSource {
    Interactive,
    Automation,
    Goal,
    Trigger,
    Schedule,
    Recovery,
    GraphChild,
    BackgroundCuration,
    Media,
    RemoteWakeup,
    Batch,
    Evaluation,
}

impl RunOriginSource {
    /// Every origin source in canonical codec order.
    pub const ALL: [Self; 12] = [
        Self::Interactive,
        Self::Automation,
        Self::Goal,
        Self::Trigger,
        Self::Schedule,
        Self::Recovery,
        Self::GraphChild,
        Self::BackgroundCuration,
        Self::Media,
        Self::RemoteWakeup,
        Self::Batch,
        Self::Evaluation,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Automation => "automation",
            Self::Goal => "goal",
            Self::Trigger => "trigger",
            Self::Schedule => "schedule",
            Self::Recovery => "recovery",
            Self::GraphChild => "graph_child",
            Self::BackgroundCuration => "background_curation",
            Self::Media => "media",
            Self::RemoteWakeup => "remote_wakeup",
            Self::Batch => "batch",
            Self::Evaluation => "evaluation",
        }
    }

    /// Parse an exact stable spelling.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|source| source.as_str() == value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OriginCoordinate {
    None,
    Automation(DurableId),
    Goal(DurableId),
    Trigger(DurableId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonInteractiveOrigin {
    source: RunOriginSource,
    event_id: DurableId,
    coordinate: OriginCoordinate,
    causal_events: Vec<DurableId>,
    cause: NestedCause,
}

impl RunOrigin {
    pub fn non_interactive(
        source: RunOriginSource,
        event_id: DurableId,
        coordinate: OriginCoordinate,
        causal_events: Vec<DurableId>,
        cause: NestedCause,
    ) -> Result<Self, RunSpecError> {
        let coordinate_matches = matches!(
            (source, &coordinate),
            (RunOriginSource::Automation, OriginCoordinate::Automation(_))
                | (RunOriginSource::Goal, OriginCoordinate::Goal(_))
                | (RunOriginSource::Trigger, OriginCoordinate::Trigger(_))
                | (
                    RunOriginSource::Schedule
                        | RunOriginSource::Recovery
                        | RunOriginSource::GraphChild
                        | RunOriginSource::BackgroundCuration
                        | RunOriginSource::Media
                        | RunOriginSource::RemoteWakeup
                        | RunOriginSource::Batch
                        | RunOriginSource::Evaluation,
                    OriginCoordinate::None
                )
        );
        if !coordinate_matches {
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
            source,
            event_id,
            coordinate,
            causal_events,
            cause,
        })))
    }

    #[must_use]
    pub const fn source(&self) -> RunOriginSource {
        match self {
            Self::Interactive => RunOriginSource::Interactive,
            Self::NonInteractive(origin) => origin.source,
        }
    }

    #[must_use]
    pub const fn non_interactive_details(&self) -> Option<&NonInteractiveOrigin> {
        match self {
            Self::Interactive => None,
            Self::NonInteractive(origin) => Some(origin),
        }
    }
}

impl NonInteractiveOrigin {
    #[must_use]
    pub const fn source(&self) -> RunOriginSource {
        self.source
    }

    #[must_use]
    pub const fn event_id(&self) -> &DurableId {
        &self.event_id
    }

    #[must_use]
    pub const fn automation(&self) -> Option<&DurableId> {
        match &self.coordinate {
            OriginCoordinate::Automation(id) => Some(id),
            _ => None,
        }
    }

    #[must_use]
    pub const fn goal(&self) -> Option<&DurableId> {
        match &self.coordinate {
            OriginCoordinate::Goal(id) => Some(id),
            _ => None,
        }
    }

    #[must_use]
    pub const fn trigger(&self) -> Option<&DurableId> {
        match &self.coordinate {
            OriginCoordinate::Trigger(id) => Some(id),
            _ => None,
        }
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

impl PortabilityPolicy {
    /// Stable spelling of the portability policy kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pinned => "pinned",
            Self::Portable { .. } => "portable",
        }
    }

    /// The workspace transfer coordinate, only for a portable policy.
    #[must_use]
    pub const fn workspace_transfer(self) -> Option<WorkspaceTransfer> {
        match self {
            Self::Pinned => None,
            Self::Portable {
                workspace_transfer, ..
            } => Some(workspace_transfer),
        }
    }

    /// The artifact transfer coordinate, only for a portable policy.
    #[must_use]
    pub const fn artifact_transfer(self) -> Option<ArtifactTransfer> {
        match self {
            Self::Pinned => None,
            Self::Portable {
                artifact_transfer, ..
            } => Some(artifact_transfer),
        }
    }

    /// Reconstruct a policy from its exact spelling and optional transfers.
    ///
    /// `pinned` accepts no transfer payload and `portable` requires both
    /// transfers. Unknown spellings and every missing or extra payload refuse.
    #[must_use]
    pub fn from_spelling(
        value: &str,
        workspace_transfer: Option<WorkspaceTransfer>,
        artifact_transfer: Option<ArtifactTransfer>,
    ) -> Option<Self> {
        match (value, workspace_transfer, artifact_transfer) {
            ("pinned", None, None) => Some(Self::Pinned),
            ("portable", Some(workspace_transfer), Some(artifact_transfer)) => {
                Some(Self::Portable {
                    workspace_transfer,
                    artifact_transfer,
                })
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteAttestationPolicy {
    NotRequired,
    Signed,
    MutuallyAuthenticated,
}

impl RemoteAttestationPolicy {
    /// Every remote-attestation requirement in canonical codec order.
    pub const ALL: [Self; 3] = [Self::NotRequired, Self::Signed, Self::MutuallyAuthenticated];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::Signed => "signed",
            Self::MutuallyAuthenticated => "mutually_authenticated",
        }
    }

    /// Parse an exact stable spelling.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|policy| policy.as_str() == value)
    }
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

impl RunnerEventDialect {
    /// Every runner event dialect in canonical codec order.
    pub const ALL: [Self; 1] = [Self::AutomoniqueRunnerV1];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutomoniqueRunnerV1 => "automonique_runner_v1",
        }
    }

    /// Parse an exact stable spelling.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|dialect| dialect.as_str() == value)
    }
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
    pub scheduler_reservation: SchedulerReservationBinding,
    pub artifact_grants: ArtifactGrantBindings,
    pub credential_bindings: Vec<CredentialBinding>,
    pub event_dialect: RunnerEventDialect,
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
    pub const fn scheduler_reservation(&self) -> &SchedulerReservationBinding {
        &self.0.scheduler_reservation
    }
    pub fn artifact_grants(&self) -> &[ArtifactGrantBinding] {
        self.0.artifact_grants.as_slice()
    }
    pub fn credential_bindings(&self) -> &[CredentialBinding] {
        &self.0.credential_bindings
    }
    pub const fn event_dialect(&self) -> RunnerEventDialect {
        self.0.event_dialect
    }
    pub(crate) fn validate_against(
        &self,
        coordinates: &RunCoordinates,
        prompt: &PromptDeliveryPlan,
        sandbox: &SandboxSpec,
    ) -> Result<(), RunSpecError> {
        self.validate_session(coordinates, prompt, sandbox)?;
        let context = self.context_manifest();
        if context.policy().len() > MAX_JSON_ENTRIES || context.supplied().len() > MAX_JSON_ENTRIES
        {
            return Err(RunSpecError::FieldInvalid("context_manifest"));
        }
        let declared_tokens = context
            .policy()
            .iter()
            .map(|component| component.caps().token_cap())
            .chain(
                context
                    .supplied()
                    .iter()
                    .map(|component| component.caps().token_cap()),
            )
            .try_fold(0_u64, u64::checked_add)
            .ok_or(RunSpecError::FieldInvalid("context_manifest"))?;
        if declared_tokens > context.token_budget().total_tokens() {
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
