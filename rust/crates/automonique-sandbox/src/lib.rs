// SPDX-License-Identifier: Elastic-2.0

//! Fail-closed sandbox plan compilation for the first runner foundation.
//!
//! This crate compiles reviewed policy and a host feature report into a plan a
//! runner may consume. It does **not** install or verify an operating-system
//! boundary. In particular, a successful admission means “the reported host
//! features match the pinned policy”, not “Landlock, namespaces or resource
//! controls are active”. The runner must apply those controls and supply its
//! own independently observed enforcement evidence in a later slice.
//! The only policy and report constructors currently exposed accept
//! caller-supplied inputs, so their plans remain observation-only and cannot be
//! presented as production-runner admission.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use automonique_protocol::sandbox::{
    FilesystemAccess, ImplementationDigest, NetworkAccess, PolicyDigest, ProviderControlEgress,
    SandboxProfile, ToolWorkloadEgress, WorkspaceContextHash,
};
use sha2::{Digest as _, Sha256};

/// Stable feature names understood by this compiler.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HostCapability {
    /// A mount view that excludes unrelated host paths.
    PrivateMountView,
    /// A Landlock ruleset can be installed by the runner.
    Landlock,
    /// A dedicated descendant-owning process boundary is available.
    ProcessBoundary,
    /// Resource limits and bounded runtime are available.
    ResourceLimits,
    /// Ambient descriptors and sockets can be closed or explicitly inherited.
    DescriptorIsolation,
    /// Tool/workload network denial can be enforced independently.
    ToolNetworkDeny,
    /// A writable isolated workspace can be provisioned.
    IsolatedWritableWorkspace,
    /// Trusted provider-control egress can be separated from tool egress.
    ProviderControlSeparation,
}

impl HostCapability {
    /// Every capability known by this crate.
    pub const ALL: [Self; 8] = [
        Self::PrivateMountView,
        Self::Landlock,
        Self::ProcessBoundary,
        Self::ResourceLimits,
        Self::DescriptorIsolation,
        Self::ToolNetworkDeny,
        Self::IsolatedWritableWorkspace,
        Self::ProviderControlSeparation,
    ];

    /// Stable canonical spelling used in digests and findings.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrivateMountView => "private_mount_view",
            Self::Landlock => "landlock",
            Self::ProcessBoundary => "process_boundary",
            Self::ResourceLimits => "resource_limits",
            Self::DescriptorIsolation => "descriptor_isolation",
            Self::ToolNetworkDeny => "tool_network_deny",
            Self::IsolatedWritableWorkspace => "isolated_writable_workspace",
            Self::ProviderControlSeparation => "provider_control_separation",
        }
    }
}

/// The only profiles supported by the initial compiler.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SupportedMode {
    /// Immutable registered snapshot, read-only, with no tool network.
    Observe,
    /// One isolated writable workspace, with no tool network.
    WorkspaceOffline,
}

impl SupportedMode {
    /// Stable profile identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::WorkspaceOffline => "workspace-offline",
        }
    }

    const fn filesystem(self) -> FilesystemAccess {
        match self {
            Self::Observe => FilesystemAccess::ReadOnlySnapshot,
            Self::WorkspaceOffline => FilesystemAccess::IsolatedWritable,
        }
    }

    fn required_capabilities(self) -> BTreeSet<HostCapability> {
        let mut required = BTreeSet::from([
            HostCapability::PrivateMountView,
            HostCapability::Landlock,
            HostCapability::ProcessBoundary,
            HostCapability::ResourceLimits,
            HostCapability::DescriptorIsolation,
            HostCapability::ToolNetworkDeny,
        ]);
        if matches!(self, Self::WorkspaceOffline) {
            required.insert(HostCapability::IsolatedWritableWorkspace);
        }
        required
    }
}

/// Trusted-provider egress, deliberately distinct from tool egress.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProviderEgressPolicy {
    /// The provider receives no network authority.
    Denied,
    /// The runner may connect only through a separately reviewed named broker.
    BrokeredNamed,
}

impl ProviderEgressPolicy {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::BrokeredNamed => "brokered_named",
        }
    }

    const fn protocol_value(self) -> ProviderControlEgress {
        match self {
            Self::Denied => ProviderControlEgress::denied(),
            Self::BrokeredNamed => ProviderControlEgress::brokered(NetworkAccess::BrokeredNamed),
        }
    }
}

/// The tool-workload policy for both supported modes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ToolEgressPolicy {
    /// All model-directed tool network is denied.
    Denied,
}

impl ToolEgressPolicy {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        "denied"
    }

    const fn protocol_value(self) -> ToolWorkloadEgress {
        ToolWorkloadEgress::denied()
    }
}

/// Why an admitted plan may be consumed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PlanUse {
    /// Read-only observation work only; no mutating workload may use the plan.
    ObservationOnly,
    /// Eligible for a runner that subsequently applies and attests enforcement.
    AdmittedForRunner,
}

impl PlanUse {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObservationOnly => "observation_only",
            Self::AdmittedForRunner => "admitted_for_runner",
        }
    }
}

/// One feature reported by a host probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbedFeature {
    capability: HostCapability,
    implementation: ImplementationDigest,
}

impl ProbedFeature {
    /// Record an implementation observed by a probe.
    #[must_use]
    pub const fn new(capability: HostCapability, implementation: ImplementationDigest) -> Self {
        Self {
            capability,
            implementation,
        }
    }

    /// The capability reported.
    #[must_use]
    pub const fn capability(&self) -> HostCapability {
        self.capability
    }

    /// The observed implementation digest.
    #[must_use]
    pub const fn implementation(&self) -> &ImplementationDigest {
        &self.implementation
    }
}

/// A deterministic, duplicate-free host feature report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostProbeReport {
    features: BTreeMap<HostCapability, ImplementationDigest>,
    digest: ReportDigest,
    source: EvidenceSource,
}

impl HostProbeReport {
    /// Build a report. Duplicate capability reports fail closed.
    pub fn new(features: impl IntoIterator<Item = ProbedFeature>) -> Result<Self, ProbeError> {
        let mut collected = BTreeMap::new();
        for feature in features {
            if collected
                .insert(feature.capability, feature.implementation)
                .is_some()
            {
                return Err(ProbeError::DuplicateFeature(feature.capability));
            }
        }
        let digest = ReportDigest(hash_canonical(
            collected
                .iter()
                .map(|(capability, implementation)| {
                    format!("{}={implementation}\n", capability.as_str())
                })
                .collect::<String>()
                .as_bytes(),
        ));
        Ok(Self {
            features: collected,
            digest,
            source: EvidenceSource::CallerSupplied,
        })
    }

    /// Lookup the reported implementation of a capability.
    #[must_use]
    pub fn implementation(&self, capability: HostCapability) -> Option<&ImplementationDigest> {
        self.features.get(&capability)
    }

    /// Digest of the canonical report.
    #[must_use]
    pub const fn digest(&self) -> &ReportDigest {
        &self.digest
    }

    /// Provenance of this feature evidence.
    ///
    /// Reports constructed by this first slice are caller-supplied fixture
    /// inputs. They can be checked for internal consistency, but cannot make a
    /// plan eligible for a production runner.
    #[must_use]
    pub const fn source(&self) -> EvidenceSource {
        self.source
    }
}

/// Trust class of an admission input.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EvidenceSource {
    /// Supplied by the caller rather than independently observed or reviewed.
    CallerSupplied,
}

/// A source of host feature evidence.
///
/// The trait is intentionally observation-only: it cannot install a feature.
pub trait HostFeatureProbe {
    /// Probe without mutating host configuration.
    fn probe(&self) -> Result<HostProbeReport, ProbeError>;
}

/// A fixed, caller-supplied probe for fixtures and tests.
#[derive(Clone, Debug)]
pub struct StaticHostProbe {
    report: HostProbeReport,
}

impl StaticHostProbe {
    /// Wrap a previously validated report.
    #[must_use]
    pub const fn new(report: HostProbeReport) -> Self {
        Self { report }
    }
}

impl HostFeatureProbe for StaticHostProbe {
    fn probe(&self) -> Result<HostProbeReport, ProbeError> {
        Ok(self.report.clone())
    }
}

/// Probe construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeError {
    /// A probe reported one capability more than once.
    DuplicateFeature(HostCapability),
    /// An internally generated SHA-256 digest failed typed parsing.
    GeneratedDigestInvalid,
}

impl fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateFeature(capability) => {
                write!(formatter, "probe repeated {}", capability.as_str())
            }
            Self::GeneratedDigestInvalid => {
                formatter.write_str("generated admission digest was invalid")
            }
        }
    }
}

impl Error for ProbeError {}

/// Caller-supplied implementation pins for deterministic plan compilation.
///
/// Construction validates and hashes the pins but does not prove that they
/// came from a reviewed policy artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionPolicy {
    accepted: BTreeMap<HostCapability, ImplementationDigest>,
    digest: PolicyDigest,
    source: EvidenceSource,
}

impl AdmissionPolicy {
    /// Construct a duplicate-free pin set.
    pub fn new(features: impl IntoIterator<Item = ProbedFeature>) -> Result<Self, ProbeError> {
        let accepted = HostProbeReport::new(features)?.features;
        let canonical = accepted
            .iter()
            .map(|(capability, implementation)| {
                format!("{}={implementation}\n", capability.as_str())
            })
            .collect::<String>();
        let digest = PolicyDigest::parse(&hash_canonical(canonical.as_bytes()))
            .map_err(|_| ProbeError::GeneratedDigestInvalid)?;
        Ok(Self {
            accepted,
            digest,
            source: EvidenceSource::CallerSupplied,
        })
    }

    fn accepted(&self, capability: HostCapability) -> Option<&ImplementationDigest> {
        self.accepted.get(&capability)
    }

    /// Digest derived from the complete canonical pin set.
    #[must_use]
    pub const fn digest(&self) -> &PolicyDigest {
        &self.digest
    }

    /// Provenance of this policy input.
    #[must_use]
    pub const fn source(&self) -> EvidenceSource {
        self.source
    }
}

/// Inputs to one compilation.
#[derive(Clone, Debug)]
pub struct CompileRequest {
    /// Supported profile.
    pub mode: SupportedMode,
    /// Expected digest of the complete admission policy. Compilation compares
    /// this with the digest derived from `AdmissionPolicy`; it is not accepted
    /// as an independent assertion of policy contents.
    pub policy_digest: PolicyDigest,
    /// Workspace/tenant security-context digest.
    pub workspace_context: WorkspaceContextHash,
    /// Trusted provider-control egress.
    pub provider_egress: ProviderEgressPolicy,
}

/// A deterministic plan digest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlanDigest(String);

impl PlanDigest {
    /// Canonical `sha256:<hex>` spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PlanDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Digest of a canonical host probe report.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReportDigest(String);

impl ReportDigest {
    /// Canonical `sha256:<hex>` spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An immutable admission result. It is a runner input, not enforcement proof.
#[derive(Clone, Debug)]
pub struct AdmissionPlan {
    mode: SupportedMode,
    use_class: PlanUse,
    profile: SandboxProfile,
    policy_digest: PolicyDigest,
    workspace_context: WorkspaceContextHash,
    provider_egress: ProviderEgressPolicy,
    tool_egress: ToolEgressPolicy,
    host_report_digest: ReportDigest,
    required_features: Vec<ProbedFeature>,
    digest: PlanDigest,
}

impl AdmissionPlan {
    /// Supported mode.
    #[must_use]
    pub const fn mode(&self) -> SupportedMode {
        self.mode
    }

    /// Whether this is observation-only or eligible for runner enforcement.
    #[must_use]
    pub const fn use_class(&self) -> PlanUse {
        self.use_class
    }

    /// Protocol profile compiled for downstream use.
    #[must_use]
    pub const fn profile(&self) -> &SandboxProfile {
        &self.profile
    }

    /// Complete policy digest.
    #[must_use]
    pub const fn policy_digest(&self) -> &PolicyDigest {
        &self.policy_digest
    }

    /// Workspace security-context digest.
    #[must_use]
    pub const fn workspace_context(&self) -> &WorkspaceContextHash {
        &self.workspace_context
    }

    /// Trusted provider-control egress decision.
    #[must_use]
    pub const fn provider_egress(&self) -> ProviderEgressPolicy {
        self.provider_egress
    }

    /// Model-directed tool egress decision.
    #[must_use]
    pub const fn tool_egress(&self) -> ToolEgressPolicy {
        self.tool_egress
    }

    /// The protocol value for provider-control egress.
    #[must_use]
    pub const fn provider_control_egress(&self) -> ProviderControlEgress {
        self.provider_egress.protocol_value()
    }

    /// The protocol value for tool-workload egress.
    #[must_use]
    pub const fn tool_workload_egress(&self) -> ToolWorkloadEgress {
        self.tool_egress.protocol_value()
    }

    /// Digest of host evidence used for admission.
    #[must_use]
    pub const fn host_report_digest(&self) -> &ReportDigest {
        &self.host_report_digest
    }

    /// Required features and their exact accepted implementations.
    #[must_use]
    pub fn required_features(&self) -> &[ProbedFeature] {
        &self.required_features
    }

    /// Digest of the complete canonical plan.
    #[must_use]
    pub const fn digest(&self) -> &PlanDigest {
        &self.digest
    }
}

/// Admission refusal. There is no weaker-plan success variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    /// The request named a policy other than the policy passed to compilation.
    PolicyDigestMismatch {
        /// Digest expected by the request.
        requested: String,
        /// Digest computed from the actual policy pins.
        actual: String,
    },
    /// The host omitted a required capability.
    MissingHostFeature(HostCapability),
    /// Policy did not pin an implementation for a required capability.
    UnpinnedFeature(HostCapability),
    /// Host implementation differs from the reviewed pin.
    ImplementationRejected {
        /// Capability whose implementation differed.
        capability: HostCapability,
        /// Pinned implementation.
        accepted: String,
        /// Reported implementation.
        offered: String,
    },
    /// The protocol profile itself could not be constructed.
    InvalidProfile(String),
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyDigestMismatch { requested, actual } => write!(
                formatter,
                "request policy digest {requested} does not match actual policy {actual}"
            ),
            Self::MissingHostFeature(capability) => {
                write!(
                    formatter,
                    "required host feature {} is absent",
                    capability.as_str()
                )
            }
            Self::UnpinnedFeature(capability) => {
                write!(
                    formatter,
                    "required host feature {} has no policy pin",
                    capability.as_str()
                )
            }
            Self::ImplementationRejected {
                capability,
                accepted,
                offered,
            } => write!(
                formatter,
                "host feature {} used {offered}, expected {accepted}",
                capability.as_str()
            ),
            Self::InvalidProfile(reason) => write!(formatter, "invalid profile: {reason}"),
        }
    }
}

impl Error for AdmissionError {}

/// Compile the selected profile against a non-mutating host probe.
pub fn compile(
    request: CompileRequest,
    policy: &AdmissionPolicy,
    probe: &impl HostFeatureProbe,
) -> Result<AdmissionPlan, CompileError> {
    let report = probe.probe().map_err(CompileError::Probe)?;
    compile_report(request, policy, &report).map_err(CompileError::Admission)
}

/// Compilation failure with probe/admission provenance kept distinct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompileError {
    /// Host probing failed.
    Probe(ProbeError),
    /// The resulting report was refused.
    Admission(AdmissionError),
}

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Probe(error) => write!(formatter, "host probe failed: {error}"),
            Self::Admission(error) => error.fmt(formatter),
        }
    }
}

impl Error for CompileError {}

fn compile_report(
    request: CompileRequest,
    policy: &AdmissionPolicy,
    report: &HostProbeReport,
) -> Result<AdmissionPlan, AdmissionError> {
    if request.policy_digest != policy.digest {
        return Err(AdmissionError::PolicyDigestMismatch {
            requested: request.policy_digest.to_string(),
            actual: policy.digest.to_string(),
        });
    }

    let mut required = request.mode.required_capabilities();
    if matches!(request.provider_egress, ProviderEgressPolicy::BrokeredNamed) {
        required.insert(HostCapability::ProviderControlSeparation);
    }

    let mut admitted = Vec::with_capacity(required.len());
    for capability in required {
        let accepted = policy
            .accepted(capability)
            .ok_or(AdmissionError::UnpinnedFeature(capability))?;
        let offered = report
            .implementation(capability)
            .ok_or(AdmissionError::MissingHostFeature(capability))?;
        if offered != accepted {
            return Err(AdmissionError::ImplementationRejected {
                capability,
                accepted: accepted.to_string(),
                offered: offered.to_string(),
            });
        }
        admitted.push(ProbedFeature::new(capability, offered.clone()));
    }

    let tool_egress = ToolEgressPolicy::Denied;
    let profile = SandboxProfile::new(
        request.mode.as_str(),
        1,
        request.mode.filesystem(),
        tool_egress.protocol_value(),
    )
    .map_err(|error| AdmissionError::InvalidProfile(error.to_string()))?;
    // Both report and policy constructors in this slice accept caller-supplied
    // inputs. Matching those inputs proves deterministic compilation, not
    // independent observation, policy review, or OS enforcement. Consequently
    // neither supported mode is runner-admissible yet.
    let use_class = PlanUse::ObservationOnly;
    let canonical = canonical_plan(CanonicalPlanParts {
        mode: request.mode,
        use_class,
        policy_digest: policy.digest(),
        workspace_context: &request.workspace_context,
        provider_egress: request.provider_egress,
        tool_egress,
        host_report: report.digest(),
        features: &admitted,
    });
    Ok(AdmissionPlan {
        mode: request.mode,
        use_class,
        profile,
        policy_digest: policy.digest.clone(),
        workspace_context: request.workspace_context,
        provider_egress: request.provider_egress,
        tool_egress,
        host_report_digest: report.digest.clone(),
        required_features: admitted,
        digest: PlanDigest(hash_canonical(canonical.as_bytes())),
    })
}

struct CanonicalPlanParts<'a> {
    mode: SupportedMode,
    use_class: PlanUse,
    policy_digest: &'a PolicyDigest,
    workspace_context: &'a WorkspaceContextHash,
    provider_egress: ProviderEgressPolicy,
    tool_egress: ToolEgressPolicy,
    host_report: &'a ReportDigest,
    features: &'a [ProbedFeature],
}

fn canonical_plan(parts: CanonicalPlanParts<'_>) -> String {
    let mut value = format!(
        "schema=automonique.sandbox.admission/v1\nmode={}\nuse={}\npolicy={}\nworkspace={}\nprovider_egress={}\ntool_egress={}\nhost_report={}\n",
        parts.mode.as_str(),
        parts.use_class.as_str(),
        parts.policy_digest,
        parts.workspace_context,
        parts.provider_egress.as_str(),
        parts.tool_egress.as_str(),
        parts.host_report.as_str(),
    );
    for feature in parts.features {
        value.push_str("feature=");
        value.push_str(feature.capability.as_str());
        value.push('=');
        value.push_str(&feature.implementation.to_string());
        value.push('\n');
    }
    value
}

fn hash_canonical(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(7 + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// Whether an existing host plan can serve a requested plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReuseDecision {
    /// Same subject and identical-or-narrower requested authority.
    Reuse,
    /// A different or wider request needs a new reviewed host.
    RequiresNewHost,
}

/// Evaluate reuse without silently changing either plan.
#[must_use]
pub fn evaluate_reuse(existing: &AdmissionPlan, requested: &AdmissionPlan) -> ReuseDecision {
    let same_subject = existing.workspace_context == requested.workspace_context;
    let same_policy = existing.policy_digest == requested.policy_digest;
    let same_report = existing.host_report_digest == requested.host_report_digest;
    let same_implementations = requested.required_features.iter().all(|requested_feature| {
        existing.required_features.iter().any(|existing_feature| {
            existing_feature.capability == requested_feature.capability
                && existing_feature.implementation == requested_feature.implementation
        })
    });
    let mode_is_narrower = requested.mode <= existing.mode;
    let provider_is_narrower = requested.provider_egress <= existing.provider_egress;
    let tool_is_narrower = requested.tool_egress <= existing.tool_egress;
    if same_subject
        && same_policy
        && same_report
        && same_implementations
        && mode_is_narrower
        && provider_is_narrower
        && tool_is_narrower
    {
        ReuseDecision::Reuse
    } else {
        ReuseDecision::RequiresNewHost
    }
}

/// Provenance class for this slice's immutable attestation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AttestationEvidence {
    /// The admission compiler bound its own inputs; OS enforcement is unverified.
    AdmissionInputsOnly,
}

/// Immutable evidence binding the exact plan and host report used at admission.
///
/// This is deliberately not named an enforcement attestation. It proves only
/// that admission inputs are unchanged across adoption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionAttestation {
    plan_digest: PlanDigest,
    host_report_digest: ReportDigest,
    evidence: AttestationEvidence,
}

impl AdmissionAttestation {
    /// Bind an admitted plan's immutable inputs.
    #[must_use]
    pub fn record(plan: &AdmissionPlan) -> Self {
        Self {
            plan_digest: plan.digest.clone(),
            host_report_digest: plan.host_report_digest.clone(),
            evidence: AttestationEvidence::AdmissionInputsOnly,
        }
    }

    /// Plan digest.
    #[must_use]
    pub const fn plan_digest(&self) -> &PlanDigest {
        &self.plan_digest
    }

    /// Probe report digest.
    #[must_use]
    pub const fn host_report_digest(&self) -> &ReportDigest {
        &self.host_report_digest
    }

    /// Honest evidence class.
    #[must_use]
    pub const fn evidence(&self) -> AttestationEvidence {
        self.evidence
    }
}

/// Operations retained after a mismatch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QuarantinedOperation {
    /// Bounded observation.
    Observe,
    /// Reconcile durable evidence.
    Reconcile,
    /// Cancel the affected work.
    Cancel,
}

/// Why adoption quarantined the plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuarantineReason {
    /// No recorded evidence exists.
    MissingRecordedAttestation,
    /// No current observation exists.
    MissingObservedAttestation,
    /// The plan digest changed.
    PlanDigestMismatch,
    /// The host probe report changed.
    HostReportMismatch,
    /// The evidence class changed.
    EvidenceClassMismatch,
}

/// Restricted result of a refused adoption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Quarantine {
    reason: QuarantineReason,
}

impl Quarantine {
    /// The only operations retained while quarantined.
    pub const PERMITTED: [QuarantinedOperation; 3] = [
        QuarantinedOperation::Observe,
        QuarantinedOperation::Reconcile,
        QuarantinedOperation::Cancel,
    ];

    /// Why adoption failed.
    #[must_use]
    pub const fn reason(self) -> QuarantineReason {
        self.reason
    }

    /// Closed permitted operation set.
    #[must_use]
    pub const fn permitted_operations(self) -> [QuarantinedOperation; 3] {
        Self::PERMITTED
    }
}

/// Adoption result for admission evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionOutcome {
    /// Exact evidence match.
    Adopted,
    /// Missing or mismatched evidence; execution must not resume.
    Quarantined(Quarantine),
}

/// Compare recorded evidence to a fresh observation.
#[must_use]
pub fn adopt(
    recorded: Option<&AdmissionAttestation>,
    observed: Option<&AdmissionAttestation>,
) -> AdoptionOutcome {
    let reason = match (recorded, observed) {
        (None, _) => Some(QuarantineReason::MissingRecordedAttestation),
        (Some(_), None) => Some(QuarantineReason::MissingObservedAttestation),
        (Some(recorded), Some(observed)) => {
            if recorded.host_report_digest != observed.host_report_digest {
                Some(QuarantineReason::HostReportMismatch)
            } else if recorded.plan_digest != observed.plan_digest {
                Some(QuarantineReason::PlanDigestMismatch)
            } else if recorded.evidence != observed.evidence {
                Some(QuarantineReason::EvidenceClassMismatch)
            } else {
                None
            }
        }
    };
    match reason {
        None => AdoptionOutcome::Adopted,
        Some(reason) => AdoptionOutcome::Quarantined(Quarantine { reason }),
    }
}
