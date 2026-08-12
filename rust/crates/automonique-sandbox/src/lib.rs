// SPDX-License-Identifier: Elastic-2.0

//! Fail-closed sandbox plan compilation for the first runner foundation.
//!
//! This crate compiles policy and host evidence into a plan a runner may
//! consume. It does **not** install an operating-system boundary. The Linux
//! probe added here reads fixed kernel-owned process interfaces without taking
//! caller-supplied paths, but those observations do not prove that Landlock,
//! mount isolation, or network denial has been applied to a future worker.
//! Consequently every currently constructible plan remains observation-only.
//!
//! A sealed, runner-bound, one-use handoff is defined for a future enforcing
//! runner. No public path can issue one from an observation-only plan. This
//! keeps the binding and quarantine contract executable without mislabeling a
//! host observation as enforcement.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read as _;
#[cfg(target_os = "linux")]
use std::path::Path;

use automonique_protocol::sandbox::{
    FilesystemAccess, ImplementationDigest, NetworkAccess, PolicyDigest, ProviderControlEgress,
    SandboxProfile, ToolWorkloadEgress, WorkspaceContextHash,
};
use sha2::{Digest as _, Sha256};

mod release_trust;

pub use release_trust::{ReleaseBoundaryCandidate, ReleaseBoundaryError, ReleaseBoundaryParts};

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

    fn independently_observed_linux(observation: &[u8]) -> Self {
        Self {
            features: BTreeMap::new(),
            digest: ReportDigest(hash_canonical(observation)),
            source: EvidenceSource::IndependentlyObservedLinux,
        }
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
    /// Caller-supplied fixtures and fixed-path Linux observations are distinct
    /// evidence classes. Neither is an enforcement attestation.
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
    /// Read directly from fixed kernel-owned Linux process interfaces.
    IndependentlyObservedLinux,
    /// Pinned in reviewed product code rather than supplied at admission time.
    EmbeddedReviewedPolicy,
}

impl EvidenceSource {
    /// Stable spelling bound into plan and attestation digests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CallerSupplied => "caller_supplied",
            Self::IndependentlyObservedLinux => "independently_observed_linux",
            Self::EmbeddedReviewedPolicy => "embedded_reviewed_policy",
        }
    }
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

/// Fixed-path, read-only observation of the current Linux process host.
///
/// The probe intentionally reports no [`HostCapability`]. Kernel release,
/// namespace identities, security status, limits, and the current mount view
/// are independently observed and digest-bound, but none proves that a future
/// worker has had Landlock, private mounts, descriptor closure, or network
/// denial applied. Admission therefore fails closed on the first required
/// capability until a runner supplies real enforcement evidence.
#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxHostProbe;

impl LinuxHostProbe {
    /// Construct the fixed-path probe.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl HostFeatureProbe for LinuxHostProbe {
    fn probe(&self) -> Result<HostProbeReport, ProbeError> {
        independently_observe_linux()
    }
}

/// Probe construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeError {
    /// A probe reported one capability more than once.
    DuplicateFeature(HostCapability),
    /// An internally generated SHA-256 digest failed typed parsing.
    GeneratedDigestInvalid,
    /// The independently observed probe is available only on Linux.
    UnsupportedHost,
    /// A fixed kernel-owned observation could not be read safely.
    ObservationUnavailable(&'static str),
    /// A fixed kernel-owned observation exceeded its defensive byte ceiling.
    ObservationTooLarge(&'static str),
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
            Self::UnsupportedHost => formatter.write_str("Linux host observation is unavailable"),
            Self::ObservationUnavailable(observation) => {
                write!(
                    formatter,
                    "Linux host observation {observation} is unavailable"
                )
            }
            Self::ObservationTooLarge(observation) => {
                write!(
                    formatter,
                    "Linux host observation {observation} exceeded its limit"
                )
            }
        }
    }
}

impl Error for ProbeError {}

#[cfg(target_os = "linux")]
fn independently_observe_linux() -> Result<HostProbeReport, ProbeError> {
    const SMALL_LIMIT: usize = 64 * 1024;
    const MOUNTINFO_LIMIT: usize = 1024 * 1024;

    let os_release = read_fixed_linux_file(
        Path::new("/proc/sys/kernel/osrelease"),
        "kernel_release",
        SMALL_LIMIT,
    )?;
    let status = read_fixed_linux_file(
        Path::new("/proc/self/status"),
        "process_status",
        SMALL_LIMIT,
    )?;
    let limits = read_fixed_linux_file(
        Path::new("/proc/self/limits"),
        "process_limits",
        SMALL_LIMIT,
    )?;
    let mountinfo = read_fixed_linux_file(
        Path::new("/proc/self/mountinfo"),
        "mount_view",
        MOUNTINFO_LIMIT,
    )?;
    let security_status = selected_linux_status(&status)?;

    let mut canonical = String::from("schema=automonique.sandbox.linux-observation/v1\n");
    for (name, bytes) in [
        ("kernel_release", os_release.as_slice()),
        ("security_status", security_status.as_slice()),
        ("process_limits", limits.as_slice()),
        ("mount_view", mountinfo.as_slice()),
    ] {
        canonical.push_str("fact=");
        canonical.push_str(name);
        canonical.push('=');
        canonical.push_str(&hash_canonical(bytes));
        canonical.push('\n');
    }
    for (name, path) in [
        ("mount_namespace", "/proc/self/ns/mnt"),
        ("network_namespace", "/proc/self/ns/net"),
        ("pid_namespace", "/proc/self/ns/pid"),
        ("user_namespace", "/proc/self/ns/user"),
    ] {
        let identity =
            std::fs::read_link(path).map_err(|_| ProbeError::ObservationUnavailable(name))?;
        let identity = identity
            .to_str()
            .ok_or(ProbeError::ObservationUnavailable(name))?;
        if identity.len() > 256 || identity.chars().any(char::is_control) {
            return Err(ProbeError::ObservationUnavailable(name));
        }
        canonical.push_str("fact=");
        canonical.push_str(name);
        canonical.push('=');
        canonical.push_str(&hash_canonical(identity.as_bytes()));
        canonical.push('\n');
    }
    Ok(HostProbeReport::independently_observed_linux(
        canonical.as_bytes(),
    ))
}

#[cfg(not(target_os = "linux"))]
fn independently_observe_linux() -> Result<HostProbeReport, ProbeError> {
    Err(ProbeError::UnsupportedHost)
}

#[cfg(target_os = "linux")]
fn read_fixed_linux_file(
    path: &Path,
    name: &'static str,
    max_bytes: usize,
) -> Result<Vec<u8>, ProbeError> {
    let file = File::open(path).map_err(|_| ProbeError::ObservationUnavailable(name))?;
    let limit = u64::try_from(max_bytes)
        .map_err(|_| ProbeError::ObservationTooLarge(name))?
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| ProbeError::ObservationUnavailable(name))?;
    if bytes.len() > max_bytes {
        return Err(ProbeError::ObservationTooLarge(name));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn selected_linux_status(status: &[u8]) -> Result<Vec<u8>, ProbeError> {
    let status = std::str::from_utf8(status)
        .map_err(|_| ProbeError::ObservationUnavailable("process_status"))?;
    let mut selected = String::new();
    for field in ["NoNewPrivs:", "Seccomp:", "Seccomp_filters:"] {
        let line = status
            .lines()
            .find(|line| line.starts_with(field))
            .ok_or(ProbeError::ObservationUnavailable("process_status"))?;
        selected.push_str(line);
        selected.push('\n');
    }
    Ok(selected.into_bytes())
}

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
    policy_source: EvidenceSource,
    workspace_context: WorkspaceContextHash,
    provider_egress: ProviderEgressPolicy,
    tool_egress: ToolEgressPolicy,
    host_report_digest: ReportDigest,
    report_source: EvidenceSource,
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

    /// Provenance class of the exact policy bound into this plan.
    #[must_use]
    pub const fn policy_source(&self) -> EvidenceSource {
        self.policy_source
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

    /// Provenance class of the host evidence bound into the plan.
    #[must_use]
    pub const fn report_source(&self) -> EvidenceSource {
        self.report_source
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
    // Independent process observation is still not evidence that the runner
    // applied a boundary to a worker. Consequently neither supported mode is
    // runner-admissible in this slice.
    let use_class = PlanUse::ObservationOnly;
    let canonical = canonical_plan(CanonicalPlanParts {
        mode: request.mode,
        use_class,
        policy_digest: policy.digest(),
        policy_source: policy.source(),
        workspace_context: &request.workspace_context,
        provider_egress: request.provider_egress,
        tool_egress,
        host_report: report.digest(),
        report_source: report.source(),
        features: &admitted,
    });
    Ok(AdmissionPlan {
        mode: request.mode,
        use_class,
        profile,
        policy_digest: policy.digest.clone(),
        policy_source: policy.source,
        workspace_context: request.workspace_context,
        provider_egress: request.provider_egress,
        tool_egress,
        host_report_digest: report.digest.clone(),
        report_source: report.source,
        required_features: admitted,
        digest: PlanDigest(hash_canonical(canonical.as_bytes())),
    })
}

struct CanonicalPlanParts<'a> {
    mode: SupportedMode,
    use_class: PlanUse,
    policy_digest: &'a PolicyDigest,
    policy_source: EvidenceSource,
    workspace_context: &'a WorkspaceContextHash,
    provider_egress: ProviderEgressPolicy,
    tool_egress: ToolEgressPolicy,
    host_report: &'a ReportDigest,
    report_source: EvidenceSource,
    features: &'a [ProbedFeature],
}

fn canonical_plan(parts: CanonicalPlanParts<'_>) -> String {
    let mut value = format!(
        "schema=automonique.sandbox.admission/v1\nmode={}\nuse={}\npolicy={}\npolicy_source={}\nworkspace={}\nprovider_egress={}\ntool_egress={}\nhost_report={}\nreport_source={}\n",
        parts.mode.as_str(),
        parts.use_class.as_str(),
        parts.policy_digest,
        parts.policy_source.as_str(),
        parts.workspace_context,
        parts.provider_egress.as_str(),
        parts.tool_egress.as_str(),
        parts.host_report.as_str(),
        parts.report_source.as_str(),
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
    /// Fixed kernel-owned Linux process observations were bound; enforcement is
    /// still unverified.
    IndependentlyObservedLinux,
}

impl AttestationEvidence {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AdmissionInputsOnly => "admission_inputs_only",
            Self::IndependentlyObservedLinux => "independently_observed_linux",
        }
    }
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
            evidence: match plan.report_source {
                EvidenceSource::CallerSupplied | EvidenceSource::EmbeddedReviewedPolicy => {
                    AttestationEvidence::AdmissionInputsOnly
                }
                EvidenceSource::IndependentlyObservedLinux => {
                    AttestationEvidence::IndependentlyObservedLinux
                }
            },
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

const MAX_RUNNER_BINDING_ID_BYTES: usize = 160;
static NEXT_SEALER_ID: AtomicU64 = AtomicU64::new(1);

/// Exact runner, run, workspace root, and provider executable subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerBinding {
    runner_id: String,
    run_id: String,
    workspace_root_digest: ImplementationDigest,
    provider_executable_digest: ImplementationDigest,
}

impl RunnerBinding {
    /// Construct a bounded runner subject.
    pub fn new(
        runner_id: impl Into<String>,
        run_id: impl Into<String>,
        workspace_root_digest: ImplementationDigest,
        provider_executable_digest: ImplementationDigest,
    ) -> Result<Self, RunnerBindingError> {
        let runner_id = runner_id.into();
        let run_id = run_id.into();
        validate_runner_binding_id(&runner_id, "runner_id")?;
        validate_runner_binding_id(&run_id, "run_id")?;
        Ok(Self {
            runner_id,
            run_id,
            workspace_root_digest,
            provider_executable_digest,
        })
    }

    /// Exact runner process identity selected by the control plane.
    #[must_use]
    pub fn runner_id(&self) -> &str {
        &self.runner_id
    }

    /// Exact durable run identity.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Digest of the exact workspace root identity/manifest.
    #[must_use]
    pub const fn workspace_root_digest(&self) -> &ImplementationDigest {
        &self.workspace_root_digest
    }

    /// Digest of the exact provider executable selected for the run.
    #[must_use]
    pub const fn provider_executable_digest(&self) -> &ImplementationDigest {
        &self.provider_executable_digest
    }
}

/// Invalid runner/run coordinate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerBindingError {
    /// The named coordinate was empty, oversized, or contained a control.
    InvalidField(&'static str),
}

impl fmt::Display for RunnerBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(formatter, "invalid runner binding field {field}"),
        }
    }
}

impl Error for RunnerBindingError {}

/// In-process issuer for opaque runner handoffs.
///
/// Construction performs a fresh fixed-path Linux observation. The issuer
/// cannot turn that observation into authority: [`Self::issue`] additionally
/// requires a runner-admitted workspace-offline plan backed by reviewed policy
/// and the exact same independently observed report. No public plan compiler in
/// this slice produces such a plan.
#[derive(Debug)]
pub struct RunnerAdmissionSealer {
    issuer_digest: String,
    observed_report_digest: ReportDigest,
    next_token_sequence: u64,
}

impl RunnerAdmissionSealer {
    /// Independently observe the current Linux host and bind an issuer to it.
    pub fn observe() -> Result<Self, ProbeError> {
        let report = LinuxHostProbe::new().probe()?;
        Self::from_observed_report(&report)
    }

    fn from_observed_report(report: &HostProbeReport) -> Result<Self, ProbeError> {
        if report.source != EvidenceSource::IndependentlyObservedLinux {
            return Err(ProbeError::ObservationUnavailable("evidence_source"));
        }
        let instance = NEXT_SEALER_ID.fetch_add(1, Ordering::Relaxed);
        let issuer_digest = hash_canonical(
            format!(
                "schema=automonique.sandbox.runner-sealer/v1\nreport={}\nprocess={}\ninstance={}\n",
                report.digest.as_str(),
                std::process::id(),
                instance
            )
            .as_bytes(),
        );
        Ok(Self {
            issuer_digest,
            observed_report_digest: report.digest.clone(),
            next_token_sequence: 1,
        })
    }

    /// Seal one exact, runner-bound handoff.
    ///
    /// This refuses every plan currently available from public compilation.
    /// It becomes usable only when a later enforcing runner can produce an
    /// admitted plan with reviewed policy and independently observed evidence.
    pub fn issue(
        &mut self,
        plan: &AdmissionPlan,
        binding: RunnerBinding,
    ) -> Result<RunnerAdmissionToken, RunnerAdmissionError> {
        if plan.use_class != PlanUse::AdmittedForRunner {
            return Err(RunnerAdmissionError::ObservationOnly);
        }
        if plan.mode != SupportedMode::WorkspaceOffline {
            return Err(RunnerAdmissionError::UnsupportedMode);
        }
        if plan.provider_egress != ProviderEgressPolicy::Denied
            || plan.tool_egress != ToolEgressPolicy::Denied
        {
            return Err(RunnerAdmissionError::EgressNotDenied);
        }
        if plan.policy_source != EvidenceSource::EmbeddedReviewedPolicy {
            return Err(RunnerAdmissionError::UnreviewedPolicy);
        }
        if plan.report_source != EvidenceSource::IndependentlyObservedLinux
            || plan.host_report_digest != self.observed_report_digest
        {
            return Err(RunnerAdmissionError::ObservedReportMismatch);
        }
        let sequence = self.next_token_sequence;
        self.next_token_sequence = self
            .next_token_sequence
            .checked_add(1)
            .ok_or(RunnerAdmissionError::IssuerExhausted)?;
        let attestation = AdmissionAttestation::record(plan);
        let seal = runner_token_seal(&self.issuer_digest, sequence, plan, &binding, &attestation);
        Ok(RunnerAdmissionToken {
            issuer_digest: self.issuer_digest.clone(),
            sequence,
            plan_digest: plan.digest.clone(),
            policy_digest: plan.policy_digest.clone(),
            host_report_digest: plan.host_report_digest.clone(),
            workspace_context: plan.workspace_context.clone(),
            binding,
            recorded_attestation: attestation,
            seal,
            used: false,
        })
    }

    /// Refuse a release-manifest candidate until an independent review trust
    /// root can authenticate it.
    ///
    /// [`ReleaseBoundaryCandidate`] proves only that one canonical manifest
    /// declares the helper digest and is consistently bound to caller-declared
    /// boundary-installer, inert-fixture, workspace, provider, runner, and run
    /// coordinates. The checked-in release protocol has no signature or
    /// trusted release-store handle, so even a perfectly consistent
    /// caller-built candidate cannot mint a one-use token.
    pub fn issue_release_candidate(
        &mut self,
        _plan: &AdmissionPlan,
        _candidate: &ReleaseBoundaryCandidate,
    ) -> Result<RunnerAdmissionToken, RunnerAdmissionError> {
        Err(RunnerAdmissionError::MissingIndependentReleaseReview)
    }

    /// Consume one token for an exact subject and fresh observed attestation.
    ///
    /// Every attempt after seal validation consumes the token, including a
    /// wrong-subject or stale-attestation attempt. The returned receipt states
    /// only that the handoff matched; it is not OS enforcement evidence.
    pub fn consume(
        &self,
        token: &mut RunnerAdmissionToken,
        presented: &RunnerBinding,
        observed: &AdmissionAttestation,
    ) -> Result<RunnerAdmissionReceipt, RunnerAdmissionError> {
        if token.used {
            return Err(RunnerAdmissionError::AlreadyConsumed);
        }
        token.used = true;
        if token.issuer_digest != self.issuer_digest
            || token.seal != runner_token_seal_from_token(&self.issuer_digest, token)
        {
            return Err(RunnerAdmissionError::SealMismatch);
        }
        if token.binding.runner_id != presented.runner_id
            || token.binding.run_id != presented.run_id
        {
            return Err(RunnerAdmissionError::WrongSubject);
        }
        if token.binding.workspace_root_digest != presented.workspace_root_digest {
            return Err(RunnerAdmissionError::WorkspaceDigestMismatch);
        }
        if token.binding.provider_executable_digest != presented.provider_executable_digest {
            return Err(RunnerAdmissionError::ProviderDigestMismatch);
        }
        if let AdoptionOutcome::Quarantined(quarantine) =
            adopt(Some(&token.recorded_attestation), Some(observed))
        {
            return Err(RunnerAdmissionError::Quarantined(quarantine.reason()));
        }
        Ok(RunnerAdmissionReceipt {
            plan_digest: token.plan_digest.clone(),
            workspace_context: token.workspace_context.clone(),
            binding: token.binding.clone(),
        })
    }
}

/// Opaque one-use handoff. It is deliberately neither cloneable nor serializable.
pub struct RunnerAdmissionToken {
    issuer_digest: String,
    sequence: u64,
    plan_digest: PlanDigest,
    policy_digest: PolicyDigest,
    host_report_digest: ReportDigest,
    workspace_context: WorkspaceContextHash,
    binding: RunnerBinding,
    recorded_attestation: AdmissionAttestation,
    seal: String,
    used: bool,
}

impl fmt::Debug for RunnerAdmissionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunnerAdmissionToken")
            .field("sequence", &self.sequence)
            .field("plan_digest", &self.plan_digest)
            .field("binding", &self.binding)
            .field("used", &self.used)
            .finish_non_exhaustive()
    }
}

/// Successful exact-token adoption by its selected runner.
///
/// This receipt is admission evidence only. It does not claim that the runner
/// installed a mount, Landlock, network, process, or resource boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerAdmissionReceipt {
    plan_digest: PlanDigest,
    workspace_context: WorkspaceContextHash,
    binding: RunnerBinding,
}

impl RunnerAdmissionReceipt {
    /// Exact plan admitted for handoff.
    #[must_use]
    pub const fn plan_digest(&self) -> &PlanDigest {
        &self.plan_digest
    }

    /// Exact workspace security context.
    #[must_use]
    pub const fn workspace_context(&self) -> &WorkspaceContextHash {
        &self.workspace_context
    }

    /// Exact runner/run/workspace/provider subject.
    #[must_use]
    pub const fn binding(&self) -> &RunnerBinding {
        &self.binding
    }
}

/// Refusal to issue or consume runner admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerAdmissionError {
    /// The plan carries no runner authority.
    ObservationOnly,
    /// Only the minimal workspace-offline mode is eligible.
    UnsupportedMode,
    /// Both provider and tool network must be denied.
    EgressNotDenied,
    /// Caller-supplied policy cannot mint runner authority.
    UnreviewedPolicy,
    /// The plan was not built from this issuer's independent observation.
    ObservedReportMismatch,
    /// A consistent release-manifest candidate lacks an independent release
    /// review trust root and therefore cannot authorize execution.
    MissingIndependentReleaseReview,
    /// The issuer exhausted its unique in-process sequence.
    IssuerExhausted,
    /// This exact token was already attempted.
    AlreadyConsumed,
    /// The token did not originate from this issuer or its immutable seal drifted.
    SealMismatch,
    /// Runner or durable run identity differed.
    WrongSubject,
    /// Workspace-root identity/manifest digest differed.
    WorkspaceDigestMismatch,
    /// Provider executable digest differed.
    ProviderDigestMismatch,
    /// Fresh observed evidence mismatched and execution is quarantined.
    Quarantined(QuarantineReason),
}

impl fmt::Display for RunnerAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObservationOnly => formatter.write_str("plan is observation-only"),
            Self::UnsupportedMode => formatter.write_str("plan mode is not workspace-offline"),
            Self::EgressNotDenied => formatter.write_str("runner admission requires denied egress"),
            Self::UnreviewedPolicy => formatter.write_str("admission policy is caller-supplied"),
            Self::ObservedReportMismatch => {
                formatter.write_str("plan does not match this observed host report")
            }
            Self::MissingIndependentReleaseReview => {
                formatter.write_str("release candidate lacks independent release review")
            }
            Self::IssuerExhausted => formatter.write_str("runner admission issuer is exhausted"),
            Self::AlreadyConsumed => formatter.write_str("runner admission token was already used"),
            Self::SealMismatch => formatter.write_str("runner admission token seal mismatched"),
            Self::WrongSubject => formatter.write_str("runner admission subject mismatched"),
            Self::WorkspaceDigestMismatch => {
                formatter.write_str("workspace root digest mismatched")
            }
            Self::ProviderDigestMismatch => {
                formatter.write_str("provider executable digest mismatched")
            }
            Self::Quarantined(reason) => {
                write!(formatter, "runner admission quarantined: {reason:?}")
            }
        }
    }
}

impl Error for RunnerAdmissionError {}

fn validate_runner_binding_id(value: &str, field: &'static str) -> Result<(), RunnerBindingError> {
    if value.is_empty()
        || value.len() > MAX_RUNNER_BINDING_ID_BYTES
        || value.chars().any(char::is_control)
    {
        Err(RunnerBindingError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn runner_token_seal(
    issuer_digest: &str,
    sequence: u64,
    plan: &AdmissionPlan,
    binding: &RunnerBinding,
    attestation: &AdmissionAttestation,
) -> String {
    runner_token_seal_parts(RunnerTokenSealParts {
        issuer_digest,
        sequence,
        plan_digest: &plan.digest,
        policy_digest: &plan.policy_digest,
        host_report_digest: &plan.host_report_digest,
        workspace_context: &plan.workspace_context,
        binding,
        attestation,
    })
}

fn runner_token_seal_from_token(issuer_digest: &str, token: &RunnerAdmissionToken) -> String {
    runner_token_seal_parts(RunnerTokenSealParts {
        issuer_digest,
        sequence: token.sequence,
        plan_digest: &token.plan_digest,
        policy_digest: &token.policy_digest,
        host_report_digest: &token.host_report_digest,
        workspace_context: &token.workspace_context,
        binding: &token.binding,
        attestation: &token.recorded_attestation,
    })
}

struct RunnerTokenSealParts<'a> {
    issuer_digest: &'a str,
    sequence: u64,
    plan_digest: &'a PlanDigest,
    policy_digest: &'a PolicyDigest,
    host_report_digest: &'a ReportDigest,
    workspace_context: &'a WorkspaceContextHash,
    binding: &'a RunnerBinding,
    attestation: &'a AdmissionAttestation,
}

fn runner_token_seal_parts(parts: RunnerTokenSealParts<'_>) -> String {
    hash_canonical(
        format!(
            "schema=automonique.sandbox.runner-token/v1\nissuer={}\nsequence={}\nplan={}\npolicy={}\nreport={}\nworkspace_context={}\nrunner={}\nrun={}\nworkspace_root={}\nprovider_executable={}\nattested_plan={}\nattested_report={}\nattestation_evidence={}\n",
            parts.issuer_digest,
            parts.sequence,
            parts.plan_digest,
            parts.policy_digest,
            parts.host_report_digest.as_str(),
            parts.workspace_context,
            parts.binding.runner_id,
            parts.binding.run_id,
            parts.binding.workspace_root_digest,
            parts.binding.provider_executable_digest,
            parts.attestation.plan_digest,
            parts.attestation.host_report_digest.as_str(),
            parts.attestation.evidence.as_str(),
        )
        .as_bytes(),
    )
}

#[cfg(test)]
mod runner_admission_tests {
    use super::*;

    fn typed_digest(seed: u8) -> ImplementationDigest {
        ImplementationDigest::parse(&format!("sha256:{seed:02x}{}", "00".repeat(31)))
            .expect("test digest")
    }

    pub(super) fn observed_report() -> HostProbeReport {
        let mut report = HostProbeReport::new(HostCapability::ALL.into_iter().enumerate().map(
            |(index, capability)| ProbedFeature::new(capability, typed_digest(index as u8 + 1)),
        ))
        .expect("feature report");
        report.source = EvidenceSource::IndependentlyObservedLinux;
        report.digest = ReportDigest(hash_canonical(
            format!("test-observed-report={}\n", report.digest.as_str()).as_bytes(),
        ));
        report
    }

    pub(super) fn runner_plan(report: &HostProbeReport) -> AdmissionPlan {
        let mut policy = AdmissionPolicy::new(HostCapability::ALL.into_iter().enumerate().map(
            |(index, capability)| ProbedFeature::new(capability, typed_digest(index as u8 + 1)),
        ))
        .expect("policy");
        policy.source = EvidenceSource::EmbeddedReviewedPolicy;
        let mut plan = compile_report(
            CompileRequest {
                mode: SupportedMode::WorkspaceOffline,
                policy_digest: policy.digest.clone(),
                workspace_context: WorkspaceContextHash::parse(&format!(
                    "sha256:41{}",
                    "00".repeat(31)
                ))
                .expect("workspace context"),
                provider_egress: ProviderEgressPolicy::Denied,
            },
            &policy,
            report,
        )
        .expect("future runner plan inputs");
        plan.use_class = PlanUse::AdmittedForRunner;
        refresh_plan_digest(&mut plan);
        plan
    }

    fn refresh_plan_digest(plan: &mut AdmissionPlan) {
        let canonical = canonical_plan(CanonicalPlanParts {
            mode: plan.mode,
            use_class: plan.use_class,
            policy_digest: &plan.policy_digest,
            policy_source: plan.policy_source,
            workspace_context: &plan.workspace_context,
            provider_egress: plan.provider_egress,
            tool_egress: plan.tool_egress,
            host_report: &plan.host_report_digest,
            report_source: plan.report_source,
            features: &plan.required_features,
        });
        plan.digest = PlanDigest(hash_canonical(canonical.as_bytes()));
    }

    fn binding(runner: &str, run: &str, workspace_seed: u8, provider_seed: u8) -> RunnerBinding {
        RunnerBinding::new(
            runner,
            run,
            typed_digest(workspace_seed),
            typed_digest(provider_seed),
        )
        .expect("binding")
    }

    fn fixture() -> (RunnerAdmissionSealer, AdmissionPlan, RunnerBinding) {
        let report = observed_report();
        let sealer = RunnerAdmissionSealer::from_observed_report(&report).expect("sealer");
        let plan = runner_plan(&report);
        let binding = binding("runner-a", "run-a", 31, 32);
        (sealer, plan, binding)
    }

    #[test]
    fn token_is_single_use_and_bound_to_exact_subject() {
        let (mut sealer, plan, exact) = fixture();
        let observed = AdmissionAttestation::record(&plan);
        let mut token = sealer.issue(&plan, exact.clone()).expect("issued");
        let receipt = sealer
            .consume(&mut token, &exact, &observed)
            .expect("consumed once");
        assert_eq!(receipt.binding(), &exact);
        assert_eq!(
            sealer.consume(&mut token, &exact, &observed),
            Err(RunnerAdmissionError::AlreadyConsumed)
        );

        let mut token = sealer.issue(&plan, exact.clone()).expect("issued");
        let wrong_subject = binding("runner-b", "run-a", 31, 32);
        assert_eq!(
            sealer.consume(&mut token, &wrong_subject, &observed),
            Err(RunnerAdmissionError::WrongSubject)
        );
        assert_eq!(
            sealer.consume(&mut token, &exact, &observed),
            Err(RunnerAdmissionError::AlreadyConsumed),
            "a failed widening attempt also burns the token"
        );
    }

    #[test]
    fn workspace_and_provider_digest_widening_are_refused() {
        let (mut sealer, plan, exact) = fixture();
        let observed = AdmissionAttestation::record(&plan);
        let mut workspace_token = sealer.issue(&plan, exact.clone()).expect("issued");
        let wrong_workspace = binding("runner-a", "run-a", 33, 32);
        assert_eq!(
            sealer.consume(&mut workspace_token, &wrong_workspace, &observed),
            Err(RunnerAdmissionError::WorkspaceDigestMismatch)
        );

        let mut provider_token = sealer.issue(&plan, exact).expect("issued");
        let wrong_provider = binding("runner-a", "run-a", 31, 34);
        assert_eq!(
            sealer.consume(&mut provider_token, &wrong_provider, &observed),
            Err(RunnerAdmissionError::ProviderDigestMismatch)
        );
    }

    #[test]
    fn observed_attestation_drift_quarantines() {
        let (mut sealer, plan, exact) = fixture();
        let mut changed = AdmissionAttestation::record(&plan);
        changed.host_report_digest = ReportDigest(hash_canonical(b"changed observed report"));
        let mut token = sealer.issue(&plan, exact.clone()).expect("issued");
        assert_eq!(
            sealer.consume(&mut token, &exact, &changed),
            Err(RunnerAdmissionError::Quarantined(
                QuarantineReason::HostReportMismatch
            ))
        );
    }

    #[test]
    fn observation_only_and_caller_policy_cannot_issue() {
        let report = observed_report();
        let mut sealer =
            RunnerAdmissionSealer::from_observed_report(&report).expect("observed sealer");
        let mut plan = runner_plan(&report);
        let exact = binding("runner-a", "run-a", 31, 32);
        plan.use_class = PlanUse::ObservationOnly;
        refresh_plan_digest(&mut plan);
        assert!(matches!(
            sealer.issue(&plan, exact.clone()),
            Err(RunnerAdmissionError::ObservationOnly)
        ));

        plan.use_class = PlanUse::AdmittedForRunner;
        plan.policy_source = EvidenceSource::CallerSupplied;
        refresh_plan_digest(&mut plan);
        assert!(matches!(
            sealer.issue(&plan, exact),
            Err(RunnerAdmissionError::UnreviewedPolicy)
        ));
    }
}
