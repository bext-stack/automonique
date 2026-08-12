// SPDX-License-Identifier: Elastic-2.0

//! Read-only Linux execution-boundary detection.
//!
//! This module observes whether selected kernel interfaces are present. It
//! deliberately does not equate interface availability with an installed
//! boundary. No type in this module grants permission to launch a provider.
//! Every assessment produces a [`LaunchRefusal`] until a later implementation
//! can install and attest all requirements on the exact descendant tree.

use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::fmt;

#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
#[cfg(target_os = "linux")]
use std::io::Read as _;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt as _;
#[cfg(target_os = "linux")]
use std::path::Path;

const MAX_ID_BYTES: usize = 160;
const MAX_FIXED_OBSERVATION_BYTES: usize = 1024 * 1024;

/// Exact properties required before a provider process may be launched.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BoundaryRequirement {
    /// Every descendant remains in a kernel-owned containment domain.
    DescendantCompleteContainment,
    /// Only an explicit descriptor allowlist reaches the first child.
    DescriptorClosure,
    /// The writable workspace is isolated from unrelated host paths.
    FilesystemIsolation,
    /// Provider and descendants cannot create network traffic.
    NetworkDenial,
    /// Timeout/cancellation reaps every descendant and removes residue.
    CompleteCleanup,
}

impl BoundaryRequirement {
    /// Complete requirement set for a future provider-launch gate.
    pub const ALL: [Self; 5] = [
        Self::DescendantCompleteContainment,
        Self::DescriptorClosure,
        Self::FilesystemIsolation,
        Self::NetworkDenial,
        Self::CompleteCleanup,
    ];

    /// Stable spelling used in evidence digests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DescendantCompleteContainment => "descendant_complete_containment",
            Self::DescriptorClosure => "descriptor_closure",
            Self::FilesystemIsolation => "filesystem_isolation",
            Self::NetworkDenial => "network_denial",
            Self::CompleteCleanup => "complete_cleanup",
        }
    }
}

/// Kernel interface whose presence may support a later boundary installer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LinuxPrimitive {
    /// A cgroup v2 controller view is visible at the fixed kernel path.
    CgroupV2,
    /// The cgroup v2 atomic descendant-kill interface is visible.
    CgroupKill,
    /// The current process exposes a mount-namespace identity.
    MountNamespace,
    /// The current process exposes a network-namespace identity.
    NetworkNamespace,
    /// The kernel exposes the process descriptor directory.
    ProcessDescriptorView,
    /// The kernel publishes a Landlock security filesystem entry.
    LandlockInterface,
}

impl LinuxPrimitive {
    const ALL: [Self; 6] = [
        Self::CgroupV2,
        Self::CgroupKill,
        Self::MountNamespace,
        Self::NetworkNamespace,
        Self::ProcessDescriptorView,
        Self::LandlockInterface,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::CgroupV2 => "cgroup_v2",
            Self::CgroupKill => "cgroup_kill",
            Self::MountNamespace => "mount_namespace",
            Self::NetworkNamespace => "network_namespace",
            Self::ProcessDescriptorView => "process_descriptor_view",
            Self::LandlockInterface => "landlock_interface",
        }
    }
}

/// Detection result for one required property.
///
/// Neither variant is enforcement. `PrimitiveObserved` means only that one or
/// more supporting kernel interfaces were visible to the probing process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundaryStatus {
    /// Supporting interfaces were observed, but no boundary was installed or
    /// exercised against a child process.
    PrimitiveObserved(Vec<LinuxPrimitive>),
    /// No supporting interface was observed for this requirement.
    Unavailable,
}

impl BoundaryStatus {
    /// This detection-only slice never attests an enforced requirement.
    #[must_use]
    pub const fn is_enforced(&self) -> bool {
        false
    }
}

/// Exact future launch subject bound into detection evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundarySubject {
    runner_id: String,
    run_id: String,
    workspace_root_sha256: String,
    provider_executable_sha256: String,
}

impl BoundarySubject {
    /// Construct an exact bounded subject.
    pub fn new(
        runner_id: impl Into<String>,
        run_id: impl Into<String>,
        workspace_root_sha256: impl Into<String>,
        provider_executable_sha256: impl Into<String>,
    ) -> Result<Self, BoundaryProbeError> {
        let runner_id = runner_id.into();
        let run_id = run_id.into();
        let workspace_root_sha256 = workspace_root_sha256.into();
        let provider_executable_sha256 = provider_executable_sha256.into();
        validate_id(&runner_id, "runner_id")?;
        validate_id(&run_id, "run_id")?;
        validate_sha256(&workspace_root_sha256, "workspace_root_sha256")?;
        validate_sha256(&provider_executable_sha256, "provider_executable_sha256")?;
        Ok(Self {
            runner_id,
            run_id,
            workspace_root_sha256,
            provider_executable_sha256,
        })
    }

    /// Runner identity selected for the future launch.
    #[must_use]
    pub fn runner_id(&self) -> &str {
        &self.runner_id
    }

    /// Durable run identity.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Digest of the exact workspace root identity or manifest.
    #[must_use]
    pub fn workspace_root_sha256(&self) -> &str {
        &self.workspace_root_sha256
    }

    /// Digest of the exact provider executable.
    #[must_use]
    pub fn provider_executable_sha256(&self) -> &str {
        &self.provider_executable_sha256
    }
}

/// Independently observed, detection-only assessment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionBoundaryAssessment {
    subject: BoundarySubject,
    statuses: Vec<(BoundaryRequirement, BoundaryStatus)>,
    evidence_sha256: String,
}

impl ExecutionBoundaryAssessment {
    /// Observe fixed Linux kernel paths without installing or changing a
    /// boundary. Caller-supplied filesystem paths are not accepted.
    pub fn observe(subject: BoundarySubject) -> Result<Self, BoundaryProbeError> {
        let primitives = observe_linux_primitives()?;
        Ok(Self::from_primitives(subject, &primitives))
    }

    fn from_primitives(subject: BoundarySubject, primitives: &[PrimitiveObservation]) -> Self {
        let statuses = BoundaryRequirement::ALL
            .into_iter()
            .map(|requirement| {
                let supporting = supporting_primitives(requirement)
                    .iter()
                    .copied()
                    .filter(|primitive| {
                        primitives.iter().any(|observation| {
                            observation.primitive == *primitive && observation.available
                        })
                    })
                    .collect::<Vec<_>>();
                let status = if supporting.is_empty() {
                    BoundaryStatus::Unavailable
                } else {
                    BoundaryStatus::PrimitiveObserved(supporting)
                };
                (requirement, status)
            })
            .collect::<Vec<_>>();
        let canonical = canonical_assessment(&subject, primitives, &statuses);
        Self {
            subject,
            statuses,
            evidence_sha256: sha256(canonical.as_bytes()),
        }
    }

    /// Exact subject of the observation.
    #[must_use]
    pub const fn subject(&self) -> &BoundarySubject {
        &self.subject
    }

    /// Detection result for a required property.
    #[must_use]
    pub fn status(&self, requirement: BoundaryRequirement) -> &BoundaryStatus {
        self.statuses
            .iter()
            .find_map(|(candidate, status)| (*candidate == requirement).then_some(status))
            .expect("complete closed requirement set")
    }

    /// Digest binding the subject and every fixed-path observation.
    #[must_use]
    pub fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }

    /// Produce the mandatory launch refusal for this detection-only slice.
    ///
    /// There is intentionally no success counterpart or launch token.
    #[must_use]
    pub fn launch_refusal(&self) -> LaunchRefusal {
        LaunchRefusal {
            evidence_sha256: self.evidence_sha256.clone(),
            unenforced: BoundaryRequirement::ALL.to_vec(),
            blockers: vec![LaunchBlocker::MissingDescriptorClosure],
        }
    }
}

/// A concrete blocker that prevents installing the complete launch boundary.
///
/// This is narrower than [`BoundaryRequirement`]: requirements describe the
/// final invariant, while blockers explain a presently verified reason the
/// runner cannot claim that invariant.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LaunchBlocker {
    /// The runner has no installed, digest-pinned path that closes every
    /// descriptor outside an explicit allowlist before the boundary installer
    /// runs. Merely observing `/proc/self/fd` is not descriptor closure.
    MissingDescriptorClosure,
}

impl LaunchBlocker {
    /// Stable non-payload category for logs and protocol adapters.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::MissingDescriptorClosure => "missing_descriptor_closure",
        }
    }
}

/// Evidence-bound refusal to launch a provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchRefusal {
    evidence_sha256: String,
    unenforced: Vec<BoundaryRequirement>,
    blockers: Vec<LaunchBlocker>,
}

impl LaunchRefusal {
    /// Assessment digest that produced this refusal.
    #[must_use]
    pub fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }

    /// Every requirement remains unenforced.
    #[must_use]
    pub fn unenforced_requirements(&self) -> &[BoundaryRequirement] {
        &self.unenforced
    }

    /// Concrete, typed reasons the complete boundary cannot be installed.
    #[must_use]
    pub fn blockers(&self) -> &[LaunchBlocker] {
        &self.blockers
    }
}

/// Bounded host-observation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryProbeError {
    /// A subject field was empty, overlong, malformed, or control-bearing.
    InvalidField(&'static str),
    /// Fixed Linux kernel interfaces are unavailable on this host.
    UnsupportedHost,
    /// A mandatory fixed kernel observation could not be read.
    ObservationUnavailable(&'static str),
    /// A fixed kernel observation exceeded its defensive byte bound.
    ObservationTooLarge(&'static str),
}

impl fmt::Display for BoundaryProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(formatter, "invalid boundary field {field}"),
            Self::UnsupportedHost => formatter.write_str("Linux boundary detection is unavailable"),
            Self::ObservationUnavailable(name) => {
                write!(formatter, "fixed Linux observation {name} is unavailable")
            }
            Self::ObservationTooLarge(name) => {
                write!(
                    formatter,
                    "fixed Linux observation {name} exceeded its bound"
                )
            }
        }
    }
}

impl Error for BoundaryProbeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PrimitiveObservation {
    primitive: LinuxPrimitive,
    available: bool,
    fact_sha256: String,
}

fn supporting_primitives(requirement: BoundaryRequirement) -> &'static [LinuxPrimitive] {
    match requirement {
        BoundaryRequirement::DescendantCompleteContainment => {
            &[LinuxPrimitive::CgroupV2, LinuxPrimitive::CgroupKill]
        }
        BoundaryRequirement::DescriptorClosure => &[LinuxPrimitive::ProcessDescriptorView],
        BoundaryRequirement::FilesystemIsolation => &[
            LinuxPrimitive::MountNamespace,
            LinuxPrimitive::LandlockInterface,
        ],
        BoundaryRequirement::NetworkDenial => &[LinuxPrimitive::NetworkNamespace],
        BoundaryRequirement::CompleteCleanup => &[LinuxPrimitive::CgroupKill],
    }
}

#[cfg(target_os = "linux")]
fn observe_linux_primitives() -> Result<Vec<PrimitiveObservation>, BoundaryProbeError> {
    let mount_namespace = read_namespace("/proc/self/ns/mnt", "mount_namespace")?;
    let network_namespace = read_namespace("/proc/self/ns/net", "network_namespace")?;
    let cgroup_membership = read_fixed_file("/proc/self/cgroup", "cgroup_membership")?;
    let cgroup_controllers = read_optional_fixed_file("/sys/fs/cgroup/cgroup.controllers")?;

    let observations = [
        observation(
            LinuxPrimitive::CgroupV2,
            cgroup_controllers.as_deref(),
            &cgroup_membership,
        ),
        observation(
            LinuxPrimitive::CgroupKill,
            read_optional_fixed_file("/sys/fs/cgroup/cgroup.kill")?.as_deref(),
            b"cgroup.kill unavailable",
        ),
        available_observation(LinuxPrimitive::MountNamespace, mount_namespace.as_bytes()),
        available_observation(
            LinuxPrimitive::NetworkNamespace,
            network_namespace.as_bytes(),
        ),
        observation(
            LinuxPrimitive::ProcessDescriptorView,
            std::fs::read_dir("/proc/self/fd")
                .ok()
                .as_ref()
                .map(|_| b"present".as_slice()),
            b"descriptor view unavailable",
        ),
        observation(
            LinuxPrimitive::LandlockInterface,
            read_optional_fixed_file("/sys/kernel/security/landlock")?.as_deref(),
            b"landlock securityfs entry unavailable",
        ),
    ];
    Ok(observations.into_iter().collect())
}

#[cfg(not(target_os = "linux"))]
fn observe_linux_primitives() -> Result<Vec<PrimitiveObservation>, BoundaryProbeError> {
    Err(BoundaryProbeError::UnsupportedHost)
}

fn observation(
    primitive: LinuxPrimitive,
    available_fact: Option<&[u8]>,
    unavailable_fact: &[u8],
) -> PrimitiveObservation {
    let (available, fact) = available_fact.map_or((false, unavailable_fact), |fact| (true, fact));
    PrimitiveObservation {
        primitive,
        available,
        fact_sha256: sha256(fact),
    }
}

fn available_observation(primitive: LinuxPrimitive, fact: &[u8]) -> PrimitiveObservation {
    PrimitiveObservation {
        primitive,
        available: true,
        fact_sha256: sha256(fact),
    }
}

#[cfg(target_os = "linux")]
fn read_fixed_file(path: &'static str, name: &'static str) -> Result<Vec<u8>, BoundaryProbeError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(Path::new(path))
        .map_err(|_| BoundaryProbeError::ObservationUnavailable(name))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((MAX_FIXED_OBSERVATION_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| BoundaryProbeError::ObservationUnavailable(name))?;
    if bytes.len() > MAX_FIXED_OBSERVATION_BYTES {
        return Err(BoundaryProbeError::ObservationTooLarge(name));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn read_optional_fixed_file(path: &'static str) -> Result<Option<Vec<u8>>, BoundaryProbeError> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(Path::new(path))
    {
        Ok(mut file) => {
            let mut bytes = Vec::new();
            file.by_ref()
                .take((MAX_FIXED_OBSERVATION_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| BoundaryProbeError::ObservationUnavailable("optional_interface"))?;
            if bytes.len() > MAX_FIXED_OBSERVATION_BYTES {
                return Err(BoundaryProbeError::ObservationTooLarge(
                    "optional_interface",
                ));
            }
            Ok(Some(bytes))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Ok(None),
    }
}

#[cfg(target_os = "linux")]
fn read_namespace(path: &'static str, name: &'static str) -> Result<String, BoundaryProbeError> {
    let identity =
        std::fs::read_link(path).map_err(|_| BoundaryProbeError::ObservationUnavailable(name))?;
    let identity = identity
        .to_str()
        .ok_or(BoundaryProbeError::ObservationUnavailable(name))?;
    if identity.is_empty() || identity.len() > 256 || identity.chars().any(char::is_control) {
        return Err(BoundaryProbeError::ObservationUnavailable(name));
    }
    Ok(identity.to_owned())
}

fn canonical_assessment(
    subject: &BoundarySubject,
    observations: &[PrimitiveObservation],
    statuses: &[(BoundaryRequirement, BoundaryStatus)],
) -> String {
    let mut canonical = format!(
        "schema=automonique.runner.boundary-detection/v1\nrunner={}\nrun={}\nworkspace={}\nprovider={}\n",
        subject.runner_id,
        subject.run_id,
        subject.workspace_root_sha256,
        subject.provider_executable_sha256,
    );
    for primitive in LinuxPrimitive::ALL {
        let observation = observations
            .iter()
            .find(|candidate| candidate.primitive == primitive);
        canonical.push_str("primitive=");
        canonical.push_str(primitive.as_str());
        match observation {
            Some(observation) => {
                canonical.push_str(if observation.available {
                    ":available:"
                } else {
                    ":unavailable:"
                });
                canonical.push_str(&observation.fact_sha256);
            }
            None => canonical.push_str(":unavailable:missing"),
        }
        canonical.push('\n');
    }
    for (requirement, status) in statuses {
        canonical.push_str("requirement=");
        canonical.push_str(requirement.as_str());
        canonical.push_str(":unenforced:");
        match status {
            BoundaryStatus::PrimitiveObserved(primitives) => {
                for primitive in primitives {
                    canonical.push_str(primitive.as_str());
                    canonical.push(',');
                }
            }
            BoundaryStatus::Unavailable => canonical.push_str("unavailable"),
        }
        canonical.push('\n');
    }
    canonical
}

fn validate_id(value: &str, field: &'static str) -> Result<(), BoundaryProbeError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES || value.chars().any(char::is_control) {
        Err(BoundaryProbeError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), BoundaryProbeError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(BoundaryProbeError::InvalidField(field))
    }
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(run: &str, workspace: char, provider: char) -> BoundarySubject {
        BoundarySubject::new(
            "runner-a",
            run,
            workspace.to_string().repeat(64),
            provider.to_string().repeat(64),
        )
        .expect("subject")
    }

    fn observation(primitive: LinuxPrimitive, available: bool) -> PrimitiveObservation {
        PrimitiveObservation {
            primitive,
            available,
            fact_sha256: sha256(primitive.as_str().as_bytes()),
        }
    }

    #[test]
    fn every_requirement_remains_unenforced_when_all_primitives_exist() {
        let observations = LinuxPrimitive::ALL
            .into_iter()
            .map(|primitive| observation(primitive, true))
            .collect::<Vec<_>>();
        let assessment =
            ExecutionBoundaryAssessment::from_primitives(subject("run-a", 'a', 'b'), &observations);
        for requirement in BoundaryRequirement::ALL {
            assert!(matches!(
                assessment.status(requirement),
                BoundaryStatus::PrimitiveObserved(_)
            ));
            assert!(!assessment.status(requirement).is_enforced());
        }
        assert_eq!(
            assessment.launch_refusal().unenforced_requirements(),
            BoundaryRequirement::ALL
        );
        assert_eq!(
            assessment.launch_refusal().blockers(),
            [LaunchBlocker::MissingDescriptorClosure]
        );
    }

    #[test]
    fn missing_features_are_explicit_and_never_silently_downgrade() {
        let observations = LinuxPrimitive::ALL
            .into_iter()
            .map(|primitive| observation(primitive, false))
            .collect::<Vec<_>>();
        let assessment =
            ExecutionBoundaryAssessment::from_primitives(subject("run-a", 'a', 'b'), &observations);
        for requirement in BoundaryRequirement::ALL {
            assert_eq!(assessment.status(requirement), &BoundaryStatus::Unavailable);
        }
        assert_eq!(assessment.launch_refusal().unenforced.len(), 5);
        assert_eq!(
            assessment.launch_refusal().blockers,
            [LaunchBlocker::MissingDescriptorClosure]
        );
    }

    #[test]
    fn evidence_binds_run_workspace_provider_and_observed_facts() {
        let observations = LinuxPrimitive::ALL
            .into_iter()
            .map(|primitive| observation(primitive, true))
            .collect::<Vec<_>>();
        let baseline =
            ExecutionBoundaryAssessment::from_primitives(subject("run-a", 'a', 'b'), &observations);
        for changed in [
            subject("run-b", 'a', 'b'),
            subject("run-a", 'c', 'b'),
            subject("run-a", 'a', 'd'),
            BoundarySubject::new("runner-b", "run-a", "a".repeat(64), "b".repeat(64))
                .expect("different runner"),
        ] {
            assert_ne!(
                baseline.evidence_sha256,
                ExecutionBoundaryAssessment::from_primitives(changed, &observations)
                    .evidence_sha256
            );
        }
        let mut changed_facts = observations;
        changed_facts[0].fact_sha256 = sha256(b"changed fixed-path observation");
        assert_ne!(
            baseline.evidence_sha256,
            ExecutionBoundaryAssessment::from_primitives(
                subject("run-a", 'a', 'b'),
                &changed_facts,
            )
            .evidence_sha256
        );
    }

    #[test]
    fn subject_coordinates_and_digests_are_bounded() {
        assert_eq!(
            BoundarySubject::new("", "run", "a".repeat(64), "b".repeat(64)),
            Err(BoundaryProbeError::InvalidField("runner_id"))
        );
        assert_eq!(
            BoundarySubject::new("runner", "run", "A".repeat(64), "b".repeat(64)),
            Err(BoundaryProbeError::InvalidField("workspace_root_sha256"))
        );
        assert_eq!(
            BoundarySubject::new("runner", "run\n", "a".repeat(64), "b".repeat(64)),
            Err(BoundaryProbeError::InvalidField("run_id"))
        );
    }
}
