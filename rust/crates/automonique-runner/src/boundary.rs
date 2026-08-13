// SPDX-License-Identifier: Elastic-2.0

//! Read-only Linux execution-boundary detection.
//!
//! This module observes whether selected kernel interfaces are present. It
//! deliberately does not equate interface availability with an installed
//! boundary. No type in this module grants permission to launch a provider.
//! Every assessment produces a [`LaunchRefusal`] until a later implementation
//! can install and attest all requirements on the exact descendant tree.
//!
//! # Two kinds of observation, and why Landlock is the second kind
//!
//! Most observations here are fixed-path reads: an interface counts as present
//! when this process can open it. Landlock cannot be measured that way. The
//! securityfs entry `/sys/kernel/security/landlock` records whether securityfs
//! publishes a Landlock directory, not whether the kernel accepts Landlock
//! access rights, and the two disagree: on the development host for this crate
//! the entry is absent while the kernel answers the Landlock version query with
//! ABI 4. Reading that path would therefore report "no Landlock" on a host that
//! fully supports it. The Landlock observation is taken instead from
//! [`crate::capability::LandlockFinding`], which asks the kernel directly; see
//! that module's "Why the securityfs entry is not consulted" section for the
//! measurement itself. That query allocates no ruleset descriptor and restricts
//! nothing, so this module remains read-only and side-effect free.
//!
//! Correcting the measurement changes nothing about what this module claims. A
//! measured ABI floor says a launcher *could* install a ruleset; it never says
//! one is installed. [`BoundaryStatus::is_enforced`] stays `false` for every
//! status produced here, including one built from a kernel that supports
//! Landlock at every level this build can name.

use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use crate::capability::LandlockFinding;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
#[cfg(target_os = "linux")]
use std::io::Read as _;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt as _;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt as _;

const MAX_ID_BYTES: usize = 160;
const MAX_FIXED_OBSERVATION_BYTES: usize = 1024 * 1024;
const BWRAP_PATH: &str = "/usr/bin/bwrap";
const FIXTURE_PATH: &str = "/usr/bin/busybox";

const FIXTURE_SCRIPT: &str = r#"set -eu
eval "exec $AUTOMONIQUE_FIXTURE_FD<&-" 2>/dev/null || true
eval "exec $AUTOMONIQUE_WORKSPACE_FD<&-" 2>/dev/null || true
for path in /proc/$$/fd/*; do
  fd=${path##*/}
  case "$fd" in 0|1|2) ;; *) eval "exec $fd<&-" 2>/dev/null || true ;; esac
done
fds=
for path in /proc/$$/fd/*; do
  fd=${path##*/}
  if [ -n "$fds" ]; then fds="$fds,$fd"; else fds="$fd"; fi
done
cap_eff=
no_new_privs=
uid=
gid=
while IFS=: read -r key value; do
  value=${value#?}
  case "$key" in
    CapEff) cap_eff=$value ;;
    NoNewPrivs) no_new_privs=$value ;;
    Uid) uid=$value ;;
    Gid) gid=$value ;;
  esac
done < /proc/$$/status
root_entries=
for path in /*; do
  entry=${path##*/}
  if [ -n "$root_entries" ]; then root_entries="$root_entries,$entry"; else root_entries="$entry"; fi
done
printf '%s\n' \
  'schema=automonique.runner.trusted-fixture/v1' \
  "run_id=$AUTOMONIQUE_RUN_ID" \
  "helper_sha256=$AUTOMONIQUE_HELPER_SHA256" \
  "bwrap_sha256=$AUTOMONIQUE_BWRAP_SHA256" \
  "fixture_sha256=$AUTOMONIQUE_FIXTURE_SHA256" \
  "workspace_identity_sha256=$AUTOMONIQUE_WORKSPACE_SHA256" \
  "fds=$fds" \
  "user_ns=$(/busybox readlink /proc/self/ns/user)" \
  "mount_ns=$(/busybox readlink /proc/self/ns/mnt)" \
  "pid_ns=$(/busybox readlink /proc/self/ns/pid)" \
  "network_ns=$(/busybox readlink /proc/self/ns/net)" \
  "cap_eff=$cap_eff" \
  "no_new_privs=$no_new_privs" \
  "uid=$uid" \
  "gid=$gid" \
  "root_entries=$root_entries" \
  'workspace=/workspace' \
  'network=isolated_namespace' \
  'fixture=busybox_attestation_only'
"#;

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
    /// The running kernel accepts Landlock access rights.
    ///
    /// Measured by the Landlock version query, never by the presence of the
    /// securityfs entry: that entry is a visibility fact and this is a support
    /// fact. Accepting access rights is still not a ruleset; see the module
    /// documentation.
    LandlockSupport,
}

impl LinuxPrimitive {
    const ALL: [Self; 6] = [
        Self::CgroupV2,
        Self::CgroupKill,
        Self::MountNamespace,
        Self::NetworkNamespace,
        Self::ProcessDescriptorView,
        Self::LandlockSupport,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::CgroupV2 => "cgroup_v2",
            Self::CgroupKill => "cgroup_kill",
            Self::MountNamespace => "mount_namespace",
            Self::NetworkNamespace => "network_namespace",
            Self::ProcessDescriptorView => "process_descriptor_view",
            Self::LandlockSupport => "landlock_support",
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
    /// Observe fixed Linux kernel paths, and ask the kernel its Landlock
    /// version, without installing or changing a boundary. Caller-supplied
    /// filesystem paths are not accepted, and no observation here allocates a
    /// ruleset descriptor, creates a cgroup, or unshares a namespace.
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
            blockers: vec![LaunchBlocker::MissingReviewedHelperPin],
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
    /// A descriptor-closing helper exists, but no independently reviewed
    /// release manifest currently binds its identity to the opened executable.
    /// Self-measurement or caller-selected digests cannot establish authority.
    MissingReviewedHelperPin,
}

impl LaunchBlocker {
    /// Stable non-payload category for logs and protocol adapters.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::MissingDescriptorClosure => "missing_descriptor_closure",
            Self::MissingReviewedHelperPin => "missing_reviewed_helper_pin",
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

// The helper below is a directly exercised mechanism, not a product authority.
// A future launcher needs an independently reviewed release-manifest pin and
// must execute the same opened descriptor before any success type is added.
/// Entrypoint for the dedicated descriptor-closure executable.
///
/// This is public only so the package's separate binary target can call it;
/// it does not mint evidence or grant product execution authority.
#[doc(hidden)]
pub fn descriptor_closure_helper_main() -> i32 {
    #[cfg(not(target_os = "linux"))]
    {
        64
    }
    #[cfg(target_os = "linux")]
    {
        match descriptor_closure_helper_linux() {
            Ok(never) => match never {},
            Err(category) => {
                let _ = writeln!(
                    std::io::stderr(),
                    "automonique fixture helper refused: {category}"
                );
                64
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn descriptor_closure_helper_linux() -> Result<std::convert::Infallible, &'static str> {
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use nix::unistd::{close, fexecve};
    use std::collections::BTreeSet;

    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments.len() != 12 || arguments[1] != "--automonique-fd-closure-v1" {
        return Err("argv");
    }
    let string = |index: usize| arguments[index].to_str().ok_or("argv");
    let bwrap_path = string(2)?;
    let expected_bwrap = string(3)?;
    let fixture_path = string(4)?;
    let expected_fixture = string(5)?;
    let workspace_path = PathBuf::from(&arguments[6]);
    let expected_device = string(7)?
        .parse::<u64>()
        .map_err(|_| "workspace_identity")?;
    let expected_inode = string(8)?
        .parse::<u64>()
        .map_err(|_| "workspace_identity")?;
    let expected_helper = string(9)?;
    let run_id = string(10)?;
    let workspace_sha256 = string(11)?;
    let helper = File::open("/proc/self/exe").map_err(|_| "helper_digest")?;
    if bwrap_path != BWRAP_PATH
        || fixture_path != FIXTURE_PATH
        || sha256_reader(&helper).map_err(|_| "helper_digest")? != expected_helper
    {
        return Err("pin");
    }
    let bwrap = open_pinned_file(Path::new(bwrap_path), expected_bwrap, "bwrap")?;
    let fixture = open_pinned_file(Path::new(fixture_path), expected_fixture, "fixture")?;
    let workspace = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(&workspace_path)
        .map_err(|_| "workspace_open")?;
    let metadata = workspace.metadata().map_err(|_| "workspace_identity")?;
    if metadata.dev() != expected_device || metadata.ino() != expected_inode {
        return Err("workspace_identity");
    }
    for descriptor in [fixture.as_raw_fd(), workspace.as_raw_fd()] {
        fcntl(descriptor, FcntlArg::F_SETFD(FdFlag::empty())).map_err(|_| "fd_flags")?;
    }
    let allowed = BTreeSet::from([
        0,
        1,
        2,
        bwrap.as_raw_fd(),
        fixture.as_raw_fd(),
        workspace.as_raw_fd(),
    ]);
    let descriptors = std::fs::read_dir("/proc/self/fd")
        .map_err(|_| "fd_view")?
        .map(|entry| {
            entry
                .map_err(|_| "fd_view")?
                .file_name()
                .to_str()
                .ok_or("fd_view")?
                .parse::<i32>()
                .map_err(|_| "fd_view")
        })
        .collect::<Result<Vec<_>, _>>()?;
    for descriptor in descriptors {
        if !allowed.contains(&descriptor) {
            match close(descriptor) {
                Ok(()) | Err(nix::errno::Errno::EBADF) => {}
                Err(_) => return Err("fd_close"),
            }
        }
    }
    let fixture_fd = fixture.as_raw_fd().to_string();
    let workspace_fd = workspace.as_raw_fd().to_string();
    let owned_arguments = [
        "bwrap",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--tmpfs",
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--dir",
        "/workspace",
        "--bind-fd",
        workspace_fd.as_str(),
        "/workspace",
        "--ro-bind-fd",
        fixture_fd.as_str(),
        "/fixture",
        "--symlink",
        "fixture",
        "/busybox",
        "--chdir",
        "/workspace",
        "--cap-drop",
        "ALL",
        "--setenv",
        "AUTOMONIQUE_RUN_ID",
        run_id,
        "--setenv",
        "AUTOMONIQUE_HELPER_SHA256",
        expected_helper,
        "--setenv",
        "AUTOMONIQUE_BWRAP_SHA256",
        expected_bwrap,
        "--setenv",
        "AUTOMONIQUE_FIXTURE_SHA256",
        expected_fixture,
        "--setenv",
        "AUTOMONIQUE_WORKSPACE_SHA256",
        workspace_sha256,
        "--setenv",
        "AUTOMONIQUE_FIXTURE_FD",
        fixture_fd.as_str(),
        "--setenv",
        "AUTOMONIQUE_WORKSPACE_FD",
        workspace_fd.as_str(),
        "--argv0",
        "busybox",
        "--",
        "/fixture",
        "sh",
        "-c",
        FIXTURE_SCRIPT,
    ];
    let arguments = owned_arguments
        .iter()
        .map(|value| CString::new(*value).map_err(|_| "argv"))
        .collect::<Result<Vec<_>, _>>()?;
    let environment: Vec<CString> = Vec::new();
    fexecve(bwrap.as_raw_fd(), &arguments, &environment).map_err(|_| "exec")
}

#[cfg(target_os = "linux")]
fn open_pinned_file(path: &Path, expected: &str, name: &'static str) -> Result<File, &'static str> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| name)?;
    let actual = sha256_reader(&file).map_err(|_| name)?;
    if actual != expected {
        return Err(name);
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn sha256_reader(file: &File) -> Result<String, std::io::Error> {
    use std::os::unix::fs::FileExt as _;
    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read_at(&mut buffer, offset)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        offset = offset.saturating_add(read as u64);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    Ok(output)
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
            LinuxPrimitive::LandlockSupport,
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
        landlock_observation(LandlockFinding::probe()),
    ];
    Ok(observations.into_iter().collect())
}

/// Record what the running kernel answered to the Landlock version query.
///
/// The measured ABI floor is bound into the fact digest, so two hosts that both
/// support Landlock at different floors do not mint the same evidence, and a
/// kernel upgrade that raises the floor is visible in the digest rather than
/// silently absorbed.
///
/// This function is the whole Landlock observation. It reads no securityfs
/// path, and it deliberately cannot: a host where the entry is absent and the
/// kernel supports Landlock must be recorded as supporting Landlock.
#[cfg(target_os = "linux")]
fn landlock_observation(finding: LandlockFinding) -> PrimitiveObservation {
    let supported = finding
        .abi()
        .map(|abi| format!("landlock enforceable abi {}", abi.level()));
    observation(
        LinuxPrimitive::LandlockSupport,
        supported.as_deref().map(str::as_bytes),
        b"landlock unsupported by the running kernel",
    )
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
    std::io::Read::by_ref(&mut file)
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
            std::io::Read::by_ref(&mut file)
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
            [LaunchBlocker::MissingReviewedHelperPin]
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
            [LaunchBlocker::MissingReviewedHelperPin]
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

    /// The mapping from a kernel answer to a recorded observation is the point
    /// of the fix, so it is pinned in both directions. A kernel that refuses
    /// every Landlock access right must never be recorded as supporting
    /// Landlock, and a kernel that accepts them must be, whatever securityfs
    /// does or does not publish.
    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_availability_follows_the_kernel_answer_in_both_directions() {
        let unsupported = landlock_observation(LandlockFinding::Unsupported);
        assert_eq!(unsupported.primitive, LinuxPrimitive::LandlockSupport);
        assert!(
            !unsupported.available,
            "a kernel that accepts no Landlock access right must not be recorded as supporting it"
        );

        for level in [
            crate::capability::LANDLOCK_ABI_FILESYSTEM,
            crate::capability::LANDLOCK_ABI_TCP,
            crate::capability::LANDLOCK_ABI_HIGHEST_KNOWN,
        ] {
            let abi = crate::capability::LandlockAbi::from_level(level).expect("known ABI level");
            let supported = landlock_observation(LandlockFinding::Enforceable(abi));
            assert!(
                supported.available,
                "ABI {level} was measured but not recorded as support"
            );
            assert_ne!(
                supported.fact_sha256, unsupported.fact_sha256,
                "support and non-support must not share a fact digest"
            );
        }
    }

    /// A measured ABI floor is evidence, so a host at a different floor must
    /// not mint the same digest. Collapsing the levels would let a kernel
    /// downgrade pass unnoticed through the evidence chain.
    #[cfg(target_os = "linux")]
    #[test]
    fn each_measured_landlock_floor_produces_distinct_evidence() {
        let mut digests = Vec::new();
        for level in crate::capability::LANDLOCK_ABI_FILESYSTEM
            ..=crate::capability::LANDLOCK_ABI_HIGHEST_KNOWN
        {
            let abi = crate::capability::LandlockAbi::from_level(level).expect("known ABI level");
            let mut observations = LinuxPrimitive::ALL
                .into_iter()
                .map(|primitive| observation(primitive, true))
                .collect::<Vec<_>>();
            let landlock = landlock_observation(LandlockFinding::Enforceable(abi));
            for entry in &mut observations {
                if entry.primitive == LinuxPrimitive::LandlockSupport {
                    entry.clone_from(&landlock);
                }
            }
            let assessment = ExecutionBoundaryAssessment::from_primitives(
                subject("run-a", 'a', 'b'),
                &observations,
            );
            assert!(
                !digests.contains(&assessment.evidence_sha256),
                "ABI {level} reused an evidence digest from a different floor"
            );
            digests.push(assessment.evidence_sha256);
        }
    }

    /// Landlock is a supporting interface for filesystem isolation only. A
    /// corrected Landlock observation must not leak into any other requirement,
    /// and must never turn detection into enforcement.
    #[test]
    fn landlock_support_backs_filesystem_isolation_and_nothing_else() {
        for requirement in BoundaryRequirement::ALL {
            let backs_landlock =
                supporting_primitives(requirement).contains(&LinuxPrimitive::LandlockSupport);
            assert_eq!(
                backs_landlock,
                requirement == BoundaryRequirement::FilesystemIsolation,
                "{requirement:?} disagrees with the documented Landlock mapping"
            );
        }

        let mut observations = LinuxPrimitive::ALL
            .into_iter()
            .map(|primitive| observation(primitive, false))
            .collect::<Vec<_>>();
        for entry in &mut observations {
            if entry.primitive == LinuxPrimitive::LandlockSupport {
                entry.available = true;
            }
        }
        let assessment =
            ExecutionBoundaryAssessment::from_primitives(subject("run-a", 'a', 'b'), &observations);
        assert_eq!(
            assessment.status(BoundaryRequirement::FilesystemIsolation),
            &BoundaryStatus::PrimitiveObserved(vec![LinuxPrimitive::LandlockSupport])
        );
        assert!(
            !assessment
                .status(BoundaryRequirement::FilesystemIsolation)
                .is_enforced(),
            "observed Landlock support is not an installed filesystem boundary"
        );
        for requirement in BoundaryRequirement::ALL {
            if requirement != BoundaryRequirement::FilesystemIsolation {
                assert_eq!(assessment.status(requirement), &BoundaryStatus::Unavailable);
            }
        }
        assert_eq!(
            assessment.launch_refusal().unenforced_requirements(),
            BoundaryRequirement::ALL,
            "Landlock support must not reduce the unenforced requirement set"
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
