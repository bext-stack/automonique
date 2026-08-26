// SPDX-License-Identifier: Elastic-2.0

//! Workload identity: a host uid that is not the supervisor's.
//!
//! Every process the supervisor launched used to run as the supervisor's own
//! uid, so any process of that uid on the host could read the workload's
//! `/proc/<pid>/environ`, open its `/proc/<pid>/fd/0` (the prompt) and trace
//! it. This module gives the workload a kernel identity of its own without a
//! privileged component of ours: an unprivileged user namespace whose mapping
//! is written by the distribution's setuid `newuidmap`/`newgidmap` from the
//! account's subordinate ranges in `/etc/subuid` and `/etc/subgid`.
//!
//! # The identity
//!
//! Inside the namespace the mapping is exactly two uid lines and one gid line:
//!
//! ```text
//! uid_map:  0    <supervisor uid>   1      (the host account is the namespace's root)
//!           <W>  <subordinate uid>  1      (the workload)
//! gid_map:  0    <supervisor gid>   1
//! ```
//!
//! `W`, the workload's uid as it sees itself, is the supervisor's own uid
//! *number*: `getpwuid` inside the sandbox keeps answering, `HOME` and the
//! account name look the same as before, and nothing a provider client does
//! with its uid changes. What changes is the kernel's view: the workload's
//! host uid is the **highest uid of the account's first subordinate range**
//! (`start + count - 1`). Rootless container tooling maps container uids
//! upward from the *start* of the same range, so the top of it is the entry
//! least likely to be shared with a container process. The choice is fixed
//! per host, not per run: two runs of one supervisor share a host uid, which
//! is the same relationship they had before, and a different account's runs
//! never share one because subordinate ranges do not overlap.
//!
//! The workload's gid is unchanged: the supervisor's group, which the
//! namespace sees as its root group. Mapping the account's own gid is what
//! `newgidmap` permits an unprivileged caller, and it costs `setgroups`: the
//! kernel writes `deny` to `/proc/<pid>/setgroups` for such a mapping, so the
//! workload inherits the supervisor's supplementary groups and can neither
//! add to nor drop them. That inheritance is the same as before this module
//! existed and is named in the operations document as a residual.
//!
//! # Files: identity is separated, discretionary access is not
//!
//! A workload that could no longer open the supervisor's files would not be a
//! workload: the workspace, the provider home and the run's scratch mount are
//! all owned by the supervisor. Inside the namespace the workload therefore
//! keeps exactly three capabilities, `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`
//! and `CAP_FOWNER`, in its ambient set, so they survive `execve`. The kernel
//! honours them only over inodes whose owner and group are both mapped in the
//! namespace — the supervisor's files and the workload's own — and never over
//! root-owned system files, which stay at their `other` bits. So the workload
//! can do to the supervisor's files what the supervisor can, which is what it
//! could do before, and the Landlock allowlist remains the filesystem
//! boundary. Files the workload creates are owned by its subordinate uid and
//! the supervisor's group; its umask is set to [`WORKLOAD_UMASK`] so the
//! supervisor keeps group write access to them.
//!
//! Every other capability is dropped from the bounding set, and the helper
//! sets `no_new_privs` before `execve` as it always did, so the workload cannot
//! regain any. The seccomp filter installed after this module runs denies
//! `unshare`, `setns`, `clone` with namespace flags and `clone3`, so the
//! workload cannot open a nested namespace in which it would be root again.
//!
//! # Host prerequisites, and fail-closed
//!
//! The switch needs the kernel to permit unprivileged user namespaces, a
//! subordinate uid and gid range for the account, the setuid-root mapping
//! helpers, and — on hosts that transition unconfined namespace creators to a
//! capability-less AppArmor profile — a profile that grants the launch helper
//! `userns`. Nothing here trusts a configuration file for any of that: the
//! same sequence the launch performs is what the capability probe runs, in a
//! throwaway child, and the probe's answer is that child's own `/proc` view of
//! itself after the switch. When any step fails the launch is refused before
//! the workload exists, and the daemon's readiness reports the host as unable
//! to enforce the sandbox.
//!
//! # Why the supervisor is not involved
//!
//! `newuidmap` must run outside the new namespace, as a process of the same
//! host uid as its target. The entry helper spawns one **mapper** — itself,
//! through `/proc/self/exe`, in [`MAP_MODE_FLAG`] mode — before it unshares,
//! releases it with one byte after, and waits for it. The mapper maps its
//! parent and exits; no plan content, no argument and no environment crosses
//! that boundary in either direction, and the supervisor's launch protocol is
//! unchanged.

use crate::HELPER_REFUSED_EXIT;
use nix::sched::CloneFlags;
use nix::unistd::{Uid, User};
use rustix::thread::{CapabilitySet, CapabilitySets};
use std::fmt;
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The account's subordinate uid ranges, in `shadow`'s `owner:start:count`.
pub const SUBUID_PATH: &str = "/etc/subuid";
/// The account's subordinate gid ranges.
pub const SUBGID_PATH: &str = "/etc/subgid";
/// The distribution's setuid-root uid mapper.
pub const NEWUIDMAP_PATH: &str = "/usr/bin/newuidmap";
/// The distribution's setuid-root gid mapper.
pub const NEWGIDMAP_PATH: &str = "/usr/bin/newgidmap";
/// The launch helper's `argv[1]` that turns it into the mapper for its parent.
pub const MAP_MODE_FLAG: &str = "--map-workload-identity";
/// The launch helper's `argv[1]` that turns it into the identity probe.
pub const PROBE_MODE_FLAG: &str = "--probe-workload-identity";
/// The umask the workload starts with: group write is kept so the supervisor,
/// whose group the workload keeps, can manage what the workload creates.
pub const WORKLOAD_UMASK: u32 = 0o002;
/// The in-namespace uid and gid the supervisor's own identity maps to.
pub const SUPERVISOR_NAMESPACE_ID: u32 = 0;
/// The capabilities the workload keeps inside its namespace, ambient.
pub const WORKLOAD_CAPABILITIES: CapabilitySet = CapabilitySet::DAC_OVERRIDE
    .union(CapabilitySet::DAC_READ_SEARCH)
    .union(CapabilitySet::FOWNER);

/// The one byte the helper sends its mapper once the namespace exists.
const MAPPER_RELEASE: &[u8] = b"go\n";
/// Bound on a subordinate id file read.
const MAX_SUBID_BYTES: usize = 1024 * 1024;
/// Bound on an id-map or `setgroups` read.
const MAX_MAP_BYTES: usize = 4096;
/// Bound on the process status read.
const MAX_STATUS_BYTES: usize = 64 * 1024;
/// Bound on the probe child's report.
const MAX_REPORT_BYTES: usize = 4096;
/// The setuid bit, as `st_mode` carries it.
const S_ISUID: u32 = 0o4000;
/// Every capability this build can name in the bounding set. A kernel that
/// defines more keeps them in the bounding set; the workload is not root and
/// runs with `no_new_privs`, so it cannot acquire them, and the readback below
/// compares only the bits this build knows.
const KNOWN_CAPABILITIES: [CapabilitySet; 41] = [
    CapabilitySet::CHOWN,
    CapabilitySet::DAC_OVERRIDE,
    CapabilitySet::DAC_READ_SEARCH,
    CapabilitySet::FOWNER,
    CapabilitySet::FSETID,
    CapabilitySet::KILL,
    CapabilitySet::SETGID,
    CapabilitySet::SETUID,
    CapabilitySet::SETPCAP,
    CapabilitySet::LINUX_IMMUTABLE,
    CapabilitySet::NET_BIND_SERVICE,
    CapabilitySet::NET_BROADCAST,
    CapabilitySet::NET_ADMIN,
    CapabilitySet::NET_RAW,
    CapabilitySet::IPC_LOCK,
    CapabilitySet::IPC_OWNER,
    CapabilitySet::SYS_MODULE,
    CapabilitySet::SYS_RAWIO,
    CapabilitySet::SYS_CHROOT,
    CapabilitySet::SYS_PTRACE,
    CapabilitySet::SYS_PACCT,
    CapabilitySet::SYS_ADMIN,
    CapabilitySet::SYS_BOOT,
    CapabilitySet::SYS_NICE,
    CapabilitySet::SYS_RESOURCE,
    CapabilitySet::SYS_TIME,
    CapabilitySet::SYS_TTY_CONFIG,
    CapabilitySet::MKNOD,
    CapabilitySet::LEASE,
    CapabilitySet::AUDIT_WRITE,
    CapabilitySet::AUDIT_CONTROL,
    CapabilitySet::SETFCAP,
    CapabilitySet::MAC_OVERRIDE,
    CapabilitySet::MAC_ADMIN,
    CapabilitySet::SYSLOG,
    CapabilitySet::WAKE_ALARM,
    CapabilitySet::BLOCK_SUSPEND,
    CapabilitySet::AUDIT_READ,
    CapabilitySet::PERFMON,
    CapabilitySet::BPF,
    CapabilitySet::CHECKPOINT_RESTORE,
];
/// The ambient capabilities, one bit at a time as the prctl interface takes
/// them.
const WORKLOAD_AMBIENT: [CapabilitySet; 3] = [
    CapabilitySet::DAC_OVERRIDE,
    CapabilitySet::DAC_READ_SEARCH,
    CapabilitySet::FOWNER,
];
const PROBE_SEPARABLE: &str = "workload-identity: separable";
const PROBE_UNAVAILABLE: &str = "workload-identity: unavailable";

/// The identity a workload runs under, as the kernel sees it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkloadIdentity {
    namespace_uid: u32,
    host_uid: u32,
    host_gid: u32,
}

impl WorkloadIdentity {
    /// The uid the workload sees itself as inside its namespace.
    #[must_use]
    pub const fn namespace_uid(self) -> u32 {
        self.namespace_uid
    }

    /// The host uid the workload runs under: what `/proc/<pid>/status` shows
    /// from outside the namespace, and what every permission check uses.
    #[must_use]
    pub const fn host_uid(self) -> u32 {
        self.host_uid
    }

    /// The host gid the workload runs under: the supervisor's own group.
    #[must_use]
    pub const fn host_gid(self) -> u32 {
        self.host_gid
    }
}

impl fmt::Display for WorkloadIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "namespace uid {} on host uid {} gid {}",
            self.namespace_uid, self.host_uid, self.host_gid
        )
    }
}

/// Exactly why a workload cannot be given an identity of its own here.
///
/// Comparable and copyable, so the capability model can carry it beside the
/// other typed causes. The verbatim detail travels in [`IdentityError`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkloadIdentityDenial {
    /// No launch helper was available to probe, so nothing was attempted.
    NoLaunchHelper,
    /// The helper could not be spawned or gave no report.
    HelperUnavailable,
    /// The helper answered something this build cannot read.
    ProbeInconclusive,
    /// The supervisor is uid 0. The switch is designed for an unprivileged
    /// supervisor; a root supervisor needs no user namespace and gets none.
    SupervisorIsRoot,
    /// The supervisor's uid has no `passwd` entry, so its subordinate ranges
    /// cannot be looked up by name.
    OwnerUnresolvable,
    /// `/etc/subuid` names no range for the account.
    NoSubordinateUids,
    /// `/etc/subgid` names no range for the account.
    NoSubordinateGids,
    /// The account's first subordinate range cannot yield a usable uid.
    SubordinateRangeUnusable,
    /// `newuidmap` or `newgidmap` is missing, not setuid root, or not
    /// executable.
    MapperUnavailable,
    /// `unshare(CLONE_NEWUSER)` was refused by the kernel.
    NamespaceCreationRefused,
    /// The mapper exited without writing the mapping.
    MappingRefused,
    /// The mapping the kernel reports is not the one that was requested.
    MappingUnconfirmed,
    /// `setresuid` inside the namespace was refused. On a host with
    /// `kernel.apparmor_restrict_unprivileged_userns`, this is the AppArmor
    /// `unprivileged_userns` transition: the launch helper needs a profile
    /// that grants it `userns`.
    CredentialSwitchRefused,
    /// A capability set, the bounding set or the ambient set could not be
    /// shaped as required.
    CapabilityShapingRefused,
    /// The process's own status after the switch is not the identity asked
    /// for.
    IdentityUnconfirmed,
}

impl WorkloadIdentityDenial {
    /// Every denial, for closed coverage.
    pub const ALL: [Self; 15] = [
        Self::NoLaunchHelper,
        Self::HelperUnavailable,
        Self::ProbeInconclusive,
        Self::SupervisorIsRoot,
        Self::OwnerUnresolvable,
        Self::NoSubordinateUids,
        Self::NoSubordinateGids,
        Self::SubordinateRangeUnusable,
        Self::MapperUnavailable,
        Self::NamespaceCreationRefused,
        Self::MappingRefused,
        Self::MappingUnconfirmed,
        Self::CredentialSwitchRefused,
        Self::CapabilityShapingRefused,
        Self::IdentityUnconfirmed,
    ];

    /// Stable spelling for logs, protocol adapters and the probe report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoLaunchHelper => "no_launch_helper",
            Self::HelperUnavailable => "helper_unavailable",
            Self::ProbeInconclusive => "probe_inconclusive",
            Self::SupervisorIsRoot => "supervisor_is_root",
            Self::OwnerUnresolvable => "owner_unresolvable",
            Self::NoSubordinateUids => "no_subordinate_uids",
            Self::NoSubordinateGids => "no_subordinate_gids",
            Self::SubordinateRangeUnusable => "subordinate_range_unusable",
            Self::MapperUnavailable => "mapper_unavailable",
            Self::NamespaceCreationRefused => "namespace_creation_refused",
            Self::MappingRefused => "mapping_refused",
            Self::MappingUnconfirmed => "mapping_unconfirmed",
            Self::CredentialSwitchRefused => "credential_switch_refused",
            Self::CapabilityShapingRefused => "capability_shaping_refused",
            Self::IdentityUnconfirmed => "identity_unconfirmed",
        }
    }

    /// The denial spelled `code`, if any.
    #[must_use]
    pub fn parse(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|denial| denial.as_str() == code)
    }
}

impl fmt::Display for WorkloadIdentityDenial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NoLaunchHelper => "no launch helper was available to probe the workload identity",
            Self::HelperUnavailable => {
                "the launch helper could not be spawned for the identity probe"
            }
            Self::ProbeInconclusive => {
                "the identity probe answered something this build cannot read"
            }
            Self::SupervisorIsRoot => {
                "the supervisor runs as uid 0, which the identity switch refuses"
            }
            Self::OwnerUnresolvable => "the supervisor's uid has no passwd entry",
            Self::NoSubordinateUids => {
                "/etc/subuid names no subordinate uid range for this account"
            }
            Self::NoSubordinateGids => {
                "/etc/subgid names no subordinate gid range for this account"
            }
            Self::SubordinateRangeUnusable => {
                "the account's first subordinate range yields no usable workload uid"
            }
            Self::MapperUnavailable => {
                "newuidmap or newgidmap is missing, not setuid root, or not executable"
            }
            Self::NamespaceCreationRefused => "the kernel refused an unprivileged user namespace",
            Self::MappingRefused => "the mapper did not write the namespace's id maps",
            Self::MappingUnconfirmed => "the kernel's id maps are not the ones requested",
            Self::CredentialSwitchRefused => {
                "the uid switch inside the namespace was refused; on a host that restricts \
                 unprivileged user namespaces the launch helper needs an AppArmor profile \
                 granting it userns"
            }
            Self::CapabilityShapingRefused => {
                "the workload's capability sets could not be shaped inside the namespace"
            }
            Self::IdentityUnconfirmed => {
                "the process status after the switch does not show the requested identity"
            }
        })
    }
}

/// A typed denial with the verbatim detail of the step that produced it.
#[derive(Debug)]
pub struct IdentityError {
    denial: WorkloadIdentityDenial,
    detail: String,
}

impl IdentityError {
    fn new(denial: WorkloadIdentityDenial, detail: impl Into<String>) -> Self {
        Self {
            denial,
            detail: detail.into(),
        }
    }

    /// The comparable reason.
    #[must_use]
    pub const fn denial(&self) -> WorkloadIdentityDenial {
        self.denial
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            write!(formatter, "{}", self.denial)
        } else {
            write!(formatter, "{}: {}", self.denial, self.detail)
        }
    }
}

impl std::error::Error for IdentityError {}

/// The mapping one launch will ask for, resolved from the host's files.
///
/// Resolving one performs no switch. The same function runs in the helper
/// (which asks for it) and in the mapper (which writes it), so the two agree
/// by construction and the helper's readback catches the one case they could
/// not: a subordinate file edited between the two reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityPlan {
    supervisor_uid: u32,
    supervisor_gid: u32,
    workload: WorkloadIdentity,
    newuidmap: PathBuf,
    newgidmap: PathBuf,
}

impl IdentityPlan {
    /// The identity the plan gives the workload.
    #[must_use]
    pub const fn workload(&self) -> WorkloadIdentity {
        self.workload
    }

    /// The host uid the namespace maps to its root.
    #[must_use]
    pub const fn supervisor_uid(&self) -> u32 {
        self.supervisor_uid
    }

    /// The host gid the namespace maps to its root group.
    #[must_use]
    pub const fn supervisor_gid(&self) -> u32 {
        self.supervisor_gid
    }
}

/// Where the plan's inputs live; the host's conventional paths by default.
#[derive(Clone, Debug)]
pub struct IdentitySources {
    subuid: PathBuf,
    subgid: PathBuf,
    newuidmap: PathBuf,
    newgidmap: PathBuf,
}

impl IdentitySources {
    /// This host's conventional locations.
    #[must_use]
    pub fn host_default() -> Self {
        Self {
            subuid: PathBuf::from(SUBUID_PATH),
            subgid: PathBuf::from(SUBGID_PATH),
            newuidmap: PathBuf::from(NEWUIDMAP_PATH),
            newgidmap: PathBuf::from(NEWGIDMAP_PATH),
        }
    }

    /// Explicit locations, for tests.
    pub fn at(
        subuid: impl Into<PathBuf>,
        subgid: impl Into<PathBuf>,
        newuidmap: impl Into<PathBuf>,
        newgidmap: impl Into<PathBuf>,
    ) -> Self {
        Self {
            subuid: subuid.into(),
            subgid: subgid.into(),
            newuidmap: newuidmap.into(),
            newgidmap: newgidmap.into(),
        }
    }
}

/// Resolve the plan for the calling process from the host's own files.
pub fn resolve_identity_plan() -> Result<IdentityPlan, IdentityError> {
    let uid = nix::unistd::getuid();
    let gid = nix::unistd::getgid();
    let name = User::from_uid(uid).ok().flatten().map(|user| user.name);
    resolve_identity_plan_for(
        &IdentitySources::host_default(),
        uid.as_raw(),
        gid.as_raw(),
        name.as_deref(),
    )
}

/// Resolve the plan for an account, from explicit sources.
///
/// `name` is the account's `passwd` name when it has one; a subordinate file
/// may name the owner either way, and `shadow` accepts both spellings.
pub fn resolve_identity_plan_for(
    sources: &IdentitySources,
    supervisor_uid: u32,
    supervisor_gid: u32,
    name: Option<&str>,
) -> Result<IdentityPlan, IdentityError> {
    if supervisor_uid == 0 {
        return Err(IdentityError::new(
            WorkloadIdentityDenial::SupervisorIsRoot,
            "",
        ));
    }
    let numeric = supervisor_uid.to_string();
    let mut owners = vec![numeric.as_str()];
    match name {
        Some(name) => owners.push(name),
        None => {
            return Err(IdentityError::new(
                WorkloadIdentityDenial::OwnerUnresolvable,
                format!("uid {supervisor_uid}"),
            ));
        }
    }

    let subuid = read_bounded(&sources.subuid, MAX_SUBID_BYTES).map_err(|error| {
        IdentityError::new(
            WorkloadIdentityDenial::NoSubordinateUids,
            format!("{}: {error}", sources.subuid.display()),
        )
    })?;
    let (uid_start, uid_count) = first_subordinate_range(&subuid, &owners).ok_or_else(|| {
        IdentityError::new(
            WorkloadIdentityDenial::NoSubordinateUids,
            format!("{} names no range for {owners:?}", sources.subuid.display()),
        )
    })?;
    let subgid = read_bounded(&sources.subgid, MAX_SUBID_BYTES).map_err(|error| {
        IdentityError::new(
            WorkloadIdentityDenial::NoSubordinateGids,
            format!("{}: {error}", sources.subgid.display()),
        )
    })?;
    // The gid range is required because `newgidmap` refuses an account with
    // none, even though the mapping written maps only the account's own gid.
    first_subordinate_range(&subgid, &owners).ok_or_else(|| {
        IdentityError::new(
            WorkloadIdentityDenial::NoSubordinateGids,
            format!("{} names no range for {owners:?}", sources.subgid.display()),
        )
    })?;

    let host_uid = subordinate_top(uid_start, uid_count, supervisor_uid).ok_or_else(|| {
        IdentityError::new(
            WorkloadIdentityDenial::SubordinateRangeUnusable,
            format!("range {uid_start}:{uid_count}"),
        )
    })?;

    verify_mapper(&sources.newuidmap)?;
    verify_mapper(&sources.newgidmap)?;

    Ok(IdentityPlan {
        supervisor_uid,
        supervisor_gid,
        workload: WorkloadIdentity {
            namespace_uid: supervisor_uid,
            host_uid,
            host_gid: supervisor_gid,
        },
        newuidmap: sources.newuidmap.clone(),
        newgidmap: sources.newgidmap.clone(),
    })
}

/// The first `owner:start:count` line naming one of `owners`, as numbers.
///
/// Malformed lines are skipped rather than refused: `shadow` skips them too,
/// and refusing on one would make an unrelated account's typo this account's
/// outage.
fn first_subordinate_range(contents: &str, owners: &[&str]) -> Option<(u32, u32)> {
    contents.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let mut fields = line.split(':');
        let owner = fields.next()?;
        if !owners.contains(&owner) {
            return None;
        }
        let start = fields.next()?.trim().parse::<u32>().ok()?;
        let count = fields.next()?.trim().parse::<u32>().ok()?;
        if fields.next().is_some() {
            return None;
        }
        Some((start, count))
    })
}

/// The highest uid of a range, refusing ranges that cannot hold a workload.
///
/// The range must be non-empty, must not begin at uid 0, must not reach the
/// overflow uid or the end of the uid space, and must not contain the
/// supervisor's own uid — a misconfigured range that overlapped it would
/// hand the workload back the identity this module exists to take away.
fn subordinate_top(start: u32, count: u32, supervisor_uid: u32) -> Option<u32> {
    const OVERFLOW_UID: u32 = 65_534;
    let top = start.checked_add(count.checked_sub(1)?)?;
    if start == 0 || top == OVERFLOW_UID || top == u32::MAX || top == u32::MAX - 1 {
        return None;
    }
    if (start..=top).contains(&supervisor_uid) {
        return None;
    }
    Some(top)
}

/// Refuse unless `path` is a regular, root-owned, setuid, executable file.
fn verify_mapper(path: &Path) -> Result<(), IdentityError> {
    let unavailable = |detail: String| {
        IdentityError::new(
            WorkloadIdentityDenial::MapperUnavailable,
            format!("{}: {detail}", path.display()),
        )
    };
    let metadata = std::fs::metadata(path).map_err(|error| unavailable(error.to_string()))?;
    if !metadata.is_file() {
        return Err(unavailable("not a regular file".to_owned()));
    }
    if metadata.uid() != 0 || metadata.permissions().mode() & S_ISUID == 0 {
        return Err(unavailable("not setuid root".to_owned()));
    }
    if nix::unistd::access(path, nix::unistd::AccessFlags::X_OK).is_err() {
        return Err(unavailable("not executable by this uid".to_owned()));
    }
    Ok(())
}

/// Give the calling process the workload identity, irreversibly.
///
/// Runs in the entry helper between program staging and descriptor closure,
/// and in the probe child. The sequence is: resolve the plan; spawn the
/// mapper; `unshare(CLONE_NEWUSER)`; release the mapper and wait for it; read
/// the kernel's maps back; switch to the workload uid; shape the capability
/// sets; read the process status back; set the umask. Any failure is a typed
/// refusal, and a process that returns `Ok` *is* the workload identity by the
/// kernel's own account.
///
/// The caller must be single-threaded: `unshare(CLONE_NEWUSER)` refuses a
/// threaded process, and the credential calls are per-thread on Linux.
pub fn separate_workload_identity() -> Result<WorkloadIdentity, IdentityError> {
    let plan = resolve_identity_plan()?;

    // The mapper is this very binary, spawned through `/proc/self/exe` so a
    // helper whose file was replaced mid-launch still runs its own bytes. It
    // starts before the namespace exists, because a process created after
    // `unshare` would be inside the namespace, where a setuid helper is not
    // setuid. It waits on its stdin for the release byte.
    let mut mapper = Command::new("/proc/self/exe")
        .arg(MAP_MODE_FLAG)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| {
            IdentityError::new(
                WorkloadIdentityDenial::MapperUnavailable,
                format!("the mapper could not be spawned: {error}"),
            )
        })?;
    let mut release = mapper
        .stdin
        .take()
        .expect("the mapper's stdin was requested piped");

    if let Err(error) = nix::sched::unshare(CloneFlags::CLONE_NEWUSER) {
        abandon(&mut mapper);
        return Err(IdentityError::new(
            WorkloadIdentityDenial::NamespaceCreationRefused,
            error.to_string(),
        ));
    }

    if let Err(error) = release.write_all(MAPPER_RELEASE) {
        abandon(&mut mapper);
        return Err(IdentityError::new(
            WorkloadIdentityDenial::MappingRefused,
            format!("the mapper could not be released: {error}"),
        ));
    }
    drop(release);
    match mapper.wait() {
        Ok(status) if status.success() => {}
        Ok(status) => {
            return Err(IdentityError::new(
                WorkloadIdentityDenial::MappingRefused,
                format!("the mapper exited with {status}"),
            ));
        }
        Err(error) => {
            return Err(IdentityError::new(
                WorkloadIdentityDenial::MappingRefused,
                format!("the mapper could not be waited for: {error}"),
            ));
        }
    }

    confirm_maps(&plan)?;
    switch_credentials(&plan)?;
    confirm_identity(&plan)?;

    let _previous = nix::sys::stat::umask(
        nix::sys::stat::Mode::from_bits(WORKLOAD_UMASK).expect("the umask is a mode"),
    );
    Ok(plan.workload)
}

/// Kill and reap a mapper that will not be released.
fn abandon(mapper: &mut std::process::Child) {
    let _ = mapper.kill();
    let _ = mapper.wait();
}

/// Read the kernel's maps back and refuse anything but the plan's exact lines.
fn confirm_maps(plan: &IdentityPlan) -> Result<(), IdentityError> {
    let unconfirmed =
        |detail: String| IdentityError::new(WorkloadIdentityDenial::MappingUnconfirmed, detail);
    let uid_map = read_bounded(Path::new("/proc/self/uid_map"), MAX_MAP_BYTES)
        .map_err(|error| unconfirmed(format!("uid_map: {error}")))?;
    let mut observed =
        parse_id_map(&uid_map).ok_or_else(|| unconfirmed("uid_map unreadable".to_owned()))?;
    observed.sort_unstable();
    let mut expected = vec![
        (SUPERVISOR_NAMESPACE_ID, plan.supervisor_uid, 1),
        (plan.workload.namespace_uid, plan.workload.host_uid, 1),
    ];
    expected.sort_unstable();
    if observed != expected {
        return Err(unconfirmed(format!(
            "uid_map is {observed:?}, expected {expected:?}"
        )));
    }

    let gid_map = read_bounded(Path::new("/proc/self/gid_map"), MAX_MAP_BYTES)
        .map_err(|error| unconfirmed(format!("gid_map: {error}")))?;
    let observed =
        parse_id_map(&gid_map).ok_or_else(|| unconfirmed("gid_map unreadable".to_owned()))?;
    let expected = vec![(SUPERVISOR_NAMESPACE_ID, plan.supervisor_gid, 1)];
    if observed != expected {
        return Err(unconfirmed(format!(
            "gid_map is {observed:?}, expected {expected:?}"
        )));
    }

    let setgroups = read_bounded(Path::new("/proc/self/setgroups"), MAX_MAP_BYTES)
        .map_err(|error| unconfirmed(format!("setgroups: {error}")))?;
    if setgroups.trim() != "deny" {
        return Err(unconfirmed(format!("setgroups is {:?}", setgroups.trim())));
    }
    Ok(())
}

/// `(inner, outer, count)` triples from an id-map file, in file order.
fn parse_id_map(contents: &str) -> Option<Vec<(u32, u32, u32)>> {
    contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let inner = fields.next()?.parse().ok()?;
            let outer = fields.next()?.parse().ok()?;
            let count = fields.next()?.parse().ok()?;
            if fields.next().is_some() {
                return None;
            }
            Some((inner, outer, count))
        })
        .collect()
}

/// Become the workload uid and keep exactly the workload's capabilities.
fn switch_credentials(plan: &IdentityPlan) -> Result<(), IdentityError> {
    let shaping = |step: &str, error: rustix::io::Errno| {
        IdentityError::new(
            WorkloadIdentityDenial::CapabilityShapingRefused,
            format!("{step}: {error}"),
        )
    };

    // Leaving in-namespace root clears the effective set and, without this,
    // the permitted set too. The permitted set is what the shaping below
    // narrows from, so keep it across the switch.
    rustix::thread::set_keep_capabilities(true)
        .map_err(|error| shaping("keep capabilities", error))?;

    let workload = Uid::from_raw(plan.workload.namespace_uid);
    nix::unistd::setresuid(workload, workload, workload).map_err(|error| {
        IdentityError::new(
            WorkloadIdentityDenial::CredentialSwitchRefused,
            format!(
                "setresuid to namespace uid {}: {error}",
                plan.workload.namespace_uid
            ),
        )
    })?;

    // Effective was cleared by the uid change; restore it from permitted so
    // CAP_SETPCAP is usable for the inheritable and bounding-set edits.
    let current = rustix::thread::capabilities(None).map_err(|error| shaping("capget", error))?;
    rustix::thread::set_capabilities(
        None,
        CapabilitySets {
            effective: current.permitted,
            permitted: current.permitted,
            inheritable: current.inheritable,
        },
    )
    .map_err(|error| shaping("restore effective", error))?;
    rustix::thread::set_capabilities(
        None,
        CapabilitySets {
            effective: current.permitted,
            permitted: current.permitted,
            inheritable: WORKLOAD_CAPABILITIES,
        },
    )
    .map_err(|error| shaping("set inheritable", error))?;

    // The bounding set bounds what any later exec could add. Drop everything
    // this build can name except the workload's three.
    for capability in KNOWN_CAPABILITIES {
        if WORKLOAD_CAPABILITIES.contains(capability) {
            continue;
        }
        let present = rustix::thread::capability_is_in_bounding_set(capability)
            .map_err(|error| shaping("read bounding set", error))?;
        if present {
            rustix::thread::remove_capability_from_bounding_set(capability)
                .map_err(|error| shaping("drop from bounding set", error))?;
        }
    }

    rustix::thread::set_capabilities(
        None,
        CapabilitySets {
            effective: WORKLOAD_CAPABILITIES,
            permitted: WORKLOAD_CAPABILITIES,
            inheritable: WORKLOAD_CAPABILITIES,
        },
    )
    .map_err(|error| shaping("narrow to workload capabilities", error))?;

    // Ambient is what crosses `execve` for a non-root process without file
    // capabilities; raising needs the capability in both permitted and
    // inheritable, which the sets above guarantee.
    for capability in WORKLOAD_AMBIENT {
        rustix::thread::configure_capability_in_ambient_set(capability, true)
            .map_err(|error| shaping("raise ambient", error))?;
    }

    rustix::thread::set_keep_capabilities(false)
        .map_err(|error| shaping("reset keep capabilities", error))?;
    Ok(())
}

/// The bits of every capability this build names.
fn known_capability_mask() -> u64 {
    KNOWN_CAPABILITIES
        .into_iter()
        .fold(0, |mask, capability| mask | capability.bits())
}

/// The process's own status after the switch, as evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityStatus {
    /// `Uid:` real, effective, saved, filesystem — in the namespace's terms.
    pub uid: [u32; 4],
    /// `Gid:` real, effective, saved, filesystem — in the namespace's terms.
    pub gid: [u32; 4],
    /// `CapInh:`.
    pub inheritable: u64,
    /// `CapPrm:`.
    pub permitted: u64,
    /// `CapEff:`.
    pub effective: u64,
    /// `CapBnd:`.
    pub bounding: u64,
    /// `CapAmb:`.
    pub ambient: u64,
}

impl IdentityStatus {
    /// Parse the fields this module confirms out of a `/proc/<pid>/status`.
    #[must_use]
    pub fn parse(status: &str) -> Option<Self> {
        let mut uid = None;
        let mut gid = None;
        let mut inheritable = None;
        let mut permitted = None;
        let mut effective = None;
        let mut bounding = None;
        let mut ambient = None;
        for line in status.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key {
                "Uid" => uid = parse_four(value),
                "Gid" => gid = parse_four(value),
                "CapInh" => inheritable = u64::from_str_radix(value, 16).ok(),
                "CapPrm" => permitted = u64::from_str_radix(value, 16).ok(),
                "CapEff" => effective = u64::from_str_radix(value, 16).ok(),
                "CapBnd" => bounding = u64::from_str_radix(value, 16).ok(),
                "CapAmb" => ambient = u64::from_str_radix(value, 16).ok(),
                _ => {}
            }
        }
        Some(Self {
            uid: uid?,
            gid: gid?,
            inheritable: inheritable?,
            permitted: permitted?,
            effective: effective?,
            bounding: bounding?,
            ambient: ambient?,
        })
    }
}

fn parse_four(value: &str) -> Option<[u32; 4]> {
    let mut fields = value.split_ascii_whitespace();
    let parsed = [
        fields.next()?.parse().ok()?,
        fields.next()?.parse().ok()?,
        fields.next()?.parse().ok()?,
        fields.next()?.parse().ok()?,
    ];
    if fields.next().is_some() {
        return None;
    }
    Some(parsed)
}

/// Refuse unless `/proc/self/status` shows exactly the identity asked for.
fn confirm_identity(plan: &IdentityPlan) -> Result<(), IdentityError> {
    let unconfirmed =
        |detail: String| IdentityError::new(WorkloadIdentityDenial::IdentityUnconfirmed, detail);
    let status = read_bounded(Path::new("/proc/self/status"), MAX_STATUS_BYTES)
        .map_err(|error| unconfirmed(format!("status: {error}")))?;
    let status = IdentityStatus::parse(&status)
        .ok_or_else(|| unconfirmed("status unreadable".to_owned()))?;
    let uid = plan.workload.namespace_uid;
    if status.uid != [uid; 4] {
        return Err(unconfirmed(format!(
            "Uid is {:?}, expected {uid}",
            status.uid
        )));
    }
    if status.gid != [SUPERVISOR_NAMESPACE_ID; 4] {
        return Err(unconfirmed(format!(
            "Gid is {:?}, expected {SUPERVISOR_NAMESPACE_ID}",
            status.gid
        )));
    }
    let wanted = WORKLOAD_CAPABILITIES.bits();
    for (name, observed) in [
        ("CapInh", status.inheritable),
        ("CapPrm", status.permitted),
        ("CapEff", status.effective),
        ("CapAmb", status.ambient),
    ] {
        if observed != wanted {
            return Err(unconfirmed(format!(
                "{name} is {observed:016x}, expected {wanted:016x}"
            )));
        }
    }
    if status.bounding & known_capability_mask() != wanted {
        return Err(unconfirmed(format!(
            "CapBnd is {:016x}, expected {wanted:016x} over the known bits",
            status.bounding
        )));
    }
    Ok(())
}

/// Read a fixed path under a byte bound, refusing symlinks.
fn read_bounded(path: &Path, limit: usize) -> Result<String, std::io::Error> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(limit + 1).expect("bound fits"))
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::Error::other("exceeds the read bound"));
    }
    String::from_utf8(bytes).map_err(|_| std::io::Error::other("not UTF-8"))
}

/// Process body for [`MAP_MODE_FLAG`]: map the parent, then exit.
///
/// The parent has unshared its user namespace and is blocked on this
/// process's exit. It sends one release line first, so a mapper started by
/// anything else waits forever on nothing rather than writing a map.
#[must_use]
pub fn map_workload_identity_main() -> i32 {
    match map_parent_identity() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("automonique-launch-enter: identity mapper refused: {error}");
            HELPER_REFUSED_EXIT
        }
    }
}

fn map_parent_identity() -> Result<(), IdentityError> {
    let mut release = vec![0_u8; MAPPER_RELEASE.len()];
    std::io::stdin()
        .lock()
        .read_exact(&mut release)
        .map_err(|error| {
            IdentityError::new(
                WorkloadIdentityDenial::MappingRefused,
                format!("no release from the helper: {error}"),
            )
        })?;
    if release != MAPPER_RELEASE {
        return Err(IdentityError::new(
            WorkloadIdentityDenial::MappingRefused,
            "the release line is not the expected one",
        ));
    }
    let plan = resolve_identity_plan()?;
    let parent = nix::unistd::getppid().as_raw();
    if parent <= 1 {
        return Err(IdentityError::new(
            WorkloadIdentityDenial::MappingRefused,
            "the helper is gone",
        ));
    }
    let uid_arguments = [
        SUPERVISOR_NAMESPACE_ID,
        plan.supervisor_uid,
        1,
        plan.workload.namespace_uid,
        plan.workload.host_uid,
        1,
    ];
    run_mapper(&plan.newuidmap, parent, &uid_arguments)?;
    let gid_arguments = [SUPERVISOR_NAMESPACE_ID, plan.supervisor_gid, 1];
    run_mapper(&plan.newgidmap, parent, &gid_arguments)?;
    Ok(())
}

/// `newuidmap`/`newgidmap <pid> <inner> <outer> <count> ...`, typed argv.
fn run_mapper(mapper: &Path, target: i32, arguments: &[u32]) -> Result<(), IdentityError> {
    let mut command = Command::new(mapper);
    command.arg(target.to_string());
    for argument in arguments {
        command.arg(argument.to_string());
    }
    let status = command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| {
            IdentityError::new(
                WorkloadIdentityDenial::MapperUnavailable,
                format!("{}: {error}", mapper.display()),
            )
        })?;
    if !status.success() {
        return Err(IdentityError::new(
            WorkloadIdentityDenial::MappingRefused,
            format!("{} exited with {status}", mapper.display()),
        ));
    }
    Ok(())
}

/// Process body for [`PROBE_MODE_FLAG`]: perform the switch on this throwaway
/// process and report the outcome as one line on stdout.
#[must_use]
pub fn probe_workload_identity_main() -> i32 {
    match separate_workload_identity() {
        Ok(identity) => {
            println!(
                "{PROBE_SEPARABLE} ns_uid={} host_uid={} host_gid={}",
                identity.namespace_uid, identity.host_uid, identity.host_gid
            );
            0
        }
        Err(error) => {
            println!(
                "{PROBE_UNAVAILABLE} code={} reason={error}",
                error.denial().as_str()
            );
            HELPER_REFUSED_EXIT
        }
    }
}

/// Read the probe child's one-line report.
///
/// `None` when the line is not a report at all; `Some(Err)` for a report of a
/// denial, with [`WorkloadIdentityDenial::ProbeInconclusive`] for a code this
/// build does not know.
#[must_use]
pub fn parse_probe_report(line: &str) -> Option<Result<WorkloadIdentity, WorkloadIdentityDenial>> {
    let line = line.trim();
    if let Some(fields) = line.strip_prefix(PROBE_SEPARABLE) {
        let mut namespace_uid = None;
        let mut host_uid = None;
        let mut host_gid = None;
        for field in fields.split_ascii_whitespace() {
            let (key, value) = field.split_once('=')?;
            let value = value.parse::<u32>().ok()?;
            match key {
                "ns_uid" => namespace_uid = Some(value),
                "host_uid" => host_uid = Some(value),
                "host_gid" => host_gid = Some(value),
                _ => return None,
            }
        }
        return Some(Ok(WorkloadIdentity {
            namespace_uid: namespace_uid?,
            host_uid: host_uid?,
            host_gid: host_gid?,
        }));
    }
    let fields = line.strip_prefix(PROBE_UNAVAILABLE)?;
    let code = fields
        .split_ascii_whitespace()
        .find_map(|field| field.strip_prefix("code="))?;
    Some(Err(
        WorkloadIdentityDenial::parse(code).unwrap_or(WorkloadIdentityDenial::ProbeInconclusive)
    ))
}

/// Ask `helper` what identity a workload would get, in a throwaway child.
///
/// The child is the helper in [`PROBE_MODE_FLAG`] mode: it performs the whole
/// switch on itself and reports its own kernel view, so the answer is the
/// launch's answer rather than a reading of configuration files. The
/// supervisor's own process is not touched.
pub fn probe_with_launch_helper(helper: &Path) -> Result<WorkloadIdentity, WorkloadIdentityDenial> {
    let output = Command::new(helper)
        .arg(PROBE_MODE_FLAG)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| WorkloadIdentityDenial::HelperUnavailable)?;
    if output.stdout.len() > MAX_REPORT_BYTES {
        return Err(WorkloadIdentityDenial::ProbeInconclusive);
    }
    let report =
        String::from_utf8(output.stdout).map_err(|_| WorkloadIdentityDenial::ProbeInconclusive)?;
    let Some(line) = report.lines().next() else {
        return Err(WorkloadIdentityDenial::HelperUnavailable);
    };
    match parse_probe_report(line) {
        Some(Ok(identity)) if output.status.success() => Ok(identity),
        Some(Ok(_)) => Err(WorkloadIdentityDenial::ProbeInconclusive),
        Some(Err(denial)) => Err(denial),
        None => Err(WorkloadIdentityDenial::ProbeInconclusive),
    }
}

/// Opened for its side effect in tests: a file that must exist and be a
/// regular file for the mapper check to pass.
#[cfg(test)]
fn touch(path: &Path) -> std::fs::File {
    std::fs::File::create(path).expect("fixture file")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUBUID: &str = "\
# comment
ubuntu:100000:65536
alice:165536:65536
1025:200000:65536
alice:300000:10
";

    #[test]
    fn the_first_range_naming_the_owner_wins_by_name_or_number() {
        assert_eq!(
            first_subordinate_range(SUBUID, &["1025", "infra"]),
            Some((200_000, 65_536))
        );
        assert_eq!(
            first_subordinate_range(SUBUID, &["9", "alice"]),
            Some((165_536, 65_536))
        );
        assert_eq!(first_subordinate_range(SUBUID, &["9", "nobody"]), None);
    }

    #[test]
    fn malformed_lines_are_skipped_not_refused() {
        let contents = "alice:notanumber:5\nalice:10:x\nalice:1:2:3\nalice:400000:8\n";
        assert_eq!(
            first_subordinate_range(contents, &["alice"]),
            Some((400_000, 8))
        );
    }

    #[test]
    fn the_workload_uid_is_the_top_of_the_range_and_never_the_supervisor() {
        assert_eq!(subordinate_top(100_000, 65_536, 1025), Some(165_535));
        assert_eq!(subordinate_top(100_000, 1, 1025), Some(100_000));
        assert_eq!(subordinate_top(100_000, 0, 1025), None, "empty range");
        assert_eq!(
            subordinate_top(0, 10, 1025),
            None,
            "a range starting at root"
        );
        assert_eq!(
            subordinate_top(1000, 100, 1025),
            None,
            "contains the supervisor"
        );
        assert_eq!(
            subordinate_top(65_000, 535, 1025),
            None,
            "ends on the overflow uid"
        );
        assert_eq!(subordinate_top(u32::MAX - 5, 10, 1025), None, "overflows");
        assert_eq!(
            subordinate_top(u32::MAX - 5, 6, 1025),
            None,
            "ends on the last uid"
        );
    }

    #[test]
    fn id_maps_parse_as_the_kernel_prints_them() {
        let parsed =
            parse_id_map("         0       1025          1\n      1025     265535          1\n");
        assert_eq!(parsed, Some(vec![(0, 1025, 1), (1025, 265_535, 1)]));
        assert_eq!(parse_id_map("0 1025\n"), None);
        assert_eq!(parse_id_map(""), Some(Vec::new()));
    }

    #[test]
    fn status_fields_parse_and_the_workload_mask_is_three_bits() {
        let status = "Name:\tx\nUid:\t1025\t1025\t1025\t1025\nGid:\t0\t0\t0\t0\n\
                      CapInh:\t000000000000000e\nCapPrm:\t000000000000000e\n\
                      CapEff:\t000000000000000e\nCapBnd:\t000000000000000e\n\
                      CapAmb:\t000000000000000e\n";
        let parsed = IdentityStatus::parse(status).unwrap();
        assert_eq!(parsed.uid, [1025; 4]);
        assert_eq!(parsed.gid, [0; 4]);
        assert_eq!(parsed.ambient, WORKLOAD_CAPABILITIES.bits());
        assert_eq!(WORKLOAD_CAPABILITIES.bits(), 0b1110);
        assert_eq!(WORKLOAD_CAPABILITIES.bits().count_ones(), 3);
        assert!(IdentityStatus::parse("Uid:\t1\t1\t1\t1\n").is_none());
        assert_eq!(known_capability_mask(), (1_u64 << 41) - 1);
    }

    #[test]
    fn the_probe_report_round_trips() {
        let identity = WorkloadIdentity {
            namespace_uid: 1025,
            host_uid: 265_535,
            host_gid: 1025,
        };
        let line = format!(
            "{PROBE_SEPARABLE} ns_uid={} host_uid={} host_gid={}",
            identity.namespace_uid, identity.host_uid, identity.host_gid
        );
        assert_eq!(parse_probe_report(&line), Some(Ok(identity)));
        for denial in WorkloadIdentityDenial::ALL {
            let line = format!(
                "{PROBE_UNAVAILABLE} code={} reason=whatever",
                denial.as_str()
            );
            assert_eq!(parse_probe_report(&line), Some(Err(denial)));
            assert_eq!(WorkloadIdentityDenial::parse(denial.as_str()), Some(denial));
        }
        assert_eq!(
            parse_probe_report(&format!("{PROBE_UNAVAILABLE} code=from_the_future")),
            Some(Err(WorkloadIdentityDenial::ProbeInconclusive))
        );
        assert_eq!(parse_probe_report("hello"), None);
        assert_eq!(
            parse_probe_report(&format!("{PROBE_SEPARABLE} ns_uid=1")),
            None
        );
    }

    #[test]
    fn the_plan_is_refused_closed_for_each_missing_prerequisite() {
        let temporary = tempfile::tempdir().unwrap();
        let subuid = temporary.path().join("subuid");
        let subgid = temporary.path().join("subgid");
        let newuidmap = temporary.path().join("newuidmap");
        let newgidmap = temporary.path().join("newgidmap");
        let sources = IdentitySources::at(&subuid, &subgid, &newuidmap, &newgidmap);

        let denial = |result: Result<IdentityPlan, IdentityError>| result.unwrap_err().denial();

        assert_eq!(
            denial(resolve_identity_plan_for(&sources, 0, 0, Some("root"))),
            WorkloadIdentityDenial::SupervisorIsRoot
        );
        assert_eq!(
            denial(resolve_identity_plan_for(&sources, 1025, 1025, None)),
            WorkloadIdentityDenial::OwnerUnresolvable
        );
        assert_eq!(
            denial(resolve_identity_plan_for(&sources, 1025, 1025, Some("me"))),
            WorkloadIdentityDenial::NoSubordinateUids,
            "no subuid file at all"
        );
        std::fs::write(&subuid, "other:100000:65536\n").unwrap();
        assert_eq!(
            denial(resolve_identity_plan_for(&sources, 1025, 1025, Some("me"))),
            WorkloadIdentityDenial::NoSubordinateUids
        );
        std::fs::write(&subuid, "me:200000:65536\n").unwrap();
        assert_eq!(
            denial(resolve_identity_plan_for(&sources, 1025, 1025, Some("me"))),
            WorkloadIdentityDenial::NoSubordinateGids
        );
        std::fs::write(&subgid, "1025:200000:65536\n").unwrap();
        assert_eq!(
            denial(resolve_identity_plan_for(&sources, 1025, 1025, Some("me"))),
            WorkloadIdentityDenial::MapperUnavailable,
            "no mapper binaries"
        );
        // A range that contains the supervisor's own uid is refused before
        // the mappers are even looked at.
        std::fs::write(&subuid, "me:1000:100\n").unwrap();
        assert_eq!(
            denial(resolve_identity_plan_for(&sources, 1025, 1025, Some("me"))),
            WorkloadIdentityDenial::SubordinateRangeUnusable
        );
        std::fs::write(&subuid, "me:200000:65536\n").unwrap();
        // Present but not setuid root: still unavailable.
        drop(touch(&newuidmap));
        drop(touch(&newgidmap));
        assert_eq!(
            denial(resolve_identity_plan_for(&sources, 1025, 1025, Some("me"))),
            WorkloadIdentityDenial::MapperUnavailable
        );
    }

    #[test]
    fn the_plan_names_the_top_of_the_first_range_with_the_host_mappers() {
        let temporary = tempfile::tempdir().unwrap();
        let subuid = temporary.path().join("subuid");
        let subgid = temporary.path().join("subgid");
        std::fs::write(&subuid, "me:200000:65536\nme:300000:10\n").unwrap();
        std::fs::write(&subgid, "me:200000:65536\n").unwrap();
        // The host's real mappers, when present, satisfy the setuid check;
        // without them the plan is refused and this test says so.
        let sources = IdentitySources::at(&subuid, &subgid, NEWUIDMAP_PATH, NEWGIDMAP_PATH);
        match resolve_identity_plan_for(&sources, 1025, 1025, Some("me")) {
            Ok(plan) => {
                assert_eq!(plan.workload().namespace_uid(), 1025);
                assert_eq!(plan.workload().host_uid(), 265_535);
                assert_eq!(plan.workload().host_gid(), 1025);
                assert_eq!(plan.supervisor_uid(), 1025);
                assert_eq!(plan.supervisor_gid(), 1025);
            }
            Err(error) => {
                assert_eq!(error.denial(), WorkloadIdentityDenial::MapperUnavailable);
                eprintln!("[identity] NOT PROVEN: {error}");
            }
        }
    }
}
