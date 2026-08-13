// SPDX-License-Identifier: Elastic-2.0

//! Read-only host capability probe and enforcement-mode selection.
//!
//! Unlike [`crate::containment`], which installs and exercises a real boundary,
//! and unlike [`crate::boundary`], which only records that kernel interfaces are
//! visible, this module answers one narrower question: **which enforcement
//! mechanisms could this host actually give a launcher, and what does the
//! strongest reachable combination fail to provide?**
//!
//! Three rules shape every type here.
//!
//! 1. *Observation is not installation.* A finding says a mechanism is
//!    available to a launcher that installs it correctly. No finding says a
//!    boundary exists. Nothing in this module runs a workload, and no value it
//!    returns is authority to launch one.
//! 2. *A probe must not become the thing it measures.* The probe never creates a
//!    cgroup, never allocates a Landlock ruleset descriptor, never calls
//!    `restrict_self`, never sets `PR_SET_NO_NEW_PRIVS`, never installs a
//!    seccomp filter, and never calls `unshare`. Any of those would restrict the
//!    supervisor itself, permanently and irreversibly, as a side effect of
//!    asking a question.
//! 3. *Degradation is never silent.* [`HostCapabilities::select_mode`] returns
//!    either a mode that enforces every requested property, or a typed refusal
//!    naming each requested property no available mode can enforce and which
//!    mechanism was blocked for it. A successful selection additionally carries
//!    every property the mode does *not* enforce, so a caller that asked for
//!    little still learns exactly what it did not get.
//!
//! # Why the securityfs entry is not consulted
//!
//! [`crate::boundary`] treats `/sys/kernel/security/landlock` as the Landlock
//! signal. That path is a visibility observation, not a support observation, and
//! the two disagree: on the development host for this module the securityfs
//! entry is absent while the kernel answers the Landlock version query with ABI
//! 4. This module therefore asks the kernel directly, through the `landlock`
//! crate's compatibility engine, and ignores securityfs entirely.

use crate::containment::{ContainmentDomain, ContainmentError};
use crate::landlock_abi::KNOWN as KNOWN_LANDLOCK_ABI;
use landlock::{
    ABI, Access as _, AccessFs, AccessNet, CompatLevel, Compatible as _, Ruleset, RulesetAttr as _,
    Scope,
};
use std::fmt;
use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

/// Lowest Landlock ABI that defines filesystem access rights (Linux 5.13).
pub const LANDLOCK_ABI_FILESYSTEM: u8 = 1;
/// Lowest Landlock ABI that defines TCP bind and connect access rights
/// (Linux 6.7).
pub const LANDLOCK_ABI_TCP: u8 = 4;
/// Highest Landlock ABI level the pinned `landlock` crate can describe. A
/// kernel newer than this is reported as this level, never higher.
pub const LANDLOCK_ABI_HIGHEST_KNOWN: u8 = 9;

/// Kernel-published list of seccomp filter actions.
const SECCOMP_ACTIONS_PATH: &str = "/proc/sys/kernel/seccomp/actions_avail";
/// Per-process status view, whose `Seccomp:` line implies `CONFIG_SECCOMP`.
const PROC_STATUS_PATH: &str = "/proc/self/status";
/// User-namespace identity of this process; absent without `CONFIG_USER_NS`.
const USER_NS_PATH: &str = "/proc/self/ns/user";
/// Per-user-namespace creation quota. Zero forbids creation outright.
const MAX_USER_NAMESPACES_PATH: &str = "/proc/sys/user/max_user_namespaces";
/// Debian/Ubuntu toggle for unprivileged `unshare(CLONE_NEWUSER)`.
const UNPRIVILEGED_USERNS_CLONE_PATH: &str = "/proc/sys/kernel/unprivileged_userns_clone";
/// Ubuntu AppArmor restriction on unprivileged user-namespace creation.
const APPARMOR_RESTRICT_USERNS_PATH: &str =
    "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

/// Bound on a numeric sysctl read.
const MAX_SYSCTL_BYTES: usize = 64;
/// Bound on the seccomp action list read.
const MAX_ACTIONS_BYTES: usize = 4096;
/// Bound on the process status read.
const MAX_STATUS_BYTES: usize = 64 * 1024;

/// Seccomp actions that can actually refuse a syscall. A filter built only from
/// `log` and `allow` denies nothing, so its availability is not a restriction.
const DENYING_SECCOMP_ACTIONS: [&str; 5] = ["kill_process", "kill_thread", "kill", "errno", "trap"];

/// A measured Landlock ABI level.
///
/// This is a **floor**, not necessarily the kernel's exact level. The probe
/// establishes it by asking which access rights the running kernel accepts as a
/// hard requirement, and consecutive ABI levels sometimes define identical
/// access-right sets: ABI 6, 7, and 8 differ only in `restrict_self` flags,
/// which cannot be measured without restricting this process. A kernel at ABI 8
/// is therefore reported as 6. Reporting the floor can only understate what the
/// host offers, never overstate it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LandlockAbi(u8);

impl LandlockAbi {
    /// Construct an exact level, rejecting anything outside the known range.
    #[must_use]
    pub const fn from_level(level: u8) -> Option<Self> {
        match level {
            LANDLOCK_ABI_FILESYSTEM..=LANDLOCK_ABI_HIGHEST_KNOWN => Some(Self(level)),
            _ => None,
        }
    }

    /// Measured ABI level.
    #[must_use]
    pub const fn level(self) -> u8 {
        self.0
    }

    /// Whether this level defines filesystem access rights.
    ///
    /// True for every constructible value: ABI 1 already defines them. The
    /// method exists so callers state the requirement rather than assume it.
    #[must_use]
    pub const fn restricts_filesystem(self) -> bool {
        self.0 >= LANDLOCK_ABI_FILESYSTEM
    }

    /// Whether this level can deny TCP bind and connect.
    ///
    /// Landlock's network access rights cover exactly those two operations. No
    /// Landlock ruleset at any level denies UDP, raw sockets, or unix sockets,
    /// which is why [`BoundaryProperty::TcpDenial`] and
    /// [`BoundaryProperty::CompleteNetworkDenial`] are separate properties.
    #[must_use]
    pub const fn denies_tcp(self) -> bool {
        self.0 >= LANDLOCK_ABI_TCP
    }
}

impl fmt::Display for LandlockAbi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ABI {}", self.0)
    }
}

/// Why this host offers no usable cgroup v2 containment domain.
///
/// This is a comparable projection of [`ContainmentError`], restricted to the
/// outcomes [`ContainmentDomain::discover`] can produce. The verbatim error
/// stays inside [`ContainmentFinding::Unusable`]; this exists so a refusal can
/// be compared and routed without collapsing "no cgroup v2 at all" into "cgroup
/// v2 present but not delegated to this process".
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ContainmentUnavailable {
    /// No unified cgroup v2 hierarchy describes this process.
    NoUnifiedHierarchy,
    /// The hierarchy exists, but this process's own cgroup is not writable, so
    /// it cannot create or populate child cgroups. cgroup v2 delegation
    /// containment forbids migrating a process across an unowned ancestor.
    NotDelegated,
    /// The domain exposes no `cgroup.kill`, so termination could not be made
    /// atomic and descendant-complete.
    NoAtomicKill,
    /// The domain could not be read at all.
    Unreadable,
}

impl ContainmentUnavailable {
    /// Stable spelling for logs and protocol adapters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoUnifiedHierarchy => "no_unified_hierarchy",
            Self::NotDelegated => "not_delegated",
            Self::NoAtomicKill => "no_atomic_kill",
            Self::Unreadable => "unreadable",
        }
    }
}

impl fmt::Display for ContainmentUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoUnifiedHierarchy => {
                formatter.write_str("no unified cgroup v2 hierarchy describes this process")
            }
            Self::NotDelegated => formatter.write_str(
                "this process's own cgroup is not delegated, so it cannot place children",
            ),
            Self::NoAtomicKill => {
                formatter.write_str("the domain exposes no atomic cgroup.kill interface")
            }
            Self::Unreadable => formatter.write_str("the cgroup domain could not be read"),
        }
    }
}

/// Whether this process can place children in a kernel-owned containment domain.
///
/// A finding is an observation, never a handle. [`Self::Delegated`] carries
/// nothing: obtaining an actual domain still requires
/// [`ContainmentDomain::discover`], which re-checks every precondition itself.
/// Fabricating this finding therefore grants nothing.
#[derive(Debug)]
pub enum ContainmentFinding {
    /// This process's own cgroup is a delegated, writable domain exposing
    /// `cgroup.kill`, so a launcher can create a run cgroup beneath it.
    Delegated,
    /// No usable domain, with the verbatim typed reason from discovery.
    Unusable(ContainmentError),
}

impl ContainmentFinding {
    /// Observe this process's own cgroup. Read-only: discovery only stats fixed
    /// kernel paths, reads `/proc/self/cgroup`, and tests write access.
    #[must_use]
    pub fn probe() -> Self {
        match ContainmentDomain::discover() {
            Ok(_) => Self::Delegated,
            Err(error) => Self::Unusable(error),
        }
    }

    /// Whether a launcher could create a run cgroup on this host.
    #[must_use]
    pub const fn is_delegated(&self) -> bool {
        matches!(self, Self::Delegated)
    }

    /// Comparable reason a domain is unusable, or `None` when one exists.
    #[must_use]
    pub fn denial(&self) -> Option<ContainmentUnavailable> {
        match self {
            Self::Delegated => None,
            Self::Unusable(error) => Some(match error {
                ContainmentError::NotUnifiedCgroupV2 => ContainmentUnavailable::NoUnifiedHierarchy,
                ContainmentError::DomainNotDelegated => ContainmentUnavailable::NotDelegated,
                ContainmentError::MissingAtomicKill => ContainmentUnavailable::NoAtomicKill,
                // Discovery produces no other variant. A future variant is
                // reported as unreadable rather than silently treated as usable.
                _ => ContainmentUnavailable::Unreadable,
            }),
        }
    }
}

/// What Landlock the running kernel would give a launcher.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LandlockFinding {
    /// The kernel accepts every access right defined up to this ABI level as a
    /// hard requirement. Enforcement still depends on a launcher applying a
    /// ruleset to the workload before `exec`; nothing is applied here.
    Enforceable(LandlockAbi),
    /// The running kernel accepts no Landlock access right this build knows, so
    /// no Landlock boundary can be installed.
    ///
    /// The kernel exposes no interface this read-only probe can reach that
    /// separates "not built in" from "built but not enabled at boot", so
    /// neither is claimed.
    Unsupported,
}

impl LandlockFinding {
    /// Measure the Landlock ABI floor without creating or applying a ruleset.
    ///
    /// The only kernel interaction is `landlock_create_ruleset(NULL, 0,
    /// LANDLOCK_CREATE_RULESET_VERSION)`, issued inside `Ruleset::default()`.
    /// That call is a pure version query: it allocates no descriptor and
    /// changes no process state. [`Ruleset::create`] and `restrict_self` are
    /// deliberately never reached.
    #[must_use]
    pub fn probe() -> Self {
        let mut measured = None;
        // Access-right sets are cumulative across ABI levels, so the first level
        // this kernel rejects bounds every higher level.
        for (level, abi) in KNOWN_LANDLOCK_ABI {
            if !abi_is_hard_requirable(abi) {
                break;
            }
            measured = LandlockAbi::from_level(level);
        }
        measured.map_or(Self::Unsupported, Self::Enforceable)
    }

    /// Measured ABI floor, or `None` when Landlock cannot be used at all.
    #[must_use]
    pub const fn abi(self) -> Option<LandlockAbi> {
        match self {
            Self::Enforceable(abi) => Some(abi),
            Self::Unsupported => None,
        }
    }
}

/// Whether the running kernel accepts every access right defined up to `abi`.
///
/// [`CompatLevel::HardRequirement`] turns an unsupported access right into a
/// build error instead of a silent downgrade, which is exactly the question
/// being asked. Only the builder is exercised; no ruleset is created.
fn abi_is_hard_requirable(abi: ABI) -> bool {
    let ruleset = Ruleset::default().set_compatibility(CompatLevel::HardRequirement);

    let filesystem = AccessFs::from_all(abi);
    if filesystem.is_empty() {
        return false;
    }
    let Ok(ruleset) = ruleset.handle_access(filesystem) else {
        return false;
    };

    // Empty access sets are rejected by the builder, so a level that defines no
    // network or scope rights simply contributes no check.
    let network = AccessNet::from_all(abi);
    let ruleset = if network.is_empty() {
        ruleset
    } else {
        match ruleset.handle_access(network) {
            Ok(ruleset) => ruleset,
            Err(_) => return false,
        }
    };

    let scope = Scope::from_all(abi);
    if scope.is_empty() {
        return true;
    }
    ruleset.scope(scope).is_ok()
}

/// A read-only kernel policy that forbids unprivileged user-namespace creation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UserNamespaceDenial {
    /// The kernel exposes no user-namespace identity for this process, so it
    /// was built without `CONFIG_USER_NS`.
    NoKernelSupport,
    /// `/proc/sys/user/max_user_namespaces` is zero: the creation quota for
    /// this namespace is exhausted by policy.
    QuotaZero,
    /// `/proc/sys/kernel/unprivileged_userns_clone` is zero: the distribution
    /// toggle for unprivileged creation is off.
    UnprivilegedCloneDisabled,
    /// `/proc/sys/kernel/apparmor_restrict_unprivileged_userns` is set:
    /// AppArmor denies unprivileged creation to processes whose profile does
    /// not carry the `userns` permission.
    ApparmorRestricted,
}

impl UserNamespaceDenial {
    /// Stable spelling for logs and protocol adapters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoKernelSupport => "no_kernel_support",
            Self::QuotaZero => "quota_zero",
            Self::UnprivilegedCloneDisabled => "unprivileged_clone_disabled",
            Self::ApparmorRestricted => "apparmor_restricted",
        }
    }

    /// Fixed kernel path whose value produced this denial, when there is one.
    ///
    /// Exposed so a caller (or a test) can re-read the same ground truth
    /// independently instead of trusting this module's reading of it.
    #[must_use]
    pub const fn evidence_path(self) -> Option<&'static str> {
        match self {
            Self::NoKernelSupport => None,
            Self::QuotaZero => Some(MAX_USER_NAMESPACES_PATH),
            Self::UnprivilegedCloneDisabled => Some(UNPRIVILEGED_USERNS_CLONE_PATH),
            Self::ApparmorRestricted => Some(APPARMOR_RESTRICT_USERNS_PATH),
        }
    }
}

impl fmt::Display for UserNamespaceDenial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoKernelSupport => {
                formatter.write_str("the kernel exposes no user-namespace identity")
            }
            Self::QuotaZero => {
                write!(formatter, "{MAX_USER_NAMESPACES_PATH} is zero")
            }
            Self::UnprivilegedCloneDisabled => {
                write!(formatter, "{UNPRIVILEGED_USERNS_CLONE_PATH} is zero")
            }
            Self::ApparmorRestricted => {
                write!(
                    formatter,
                    "{APPARMOR_RESTRICT_USERNS_PATH} denies unprivileged user namespaces"
                )
            }
        }
    }
}

/// Whether a launcher could unshare a user namespace on this host.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UserNamespaceFinding {
    /// No read-only kernel policy forbids unprivileged creation.
    ///
    /// This is deliberately not spelled "available". The probe never calls
    /// `unshare(CLONE_NEWUSER)` — doing so would move this process into a new
    /// namespace as a side effect of asking — so it can rule denial out but
    /// cannot prove success.
    NoObservedDenial,
    /// A specific kernel policy forbids it.
    Denied(UserNamespaceDenial),
}

impl UserNamespaceFinding {
    /// Read the fixed kernel policies that gate unprivileged creation.
    ///
    /// A process holding `CAP_SYS_ADMIN` in the initial user namespace is
    /// exempt from the AppArmor restriction. The runner is not intended to hold
    /// that capability, and claiming the exemption would require trusting a
    /// capability reading this probe cannot confirm, so the restriction is
    /// always reported as denial. That errs toward refusing a mode this host
    /// might in fact support, never toward selecting one it does not.
    #[must_use]
    pub fn probe() -> Self {
        if std::fs::read_link(USER_NS_PATH).is_err() {
            return Self::Denied(UserNamespaceDenial::NoKernelSupport);
        }
        if read_sysctl_u64(MAX_USER_NAMESPACES_PATH) == Some(0) {
            return Self::Denied(UserNamespaceDenial::QuotaZero);
        }
        if read_sysctl_u64(UNPRIVILEGED_USERNS_CLONE_PATH) == Some(0) {
            return Self::Denied(UserNamespaceDenial::UnprivilegedCloneDisabled);
        }
        if matches!(read_sysctl_u64(APPARMOR_RESTRICT_USERNS_PATH), Some(value) if value != 0) {
            return Self::Denied(UserNamespaceDenial::ApparmorRestricted);
        }
        Self::NoObservedDenial
    }

    /// The denying policy, or `None` when none was observed.
    #[must_use]
    pub const fn denial(self) -> Option<UserNamespaceDenial> {
        match self {
            Self::NoObservedDenial => None,
            Self::Denied(denial) => Some(denial),
        }
    }
}

/// Why `seccomp(2)` filter mode cannot narrow a workload's syscall surface.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SeccompUnavailable {
    /// `/proc/self/status` reports a seccomp mode, so `CONFIG_SECCOMP` is set,
    /// but the kernel publishes no filter action list. Only strict mode may
    /// exist, and strict mode permits just `read`, `write`, `_exit`, and
    /// `sigreturn`, which no provider workload survives.
    StrictModeOnly,
    /// The kernel publishes a filter action list, but no action in it refuses a
    /// syscall, so a filter could log or allow and never deny.
    NoDenyingAction,
    /// No seccomp interface is visible to this process.
    NoInterface,
}

impl SeccompUnavailable {
    /// Stable spelling for logs and protocol adapters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StrictModeOnly => "strict_mode_only",
            Self::NoDenyingAction => "no_denying_action",
            Self::NoInterface => "no_interface",
        }
    }
}

impl fmt::Display for SeccompUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StrictModeOnly => formatter
                .write_str("only seccomp strict mode is observable, which no workload survives"),
            Self::NoDenyingAction => {
                formatter.write_str("no available seccomp action can refuse a syscall")
            }
            Self::NoInterface => formatter.write_str("no seccomp interface is visible"),
        }
    }
}

/// Whether a launcher could install a `seccomp(2)` filter on a workload.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SeccompFinding {
    /// The kernel is built with filter mode and publishes at least one action
    /// that refuses a syscall.
    ///
    /// This is availability, not installation. An unprivileged process may
    /// install a filter only after setting `PR_SET_NO_NEW_PRIVS`, which the
    /// launcher does on the child between `fork` and `exec`. This probe sets it
    /// on nothing.
    FilterAvailable,
    /// Filter mode cannot be used, with the reason.
    Unavailable(SeccompUnavailable),
}

impl SeccompFinding {
    /// Read the kernel's published seccomp action list.
    ///
    /// This determines filter support without `unsafe`, without calling
    /// `seccomp(2)`, and without installing a filter: the action list exists
    /// exactly when the kernel is built with `CONFIG_SECCOMP_FILTER`.
    #[must_use]
    pub fn probe() -> Self {
        let Some(actions) = read_bounded(SECCOMP_ACTIONS_PATH, MAX_ACTIONS_BYTES) else {
            // The status field implies CONFIG_SECCOMP, so the kernel has seccomp
            // in some form even though the filter interface is absent.
            return match read_bounded(PROC_STATUS_PATH, MAX_STATUS_BYTES) {
                Some(status) if status.lines().any(|line| line.starts_with("Seccomp:")) => {
                    Self::Unavailable(SeccompUnavailable::StrictModeOnly)
                }
                _ => Self::Unavailable(SeccompUnavailable::NoInterface),
            };
        };
        if actions
            .split_ascii_whitespace()
            .any(|action| DENYING_SECCOMP_ACTIONS.contains(&action))
        {
            Self::FilterAvailable
        } else {
            Self::Unavailable(SeccompUnavailable::NoDenyingAction)
        }
    }

    /// The reason filter mode is unusable, or `None` when it is usable.
    #[must_use]
    pub const fn denial(self) -> Option<SeccompUnavailable> {
        match self {
            Self::FilterAvailable => None,
            Self::Unavailable(reason) => Some(reason),
        }
    }
}

/// A kernel mechanism a launcher can install on a workload.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Mechanism {
    /// A delegated cgroup v2 domain holding the workload and every descendant.
    CgroupDomain,
    /// A Landlock ruleset applied to the workload before `exec`.
    Landlock,
    /// An unprivileged user namespace, and the mount and network namespaces it
    /// makes creatable.
    UserNamespace,
    /// A `seccomp(2)` filter installed on the workload before `exec`.
    SeccompFilter,
}

impl Mechanism {
    /// Stable spelling for logs and protocol adapters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CgroupDomain => "cgroup_domain",
            Self::Landlock => "landlock",
            Self::UserNamespace => "user_namespace",
            Self::SeccompFilter => "seccomp_filter",
        }
    }
}

impl fmt::Display for Mechanism {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An exact property a caller can require of a launched workload.
///
/// These are deliberately finer-grained than the mechanisms that provide them.
/// [`Self::TcpDenial`] and [`Self::CompleteNetworkDenial`] are split because
/// Landlock can satisfy the first and can never satisfy the second; collapsing
/// them into one "network denial" property would let a Landlock-only host
/// appear to offer network isolation it does not have.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BoundaryProperty {
    /// The workload and every descendant stay in a kernel-owned domain that can
    /// be terminated atomically, whatever the workload does with `fork`,
    /// `setsid`, or `setpgid`.
    DescendantContainment,
    /// The workload's filesystem view is confined to an explicit path set,
    /// enforced by the kernel and inherited across `exec`.
    FilesystemRestriction,
    /// The workload cannot bind a TCP port or open a TCP connection.
    TcpDenial,
    /// The workload cannot originate network traffic of any kind, including
    /// UDP, raw sockets, and ICMP. Only a network namespace provides this; no
    /// Landlock ABI does.
    CompleteNetworkDenial,
    /// The workload runs under a uid distinct from the supervisor's, so it
    /// cannot signal supervisor processes or write supervisor-owned files.
    UidSeparation,
    /// The workload's syscall surface is narrowed to an explicit allowlist.
    SyscallRestriction,
}

impl BoundaryProperty {
    /// Every property this module can reason about.
    pub const ALL: [Self; 6] = [
        Self::DescendantContainment,
        Self::FilesystemRestriction,
        Self::TcpDenial,
        Self::CompleteNetworkDenial,
        Self::UidSeparation,
        Self::SyscallRestriction,
    ];

    /// Stable spelling for logs and protocol adapters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DescendantContainment => "descendant_containment",
            Self::FilesystemRestriction => "filesystem_restriction",
            Self::TcpDenial => "tcp_denial",
            Self::CompleteNetworkDenial => "complete_network_denial",
            Self::UidSeparation => "uid_separation",
            Self::SyscallRestriction => "syscall_restriction",
        }
    }
}

impl fmt::Display for BoundaryProperty {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A named combination of mechanisms a launcher would install.
///
/// The modes form a ladder by how much the launcher does to the workload before
/// `exec`, each doing strictly everything the one below it does:
///
/// | mode | launcher work before `exec` |
/// |---|---|
/// | [`Self::ContainmentOnly`] | place the child in a run cgroup, then `exec` |
/// | [`Self::KernelRestricted`] | additionally set `PR_SET_NO_NEW_PRIVS`, apply a Landlock ruleset, install a seccomp filter |
/// | [`Self::NamespacedIsolation`] | additionally unshare user, mount, and network namespaces |
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EnforcementMode {
    /// Namespaced isolation: the native mode. Everything below, plus a private
    /// uid, a private mount view, and a private empty network stack.
    NamespacedIsolation,
    /// In-kernel restriction without namespaces: containment plus Landlock plus
    /// a syscall filter, all applied to a workload that keeps the supervisor's
    /// uid and the host network stack.
    KernelRestricted,
    /// Containment alone: the workload is bounded and killable, and nothing
    /// else about it is restricted.
    ContainmentOnly,
}

impl EnforcementMode {
    /// Every mode, strongest first. Selection walks this order.
    pub const LADDER: [Self; 3] = [
        Self::NamespacedIsolation,
        Self::KernelRestricted,
        Self::ContainmentOnly,
    ];

    /// Stable spelling for logs and protocol adapters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NamespacedIsolation => "namespaced_isolation",
            Self::KernelRestricted => "kernel_restricted",
            Self::ContainmentOnly => "containment_only",
        }
    }

    /// The mechanism this mode would use to enforce `property`, if any.
    ///
    /// This table is the whole model. A property is enforced only when the mode
    /// names a mechanism for it *and* that mechanism is usable on the host, so
    /// a mode can never be credited with a guarantee its mechanisms do not
    /// deliver.
    #[must_use]
    pub const fn mechanism_for(self, property: BoundaryProperty) -> Option<Mechanism> {
        match (self, property) {
            // Every mode places the workload in a run cgroup.
            (_, BoundaryProperty::DescendantContainment) => Some(Mechanism::CgroupDomain),
            // The containment-only mode installs nothing on the workload itself.
            (Self::ContainmentOnly, _) => None,
            (
                Self::KernelRestricted | Self::NamespacedIsolation,
                BoundaryProperty::SyscallRestriction,
            ) => Some(Mechanism::SeccompFilter),
            (
                Self::KernelRestricted,
                BoundaryProperty::FilesystemRestriction | BoundaryProperty::TcpDenial,
            ) => Some(Mechanism::Landlock),
            // Landlock's network rights cover TCP only, and a Landlock ruleset
            // never changes a uid, so this mode cannot reach either property.
            (
                Self::KernelRestricted,
                BoundaryProperty::CompleteNetworkDenial | BoundaryProperty::UidSeparation,
            ) => None,
            (Self::NamespacedIsolation, _) => Some(Mechanism::UserNamespace),
        }
    }

    /// Whether this mode is a real, distinct mode on `host`.
    ///
    /// A mode is available only when its own mechanisms work. Naming a mode
    /// whose distinguishing mechanism is unusable would report enforcement the
    /// launcher could not install: on a host without Landlock or seccomp,
    /// `KernelRestricted` would be byte-identical to `ContainmentOnly`.
    #[must_use]
    pub fn is_available_on(self, host: &HostCapabilities) -> bool {
        if !host.containment.is_delegated() {
            return false;
        }
        match self {
            Self::ContainmentOnly => true,
            Self::KernelRestricted => {
                host.landlock.abi().is_some() || host.seccomp == SeccompFinding::FilterAvailable
            }
            Self::NamespacedIsolation => host.user_namespace.denial().is_none(),
        }
    }

    /// Properties this mode actually enforces on `host`, ascending.
    ///
    /// Empty when the mode is unavailable: an uninstallable mode enforces
    /// nothing, and saying otherwise is exactly the silent overclaim this
    /// module exists to prevent.
    #[must_use]
    pub fn provides_on(self, host: &HostCapabilities) -> Vec<BoundaryProperty> {
        if !self.is_available_on(host) {
            return Vec::new();
        }
        BoundaryProperty::ALL
            .into_iter()
            .filter(|property| {
                self.mechanism_for(*property)
                    .is_some_and(|mechanism| host.blocker(mechanism, *property).is_none())
            })
            .collect()
    }
}

impl fmt::Display for EnforcementMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Exactly why a mechanism cannot deliver a property on this host.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UnsatisfiedCause {
    /// This process has no delegated cgroup v2 domain.
    NoContainmentDomain(ContainmentUnavailable),
    /// The running kernel accepts no Landlock access right this build knows.
    LandlockUnsupported,
    /// Landlock works, but its measured ABI floor predates the access right
    /// this property needs.
    LandlockAbiBelow {
        /// Measured floor on this host.
        observed: LandlockAbi,
        /// Lowest ABI level that defines the required access right.
        needed: u8,
    },
    /// A kernel policy forbids unprivileged user-namespace creation.
    UserNamespaceDenied(UserNamespaceDenial),
    /// `seccomp(2)` filter mode cannot narrow a syscall surface here.
    SeccompFilterUnavailable(SeccompUnavailable),
}

impl fmt::Display for UnsatisfiedCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoContainmentDomain(reason) => write!(formatter, "{reason}"),
            Self::LandlockUnsupported => {
                formatter.write_str("the running kernel supports no known Landlock access right")
            }
            Self::LandlockAbiBelow { observed, needed } => write!(
                formatter,
                "Landlock {observed} is below the ABI {needed} that defines this access right"
            ),
            Self::UserNamespaceDenied(denial) => write!(formatter, "{denial}"),
            Self::SeccompFilterUnavailable(reason) => write!(formatter, "{reason}"),
        }
    }
}

/// One mechanism that could have delivered a property, and why it cannot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockedMechanism {
    mechanism: Mechanism,
    cause: UnsatisfiedCause,
}

impl BlockedMechanism {
    /// The mechanism that is unusable for this property.
    #[must_use]
    pub const fn mechanism(&self) -> Mechanism {
        self.mechanism
    }

    /// Exactly why it is unusable.
    #[must_use]
    pub const fn cause(&self) -> UnsatisfiedCause {
        self.cause
    }
}

impl fmt::Display for BlockedMechanism {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.mechanism, self.cause)
    }
}

/// A property no mode on this host can enforce, with every blocked mechanism.
///
/// The same type carries a refusal's unsatisfiable requirements and a
/// selection's dropped guarantees, because they are the same fact: a property
/// this host cannot deliver, and the exact reason for each way it might have.
/// [`Self::blocked_mechanisms`] is never empty.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnenforceableProperty {
    property: BoundaryProperty,
    blocked: Vec<BlockedMechanism>,
}

impl UnenforceableProperty {
    /// The property that cannot be enforced.
    #[must_use]
    pub const fn property(&self) -> BoundaryProperty {
        self.property
    }

    /// Every mechanism that could have provided it, and why each is blocked.
    #[must_use]
    pub fn blocked_mechanisms(&self) -> &[BlockedMechanism] {
        &self.blocked
    }
}

impl fmt::Display for UnenforceableProperty {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} is unenforceable (", self.property)?;
        for (index, blocked) in self.blocked.iter().enumerate() {
            if index > 0 {
                formatter.write_str("; ")?;
            }
            write!(formatter, "{blocked}")?;
        }
        formatter.write_str(")")
    }
}

/// A mode that is genuinely installable on this host, and what it costs.
///
/// [`Self::dropped`] lists every property the mode does not enforce, requested
/// or not, so a caller that required little still learns the full shortfall.
/// [`Self::is_complete`] is the only way to claim nothing was given up.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModeSelection {
    mode: EnforcementMode,
    required: Vec<BoundaryProperty>,
    enforced: Vec<BoundaryProperty>,
    dropped: Vec<UnenforceableProperty>,
}

impl ModeSelection {
    /// The selected mode.
    #[must_use]
    pub const fn mode(&self) -> EnforcementMode {
        self.mode
    }

    /// The caller's requirements, deduplicated and ordered. Every one of these
    /// appears in [`Self::enforced`]; a selection is never returned otherwise.
    #[must_use]
    pub fn required(&self) -> &[BoundaryProperty] {
        &self.required
    }

    /// Every property the selected mode enforces on this host.
    #[must_use]
    pub fn enforced(&self) -> &[BoundaryProperty] {
        &self.enforced
    }

    /// Every property the selected mode does not enforce, with the reason.
    ///
    /// This is the degradation record. It is empty only when the mode delivers
    /// the complete property set.
    #[must_use]
    pub fn dropped(&self) -> &[UnenforceableProperty] {
        &self.dropped
    }

    /// Whether this mode gives up nothing at all.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.dropped.is_empty()
    }
}

impl fmt::Display for ModeSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "mode {} enforces", self.mode)?;
        for property in &self.enforced {
            write!(formatter, " {property}")?;
        }
        if self.dropped.is_empty() {
            return formatter.write_str("; nothing dropped");
        }
        formatter.write_str("; dropped: ")?;
        for (index, dropped) in self.dropped.iter().enumerate() {
            if index > 0 {
                formatter.write_str("; ")?;
            }
            write!(formatter, "{dropped}")?;
        }
        Ok(())
    }
}

/// A typed refusal to name a mode.
///
/// There is no "best effort" outcome. A caller either gets a mode that enforces
/// everything it required, or it gets this.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModeRefusal {
    /// No mode exists at all, because no mode can run without a delegated
    /// containment domain: a workload the supervisor cannot bound and kill
    /// could leave any other boundary behind by forking.
    NoEnforceableMode(ContainmentUnavailable),
    /// Modes exist, but at least one required property cannot be enforced by
    /// any of them. Never empty.
    Unenforceable(Vec<UnenforceableProperty>),
}

impl ModeRefusal {
    /// The required properties no available mode can enforce.
    ///
    /// Empty for [`Self::NoEnforceableMode`], where the missing precondition is
    /// the containment domain itself rather than any single property.
    #[must_use]
    pub fn unenforceable(&self) -> &[UnenforceableProperty] {
        match self {
            Self::NoEnforceableMode(_) => &[],
            Self::Unenforceable(properties) => properties,
        }
    }
}

impl fmt::Display for ModeRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEnforceableMode(reason) => write!(
                formatter,
                "no enforcement mode is installable on this host: {reason}"
            ),
            Self::Unenforceable(properties) => {
                formatter.write_str("required properties cannot be enforced: ")?;
                for (index, property) in properties.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str("; ")?;
                    }
                    write!(formatter, "{property}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ModeRefusal {}

/// What enforcement this host can actually provide.
///
/// Produced by [`Self::probe`], which reads fixed kernel paths and asks the
/// Landlock version query, and changes nothing. [`Self::from_findings`] exists
/// for callers that already established the findings some other way.
#[derive(Debug)]
pub struct HostCapabilities {
    containment: ContainmentFinding,
    landlock: LandlockFinding,
    user_namespace: UserNamespaceFinding,
    seccomp: SeccompFinding,
}

impl HostCapabilities {
    /// Observe this host. Read-only and side-effect free.
    ///
    /// Nothing here creates a cgroup, allocates a Landlock ruleset descriptor,
    /// calls `restrict_self`, sets `PR_SET_NO_NEW_PRIVS`, installs a seccomp
    /// filter, or calls `unshare`. Probing twice returns the same findings, and
    /// a process that probes is no more restricted afterwards than before.
    #[must_use]
    pub fn probe() -> Self {
        Self {
            containment: ContainmentFinding::probe(),
            landlock: LandlockFinding::probe(),
            user_namespace: UserNamespaceFinding::probe(),
            seccomp: SeccompFinding::probe(),
        }
    }

    /// Assemble a record from findings established elsewhere.
    ///
    /// This mints no capability. Mode selection is a pure function of the
    /// findings, and every finding is an observation rather than a handle: a
    /// caller that fabricates [`ContainmentFinding::Delegated`] still cannot
    /// obtain a [`ContainmentDomain`], which re-checks the kernel itself. The
    /// constructor exists so selection logic can be exercised against hosts
    /// this machine is not.
    #[must_use]
    pub const fn from_findings(
        containment: ContainmentFinding,
        landlock: LandlockFinding,
        user_namespace: UserNamespaceFinding,
        seccomp: SeccompFinding,
    ) -> Self {
        Self {
            containment,
            landlock,
            user_namespace,
            seccomp,
        }
    }

    /// Containment finding, carrying the verbatim typed reason when unusable.
    #[must_use]
    pub const fn containment(&self) -> &ContainmentFinding {
        &self.containment
    }

    /// Landlock finding.
    #[must_use]
    pub const fn landlock(&self) -> LandlockFinding {
        self.landlock
    }

    /// User-namespace finding.
    #[must_use]
    pub const fn user_namespace(&self) -> UserNamespaceFinding {
        self.user_namespace
    }

    /// Seccomp finding.
    #[must_use]
    pub const fn seccomp(&self) -> SeccompFinding {
        self.seccomp
    }

    /// Modes that are genuinely installable here, strongest first.
    #[must_use]
    pub fn available_modes(&self) -> Vec<EnforcementMode> {
        EnforcementMode::LADDER
            .into_iter()
            .filter(|mode| mode.is_available_on(self))
            .collect()
    }

    /// Choose the strongest installable mode that enforces every required
    /// property, or refuse and say exactly what is missing.
    ///
    /// Selection walks [`EnforcementMode::LADDER`] from strongest to weakest and
    /// takes the first available mode whose enforced set covers `required`. An
    /// empty `required` therefore yields the strongest mode this host offers,
    /// with the full shortfall recorded in [`ModeSelection::dropped`].
    pub fn select_mode(&self, required: &[BoundaryProperty]) -> Result<ModeSelection, ModeRefusal> {
        let mut wanted = required.to_vec();
        wanted.sort_unstable();
        wanted.dedup();

        let available = self.available_modes();
        if available.is_empty() {
            // Every mode needs a run cgroup, so the containment reason is the
            // whole story and no per-property breakdown would add to it.
            return Err(ModeRefusal::NoEnforceableMode(
                self.containment
                    .denial()
                    .unwrap_or(ContainmentUnavailable::Unreadable),
            ));
        }

        for mode in available.iter().copied() {
            let enforced = mode.provides_on(self);
            if wanted.iter().all(|property| enforced.contains(property)) {
                let dropped = BoundaryProperty::ALL
                    .into_iter()
                    .filter(|property| !enforced.contains(property))
                    .map(|property| self.unenforceable(property))
                    .collect();
                return Ok(ModeSelection {
                    mode,
                    required: wanted,
                    enforced,
                    dropped,
                });
            }
        }

        // A required property is unsatisfiable exactly when no available mode
        // enforces it. Computing that as a union over the available modes keeps
        // the refusal correct even if the ladder ever stops being monotone.
        let reachable = available
            .iter()
            .flat_map(|mode| mode.provides_on(self))
            .collect::<Vec<_>>();
        let mut unenforceable = wanted
            .iter()
            .copied()
            .filter(|property| !reachable.contains(property))
            .map(|property| self.unenforceable(property))
            .collect::<Vec<_>>();
        if unenforceable.is_empty() {
            // Unreachable while the ladder is monotone, which it is by
            // construction. Kept because an empty refusal would name nothing,
            // and a refusal that names nothing is the silent failure this whole
            // module exists to prevent. The strongest available mode failed to
            // cover `wanted`, so its own shortfall is non-empty.
            let strongest = available[0].provides_on(self);
            unenforceable = wanted
                .iter()
                .copied()
                .filter(|property| !strongest.contains(property))
                .map(|property| self.unenforceable(property))
                .collect();
        }
        Err(ModeRefusal::Unenforceable(unenforceable))
    }

    /// Record why `property` cannot be enforced, across every mechanism any
    /// mode would have used for it.
    fn unenforceable(&self, property: BoundaryProperty) -> UnenforceableProperty {
        let mut blocked = Vec::new();
        for mode in EnforcementMode::LADDER {
            let Some(mechanism) = mode.mechanism_for(property) else {
                continue;
            };
            if blocked
                .iter()
                .any(|entry: &BlockedMechanism| entry.mechanism == mechanism)
            {
                continue;
            }
            if let Some(cause) = self.blocker(mechanism, property) {
                blocked.push(BlockedMechanism { mechanism, cause });
            }
        }
        debug_assert!(
            !blocked.is_empty(),
            "{property} was reported unenforceable with no blocked mechanism"
        );
        UnenforceableProperty { property, blocked }
    }

    /// Why `mechanism` cannot deliver `property` here, or `None` if it can.
    ///
    /// The property matters: Landlock delivers a filesystem restriction from
    /// ABI 1 but TCP denial only from ABI 4, so the same mechanism is usable for
    /// one property and blocked for another on the same host.
    fn blocker(
        &self,
        mechanism: Mechanism,
        property: BoundaryProperty,
    ) -> Option<UnsatisfiedCause> {
        match mechanism {
            Mechanism::CgroupDomain => self
                .containment
                .denial()
                .map(UnsatisfiedCause::NoContainmentDomain),
            Mechanism::Landlock => {
                let Some(abi) = self.landlock.abi() else {
                    return Some(UnsatisfiedCause::LandlockUnsupported);
                };
                let needed = match property {
                    BoundaryProperty::TcpDenial => LANDLOCK_ABI_TCP,
                    _ => LANDLOCK_ABI_FILESYSTEM,
                };
                (abi.level() < needed).then_some(UnsatisfiedCause::LandlockAbiBelow {
                    observed: abi,
                    needed,
                })
            }
            Mechanism::UserNamespace => self
                .user_namespace
                .denial()
                .map(UnsatisfiedCause::UserNamespaceDenied),
            Mechanism::SeccompFilter => self
                .seccomp
                .denial()
                .map(UnsatisfiedCause::SeccompFilterUnavailable),
        }
    }
}

/// Read a fixed kernel path under a byte bound, refusing symlinks.
///
/// Returns `None` for every failure. A capability probe that propagated I/O
/// errors would force callers to decide what an unreadable interface means; an
/// unreadable interface is an unusable interface, and that is the only safe
/// reading.
fn read_bounded(path: &str, limit: usize) -> Option<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(Path::new(path))
        .ok()?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > limit {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// Read a numeric sysctl. `None` means absent, unreadable, or not a number,
/// which callers must not treat as any particular value.
fn read_sysctl_u64(path: &str) -> Option<u64> {
    read_bounded(path, MAX_SYSCTL_BYTES)?.trim().parse().ok()
}
