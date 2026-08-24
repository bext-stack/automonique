// SPDX-License-Identifier: Elastic-2.0

//! Deny-by-default filesystem allowlist enforced by the Landlock LSM.
//!
//! A [`FilesystemPolicy`] is an explicit list of path grants, each carrying a
//! distinct [`PathIntent`]. Applying it installs a kernel Landlock domain on the
//! calling thread: every filesystem path resolution the thread and its children
//! perform afterwards is checked against the grants, and everything not granted
//! is denied. Nothing is granted implicitly, so an empty policy denies the whole
//! filesystem.
//!
//! The domain is irreversible and inherited across `execve`, which is exactly
//! why this is applied in a freshly forked child immediately before `execv` of
//! an untrusted workload: the workload's very first instruction already runs
//! inside the allowlist, and it cannot drop the domain afterwards.
//!
//! # What this module does **not** establish
//!
//! - It is not [containment](crate::containment). Landlock bounds what a
//!   workload may *reach*, not how many processes it may spawn, how much memory
//!   it may hold, or whether it can be terminated descendant-completely.
//! - It is not network denial. This policy handles filesystem access rights
//!   only. TCP bind and connect, UDP, raw sockets, and abstract `AF_UNIX`
//!   sockets are untouched by it.
//! - It is not descriptor closure. Landlock is checked during path resolution,
//!   so a descriptor opened *before* enforcement — or inherited across `execve`
//!   — keeps working regardless of the allowlist. Closing inherited descriptors
//!   is a separate obligation.
//! - It does not restrict the syscall families the Landlock filesystem hooks do
//!   not cover. Per the kernel's own documentation these include `chmod`,
//!   `chown`, `setxattr`, `utime`, `stat`, `access`, `chdir`, `flock`, `fcntl`,
//!   and `ioctl` (see below). A read-only grant therefore still permits changing
//!   the mode, owner, or timestamps of files inside it.
//! - It does not restrict access rights added after Landlock ABI
//!   [`POLICY_LANDLOCK_ABI`]. `AccessFs::IoctlDev` (ABI 5) and
//!   `AccessFs::ResolveUnix` (ABI 9) are deliberately *not* handled, so device
//!   `ioctl` and pathname `AF_UNIX` connection are unrestricted even on a kernel
//!   that could restrict them. Handling exactly one vetted ABI keeps enforcement
//!   identical across kernels instead of silently varying with the host; raising
//!   it is a deliberate change to this module, not a runtime decision.
//! - A grant names a *hierarchy*, not a fixed set of inodes. Anything later
//!   created or mounted beneath a granted directory is inside the grant.
//! - It restricts only the calling thread (and its future children).
//!   [`FilesystemPolicy::enforce_on_current_thread`] refuses to run in a
//!   multi-threaded process rather than leave sibling threads unrestricted.
//! - The workload's own program file is subject to the policy. A policy that
//!   does not grant [`PathIntent::ReadExecute`] over the program — and over the
//!   dynamic loader and shared libraries it needs — makes the following `execv`
//!   fail. That is a correct denial, not a bug in this module.
//!
//! # Fail-closed
//!
//! Every guarantee this module cannot provide is a typed error, never a weaker
//! result. If Landlock is absent, if the kernel's ABI is older than
//! [`POLICY_LANDLOCK_ABI`], if the kernel reports anything other than a fully
//! enforced ruleset, or if `no_new_privs` did not take effect, applying the
//! policy returns [`FilesystemPolicyError`]. A partially enforced ruleset is
//! never reported as isolation.
//!
//! Note the asymmetry a caller must respect: `landlock_restrict_self` is
//! irreversible. If applying the policy fails *after* that syscall ran, the
//! calling thread may already carry a domain that cannot be removed. The
//! refusal is what must stop the workload — the caller must exit without
//! executing anything, not attempt to continue unrestricted.

use landlock::{
    ABI, Access as _, AccessFs, BitFlags, CompatLevel, Compatible as _, LandlockStatus,
    PathBeneath, Ruleset, RulesetAttr as _, RulesetCreatedAttr as _, RulesetStatus,
};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

/// Landlock ABI whose filesystem access rights this policy handles, and
/// therefore the minimum ABI the running kernel must support.
///
/// ABI 3 (Linux 6.2) is the floor because it is the first that can handle
/// `AccessFs::Truncate`. Below it, `truncate(2)` is outside every ruleset, so a
/// read-only grant could not actually stop a workload from emptying files
/// inside it — the grant would be a claim this module cannot keep.
pub const POLICY_LANDLOCK_ABI: u8 = 3;

/// Largest number of path grants one policy may carry.
///
/// A real allowlist is a short, auditable list. An unbounded one is a sign the
/// caller is enumerating the filesystem rather than restricting it, and every
/// grant costs an open descriptor while the ruleset is built.
pub const MAX_PATH_GRANTS: usize = 64;

/// Longest accepted grant path, matching the kernel's `PATH_MAX`.
pub const MAX_GRANT_PATH_BYTES: usize = 4096;

/// Upper bound on the `/proc/self/status` bytes read to count threads.
const MAX_STATUS_BYTES: usize = 64 * 1024;

/// The ABI this module compiles its access-right sets against.
const POLICY_ABI: ABI = ABI::V3;

/// What a grant permits beneath one path.
///
/// The three intents are deliberately distinct and non-overlapping in the
/// rights they add: writing never implies executing, and executing never
/// implies writing. A workspace a workload may fill with data is therefore not
/// also a place it may drop and run a new binary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PathIntent {
    /// Read file contents and list directory entries. Nothing else.
    Read,
    /// Everything [`Self::Read`] grants, plus creating, writing, truncating,
    /// deleting, and renaming beneath the grant.
    ///
    /// Renaming a file between two directories requires `AccessFs::Refer` on
    /// both sides, so without it an ordinary `mv` between two subdirectories of
    /// the same writable tree would fail; it is included for that reason.
    /// Creating device nodes (`AccessFs::MakeChar`, `AccessFs::MakeBlock`) is
    /// deliberately excluded: a workload that needs a device node is asking for
    /// something an allowlist should not silently include.
    ReadWrite,
    /// Everything [`Self::Read`] grants, plus executing files beneath the grant.
    ///
    /// Execution implies reading because the dynamic loader must read the
    /// program's interpreter and shared libraries; an execute-only grant would
    /// deny every dynamically linked program and mislead the caller.
    ReadExecute,
}

impl PathIntent {
    /// Stable short spelling, used by diagnostics and by the probe helper.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::ReadWrite => "read-write",
            Self::ReadExecute => "read-execute",
        }
    }

    /// Exact Landlock access rights this intent requests on a directory.
    fn rights(self) -> BitFlags<AccessFs> {
        let read = AccessFs::ReadFile | AccessFs::ReadDir;
        match self {
            Self::Read => read,
            Self::ReadWrite => {
                read | AccessFs::WriteFile
                    | AccessFs::Truncate
                    | AccessFs::MakeReg
                    | AccessFs::MakeDir
                    | AccessFs::MakeSym
                    | AccessFs::MakeFifo
                    | AccessFs::MakeSock
                    | AccessFs::RemoveFile
                    | AccessFs::RemoveDir
                    | AccessFs::Refer
            }
            Self::ReadExecute => read | AccessFs::Execute,
        }
    }
}

/// One entry of the allowlist: a path and what may be done beneath it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathGrant {
    path: PathBuf,
    intent: PathIntent,
}

impl PathGrant {
    /// Exact path the grant names, as accepted by the policy.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// What the grant permits beneath [`Self::path`].
    #[must_use]
    pub const fn intent(&self) -> PathIntent {
        self.intent
    }
}

/// Why a filesystem policy is refused, or cannot be enforced.
///
/// Every variant is a refusal. There is no variant meaning "restricted but
/// unverified": an allowlist this module cannot confirm the kernel enforced in
/// full is not isolation.
#[derive(Debug)]
pub enum FilesystemPolicyError {
    Io(std::io::Error),
    /// The policy carries more than [`MAX_PATH_GRANTS`] grants.
    TooManyGrants,
    /// A grant path is empty, oversized, relative, non-canonical, or the
    /// filesystem root. Relative paths would resolve against whatever directory
    /// the child happens to be in; `.`, `..`, repeated separators, and a
    /// trailing separator would make the written policy differ from the
    /// hierarchy actually granted; and granting `/` is not an allowlist.
    GrantPathRejected(PathBuf),
    /// Two grants name the same path, so the effective intent is ambiguous.
    DuplicateGrantPath(PathBuf),
    /// A grant path does not exist, so it cannot be turned into a rule. A
    /// silently dropped grant would produce a policy stricter than the one the
    /// caller wrote and audited.
    GrantPathMissing(PathBuf),
    /// A grant path's final component is a symbolic link. The hierarchy such a
    /// grant would open is its target, not the path written in the policy, so
    /// the caller must name the target itself.
    GrantPathIsSymlink(PathBuf),
    /// The caller has more than one thread. A Landlock domain applies to the
    /// calling thread only, so enforcing here would leave the siblings — and
    /// anything they later spawn — unrestricted.
    CallerNotSingleThreaded,
    /// The caller's own thread count could not be read from `/proc`, so
    /// single-threadedness could not be confirmed.
    ThreadCountUnknown,
    /// The running kernel provides no Landlock at all: it is either not built
    /// in or not enabled at boot.
    LandlockUnavailable,
    /// The kernel's Landlock ABI is older than this policy requires. `observed`
    /// is present only when the kernel reported it, which it does after
    /// enforcement; the `landlock` crate exposes no ABI probe beforehand, so a
    /// pre-enforcement refusal names the requirement without inventing a
    /// reading it does not have.
    AbiTooOld {
        observed: Option<u8>,
        required: u8,
    },
    /// The kernel accepted only part of the ruleset, or none of it. The
    /// resulting restriction is not the policy that was asked for.
    NotFullyEnforced,
    /// `no_new_privs` did not take effect, so the domain would not survive an
    /// `execve` of a set-user-ID program.
    NoNewPrivsNotSet,
    /// The kernel refused to build the ruleset. Carries the `landlock` crate's
    /// diagnostic; nothing was enforced.
    RulesetRefused(String),
    /// `landlock_restrict_self` failed, so no domain was installed.
    RestrictSelfFailed(String),
}

impl fmt::Display for FilesystemPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "filesystem policy I/O failed: {error}"),
            Self::TooManyGrants => write!(
                formatter,
                "a filesystem policy carries at most {MAX_PATH_GRANTS} path grants"
            ),
            Self::GrantPathRejected(path) => write!(
                formatter,
                "grant path is not a bounded absolute path below the root: {}",
                path.display()
            ),
            Self::DuplicateGrantPath(path) => write!(
                formatter,
                "two grants name the same path: {}",
                path.display()
            ),
            Self::GrantPathMissing(path) => {
                write!(formatter, "grant path does not exist: {}", path.display())
            }
            Self::GrantPathIsSymlink(path) => write!(
                formatter,
                "grant path is a symbolic link, so name its target instead: {}",
                path.display()
            ),
            Self::CallerNotSingleThreaded => formatter.write_str(
                "the calling process has more than one thread, so sibling threads would stay unrestricted",
            ),
            Self::ThreadCountUnknown => {
                formatter.write_str("the caller's thread count could not be read from /proc")
            }
            Self::LandlockUnavailable => {
                formatter.write_str("the running kernel provides no Landlock support")
            }
            Self::AbiTooOld { observed, required } => match observed {
                Some(observed) => write!(
                    formatter,
                    "landlock ABI {observed} is older than the required {required}"
                ),
                None => write!(
                    formatter,
                    "landlock ABI is older than the required {required}"
                ),
            },
            Self::NotFullyEnforced => {
                formatter.write_str("the kernel did not fully enforce the requested ruleset")
            }
            Self::NoNewPrivsNotSet => {
                formatter.write_str("no_new_privs did not take effect for the calling thread")
            }
            Self::RulesetRefused(message) => {
                write!(formatter, "landlock ruleset refused: {message}")
            }
            Self::RestrictSelfFailed(message) => {
                write!(formatter, "landlock_restrict_self failed: {message}")
            }
        }
    }
}

impl std::error::Error for FilesystemPolicyError {}

impl From<std::io::Error> for FilesystemPolicyError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// What the kernel reports about its own Landlock support.
///
/// A local mirror of the `landlock` crate's status, so the decision table in
/// [`assess_enforcement`] is part of this crate's API and can be exercised
/// without a kernel that lacks Landlock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelSupport {
    /// Landlock is not built into the kernel, or is not enabled at boot.
    Unavailable,
    /// Landlock is available at `abi`.
    Available {
        /// ABI both the kernel and the `landlock` crate understand. This is the
        /// version actually used to enforce.
        abi: u8,
        /// Set when the kernel's own ABI is newer than any the crate knows.
        /// Access rights introduced by that newer ABI are not handled here.
        beyond_crate: Option<i32>,
    },
}

/// How much of a requested ruleset the kernel actually enforced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RulesetEnforcement {
    /// Every requested restriction is in force.
    Full,
    /// Only some requested restrictions are in force.
    Partial,
    /// No restriction is in force.
    None,
}

/// Proof that an allowlist is in force on the calling thread.
///
/// Only produced when the kernel reported full enforcement, so holding one of
/// these means the policy — the whole policy — is installed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemIsolation {
    kernel_abi: u8,
    kernel_abi_beyond_crate: Option<i32>,
}

impl FilesystemIsolation {
    /// Landlock ABI the kernel actually enforced with.
    ///
    /// This is the kernel's reading, not the module's request. It is at least
    /// [`POLICY_LANDLOCK_ABI`] and may be higher.
    #[must_use]
    pub const fn kernel_abi(&self) -> u8 {
        self.kernel_abi
    }

    /// The kernel's own Landlock ABI when it is newer than any the `landlock`
    /// crate knows about.
    ///
    /// Present means the kernel offers access rights this policy did not ask it
    /// to handle, so those actions are unrestricted. It is reported rather than
    /// refused because refusing every future kernel would be worse than saying
    /// plainly what is not covered.
    #[must_use]
    pub const fn kernel_abi_beyond_crate(&self) -> Option<i32> {
        self.kernel_abi_beyond_crate
    }

    /// Landlock ABI whose access rights this policy handled.
    #[must_use]
    pub const fn policy_abi(&self) -> u8 {
        POLICY_LANDLOCK_ABI
    }
}

/// The exact decision table applied to what the kernel reports after
/// enforcement.
///
/// Public so the fail-closed paths are provable on any host: they cannot be
/// reached on a kernel that supports Landlock properly, and a guarantee whose
/// refusal branch is never executed is a guarantee nobody has checked.
pub fn assess_enforcement(
    support: KernelSupport,
    enforcement: RulesetEnforcement,
    no_new_privs: bool,
) -> Result<FilesystemIsolation, FilesystemPolicyError> {
    let KernelSupport::Available { abi, beyond_crate } = support else {
        return Err(FilesystemPolicyError::LandlockUnavailable);
    };
    if abi < POLICY_LANDLOCK_ABI {
        return Err(FilesystemPolicyError::AbiTooOld {
            observed: Some(abi),
            required: POLICY_LANDLOCK_ABI,
        });
    }
    if enforcement != RulesetEnforcement::Full {
        return Err(FilesystemPolicyError::NotFullyEnforced);
    }
    if !no_new_privs {
        return Err(FilesystemPolicyError::NoNewPrivsNotSet);
    }
    Ok(FilesystemIsolation {
        kernel_abi: abi,
        kernel_abi_beyond_crate: beyond_crate,
    })
}

/// A deny-by-default filesystem allowlist.
///
/// Built by adding grants, each of which is validated as it is added, so an
/// unusable policy is refused where it is written rather than in the child that
/// was about to `execv` an untrusted workload.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FilesystemPolicy {
    grants: Vec<PathGrant>,
}

impl FilesystemPolicy {
    /// A policy granting nothing, which denies the entire filesystem.
    ///
    /// This is the base every policy is built from: rights are added
    /// explicitly, never removed from an implicit whole.
    #[must_use]
    pub const fn deny_all() -> Self {
        Self { grants: Vec::new() }
    }

    /// Grant `intent` beneath `path`.
    ///
    /// The path is checked here for shape only. Its existence, and that it is
    /// not a symbolic link, are checked at enforcement time against the very
    /// descriptor the rule is built from, so the check cannot be raced.
    pub fn grant(
        mut self,
        intent: PathIntent,
        path: impl Into<PathBuf>,
    ) -> Result<Self, FilesystemPolicyError> {
        let path = path.into();
        if self.grants.len() >= MAX_PATH_GRANTS {
            return Err(FilesystemPolicyError::TooManyGrants);
        }
        validate_grant_path(&path)?;
        if self.grants.iter().any(|grant| grant.path == path) {
            return Err(FilesystemPolicyError::DuplicateGrantPath(path));
        }
        self.grants.push(PathGrant { path, intent });
        Ok(self)
    }

    /// The allowlist, in the order it was written.
    #[must_use]
    pub fn grants(&self) -> &[PathGrant] {
        &self.grants
    }

    /// Install this allowlist on the calling thread, irreversibly.
    ///
    /// Intended to run in a freshly forked child immediately before `execv`, so
    /// that the untrusted workload never executes an instruction outside the
    /// allowlist. It is *not* intended for a process that means to keep working
    /// afterwards: the domain cannot be dropped, and it applies to every child
    /// the thread later creates.
    ///
    /// On success the returned [`FilesystemIsolation`] means the kernel
    /// enforced the whole policy. On failure no grant took effect — but see the
    /// module-level note: a failure reported after `landlock_restrict_self` has
    /// already run leaves a domain in place that cannot be removed, so the
    /// caller must exit rather than continue.
    pub fn enforce_on_current_thread(&self) -> Result<FilesystemIsolation, FilesystemPolicyError> {
        self.enforce_on_current_thread_inner(None)
    }

    /// Install this allowlist while granting execute access to one already
    /// opened, immutable program descriptor.
    ///
    /// The launch helper executes a sealed memfd rather than resolving the
    /// provider path again. That detached inode must be named explicitly in
    /// the Landlock ruleset; the ordinary path grants still cover the dynamic
    /// loader, libraries, and provider-owned resources.
    pub(crate) fn enforce_on_current_thread_with_executable(
        &self,
        executable: &File,
    ) -> Result<FilesystemIsolation, FilesystemPolicyError> {
        self.enforce_on_current_thread_inner(Some(executable))
    }

    fn enforce_on_current_thread_inner(
        &self,
        executable: Option<&File>,
    ) -> Result<FilesystemIsolation, FilesystemPolicyError> {
        require_single_threaded()?;

        // HardRequirement is the whole point: with the crate's default
        // best-effort level, a kernel missing some of these rights would
        // silently produce a weaker sandbox that still looks successful.
        let mut created = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(POLICY_ABI))
            .map_err(|_| classify_unsupported_abi())?
            .create()
            .map_err(|error| FilesystemPolicyError::RulesetRefused(error.to_string()))?;

        for grant in &self.grants {
            let (descriptor, is_directory) = open_grant(&grant.path)?;
            let mut rights = grant.intent.rights();
            if !is_directory {
                // Directory-only rights on a non-directory are rejected by the
                // kernel, and would otherwise turn a legitimate file grant into
                // a refusal of the whole policy.
                rights &= AccessFs::from_file(POLICY_ABI);
            }
            created = created
                .add_rule(PathBeneath::new(descriptor, rights))
                .map_err(|error| FilesystemPolicyError::RulesetRefused(error.to_string()))?;
        }

        if let Some(executable) = executable {
            let descriptor = executable.try_clone()?;
            let metadata = descriptor.metadata()?;
            if !metadata.is_file() {
                return Err(FilesystemPolicyError::RulesetRefused(
                    "executable descriptor is not a file".to_owned(),
                ));
            }
            created = created
                .add_rule(PathBeneath::new(
                    descriptor,
                    AccessFs::ReadFile | AccessFs::Execute,
                ))
                .map_err(|error| FilesystemPolicyError::RulesetRefused(error.to_string()))?;
        }

        let status = created
            .restrict_self()
            .map_err(|error| FilesystemPolicyError::RestrictSelfFailed(error.to_string()))?;
        assess_enforcement(
            kernel_support(status.landlock),
            ruleset_enforcement(&status.ruleset),
            status.no_new_privs,
        )
    }
}

/// Translate the `landlock` crate's support reading into this crate's mirror.
fn kernel_support(status: LandlockStatus) -> KernelSupport {
    match status {
        LandlockStatus::NotEnabled | LandlockStatus::NotImplemented => KernelSupport::Unavailable,
        LandlockStatus::Available {
            effective_abi,
            kernel_abi,
        } => KernelSupport::Available {
            // `ABI` is a small non-negative enum; the cast cannot lose a value.
            abi: u8::try_from(effective_abi as u32).unwrap_or(u8::MAX),
            beyond_crate: kernel_abi,
        },
    }
}

fn ruleset_enforcement(status: &RulesetStatus) -> RulesetEnforcement {
    match status {
        RulesetStatus::FullyEnforced => RulesetEnforcement::Full,
        RulesetStatus::PartiallyEnforced => RulesetEnforcement::Partial,
        RulesetStatus::NotEnforced => RulesetEnforcement::None,
    }
}

/// Name the real cause when the kernel cannot handle this policy's access
/// rights: no Landlock at all, or a Landlock too old for the required ABI.
///
/// Only reached on the refusal path, and it performs no enforcement — building
/// a `Ruleset` probes the kernel's Landlock version and nothing more.
fn classify_unsupported_abi() -> FilesystemPolicyError {
    match Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V1))
    {
        Ok(_) => FilesystemPolicyError::AbiTooOld {
            observed: None,
            required: POLICY_LANDLOCK_ABI,
        },
        Err(_) => FilesystemPolicyError::LandlockUnavailable,
    }
}

/// Open a grant path without following a final symbolic link.
///
/// `O_PATH` gives a descriptor usable as a Landlock rule target without opening
/// the file for I/O, and `O_NOFOLLOW` means a symlinked final component yields a
/// descriptor to the link itself, which is then refused rather than silently
/// granting whatever it points at. Intermediate components are still resolved by
/// the kernel, and the rule applies to the hierarchy that resolution lands in.
fn open_grant(path: &Path) -> Result<(File, bool), FilesystemPolicyError> {
    let descriptor = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_PATH | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => FilesystemPolicyError::GrantPathMissing(path.into()),
            _ => FilesystemPolicyError::Io(error),
        })?;
    let metadata = descriptor.metadata()?;
    if metadata.file_type().is_symlink() {
        return Err(FilesystemPolicyError::GrantPathIsSymlink(path.into()));
    }
    Ok((descriptor, metadata.is_dir()))
}

/// Require a canonical absolute path naming something below the root.
///
/// This works on raw bytes rather than [`Path::components`], which silently
/// drops `.` segments: a grant is audited as written, so the written text and
/// the hierarchy the kernel resolves must be the same thing. Canonical spelling
/// also makes duplicate detection sound — `/usr` and `/usr/` would otherwise be
/// two grants of one hierarchy.
fn validate_grant_path(path: &Path) -> Result<(), FilesystemPolicyError> {
    let rejected = || FilesystemPolicyError::GrantPathRejected(path.into());
    let bytes = path.as_os_str().as_bytes();
    // A single byte can only be "" or "/", and the root is every hierarchy at
    // once, so granting it is not an allowlist.
    if bytes.len() < 2 || bytes.len() > MAX_GRANT_PATH_BYTES {
        return Err(rejected());
    }
    if bytes[0] != b'/' {
        return Err(rejected());
    }
    for segment in bytes[1..].split(|byte| *byte == b'/') {
        if segment.is_empty() || segment == b"." || segment == b".." || segment.contains(&0) {
            return Err(rejected());
        }
    }
    Ok(())
}

/// Refuse unless the calling process has exactly one thread.
///
/// A Landlock domain covers the calling thread and its future children only.
/// In the intended post-`fork`, pre-`execv` position there is exactly one
/// thread, so confirming that is confirming the whole process is covered.
pub(crate) fn require_single_threaded() -> Result<(), SingleThreadError> {
    let raw = std::fs::read("/proc/self/status").map_err(|_| SingleThreadError::Unknown)?;
    if raw.len() > MAX_STATUS_BYTES {
        return Err(SingleThreadError::Unknown);
    }
    let text = String::from_utf8(raw).map_err(|_| SingleThreadError::Unknown)?;
    let threads = text
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .map(str::trim)
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(SingleThreadError::Unknown)?;
    if threads != 1 {
        return Err(SingleThreadError::Multiple);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SingleThreadError {
    Multiple,
    Unknown,
}

impl From<SingleThreadError> for FilesystemPolicyError {
    fn from(error: SingleThreadError) -> Self {
        match error {
            SingleThreadError::Multiple => Self::CallerNotSingleThreaded,
            SingleThreadError::Unknown => Self::ThreadCountUnknown,
        }
    }
}
