// SPDX-License-Identifier: Elastic-2.0

//! Descendant-complete process containment on cgroup v2.
//!
//! Unlike [`crate::boundary`], which only observes that kernel interfaces are
//! visible, this module installs and exercises a real boundary. A run cgroup is
//! a kernel-owned containment domain: a workload cannot leave it by calling
//! `setsid`, `setpgid`, `fork`, or by daemonising, and `cgroup.kill` terminates
//! every member and descendant in one atomic kernel operation.
//!
//! What this module does **not** establish:
//!
//! - It is not filesystem isolation, network denial, or descriptor closure.
//! - It is not protection against a hostile workload running under a uid that
//!   holds write access to an ancestor cgroup. Delegation containment stops a
//!   workload from migrating outside the delegated subtree, but a same-uid
//!   workload with write access to the delegated root can migrate itself to a
//!   sibling cgroup. [`RunContainment::verify_sole_membership`] detects that
//!   after the fact; preventing it requires a separate uid or user namespace.
//!
//! Placement is race-free. The workload is never a member of any other cgroup:
//! a trusted entry helper migrates *itself* into the run cgroup, confirms its
//! own membership by reading `/proc/self/cgroup`, and only then `execv`s the
//! workload. The workload therefore first exists inside the boundary.

use nix::sys::signal::kill;
use nix::unistd::{AccessFlags, Pid, Uid, access};
use std::ffi::{CString, OsStr, OsString};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Fixed kernel mount point for the unified cgroup v2 hierarchy.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// Leaf that holds the supervising process so the domain can enable
/// controllers for its children without violating "no internal processes".
const SUPERVISOR_LEAF: &str = "supervisor";
/// Prefix for every cgroup this crate creates.
const RUN_PREFIX: &str = "run-";
/// Environment variable naming the cgroup the entry helper must join.
pub const CGROUP_DIR_ENV: &str = "AUTOMONIQUE_CGROUP_DIR";
/// Longest accepted run identifier, keeping cgroup names well inside `NAME_MAX`.
pub const MAX_RUN_ID_BYTES: usize = 64;
/// Upper bound on `cgroup.procs` bytes read in one observation.
const MAX_PROCS_BYTES: usize = 1024 * 1024;
/// Bound on how long a caller waits for a killed cgroup to drain.
const DRAIN_POLL: Duration = Duration::from_millis(2);

/// A cgroup v2 resource controller this module can enforce.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Controller {
    /// Bounds the number of processes, containing fork bombs.
    Pids,
    /// Bounds the resident memory of the whole subtree.
    Memory,
    /// Bounds CPU time consumed by the whole subtree.
    Cpu,
}

impl Controller {
    /// Stable kernel spelling used in `cgroup.subtree_control`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pids => "pids",
            Self::Memory => "memory",
            Self::Cpu => "cpu",
        }
    }

    /// Interface file that carries this controller's ceiling.
    const fn limit_file(self) -> &'static str {
        match self {
            Self::Pids => "pids.max",
            Self::Memory => "memory.max",
            Self::Cpu => "cpu.max",
        }
    }
}

/// Why containment is unavailable or refused.
///
/// Every variant is a refusal. There is no variant meaning "contained but
/// unverified": a boundary this module cannot confirm is not installed.
#[derive(Debug)]
pub enum ContainmentError {
    Io(std::io::Error),
    /// `/proc/self/cgroup` is not a single unified `0::` entry, or the fixed
    /// mount point does not expose a cgroup v2 controller view.
    NotUnifiedCgroupV2,
    /// The process's own cgroup cannot be written, so it cannot create or
    /// populate child cgroups. Delegation containment forbids placing a process
    /// across a common ancestor the caller does not own.
    DomainNotDelegated,
    /// The kernel does not expose the atomic descendant-kill interface, so
    /// termination could not be made escape-proof.
    MissingAtomicKill,
    /// A requested controller is not available to children of the domain.
    ControllerUnavailable(Controller),
    /// The run identifier is empty, oversized, or not a bounded safe name.
    RunIdRejected,
    /// A run cgroup of this name already exists; runs are never reused.
    RunCgroupExists,
    /// The helper could not confirm its own membership, so no workload ran.
    PlacementUnconfirmed,
    /// The cgroup did not drain within the caller's deadline.
    DrainTimeout,
    /// A foreign process joined the run cgroup, so sole membership is false.
    ForeignMembership,
    /// The cgroup directory could not be removed, leaving kernel residue.
    Residue,
}

impl fmt::Display for ContainmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "containment I/O failed: {error}"),
            Self::NotUnifiedCgroupV2 => {
                formatter.write_str("no unified cgroup v2 hierarchy is mounted for this process")
            }
            Self::DomainNotDelegated => formatter.write_str(
                "the process's own cgroup is not delegated, so it cannot place children",
            ),
            Self::MissingAtomicKill => {
                formatter.write_str("the kernel exposes no cgroup.kill interface")
            }
            Self::ControllerUnavailable(controller) => write!(
                formatter,
                "the {} controller is unavailable to children of this domain",
                controller.as_str()
            ),
            Self::RunIdRejected => formatter.write_str("run identifier is not a bounded safe name"),
            Self::RunCgroupExists => formatter.write_str("run cgroup already exists"),
            Self::PlacementUnconfirmed => {
                formatter.write_str("the entry helper could not confirm cgroup membership")
            }
            Self::DrainTimeout => {
                formatter.write_str("the killed cgroup did not drain within the deadline")
            }
            Self::ForeignMembership => {
                formatter.write_str("a process outside the launched tree joined the run cgroup")
            }
            Self::Residue => formatter.write_str("the run cgroup could not be removed"),
        }
    }
}

impl std::error::Error for ContainmentError {}

impl From<std::io::Error> for ContainmentError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// Ceilings applied to a run cgroup before any workload enters it.
///
/// A requested ceiling whose controller is unavailable is a refusal, never a
/// silent downgrade.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ContainmentLimits {
    pids_max: Option<u64>,
    memory_max_bytes: Option<u64>,
    cpu_max_millicores: Option<u64>,
}

/// CFS period used to translate exact millicores into `cpu.max` microseconds.
///
/// One second makes the protocol's minimum of one millicore exactly 1,000
/// microseconds, which is accepted by the kernel rather than being rounded up.
pub const CPU_MAX_PERIOD_MICROS: u64 = 1_000_000;

impl ContainmentLimits {
    /// No ceilings. Termination remains descendant-complete regardless.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            pids_max: None,
            memory_max_bytes: None,
            cpu_max_millicores: None,
        }
    }

    /// Require a maximum process count for the whole subtree.
    #[must_use]
    pub const fn with_pids_max(mut self, value: u64) -> Self {
        self.pids_max = Some(value);
        self
    }

    /// Require a maximum resident memory for the whole subtree.
    #[must_use]
    pub const fn with_memory_max_bytes(mut self, value: u64) -> Self {
        self.memory_max_bytes = Some(value);
        self
    }

    /// Require an exact CPU ceiling in thousandths of one core.
    #[must_use]
    pub const fn with_cpu_max_millicores(mut self, value: u64) -> Self {
        self.cpu_max_millicores = Some(value);
        self
    }

    /// Controllers this ceiling set requires.
    #[must_use]
    pub fn required_controllers(&self) -> Vec<Controller> {
        let mut required = Vec::new();
        if self.pids_max.is_some() {
            required.push(Controller::Pids);
        }
        if self.memory_max_bytes.is_some() {
            required.push(Controller::Memory);
        }
        if self.cpu_max_millicores.is_some() {
            required.push(Controller::Cpu);
        }
        required
    }
}

/// A delegated cgroup v2 subtree in which run cgroups may be created.
///
/// Discovery is read-only and fail-closed: it refuses unless this process can
/// actually place descendants, so a caller never learns of a domain it cannot
/// use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainmentDomain {
    root: PathBuf,
}

impl ContainmentDomain {
    /// Discover this process's own delegated cgroup.
    ///
    /// The process's own cgroup is the only correct domain. cgroup v2
    /// delegation containment permits migrating a process only within the
    /// subtree the caller owns, so a domain elsewhere in the hierarchy would
    /// pass every static check and then refuse placement at launch.
    pub fn discover() -> Result<Self, ContainmentError> {
        let root = Path::new(CGROUP_ROOT);
        if !root.join("cgroup.controllers").is_file() {
            return Err(ContainmentError::NotUnifiedCgroupV2);
        }
        let own = own_cgroup_path()?;
        let path = join_cgroup_relative(root, &own);
        Self::at(path)
    }

    /// Adopt an exact already-known domain directory.
    ///
    /// Applies the same fail-closed checks as [`Self::discover`].
    pub fn at(path: impl Into<PathBuf>) -> Result<Self, ContainmentError> {
        let root = path.into();
        let metadata = fs::symlink_metadata(&root)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ContainmentError::NotUnifiedCgroupV2);
        }
        if !root.join("cgroup.procs").is_file() {
            return Err(ContainmentError::NotUnifiedCgroupV2);
        }
        if !root.join("cgroup.kill").is_file() {
            return Err(ContainmentError::MissingAtomicKill);
        }
        // A domain that cannot be written cannot receive child cgroups, and a
        // process cannot be migrated across an ancestor the caller does not own.
        if access(&root, AccessFlags::W_OK).is_err() {
            return Err(ContainmentError::DomainNotDelegated);
        }
        Ok(Self { root })
    }

    /// Exact domain directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Controllers the domain itself may enable for its children.
    pub fn available_controllers(&self) -> Result<Vec<Controller>, ContainmentError> {
        let text = read_interface(&self.root.join("cgroup.controllers"))?;
        Ok(parse_controllers(&text))
    }

    /// Controllers currently enabled for children of the domain.
    pub fn enabled_controllers(&self) -> Result<Vec<Controller>, ContainmentError> {
        let text = read_interface(&self.root.join("cgroup.subtree_control"))?;
        Ok(parse_controllers(&text))
    }

    /// Move this process into a dedicated supervisor leaf and enable
    /// `controllers` for the domain's children.
    ///
    /// This is deliberately explicit and mutating. cgroup v2 forbids a cgroup
    /// from holding member processes while distributing controllers to its
    /// children, so a supervisor that wants bounded children must first vacate
    /// the domain itself. Callers that need only descendant-complete
    /// termination never have to call this.
    pub fn prepare(&self, controllers: &[Controller]) -> Result<(), ContainmentError> {
        let available = self.available_controllers()?;
        for controller in controllers {
            if !available.contains(controller) {
                return Err(ContainmentError::ControllerUnavailable(*controller));
            }
        }
        let supervisor = self.root.join(SUPERVISOR_LEAF);
        match fs::create_dir(&supervisor) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(ContainmentError::Io(error)),
        }
        write_interface(&supervisor.join("cgroup.procs"), b"0")
            .map_err(|_| ContainmentError::DomainNotDelegated)?;
        let enabled = self.enabled_controllers()?;
        for controller in controllers {
            if enabled.contains(controller) {
                continue;
            }
            let directive = format!("+{}", controller.as_str());
            write_interface(
                &self.root.join("cgroup.subtree_control"),
                directive.as_bytes(),
            )
            .map_err(|_| ContainmentError::ControllerUnavailable(*controller))?;
        }
        Ok(())
    }
}

/// One run's kernel containment domain.
///
/// Dropping the value kills and removes the cgroup, so an unwinding or
/// early-returning caller cannot leave an unbounded process tree behind.
#[derive(Debug)]
pub struct RunContainment {
    path: PathBuf,
    removed: bool,
}

impl RunContainment {
    /// Create an exclusive cgroup for `run_id` and apply `limits` before any
    /// workload can enter it.
    pub fn create(
        domain: &ContainmentDomain,
        run_id: &str,
        limits: ContainmentLimits,
    ) -> Result<Self, ContainmentError> {
        validate_run_id(run_id)?;
        let path = domain.root().join(format!("{RUN_PREFIX}{run_id}"));
        match fs::create_dir(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(ContainmentError::RunCgroupExists);
            }
            Err(error) => return Err(ContainmentError::Io(error)),
        }
        let containment = Self {
            path,
            removed: false,
        };
        // Ceilings are applied before the cgroup can hold a process, so no
        // workload ever runs for an instant without them. An early return here
        // drops `containment`, which removes the cgroup it just created.
        containment.apply(limits)?;
        if !containment.path.join("cgroup.kill").is_file() {
            return Err(ContainmentError::MissingAtomicKill);
        }
        Ok(containment)
    }

    fn apply(&self, limits: ContainmentLimits) -> Result<(), ContainmentError> {
        for (controller, value) in [
            (Controller::Pids, limits.pids_max),
            (Controller::Memory, limits.memory_max_bytes),
        ] {
            let Some(value) = value else { continue };
            let file = self.path.join(controller.limit_file());
            if !file.is_file() {
                return Err(ContainmentError::ControllerUnavailable(controller));
            }
            write_interface(&file, value.to_string().as_bytes())
                .map_err(|_| ContainmentError::ControllerUnavailable(controller))?;
        }
        if let Some(millicores) = limits.cpu_max_millicores {
            let quota = millicores
                .checked_mul(CPU_MAX_PERIOD_MICROS / 1_000)
                .ok_or(ContainmentError::ControllerUnavailable(Controller::Cpu))?;
            let file = self.path.join(Controller::Cpu.limit_file());
            if !file.is_file() {
                return Err(ContainmentError::ControllerUnavailable(Controller::Cpu));
            }
            let value = format!("{quota} {CPU_MAX_PERIOD_MICROS}");
            write_interface(&file, value.as_bytes())
                .map_err(|_| ContainmentError::ControllerUnavailable(Controller::Cpu))?;
        }
        Ok(())
    }

    /// Exact cgroup directory. This is the value the entry helper joins.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Processes currently inside the boundary, including every descendant.
    pub fn member_pids(&self) -> Result<Vec<Pid>, ContainmentError> {
        let text = read_interface(&self.path.join("cgroup.procs"))?;
        Ok(text
            .lines()
            .filter_map(|line| line.trim().parse::<i32>().ok())
            .map(Pid::from_raw)
            .collect())
    }

    /// Whether the boundary currently holds no process.
    pub fn is_empty(&self) -> Result<bool, ContainmentError> {
        Ok(self.member_pids()?.is_empty())
    }

    /// Confirm that every member descends from the launched tree.
    ///
    /// A same-uid workload holding write access to the delegated root could
    /// migrate a foreign process in. This detects that; it does not prevent it.
    pub fn verify_sole_membership(&self, expected: &[Pid]) -> Result<(), ContainmentError> {
        let members = self.member_pids()?;
        if members.iter().any(|member| !expected.contains(member)) {
            return Err(ContainmentError::ForeignMembership);
        }
        Ok(())
    }

    /// Atomically SIGKILL every member and descendant.
    ///
    /// This is the operation a process group cannot provide. Kernel cgroup
    /// membership is inherited across `fork` and unaffected by `setsid` and
    /// `setpgid`, so no descendant can place itself outside this kill.
    pub fn kill(&self) -> Result<(), ContainmentError> {
        match write_interface(&self.path.join("cgroup.kill"), b"1") {
            Ok(()) => Ok(()),
            // A cgroup already removed holds nothing left to kill.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ContainmentError::Io(error)),
        }
    }

    /// Kill the tree and wait, bounded, for the kernel to drain it.
    ///
    /// Draining is not instantaneous: a killed process leaves the cgroup only
    /// once it is reaped, so the caller must have waited on its direct child or
    /// left it to a subreaper.
    pub fn kill_and_drain(&self, deadline: Duration) -> Result<(), ContainmentError> {
        self.kill()?;
        let started = Instant::now();
        loop {
            if self.is_empty()? {
                return Ok(());
            }
            if started.elapsed() >= deadline {
                return Err(ContainmentError::DrainTimeout);
            }
            std::thread::sleep(DRAIN_POLL);
        }
    }

    /// Kill, drain, and remove the cgroup, leaving no kernel residue.
    pub fn dispose(mut self, deadline: Duration) -> Result<(), ContainmentError> {
        let started = Instant::now();
        self.kill_and_drain(deadline)?;
        // A descendant can leave `cgroup.procs` before the cgroup filesystem
        // releases its final internal reference. A single immediate rmdir is
        // therefore racy for short-lived supervised process trees. Retry only
        // the bounded residue case; the same caller-supplied deadline still
        // caps the complete disposal operation.
        loop {
            match self.remove_now() {
                Ok(()) => return Ok(()),
                Err(ContainmentError::Residue) if started.elapsed() < deadline => {
                    std::thread::sleep(DRAIN_POLL);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn remove_now(&mut self) -> Result<(), ContainmentError> {
        if self.removed {
            return Ok(());
        }
        match fs::remove_dir(&self.path) {
            Ok(()) => {
                self.removed = true;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.removed = true;
                Ok(())
            }
            Err(_) => Err(ContainmentError::Residue),
        }
    }
}

impl Drop for RunContainment {
    fn drop(&mut self) {
        if self.removed {
            return;
        }
        // Best-effort teardown. A caller wanting a reported outcome uses
        // `dispose`; Drop exists so a panic cannot leak a live process tree.
        let _ = self.kill();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match self.is_empty() {
                Ok(true) => break,
                Ok(false) => std::thread::sleep(DRAIN_POLL),
                Err(_) => break,
            }
        }
        let _ = fs::remove_dir(&self.path);
    }
}

/// Entry-helper process body.
///
/// Runs as the first child of the runner. It migrates itself into the cgroup
/// named by [`CGROUP_DIR_ENV`], confirms its own membership from
/// `/proc/self/cgroup`, and only then replaces itself with the workload. If any
/// step fails it exits without executing anything, so a workload never runs
/// outside the boundary.
///
/// Usage: `automonique-cgroup-enter -- <program> [args...]`
#[must_use]
pub fn containment_entry_helper_main() -> i32 {
    match enter_and_exec() {
        Ok(()) => 0,
        Err(code) => code,
    }
}

/// Exit code used when the helper refuses before executing the workload.
pub const HELPER_REFUSED_EXIT: i32 = 121;

fn enter_and_exec() -> Result<(), i32> {
    let target = std::env::var_os(CGROUP_DIR_ENV).ok_or(HELPER_REFUSED_EXIT)?;
    let target = PathBuf::from(target);

    let mut arguments = std::env::args_os().skip(1);
    let separator = arguments.next().ok_or(HELPER_REFUSED_EXIT)?;
    if separator != OsStr::new("--") {
        return Err(HELPER_REFUSED_EXIT);
    }
    let argv = arguments.collect::<Vec<OsString>>();
    let program = argv.first().ok_or(HELPER_REFUSED_EXIT)?.clone();

    join_and_confirm_membership(&target).map_err(|_| HELPER_REFUSED_EXIT)?;

    let program = CString::new(program.into_vec()).map_err(|_| HELPER_REFUSED_EXIT)?;
    let argv = argv
        .into_iter()
        .map(|argument| CString::new(argument.into_vec()))
        .collect::<Result<Vec<CString>, _>>()
        .map_err(|_| HELPER_REFUSED_EXIT)?;
    // Only reached inside the boundary; `execv` returns only on failure.
    nix::unistd::execv(&program, &argv).map_err(|_| HELPER_REFUSED_EXIT)?;
    Err(HELPER_REFUSED_EXIT)
}

/// Migrate the calling process into `target` and confirm from the kernel.
///
/// Shared by every entry helper in this crate: the write alone is not trusted —
/// membership is read back from `/proc/self/cgroup`, so a caller that returns
/// `Ok` is genuinely inside the boundary. On any error the caller must exit
/// without executing a workload.
pub(crate) fn join_and_confirm_membership(target: &Path) -> Result<(), ContainmentError> {
    write_interface(&target.join("cgroup.procs"), b"0")
        .map_err(|_| ContainmentError::PlacementUnconfirmed)?;
    let observed = own_cgroup_path()?;
    let expected = target
        .strip_prefix(CGROUP_ROOT)
        .map_err(|_| ContainmentError::PlacementUnconfirmed)?;
    let observed = observed.trim_start_matches('/');
    if Path::new(observed) != expected {
        return Err(ContainmentError::PlacementUnconfirmed);
    }
    Ok(())
}

/// Whether a process is still visible to this process.
///
/// Used to prove that a killed descendant is genuinely gone.
#[must_use]
pub fn process_is_live(pid: Pid) -> bool {
    kill(pid, None).is_ok()
}

fn own_cgroup_path() -> Result<String, ContainmentError> {
    let raw = fs::read_to_string("/proc/self/cgroup")?;
    let mut entries = raw.lines().filter(|line| !line.trim().is_empty());
    let first = entries.next().ok_or(ContainmentError::NotUnifiedCgroupV2)?;
    // A unified v2 hierarchy is exactly one `0::<path>` entry. Any additional
    // entry means v1 controllers are mounted and this process's containment is
    // not described by a single domain.
    if entries.next().is_some() {
        return Err(ContainmentError::NotUnifiedCgroupV2);
    }
    first
        .strip_prefix("0::")
        .map(str::to_owned)
        .ok_or(ContainmentError::NotUnifiedCgroupV2)
}

fn join_cgroup_relative(root: &Path, relative: &str) -> PathBuf {
    let relative = relative.trim_start_matches('/');
    if relative.is_empty() {
        root.to_path_buf()
    } else {
        root.join(relative)
    }
}

fn validate_run_id(run_id: &str) -> Result<(), ContainmentError> {
    if run_id.is_empty() || run_id.len() > MAX_RUN_ID_BYTES {
        return Err(ContainmentError::RunIdRejected);
    }
    // A cgroup name becomes a directory entry; restrict it to a bounded safe
    // alphabet so no run identifier can traverse or collide with kernel files.
    if !run_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(ContainmentError::RunIdRejected);
    }
    Ok(())
}

fn parse_controllers(text: &str) -> Vec<Controller> {
    text.split_ascii_whitespace()
        .filter_map(|token| match token {
            "pids" => Some(Controller::Pids),
            "memory" => Some(Controller::Memory),
            "cpu" => Some(Controller::Cpu),
            _ => None,
        })
        .collect()
}

fn read_interface(path: &Path) -> Result<String, ContainmentError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(ContainmentError::NotUnifiedCgroupV2);
    }
    let raw = fs::read(path)?;
    if raw.len() > MAX_PROCS_BYTES {
        return Err(ContainmentError::NotUnifiedCgroupV2);
    }
    String::from_utf8(raw).map_err(|_| ContainmentError::NotUnifiedCgroupV2)
}

/// Write one cgroup interface value.
///
/// Kernel cgroup files take a single write per value and must not be truncated
/// or appended to, so this opens write-only without `O_TRUNC` or `O_APPEND`.
fn write_interface(path: &Path, value: &[u8]) -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(value)
}

/// Whether the caller's own cgroup is owned by the current user.
///
/// Reported for diagnostics; ownership alone is not delegation.
pub fn domain_is_owned(domain: &ContainmentDomain) -> Result<bool, ContainmentError> {
    let metadata = fs::symlink_metadata(domain.root())?;
    Ok(metadata.uid() == Uid::current().as_raw())
}
