// SPDX-License-Identifier: Elastic-2.0

//! Bounded, read-only Linux host-setting inspection.
//!
//! Every check here reports what the kernel can be *asked*, never what has been
//! installed. Two distinctions are load-bearing and are therefore reported as
//! separate checks rather than merged:
//!
//! - **Visible is not usable.** [`inspect_cgroup_v2_controllers`] reads the
//!   controller list published at a cgroup path. That says the unified
//!   hierarchy exists and which controllers it offers; it says nothing about
//!   whether *this* process may create a child cgroup beneath its own. A
//!   supervisor on a host with a perfect controller list and an undelegated
//!   cgroup can bound nothing. [`inspect_cgroup_v2_delegation`] asks that
//!   second question, through the same discovery the runner itself uses.
//! - **Published is not supported.** Landlock has a securityfs entry, and its
//!   presence is uncorrelated with whether the kernel accepts Landlock access
//!   rights: on the development host for this crate the entry is absent while
//!   the kernel reports ABI 4. [`inspect_landlock_support`] therefore never
//!   reads securityfs; it reuses the runner's syscall-grounded measurement.
//!
//! No check writes, creates, unshares, or restricts anything. Discovery stats
//! fixed kernel paths and tests write *permission*; the Landlock measurement is
//! a version query that allocates no ruleset descriptor.

use automonique_protocol::{CheckStatus, DoctorCheck, DoctorReason, FindingCode, FindingMessage};
use automonique_runner::capability::{
    ContainmentFinding, ContainmentUnavailable, LANDLOCK_ABI_TCP, LandlockFinding,
};
use automonique_runner::{ContainmentDomain, ContainmentError, Controller};
use nix::errno::Errno;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::{Mode, SFlag, fstat};
use nix::unistd::{close, read};
use std::path::Path;

const CGROUP_CONTROLLERS_LIMIT: usize = 4_096;
const USER_NAMESPACES_LIMIT: usize = 32;
const REQUIRED_CONTROLLERS: [&str; 4] = ["cpu", "io", "memory", "pids"];

/// Inspect a caller-selected cgroup-v2 controller file without following links.
///
/// A healthy result means the named controller list exists and offers every
/// controller this product needs. It does **not** mean a run cgroup can be
/// created: the controller list is published by the hierarchy, not granted to
/// this process. [`inspect_cgroup_v2_delegation`] answers that.
#[must_use]
pub fn inspect_cgroup_v2_controllers(path: &Path) -> DoctorCheck {
    let bytes = match read_bounded_regular(path, CGROUP_CONTROLLERS_LIMIT) {
        Ok(bytes) => bytes,
        Err(ReadFailure::Missing) => {
            return non_healthy(
                "kernel.cgroup-v2.controllers",
                CheckStatus::Finding,
                "kernel.cgroup-v2.controllers-missing",
                "The cgroup v2 controller list is absent",
            );
        }
        Err(ReadFailure::Unavailable) => {
            return non_healthy(
                "kernel.cgroup-v2.controllers",
                CheckStatus::Unavailable,
                "kernel.cgroup-v2.controllers-unavailable",
                "The cgroup v2 controller list could not be read safely",
            );
        }
    };
    let Some(controllers) = parse_controllers(&bytes) else {
        return non_healthy(
            "kernel.cgroup-v2.controllers",
            CheckStatus::Unavailable,
            "kernel.cgroup-v2.controllers-malformed",
            "The cgroup v2 controller list is malformed",
        );
    };
    if REQUIRED_CONTROLLERS
        .iter()
        .all(|required| controllers.contains(required))
    {
        healthy("kernel.cgroup-v2.controllers")
    } else {
        non_healthy(
            "kernel.cgroup-v2.controllers",
            CheckStatus::Finding,
            "kernel.cgroup-v2.controllers-incomplete",
            "Required cgroup v2 controllers are absent",
        )
    }
}

/// Inspect a caller-selected `max_user_namespaces` file without following links.
#[must_use]
pub fn inspect_max_user_namespaces(path: &Path) -> DoctorCheck {
    let bytes = match read_bounded_regular(path, USER_NAMESPACES_LIMIT) {
        Ok(bytes) => bytes,
        Err(ReadFailure::Missing | ReadFailure::Unavailable) => {
            return non_healthy(
                "kernel.max-user-namespaces-setting",
                CheckStatus::Unavailable,
                "kernel.max-user-namespaces-setting-unavailable",
                "The maximum user namespace host setting could not be read safely",
            );
        }
    };
    let Some(value) = parse_unsigned(&bytes) else {
        return non_healthy(
            "kernel.max-user-namespaces-setting",
            CheckStatus::Unavailable,
            "kernel.max-user-namespaces-setting-malformed",
            "The maximum user namespace host setting is malformed",
        );
    };
    if value == 0 {
        non_healthy(
            "kernel.max-user-namespaces-setting",
            CheckStatus::Finding,
            "kernel.max-user-namespaces-setting-zero",
            "The configured maximum user namespace count is zero",
        )
    } else {
        healthy("kernel.max-user-namespaces-setting")
    }
}

/// Inspect whether this process's own cgroup is a usable containment domain.
///
/// This is the delegation question the controller list cannot answer. It is
/// resolved by [`ContainmentDomain::discover`] — the same call the runner makes
/// before it will create a run cgroup — so the doctor cannot report a domain
/// the runner would then refuse, or refuse one the runner would accept.
///
/// Read-only: discovery stats fixed kernel paths, reads `/proc/self/cgroup`,
/// and tests write permission with `access(2)`. It creates no cgroup and moves
/// no process.
///
/// A healthy result means a launcher *could* create a bounded, atomically
/// killable run cgroup here. It is not a boundary; nothing is contained yet.
#[must_use]
pub fn inspect_cgroup_v2_delegation() -> DoctorCheck {
    delegation_check(ContainmentDomain::discover())
}

/// Inspect whether this process's delegated domain enables resource controls.
///
/// A controller listed in `cgroup.controllers` is merely available to the
/// delegated domain. It constrains child cgroups only after it also appears in
/// `cgroup.subtree_control`. Reading both through [`ContainmentDomain`] keeps
/// this check aligned with the exact hierarchy the runner will use.
#[must_use]
pub fn inspect_cgroup_v2_enabled_controllers() -> DoctorCheck {
    let Ok(domain) = ContainmentDomain::discover() else {
        return non_healthy(
            "kernel.cgroup-v2.controllers-enabled",
            CheckStatus::Unavailable,
            "kernel.cgroup-v2.controllers-enabled-domain-unavailable",
            "Enabled child controllers are unavailable without a delegated cgroup v2 domain",
        );
    };
    enabled_controller_check(&domain)
}

fn enabled_controller_check(domain: &ContainmentDomain) -> DoctorCheck {
    let (Ok(available), Ok(enabled)) =
        (domain.available_controllers(), domain.enabled_controllers())
    else {
        return non_healthy(
            "kernel.cgroup-v2.controllers-enabled",
            CheckStatus::Unavailable,
            "kernel.cgroup-v2.controllers-enabled-unreadable",
            "The delegated cgroup controller state could not be read",
        );
    };
    const REQUIRED: [Controller; 3] = [Controller::Cpu, Controller::Memory, Controller::Pids];
    if REQUIRED
        .iter()
        .all(|controller| available.contains(controller) && enabled.contains(controller))
    {
        healthy("kernel.cgroup-v2.controllers-enabled")
    } else {
        non_healthy(
            "kernel.cgroup-v2.controllers-enabled",
            CheckStatus::Finding,
            "kernel.cgroup-v2.controllers-enabled-incomplete",
            "Required cgroup controllers are not enabled for child workloads",
        )
    }
}

/// Project a discovery outcome into a doctor check.
///
/// The typed reason is not re-derived here. It comes from
/// [`ContainmentFinding::denial`], the projection the runner's capability probe
/// already applies to the same errors, so the doctor and the probe cannot drift
/// into disagreeing about why a host has no domain.
fn delegation_check(discovered: Result<ContainmentDomain, ContainmentError>) -> DoctorCheck {
    let finding = match discovered {
        Ok(_) => ContainmentFinding::Delegated,
        Err(error) => ContainmentFinding::Unusable(error),
    };
    let Some(denial) = finding.denial() else {
        return healthy("kernel.cgroup-v2.delegation");
    };
    let (status, reason_code, message) = match denial {
        ContainmentUnavailable::NoUnifiedHierarchy => (
            CheckStatus::Finding,
            "kernel.cgroup-v2.delegation-no-unified-hierarchy",
            "No unified cgroup v2 hierarchy describes this process",
        ),
        ContainmentUnavailable::NotDelegated => (
            CheckStatus::Finding,
            "kernel.cgroup-v2.delegation-not-delegated",
            "The cgroup v2 hierarchy is visible but this process's own cgroup is not delegated to it",
        ),
        ContainmentUnavailable::NoAtomicKill => (
            CheckStatus::Finding,
            "kernel.cgroup-v2.delegation-no-atomic-kill",
            "This process's cgroup exposes no atomic cgroup.kill interface",
        ),
        ContainmentUnavailable::Unreadable => (
            CheckStatus::Unavailable,
            "kernel.cgroup-v2.delegation-unreadable",
            "The containment domain for this process could not be read",
        ),
    };
    non_healthy("kernel.cgroup-v2.delegation", status, reason_code, message)
}

/// Inspect whether the running kernel accepts Landlock access rights.
///
/// The securityfs entry `/sys/kernel/security/landlock` is deliberately not
/// consulted. Its presence records that securityfs publishes a Landlock
/// directory, not that the kernel supports Landlock, and the two disagree on
/// real hosts. The measurement is [`LandlockFinding::probe`], a Landlock
/// version query that allocates no ruleset descriptor and restricts nothing.
///
/// A healthy result means a launcher could apply a ruleset that both confines a
/// filesystem view and denies TCP. It does **not** mean any ruleset is applied:
/// enforcement requires a launcher to install one on a workload before `exec`,
/// and this check installs nothing.
#[must_use]
pub fn inspect_landlock_support() -> DoctorCheck {
    landlock_check(LandlockFinding::probe())
}

/// Project a Landlock measurement into a doctor check.
///
/// Three outcomes, because the kernel really offers three. Landlock defines
/// filesystem access rights from ABI 1 but TCP access rights only from ABI 4,
/// so a kernel between them can confine a filesystem and can never deny a
/// connection. Reporting that as healthy would credit the host with a network
/// restriction it cannot install.
fn landlock_check(finding: LandlockFinding) -> DoctorCheck {
    let Some(abi) = finding.abi() else {
        return non_healthy(
            "kernel.landlock-support",
            CheckStatus::Finding,
            "kernel.landlock-support-absent",
            "The running kernel accepts no Landlock access right this build can name",
        );
    };
    if abi.denies_tcp() {
        return healthy("kernel.landlock-support");
    }
    non_healthy(
        "kernel.landlock-support",
        CheckStatus::Finding,
        "kernel.landlock-support-below-tcp-abi",
        &format!(
            "Landlock {abi} is below the ABI {LANDLOCK_ABI_TCP} that defines TCP access rights"
        ),
    )
}

fn parse_controllers(bytes: &[u8]) -> Option<Vec<&str>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut controllers = Vec::new();
    for token in text.split_ascii_whitespace() {
        if token.is_empty()
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            || controllers.contains(&token)
        {
            return None;
        }
        controllers.push(token);
    }
    Some(controllers)
}

fn parse_unsigned(bytes: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(bytes).ok()?.trim_ascii();
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[derive(Clone, Copy)]
enum ReadFailure {
    Missing,
    Unavailable,
}

/// Open `path` read-only, refusing every symlink, suppressing access-time
/// updates where the kernel permits it.
///
/// `O_NOATIME` is only permitted to a file's owner or to `CAP_FOWNER`, and it
/// fails with `EPERM` rather than being ignored. The kernel interfaces this
/// module is pointed at are root-owned — `/sys/fs/cgroup/cgroup.controllers`
/// and `/proc/sys/user/max_user_namespaces` both are — so demanding the flag
/// made an unprivileged doctor report every one of them as unreadable while an
/// ordinary read of the same path succeeded. That is a false measurement of
/// exactly the kind this module exists to avoid: it reports a property of the
/// prober's privileges as a property of the host.
///
/// The flag is therefore requested first and dropped only on `EPERM`. Files the
/// process owns keep the guarantee that inspection leaves their access time
/// untouched; for a file it does not own, the access time may advance. Nothing
/// here ever writes content, creates, removes, or changes a mode, and the
/// retried open is the same path, the same flags otherwise, and the same
/// symlink refusal.
fn read_bounded_regular(path: &Path, limit: usize) -> Result<Vec<u8>, ReadFailure> {
    let open = |flags| {
        let how = OpenHow::new()
            .flags(flags)
            .mode(Mode::empty())
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS);
        openat2(nix::libc::AT_FDCWD, path, how)
    };
    let bounded = OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW;
    let descriptor = match open(bounded | OFlag::O_NOATIME) {
        Ok(descriptor) => Ok(descriptor),
        Err(Errno::EPERM) => open(bounded),
        Err(error) => Err(error),
    }
    .map_err(|error| {
        if error == Errno::ENOENT {
            ReadFailure::Missing
        } else {
            ReadFailure::Unavailable
        }
    })?;
    let result = read_open_descriptor(descriptor, limit);
    let close_result = close(descriptor);
    match (result, close_result) {
        (Ok(bytes), Ok(())) => Ok(bytes),
        (Err(error), _) => Err(error),
        (Ok(_), Err(_)) => Err(ReadFailure::Unavailable),
    }
}

fn read_open_descriptor(descriptor: i32, limit: usize) -> Result<Vec<u8>, ReadFailure> {
    let metadata = fstat(descriptor).map_err(|_| ReadFailure::Unavailable)?;
    if !SFlag::from_bits_truncate(metadata.st_mode).contains(SFlag::S_IFREG) {
        return Err(ReadFailure::Unavailable);
    }
    let mut bytes = vec![0; limit + 1];
    let mut length = 0usize;
    loop {
        match read(descriptor, &mut bytes[length..]) {
            Ok(0) => {
                bytes.truncate(length);
                return Ok(bytes);
            }
            Ok(count) => {
                length += count;
                if length > limit {
                    return Err(ReadFailure::Unavailable);
                }
            }
            Err(Errno::EINTR) => {}
            Err(_) => return Err(ReadFailure::Unavailable),
        }
    }
}

fn healthy(code: &str) -> DoctorCheck {
    DoctorCheck::new(
        FindingCode::new(code).expect("constant check code is valid"),
        CheckStatus::Healthy,
        None,
    )
    .expect("constant healthy check is coherent")
}

/// Build a non-healthy check.
///
/// Every code passed here is a constant. One message is assembled at runtime
/// from a measured Landlock ABI level, which is a single-line ASCII string
/// bounded well under [`automonique_protocol::MAX_FINDING_MESSAGE_BYTES`], so
/// it satisfies the same grammar the constants do.
fn non_healthy(
    check_code: &str,
    status: CheckStatus,
    reason_code: &str,
    message: &str,
) -> DoctorCheck {
    DoctorCheck::new(
        FindingCode::new(check_code).expect("constant check code is valid"),
        status,
        Some(DoctorReason::new(
            FindingCode::new(reason_code).expect("constant reason code is valid"),
            FindingMessage::new(message).expect("bounded single-line reason message is valid"),
        )),
    )
    .expect("constant non-healthy check is coherent")
}

#[cfg(test)]
mod tests {
    use super::{delegation_check, enabled_controller_check, landlock_check};
    use automonique_protocol::CheckStatus;
    use automonique_runner::ContainmentDomain;
    use automonique_runner::capability::{
        LANDLOCK_ABI_FILESYSTEM, LANDLOCK_ABI_HIGHEST_KNOWN, LANDLOCK_ABI_TCP, LandlockAbi,
        LandlockFinding,
    };
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    fn abi(level: u8) -> LandlockAbi {
        LandlockAbi::from_level(level).expect("test fixture uses a nameable ABI level")
    }

    fn reason_code(check: &automonique_protocol::DoctorCheck) -> &str {
        check
            .reason()
            .expect("a non-healthy check must carry a reason")
            .code()
            .as_str()
    }

    fn controller_domain(available: &str, enabled: &str) -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("cgroup fixture");
        for (name, content) in [
            ("cgroup.procs", ""),
            ("cgroup.kill", ""),
            ("cgroup.controllers", available),
            ("cgroup.subtree_control", enabled),
        ] {
            std::fs::write(root.path().join(name), content).expect("fixture interface");
        }
        root
    }

    #[test]
    fn child_controller_readback_distinguishes_available_from_enabled() {
        let complete = controller_domain("cpu memory pids", "cpu memory pids");
        let complete = ContainmentDomain::at(complete.path()).expect("complete domain");
        assert_eq!(
            enabled_controller_check(&complete).status(),
            CheckStatus::Healthy
        );

        let inert = controller_domain("cpu memory pids", "pids");
        let inert = ContainmentDomain::at(inert.path()).expect("inert domain");
        let check = enabled_controller_check(&inert);
        assert_eq!(check.status(), CheckStatus::Finding);
        assert_eq!(
            reason_code(&check),
            "kernel.cgroup-v2.controllers-enabled-incomplete"
        );
    }

    /// A kernel that refuses every Landlock access right must never produce a
    /// healthy Landlock line. This is the direction that would let the doctor
    /// promise a filesystem restriction the host cannot install.
    #[test]
    fn an_unsupporting_kernel_never_yields_a_healthy_landlock_line() {
        let check = landlock_check(LandlockFinding::Unsupported);
        assert_eq!(check.code().as_str(), "kernel.landlock-support");
        assert_eq!(check.status(), CheckStatus::Finding);
        assert_eq!(reason_code(&check), "kernel.landlock-support-absent");
    }

    /// Landlock defines filesystem rights from ABI 1 and TCP rights only from
    /// ABI 4. A host between them must not read as healthy, and the shortfall
    /// must name the level it fell short of rather than merely failing.
    #[test]
    fn the_landlock_line_splits_at_the_abi_that_defines_tcp_rights() {
        for level in LANDLOCK_ABI_FILESYSTEM..=LANDLOCK_ABI_HIGHEST_KNOWN {
            let check = landlock_check(LandlockFinding::Enforceable(abi(level)));
            assert_eq!(check.code().as_str(), "kernel.landlock-support");
            if level >= LANDLOCK_ABI_TCP {
                assert_eq!(
                    check.status(),
                    CheckStatus::Healthy,
                    "ABI {level} covers every Landlock property this product asks for"
                );
                assert!(check.reason().is_none());
            } else {
                assert_eq!(
                    check.status(),
                    CheckStatus::Finding,
                    "ABI {level} cannot deny TCP and must not read as healthy"
                );
                assert_eq!(reason_code(&check), "kernel.landlock-support-below-tcp-abi");
                let message = check
                    .reason()
                    .expect("reason")
                    .message()
                    .as_str()
                    .to_owned();
                assert!(
                    message.contains(&format!("ABI {LANDLOCK_ABI_TCP}")),
                    "the shortfall must name the level it fell short of: {message}"
                );
                assert!(
                    message.contains(&abi(level).to_string()),
                    "the shortfall must name the measured floor: {message}"
                );
            }
        }
    }

    /// Every distinct reason discovery can produce must reach the operator as a
    /// distinct reason code. Collapsing them would hide the one case an
    /// operator can actually act on: a visible hierarchy that is not delegated.
    #[test]
    fn each_delegation_outcome_reaches_the_operator_as_its_own_reason() {
        let directory = tempfile::tempdir().expect("fixtures");

        let bare = directory.path().join("bare");
        std::fs::create_dir(&bare).expect("bare domain");
        let check = delegation_check(ContainmentDomain::at(&bare));
        assert_eq!(check.code().as_str(), "kernel.cgroup-v2.delegation");
        assert_eq!(check.status(), CheckStatus::Finding);
        assert_eq!(
            reason_code(&check),
            "kernel.cgroup-v2.delegation-no-unified-hierarchy"
        );

        let unkillable = directory.path().join("unkillable");
        std::fs::create_dir(&unkillable).expect("domain without atomic kill");
        std::fs::write(unkillable.join("cgroup.procs"), b"").expect("procs interface");
        let check = delegation_check(ContainmentDomain::at(&unkillable));
        assert_eq!(check.status(), CheckStatus::Finding);
        assert_eq!(
            reason_code(&check),
            "kernel.cgroup-v2.delegation-no-atomic-kill"
        );

        let delegated = directory.path().join("delegated");
        std::fs::create_dir(&delegated).expect("delegated domain");
        std::fs::write(delegated.join("cgroup.procs"), b"").expect("procs interface");
        std::fs::write(delegated.join("cgroup.kill"), b"").expect("kill interface");
        let check = delegation_check(ContainmentDomain::at(&delegated));
        assert_eq!(check.status(), CheckStatus::Healthy);
        assert!(check.reason().is_none());

        // Root passes every write-access test, so the undelegated case is not
        // constructible there. Asserting it anyway would make this test report
        // a property of the test user rather than of the code.
        if !nix::unistd::Uid::effective().is_root() {
            std::fs::set_permissions(&delegated, std::fs::Permissions::from_mode(0o500))
                .expect("read-only domain");
            let check = delegation_check(ContainmentDomain::at(&delegated));
            assert_eq!(check.status(), CheckStatus::Finding);
            assert_eq!(
                reason_code(&check),
                "kernel.cgroup-v2.delegation-not-delegated"
            );
            std::fs::set_permissions(&delegated, std::fs::Permissions::from_mode(0o700))
                .expect("restore for cleanup");
        }
    }

    /// A hierarchy whose controller list is complete says nothing about whether
    /// this process may place a child in it. If one check ever implied the
    /// other, a host that can bound nothing would read as able to bound a run.
    #[test]
    fn a_complete_controller_list_does_not_imply_delegation() {
        let directory = tempfile::tempdir().expect("fixtures");
        let controllers = directory.path().join("cgroup.controllers");
        std::fs::write(&controllers, b"cpuset cpu io memory hugetlb pids\n")
            .expect("controller list");
        assert_eq!(
            super::inspect_cgroup_v2_controllers(&controllers).status(),
            CheckStatus::Healthy
        );
        assert_eq!(
            delegation_check(ContainmentDomain::at(directory.path())).status(),
            CheckStatus::Finding,
            "a directory with a controller list but no cgroup interfaces is not a domain"
        );
    }

    /// A root-owned kernel file that any ordinary read can parse must never be
    /// reported unreadable. `O_NOATIME` is refused to a non-owner, so demanding
    /// it turned the prober's own privileges into a claim about the host.
    #[test]
    fn a_readable_kernel_file_is_never_reported_unavailable() {
        let path = Path::new("/proc/sys/user/max_user_namespaces");
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        if text.trim().parse::<u64>().is_err() {
            return;
        }
        assert_ne!(
            super::inspect_max_user_namespaces(path).status(),
            CheckStatus::Unavailable,
            "an ordinary read parsed {path:?} but the doctor called it unreadable"
        );
    }
}
