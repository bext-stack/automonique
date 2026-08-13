// SPDX-License-Identifier: Elastic-2.0

use automonique_cli::{
    inspect_cgroup_v2_controllers, inspect_cgroup_v2_delegation, inspect_landlock_support,
    inspect_max_user_namespaces,
};
use automonique_protocol::CheckStatus;
use automonique_runner::ContainmentDomain;
use automonique_runner::capability::{LANDLOCK_ABI_TCP, LandlockFinding};
use std::fs::FileTimes;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    bytes: Vec<u8>,
    len: u64,
    mode: u32,
    inode: u64,
    atime: i64,
    atime_nsec: i64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

fn snapshot(path: &Path) -> Snapshot {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOATIME | nix::libc::O_NOFOLLOW)
        .open(path)
        .expect("open fixture without atime mutation");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("fixture content");
    let metadata = std::fs::symlink_metadata(path).expect("fixture metadata");
    Snapshot {
        bytes,
        len: metadata.len(),
        #[cfg(unix)]
        mode: metadata.mode(),
        #[cfg(not(unix))]
        mode: 0,
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(not(unix))]
        inode: 0,
        #[cfg(unix)]
        atime: metadata.atime(),
        #[cfg(not(unix))]
        atime: 0,
        #[cfg(unix)]
        atime_nsec: metadata.atime_nsec(),
        #[cfg(not(unix))]
        atime_nsec: 0,
        #[cfg(unix)]
        mtime: metadata.mtime(),
        #[cfg(not(unix))]
        mtime: 0,
        #[cfg(unix)]
        mtime_nsec: metadata.mtime_nsec(),
        #[cfg(not(unix))]
        mtime_nsec: 0,
        #[cfg(unix)]
        ctime: metadata.ctime(),
        #[cfg(not(unix))]
        ctime: 0,
        #[cfg(unix)]
        ctime_nsec: metadata.ctime_nsec(),
        #[cfg(not(unix))]
        ctime_nsec: 0,
    }
}

#[test]
fn kernel_reads_do_not_update_access_time() {
    let directory = tempfile::tempdir().expect("fixtures");
    let path = write_fixture(&directory, "atime.controllers", b"cpu io memory pids\n");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open fixture for time setup");
    file.set_times(
        FileTimes::new()
            .set_accessed(UNIX_EPOCH + Duration::from_secs(1))
            .set_modified(UNIX_EPOCH + Duration::from_secs(2)),
    )
    .expect("set fixture times");
    drop(file);
    let before = snapshot(&path);

    assert_eq!(
        inspect_cgroup_v2_controllers(&path).status(),
        CheckStatus::Healthy
    );
    assert_unchanged(&path, &before);
}

fn write_fixture(directory: &tempfile::TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = directory.path().join(name);
    std::fs::write(&path, bytes).expect("write fixture");
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("fixture mode");
    path
}

fn assert_unchanged(path: &Path, before: &Snapshot) {
    assert_eq!(&snapshot(path), before);
}

#[test]
fn controller_inspection_requires_all_four_tokens_without_mutation() {
    let directory = tempfile::tempdir().expect("fixtures");
    let healthy_path = write_fixture(
        &directory,
        "healthy.controllers",
        b"cpuset cpu io memory hugetlb pids\n",
    );
    let healthy_before = snapshot(&healthy_path);
    let healthy = inspect_cgroup_v2_controllers(&healthy_path);
    assert_eq!(healthy.status(), CheckStatus::Healthy);
    assert_unchanged(&healthy_path, &healthy_before);

    let incomplete_path = write_fixture(&directory, "incomplete.controllers", b"cpu io memory\n");
    let incomplete_before = snapshot(&incomplete_path);
    let incomplete = inspect_cgroup_v2_controllers(&incomplete_path);
    assert_eq!(incomplete.status(), CheckStatus::Finding);
    assert_eq!(
        incomplete.reason().expect("reason").code().as_str(),
        "kernel.cgroup-v2.controllers-incomplete"
    );
    assert_unchanged(&incomplete_path, &incomplete_before);

    let missing = directory.path().join("missing.controllers");
    let missing_check = inspect_cgroup_v2_controllers(&missing);
    assert_eq!(missing_check.status(), CheckStatus::Finding);
    assert!(!missing.exists());
}

#[test]
fn malformed_oversized_and_symlinked_controller_inputs_are_unavailable() {
    let directory = tempfile::tempdir().expect("fixtures");
    for (name, content) in [
        ("malformed.controllers", b"cpu io memory PIDS\n".as_slice()),
        (
            "duplicate.controllers",
            b"cpu io memory pids pids\n".as_slice(),
        ),
        ("oversized.controllers", vec![b'a'; 4_097].as_slice()),
    ] {
        let path = write_fixture(&directory, name, content);
        let before = snapshot(&path);
        assert_eq!(
            inspect_cgroup_v2_controllers(&path).status(),
            CheckStatus::Unavailable
        );
        assert_unchanged(&path, &before);
    }

    let target = write_fixture(&directory, "target.controllers", b"cpu io memory pids\n");
    let link = directory.path().join("linked.controllers");
    std::os::unix::fs::symlink(&target, &link).expect("fixture symlink");
    let target_before = snapshot(&target);
    let link_before = std::fs::symlink_metadata(&link).expect("link metadata");
    assert_eq!(
        inspect_cgroup_v2_controllers(&link).status(),
        CheckStatus::Unavailable
    );
    assert_eq!(
        std::fs::symlink_metadata(&link)
            .expect("link metadata")
            .ino(),
        link_before.ino()
    );
    assert_unchanged(&target, &target_before);
}

#[test]
fn namespace_setting_distinguishes_enabled_disabled_and_unavailable() {
    let directory = tempfile::tempdir().expect("fixtures");
    let enabled_path = write_fixture(&directory, "enabled", b"1024\n");
    let enabled_before = snapshot(&enabled_path);
    assert_eq!(
        inspect_max_user_namespaces(&enabled_path).status(),
        CheckStatus::Healthy
    );
    assert_eq!(
        inspect_max_user_namespaces(&enabled_path).code().as_str(),
        "kernel.max-user-namespaces-setting"
    );
    assert_unchanged(&enabled_path, &enabled_before);

    let disabled_path = write_fixture(&directory, "disabled", b"0\n");
    let disabled_before = snapshot(&disabled_path);
    let disabled = inspect_max_user_namespaces(&disabled_path);
    assert_eq!(disabled.status(), CheckStatus::Finding);
    assert_eq!(
        disabled.reason().expect("reason").code().as_str(),
        "kernel.max-user-namespaces-setting-zero"
    );
    assert_unchanged(&disabled_path, &disabled_before);

    for (name, content) in [
        ("malformed", b"1x\n".as_slice()),
        ("negative", b"-1\n".as_slice()),
        ("oversized", b"111111111111111111111111111111111".as_slice()),
    ] {
        let path = write_fixture(&directory, name, content);
        let before = snapshot(&path);
        assert_eq!(
            inspect_max_user_namespaces(&path).status(),
            CheckStatus::Unavailable
        );
        assert_unchanged(&path, &before);
    }

    let missing = directory.path().join("missing");
    assert_eq!(
        inspect_max_user_namespaces(&missing).status(),
        CheckStatus::Unavailable
    );
    assert_eq!(
        inspect_max_user_namespaces(&missing).code().as_str(),
        "kernel.max-user-namespaces-setting"
    );
    assert!(!missing.exists());
}

#[test]
fn symlinked_namespace_setting_is_unavailable_without_target_mutation() {
    let directory = tempfile::tempdir().expect("fixtures");
    let target = write_fixture(&directory, "target", b"1024\n");
    let link = directory.path().join("linked");
    std::os::unix::fs::symlink(&target, &link).expect("fixture symlink");
    let target_before = snapshot(&target);
    let link_before = std::fs::symlink_metadata(&link).expect("link metadata");

    assert_eq!(
        inspect_max_user_namespaces(&link).status(),
        CheckStatus::Unavailable
    );
    assert_eq!(
        std::fs::symlink_metadata(&link)
            .expect("link metadata")
            .ino(),
        link_before.ino()
    );
    assert_unchanged(&target, &target_before);
}

#[test]
fn symlinked_parent_is_unavailable_without_target_mutation() {
    let target_directory = tempfile::tempdir().expect("target directory");
    let target = write_fixture(&target_directory, "controllers", b"cpu io memory pids\n");
    let target_before = snapshot(&target);
    let link_root = tempfile::tempdir().expect("link root");
    let linked_parent = link_root.path().join("linked");
    std::os::unix::fs::symlink(target_directory.path(), &linked_parent).expect("parent symlink");

    assert_eq!(
        inspect_cgroup_v2_controllers(&linked_parent.join("controllers")).status(),
        CheckStatus::Unavailable
    );
    assert_unchanged(&target, &target_before);
}

/// The securityfs entry the runner's boundary probe used to consult. Read here
/// only to prove the doctor line does not depend on it.
const LANDLOCK_SECURITYFS_ENTRY: &str = "/sys/kernel/security/landlock";

/// The Landlock line must report what the kernel answers, not what securityfs
/// publishes.
///
/// Written as an agreement with an independent probe rather than as a host
/// constant, so it is equally correct on a kernel with no Landlock at all. The
/// clause with teeth is the securityfs one: on a host where that entry is
/// absent and the kernel nevertheless supports Landlock — this crate's
/// development host is exactly that — a securityfs-derived line reports absence
/// and fails here.
#[test]
fn the_landlock_line_follows_the_kernel_not_the_securityfs_entry() {
    let check = inspect_landlock_support();
    assert_eq!(check.code().as_str(), "kernel.landlock-support");

    let securityfs_entry = Path::new(LANDLOCK_SECURITYFS_ENTRY).exists();
    match LandlockFinding::probe().abi() {
        Some(measured) if measured.denies_tcp() => {
            assert_eq!(
                check.status(),
                CheckStatus::Healthy,
                "the kernel reports {measured} but the doctor line is not healthy; securityfs entry present: {securityfs_entry}"
            );
            assert!(measured.level() >= LANDLOCK_ABI_TCP);
        }
        Some(measured) => {
            assert_eq!(check.status(), CheckStatus::Finding);
            assert_eq!(
                check.reason().expect("reason").code().as_str(),
                "kernel.landlock-support-below-tcp-abi",
                "a kernel at {measured} restricts filesystems but cannot deny TCP"
            );
        }
        None => {
            assert_eq!(check.status(), CheckStatus::Finding);
            assert_eq!(
                check.reason().expect("reason").code().as_str(),
                "kernel.landlock-support-absent",
                "securityfs entry present: {securityfs_entry}"
            );
        }
    }
}

/// The delegation line must agree with the call the runner itself makes before
/// creating a run cgroup, so the doctor cannot promise a domain the runner
/// would refuse, nor refuse one the runner would accept.
#[test]
fn the_delegation_line_matches_the_discovery_the_runner_uses() {
    let check = inspect_cgroup_v2_delegation();
    assert_eq!(check.code().as_str(), "kernel.cgroup-v2.delegation");
    assert_eq!(
        check.status() == CheckStatus::Healthy,
        ContainmentDomain::discover().is_ok(),
        "the doctor and ContainmentDomain::discover disagree about delegation"
    );
    if check.status() != CheckStatus::Healthy {
        let code = check
            .reason()
            .expect("a non-healthy delegation line must say why")
            .code()
            .as_str()
            .to_owned();
        assert!(
            code.starts_with("kernel.cgroup-v2.delegation-"),
            "an unusable domain must name its own reason: {code}"
        );
    }
}

/// Delegation is a separate fact from controller visibility. A host whose
/// controller list is complete may still be unable to place a single child, so
/// neither line may be inferred from the other.
#[test]
fn controller_visibility_and_delegation_are_reported_separately() {
    let controllers = inspect_cgroup_v2_controllers(Path::new("/sys/fs/cgroup/cgroup.controllers"));
    let delegation = inspect_cgroup_v2_delegation();
    assert_ne!(controllers.code().as_str(), delegation.code().as_str());
    if controllers.status() == CheckStatus::Healthy && ContainmentDomain::discover().is_err() {
        assert_ne!(
            delegation.status(),
            CheckStatus::Healthy,
            "a complete controller list was allowed to stand in for delegation"
        );
    }
}

/// Asking these questions must not answer them. A probe that created a cgroup,
/// applied a ruleset, or set no_new_privs would restrict the doctor itself, and
/// nothing could undo it.
///
/// Read through `/proc/thread-self`, never `/proc/self`: `no_new_privs`, the
/// seccomp fields, and the mount namespace are per-thread while `/proc/self`
/// reports the thread-group leader, so a check that restricted the worker
/// thread this test runs on would leave no trace there.
#[test]
fn the_new_kernel_checks_do_not_restrict_or_mutate_the_calling_process() {
    let field = |name: &str| {
        std::fs::read_to_string("/proc/thread-self/status")
            .ok()?
            .lines()
            .find_map(|line| line.strip_prefix(name).map(|value| value.trim().to_owned()))
    };
    let observe = || {
        (
            field("NoNewPrivs:"),
            field("Seccomp:"),
            field("Seccomp_filters:"),
            std::fs::read_link("/proc/thread-self/ns/user").ok(),
            std::fs::read_link("/proc/thread-self/ns/mnt").ok(),
            std::fs::read_link("/proc/thread-self/ns/net").ok(),
            std::fs::read_to_string("/proc/thread-self/cgroup").ok(),
        )
    };

    let before = observe();
    let first = (
        inspect_landlock_support().status(),
        inspect_cgroup_v2_delegation().status(),
    );
    let after = observe();
    assert_eq!(
        before, after,
        "a kernel check changed this process's no_new_privs, seccomp, namespace, or cgroup state"
    );
    assert!(
        std::fs::read_dir("/").is_ok(),
        "a kernel check restricted this process's filesystem view"
    );

    // A check with side effects would not answer the same way twice.
    let second = (
        inspect_landlock_support().status(),
        inspect_cgroup_v2_delegation().status(),
    );
    assert_eq!(first, second);
}
