// SPDX-License-Identifier: Elastic-2.0

use automonique_cli::{inspect_runtime, run};
use automonique_protocol::{CheckStatus, ReportStatus};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;

fn assert_bounded_usage(stderr: &[u8]) {
    let usage = std::str::from_utf8(stderr).expect("usage is UTF-8");
    assert!(usage.starts_with("usage: automonique doctor [--json]\n"));
    assert!(usage.ends_with("       automonique shutdown\n"));
    assert!(usage.len() <= 2 * 1024);
}

fn private_runtime() -> tempfile::TempDir {
    let runtime = tempfile::tempdir().expect("runtime");
    std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private base");
    let product = runtime.path().join("automonique");
    std::fs::create_dir(&product).expect("product directory");
    std::fs::set_permissions(&product, std::fs::Permissions::from_mode(0o700))
        .expect("private product");
    runtime
}

#[test]
fn private_runtime_is_healthy_and_missing_is_unavailable() {
    let runtime = private_runtime();
    let report = inspect_runtime(Some(runtime.path().as_os_str())).expect("report");
    assert_eq!(report.status(), ReportStatus::Healthy);
    assert_eq!(report.checks()[0].status(), CheckStatus::Healthy);

    let missing = tempfile::tempdir().expect("base");
    std::fs::set_permissions(missing.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private base");
    let report = inspect_runtime(Some(missing.path().as_os_str())).expect("report");
    assert_eq!(report.checks()[0].status(), CheckStatus::Unavailable);
    assert!(!missing.path().join("automonique").exists());
}

#[test]
fn relative_and_permissive_paths_fail_without_mutation() {
    let relative = inspect_runtime(Some(std::ffi::OsStr::new("relative"))).expect("report");
    assert_eq!(relative.checks()[0].status(), CheckStatus::Finding);
    let root = inspect_runtime(Some(std::ffi::OsStr::new("/"))).expect("report");
    assert_eq!(root.checks()[0].status(), CheckStatus::Finding);

    let runtime = private_runtime();
    let product = runtime.path().join("automonique");
    std::fs::set_permissions(&product, std::fs::Permissions::from_mode(0o755))
        .expect("permissive mode");
    let report = inspect_runtime(Some(runtime.path().as_os_str())).expect("report");
    assert_eq!(report.checks()[0].status(), CheckStatus::Finding);
    assert_eq!(
        std::fs::metadata(&product)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o755
    );
}

#[test]
fn final_symlink_is_reported_without_following_or_changing_it() {
    let runtime = tempfile::tempdir().expect("runtime");
    std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private base");
    let target = tempfile::tempdir().expect("target");
    std::os::unix::fs::symlink(target.path(), runtime.path().join("automonique")).expect("symlink");
    let report = inspect_runtime(Some(runtime.path().as_os_str())).expect("report");
    assert_eq!(report.checks()[0].status(), CheckStatus::Finding);
    assert!(
        std::fs::symlink_metadata(runtime.path().join("automonique"))
            .expect("metadata")
            .file_type()
            .is_symlink()
    );
}

#[test]
fn base_symlink_and_wrong_type_are_findings() {
    let parent = tempfile::tempdir().expect("parent");
    let target = private_runtime();
    let linked = parent.path().join("runtime-link");
    std::os::unix::fs::symlink(target.path(), &linked).expect("base symlink");
    let report = inspect_runtime(Some(linked.as_os_str())).expect("report");
    assert_eq!(report.checks()[0].status(), CheckStatus::Finding);

    let runtime = tempfile::tempdir().expect("runtime");
    std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private base");
    std::fs::write(runtime.path().join("automonique"), b"not a directory").expect("regular file");
    let report = inspect_runtime(Some(runtime.path().as_os_str())).expect("report");
    assert_eq!(report.checks()[0].status(), CheckStatus::Finding);
}

#[test]
fn non_utf8_argv_is_a_bounded_usage_error() {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run([OsString::from_vec(vec![0xff])], &mut stdout, &mut stderr);
    assert_eq!(exit, 2);
    assert!(stdout.is_empty());
    assert_bounded_usage(&stderr);
}

#[test]
fn argv_rejection_never_reads_past_the_fourth_item() {
    let mut index = 0usize;
    let arguments = std::iter::from_fn(move || {
        index += 1;
        match index {
            1 => Some(OsString::from("doctor")),
            2 => Some(OsString::from("--json")),
            3 => Some(OsString::from("extra")),
            4 => Some(OsString::from("extra-again")),
            _ => panic!("argument parser read beyond its fixed bound"),
        }
    });
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    assert_eq!(run(arguments, &mut stdout, &mut stderr), 2);
    assert!(stdout.is_empty());
    assert_bounded_usage(&stderr);
}

/// Every fact a boundary installer would have changed about the caller.
///
/// Read through `/proc/thread-self`, never `/proc/self`. `no_new_privs`, the
/// seccomp fields, and the mount namespace are per-*thread*, while `/proc/self`
/// reports the thread-group leader. A test runs on a worker thread, so a check
/// that restricted the thread it ran on would be completely invisible in
/// `/proc/self/status` and this test would pass over a real side effect.
///
/// These fields are not touched by any other test in this binary, and a
/// per-thread view is unaffected by tests running in parallel on other threads,
/// so the comparison is sound under the default test harness.
fn restriction_state() -> Vec<Option<String>> {
    let status = |name: &str| {
        std::fs::read_to_string("/proc/thread-self/status")
            .ok()?
            .lines()
            .find_map(|line| line.strip_prefix(name).map(|value| value.trim().to_owned()))
    };
    let link = |path: &str| {
        std::fs::read_link(path)
            .ok()
            .map(|target| target.to_string_lossy().into_owned())
    };
    vec![
        status("NoNewPrivs:"),
        status("Seccomp:"),
        status("Seccomp_filters:"),
        link("/proc/thread-self/ns/user"),
        link("/proc/thread-self/ns/mnt"),
        link("/proc/thread-self/ns/net"),
        link("/proc/thread-self/ns/pid"),
        std::fs::read_to_string("/proc/thread-self/cgroup").ok(),
    ]
}

/// Names directly inside this process's own cgroup, when it can be listed.
///
/// A probe that created a run cgroup to answer the delegation question would
/// leave a directory here, and one that failed to clean up would leave residue.
fn own_cgroup_entries() -> Option<Vec<String>> {
    let membership = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let relative = membership.lines().next()?.strip_prefix("0::")?.to_owned();
    let mut names = std::fs::read_dir(format!(
        "/sys/fs/cgroup/{}",
        relative.trim_start_matches('/')
    ))
    .ok()?
    .filter_map(|entry| Some(entry.ok()?.file_name().to_string_lossy().into_owned()))
    .collect::<Vec<_>>();
    names.sort();
    Some(names)
}

/// No descriptor open in this process is a Landlock ruleset.
///
/// `Ruleset::create` would allocate one; the capability probe stops at the
/// version query and must not. Matching on the link target rather than counting
/// descriptors keeps this correct while other tests in this binary open files.
fn open_landlock_descriptors() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/proc/self/fd") else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| {
            let target = std::fs::read_link(entry.ok()?.path()).ok()?;
            let target = target.to_string_lossy().into_owned();
            target.to_lowercase().contains("landlock").then_some(target)
        })
        .collect()
}

/// The doctor command, end to end, must answer its kernel questions without
/// becoming their answer.
///
/// The capability probe the new checks call is documented side-effect free: it
/// never creates a cgroup, never allocates a ruleset descriptor, never calls
/// `restrict_self`, never sets `PR_SET_NO_NEW_PRIVS`, and never unshares. Each
/// of those is pinned here against the whole `doctor` path rather than against
/// the individual checks, because it is the wired-together report an operator
/// actually runs. The report is also asserted to contain the new checks, so
/// this cannot pass by quietly reporting on a doctor that no longer has them.
#[test]
fn the_whole_doctor_report_is_read_only_with_the_kernel_checks_wired_in() {
    let before = restriction_state();
    let cgroup_before = own_cgroup_entries();

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run(["doctor"], &mut stdout, &mut stderr);

    let after = restriction_state();
    assert_eq!(
        before, after,
        "running doctor changed this process's no_new_privs, seccomp, namespace, or cgroup state"
    );
    assert_eq!(
        cgroup_before,
        own_cgroup_entries(),
        "running doctor created or removed something inside this process's own cgroup"
    );
    assert!(
        open_landlock_descriptors().is_empty(),
        "running doctor left a Landlock ruleset descriptor open: {:?}",
        open_landlock_descriptors()
    );
    assert!(
        std::fs::read_dir("/").is_ok(),
        "running doctor restricted this process's own filesystem view"
    );

    // A doctor that dropped these checks would satisfy every assertion above
    // for the wrong reason, so the report must be shown to still carry them.
    let report = std::str::from_utf8(&stdout).expect("doctor output is UTF-8");
    for code in [
        "kernel.landlock-support",
        "kernel.cgroup-v2.delegation",
        "kernel.cgroup-v2.controllers",
        "kernel.max-user-namespaces-setting",
    ] {
        assert!(
            report.contains(code),
            "the doctor report no longer carries {code}: {report}"
        );
    }
    // Healthy exits 0 and any finding or unavailable check exits 1; which one
    // this host produces is not this test's business.
    assert!(exit <= 1, "doctor exited {exit}");

    // A check with a side effect would not answer the same way twice.
    let mut repeat = Vec::new();
    let mut repeat_stderr = Vec::new();
    assert_eq!(run(["doctor"], &mut repeat, &mut repeat_stderr), exit);
    assert_eq!(
        stdout, repeat,
        "two consecutive doctor runs disagreed, so a check has a side effect"
    );
}
