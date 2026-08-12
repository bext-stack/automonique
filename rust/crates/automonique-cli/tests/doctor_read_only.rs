// SPDX-License-Identifier: Elastic-2.0

use automonique_cli::{inspect_runtime, run};
use automonique_protocol::{CheckStatus, ReportStatus};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;

const USAGE: &[u8] = b"usage: automonique doctor [--json]\n       automonique status [--json]\n       automonique submit <scope> <idempotency-key> < task.txt\n       automonique shutdown\n";

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
    assert_eq!(stderr, USAGE);
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
    assert_eq!(stderr, USAGE);
}
