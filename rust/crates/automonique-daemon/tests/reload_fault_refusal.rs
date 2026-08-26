// SPDX-License-Identifier: Elastic-2.0

//! A daemon built without `reload-fault-injection` refuses to open while a
//! fault is scripted in its environment.
//!
//! The feature exists for the process-level failure-matrix proofs in the
//! `automonique` binary crate, which enable it as a dev-dependency; every
//! shipping build is built without it, and such a build has no hook, no
//! parser and no fault module at all. What it does have is this refusal:
//! `AUTOMONIQUE_RELOAD_FAULT` present means `Daemon::open` stops before it
//! touches anything durable, under `protocol_refused` /
//! `reload_fault_injection_unavailable`, rather than running a handoff that
//! nobody could tell was meant to be scripted.
//!
//! This file compiles only in a build without the feature — `cargo test -p
//! automonique-daemon` on its own. A workspace-wide test run unifies the
//! feature in through the binary crate's dev-dependency and compiles it to
//! nothing; the feature-enabled counterpart, a malformed script refused by
//! the product binary, is `automonique/tests/reload_failure_matrix.rs`.
//!
//! The variable has to be set in a process's environment and this workspace
//! forbids unsafe code, so the test re-runs itself as a child process with
//! the variable set and asserts on the child's result.
#![cfg(not(feature = "reload-fault-injection"))]

use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;

use automonique_daemon::{Daemon, DaemonConfig, DaemonError, RELOAD_FAULT_ENV};

#[path = "support/isolation.rs"]
mod test_isolation;

const TEST_NAME: &str = "a_build_without_fault_injection_refuses_to_open_while_a_fault_is_scripted";
/// Printed by the child role beside the refusal it observed, so the parent
/// asserts on the branch that ran and not only on the child's exit status.
const MARKER: &str = "[reload_fault_refusal] refused before opening: ";

fn fixture() -> (tempfile::TempDir, DaemonConfig) {
    let root = tempfile::tempdir().expect("temporary root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private root");
    let runtime = root.path().join("runtime");
    test_isolation::assert_isolated_runtime_root(&runtime);
    let state = root.path().join("state");
    std::fs::create_dir(&runtime).expect("runtime root");
    std::fs::create_dir(&state).expect("state root");
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
        .expect("private runtime");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
        .expect("private state");
    (
        root,
        DaemonConfig {
            runtime_root: runtime,
            state_root: state,
        },
    )
}

#[test]
fn a_build_without_fault_injection_refuses_to_open_while_a_fault_is_scripted() {
    if std::env::var_os(RELOAD_FAULT_ENV).is_some() {
        // The child role: a fault is scripted, and this build cannot honour
        // one. Opening refuses before the state directory, the database or
        // the socket exist.
        let (_root, config) = fixture();
        let refused = Daemon::open(&config)
            .err()
            .expect("a scripted fault is refused by a build that cannot inject it");
        assert!(
            matches!(
                refused,
                DaemonError::ProtocolRefused("reload_fault_injection_unavailable")
            ),
            "{refused:?}"
        );
        assert_eq!(refused.category(), "protocol_refused");
        assert!(!config.state_dir().exists(), "nothing durable was created");
        assert!(!config.database_path().exists());
        assert!(!config.admin_socket().exists());
        eprintln!("{MARKER}{refused}");
        return;
    }

    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", TEST_NAME, "--test-threads=1", "--nocapture"])
        .env(RELOAD_FAULT_ENV, "candidate_warm:abort_source")
        .output()
        .expect("child test run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the child did not observe the refusal:\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("test result: ok. 1 passed"),
        "the child ran exactly this test:\n{stdout}"
    );
    assert!(
        stderr.contains(&format!(
            "{MARKER}local administration protocol refused: reload_fault_injection_unavailable"
        )),
        "the child reached the refusal branch:\n{stderr}"
    );
}
