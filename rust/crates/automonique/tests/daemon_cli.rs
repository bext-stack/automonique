// SPDX-License-Identifier: Elastic-2.0

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

fn roots() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let root = tempfile::tempdir().expect("temporary root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private root");
    let runtime = root.path().join("runtime");
    let state = root.path().join("state");
    std::fs::create_dir(&runtime).expect("runtime root");
    std::fs::create_dir(&state).expect("state root");
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
        .expect("private runtime");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
        .expect("private state");
    (root, runtime, state)
}

fn command(runtime: &std::path::Path, state: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_automonique"));
    command
        .env("XDG_RUNTIME_DIR", runtime)
        .env("XDG_STATE_HOME", state)
        .env_remove("AUTOMONIQUE_CONFIG")
        .env_remove("AUTOMONIQUE_HOME");
    command
}

fn launch(runtime: &std::path::Path, state: &std::path::Path) -> Child {
    command(runtime, state)
        .args(["daemon", "--foreground"])
        .spawn()
        .expect("launch daemon")
}

fn run(runtime: &std::path::Path, state: &std::path::Path, args: &[&str]) -> Output {
    command(runtime, state)
        .args(args)
        .output()
        .expect("run client")
}

fn run_with_stdin(
    runtime: &std::path::Path,
    state: &std::path::Path,
    args: &[&str],
    input: &[u8],
) -> Output {
    let mut child = command(runtime, state)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run client");
    child
        .stdin
        .take()
        .expect("client stdin")
        .write_all(input)
        .expect("write client stdin");
    child.wait_with_output().expect("client output")
}

fn wait_ready(runtime: &std::path::Path, state: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let output = run(runtime, state, &["status", "--json"]);
        if output.status.success() {
            return;
        }
        assert!(Instant::now() < deadline, "daemon did not become ready");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn the_product_binary_serves_status_and_shutdown_end_to_end() {
    let (_root, runtime, state) = roots();
    let mut daemon = launch(&runtime, &state);
    wait_ready(&runtime, &state);

    let human = run(&runtime, &state, &["status"]);
    assert!(human.status.success());
    let human = String::from_utf8(human.stdout).expect("UTF-8 status");
    assert!(human.contains("Automonique daemon: ready"), "{human}");
    assert!(human.contains("accepting intake: true"), "{human}");

    let json = run(&runtime, &state, &["status", "--json"]);
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).expect("JSON status");
    assert_eq!(value["state"], "ready");
    assert_eq!(value["accepting_intake"], true);
    assert!(
        value["event_cursor"]
            .as_u64()
            .is_some_and(|cursor| cursor >= 1)
    );

    let accepted = run_with_stdin(
        &runtime,
        &state,
        &["submit", "workspace:test", "cli:test:1"],
        b"synthetic local task",
    );
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    assert_eq!(
        accepted.stdout,
        b"Automonique synthetic task accepted: inbox_id=1 duplicate=false\n"
    );

    let after_first = run(&runtime, &state, &["status", "--json"]);
    assert!(after_first.status.success());
    let after_first: serde_json::Value =
        serde_json::from_slice(&after_first.stdout).expect("status after first execution");
    assert_eq!(after_first["inbox_pending"], 0);
    assert_eq!(after_first["running"], 0);
    assert_eq!(after_first["outbox_pending"], 1);
    let terminal_cursor = after_first["event_cursor"]
        .as_u64()
        .expect("terminal event cursor");

    let duplicate = run_with_stdin(
        &runtime,
        &state,
        &["submit", "workspace:test", "cli:test:1"],
        b"synthetic local task",
    );
    assert!(
        duplicate.status.success(),
        "{}",
        String::from_utf8_lossy(&duplicate.stderr)
    );
    assert_eq!(
        duplicate.stdout,
        b"Automonique synthetic task accepted: inbox_id=1 duplicate=true\n"
    );

    let after_submit = run(&runtime, &state, &["status", "--json"]);
    assert!(after_submit.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&after_submit.stdout).expect("JSON status after submission");
    assert_eq!(value["inbox_pending"], 0);
    assert_eq!(value["running"], 0);
    assert_eq!(value["outbox_pending"], 1);
    assert_eq!(value["event_cursor"], terminal_cursor);

    let shutdown = run(&runtime, &state, &["shutdown"]);
    assert!(shutdown.status.success());
    assert_eq!(shutdown.stdout, b"Automonique daemon shutdown accepted\n");
    assert!(daemon.wait().expect("wait daemon").success());
    assert!(!runtime.join("automonique/admin.sock").exists());
    assert!(state.join("automonique/automonique.sqlite3").is_file());

    // A process restart observes the durable terminal and never creates a
    // second run or fake receipt for the completed input.
    daemon = launch(&runtime, &state);
    wait_ready(&runtime, &state);
    let restarted = run(&runtime, &state, &["status", "--json"]);
    assert!(restarted.status.success());
    let restarted: serde_json::Value =
        serde_json::from_slice(&restarted.stdout).expect("status after restart");
    assert_eq!(restarted["inbox_pending"], 0);
    assert_eq!(restarted["running"], 0);
    assert_eq!(restarted["outbox_pending"], 1);

    // Reusing a stable key with different input fails closed without stopping
    // the daemon or changing the one durable result.
    let conflict = run_with_stdin(
        &runtime,
        &state,
        &["submit", "workspace:test", "cli:test:1"],
        b"changed task",
    );
    assert!(!conflict.status.success());
    let after_conflict = run(&runtime, &state, &["status", "--json"]);
    assert!(after_conflict.status.success());
    let after_conflict: serde_json::Value =
        serde_json::from_slice(&after_conflict.stdout).expect("status after conflict");
    assert_eq!(after_conflict["outbox_pending"], 1);

    // Command-looking fixture text stays inert: the only effects are durable
    // SQLite records in the configured state root.
    let marker = state.join("must-not-exist");
    let command_like = format!("touch {}", marker.display());
    let inert = run_with_stdin(
        &runtime,
        &state,
        &["submit", "workspace:inert", "cli:test:2"],
        command_like.as_bytes(),
    );
    assert!(inert.status.success());
    let failed = run_with_stdin(
        &runtime,
        &state,
        &["submit", "workspace:failure", "cli:test:3"],
        b"fail",
    );
    assert!(failed.status.success());
    let final_status = run(&runtime, &state, &["status", "--json"]);
    assert!(final_status.status.success());
    let final_status: serde_json::Value =
        serde_json::from_slice(&final_status.stdout).expect("final status");
    assert_eq!(final_status["inbox_pending"], 0);
    assert_eq!(final_status["running"], 0);
    assert_eq!(final_status["outbox_pending"], 3);
    assert!(!marker.exists());

    assert!(run(&runtime, &state, &["shutdown"]).status.success());
    assert!(daemon.wait().expect("wait restarted daemon").success());
    let store = automonique_store::Store::open(state.join("automonique/automonique.sqlite3"))
        .expect("inspect durable state");
    assert_eq!(store.run_snapshot(1).expect("first run").state, "succeeded");
    assert_eq!(store.run_snapshot(2).expect("inert run").state, "succeeded");
    assert_eq!(store.run_snapshot(3).expect("failed run").state, "failed");
    for outbox_id in 1..=3 {
        let outbox = store.outbox_snapshot(outbox_id).expect("fake receipt");
        assert_eq!(outbox.kind, "fake.receipt");
        assert_eq!(outbox.state, "pending");
    }
}
