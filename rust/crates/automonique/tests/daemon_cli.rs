// SPDX-License-Identifier: Elastic-2.0

use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Output};
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
    assert!(human.contains("accepting intake: false"), "{human}");

    let json = run(&runtime, &state, &["status", "--json"]);
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).expect("JSON status");
    assert_eq!(value["state"], "ready");
    assert_eq!(value["accepting_intake"], false);
    assert!(
        value["event_cursor"]
            .as_u64()
            .is_some_and(|cursor| cursor >= 1)
    );

    let shutdown = run(&runtime, &state, &["shutdown"]);
    assert!(shutdown.status.success());
    assert_eq!(shutdown.stdout, b"Automonique daemon shutdown accepted\n");
    assert!(daemon.wait().expect("wait daemon").success());
    assert!(!runtime.join("automonique/admin.sock").exists());
    assert!(state.join("automonique/automonique.sqlite3").is_file());
}
