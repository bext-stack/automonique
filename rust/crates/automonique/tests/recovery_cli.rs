// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

#[path = "support/isolation.rs"]
mod test_isolation;

#[test]
fn backup_restore_and_disconnected_start_drill() {
    let root = tempfile::tempdir().expect("root");
    make_private(root.path());
    let source_runtime = root.path().join("source-runtime");
    let source_state = root.path().join("source-state");
    let restored_runtime = root.path().join("restored-runtime");
    let restored_state = root.path().join("restored-state");
    let backup_root = root.path().join("backups");
    for path in [
        &source_runtime,
        &source_state,
        &restored_runtime,
        &restored_state,
    ] {
        fs::create_dir(path).expect("root directory");
        make_private(path);
    }

    let mut source_daemon = launch(&source_runtime, &source_state, false);
    wait_ready(&source_runtime, &source_state);
    assert!(
        run(&source_runtime, &source_state, &["shutdown"])
            .status
            .success()
    );
    assert!(source_daemon.wait().expect("source shutdown").success());
    seed_to_sixteen_databases(&source_state.join("automonique"));

    let backup = run(
        &source_runtime,
        &source_state,
        &[
            "backup",
            "create",
            backup_root.to_str().expect("backup path"),
        ],
    );
    assert!(
        backup.status.success(),
        "{}",
        String::from_utf8_lossy(&backup.stderr)
    );
    let recovery_set = String::from_utf8(backup.stdout)
        .expect("backup path output")
        .trim()
        .to_owned();
    let verified = run(
        &source_runtime,
        &source_state,
        &["backup", "verify", &recovery_set],
    );
    assert!(verified.status.success());
    assert!(String::from_utf8_lossy(&verified.stdout).contains("verified 16 databases"));

    let restore_target = restored_state.join("automonique");
    let clean_host =
        std::env::var_os("AUTOMONIQUE_CLEAN_HOST").as_deref() == Some(std::ffi::OsStr::new("1"));
    let scope = if clean_host {
        "clean-host"
    } else {
        "local-fixture"
    };
    let drill = command(&restored_runtime, &restored_state)
        .env("AUTOMONIQUE_CLEAN_HOST", if clean_host { "1" } else { "0" })
        .args([
            "restore",
            "drill",
            "--scope",
            scope,
            "--from",
            &recovery_set,
            "--into",
            restore_target.to_str().expect("restore path"),
        ])
        .output()
        .expect("restore drill");
    assert!(
        drill.status.success(),
        "{}",
        String::from_utf8_lossy(&drill.stderr)
    );
    let report = String::from_utf8(drill.stdout).expect("drill report");
    assert!(report.contains(&format!("scope={scope}")));
    assert!(report.contains("databases=16"));
    assert!(report.contains(if clean_host {
        "objective_met=true"
    } else {
        "objective_met=not_applicable"
    }));

    write_invalid_transport_configs(&restore_target);
    let mut restored_daemon = launch(&restored_runtime, &restored_state, true);
    wait_ready(&restored_runtime, &restored_state);
    let status = run(&restored_runtime, &restored_state, &["status", "--json"]);
    assert!(status.status.success());
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status JSON");
    assert_eq!(status["accepting_intake"], false);
    assert_eq!(status["telegram_state"], "disabled_no_client");
    assert!(
        run(&restored_runtime, &restored_state, &["shutdown"])
            .status
            .success()
    );
    assert!(restored_daemon.wait().expect("restored shutdown").success());
}

fn seed_to_sixteen_databases(state_dir: &Path) {
    let existing = fs::read_dir(state_dir)
        .expect("state directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.path().extension().and_then(|value| value.to_str()) == Some("sqlite3")
        })
        .count();
    assert!(existing <= 16, "fixture already has {existing} databases");
    for index in existing..16 {
        let connection =
            rusqlite::Connection::open(state_dir.join(format!("recovery-fixture-{index}.sqlite3")))
                .expect("fixture database");
        connection
            .execute("CREATE TABLE fixture (value INTEGER NOT NULL)", [])
            .expect("fixture schema");
        connection
            .execute("INSERT INTO fixture VALUES (?1)", [index])
            .expect("fixture row");
    }
}

fn write_invalid_transport_configs(state_dir: &Path) {
    for (directory, leaf) in [
        ("telegram", "bot.conf"),
        ("slack", "slack.conf"),
        ("support", "fleet.conf"),
    ] {
        let directory = state_dir.join(directory);
        fs::create_dir_all(&directory).expect("config directory");
        make_private(&directory);
        let path = directory.join(leaf);
        fs::write(&path, b"this configuration is deliberately invalid\n").expect("invalid config");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private config");
    }
}

fn launch(runtime: &Path, state: &Path, disconnected: bool) -> Child {
    let mut command = command(runtime, state);
    command.args(["daemon", "--foreground"]);
    if disconnected {
        command.arg("--disconnected-recovery");
    }
    command.spawn().expect("daemon")
}

fn wait_ready(runtime: &Path, state: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if run(runtime, state, &["status", "--json"]).status.success() {
            return;
        }
        assert!(Instant::now() < deadline, "daemon did not become ready");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn run(runtime: &Path, state: &Path, arguments: &[&str]) -> Output {
    command(runtime, state)
        .args(arguments)
        .output()
        .expect("command")
}

fn command(runtime: &Path, state: &Path) -> Command {
    test_isolation::assert_isolated_runtime_root(runtime);
    let mut command = Command::new(env!("CARGO_BIN_EXE_automonique"));
    command
        .env("XDG_RUNTIME_DIR", runtime)
        .env("XDG_STATE_HOME", state)
        .env_remove("AUTOMONIQUE_CONFIG")
        .env_remove("AUTOMONIQUE_HOME");
    command
}

fn make_private(path: &Path) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private directory");
}
