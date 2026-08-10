// SPDX-License-Identifier: Elastic-2.0

use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const RUN: &str = "session_status_fixture_001";

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    state: PathBuf,
    base: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("fixture");
        let root = directory.path().join("repo");
        fs::create_dir_all(root.join(".automonique/state")).expect("state directory");
        fs::write(root.join(".gitignore"), b".automonique/state/\n").expect("ignore");
        git(&root, &["init", "-q"]);
        git(&root, &["config", "user.name", "Fixture"]);
        git(
            &root,
            &["config", "user.email", "fixture@automonique.invalid"],
        );
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "fixture"]);
        let base = git_output(&root, &["rev-parse", "HEAD"]);
        let state = root.join(".automonique/state/harness-loop.json");
        let fixture = Self {
            _directory: directory,
            root,
            state,
            base,
        };
        fixture.write_state("claimed");
        fixture
    }

    fn document(&self, status: &str) -> Value {
        json!({
            "base": self.base,
            "branch": "master",
            "deadline_at": "2099-01-01T00:00:00+00:00",
            "driver": "codex_session",
            "failures": 0,
            "iteration": 1,
            "packet": format!(".automonique/state/runs/{RUN}/packet.json"),
            "packet_sha256": "1".repeat(64),
            "run_id": RUN,
            "schema": "automonique.harness-loop-state/v1",
            "started_at": "2026-01-01T00:00:00+00:00",
            "status": status,
            "stop_reason": null,
            "unchanged_results": 0,
            "updated_at": "2026-01-01T00:00:00+00:00",
            "work_id": "R0-19"
        })
    }

    fn write_state(&self, status: &str) {
        fs::write(
            &self.state,
            serde_json::to_vec_pretty(&self.document(status)).expect("state JSON"),
        )
        .expect("state");
    }

    fn run(&self, extra: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_automonique-lab"))
            .current_dir(self.root.join(".automonique"))
            .arg("harness-status")
            .args(extra)
            .output()
            .expect("status command")
    }
}

fn git(root: &Path, arguments: &[&str]) {
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .status()
            .expect("git")
            .success()
    );
}

fn git_output(root: &Path, arguments: &[&str]) -> String {
    String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .output()
            .expect("git")
            .stdout,
    )
    .expect("UTF-8")
    .trim()
    .to_owned()
}

#[test]
fn current_claim_is_redacted_deterministic_and_read_only() {
    let fixture = Fixture::new();
    let state_before = fs::read(&fixture.state).expect("state before");
    let index = fixture.root.join(".git/index");
    let index_before = fs::read(&index).expect("index before");

    let first = fixture.run(&[]);
    let second = fixture.run(&[]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());
    let status: Value = serde_json::from_slice(&first.stdout).expect("status JSON");
    assert_eq!(status["schema"], "automonique.lab-harness-status/v1");
    assert_eq!(status["status"], "claimed");
    assert_eq!(status["driver"], "codex_session");
    assert_eq!(status["runId"], RUN);
    assert_eq!(status["workId"], "R0-19");
    assert_eq!(status["base"], fixture.base);
    assert!(status.get("branch").is_none());
    assert!(status.get("packet").is_none());
    assert!(status.get("packetPath").is_none());
    assert!(
        !String::from_utf8_lossy(&first.stdout).contains(fixture.root.to_string_lossy().as_ref())
    );

    assert_eq!(fs::read(&fixture.state).expect("state after"), state_before);
    assert_eq!(fs::read(index).expect("index after"), index_before);
    assert!(!fixture.root.join(".git/index.lock").exists());
    assert!(git_output(&fixture.root, &["status", "--porcelain"]).is_empty());
}

#[test]
fn missing_state_is_idle_without_creating_state() {
    let fixture = Fixture::new();
    fs::remove_file(&fixture.state).expect("remove state");
    let output = fixture.run(&[]);
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).expect("idle JSON"),
        json!({"schema":"automonique.lab-harness-status/v1","status":"idle"})
    );
    assert!(!fixture.state.exists());
}

#[test]
fn symlink_oversize_malformed_and_unknown_status_fail_closed() {
    let fixture = Fixture::new();
    let target = fixture._directory.path().join("outside-state.json");
    let target_bytes = serde_json::to_vec(&fixture.document("claimed")).expect("target JSON");
    fs::write(&target, &target_bytes).expect("target");
    fs::remove_file(&fixture.state).expect("remove state");
    symlink(&target, &fixture.state).expect("state symlink");
    let denied = fixture.run(&[]);
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    assert_eq!(fs::read(&target).expect("target after"), target_bytes);
    assert!(!String::from_utf8_lossy(&denied.stderr).contains(target.to_string_lossy().as_ref()));

    fs::remove_file(&fixture.state).expect("remove link");
    fs::write(&fixture.state, vec![b'x'; 32 * 1024 + 1]).expect("oversize state");
    assert!(!fixture.run(&[]).status.success());

    fs::write(&fixture.state, b"{not-json}\n").expect("malformed state");
    assert!(!fixture.run(&[]).status.success());

    fixture.write_state("unknown_future_status");
    let unknown = fixture.run(&[]);
    assert!(!unknown.status.success());
    assert!(unknown.stdout.is_empty());
}

#[test]
fn extra_arguments_and_unknown_fields_are_rejected() {
    let fixture = Fixture::new();
    let extra = fixture.run(&["--state", "/tmp/alternate"]);
    assert!(!extra.status.success());
    assert!(extra.stdout.is_empty());
    assert!(!fixture._directory.path().join("alternate").exists());

    let mut document = fixture.document("claimed");
    document["secret_path"] = json!("/private/example");
    fs::write(
        &fixture.state,
        serde_json::to_vec(&document).expect("unknown-field JSON"),
    )
    .expect("unknown-field state");
    let unknown = fixture.run(&[]);
    assert!(!unknown.status.success());
    assert!(unknown.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&unknown.stderr).contains("/private/example"));
}

#[test]
fn known_text_fields_cannot_be_used_as_a_redaction_bypass() {
    let fixture = Fixture::new();
    for (field, value) in [
        ("branch", "/synthetic/private/path"),
        ("stop_reason", "/synthetic/private/reason"),
        ("updated_at", "/synthetic/private/time"),
    ] {
        let mut document = fixture.document("claimed");
        document[field] = json!(value);
        fs::write(
            &fixture.state,
            serde_json::to_vec(&document).expect("injection JSON"),
        )
        .expect("injection state");
        let denied = fixture.run(&[]);
        assert!(!denied.status.success(), "{field} injection was accepted");
        assert!(denied.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&denied.stderr).contains(value));
    }

    let mut local = fixture.document("stopped");
    let object = local.as_object_mut().expect("state object");
    object.insert("driver".into(), json!("local_process"));
    object.remove("deadline_at");
    object.remove("packet");
    object.remove("packet_sha256");
    object.insert("last_exit_code".into(), json!(-15));
    object.insert("stop_reason".into(), json!("worker_timeout"));
    fs::write(
        &fixture.state,
        serde_json::to_vec(&local).expect("local state JSON"),
    )
    .expect("local state");
    assert!(fixture.run(&[]).status.success());
}
