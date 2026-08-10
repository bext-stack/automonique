// SPDX-License-Identifier: Elastic-2.0

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const RUN: &str = "session_cli_fixture_001";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repository root")
        .to_path_buf()
}

fn digest(path: &Path) -> String {
    hex::encode(Sha256::digest(std::fs::read(path).expect("input")))
}

struct Fixture {
    _directory: tempfile::TempDir,
    packet: PathBuf,
    packet_digest: String,
    root: PathBuf,
    base: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("fixture");
        let root = directory.path().join("repo");
        let source = repository_root();
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(root.join(".gitignore"), b".automonique/state/\n").expect("ignore");
        for relative in [
            "plan/work-graph.toml",
            ".automonique/dev/program.yaml",
            ".automonique/dev/objectives.json",
            ".automonique/dev/guides/manifest.json",
        ] {
            let target = root.join(relative);
            std::fs::create_dir_all(target.parent().expect("parent")).expect("dirs");
            std::fs::copy(source.join(relative), target).expect("copy generated input");
        }
        let program_bytes =
            std::fs::read(root.join(".automonique/dev/program.yaml")).expect("program");
        let body = program_bytes
            .strip_prefix(b"# SPDX-License-Identifier: Elastic-2.0\n")
            .expect("header");
        let program: Value = serde_json::from_slice(body).expect("program JSON");
        let objectives: Value = serde_json::from_slice(
            &std::fs::read(root.join(".automonique/dev/objectives.json")).expect("objectives"),
        )
        .expect("objectives JSON");
        let work = program["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|item| item["id"] == "R0-19")
            .expect("work")
            .clone();
        let objective = objectives["objectives"]
            .as_array()
            .expect("objectives")
            .iter()
            .find(|item| item["work_id"] == "R0-19")
            .expect("objective")
            .clone();
        let program_sha = digest(&root.join(".automonique/dev/program.yaml"));
        let objectives_sha = digest(&root.join(".automonique/dev/objectives.json"));
        let guides_sha = digest(&root.join(".automonique/dev/guides/manifest.json"));
        git(&root, &["init", "-q"]);
        git(&root, &["config", "user.name", "Fixture"]);
        git(
            &root,
            &["config", "user.email", "fixture@automonique.invalid"],
        );
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "fixture"]);
        let base = git_output(&root, &["rev-parse", "HEAD"]);
        let packet_document = json!({
            "attempt_baseline":{"admission_safety_checks":"pass","git_head":base,"guides_sha256":guides_sha,"objectives_sha256":objectives_sha,"program_sha256":program_sha,"worktree_clean":true},
            "driver":"codex_session","guides_sha256":guides_sha,"immutable_base":base,"integration_ceiling":"proposal_only","iteration":1,
            "objective":objective,"objectives_sha256":objectives_sha,"prior_iteration":null,"program_sha256":program_sha,"run_id":RUN,
            "schema":"automonique.harness-objective-packet/v1","session_coordination":{"native_subagents":true},"work_item":work
        });
        let packet = root.join(format!(".automonique/state/runs/{RUN}/packet.json"));
        std::fs::create_dir_all(packet.parent().expect("packet parent")).expect("packet dirs");
        std::fs::write(
            &packet,
            serde_json::to_vec_pretty(&packet_document).expect("packet JSON"),
        )
        .expect("packet");
        let packet_digest = digest(&packet);
        let state = json!({"base":base,"branch":"master","deadline_at":"2099-01-01T00:00:00+00:00","driver":"codex_session","failures":0,"iteration":1,"packet":format!(".automonique/state/runs/{RUN}/packet.json"),"packet_sha256":packet_digest,"run_id":RUN,"schema":"automonique.harness-loop-state/v1","started_at":"2026-01-01T00:00:00+00:00","status":"claimed","stop_reason":null,"unchanged_results":0,"updated_at":"2026-01-01T00:00:00+00:00","work_id":"R0-19"});
        std::fs::write(
            root.join(".automonique/state/harness-loop.json"),
            serde_json::to_vec_pretty(&state).expect("state"),
        )
        .expect("state");
        Self {
            _directory: directory,
            packet,
            packet_digest,
            root,
            base,
        }
    }

    fn run(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_automonique-lab"))
            .current_dir(&self.root)
            .arg("program-select")
            .output()
            .expect("lab command")
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
    .expect("utf8")
    .trim()
    .to_owned()
}

#[test]
fn immutable_packet_selects_the_exact_generated_work() {
    let fixture = Fixture::new();
    let output = fixture.run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let proposal: Value = serde_json::from_slice(&output.stdout).expect("proposal JSON");
    assert_eq!(proposal["schema"], "automonique.lab-proposal/v1");
    assert_eq!(proposal["immutableBase"], fixture.base);
    assert_eq!(proposal["runId"], RUN);
    assert_eq!(proposal["workId"], "R0-19");
    assert_eq!(proposal["packetSha256"], fixture.packet_digest);
    assert!(
        proposal["graphSha256"]
            .as_str()
            .is_some_and(|value| value.len() == 64)
    );
}

#[test]
fn wrong_digest_and_arbitrary_input_api_are_redacted_denials() {
    let fixture = Fixture::new();
    std::fs::write(&fixture.packet, b"{}\n").expect("packet drift");
    let denied = fixture.run();
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    let error = String::from_utf8(denied.stderr).expect("error");
    assert!(error.contains("program selection denied"));
    assert!(!error.contains(fixture.packet.to_string_lossy().as_ref()));

    let old = Command::new(env!("CARGO_BIN_EXE_automonique-lab"))
        .args([
            "program-select",
            "--program",
            "/tmp/alternate",
            "--objectives",
            "/tmp/alternate",
        ])
        .output()
        .expect("old API");
    assert!(!old.status.success());
    assert!(old.stdout.is_empty());
}
