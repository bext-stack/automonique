// SPDX-License-Identifier: Elastic-2.0

use automonique_lab::canonical_json::{decode_response_for, encode_request};
use automonique_lab::framing::{FrameLimits, decode_frame, encode_frame};
use automonique_lab::protocol::{LabRequest, LabResponse, ObserveRequest, OpaqueId, UnitState};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::Duration;

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
    /// The work item this fixture selected, resolved at build time rather than
    /// named, so a plan change cannot break a worktree test.
    selected_id: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("fixture");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private fixture");
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
        for relative in [
            "tools/fixture.txt",
            "rust/Cargo.toml",
            "rust/Cargo.lock",
            "rust/crates/automonique-lab/fixture.txt",
            "sdk/typescript/packages/lab/fixture.txt",
        ] {
            let target = root.join(relative);
            std::fs::create_dir_all(target.parent().expect("fixture parent"))
                .expect("fixture dirs");
            std::fs::write(target, b"fixture\n").expect("leased fixture");
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
        // Any runnable item with a validated objective. Naming one coupled this
        // fixture to the plan: when GATE-HARNESS froze the harness tail, tests
        // about worktree allocation failed for reasons unrelated to worktrees.
        let objectives_list = objectives["objectives"].as_array().expect("objectives");
        let work = program["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|item| {
                item["runnable"] == true
                    && objectives_list.iter().any(|objective| {
                        objective["work_id"] == item["id"]
                            && objective["autonomous_eligible"] == true
                    })
            })
            .expect("a runnable, autonomous-eligible work item")
            .clone();
        let selected_id = work["id"].as_str().expect("work id").to_owned();
        let objective = objectives_list
            .iter()
            .find(|item| item["work_id"] == selected_id.as_str())
            .expect("objective")
            .clone();
        // Materialise the selected item's own lease rather than one item's
        // paths, so the fixture follows the selection instead of pinning it.
        for path in work["allowed_paths"].as_array().expect("allowed paths") {
            let relative = path.as_str().expect("lease path");
            let target = if relative.ends_with('/') {
                root.join(relative).join("fixture.txt")
            } else {
                root.join(relative)
            };
            std::fs::create_dir_all(target.parent().expect("lease parent")).expect("lease dirs");
            if !target.exists() {
                std::fs::write(&target, b"fixture\n").expect("leased fixture");
            }
        }
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
        let state = json!({"base":base,"branch":"master","deadline_at":"2099-01-01T00:00:00+00:00","driver":"codex_session","failures":0,"iteration":1,"packet":format!(".automonique/state/runs/{RUN}/packet.json"),"packet_sha256":packet_digest,"run_id":RUN,"schema":"automonique.harness-loop-state/v1","started_at":"2026-01-01T00:00:00+00:00","status":"claimed","stop_reason":null,"unchanged_results":0,"updated_at":"2026-01-01T00:00:00+00:00","work_id":selected_id});
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
            selected_id,
        }
    }

    fn run(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_automonique-lab"))
            .current_dir(&self.root)
            .arg("program-select")
            .output()
            .expect("lab command")
    }

    fn admit(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_automonique-lab"))
            .current_dir(&self.root)
            .arg("admit-worktree")
            .output()
            .expect("lab admission command")
    }

    fn runtime_root(&self) -> PathBuf {
        let uid = nix::unistd::Uid::effective().as_raw();
        let canonical = self.root.canonicalize().expect("repository");
        let repository_id = hex::encode(Sha256::digest(std::os::unix::ffi::OsStrExt::as_bytes(
            canonical.as_os_str(),
        )));
        PathBuf::from("/run/user")
            .join(uid.to_string())
            .join("automonique/l")
            .join(repository_id)
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
    assert_eq!(proposal["workId"], fixture.selected_id.as_str());
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

#[test]
fn admitted_cli_allocates_and_replays_the_packet_bound_worktree() {
    let fixture = Fixture::new();
    let runtime = fixture.runtime_root();
    let _ = std::fs::remove_dir_all(&runtime);
    let applied = fixture.admit();
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    assert!(applied.stderr.is_empty());
    let applied: Value = serde_json::from_slice(&applied.stdout).expect("admission JSON");
    assert_eq!(applied["schema"], "automonique.lab-admission/v1");
    assert_eq!(applied["runId"], RUN);
    assert_eq!(applied["workId"], fixture.selected_id.as_str());
    assert_eq!(applied["attempt"]["state"], "paused");
    assert_eq!(applied["worktree"]["state"], "allocated");
    assert_eq!(applied["worktree"]["reconciliation"], "applied");

    let replayed = fixture.admit();
    assert!(
        replayed.status.success(),
        "{}",
        String::from_utf8_lossy(&replayed.stderr)
    );
    let replayed: Value = serde_json::from_slice(&replayed.stdout).expect("replay JSON");
    assert_eq!(
        replayed["attempt"]["revision"],
        applied["attempt"]["revision"]
    );
    assert_eq!(
        replayed["worktree"]["requestDigest"],
        applied["worktree"]["requestDigest"]
    );
    assert_eq!(replayed["worktree"]["reconciliation"], "replayed");

    let mut server = Command::new(env!("CARGO_BIN_EXE_automonique-lab"))
        .current_dir(&fixture.root)
        .arg("serve-admitted-once")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("admitted server");
    let socket = runtime.join("s");
    for _ in 0..500 {
        if socket.exists() {
            break;
        }
        assert!(server.try_wait().expect("server status").is_none());
        thread::sleep(Duration::from_millis(2));
    }
    assert!(socket.exists());
    let request = LabRequest::Observe(
        ObserveRequest::new(
            OpaqueId::new("admitted-observe").expect("request ID"),
            OpaqueId::new("objective:R0-19").expect("objective ID"),
            OpaqueId::new("objective:R0-19").expect("unit ID"),
            0,
            64,
        )
        .expect("observe request"),
    );
    let limits = FrameLimits::new(1024 * 1024).expect("frame limits");
    let payload = encode_request(&request).expect("request payload");
    let frame = encode_frame(&payload, limits).expect("request frame");
    let mut stream = UnixStream::connect(&socket).expect("admitted socket");
    stream.write_all(&frame).expect("request write");
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).expect("response prefix");
    let mut response_frame = prefix.to_vec();
    let mut response_payload = vec![0_u8; u32::from_be_bytes(prefix) as usize];
    stream
        .read_exact(&mut response_payload)
        .expect("response payload");
    response_frame.extend_from_slice(&response_payload);
    let response_payload = decode_frame(&response_frame, limits).expect("response frame");
    let response = decode_response_for(response_payload, &request).expect("response document");
    assert_eq!(
        match response {
            LabResponse::Observed(value) => value.unit().state(),
            _ => panic!("unexpected admitted response"),
        },
        UnitState::Paused
    );
    assert!(server.wait().expect("server wait").success());

    let alternate = fixture._directory.path().join("alternate-runtime");
    let denied = Command::new(env!("CARGO_BIN_EXE_automonique-lab"))
        .current_dir(&fixture.root)
        .args([
            "admit-worktree",
            "--state",
            alternate.to_str().expect("alternate path"),
        ])
        .output()
        .expect("alternate admission");
    assert!(!denied.status.success());
    assert!(!alternate.exists());
    std::fs::remove_dir_all(runtime).expect("runtime cleanup");
}
