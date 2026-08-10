// SPDX-License-Identifier: Elastic-2.0

use automonique_lab::program::{ProgramError, select_admitted};
use automonique_lab::protocol::Sha256Digest;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

const HEADER: &[u8] = b"# SPDX-License-Identifier: Elastic-2.0\n";
const RUN: &str = "session_20260810T092429Z_06b042a4";

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    packet: PathBuf,
    base: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("fixture");
        let root = directory.path().join("repo");
        let packet = root.join(format!(".automonique/state/runs/{RUN}/packet.json"));
        std::fs::create_dir_all(packet.parent().expect("packet parent")).expect("state dirs");
        std::fs::create_dir_all(root.join(".automonique/dev/guides")).expect("dev dirs");
        std::fs::create_dir_all(root.join("plan")).expect("plan dirs");
        std::fs::write(root.join(".gitignore"), b".automonique/state/\n").expect("ignore");
        std::fs::write(
            root.join("plan/work-graph.toml"),
            b"[work]\nid='WORK-001'\n",
        )
        .expect("graph");
        std::fs::write(root.join(".automonique/dev/guides/manifest.json"), b"{}\n")
            .expect("guides");
        let graph = digest(&root.join("plan/work-graph.toml"));
        let program = json!({
            "schema":"automonique.dev-program/v1",
            "source":{"graph":"plan/work-graph.toml","graph_sha256":graph.as_str(),"item_count":1},
            "items":[{"id":"WORK-001","epic":"WORK","track":"core","title":"Work","summary":null,
                "depends_on":[],"blocked_by_gates":[],"licence":"Elastic-2.0","allowed_paths":["rust/example.rs"],
                "closes_gate":null,"status":"blocked","contract":"plan/contracts/WORK-001.md","runnable":true}]
        });
        let mut program_bytes = HEADER.to_vec();
        program_bytes.extend(serde_json::to_vec_pretty(&program).expect("program JSON"));
        std::fs::write(root.join(".automonique/dev/program.yaml"), program_bytes).expect("program");
        let objectives = json!({"schema":"automonique.dev-objectives/v1","objectives":[{
            "id":"objective:WORK-001","work_id":"WORK-001","objective":"Produce one bounded proposal.",
            "metric":{"name":"checks","target":1,"anti_regression":"No regression"},
            "baseline":{"value":null,"reason":"Measure base"},
            "budget":{"max_iterations":3,"max_wall_seconds":300,"max_worker_seconds":200,"max_unchanged_results":1,"max_failures":2},
            "tests":["Unit"],"stop_conditions":["Stop on drift"],"hill_climbability":90,
            "autonomous_eligible":true,"allowed_paths":["rust/example.rs"],"licence":"Elastic-2.0","sources":["plan/contracts/WORK-001.md"]
        }]});
        std::fs::write(
            root.join(".automonique/dev/objectives.json"),
            serde_json::to_vec_pretty(&objectives).expect("objectives JSON"),
        )
        .expect("objectives");
        git(&root, &["init", "-q"]);
        git(&root, &["config", "user.name", "Fixture"]);
        git(
            &root,
            &["config", "user.email", "fixture@automonique.invalid"],
        );
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "fixture"]);
        let base = git_output(&root, &["rev-parse", "HEAD"]);
        let fixture = Self {
            _directory: directory,
            root,
            packet,
            base,
        };
        fixture.write_packet(&fixture.base);
        fixture.write_state();
        fixture
    }

    fn write_packet(&self, base: &str) {
        let program = digest(&self.root.join(".automonique/dev/program.yaml"));
        let objectives = digest(&self.root.join(".automonique/dev/objectives.json"));
        let guides = digest(&self.root.join(".automonique/dev/guides/manifest.json"));
        let program_bytes =
            std::fs::read(self.root.join(".automonique/dev/program.yaml")).expect("program bytes");
        let program_document: serde_json::Value =
            serde_json::from_slice(program_bytes.strip_prefix(HEADER).expect("program header"))
                .expect("program document");
        let work = program_document["items"][0].clone();
        let objectives_document: serde_json::Value = serde_json::from_slice(
            &std::fs::read(self.root.join(".automonique/dev/objectives.json"))
                .expect("objectives bytes"),
        )
        .expect("objectives document");
        let objective = objectives_document["objectives"][0].clone();
        let packet = json!({
            "attempt_baseline":{"admission_safety_checks":"pass","git_head":base,"guides_sha256":guides.as_str(),"objectives_sha256":objectives.as_str(),"program_sha256":program.as_str(),"worktree_clean":true},
            "driver":"codex_session","guides_sha256":guides.as_str(),"immutable_base":base,"integration_ceiling":"proposal_only","iteration":1,
            "objective": objective,
            "objectives_sha256":objectives.as_str(),"prior_iteration":null,"program_sha256":program.as_str(),"run_id":RUN,"schema":"automonique.harness-objective-packet/v1",
            "session_coordination":{"native_subagents":true},
            "work_item": work
        });
        std::fs::write(
            &self.packet,
            serde_json::to_vec_pretty(&packet).expect("packet JSON"),
        )
        .expect("packet");
    }

    fn write_state(&self) {
        let state = json!({"base":self.base,"branch":"master","deadline_at":"2099-01-01T00:00:00+00:00","driver":"codex_session","failures":0,"iteration":1,"packet":format!(".automonique/state/runs/{RUN}/packet.json"),"packet_sha256":digest(&self.packet).as_str(),"run_id":RUN,"schema":"automonique.harness-loop-state/v1","started_at":"2026-01-01T00:00:00+00:00","status":"claimed","stop_reason":null,"unchanged_results":0,"updated_at":"2026-01-01T00:00:00+00:00","work_id":"WORK-001"});
        std::fs::write(
            self.root.join(".automonique/state/harness-loop.json"),
            serde_json::to_vec_pretty(&state).expect("state"),
        )
        .expect("state");
    }

    fn select(&self) -> Result<automonique_lab::program::RunnableProposal, ProgramError> {
        static CWD: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = CWD.get_or_init(|| Mutex::new(())).lock().expect("cwd lock");
        let prior = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(&self.root).expect("fixture cwd");
        let result = select_admitted();
        std::env::set_current_dir(prior).expect("restore cwd");
        result
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

fn digest(path: &Path) -> Sha256Digest {
    Sha256Digest::new(hex::encode(Sha256::digest(
        std::fs::read(path).expect("bytes"),
    )))
    .expect("digest")
}

#[test]
fn packet_rooted_selection_binds_every_input_and_does_not_mutate() {
    let fixture = Fixture::new();
    let before = std::fs::read(&fixture.packet).expect("packet");
    let proposal = fixture.select().expect("proposal");
    assert_eq!(proposal.immutable_base().as_str(), fixture.base);
    assert_eq!(proposal.run_id().as_str(), RUN);
    assert_eq!(proposal.work_id().as_str(), "WORK-001");
    assert_eq!(proposal.packet_digest(), &digest(&fixture.packet));
    assert_eq!(
        proposal.graph_digest(),
        &digest(&fixture.root.join("plan/work-graph.toml"))
    );
    assert_eq!(
        proposal.program_digest(),
        &digest(&fixture.root.join(".automonique/dev/program.yaml"))
    );
    assert_eq!(
        proposal.objectives_digest(),
        &digest(&fixture.root.join(".automonique/dev/objectives.json"))
    );
    assert_eq!(
        proposal.guides_digest(),
        &digest(&fixture.root.join(".automonique/dev/guides/manifest.json"))
    );
    assert_eq!(std::fs::read(&fixture.packet).expect("packet"), before);
}

#[test]
fn packet_digest_and_bound_file_drift_fail_closed() {
    let fixture = Fixture::new();
    std::fs::write(&fixture.packet, b"{}\n").expect("drift packet");
    assert_eq!(fixture.select(), Err(ProgramError::PacketDigestMismatch));

    let fixture = Fixture::new();
    std::fs::write(
        fixture.root.join(".automonique/dev/program.yaml"),
        b"drift\n",
    )
    .expect("drift program");
    assert!(fixture.select().is_err());

    let fixture = Fixture::new();
    std::fs::write(
        fixture.root.join(".automonique/dev/objectives.json"),
        b"{}\n",
    )
    .expect("drift objectives");
    assert_eq!(
        fixture.select(),
        Err(ProgramError::InvalidPacket("dirty worktree"))
    );
}

#[test]
fn self_consistent_packet_cannot_redirect_the_graph_path() {
    let fixture = Fixture::new();
    let program_path = fixture.root.join(".automonique/dev/program.yaml");
    let bytes = std::fs::read(&program_path).expect("program");
    let mut document: serde_json::Value =
        serde_json::from_slice(bytes.strip_prefix(HEADER).expect("header")).expect("JSON");
    document["source"]["graph"] = json!("alternate/work-graph.toml");
    let mut changed = HEADER.to_vec();
    changed.extend(serde_json::to_vec_pretty(&document).expect("changed program"));
    std::fs::write(&program_path, changed).expect("program");
    fixture.write_packet(&fixture.base);
    fixture.write_state();
    assert!(fixture.select().is_err());
}

#[test]
fn alternate_graph_and_guides_are_not_admitted_by_a_self_consistent_program() {
    let fixture = Fixture::new();
    std::fs::write(fixture.root.join("plan/work-graph.toml"), b"alternate\n")
        .expect("alternate graph");
    assert!(fixture.select().is_err());

    let fixture = Fixture::new();
    std::fs::write(
        fixture.root.join(".automonique/dev/guides/manifest.json"),
        b"alternate\n",
    )
    .expect("alternate guides");
    assert!(fixture.select().is_err());
}

#[test]
fn base_and_run_path_drift_are_rejected() {
    let fixture = Fixture::new();
    fixture.write_packet("1111111111111111111111111111111111111111");
    fixture.write_state();
    assert!(fixture.select().is_err());

    let fixture = Fixture::new();
    let wrong = fixture
        .root
        .join(".automonique/state/runs/other/packet.json");
    std::fs::create_dir_all(wrong.parent().expect("parent")).expect("dir");
    std::fs::copy(&fixture.packet, &wrong).expect("copy");
    let mut state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture.root.join(".automonique/state/harness-loop.json")).expect("state"),
    )
    .expect("json");
    state["packet"] = json!(format!(".automonique/state/runs/other/packet.json"));
    state["packet_sha256"] = json!(digest(&wrong).as_str());
    std::fs::write(
        fixture.root.join(".automonique/state/harness-loop.json"),
        serde_json::to_vec_pretty(&state).expect("state"),
    )
    .expect("state");
    assert!(fixture.select().is_err());
}

#[test]
fn harness_status_head_and_dirty_tree_fail_closed() {
    let fixture = Fixture::new();
    let state_path = fixture.root.join(".automonique/state/harness-loop.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).expect("state")).expect("state JSON");
    state["status"] = json!("stopped");
    std::fs::write(
        &state_path,
        serde_json::to_vec_pretty(&state).expect("state"),
    )
    .expect("state");
    assert!(fixture.select().is_err());

    let fixture = Fixture::new();
    std::fs::write(fixture.root.join("dirty.txt"), b"dirty\n").expect("dirty");
    assert_eq!(
        fixture.select(),
        Err(ProgramError::InvalidPacket("dirty worktree"))
    );

    let fixture = Fixture::new();
    std::fs::write(fixture.root.join("committed.txt"), b"new head\n").expect("file");
    git(&fixture.root, &["add", "committed.txt"]);
    git(&fixture.root, &["commit", "-qm", "new head"]);
    assert_eq!(
        fixture.select(),
        Err(ProgramError::InvalidPacket("Git base"))
    );
}

#[cfg(unix)]
#[test]
fn repository_fsmonitor_command_is_never_executed() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let marker = fixture._directory.path().join("fsmonitor-ran");
    let script = fixture._directory.path().join("fsmonitor.sh");
    std::fs::write(
        &script,
        format!("#!/bin/sh\nprintf invoked > '{}'\n", marker.display()),
    )
    .expect("script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).expect("script mode");
    git(
        &fixture.root,
        &[
            "config",
            "core.fsmonitor",
            script.to_str().expect("script path"),
        ],
    );

    fixture.select().expect("selection without fsmonitor");
    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
fn symlinked_parent_and_oversize_packet_are_rejected() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let real = fixture.packet.parent().expect("parent").to_path_buf();
    let moved = fixture.root.join(".automonique/state/packet-real");
    std::fs::rename(&real, &moved).expect("move");
    symlink(&moved, &real).expect("symlink");
    assert_eq!(fixture.select(), Err(ProgramError::UnsafeInput));

    std::fs::remove_file(&real).expect("unlink");
    std::fs::rename(&moved, &real).expect("restore");
    std::fs::write(&fixture.packet, vec![b'x'; 64 * 1024 + 1]).expect("oversize");
    fixture.write_state();
    assert_eq!(fixture.select(), Err(ProgramError::InputTooLarge));
}
