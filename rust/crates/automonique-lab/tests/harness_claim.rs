// SPDX-License-Identifier: Elastic-2.0

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    base: String,
    /// The work item this fixture claims, resolved from the copied program and
    /// objectives rather than named, so a plan change cannot break a claim test.
    selected_id: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private fixture");
        let root = directory.path().join("repo");
        fs::create_dir_all(&root).expect("repository");
        fs::write(root.join(".gitignore"), b".automonique/state/\n").expect("ignore state");
        let source = repository_root();
        for relative in [
            "plan/work-graph.toml",
            ".automonique/dev/program.yaml",
            ".automonique/dev/objectives.json",
            ".automonique/dev/guides/manifest.json",
            ".automonique/dev/loop.json",
        ] {
            let destination = root.join(relative);
            fs::create_dir_all(destination.parent().expect("input parent"))
                .expect("input directories");
            fs::copy(source.join(relative), destination).expect("copy generated input");
        }
        for relative in ["plan/check.py", "tools/program.py", "tools/guides.py"] {
            let destination = root.join(relative);
            fs::create_dir_all(destination.parent().expect("check parent"))
                .expect("check directories");
            fs::write(destination, b"raise SystemExit(0)\n").expect("fixed check");
        }
        git(&root, &["init", "-q"]);
        git(&root, &["config", "user.name", "Fixture"]);
        git(
            &root,
            &["config", "user.email", "fixture@automonique.invalid"],
        );
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "fixture"]);
        let base = git_output(&root, &["rev-parse", "HEAD"]);
        let selected_id = selectable_work_id(&root);
        Self {
            _directory: directory,
            root,
            base,
            selected_id,
        }
    }

    fn replace_check(&self, relative: &str, body: &[u8]) {
        fs::write(self.root.join(relative), body).expect("replace check");
        git(&self.root, &["add", relative]);
        git(&self.root, &["commit", "-qm", "replace check"]);
    }

    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_automonique-lab"))
            .current_dir(self.root.join(".automonique/dev/guides"))
            .args(arguments)
            .output()
            .expect("lab command")
    }

    fn claim(&self) -> Output {
        self.run(&["harness-claim", "--item", &self.selected_id])
    }
}

/// A claimable item: runnable, with an autonomous-eligible objective. Naming
/// one coupled this fixture to the plan, so freezing a gate broke claim tests
/// for reasons unrelated to claims. The *last* such item is taken so `--item`
/// still has to be honoured — the default selection would return the first.
fn selectable_work_id(root: &Path) -> String {
    let program = fs::read(root.join(".automonique/dev/program.yaml")).expect("program");
    let program: Value = serde_json::from_slice(
        program
            .strip_prefix(b"# SPDX-License-Identifier: Elastic-2.0\n")
            .expect("program header"),
    )
    .expect("program JSON");
    let objectives: Value = serde_json::from_slice(
        &fs::read(root.join(".automonique/dev/objectives.json")).expect("objectives"),
    )
    .expect("objectives JSON");
    let objectives = objectives["objectives"].as_array().expect("objectives");
    program["items"]
        .as_array()
        .expect("items")
        .iter()
        .rev()
        .find(|item| {
            item["runnable"] == true
                && objectives.iter().any(|objective| {
                    objective["work_id"] == item["id"] && objective["autonomous_eligible"] == true
                })
        })
        .expect("a runnable, autonomous-eligible work item")["id"]
        .as_str()
        .expect("work id")
        .to_owned()
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repository root")
        .to_path_buf()
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
            .expect("git output")
            .stdout,
    )
    .expect("UTF-8")
    .trim()
    .to_owned()
}

fn digest(path: &Path) -> String {
    hex::encode(Sha256::digest(fs::read(path).expect("digest input")))
}

#[test]
fn operational_claim_is_accepted_by_rust_status_and_selection() {
    let fixture = Fixture::new();
    let index = fixture.root.join(".git/index");
    let index_before = fs::read(&index).expect("index before");
    let program = fixture.root.join(".automonique/dev/program.yaml");
    let program_before = fs::read(&program).expect("program before");

    let claimed = fixture.claim();
    assert!(
        claimed.status.success(),
        "{}",
        String::from_utf8_lossy(&claimed.stderr)
    );
    assert!(claimed.stderr.is_empty());
    let receipt: Value = serde_json::from_slice(&claimed.stdout).expect("claim receipt");
    assert_eq!(receipt["schema"], "automonique.lab-harness-claim/v1");
    assert_eq!(receipt["status"], "claimed");
    assert_eq!(receipt["driver"], "codex_session");
    assert_eq!(receipt["workId"], fixture.selected_id.as_str());
    assert_eq!(receipt["integrationCeiling"], "proposal_only");
    assert!(
        receipt["runId"]
            .as_str()
            .is_some_and(|value| value.starts_with("session_") && value.len() == 33)
    );

    let packet_relative = receipt["packetPath"].as_str().expect("packet path");
    let packet = fixture.root.join(packet_relative);
    assert_eq!(receipt["packetSha256"], digest(&packet));
    assert_eq!(
        fs::metadata(&packet)
            .expect("packet metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let status = fixture.run(&["harness-status"]);
    assert!(status.status.success());
    let status: Value = serde_json::from_slice(&status.stdout).expect("status JSON");
    assert_eq!(status["status"], "claimed");
    assert_eq!(status["workId"], fixture.selected_id.as_str());
    assert_eq!(status["base"], fixture.base);
    assert_eq!(status["runId"], receipt["runId"]);

    let selected = fixture.run(&["program-select"]);
    assert!(
        selected.status.success(),
        "{}",
        String::from_utf8_lossy(&selected.stderr)
    );
    let selected: Value = serde_json::from_slice(&selected.stdout).expect("proposal JSON");
    assert_eq!(selected["workId"], fixture.selected_id.as_str());
    assert_eq!(selected["immutableBase"], fixture.base);
    assert_eq!(selected["runId"], receipt["runId"]);
    assert_eq!(selected["packetSha256"], receipt["packetSha256"]);

    assert_eq!(fs::read(index).expect("index after"), index_before);
    assert_eq!(fs::read(program).expect("program after"), program_before);
    assert!(git_output(&fixture.root, &["status", "--porcelain"]).is_empty());
}

#[test]
fn nonzero_and_output_limit_checks_fail_before_publication() {
    let nonzero = Fixture::new();
    nonzero.replace_check("plan/check.py", b"raise SystemExit(17)\n");
    let denied = nonzero.claim();
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("harness claim denied"));
    assert!(!nonzero.root.join(".automonique/state").exists());
    assert!(git_output(&nonzero.root, &["status", "--porcelain"]).is_empty());

    let noisy = Fixture::new();
    noisy.replace_check(
        "plan/check.py",
        b"import sys\nsys.stdout.write('x' * 300000)\n",
    );
    let denied = noisy.claim();
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("harness claim denied"));
    assert!(!noisy.root.join(".automonique/state").exists());
    assert!(git_output(&noisy.root, &["status", "--porcelain"]).is_empty());
}

#[test]
fn dirty_repository_and_caller_supplied_surfaces_are_denied() {
    let dirty = Fixture::new();
    fs::write(dirty.root.join("unleased.txt"), b"dirty\n").expect("dirty fixture");
    let denied = dirty.claim();
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    assert!(!dirty.root.join(".automonique/state").exists());

    let alternate = Fixture::new();
    let outside = alternate._directory.path().join("outside-state");
    let denied = alternate.run(&[
        "harness-claim",
        "--state",
        outside.to_str().expect("outside path"),
    ]);
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    assert!(!outside.exists());
    assert!(!alternate.root.join(".automonique/state").exists());

    let denied = alternate.run(&[
        "harness-claim",
        "--item",
        &alternate.selected_id,
        "--check",
        "/tmp/arbitrary",
    ]);
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    assert!(!alternate.root.join(".automonique/state").exists());
}
