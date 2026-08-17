// SPDX-License-Identifier: Elastic-2.0

//! Owner-operated immutable release build and activation.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Output, Stdio};

use automonique_daemon::release_activation::{CodeReleaseActivator, SystemdUserSupervisor};
use automonique_daemon::release_builder::{BuiltRelease, build_release};

const MAX_GIT_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Eq, PartialEq)]
enum OperatorCommand {
    Build {
        state_dir: PathBuf,
        worktree: PathBuf,
        plan_digest: String,
        changed_paths: Vec<String>,
    },
    Activate {
        state_dir: PathBuf,
        unit: String,
        manifest_digest: String,
    },
    Deploy {
        state_dir: PathBuf,
        worktree: PathBuf,
        unit: String,
        plan_digest: String,
        changed_paths: Vec<String>,
    },
}

struct SourceSnapshot {
    sha: String,
    tree: String,
}

fn main() -> ExitCode {
    match parse(std::env::args_os().skip(1).collect()).and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(category) => {
            eprintln!("automonique-release refused: {category}");
            ExitCode::FAILURE
        }
    }
}

fn parse(arguments: Vec<OsString>) -> Result<OperatorCommand, &'static str> {
    match arguments.as_slice() {
        [
            verb,
            state_flag,
            state_dir,
            worktree_flag,
            worktree,
            plan_flag,
            plan_digest,
            rest @ ..,
        ] if verb == "build"
            && state_flag == "--state-dir"
            && worktree_flag == "--worktree"
            && plan_flag == "--plan-digest" =>
        {
            Ok(OperatorCommand::Build {
                state_dir: PathBuf::from(state_dir),
                worktree: PathBuf::from(worktree),
                plan_digest: utf8(plan_digest, "plan_digest")?,
                changed_paths: parse_changed_paths(rest)?,
            })
        }
        [
            verb,
            state_flag,
            state_dir,
            unit_flag,
            unit,
            manifest_flag,
            manifest,
        ] if verb == "activate"
            && state_flag == "--state-dir"
            && unit_flag == "--unit"
            && manifest_flag == "--manifest" =>
        {
            Ok(OperatorCommand::Activate {
                state_dir: PathBuf::from(state_dir),
                unit: utf8(unit, "unit")?,
                manifest_digest: utf8(manifest, "manifest")?,
            })
        }
        [
            verb,
            state_flag,
            state_dir,
            worktree_flag,
            worktree,
            unit_flag,
            unit,
            plan_flag,
            plan_digest,
            rest @ ..,
        ] if verb == "deploy"
            && state_flag == "--state-dir"
            && worktree_flag == "--worktree"
            && unit_flag == "--unit"
            && plan_flag == "--plan-digest" =>
        {
            Ok(OperatorCommand::Deploy {
                state_dir: PathBuf::from(state_dir),
                worktree: PathBuf::from(worktree),
                unit: utf8(unit, "unit")?,
                plan_digest: utf8(plan_digest, "plan_digest")?,
                changed_paths: parse_changed_paths(rest)?,
            })
        }
        _ => Err("usage"),
    }
}

fn parse_changed_paths(arguments: &[OsString]) -> Result<Vec<String>, &'static str> {
    if arguments.is_empty() || !arguments.len().is_multiple_of(2) {
        return Err("changed_paths");
    }
    arguments
        .chunks_exact(2)
        .map(|pair| {
            if pair[0] != "--changed-path" {
                return Err("changed_paths");
            }
            utf8(&pair[1], "changed_paths")
        })
        .collect()
}

fn utf8(value: &OsStr, field: &'static str) -> Result<String, &'static str> {
    value.to_str().map(str::to_owned).ok_or(field)
}

fn run(command: OperatorCommand) -> Result<(), &'static str> {
    match command {
        OperatorCommand::Build {
            state_dir,
            worktree,
            plan_digest,
            changed_paths,
        } => {
            let release = build(&state_dir, &worktree, &plan_digest, &changed_paths)?;
            print_release(&release);
            Ok(())
        }
        OperatorCommand::Activate {
            state_dir,
            unit,
            manifest_digest,
        } => activate(&state_dir, &unit, &manifest_digest),
        OperatorCommand::Deploy {
            state_dir,
            worktree,
            unit,
            plan_digest,
            changed_paths,
        } => {
            let release = build(&state_dir, &worktree, &plan_digest, &changed_paths)?;
            require_idle_runtime(&state_dir)?;
            activate(&state_dir, &unit, &release.manifest_digest)
        }
    }
}

fn build(
    state_dir: &Path,
    worktree: &Path,
    plan_digest: &str,
    changed_paths: &[String],
) -> Result<BuiltRelease, &'static str> {
    let source = clean_source_snapshot(worktree)?;
    build_release(
        state_dir,
        worktree,
        &source.sha,
        &source.tree,
        plan_digest,
        changed_paths,
    )
    .map_err(|_| "release_build")
}

fn clean_source_snapshot(worktree: &Path) -> Result<SourceSnapshot, &'static str> {
    if !worktree.is_absolute() {
        return Err("worktree");
    }
    let status = git(
        worktree,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if !status.stdout.is_empty() {
        return Err("dirty_worktree");
    }
    let sha = git_line(worktree, &["rev-parse", "HEAD"])?;
    let tree = git_line(worktree, &["rev-parse", "HEAD^{tree}"])?;
    Ok(SourceSnapshot { sha, tree })
}

fn git(worktree: &Path, arguments: &[&str]) -> Result<Output, &'static str> {
    let output = Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "git")?;
    if !output.status.success()
        || output.stdout.len().saturating_add(output.stderr.len()) > MAX_GIT_OUTPUT_BYTES
    {
        return Err("git");
    }
    Ok(output)
}

fn git_line(worktree: &Path, arguments: &[&str]) -> Result<String, &'static str> {
    let output = git(worktree, arguments)?;
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|_| "git")?
        .trim();
    if value.is_empty() || value.lines().count() != 1 {
        return Err("git");
    }
    Ok(value.to_owned())
}

fn require_idle_runtime(state_dir: &Path) -> Result<(), &'static str> {
    let state_home = state_dir.parent().ok_or("state_dir")?;
    let current = state_dir.join("improvement-code/current/bin/automonique");
    let output = Command::new(current)
        .args(["status", "--json"])
        .env("XDG_STATE_HOME", state_home)
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "runtime_status")?;
    if !output.status.success() || output.stdout.len() > MAX_GIT_OUTPUT_BYTES {
        return Err("runtime_status");
    }
    idle_status(&output.stdout)
}

fn idle_status(bytes: &[u8]) -> Result<(), &'static str> {
    let status: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| "runtime_status")?;
    let zero =
        |pointer: &str| status.pointer(pointer).and_then(serde_json::Value::as_u64) == Some(0);
    if status.get("state").and_then(serde_json::Value::as_str) != Some("ready")
        || status
            .get("accepting_intake")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        || !zero("/running")
        || !zero("/inbox_pending")
        || !zero("/outbox_pending")
        || !zero("/operational/outbox_in_flight_ambiguous")
        || !zero("/operational/outbox_in_flight_live")
        || !zero("/operational/reconciliation_pending")
    {
        return Err("runtime_not_idle");
    }
    Ok(())
}

fn activate(state_dir: &Path, unit: &str, manifest_digest: &str) -> Result<(), &'static str> {
    let root = state_dir.join("improvement-code");
    let mut activator = CodeReleaseActivator::new(root, unit, SystemdUserSupervisor)
        .map_err(|_| "release_activation")?;
    let receipt = activator
        .activate(manifest_digest)
        .map_err(|_| "release_activation")?;
    println!("source_sha={}", receipt.release.source_sha);
    println!("manifest_digest={}", receipt.release.manifest_digest);
    Ok(())
}

fn print_release(release: &BuiltRelease) {
    println!("manifest_digest={}", release.manifest_digest);
    println!("release_directory={}", release.release_directory.display());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn arguments_are_closed_to_build_activate_and_deploy() {
        let build = parse(vec![
            "build".into(),
            "--state-dir".into(),
            "/private/state".into(),
            "--worktree".into(),
            "/workspace".into(),
            "--plan-digest".into(),
            format!("sha256:{}", "a".repeat(64)).into(),
            "--changed-path".into(),
            "rust/example.rs".into(),
        ])
        .expect("build");
        assert!(matches!(build, OperatorCommand::Build { .. }));

        let activate = parse(vec![
            "activate".into(),
            "--state-dir".into(),
            "/private/state".into(),
            "--unit".into(),
            "automonique.service".into(),
            "--manifest".into(),
            format!("sha256:{}", "b".repeat(64)).into(),
        ])
        .expect("activate");
        assert!(matches!(activate, OperatorCommand::Activate { .. }));

        assert_eq!(parse(vec!["deploy".into()]), Err("usage"));
    }

    #[test]
    fn idle_status_requires_every_restart_gate_to_be_clean() {
        let ready = br#"{"state":"ready","accepting_intake":true,"running":0,"inbox_pending":0,"outbox_pending":0,"operational":{"outbox_in_flight_ambiguous":0,"outbox_in_flight_live":0,"reconciliation_pending":0}}"#;
        assert_eq!(idle_status(ready), Ok(()));
        for pointer in ["running", "inbox_pending", "outbox_pending"] {
            let dirty = String::from_utf8(ready.to_vec()).expect("json").replacen(
                &format!("\"{pointer}\":0"),
                &format!("\"{pointer}\":1"),
                1,
            );
            assert_eq!(idle_status(dirty.as_bytes()), Err("runtime_not_idle"));
        }
    }

    #[test]
    fn source_snapshot_refuses_uncommitted_bytes() {
        let repository = tempfile::tempdir().expect("repository");
        run_git(repository.path(), &["init"]);
        run_git(repository.path(), &["config", "user.name", "test"]);
        run_git(repository.path(), &["config", "user.email", "test.invalid"]);
        fs::write(repository.path().join("one.txt"), "one").expect("source");
        run_git(repository.path(), &["add", "one.txt"]);
        run_git(repository.path(), &["commit", "-m", "one"]);

        clean_source_snapshot(repository.path()).expect("clean snapshot");

        fs::write(repository.path().join("two.txt"), "two").expect("dirty source");
        assert_eq!(
            clean_source_snapshot(repository.path()).err(),
            Some("dirty_worktree")
        );
    }

    fn run_git(repository: &Path, arguments: &[&str]) {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(repository)
                .args(arguments)
                .status()
                .expect("git")
                .success()
        );
    }
}
