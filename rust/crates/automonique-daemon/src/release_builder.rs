// SPDX-License-Identifier: Elastic-2.0

//! Host-observed immutable release materialization for tested candidates.

use std::error::Error;
use std::fmt;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::json;
use sha2::{Digest, Sha256};

use automonique_build_identity::DECLARED_REVISION_VARIABLE;

use crate::release_activation::ReleaseKind;

const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_SKILLS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltRelease {
    pub manifest_digest: String,
    pub kind: ReleaseKind,
    pub release_directory: PathBuf,
}

pub fn build_release(
    state_dir: &Path,
    worktree: &Path,
    candidate_sha: &str,
    candidate_tree: &str,
    plan_digest: &str,
    changed_paths: &[String],
) -> Result<BuiltRelease, ReleaseBuildError> {
    private_directory(state_dir)?;
    let worktree = fs::canonicalize(worktree).map_err(ReleaseBuildError::Io)?;
    if !worktree.is_dir() || !worktree.join(".git").exists() {
        return Err(ReleaseBuildError::UnsafePath("worktree"));
    }
    validate_sha1(candidate_sha, "candidate_sha")?;
    validate_sha1(candidate_tree, "candidate_tree")?;
    validate_prefixed_sha256(plan_digest)?;
    if git_text(&worktree, &["rev-parse", "HEAD"])? != candidate_sha
        || git_text(&worktree, &["rev-parse", "HEAD^{tree}"])? != candidate_tree
    {
        return Err(ReleaseBuildError::CandidateMismatch);
    }
    let kind = ReleaseKind::classify(changed_paths)
        .map_err(|_| ReleaseBuildError::InvalidField("changed_paths"))?;
    match kind {
        ReleaseKind::SkillOnly => {
            build_skill_release(state_dir, &worktree, candidate_sha, plan_digest, kind)
        }
        ReleaseKind::Code => build_code_release(
            state_dir,
            &worktree,
            candidate_sha,
            plan_digest,
            changed_paths,
            kind,
            None,
        ),
        ReleaseKind::Mixed => {
            let skills = build_skill_release(
                state_dir,
                &worktree,
                candidate_sha,
                plan_digest,
                ReleaseKind::SkillOnly,
            )?;
            build_code_release(
                state_dir,
                &worktree,
                candidate_sha,
                plan_digest,
                changed_paths,
                kind,
                Some(&skills.manifest_digest),
            )
        }
    }
}

fn build_skill_release(
    state_dir: &Path,
    worktree: &Path,
    candidate_sha: &str,
    plan_digest: &str,
    kind: ReleaseKind,
) -> Result<BuiltRelease, ReleaseBuildError> {
    let skills = collect_skills(worktree)?;
    if skills.is_empty() || skills.len() > MAX_SKILLS {
        return Err(ReleaseBuildError::InvalidField("skills"));
    }
    let files = skills
        .iter()
        .map(|(path, bytes)| {
            json!({
                "path": path,
                "sha256": encode_hex(&Sha256::digest(bytes)),
            })
        })
        .collect::<Vec<_>>();
    let manifest = serde_json::to_vec(&json!({
        "schema": "automonique.skill-release/v1",
        "source_sha": candidate_sha,
        "plan_digest": plan_digest,
        "files": files,
    }))
    .map_err(|_| ReleaseBuildError::InvalidField("manifest"))?;
    let digest = encode_hex(&Sha256::digest(&manifest));
    let releases = state_dir.join("improvement-skills/releases");
    let release = materialize(&releases, &digest, |staging| {
        for (path, bytes) in &skills {
            let target = staging.join(path);
            private_create_dir_all(
                target
                    .parent()
                    .ok_or(ReleaseBuildError::UnsafePath("skill"))?,
            )?;
            write_immutable(&target, bytes)?;
        }
        write_immutable(&staging.join("manifest.json"), &manifest)
    })?;
    Ok(BuiltRelease {
        manifest_digest: format!("sha256:{digest}"),
        kind,
        release_directory: release,
    })
}

fn build_code_release(
    state_dir: &Path,
    worktree: &Path,
    candidate_sha: &str,
    plan_digest: &str,
    changed_paths: &[String],
    kind: ReleaseKind,
    skill_manifest_digest: Option<&str>,
) -> Result<BuiltRelease, ReleaseBuildError> {
    // Every compilation below is told which commit it is building, so the
    // binaries carry that revision themselves rather than depending on the
    // manifest beside them staying attached. The worktree's `HEAD` was already
    // checked against `candidate_sha` above, so this declares a fact rather
    // than overriding one.
    let output = bounded_output(
        Command::new("cargo")
            .current_dir(worktree.join("rust"))
            .env(DECLARED_REVISION_VARIABLE, candidate_sha)
            .args(["build", "--release", "--locked", "-p", "automonique"]),
    )?;
    if !output.status.success() {
        return Err(ReleaseBuildError::BuildFailed);
    }
    let launch_helper_output = bounded_output(
        Command::new("cargo")
            .current_dir(worktree.join("rust"))
            .env(DECLARED_REVISION_VARIABLE, candidate_sha)
            .args([
                "build",
                "--release",
                "--locked",
                "-p",
                "automonique-runner",
                "--bin",
                "automonique-launch-enter",
            ]),
    )?;
    if !launch_helper_output.status.success() {
        return Err(ReleaseBuildError::BuildFailed);
    }
    let chat_provider_target = worktree.join("rust/target/chat-provider-static");
    let chat_provider_output = bounded_output(
        Command::new("cargo")
            .current_dir(worktree.join("rust"))
            .env("CARGO_TARGET_DIR", &chat_provider_target)
            .env(DECLARED_REVISION_VARIABLE, candidate_sha)
            .args([
                "rustc",
                "--release",
                "--locked",
                "-p",
                "automonique-chat-provider",
                "--bin",
                "automonique-chat-provider",
                "--",
                "-C",
                "target-feature=+crt-static",
            ]),
    )?;
    if !chat_provider_output.status.success() {
        return Err(ReleaseBuildError::BuildFailed);
    }
    let binary = worktree.join("rust/target/release/automonique");
    let binary_bytes = fs::read(&binary).map_err(ReleaseBuildError::Io)?;
    if binary_bytes.is_empty() || binary_bytes.len() > 512 * 1024 * 1024 {
        return Err(ReleaseBuildError::InvalidField("binary"));
    }
    let binary_digest = encode_hex(&Sha256::digest(&binary_bytes));
    let chat_provider = chat_provider_target.join("release/automonique-chat-provider");
    let chat_provider_bytes = fs::read(&chat_provider).map_err(ReleaseBuildError::Io)?;
    if chat_provider_bytes.is_empty() || chat_provider_bytes.len() > 512 * 1024 * 1024 {
        return Err(ReleaseBuildError::InvalidField("chat_provider_binary"));
    }
    let chat_provider_digest = encode_hex(&Sha256::digest(&chat_provider_bytes));
    let launch_helper = worktree.join("rust/target/release/automonique-launch-enter");
    let launch_helper_bytes = fs::read(&launch_helper).map_err(ReleaseBuildError::Io)?;
    if launch_helper_bytes.is_empty() || launch_helper_bytes.len() > 512 * 1024 * 1024 {
        return Err(ReleaseBuildError::InvalidField("launch_helper_binary"));
    }
    let launch_helper_digest = encode_hex(&Sha256::digest(&launch_helper_bytes));
    let manage_worker = worktree.join("tools/run_manage_fleet_worker.sh");
    let manage_worker_bytes = fs::read(&manage_worker).map_err(ReleaseBuildError::Io)?;
    if manage_worker_bytes.is_empty() || manage_worker_bytes.len() > 1024 * 1024 {
        return Err(ReleaseBuildError::InvalidField("manage_worker"));
    }
    let manage_worker_digest = encode_hex(&Sha256::digest(&manage_worker_bytes));
    let manifest = serde_json::to_vec(&json!({
        "schema": "automonique.code-release/v1",
        "source_sha": candidate_sha,
        "plan_digest": plan_digest,
        "binary_path": "bin/automonique",
        "binary_sha256": binary_digest,
        "chat_provider_binary_path": "bin/automonique-chat-provider",
        "chat_provider_binary_sha256": chat_provider_digest,
        "launch_helper_binary_path": "bin/automonique-launch-enter",
        "launch_helper_binary_sha256": launch_helper_digest,
        "manage_worker_path": "bin/automonique-manage-worker",
        "manage_worker_sha256": manage_worker_digest,
        "changed_paths": changed_paths,
        "skill_manifest_digest": skill_manifest_digest,
    }))
    .map_err(|_| ReleaseBuildError::InvalidField("manifest"))?;
    let digest = encode_hex(&Sha256::digest(&manifest));
    let releases = state_dir.join("improvement-code/releases");
    let release = materialize(&releases, &digest, |staging| {
        private_create_dir_all(&staging.join("bin"))?;
        write_executable(&staging.join("bin/automonique"), &binary_bytes)?;
        write_executable(
            &staging.join("bin/automonique-chat-provider"),
            &chat_provider_bytes,
        )?;
        write_executable(
            &staging.join("bin/automonique-launch-enter"),
            &launch_helper_bytes,
        )?;
        write_executable(
            &staging.join("bin/automonique-manage-worker"),
            &manage_worker_bytes,
        )?;
        write_immutable(&staging.join("manifest.json"), &manifest)
    })?;
    Ok(BuiltRelease {
        manifest_digest: format!("sha256:{digest}"),
        kind,
        release_directory: release,
    })
}

fn collect_skills(worktree: &Path) -> Result<Vec<(String, Vec<u8>)>, ReleaseBuildError> {
    let root = worktree.join("skills");
    let mut skills = Vec::new();
    if !root.is_dir() {
        return Ok(skills);
    }
    for entry in fs::read_dir(&root).map_err(ReleaseBuildError::Io)? {
        let entry = entry.map_err(ReleaseBuildError::Io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ReleaseBuildError::InvalidField("skill name"))?;
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ReleaseBuildError::InvalidField("skill name"));
        }
        let file = entry.path().join("SKILL.md");
        if !file.is_file() {
            continue;
        }
        let bytes = fs::read(&file).map_err(ReleaseBuildError::Io)?;
        if bytes.is_empty() || bytes.len() > 8 * 1024 {
            return Err(ReleaseBuildError::InvalidField("skill"));
        }
        skills.push((format!("skills/{name}/SKILL.md"), bytes));
    }
    skills.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(skills)
}

fn materialize<F>(releases: &Path, digest: &str, populate: F) -> Result<PathBuf, ReleaseBuildError>
where
    F: FnOnce(&Path) -> Result<(), ReleaseBuildError>,
{
    private_create_dir_all(releases)?;
    let release = releases.join(digest);
    if release.exists() {
        return Ok(release);
    }
    let staging = releases.join(format!(".staging-{digest}"));
    if staging.exists() {
        return Err(ReleaseBuildError::StateConflict);
    }
    private_create_dir_all(&staging)?;
    populate(&staging)?;
    fs::File::open(&staging)
        .and_then(|directory| directory.sync_all())
        .map_err(ReleaseBuildError::Io)?;
    fs::rename(&staging, &release).map_err(ReleaseBuildError::Io)?;
    fs::File::open(releases)
        .and_then(|directory| directory.sync_all())
        .map_err(ReleaseBuildError::Io)?;
    Ok(release)
}

fn private_create_dir_all(path: &Path) -> Result<(), ReleaseBuildError> {
    if !path.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(ReleaseBuildError::Io)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(ReleaseBuildError::Io)
}

fn write_immutable(path: &Path, bytes: &[u8]) -> Result<(), ReleaseBuildError> {
    fs::write(path, bytes).map_err(ReleaseBuildError::Io)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(ReleaseBuildError::Io)?;
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(ReleaseBuildError::Io)
}

fn write_executable(path: &Path, bytes: &[u8]) -> Result<(), ReleaseBuildError> {
    fs::write(path, bytes).map_err(ReleaseBuildError::Io)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(ReleaseBuildError::Io)?;
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(ReleaseBuildError::Io)
}

fn private_directory(path: &Path) -> Result<(), ReleaseBuildError> {
    if !path.is_absolute() {
        return Err(ReleaseBuildError::UnsafePath("state_dir"));
    }
    let metadata = fs::symlink_metadata(path).map_err(ReleaseBuildError::Io)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(ReleaseBuildError::UnsafePath("state_dir"));
    }
    Ok(())
}

fn git_text(repository: &Path, arguments: &[&str]) -> Result<String, ReleaseBuildError> {
    let output = bounded_output(
        Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(arguments),
    )?;
    if !output.status.success() {
        return Err(ReleaseBuildError::CandidateMismatch);
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| ReleaseBuildError::CandidateMismatch)?
        .trim();
    Ok(text.to_owned())
}

fn bounded_output(command: &mut Command) -> Result<Output, ReleaseBuildError> {
    let output = command.output().map_err(ReleaseBuildError::Io)?;
    if output.stdout.len().saturating_add(output.stderr.len()) > MAX_OUTPUT_BYTES {
        return Err(ReleaseBuildError::OutputLimit);
    }
    Ok(output)
}

fn validate_sha1(value: &str, field: &'static str) -> Result<(), ReleaseBuildError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ReleaseBuildError::InvalidField(field));
    }
    Ok(())
}

fn validate_prefixed_sha256(value: &str) -> Result<(), ReleaseBuildError> {
    let Some(value) = value.strip_prefix("sha256:") else {
        return Err(ReleaseBuildError::InvalidField("plan_digest"));
    };
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ReleaseBuildError::InvalidField("plan_digest"));
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Debug)]
pub enum ReleaseBuildError {
    InvalidField(&'static str),
    UnsafePath(&'static str),
    CandidateMismatch,
    BuildFailed,
    StateConflict,
    OutputLimit,
    Io(std::io::Error),
}

impl fmt::Display for ReleaseBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(formatter, "invalid release build field: {field}"),
            Self::UnsafePath(path) => write!(formatter, "unsafe release build path: {path}"),
            Self::CandidateMismatch => formatter.write_str("release candidate no longer matches"),
            Self::BuildFailed => formatter.write_str("release build failed"),
            Self::StateConflict => formatter.write_str("release build is already in progress"),
            Self::OutputLimit => formatter.write_str("release build output exceeded limit"),
            Self::Io(error) => write!(formatter, "release build I/O failed: {error}"),
        }
    }
}

impl Error for ReleaseBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skill_release_is_a_complete_digest_named_snapshot() {
        let state = tempfile::tempdir().expect("state");
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).expect("mode");
        let worktree = tempfile::tempdir().expect("worktree");
        run(Command::new("git").arg("init").arg(worktree.path()));
        fs::create_dir_all(worktree.path().join("skills/example")).expect("skills");
        fs::write(
            worktree.path().join("skills/example/SKILL.md"),
            "---\nname: example\ndescription: Example.\n---\nDo the approved thing.\n",
        )
        .expect("skill");
        run(Command::new("git")
            .arg("-C")
            .arg(worktree.path())
            .args(["add", "--all"]));
        run(Command::new("git")
            .arg("-C")
            .arg(worktree.path())
            .args(["-c", "user.name=test", "-c", "user.email=test.invalid"])
            .args(["commit", "-m", "skill"]));
        let sha = git_text(worktree.path(), &["rev-parse", "HEAD"]).expect("sha");
        let tree = git_text(worktree.path(), &["rev-parse", "HEAD^{tree}"]).expect("tree");
        let release = build_release(
            state.path(),
            worktree.path(),
            &sha,
            &tree,
            &format!("sha256:{}", "b".repeat(64)),
            &["skills/example/SKILL.md".to_owned()],
        )
        .expect("release");
        assert_eq!(release.kind, ReleaseKind::SkillOnly);
        assert!(release.release_directory.join("manifest.json").is_file());
        assert!(
            release
                .release_directory
                .join("skills/example/SKILL.md")
                .is_file()
        );
    }

    #[test]
    fn release_binary_is_owner_executable() {
        let root = tempfile::tempdir().expect("root");
        let binary = root.path().join("automonique");
        write_executable(&binary, b"candidate").expect("write executable");
        assert_eq!(
            fs::metadata(binary).expect("metadata").permissions().mode() & 0o777,
            0o700
        );
    }

    fn run(command: &mut Command) {
        assert!(command.output().expect("command").status.success());
    }
}
