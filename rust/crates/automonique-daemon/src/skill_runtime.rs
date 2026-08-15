// SPDX-License-Identifier: Elastic-2.0

//! Immutable, approval-fed skills with read-on-every-run hot reload.
//!
//! Skill releases live below a private state root. `current` is an atomic
//! relative symlink to one digest-named immutable release. Every provider run
//! reopens and re-verifies that target, so a skill-only release becomes active
//! without restarting the daemon while a malformed or partially written bundle
//! fails closed.

use std::error::Error;
use std::fmt;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

const ROOT_NAME: &str = "improvement-skills";
const RELEASES_NAME: &str = "releases";
const CURRENT_NAME: &str = "current";
const MANIFEST_NAME: &str = "manifest.json";
const MANIFEST_SCHEMA: &str = "automonique.skill-release/v1";
const MAX_MANIFEST_BYTES: u64 = 128 * 1024;
const MAX_SKILL_BYTES: u64 = 8 * 1024;
const MAX_TOTAL_SKILL_BYTES: usize = 8 * 1024;
const MAX_SKILLS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveSkills {
    pub manifest_digest: String,
    pub source_sha: String,
    pub plan_digest: String,
    pub instructions: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillActivationReceipt {
    pub active: ActiveSkills,
    previous_target: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    source_sha: String,
    plan_digest: String,
    files: Vec<ManifestFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    path: String,
    sha256: String,
}

/// Load and verify the currently selected skill release.
pub fn load_active(state_dir: &Path) -> Result<Option<ActiveSkills>, SkillRuntimeError> {
    let root = private_root(state_dir)?;
    let current = root.join(CURRENT_NAME);
    let target = match fs::read_link(&current) {
        Ok(target) => target,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(SkillRuntimeError::Io(error)),
    };
    let digest = release_target_digest(&target)?;
    let release = fs::canonicalize(root.join(&target)).map_err(SkillRuntimeError::Io)?;
    let releases = fs::canonicalize(root.join(RELEASES_NAME)).map_err(SkillRuntimeError::Io)?;
    if release.parent() != Some(releases.as_path()) {
        return Err(SkillRuntimeError::UnsafePath(
            "active release escaped releases root",
        ));
    }
    load_release(&release, digest).map(Some).map(|active| {
        active.map(|mut value| {
            value.manifest_digest = format!("sha256:{digest}");
            value
        })
    })
}

/// Atomically select an already materialized immutable release.
///
/// The expected manifest digest is the exact value approved at the release
/// gate. No network or source checkout occurs here.
pub fn activate(
    state_dir: &Path,
    expected_manifest_digest: &str,
) -> Result<ActiveSkills, SkillRuntimeError> {
    activate_with_receipt(state_dir, expected_manifest_digest).map(|receipt| receipt.active)
}

pub fn activate_with_receipt(
    state_dir: &Path,
    expected_manifest_digest: &str,
) -> Result<SkillActivationReceipt, SkillRuntimeError> {
    let digest = expected_manifest_digest
        .strip_prefix("sha256:")
        .ok_or(SkillRuntimeError::InvalidManifest("manifest digest"))?;
    validate_sha256(digest, "manifest digest")?;
    let root = private_root(state_dir)?;
    let previous_target = match fs::read_link(root.join(CURRENT_NAME)) {
        Ok(target) => {
            release_target_digest(&target)?;
            Some(target)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(SkillRuntimeError::Io(error)),
    };
    let release = root.join(RELEASES_NAME).join(digest);
    let release = fs::canonicalize(&release).map_err(SkillRuntimeError::Io)?;
    let mut active = load_release(&release, digest)?;
    let temporary = root.join(format!(".current-{digest}"));
    match fs::symlink_metadata(&temporary) {
        Ok(_) => return Err(SkillRuntimeError::StateConflict),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(SkillRuntimeError::Io(error)),
    }
    symlink(Path::new(RELEASES_NAME).join(digest), &temporary).map_err(SkillRuntimeError::Io)?;
    fs::rename(&temporary, root.join(CURRENT_NAME)).map_err(SkillRuntimeError::Io)?;
    sync_directory(&root)?;
    active.manifest_digest = expected_manifest_digest.to_owned();
    Ok(SkillActivationReceipt {
        active,
        previous_target,
    })
}

pub fn rollback(
    state_dir: &Path,
    receipt: &SkillActivationReceipt,
) -> Result<(), SkillRuntimeError> {
    let root = private_root(state_dir)?;
    let current = root.join(CURRENT_NAME);
    match receipt.previous_target.as_deref() {
        Some(target) => {
            release_target_digest(target)?;
            let temporary = root.join(".current-rollback");
            if fs::symlink_metadata(&temporary).is_ok() {
                return Err(SkillRuntimeError::StateConflict);
            }
            symlink(target, &temporary).map_err(SkillRuntimeError::Io)?;
            fs::rename(&temporary, current).map_err(SkillRuntimeError::Io)?;
        }
        None => match fs::remove_file(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(SkillRuntimeError::Io(error)),
        },
    }
    sync_directory(&root)
}

fn load_release(release: &Path, digest: &str) -> Result<ActiveSkills, SkillRuntimeError> {
    let metadata = fs::metadata(release).map_err(SkillRuntimeError::Io)?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(SkillRuntimeError::UnsafePath("release directory"));
    }
    let manifest_bytes = read_bounded(&release.join(MANIFEST_NAME), MAX_MANIFEST_BYTES)?;
    if encode_hex(&Sha256::digest(&manifest_bytes)) != digest {
        return Err(SkillRuntimeError::DigestMismatch("manifest"));
    }
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| SkillRuntimeError::InvalidManifest("JSON"))?;
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(SkillRuntimeError::InvalidManifest("schema"));
    }
    validate_sha1(&manifest.source_sha, "source_sha")?;
    validate_prefixed_sha256(&manifest.plan_digest, "plan_digest")?;
    if manifest.files.is_empty() || manifest.files.len() > MAX_SKILLS {
        return Err(SkillRuntimeError::InvalidManifest("files"));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut instructions = String::new();
    for file in &manifest.files {
        let skill_name = skill_path(&file.path)?;
        if !seen.insert(file.path.as_str()) {
            return Err(SkillRuntimeError::InvalidManifest("duplicate file"));
        }
        validate_sha256(&file.sha256, "file digest")?;
        let bytes = read_bounded(&release.join(&file.path), MAX_SKILL_BYTES)?;
        if encode_hex(&Sha256::digest(&bytes)) != file.sha256 {
            return Err(SkillRuntimeError::DigestMismatch("skill"));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| SkillRuntimeError::InvalidManifest("skill UTF-8"))?;
        if text.trim().is_empty() || text.contains('\0') {
            return Err(SkillRuntimeError::InvalidManifest("skill content"));
        }
        if instructions.len().saturating_add(text.len()) > MAX_TOTAL_SKILL_BYTES {
            return Err(SkillRuntimeError::InvalidManifest("skill total"));
        }
        instructions.push_str("\n\n[approved_skill name=\"");
        instructions.push_str(skill_name);
        instructions.push_str("\"]\n");
        instructions.push_str(text);
        instructions.push_str("\n[/approved_skill]");
    }
    Ok(ActiveSkills {
        manifest_digest: String::new(),
        source_sha: manifest.source_sha,
        plan_digest: manifest.plan_digest,
        instructions,
    })
}

fn private_root(state_dir: &Path) -> Result<PathBuf, SkillRuntimeError> {
    let metadata = fs::metadata(state_dir).map_err(SkillRuntimeError::Io)?;
    if !state_dir.is_absolute()
        || !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(SkillRuntimeError::UnsafePath("state directory"));
    }
    let root = state_dir.join(ROOT_NAME);
    let releases = root.join(RELEASES_NAME);
    for path in [&root, &releases] {
        if !path.exists() {
            fs::create_dir(path).map_err(SkillRuntimeError::Io)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(SkillRuntimeError::Io)?;
        }
        let metadata = fs::symlink_metadata(path).map_err(SkillRuntimeError::Io)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(SkillRuntimeError::UnsafePath("skills root"));
        }
    }
    Ok(root)
}

fn release_target_digest(target: &Path) -> Result<&str, SkillRuntimeError> {
    let mut components = target.components();
    if components.next() != Some(Component::Normal(RELEASES_NAME.as_ref())) {
        return Err(SkillRuntimeError::UnsafePath("active release target"));
    }
    let Some(Component::Normal(digest)) = components.next() else {
        return Err(SkillRuntimeError::UnsafePath("active release target"));
    };
    if components.next().is_some() {
        return Err(SkillRuntimeError::UnsafePath("active release target"));
    }
    let digest = digest
        .to_str()
        .ok_or(SkillRuntimeError::UnsafePath("active release target"))?;
    validate_sha256(digest, "active release digest")?;
    Ok(digest)
}

fn skill_path(path: &str) -> Result<&str, SkillRuntimeError> {
    let mut parts = path.split('/');
    if parts.next() != Some("skills") {
        return Err(SkillRuntimeError::InvalidManifest("skill path"));
    }
    let name = parts
        .next()
        .ok_or(SkillRuntimeError::InvalidManifest("skill path"))?;
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || parts.next() != Some("SKILL.md")
        || parts.next().is_some()
    {
        return Err(SkillRuntimeError::InvalidManifest("skill path"));
    }
    Ok(name)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, SkillRuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(SkillRuntimeError::Io)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > limit
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(SkillRuntimeError::UnsafePath("release file"));
    }
    fs::read(path).map_err(SkillRuntimeError::Io)
}

fn sync_directory(path: &Path) -> Result<(), SkillRuntimeError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(SkillRuntimeError::Io)
}

fn validate_prefixed_sha256(value: &str, field: &'static str) -> Result<(), SkillRuntimeError> {
    validate_sha256(
        value
            .strip_prefix("sha256:")
            .ok_or(SkillRuntimeError::InvalidManifest(field))?,
        field,
    )
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), SkillRuntimeError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(SkillRuntimeError::InvalidManifest(field));
    }
    Ok(())
}

fn validate_sha1(value: &str, field: &'static str) -> Result<(), SkillRuntimeError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(SkillRuntimeError::InvalidManifest(field));
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[derive(Debug)]
pub enum SkillRuntimeError {
    UnsafePath(&'static str),
    InvalidManifest(&'static str),
    DigestMismatch(&'static str),
    StateConflict,
    Io(std::io::Error),
}

impl fmt::Display for SkillRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafePath(reason) => write!(formatter, "unsafe skill release path: {reason}"),
            Self::InvalidManifest(field) => {
                write!(formatter, "invalid skill release manifest: {field}")
            }
            Self::DigestMismatch(field) => {
                write!(formatter, "skill release digest mismatch: {field}")
            }
            Self::StateConflict => {
                formatter.write_str("skill release activation already in progress")
            }
            Self::Io(error) => write!(formatter, "skill release I/O error: {error}"),
        }
    }
}

impl Error for SkillRuntimeError {
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

    fn release() -> (tempfile::TempDir, String) {
        let state = tempfile::tempdir().expect("state");
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).expect("private");
        let skill = b"---\nname: durable-plans\ndescription: Keep plans durable.\n---\nAlways bind approval to the exact plan.";
        let skill_digest = encode_hex(&Sha256::digest(skill));
        let manifest = format!(
            "{{\"schema\":\"{MANIFEST_SCHEMA}\",\"source_sha\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"plan_digest\":\"sha256:{}\",\"files\":[{{\"path\":\"skills/durable-plans/SKILL.md\",\"sha256\":\"{skill_digest}\"}}]}}",
            "b".repeat(64)
        );
        let digest = encode_hex(&Sha256::digest(manifest.as_bytes()));
        let directory = state
            .path()
            .join(ROOT_NAME)
            .join(RELEASES_NAME)
            .join(&digest);
        fs::create_dir_all(directory.join("skills/durable-plans")).expect("release");
        for ancestor in [
            state.path().join(ROOT_NAME),
            state.path().join(ROOT_NAME).join(RELEASES_NAME),
            directory.clone(),
            directory.join("skills"),
            directory.join("skills/durable-plans"),
        ] {
            fs::set_permissions(ancestor, fs::Permissions::from_mode(0o700)).expect("private");
        }
        fs::write(directory.join(MANIFEST_NAME), manifest).expect("manifest");
        fs::write(directory.join("skills/durable-plans/SKILL.md"), skill).expect("skill");
        for file in [
            directory.join(MANIFEST_NAME),
            directory.join("skills/durable-plans/SKILL.md"),
        ] {
            fs::set_permissions(file, fs::Permissions::from_mode(0o600)).expect("private file");
        }
        (state, format!("sha256:{digest}"))
    }

    #[test]
    fn activation_is_atomic_and_every_load_revalidates_content() {
        let (state, digest) = release();
        let active = activate(state.path(), &digest).expect("activate");
        assert_eq!(active.manifest_digest, digest);
        assert!(active.instructions.contains("Always bind approval"));
        assert_eq!(load_active(state.path()).expect("load"), Some(active));

        let target =
            fs::canonicalize(state.path().join(ROOT_NAME).join(CURRENT_NAME)).expect("target");
        fs::write(target.join("skills/durable-plans/SKILL.md"), b"tampered").expect("tamper");
        assert!(matches!(
            load_active(state.path()),
            Err(SkillRuntimeError::DigestMismatch("skill"))
        ));
    }
}
