// SPDX-License-Identifier: Elastic-2.0

//! Immutable code release activation with supervised restart and rollback.
//!
//! This adapter is invoked only after the release challenge moved durable
//! improvement state to `release_approved`. It atomically points `current` at
//! the exact manifest digest, restarts one configured systemd user unit, and
//! restores the prior target if readiness fails. It never builds, downloads,
//! merges, or chooses a unit from model output.

use std::error::Error;
use std::fmt;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_SCHEMA: &str = "automonique.code-release/v1";
const MANIFEST_NAME: &str = "manifest.json";
const RELEASES_NAME: &str = "releases";
const CURRENT_NAME: &str = "current";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const MAX_MANIFEST_BYTES: u64 = 128 * 1024;
const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CHANGED_PATHS: usize = 8_192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseKind {
    SkillOnly,
    Code,
    Mixed,
}

impl ReleaseKind {
    pub fn classify(paths: &[String]) -> Result<Self, ReleaseActivationError> {
        if paths.is_empty() || paths.len() > MAX_CHANGED_PATHS {
            return Err(ReleaseActivationError::InvalidManifest("changed_paths"));
        }
        let mut skills = false;
        let mut code = false;
        for path in paths {
            validate_relative_path(path)?;
            if is_skill_path(path) {
                skills = true;
            } else {
                code = true;
            }
        }
        Ok(match (skills, code) {
            (true, false) => Self::SkillOnly,
            (false, true) => Self::Code,
            (true, true) => Self::Mixed,
            (false, false) => unreachable!("paths are non-empty"),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    source_sha: String,
    plan_digest: String,
    binary_path: String,
    binary_sha256: String,
    changed_paths: Vec<String>,
    #[serde(default)]
    skill_manifest_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCodeRelease {
    pub manifest_digest: String,
    pub source_sha: String,
    pub plan_digest: String,
    pub binary_sha256: String,
    pub kind: ReleaseKind,
    pub skill_manifest_digest: Option<String>,
    release_target: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationReceipt {
    pub release: VerifiedCodeRelease,
    pub previous_target: Option<PathBuf>,
}

pub trait ReleaseSupervisor {
    fn restart(&mut self, unit: &str) -> Result<(), ReleaseActivationError>;
    fn ready(&mut self, unit: &str) -> Result<bool, ReleaseActivationError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemdUserSupervisor;

impl ReleaseSupervisor for SystemdUserSupervisor {
    fn restart(&mut self, unit: &str) -> Result<(), ReleaseActivationError> {
        validate_unit(unit)?;
        let status = Command::new(SYSTEMCTL)
            .args(["--user", "restart", unit])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(ReleaseActivationError::Io)?;
        if status.success() {
            Ok(())
        } else {
            Err(ReleaseActivationError::Supervisor)
        }
    }

    fn ready(&mut self, unit: &str) -> Result<bool, ReleaseActivationError> {
        validate_unit(unit)?;
        Command::new(SYSTEMCTL)
            .args(["--user", "is-active", "--quiet", unit])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .map_err(ReleaseActivationError::Io)
    }
}

pub struct CodeReleaseActivator<S> {
    root: PathBuf,
    unit: String,
    supervisor: S,
}

impl<S: ReleaseSupervisor> CodeReleaseActivator<S> {
    pub fn new(
        root: impl AsRef<Path>,
        unit: &str,
        supervisor: S,
    ) -> Result<Self, ReleaseActivationError> {
        validate_unit(unit)?;
        let root = private_directory(root.as_ref())?;
        let releases = root.join(RELEASES_NAME);
        if !releases.exists() {
            fs::create_dir(&releases).map_err(ReleaseActivationError::Io)?;
            fs::set_permissions(&releases, fs::Permissions::from_mode(0o700))
                .map_err(ReleaseActivationError::Io)?;
        }
        private_directory(&releases)?;
        Ok(Self {
            root,
            unit: unit.to_owned(),
            supervisor,
        })
    }

    /// Select, restart and verify one exact code or mixed release. Skill-only
    /// releases belong to `skill_runtime::activate` and are refused here.
    pub fn activate(
        &mut self,
        expected_manifest_digest: &str,
    ) -> Result<ActivationReceipt, ReleaseActivationError> {
        let release = self.verify(expected_manifest_digest)?;
        if release.kind == ReleaseKind::SkillOnly {
            return Err(ReleaseActivationError::WrongActivator);
        }
        let current = self.root.join(CURRENT_NAME);
        let previous_target = read_current_target(&current)?;
        let state_dir = self
            .root
            .parent()
            .ok_or(ReleaseActivationError::UnsafePath("release root"))?;
        let skill_receipt = match release.kind {
            ReleaseKind::Mixed => Some(
                crate::skill_runtime::activate_with_receipt(
                    state_dir,
                    release.skill_manifest_digest.as_deref().ok_or(
                        ReleaseActivationError::InvalidManifest("skill_manifest_digest"),
                    )?,
                )
                .map_err(|_| ReleaseActivationError::Supervisor)?,
            ),
            ReleaseKind::Code => None,
            ReleaseKind::SkillOnly => return Err(ReleaseActivationError::WrongActivator),
        };
        if let Err(error) = install_link(&self.root, &release.release_target, "activate") {
            if let Some(receipt) = &skill_receipt
                && crate::skill_runtime::rollback(state_dir, receipt).is_err()
            {
                return Err(ReleaseActivationError::RollbackFailed);
            }
            return Err(error);
        }
        let accepted = self.supervisor.restart(&self.unit).is_ok()
            && self.supervisor.ready(&self.unit).unwrap_or(false);
        if accepted {
            return Ok(ActivationReceipt {
                release,
                previous_target,
            });
        }
        restore_link(&self.root, previous_target.as_deref())?;
        let skill_rolled_back = skill_receipt
            .as_ref()
            .is_none_or(|receipt| crate::skill_runtime::rollback(state_dir, receipt).is_ok());
        let rollback_ready = self.supervisor.restart(&self.unit).is_ok()
            && self.supervisor.ready(&self.unit).unwrap_or(false);
        if rollback_ready && skill_rolled_back {
            Err(ReleaseActivationError::ActivationRolledBack)
        } else {
            Err(ReleaseActivationError::RollbackFailed)
        }
    }

    pub fn verify(
        &self,
        expected_manifest_digest: &str,
    ) -> Result<VerifiedCodeRelease, ReleaseActivationError> {
        let digest = expected_manifest_digest
            .strip_prefix("sha256:")
            .ok_or(ReleaseActivationError::InvalidManifest("manifest_digest"))?;
        validate_sha256(digest, "manifest_digest")?;
        let relative = Path::new(RELEASES_NAME).join(digest);
        let release =
            fs::canonicalize(self.root.join(&relative)).map_err(ReleaseActivationError::Io)?;
        if release.parent() != Some(self.root.join(RELEASES_NAME).as_path()) {
            return Err(ReleaseActivationError::UnsafePath("release"));
        }
        private_directory(&release)?;
        let manifest_path = release.join(MANIFEST_NAME);
        let manifest_bytes = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
        if encode_hex(&Sha256::digest(&manifest_bytes)) != digest {
            return Err(ReleaseActivationError::DigestMismatch("manifest"));
        }
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|_| ReleaseActivationError::InvalidManifest("JSON"))?;
        if manifest.schema != MANIFEST_SCHEMA {
            return Err(ReleaseActivationError::InvalidManifest("schema"));
        }
        validate_sha1(&manifest.source_sha, "source_sha")?;
        validate_prefixed_sha256(&manifest.plan_digest, "plan_digest")?;
        validate_sha256(&manifest.binary_sha256, "binary_sha256")?;
        validate_binary_path(&manifest.binary_path)?;
        let binary = release.join(&manifest.binary_path);
        let binary_bytes = read_bounded(&binary, MAX_BINARY_BYTES)?;
        if encode_hex(&Sha256::digest(&binary_bytes)) != manifest.binary_sha256 {
            return Err(ReleaseActivationError::DigestMismatch("binary"));
        }
        let kind = ReleaseKind::classify(&manifest.changed_paths)?;
        match (kind, manifest.skill_manifest_digest.as_deref()) {
            (ReleaseKind::Mixed, Some(digest)) => {
                validate_prefixed_sha256(digest, "skill_manifest_digest")?
            }
            (ReleaseKind::Mixed, None) => {
                return Err(ReleaseActivationError::InvalidManifest(
                    "skill_manifest_digest",
                ));
            }
            (_, Some(_)) => {
                return Err(ReleaseActivationError::InvalidManifest(
                    "skill_manifest_digest",
                ));
            }
            (_, None) => {}
        }
        Ok(VerifiedCodeRelease {
            manifest_digest: expected_manifest_digest.to_owned(),
            source_sha: manifest.source_sha,
            plan_digest: manifest.plan_digest,
            binary_sha256: manifest.binary_sha256,
            kind,
            skill_manifest_digest: manifest.skill_manifest_digest,
            release_target: relative,
        })
    }
}

fn install_link(root: &Path, target: &Path, purpose: &str) -> Result<(), ReleaseActivationError> {
    let temporary = root.join(format!(".current-{purpose}"));
    match fs::symlink_metadata(&temporary) {
        Ok(_) => return Err(ReleaseActivationError::StateConflict),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(ReleaseActivationError::Io(error)),
    }
    symlink(target, &temporary).map_err(ReleaseActivationError::Io)?;
    fs::rename(&temporary, root.join(CURRENT_NAME)).map_err(ReleaseActivationError::Io)?;
    sync_directory(root)
}

fn restore_link(root: &Path, previous: Option<&Path>) -> Result<(), ReleaseActivationError> {
    match previous {
        Some(target) => install_link(root, target, "rollback"),
        None => {
            let current = root.join(CURRENT_NAME);
            if current.exists() || fs::symlink_metadata(&current).is_ok() {
                fs::remove_file(current).map_err(ReleaseActivationError::Io)?;
                sync_directory(root)?;
            }
            Ok(())
        }
    }
}

fn read_current_target(path: &Path) -> Result<Option<PathBuf>, ReleaseActivationError> {
    match fs::read_link(path) {
        Ok(target) => {
            validate_release_target(&target)?;
            Ok(Some(target))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ReleaseActivationError::Io(error)),
    }
}

fn validate_release_target(target: &Path) -> Result<(), ReleaseActivationError> {
    let mut components = target.components();
    if components.next() != Some(Component::Normal(RELEASES_NAME.as_ref())) {
        return Err(ReleaseActivationError::UnsafePath("current target"));
    }
    let Some(Component::Normal(digest)) = components.next() else {
        return Err(ReleaseActivationError::UnsafePath("current target"));
    };
    if components.next().is_some() {
        return Err(ReleaseActivationError::UnsafePath("current target"));
    }
    validate_sha256(
        digest
            .to_str()
            .ok_or(ReleaseActivationError::UnsafePath("current target"))?,
        "current target",
    )
}

fn private_directory(path: &Path) -> Result<PathBuf, ReleaseActivationError> {
    if !path.is_absolute() {
        return Err(ReleaseActivationError::UnsafePath("relative directory"));
    }
    let canonical = fs::canonicalize(path).map_err(ReleaseActivationError::Io)?;
    let metadata = fs::symlink_metadata(&canonical).map_err(ReleaseActivationError::Io)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ReleaseActivationError::UnsafePath("private directory"));
    }
    Ok(canonical)
}

fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, ReleaseActivationError> {
    let metadata = fs::symlink_metadata(path).map_err(ReleaseActivationError::Io)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > max
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ReleaseActivationError::UnsafePath("release file"));
    }
    fs::read(path).map_err(ReleaseActivationError::Io)
}

fn validate_unit(unit: &str) -> Result<(), ReleaseActivationError> {
    if unit.is_empty()
        || unit.len() > 128
        || !unit.ends_with(".service")
        || !unit
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@'))
    {
        return Err(ReleaseActivationError::InvalidField("unit"));
    }
    Ok(())
}

fn validate_binary_path(path: &str) -> Result<(), ReleaseActivationError> {
    let mut components = Path::new(path).components();
    if components.next() != Some(Component::Normal("bin".as_ref()))
        || components.next() != Some(Component::Normal("automonique".as_ref()))
        || components.next().is_some()
    {
        return Err(ReleaseActivationError::InvalidManifest("binary_path"));
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), ReleaseActivationError> {
    if path.is_empty() || path.len() > 1_024 || Path::new(path).is_absolute() {
        return Err(ReleaseActivationError::InvalidManifest("changed_path"));
    }
    for component in Path::new(path).components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(ReleaseActivationError::InvalidManifest("changed_path"));
        }
    }
    Ok(())
}

fn is_skill_path(path: &str) -> bool {
    let mut parts = path.split('/');
    parts.next() == Some("skills")
        && parts.next().is_some_and(|name| !name.is_empty())
        && parts.next().is_some()
}

fn validate_prefixed_sha256(
    value: &str,
    field: &'static str,
) -> Result<(), ReleaseActivationError> {
    validate_sha256(
        value
            .strip_prefix("sha256:")
            .ok_or(ReleaseActivationError::InvalidManifest(field))?,
        field,
    )
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), ReleaseActivationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ReleaseActivationError::InvalidManifest(field));
    }
    Ok(())
}

fn validate_sha1(value: &str, field: &'static str) -> Result<(), ReleaseActivationError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ReleaseActivationError::InvalidManifest(field));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ReleaseActivationError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(ReleaseActivationError::Io)
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
pub enum ReleaseActivationError {
    InvalidField(&'static str),
    InvalidManifest(&'static str),
    UnsafePath(&'static str),
    DigestMismatch(&'static str),
    WrongActivator,
    StateConflict,
    Supervisor,
    ActivationRolledBack,
    RollbackFailed,
    Io(std::io::Error),
}

impl fmt::Display for ReleaseActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => {
                write!(formatter, "invalid release activation field: {field}")
            }
            Self::InvalidManifest(field) => {
                write!(formatter, "invalid code release manifest: {field}")
            }
            Self::UnsafePath(reason) => write!(formatter, "unsafe code release path: {reason}"),
            Self::DigestMismatch(field) => {
                write!(formatter, "code release digest mismatch: {field}")
            }
            Self::WrongActivator => {
                formatter.write_str("skill-only release requires hot activation")
            }
            Self::StateConflict => formatter.write_str("release activation already in progress"),
            Self::Supervisor => formatter.write_str("release supervisor refused restart"),
            Self::ActivationRolledBack => {
                formatter.write_str("release activation failed and was rolled back")
            }
            Self::RollbackFailed => {
                formatter.write_str("release activation and rollback both failed")
            }
            Self::Io(error) => write!(formatter, "release activation I/O error: {error}"),
        }
    }
}

impl Error for ReleaseActivationError {
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
    use std::collections::VecDeque;

    #[derive(Debug)]
    struct FakeSupervisor {
        outcomes: VecDeque<bool>,
        restarts: usize,
    }

    impl ReleaseSupervisor for FakeSupervisor {
        fn restart(&mut self, _unit: &str) -> Result<(), ReleaseActivationError> {
            self.restarts += 1;
            Ok(())
        }
        fn ready(&mut self, _unit: &str) -> Result<bool, ReleaseActivationError> {
            Ok(self.outcomes.pop_front().unwrap_or(false))
        }
    }

    fn add_release(root: &Path, source: char) -> String {
        let binary = format!("automonique-{source}").into_bytes();
        let binary_digest = encode_hex(&Sha256::digest(&binary));
        let source_sha = source.to_string().repeat(40);
        let manifest = format!(
            "{{\"schema\":\"{MANIFEST_SCHEMA}\",\"source_sha\":\"{source_sha}\",\"plan_digest\":\"sha256:{}\",\"binary_path\":\"bin/automonique\",\"binary_sha256\":\"{binary_digest}\",\"changed_paths\":[\"rust/crates/automonique-daemon/src/lib.rs\"]}}",
            "b".repeat(64)
        );
        let digest = encode_hex(&Sha256::digest(manifest.as_bytes()));
        let release = root.join(RELEASES_NAME).join(&digest);
        fs::create_dir_all(release.join("bin")).expect("release");
        for path in [
            root.join(RELEASES_NAME),
            release.clone(),
            release.join("bin"),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private");
        }
        fs::write(release.join(MANIFEST_NAME), manifest).expect("manifest");
        fs::write(release.join("bin/automonique"), binary).expect("binary");
        for file in [release.join(MANIFEST_NAME), release.join("bin/automonique")] {
            fs::set_permissions(file, fs::Permissions::from_mode(0o600)).expect("private file");
        }
        format!("sha256:{digest}")
    }

    #[test]
    fn failed_readiness_restores_the_previous_release_and_restarts_again() {
        let root = tempfile::tempdir().expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private");
        fs::create_dir(root.path().join(RELEASES_NAME)).expect("releases");
        fs::set_permissions(
            root.path().join(RELEASES_NAME),
            fs::Permissions::from_mode(0o700),
        )
        .expect("private");
        let previous = add_release(root.path(), 'a');
        let candidate = add_release(root.path(), 'c');
        let previous_target = Path::new(RELEASES_NAME).join(previous.trim_start_matches("sha256:"));
        symlink(&previous_target, root.path().join(CURRENT_NAME)).expect("current");
        let supervisor = FakeSupervisor {
            outcomes: VecDeque::from([false, true]),
            restarts: 0,
        };
        let mut activator =
            CodeReleaseActivator::new(root.path(), "automonique.service", supervisor)
                .expect("activator");
        assert!(matches!(
            activator.activate(&candidate),
            Err(ReleaseActivationError::ActivationRolledBack)
        ));
        assert_eq!(
            fs::read_link(root.path().join(CURRENT_NAME)).expect("current"),
            previous_target
        );
        assert_eq!(activator.supervisor.restarts, 2);
    }

    #[test]
    fn release_kind_separates_hot_skills_from_code_restart() {
        assert_eq!(
            ReleaseKind::classify(&["skills/plans/SKILL.md".to_owned()]).expect("skills"),
            ReleaseKind::SkillOnly
        );
        assert_eq!(
            ReleaseKind::classify(&["rust/src/lib.rs".to_owned()]).expect("code"),
            ReleaseKind::Code
        );
        assert_eq!(
            ReleaseKind::classify(&[
                "skills/plans/SKILL.md".to_owned(),
                "rust/src/lib.rs".to_owned()
            ])
            .expect("mixed"),
            ReleaseKind::Mixed
        );
    }
}
