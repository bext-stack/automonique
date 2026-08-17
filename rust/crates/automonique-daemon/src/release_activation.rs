// SPDX-License-Identifier: Elastic-2.0

//! Immutable code release activation with supervised restart and rollback.
//!
//! This adapter is invoked only after the release challenge moved durable
//! improvement state to `release_approved`. It atomically points `current` at
//! the exact manifest digest, restarts one configured systemd user unit, and
//! restores the prior target if readiness fails. Before changing the link it
//! proves the supervisor permits an unbounded orderly stop, so accepted work
//! is joined by the daemon rather than killed at a service timeout. It never
//! builds, downloads, merges, or chooses a unit from model output.

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
    #[serde(default)]
    chat_provider_binary_path: Option<String>,
    #[serde(default)]
    chat_provider_binary_sha256: Option<String>,
    #[serde(default)]
    launch_helper_binary_path: Option<String>,
    #[serde(default)]
    launch_helper_binary_sha256: Option<String>,
    #[serde(default)]
    manage_worker_path: Option<String>,
    #[serde(default)]
    manage_worker_sha256: Option<String>,
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

/// The boundary between "a release is approved and chosen" and "how the new
/// code takes over".
///
/// There is one variant, and the point of naming the boundary while there is
/// only one is that the generation handoff specified in
/// `docs/product-plan/requirements/reload-protocol.md` — where the active
/// generation reloads in place and in-flight work survives — becomes a second
/// variant here rather than a second activation path somewhere else.
/// Everything below this line is shared by both and does not move: verifying
/// the release, the atomic `current` link, and the rollback discipline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationMechanism {
    /// Switch the link, restart the supervised unit, verify readiness, and
    /// restore the previous link if readiness fails.
    ///
    /// The daemon's orderly SIGTERM path stops intake and joins accepted work.
    /// Activation admits this mechanism only when the service has an unbounded
    /// stop timeout, preventing the supervisor from converting a long drain
    /// into a kill. A process still cannot survive its own restart, which is
    /// why the improvement worker performs this out of band in a transient
    /// unit — a property of this variant, not of activation.
    SupervisedRestart,
}

impl ActivationMechanism {
    /// The mechanism in use. It stays `SupervisedRestart` until generation
    /// handoff exists to be the other one.
    pub const CURRENT: Self = Self::SupervisedRestart;
}

pub trait ReleaseSupervisor {
    /// Whether an orderly stop may take as long as accepted work needs.
    fn drain_guaranteed(&mut self, unit: &str) -> Result<bool, ReleaseActivationError>;
    fn restart(&mut self, unit: &str) -> Result<(), ReleaseActivationError>;
    fn ready(&mut self, unit: &str) -> Result<bool, ReleaseActivationError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemdUserSupervisor;

impl ReleaseSupervisor for SystemdUserSupervisor {
    fn drain_guaranteed(&mut self, unit: &str) -> Result<bool, ReleaseActivationError> {
        validate_unit(unit)?;
        let output = Command::new(SYSTEMCTL)
            .args([
                "--user",
                "show",
                unit,
                "--property=TimeoutStopUSec",
                "--value",
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(ReleaseActivationError::Io)?;
        Ok(output.status.success() && output.stdout == b"infinity\n")
    }

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

    /// Select, activate and verify one exact code or mixed release through the
    /// current mechanism. Skill-only releases belong to
    /// `skill_runtime::activate` and are refused here.
    pub fn activate(
        &mut self,
        expected_manifest_digest: &str,
    ) -> Result<ActivationReceipt, ReleaseActivationError> {
        self.activate_with(ActivationMechanism::CURRENT, expected_manifest_digest)
    }

    /// The same activation, with the take-over mechanism named explicitly.
    pub fn activate_with(
        &mut self,
        mechanism: ActivationMechanism,
        expected_manifest_digest: &str,
    ) -> Result<ActivationReceipt, ReleaseActivationError> {
        let release = self.verify(expected_manifest_digest)?;
        if release.kind == ReleaseKind::SkillOnly {
            return Err(ReleaseActivationError::WrongActivator);
        }
        if mechanism == ActivationMechanism::SupervisedRestart
            && !self.supervisor.drain_guaranteed(&self.unit)?
        {
            return Err(ReleaseActivationError::DrainNotGuaranteed);
        }
        let current = self.root.join(CURRENT_NAME);
        let previous_target = read_current_target(&current)?;
        // Owned, because the take-over step below needs `&mut self` and a
        // borrow of `self.root` would outlive the point it is taken.
        let state_dir = self
            .root
            .parent()
            .ok_or(ReleaseActivationError::UnsafePath("release root"))?
            .to_path_buf();
        let skill_receipt = match release.kind {
            ReleaseKind::Mixed => Some(
                crate::skill_runtime::activate_with_receipt(
                    &state_dir,
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
                && crate::skill_runtime::rollback(&state_dir, receipt).is_err()
            {
                return Err(ReleaseActivationError::RollbackFailed);
            }
            return Err(error);
        }
        if self.take_over(mechanism) {
            return Ok(ActivationReceipt {
                release,
                previous_target,
            });
        }
        restore_link(&self.root, previous_target.as_deref())?;
        let skill_rolled_back = skill_receipt
            .as_ref()
            .is_none_or(|receipt| crate::skill_runtime::rollback(&state_dir, receipt).is_ok());
        if self.take_over(mechanism) && skill_rolled_back {
            Err(ReleaseActivationError::ActivationRolledBack)
        } else {
            Err(ReleaseActivationError::RollbackFailed)
        }
    }

    /// Hand control to whatever the `current` link now points at, and report
    /// whether it came up. The link is already in place either way, so this is
    /// the only step a second mechanism replaces.
    fn take_over(&mut self, mechanism: ActivationMechanism) -> bool {
        match mechanism {
            ActivationMechanism::SupervisedRestart => {
                self.supervisor.restart(&self.unit).is_ok()
                    && self.supervisor.ready(&self.unit).unwrap_or(false)
            }
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
        match (
            manifest.chat_provider_binary_path.as_deref(),
            manifest.chat_provider_binary_sha256.as_deref(),
        ) {
            (Some(path), Some(digest)) => {
                validate_chat_provider_binary_path(path)?;
                validate_sha256(digest, "chat_provider_binary_sha256")?;
                let bytes = read_bounded(&release.join(path), MAX_BINARY_BYTES)?;
                if encode_hex(&Sha256::digest(&bytes)) != digest {
                    return Err(ReleaseActivationError::DigestMismatch(
                        "chat_provider_binary",
                    ));
                }
            }
            (None, None) => {}
            _ => {
                return Err(ReleaseActivationError::InvalidManifest(
                    "chat_provider_binary",
                ));
            }
        }
        match (
            manifest.launch_helper_binary_path.as_deref(),
            manifest.launch_helper_binary_sha256.as_deref(),
        ) {
            (Some(path), Some(digest)) => {
                validate_launch_helper_binary_path(path)?;
                validate_sha256(digest, "launch_helper_binary_sha256")?;
                let bytes = read_bounded(&release.join(path), MAX_BINARY_BYTES)?;
                if encode_hex(&Sha256::digest(&bytes)) != digest {
                    return Err(ReleaseActivationError::DigestMismatch(
                        "launch_helper_binary",
                    ));
                }
            }
            (None, None) => {}
            _ => {
                return Err(ReleaseActivationError::InvalidManifest(
                    "launch_helper_binary",
                ));
            }
        }
        match (
            manifest.manage_worker_path.as_deref(),
            manifest.manage_worker_sha256.as_deref(),
        ) {
            (Some(path), Some(digest)) => {
                validate_manage_worker_path(path)?;
                validate_sha256(digest, "manage_worker_sha256")?;
                let bytes = read_bounded(&release.join(path), MAX_BINARY_BYTES)?;
                if encode_hex(&Sha256::digest(&bytes)) != digest {
                    return Err(ReleaseActivationError::DigestMismatch("manage_worker"));
                }
            }
            (None, None) => {}
            _ => {
                return Err(ReleaseActivationError::InvalidManifest("manage_worker"));
            }
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

fn validate_chat_provider_binary_path(path: &str) -> Result<(), ReleaseActivationError> {
    let mut components = Path::new(path).components();
    if components.next() != Some(Component::Normal("bin".as_ref()))
        || components.next() != Some(Component::Normal("automonique-chat-provider".as_ref()))
        || components.next().is_some()
    {
        return Err(ReleaseActivationError::InvalidManifest(
            "chat_provider_binary_path",
        ));
    }
    Ok(())
}

fn validate_launch_helper_binary_path(path: &str) -> Result<(), ReleaseActivationError> {
    let mut components = Path::new(path).components();
    if components.next() != Some(Component::Normal("bin".as_ref()))
        || components.next() != Some(Component::Normal("automonique-launch-enter".as_ref()))
        || components.next().is_some()
    {
        return Err(ReleaseActivationError::InvalidManifest(
            "launch_helper_binary_path",
        ));
    }
    Ok(())
}

fn validate_manage_worker_path(path: &str) -> Result<(), ReleaseActivationError> {
    if path != "bin/automonique-manage-worker" {
        return Err(ReleaseActivationError::InvalidManifest(
            "manage_worker_path",
        ));
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
    DrainNotGuaranteed,
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
            Self::DrainNotGuaranteed => formatter
                .write_str("release supervisor does not guarantee an unbounded graceful drain"),
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
        drain_guaranteed: bool,
    }

    impl ReleaseSupervisor for FakeSupervisor {
        fn drain_guaranteed(&mut self, _unit: &str) -> Result<bool, ReleaseActivationError> {
            Ok(self.drain_guaranteed)
        }
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
        let chat_provider = format!("chat-provider-{source}").into_bytes();
        let chat_provider_digest = encode_hex(&Sha256::digest(&chat_provider));
        let launch_helper = format!("launch-helper-{source}").into_bytes();
        let launch_helper_digest = encode_hex(&Sha256::digest(&launch_helper));
        let source_sha = source.to_string().repeat(40);
        let manifest = format!(
            "{{\"schema\":\"{MANIFEST_SCHEMA}\",\"source_sha\":\"{source_sha}\",\"plan_digest\":\"sha256:{}\",\"binary_path\":\"bin/automonique\",\"binary_sha256\":\"{binary_digest}\",\"chat_provider_binary_path\":\"bin/automonique-chat-provider\",\"chat_provider_binary_sha256\":\"{chat_provider_digest}\",\"launch_helper_binary_path\":\"bin/automonique-launch-enter\",\"launch_helper_binary_sha256\":\"{launch_helper_digest}\",\"changed_paths\":[\"rust/crates/automonique-daemon/src/lib.rs\"]}}",
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
        fs::write(release.join("bin/automonique-chat-provider"), chat_provider)
            .expect("chat provider");
        fs::write(release.join("bin/automonique-launch-enter"), launch_helper)
            .expect("launch helper");
        for file in [
            release.join(MANIFEST_NAME),
            release.join("bin/automonique"),
            release.join("bin/automonique-chat-provider"),
            release.join("bin/automonique-launch-enter"),
        ] {
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
            drain_guaranteed: true,
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

    #[derive(Debug)]
    struct RecordingSupervisor {
        calls: Vec<&'static str>,
        readiness: VecDeque<bool>,
    }

    impl ReleaseSupervisor for RecordingSupervisor {
        fn drain_guaranteed(&mut self, _unit: &str) -> Result<bool, ReleaseActivationError> {
            self.calls.push("drain_guaranteed");
            Ok(true)
        }
        fn restart(&mut self, _unit: &str) -> Result<(), ReleaseActivationError> {
            self.calls.push("restart");
            Ok(())
        }
        fn ready(&mut self, _unit: &str) -> Result<bool, ReleaseActivationError> {
            self.calls.push("ready");
            Ok(self.readiness.pop_front().unwrap_or(false))
        }
    }

    /// The seam must not have changed what activation does. This pins the
    /// restart variant's exact supervisor sequence, so a handoff variant added
    /// later cannot quietly alter the one that exists.
    #[test]
    fn the_restart_mechanism_switches_the_link_then_restarts_and_verifies() {
        assert_eq!(
            ActivationMechanism::CURRENT,
            ActivationMechanism::SupervisedRestart,
            "the default entry point must still select the restart mechanism"
        );

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
        let candidate_target =
            Path::new(RELEASES_NAME).join(candidate.trim_start_matches("sha256:"));
        symlink(&previous_target, root.path().join(CURRENT_NAME)).expect("current");

        let mut activator = CodeReleaseActivator::new(
            root.path(),
            "automonique.service",
            RecordingSupervisor {
                calls: Vec::new(),
                readiness: VecDeque::from([true]),
            },
        )
        .expect("activator");
        let receipt = activator
            .activate_with(ActivationMechanism::SupervisedRestart, &candidate)
            .expect("activated");

        assert_eq!(
            activator.supervisor.calls,
            ["drain_guaranteed", "restart", "ready"]
        );
        assert_eq!(
            fs::read_link(root.path().join(CURRENT_NAME)).expect("current"),
            candidate_target
        );
        assert_eq!(receipt.previous_target.as_deref(), Some(&*previous_target));
        assert_eq!(receipt.release.manifest_digest, candidate);
    }

    #[test]
    fn a_bounded_stop_timeout_refuses_before_switching_the_release() {
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
        let mut activator = CodeReleaseActivator::new(
            root.path(),
            "automonique.service",
            FakeSupervisor {
                outcomes: VecDeque::new(),
                restarts: 0,
                drain_guaranteed: false,
            },
        )
        .expect("activator");

        assert!(matches!(
            activator.activate(&candidate),
            Err(ReleaseActivationError::DrainNotGuaranteed)
        ));
        assert_eq!(
            fs::read_link(root.path().join(CURRENT_NAME)).expect("current"),
            previous_target
        );
        assert_eq!(activator.supervisor.restarts, 0);
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
