// SPDX-License-Identifier: Elastic-2.0

//! Host composition for the approved-plan lab, release builder and publisher.

use std::error::Error;
use std::fmt;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use automonique_github_connector::RepoTarget;
use automonique_lab::improvement_executor::{
    CodexRuntimePin, ImprovementExecutionReceipt, ImprovementExecutionRequest, ImprovementExecutor,
    PinnedCodexAgent, VerificationProfile,
};
use automonique_store::improvements::ImprovementRecord;
use serde::Deserialize;

use crate::improvement_publish::{CandidatePublisher, CandidatePushReceipt};
use crate::improvements::PreparedRenderedPlan;
use crate::release_builder::{BuiltRelease, build_release};

const CONFIG_NAME: &str = "improvement-lab.json";
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigDocument {
    schema: String,
    repository: PathBuf,
    worktree_root: PathBuf,
    codex_binary: PathBuf,
    codex_binary_sha256: String,
    codex_home: PathBuf,
    cargo_home: PathBuf,
    rustup_home: PathBuf,
    model: String,
    systemd_unit: String,
}

#[derive(Clone, Debug)]
struct WorkerConfig {
    repository: PathBuf,
    worktree_root: PathBuf,
    pin: CodexRuntimePin,
    codex_auth_file: PathBuf,
    systemd_unit: String,
}

#[derive(Debug)]
pub struct ImprovementWorker {
    state_dir: PathBuf,
    config: WorkerConfig,
    publisher: CandidatePublisher,
}

#[derive(Debug)]
pub struct ImprovementWorkerReceipt {
    pub execution: ImprovementExecutionReceipt,
    pub push: CandidatePushReceipt,
    pub release: BuiltRelease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationDisposition {
    HotActive,
    Scheduled,
}

impl ImprovementWorker {
    /// Load the owner-provisioned lab configuration. An absent file disables
    /// implementation but does not disable plan drafting and review.
    pub fn load(state_dir: &Path) -> Result<Option<Self>, ImprovementWorkerError> {
        let state_metadata = fs::symlink_metadata(state_dir).map_err(ImprovementWorkerError::Io)?;
        if !state_dir.is_absolute()
            || !state_metadata.is_dir()
            || state_metadata.file_type().is_symlink()
            || state_metadata.uid() != nix::unistd::geteuid().as_raw()
            || state_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(ImprovementWorkerError::InvalidConfiguration);
        }
        let config_path = state_dir.join(CONFIG_NAME);
        let metadata = match fs::symlink_metadata(&config_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(ImprovementWorkerError::Io(error)),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() == 0
            || metadata.len() > MAX_CONFIG_BYTES
        {
            return Err(ImprovementWorkerError::InvalidConfiguration);
        }
        let bytes = fs::read(config_path).map_err(ImprovementWorkerError::Io)?;
        let document: ConfigDocument = serde_json::from_slice(&bytes)
            .map_err(|_| ImprovementWorkerError::InvalidConfiguration)?;
        if document.schema != "automonique.improvement-lab-config/v1" {
            return Err(ImprovementWorkerError::InvalidConfiguration);
        }
        let target = RepoTarget::parse("bext-stack", "automonique")
            .map_err(|_| ImprovementWorkerError::InvalidConfiguration)?;
        let codex_auth_file = document.codex_home.join("auth.json");
        private_auth_file(&codex_auth_file)?;
        Ok(Some(Self {
            state_dir: state_dir.to_path_buf(),
            config: WorkerConfig {
                repository: document.repository,
                worktree_root: document.worktree_root,
                pin: CodexRuntimePin {
                    binary: document.codex_binary,
                    binary_sha256: document.codex_binary_sha256,
                    // Replaced by a fresh attempt-specific home before launch.
                    codex_home: state_dir.to_path_buf(),
                    cargo_home: document.cargo_home,
                    rustup_home: document.rustup_home,
                    model: document.model,
                },
                codex_auth_file,
                systemd_unit: document.systemd_unit,
            },
            publisher: CandidatePublisher::production(target),
        }))
    }

    pub fn execute(
        &mut self,
        improvement: &ImprovementRecord,
        prepared: &PreparedRenderedPlan,
    ) -> Result<ImprovementWorkerReceipt, ImprovementWorkerError> {
        if improvement.source_base_sha.as_deref() != Some(prepared.source_base_sha.as_str())
            || improvement.plan_digest.as_deref() != Some(prepared.plan.sha256.as_str())
        {
            return Err(ImprovementWorkerError::ApprovalMismatch);
        }
        let mut pin = self.config.pin.clone();
        pin.codex_home = self.prepare_codex_home(improvement, prepared)?;
        let mut executor = ImprovementExecutor::open(
            &self.config.repository,
            &self.config.worktree_root,
            VerificationProfile::RustWorkspace,
            PinnedCodexAgent::new(pin),
        )?;
        let execution = executor.execute(&ImprovementExecutionRequest {
            public_id: improvement.public_id(),
            revision: improvement.revision,
            source_base_sha: prepared.source_base_sha.clone(),
            plan_digest: prepared.plan.sha256.clone(),
            plan_markdown: prepared.plan.markdown.clone(),
        })?;
        let release = build_release(
            &self.state_dir,
            &execution.worktree,
            &execution.candidate_sha,
            &execution.candidate_tree,
            &execution.plan_digest,
            &execution.changed_paths,
        )?;
        let push = self.publisher.publish(
            &execution.worktree,
            &execution.public_id,
            improvement.revision,
            &execution.candidate_sha,
            &execution.candidate_tree,
        )?;
        Ok(ImprovementWorkerReceipt {
            execution,
            push,
            release,
        })
    }

    fn prepare_codex_home(
        &self,
        improvement: &ImprovementRecord,
        prepared: &PreparedRenderedPlan,
    ) -> Result<PathBuf, ImprovementWorkerError> {
        let digest = prepared
            .plan
            .sha256
            .strip_prefix("sha256:")
            .ok_or(ImprovementWorkerError::ApprovalMismatch)?;
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ImprovementWorkerError::ApprovalMismatch);
        }
        let root = self.state_dir.join("improvement-codex");
        private_create_dir_all(&root)?;
        let home = root.join(format!(
            "{}-r{}-{}",
            improvement.public_id().to_ascii_lowercase(),
            improvement.revision,
            &digest[..16]
        ));
        private_create_dir_all(&home)?;
        let target = home.join("auth.json");
        if !target.exists() {
            fs::copy(&self.config.codex_auth_file, &target).map_err(ImprovementWorkerError::Io)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
                .map_err(ImprovementWorkerError::Io)?;
        }
        private_auth_file(&target)?;
        Ok(home)
    }

    pub fn activate(
        &mut self,
        improvement: &ImprovementRecord,
        manifest_digest: &str,
    ) -> Result<ActivationDisposition, ImprovementWorkerError> {
        let digest = manifest_digest
            .strip_prefix("sha256:")
            .ok_or(ImprovementWorkerError::ApprovalMismatch)?;
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ImprovementWorkerError::ApprovalMismatch);
        }
        let code_release = self
            .state_dir
            .join("improvement-code/releases")
            .join(digest);
        if code_release.is_dir() {
            self.schedule_code_activation(improvement, manifest_digest)?;
            Ok(ActivationDisposition::Scheduled)
        } else {
            crate::skill_runtime::activate(&self.state_dir, manifest_digest)
                .map(drop)
                .map_err(ImprovementWorkerError::SkillActivation)?;
            Ok(ActivationDisposition::HotActive)
        }
    }

    fn schedule_code_activation(
        &self,
        improvement: &ImprovementRecord,
        manifest_digest: &str,
    ) -> Result<(), ImprovementWorkerError> {
        let executable = std::env::current_exe().map_err(ImprovementWorkerError::Io)?;
        let transient_unit = format!("automonique-improvement-{}", improvement.public_id());
        let status = Command::new("/usr/bin/systemd-run")
            .args(["--user", "--collect", "--unit"])
            .arg(&transient_unit)
            .args(["--property", "Type=oneshot"])
            .arg(executable)
            .args(["improvement-activate", "--state-dir"])
            .arg(&self.state_dir)
            .args(["--improvement-id", &improvement.entry_id.to_string()])
            .args(["--revision", &improvement.revision.to_string()])
            .args(["--manifest", manifest_digest])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(ImprovementWorkerError::Io)?;
        if !status.success() {
            return Err(ImprovementWorkerError::ActivationScheduling);
        }
        Ok(())
    }

    fn activate_code_now(&mut self, manifest_digest: &str) -> Result<(), ImprovementWorkerError> {
        let root = self.state_dir.join("improvement-code");
        let mut activator = crate::release_activation::CodeReleaseActivator::new(
            root,
            &self.config.systemd_unit,
            crate::release_activation::SystemdUserSupervisor,
        )
        .map_err(ImprovementWorkerError::Activation)?;
        activator
            .activate(manifest_digest)
            .map(drop)
            .map_err(ImprovementWorkerError::Activation)
    }
}

#[derive(Debug)]
pub enum ImprovementWorkerError {
    InvalidConfiguration,
    ApprovalMismatch,
    Io(std::io::Error),
    Execution(automonique_lab::improvement_executor::ImprovementExecutionError),
    Release(crate::release_builder::ReleaseBuildError),
    Publish(crate::improvement_publish::CandidatePublishError),
    Activation(crate::release_activation::ReleaseActivationError),
    SkillActivation(crate::skill_runtime::SkillRuntimeError),
    ActivationScheduling,
}

impl fmt::Display for ImprovementWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => formatter.write_str("improvement lab is misconfigured"),
            Self::ApprovalMismatch => {
                formatter.write_str("approved improvement coordinates changed")
            }
            Self::Io(error) => write!(formatter, "improvement worker I/O failed: {error}"),
            Self::Execution(error) => write!(formatter, "improvement execution failed: {error}"),
            Self::Release(error) => write!(formatter, "release build failed: {error}"),
            Self::Publish(error) => write!(formatter, "candidate publication failed: {error}"),
            Self::Activation(error) => write!(formatter, "code activation failed: {error}"),
            Self::SkillActivation(error) => write!(formatter, "skill activation failed: {error}"),
            Self::ActivationScheduling => {
                formatter.write_str("code activation could not be scheduled")
            }
        }
    }
}

pub fn run_scheduled_activation(
    state_dir: &Path,
    improvement_id: i64,
    expected_revision: u64,
    manifest_digest: &str,
) -> Result<(), ImprovementWorkerError> {
    // Give the Telegram poller a short bounded opportunity to commit the
    // scheduling reply before this helper restarts its generation.
    std::thread::sleep(Duration::from_secs(2));
    let mut worker =
        ImprovementWorker::load(state_dir)?.ok_or(ImprovementWorkerError::InvalidConfiguration)?;
    let mut coordinator = crate::improvements::ImprovementCoordinator::open_default(state_dir)
        .map_err(|_| ImprovementWorkerError::ApprovalMismatch)?;
    let current = coordinator
        .store()
        .get(improvement_id)
        .map_err(|_| ImprovementWorkerError::ApprovalMismatch)?
        .ok_or(ImprovementWorkerError::ApprovalMismatch)?;
    if current.revision != expected_revision
        || current.state != automonique_store::improvements::ImprovementState::Activating
        || current.release_manifest_digest.as_deref() != Some(manifest_digest)
    {
        return Err(ImprovementWorkerError::ApprovalMismatch);
    }
    let now_ms = crate::unix_millis().unwrap_or(current.updated_at_ms);
    match worker.activate_code_now(manifest_digest) {
        Ok(()) => coordinator
            .complete_activation(improvement_id, expected_revision, manifest_digest, now_ms)
            .map(drop)
            .map_err(|_| ImprovementWorkerError::ApprovalMismatch),
        Err(ImprovementWorkerError::Activation(
            crate::release_activation::ReleaseActivationError::ActivationRolledBack,
        )) => coordinator
            .rolled_back(
                improvement_id,
                expected_revision,
                "activation_readiness_failed",
                now_ms,
            )
            .map(drop)
            .map_err(|_| ImprovementWorkerError::ApprovalMismatch),
        Err(error) => {
            let _ = coordinator.fail(
                improvement_id,
                expected_revision,
                "activation_failed",
                now_ms,
            );
            Err(error)
        }
    }
}

impl Error for ImprovementWorkerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Execution(error) => Some(error),
            Self::Release(error) => Some(error),
            Self::Publish(error) => Some(error),
            Self::Activation(error) => Some(error),
            Self::SkillActivation(error) => Some(error),
            _ => None,
        }
    }
}

impl From<automonique_lab::improvement_executor::ImprovementExecutionError>
    for ImprovementWorkerError
{
    fn from(error: automonique_lab::improvement_executor::ImprovementExecutionError) -> Self {
        Self::Execution(error)
    }
}

impl From<crate::release_builder::ReleaseBuildError> for ImprovementWorkerError {
    fn from(error: crate::release_builder::ReleaseBuildError) -> Self {
        Self::Release(error)
    }
}

impl From<crate::improvement_publish::CandidatePublishError> for ImprovementWorkerError {
    fn from(error: crate::improvement_publish::CandidatePublishError) -> Self {
        Self::Publish(error)
    }
}

fn private_create_dir_all(path: &Path) -> Result<(), ImprovementWorkerError> {
    if !path.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(ImprovementWorkerError::Io)?;
    }
    let metadata = fs::symlink_metadata(path).map_err(ImprovementWorkerError::Io)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ImprovementWorkerError::InvalidConfiguration);
    }
    Ok(())
}

fn private_auth_file(path: &Path) -> Result<(), ImprovementWorkerError> {
    let metadata = fs::symlink_metadata(path).map_err(ImprovementWorkerError::Io)?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() == 0
        || metadata.len() > 1024 * 1024
    {
        return Err(ImprovementWorkerError::InvalidConfiguration);
    }
    Ok(())
}
