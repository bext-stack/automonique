// SPDX-License-Identifier: Elastic-2.0

//! Closed production capability map and private target registry for Platform
//! v2 review effects.
//!
//! The registry is deliberately not a capability switch. It binds an exact
//! project/workspace/authority tuple to a typed operator-owned target, but an
//! action is exposed only after its provider adapter can also prove exact
//! source provenance and reconcile an ambiguous write. This prevents merely
//! installing credentials or a repository path from enabling an unsafe
//! mutation.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use automonique_github_connector::{GitHubToken, RepoTarget, WorkflowRunId};
use automonique_protocol::digest::{Sha256, Sha256Digest};
use automonique_protocol::platform_v2::{
    ProjectId, WorkContextIdentity, WorkContextTargetKind, WorkSessionId,
};
use automonique_protocol::platform_v2_review::{
    ReviewAction, ReviewAuthority, ReviewAuthorityId, ReviewAuthorityKind, ReviewCheckId,
};
use automonique_protocol::primitives::Revision;

use crate::platform_v2_github_check_adapter::{
    GitHubActionsWriteCapability, GitHubCheckRerunAdapter,
};
use nix::libc;
use serde::Deserialize;

pub const REVIEW_REGISTRY_FILE_NAME: &str = "platform-v2-review-registry.json";
pub const REVIEW_GITHUB_CREDENTIALS_FILE_NAME: &str = "platform-v2-review-github-credentials.json";

const MAX_REGISTRY_BYTES: u64 = 512 * 1024;
const MAX_BINDINGS: usize = 4096;
const MAX_TOKEN_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileGeneration {
    device: u64,
    inode: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    length: u64,
    digest: Sha256Digest,
}

struct PrivateSnapshot {
    bytes: Vec<u8>,
    generation: FileGeneration,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryDocument {
    version: u8,
    generation: String,
    #[serde(default)]
    bindings: Vec<RegistryBinding>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryBinding {
    project: String,
    workspace_kind: String,
    workspace_id: String,
    authority_kind: String,
    authority_id: String,
    target: RegistryTarget,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryCiCheck {
    check_id: String,
    run_id: u64,
    head_sha: String,
    observed_attempt: u32,
    observed_check_revision: u64,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RegistryTarget {
    LocalRepository {
        canonical_root: PathBuf,
    },
    RetainedSession {
        provider: String,
        session_id: String,
        work_session_id: String,
    },
    Ci {
        provider: String,
        target: String,
        credential_reference: String,
        #[serde(default)]
        checks: Vec<RegistryCiCheck>,
    },
    PullRequest {
        provider: String,
        repository: String,
        credential_reference: String,
    },
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct GitHubCredentialDocument {
    version: u8,
    generation: String,
    #[serde(default)]
    credentials: Vec<GitHubCredential>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct GitHubCredential {
    reference: String,
    repository: String,
    actions_write: bool,
    token: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReviewEffectPlan {
    LocalStore,
    RetainedSession {
        provider: String,
        provider_session_id: String,
        work_session_id: WorkSessionId,
        registry_generation: [u8; 32],
    },
    GitHubCheckRerun {
        credential_reference: String,
        repository: RepoTarget,
        run_id: WorkflowRunId,
        head_sha: String,
        observed_attempt: u32,
        expected_check_revision: Revision,
        registry_generation: [u8; 32],
        credential_generation: [u8; 32],
    },
}

/// Registry-fenced review adapter composition.
///
/// `None` is represented by an empty adapter and retains the previous
/// fail-closed behavior. An installed malformed or insecure registry is an
/// error so production never silently ignores an operator mistake.
#[derive(Default)]
pub(crate) struct ProductionReviewEffectAdapter {
    installed: Option<InstalledRegistry>,
    github_credentials: Option<InstalledGitHubCredentials>,
}

struct InstalledRegistry {
    path: PathBuf,
    expected_uid: u32,
    generation: FileGeneration,
    document: RegistryDocument,
}

struct InstalledGitHubCredentials {
    path: PathBuf,
    expected_uid: u32,
    generation: FileGeneration,
    document: GitHubCredentialDocument,
}

impl std::fmt::Debug for ProductionReviewEffectAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionReviewEffectAdapter")
            .field("installed", &self.installed.is_some())
            .finish()
    }
}

impl ProductionReviewEffectAdapter {
    pub(crate) fn open(path: &Path, expected_uid: u32) -> Result<Self, &'static str> {
        let credential_path = path
            .parent()
            .ok_or("platform_v2_review_registry_invalid")?
            .join(REVIEW_GITHUB_CREDENTIALS_FILE_NAME);
        let github_credentials = match read_private_file(&credential_path, expected_uid)? {
            Some(snapshot) => {
                let document: GitHubCredentialDocument = serde_json::from_slice(&snapshot.bytes)
                    .map_err(|_| "platform_v2_review_github_credentials_invalid")?;
                validate_github_credentials(&document)?;
                Some(InstalledGitHubCredentials {
                    path: credential_path,
                    expected_uid,
                    generation: snapshot.generation,
                    document,
                })
            }
            None => None,
        };
        let Some(snapshot) = read_private_file(path, expected_uid)? else {
            return Ok(Self {
                installed: None,
                github_credentials,
            });
        };
        let document: RegistryDocument = serde_json::from_slice(&snapshot.bytes)
            .map_err(|_| "platform_v2_review_registry_invalid")?;
        validate_registry(&document, expected_uid)?;
        Ok(Self {
            installed: Some(InstalledRegistry {
                path: path.to_path_buf(),
                expected_uid,
                generation: snapshot.generation,
                document,
            }),
            github_credentials,
        })
    }

    pub(crate) fn plan(
        &self,
        project: &ProjectId,
        workspace: &WorkContextIdentity,
        authority: &ReviewAuthority,
        action: &ReviewAction,
    ) -> Result<ReviewEffectPlan, &'static str> {
        if matches!(
            action,
            ReviewAction::AddComment { .. } | ReviewAction::ApproveReview { .. }
        ) {
            return Ok(ReviewEffectPlan::LocalStore);
        }
        self.verify_generation()?;
        let binding = self.installed.as_ref().and_then(|installed| {
            installed
                .document
                .bindings
                .iter()
                .find(|binding| binding.matches(project, workspace, authority))
        });
        if let Some(binding) = binding
            && !binding.target.accepts(authority.kind())
        {
            return Err("platform_v2_review_registry_incoherent");
        }
        if matches!(
            action,
            ReviewAction::SendCommentToAgent { .. } | ReviewAction::BatchSendCommentsToAgent { .. }
        ) && let (
            Some(installed),
            Some(RegistryBinding {
                target:
                    RegistryTarget::RetainedSession {
                        provider,
                        session_id,
                        work_session_id,
                    },
                ..
            }),
        ) = (&self.installed, binding)
        {
            if provider != "jcode" {
                return Err("platform_v2_review_agent_provider_unavailable");
            }
            return Ok(ReviewEffectPlan::RetainedSession {
                provider: provider.clone(),
                provider_session_id: session_id.clone(),
                work_session_id: WorkSessionId::new(work_session_id.clone())
                    .map_err(|_| "platform_v2_review_registry_incoherent")?,
                registry_generation: *installed.generation.digest.as_bytes(),
            });
        }
        if let (
            ReviewAction::RerunCheck {
                check_id,
                expected_check_revision,
            },
            Some(installed),
            Some(RegistryBinding {
                target:
                    RegistryTarget::Ci {
                        provider,
                        target,
                        credential_reference,
                        checks,
                    },
                ..
            }),
        ) = (action, &self.installed, binding)
        {
            if provider != "github" {
                return Err("platform_v2_review_ci_provider_unavailable");
            }
            let check = checks
                .iter()
                .find(|candidate| candidate.check_id == check_id.as_str())
                .ok_or("platform_v2_review_ci_check_unavailable")?;
            let check_revision = Revision::new(check.observed_check_revision)
                .map_err(|_| "platform_v2_review_registry_incoherent")?;
            if check_revision != *expected_check_revision {
                return Err("platform_v2_review_ci_check_changed");
            }
            let credentials = self
                .github_credentials
                .as_ref()
                .ok_or("platform_v2_review_ci_credential_unavailable")?;
            let credential = credentials
                .document
                .credentials
                .iter()
                .find(|candidate| candidate.reference == *credential_reference)
                .ok_or("platform_v2_review_ci_credential_unavailable")?;
            if !credential.actions_write || credential.repository != *target {
                return Err("platform_v2_review_ci_credential_incoherent");
            }
            return Ok(ReviewEffectPlan::GitHubCheckRerun {
                credential_reference: credential_reference.clone(),
                repository: parse_repository(target)?,
                run_id: WorkflowRunId::new(check.run_id)
                    .map_err(|_| "platform_v2_review_registry_incoherent")?,
                head_sha: check.head_sha.clone(),
                observed_attempt: check.observed_attempt,
                expected_check_revision: check_revision,
                registry_generation: *installed.generation.digest.as_bytes(),
                credential_generation: *credentials.generation.digest.as_bytes(),
            });
        }
        Err(unavailable_category(action))
    }

    pub(crate) fn verify_generation(&self) -> Result<(), &'static str> {
        let Some(installed) = &self.installed else {
            return Ok(());
        };
        let current = read_private_file(&installed.path, installed.expected_uid)?
            .ok_or("platform_v2_review_registry_changed")?;
        if current.generation != installed.generation {
            return Err("platform_v2_review_registry_changed");
        }
        self.verify_github_credential_generation(None)
    }

    pub(crate) fn github_adapter(
        &self,
        credential_reference: &str,
        repository: &RepoTarget,
        expected_generation: [u8; 32],
    ) -> Result<GitHubCheckRerunAdapter, &'static str> {
        self.verify_github_credential_generation(Some(expected_generation))?;
        let installed = self
            .github_credentials
            .as_ref()
            .ok_or("platform_v2_review_ci_credential_unavailable")?;
        let coordinate = repository.to_string();
        let credential = installed
            .document
            .credentials
            .iter()
            .find(|candidate| candidate.reference == credential_reference)
            .ok_or("platform_v2_review_ci_credential_unavailable")?;
        if !credential.actions_write || credential.repository != coordinate {
            return Err("platform_v2_review_ci_credential_incoherent");
        }
        let token = GitHubToken::new(credential.token.as_bytes().to_vec())
            .map_err(|_| "platform_v2_review_ci_credential_invalid")?;
        let capability = GitHubActionsWriteCapability::production(
            credential_reference,
            repository.clone(),
            token,
        )
        .map_err(|_| "platform_v2_review_ci_credential_invalid")?;
        Ok(GitHubCheckRerunAdapter::new(capability))
    }

    fn verify_github_credential_generation(
        &self,
        expected: Option<[u8; 32]>,
    ) -> Result<(), &'static str> {
        let Some(installed) = &self.github_credentials else {
            return if expected.is_none() {
                Ok(())
            } else {
                Err("platform_v2_review_ci_credentials_changed")
            };
        };
        let current = read_private_file(&installed.path, installed.expected_uid)?
            .ok_or("platform_v2_review_ci_credentials_changed")?;
        if current.generation != installed.generation
            || expected.is_some_and(|digest| current.generation.digest.as_bytes() != &digest)
        {
            return Err("platform_v2_review_ci_credentials_changed");
        }
        Ok(())
    }
}

/// Reopen and validate the private registry immediately before an already
/// admitted retained-session effect crosses into provider custody.
pub(crate) fn verify_registry_generation(
    path: &Path,
    expected_uid: u32,
    expected_digest: [u8; 32],
) -> Result<(), &'static str> {
    let snapshot =
        read_private_file(path, expected_uid)?.ok_or("platform_v2_review_registry_changed")?;
    let document: RegistryDocument = serde_json::from_slice(&snapshot.bytes)
        .map_err(|_| "platform_v2_review_registry_invalid")?;
    validate_registry(&document, expected_uid)?;
    if snapshot.generation.digest.as_bytes() != &expected_digest {
        return Err("platform_v2_review_registry_changed");
    }
    Ok(())
}

impl RegistryBinding {
    fn matches(
        &self,
        project: &ProjectId,
        workspace: &WorkContextIdentity,
        authority: &ReviewAuthority,
    ) -> bool {
        self.project == project.as_str()
            && self.workspace_kind == workspace.kind().as_str()
            && self.workspace_id == workspace.id()
            && self.authority_kind == authority.kind().as_str()
            && self.authority_id == authority.id().as_str()
    }

    fn key(&self) -> (&str, &str, &str, &str, &str) {
        (
            &self.project,
            &self.workspace_kind,
            &self.workspace_id,
            &self.authority_kind,
            &self.authority_id,
        )
    }
}

impl RegistryTarget {
    const fn accepts(&self, authority: ReviewAuthorityKind) -> bool {
        matches!(
            (self, authority),
            (Self::LocalRepository { .. }, ReviewAuthorityKind::Git)
                | (Self::RetainedSession { .. }, ReviewAuthorityKind::Review)
                | (Self::Ci { .. }, ReviewAuthorityKind::Ci)
                | (Self::PullRequest { .. }, ReviewAuthorityKind::PullRequest)
        )
    }
}

fn unavailable_category(action: &ReviewAction) -> &'static str {
    match action {
        ReviewAction::AddComment { .. } | ReviewAction::ApproveReview { .. } => {
            "platform_v2_review_adapter_incoherent"
        }
        ReviewAction::SendCommentToAgent { .. } | ReviewAction::BatchSendCommentsToAgent { .. } => {
            "platform_v2_review_agent_adapter_unavailable"
        }
        ReviewAction::Stage { .. }
        | ReviewAction::Unstage { .. }
        | ReviewAction::Commit { .. }
        | ReviewAction::ResolveConflict { .. } => "platform_v2_review_git_adapter_unavailable",
        ReviewAction::RerunCheck { .. } => "platform_v2_review_ci_adapter_unavailable",
        ReviewAction::OpenPullRequest { .. }
        | ReviewAction::UpdatePullRequest { .. }
        | ReviewAction::MergePullRequest { .. } => {
            "platform_v2_review_pull_request_adapter_unavailable"
        }
    }
}

fn validate_registry(document: &RegistryDocument, expected_uid: u32) -> Result<(), &'static str> {
    if document.version != 1
        || !safe_token(&document.generation)
        || document.bindings.len() > MAX_BINDINGS
    {
        return Err("platform_v2_review_registry_invalid");
    }
    let mut keys = BTreeSet::new();
    let mut repository_roots = BTreeSet::new();
    for binding in &document.bindings {
        let workspace_kind = WorkContextTargetKind::parse(&binding.workspace_kind)
            .map_err(|_| "platform_v2_review_registry_invalid")?;
        if !safe_token(&binding.project)
            || ProjectId::new(binding.project.clone()).is_err()
            || !safe_token(&binding.workspace_id)
            || WorkContextIdentity::parse_local(workspace_kind, &binding.workspace_id).is_err()
            || !matches!(
                workspace_kind,
                WorkContextTargetKind::UserWorkspace
                    | WorkContextTargetKind::AttemptWorkspace
                    | WorkContextTargetKind::Session
            )
            || ReviewAuthorityKind::parse(&binding.authority_kind).is_err()
            || !safe_token(&binding.authority_id)
            || ReviewAuthorityId::new(binding.authority_id.clone()).is_err()
            || !keys.insert(binding.key())
        {
            return Err("platform_v2_review_registry_invalid");
        }
        let authority = ReviewAuthorityKind::parse(&binding.authority_kind)
            .map_err(|_| "platform_v2_review_registry_invalid")?;
        if !binding.target.accepts(authority) {
            return Err("platform_v2_review_registry_invalid");
        }
        match &binding.target {
            RegistryTarget::LocalRepository { canonical_root } => {
                let root = validate_private_repository(canonical_root, expected_uid)?;
                if !repository_roots.insert(root) {
                    return Err("platform_v2_review_registry_invalid");
                }
            }
            RegistryTarget::RetainedSession {
                provider,
                session_id,
                work_session_id,
            } => {
                if !safe_token(provider)
                    || !safe_token(session_id)
                    || !safe_token(work_session_id)
                    || WorkSessionId::new(work_session_id.clone()).is_err()
                {
                    return Err("platform_v2_review_registry_invalid");
                }
            }
            RegistryTarget::Ci {
                provider,
                target,
                credential_reference,
                checks,
            } => {
                if !safe_token(provider)
                    || !safe_coordinate(target)
                    || !safe_github_reference(credential_reference)
                    || checks.len() > MAX_BINDINGS
                    || (provider == "github" && parse_repository(target).is_err())
                {
                    return Err("platform_v2_review_registry_invalid");
                }
                let mut check_ids = BTreeSet::new();
                for check in checks {
                    if ReviewCheckId::new(check.check_id.clone()).is_err()
                        || !check_ids.insert(&check.check_id)
                        || WorkflowRunId::new(check.run_id).is_err()
                        || check.observed_attempt == 0
                        || Revision::new(check.observed_check_revision).is_err()
                        || !valid_head_sha(&check.head_sha)
                    {
                        return Err("platform_v2_review_registry_invalid");
                    }
                }
            }
            RegistryTarget::PullRequest {
                provider,
                repository,
                credential_reference,
            } => {
                if !safe_token(provider)
                    || !safe_coordinate(repository)
                    || !safe_token(credential_reference)
                {
                    return Err("platform_v2_review_registry_invalid");
                }
            }
        }
    }
    for left in &repository_roots {
        for right in &repository_roots {
            if left != right && (left.starts_with(right) || right.starts_with(left)) {
                return Err("platform_v2_review_registry_invalid");
            }
        }
    }
    Ok(())
}

fn validate_github_credentials(document: &GitHubCredentialDocument) -> Result<(), &'static str> {
    if document.version != 1
        || !safe_token(&document.generation)
        || document.credentials.len() > MAX_BINDINGS
    {
        return Err("platform_v2_review_github_credentials_invalid");
    }
    let mut references = BTreeSet::new();
    for credential in &document.credentials {
        if !safe_github_reference(&credential.reference)
            || !references.insert(&credential.reference)
            || parse_repository(&credential.repository).is_err()
            || GitHubToken::new(credential.token.as_bytes().to_vec()).is_err()
        {
            return Err("platform_v2_review_github_credentials_invalid");
        }
    }
    Ok(())
}

fn parse_repository(value: &str) -> Result<RepoTarget, &'static str> {
    let (owner, repository) = value
        .split_once('/')
        .ok_or("platform_v2_review_registry_invalid")?;
    if repository.contains('/') {
        return Err("platform_v2_review_registry_invalid");
    }
    RepoTarget::parse(owner, repository).map_err(|_| "platform_v2_review_registry_invalid")
}

fn valid_head_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_private_repository(path: &Path, expected_uid: u32) -> Result<PathBuf, &'static str> {
    if !path.is_absolute() {
        return Err("platform_v2_review_registry_invalid");
    }
    let canonical = fs::canonicalize(path).map_err(|_| "platform_v2_review_registry_invalid")?;
    if canonical != path {
        return Err("platform_v2_review_registry_invalid");
    }
    validate_private_directory(&canonical, expected_uid)?;
    let git = canonical.join(".git");
    let metadata = fs::symlink_metadata(&git).map_err(|_| "platform_v2_review_registry_invalid")?;
    if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
        return Err("platform_v2_review_registry_invalid");
    }
    if metadata.uid() != expected_uid || metadata.mode() & 0o022 != 0 {
        return Err("platform_v2_review_registry_invalid");
    }
    Ok(canonical)
}

fn validate_private_directory(path: &Path, expected_uid: u32) -> Result<(), &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "platform_v2_review_registry_invalid")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err("platform_v2_review_registry_invalid");
    }
    Ok(())
}

fn read_private_file(
    path: &Path,
    expected_uid: u32,
) -> Result<Option<PrivateSnapshot>, &'static str> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("platform_v2_review_registry_insecure"),
    };
    let before = file
        .metadata()
        .map_err(|_| "platform_v2_review_registry_insecure")?;
    validate_private_file_metadata(&before, expected_uid)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_REGISTRY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "platform_v2_review_registry_insecure")?;
    if bytes.len() as u64 > MAX_REGISTRY_BYTES {
        return Err("platform_v2_review_registry_invalid");
    }
    let after = file
        .metadata()
        .map_err(|_| "platform_v2_review_registry_insecure")?;
    validate_private_file_metadata(&after, expected_uid)?;
    let before_generation = generation(&before, &bytes);
    let after_generation = generation(&after, &bytes);
    if before_generation != after_generation {
        return Err("platform_v2_review_registry_changed");
    }
    Ok(Some(PrivateSnapshot {
        bytes,
        generation: after_generation,
    }))
}

fn validate_private_file_metadata(
    metadata: &fs::Metadata,
    expected_uid: u32,
) -> Result<(), &'static str> {
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.len() > MAX_REGISTRY_BYTES
    {
        return Err("platform_v2_review_registry_insecure");
    }
    Ok(())
}

fn generation(metadata: &fs::Metadata, bytes: &[u8]) -> FileGeneration {
    FileGeneration {
        device: metadata.dev(),
        inode: metadata.ino(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        length: metadata.len(),
        digest: Sha256::digest(bytes),
    }
}

fn safe_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOKEN_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
        && !value.starts_with('-')
        && !value.contains("..")
}

fn safe_coordinate(value: &str) -> bool {
    safe_token(value) && value.contains('/')
}

fn safe_github_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOKEN_BYTES
        && !value.starts_with('-')
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    use automonique_protocol::platform_v2::{ProjectId, UserWorkspaceId};
    use automonique_protocol::platform_v2_review::{
        ReviewAuthorityId, ReviewCommentId, ReviewProposalId,
    };
    use automonique_protocol::primitives::Revision;
    use tempfile::TempDir;

    fn uid() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    fn write_registry(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn git_binding(root: &Path) -> String {
        format!(
            r#"{{"version":1,"generation":"generation-1","bindings":[{{"project":"project-1","workspace_kind":"user_workspace","workspace_id":"workspace-1","authority_kind":"git","authority_id":"git-1","target":{{"kind":"local_repository","canonical_root":{}}}}}]}}"#,
            serde_json::to_string(root).unwrap()
        )
    }

    fn action() -> ReviewAction {
        ReviewAction::Stage {
            proposal_id: ReviewProposalId::new("proposal-1").unwrap(),
        }
    }

    fn git_authority() -> ReviewAuthority {
        ReviewAuthority::new(
            ReviewAuthorityKind::Git,
            ReviewAuthorityId::new("git-1").unwrap(),
        )
    }

    fn workspace() -> WorkContextIdentity {
        WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("workspace-1").unwrap())
    }

    fn review_authority() -> ReviewAuthority {
        ReviewAuthority::new(
            ReviewAuthorityKind::Review,
            ReviewAuthorityId::new("review-1").unwrap(),
        )
    }

    fn send_action() -> ReviewAction {
        ReviewAction::SendCommentToAgent {
            comment_id: ReviewCommentId::new("comment-1").unwrap(),
            expected_comment_revision: Revision::FIRST,
        }
    }

    fn ci_authority() -> ReviewAuthority {
        ReviewAuthority::new(
            ReviewAuthorityKind::Ci,
            ReviewAuthorityId::new("ci-1").unwrap(),
        )
    }

    fn rerun_action(revision: u64) -> ReviewAction {
        ReviewAction::RerunCheck {
            check_id: ReviewCheckId::new("check-1").unwrap(),
            expected_check_revision: Revision::new(revision).unwrap(),
        }
    }

    fn github_registry() -> &'static str {
        r#"{"version":1,"generation":"generation-1","bindings":[{"project":"project-1","workspace_kind":"user_workspace","workspace_id":"workspace-1","authority_kind":"ci","authority_id":"ci-1","target":{"kind":"ci","provider":"github","target":"example-org/example-repo","credential_reference":"github-actions-mobile","checks":[{"check_id":"check-1","run_id":91,"head_sha":"0123456789abcdef0123456789abcdef01234567","observed_attempt":3,"observed_check_revision":7}]}}]}"#
    }

    fn github_credentials(actions_write: bool, repository: &str) -> String {
        format!(
            r#"{{"version":1,"generation":"credential-generation-1","credentials":[{{"reference":"github-actions-mobile","repository":"{repository}","actions_write":{actions_write},"token":"github_pat_fixture"}}]}}"#
        )
    }

    #[test]
    fn absent_registry_keeps_external_effects_unavailable() {
        let temporary = TempDir::new().unwrap();
        let adapter =
            ProductionReviewEffectAdapter::open(&temporary.path().join("missing"), uid()).unwrap();
        assert_eq!(
            adapter.plan(
                &ProjectId::new("project-1").unwrap(),
                &workspace(),
                &git_authority(),
                &action()
            ),
            Err("platform_v2_review_git_adapter_unavailable")
        );
    }

    #[test]
    fn secure_exact_binding_does_not_fabricate_a_capability() {
        let temporary = TempDir::new().unwrap();
        let repository = temporary.path().join("repository");
        fs::create_dir(&repository).unwrap();
        fs::create_dir(repository.join(".git")).unwrap();
        fs::set_permissions(&repository, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(repository.join(".git"), fs::Permissions::from_mode(0o700)).unwrap();
        let registry = temporary.path().join("registry.json");
        write_registry(&registry, &git_binding(&repository));
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        assert_eq!(
            adapter.plan(
                &ProjectId::new("project-1").unwrap(),
                &workspace(),
                &git_authority(),
                &action()
            ),
            Err("platform_v2_review_git_adapter_unavailable")
        );
    }

    #[test]
    fn exact_jcode_retained_session_binding_is_a_closed_delivery_plan() {
        let temporary = TempDir::new().unwrap();
        let registry = temporary.path().join("registry.json");
        write_registry(
            &registry,
            r#"{"version":1,"generation":"generation-1","bindings":[{"project":"project-1","workspace_kind":"user_workspace","workspace_id":"workspace-1","authority_kind":"review","authority_id":"review-1","target":{"kind":"retained_session","provider":"jcode","session_id":"provider-session-1","work_session_id":"work-session-1"}}]}"#,
        );
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        let plan = adapter
            .plan(
                &ProjectId::new("project-1").unwrap(),
                &workspace(),
                &review_authority(),
                &send_action(),
            )
            .unwrap();
        match plan {
            ReviewEffectPlan::RetainedSession {
                provider,
                provider_session_id,
                work_session_id,
                registry_generation,
            } => {
                assert_eq!(provider, "jcode");
                assert_eq!(provider_session_id, "provider-session-1");
                assert_eq!(work_session_id.as_str(), "work-session-1");
                assert_ne!(registry_generation, [0; 32]);
            }
            ReviewEffectPlan::LocalStore | ReviewEffectPlan::GitHubCheckRerun { .. } => {
                panic!("external action became another effect")
            }
        }
    }

    #[test]
    fn exact_github_check_and_actions_write_credential_advertise_one_closed_plan() {
        let temporary = TempDir::new().unwrap();
        let registry = temporary.path().join("registry.json");
        let credentials = temporary.path().join(REVIEW_GITHUB_CREDENTIALS_FILE_NAME);
        write_registry(&registry, github_registry());
        write_registry(
            &credentials,
            &github_credentials(true, "example-org/example-repo"),
        );
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        let plan = adapter
            .plan(
                &ProjectId::new("project-1").unwrap(),
                &workspace(),
                &ci_authority(),
                &rerun_action(7),
            )
            .unwrap();
        match plan {
            ReviewEffectPlan::GitHubCheckRerun {
                credential_reference,
                repository,
                run_id,
                head_sha,
                observed_attempt,
                expected_check_revision,
                registry_generation,
                credential_generation,
            } => {
                assert_eq!(credential_reference, "github-actions-mobile");
                assert_eq!(repository.to_string(), "example-org/example-repo");
                assert_eq!(run_id.get(), 91);
                assert_eq!(head_sha, "0123456789abcdef0123456789abcdef01234567");
                assert_eq!(observed_attempt, 3);
                assert_eq!(expected_check_revision, Revision::new(7).unwrap());
                assert_ne!(registry_generation, [0; 32]);
                assert_ne!(credential_generation, [0; 32]);
            }
            _ => panic!("exact GitHub plan expected"),
        }
        assert!(!format!("{adapter:?}").contains("github_pat_fixture"));
    }

    #[test]
    fn github_capability_fails_closed_for_legacy_stale_or_underprivileged_records() {
        let temporary = TempDir::new().unwrap();
        let registry = temporary.path().join("registry.json");
        let credentials = temporary.path().join(REVIEW_GITHUB_CREDENTIALS_FILE_NAME);
        write_registry(
            &registry,
            r#"{"version":1,"generation":"generation-1","bindings":[{"project":"project-1","workspace_kind":"user_workspace","workspace_id":"workspace-1","authority_kind":"ci","authority_id":"ci-1","target":{"kind":"ci","provider":"github","target":"example-org/example-repo","credential_reference":"github-actions-mobile"}}]}"#,
        );
        write_registry(
            &credentials,
            &github_credentials(true, "example-org/example-repo"),
        );
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        assert_eq!(
            adapter.plan(
                &ProjectId::new("project-1").unwrap(),
                &workspace(),
                &ci_authority(),
                &rerun_action(7)
            ),
            Err("platform_v2_review_ci_check_unavailable")
        );

        write_registry(&registry, github_registry());
        fs::remove_file(&credentials).unwrap();
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        assert_eq!(
            adapter.plan(
                &ProjectId::new("project-1").unwrap(),
                &workspace(),
                &ci_authority(),
                &rerun_action(7)
            ),
            Err("platform_v2_review_ci_credential_unavailable")
        );

        write_registry(
            &credentials,
            &github_credentials(false, "example-org/example-repo"),
        );
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        assert_eq!(
            adapter.plan(
                &ProjectId::new("project-1").unwrap(),
                &workspace(),
                &ci_authority(),
                &rerun_action(7)
            ),
            Err("platform_v2_review_ci_credential_incoherent")
        );

        write_registry(
            &credentials,
            &github_credentials(true, "example-org/other-repo"),
        );
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        assert_eq!(
            adapter.plan(
                &ProjectId::new("project-1").unwrap(),
                &workspace(),
                &ci_authority(),
                &rerun_action(7)
            ),
            Err("platform_v2_review_ci_credential_incoherent")
        );

        write_registry(
            &credentials,
            &github_credentials(true, "example-org/example-repo"),
        );
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        assert_eq!(
            adapter.plan(
                &ProjectId::new("project-1").unwrap(),
                &workspace(),
                &ci_authority(),
                &rerun_action(8)
            ),
            Err("platform_v2_review_ci_check_changed")
        );
        write_registry(
            &credentials,
            &github_credentials(true, "example-org/example-repo-rotated"),
        );
        assert_eq!(
            adapter.verify_generation(),
            Err("platform_v2_review_ci_credentials_changed")
        );
    }

    #[test]
    fn malformed_or_insecure_github_credentials_never_install() {
        let temporary = TempDir::new().unwrap();
        let registry = temporary.path().join("registry.json");
        let credentials = temporary.path().join(REVIEW_GITHUB_CREDENTIALS_FILE_NAME);
        write_registry(&registry, github_registry());
        write_registry(
            &credentials,
            &github_credentials(true, "example-org/example-repo"),
        );
        fs::set_permissions(&credentials, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            ProductionReviewEffectAdapter::open(&registry, uid()),
            Err("platform_v2_review_registry_insecure")
        ));
        fs::set_permissions(&credentials, fs::Permissions::from_mode(0o600)).unwrap();
        write_registry(
            &credentials,
            r#"{"version":1,"generation":"g","credentials":[{"reference":"github-actions-mobile","repository":"example-org/example-repo","actions_write":true,"token":"token with spaces"}]}"#,
        );
        assert!(matches!(
            ProductionReviewEffectAdapter::open(&registry, uid()),
            Err("platform_v2_review_github_credentials_invalid")
        ));
    }

    #[test]
    fn registry_rejects_loose_permissions_and_symlinks() {
        let temporary = TempDir::new().unwrap();
        let registry = temporary.path().join("registry.json");
        write_registry(
            &registry,
            r#"{"version":1,"generation":"generation-1","bindings":[]}"#,
        );
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            ProductionReviewEffectAdapter::open(&registry, uid()),
            Err("platform_v2_review_registry_insecure")
        ));
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).unwrap();
        let link = temporary.path().join("link.json");
        symlink(&registry, &link).unwrap();
        assert!(matches!(
            ProductionReviewEffectAdapter::open(&link, uid()),
            Err("platform_v2_review_registry_insecure")
        ));
    }

    #[test]
    fn registry_rejects_every_special_permission_bit() {
        let temporary = TempDir::new().unwrap();
        let registry = temporary.path().join("registry.json");
        write_registry(
            &registry,
            r#"{"version":1,"generation":"generation-1","bindings":[]}"#,
        );
        for mode in [0o4600, 0o2600, 0o1600] {
            fs::set_permissions(&registry, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                fs::symlink_metadata(&registry)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                mode
            );
            assert!(matches!(
                ProductionReviewEffectAdapter::open(&registry, uid()),
                Err("platform_v2_review_registry_insecure")
            ));
        }
    }

    #[test]
    fn adapter_debug_is_redacted_for_every_private_target_field() {
        let temporary = TempDir::new().unwrap();
        let registry = temporary.path().join("registry.json");
        write_registry(
            &registry,
            r#"{"version":1,"generation":"sensitive-generation","bindings":[{"project":"project-sensitive","workspace_kind":"user_workspace","workspace_id":"workspace-sensitive","authority_kind":"ci","authority_id":"ci-sensitive","target":{"kind":"ci","provider":"provider-sensitive","target":"owner-sensitive/repository-sensitive","credential_reference":"credential-sensitive"}}]}"#,
        );
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        let rendered = format!("{adapter:?}");
        assert_eq!(
            rendered,
            "ProductionReviewEffectAdapter { installed: true }"
        );
        for private in [
            "sensitive-generation",
            "project-sensitive",
            "workspace-sensitive",
            "ci-sensitive",
            "provider-sensitive",
            "owner-sensitive/repository-sensitive",
            "credential-sensitive",
        ] {
            assert!(!rendered.contains(private));
        }
    }

    #[test]
    fn registry_generation_is_fenced_after_open() {
        let temporary = TempDir::new().unwrap();
        let registry = temporary.path().join("registry.json");
        write_registry(
            &registry,
            r#"{"version":1,"generation":"generation-1","bindings":[]}"#,
        );
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        write_registry(
            &registry,
            r#"{"version":1,"generation":"generation-2","bindings":[]}"#,
        );
        assert_eq!(
            adapter.plan(
                &ProjectId::new("project-1").unwrap(),
                &workspace(),
                &git_authority(),
                &action()
            ),
            Err("platform_v2_review_registry_changed")
        );
    }

    #[test]
    fn queued_registry_generation_is_securely_reverified_before_execution() {
        let temporary = TempDir::new().unwrap();
        let registry = temporary.path().join("registry.json");
        write_registry(
            &registry,
            r#"{"version":1,"generation":"generation-1","bindings":[]}"#,
        );
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        let expected = *adapter
            .installed
            .as_ref()
            .unwrap()
            .generation
            .digest
            .as_bytes();
        verify_registry_generation(&registry, uid(), expected).unwrap();
        write_registry(
            &registry,
            r#"{"version":1,"generation":"generation-2","bindings":[]}"#,
        );
        assert_eq!(
            verify_registry_generation(&registry, uid(), expected),
            Err("platform_v2_review_registry_changed")
        );
    }

    #[test]
    fn registry_rejects_duplicate_keys_and_cross_family_targets() {
        let temporary = TempDir::new().unwrap();
        let registry = temporary.path().join("registry.json");
        let duplicate = r#"{"version":1,"generation":"generation-1","bindings":[{"project":"project-1","workspace_kind":"user_workspace","workspace_id":"workspace-1","authority_kind":"ci","authority_id":"ci-1","target":{"kind":"ci","provider":"github","target":"owner/repository","credential_reference":"credential-1"}},{"project":"project-1","workspace_kind":"user_workspace","workspace_id":"workspace-1","authority_kind":"ci","authority_id":"ci-1","target":{"kind":"ci","provider":"github","target":"owner/repository","credential_reference":"credential-2"}}]}"#;
        write_registry(&registry, duplicate);
        assert!(matches!(
            ProductionReviewEffectAdapter::open(&registry, uid()),
            Err("platform_v2_review_registry_invalid")
        ));

        let incoherent = r#"{"version":1,"generation":"generation-1","bindings":[{"project":"project-1","workspace_kind":"user_workspace","workspace_id":"workspace-1","authority_kind":"git","authority_id":"git-1","target":{"kind":"ci","provider":"github","target":"owner/repository","credential_reference":"credential-1"}}]}"#;
        write_registry(&registry, incoherent);
        assert!(matches!(
            ProductionReviewEffectAdapter::open(&registry, uid()),
            Err("platform_v2_review_registry_invalid")
        ));
    }
}
