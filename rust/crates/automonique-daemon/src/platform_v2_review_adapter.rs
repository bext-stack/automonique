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

use automonique_protocol::digest::{Sha256, Sha256Digest};
use automonique_protocol::platform_v2::{ProjectId, WorkContextIdentity, WorkContextTargetKind};
use automonique_protocol::platform_v2_review::{
    ReviewAction, ReviewAuthority, ReviewAuthorityId, ReviewAuthorityKind,
};
use nix::libc;
use serde::Deserialize;

pub const REVIEW_REGISTRY_FILE_NAME: &str = "platform-v2-review-registry.json";

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
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RegistryTarget {
    LocalRepository {
        canonical_root: PathBuf,
    },
    RetainedSession {
        provider: String,
        session_id: String,
    },
    Ci {
        provider: String,
        target: String,
        credential_reference: String,
    },
    PullRequest {
        provider: String,
        repository: String,
        credential_reference: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReviewEffectPlan {
    LocalStore,
}

/// Registry-fenced review adapter composition.
///
/// `None` is represented by an empty adapter and retains the previous
/// fail-closed behavior. An installed malformed or insecure registry is an
/// error so production never silently ignores an operator mistake.
#[derive(Default)]
pub(crate) struct ProductionReviewEffectAdapter {
    installed: Option<InstalledRegistry>,
}

struct InstalledRegistry {
    path: PathBuf,
    expected_uid: u32,
    generation: FileGeneration,
    document: RegistryDocument,
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
        let Some(snapshot) = read_private_file(path, expected_uid)? else {
            return Ok(Self::default());
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
        // Resolve the private target before returning a family-specific
        // refusal. This proves the registry is coherent without revealing its
        // contents or treating its presence as authority to perform a write.
        if let Some(installed) = &self.installed {
            let binding = installed
                .document
                .bindings
                .iter()
                .find(|binding| binding.matches(project, workspace, authority));
            if let Some(binding) = binding
                && !binding.target.accepts(authority.kind())
            {
                return Err("platform_v2_review_registry_incoherent");
            }
        }
        Err(unavailable_category(action))
    }

    fn verify_generation(&self) -> Result<(), &'static str> {
        let Some(installed) = &self.installed else {
            return Ok(());
        };
        let current = read_private_file(&installed.path, installed.expected_uid)?
            .ok_or("platform_v2_review_registry_changed")?;
        if current.generation != installed.generation {
            return Err("platform_v2_review_registry_changed");
        }
        Ok(())
    }
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
            } => {
                if !safe_token(provider) || !safe_token(session_id) {
                    return Err("platform_v2_review_registry_invalid");
                }
            }
            RegistryTarget::Ci {
                provider,
                target,
                credential_reference,
            } => {
                if !safe_token(provider)
                    || !safe_coordinate(target)
                    || !safe_token(credential_reference)
                {
                    return Err("platform_v2_review_registry_invalid");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    use automonique_protocol::platform_v2::{ProjectId, UserWorkspaceId};
    use automonique_protocol::platform_v2_review::{ReviewAuthorityId, ReviewProposalId};
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
