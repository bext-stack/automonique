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
#[cfg(test)]
use std::sync::Arc;

use automonique_github_connector::{
    BranchName, GitHubToken, IssueNumber, RepoTarget, WorkflowRunId,
};
use automonique_protocol::digest::{Sha256, Sha256Digest};
use automonique_protocol::identity::Actor;
use automonique_protocol::platform_v2::{
    ProjectId, WorkContextIdentity, WorkContextTargetKind, WorkSessionId,
};
use automonique_protocol::platform_v2_review::{
    ConflictResolution, PullRequestId, ReviewAction, ReviewAuthority, ReviewAuthorityId,
    ReviewAuthorityKind, ReviewCheckId, ReviewField, ReviewFileId, ReviewProposalId,
    ReviewProposalKind,
};
use automonique_protocol::primitives::Revision;

use crate::platform_v2_git_worktree_adapter::{
    ConflictSide, GitStagingFamily, GitStagingGrants, GitWorktreeAdapter, GitWorktreeObservation,
    GitWorktreeState, GitWorktreeWriteCapability, RepositoryFile,
};
#[cfg(test)]
use crate::platform_v2_github_check_adapter::SharedGitHubActionsTransport;
use crate::platform_v2_github_check_adapter::{
    GitHubActionsWriteCapability, GitHubCheckRerunAdapter,
};
#[cfg(test)]
use crate::platform_v2_github_pull_request_adapter::SharedGitHubPullRequestTransport;
use crate::platform_v2_github_pull_request_adapter::{
    GitHubPullRequestAdapter, GitHubPullRequestFamily, GitHubPullRequestObservation,
    GitHubPullRequestWriteCapability,
};
use nix::libc;
use serde::Deserialize;
use serde::Deserializer;
use zeroize::{Zeroize, Zeroizing};

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
    bytes: Zeroizing<Vec<u8>>,
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
        /// Authority to move index entries: staging and unstaging.
        ///
        /// The two are one grant because they are each other's inverse on the
        /// same surface — anyone who can stage a file can unstage it — so
        /// splitting them would fence nothing.
        #[serde(default)]
        index_write: bool,
        /// Authority to record the index as a commit, held separately.
        ///
        /// This is the only local write that creates an object and moves a
        /// ref, the only one whose effect a push, a pull-request head or a CI
        /// trigger can observe, and the only one the review surface cannot
        /// undo. A deployment that wants an agent preparing changes from a
        /// phone but never recording them installs `index_write` alone.
        #[serde(default)]
        commit: bool,
        /// Authority to collapse an unmerged path to a side git recorded,
        /// held separately again because it is the only local write that
        /// overwrites working-tree bytes.
        ///
        /// All three default to false, so a binding installed before this
        /// existed keeps parsing and grants exactly what it granted before:
        /// nothing.
        #[serde(default)]
        conflict_resolution: bool,
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
        /// The branch a pull request lands onto. Operator-owned, never a
        /// client string: a review action names no branch, so a client can
        /// neither retarget a proposal nor point one at a protected branch it
        /// was not granted.
        #[serde(default)]
        base_branch: Option<String>,
        /// The branch a pull request proposes from, on the same terms.
        ///
        /// Both are optional so a document installed before the pull-request
        /// adapter existed keeps parsing. Migration grants nothing: a binding
        /// without them can plan no pull-request action at all, which is
        /// exactly what it could do before.
        #[serde(default)]
        head_branch: Option<String>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GitHubCredentialDocument {
    version: u8,
    generation: String,
    #[serde(default)]
    credentials: Vec<GitHubCredential>,
}

struct SecretString(Zeroizing<String>);

impl SecretString {
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn take_bytes(&mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut *self.0).into_bytes())
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

#[cfg(test)]
std::thread_local! {
    static SECRET_STRING_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        SECRET_STRING_DROPS.with(|drops| drops.set(drops.get() + 1));
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GitHubCredential {
    reference: String,
    repository: String,
    actions_write: bool,
    /// Authority to open and update pull requests, held separately from
    /// `actions_write`.
    ///
    /// Re-running a workflow re-executes something a maintainer already
    /// approved onto a ref that already exists. Writing a pull request
    /// proposes new code. They are different powers, so installing one must
    /// never confer the other, and an operator who wants CI reruns from a
    /// phone must not get repository writes as a side effect.
    ///
    /// Defaulted rather than required so an installed credential document
    /// keeps parsing across the upgrade. Migration is silent and grants
    /// nothing: an existing document has neither flag, so it can do exactly
    /// what it could before.
    #[serde(default)]
    pull_request_write: bool,
    /// Authority to merge a pull request, held separately again.
    ///
    /// This is the only credential scope whose use can move code into a
    /// protected branch and trigger a deploy, so it is never implied by
    /// `pull_request_write`. A deployment that wants an agent to propose
    /// changes but never land them installs the write scope alone.
    #[serde(default)]
    pull_request_merge: bool,
    token: SecretString,
}

struct InstalledGitHubCredentialDocument {
    credentials: Vec<InstalledGitHubCredential>,
}

/// What the capability surface already knows about one pull request.
///
/// A grouping for one call, never a grant: every field here came from the
/// server-owned review snapshot, and none of it is proof the provider would
/// admit anything.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PullRequestCapabilityTarget<'a> {
    pub family: GitHubPullRequestFamily,
    /// Absent exactly when the family is `Open`.
    pub number: Option<IssueNumber>,
    /// Present only for a merge, which is the one family the snapshot pins a
    /// head for.
    pub expected_head_revision: Option<&'a ReviewField>,
    pub expected_pull_request_revision: Revision,
}

/// What the capability surface already knows about one staging proposal.
///
/// A grouping for one call, never a grant: every field came from the
/// server-owned review snapshot, and none of it is proof the repository is in
/// a state where the write can be performed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GitStagingCapabilityTarget<'a> {
    pub proposal_id: &'a ReviewProposalId,
    pub kind: ReviewProposalKind,
    /// Present exactly when the kind is `ResolveConflict`.
    pub file_id: Option<&'a ReviewFileId>,
    /// Present exactly when the kind is `ResolveConflict`.
    pub resolution: Option<ConflictResolution>,
}

/// The pull-request powers one installed credential carries.
///
/// Two independent flags rather than a level, because they are withheld
/// independently: a deployment that wants an agent to propose changes but
/// never land them installs `write` alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GitHubPullRequestScopes {
    pub write: bool,
    pub merge: bool,
}

struct InstalledGitHubCredential {
    reference: String,
    repository: String,
    actions_write: bool,
    pull_request_write: bool,
    pull_request_merge: bool,
    token: Zeroizing<Vec<u8>>,
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
    /// One of the three independently withheld pull-request writes.
    ///
    /// Everything here is either operator-owned (repository, branches,
    /// credential) or already fenced by the server-owned review snapshot
    /// (`number`, `expected_head_revision`, `expected_pull_request_revision`).
    /// No client string appears at all. The title an open or an update carries
    /// is deliberately absent: it names nothing the server must agree about,
    /// so it stays client-owned and unfenced, and a plan can therefore be
    /// built for advertisement before any client has chosen one.
    ///
    /// A plan is not yet a capability. It says a write *could* be addressed;
    /// only [`ProductionReviewEffectAdapter::preflight_github_pull_request_capability`]
    /// can say the provider would admit one.
    GitHubPullRequest {
        family: GitHubPullRequestFamily,
        credential_reference: String,
        repository: RepoTarget,
        base_branch: BranchName,
        head_branch: BranchName,
        /// The GitHub pull-request number, absent only for an open.
        number: Option<IssueNumber>,
        /// The head the review snapshot pinned, for a merge only. The other
        /// two families learn their head from the preflight instead, because
        /// the snapshot has none to pin for an open and an update is not
        /// head-sensitive.
        expected_head_revision: Option<String>,
        /// Whether the installed credential also carries the merge scope.
        /// Carried into the capability so the adapter refuses a merge on its
        /// own account, independently of this module's own check.
        merge_allowed: bool,
        expected_pull_request_revision: Revision,
        registry_generation: [u8; 32],
        credential_generation: [u8; 32],
    },
    /// One of the three independently withheld local repository writes.
    ///
    /// Everything here is operator-owned — the canonical root and the grants
    /// come from the registry — or server-owned: the proposal id reaching this
    /// point came from the review snapshot, and `ReviewSnapshot::resolve_action`
    /// has already refused any id the snapshot does not hold at the kind the
    /// action claims. No client string appears at all.
    ///
    /// Deliberately absent: the files. A plan says a write *could* be
    /// addressed to this repository; it does not carry what the write would
    /// touch, because that is read from the repository by
    /// [`ProductionReviewEffectAdapter::observe_git_staging`] rather than
    /// declared. A registry binding and an installed grant prove a
    /// configuration, never a worktree.
    GitStaging {
        family: GitStagingFamily,
        canonical_root: PathBuf,
        grants: GitStagingGrants,
        proposal_id: ReviewProposalId,
        registry_generation: [u8; 32],
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
    #[cfg(test)]
    github_test_transport: Option<SharedGitHubActionsTransport>,
    #[cfg(test)]
    github_pull_request_test_transport: Option<SharedGitHubPullRequestTransport>,
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
    document: InstalledGitHubCredentialDocument,
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
            Some(mut snapshot) => {
                let document = parse_github_credentials(&mut snapshot.bytes)?;
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
                #[cfg(test)]
                github_test_transport: None,
                #[cfg(test)]
                github_pull_request_test_transport: None,
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
            #[cfg(test)]
            github_test_transport: None,
            #[cfg(test)]
            github_pull_request_test_transport: None,
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
            if check.observed_attempt.checked_add(1).is_none()
                || check_revision
                    .get()
                    .checked_add(1)
                    .and_then(|next| Revision::new(next).ok())
                    .is_none()
            {
                return Err("platform_v2_review_registry_incoherent");
            }
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
        // A staging action now reaches a repository plan. The plan carries the
        // operator's canonical root and grants and nothing else: it says which
        // repository a write would be addressed to, never that the repository
        // is in a state where the write can be performed. Only
        // `observe_git_staging`, reading the worktree, can say that.
        if let (
            Some(installed),
            Some(RegistryBinding {
                target:
                    RegistryTarget::LocalRepository {
                        canonical_root,
                        index_write,
                        commit,
                        conflict_resolution,
                    },
                ..
            }),
        ) = (&self.installed, binding)
            && let Some((family, proposal_id)) = staging_family(action)
        {
            let grants = GitStagingGrants {
                index_write: *index_write,
                commit: *commit,
                conflict_resolution: *conflict_resolution,
            };
            // A binding installed before the grants existed carries none. It
            // can plan nothing, which is exactly what it could do before, and
            // it says so rather than assuming an operator meant to allow
            // everything they had no way to spell.
            if !grants.any() {
                return Err("platform_v2_review_git_grants_unavailable");
            }
            // Each grant is refused on its own account, so an operator can
            // tell a withheld commit from a withheld conflict resolution and
            // from a binding that grants nothing at all.
            if !grants.allows(family) {
                return Err(match family {
                    GitStagingFamily::Commit => "platform_v2_review_git_commit_unavailable",
                    GitStagingFamily::ResolveConflict => {
                        "platform_v2_review_git_conflict_resolution_unavailable"
                    }
                    GitStagingFamily::Stage | GitStagingFamily::Unstage => {
                        "platform_v2_review_git_index_write_unavailable"
                    }
                });
            }
            return Ok(ReviewEffectPlan::GitStaging {
                family,
                canonical_root: canonical_root.clone(),
                grants,
                proposal_id: proposal_id.clone(),
                registry_generation: *installed.generation.digest.as_bytes(),
            });
        }
        // A pull-request action now reaches a provider plan, but a plan is
        // still not authority. Every refusal below stays specific, so an
        // operator can tell an incomplete credential from a binding that
        // names no branches, and the merge scope stays observably withheld on
        // its own rather than only declared.
        if matches!(
            action,
            ReviewAction::OpenPullRequest { .. }
                | ReviewAction::UpdatePullRequest { .. }
                | ReviewAction::MergePullRequest { .. }
        ) && let (
            Some(installed),
            Some(RegistryBinding {
                target:
                    RegistryTarget::PullRequest {
                        provider,
                        repository,
                        credential_reference,
                        base_branch,
                        head_branch,
                    },
                ..
            }),
        ) = (&self.installed, binding)
        {
            if provider != "github" {
                return Err("platform_v2_review_pull_request_provider_unavailable");
            }
            let scopes = self
                .github_pull_request_scopes(credential_reference)
                .ok_or("platform_v2_review_pull_request_credential_unavailable")?;
            if !self.github_credential_matches_repository(credential_reference, repository) {
                return Err("platform_v2_review_pull_request_credential_incoherent");
            }
            if !scopes.write {
                return Err("platform_v2_review_pull_request_credential_unavailable");
            }
            // Merging is withheld on its own. A credential that may propose
            // changes must not be able to land them, and that stays true
            // now that the adapter exists rather than only before it.
            if matches!(action, ReviewAction::MergePullRequest { .. }) && !scopes.merge {
                return Err("platform_v2_review_pull_request_merge_unavailable");
            }
            // A binding installed before the adapter existed names no
            // branches. It can plan nothing, which is exactly what it could
            // do before, and it says so rather than guessing a default branch.
            let (Some(base_branch), Some(head_branch)) = (base_branch, head_branch) else {
                return Err("platform_v2_review_pull_request_branches_unavailable");
            };
            let base_branch = BranchName::new(base_branch)
                .map_err(|_| "platform_v2_review_registry_incoherent")?;
            let head_branch = BranchName::new(head_branch)
                .map_err(|_| "platform_v2_review_registry_incoherent")?;
            if base_branch == head_branch {
                return Err("platform_v2_review_registry_incoherent");
            }
            let credentials = self
                .github_credentials
                .as_ref()
                .ok_or("platform_v2_review_pull_request_credential_unavailable")?;
            let (family, number, expected_head_revision, expected_pull_request_revision) =
                match action {
                    ReviewAction::OpenPullRequest {
                        expected_pull_request_revision,
                        ..
                    } => (
                        GitHubPullRequestFamily::Open,
                        None,
                        None,
                        *expected_pull_request_revision,
                    ),
                    ReviewAction::UpdatePullRequest {
                        pull_request_id,
                        expected_pull_request_revision,
                        ..
                    } => (
                        GitHubPullRequestFamily::Update,
                        Some(github_pull_request_number(pull_request_id)?),
                        None,
                        *expected_pull_request_revision,
                    ),
                    ReviewAction::MergePullRequest {
                        pull_request_id,
                        expected_pull_request_revision,
                        expected_head_revision,
                    } => (
                        GitHubPullRequestFamily::Merge,
                        Some(github_pull_request_number(pull_request_id)?),
                        Some(github_head_revision(expected_head_revision)?),
                        *expected_pull_request_revision,
                    ),
                    _ => return Err("platform_v2_review_plan_invalid"),
                };
            if expected_pull_request_revision
                .get()
                .checked_add(1)
                .and_then(|next| Revision::new(next).ok())
                .is_none()
            {
                return Err("platform_v2_review_registry_incoherent");
            }
            return Ok(ReviewEffectPlan::GitHubPullRequest {
                family,
                credential_reference: credential_reference.clone(),
                repository: parse_repository(repository)?,
                base_branch,
                head_branch,
                number,
                expected_head_revision,
                merge_allowed: scopes.merge,
                expected_pull_request_revision,
                registry_generation: *installed.generation.digest.as_bytes(),
                credential_generation: *credentials.generation.digest.as_bytes(),
            });
        }
        Err(unavailable_category(action))
    }

    fn github_credential_matches_repository(&self, reference: &str, repository: &str) -> bool {
        self.github_credentials.as_ref().is_some_and(|installed| {
            installed.document.credentials.iter().any(|candidate| {
                candidate.reference == reference && candidate.repository == repository
            })
        })
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
        // The typed connector owns this one short-lived copy. The installed
        // credential remains in its zeroizing container and is never Clone or
        // Debug; the client copy is scrubbed by GitHubToken on drop.
        #[cfg(test)]
        let capability = if let Some(transport) = &self.github_test_transport {
            GitHubActionsWriteCapability::testing(
                credential_reference,
                repository.clone(),
                Arc::clone(transport),
            )
            .map_err(|_| "platform_v2_review_ci_credential_invalid")?
        } else {
            let token = GitHubToken::new(credential.token.to_vec())
                .map_err(|_| "platform_v2_review_ci_credential_invalid")?;
            GitHubActionsWriteCapability::production(
                credential_reference,
                repository.clone(),
                token,
            )
            .map_err(|_| "platform_v2_review_ci_credential_invalid")?
        };
        #[cfg(not(test))]
        let capability = {
            let token = GitHubToken::new(credential.token.to_vec())
                .map_err(|_| "platform_v2_review_ci_credential_invalid")?;
            GitHubActionsWriteCapability::production(
                credential_reference,
                repository.clone(),
                token,
            )
            .map_err(|_| "platform_v2_review_ci_credential_invalid")?
        };
        Ok(GitHubCheckRerunAdapter::new(capability))
    }

    /// Build the plan for one pull-request family without an action.
    ///
    /// The capability surface must decide whether to advertise a control
    /// *before* any client has named a title, so this takes only what the
    /// server already owns: the review coordinate, the family, and the
    /// identity the snapshot pinned. `plan` is the same computation reached
    /// from an action; both funnel through the identical binding, scope and
    /// branch checks, so a control can never be advertised on a looser test
    /// than the one the write is admitted under.
    pub(crate) fn pull_request_effect_plan(
        &self,
        project: &ProjectId,
        workspace: &WorkContextIdentity,
        authority: &ReviewAuthority,
        target: PullRequestCapabilityTarget<'_>,
    ) -> Result<ReviewEffectPlan, &'static str> {
        let PullRequestCapabilityTarget {
            family,
            number,
            expected_head_revision,
            expected_pull_request_revision,
        } = target;
        // Reaching the same arm as an action does keeps the two paths honest:
        // a placeholder title is never sent anywhere, because the plan does
        // not carry one.
        let probe = match family {
            GitHubPullRequestFamily::Open => ReviewAction::OpenPullRequest {
                expected_pull_request_revision,
                title: ReviewField::new("capability-probe")
                    .map_err(|_| "platform_v2_review_plan_invalid")?,
            },
            GitHubPullRequestFamily::Update => ReviewAction::UpdatePullRequest {
                pull_request_id: PullRequestId::new(
                    number
                        .ok_or("platform_v2_review_pull_request_identity_invalid")?
                        .get()
                        .to_string(),
                )
                .map_err(|_| "platform_v2_review_pull_request_identity_invalid")?,
                expected_pull_request_revision,
                title: ReviewField::new("capability-probe")
                    .map_err(|_| "platform_v2_review_plan_invalid")?,
            },
            GitHubPullRequestFamily::Merge => ReviewAction::MergePullRequest {
                pull_request_id: PullRequestId::new(
                    number
                        .ok_or("platform_v2_review_pull_request_identity_invalid")?
                        .get()
                        .to_string(),
                )
                .map_err(|_| "platform_v2_review_pull_request_identity_invalid")?,
                expected_pull_request_revision,
                expected_head_revision: expected_head_revision
                    .ok_or("platform_v2_review_pull_request_identity_invalid")?
                    .clone(),
            },
        };
        self.plan(project, workspace, authority, &probe)
    }

    /// Mint the fixed-origin pull-request capability for one exact plan.
    ///
    /// The credential is re-read and re-verified here, not trusted from the
    /// plan: a credential document swapped between planning and execution must
    /// invalidate the write rather than silently perform it with a different
    /// token.
    pub(crate) fn github_pull_request_adapter(
        &self,
        credential_reference: &str,
        repository: &RepoTarget,
        base_branch: &BranchName,
        head_branch: &BranchName,
        require_merge: bool,
        expected_generation: [u8; 32],
    ) -> Result<GitHubPullRequestAdapter, &'static str> {
        self.verify_github_credential_generation(Some(expected_generation))
            .map_err(|_| "platform_v2_review_pull_request_credentials_changed")?;
        let installed = self
            .github_credentials
            .as_ref()
            .ok_or("platform_v2_review_pull_request_credential_unavailable")?;
        let coordinate = repository.to_string();
        let credential = installed
            .document
            .credentials
            .iter()
            .find(|candidate| candidate.reference == credential_reference)
            .ok_or("platform_v2_review_pull_request_credential_unavailable")?;
        if !credential.pull_request_write || credential.repository != coordinate {
            return Err("platform_v2_review_pull_request_credential_incoherent");
        }
        // Merge is checked here as well as in `plan`. A credential that may
        // propose changes must not be able to land them however the caller
        // reached this point.
        if require_merge && !credential.pull_request_merge {
            return Err("platform_v2_review_pull_request_merge_unavailable");
        }
        // The typed connector owns this one short-lived copy. The installed
        // credential remains in its zeroizing container and is never Clone or
        // Debug; the client copy is scrubbed by GitHubToken on drop.
        #[cfg(test)]
        let capability = if let Some(transport) = &self.github_pull_request_test_transport {
            GitHubPullRequestWriteCapability::testing(
                credential_reference,
                repository.clone(),
                base_branch.clone(),
                head_branch.clone(),
                credential.pull_request_merge,
                Arc::clone(transport),
            )
            .map_err(|_| "platform_v2_review_pull_request_credential_invalid")?
        } else {
            let token = GitHubToken::new(credential.token.to_vec())
                .map_err(|_| "platform_v2_review_pull_request_credential_invalid")?;
            GitHubPullRequestWriteCapability::production(
                credential_reference,
                repository.clone(),
                base_branch.clone(),
                head_branch.clone(),
                credential.pull_request_merge,
                token,
            )
            .map_err(|_| "platform_v2_review_pull_request_credential_invalid")?
        };
        #[cfg(not(test))]
        let capability = {
            let token = GitHubToken::new(credential.token.to_vec())
                .map_err(|_| "platform_v2_review_pull_request_credential_invalid")?;
            GitHubPullRequestWriteCapability::production(
                credential_reference,
                repository.clone(),
                base_branch.clone(),
                head_branch.clone(),
                credential.pull_request_merge,
                token,
            )
            .map_err(|_| "platform_v2_review_pull_request_credential_invalid")?
        };
        Ok(GitHubPullRequestAdapter::new(capability))
    }

    /// Advertise a pull-request write only after a fresh, mutation-free
    /// provider read proves the exact thing the write depends on.
    ///
    /// The returned observation is the only thing a capability slot may be
    /// minted from, and it is what the confirmation digest commits to. What
    /// each family's read proves is documented on
    /// [`GitHubPullRequestAdapter::preflight_observation`]; in one line each:
    /// an open proves both branches exist, pins the head commit it would
    /// propose, and proves nothing is already open for the pair; an update
    /// proves the numbered pull request is open on that exact pair; a merge
    /// proves all of that plus that GitHub itself calls it mergeable at the
    /// head the snapshot pinned.
    pub(crate) fn preflight_github_pull_request_capability(
        &self,
        plan: &ReviewEffectPlan,
    ) -> Result<GitHubPullRequestObservation, &'static str> {
        let ReviewEffectPlan::GitHubPullRequest {
            family,
            credential_reference,
            repository,
            base_branch,
            head_branch,
            number,
            expected_head_revision,
            merge_allowed,
            credential_generation,
            ..
        } = plan
        else {
            return Err("platform_v2_review_pull_request_adapter_unavailable");
        };
        let merge = *family == GitHubPullRequestFamily::Merge;
        if merge && !*merge_allowed {
            return Err("platform_v2_review_pull_request_merge_unavailable");
        }
        let adapter = self.github_pull_request_adapter(
            credential_reference,
            repository,
            base_branch,
            head_branch,
            merge,
            *credential_generation,
        )?;
        adapter
            .preflight_observation(
                repository,
                *family,
                *number,
                expected_head_revision.as_deref(),
            )
            .map_err(|_| "platform_v2_review_pull_request_preflight_refused")
    }

    /// Commit an inert client confirmation to the exact actor, review
    /// coordinate, provider target, live observation, and installed
    /// registry/credential generations that were preflighted.
    ///
    /// The observation is part of the digest, which is what makes this
    /// revision-binding rather than merely authenticated: a branch that moves
    /// between advertisement and execution produces a different digest, so the
    /// client's confirmation stops matching and the write is refused instead
    /// of landing a change nobody saw.
    ///
    /// The title is deliberately not committed to. It is client-owned and
    /// names nothing the server must agree about; the repository, the branch
    /// pair and the pull request are all operator- or server-owned and every
    /// one of them is committed to here. Fencing the title would also make a
    /// slot unadvertisable, since the server must decide whether the control
    /// exists before any client has chosen one.
    #[allow(clippy::too_many_arguments)] // Every field is an independently fenced commitment input.
    pub(crate) fn github_pull_request_confirmation_digest(
        &self,
        actor: &Actor,
        project: &ProjectId,
        workspace: &WorkContextIdentity,
        authority: &ReviewAuthority,
        snapshot_revision: Revision,
        workspace_revision: Revision,
        plan: &ReviewEffectPlan,
        observation: &GitHubPullRequestObservation,
    ) -> Result<[u8; 32], &'static str> {
        let ReviewEffectPlan::GitHubPullRequest {
            family,
            credential_reference,
            repository,
            base_branch,
            head_branch,
            number,
            expected_head_revision,
            expected_pull_request_revision,
            registry_generation,
            credential_generation,
            ..
        } = plan
        else {
            return Err("platform_v2_review_confirmation_invalid");
        };
        // The observation must be of the thing the plan names. A digest minted
        // over a read of some other pull request would commit to nothing.
        if observation.family() != *family || observation.number() != *number {
            return Err("platform_v2_review_confirmation_invalid");
        }
        if *family == GitHubPullRequestFamily::Merge
            && (!observation.mergeable()
                || expected_head_revision.as_deref() != Some(observation.head_sha()))
        {
            return Err("platform_v2_review_confirmation_invalid");
        }
        let mut document = Vec::new();
        push_confirmation_field(
            &mut document,
            b"automonique.review-pull-request-confirmation/v1",
        );
        for field in [
            registry_generation.as_slice(),
            credential_generation.as_slice(),
            actor.tenant().as_bytes(),
            actor.id().as_bytes(),
            project.as_str().as_bytes(),
            workspace.kind().as_str().as_bytes(),
            workspace.id().as_bytes(),
            authority.kind().as_str().as_bytes(),
            authority.id().as_str().as_bytes(),
            credential_reference.as_bytes(),
            repository.owner().as_str().as_bytes(),
            repository.repo().as_str().as_bytes(),
            family.as_str().as_bytes(),
            base_branch.as_str().as_bytes(),
            head_branch.as_str().as_bytes(),
            // The live head, not one an operator declared. This is the field
            // that makes the digest expire when the branch moves.
            observation.head_sha().as_bytes(),
            expected_head_revision
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        ] {
            push_confirmation_field(&mut document, field);
        }
        push_confirmation_field(
            &mut document,
            &number
                .map(IssueNumber::get)
                .unwrap_or_default()
                .to_be_bytes(),
        );
        push_confirmation_field(
            &mut document,
            &[
                u8::from(number.is_some()),
                u8::from(expected_head_revision.is_some()),
                u8::from(observation.mergeable()),
            ],
        );
        push_confirmation_field(&mut document, &snapshot_revision.get().to_be_bytes());
        push_confirmation_field(&mut document, &workspace_revision.get().to_be_bytes());
        push_confirmation_field(
            &mut document,
            &expected_pull_request_revision.get().to_be_bytes(),
        );
        Ok(*Sha256::digest(&document).as_bytes())
    }

    /// The receipt correlation for one pull-request confirmation.
    ///
    /// Domain-separated from the check-rerun correlation so a receipt minted
    /// for one family can never be recovered against the other.
    pub(crate) fn github_pull_request_receipt_correlation_digest(
        confirmation: [u8; 32],
    ) -> [u8; 32] {
        let mut document = Vec::new();
        push_confirmation_field(
            &mut document,
            b"automonique.review-pull-request-receipt-correlation/v1",
        );
        push_confirmation_field(&mut document, &confirmation);
        *Sha256::digest(&document).as_bytes()
    }

    #[cfg(test)]
    pub(crate) fn set_github_test_transport(&mut self, transport: SharedGitHubActionsTransport) {
        self.github_test_transport = Some(transport);
    }

    #[cfg(test)]
    pub(crate) fn set_github_pull_request_test_transport(
        &mut self,
        transport: SharedGitHubPullRequestTransport,
    ) {
        self.github_pull_request_test_transport = Some(transport);
    }

    /// Advertise a rerun only after a fresh, mutation-free provider GET proves
    /// the registry's exact run attempt, head SHA, and completed status.
    pub(crate) fn preflight_github_capability(
        &self,
        plan: &ReviewEffectPlan,
    ) -> Result<(), &'static str> {
        let ReviewEffectPlan::GitHubCheckRerun {
            credential_reference,
            repository,
            run_id,
            head_sha,
            observed_attempt,
            credential_generation,
            ..
        } = plan
        else {
            return Err("platform_v2_review_ci_check_unavailable");
        };
        let adapter =
            self.github_adapter(credential_reference, repository, *credential_generation)?;
        adapter
            .preflight_observation(repository, *run_id, head_sha, *observed_attempt)
            .map_err(|_| "platform_v2_review_ci_preflight_refused")
    }

    /// Commit an inert client confirmation to the exact actor, review
    /// coordinate, provider target, and installed registry/credential
    /// generations that were preflighted for advertisement.
    #[allow(clippy::too_many_arguments)] // Every field is an independently fenced commitment input.
    pub(crate) fn github_confirmation_digest(
        &self,
        actor: &Actor,
        project: &ProjectId,
        workspace: &WorkContextIdentity,
        authority: &ReviewAuthority,
        snapshot_revision: Revision,
        workspace_revision: Revision,
        action: &ReviewAction,
        plan: &ReviewEffectPlan,
    ) -> Result<[u8; 32], &'static str> {
        let (
            ReviewAction::RerunCheck {
                check_id,
                expected_check_revision,
            },
            ReviewEffectPlan::GitHubCheckRerun {
                credential_reference,
                repository,
                run_id,
                head_sha,
                observed_attempt,
                expected_check_revision: plan_check_revision,
                registry_generation,
                credential_generation,
            },
        ) = (action, plan)
        else {
            return Err("platform_v2_review_confirmation_invalid");
        };
        if expected_check_revision != plan_check_revision {
            return Err("platform_v2_review_confirmation_invalid");
        }
        let mut document = Vec::new();
        push_confirmation_field(&mut document, b"automonique.review-rerun-confirmation/v1");
        for field in [
            registry_generation.as_slice(),
            credential_generation.as_slice(),
            actor.tenant().as_bytes(),
            actor.id().as_bytes(),
            project.as_str().as_bytes(),
            workspace.kind().as_str().as_bytes(),
            workspace.id().as_bytes(),
            authority.kind().as_str().as_bytes(),
            authority.id().as_str().as_bytes(),
            credential_reference.as_bytes(),
            repository.owner().as_str().as_bytes(),
            repository.repo().as_str().as_bytes(),
            head_sha.as_bytes(),
            check_id.as_str().as_bytes(),
        ] {
            push_confirmation_field(&mut document, field);
        }
        push_confirmation_field(&mut document, &run_id.get().to_be_bytes());
        push_confirmation_field(&mut document, &observed_attempt.to_be_bytes());
        push_confirmation_field(&mut document, &snapshot_revision.get().to_be_bytes());
        push_confirmation_field(&mut document, &workspace_revision.get().to_be_bytes());
        push_confirmation_field(&mut document, &expected_check_revision.get().to_be_bytes());
        Ok(*Sha256::digest(&document).as_bytes())
    }

    /// Build the plan for one staging proposal without an action.
    ///
    /// The capability surface must decide whether to advertise a control from
    /// what the snapshot already holds — a proposal id, its kind, and for a
    /// conflict resolution the file and side. `plan` is the same computation
    /// reached from an action; both funnel through the identical binding and
    /// grant checks, so a control can never be advertised on a looser test
    /// than the write is admitted under.
    pub(crate) fn git_staging_effect_plan(
        &self,
        project: &ProjectId,
        workspace: &WorkContextIdentity,
        authority: &ReviewAuthority,
        target: GitStagingCapabilityTarget<'_>,
    ) -> Result<ReviewEffectPlan, &'static str> {
        self.plan(project, workspace, authority, &staging_probe(target)?)
    }

    /// Mint the fixed-root capability for one exact plan.
    ///
    /// The registry is re-read and re-verified here, not trusted from the
    /// plan: a registry swapped between planning and execution must invalidate
    /// the write rather than silently perform it against a different
    /// repository. The capability itself then re-validates the root on disk,
    /// because a directory can be replaced after a registry was read.
    pub(crate) fn git_worktree_adapter(
        &self,
        canonical_root: &Path,
        grants: GitStagingGrants,
        expected_generation: [u8; 32],
    ) -> Result<GitWorktreeAdapter, &'static str> {
        let installed = self
            .installed
            .as_ref()
            .ok_or("platform_v2_review_git_adapter_unavailable")?;
        verify_registry_generation(&installed.path, installed.expected_uid, expected_generation)?;
        // The grants are re-read from the freshly verified document rather
        // than taken from the plan, so a binding whose grants were narrowed
        // between advertisement and execution narrows the write too.
        let installed_grants = installed
            .document
            .bindings
            .iter()
            .find_map(|binding| match &binding.target {
                RegistryTarget::LocalRepository {
                    canonical_root: root,
                    index_write,
                    commit,
                    conflict_resolution,
                } if root == canonical_root => Some(GitStagingGrants {
                    index_write: *index_write,
                    commit: *commit,
                    conflict_resolution: *conflict_resolution,
                }),
                _ => None,
            })
            .ok_or("platform_v2_review_git_repository_unavailable")?;
        if installed_grants != grants {
            return Err("platform_v2_review_git_grants_changed");
        }
        let capability = GitWorktreeWriteCapability::production(
            canonical_root,
            installed.expected_uid,
            installed_grants,
        )
        .map_err(|_| "platform_v2_review_git_repository_unavailable")?;
        Ok(GitWorktreeAdapter::new(capability))
    }

    /// Take the one mutation-free repository read every staging capability in
    /// a response is minted from.
    ///
    /// Taken once for every path a snapshot names, so each control the
    /// response carries names the same `HEAD` and the same index by
    /// construction rather than by a check after the fact.
    pub(crate) fn git_worktree_state(
        &self,
        plan: &ReviewEffectPlan,
        paths: &[RepositoryFile],
    ) -> Result<GitWorktreeState, &'static str> {
        let ReviewEffectPlan::GitStaging {
            canonical_root,
            grants,
            registry_generation,
            ..
        } = plan
        else {
            return Err("platform_v2_review_git_adapter_unavailable");
        };
        self.git_worktree_adapter(canonical_root, *grants, *registry_generation)?
            .read(paths)
            .map_err(|_| "platform_v2_review_git_repository_unavailable")
    }

    /// Advertise a staging write only after that read proves the exact thing
    /// the write depends on.
    ///
    /// The returned observation is the only thing a capability slot may be
    /// minted from, and it is what the confirmation digest commits to. What
    /// each family's read proves is documented on
    /// [`GitWorktreeAdapter::observe`]; in one line each: a stage proves every
    /// named file has changes the index does not hold; an unstage proves every
    /// named file's index entry differs from `HEAD`; a commit proves the whole
    /// index is exactly the proposal, on an attached branch, in a repository
    /// that is in no multi-step operation and names a committer; and a
    /// conflict resolution proves the one named path is unmerged with the
    /// requested side actually recorded.
    pub(crate) fn observe_git_staging(
        &self,
        plan: &ReviewEffectPlan,
        state: &GitWorktreeState,
        paths: &[RepositoryFile],
        side: Option<ConflictSide>,
    ) -> Result<GitWorktreeObservation, &'static str> {
        let ReviewEffectPlan::GitStaging {
            family,
            canonical_root,
            grants,
            registry_generation,
            ..
        } = plan
        else {
            return Err("platform_v2_review_git_adapter_unavailable");
        };
        self.git_worktree_adapter(canonical_root, *grants, *registry_generation)?
            .observe(state, *family, paths, side)
            .map_err(|_| "platform_v2_review_git_preflight_refused")
    }

    /// Read and observe in one step, for the execution path where exactly one
    /// proposal is in play.
    pub(crate) fn preflight_git_staging_capability(
        &self,
        plan: &ReviewEffectPlan,
        paths: &[RepositoryFile],
        side: Option<ConflictSide>,
    ) -> Result<GitWorktreeObservation, &'static str> {
        let state = self.git_worktree_state(plan, paths)?;
        self.observe_git_staging(plan, &state, paths, side)
    }

    /// Commit an inert client confirmation to the exact actor, review
    /// coordinate, repository, grants, live observation, and installed
    /// registry generation that were preflighted.
    ///
    /// The observation is part of the digest, which is what makes this
    /// worktree-binding rather than merely authenticated. It carries the
    /// commit `HEAD` resolved to, the branch it is attached to, the whole
    /// index, and each named file's objects, conflict stages and working-tree
    /// stat identity — so a repository that moves between advertisement and
    /// execution produces a different digest, the client's confirmation stops
    /// matching, and the write is refused instead of landing against a state
    /// nobody saw.
    ///
    /// This is the field set PR #221 recorded as unavailable. It is not
    /// derived from the proposal or from the snapshot revision, neither of
    /// which pins a worktree; it is read from the repository.
    #[allow(clippy::too_many_arguments)] // Every field is an independently fenced commitment input.
    pub(crate) fn git_staging_confirmation_digest(
        &self,
        actor: &Actor,
        project: &ProjectId,
        workspace: &WorkContextIdentity,
        authority: &ReviewAuthority,
        snapshot_revision: Revision,
        workspace_revision: Revision,
        plan: &ReviewEffectPlan,
        conflict: Option<(&ReviewFileId, ConflictResolution)>,
        observation: &GitWorktreeObservation,
    ) -> Result<[u8; 32], &'static str> {
        let ReviewEffectPlan::GitStaging {
            family,
            canonical_root,
            grants,
            proposal_id,
            registry_generation,
        } = plan
        else {
            return Err("platform_v2_review_confirmation_invalid");
        };
        // The observation must be of the thing the plan names, and a
        // resolution's side must be the one the client will send. A digest
        // minted over a read of some other family, or of the other side of the
        // conflict, would commit to nothing.
        if observation.family() != *family
            || observation.side()
                != conflict.map(|(_, resolution)| ConflictSide::from_resolution(resolution))
            || (*family == GitStagingFamily::ResolveConflict) != conflict.is_some()
        {
            return Err("platform_v2_review_confirmation_invalid");
        }
        let mut document = Vec::new();
        push_confirmation_field(
            &mut document,
            b"automonique.review-git-staging-confirmation/v1",
        );
        push_confirmation_field(&mut document, registry_generation.as_slice());
        push_confirmation_field(&mut document, canonical_root.as_os_str().as_encoded_bytes());
        for field in [
            actor.tenant().as_bytes(),
            actor.id().as_bytes(),
            project.as_str().as_bytes(),
            workspace.kind().as_str().as_bytes(),
            workspace.id().as_bytes(),
            authority.kind().as_str().as_bytes(),
            authority.id().as_str().as_bytes(),
            family.as_str().as_bytes(),
            proposal_id.as_str().as_bytes(),
            conflict.map_or("", |(file, _)| file.as_str()).as_bytes(),
            conflict
                .map_or("", |(_, resolution)| resolution.as_str())
                .as_bytes(),
        ] {
            push_confirmation_field(&mut document, field);
        }
        // The grants are inside the digest, so a control advertised under one
        // set cannot be executed after an operator narrowed them.
        push_confirmation_field(
            &mut document,
            &[
                u8::from(grants.index_write),
                u8::from(grants.commit),
                u8::from(grants.conflict_resolution),
            ],
        );
        // The live worktree, not one an operator declared. This is the field
        // that makes the digest expire when HEAD or the index moves.
        push_confirmation_field(&mut document, &observation.digest());
        push_confirmation_field(&mut document, &snapshot_revision.get().to_be_bytes());
        push_confirmation_field(&mut document, &workspace_revision.get().to_be_bytes());
        Ok(*Sha256::digest(&document).as_bytes())
    }

    /// The receipt correlation for one staging confirmation.
    ///
    /// Domain-separated from the other families' correlations so a receipt
    /// minted for one can never be recovered against another.
    pub(crate) fn git_staging_receipt_correlation_digest(confirmation: [u8; 32]) -> [u8; 32] {
        let mut document = Vec::new();
        push_confirmation_field(
            &mut document,
            b"automonique.review-git-staging-receipt-correlation/v1",
        );
        push_confirmation_field(&mut document, &confirmation);
        *Sha256::digest(&document).as_bytes()
    }

    /// Read the pull-request scopes an installed credential carries.
    ///
    /// This is the seam a future pull-request adapter consumes, and it
    /// deliberately answers a question rather than granting anything. Holding
    /// a scope is a configuration fact; it is not proof that a pull request
    /// can be opened or merged, which is why no capability is minted from it
    /// alone. The provider preflight that would supply that proof does not
    /// exist yet, so today nothing reads this except the tests that pin the
    /// split.
    pub(crate) fn github_pull_request_scopes(
        &self,
        credential_reference: &str,
    ) -> Option<GitHubPullRequestScopes> {
        self.github_credentials
            .as_ref()?
            .document
            .credentials
            .iter()
            .find(|candidate| candidate.reference == credential_reference)
            .map(|credential| GitHubPullRequestScopes {
                write: credential.pull_request_write,
                merge: credential.pull_request_merge,
            })
    }

    pub(crate) fn github_receipt_correlation_digest(confirmation: [u8; 32]) -> [u8; 32] {
        let mut document = Vec::new();
        push_confirmation_field(
            &mut document,
            b"automonique.review-rerun-receipt-correlation/v1",
        );
        push_confirmation_field(&mut document, &confirmation);
        *Sha256::digest(&document).as_bytes()
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

/// Read the GitHub pull-request number out of a review projection id.
///
/// For a GitHub-backed workspace the review contract's opaque
/// [`PullRequestId`] *is* the pull-request number in decimal. That is a
/// projection convention rather than an inference from client input: the id
/// reaching here came from the server-owned review snapshot, and
/// `ReviewSnapshot::resolve_action` has already refused any action whose id is
/// not the one the snapshot holds. A client therefore cannot name a pull
/// request the server did not itself observe, and the operator registry pins
/// which repository the number is read in.
///
/// The grammar is strict on purpose: an id with a leading zero or a sign would
/// be a second spelling of the same pull request, and two spellings of one
/// coordinate is two rows in every fence keyed on it.
fn github_pull_request_number(id: &PullRequestId) -> Result<IssueNumber, &'static str> {
    let value = id.as_str();
    if value.is_empty()
        || value.len() > 7
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("platform_v2_review_pull_request_identity_invalid");
    }
    value
        .parse::<u32>()
        .ok()
        .and_then(|number| IssueNumber::new(number).ok())
        .ok_or("platform_v2_review_pull_request_identity_invalid")
}

/// Read a commit id out of a review projection head revision.
fn github_head_revision(value: &ReviewField) -> Result<String, &'static str> {
    if !valid_head_sha(value.as_str()) {
        return Err("platform_v2_review_pull_request_identity_invalid");
    }
    Ok(value.as_str().to_owned())
}

/// The staging family and proposal one review action names, if it is one.
const fn staging_family(action: &ReviewAction) -> Option<(GitStagingFamily, &ReviewProposalId)> {
    match action {
        ReviewAction::Stage { proposal_id } => Some((GitStagingFamily::Stage, proposal_id)),
        ReviewAction::Unstage { proposal_id } => Some((GitStagingFamily::Unstage, proposal_id)),
        ReviewAction::Commit { proposal_id } => Some((GitStagingFamily::Commit, proposal_id)),
        ReviewAction::ResolveConflict { proposal_id, .. } => {
            Some((GitStagingFamily::ResolveConflict, proposal_id))
        }
        _ => None,
    }
}

/// The action one staging capability probe reaches `plan` through.
///
/// Reaching the same arm an action does keeps advertisement and admission on
/// one test. The probe is never sent anywhere: `plan` reads only the family
/// and the proposal id from it, both of which the snapshot already owns.
fn staging_probe(target: GitStagingCapabilityTarget<'_>) -> Result<ReviewAction, &'static str> {
    let GitStagingCapabilityTarget {
        proposal_id,
        kind,
        file_id,
        resolution,
    } = target;
    let proposal_id = proposal_id.clone();
    Ok(match kind {
        ReviewProposalKind::Stage => ReviewAction::Stage { proposal_id },
        ReviewProposalKind::Unstage => ReviewAction::Unstage { proposal_id },
        ReviewProposalKind::Commit => ReviewAction::Commit { proposal_id },
        ReviewProposalKind::ResolveConflict => ReviewAction::ResolveConflict {
            proposal_id,
            file_id: file_id.ok_or("platform_v2_review_plan_invalid")?.clone(),
            resolution: resolution.ok_or("platform_v2_review_plan_invalid")?,
        },
    })
}

fn push_confirmation_field(document: &mut Vec<u8>, field: &[u8]) {
    document.extend_from_slice(&(field.len() as u64).to_be_bytes());
    document.extend_from_slice(field);
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
            RegistryTarget::LocalRepository { canonical_root, .. } => {
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
                        || check.observed_attempt.checked_add(1).is_none()
                        || !valid_head_sha(&check.head_sha)
                    {
                        return Err("platform_v2_review_registry_invalid");
                    }
                    let check_revision = Revision::new(check.observed_check_revision)
                        .map_err(|_| "platform_v2_review_registry_invalid")?;
                    if check_revision
                        .get()
                        .checked_add(1)
                        .and_then(|next| Revision::new(next).ok())
                        .is_none()
                    {
                        return Err("platform_v2_review_registry_invalid");
                    }
                }
            }
            RegistryTarget::PullRequest {
                provider,
                repository,
                credential_reference,
                base_branch,
                head_branch,
            } => {
                if !safe_token(provider)
                    || !safe_coordinate(repository)
                    || !safe_token(credential_reference)
                    || (provider == "github" && parse_repository(repository).is_err())
                {
                    return Err("platform_v2_review_registry_invalid");
                }
                // Branches are optional, so a document written before the
                // pull-request adapter existed still parses. Present ones are
                // validated all the way to the connector's own grammar, and a
                // binding naming one branch twice would propose a pull
                // request from a branch onto itself.
                for branch in [base_branch, head_branch].into_iter().flatten() {
                    if BranchName::new(branch).is_err() {
                        return Err("platform_v2_review_registry_invalid");
                    }
                }
                if let (Some(base), Some(head)) = (base_branch, head_branch)
                    && base == head
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

fn parse_github_credentials(
    bytes: &mut [u8],
) -> Result<InstalledGitHubCredentialDocument, &'static str> {
    let parsed = serde_json::from_slice::<GitHubCredentialDocument>(bytes);
    // The private-file snapshot is only a serde staging buffer. Scrub it on
    // both valid and invalid JSON paths before returning or validating fields.
    bytes.zeroize();
    let mut document = parsed.map_err(|_| "platform_v2_review_github_credentials_invalid")?;
    if document.version != 1
        || !safe_token(&document.generation)
        || document.credentials.len() > MAX_BINDINGS
    {
        return Err("platform_v2_review_github_credentials_invalid");
    }
    let mut references = BTreeSet::<String>::new();
    let mut credentials = Vec::with_capacity(document.credentials.len());
    for mut credential in document.credentials.drain(..) {
        if !safe_github_reference(&credential.reference)
            || !references.insert(credential.reference.clone())
            || parse_repository(&credential.repository).is_err()
            || GitHubToken::validate(credential.token.as_bytes()).is_err()
        {
            return Err("platform_v2_review_github_credentials_invalid");
        }
        // Merging is a strictly stronger power than writing, so a document
        // granting merge without write is incoherent rather than a shorthand
        // for both. Refusing it keeps the two flags independently meaningful
        // and stops an operator from believing they withheld the write scope.
        if credential.pull_request_merge && !credential.pull_request_write {
            return Err("platform_v2_review_github_credentials_invalid");
        }
        let token = credential.token.take_bytes();
        credentials.push(InstalledGitHubCredential {
            reference: credential.reference.clone(),
            repository: credential.repository.clone(),
            actions_write: credential.actions_write,
            pull_request_write: credential.pull_request_write,
            pull_request_merge: credential.pull_request_merge,
            token,
        });
    }
    Ok(InstalledGitHubCredentialDocument { credentials })
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
    let mut bytes = Zeroizing::new(Vec::new());
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
        ConflictResolution, PullRequestId, ReviewAuthorityId, ReviewCommentId, ReviewField,
        ReviewFileId, ReviewProposalId,
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

    /// A `local_repository` binding carrying exactly the named grants.
    fn git_binding_with(root: &Path, grants: &str) -> String {
        format!(
            r#"{{"version":1,"generation":"generation-1","bindings":[{{"project":"project-1","workspace_kind":"user_workspace","workspace_id":"workspace-1","authority_kind":"git","authority_id":"git-1","target":{{"kind":"local_repository","canonical_root":{},{grants}}}}}]}}"#,
            serde_json::to_string(root).unwrap()
        )
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

    /// Replaces the pin PR #221 left here, on the terms it set.
    ///
    /// That pin said a staging capability could not be minted because a
    /// confirmation digest would have to commit to the HEAD object id and the
    /// index state, and no projection this crate could read carried either. It
    /// was meant to fail when a git adapter landed, and to be replaced rather
    /// than deleted.
    ///
    /// What replaces it fails closed for everything the preflight still cannot
    /// prove. A binding that grants nothing plans nothing, and each grant is
    /// refused on its own account, so an operator reads a withheld commit as a
    /// withheld commit rather than as a generic unavailability. Committing is
    /// separate from index writes for the reason merging is separate from
    /// opening a pull request: it is the only local write whose effect is
    /// visible outside the checkout and the only one this surface cannot undo.
    /// Conflict resolution is separate again, because it is the only one that
    /// overwrites working-tree bytes.
    ///
    /// What the pin asked for now exists: `plan` consumes the binding, and
    /// `observe_git_staging` reads HEAD and the whole index off the repository
    /// so the digest commits to them. What is still refused here is everything
    /// short of that.
    #[test]
    fn a_binding_grants_only_the_staging_families_it_names() {
        let temporary = TempDir::new().unwrap();
        let repository = temporary.path().join("repository");
        fs::create_dir(&repository).unwrap();
        fs::create_dir(repository.join(".git")).unwrap();
        fs::set_permissions(&repository, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(repository.join(".git"), fs::Permissions::from_mode(0o700)).unwrap();
        let registry = temporary.path().join("registry.json");
        let plan_for = |body: &str, action: &ReviewAction| {
            write_registry(&registry, body);
            ProductionReviewEffectAdapter::open(&registry, uid())
                .unwrap()
                .plan(
                    &ProjectId::new("project-1").unwrap(),
                    &workspace(),
                    &git_authority(),
                    action,
                )
        };
        let stage = ReviewAction::Stage {
            proposal_id: ReviewProposalId::new("proposal-1").unwrap(),
        };
        let unstage = ReviewAction::Unstage {
            proposal_id: ReviewProposalId::new("proposal-1").unwrap(),
        };
        let commit = ReviewAction::Commit {
            proposal_id: ReviewProposalId::new("proposal-1").unwrap(),
        };
        let resolve = ReviewAction::ResolveConflict {
            proposal_id: ReviewProposalId::new("proposal-1").unwrap(),
            file_id: ReviewFileId::new("file-1").unwrap(),
            resolution: ConflictResolution::KeepCurrent,
        };

        // A binding written before the grants existed carries none, so it can
        // plan nothing -- exactly what it could do before, and it says so
        // rather than assuming an operator meant to allow what they had no way
        // to spell.
        for action in [&stage, &unstage, &commit, &resolve] {
            assert_eq!(
                plan_for(&git_binding(&repository), action),
                Err("platform_v2_review_git_grants_unavailable"),
                "{:?} must stay unavailable for a binding that grants nothing",
                action.kind(),
            );
        }

        // Index writes alone: staging and unstaging plan, committing and
        // resolving do not, and each says which grant it wanted.
        let index_only = git_binding_with(&repository, r#""index_write":true"#);
        assert!(matches!(
            plan_for(&index_only, &stage),
            Ok(ReviewEffectPlan::GitStaging {
                family: GitStagingFamily::Stage,
                ..
            })
        ));
        assert!(matches!(
            plan_for(&index_only, &unstage),
            Ok(ReviewEffectPlan::GitStaging {
                family: GitStagingFamily::Unstage,
                ..
            })
        ));
        assert_eq!(
            plan_for(&index_only, &commit),
            Err("platform_v2_review_git_commit_unavailable"),
            "a grant to move index entries must never imply recording them",
        );
        assert_eq!(
            plan_for(&index_only, &resolve),
            Err("platform_v2_review_git_conflict_resolution_unavailable"),
        );

        // And the reverse: committing does not imply index writes, and
        // resolving is not implied by either.
        let commit_only = git_binding_with(&repository, r#""commit":true"#);
        assert!(matches!(
            plan_for(&commit_only, &commit),
            Ok(ReviewEffectPlan::GitStaging {
                family: GitStagingFamily::Commit,
                ..
            })
        ));
        assert_eq!(
            plan_for(&commit_only, &stage),
            Err("platform_v2_review_git_index_write_unavailable"),
        );
        let resolve_only = git_binding_with(&repository, r#""conflict_resolution":true"#);
        assert!(matches!(
            plan_for(&resolve_only, &resolve),
            Ok(ReviewEffectPlan::GitStaging {
                family: GitStagingFamily::ResolveConflict,
                ..
            })
        ));
        assert_eq!(
            plan_for(&resolve_only, &stage),
            Err("platform_v2_review_git_index_write_unavailable"),
        );
    }

    /// A plan is still not a capability, and the digest still refuses
    /// everything it was not minted over.
    ///
    /// This is the other half of the replaced pin. `plan` now consumes the
    /// binding, so the thing that must stay true is narrower and sharper: a
    /// plan says a write could be addressed to a repository, and only an
    /// observation of that repository can say the write is performable. A
    /// confirmation minted over another family, or over the other side of a
    /// conflict, commits to nothing and is refused.
    #[test]
    fn a_staging_confirmation_is_refused_for_anything_it_was_not_minted_over() {
        let temporary = TempDir::new().unwrap();
        let repository = temporary.path().join("repository");
        fs::create_dir(&repository).unwrap();
        fs::create_dir(repository.join(".git")).unwrap();
        fs::set_permissions(&repository, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(repository.join(".git"), fs::Permissions::from_mode(0o700)).unwrap();
        let registry = temporary.path().join("registry.json");
        write_registry(
            &registry,
            &git_binding_with(
                &repository,
                r#""index_write":true,"commit":true,"conflict_resolution":true"#,
            ),
        );
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        let project = ProjectId::new("project-1").unwrap();
        let actor = Actor::new("tenant-1", "actor-1").unwrap();
        let plan = adapter
            .plan(
                &project,
                &workspace(),
                &git_authority(),
                &ReviewAction::Stage {
                    proposal_id: ReviewProposalId::new("proposal-1").unwrap(),
                },
            )
            .unwrap();

        // A registry binding and an installed grant are configuration. The
        // repository here has a `.git` directory and no repository in it, so
        // there is nothing to observe and nothing may be minted.
        assert!(
            adapter
                .preflight_git_staging_capability(
                    &plan,
                    &[RepositoryFile::new("src/review.rs").unwrap()],
                    None,
                )
                .is_err(),
            "a binding proves a configuration, never a worktree",
        );

        // A staging plan cannot borrow another family's confirmation lane, and
        // the staging lane refuses a plan that is not a staging plan.
        assert_eq!(
            adapter.github_confirmation_digest(
                &actor,
                &project,
                &workspace(),
                &git_authority(),
                Revision::FIRST,
                Revision::FIRST,
                &ReviewAction::Stage {
                    proposal_id: ReviewProposalId::new("proposal-1").unwrap(),
                },
                &plan,
            ),
            Err("platform_v2_review_confirmation_invalid"),
        );
        assert_eq!(
            adapter.git_worktree_state(&ReviewEffectPlan::LocalStore, &[]),
            Err("platform_v2_review_git_adapter_unavailable"),
        );
    }

    /// No staging action can borrow another family's confirmation.
    ///
    /// The confirmation digest is the only thing binding an advertised
    /// preview to a real server adapter. `github_confirmation_digest` is
    /// shaped for a check rerun and refuses anything else, so a staging
    /// action cannot acquire a commitment by reaching for the one lane that
    /// mints them. That has to stay true independently of `plan`, because the
    /// two could be closed separately.
    #[test]
    fn no_staging_action_can_borrow_the_check_rerun_confirmation() {
        let temporary = TempDir::new().unwrap();
        let repository = temporary.path().join("repository");
        fs::create_dir(&repository).unwrap();
        fs::create_dir(repository.join(".git")).unwrap();
        fs::set_permissions(&repository, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(repository.join(".git"), fs::Permissions::from_mode(0o700)).unwrap();
        let registry = temporary.path().join("registry.json");
        write_registry(&registry, &git_binding(&repository));
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        for action in [
            ReviewAction::Stage {
                proposal_id: ReviewProposalId::new("proposal-1").unwrap(),
            },
            ReviewAction::Commit {
                proposal_id: ReviewProposalId::new("proposal-1").unwrap(),
            },
        ] {
            assert_eq!(
                adapter.github_confirmation_digest(
                    &Actor::new("tenant-1", "actor-1").unwrap(),
                    &ProjectId::new("project-1").unwrap(),
                    &workspace(),
                    &git_authority(),
                    Revision::FIRST,
                    Revision::FIRST,
                    &action,
                    &ReviewEffectPlan::LocalStore,
                ),
                Err("platform_v2_review_confirmation_invalid"),
                "{:?} must not mint a confirmation",
                action.kind(),
            );
        }
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
            ReviewEffectPlan::LocalStore
            | ReviewEffectPlan::GitHubCheckRerun { .. }
            | ReviewEffectPlan::GitHubPullRequest { .. }
            | ReviewEffectPlan::GitStaging { .. } => {
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
    fn github_confirmation_binds_actor_revision_and_installed_generations() {
        let temporary = TempDir::new().unwrap();
        let registry = temporary.path().join("registry.json");
        let credentials = temporary.path().join(REVIEW_GITHUB_CREDENTIALS_FILE_NAME);
        write_registry(&registry, github_registry());
        write_registry(
            &credentials,
            &github_credentials(true, "example-org/example-repo"),
        );
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        let project = ProjectId::new("project-1").unwrap();
        let workspace = workspace();
        let authority = ci_authority();
        let action = rerun_action(7);
        let plan = adapter
            .plan(&project, &workspace, &authority, &action)
            .unwrap();
        let actor = Actor::new("tenant-1", "actor-1").unwrap();
        let baseline = adapter
            .github_confirmation_digest(
                &actor,
                &project,
                &workspace,
                &authority,
                Revision::new(9).unwrap(),
                Revision::new(3).unwrap(),
                &action,
                &plan,
            )
            .unwrap();
        assert_ne!(
            baseline,
            adapter
                .github_confirmation_digest(
                    &Actor::new("tenant-1", "actor-2").unwrap(),
                    &project,
                    &workspace,
                    &authority,
                    Revision::new(9).unwrap(),
                    Revision::new(3).unwrap(),
                    &action,
                    &plan,
                )
                .unwrap()
        );
        assert_ne!(
            baseline,
            adapter
                .github_confirmation_digest(
                    &actor,
                    &project,
                    &workspace,
                    &authority,
                    Revision::new(9).unwrap(),
                    Revision::new(4).unwrap(),
                    &action,
                    &plan
                )
                .unwrap()
        );
        assert_ne!(
            baseline,
            adapter
                .github_confirmation_digest(
                    &actor,
                    &project,
                    &workspace,
                    &authority,
                    Revision::new(10).unwrap(),
                    Revision::new(3).unwrap(),
                    &action,
                    &plan,
                )
                .unwrap()
        );
        let mut changed_generation = plan.clone();
        let ReviewEffectPlan::GitHubCheckRerun {
            registry_generation,
            ..
        } = &mut changed_generation
        else {
            panic!("github plan expected")
        };
        registry_generation[0] ^= 1;
        assert_ne!(
            baseline,
            adapter
                .github_confirmation_digest(
                    &actor,
                    &project,
                    &workspace,
                    &authority,
                    Revision::new(9).unwrap(),
                    Revision::new(3).unwrap(),
                    &action,
                    &changed_generation,
                )
                .unwrap()
        );
    }

    #[test]
    fn github_credential_staging_bytes_are_scrubbed_on_success_and_error() {
        let reset_secret_drops = || SECRET_STRING_DROPS.with(|drops| drops.set(0));
        let secret_drops = || SECRET_STRING_DROPS.with(std::cell::Cell::get);
        assert!(std::mem::needs_drop::<GitHubCredential>());
        let mut valid = github_credentials(true, "example-org/example-repo").into_bytes();
        let installed = parse_github_credentials(&mut valid).unwrap();
        assert!(valid.iter().all(|byte| *byte == 0));
        assert_eq!(installed.credentials.len(), 1);
        assert!(GitHubToken::new(installed.credentials[0].token.to_vec()).is_ok());

        let secret = "github_pat_invalid!secret";
        reset_secret_drops();
        let mut invalid = format!(
            r#"{{"version":1,"generation":"credential-generation-1","credentials":[{{"reference":"github-actions-mobile","repository":"example-org/example-repo","actions_write":true,"token":"{secret}"}}]}}"#
        )
        .into_bytes();
        let error = match parse_github_credentials(&mut invalid) {
            Ok(_) => panic!("invalid token accepted"),
            Err(error) => error,
        };
        assert_eq!(error, "platform_v2_review_github_credentials_invalid");
        assert!(!error.contains(secret));
        assert!(invalid.iter().all(|byte| *byte == 0));
        assert_eq!(secret_drops(), 1);

        for trailing in [
            r#","unknown_after_token":true"#,
            r#","actions_write":"malformed-after-token""#,
        ] {
            reset_secret_drops();
            let secret = "github_pat_partial_deserialize_secret";
            let mut partial = format!(
                r#"{{"version":1,"generation":"credential-generation-1","credentials":[{{"reference":"github-actions-mobile","repository":"example-org/example-repo","token":"{secret}"{trailing}}}]}}"#
            )
            .into_bytes();
            let error = match parse_github_credentials(&mut partial) {
                Ok(_) => panic!("partial invalid credentials accepted"),
                Err(error) => error,
            };
            assert_eq!(error, "platform_v2_review_github_credentials_invalid");
            assert!(!error.contains(secret));
            assert!(partial.iter().all(|byte| *byte == 0));
            assert_eq!(secret_drops(), 1, "trailing field {trailing}");
        }

        let mut malformed = br#"{"token":"github_pat_malformed""#.to_vec();
        let error = match parse_github_credentials(&mut malformed) {
            Ok(_) => panic!("malformed credentials accepted"),
            Err(error) => error,
        };
        assert_eq!(error, "platform_v2_review_github_credentials_invalid");
        assert!(malformed.iter().all(|byte| *byte == 0));
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

    fn pull_request_authority() -> ReviewAuthority {
        ReviewAuthority::new(
            ReviewAuthorityKind::PullRequest,
            ReviewAuthorityId::new("pull-request-1").unwrap(),
        )
    }

    fn pull_request_registry() -> &'static str {
        r#"{"version":1,"generation":"generation-1","bindings":[{"project":"project-1","workspace_kind":"user_workspace","workspace_id":"workspace-1","authority_kind":"pull_request","authority_id":"pull-request-1","target":{"kind":"pull_request","provider":"github","repository":"example-org/example-repo","credential_reference":"github-pull-request-mobile","base_branch":"main","head_branch":"agent-work"}}]}"#
    }

    /// The shape every deployment installed before the adapter existed.
    fn branchless_pull_request_registry() -> &'static str {
        r#"{"version":1,"generation":"generation-1","bindings":[{"project":"project-1","workspace_kind":"user_workspace","workspace_id":"workspace-1","authority_kind":"pull_request","authority_id":"pull-request-1","target":{"kind":"pull_request","provider":"github","repository":"example-org/example-repo","credential_reference":"github-pull-request-mobile"}}]}"#
    }

    /// A provider that answers every read with a refusal, so a preflight can
    /// prove nothing and no slot may be minted.
    fn refusing_transport() -> SharedGitHubPullRequestTransport {
        use crate::platform_v2_github_pull_request_adapter::GitHubPullRequestTransport;
        use automonique_github_connector::{
            CreatePullRequestRequest, GetBranchRequest, GetPullRequestRequest, GitHubBranch,
            GitHubFailure, GitHubMergeReceipt, GitHubOutcome, GitHubPullRequest,
            GitHubPullRequestRef, GitHubRejection, GitHubReply, ListPullRequestsRequest,
            MergePullRequestRequest, RateLimit, ServerMessage, UpdatePullRequestRequest,
        };

        struct Refusing;

        fn refused<T>() -> Result<GitHubReply<T>, GitHubFailure> {
            let rate = RateLimit::new(None, None, None);
            Ok(GitHubReply::new(
                rate,
                GitHubOutcome::Rejected(GitHubRejection::new(
                    404,
                    ServerMessage::sanitized("not found"),
                    &rate,
                    None,
                )),
            ))
        }

        impl GitHubPullRequestTransport for Refusing {
            fn get_branch(
                &self,
                _: &GetBranchRequest,
            ) -> Result<GitHubReply<GitHubBranch>, GitHubFailure> {
                refused()
            }
            fn get_pull_request(
                &self,
                _: &GetPullRequestRequest,
            ) -> Result<GitHubReply<GitHubPullRequest>, GitHubFailure> {
                refused()
            }
            fn list_pull_requests(
                &self,
                _: &ListPullRequestsRequest,
            ) -> Result<GitHubReply<Vec<GitHubPullRequestRef>>, GitHubFailure> {
                refused()
            }
            fn create_pull_request(
                &self,
                _: &CreatePullRequestRequest,
            ) -> Result<GitHubReply<GitHubPullRequestRef>, GitHubFailure> {
                panic!("a preflight must never write")
            }
            fn update_pull_request(
                &self,
                _: &UpdatePullRequestRequest,
            ) -> Result<GitHubReply<GitHubPullRequest>, GitHubFailure> {
                panic!("a preflight must never write")
            }
            fn merge_pull_request(
                &self,
                _: &MergePullRequestRequest,
            ) -> Result<GitHubReply<GitHubMergeReceipt>, GitHubFailure> {
                panic!("a preflight must never write")
            }
        }

        Arc::new(std::sync::Mutex::new(Box::new(Refusing)))
    }

    fn pull_request_actions() -> Vec<ReviewAction> {
        vec![
            ReviewAction::OpenPullRequest {
                expected_pull_request_revision: Revision::FIRST,
                title: ReviewField::new("Title").unwrap(),
            },
            ReviewAction::UpdatePullRequest {
                pull_request_id: PullRequestId::new("77").unwrap(),
                expected_pull_request_revision: Revision::FIRST,
                title: ReviewField::new("Title").unwrap(),
            },
            ReviewAction::MergePullRequest {
                pull_request_id: PullRequestId::new("77").unwrap(),
                expected_pull_request_revision: Revision::FIRST,
                expected_head_revision: ReviewField::new(
                    "0123456789abcdef0123456789abcdef01234567",
                )
                .unwrap(),
            },
        ]
    }

    fn write_credentials(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn credential_document(scopes: &str) -> String {
        format!(
            r#"{{"version":1,"generation":"generation-1","credentials":[{{"reference":"github-pull-request-mobile","repository":"example-org/example-repo","actions_write":false,{scopes}"token":"ghp_000000000000000000000000000000000000"}}]}}"#
        )
    }

    /// Pull-request authority is its own credential scope, and merging is its
    /// own scope again.
    ///
    /// `actions_write` re-runs a workflow a maintainer already approved, onto
    /// a ref that already exists. Writing a pull request proposes new code,
    /// and merging one moves that code into a protected branch where it can
    /// trigger a deploy. Three different powers, so installing one must never
    /// confer another. An operator who wants CI reruns from a phone must not
    /// discover they also handed out repository writes.
    #[test]
    fn pull_request_scopes_are_withheld_independently_of_actions_write() {
        let temporary = TempDir::new().unwrap();
        let registry = temporary.path().join("registry.json");
        write_registry(&registry, pull_request_registry());
        let credentials = temporary.path().join(REVIEW_GITHUB_CREDENTIALS_FILE_NAME);

        // The scope an existing deployment already has on disk: no
        // pull-request keys at all, because they did not exist when it was
        // installed. It must keep parsing, and it must gain nothing.
        write_credentials(&credentials, &credential_document(""));
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        assert_eq!(
            adapter.github_pull_request_scopes("github-pull-request-mobile"),
            Some(GitHubPullRequestScopes {
                write: false,
                merge: false,
            }),
            "an installed document that predates the split grants neither scope",
        );

        // Proposing changes without being able to land them is the useful
        // middle state, and it has to be expressible.
        write_credentials(
            &credentials,
            &credential_document(r#""pull_request_write":true,"#),
        );
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        assert_eq!(
            adapter.github_pull_request_scopes("github-pull-request-mobile"),
            Some(GitHubPullRequestScopes {
                write: true,
                merge: false,
            }),
            "write must not imply merge",
        );

        write_credentials(
            &credentials,
            &credential_document(r#""pull_request_write":true,"pull_request_merge":true,"#),
        );
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        assert_eq!(
            adapter.github_pull_request_scopes("github-pull-request-mobile"),
            Some(GitHubPullRequestScopes {
                write: true,
                merge: true,
            }),
        );

        // Merge without write is incoherent rather than shorthand for both.
        // Accepting it would let an operator believe they withheld the write
        // scope while handing out the strictly stronger one.
        write_credentials(
            &credentials,
            &credential_document(r#""pull_request_merge":true,"#),
        );
        assert_eq!(
            ProductionReviewEffectAdapter::open(&registry, uid()).err(),
            Some("platform_v2_review_github_credentials_invalid"),
        );
    }

    /// Holding every pull-request scope still mints no capability.
    ///
    /// This is the rule the whole capability surface rests on, and it survives
    /// the adapter landing rather than being retired by it. `plan` now returns
    /// a plan, because the registry and the credential together say *where* a
    /// write would go. That is still not authority: only a live provider read
    /// can say the write would be admitted, and nothing is advertised until
    /// one has answered.
    ///
    /// This replaces the earlier version of this test, which pinned the same
    /// rule against a `plan` that had no pull-request arm at all.
    #[test]
    fn a_fully_scoped_pull_request_credential_still_proves_nothing_by_itself() {
        let temporary = TempDir::new().unwrap();
        let registry = temporary.path().join("registry.json");
        write_registry(&registry, pull_request_registry());
        write_credentials(
            &temporary.path().join(REVIEW_GITHUB_CREDENTIALS_FILE_NAME),
            &credential_document(r#""pull_request_write":true,"pull_request_merge":true,"#),
        );
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        assert_eq!(
            adapter.github_pull_request_scopes("github-pull-request-mobile"),
            Some(GitHubPullRequestScopes {
                write: true,
                merge: true,
            }),
            "the scopes really are installed, so what follows is not about them",
        );
        for action in pull_request_actions() {
            let plan = adapter
                .plan(
                    &ProjectId::new("project-1").unwrap(),
                    &workspace(),
                    &pull_request_authority(),
                    &action,
                )
                .expect("a fully scoped binding addresses a plan");
            assert!(matches!(plan, ReviewEffectPlan::GitHubPullRequest { .. }));
        }

        // A provider that refuses every read proves nothing, so nothing is
        // advertised. Fail-closed is the whole point: an empty slot is an
        // honest answer, an advertised control that refuses is not.
        let mut adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        adapter.set_github_pull_request_test_transport(refusing_transport());
        for action in pull_request_actions() {
            let plan = adapter
                .plan(
                    &ProjectId::new("project-1").unwrap(),
                    &workspace(),
                    &pull_request_authority(),
                    &action,
                )
                .unwrap();
            assert_eq!(
                adapter
                    .preflight_github_pull_request_capability(&plan)
                    .err(),
                Some("platform_v2_review_pull_request_preflight_refused"),
                "{:?} must not be advertised on a provider that refuses",
                action.kind(),
            );
        }
    }

    /// A binding installed before the adapter existed names no branches, and
    /// a pull request cannot be proposed from a branch nobody named.
    ///
    /// This is the migration state every deployment is in today. It confers
    /// exactly what it conferred before — nothing — and says so precisely,
    /// rather than guessing a default branch on the operator's behalf.
    #[test]
    fn a_branchless_pull_request_binding_can_address_nothing() {
        let temporary = TempDir::new().unwrap();
        let registry = temporary.path().join("registry.json");
        write_registry(&registry, branchless_pull_request_registry());
        write_credentials(
            &temporary.path().join(REVIEW_GITHUB_CREDENTIALS_FILE_NAME),
            &credential_document(r#""pull_request_write":true,"pull_request_merge":true,"#),
        );
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        for action in pull_request_actions() {
            assert_eq!(
                adapter.plan(
                    &ProjectId::new("project-1").unwrap(),
                    &workspace(),
                    &pull_request_authority(),
                    &action,
                ),
                Err("platform_v2_review_pull_request_branches_unavailable"),
                "{:?} must name no branch it was not given",
                action.kind(),
            );
        }
    }

    /// Every step before the provider is still a separate, named refusal.
    ///
    /// An operator must be able to tell a missing credential from an unscoped
    /// one from a withheld merge, and merging must stay refused on its own
    /// account now that the adapter exists rather than only before it.
    #[test]
    fn an_installed_pull_request_binding_refuses_each_missing_piece_for_its_own_reason() {
        let temporary = TempDir::new().unwrap();
        let registry = temporary.path().join("registry.json");
        write_registry(&registry, pull_request_registry());
        let credentials = temporary.path().join(REVIEW_GITHUB_CREDENTIALS_FILE_NAME);

        // A complete binding whose credential was never installed. The
        // binding alone confers nothing.
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        for action in pull_request_actions() {
            assert_eq!(
                adapter.plan(
                    &ProjectId::new("project-1").unwrap(),
                    &workspace(),
                    &pull_request_authority(),
                    &action,
                ),
                Err("platform_v2_review_pull_request_credential_unavailable"),
                "{:?} must not be conferred by a binding alone",
                action.kind(),
            );
        }

        // The credential exists but carries no pull-request scope, which is
        // every credential installed before the scopes were split out.
        write_credentials(&credentials, &credential_document(""));
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        for action in pull_request_actions() {
            assert_eq!(
                adapter.plan(
                    &ProjectId::new("project-1").unwrap(),
                    &workspace(),
                    &pull_request_authority(),
                    &action,
                ),
                Err("platform_v2_review_pull_request_credential_unavailable"),
                "{:?} must not be conferred by an unscoped credential",
                action.kind(),
            );
        }

        // Write without merge. This is the state a deployment lands in when
        // it wants an agent to propose changes but never land them: opening
        // and updating now reach a plan, while merging is stopped by the
        // withheld scope before any provider is addressed.
        write_credentials(
            &credentials,
            &credential_document(r#""pull_request_write":true,"#),
        );
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        for action in pull_request_actions() {
            let planned = adapter.plan(
                &ProjectId::new("project-1").unwrap(),
                &workspace(),
                &pull_request_authority(),
                &action,
            );
            if matches!(action, ReviewAction::MergePullRequest { .. }) {
                assert_eq!(
                    planned,
                    Err("platform_v2_review_pull_request_merge_unavailable"),
                    "a credential that may propose changes must never land them",
                );
            } else {
                assert!(
                    matches!(planned, Ok(ReviewEffectPlan::GitHubPullRequest { .. })),
                    "{:?} must reach a plan on a write-scoped credential",
                    action.kind(),
                );
            }
        }
    }

    /// No pull-request plan means no server-minted confirmation, and that
    /// confirmation is the only thing binding a preview to a real adapter.
    #[test]
    fn no_pull_request_action_can_borrow_the_check_rerun_confirmation() {
        let temporary = TempDir::new().unwrap();
        let registry = temporary.path().join("registry.json");
        write_registry(&registry, pull_request_registry());
        let adapter = ProductionReviewEffectAdapter::open(&registry, uid()).unwrap();
        // Only a check-rerun plan reaches a provider observation, so a
        // pull-request action cannot acquire one by accident.
        assert_eq!(
            adapter.preflight_github_capability(&ReviewEffectPlan::LocalStore),
            Err("platform_v2_review_ci_check_unavailable")
        );
        for action in pull_request_actions() {
            assert_eq!(
                adapter.github_confirmation_digest(
                    &Actor::new("tenant-1", "actor-1").unwrap(),
                    &ProjectId::new("project-1").unwrap(),
                    &workspace(),
                    &pull_request_authority(),
                    Revision::FIRST,
                    Revision::FIRST,
                    &action,
                    &ReviewEffectPlan::LocalStore,
                ),
                Err("platform_v2_review_confirmation_invalid"),
                "{:?} must not mint a confirmation",
                action.kind(),
            );
        }
    }
}
