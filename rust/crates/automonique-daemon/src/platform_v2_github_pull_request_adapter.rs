// SPDX-License-Identifier: Elastic-2.0

//! Exact, least-privilege GitHub pull-request write boundary.
//!
//! This is the sibling of [`crate::platform_v2_github_check_adapter`] and it
//! keeps that adapter's shape deliberately: a caller persists a
//! [`GitHubPullRequestSubmission`] after `begin_custody` and before `submit`,
//! any failure after that point is ambiguous, and `submit` refuses every state
//! except `CustodyStarted`, so an ambiguous write can never be replayed
//! blindly. None of the three GitHub endpoints accepts an idempotency key.
//!
//! Three things differ, because a pull request is not a workflow run.
//!
//! * The family is explicit. Opening, updating and merging are three separate
//!   plans, and merging additionally requires the capability to have been
//!   built with the merge scope. A credential that may propose changes cannot
//!   land them even if a caller hands this adapter a merge plan.
//! * Every plan pins a head commit that a live read proved, and every family's
//!   preflight refuses when the branch has moved off it. For a merge that
//!   fence is also sent to GitHub as the merge `sha`, so the provider refuses
//!   a stale merge independently of anything this process believes.
//! * An open has nothing to name until the write succeeds. The provider-issued
//!   number returned by the create is the only correlation this process will
//!   ever hold for the pull request it opened, so it is carried out of
//!   `submit` and must be durably recorded with the accepted custody.
//!
//! The capability is fixed to one repository, one head branch, one base
//! branch, and one explicit credential reference. There is no `gh` subprocess,
//! ambient account lookup, arbitrary URL, branch push, shell, or generic
//! execute fallback.

use automonique_github_connector::{
    BranchName, CreatePullRequestRequest, GetBranchRequest, GetPullRequestRequest, GitHubBase,
    GitHubBranch, GitHubClient, GitHubFailure, GitHubMergeReceipt, GitHubOutcome,
    GitHubPullRequest, GitHubPullRequestRef, GitHubReply, GitHubToken, HeadRevision, IssueNumber,
    ListPullRequestsRequest, MergePullRequestRequest, PullRequestLifecycle,
    PullRequestMergeability, RepoTarget, UpdatePullRequestRequest,
};
use automonique_protocol::digest::Sha256;
use automonique_protocol::identity::Actor;
use automonique_protocol::platform::IdempotencyKey;
use automonique_protocol::platform_v2::{ProjectId, WorkContextIdentity};
use automonique_protocol::platform_v2_review::{ReviewAuthority, ReviewAuthorityKind};
use automonique_protocol::primitives::Revision;
#[cfg(test)]
use std::sync::{Arc, Mutex};

const MAX_CREDENTIAL_REFERENCE_BYTES: usize = 256;

/// Longest title this adapter will carry to GitHub.
///
/// The review contract's title is a bounded field already; this is the second
/// ceiling, so a protocol change cannot widen what reaches the provider
/// without this file changing too.
pub const MAX_PULL_REQUEST_TITLE_BYTES: usize = 256;

/// Stable, content-free failures safe for receipts and logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubPullRequestError {
    InvalidPlan,
    CapabilityMismatch,
    /// The plan is a merge and this capability was not built with the merge
    /// scope. Distinct from [`Self::CapabilityMismatch`] so a withheld merge
    /// is observable as a withheld merge rather than as a mismatched target.
    MergeWithheld,
    ProviderUnavailable,
    ProviderRefused,
    ResourceChanged,
    SubmissionState,
}

/// Which of the three independently withheld pull-request writes a plan is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubPullRequestFamily {
    Open,
    Update,
    Merge,
}

impl GitHubPullRequestFamily {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Update => "update",
            Self::Merge => "merge",
        }
    }
}

/// What one mutation-free read proved about the provider, immediately before
/// a capability was advertised or a write admitted.
///
/// This is the whole of what a slot may be minted from. A configuration fact —
/// an installed credential, a registry binding, a scope flag — proves none of
/// it, which is why nothing here can be constructed without a live read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubPullRequestObservation {
    family: GitHubPullRequestFamily,
    /// The pull-request number, absent only for an open: there is no pull
    /// request yet to number.
    number: Option<IssueNumber>,
    /// The head commit the provider reported, for the branch an open would
    /// propose from or the pull request an update or merge names.
    head_sha: String,
    /// Whether the provider reported this pull request mergeable now. Always
    /// false for an open, which proposes rather than lands.
    mergeable: bool,
}

impl GitHubPullRequestObservation {
    #[must_use]
    pub const fn family(&self) -> GitHubPullRequestFamily {
        self.family
    }

    #[must_use]
    pub const fn number(&self) -> Option<IssueNumber> {
        self.number
    }

    #[must_use]
    pub fn head_sha(&self) -> &str {
        &self.head_sha
    }

    #[must_use]
    pub const fn mergeable(&self) -> bool {
        self.mergeable
    }
}

/// Every authority and provider coordinate captured by the confirmation.
///
/// `observed_head_sha` is the commit a preflight proved, not one an operator
/// declared: for an open it is the tip of the head branch, and for an update
/// or a merge it is the pull request's own head. It is part of the digest, so
/// a branch that moves between advertisement and execution invalidates the
/// client's confirmation rather than silently landing a different change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubPullRequestPlan {
    digest: [u8; 32],
    registry_generation_digest: [u8; 32],
    credential_generation_digest: [u8; 32],
    credential_reference: String,
    target: RepoTarget,
    family: GitHubPullRequestFamily,
    base_branch: BranchName,
    head_branch: BranchName,
    number: Option<IssueNumber>,
    observed_head_sha: String,
    title: Option<String>,
    tenant: String,
    actor: String,
    project: ProjectId,
    workspace: WorkContextIdentity,
    authority: ReviewAuthority,
    idempotency_key: IdempotencyKey,
    expected_snapshot_revision: Revision,
    expected_pull_request_revision: Revision,
}

/// The coordinates one pull-request plan names, grouped so the constructor
/// cannot acquire a tenth positional string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubPullRequestTarget {
    pub target: RepoTarget,
    pub family: GitHubPullRequestFamily,
    pub base_branch: BranchName,
    pub head_branch: BranchName,
    /// Present exactly when the family is not `Open`.
    pub number: Option<IssueNumber>,
    /// The commit a preflight observed.
    pub observed_head_sha: String,
    /// Present exactly when the family is not `Merge`: a merge changes no
    /// title, and an open or update is the only thing that carries one.
    pub title: Option<String>,
}

/// The review coordinate one pull-request plan is bound to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubPullRequestReviewBinding {
    pub project: ProjectId,
    pub workspace: WorkContextIdentity,
    pub authority: ReviewAuthority,
    pub idempotency_key: IdempotencyKey,
    pub expected_snapshot_revision: Revision,
    pub expected_pull_request_revision: Revision,
}

impl GitHubPullRequestPlan {
    /// Bind a user-confirmed review action to one exact observed pull request.
    pub fn new(
        registry_generation_digest: [u8; 32],
        credential_generation_digest: [u8; 32],
        credential_reference: &str,
        provider: GitHubPullRequestTarget,
        actor: &Actor,
        review: GitHubPullRequestReviewBinding,
    ) -> Result<Self, GitHubPullRequestError> {
        let family_shape = match provider.family {
            // An open has no number to commit to and must carry the title it
            // will propose.
            GitHubPullRequestFamily::Open => provider.number.is_none() && provider.title.is_some(),
            GitHubPullRequestFamily::Update => {
                provider.number.is_some() && provider.title.is_some()
            }
            // A merge names no title: retitling is a separate power with its
            // own grant, and folding it in would let a merge rewrite the
            // proposal it lands.
            GitHubPullRequestFamily::Merge => provider.number.is_some() && provider.title.is_none(),
        };
        if !safe_reference(credential_reference)
            || review.authority.kind() != ReviewAuthorityKind::PullRequest
            || !family_shape
            || provider.base_branch == provider.head_branch
            || !valid_head_sha(&provider.observed_head_sha)
            || provider
                .title
                .as_ref()
                .is_some_and(|title| !valid_title(title))
            || revision_successor(review.expected_snapshot_revision).is_none()
            || revision_successor(review.expected_pull_request_revision).is_none()
        {
            return Err(GitHubPullRequestError::InvalidPlan);
        }
        let mut plan = Self {
            digest: [0; 32],
            registry_generation_digest,
            credential_generation_digest,
            credential_reference: credential_reference.to_owned(),
            target: provider.target,
            family: provider.family,
            base_branch: provider.base_branch,
            head_branch: provider.head_branch,
            number: provider.number,
            observed_head_sha: provider.observed_head_sha,
            title: provider.title,
            tenant: actor.tenant().to_owned(),
            actor: actor.id().to_owned(),
            project: review.project,
            workspace: review.workspace,
            authority: review.authority,
            idempotency_key: review.idempotency_key,
            expected_snapshot_revision: review.expected_snapshot_revision,
            expected_pull_request_revision: review.expected_pull_request_revision,
        };
        plan.digest = plan_digest(&plan);
        Ok(plan)
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    #[must_use]
    pub fn credential_reference(&self) -> &str {
        &self.credential_reference
    }

    #[must_use]
    pub const fn registry_generation_digest(&self) -> [u8; 32] {
        self.registry_generation_digest
    }

    #[must_use]
    pub const fn credential_generation_digest(&self) -> [u8; 32] {
        self.credential_generation_digest
    }

    #[must_use]
    pub const fn target(&self) -> &RepoTarget {
        &self.target
    }

    #[must_use]
    pub const fn family(&self) -> GitHubPullRequestFamily {
        self.family
    }

    #[must_use]
    pub const fn base_branch(&self) -> &BranchName {
        &self.base_branch
    }

    #[must_use]
    pub const fn head_branch(&self) -> &BranchName {
        &self.head_branch
    }

    #[must_use]
    pub const fn number(&self) -> Option<IssueNumber> {
        self.number
    }

    #[must_use]
    pub fn observed_head_sha(&self) -> &str {
        &self.observed_head_sha
    }

    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }

    #[must_use]
    pub const fn project(&self) -> &ProjectId {
        &self.project
    }

    #[must_use]
    pub const fn workspace(&self) -> &WorkContextIdentity {
        &self.workspace
    }

    #[must_use]
    pub const fn authority(&self) -> &ReviewAuthority {
        &self.authority
    }

    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    #[must_use]
    pub const fn expected_snapshot_revision(&self) -> Revision {
        self.expected_snapshot_revision
    }

    #[must_use]
    pub const fn expected_pull_request_revision(&self) -> Revision {
        self.expected_pull_request_revision
    }
}

fn revision_successor(value: Revision) -> Option<Revision> {
    value
        .get()
        .checked_add(1)
        .and_then(|next| Revision::new(next).ok())
}

/// Durable custody state for a single plan digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubPullRequestCustody {
    NotStarted,
    CustodyStarted,
    Accepted,
    Ambiguous,
    Refused,
    Completed,
}

/// The minimal durable record a store must persist before the provider call.
///
/// `opened_number` is the one field the check-rerun submission has no analogue
/// for. An open produces an identity that did not exist before the write, and
/// a later read cannot recover which of the repository's pull requests was
/// ours, so the provider-issued number must be persisted with the accepted
/// custody or the effect becomes permanently uncorrelatable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubPullRequestSubmission {
    plan_digest: [u8; 32],
    custody: GitHubPullRequestCustody,
    opened_number: Option<IssueNumber>,
}

impl GitHubPullRequestSubmission {
    #[must_use]
    pub fn new(plan: &GitHubPullRequestPlan) -> Self {
        Self {
            plan_digest: plan.digest(),
            custody: GitHubPullRequestCustody::NotStarted,
            opened_number: None,
        }
    }

    /// Rehydrate the exact durable state after a process restart.
    pub fn restore(
        plan: &GitHubPullRequestPlan,
        plan_digest: [u8; 32],
        custody: GitHubPullRequestCustody,
        opened_number: Option<IssueNumber>,
    ) -> Result<Self, GitHubPullRequestError> {
        if plan.digest() != plan_digest {
            return Err(GitHubPullRequestError::SubmissionState);
        }
        // A recorded number is only ever meaningful for an open, and an open
        // that reached `Accepted` must have one: without it the pull request
        // this process created can never be named again, so a row missing it
        // is corruption rather than a state to carry on from.
        let coherent = match (plan.family, custody) {
            // Nothing but an open ever holds a provider-issued number.
            (GitHubPullRequestFamily::Update | GitHubPullRequestFamily::Merge, _) => {
                opened_number.is_none()
            }
            // The number arrives with the create's own response, so it cannot
            // exist before the write was attempted.
            (
                GitHubPullRequestFamily::Open,
                GitHubPullRequestCustody::NotStarted | GitHubPullRequestCustody::CustodyStarted,
            ) => opened_number.is_none(),
            (
                GitHubPullRequestFamily::Open,
                GitHubPullRequestCustody::Accepted | GitHubPullRequestCustody::Completed,
            ) => opened_number.is_some(),
            // Ambiguous and refused admit either: a write this process never
            // saw acknowledged has no number, and one that was acknowledged
            // and later downgraded keeps the number it earned.
            (
                GitHubPullRequestFamily::Open,
                GitHubPullRequestCustody::Ambiguous | GitHubPullRequestCustody::Refused,
            ) => true,
        };
        if !coherent {
            return Err(GitHubPullRequestError::SubmissionState);
        }
        Ok(Self {
            plan_digest,
            custody,
            opened_number,
        })
    }

    /// Transition to the state that must be durably committed before `submit`.
    pub fn begin_custody(&mut self) -> Result<(), GitHubPullRequestError> {
        if self.custody != GitHubPullRequestCustody::NotStarted {
            return Err(GitHubPullRequestError::SubmissionState);
        }
        self.custody = GitHubPullRequestCustody::CustodyStarted;
        Ok(())
    }

    #[must_use]
    pub const fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    #[must_use]
    pub const fn custody(&self) -> GitHubPullRequestCustody {
        self.custody
    }

    /// The provider-issued number an accepted open returned.
    #[must_use]
    pub const fn opened_number(&self) -> Option<IssueNumber> {
        self.opened_number
    }
}

pub(crate) trait GitHubPullRequestTransport {
    fn get_branch(
        &self,
        request: &GetBranchRequest,
    ) -> Result<GitHubReply<GitHubBranch>, GitHubFailure>;

    fn get_pull_request(
        &self,
        request: &GetPullRequestRequest,
    ) -> Result<GitHubReply<GitHubPullRequest>, GitHubFailure>;

    fn list_pull_requests(
        &self,
        request: &ListPullRequestsRequest,
    ) -> Result<GitHubReply<Vec<GitHubPullRequestRef>>, GitHubFailure>;

    fn create_pull_request(
        &self,
        request: &CreatePullRequestRequest,
    ) -> Result<GitHubReply<GitHubPullRequestRef>, GitHubFailure>;

    fn update_pull_request(
        &self,
        request: &UpdatePullRequestRequest,
    ) -> Result<GitHubReply<GitHubPullRequest>, GitHubFailure>;

    fn merge_pull_request(
        &self,
        request: &MergePullRequestRequest,
    ) -> Result<GitHubReply<GitHubMergeReceipt>, GitHubFailure>;
}

#[cfg(test)]
pub(crate) type SharedGitHubPullRequestTransport =
    Arc<Mutex<Box<dyn GitHubPullRequestTransport + Send>>>;

#[cfg(test)]
struct SharedTestTransport(SharedGitHubPullRequestTransport);

#[cfg(test)]
impl GitHubPullRequestTransport for SharedTestTransport {
    fn get_branch(
        &self,
        request: &GetBranchRequest,
    ) -> Result<GitHubReply<GitHubBranch>, GitHubFailure> {
        self.0
            .lock()
            .expect("test GitHub transport")
            .get_branch(request)
    }

    fn get_pull_request(
        &self,
        request: &GetPullRequestRequest,
    ) -> Result<GitHubReply<GitHubPullRequest>, GitHubFailure> {
        self.0
            .lock()
            .expect("test GitHub transport")
            .get_pull_request(request)
    }

    fn list_pull_requests(
        &self,
        request: &ListPullRequestsRequest,
    ) -> Result<GitHubReply<Vec<GitHubPullRequestRef>>, GitHubFailure> {
        self.0
            .lock()
            .expect("test GitHub transport")
            .list_pull_requests(request)
    }

    fn create_pull_request(
        &self,
        request: &CreatePullRequestRequest,
    ) -> Result<GitHubReply<GitHubPullRequestRef>, GitHubFailure> {
        self.0
            .lock()
            .expect("test GitHub transport")
            .create_pull_request(request)
    }

    fn update_pull_request(
        &self,
        request: &UpdatePullRequestRequest,
    ) -> Result<GitHubReply<GitHubPullRequest>, GitHubFailure> {
        self.0
            .lock()
            .expect("test GitHub transport")
            .update_pull_request(request)
    }

    fn merge_pull_request(
        &self,
        request: &MergePullRequestRequest,
    ) -> Result<GitHubReply<GitHubMergeReceipt>, GitHubFailure> {
        self.0
            .lock()
            .expect("test GitHub transport")
            .merge_pull_request(request)
    }
}

impl GitHubPullRequestTransport for GitHubClient {
    fn get_branch(
        &self,
        request: &GetBranchRequest,
    ) -> Result<GitHubReply<GitHubBranch>, GitHubFailure> {
        GitHubClient::get_branch(self, request)
    }

    fn get_pull_request(
        &self,
        request: &GetPullRequestRequest,
    ) -> Result<GitHubReply<GitHubPullRequest>, GitHubFailure> {
        GitHubClient::get_pull_request(self, request)
    }

    fn list_pull_requests(
        &self,
        request: &ListPullRequestsRequest,
    ) -> Result<GitHubReply<Vec<GitHubPullRequestRef>>, GitHubFailure> {
        GitHubClient::list_pull_requests(self, request)
    }

    fn create_pull_request(
        &self,
        request: &CreatePullRequestRequest,
    ) -> Result<GitHubReply<GitHubPullRequestRef>, GitHubFailure> {
        GitHubClient::create_pull_request(self, request)
    }

    fn update_pull_request(
        &self,
        request: &UpdatePullRequestRequest,
    ) -> Result<GitHubReply<GitHubPullRequest>, GitHubFailure> {
        GitHubClient::update_pull_request(self, request)
    }

    fn merge_pull_request(
        &self,
        request: &MergePullRequestRequest,
    ) -> Result<GitHubReply<GitHubMergeReceipt>, GitHubFailure> {
        GitHubClient::merge_pull_request(self, request)
    }
}

/// One explicit pull-request credential capability fixed to one repository and
/// one branch pair.
///
/// `merge_allowed` is carried here rather than only checked upstream. The
/// review adapter already refuses a merge for a credential without the merge
/// scope, and this is the second, independent refusal: an adapter handed a
/// merge plan built from a write-only credential must not perform it, whatever
/// the caller believed. Two flags would be one flag too many if the scopes
/// were a level, but they are withheld independently by design.
pub struct GitHubPullRequestWriteCapability {
    credential_reference: String,
    target: RepoTarget,
    base_branch: BranchName,
    head_branch: BranchName,
    merge_allowed: bool,
    #[cfg(not(test))]
    client: GitHubClient,
    #[cfg(test)]
    client: Box<dyn GitHubPullRequestTransport>,
}

impl GitHubPullRequestWriteCapability {
    /// Construct the production fixed-origin capability.
    pub fn production(
        credential_reference: &str,
        target: RepoTarget,
        base_branch: BranchName,
        head_branch: BranchName,
        merge_allowed: bool,
        token: GitHubToken,
    ) -> Result<Self, GitHubPullRequestError> {
        if !safe_reference(credential_reference) || base_branch == head_branch {
            return Err(GitHubPullRequestError::InvalidPlan);
        }
        let client = GitHubClient::new(GitHubBase::production(), token);
        Ok(Self {
            credential_reference: credential_reference.to_owned(),
            target,
            base_branch,
            head_branch,
            merge_allowed,
            #[cfg(not(test))]
            client,
            #[cfg(test)]
            client: Box::new(client),
        })
    }

    #[cfg(test)]
    pub(crate) fn testing(
        credential_reference: &str,
        target: RepoTarget,
        base_branch: BranchName,
        head_branch: BranchName,
        merge_allowed: bool,
        transport: SharedGitHubPullRequestTransport,
    ) -> Result<Self, GitHubPullRequestError> {
        if !safe_reference(credential_reference) || base_branch == head_branch {
            return Err(GitHubPullRequestError::InvalidPlan);
        }
        Ok(Self {
            credential_reference: credential_reference.to_owned(),
            target,
            base_branch,
            head_branch,
            merge_allowed,
            client: Box::new(SharedTestTransport(transport)),
        })
    }

    #[cfg(not(test))]
    fn transport(&self) -> &GitHubClient {
        &self.client
    }

    #[cfg(test)]
    fn transport(&self) -> &dyn GitHubPullRequestTransport {
        self.client.as_ref()
    }

    #[must_use]
    pub const fn merge_allowed(&self) -> bool {
        self.merge_allowed
    }
}

/// Production adapter. It exposes only preflight, one-shot submit, and lookup.
pub struct GitHubPullRequestAdapter {
    capability: GitHubPullRequestWriteCapability,
}

impl GitHubPullRequestAdapter {
    #[must_use]
    pub const fn new(capability: GitHubPullRequestWriteCapability) -> Self {
        Self { capability }
    }

    /// Read the live provider baseline used to advertise one exact capability.
    ///
    /// This is deliberately GET-only and accepts no path or operation. The
    /// returned observation is the only thing a capability slot may be minted
    /// from: an installed credential and a registry binding prove nothing on
    /// their own, and a slot minted from them would advertise a control that
    /// always refuses.
    ///
    /// What each family's read proves:
    ///
    /// * **Open** — the head branch exists and its tip is exactly the commit
    ///   returned; the base branch exists; and no pull request is already open
    ///   for that head/base pair, which is the condition GitHub would refuse
    ///   the create on and which the review snapshot claims by reporting the
    ///   pull request absent.
    /// * **Update** — the numbered pull request exists in this exact
    ///   repository, is open or draft, proposes from this exact head branch
    ///   onto this exact base branch, and has not already been merged.
    /// * **Merge** — everything the update read proves, plus that GitHub
    ///   itself reports the pull request mergeable now, and that its head is
    ///   the commit the caller expects. A `mergeable` GitHub has not finished
    ///   computing is not a yes.
    pub fn preflight_observation(
        &self,
        target: &RepoTarget,
        family: GitHubPullRequestFamily,
        number: Option<IssueNumber>,
        expected_head_sha: Option<&str>,
    ) -> Result<GitHubPullRequestObservation, GitHubPullRequestError> {
        if &self.capability.target != target {
            return Err(GitHubPullRequestError::CapabilityMismatch);
        }
        if family == GitHubPullRequestFamily::Merge && !self.capability.merge_allowed {
            return Err(GitHubPullRequestError::MergeWithheld);
        }
        match family {
            GitHubPullRequestFamily::Open => {
                if number.is_some() {
                    return Err(GitHubPullRequestError::CapabilityMismatch);
                }
                self.observe_openable(expected_head_sha)
            }
            GitHubPullRequestFamily::Update | GitHubPullRequestFamily::Merge => {
                let number = number.ok_or(GitHubPullRequestError::CapabilityMismatch)?;
                self.observe_existing(family, number, expected_head_sha)
            }
        }
    }

    fn observe_openable(
        &self,
        expected_head_sha: Option<&str>,
    ) -> Result<GitHubPullRequestObservation, GitHubPullRequestError> {
        let transport = self.capability.transport();
        let head = read_branch(
            transport,
            &self.capability.target,
            &self.capability.head_branch,
        )?;
        // The base is read too. GitHub would refuse a create naming a base it
        // does not have, and a capability advertised on a base that has been
        // deleted is a control that always refuses.
        read_branch(
            transport,
            &self.capability.target,
            &self.capability.base_branch,
        )?;
        if expected_head_sha.is_some_and(|expected| expected != head.commit_sha) {
            return Err(GitHubPullRequestError::ResourceChanged);
        }
        let request = ListPullRequestsRequest::new(
            self.capability.target.clone(),
            self.capability.head_branch.clone(),
            self.capability.base_branch.clone(),
        );
        let existing = match list_open_pull_requests(transport, &request) {
            Ok(reply) => match reply.into_outcome() {
                GitHubOutcome::Accepted(matches) => matches,
                GitHubOutcome::Rejected(_) => {
                    return Err(GitHubPullRequestError::ProviderRefused);
                }
            },
            Err(_) => return Err(GitHubPullRequestError::ProviderUnavailable),
        };
        if !existing.is_empty() {
            // The review projection said absent and GitHub says otherwise, so
            // nothing may be advertised from this read.
            return Err(GitHubPullRequestError::ResourceChanged);
        }
        Ok(GitHubPullRequestObservation {
            family: GitHubPullRequestFamily::Open,
            number: None,
            head_sha: head.commit_sha,
            mergeable: false,
        })
    }

    fn observe_existing(
        &self,
        family: GitHubPullRequestFamily,
        number: IssueNumber,
        expected_head_sha: Option<&str>,
    ) -> Result<GitHubPullRequestObservation, GitHubPullRequestError> {
        let pull = read_pull_request(self.capability.transport(), &self.capability.target, number)?;
        if pull.number != number
            || pull.merged
            || pull.state != PullRequestLifecycle::Open
            || pull.head_ref != self.capability.head_branch.as_str()
            || pull.base_ref != self.capability.base_branch.as_str()
            || !valid_head_sha(&pull.head_sha)
        {
            return Err(GitHubPullRequestError::ResourceChanged);
        }
        if expected_head_sha.is_some_and(|expected| expected != pull.head_sha) {
            return Err(GitHubPullRequestError::ResourceChanged);
        }
        let mergeable = pull.mergeable == PullRequestMergeability::Mergeable;
        if family == GitHubPullRequestFamily::Merge {
            // A merge is only ever advertised for a pull request GitHub itself
            // reports mergeable. `Unknown` is GitHub still computing, and a
            // draft is not landable at all.
            if !mergeable || pull.draft {
                return Err(GitHubPullRequestError::ResourceChanged);
            }
        }
        Ok(GitHubPullRequestObservation {
            family,
            number: Some(number),
            head_sha: pull.head_sha,
            mergeable,
        })
    }

    /// Verify the exact observed pull request before custody begins.
    pub fn preflight(
        &self,
        plan: &GitHubPullRequestPlan,
    ) -> Result<GitHubPullRequestObservation, GitHubPullRequestError> {
        self.verify_capability(plan)?;
        self.preflight_observation(
            &plan.target,
            plan.family,
            plan.number,
            Some(&plan.observed_head_sha),
        )
    }

    /// Perform the only write. The durable state must already say custody
    /// began.
    pub fn submit(
        &self,
        plan: &GitHubPullRequestPlan,
        submission: &mut GitHubPullRequestSubmission,
    ) -> Result<GitHubPullRequestCustody, GitHubPullRequestError> {
        verify_submission(plan, submission)?;
        if submission.custody != GitHubPullRequestCustody::CustodyStarted {
            return Err(GitHubPullRequestError::SubmissionState);
        }
        if let Err(error) = self.preflight(plan) {
            // No write has occurred yet, so even an unavailable preflight is a
            // proved-not-started refusal rather than provider ambiguity.
            submission.custody = GitHubPullRequestCustody::Refused;
            return Err(error);
        }
        match plan.family {
            GitHubPullRequestFamily::Open => self.submit_open(plan, submission),
            GitHubPullRequestFamily::Update => self.submit_update(plan, submission),
            GitHubPullRequestFamily::Merge => self.submit_merge(plan, submission),
        }
    }

    fn submit_open(
        &self,
        plan: &GitHubPullRequestPlan,
        submission: &mut GitHubPullRequestSubmission,
    ) -> Result<GitHubPullRequestCustody, GitHubPullRequestError> {
        let title = plan
            .title
            .as_deref()
            .and_then(|value| automonique_github_connector::IssueTitle::new(value).ok())
            .ok_or(GitHubPullRequestError::InvalidPlan)?;
        let request = CreatePullRequestRequest::new(
            plan.target.clone(),
            title,
            plan.head_branch.clone(),
            plan.base_branch.clone(),
        );
        match create_pull_request(self.capability.transport(), &request) {
            Ok(reply) => match reply.into_outcome() {
                GitHubOutcome::Accepted(opened) => {
                    submission.opened_number = Some(opened.number);
                    submission.custody = GitHubPullRequestCustody::Accepted;
                    Ok(submission.custody)
                }
                GitHubOutcome::Rejected(rejection) if rejection.status() < 500 => {
                    submission.custody = GitHubPullRequestCustody::Refused;
                    Err(GitHubPullRequestError::ProviderRefused)
                }
                GitHubOutcome::Rejected(_) => {
                    submission.custody = GitHubPullRequestCustody::Ambiguous;
                    Err(GitHubPullRequestError::ProviderUnavailable)
                }
            },
            Err(_) => {
                submission.custody = GitHubPullRequestCustody::Ambiguous;
                Err(GitHubPullRequestError::ProviderUnavailable)
            }
        }
    }

    fn submit_update(
        &self,
        plan: &GitHubPullRequestPlan,
        submission: &mut GitHubPullRequestSubmission,
    ) -> Result<GitHubPullRequestCustody, GitHubPullRequestError> {
        let number = plan.number.ok_or(GitHubPullRequestError::InvalidPlan)?;
        let title = plan
            .title
            .as_deref()
            .and_then(|value| automonique_github_connector::IssueTitle::new(value).ok())
            .ok_or(GitHubPullRequestError::InvalidPlan)?;
        let request = UpdatePullRequestRequest::new(plan.target.clone(), number, title);
        match update_pull_request(self.capability.transport(), &request) {
            Ok(reply) => match reply.into_outcome() {
                GitHubOutcome::Accepted(_) => {
                    submission.custody = GitHubPullRequestCustody::Accepted;
                    Ok(submission.custody)
                }
                GitHubOutcome::Rejected(rejection) if rejection.status() < 500 => {
                    submission.custody = GitHubPullRequestCustody::Refused;
                    Err(GitHubPullRequestError::ProviderRefused)
                }
                GitHubOutcome::Rejected(_) => {
                    submission.custody = GitHubPullRequestCustody::Ambiguous;
                    Err(GitHubPullRequestError::ProviderUnavailable)
                }
            },
            Err(_) => {
                submission.custody = GitHubPullRequestCustody::Ambiguous;
                Err(GitHubPullRequestError::ProviderUnavailable)
            }
        }
    }

    fn submit_merge(
        &self,
        plan: &GitHubPullRequestPlan,
        submission: &mut GitHubPullRequestSubmission,
    ) -> Result<GitHubPullRequestCustody, GitHubPullRequestError> {
        if !self.capability.merge_allowed {
            submission.custody = GitHubPullRequestCustody::Refused;
            return Err(GitHubPullRequestError::MergeWithheld);
        }
        let number = plan.number.ok_or(GitHubPullRequestError::InvalidPlan)?;
        let head = HeadRevision::new(&plan.observed_head_sha)
            .map_err(|_| GitHubPullRequestError::InvalidPlan)?;
        let request = MergePullRequestRequest::new(plan.target.clone(), number, head);
        match merge_pull_request(self.capability.transport(), &request) {
            Ok(reply) => match reply.into_outcome() {
                // GitHub answers 200 with `merged: false` when it accepted the
                // request and declined the merge. That is a refusal, not a
                // landed change, and treating it as success would report a
                // merge that never happened.
                GitHubOutcome::Accepted(receipt) if receipt.merged => {
                    submission.custody = GitHubPullRequestCustody::Accepted;
                    Ok(submission.custody)
                }
                GitHubOutcome::Accepted(_) => {
                    submission.custody = GitHubPullRequestCustody::Refused;
                    Err(GitHubPullRequestError::ProviderRefused)
                }
                GitHubOutcome::Rejected(rejection) if rejection.status() < 500 => {
                    submission.custody = GitHubPullRequestCustody::Refused;
                    Err(GitHubPullRequestError::ProviderRefused)
                }
                GitHubOutcome::Rejected(_) => {
                    submission.custody = GitHubPullRequestCustody::Ambiguous;
                    Err(GitHubPullRequestError::ProviderUnavailable)
                }
            },
            Err(_) => {
                submission.custody = GitHubPullRequestCustody::Ambiguous;
                Err(GitHubPullRequestError::ProviderUnavailable)
            }
        }
    }

    /// Reconcile without ever issuing a write.
    ///
    /// The attribution rule is the one the check-rerun adapter established and
    /// it matters more here, not less. A later read carries no provider-issued
    /// correlation token, so an observation that merely *matches* what our
    /// write would have produced is not proof our write produced it. Only a
    /// submission that already received the provider's acknowledgement for
    /// this exact plan may complete.
    pub fn reconcile(
        &self,
        plan: &GitHubPullRequestPlan,
        submission: &mut GitHubPullRequestSubmission,
    ) -> Result<GitHubPullRequestCustody, GitHubPullRequestError> {
        self.verify_capability(plan)?;
        verify_submission(plan, submission)?;
        if matches!(
            submission.custody,
            GitHubPullRequestCustody::Refused | GitHubPullRequestCustody::Completed
        ) {
            return Ok(submission.custody);
        }
        let correlated = submission.custody == GitHubPullRequestCustody::Accepted;
        let landed = match plan.family {
            GitHubPullRequestFamily::Open => self.reconcile_open(plan, submission)?,
            GitHubPullRequestFamily::Update => self.reconcile_update(plan)?,
            GitHubPullRequestFamily::Merge => self.reconcile_merge(plan)?,
        };
        submission.custody = match (landed, correlated, submission.custody) {
            (true, true, _) => GitHubPullRequestCustody::Completed,
            // An uncorrelated observation of the effect could be another
            // actor's write. Claiming it would forge attribution, so this
            // stays ambiguous forever rather than resolving to a lie.
            (_, _, GitHubPullRequestCustody::NotStarted) => GitHubPullRequestCustody::NotStarted,
            // GitHub can acknowledge a write before a later read shows it.
            // Preserve the provider-issued attribution so a subsequent exact
            // observation can still complete this receipt.
            (false, true, _) => GitHubPullRequestCustody::Accepted,
            _ => GitHubPullRequestCustody::Ambiguous,
        };
        Ok(submission.custody)
    }

    fn reconcile_open(
        &self,
        plan: &GitHubPullRequestPlan,
        submission: &GitHubPullRequestSubmission,
    ) -> Result<bool, GitHubPullRequestError> {
        let Some(number) = submission.opened_number else {
            // Without the provider-issued number this process holds nothing
            // that names the pull request it may have opened. Reading the
            // repository's open pull requests could only ever find someone
            // else's, so no read is made at all.
            return Ok(false);
        };
        let pull = read_pull_request(self.capability.transport(), &plan.target, number)?;
        Ok(pull.number == number
            && pull.head_ref == plan.head_branch.as_str()
            && pull.base_ref == plan.base_branch.as_str())
    }

    fn reconcile_update(
        &self,
        plan: &GitHubPullRequestPlan,
    ) -> Result<bool, GitHubPullRequestError> {
        let number = plan.number.ok_or(GitHubPullRequestError::InvalidPlan)?;
        let title = plan
            .title
            .as_deref()
            .ok_or(GitHubPullRequestError::InvalidPlan)?;
        let pull = read_pull_request(self.capability.transport(), &plan.target, number)?;
        Ok(pull.number == number && pull.title == title)
    }

    fn reconcile_merge(
        &self,
        plan: &GitHubPullRequestPlan,
    ) -> Result<bool, GitHubPullRequestError> {
        let number = plan.number.ok_or(GitHubPullRequestError::InvalidPlan)?;
        let pull = read_pull_request(self.capability.transport(), &plan.target, number)?;
        // A merge that landed carries our exact fenced head. A pull request
        // merged at a different head is somebody else's merge of the same
        // branch after ours was refused.
        Ok(pull.number == number && pull.merged && pull.head_sha == plan.observed_head_sha)
    }

    fn verify_capability(
        &self,
        plan: &GitHubPullRequestPlan,
    ) -> Result<(), GitHubPullRequestError> {
        if plan.family == GitHubPullRequestFamily::Merge && !self.capability.merge_allowed {
            return Err(GitHubPullRequestError::MergeWithheld);
        }
        if self.capability.credential_reference != plan.credential_reference
            || self.capability.target != plan.target
            || self.capability.base_branch != plan.base_branch
            || self.capability.head_branch != plan.head_branch
        {
            return Err(GitHubPullRequestError::CapabilityMismatch);
        }
        Ok(())
    }
}

fn list_open_pull_requests(
    transport: &(impl GitHubPullRequestTransport + ?Sized),
    request: &ListPullRequestsRequest,
) -> Result<GitHubReply<Vec<GitHubPullRequestRef>>, GitHubFailure> {
    transport.list_pull_requests(request)
}

fn create_pull_request(
    transport: &(impl GitHubPullRequestTransport + ?Sized),
    request: &CreatePullRequestRequest,
) -> Result<GitHubReply<GitHubPullRequestRef>, GitHubFailure> {
    transport.create_pull_request(request)
}

fn update_pull_request(
    transport: &(impl GitHubPullRequestTransport + ?Sized),
    request: &UpdatePullRequestRequest,
) -> Result<GitHubReply<GitHubPullRequest>, GitHubFailure> {
    transport.update_pull_request(request)
}

fn merge_pull_request(
    transport: &(impl GitHubPullRequestTransport + ?Sized),
    request: &MergePullRequestRequest,
) -> Result<GitHubReply<GitHubMergeReceipt>, GitHubFailure> {
    transport.merge_pull_request(request)
}

fn read_branch(
    transport: &(impl GitHubPullRequestTransport + ?Sized),
    target: &RepoTarget,
    branch: &BranchName,
) -> Result<GitHubBranch, GitHubPullRequestError> {
    let request = GetBranchRequest::new(target.clone(), branch.clone());
    match transport.get_branch(&request) {
        Ok(reply) => match reply.into_outcome() {
            GitHubOutcome::Accepted(observed) => {
                if observed.name != branch.as_str() || !valid_head_sha(&observed.commit_sha) {
                    return Err(GitHubPullRequestError::ResourceChanged);
                }
                Ok(observed)
            }
            GitHubOutcome::Rejected(_) => Err(GitHubPullRequestError::ProviderRefused),
        },
        Err(_) => Err(GitHubPullRequestError::ProviderUnavailable),
    }
}

fn read_pull_request(
    transport: &(impl GitHubPullRequestTransport + ?Sized),
    target: &RepoTarget,
    number: IssueNumber,
) -> Result<GitHubPullRequest, GitHubPullRequestError> {
    let request = GetPullRequestRequest::new(target.clone(), number);
    match transport.get_pull_request(&request) {
        Ok(reply) => match reply.into_outcome() {
            GitHubOutcome::Accepted(pull) => Ok(pull),
            GitHubOutcome::Rejected(_) => Err(GitHubPullRequestError::ProviderRefused),
        },
        Err(_) => Err(GitHubPullRequestError::ProviderUnavailable),
    }
}

fn verify_submission(
    plan: &GitHubPullRequestPlan,
    submission: &GitHubPullRequestSubmission,
) -> Result<(), GitHubPullRequestError> {
    if submission.plan_digest != plan.digest || plan_digest(plan) != plan.digest {
        return Err(GitHubPullRequestError::SubmissionState);
    }
    Ok(())
}

fn safe_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CREDENTIAL_REFERENCE_BYTES
        && !value.starts_with('-')
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_head_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_title(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && value.len() <= MAX_PULL_REQUEST_TITLE_BYTES
        && !value.chars().any(char::is_control)
        && trimmed == value
}

fn plan_digest(plan: &GitHubPullRequestPlan) -> [u8; 32] {
    let mut document = Vec::new();
    push_field(&mut document, b"automonique.github-pull-request/v1");
    push_field(&mut document, &plan.registry_generation_digest);
    push_field(&mut document, &plan.credential_generation_digest);
    for field in [
        plan.credential_reference.as_bytes(),
        plan.target.owner().as_str().as_bytes(),
        plan.target.repo().as_str().as_bytes(),
        plan.family.as_str().as_bytes(),
        plan.base_branch.as_str().as_bytes(),
        plan.head_branch.as_str().as_bytes(),
        plan.observed_head_sha.as_bytes(),
        plan.title.as_deref().unwrap_or_default().as_bytes(),
        plan.tenant.as_bytes(),
        plan.actor.as_bytes(),
        plan.project.as_str().as_bytes(),
        plan.workspace.kind().as_str().as_bytes(),
        plan.workspace.id().as_bytes(),
        plan.authority.kind().as_str().as_bytes(),
        plan.authority.id().as_str().as_bytes(),
        plan.idempotency_key.as_str().as_bytes(),
    ] {
        push_field(&mut document, field);
    }
    // An absent number and a number are distinguished by the length prefix,
    // so an open can never collide with an update of pull request zero.
    push_field(
        &mut document,
        &plan
            .number
            .map(IssueNumber::get)
            .unwrap_or_default()
            .to_be_bytes(),
    );
    push_field(
        &mut document,
        &[
            u8::from(plan.number.is_some()),
            u8::from(plan.title.is_some()),
        ],
    );
    push_field(
        &mut document,
        &plan.expected_snapshot_revision.get().to_be_bytes(),
    );
    push_field(
        &mut document,
        &plan.expected_pull_request_revision.get().to_be_bytes(),
    );
    *Sha256::digest(&document).as_bytes()
}

fn push_field(document: &mut Vec<u8>, field: &[u8]) {
    document.extend_from_slice(&(field.len() as u64).to_be_bytes());
    document.extend_from_slice(field);
}

#[cfg(test)]
mod tests {
    use super::*;
    use automonique_github_connector::{GitHubRejection, RateLimit, ServerMessage};
    use automonique_protocol::platform_v2::UserWorkspaceId;
    use automonique_protocol::platform_v2_review::ReviewAuthorityId;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    const HEAD: &str = "0123456789abcdef0123456789abcdef01234567";
    const MOVED: &str = "89abcdef0123456789abcdef0123456789abcdef";

    #[derive(Default)]
    struct FakeTransport {
        branches: RefCell<VecDeque<Result<GitHubReply<GitHubBranch>, GitHubFailure>>>,
        pulls: RefCell<VecDeque<Result<GitHubReply<GitHubPullRequest>, GitHubFailure>>>,
        listings: RefCell<VecDeque<Result<GitHubReply<Vec<GitHubPullRequestRef>>, GitHubFailure>>>,
        creates: RefCell<VecDeque<Result<GitHubReply<GitHubPullRequestRef>, GitHubFailure>>>,
        updates: RefCell<VecDeque<Result<GitHubReply<GitHubPullRequest>, GitHubFailure>>>,
        merges: RefCell<VecDeque<Result<GitHubReply<GitHubMergeReceipt>, GitHubFailure>>>,
        writes: Cell<usize>,
    }

    impl FakeTransport {
        fn openable() -> Self {
            let fake = Self::default();
            fake.branches
                .borrow_mut()
                .push_back(accepted(branch("agent-work", HEAD)));
            fake.branches
                .borrow_mut()
                .push_back(accepted(branch("main", MOVED)));
            fake.listings.borrow_mut().push_back(accepted(Vec::new()));
            fake
        }

        fn with_pull(pull: GitHubPullRequest) -> Self {
            let fake = Self::default();
            fake.pulls.borrow_mut().push_back(accepted(pull));
            fake
        }

        fn push_pull(&self, pull: GitHubPullRequest) {
            self.pulls.borrow_mut().push_back(accepted(pull));
        }
    }

    impl GitHubPullRequestTransport for FakeTransport {
        fn get_branch(
            &self,
            _: &GetBranchRequest,
        ) -> Result<GitHubReply<GitHubBranch>, GitHubFailure> {
            self.branches
                .borrow_mut()
                .pop_front()
                .expect("scripted branch read")
        }

        fn get_pull_request(
            &self,
            _: &GetPullRequestRequest,
        ) -> Result<GitHubReply<GitHubPullRequest>, GitHubFailure> {
            self.pulls
                .borrow_mut()
                .pop_front()
                .expect("scripted pull read")
        }

        fn list_pull_requests(
            &self,
            _: &ListPullRequestsRequest,
        ) -> Result<GitHubReply<Vec<GitHubPullRequestRef>>, GitHubFailure> {
            self.listings
                .borrow_mut()
                .pop_front()
                .expect("scripted listing")
        }

        fn create_pull_request(
            &self,
            _: &CreatePullRequestRequest,
        ) -> Result<GitHubReply<GitHubPullRequestRef>, GitHubFailure> {
            self.writes.set(self.writes.get() + 1);
            self.creates
                .borrow_mut()
                .pop_front()
                .expect("scripted create")
        }

        fn update_pull_request(
            &self,
            _: &UpdatePullRequestRequest,
        ) -> Result<GitHubReply<GitHubPullRequest>, GitHubFailure> {
            self.writes.set(self.writes.get() + 1);
            self.updates
                .borrow_mut()
                .pop_front()
                .expect("scripted update")
        }

        fn merge_pull_request(
            &self,
            _: &MergePullRequestRequest,
        ) -> Result<GitHubReply<GitHubMergeReceipt>, GitHubFailure> {
            self.writes.set(self.writes.get() + 1);
            self.merges
                .borrow_mut()
                .pop_front()
                .expect("scripted merge")
        }
    }

    fn accepted<T>(value: T) -> Result<GitHubReply<T>, GitHubFailure> {
        Ok(GitHubReply::new(
            RateLimit::new(None, None, None),
            GitHubOutcome::Accepted(value),
        ))
    }

    fn rejected<T>(status: u16) -> Result<GitHubReply<T>, GitHubFailure> {
        let rate = RateLimit::new(None, None, None);
        Ok(GitHubReply::new(
            rate,
            GitHubOutcome::Rejected(GitHubRejection::new(
                status,
                ServerMessage::sanitized("refused"),
                &rate,
                None,
            )),
        ))
    }

    fn branch(name: &str, sha: &str) -> GitHubBranch {
        GitHubBranch {
            name: name.to_owned(),
            commit_sha: sha.to_owned(),
        }
    }

    fn pull(
        state: PullRequestLifecycle,
        merged: bool,
        mergeable: PullRequestMergeability,
        sha: &str,
    ) -> GitHubPullRequest {
        GitHubPullRequest {
            number: IssueNumber::new(77).expect("number"),
            title: "Proposer le correctif".to_owned(),
            state,
            draft: false,
            merged,
            mergeable,
            head_ref: "agent-work".to_owned(),
            head_sha: sha.to_owned(),
            base_ref: "main".to_owned(),
        }
    }

    fn target() -> RepoTarget {
        RepoTarget::parse("example-org", "example-repo").expect("target")
    }

    fn capability(fake: FakeTransport, merge_allowed: bool) -> GitHubPullRequestWriteCapability {
        GitHubPullRequestWriteCapability::testing(
            "review-pr",
            target(),
            BranchName::new("main").expect("base"),
            BranchName::new("agent-work").expect("head"),
            merge_allowed,
            Arc::new(Mutex::new(
                Box::new(fake) as Box<dyn GitHubPullRequestTransport + Send>
            )),
        )
        .expect("capability")
    }

    fn actor() -> Actor {
        Actor::new("tenant-1", "actor-1").expect("actor")
    }

    fn binding() -> GitHubPullRequestReviewBinding {
        GitHubPullRequestReviewBinding {
            project: ProjectId::new("project-1".to_owned()).expect("project"),
            workspace: WorkContextIdentity::UserWorkspace(
                UserWorkspaceId::new("workspace-1").expect("workspace"),
            ),
            authority: ReviewAuthority::new(
                ReviewAuthorityKind::PullRequest,
                ReviewAuthorityId::new("pr-authority".to_owned()).expect("authority"),
            ),
            idempotency_key: IdempotencyKey::new("key-1".to_owned()).expect("key"),
            expected_snapshot_revision: Revision::FIRST,
            expected_pull_request_revision: Revision::FIRST,
        }
    }

    fn plan_for(family: GitHubPullRequestFamily, sha: &str) -> GitHubPullRequestPlan {
        GitHubPullRequestPlan::new(
            [1; 32],
            [2; 32],
            "review-pr",
            GitHubPullRequestTarget {
                target: target(),
                family,
                base_branch: BranchName::new("main").expect("base"),
                head_branch: BranchName::new("agent-work").expect("head"),
                number: match family {
                    GitHubPullRequestFamily::Open => None,
                    _ => Some(IssueNumber::new(77).expect("number")),
                },
                observed_head_sha: sha.to_owned(),
                title: match family {
                    GitHubPullRequestFamily::Merge => None,
                    _ => Some("Proposer le correctif".to_owned()),
                },
            },
            &actor(),
            binding(),
        )
        .expect("plan")
    }

    fn started(plan: &GitHubPullRequestPlan) -> GitHubPullRequestSubmission {
        let mut submission = GitHubPullRequestSubmission::new(plan);
        submission.begin_custody().expect("custody");
        submission
    }

    #[test]
    fn an_open_is_only_observed_when_the_branches_exist_and_nothing_is_already_proposed() {
        let adapter = GitHubPullRequestAdapter::new(capability(FakeTransport::openable(), false));
        let observation = adapter
            .preflight_observation(&target(), GitHubPullRequestFamily::Open, None, None)
            .expect("observation");
        assert_eq!(observation.family(), GitHubPullRequestFamily::Open);
        assert_eq!(observation.number(), None);
        assert_eq!(observation.head_sha(), HEAD);
        assert!(!observation.mergeable());
    }

    #[test]
    fn an_open_is_refused_when_github_already_has_one_for_the_pair() {
        let fake = FakeTransport::default();
        fake.branches
            .borrow_mut()
            .push_back(accepted(branch("agent-work", HEAD)));
        fake.branches
            .borrow_mut()
            .push_back(accepted(branch("main", MOVED)));
        fake.listings
            .borrow_mut()
            .push_back(accepted(vec![GitHubPullRequestRef {
                number: IssueNumber::new(77).expect("number"),
                head_sha: HEAD.to_owned(),
            }]));
        let adapter = GitHubPullRequestAdapter::new(capability(fake, false));
        assert_eq!(
            adapter
                .preflight_observation(&target(), GitHubPullRequestFamily::Open, None, None)
                .err(),
            Some(GitHubPullRequestError::ResourceChanged),
            "the projection said absent and the provider disagrees, so nothing may be advertised"
        );
    }

    #[test]
    fn an_open_is_refused_when_the_head_branch_moved_off_the_advertised_commit() {
        let adapter = GitHubPullRequestAdapter::new(capability(FakeTransport::openable(), false));
        assert_eq!(
            adapter
                .preflight_observation(&target(), GitHubPullRequestFamily::Open, None, Some(MOVED))
                .err(),
            Some(GitHubPullRequestError::ResourceChanged)
        );
    }

    #[test]
    fn an_update_is_observed_only_for_an_open_pull_request_on_the_bound_branch_pair() {
        let adapter = GitHubPullRequestAdapter::new(capability(
            FakeTransport::with_pull(pull(
                PullRequestLifecycle::Open,
                false,
                PullRequestMergeability::Unknown,
                HEAD,
            )),
            false,
        ));
        let observation = adapter
            .preflight_observation(
                &target(),
                GitHubPullRequestFamily::Update,
                Some(IssueNumber::new(77).expect("number")),
                Some(HEAD),
            )
            .expect("observation");
        assert_eq!(observation.number(), IssueNumber::new(77).ok());
        assert_eq!(observation.head_sha(), HEAD);
        assert!(
            !observation.mergeable(),
            "a mergeable GitHub has not finished computing is not a yes"
        );
    }

    #[test]
    fn a_merge_is_never_observed_for_a_pull_request_github_will_not_merge() {
        for state in [
            pull(
                PullRequestLifecycle::Open,
                false,
                PullRequestMergeability::Conflicted,
                HEAD,
            ),
            pull(
                PullRequestLifecycle::Open,
                false,
                PullRequestMergeability::Unknown,
                HEAD,
            ),
            pull(
                PullRequestLifecycle::Closed,
                true,
                PullRequestMergeability::Mergeable,
                HEAD,
            ),
        ] {
            let adapter =
                GitHubPullRequestAdapter::new(capability(FakeTransport::with_pull(state), true));
            assert_eq!(
                adapter
                    .preflight_observation(
                        &target(),
                        GitHubPullRequestFamily::Merge,
                        Some(IssueNumber::new(77).expect("number")),
                        Some(HEAD),
                    )
                    .err(),
                Some(GitHubPullRequestError::ResourceChanged)
            );
        }
    }

    #[test]
    fn a_merge_is_refused_by_the_adapter_when_the_credential_withheld_the_merge_scope() {
        let fake = FakeTransport::with_pull(pull(
            PullRequestLifecycle::Open,
            false,
            PullRequestMergeability::Mergeable,
            HEAD,
        ));
        let adapter = GitHubPullRequestAdapter::new(capability(fake, false));
        assert_eq!(
            adapter
                .preflight_observation(
                    &target(),
                    GitHubPullRequestFamily::Merge,
                    Some(IssueNumber::new(77).expect("number")),
                    Some(HEAD),
                )
                .err(),
            Some(GitHubPullRequestError::MergeWithheld),
            "a credential that may propose changes must never be able to land them"
        );
        let plan = plan_for(GitHubPullRequestFamily::Merge, HEAD);
        let mut submission = started(&plan);
        assert_eq!(
            adapter.submit(&plan, &mut submission).err(),
            Some(GitHubPullRequestError::MergeWithheld)
        );
        assert_eq!(submission.custody(), GitHubPullRequestCustody::Refused);
    }

    #[test]
    fn an_open_records_the_provider_issued_number_with_its_accepted_custody() {
        let fake = FakeTransport::openable();
        fake.creates
            .borrow_mut()
            .push_back(accepted(GitHubPullRequestRef {
                number: IssueNumber::new(91).expect("number"),
                head_sha: HEAD.to_owned(),
            }));
        let adapter = GitHubPullRequestAdapter::new(capability(fake, false));
        let plan = plan_for(GitHubPullRequestFamily::Open, HEAD);
        let mut submission = started(&plan);
        assert_eq!(
            adapter.submit(&plan, &mut submission).expect("submit"),
            GitHubPullRequestCustody::Accepted
        );
        assert_eq!(submission.opened_number(), IssueNumber::new(91).ok());
    }

    #[test]
    fn a_submit_refuses_every_state_except_the_one_that_was_durably_committed() {
        let plan = plan_for(GitHubPullRequestFamily::Open, HEAD);
        for custody in [
            GitHubPullRequestCustody::NotStarted,
            GitHubPullRequestCustody::Accepted,
            GitHubPullRequestCustody::Ambiguous,
            GitHubPullRequestCustody::Refused,
            GitHubPullRequestCustody::Completed,
        ] {
            let adapter =
                GitHubPullRequestAdapter::new(capability(FakeTransport::default(), false));
            let opened = matches!(
                custody,
                GitHubPullRequestCustody::Accepted | GitHubPullRequestCustody::Completed
            )
            .then(|| IssueNumber::new(91).expect("number"));
            let mut submission =
                GitHubPullRequestSubmission::restore(&plan, plan.digest(), custody, opened)
                    .expect("restore");
            assert_eq!(
                adapter.submit(&plan, &mut submission).err(),
                Some(GitHubPullRequestError::SubmissionState),
                "no write may follow custody state {custody:?}"
            );
        }
    }

    #[test]
    fn a_transport_failure_after_the_write_leaves_the_submission_ambiguous() {
        let fake = FakeTransport::openable();
        fake.creates
            .borrow_mut()
            .push_back(Err(GitHubFailure::TimedOut));
        let adapter = GitHubPullRequestAdapter::new(capability(fake, false));
        let plan = plan_for(GitHubPullRequestFamily::Open, HEAD);
        let mut submission = started(&plan);
        assert_eq!(
            adapter.submit(&plan, &mut submission).err(),
            Some(GitHubPullRequestError::ProviderUnavailable)
        );
        assert_eq!(submission.custody(), GitHubPullRequestCustody::Ambiguous);
    }

    #[test]
    fn an_ambiguous_open_never_claims_a_pull_request_it_cannot_correlate() {
        let fake = FakeTransport::default();
        // The pull request the plan would have opened now exists, but this
        // process never received a number for it.
        fake.push_pull(pull(
            PullRequestLifecycle::Open,
            false,
            PullRequestMergeability::Mergeable,
            HEAD,
        ));
        let adapter = GitHubPullRequestAdapter::new(capability(fake, false));
        let plan = plan_for(GitHubPullRequestFamily::Open, HEAD);
        let mut submission = GitHubPullRequestSubmission::restore(
            &plan,
            plan.digest(),
            GitHubPullRequestCustody::Ambiguous,
            None,
        )
        .expect("restore");
        assert_eq!(
            adapter
                .reconcile(&plan, &mut submission)
                .expect("reconcile"),
            GitHubPullRequestCustody::Ambiguous,
            "an uncorrelated observation could be another actor's pull request"
        );
    }

    #[test]
    fn an_accepted_open_completes_once_its_own_number_reads_back() {
        let fake = FakeTransport::default();
        fake.push_pull(GitHubPullRequest {
            number: IssueNumber::new(91).expect("number"),
            ..pull(
                PullRequestLifecycle::Open,
                false,
                PullRequestMergeability::Mergeable,
                HEAD,
            )
        });
        let adapter = GitHubPullRequestAdapter::new(capability(fake, false));
        let plan = plan_for(GitHubPullRequestFamily::Open, HEAD);
        let mut submission = GitHubPullRequestSubmission::restore(
            &plan,
            plan.digest(),
            GitHubPullRequestCustody::Accepted,
            IssueNumber::new(91).ok(),
        )
        .expect("restore");
        assert_eq!(
            adapter
                .reconcile(&plan, &mut submission)
                .expect("reconcile"),
            GitHubPullRequestCustody::Completed
        );
    }

    #[test]
    fn a_merge_completes_only_when_the_landed_head_is_the_one_it_was_fenced_on() {
        for (landed_sha, expected) in [
            (HEAD, GitHubPullRequestCustody::Completed),
            (MOVED, GitHubPullRequestCustody::Accepted),
        ] {
            let fake = FakeTransport::default();
            fake.push_pull(pull(
                PullRequestLifecycle::Closed,
                true,
                PullRequestMergeability::Unknown,
                landed_sha,
            ));
            let adapter = GitHubPullRequestAdapter::new(capability(fake, true));
            let plan = plan_for(GitHubPullRequestFamily::Merge, HEAD);
            let mut submission = GitHubPullRequestSubmission::restore(
                &plan,
                plan.digest(),
                GitHubPullRequestCustody::Accepted,
                None,
            )
            .expect("restore");
            assert_eq!(
                adapter
                    .reconcile(&plan, &mut submission)
                    .expect("reconcile"),
                expected,
                "a merge at {landed_sha} must not be claimed as ours"
            );
        }
    }

    #[test]
    fn a_merge_github_declined_at_two_hundred_is_a_refusal_rather_than_a_landed_change() {
        let fake = FakeTransport::with_pull(pull(
            PullRequestLifecycle::Open,
            false,
            PullRequestMergeability::Mergeable,
            HEAD,
        ));
        fake.merges
            .borrow_mut()
            .push_back(accepted(GitHubMergeReceipt {
                merged: false,
                merge_commit_sha: None,
            }));
        let adapter = GitHubPullRequestAdapter::new(capability(fake, true));
        let plan = plan_for(GitHubPullRequestFamily::Merge, HEAD);
        let mut submission = started(&plan);
        assert_eq!(
            adapter.submit(&plan, &mut submission).err(),
            Some(GitHubPullRequestError::ProviderRefused)
        );
        assert_eq!(submission.custody(), GitHubPullRequestCustody::Refused);
    }

    #[test]
    fn a_client_refusal_is_proved_not_started_rather_than_ambiguous() {
        let fake = FakeTransport::with_pull(pull(
            PullRequestLifecycle::Open,
            false,
            PullRequestMergeability::Mergeable,
            HEAD,
        ));
        fake.merges.borrow_mut().push_back(rejected(409));
        let adapter = GitHubPullRequestAdapter::new(capability(fake, true));
        let plan = plan_for(GitHubPullRequestFamily::Merge, HEAD);
        let mut submission = started(&plan);
        assert_eq!(
            adapter.submit(&plan, &mut submission).err(),
            Some(GitHubPullRequestError::ProviderRefused)
        );
        assert_eq!(submission.custody(), GitHubPullRequestCustody::Refused);
    }

    #[test]
    fn a_stale_head_stops_the_write_before_it_reaches_the_provider() {
        let fake = FakeTransport::with_pull(pull(
            PullRequestLifecycle::Open,
            false,
            PullRequestMergeability::Mergeable,
            MOVED,
        ));
        let adapter = GitHubPullRequestAdapter::new(capability(fake, true));
        let plan = plan_for(GitHubPullRequestFamily::Merge, HEAD);
        let mut submission = started(&plan);
        assert_eq!(
            adapter.submit(&plan, &mut submission).err(),
            Some(GitHubPullRequestError::ResourceChanged)
        );
        assert_eq!(submission.custody(), GitHubPullRequestCustody::Refused);
    }

    #[test]
    fn a_plan_digest_separates_every_family_target_and_review_coordinate() {
        let open = plan_for(GitHubPullRequestFamily::Open, HEAD);
        let update = plan_for(GitHubPullRequestFamily::Update, HEAD);
        let merge = plan_for(GitHubPullRequestFamily::Merge, HEAD);
        let moved = plan_for(GitHubPullRequestFamily::Update, MOVED);
        let mut digests = vec![
            open.digest(),
            update.digest(),
            merge.digest(),
            moved.digest(),
        ];
        digests.sort_unstable();
        digests.dedup();
        assert_eq!(digests.len(), 4, "no two distinct plans may share a digest");
    }

    #[test]
    fn a_plan_refuses_a_shape_its_family_cannot_have() {
        let cases = [
            (GitHubPullRequestFamily::Open, Some(77), Some("t")),
            (GitHubPullRequestFamily::Open, None, None),
            (GitHubPullRequestFamily::Update, None, Some("t")),
            (GitHubPullRequestFamily::Update, Some(77), None),
            (GitHubPullRequestFamily::Merge, Some(77), Some("t")),
            (GitHubPullRequestFamily::Merge, None, None),
        ];
        for (family, number, title) in cases {
            let built = GitHubPullRequestPlan::new(
                [1; 32],
                [2; 32],
                "review-pr",
                GitHubPullRequestTarget {
                    target: target(),
                    family,
                    base_branch: BranchName::new("main").expect("base"),
                    head_branch: BranchName::new("agent-work").expect("head"),
                    number: number.map(|value| IssueNumber::new(value).expect("number")),
                    observed_head_sha: HEAD.to_owned(),
                    title: title.map(str::to_owned),
                },
                &actor(),
                binding(),
            );
            assert_eq!(
                built.err(),
                Some(GitHubPullRequestError::InvalidPlan),
                "family {family:?} must refuse number={number:?} title={title:?}"
            );
        }
    }

    #[test]
    fn a_restored_submission_refuses_a_number_its_family_cannot_own() {
        let update = plan_for(GitHubPullRequestFamily::Update, HEAD);
        assert_eq!(
            GitHubPullRequestSubmission::restore(
                &update,
                update.digest(),
                GitHubPullRequestCustody::Accepted,
                IssueNumber::new(91).ok(),
            )
            .err(),
            Some(GitHubPullRequestError::SubmissionState)
        );
        let open = plan_for(GitHubPullRequestFamily::Open, HEAD);
        assert_eq!(
            GitHubPullRequestSubmission::restore(
                &open,
                open.digest(),
                GitHubPullRequestCustody::Accepted,
                None,
            )
            .err(),
            Some(GitHubPullRequestError::SubmissionState),
            "an accepted open without its number can never be correlated again"
        );
    }
}
