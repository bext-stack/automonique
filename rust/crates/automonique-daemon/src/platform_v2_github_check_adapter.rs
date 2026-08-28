// SPDX-License-Identifier: Elastic-2.0

//! Exact, least-privilege GitHub Actions workflow-rerun boundary.
//!
//! GitHub's rerun endpoint accepts no idempotency key. This adapter therefore
//! separates durable custody admission from the one allowed POST. A caller
//! persists [`GitHubCheckRerunSubmission`] after `begin_custody` and before
//! `submit`; any crash or transport failure after that point is ambiguous and
//! may only be reconciled by reading a later `run_attempt`. `submit` refuses
//! every state except `CustodyStarted`, so an ambiguous write can never be
//! replayed blindly.
//!
//! The capability is fixed to one repository and one explicit credential
//! reference whose operator-side grant is GitHub Actions repository
//! permission `write`. There is no `gh` subprocess, ambient account lookup,
//! arbitrary URL, workflow dispatch, shell, or generic execute fallback.

use automonique_github_connector::{
    GetWorkflowRunRequest, GitHubBase, GitHubClient, GitHubFailure, GitHubOutcome, GitHubReply,
    GitHubToken, GitHubWorkflowRun, RepoTarget, RerunWorkflowRequest, WorkflowRunId,
    WorkflowRunStatus,
};
use automonique_protocol::digest::Sha256;
use automonique_protocol::identity::Actor;
use automonique_protocol::platform::IdempotencyKey;
use automonique_protocol::platform_v2::{ProjectId, WorkContextIdentity};
use automonique_protocol::platform_v2_review::{
    ReviewAuthority, ReviewAuthorityKind, ReviewCheckId,
};
use automonique_protocol::primitives::Revision;

const MAX_CREDENTIAL_REFERENCE_BYTES: usize = 256;

/// Stable, content-free failures safe for receipts and logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubCheckRerunError {
    InvalidPlan,
    CapabilityMismatch,
    ProviderUnavailable,
    ProviderRefused,
    ResourceChanged,
    SubmissionState,
}

/// Every authority and provider coordinate captured by the confirmation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubCheckRerunPlan {
    digest: [u8; 32],
    registry_generation_digest: [u8; 32],
    credential_generation_digest: [u8; 32],
    credential_reference: String,
    target: RepoTarget,
    run_id: WorkflowRunId,
    head_sha: String,
    observed_run_attempt: u32,
    tenant: String,
    actor: String,
    project: ProjectId,
    workspace: WorkContextIdentity,
    authority: ReviewAuthority,
    idempotency_key: IdempotencyKey,
    check_id: ReviewCheckId,
    expected_snapshot_revision: Revision,
    expected_check_revision: Revision,
}

impl GitHubCheckRerunPlan {
    /// Bind a user-confirmed review action to one exact observed workflow run.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry_generation_digest: [u8; 32],
        credential_generation_digest: [u8; 32],
        credential_reference: &str,
        target: RepoTarget,
        run_id: WorkflowRunId,
        head_sha: &str,
        observed_run_attempt: u32,
        actor: &Actor,
        project: ProjectId,
        workspace: WorkContextIdentity,
        authority: ReviewAuthority,
        idempotency_key: IdempotencyKey,
        check_id: ReviewCheckId,
        expected_snapshot_revision: Revision,
        expected_check_revision: Revision,
    ) -> Result<Self, GitHubCheckRerunError> {
        if !safe_reference(credential_reference)
            || authority.kind() != ReviewAuthorityKind::Ci
            || observed_run_attempt == 0
            || !valid_head_sha(head_sha)
        {
            return Err(GitHubCheckRerunError::InvalidPlan);
        }
        let mut plan = Self {
            digest: [0; 32],
            registry_generation_digest,
            credential_generation_digest,
            credential_reference: credential_reference.to_owned(),
            target,
            run_id,
            head_sha: head_sha.to_owned(),
            observed_run_attempt,
            tenant: actor.tenant().to_owned(),
            actor: actor.id().to_owned(),
            project,
            workspace,
            authority,
            idempotency_key,
            check_id,
            expected_snapshot_revision,
            expected_check_revision,
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
    pub const fn run_id(&self) -> WorkflowRunId {
        self.run_id
    }

    #[must_use]
    pub fn head_sha(&self) -> &str {
        &self.head_sha
    }

    #[must_use]
    pub const fn observed_run_attempt(&self) -> u32 {
        self.observed_run_attempt
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
    pub const fn check_id(&self) -> &ReviewCheckId {
        &self.check_id
    }

    #[must_use]
    pub const fn expected_snapshot_revision(&self) -> Revision {
        self.expected_snapshot_revision
    }

    #[must_use]
    pub const fn expected_check_revision(&self) -> Revision {
        self.expected_check_revision
    }
}

/// Durable custody state for a single plan digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubCheckRerunCustody {
    NotStarted,
    CustodyStarted,
    Accepted,
    Ambiguous,
    Refused,
    Completed,
}

/// The minimal durable record a store must persist before the provider call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubCheckRerunSubmission {
    plan_digest: [u8; 32],
    custody: GitHubCheckRerunCustody,
}

impl GitHubCheckRerunSubmission {
    #[must_use]
    pub fn new(plan: &GitHubCheckRerunPlan) -> Self {
        Self {
            plan_digest: plan.digest(),
            custody: GitHubCheckRerunCustody::NotStarted,
        }
    }

    /// Rehydrate the exact durable state after a process restart.
    pub fn restore(
        plan: &GitHubCheckRerunPlan,
        plan_digest: [u8; 32],
        custody: GitHubCheckRerunCustody,
    ) -> Result<Self, GitHubCheckRerunError> {
        if plan.digest() != plan_digest {
            return Err(GitHubCheckRerunError::SubmissionState);
        }
        Ok(Self {
            plan_digest,
            custody,
        })
    }

    /// Transition to the state that must be durably committed before `submit`.
    pub fn begin_custody(&mut self) -> Result<(), GitHubCheckRerunError> {
        if self.custody != GitHubCheckRerunCustody::NotStarted {
            return Err(GitHubCheckRerunError::SubmissionState);
        }
        self.custody = GitHubCheckRerunCustody::CustodyStarted;
        Ok(())
    }

    #[must_use]
    pub const fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    #[must_use]
    pub const fn custody(&self) -> GitHubCheckRerunCustody {
        self.custody
    }
}

trait GitHubActionsTransport {
    fn get_workflow_run(
        &self,
        request: &GetWorkflowRunRequest,
    ) -> Result<GitHubReply<GitHubWorkflowRun>, GitHubFailure>;

    fn rerun_workflow(
        &self,
        request: &RerunWorkflowRequest,
    ) -> Result<GitHubReply<()>, GitHubFailure>;
}

impl GitHubActionsTransport for GitHubClient {
    fn get_workflow_run(
        &self,
        request: &GetWorkflowRunRequest,
    ) -> Result<GitHubReply<GitHubWorkflowRun>, GitHubFailure> {
        GitHubClient::get_workflow_run(self, request)
    }

    fn rerun_workflow(
        &self,
        request: &RerunWorkflowRequest,
    ) -> Result<GitHubReply<()>, GitHubFailure> {
        GitHubClient::rerun_workflow(self, request)
    }
}

/// One explicit `Actions: write` credential capability fixed to one repository.
///
/// `credential_reference` is an operator-owned non-secret selector. The token
/// remains inside [`GitHubClient`] and has no display path.
pub struct GitHubActionsWriteCapability {
    credential_reference: String,
    target: RepoTarget,
    client: GitHubClient,
}

impl GitHubActionsWriteCapability {
    /// Construct the production fixed-origin capability.
    pub fn production(
        credential_reference: &str,
        target: RepoTarget,
        token: GitHubToken,
    ) -> Result<Self, GitHubCheckRerunError> {
        if !safe_reference(credential_reference) {
            return Err(GitHubCheckRerunError::InvalidPlan);
        }
        Ok(Self {
            credential_reference: credential_reference.to_owned(),
            target,
            client: GitHubClient::new(GitHubBase::production(), token),
        })
    }
}

/// Production adapter. It exposes only preflight, one-shot submit, and lookup.
pub struct GitHubCheckRerunAdapter {
    capability: GitHubActionsWriteCapability,
}

impl GitHubCheckRerunAdapter {
    #[must_use]
    pub const fn new(capability: GitHubActionsWriteCapability) -> Self {
        Self { capability }
    }

    /// Verify the exact observed run before custody begins.
    pub fn preflight(&self, plan: &GitHubCheckRerunPlan) -> Result<(), GitHubCheckRerunError> {
        preflight(
            &self.capability.client,
            &self.capability.credential_reference,
            &self.capability.target,
            plan,
        )
    }

    /// Perform the only POST. The durable state must already say custody began.
    pub fn submit(
        &self,
        plan: &GitHubCheckRerunPlan,
        submission: &mut GitHubCheckRerunSubmission,
    ) -> Result<GitHubCheckRerunCustody, GitHubCheckRerunError> {
        submit(
            &self.capability.client,
            &self.capability.credential_reference,
            &self.capability.target,
            plan,
            submission,
        )
    }

    /// Reconcile without ever issuing a POST.
    pub fn reconcile(
        &self,
        plan: &GitHubCheckRerunPlan,
        submission: &mut GitHubCheckRerunSubmission,
    ) -> Result<GitHubCheckRerunCustody, GitHubCheckRerunError> {
        reconcile(
            &self.capability.client,
            &self.capability.credential_reference,
            &self.capability.target,
            plan,
            submission,
        )
    }
}

fn preflight(
    transport: &impl GitHubActionsTransport,
    credential_reference: &str,
    target: &RepoTarget,
    plan: &GitHubCheckRerunPlan,
) -> Result<(), GitHubCheckRerunError> {
    verify_capability(credential_reference, target, plan)?;
    let run = inspect(transport, plan)?;
    if !exact_baseline(&run, plan) {
        return Err(GitHubCheckRerunError::ResourceChanged);
    }
    Ok(())
}

fn submit(
    transport: &impl GitHubActionsTransport,
    credential_reference: &str,
    target: &RepoTarget,
    plan: &GitHubCheckRerunPlan,
    submission: &mut GitHubCheckRerunSubmission,
) -> Result<GitHubCheckRerunCustody, GitHubCheckRerunError> {
    verify_submission(plan, submission)?;
    if submission.custody != GitHubCheckRerunCustody::CustodyStarted {
        return Err(GitHubCheckRerunError::SubmissionState);
    }
    if let Err(error) = preflight(transport, credential_reference, target, plan) {
        // No POST has occurred yet, so even an unavailable preflight is a
        // proved-not-started refusal rather than provider ambiguity.
        submission.custody = GitHubCheckRerunCustody::Refused;
        return Err(error);
    }
    let request = RerunWorkflowRequest::new(plan.target.clone(), plan.run_id);
    match transport.rerun_workflow(&request) {
        Ok(reply) => match reply.into_outcome() {
            GitHubOutcome::Accepted(()) => {
                submission.custody = GitHubCheckRerunCustody::Accepted;
                Ok(submission.custody)
            }
            GitHubOutcome::Rejected(rejection) if rejection.status() < 500 => {
                submission.custody = GitHubCheckRerunCustody::Refused;
                Err(GitHubCheckRerunError::ProviderRefused)
            }
            GitHubOutcome::Rejected(_) => {
                submission.custody = GitHubCheckRerunCustody::Ambiguous;
                Err(GitHubCheckRerunError::ProviderUnavailable)
            }
        },
        Err(_) => {
            submission.custody = GitHubCheckRerunCustody::Ambiguous;
            Err(GitHubCheckRerunError::ProviderUnavailable)
        }
    }
}

fn reconcile(
    transport: &impl GitHubActionsTransport,
    credential_reference: &str,
    target: &RepoTarget,
    plan: &GitHubCheckRerunPlan,
    submission: &mut GitHubCheckRerunSubmission,
) -> Result<GitHubCheckRerunCustody, GitHubCheckRerunError> {
    verify_capability(credential_reference, target, plan)?;
    verify_submission(plan, submission)?;
    if matches!(
        submission.custody,
        GitHubCheckRerunCustody::Refused | GitHubCheckRerunCustody::Completed
    ) {
        return Ok(submission.custody);
    }
    let run = inspect(transport, plan)?;
    if run.id != plan.run_id || run.head_sha != plan.head_sha {
        return Err(GitHubCheckRerunError::ResourceChanged);
    }
    let next_attempt = plan
        .observed_run_attempt
        .checked_add(1)
        .ok_or(GitHubCheckRerunError::InvalidPlan)?;
    if run.run_attempt == next_attempt
        && submission.custody != GitHubCheckRerunCustody::NotStarted
        && submission.custody != GitHubCheckRerunCustody::Refused
    {
        submission.custody = GitHubCheckRerunCustody::Completed;
        return Ok(submission.custody);
    }
    if run.run_attempt != plan.observed_run_attempt {
        return Err(GitHubCheckRerunError::ResourceChanged);
    }
    submission.custody = match submission.custody {
        GitHubCheckRerunCustody::NotStarted => GitHubCheckRerunCustody::NotStarted,
        GitHubCheckRerunCustody::Refused => GitHubCheckRerunCustody::Refused,
        GitHubCheckRerunCustody::Completed => GitHubCheckRerunCustody::Completed,
        GitHubCheckRerunCustody::CustodyStarted
        | GitHubCheckRerunCustody::Accepted
        | GitHubCheckRerunCustody::Ambiguous => GitHubCheckRerunCustody::Ambiguous,
    };
    Ok(submission.custody)
}

fn inspect(
    transport: &impl GitHubActionsTransport,
    plan: &GitHubCheckRerunPlan,
) -> Result<GitHubWorkflowRun, GitHubCheckRerunError> {
    let request = GetWorkflowRunRequest::new(plan.target.clone(), plan.run_id);
    match transport.get_workflow_run(&request) {
        Ok(reply) => match reply.into_outcome() {
            GitHubOutcome::Accepted(run) => Ok(run),
            GitHubOutcome::Rejected(_) => Err(GitHubCheckRerunError::ProviderRefused),
        },
        Err(_) => Err(GitHubCheckRerunError::ProviderUnavailable),
    }
}

fn exact_baseline(run: &GitHubWorkflowRun, plan: &GitHubCheckRerunPlan) -> bool {
    run.id == plan.run_id
        && run.head_sha == plan.head_sha
        && run.run_attempt == plan.observed_run_attempt
        && run.status == WorkflowRunStatus::Completed
}

fn verify_capability(
    credential_reference: &str,
    target: &RepoTarget,
    plan: &GitHubCheckRerunPlan,
) -> Result<(), GitHubCheckRerunError> {
    if credential_reference != plan.credential_reference || target != &plan.target {
        return Err(GitHubCheckRerunError::CapabilityMismatch);
    }
    Ok(())
}

fn verify_submission(
    plan: &GitHubCheckRerunPlan,
    submission: &GitHubCheckRerunSubmission,
) -> Result<(), GitHubCheckRerunError> {
    if submission.plan_digest != plan.digest || plan_digest(plan) != plan.digest {
        return Err(GitHubCheckRerunError::SubmissionState);
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

fn plan_digest(plan: &GitHubCheckRerunPlan) -> [u8; 32] {
    let mut document = Vec::new();
    push_field(&mut document, b"automonique.github-check-rerun/v1");
    push_field(&mut document, &plan.registry_generation_digest);
    push_field(&mut document, &plan.credential_generation_digest);
    for field in [
        plan.credential_reference.as_bytes(),
        plan.target.owner().as_str().as_bytes(),
        plan.target.repo().as_str().as_bytes(),
        plan.head_sha.as_bytes(),
        plan.tenant.as_bytes(),
        plan.actor.as_bytes(),
        plan.project.as_str().as_bytes(),
        plan.workspace.kind().as_str().as_bytes(),
        plan.workspace.id().as_bytes(),
        plan.authority.kind().as_str().as_bytes(),
        plan.authority.id().as_str().as_bytes(),
        plan.idempotency_key.as_str().as_bytes(),
        plan.check_id.as_str().as_bytes(),
    ] {
        push_field(&mut document, field);
    }
    push_field(&mut document, &plan.run_id.get().to_be_bytes());
    push_field(&mut document, &plan.observed_run_attempt.to_be_bytes());
    push_field(
        &mut document,
        &plan.expected_snapshot_revision.get().to_be_bytes(),
    );
    push_field(
        &mut document,
        &plan.expected_check_revision.get().to_be_bytes(),
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

    struct FakeTransport {
        reads: RefCell<VecDeque<Result<GitHubReply<GitHubWorkflowRun>, GitHubFailure>>>,
        writes: RefCell<VecDeque<Result<GitHubReply<()>, GitHubFailure>>>,
        read_count: Cell<usize>,
        write_count: Cell<usize>,
    }

    impl FakeTransport {
        fn new(
            reads: Vec<Result<GitHubReply<GitHubWorkflowRun>, GitHubFailure>>,
            writes: Vec<Result<GitHubReply<()>, GitHubFailure>>,
        ) -> Self {
            Self {
                reads: RefCell::new(reads.into()),
                writes: RefCell::new(writes.into()),
                read_count: Cell::new(0),
                write_count: Cell::new(0),
            }
        }
    }

    impl GitHubActionsTransport for FakeTransport {
        fn get_workflow_run(
            &self,
            _: &GetWorkflowRunRequest,
        ) -> Result<GitHubReply<GitHubWorkflowRun>, GitHubFailure> {
            self.read_count.set(self.read_count.get() + 1);
            self.reads.borrow_mut().pop_front().expect("scripted read")
        }

        fn rerun_workflow(
            &self,
            _: &RerunWorkflowRequest,
        ) -> Result<GitHubReply<()>, GitHubFailure> {
            self.write_count.set(self.write_count.get() + 1);
            self.writes
                .borrow_mut()
                .pop_front()
                .expect("scripted write")
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
                ServerMessage::sanitized("fixture refusal"),
                &rate,
                None,
            )),
        ))
    }

    fn run(attempt: u32) -> GitHubWorkflowRun {
        GitHubWorkflowRun {
            id: WorkflowRunId::new(91).unwrap(),
            head_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            run_attempt: attempt,
            status: WorkflowRunStatus::Completed,
        }
    }

    fn plan() -> GitHubCheckRerunPlan {
        GitHubCheckRerunPlan::new(
            [7; 32],
            [8; 32],
            "github-actions-mobile",
            RepoTarget::parse("example-org", "example-repo").unwrap(),
            WorkflowRunId::new(91).unwrap(),
            "0123456789abcdef0123456789abcdef01234567",
            3,
            &Actor::new("tenant-1", "actor-1").unwrap(),
            ProjectId::new("project-1").unwrap(),
            WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("workspace-1").unwrap()),
            ReviewAuthority::new(
                ReviewAuthorityKind::Ci,
                ReviewAuthorityId::new("ci-1").unwrap(),
            ),
            IdempotencyKey::new("rerun-1").unwrap(),
            ReviewCheckId::new("check-1").unwrap(),
            Revision::new(9).unwrap(),
            Revision::new(7).unwrap(),
        )
        .unwrap()
    }

    fn target() -> RepoTarget {
        RepoTarget::parse("example-org", "example-repo").unwrap()
    }

    #[test]
    fn plan_digest_binds_actor_scope_revisions_and_provider_coordinate() {
        let first = plan();
        let mut other = plan();
        other.actor = "actor-2".to_owned();
        other.digest = plan_digest(&other);
        assert_ne!(first.digest(), other.digest());
        assert_eq!(first.tenant(), "tenant-1");
        assert_eq!(first.actor(), "actor-1");
        assert_eq!(first.check_id().as_str(), "check-1");
        assert_eq!(first.expected_snapshot_revision().get(), 9);
        assert_eq!(first.expected_check_revision().get(), 7);
    }

    #[test]
    fn capability_mismatch_and_stale_baseline_never_post() {
        let transport = FakeTransport::new(vec![accepted(run(4))], vec![]);
        assert_eq!(
            preflight(&transport, "wrong-credential", &target(), &plan()),
            Err(GitHubCheckRerunError::CapabilityMismatch)
        );
        assert_eq!(transport.read_count.get(), 0);

        assert_eq!(
            preflight(&transport, "github-actions-mobile", &target(), &plan()),
            Err(GitHubCheckRerunError::ResourceChanged)
        );
        assert_eq!(transport.write_count.get(), 0);
    }

    #[test]
    fn exact_baseline_allows_exactly_one_post_and_retry_is_refused_locally() {
        let transport = FakeTransport::new(vec![accepted(run(3))], vec![accepted(())]);
        let plan = plan();
        let mut submission = GitHubCheckRerunSubmission::new(&plan);
        submission.begin_custody().unwrap();
        assert_eq!(
            submit(
                &transport,
                "github-actions-mobile",
                &target(),
                &plan,
                &mut submission,
            ),
            Ok(GitHubCheckRerunCustody::Accepted)
        );
        assert_eq!(transport.write_count.get(), 1);
        assert_eq!(
            submit(
                &transport,
                "github-actions-mobile",
                &target(),
                &plan,
                &mut submission,
            ),
            Err(GitHubCheckRerunError::SubmissionState)
        );
        assert_eq!(transport.write_count.get(), 1, "must never replay");
    }

    #[test]
    fn ambiguous_post_stays_ambiguous_until_exactly_one_later_attempt_exists() {
        let transport = FakeTransport::new(
            vec![accepted(run(3)), accepted(run(3)), accepted(run(4))],
            vec![Err(GitHubFailure::TimedOut)],
        );
        let plan = plan();
        let mut submission = GitHubCheckRerunSubmission::new(&plan);
        submission.begin_custody().unwrap();
        assert_eq!(
            submit(
                &transport,
                "github-actions-mobile",
                &target(),
                &plan,
                &mut submission,
            ),
            Err(GitHubCheckRerunError::ProviderUnavailable)
        );
        assert_eq!(submission.custody(), GitHubCheckRerunCustody::Ambiguous);
        assert_eq!(
            reconcile(
                &transport,
                "github-actions-mobile",
                &target(),
                &plan,
                &mut submission,
            ),
            Ok(GitHubCheckRerunCustody::Ambiguous)
        );
        assert_eq!(
            reconcile(
                &transport,
                "github-actions-mobile",
                &target(),
                &plan,
                &mut submission,
            ),
            Ok(GitHubCheckRerunCustody::Completed)
        );
        assert_eq!(transport.write_count.get(), 1);
    }

    #[test]
    fn restored_custody_started_reconciles_by_get_and_never_posts() {
        let transport = FakeTransport::new(vec![accepted(run(3))], vec![]);
        let plan = plan();
        let mut submission = GitHubCheckRerunSubmission::restore(
            &plan,
            plan.digest(),
            GitHubCheckRerunCustody::CustodyStarted,
        )
        .unwrap();
        assert_eq!(
            reconcile(
                &transport,
                "github-actions-mobile",
                &target(),
                &plan,
                &mut submission,
            ),
            Ok(GitHubCheckRerunCustody::Ambiguous)
        );
        assert_eq!(transport.read_count.get(), 1);
        assert_eq!(transport.write_count.get(), 0);
        assert_eq!(
            GitHubCheckRerunSubmission::restore(
                &plan,
                [0; 32],
                GitHubCheckRerunCustody::CustodyStarted,
            ),
            Err(GitHubCheckRerunError::SubmissionState)
        );
    }

    #[test]
    fn concurrent_multiple_attempts_or_changed_head_never_complete_our_receipt() {
        let mut changed = run(4);
        changed.head_sha = "ffffffffffffffffffffffffffffffffffffffff".to_owned();
        let transport = FakeTransport::new(vec![accepted(run(5)), accepted(changed)], vec![]);
        let plan = plan();
        let mut submission = GitHubCheckRerunSubmission::new(&plan);
        submission.begin_custody().unwrap();
        submission.custody = GitHubCheckRerunCustody::Ambiguous;
        for _ in 0..2 {
            assert_eq!(
                reconcile(
                    &transport,
                    "github-actions-mobile",
                    &target(),
                    &plan,
                    &mut submission,
                ),
                Err(GitHubCheckRerunError::ResourceChanged)
            );
            assert_ne!(submission.custody(), GitHubCheckRerunCustody::Completed);
        }
    }

    #[test]
    fn provider_refusals_distinguish_known_refusal_from_server_ambiguity() {
        let transport = FakeTransport::new(
            vec![accepted(run(3)), accepted(run(3))],
            vec![rejected(403), rejected(500)],
        );
        let plan = plan();
        let mut denied = GitHubCheckRerunSubmission::new(&plan);
        denied.begin_custody().unwrap();
        assert_eq!(
            submit(
                &transport,
                "github-actions-mobile",
                &target(),
                &plan,
                &mut denied,
            ),
            Err(GitHubCheckRerunError::ProviderRefused)
        );
        assert_eq!(denied.custody(), GitHubCheckRerunCustody::Refused);

        let mut failed = GitHubCheckRerunSubmission::new(&plan);
        failed.begin_custody().unwrap();
        assert_eq!(
            submit(
                &transport,
                "github-actions-mobile",
                &target(),
                &plan,
                &mut failed,
            ),
            Err(GitHubCheckRerunError::ProviderUnavailable)
        );
        assert_eq!(failed.custody(), GitHubCheckRerunCustody::Ambiguous);
    }

    #[test]
    fn unavailable_preflight_is_known_not_started_and_final_states_do_no_io() {
        let transport = FakeTransport::new(vec![Err(GitHubFailure::TimedOut)], vec![]);
        let plan = plan();
        let mut submission = GitHubCheckRerunSubmission::new(&plan);
        submission.begin_custody().unwrap();
        assert_eq!(
            submit(
                &transport,
                "github-actions-mobile",
                &target(),
                &plan,
                &mut submission,
            ),
            Err(GitHubCheckRerunError::ProviderUnavailable)
        );
        assert_eq!(submission.custody(), GitHubCheckRerunCustody::Refused);
        assert_eq!(transport.write_count.get(), 0);
        let reads = transport.read_count.get();
        assert_eq!(
            reconcile(
                &transport,
                "github-actions-mobile",
                &target(),
                &plan,
                &mut submission,
            ),
            Ok(GitHubCheckRerunCustody::Refused)
        );
        assert_eq!(transport.read_count.get(), reads);
    }
}
