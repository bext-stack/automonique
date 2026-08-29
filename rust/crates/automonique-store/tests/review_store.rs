// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

use automonique_protocol::platform::IdempotencyKey;
use automonique_protocol::platform_v2_review::*;
use automonique_protocol::platform_v2_review_api::{
    decode_review_action_request, decode_review_snapshot,
};
use automonique_protocol::primitives::Revision;
use automonique_store::review_store::{
    ApprovalPolicy, REVIEW_STORE_SCHEMA_VERSION, ReviewActionAdmission, ReviewApprovalDecision,
    ReviewApprovalDocument, ReviewExternalEffectCustody, ReviewExternalEffectPlan,
    ReviewPullRequestFamily, ReviewStore, ReviewStoreError, ReviewWriteAdmission,
};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const SNAPSHOT: &[u8] =
    include_bytes!("../../automonique-protocol/fixtures/platform-v2-review-v2.json");
const LEGACY_SNAPSHOT: &[u8] =
    include_bytes!("../../automonique-protocol/fixtures/platform-v2-review-v1.json");
const ACTION: &[u8] =
    include_bytes!("../../automonique-protocol/fixtures/platform-v2-review-action-v1.json");

struct PrivateStore {
    _directory: TempDir,
    path: PathBuf,
}
impl PrivateStore {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let path = directory.path().join("review.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }
    fn path(&self) -> &Path {
        &self.path
    }
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("revision")
}
fn snapshot() -> automonique_protocol::platform_v2_review::ReviewSnapshot {
    decode_review_snapshot(SNAPSHOT).expect("shared snapshot fixture")
}
fn legacy_snapshot() -> ReviewSnapshot {
    decode_review_snapshot(LEGACY_SNAPSHOT).expect("historical review/v1 fixture")
}
fn downgrade_review_store_to_v1(path: &Path) {
    let connection = Connection::open(path).expect("open v2 store for downgrade");
    connection
        .execute_batch(
            "DROP TABLE review_github_pull_request_effect_plans; DROP TABLE review_github_check_effect_plans; DROP TABLE review_external_effect_targets; DROP TABLE review_external_effect_plans; DROP TABLE review_external_effect_migration_tombstones; ALTER TABLE review_snapshots DROP COLUMN protocol_schema; PRAGMA user_version=1;",
        )
        .expect("construct historical v1 store");
}
fn action_snapshot(conflicted: bool) -> ReviewSnapshot {
    let base = snapshot();
    let original_file = &base.files()[0];
    let file = ReviewFile::new(
        original_file.id().clone(),
        original_file.path().clone(),
        original_file.change(),
        original_file.worktree(),
        original_file.preview().clone(),
        if conflicted {
            ConflictState::Unresolved
        } else {
            ConflictState::None
        },
        original_file.hunks().to_vec(),
    )
    .expect("file");
    let original_comment = &base.comments()[0];
    let comment = ReviewComment::new(
        original_comment.id().clone(),
        original_comment.revision(),
        original_comment.actor().clone(),
        original_comment.body().clone(),
        original_comment.anchor().clone(),
        CommentAgentState::NotSent,
        original_comment.unread(),
    );
    let git = ReviewAuthority::new(
        ReviewAuthorityKind::Git,
        ReviewAuthorityId::new("authority-1").expect("git authority"),
    );
    let proposals = if conflicted {
        vec![
            ReviewProposal::new(
                ReviewProposalId::new("proposal-resolve").expect("proposal"),
                ReviewProposalKind::ResolveConflict,
                git,
                vec![file.id().clone()],
                None,
            )
            .expect("resolve proposal"),
        ]
    } else {
        vec![
            ReviewProposal::new(
                ReviewProposalId::new("proposal-commit").expect("proposal"),
                ReviewProposalKind::Commit,
                git.clone(),
                vec![file.id().clone()],
                Some(ReviewField::new("typed commit").expect("subject")),
            )
            .expect("commit proposal"),
            ReviewProposal::new(
                ReviewProposalId::new("proposal-stage").expect("proposal"),
                ReviewProposalKind::Stage,
                git.clone(),
                vec![file.id().clone()],
                None,
            )
            .expect("stage proposal"),
            ReviewProposal::new(
                ReviewProposalId::new("proposal-unstage").expect("proposal"),
                ReviewProposalKind::Unstage,
                git,
                vec![file.id().clone()],
                None,
            )
            .expect("unstage proposal"),
        ]
    };
    ReviewSnapshot::new(
        base.workspace().clone(),
        base.revision(),
        vec![file],
        vec![comment],
        proposals,
        base.checks().to_vec(),
        base.review().clone(),
        base.pull_request().clone(),
        base.delivery().clone(),
        vec![],
    )
    .expect("action snapshot")
}
fn request() -> ReviewActionRequest {
    decode_review_action_request(ACTION).expect("shared action fixture")
}
fn request_variant(
    base: &ReviewActionRequest,
    key: &str,
    actor: &str,
    expected: Revision,
    check_revision: Revision,
) -> ReviewActionRequest {
    ReviewActionRequest::new(
        base.workspace().clone(),
        expected,
        ReviewActorId::new(actor).expect("actor"),
        base.authentication(),
        base.authority().clone(),
        IdempotencyKey::new(key).expect("key"),
        ReviewAction::RerunCheck {
            check_id: ReviewCheckId::new("check-1").expect("check"),
            expected_check_revision: check_revision,
        },
    )
    .expect("request")
}
fn external_plan(request: &ReviewActionRequest, payload: &[u8]) -> ReviewExternalEffectPlan {
    let request_digest =
        ReviewStore::action_request_digest(request, ApprovalPolicy::NotRequired).expect("digest");
    ReviewExternalEffectPlan::retained_session(
        request_digest,
        [7; 32],
        "jcode",
        "work-session-1",
        "provider-session-1",
        revision(3),
        revision(5),
        &format!(
            "v2-review-{}",
            request_digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ),
        payload.to_vec(),
    )
    .expect("external plan")
}

fn github_external_plan(request: &ReviewActionRequest) -> ReviewExternalEffectPlan {
    github_external_plan_for(request, "example-org", "example-repo", 91, 3)
}

fn github_external_plan_for(
    request: &ReviewActionRequest,
    owner: &str,
    repository: &str,
    run_id: u64,
    attempt: u32,
) -> ReviewExternalEffectPlan {
    let request_digest =
        ReviewStore::action_request_digest(request, ApprovalPolicy::NotRequired).expect("digest");
    ReviewExternalEffectPlan::github_check_rerun(
        request_digest,
        [7; 32],
        [8; 32],
        "github-actions-mobile",
        owner,
        repository,
        run_id,
        "0123456789abcdef0123456789abcdef01234567",
        attempt,
        ReviewCheckId::new("check-1").unwrap(),
        revision(7),
        revision(11),
        [9; 32],
    )
    .expect("github effect plan")
}

#[test]
fn github_run_attempt_reservation_is_atomic_case_insensitive_cross_actor_and_durable() {
    let private = PrivateStore::new();
    let (left_request, right_request) = {
        let mut store = ReviewStore::open(private.path()).unwrap();
        let base = seed(&mut store);
        let left = request_variant(
            &base,
            "reserve-left",
            "actor-reserve-left",
            revision(9),
            revision(7),
        );
        let right = request_variant(
            &base,
            "reserve-right",
            "actor-reserve-right",
            revision(9),
            revision(7),
        );
        for request in [&left, &right] {
            store
                .grant_authority(
                    request.workspace(),
                    request.actor(),
                    request.authentication(),
                    request.authority(),
                    11,
                )
                .unwrap();
        }
        (left, right)
    };
    let barrier = Arc::new(Barrier::new(2));
    let path = private.path().to_path_buf();
    let left_barrier = Arc::clone(&barrier);
    let left = std::thread::spawn(move || {
        let mut store = ReviewStore::open(&path).unwrap();
        let plan = github_external_plan_for(&left_request, "Example-Org", "Example-Repo", 91, 3);
        left_barrier.wait();
        store.prepare_external_action(&left_request, ApprovalPolicy::NotRequired, &plan, 12)
    });
    let path = private.path().to_path_buf();
    let right_barrier = Arc::clone(&barrier);
    let right = std::thread::spawn(move || {
        let mut store = ReviewStore::open(&path).unwrap();
        let plan = github_external_plan_for(&right_request, "example-org", "example-repo", 91, 3);
        right_barrier.wait();
        store.prepare_external_action(&right_request, ApprovalPolicy::NotRequired, &plan, 12)
    });
    let results = [left.join().unwrap(), right.join().unwrap()];
    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count(),
        1,
        "exactly one actor must reserve the provider attempt"
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                Err(ReviewStoreError::Conflict("github_check_run_attempt"))
            ))
            .count(),
        1
    );

    let base = request();
    let after_restart = request_variant(
        &base,
        "reserve-after-restart",
        "actor-reserve-after-restart",
        revision(9),
        revision(7),
    );
    let mut store = ReviewStore::open(private.path()).unwrap();
    store
        .grant_authority(
            after_restart.workspace(),
            after_restart.actor(),
            after_restart.authentication(),
            after_restart.authority(),
            13,
        )
        .unwrap();
    let plan = github_external_plan_for(&after_restart, "EXAMPLE-ORG", "EXAMPLE-REPO", 91, 3);
    assert!(matches!(
        store.prepare_external_action(&after_restart, ApprovalPolicy::NotRequired, &plan, 14),
        Err(ReviewStoreError::Conflict("github_check_run_attempt"))
    ));
}

#[test]
fn github_plan_rejects_every_successor_overflow_before_reservation() {
    let base = request();
    let request_digest =
        ReviewStore::action_request_digest(&base, ApprovalPolicy::NotRequired).unwrap();
    assert!(
        ReviewExternalEffectPlan::github_check_rerun(
            request_digest,
            [7; 32],
            [8; 32],
            "github-actions-mobile",
            "example-org",
            "example-repo",
            91,
            "0123456789abcdef0123456789abcdef01234567",
            u32::MAX,
            ReviewCheckId::new("check-1").unwrap(),
            revision(7),
            revision(11),
            [9; 32],
        )
        .is_err()
    );
    assert!(
        ReviewExternalEffectPlan::github_check_rerun(
            request_digest,
            [7; 32],
            [8; 32],
            "github-actions-mobile",
            "example-org",
            "example-repo",
            91,
            "0123456789abcdef0123456789abcdef01234567",
            3,
            ReviewCheckId::new("check-1").unwrap(),
            revision(i64::MAX as u64),
            revision(11),
            [9; 32],
        )
        .is_err()
    );
    assert!(
        ReviewExternalEffectPlan::github_check_rerun(
            request_digest,
            [7; 32],
            [8; 32],
            "github-actions-mobile",
            "example-org",
            "example-repo",
            91,
            "0123456789abcdef0123456789abcdef01234567",
            3,
            ReviewCheckId::new("check-1").unwrap(),
            revision(7),
            revision(11),
            [0; 32],
        )
        .is_err()
    );
}

#[test]
fn github_plan_digest_binds_the_authoritative_workspace_revision() {
    let request = request();
    let first = github_external_plan(&request);
    let request_digest =
        ReviewStore::action_request_digest(&request, ApprovalPolicy::NotRequired).unwrap();
    let changed = ReviewExternalEffectPlan::github_check_rerun(
        request_digest,
        [7; 32],
        [8; 32],
        "github-actions-mobile",
        "example-org",
        "example-repo",
        91,
        "0123456789abcdef0123456789abcdef01234567",
        3,
        ReviewCheckId::new("check-1").unwrap(),
        revision(7),
        revision(12),
        [9; 32],
    )
    .unwrap();
    assert_ne!(first.digest(), changed.digest());
    assert_eq!(
        changed.github_expected_workspace_revision(),
        Some(revision(12))
    );
}

#[test]
fn github_check_plan_and_custody_survive_restart_without_reopening_write_admission() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).unwrap();
    let request = seed(&mut store);
    let plan = github_external_plan(&request);
    let action = match store
        .prepare_external_action(&request, ApprovalPolicy::NotRequired, &plan, 12)
        .unwrap()
    {
        ReviewActionAdmission::New(action) => action,
        ReviewActionAdmission::Replay(_) => panic!("new action expected"),
    };
    assert_eq!(
        store
            .external_action(
                request.workspace(),
                request.actor(),
                request.authentication(),
                request.authority(),
                request.idempotency_key(),
                13,
            )
            .unwrap()
            .unwrap()
            .1
            .github_custody(),
        Some(ReviewExternalEffectCustody::NotStarted)
    );
    assert!(matches!(
        store
            .start_write(&action.preview_id, action.request_digest, 13)
            .unwrap(),
        ReviewWriteAdmission::New(_)
    ));
    drop(store);

    let mut store = ReviewStore::open(private.path()).unwrap();
    let (restarted, restarted_plan) = store
        .external_action(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            14,
        )
        .unwrap()
        .unwrap();
    assert_eq!(restarted_plan.digest(), plan.digest());
    assert_eq!(
        restarted_plan.github_receipt_correlation_digest(),
        Some([9; 32])
    );
    assert_eq!(
        restarted_plan.github_expected_workspace_revision(),
        Some(revision(11))
    );
    assert_eq!(
        restarted_plan.github_custody(),
        Some(ReviewExternalEffectCustody::CustodyStarted)
    );
    assert!(matches!(
        store
            .start_write(&restarted.preview_id, restarted.request_digest, 14)
            .unwrap(),
        ReviewWriteAdmission::Replay(_)
    ));
    let unknown = store
        .settle_github_check_rerun(
            &restarted.preview_id,
            restarted.request_digest,
            ReviewExternalEffectCustody::Ambiguous,
            15,
        )
        .unwrap();
    assert_eq!(unknown.outcome(), ReviewReceiptOutcome::Unknown);
    drop(store);

    let mut store = ReviewStore::open(private.path()).unwrap();
    let (restarted, restarted_plan) = store
        .external_action(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            16,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        restarted_plan.github_custody(),
        Some(ReviewExternalEffectCustody::Ambiguous)
    );
    let completed = store
        .settle_github_check_rerun(
            &restarted.preview_id,
            restarted.request_digest,
            ReviewExternalEffectCustody::Completed,
            16,
        )
        .unwrap();
    assert_eq!(completed.outcome(), ReviewReceiptOutcome::Completed);
    assert_eq!(completed.revision(), Some(revision(10)));
    let snapshot = store.snapshot(request.workspace()).unwrap().unwrap();
    let check = snapshot
        .checks()
        .iter()
        .find(|check| check.id().as_str() == "check-1")
        .unwrap();
    assert_eq!(check.state(), CheckState::Running);
    assert_eq!(check.freshness().observed_revision(), revision(8));
}

#[test]
fn github_check_external_plan_must_match_the_exact_action_target_revision() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).unwrap();
    let request = seed(&mut store);
    let request_digest =
        ReviewStore::action_request_digest(&request, ApprovalPolicy::NotRequired).unwrap();
    let wrong = ReviewExternalEffectPlan::github_check_rerun(
        request_digest,
        [7; 32],
        [8; 32],
        "github-actions-mobile",
        "example-org",
        "example-repo",
        91,
        "0123456789abcdef0123456789abcdef01234567",
        3,
        ReviewCheckId::new("check-2").unwrap(),
        revision(7),
        revision(11),
        [9; 32],
    )
    .unwrap();
    assert!(matches!(
        store.prepare_external_action(&request, ApprovalPolicy::NotRequired, &wrong, 12),
        Err(ReviewStoreError::Conflict("external_effect_request"))
    ));
}
fn seed(store: &mut ReviewStore) -> ReviewActionRequest {
    let snapshot = snapshot();
    let request = request();
    store.put_snapshot(&snapshot, 10).expect("snapshot");
    store
        .grant_authority(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            11,
        )
        .expect("authority grant");
    request
}

const PR_HEAD: &str = "0123456789abcdef0123456789abcdef01234567";

/// A snapshot whose pull-request projection is in one exact state, with an id
/// spelled the way a GitHub-backed workspace spells one: the decimal number.
fn pull_request_snapshot(
    state: PullRequestState,
    readiness: MergeReadiness,
    id: Option<&str>,
    head: Option<&str>,
) -> ReviewSnapshot {
    let base = snapshot();
    let projection = PullRequestProjection::new(
        id.map(|value| PullRequestId::new(value).expect("pull request id")),
        state,
        readiness,
        head.map(|value| ReviewField::new(value).expect("head")),
        base.pull_request().authority().clone(),
        ReviewFreshness::new(ReviewFreshnessState::Fresh, revision(8), 1_800_000_000_000)
            .expect("freshness"),
    )
    .expect("pull request projection");
    ReviewSnapshot::new(
        base.workspace().clone(),
        base.revision(),
        base.files().to_vec(),
        base.comments().to_vec(),
        base.proposals().to_vec(),
        base.checks().to_vec(),
        base.review().clone(),
        projection,
        base.delivery().clone(),
        vec![],
    )
    .expect("pull request snapshot")
}

fn pull_request_request(key: &str, actor: &str, action: ReviewAction) -> ReviewActionRequest {
    let base = request();
    ReviewActionRequest::new(
        base.workspace().clone(),
        revision(9),
        ReviewActorId::new(actor).expect("actor"),
        base.authentication(),
        ReviewAuthority::new(
            ReviewAuthorityKind::PullRequest,
            ReviewAuthorityId::new("authority-1").expect("authority"),
        ),
        IdempotencyKey::new(key).expect("key"),
        action,
    )
    .expect("request")
}

fn seed_pull_request(store: &mut ReviewStore, snapshot: &ReviewSnapshot) {
    store.put_snapshot(snapshot, 10).expect("snapshot");
    store
        .grant_authority(
            snapshot.workspace(),
            &ReviewActorId::new("actor-1").expect("actor"),
            ReviewAuthentication::UserSession,
            &ReviewAuthority::new(
                ReviewAuthorityKind::PullRequest,
                ReviewAuthorityId::new("authority-1").expect("authority"),
            ),
            11,
        )
        .expect("authority grant");
}

#[allow(clippy::too_many_arguments)]
fn pull_request_plan(
    request: &ReviewActionRequest,
    family: ReviewPullRequestFamily,
    number: Option<u32>,
    head: &str,
    title: Option<&str>,
    owner: &str,
    repository: &str,
) -> ReviewExternalEffectPlan {
    let request_digest =
        ReviewStore::action_request_digest(request, ApprovalPolicy::NotRequired).expect("digest");
    ReviewExternalEffectPlan::github_pull_request(
        request_digest,
        [7; 32],
        [8; 32],
        "github-pull-request-mobile",
        (owner, repository),
        family,
        ("main", "agent-work"),
        number,
        head,
        title,
        revision(8),
        revision(11),
        [9; 32],
    )
    .expect("pull request effect plan")
}

fn admit(store: &mut ReviewStore, request: &ReviewActionRequest, plan: &ReviewExternalEffectPlan) {
    store
        .prepare_external_action(request, ApprovalPolicy::NotRequired, plan, 12)
        .expect("prepare");
    let preview = store
        .external_action(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            13,
        )
        .expect("read back")
        .expect("action")
        .0
        .preview_id;
    store
        .start_write(&preview, plan.request_digest(), 14)
        .expect("start write");
}

fn preview_of(store: &ReviewStore, request: &ReviewActionRequest) -> String {
    store
        .external_action(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            15,
        )
        .expect("read back")
        .expect("action")
        .0
        .preview_id
}

/// Completing an open adopts the pull request the provider actually issued.
///
/// The number is not in the plan, because it did not exist when the plan was
/// sealed. It reaches the projection only from the create's own response, so
/// this also pins that a completion without one is refused rather than
/// inventing an identity.
#[test]
fn a_completed_open_adopts_the_provider_issued_number_and_never_claims_readiness() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).unwrap();
    let snapshot = pull_request_snapshot(
        PullRequestState::Absent,
        MergeReadiness::Unknown,
        None,
        None,
    );
    seed_pull_request(&mut store, &snapshot);
    let request = pull_request_request(
        "open-1",
        "actor-1",
        ReviewAction::OpenPullRequest {
            expected_pull_request_revision: revision(8),
            title: ReviewField::new("Proposer le correctif").unwrap(),
        },
    );
    let plan = pull_request_plan(
        &request,
        ReviewPullRequestFamily::Open,
        None,
        PR_HEAD,
        Some("Proposer le correctif"),
        "example-org",
        "example-repo",
    );
    admit(&mut store, &request, &plan);
    let preview = preview_of(&store, &request);

    assert!(
        matches!(
            store.settle_github_pull_request(
                &preview,
                plan.request_digest(),
                ReviewExternalEffectCustody::Completed,
                None,
                16,
            ),
            Err(ReviewStoreError::InvalidField("github_pull_request_number"))
        ),
        "an open cannot complete without the number the provider issued",
    );

    let receipt = store
        .settle_github_pull_request(
            &preview,
            plan.request_digest(),
            ReviewExternalEffectCustody::Completed,
            Some(91),
            17,
        )
        .expect("settle");
    assert_eq!(receipt.outcome(), ReviewReceiptOutcome::Completed);
    let next = store
        .snapshot(request.workspace())
        .expect("snapshot")
        .expect("present");
    assert_eq!(next.revision(), revision(10));
    assert_eq!(next.pull_request().state(), PullRequestState::Open);
    assert_eq!(
        next.pull_request().id().map(PullRequestId::as_str),
        Some("91")
    );
    assert_eq!(
        next.pull_request().head_revision().map(ReviewField::as_str),
        Some(PR_HEAD)
    );
    assert_eq!(
        next.pull_request().readiness(),
        MergeReadiness::Unknown,
        "opening a pull request says nothing about whether GitHub will merge it",
    );
    assert_eq!(
        next.pull_request().freshness().observed_revision(),
        revision(9)
    );
}

/// Completing a merge retires the readiness it was advertised on.
#[test]
fn a_completed_merge_lands_the_projection_and_stops_calling_it_ready() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).unwrap();
    let snapshot = pull_request_snapshot(
        PullRequestState::Open,
        MergeReadiness::Ready,
        Some("91"),
        Some(PR_HEAD),
    );
    seed_pull_request(&mut store, &snapshot);
    let request = pull_request_request(
        "merge-1",
        "actor-1",
        ReviewAction::MergePullRequest {
            pull_request_id: PullRequestId::new("91").unwrap(),
            expected_pull_request_revision: revision(8),
            expected_head_revision: ReviewField::new(PR_HEAD).unwrap(),
        },
    );
    let plan = pull_request_plan(
        &request,
        ReviewPullRequestFamily::Merge,
        Some(91),
        PR_HEAD,
        None,
        "example-org",
        "example-repo",
    );
    admit(&mut store, &request, &plan);
    let preview = preview_of(&store, &request);
    let receipt = store
        .settle_github_pull_request(
            &preview,
            plan.request_digest(),
            ReviewExternalEffectCustody::Completed,
            None,
            16,
        )
        .expect("settle");
    assert_eq!(receipt.outcome(), ReviewReceiptOutcome::Completed);
    let next = store
        .snapshot(request.workspace())
        .expect("snapshot")
        .expect("present");
    assert_eq!(next.pull_request().state(), PullRequestState::Merged);
    assert_eq!(
        next.pull_request().readiness(),
        MergeReadiness::Unknown,
        "a merged pull request is not ready to merge",
    );
    assert_eq!(
        next.pull_request().id().map(PullRequestId::as_str),
        Some("91")
    );
}

/// A retitle changes nothing the projection carries but its revision, which is
/// the honest answer: the review projection holds no title.
#[test]
fn a_completed_update_moves_only_the_revision() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).unwrap();
    let snapshot = pull_request_snapshot(
        PullRequestState::Draft,
        MergeReadiness::Blocked,
        Some("91"),
        Some(PR_HEAD),
    );
    seed_pull_request(&mut store, &snapshot);
    let request = pull_request_request(
        "update-1",
        "actor-1",
        ReviewAction::UpdatePullRequest {
            pull_request_id: PullRequestId::new("91").unwrap(),
            expected_pull_request_revision: revision(8),
            title: ReviewField::new("Titre revu").unwrap(),
        },
    );
    let plan = pull_request_plan(
        &request,
        ReviewPullRequestFamily::Update,
        Some(91),
        PR_HEAD,
        Some("Titre revu"),
        "example-org",
        "example-repo",
    );
    admit(&mut store, &request, &plan);
    let preview = preview_of(&store, &request);
    store
        .settle_github_pull_request(
            &preview,
            plan.request_digest(),
            ReviewExternalEffectCustody::Completed,
            None,
            16,
        )
        .expect("settle");
    let next = store
        .snapshot(request.workspace())
        .expect("snapshot")
        .expect("present");
    assert_eq!(next.pull_request().state(), PullRequestState::Draft);
    assert_eq!(next.pull_request().readiness(), MergeReadiness::Blocked);
    assert_eq!(
        next.pull_request().freshness().observed_revision(),
        revision(9)
    );
    assert_eq!(next.revision(), revision(10));
}

/// The cross-actor fence, the analogue of the check table's run/attempt fence.
///
/// Two actors merging the same pull request at the same head are one effect,
/// however differently they spelled the request. The second is refused at
/// admission rather than at the provider.
#[test]
fn one_merge_per_pull_request_per_exact_head_is_reserved_across_actors() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).unwrap();
    let snapshot = pull_request_snapshot(
        PullRequestState::Open,
        MergeReadiness::Ready,
        Some("91"),
        Some(PR_HEAD),
    );
    seed_pull_request(&mut store, &snapshot);
    for actor in ["actor-1", "actor-2"] {
        store
            .grant_authority(
                snapshot.workspace(),
                &ReviewActorId::new(actor).unwrap(),
                ReviewAuthentication::UserSession,
                &ReviewAuthority::new(
                    ReviewAuthorityKind::PullRequest,
                    ReviewAuthorityId::new("authority-1").unwrap(),
                ),
                11,
            )
            .expect("authority grant");
    }
    let merge = |key: &str, actor: &str| {
        pull_request_request(
            key,
            actor,
            ReviewAction::MergePullRequest {
                pull_request_id: PullRequestId::new("91").unwrap(),
                expected_pull_request_revision: revision(8),
                expected_head_revision: ReviewField::new(PR_HEAD).unwrap(),
            },
        )
    };
    let first = merge("merge-left", "actor-1");
    let plan = pull_request_plan(
        &first,
        ReviewPullRequestFamily::Merge,
        Some(91),
        PR_HEAD,
        None,
        "example-org",
        "example-repo",
    );
    store
        .prepare_external_action(&first, ApprovalPolicy::NotRequired, &plan, 12)
        .expect("first merge admitted");

    let second = merge("merge-right", "actor-2");
    let rival = pull_request_plan(
        &second,
        ReviewPullRequestFamily::Merge,
        Some(91),
        PR_HEAD,
        None,
        // Case differs, and the fence is case-insensitive on the repository
        // exactly as the check-rerun one is.
        "Example-Org",
        "Example-Repo",
    );
    assert!(
        matches!(
            store.prepare_external_action(&second, ApprovalPolicy::NotRequired, &rival, 13),
            Err(ReviewStoreError::Conflict("github_pull_request_effect"))
        ),
        "two actors merging one pull request at one head are one effect",
    );

    // The fence is per effect, not per pull request. Retitling the same pull
    // request is a different write and must still be admissible alongside the
    // reserved merge.
    let update = pull_request_request(
        "update-alongside",
        "actor-2",
        ReviewAction::UpdatePullRequest {
            pull_request_id: PullRequestId::new("91").unwrap(),
            expected_pull_request_revision: revision(8),
            title: ReviewField::new("Titre revu").unwrap(),
        },
    );
    let update_plan = pull_request_plan(
        &update,
        ReviewPullRequestFamily::Update,
        Some(91),
        PR_HEAD,
        Some("Titre revu"),
        "example-org",
        "example-repo",
    );
    store
        .prepare_external_action(&update, ApprovalPolicy::NotRequired, &update_plan, 14)
        .expect("a retitle is not the reserved merge");
}

/// A merge at a head the branch has since moved to is a different landing, and
/// the reservation must not swallow it.
#[test]
fn a_merge_at_a_different_head_is_a_different_reserved_effect() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).unwrap();
    let moved = "89abcdef0123456789abcdef0123456789abcdef";
    let first = pull_request_snapshot(
        PullRequestState::Open,
        MergeReadiness::Ready,
        Some("91"),
        Some(PR_HEAD),
    );
    seed_pull_request(&mut store, &first);
    let merge_at_head = pull_request_request(
        "merge-head",
        "actor-1",
        ReviewAction::MergePullRequest {
            pull_request_id: PullRequestId::new("91").unwrap(),
            expected_pull_request_revision: revision(8),
            expected_head_revision: ReviewField::new(PR_HEAD).unwrap(),
        },
    );
    let plan = pull_request_plan(
        &merge_at_head,
        ReviewPullRequestFamily::Merge,
        Some(91),
        PR_HEAD,
        None,
        "example-org",
        "example-repo",
    );
    store
        .prepare_external_action(&merge_at_head, ApprovalPolicy::NotRequired, &plan, 12)
        .expect("first merge admitted");

    // The branch advanced, so the workspace observed a new snapshot.
    let advanced = ReviewSnapshot::new(
        first.workspace().clone(),
        revision(10),
        first.files().to_vec(),
        first.comments().to_vec(),
        first.proposals().to_vec(),
        first.checks().to_vec(),
        first.review().clone(),
        PullRequestProjection::new(
            Some(PullRequestId::new("91").unwrap()),
            PullRequestState::Open,
            MergeReadiness::Ready,
            Some(ReviewField::new(moved).unwrap()),
            first.pull_request().authority().clone(),
            ReviewFreshness::new(ReviewFreshnessState::Fresh, revision(9), 1_800_000_000_001)
                .unwrap(),
        )
        .unwrap(),
        first.delivery().clone(),
        vec![],
    )
    .unwrap();
    store
        .put_snapshot(&advanced, 13)
        .expect("advanced snapshot");

    let base = request();
    let merge_at_moved = ReviewActionRequest::new(
        base.workspace().clone(),
        revision(10),
        ReviewActorId::new("actor-1").unwrap(),
        base.authentication(),
        ReviewAuthority::new(
            ReviewAuthorityKind::PullRequest,
            ReviewAuthorityId::new("authority-1").unwrap(),
        ),
        IdempotencyKey::new("merge-moved").unwrap(),
        ReviewAction::MergePullRequest {
            pull_request_id: PullRequestId::new("91").unwrap(),
            expected_pull_request_revision: revision(9),
            expected_head_revision: ReviewField::new(moved).unwrap(),
        },
    )
    .unwrap();
    let request_digest =
        ReviewStore::action_request_digest(&merge_at_moved, ApprovalPolicy::NotRequired).unwrap();
    let moved_plan = ReviewExternalEffectPlan::github_pull_request(
        request_digest,
        [7; 32],
        [8; 32],
        "github-pull-request-mobile",
        ("example-org", "example-repo"),
        ReviewPullRequestFamily::Merge,
        ("main", "agent-work"),
        Some(91),
        moved,
        None,
        revision(9),
        revision(11),
        [9; 32],
    )
    .unwrap();
    store
        .prepare_external_action(
            &merge_at_moved,
            ApprovalPolicy::NotRequired,
            &moved_plan,
            14,
        )
        .expect("a merge at a different head is a different effect");
}

/// A plan and the action it was prepared for must be the same write.
#[test]
fn a_pull_request_plan_that_disagrees_with_its_action_is_refused_at_admission() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).unwrap();
    let snapshot = pull_request_snapshot(
        PullRequestState::Open,
        MergeReadiness::Ready,
        Some("91"),
        Some(PR_HEAD),
    );
    seed_pull_request(&mut store, &snapshot);
    let request = pull_request_request(
        "update-mismatch",
        "actor-1",
        ReviewAction::UpdatePullRequest {
            pull_request_id: PullRequestId::new("91").unwrap(),
            expected_pull_request_revision: revision(8),
            title: ReviewField::new("Titre revu").unwrap(),
        },
    );
    // The plan names a different pull request than the action does.
    let plan = pull_request_plan(
        &request,
        ReviewPullRequestFamily::Update,
        Some(92),
        PR_HEAD,
        Some("Titre revu"),
        "example-org",
        "example-repo",
    );
    assert!(matches!(
        store.prepare_external_action(&request, ApprovalPolicy::NotRequired, &plan, 12),
        Err(ReviewStoreError::Conflict("external_effect_request"))
    ),);
    // So does a plan that names a different title.
    let retitled = pull_request_plan(
        &request,
        ReviewPullRequestFamily::Update,
        Some(91),
        PR_HEAD,
        Some("Autre titre"),
        "example-org",
        "example-repo",
    );
    assert!(matches!(
        store.prepare_external_action(&request, ApprovalPolicy::NotRequired, &retitled, 13),
        Err(ReviewStoreError::Conflict("external_effect_request"))
    ),);
    // And so does a plan for a different family entirely.
    let merge = pull_request_plan(
        &request,
        ReviewPullRequestFamily::Merge,
        Some(91),
        PR_HEAD,
        None,
        "example-org",
        "example-repo",
    );
    assert!(matches!(
        store.prepare_external_action(&request, ApprovalPolicy::NotRequired, &merge, 14),
        Err(ReviewStoreError::Conflict("external_effect_request"))
    ),);
}

/// The opened number is write-once. The pull request this process created
/// cannot change identity between a crash and a reconciliation.
#[test]
fn an_opened_number_cannot_be_rewritten_by_a_later_settlement() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).unwrap();
    let snapshot = pull_request_snapshot(
        PullRequestState::Absent,
        MergeReadiness::Unknown,
        None,
        None,
    );
    seed_pull_request(&mut store, &snapshot);
    let request = pull_request_request(
        "open-once",
        "actor-1",
        ReviewAction::OpenPullRequest {
            expected_pull_request_revision: revision(8),
            title: ReviewField::new("Proposer le correctif").unwrap(),
        },
    );
    let plan = pull_request_plan(
        &request,
        ReviewPullRequestFamily::Open,
        None,
        PR_HEAD,
        Some("Proposer le correctif"),
        "example-org",
        "example-repo",
    );
    admit(&mut store, &request, &plan);
    let preview = preview_of(&store, &request);
    store
        .settle_github_pull_request(
            &preview,
            plan.request_digest(),
            ReviewExternalEffectCustody::Accepted,
            Some(91),
            16,
        )
        .expect("accept");
    assert!(matches!(
        store.settle_github_pull_request(
            &preview,
            plan.request_digest(),
            ReviewExternalEffectCustody::Completed,
            Some(92),
            17,
        ),
        Err(ReviewStoreError::Conflict("github_pull_request_number"))
    ),);
    let (_, stored) = store
        .external_action(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            18,
        )
        .expect("read back")
        .expect("action");
    assert_eq!(stored.github_pull_request_opened_number(), Some(91));
    assert!(stored.is_github_pull_request());
    assert!(stored.is_github_effect());
    assert!(!stored.is_github_check_rerun());
}

/// A store that has never seen a pull-request write migrates into one that can
/// hold them, without touching anything it already held.
#[test]
fn v6_store_gains_pull_request_custody_without_disturbing_check_reruns() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).unwrap();
    let request = seed(&mut store);
    let plan = github_external_plan(&request);
    store
        .prepare_external_action(&request, ApprovalPolicy::NotRequired, &plan, 12)
        .unwrap();
    drop(store);
    let raw = Connection::open(private.path()).unwrap();
    raw.execute_batch("DROP TABLE review_github_pull_request_effect_plans; PRAGMA user_version=6;")
        .unwrap();
    drop(raw);

    let store = ReviewStore::open(private.path()).expect("migrate v6");
    let (_, migrated) = store
        .external_action(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            13,
        )
        .unwrap()
        .unwrap();
    assert!(migrated.is_github_check_rerun());
    assert_eq!(migrated.github_pull_request_family(), None);
    drop(store);
    let raw = Connection::open(private.path()).unwrap();
    assert_eq!(
        raw.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .unwrap(),
        REVIEW_STORE_SCHEMA_VERSION
    );
    let tables: i64 = raw
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='review_github_pull_request_effect_plans'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tables, 1);
}

#[test]
fn validate_action_checks_authority_and_revision_without_admitting_custody() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).unwrap();
    let request = seed(&mut store);
    store.validate_action(&request, 12).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(private.path()).unwrap();
    let previews: i64 = connection
        .query_row("SELECT count(*) FROM review_action_previews", [], |row| {
            row.get(0)
        })
        .unwrap();
    let receipts: i64 = connection
        .query_row("SELECT count(*) FROM review_action_receipts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!((previews, receipts), (0, 0));
}

#[test]
fn local_comment_effect_is_atomic_exactly_once_and_actor_attributed() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let initial = snapshot();
    let actor = ReviewActorId::new("actor-local-comment").expect("actor");
    let authority = initial.review().authority().clone();
    store.put_snapshot(&initial, 10).expect("snapshot");
    store
        .grant_authority(
            initial.workspace(),
            &actor,
            ReviewAuthentication::UserSession,
            &authority,
            11,
        )
        .expect("grant");
    let request = ReviewActionRequest::new(
        initial.workspace().clone(),
        initial.revision(),
        actor.clone(),
        ReviewAuthentication::UserSession,
        authority,
        IdempotencyKey::new("local-comment-once").expect("key"),
        ReviewAction::AddComment {
            comment_id: ReviewCommentId::new("comment-local").expect("comment"),
            anchor: initial.comments()[0].anchor().clone(),
            body: ReviewText::new("A bounded attributed comment.").expect("body"),
        },
    )
    .expect("request");

    let completed = store
        .execute_local_action(&request, 12)
        .expect("execute local action");
    assert_eq!(completed.outcome(), ReviewReceiptOutcome::Completed);
    assert_eq!(completed.revision(), Some(revision(10)));
    assert_eq!(completed.actor(), &actor);
    assert_eq!(
        store
            .execute_local_action(&request, 13)
            .expect("terminal replay"),
        completed
    );
    assert_eq!(
        store
            .non_rerun_receipt(
                request.workspace(),
                request.actor(),
                request.authentication(),
                request.authority(),
                request.idempotency_key(),
                13,
            )
            .expect("generic local receipt"),
        Some(completed.clone())
    );
    let current = store
        .snapshot(initial.workspace())
        .expect("read")
        .expect("current");
    assert_eq!(current.revision(), revision(10));
    let comment = current
        .comments()
        .iter()
        .find(|comment| comment.id().as_str() == "comment-local")
        .expect("persisted comment");
    assert_eq!(comment.actor(), &actor);
    assert_eq!(comment.agent_state(), CommentAgentState::NotSent);

    drop(store);
    let raw = Connection::open(private.path()).expect("raw");
    let rows: (i64, i64, i64) = raw
        .query_row(
            "SELECT (SELECT count(*) FROM review_action_previews),(SELECT count(*) FROM review_action_receipts),(SELECT count(*) FROM review_snapshots)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("custody rows");
    assert_eq!(rows, (1, 1, 2));
}

#[test]
fn completed_local_effect_without_its_write_admission_fails_after_reopen() {
    let private = PrivateStore::new();
    let request = {
        let mut store = ReviewStore::open(private.path()).expect("open");
        let initial = snapshot();
        let actor = ReviewActorId::new("actor-local-admission").expect("actor");
        let authority = initial.review().authority().clone();
        store.put_snapshot(&initial, 10).expect("snapshot");
        store
            .grant_authority(
                initial.workspace(),
                &actor,
                ReviewAuthentication::UserSession,
                &authority,
                11,
            )
            .expect("grant");
        let request = ReviewActionRequest::new(
            initial.workspace().clone(),
            initial.revision(),
            actor,
            ReviewAuthentication::UserSession,
            authority,
            IdempotencyKey::new("local-comment-admission").expect("key"),
            ReviewAction::AddComment {
                comment_id: ReviewCommentId::new("comment-local-admission").expect("comment"),
                anchor: initial.comments()[0].anchor().clone(),
                body: ReviewText::new("A bounded attributed comment.").expect("body"),
            },
        )
        .expect("request");
        let receipt = store
            .execute_local_action(&request, 12)
            .expect("completed local action");
        assert_eq!(receipt.outcome(), ReviewReceiptOutcome::Completed);
        request
    };

    let connection = Connection::open(private.path()).expect("raw open");
    connection
        .execute(
            "UPDATE review_action_previews SET write_admission_id=NULL,write_admitted_at_ms=NULL,write_admission_document=NULL,write_admission_digest=NULL",
            [],
        )
        .expect("remove completed admission");
    drop(connection);

    let mut reopened = ReviewStore::open(private.path()).expect("reopen");
    assert!(matches!(
        reopened.receipt(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            13,
        ),
        Err(ReviewStoreError::Corrupt("write_admission"))
    ));
    assert!(matches!(
        reopened.execute_local_action(&request, 14),
        Err(ReviewStoreError::Corrupt("write_admission"))
    ));
}

#[test]
fn local_review_approval_advances_one_revision_and_replays_terminal_receipt() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let initial = snapshot();
    let actor = ReviewActorId::new("actor-local-approval").expect("actor");
    let authority = initial.review().authority().clone();
    store.put_snapshot(&initial, 10).expect("snapshot");
    store
        .grant_authority(
            initial.workspace(),
            &actor,
            ReviewAuthentication::UserSession,
            &authority,
            11,
        )
        .expect("grant");
    let request = ReviewActionRequest::new(
        initial.workspace().clone(),
        initial.revision(),
        actor.clone(),
        ReviewAuthentication::UserSession,
        authority,
        IdempotencyKey::new("local-approval-once").expect("key"),
        ReviewAction::ApproveReview {
            expected_review_revision: initial.review().freshness().observed_revision(),
        },
    )
    .expect("request");

    let receipt = store
        .execute_local_action(&request, 12)
        .expect("execute approval");
    assert_eq!(receipt.outcome(), ReviewReceiptOutcome::Completed);
    assert_eq!(receipt.actor(), &actor);
    assert_eq!(
        store
            .execute_local_action(&request, 13)
            .expect("terminal replay"),
        receipt
    );
    let current = store
        .snapshot(initial.workspace())
        .expect("read")
        .expect("current");
    assert_eq!(current.revision(), revision(10));
    assert_eq!(current.review().decision(), ReviewDecision::Approved);
    assert_eq!(
        current.review().freshness().observed_revision(),
        revision(10)
    );
}

#[test]
fn unstarted_local_custody_settles_conflict_after_revision_advances() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let initial = snapshot();
    let actor = ReviewActorId::new("actor-local-stale").expect("actor");
    let authority = initial.review().authority().clone();
    store.put_snapshot(&initial, 10).expect("snapshot");
    store
        .grant_authority(
            initial.workspace(),
            &actor,
            ReviewAuthentication::UserSession,
            &authority,
            11,
        )
        .expect("grant");
    let make = |key: &str, id: &str| {
        ReviewActionRequest::new(
            initial.workspace().clone(),
            initial.revision(),
            actor.clone(),
            ReviewAuthentication::UserSession,
            authority.clone(),
            IdempotencyKey::new(key).expect("key"),
            ReviewAction::AddComment {
                comment_id: ReviewCommentId::new(id).expect("comment"),
                anchor: initial.comments()[0].anchor().clone(),
                body: ReviewText::new("Bounded body.").expect("body"),
            },
        )
        .expect("request")
    };
    let stranded = make("local-stale-first", "comment-stale-first");
    store
        .prepare_action(&stranded, ApprovalPolicy::NotRequired, 12)
        .expect("accepted custody");
    let winner = make("local-stale-winner", "comment-stale-winner");
    store
        .execute_local_action(&winner, 13)
        .expect("winner completes");

    let conflict = store
        .execute_local_action(&stranded, 14)
        .expect("stale custody settles");
    assert_eq!(conflict.outcome(), ReviewReceiptOutcome::Conflict);
    assert_eq!(conflict.current_revision(), Some(revision(10)));
    assert_eq!(
        store
            .execute_local_action(&stranded, 15)
            .expect("conflict replay"),
        conflict
    );
    let current = store
        .snapshot(initial.workspace())
        .expect("read")
        .expect("current");
    assert!(
        current
            .comments()
            .iter()
            .all(|comment| comment.id().as_str() != "comment-stale-first")
    );
}

#[test]
fn restart_preserves_sanitized_snapshot_comments_and_sent_state() {
    let private = PrivateStore::new();
    let workspace = {
        let mut store = ReviewStore::open(private.path()).expect("open");
        let snapshot = snapshot();
        let workspace = snapshot.workspace().clone();
        store.put_snapshot(&snapshot, 10).expect("persist");
        workspace
    };
    let reopened = ReviewStore::open(private.path()).expect("reopen");
    let restored = reopened
        .snapshot(&workspace)
        .expect("read")
        .expect("snapshot");
    assert_eq!(restored, snapshot());
    let expected = &restored.comments()[0];
    let stored = reopened
        .comment(&workspace, revision(9), expected.id())
        .expect("comment read")
        .expect("comment");
    assert_eq!(stored.comment.actor().as_str(), "actor-1");
    assert_eq!(stored.comment.agent_state().as_str(), "sent");
    assert_eq!(stored.comment.anchor().file_id().as_str(), "file-1");
    assert_eq!(stored.comment.anchor().hunk_id().as_str(), "hunk-1");
}

#[test]
fn current_review_v2_snapshot_cannot_downgrade_to_v1() {
    let private = PrivateStore::new();
    let current = snapshot();
    let workspace = current.workspace().clone();
    let legacy_next_document = String::from_utf8(LEGACY_SNAPSHOT.to_vec())
        .expect("legacy fixture utf8")
        .replace("\"revision\":9,\"schema\"", "\"revision\":10,\"schema\"")
        .into_bytes();
    let legacy_next = decode_review_snapshot(&legacy_next_document).expect("legacy next revision");
    assert_eq!(legacy_next.schema(), ReviewSchemaVersion::V1);
    assert_eq!(legacy_next.revision(), revision(10));

    let mut store = ReviewStore::open(private.path()).expect("open");
    store.put_snapshot(&current, 10).expect("persist v2");
    let before: (i64, Vec<u8>, Vec<u8>, String) = Connection::open(private.path())
        .expect("raw before")
        .query_row(
            "SELECT c.revision,s.document,s.document_digest,s.protocol_schema FROM review_current c JOIN review_snapshots s USING(workspace_kind,workspace_id,revision) WHERE c.workspace_kind=?1 AND c.workspace_id=?2",
            params![current.workspace().kind().as_str(), current.workspace().id()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("current bytes before refusal");

    assert!(matches!(
        store.put_snapshot(&legacy_next, 11),
        Err(ReviewStoreError::Conflict("snapshot_schema_downgrade"))
    ));
    assert_eq!(
        store
            .snapshot(&workspace)
            .expect("read current")
            .expect("current snapshot"),
        current
    );
    drop(store);

    let raw = Connection::open(private.path()).expect("raw after");
    let after: (i64, Vec<u8>, Vec<u8>, String) = raw
        .query_row(
            "SELECT c.revision,s.document,s.document_digest,s.protocol_schema FROM review_current c JOIN review_snapshots s USING(workspace_kind,workspace_id,revision) WHERE c.workspace_kind=?1 AND c.workspace_id=?2",
            params![workspace.kind().as_str(), workspace.id()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("current bytes after refusal");
    assert_eq!(after, before);
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM review_snapshots WHERE workspace_kind=?1 AND workspace_id=?2",
            params![workspace.kind().as_str(), workspace.id()],
            |row| row.get::<_, u32>(0),
        )
        .expect("snapshot count"),
        1
    );
}

#[test]
fn populated_review_v1_store_migrates_exactly_and_remains_non_actionable() {
    let private = PrivateStore::new();
    let legacy = legacy_snapshot();
    let workspace = legacy.workspace().clone();
    {
        let mut store = ReviewStore::open(private.path()).expect("open v2");
        store
            .put_snapshot(&legacy, 10)
            .expect("persist legacy snapshot");
    }
    downgrade_review_store_to_v1(private.path());

    {
        let mut migrated = ReviewStore::open(private.path()).expect("migrate v1 to v2");
        let loaded = migrated
            .snapshot(&workspace)
            .expect("read migrated snapshot")
            .expect("snapshot exists");
        assert_eq!(loaded, legacy);
        assert_eq!(loaded.schema(), ReviewSchemaVersion::V1);
        assert!(
            loaded
                .proposals()
                .iter()
                .all(|proposal| proposal.authority().is_none())
        );

        let actor = ReviewActorId::new("legacy-actor").expect("actor");
        let git = ReviewAuthority::new(
            ReviewAuthorityKind::Git,
            ReviewAuthorityId::new("legacy-git").expect("authority"),
        );
        migrated
            .grant_authority(
                &workspace,
                &actor,
                ReviewAuthentication::UserSession,
                &git,
                11,
            )
            .expect("grant is independent of proposal custody");
        let request = ReviewActionRequest::new(
            workspace.clone(),
            loaded.revision(),
            actor,
            ReviewAuthentication::UserSession,
            git,
            IdempotencyKey::new("legacy-action").expect("key"),
            ReviewAction::Commit {
                proposal_id: ReviewProposalId::new("proposal-1").expect("proposal"),
            },
        )
        .expect("typed request");
        assert!(matches!(
            migrated.prepare_action(&request, ApprovalPolicy::NotRequired, 12),
            Err(ReviewStoreError::Protocol(_))
        ));
    }

    let reopened = ReviewStore::open(private.path()).expect("reopen migrated store");
    assert_eq!(
        reopened
            .snapshot(&workspace)
            .expect("read")
            .expect("snapshot"),
        legacy
    );
    let raw = Connection::open(private.path()).expect("raw reopen");
    assert_eq!(
        raw.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .expect("version"),
        REVIEW_STORE_SCHEMA_VERSION
    );
    let schema: String = raw
        .query_row("SELECT protocol_schema FROM review_snapshots", [], |row| {
            row.get(0)
        })
        .expect("snapshot schema");
    assert_eq!(schema, PLATFORM_REVIEW_SCHEMA_V1);
}

#[test]
fn mislabeled_authority_bearing_v1_document_is_transactionally_upgraded_to_v2() {
    let private = PrivateStore::new();
    let expected = snapshot();
    let workspace = expected.workspace().clone();
    {
        let mut store = ReviewStore::open(private.path()).expect("open v2");
        store
            .put_snapshot(&expected, 10)
            .expect("persist v2 snapshot");
    }
    downgrade_review_store_to_v1(private.path());
    let raw = Connection::open(private.path()).expect("raw legacy open");
    let current: Vec<u8> = raw
        .query_row("SELECT document FROM review_snapshots", [], |row| {
            row.get(0)
        })
        .expect("document");
    let mislabeled = String::from_utf8(current)
        .expect("canonical utf8")
        .replace(
            "automonique.platform/review/v2",
            "automonique.platform/review/v1",
        )
        .into_bytes();
    let mislabeled_digest = Sha256::digest(&mislabeled);
    raw.execute(
        "UPDATE review_snapshots SET document=?1,document_digest=?2",
        params![mislabeled, mislabeled_digest.as_slice()],
    )
    .expect("recreate briefly shipped mislabeled document");
    drop(raw);

    let migrated = ReviewStore::open(private.path()).expect("upgrade mislabeled snapshot");
    assert_eq!(
        migrated
            .snapshot(&workspace)
            .expect("read")
            .expect("snapshot"),
        expected
    );
    drop(migrated);
    let raw = Connection::open(private.path()).expect("raw reopen");
    assert_eq!(
        raw.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .expect("version"),
        REVIEW_STORE_SCHEMA_VERSION
    );
    let protocol_schema: String = raw
        .query_row("SELECT protocol_schema FROM review_snapshots", [], |row| {
            row.get(0)
        })
        .expect("schema projection");
    assert_eq!(protocol_schema, PLATFORM_REVIEW_SCHEMA_V2);
}

#[test]
fn populated_v2_store_adds_external_plan_custody_transactionally() {
    let private = PrivateStore::new();
    let expected = snapshot();
    {
        let mut store = ReviewStore::open(private.path()).expect("open v3");
        store.put_snapshot(&expected, 10).expect("snapshot");
    }
    let raw = Connection::open(private.path()).expect("raw");
    raw.execute_batch(
        "DROP TABLE review_github_pull_request_effect_plans; DROP TABLE review_github_check_effect_plans; DROP TABLE review_external_effect_targets; DROP TABLE review_external_effect_plans; DROP TABLE review_external_effect_migration_tombstones; PRAGMA user_version=2;",
    )
        .expect("construct v2 store");
    drop(raw);

    let migrated = ReviewStore::open(private.path()).expect("migrate v2");
    assert_eq!(
        migrated
            .snapshot(expected.workspace())
            .expect("read")
            .expect("snapshot"),
        expected
    );
    drop(migrated);
    let raw = Connection::open(private.path()).expect("raw reopen");
    assert_eq!(
        raw.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .unwrap(),
        REVIEW_STORE_SCHEMA_VERSION
    );
    assert!(
        raw.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='review_external_effect_plans')",
            [],
            |row| row.get::<_, bool>(0),
        )
        .unwrap()
    );
}

#[test]
fn populated_real_v3_store_migrates_to_v4_without_losing_review_state() {
    let private = PrivateStore::new();
    let expected = snapshot();
    let request = request();
    {
        let mut store = ReviewStore::open(private.path()).unwrap();
        store.put_snapshot(&expected, 10).unwrap();
        store
            .grant_authority(
                request.workspace(),
                request.actor(),
                request.authentication(),
                request.authority(),
                11,
            )
            .unwrap();
    }
    let raw = Connection::open(private.path()).unwrap();
    raw.execute_batch("DROP TABLE review_github_pull_request_effect_plans; DROP TABLE review_github_check_effect_plans; PRAGMA user_version=3;")
        .unwrap();
    drop(raw);

    let store = ReviewStore::open(private.path()).expect("migrate populated v3");
    assert_eq!(
        store.snapshot(expected.workspace()).unwrap(),
        Some(expected)
    );
    store.validate_action(&request, 12).unwrap();
    drop(store);
    let raw = Connection::open(private.path()).unwrap();
    assert_eq!(
        raw.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .unwrap(),
        REVIEW_STORE_SCHEMA_VERSION
    );
    assert!(raw
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='review_github_check_effect_plans')",
            [],
            |row| row.get::<_, bool>(0),
        )
        .unwrap());
}

#[test]
fn v4_store_adds_nullable_receipt_correlation_transactionally() {
    let private = PrivateStore::new();
    drop(ReviewStore::open(private.path()).unwrap());
    let raw = Connection::open(private.path()).unwrap();
    raw.execute_batch(
        "DROP TABLE review_github_pull_request_effect_plans;
         ALTER TABLE review_github_check_effect_plans DROP COLUMN receipt_correlation_digest;
         ALTER TABLE review_github_check_effect_plans DROP COLUMN expected_workspace_revision;
         PRAGMA user_version=4;",
    )
    .unwrap();
    drop(raw);
    drop(ReviewStore::open(private.path()).expect("migrate v4"));
    let raw = Connection::open(private.path()).unwrap();
    assert_eq!(
        raw.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .unwrap(),
        REVIEW_STORE_SCHEMA_VERSION
    );
    let columns: i64 = raw.query_row("SELECT count(*) FROM pragma_table_info('review_github_check_effect_plans') WHERE name='receipt_correlation_digest'", [], |row| row.get(0)).unwrap();
    assert_eq!(columns, 1);
}

#[test]
fn v5_store_adds_nullable_workspace_revision_and_preserves_legacy_as_unbound() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).unwrap();
    let request = seed(&mut store);
    let plan = github_external_plan(&request);
    store
        .prepare_external_action(&request, ApprovalPolicy::NotRequired, &plan, 12)
        .unwrap();
    drop(store);
    let raw = Connection::open(private.path()).unwrap();
    let document: Vec<u8> = raw
        .query_row(
            "SELECT plan_document FROM review_github_check_effect_plans",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let legacy_document = String::from_utf8(document)
        .unwrap()
        .replace(",\"expected_workspace_revision\":11", "")
        .into_bytes();
    let legacy_digest = Sha256::digest(&legacy_document);
    raw.execute(
        "UPDATE review_github_check_effect_plans
         SET plan_document=?1,plan_digest=?2",
        params![legacy_document, legacy_digest.as_slice()],
    )
    .unwrap();
    raw.execute_batch(
        "DROP TABLE review_github_pull_request_effect_plans;
         ALTER TABLE review_github_check_effect_plans DROP COLUMN expected_workspace_revision;
         PRAGMA user_version=5;",
    )
    .unwrap();
    drop(raw);
    let store = ReviewStore::open(private.path()).expect("migrate v5");
    let (_, legacy_plan) = store
        .external_action(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            13,
        )
        .unwrap()
        .unwrap();
    assert_eq!(legacy_plan.github_expected_workspace_revision(), None);
    assert_eq!(
        legacy_plan.github_receipt_correlation_digest(),
        Some([9; 32])
    );
    drop(store);
    let raw = Connection::open(private.path()).unwrap();
    assert_eq!(
        raw.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .unwrap(),
        REVIEW_STORE_SCHEMA_VERSION
    );
    let columns: i64 = raw
        .query_row(
            "SELECT count(*) FROM pragma_table_info('review_github_check_effect_plans') WHERE name='expected_workspace_revision'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(columns, 1);
}

#[test]
fn failed_populated_v3_to_v4_migration_rolls_back_version_and_preserves_data() {
    let private = PrivateStore::new();
    let expected = snapshot();
    {
        let mut store = ReviewStore::open(private.path()).unwrap();
        store.put_snapshot(&expected, 10).unwrap();
    }
    let raw = Connection::open(private.path()).unwrap();
    raw.execute_batch(
        "DROP TABLE review_github_pull_request_effect_plans; DROP TABLE review_github_check_effect_plans; CREATE TABLE review_github_check_effect_plans(marker TEXT) STRICT; PRAGMA user_version=3;",
    )
    .unwrap();
    drop(raw);

    assert!(matches!(
        ReviewStore::open(private.path()),
        Err(ReviewStoreError::Sqlite(_))
    ));
    let raw = Connection::open(private.path()).unwrap();
    assert_eq!(
        raw.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .unwrap(),
        3
    );
    let document: Vec<u8> = raw
        .query_row("SELECT document FROM review_snapshots", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(decode_review_snapshot(&document).unwrap(), expected);
    let columns: i64 = raw
        .query_row(
            "SELECT count(*) FROM pragma_table_info('review_github_check_effect_plans')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        columns, 1,
        "failed migration must leave the v3 schema untouched"
    );
}

#[test]
fn v2_migration_terminalizes_legacy_accepted_external_action_without_a_plan() {
    let private = PrivateStore::new();
    let (request, action) = {
        let mut store = ReviewStore::open(private.path()).expect("open v3");
        let snapshot = action_snapshot(false);
        store.put_snapshot(&snapshot, 10).expect("snapshot");
        let actor = ReviewActorId::new("actor-legacy-external").unwrap();
        let authority = snapshot.review().authority().clone();
        store
            .grant_authority(
                snapshot.workspace(),
                &actor,
                ReviewAuthentication::UserSession,
                &authority,
                11,
            )
            .unwrap();
        let comment = &snapshot.comments()[0];
        let request = ReviewActionRequest::new(
            snapshot.workspace().clone(),
            snapshot.revision(),
            actor,
            ReviewAuthentication::UserSession,
            authority,
            IdempotencyKey::new("legacy-external").unwrap(),
            ReviewAction::SendCommentToAgent {
                comment_id: comment.id().clone(),
                expected_comment_revision: comment.revision(),
            },
        )
        .unwrap();
        let plan = external_plan(&request, b"legacy payload unavailable after migration");
        let ReviewActionAdmission::New(action) = store
            .prepare_external_action(&request, ApprovalPolicy::NotRequired, &plan, 20)
            .unwrap()
        else {
            panic!("new")
        };
        (request, action)
    };
    let raw = Connection::open(private.path()).unwrap();
    raw.execute_batch(
        "DROP TABLE review_github_pull_request_effect_plans; DROP TABLE review_github_check_effect_plans; DROP TABLE review_external_effect_targets; DROP TABLE review_external_effect_plans; DROP TABLE review_external_effect_migration_tombstones; PRAGMA user_version=2;",
    )
    .unwrap();
    drop(raw);

    let store = ReviewStore::open(private.path()).expect("migrate legacy external custody");
    let receipt = store
        .receipt(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            21,
        )
        .unwrap()
        .expect("terminal receipt");
    assert_eq!(receipt.outcome(), ReviewReceiptOutcome::Refused);
    assert_eq!(receipt.reconciliation(), ReviewReconciliation::Final);
    assert!(
        store
            .external_action(
                request.workspace(),
                request.actor(),
                request.authentication(),
                request.authority(),
                request.idempotency_key(),
                21,
            )
            .unwrap()
            .is_none()
    );
    let raw = Connection::open(private.path()).unwrap();
    let (outcome, updated_at_ms): (String, i64) = raw
        .query_row(
            "SELECT outcome,updated_at_ms FROM review_action_receipts WHERE preview_id=?1",
            [&action.preview_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(outcome, "refused");
    assert_eq!(updated_at_ms, 20);
}

#[test]
fn v2_migration_preserves_or_conservatively_terminalizes_every_external_outcome() {
    let cases = [
        ("accepted", ReviewReceiptOutcome::Refused),
        ("accepted_write", ReviewReceiptOutcome::Conflict),
        ("unknown", ReviewReceiptOutcome::Conflict),
        ("completed", ReviewReceiptOutcome::Completed),
        ("conflict", ReviewReceiptOutcome::Conflict),
        ("refused", ReviewReceiptOutcome::Refused),
    ];
    for (case, expected) in cases {
        let private = PrivateStore::new();
        let (request, preview_id) = {
            let mut store = ReviewStore::open(private.path()).unwrap();
            let snapshot = action_snapshot(false);
            store.put_snapshot(&snapshot, 10).unwrap();
            let actor = ReviewActorId::new(format!("actor-migrate-{case}")).unwrap();
            let authority = snapshot.review().authority().clone();
            store
                .grant_authority(
                    snapshot.workspace(),
                    &actor,
                    ReviewAuthentication::UserSession,
                    &authority,
                    11,
                )
                .unwrap();
            let comment = &snapshot.comments()[0];
            let request = ReviewActionRequest::new(
                snapshot.workspace().clone(),
                snapshot.revision(),
                actor,
                ReviewAuthentication::UserSession,
                authority,
                IdempotencyKey::new(format!("migrate-{case}")).unwrap(),
                ReviewAction::SendCommentToAgent {
                    comment_id: comment.id().clone(),
                    expected_comment_revision: comment.revision(),
                },
            )
            .unwrap();
            let plan = external_plan(&request, format!("migration payload {case}").as_bytes());
            let ReviewActionAdmission::New(action) = store
                .prepare_external_action(&request, ApprovalPolicy::NotRequired, &plan, 20)
                .unwrap()
            else {
                panic!("new")
            };
            match case {
                "accepted" => {}
                "accepted_write" => {
                    store
                        .start_write(&action.preview_id, action.request_digest, 21)
                        .unwrap();
                }
                "unknown" => {
                    store
                        .start_write(&action.preview_id, action.request_digest, 21)
                        .unwrap();
                    store
                        .mark_ambiguous(&action.preview_id, action.request_digest, 22)
                        .unwrap();
                }
                "completed" => {
                    store
                        .start_write(&action.preview_id, action.request_digest, 21)
                        .unwrap();
                    store
                        .complete_retained_session_delivery(
                            &action.preview_id,
                            action.request_digest,
                            plan.transport_key(),
                            true,
                            22,
                        )
                        .unwrap();
                }
                "conflict" => {
                    store
                        .start_write(&action.preview_id, action.request_digest, 21)
                        .unwrap();
                    let mutated = ReviewComment::new(
                        comment.id().clone(),
                        revision(comment.revision().get() + 1),
                        comment.actor().clone(),
                        ReviewText::new("Migration conflict target changed").unwrap(),
                        comment.anchor().clone(),
                        comment.agent_state(),
                        comment.unread(),
                    );
                    let advanced = ReviewSnapshot::new(
                        snapshot.workspace().clone(),
                        revision(snapshot.revision().get() + 1),
                        snapshot.files().to_vec(),
                        vec![mutated],
                        snapshot.proposals().to_vec(),
                        snapshot.checks().to_vec(),
                        snapshot.review().clone(),
                        snapshot.pull_request().clone(),
                        snapshot.delivery().clone(),
                        snapshot.attention_events().to_vec(),
                    )
                    .unwrap();
                    store.put_snapshot(&advanced, 22).unwrap();
                    store
                        .complete_retained_session_delivery(
                            &action.preview_id,
                            action.request_digest,
                            plan.transport_key(),
                            true,
                            23,
                        )
                        .unwrap();
                }
                "refused" => {
                    store
                        .refuse_external_action_not_started(
                            &action.preview_id,
                            action.request_digest,
                            21,
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            (request, action.preview_id)
        };
        let raw = Connection::open(private.path()).unwrap();
        raw.execute_batch(
            "DROP TABLE review_github_pull_request_effect_plans; DROP TABLE review_github_check_effect_plans; DROP TABLE review_external_effect_targets; DROP TABLE review_external_effect_plans; DROP TABLE review_external_effect_migration_tombstones; PRAGMA user_version=2;",
        )
        .unwrap();
        drop(raw);

        let store = ReviewStore::open(private.path()).unwrap();
        let migrated = store
            .receipt(
                request.workspace(),
                request.actor(),
                request.authentication(),
                request.authority(),
                request.idempotency_key(),
                30,
            )
            .unwrap()
            .unwrap();
        assert_eq!(migrated.outcome(), expected, "case={case}");
        assert_eq!(migrated.reconciliation(), ReviewReconciliation::Final);
        drop(store);
        let raw = Connection::open(private.path()).unwrap();
        let (outcome, tombstone_digest, receipt_digest): (String, Vec<u8>, Vec<u8>) = raw
            .query_row(
                "SELECT t.outcome,t.receipt_digest,r.receipt_digest FROM review_external_effect_migration_tombstones t JOIN review_action_receipts r USING(preview_id) WHERE t.preview_id=?1",
                [&preview_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(outcome, expected.as_str());
        assert_eq!(tombstone_digest, receipt_digest);
    }
}

#[test]
fn migration_tombstone_tampering_and_native_missing_plan_corruption_fail_closed() {
    let private = PrivateStore::new();
    let (preview_id, request) = {
        let mut store = ReviewStore::open(private.path()).unwrap();
        let snapshot = action_snapshot(false);
        store.put_snapshot(&snapshot, 10).unwrap();
        let actor = ReviewActorId::new("actor-migration-corrupt").unwrap();
        let authority = snapshot.review().authority().clone();
        store
            .grant_authority(
                snapshot.workspace(),
                &actor,
                ReviewAuthentication::UserSession,
                &authority,
                11,
            )
            .unwrap();
        let comment = &snapshot.comments()[0];
        let request = ReviewActionRequest::new(
            snapshot.workspace().clone(),
            snapshot.revision(),
            actor,
            ReviewAuthentication::UserSession,
            authority,
            IdempotencyKey::new("migration-corrupt").unwrap(),
            ReviewAction::SendCommentToAgent {
                comment_id: comment.id().clone(),
                expected_comment_revision: comment.revision(),
            },
        )
        .unwrap();
        let plan = external_plan(&request, b"migration corruption payload");
        let ReviewActionAdmission::New(action) = store
            .prepare_external_action(&request, ApprovalPolicy::NotRequired, &plan, 20)
            .unwrap()
        else {
            panic!("new")
        };
        (action.preview_id, request)
    };
    let raw = Connection::open(private.path()).unwrap();
    raw.execute_batch(
        "DROP TABLE review_github_pull_request_effect_plans; DROP TABLE review_github_check_effect_plans; DROP TABLE review_external_effect_targets; DROP TABLE review_external_effect_plans; DROP TABLE review_external_effect_migration_tombstones; PRAGMA user_version=2;",
    )
    .unwrap();
    drop(raw);
    ReviewStore::open(private.path()).unwrap();
    let raw = Connection::open(private.path()).unwrap();
    raw.execute(
        "UPDATE review_external_effect_migration_tombstones SET receipt_digest=zeroblob(32) WHERE preview_id=?1",
        [&preview_id],
    )
    .unwrap();
    drop(raw);
    let store = ReviewStore::open(private.path()).unwrap();
    assert!(matches!(
        store.receipt(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            30,
        ),
        Err(ReviewStoreError::Corrupt(
            "external_effect_migration_tombstone"
        ))
    ));

    let native = PrivateStore::new();
    let request = {
        let mut store = ReviewStore::open(native.path()).unwrap();
        let snapshot = action_snapshot(false);
        store.put_snapshot(&snapshot, 10).unwrap();
        let actor = ReviewActorId::new("actor-native-missing-plan").unwrap();
        let authority = snapshot.review().authority().clone();
        store
            .grant_authority(
                snapshot.workspace(),
                &actor,
                ReviewAuthentication::UserSession,
                &authority,
                11,
            )
            .unwrap();
        let comment = &snapshot.comments()[0];
        let request = ReviewActionRequest::new(
            snapshot.workspace().clone(),
            snapshot.revision(),
            actor,
            ReviewAuthentication::UserSession,
            authority,
            IdempotencyKey::new("native-missing-plan").unwrap(),
            ReviewAction::SendCommentToAgent {
                comment_id: comment.id().clone(),
                expected_comment_revision: comment.revision(),
            },
        )
        .unwrap();
        let plan = external_plan(&request, b"native missing plan");
        store
            .prepare_external_action(&request, ApprovalPolicy::NotRequired, &plan, 20)
            .unwrap();
        request
    };
    let raw = Connection::open(native.path()).unwrap();
    raw.execute("DELETE FROM review_external_effect_targets", [])
        .unwrap();
    raw.execute("DELETE FROM review_external_effect_plans", [])
        .unwrap();
    drop(raw);
    let store = ReviewStore::open(native.path()).unwrap();
    assert!(matches!(
        store.receipt(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            30,
        ),
        Err(ReviewStoreError::Corrupt("external_effect_custody"))
    ));
}

#[test]
fn migration_refuses_legacy_completed_external_receipt_without_exact_snapshot_basis() {
    let private = PrivateStore::new();
    let completed_revision = {
        let mut store = ReviewStore::open(private.path()).unwrap();
        let snapshot = action_snapshot(false);
        store.put_snapshot(&snapshot, 10).unwrap();
        let actor = ReviewActorId::new("actor-completed-without-basis").unwrap();
        let authority = snapshot.review().authority().clone();
        store
            .grant_authority(
                snapshot.workspace(),
                &actor,
                ReviewAuthentication::UserSession,
                &authority,
                11,
            )
            .unwrap();
        let comment = &snapshot.comments()[0];
        let request = ReviewActionRequest::new(
            snapshot.workspace().clone(),
            snapshot.revision(),
            actor,
            ReviewAuthentication::UserSession,
            authority,
            IdempotencyKey::new("completed-without-basis").unwrap(),
            ReviewAction::SendCommentToAgent {
                comment_id: comment.id().clone(),
                expected_comment_revision: comment.revision(),
            },
        )
        .unwrap();
        let plan = external_plan(&request, b"completed migration basis");
        let ReviewActionAdmission::New(action) = store
            .prepare_external_action(&request, ApprovalPolicy::NotRequired, &plan, 20)
            .unwrap()
        else {
            panic!("new")
        };
        store
            .start_write(&action.preview_id, action.request_digest, 21)
            .unwrap();
        store
            .complete_retained_session_delivery(
                &action.preview_id,
                action.request_digest,
                plan.transport_key(),
                true,
                22,
            )
            .unwrap()
            .revision()
            .unwrap()
    };
    let raw = Connection::open(private.path()).unwrap();
    raw.execute(
        "DELETE FROM review_comments WHERE snapshot_revision=?1",
        [i64::try_from(completed_revision.get()).unwrap()],
    )
    .unwrap();
    raw.execute(
        "DELETE FROM review_snapshots WHERE revision=?1",
        [i64::try_from(completed_revision.get()).unwrap()],
    )
    .unwrap();
    raw.execute_batch(
        "DROP TABLE review_github_pull_request_effect_plans; DROP TABLE review_github_check_effect_plans; DROP TABLE review_external_effect_targets; DROP TABLE review_external_effect_plans; DROP TABLE review_external_effect_migration_tombstones; PRAGMA user_version=2;",
    )
    .unwrap();
    drop(raw);
    assert!(matches!(
        ReviewStore::open(private.path()),
        Err(ReviewStoreError::Corrupt("completion_basis"))
    ));
    let raw = Connection::open(private.path()).unwrap();
    assert_eq!(
        raw.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .unwrap(),
        2
    );
}

#[test]
fn corrupt_v1_migration_rolls_back_schema_and_data() {
    let private = PrivateStore::new();
    {
        let mut store = ReviewStore::open(private.path()).expect("open v2");
        store
            .put_snapshot(&legacy_snapshot(), 10)
            .expect("persist legacy snapshot");
    }
    downgrade_review_store_to_v1(private.path());
    let raw = Connection::open(private.path()).expect("raw open");
    raw.execute(
        "UPDATE review_snapshots SET document_digest=zeroblob(32)",
        [],
    )
    .expect("corrupt digest");
    drop(raw);

    assert!(matches!(
        ReviewStore::open(private.path()),
        Err(ReviewStoreError::Corrupt("snapshot_digest"))
    ));
    let raw = Connection::open(private.path()).expect("raw reopen");
    assert_eq!(
        raw.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .expect("version rolled back"),
        1
    );
    let has_v2_column: bool = raw
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('review_snapshots') WHERE name='protocol_schema')",
            [],
            |row| row.get(0),
        )
        .expect("schema inspection");
    assert!(!has_v2_column);
}

#[test]
fn exact_request_replays_and_different_body_under_same_key_conflicts() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let request = seed(&mut store);
    let ReviewActionAdmission::New(first) = store
        .prepare_action(&request, ApprovalPolicy::NotRequired, 20)
        .expect("new")
    else {
        panic!("new");
    };
    let ReviewActionAdmission::Replay(replay) = store
        .prepare_action(&request, ApprovalPolicy::NotRequired, 21)
        .expect("replay")
    else {
        panic!("replay");
    };
    assert_eq!(first.receipt, replay.receipt);
    assert_eq!(first.request_digest, replay.request_digest);

    let divergent = request_variant(
        &request,
        request.idempotency_key().as_str(),
        request.actor().as_str(),
        request.expected_revision(),
        revision(8),
    );
    let error = store
        .prepare_action(&divergent, ApprovalPolicy::NotRequired, 22)
        .expect_err("same key cannot change body");
    assert!(matches!(
        error,
        ReviewStoreError::Conflict("idempotency_key")
    ));
}

#[test]
fn typed_git_and_batch_actions_keep_one_write_custody() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let snapshot = action_snapshot(false);
    store.put_snapshot(&snapshot, 10).expect("snapshot");
    let actor = ReviewActorId::new("actor-new-actions").expect("actor");
    let git = snapshot.proposals()[0]
        .authority()
        .expect("v2 proposal authority")
        .clone();
    let review = snapshot.review().authority().clone();
    for authority in [&git, &review] {
        store
            .grant_authority(
                snapshot.workspace(),
                &actor,
                ReviewAuthentication::UserSession,
                authority,
                11,
            )
            .expect("grant");
    }
    let actions = vec![
        (
            "key-batch",
            review.clone(),
            ReviewAction::BatchSendCommentsToAgent {
                comments: vec![ReviewCommentTarget::new(
                    ReviewCommentId::new("comment-1").expect("comment"),
                    revision(2),
                )],
            },
        ),
        (
            "key-commit",
            git.clone(),
            ReviewAction::Commit {
                proposal_id: ReviewProposalId::new("proposal-commit").expect("proposal"),
            },
        ),
        (
            "key-stage",
            git.clone(),
            ReviewAction::Stage {
                proposal_id: ReviewProposalId::new("proposal-stage").expect("proposal"),
            },
        ),
        (
            "key-unstage",
            git.clone(),
            ReviewAction::Unstage {
                proposal_id: ReviewProposalId::new("proposal-unstage").expect("proposal"),
            },
        ),
    ];
    for (index, (key, authority, action)) in actions.into_iter().enumerate() {
        let request = ReviewActionRequest::new(
            snapshot.workspace().clone(),
            snapshot.revision(),
            actor.clone(),
            ReviewAuthentication::UserSession,
            authority,
            IdempotencyKey::new(key).expect("key"),
            action,
        )
        .expect("request");
        let plan = matches!(
            request.action(),
            ReviewAction::BatchSendCommentsToAgent { .. }
        )
        .then(|| external_plan(&request, b"exact batch payload"));
        let first = if let Some(plan) = plan.as_ref() {
            store.prepare_external_action(
                &request,
                ApprovalPolicy::NotRequired,
                plan,
                20 + index as i64,
            )
        } else {
            store.prepare_action(&request, ApprovalPolicy::NotRequired, 20 + index as i64)
        };
        let ReviewActionAdmission::New(prepared) = first.expect("prepare") else {
            panic!("first admission must be new")
        };
        let replay = if let Some(plan) = plan.as_ref() {
            store.prepare_external_action(
                &request,
                ApprovalPolicy::NotRequired,
                plan,
                30 + index as i64,
            )
        } else {
            store.prepare_action(&request, ApprovalPolicy::NotRequired, 30 + index as i64)
        };
        assert!(matches!(
            replay.expect("prepare replay"),
            ReviewActionAdmission::Replay(_)
        ));
        assert!(matches!(
            store
                .start_write(
                    &prepared.preview_id,
                    prepared.request_digest,
                    40 + index as i64
                )
                .expect("write"),
            ReviewWriteAdmission::New(_)
        ));
        assert!(matches!(
            store
                .start_write(
                    &prepared.preview_id,
                    prepared.request_digest,
                    50 + index as i64
                )
                .expect("write replay"),
            ReviewWriteAdmission::Replay(_)
        ));
    }

    let conflict_private = PrivateStore::new();
    let mut conflict_store = ReviewStore::open(conflict_private.path()).expect("open");
    let conflict_snapshot = action_snapshot(true);
    conflict_store
        .put_snapshot(&conflict_snapshot, 10)
        .expect("snapshot");
    let conflict_git = conflict_snapshot.proposals()[0]
        .authority()
        .expect("v2 proposal authority")
        .clone();
    conflict_store
        .grant_authority(
            conflict_snapshot.workspace(),
            &actor,
            ReviewAuthentication::UserSession,
            &conflict_git,
            11,
        )
        .expect("grant");
    let resolve = ReviewActionRequest::new(
        conflict_snapshot.workspace().clone(),
        conflict_snapshot.revision(),
        actor,
        ReviewAuthentication::UserSession,
        conflict_git,
        IdempotencyKey::new("key-resolve").expect("key"),
        ReviewAction::ResolveConflict {
            proposal_id: ReviewProposalId::new("proposal-resolve").expect("proposal"),
            file_id: ReviewFileId::new("file-1").expect("file"),
            resolution: ConflictResolution::KeepIncoming,
        },
    )
    .expect("request");
    let ReviewActionAdmission::New(prepared) = conflict_store
        .prepare_action(&resolve, ApprovalPolicy::NotRequired, 20)
        .expect("prepare")
    else {
        panic!("first admission must be new")
    };
    assert_eq!(
        prepared.request.action().kind(),
        ReviewActionKind::ResolveConflict
    );
    assert!(matches!(
        conflict_store
            .start_write(&prepared.preview_id, prepared.request_digest, 21)
            .expect("resolve write"),
        ReviewWriteAdmission::New(_)
    ));
    assert!(matches!(
        conflict_store
            .start_write(&prepared.preview_id, prepared.request_digest, 22)
            .expect("resolve replay"),
        ReviewWriteAdmission::Replay(_)
    ));
}

#[test]
fn retained_session_plan_is_exact_and_completion_advances_selected_comments_once() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let snapshot = action_snapshot(false);
    store.put_snapshot(&snapshot, 10).expect("snapshot");
    let actor = ReviewActorId::new("actor-retained-session").expect("actor");
    let authority = snapshot.review().authority().clone();
    store
        .grant_authority(
            snapshot.workspace(),
            &actor,
            ReviewAuthentication::UserSession,
            &authority,
            11,
        )
        .expect("grant");
    let comment = &snapshot.comments()[0];
    let request = ReviewActionRequest::new(
        snapshot.workspace().clone(),
        snapshot.revision(),
        actor,
        ReviewAuthentication::UserSession,
        authority,
        IdempotencyKey::new("retained-session-delivery").expect("key"),
        ReviewAction::SendCommentToAgent {
            comment_id: comment.id().clone(),
            expected_comment_revision: comment.revision(),
        },
    )
    .expect("request");
    let plan = external_plan(&request, b"exact retained-session payload");
    let ReviewActionAdmission::New(action) = store
        .prepare_external_action(&request, ApprovalPolicy::NotRequired, &plan, 20)
        .expect("prepare exact plan")
    else {
        panic!("new plan")
    };
    drop(store);
    let mut store = ReviewStore::open(private.path()).expect("reopen after plan admission");
    let (recovered, recovered_plan) = store
        .external_action(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            21,
        )
        .expect("recover plan")
        .expect("external action");
    assert_eq!(recovered.preview_id, action.preview_id);
    assert_eq!(recovered_plan, plan);
    let divergent = external_plan(&request, b"different payload");
    assert!(matches!(
        store.prepare_external_action(&request, ApprovalPolicy::NotRequired, &divergent, 22),
        Err(ReviewStoreError::Conflict("external_effect_plan"))
    ));
    let ReviewWriteAdmission::New(_) = store
        .start_write(&action.preview_id, action.request_digest, 23)
        .expect("write admission")
    else {
        panic!("new write")
    };
    let completed = store
        .complete_retained_session_delivery(
            &action.preview_id,
            action.request_digest,
            plan.transport_key(),
            true,
            24,
        )
        .expect("complete");
    assert_eq!(completed.outcome(), ReviewReceiptOutcome::Completed);
    let next = store
        .snapshot(snapshot.workspace())
        .expect("snapshot read")
        .expect("next snapshot");
    assert_eq!(next.revision(), revision(snapshot.revision().get() + 1));
    let delivered = next
        .comments()
        .iter()
        .find(|candidate| candidate.id() == comment.id())
        .expect("delivered comment");
    assert_eq!(delivered.revision(), revision(comment.revision().get() + 1));
    assert_eq!(delivered.agent_state(), CommentAgentState::Sent);
    assert_eq!(
        store
            .complete_retained_session_delivery(
                &action.preview_id,
                action.request_digest,
                plan.transport_key(),
                true,
                25,
            )
            .expect("completion replay"),
        completed
    );
    let raw = Connection::open(private.path()).expect("raw");
    let payload: Vec<u8> = raw
        .query_row(
            "SELECT payload FROM review_external_effect_plans WHERE preview_id=?1",
            [&action.preview_id],
            |row| row.get(0),
        )
        .expect("persisted payload");
    assert_eq!(payload, b"exact retained-session payload");
}

#[test]
fn external_acceptance_requires_a_plan_and_reserves_each_exact_target_once() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).unwrap();
    let snapshot = action_snapshot(false);
    store.put_snapshot(&snapshot, 10).unwrap();
    let actor = ReviewActorId::new("actor-reservation").unwrap();
    let authority = snapshot.review().authority().clone();
    store
        .grant_authority(
            snapshot.workspace(),
            &actor,
            ReviewAuthentication::UserSession,
            &authority,
            11,
        )
        .unwrap();
    let comment = &snapshot.comments()[0];
    let request = ReviewActionRequest::new(
        snapshot.workspace().clone(),
        snapshot.revision(),
        actor.clone(),
        ReviewAuthentication::UserSession,
        authority.clone(),
        IdempotencyKey::new("reservation-one").unwrap(),
        ReviewAction::SendCommentToAgent {
            comment_id: comment.id().clone(),
            expected_comment_revision: comment.revision(),
        },
    )
    .unwrap();
    assert!(matches!(
        store.prepare_action(&request, ApprovalPolicy::NotRequired, 20),
        Err(ReviewStoreError::InvalidField("external_effect_plan"))
    ));
    let plan = external_plan(&request, b"first exact payload");
    store
        .prepare_external_action(&request, ApprovalPolicy::NotRequired, &plan, 21)
        .unwrap();

    let duplicate = ReviewActionRequest::new(
        snapshot.workspace().clone(),
        snapshot.revision(),
        actor,
        ReviewAuthentication::UserSession,
        authority,
        IdempotencyKey::new("reservation-two").unwrap(),
        ReviewAction::SendCommentToAgent {
            comment_id: comment.id().clone(),
            expected_comment_revision: comment.revision(),
        },
    )
    .unwrap();
    let duplicate_plan = external_plan(&duplicate, b"second payload must not be admitted");
    assert!(matches!(
        store
            .prepare_external_action(&duplicate, ApprovalPolicy::NotRequired, &duplicate_plan, 22,),
        Err(ReviewStoreError::Conflict("external_effect_target"))
    ));
    let raw = Connection::open(private.path()).unwrap();
    assert_eq!(
        raw.query_row("SELECT count(*) FROM review_action_previews", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM review_external_effect_targets WHERE disposition='reserved'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        1
    );
}

#[test]
fn concurrent_external_keys_cannot_reserve_the_same_exact_target_twice() {
    let private = PrivateStore::new();
    let (snapshot, actor, authority) = {
        let mut store = ReviewStore::open(private.path()).unwrap();
        let snapshot = action_snapshot(false);
        store.put_snapshot(&snapshot, 10).unwrap();
        let actor = ReviewActorId::new("actor-concurrent-reservation").unwrap();
        let authority = snapshot.review().authority().clone();
        store
            .grant_authority(
                snapshot.workspace(),
                &actor,
                ReviewAuthentication::UserSession,
                &authority,
                11,
            )
            .unwrap();
        (snapshot, actor, authority)
    };
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|index| {
            let path = private.path().to_path_buf();
            let snapshot = snapshot.clone();
            let actor = actor.clone();
            let authority = authority.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let comment = &snapshot.comments()[0];
                let request = ReviewActionRequest::new(
                    snapshot.workspace().clone(),
                    snapshot.revision(),
                    actor,
                    ReviewAuthentication::UserSession,
                    authority,
                    IdempotencyKey::new(format!("concurrent-reservation-{index}")).unwrap(),
                    ReviewAction::SendCommentToAgent {
                        comment_id: comment.id().clone(),
                        expected_comment_revision: comment.revision(),
                    },
                )
                .unwrap();
                let plan = external_plan(&request, format!("payload-{index}").as_bytes());
                let mut store = ReviewStore::open(path).unwrap();
                barrier.wait();
                store.prepare_external_action(
                    &request,
                    ApprovalPolicy::NotRequired,
                    &plan,
                    20 + index,
                )
            })
        })
        .collect();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(ReviewActionAdmission::New(_))))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| {
                matches!(
                    outcome,
                    Err(ReviewStoreError::Conflict("external_effect_target"))
                )
            })
            .count(),
        1
    );
}

#[test]
fn pre_write_external_refusal_is_terminal_and_releases_the_undelivered_target() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).unwrap();
    let snapshot = action_snapshot(false);
    store.put_snapshot(&snapshot, 10).unwrap();
    let actor = ReviewActorId::new("actor-pre-write-refusal").unwrap();
    let authority = snapshot.review().authority().clone();
    store
        .grant_authority(
            snapshot.workspace(),
            &actor,
            ReviewAuthentication::UserSession,
            &authority,
            11,
        )
        .unwrap();
    let comment = &snapshot.comments()[0];
    let request = ReviewActionRequest::new(
        snapshot.workspace().clone(),
        snapshot.revision(),
        actor.clone(),
        ReviewAuthentication::UserSession,
        authority.clone(),
        IdempotencyKey::new("pre-write-refusal").unwrap(),
        ReviewAction::SendCommentToAgent {
            comment_id: comment.id().clone(),
            expected_comment_revision: comment.revision(),
        },
    )
    .unwrap();
    let plan = external_plan(&request, b"never submitted");
    let ReviewActionAdmission::New(action) = store
        .prepare_external_action(&request, ApprovalPolicy::NotRequired, &plan, 20)
        .unwrap()
    else {
        panic!("new")
    };
    store
        .revoke_authority(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            21,
        )
        .unwrap();
    let refused = store
        .refuse_external_action_not_started(&action.preview_id, action.request_digest, 22)
        .unwrap();
    assert_eq!(refused.outcome(), ReviewReceiptOutcome::Refused);
    assert_eq!(
        store
            .refuse_external_action_not_started(&action.preview_id, action.request_digest, 22)
            .unwrap(),
        refused
    );
    assert!(matches!(
        store
            .prepare_external_action(&request, ApprovalPolicy::NotRequired, &plan, 23)
            .unwrap(),
        ReviewActionAdmission::Replay(replayed) if replayed.receipt == refused
    ));
    assert!(matches!(
        store.start_write(&action.preview_id, action.request_digest, 23),
        Err(ReviewStoreError::Conflict("terminal_receipt"))
    ));

    store
        .reauthorize_authority_until(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            "pre-write-refusal-reauthorization",
            revision(1),
            24,
            100,
        )
        .unwrap();

    let retry = ReviewActionRequest::new(
        snapshot.workspace().clone(),
        snapshot.revision(),
        actor,
        ReviewAuthentication::UserSession,
        authority,
        IdempotencyKey::new("pre-write-refusal-retry").unwrap(),
        ReviewAction::SendCommentToAgent {
            comment_id: comment.id().clone(),
            expected_comment_revision: comment.revision(),
        },
    )
    .unwrap();
    let retry_plan = external_plan(&retry, b"new fence and exact retry");
    assert!(matches!(
        store
            .prepare_external_action(&retry, ApprovalPolicy::NotRequired, &retry_plan, 25,)
            .unwrap(),
        ReviewActionAdmission::New(_)
    ));
}

#[test]
fn pre_write_refusal_survives_expiry_and_an_unrelated_snapshot_advance() {
    let expired = PrivateStore::new();
    let mut store = ReviewStore::open(expired.path()).unwrap();
    let snapshot = action_snapshot(false);
    store.put_snapshot(&snapshot, 10).unwrap();
    let actor = ReviewActorId::new("actor-expired-refusal").unwrap();
    let authority = snapshot.review().authority().clone();
    store
        .grant_authority_until(
            snapshot.workspace(),
            &actor,
            ReviewAuthentication::UserSession,
            &authority,
            11,
            22,
        )
        .unwrap();
    let comment = &snapshot.comments()[0];
    let request = ReviewActionRequest::new(
        snapshot.workspace().clone(),
        snapshot.revision(),
        actor,
        ReviewAuthentication::UserSession,
        authority,
        IdempotencyKey::new("expired-pre-write-refusal").unwrap(),
        ReviewAction::SendCommentToAgent {
            comment_id: comment.id().clone(),
            expected_comment_revision: comment.revision(),
        },
    )
    .unwrap();
    let plan = external_plan(&request, b"expires while queued");
    let ReviewActionAdmission::New(action) = store
        .prepare_external_action(&request, ApprovalPolicy::NotRequired, &plan, 20)
        .unwrap()
    else {
        panic!("new")
    };
    assert_eq!(
        store
            .refuse_external_action_not_started(&action.preview_id, action.request_digest, 23)
            .unwrap()
            .outcome(),
        ReviewReceiptOutcome::Refused
    );

    let advanced = PrivateStore::new();
    let mut store = ReviewStore::open(advanced.path()).unwrap();
    let snapshot = action_snapshot(false);
    store.put_snapshot(&snapshot, 10).unwrap();
    let actor = ReviewActorId::new("actor-stale-refusal").unwrap();
    let authority = snapshot.review().authority().clone();
    store
        .grant_authority(
            snapshot.workspace(),
            &actor,
            ReviewAuthentication::UserSession,
            &authority,
            11,
        )
        .unwrap();
    let comment = &snapshot.comments()[0];
    let request = ReviewActionRequest::new(
        snapshot.workspace().clone(),
        snapshot.revision(),
        actor.clone(),
        ReviewAuthentication::UserSession,
        authority.clone(),
        IdempotencyKey::new("stale-pre-write-refusal").unwrap(),
        ReviewAction::SendCommentToAgent {
            comment_id: comment.id().clone(),
            expected_comment_revision: comment.revision(),
        },
    )
    .unwrap();
    let plan = external_plan(&request, b"snapshot advances while queued");
    let ReviewActionAdmission::New(action) = store
        .prepare_external_action(&request, ApprovalPolicy::NotRequired, &plan, 20)
        .unwrap()
    else {
        panic!("new")
    };
    let unrelated = ReviewActionRequest::new(
        snapshot.workspace().clone(),
        snapshot.revision(),
        actor,
        ReviewAuthentication::UserSession,
        authority,
        IdempotencyKey::new("advance-before-refusal").unwrap(),
        ReviewAction::AddComment {
            comment_id: ReviewCommentId::new("unrelated-before-refusal").unwrap(),
            anchor: comment.anchor().clone(),
            body: ReviewText::new("Unrelated review advance").unwrap(),
        },
    )
    .unwrap();
    store.execute_local_action(&unrelated, 21).unwrap();
    assert!(matches!(
        store.start_write(&action.preview_id, action.request_digest, 22),
        Err(ReviewStoreError::StaleRevision { .. })
    ));
    assert_eq!(
        store
            .refuse_external_action_not_started(&action.preview_id, action.request_digest, 23)
            .unwrap()
            .outcome(),
        ReviewReceiptOutcome::Refused
    );
}

#[test]
fn retained_session_terminal_delivery_rebases_over_unrelated_review_advance() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let snapshot = action_snapshot(false);
    store.put_snapshot(&snapshot, 10).expect("snapshot");
    let actor = ReviewActorId::new("actor-retained-conflict").expect("actor");
    let authority = snapshot.review().authority().clone();
    store
        .grant_authority(
            snapshot.workspace(),
            &actor,
            ReviewAuthentication::UserSession,
            &authority,
            11,
        )
        .expect("grant");
    let comment = &snapshot.comments()[0];
    let delivery = ReviewActionRequest::new(
        snapshot.workspace().clone(),
        snapshot.revision(),
        actor.clone(),
        ReviewAuthentication::UserSession,
        authority.clone(),
        IdempotencyKey::new("retained-conflict-delivery").unwrap(),
        ReviewAction::SendCommentToAgent {
            comment_id: comment.id().clone(),
            expected_comment_revision: comment.revision(),
        },
    )
    .unwrap();
    let plan = external_plan(&delivery, b"payload delivered before local conflict");
    let ReviewActionAdmission::New(action) = store
        .prepare_external_action(&delivery, ApprovalPolicy::NotRequired, &plan, 20)
        .unwrap()
    else {
        panic!("new")
    };
    store
        .start_write(&action.preview_id, action.request_digest, 21)
        .unwrap();
    let local = ReviewActionRequest::new(
        snapshot.workspace().clone(),
        snapshot.revision(),
        actor,
        ReviewAuthentication::UserSession,
        authority,
        IdempotencyKey::new("unrelated-local-comment").unwrap(),
        ReviewAction::AddComment {
            comment_id: ReviewCommentId::new("comment-unrelated").unwrap(),
            anchor: comment.anchor().clone(),
            body: ReviewText::new("Unrelated local change").unwrap(),
        },
    )
    .unwrap();
    store.execute_local_action(&local, 22).unwrap();
    let completed = store
        .complete_retained_session_delivery(
            &action.preview_id,
            action.request_digest,
            plan.transport_key(),
            true,
            23,
        )
        .unwrap();
    assert_eq!(completed.outcome(), ReviewReceiptOutcome::Completed);
    assert_eq!(
        completed.revision(),
        Some(revision(snapshot.revision().get() + 2))
    );
    let current = store.snapshot(snapshot.workspace()).unwrap().unwrap();
    assert_eq!(
        current
            .comments()
            .iter()
            .find(|candidate| candidate.id() == comment.id())
            .unwrap()
            .agent_state(),
        CommentAgentState::Sent
    );
}

#[test]
fn delivered_effect_on_a_mutated_target_is_terminal_evidence_not_a_replayable_write() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).unwrap();
    let snapshot = action_snapshot(false);
    store.put_snapshot(&snapshot, 10).unwrap();
    let actor = ReviewActorId::new("actor-mutated-delivery").unwrap();
    let authority = snapshot.review().authority().clone();
    store
        .grant_authority(
            snapshot.workspace(),
            &actor,
            ReviewAuthentication::UserSession,
            &authority,
            11,
        )
        .unwrap();
    let original = &snapshot.comments()[0];
    let request = ReviewActionRequest::new(
        snapshot.workspace().clone(),
        snapshot.revision(),
        actor,
        ReviewAuthentication::UserSession,
        authority,
        IdempotencyKey::new("mutated-delivery").unwrap(),
        ReviewAction::SendCommentToAgent {
            comment_id: original.id().clone(),
            expected_comment_revision: original.revision(),
        },
    )
    .unwrap();
    let plan = external_plan(&request, b"payload crossed the external boundary");
    let ReviewActionAdmission::New(action) = store
        .prepare_external_action(&request, ApprovalPolicy::NotRequired, &plan, 20)
        .unwrap()
    else {
        panic!("new")
    };
    store
        .start_write(&action.preview_id, action.request_digest, 21)
        .unwrap();

    let mutated_comment = ReviewComment::new(
        original.id().clone(),
        revision(original.revision().get() + 1),
        original.actor().clone(),
        ReviewText::new("Target changed while delivery was pending").unwrap(),
        original.anchor().clone(),
        original.agent_state(),
        original.unread(),
    );
    let advanced = ReviewSnapshot::new(
        snapshot.workspace().clone(),
        revision(snapshot.revision().get() + 1),
        snapshot.files().to_vec(),
        vec![mutated_comment],
        snapshot.proposals().to_vec(),
        snapshot.checks().to_vec(),
        snapshot.review().clone(),
        snapshot.pull_request().clone(),
        snapshot.delivery().clone(),
        snapshot.attention_events().to_vec(),
    )
    .unwrap();
    store.put_snapshot(&advanced, 22).unwrap();
    let terminal = store
        .complete_retained_session_delivery(
            &action.preview_id,
            action.request_digest,
            plan.transport_key(),
            true,
            23,
        )
        .unwrap();
    assert_eq!(terminal.outcome(), ReviewReceiptOutcome::Conflict);
    assert_eq!(terminal.current_revision(), Some(advanced.revision()));
    assert_eq!(
        store
            .complete_retained_session_delivery(
                &action.preview_id,
                action.request_digest,
                plan.transport_key(),
                true,
                24,
            )
            .unwrap(),
        terminal
    );
    drop(store);

    let reopened = ReviewStore::open(private.path()).expect("terminal evidence reopens");
    assert_eq!(
        reopened
            .receipt(
                request.workspace(),
                request.actor(),
                request.authentication(),
                request.authority(),
                request.idempotency_key(),
                25,
            )
            .unwrap(),
        Some(terminal)
    );
    let raw = Connection::open(private.path()).unwrap();
    assert_eq!(
        raw.query_row(
            "SELECT disposition FROM review_external_effect_targets WHERE preview_id=?1",
            [&action.preview_id],
            |row| row.get::<_, String>(0),
        )
        .unwrap(),
        "delivered_conflict"
    );
}

#[test]
fn action_target_is_resolved_against_the_authoritative_snapshot() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let request = seed(&mut store);
    let wrong_target_revision = request_variant(
        &request,
        "wrong-target-revision",
        request.actor().as_str(),
        request.expected_revision(),
        revision(8),
    );
    assert!(matches!(
        store.prepare_action(&wrong_target_revision, ApprovalPolicy::NotRequired, 20),
        Err(ReviewStoreError::Protocol(_))
    ));
}

#[test]
fn stale_revision_actor_isolation_and_authorization_are_closed() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let request = seed(&mut store);
    let stale = request_variant(
        &request,
        "stale",
        request.actor().as_str(),
        revision(8),
        revision(7),
    );
    assert!(
        matches!(store.prepare_action(&stale, ApprovalPolicy::NotRequired, 20),
        Err(ReviewStoreError::StaleRevision { current }) if current == revision(9))
    );

    let unauthorized = request_variant(&request, "other", "actor-2", revision(8), revision(7));
    assert!(matches!(
        store.prepare_action(&unauthorized, ApprovalPolicy::NotRequired, 21),
        Err(ReviewStoreError::Unauthorized)
    ));
    store
        .prepare_action(&request, ApprovalPolicy::NotRequired, 22)
        .expect("authorized");
    assert!(matches!(
        store.receipt(
            request.workspace(),
            unauthorized.actor(),
            unauthorized.authentication(),
            unauthorized.authority(),
            request.idempotency_key(),
            23,
        ),
        Err(ReviewStoreError::Unauthorized)
    ));
}

#[test]
fn provider_observation_never_becomes_local_mutation_authority() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let snapshot = snapshot();
    let request = request();
    store.put_snapshot(&snapshot, 10).expect("snapshot");
    store
        .record_provider_observation(
            request.workspace(),
            "provider-session-1",
            revision(4),
            br#"{"status":"connected"}"#,
            11,
        )
        .expect("provider observation");
    store
        .record_provider_observation(
            request.workspace(),
            "provider-session-1",
            revision(4),
            br#"{"status":"connected"}"#,
            12,
        )
        .expect("same observation is idempotent");
    assert!(matches!(
        store.record_provider_observation(
            request.workspace(),
            "provider-session-1",
            revision(4),
            br#"{"status":"different"}"#,
            13,
        ),
        Err(ReviewStoreError::Conflict("provider_observation_revision"))
    ));
    assert!(matches!(
        store.prepare_action(&request, ApprovalPolicy::NotRequired, 14),
        Err(ReviewStoreError::Unauthorized)
    ));
    assert!(matches!(
        store.grant_authority(
            request.workspace(),
            request.actor(),
            ReviewAuthentication::ProviderSession,
            request.authority(),
            15
        ),
        Err(ReviewStoreError::Unauthorized)
    ));
}

#[test]
fn approval_and_ambiguous_receipt_reconcile_after_restart_without_replay() {
    let private = PrivateStore::new();
    let (workspace, actor, authentication, authority, key, preview_id, digest, accepted) = {
        let mut store = ReviewStore::open(private.path()).expect("open");
        let request = seed(&mut store);
        let ReviewActionAdmission::New(action) = store
            .prepare_action(&request, ApprovalPolicy::Required, 20)
            .expect("preview")
        else {
            panic!("new");
        };
        assert!(matches!(
            store.mark_ambiguous(&action.preview_id, action.request_digest, 21),
            Err(ReviewStoreError::ApprovalRequired)
        ));
        let approver = ReviewActorId::new("reviewer-1").expect("approver");
        store
            .grant_authority(
                request.workspace(),
                &approver,
                ReviewAuthentication::UserSession,
                request.authority(),
                21,
            )
            .expect("approver authority");
        let approval = ReviewApprovalDocument::new(
            &action.preview_id,
            request.workspace().clone(),
            approver,
            ReviewAuthentication::UserSession,
            request.authority().clone(),
            action.request_digest,
            request.expected_revision(),
            ReviewApprovalDecision::Approved,
            100,
        )
        .expect("approval document");
        let approved = store.decide_action(&approval, 22).expect("approve");
        assert!(approved.approved);
        let ReviewWriteAdmission::New(started) = store
            .start_write(&action.preview_id, action.request_digest, 23)
            .expect("durable write admission")
        else {
            panic!("first admission must be new");
        };
        assert_eq!(started.write_admitted_at_ms, Some(23));
        let unknown = store
            .mark_ambiguous(&action.preview_id, action.request_digest, 24)
            .expect("persist unknown");
        assert_eq!(unknown.outcome().as_str(), "unknown");
        (
            request.workspace().clone(),
            request.actor().clone(),
            request.authentication(),
            request.authority().clone(),
            request.idempotency_key().clone(),
            action.preview_id,
            action.request_digest,
            action.receipt,
        )
    };
    let mut reopened = ReviewStore::open(private.path()).expect("reopen");
    let reconciled = reopened
        .receipt(&workspace, &actor, authentication, &authority, &key, 25)
        .expect("lookup")
        .expect("receipt");
    assert!(
        reopened
            .non_rerun_receipt(&workspace, &actor, authentication, &authority, &key, 25)
            .expect("generic rerun exclusion")
            .is_none()
    );
    assert_eq!(reconciled.outcome().as_str(), "unknown");
    assert_eq!(reconciled.receipt_id(), accepted.receipt_id());
    assert_eq!(
        reopened
            .mark_ambiguous(&preview_id, digest, 25)
            .expect("no replay"),
        reconciled
    );
    let next_document = String::from_utf8(SNAPSHOT.to_vec())
        .expect("fixture text")
        .replace("\"revision\":9,\"schema\"", "\"revision\":10,\"schema\"");
    let next = decode_review_snapshot(next_document.as_bytes()).expect("next snapshot");
    reopened
        .put_snapshot(&next, 26)
        .expect("authoritative result");
    let completed = ReviewActionReceipt::new(
        reconciled.receipt_id().clone(),
        reconciled.idempotency_key().clone(),
        reconciled.action_id().clone(),
        reconciled.actor().clone(),
        ReviewReceiptOutcome::Completed,
        Some(revision(10)),
        None,
        ReviewReconciliation::Final,
    )
    .expect("completed receipt");
    assert_eq!(
        reopened
            .reconcile_receipt(&preview_id, digest, &completed, 27)
            .expect("reconcile final"),
        completed
    );
    assert_eq!(
        reopened
            .reconcile_receipt(&preview_id, digest, &completed, 28)
            .expect("final retry is a read"),
        completed
    );
    let refused = ReviewActionReceipt::new(
        reconciled.receipt_id().clone(),
        reconciled.idempotency_key().clone(),
        reconciled.action_id().clone(),
        reconciled.actor().clone(),
        ReviewReceiptOutcome::Refused,
        None,
        None,
        ReviewReconciliation::Final,
    )
    .expect("refused receipt");
    assert!(matches!(
        reopened.reconcile_receipt(&preview_id, digest, &refused, 29),
        Err(ReviewStoreError::Conflict("terminal_receipt"))
    ));
}

#[test]
fn approval_is_authenticated_exact_bounded_and_expiring() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let request = seed(&mut store);
    let ReviewActionAdmission::New(action) = store
        .prepare_action(&request, ApprovalPolicy::Required, 20)
        .expect("preview")
    else {
        panic!("new");
    };
    let approver = ReviewActorId::new("reviewer-ungranted").expect("approver");
    let approval = ReviewApprovalDocument::new(
        &action.preview_id,
        request.workspace().clone(),
        approver.clone(),
        ReviewAuthentication::UserSession,
        request.authority().clone(),
        action.request_digest,
        request.expected_revision(),
        ReviewApprovalDecision::Approved,
        30,
    )
    .expect("approval");
    assert!(matches!(
        store.decide_action(&approval, 21),
        Err(ReviewStoreError::Unauthorized)
    ));
    let missing = ReviewApprovalDocument::new(
        "preview-missing",
        request.workspace().clone(),
        approver.clone(),
        ReviewAuthentication::UserSession,
        request.authority().clone(),
        action.request_digest,
        request.expected_revision(),
        ReviewApprovalDecision::Approved,
        30,
    )
    .expect("missing preview approval");
    let wrong_binding = ReviewApprovalDocument::new(
        &action.preview_id,
        request.workspace().clone(),
        approver.clone(),
        ReviewAuthentication::UserSession,
        request.authority().clone(),
        [7; 32],
        request.expected_revision(),
        ReviewApprovalDecision::Approved,
        30,
    )
    .expect("wrong binding approval");
    assert!(matches!(
        store.decide_action(&missing, 21),
        Err(ReviewStoreError::Unauthorized)
    ));
    assert!(matches!(
        store.decide_action(&wrong_binding, 21),
        Err(ReviewStoreError::Unauthorized)
    ));
    store
        .grant_authority(
            request.workspace(),
            &approver,
            ReviewAuthentication::UserSession,
            request.authority(),
            22,
        )
        .expect("grant");
    assert!(matches!(
        store.decide_action(&approval, 30),
        Err(ReviewStoreError::InvalidField("approval_expired"))
    ));
    let wrong_digest = ReviewApprovalDocument::new(
        &action.preview_id,
        request.workspace().clone(),
        approver.clone(),
        ReviewAuthentication::UserSession,
        request.authority().clone(),
        [7; 32],
        request.expected_revision(),
        ReviewApprovalDecision::Approved,
        40,
    )
    .expect("wrong digest document");
    assert!(matches!(
        store.decide_action(&wrong_digest, 23),
        Err(ReviewStoreError::Conflict("approval_binding"))
    ));
    assert!(
        ReviewApprovalDocument::new(
            &action.preview_id,
            request.workspace().clone(),
            ReviewActorId::new("provider").expect("actor"),
            ReviewAuthentication::ProviderSession,
            request.authority().clone(),
            action.request_digest,
            request.expected_revision(),
            ReviewApprovalDecision::Approved,
            40,
        )
        .is_err()
    );
    let refusal = ReviewApprovalDocument::new(
        &action.preview_id,
        request.workspace().clone(),
        approver,
        ReviewAuthentication::UserSession,
        request.authority().clone(),
        action.request_digest,
        request.expected_revision(),
        ReviewApprovalDecision::Refused,
        40,
    )
    .expect("refusal document");
    let refused = store.decide_action(&refusal, 24).expect("refusal");
    assert!(!refused.approved);
    assert_eq!(refused.receipt.outcome(), ReviewReceiptOutcome::Refused);
    let next_document = String::from_utf8(SNAPSHOT.to_vec())
        .expect("fixture")
        .replace("\"revision\":9,\"schema\"", "\"revision\":10,\"schema\"");
    let next = decode_review_snapshot(next_document.as_bytes()).expect("next snapshot");
    store.put_snapshot(&next, 25).expect("advance snapshot");
    assert!(matches!(
        store.prepare_action(&request, ApprovalPolicy::Required, 26),
        Ok(ReviewActionAdmission::Replay(value)) if value.receipt == refused.receipt
    ));
    store
        .revoke_authority(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            27,
        )
        .expect("revoke requester");
    assert!(matches!(
        store.prepare_action(&request, ApprovalPolicy::Required, 28),
        Err(ReviewStoreError::Unauthorized)
    ));
}

#[test]
fn authorized_scope_cannot_observe_a_foreign_preview() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let local_request = seed(&mut store);
    let foreign_document = String::from_utf8(SNAPSHOT.to_vec())
        .expect("fixture")
        .replace(
            "\"id\":\"wc_user_1\",\"kind\":\"user_workspace\"",
            "\"id\":\"wc_user_2\",\"kind\":\"user_workspace\"",
        );
    let foreign_snapshot =
        decode_review_snapshot(foreign_document.as_bytes()).expect("foreign snapshot");
    store
        .put_snapshot(&foreign_snapshot, 12)
        .expect("foreign snapshot persisted");
    let foreign_request = ReviewActionRequest::new(
        foreign_snapshot.workspace().clone(),
        local_request.expected_revision(),
        local_request.actor().clone(),
        local_request.authentication(),
        local_request.authority().clone(),
        IdempotencyKey::new("foreign-preview").expect("foreign key"),
        local_request.action().clone(),
    )
    .expect("foreign request");
    store
        .grant_authority(
            foreign_request.workspace(),
            foreign_request.actor(),
            foreign_request.authentication(),
            foreign_request.authority(),
            13,
        )
        .expect("foreign request authority");
    let ReviewActionAdmission::New(foreign_action) = store
        .prepare_action(&foreign_request, ApprovalPolicy::NotRequired, 14)
        .expect("foreign preview")
    else {
        panic!("new foreign preview");
    };
    store
        .start_write(
            &foreign_action.preview_id,
            foreign_action.request_digest,
            15,
        )
        .expect("foreign write admission");

    let approver = ReviewActorId::new("local-reviewer").expect("approver");
    store
        .grant_authority(
            local_request.workspace(),
            &approver,
            ReviewAuthentication::UserSession,
            local_request.authority(),
            16,
        )
        .expect("local approval authority");
    let foreign_approval = ReviewApprovalDocument::new(
        &foreign_action.preview_id,
        local_request.workspace().clone(),
        approver.clone(),
        ReviewAuthentication::UserSession,
        local_request.authority().clone(),
        foreign_action.request_digest,
        foreign_request.expected_revision(),
        ReviewApprovalDecision::Approved,
        30,
    )
    .expect("foreign approval probe");
    let missing_approval = ReviewApprovalDocument::new(
        "preview-missing",
        local_request.workspace().clone(),
        approver,
        ReviewAuthentication::UserSession,
        local_request.authority().clone(),
        foreign_action.request_digest,
        foreign_request.expected_revision(),
        ReviewApprovalDecision::Approved,
        30,
    )
    .expect("missing approval probe");
    assert!(matches!(
        store.decide_action(&foreign_approval, 17),
        Err(ReviewStoreError::NotFound)
    ));
    assert!(matches!(
        store.decide_action(&missing_approval, 17),
        Err(ReviewStoreError::NotFound)
    ));

    let verifier = ReviewActorId::new("local-adapter").expect("verifier");
    store
        .grant_authority(
            local_request.workspace(),
            &verifier,
            ReviewAuthentication::ServiceIdentity,
            local_request.authority(),
            18,
        )
        .expect("local evidence authority");
    for preview_id in [&foreign_action.preview_id[..], "preview-missing"] {
        assert!(matches!(
            store.record_completion_evidence(
                local_request.workspace(),
                preview_id,
                foreign_action.request_digest,
                &verifier,
                ReviewAuthentication::ServiceIdentity,
                local_request.authority(),
                revision(10),
                "foreign-evidence-probe",
                b"scope-confined evidence",
                19,
            ),
            Err(ReviewStoreError::NotFound)
        ));
    }
}

#[test]
fn approval_rechecks_the_current_snapshot_revision_transactionally() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let request = seed(&mut store);
    let ReviewActionAdmission::New(action) = store
        .prepare_action(&request, ApprovalPolicy::Required, 20)
        .expect("preview")
    else {
        panic!("new");
    };
    let approver = ReviewActorId::new("reviewer-1").expect("approver");
    store
        .grant_authority(
            request.workspace(),
            &approver,
            ReviewAuthentication::UserSession,
            request.authority(),
            21,
        )
        .expect("grant");
    let approval = ReviewApprovalDocument::new(
        &action.preview_id,
        request.workspace().clone(),
        approver,
        ReviewAuthentication::UserSession,
        request.authority().clone(),
        action.request_digest,
        request.expected_revision(),
        ReviewApprovalDecision::Approved,
        100,
    )
    .expect("approval");
    let next_document = String::from_utf8(SNAPSHOT.to_vec())
        .expect("fixture text")
        .replace("\"revision\":9,\"schema\"", "\"revision\":10,\"schema\"");
    let next = decode_review_snapshot(next_document.as_bytes()).expect("next snapshot");
    store.put_snapshot(&next, 22).expect("advance snapshot");
    assert!(matches!(
        store.decide_action(&approval, 23),
        Err(ReviewStoreError::StaleRevision { current }) if current == revision(10)
    ));
}

#[test]
fn reconciled_revisions_match_authoritative_state() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let request = seed(&mut store);
    let ReviewActionAdmission::New(action) = store
        .prepare_action(&request, ApprovalPolicy::NotRequired, 20)
        .expect("preview")
    else {
        panic!("new");
    };
    let conflict = |current| {
        ReviewActionReceipt::new(
            action.receipt.receipt_id().clone(),
            action.receipt.idempotency_key().clone(),
            action.receipt.action_id().clone(),
            action.receipt.actor().clone(),
            ReviewReceiptOutcome::Conflict,
            None,
            Some(revision(current)),
            ReviewReconciliation::Final,
        )
        .expect("conflict")
    };
    store
        .start_write(&action.preview_id, action.request_digest, 21)
        .expect("durable write admission");
    assert!(matches!(
        store.reconcile_receipt(&action.preview_id, action.request_digest, &conflict(8), 22),
        Err(ReviewStoreError::Conflict("current_revision"))
    ));
    assert_eq!(
        store
            .reconcile_receipt(&action.preview_id, action.request_digest, &conflict(9), 23)
            .expect("current conflict")
            .current_revision(),
        Some(revision(9))
    );
}

#[test]
fn delayed_completion_uses_the_retained_exact_result_snapshot() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let request = seed(&mut store);
    let ReviewActionAdmission::New(action) = store
        .prepare_action(&request, ApprovalPolicy::NotRequired, 20)
        .expect("preview")
    else {
        panic!("new");
    };
    store
        .start_write(&action.preview_id, action.request_digest, 21)
        .expect("durable write admission");
    let unknown = store
        .mark_ambiguous(&action.preview_id, action.request_digest, 22)
        .expect("ambiguous result");
    for (next_revision, recorded_at_ms) in [(10_u64, 23_i64), (11, 24)] {
        let document = String::from_utf8(SNAPSHOT.to_vec())
            .expect("fixture")
            .replace(
                "\"revision\":9,\"schema\"",
                &format!("\"revision\":{next_revision},\"schema\""),
            );
        let next = decode_review_snapshot(document.as_bytes()).expect("advanced snapshot");
        store
            .put_snapshot(&next, recorded_at_ms)
            .expect("advance snapshot");
    }
    let completed = ReviewActionReceipt::new(
        unknown.receipt_id().clone(),
        unknown.idempotency_key().clone(),
        unknown.action_id().clone(),
        unknown.actor().clone(),
        ReviewReceiptOutcome::Completed,
        Some(revision(10)),
        None,
        ReviewReconciliation::Final,
    )
    .expect("completed receipt");
    assert_eq!(
        store
            .reconcile_receipt(&action.preview_id, action.request_digest, &completed, 25)
            .expect("retained result snapshot proves delayed completion"),
        completed
    );
}

#[test]
fn snapshot_and_normalized_action_corruption_fail_after_reopen() {
    let snapshot_private = PrivateStore::new();
    let workspace = {
        let mut store = ReviewStore::open(snapshot_private.path()).expect("open");
        let snapshot = snapshot();
        store.put_snapshot(&snapshot, 10).expect("snapshot");
        snapshot.workspace().clone()
    };
    let connection = Connection::open(snapshot_private.path()).expect("raw open");
    connection
        .execute(
            "UPDATE review_snapshots SET document_digest=zeroblob(32)",
            [],
        )
        .expect("corrupt digest");
    drop(connection);
    let reopened = ReviewStore::open(snapshot_private.path()).expect("reopen");
    assert!(matches!(
        reopened.snapshot(&workspace),
        Err(ReviewStoreError::Corrupt("snapshot_digest"))
    ));

    let action_private = PrivateStore::new();
    let request = {
        let mut store = ReviewStore::open(action_private.path()).expect("open");
        let request = seed(&mut store);
        store
            .prepare_action(&request, ApprovalPolicy::NotRequired, 20)
            .expect("action");
        request
    };
    let connection = Connection::open(action_private.path()).expect("raw open");
    connection
        .execute(
            "UPDATE review_action_previews SET action_kind='approve_review'",
            [],
        )
        .expect("corrupt projection");
    drop(connection);
    let reopened = ReviewStore::open(action_private.path()).expect("reopen");
    assert!(matches!(
        reopened.receipt(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            21,
        ),
        Err(ReviewStoreError::Corrupt("request_digest"))
    ));
}

#[test]
fn approval_projection_corruption_cannot_authorize_after_reopen() {
    let private = PrivateStore::new();
    let (request, preview_id) = {
        let mut store = ReviewStore::open(private.path()).expect("open");
        let request = seed(&mut store);
        let ReviewActionAdmission::New(action) = store
            .prepare_action(&request, ApprovalPolicy::Required, 20)
            .expect("preview")
        else {
            panic!("new");
        };
        let approver = ReviewActorId::new("reviewer-1").expect("approver");
        store
            .grant_authority(
                request.workspace(),
                &approver,
                ReviewAuthentication::UserSession,
                request.authority(),
                21,
            )
            .expect("grant");
        let approval = ReviewApprovalDocument::new(
            &action.preview_id,
            request.workspace().clone(),
            approver,
            ReviewAuthentication::UserSession,
            request.authority().clone(),
            action.request_digest,
            request.expected_revision(),
            ReviewApprovalDecision::Approved,
            100,
        )
        .expect("approval");
        store.decide_action(&approval, 22).expect("decide");
        (request, action.preview_id)
    };
    let connection = Connection::open(private.path()).expect("raw open");
    connection
        .execute(
            "UPDATE review_action_approvals SET authority_id=?1 WHERE preview_id=?2",
            params!["forged-authority", preview_id],
        )
        .expect("corrupt approval projection");
    drop(connection);
    let reopened = ReviewStore::open(private.path()).expect("reopen");
    assert!(matches!(
        reopened.receipt(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            23,
        ),
        Err(ReviewStoreError::Corrupt("approval_projection"))
    ));
}

#[test]
fn concurrent_identical_key_has_one_new_admission_and_one_replay() {
    let private = PrivateStore::new();
    let request = {
        let mut store = ReviewStore::open(private.path()).expect("open");
        seed(&mut store)
    };
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|index| {
            let path = private.path().to_path_buf();
            let request = request.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut store = ReviewStore::open(path).expect("thread open");
                barrier.wait();
                store
                    .prepare_action(&request, ApprovalPolicy::NotRequired, 30 + index)
                    .expect("concurrent admission")
            })
        })
        .collect();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|v| matches!(v, ReviewActionAdmission::New(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|v| matches!(v, ReviewActionAdmission::Replay(_)))
            .count(),
        1
    );
    let receipts: Vec<_> = outcomes
        .into_iter()
        .map(|value| match value {
            ReviewActionAdmission::New(value) | ReviewActionAdmission::Replay(value) => {
                value.receipt
            }
        })
        .collect();
    assert_eq!(receipts[0], receipts[1]);
}

#[test]
fn concurrent_start_write_has_one_admission_and_one_explicit_replay() {
    let private = PrivateStore::new();
    let action = {
        let mut store = ReviewStore::open(private.path()).expect("open");
        let request = seed(&mut store);
        let ReviewActionAdmission::New(action) = store
            .prepare_action(&request, ApprovalPolicy::NotRequired, 20)
            .expect("preview")
        else {
            panic!("new");
        };
        action
    };
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|index| {
            let path = private.path().to_path_buf();
            let preview_id = action.preview_id.clone();
            let request_digest = action.request_digest;
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut store = ReviewStore::open(path).expect("thread open");
                barrier.wait();
                store
                    .start_write(&preview_id, request_digest, 30 + index)
                    .expect("write admission")
            })
        })
        .collect();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| matches!(value, ReviewWriteAdmission::New(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| matches!(value, ReviewWriteAdmission::Replay(_)))
            .count(),
        1
    );
}

#[test]
fn concurrent_same_key_with_different_body_has_one_admission_and_one_conflict() {
    let private = PrivateStore::new();
    let (user_request, service_request) = {
        let mut store = ReviewStore::open(private.path()).expect("open");
        let user_request = seed(&mut store);
        store
            .grant_authority(
                user_request.workspace(),
                user_request.actor(),
                ReviewAuthentication::ServiceIdentity,
                user_request.authority(),
                12,
            )
            .expect("service grant");
        let service_request = ReviewActionRequest::new(
            user_request.workspace().clone(),
            user_request.expected_revision(),
            user_request.actor().clone(),
            ReviewAuthentication::ServiceIdentity,
            user_request.authority().clone(),
            user_request.idempotency_key().clone(),
            user_request.action().clone(),
        )
        .expect("service request");
        (user_request, service_request)
    };
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = [user_request, service_request]
        .into_iter()
        .enumerate()
        .map(|(index, request)| {
            let path = private.path().to_path_buf();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut store = ReviewStore::open(path).expect("thread open");
                barrier.wait();
                store.prepare_action(
                    &request,
                    ApprovalPolicy::NotRequired,
                    40 + i64::try_from(index).expect("index"),
                )
            })
        })
        .collect();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect();
    assert_eq!(outcomes.iter().filter(|value| value.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| matches!(value, Err(ReviewStoreError::Conflict("idempotency_key"))))
            .count(),
        1
    );
}

#[test]
fn policy_is_digest_bound_and_normalized_corruption_fails_closed() {
    let private = PrivateStore::new();
    let (request, action) = {
        let mut store = ReviewStore::open(private.path()).expect("open");
        let request = seed(&mut store);
        let ReviewActionAdmission::New(action) = store
            .prepare_action(&request, ApprovalPolicy::Required, 20)
            .expect("preview")
        else {
            panic!("new");
        };
        assert!(matches!(
            store.prepare_action(&request, ApprovalPolicy::NotRequired, 21),
            Err(ReviewStoreError::Conflict("idempotency_key"))
        ));
        (request, action)
    };
    let connection = Connection::open(private.path()).expect("raw open");
    connection
        .execute(
            "UPDATE review_action_previews SET approval_required=0 WHERE preview_id=?1",
            [&action.preview_id],
        )
        .expect("corrupt duplicated policy flag");
    drop(connection);
    let reopened = ReviewStore::open(private.path()).expect("reopen");
    assert!(matches!(
        reopened.receipt(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            22,
        ),
        Err(ReviewStoreError::Corrupt("approval_requirement"))
    ));
}

#[test]
fn write_admission_expires_before_start_but_reconciliation_survives_after_start() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let request = seed(&mut store);
    let ReviewActionAdmission::New(action) = store
        .prepare_action(&request, ApprovalPolicy::Required, 20)
        .expect("preview")
    else {
        panic!("new");
    };
    let approver = ReviewActorId::new("reviewer-1").expect("approver");
    store
        .grant_authority(
            request.workspace(),
            &approver,
            ReviewAuthentication::UserSession,
            request.authority(),
            21,
        )
        .expect("approval authority");
    let approval = ReviewApprovalDocument::new(
        &action.preview_id,
        request.workspace().clone(),
        approver,
        ReviewAuthentication::UserSession,
        request.authority().clone(),
        action.request_digest,
        request.expected_revision(),
        ReviewApprovalDecision::Approved,
        30,
    )
    .expect("approval");
    store.decide_action(&approval, 22).expect("decide");
    store
        .start_write(&action.preview_id, action.request_digest, 25)
        .expect("start while approval is fresh");
    assert!(matches!(
        store.start_write(&action.preview_id, action.request_digest, 35),
        Ok(ReviewWriteAdmission::Replay(_))
    ));
    let unknown = store
        .mark_ambiguous(&action.preview_id, action.request_digest, 35)
        .expect("ambiguity survives approval expiry");
    let completed = ReviewActionReceipt::new(
        unknown.receipt_id().clone(),
        unknown.idempotency_key().clone(),
        unknown.action_id().clone(),
        unknown.actor().clone(),
        ReviewReceiptOutcome::Completed,
        Some(revision(10)),
        None,
        ReviewReconciliation::Final,
    )
    .expect("completed");
    assert!(matches!(
        store.reconcile_receipt(&action.preview_id, action.request_digest, &completed, 36),
        Err(ReviewStoreError::Conflict("result_revision"))
    ));
    let verifier = ReviewActorId::new("adapter-1").expect("verifier");
    assert!(matches!(
        store.record_completion_evidence(
            request.workspace(),
            "preview-missing",
            action.request_digest,
            &verifier,
            ReviewAuthentication::ServiceIdentity,
            request.authority(),
            revision(10),
            "ci-result-missing",
            b"not observable without authority",
            36,
        ),
        Err(ReviewStoreError::Unauthorized)
    ));
    assert!(matches!(
        store.record_completion_evidence(
            request.workspace(),
            &action.preview_id,
            [7; 32],
            &verifier,
            ReviewAuthentication::ServiceIdentity,
            request.authority(),
            revision(10),
            "ci-result-wrong-binding",
            b"not observable without authority",
            36,
        ),
        Err(ReviewStoreError::Unauthorized)
    ));
    store
        .grant_authority(
            request.workspace(),
            &verifier,
            ReviewAuthentication::ServiceIdentity,
            request.authority(),
            36,
        )
        .expect("verifier authority");
    store
        .record_completion_evidence(
            request.workspace(),
            &action.preview_id,
            action.request_digest,
            &verifier,
            ReviewAuthentication::ServiceIdentity,
            request.authority(),
            revision(10),
            "ci-result-1",
            b"verified exact CI result",
            37,
        )
        .expect("verified evidence");
    assert!(matches!(
        store.record_completion_evidence(
            request.workspace(),
            &action.preview_id,
            action.request_digest,
            &verifier,
            ReviewAuthentication::ServiceIdentity,
            request.authority(),
            revision(10),
            "ci-result-1",
            b"different claimed result",
            38,
        ),
        Err(ReviewStoreError::Conflict("completion_evidence"))
    ));
    let raw = Connection::open(private.path()).expect("raw open");
    let original_digest: Vec<u8> = raw
        .query_row(
            "SELECT evidence_digest FROM review_completion_evidence WHERE preview_id=?1",
            [&action.preview_id],
            |row| row.get(0),
        )
        .expect("evidence digest");
    raw.execute(
        "UPDATE review_completion_evidence SET evidence_digest=zeroblob(32) WHERE preview_id=?1",
        [&action.preview_id],
    )
    .expect("corrupt evidence");
    drop(raw);
    assert!(matches!(
        store.reconcile_receipt(&action.preview_id, action.request_digest, &completed, 39),
        Err(ReviewStoreError::Corrupt("completion_evidence"))
    ));
    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.execute(
        "UPDATE review_completion_evidence SET evidence_digest=?1 WHERE preview_id=?2",
        params![original_digest, action.preview_id],
    )
    .expect("restore evidence");
    drop(raw);
    assert_eq!(
        store
            .reconcile_receipt(&action.preview_id, action.request_digest, &completed, 40)
            .expect("evidence-bound completion"),
        completed
    );
    drop(store);
    let mut reopened = ReviewStore::open(private.path()).expect("reopen");
    assert_eq!(
        reopened
            .reconcile_receipt(&action.preview_id, action.request_digest, &completed, 41)
            .expect("terminal retry after reopen"),
        completed
    );

    let raw = Connection::open(private.path()).expect("raw evidence time corruption");
    let final_evidence_observed_at_ms: i64 = raw
        .query_row(
            "SELECT observed_at_ms FROM review_completion_evidence WHERE preview_id=?1",
            [&action.preview_id],
            |row| row.get(0),
        )
        .expect("final evidence observed time");
    raw.execute(
        "UPDATE review_completion_evidence SET observed_at_ms=?1 WHERE preview_id=?2",
        params![final_evidence_observed_at_ms + 1, action.preview_id],
    )
    .expect("corrupt finalized evidence observed time");
    drop(raw);
    assert!(matches!(
        reopened.receipt(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            42,
        ),
        Err(ReviewStoreError::Corrupt("completion_evidence"))
    ));
    let raw = Connection::open(private.path()).expect("raw evidence time restore");
    raw.execute(
        "UPDATE review_completion_evidence SET observed_at_ms=?1 WHERE preview_id=?2",
        params![final_evidence_observed_at_ms, action.preview_id],
    )
    .expect("restore finalized evidence observed time");
    drop(raw);

    let raw = Connection::open(private.path()).expect("raw evidence corruption");
    let final_evidence_digest: Vec<u8> = raw
        .query_row(
            "SELECT evidence_digest FROM review_completion_evidence WHERE preview_id=?1",
            [&action.preview_id],
            |row| row.get(0),
        )
        .expect("final evidence digest");
    raw.execute(
        "UPDATE review_completion_evidence SET evidence_digest=zeroblob(32) WHERE preview_id=?1",
        [&action.preview_id],
    )
    .expect("corrupt finalized evidence");
    drop(raw);
    assert!(matches!(
        reopened.receipt(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            42,
        ),
        Err(ReviewStoreError::Corrupt("completion_evidence"))
    ));
    let raw = Connection::open(private.path()).expect("raw evidence restore");
    raw.execute(
        "UPDATE review_completion_evidence SET evidence_digest=?1 WHERE preview_id=?2",
        params![final_evidence_digest, action.preview_id],
    )
    .expect("restore finalized evidence");
    drop(raw);
    assert_eq!(
        reopened
            .receipt(
                request.workspace(),
                request.actor(),
                request.authentication(),
                request.authority(),
                request.idempotency_key(),
                43,
            )
            .expect("restored finalized evidence")
            .expect("completed receipt"),
        completed
    );
    let raw = Connection::open(private.path()).expect("raw evidence deletion");
    raw.execute(
        "DELETE FROM review_completion_evidence WHERE preview_id=?1",
        [&action.preview_id],
    )
    .expect("delete finalized evidence");
    drop(raw);
    assert!(matches!(
        reopened.receipt(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            44,
        ),
        Err(ReviewStoreError::Corrupt("completion_basis"))
    ));
    drop(reopened);
    let mut reopened = ReviewStore::open(private.path()).expect("reopen without evidence");
    assert!(matches!(
        reopened.reconcile_receipt(&action.preview_id, action.request_digest, &completed, 45),
        Err(ReviewStoreError::Corrupt("completion_basis"))
    ));

    let second_request = request_variant(
        &request,
        "idem-expired-start",
        request.actor().as_str(),
        revision(9),
        revision(7),
    );
    let ReviewActionAdmission::New(second) = reopened
        .prepare_action(&second_request, ApprovalPolicy::Required, 42)
        .expect("second preview")
    else {
        panic!("new");
    };
    let second_approver = ReviewActorId::new("reviewer-2").expect("approver");
    reopened
        .grant_authority(
            request.workspace(),
            &second_approver,
            ReviewAuthentication::UserSession,
            request.authority(),
            42,
        )
        .expect("approver grant");
    let second_approval = ReviewApprovalDocument::new(
        &second.preview_id,
        request.workspace().clone(),
        second_approver,
        ReviewAuthentication::UserSession,
        request.authority().clone(),
        second.request_digest,
        revision(9),
        ReviewApprovalDecision::Approved,
        47,
    )
    .expect("approval");
    reopened
        .decide_action(&second_approval, 43)
        .expect("decide");
    assert!(matches!(
        reopened.start_write(&second.preview_id, second.request_digest, 47),
        Err(ReviewStoreError::ApprovalRequired)
    ));
}

#[test]
fn expired_or_revoked_grants_refuse_replay_and_new_write_admission() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let request = request();
    store.put_snapshot(&snapshot(), 10).expect("snapshot");
    store
        .grant_authority_until(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            11,
            25,
        )
        .expect("bounded grant");
    let ReviewActionAdmission::New(action) = store
        .prepare_action(&request, ApprovalPolicy::NotRequired, 20)
        .expect("preview")
    else {
        panic!("new");
    };
    assert!(matches!(
        store.prepare_action(&request, ApprovalPolicy::NotRequired, 25),
        Err(ReviewStoreError::Unauthorized)
    ));
    assert!(matches!(
        store.start_write(&action.preview_id, action.request_digest, 25),
        Err(ReviewStoreError::Unauthorized)
    ));
    store
        .reauthorize_authority_until(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            "reauthorization-2",
            revision(1),
            26,
            40,
        )
        .expect("renew grant");
    store
        .revoke_authority(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            27,
        )
        .expect("revoke");
    assert!(matches!(
        store.grant_authority_until(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            11,
            25,
        ),
        Err(ReviewStoreError::Conflict("authority_grant"))
    ));
    assert!(matches!(
        store.reauthorize_authority_until(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            "stale-reauthorization",
            revision(1),
            28,
            50,
        ),
        Err(ReviewStoreError::Conflict("authority_grant"))
    ));
    assert!(matches!(
        store.prepare_action(&request, ApprovalPolicy::NotRequired, 28),
        Err(ReviewStoreError::Unauthorized)
    ));
    store
        .reauthorize_authority_until(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            "reauthorization-3",
            revision(2),
            29,
            50,
        )
        .expect("explicit later reauthorization");
    assert!(matches!(
        store.prepare_action(&request, ApprovalPolicy::NotRequired, 30),
        Ok(ReviewActionAdmission::Replay(_))
    ));
    assert!(matches!(
        store.reauthorize_authority_until(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            "reauthorization-2",
            revision(3),
            31,
            60,
        ),
        Err(ReviewStoreError::Conflict("authority_grant"))
    ));
}

#[test]
fn comment_history_and_authority_namespace_are_durable_invariants() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open_scoped(private.path(), "tenant-a").expect("open tenant");
    store.put_snapshot(&snapshot(), 10).expect("snapshot");
    let same_revision_rewrite = String::from_utf8(SNAPSHOT.to_vec())
        .expect("fixture")
        .replace("\"agent_state\":\"sent\"", "\"agent_state\":\"pending\"")
        .replace("\"revision\":9,\"schema\"", "\"revision\":10,\"schema\"");
    let same_revision_rewrite =
        decode_review_snapshot(same_revision_rewrite.as_bytes()).expect("valid snapshot");
    assert!(matches!(
        store.put_snapshot(&same_revision_rewrite, 11),
        Err(ReviewStoreError::Conflict("comment_same_revision"))
    ));

    let regression = String::from_utf8(SNAPSHOT.to_vec())
        .expect("fixture")
        .replace("\"agent_state\":\"sent\"", "\"agent_state\":\"pending\"")
        .replace("\"revision\":2,\"unread\"", "\"revision\":3,\"unread\"")
        .replace("\"revision\":9,\"schema\"", "\"revision\":10,\"schema\"");
    let regression = decode_review_snapshot(regression.as_bytes()).expect("valid snapshot");
    assert!(matches!(
        store.put_snapshot(&regression, 12),
        Err(ReviewStoreError::Conflict("comment_history"))
    ));
    drop(store);
    assert!(matches!(
        ReviewStore::open_scoped(private.path(), "tenant-b"),
        Err(ReviewStoreError::Conflict("authority_namespace"))
    ));
    let same = ReviewStore::open_scoped(private.path(), "tenant-a").expect("same tenant reopen");
    assert_eq!(same.authority_namespace(), "tenant-a");
    drop(same);
    let raw = Connection::open(private.path()).expect("raw open");
    raw.execute("DELETE FROM review_store_metadata", [])
        .expect("remove namespace custody");
    drop(raw);
    assert!(matches!(
        ReviewStore::open_scoped(private.path(), "tenant-a"),
        Err(ReviewStoreError::Corrupt("authority_namespace"))
    ));
}

#[test]
fn terminal_receipt_document_and_normalized_revisions_are_verified_before_replay() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let request = seed(&mut store);
    let ReviewActionAdmission::New(action) = store
        .prepare_action(&request, ApprovalPolicy::NotRequired, 20)
        .expect("preview")
    else {
        panic!("new");
    };
    store
        .start_write(&action.preview_id, action.request_digest, 21)
        .expect("write admission");
    let next_document = String::from_utf8(SNAPSHOT.to_vec())
        .expect("fixture")
        .replace("\"revision\":9,\"schema\"", "\"revision\":10,\"schema\"");
    store
        .put_snapshot(
            &decode_review_snapshot(next_document.as_bytes()).expect("next snapshot"),
            22,
        )
        .expect("advance snapshot");
    let completed = ReviewActionReceipt::new(
        action.receipt.receipt_id().clone(),
        action.receipt.idempotency_key().clone(),
        action.receipt.action_id().clone(),
        action.receipt.actor().clone(),
        ReviewReceiptOutcome::Completed,
        Some(revision(10)),
        None,
        ReviewReconciliation::Final,
    )
    .expect("completed");
    store
        .reconcile_receipt(&action.preview_id, action.request_digest, &completed, 23)
        .expect("terminal receipt");

    let raw = Connection::open(private.path()).expect("raw open");
    let document: Vec<u8> = raw
        .query_row(
            "SELECT receipt_document FROM review_action_receipts WHERE preview_id=?1",
            [&action.preview_id],
            |row| row.get(0),
        )
        .expect("receipt document");
    let forged = String::from_utf8(document)
        .expect("canonical receipt")
        .replace("\"revision\":10", "\"revision\":11")
        .into_bytes();
    raw.execute(
        "UPDATE review_action_receipts SET receipt_document=?1 WHERE preview_id=?2",
        params![forged, action.preview_id],
    )
    .expect("forge completed revision");
    drop(raw);
    match store.prepare_action(&request, ApprovalPolicy::NotRequired, 24) {
        Err(ReviewStoreError::Corrupt("receipt_digest")) => {}
        other => panic!("forged terminal receipt returned {other:?}"),
    }

    let forged = String::from_utf8(
        Connection::open(private.path())
            .expect("raw reopen")
            .query_row(
                "SELECT receipt_document FROM review_action_receipts WHERE preview_id=?1",
                [&action.preview_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("forged receipt"),
    )
    .expect("receipt text")
    .into_bytes();
    let forged_digest: [u8; 32] = Sha256::digest(&forged).into();
    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.execute(
        "UPDATE review_action_receipts SET receipt_digest=?1 WHERE preview_id=?2",
        params![forged_digest.as_slice(), action.preview_id],
    )
    .expect("forge matching digest");
    drop(raw);
    assert!(matches!(
        store.prepare_action(&request, ApprovalPolicy::NotRequired, 25),
        Err(ReviewStoreError::Corrupt("receipt_projection"))
    ));
}

#[test]
fn receipt_polling_and_write_admission_require_live_integrity_bound_authority() {
    let private = PrivateStore::new();
    let mut store = ReviewStore::open(private.path()).expect("open");
    let request = seed(&mut store);
    let ReviewActionAdmission::New(action) = store
        .prepare_action(&request, ApprovalPolicy::NotRequired, 20)
        .expect("preview")
    else {
        panic!("new");
    };
    let ReviewWriteAdmission::New(started) = store
        .start_write(&action.preview_id, action.request_digest, 21)
        .expect("write admission")
    else {
        panic!("new write admission");
    };
    assert!(started.write_admission_id.is_some());
    assert!(
        store
            .receipt(
                request.workspace(),
                request.actor(),
                request.authentication(),
                request.authority(),
                request.idempotency_key(),
                22,
            )
            .expect("authorized poll")
            .is_some()
    );

    let raw = Connection::open(private.path()).expect("raw open");
    raw.execute(
        "UPDATE review_action_previews SET write_admission_digest=request_digest WHERE preview_id=?1",
        [&action.preview_id],
    )
    .expect("copy unrelated digest into admission");
    drop(raw);
    assert!(matches!(
        store.receipt(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            23,
        ),
        Err(ReviewStoreError::Corrupt("write_admission"))
    ));

    store
        .revoke_authority(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            24,
        )
        .expect("revoke polling authority");
    assert!(matches!(
        store.receipt(
            request.workspace(),
            request.actor(),
            request.authentication(),
            request.authority(),
            request.idempotency_key(),
            25,
        ),
        Err(ReviewStoreError::Unauthorized)
    ));
}
