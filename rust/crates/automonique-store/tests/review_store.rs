// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

use automonique_protocol::platform::IdempotencyKey;
use automonique_protocol::platform_v2_review::{
    ReviewAction, ReviewActionReceipt, ReviewActionRequest, ReviewActorId, ReviewAuthentication,
    ReviewCheckId, ReviewReceiptOutcome, ReviewReconciliation,
};
use automonique_protocol::platform_v2_review_api::{
    decode_review_action_request, decode_review_snapshot,
};
use automonique_protocol::primitives::Revision;
use automonique_store::review_store::{
    ApprovalPolicy, ReviewActionAdmission, ReviewStore, ReviewStoreError,
};
use tempfile::TempDir;

const SNAPSHOT: &[u8] =
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
    assert!(
        store
            .receipt(
                request.workspace(),
                unauthorized.actor(),
                request.idempotency_key()
            )
            .expect("isolated lookup")
            .is_none()
    );
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
    let (workspace, actor, key, preview_id, digest, accepted) = {
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
        let approved = store
            .approve_action(
                &action.preview_id,
                action.request_digest,
                request.expected_revision(),
                &approver,
                22,
            )
            .expect("approve");
        assert!(approved.approved);
        let unknown = store
            .mark_ambiguous(&action.preview_id, action.request_digest, 23)
            .expect("persist unknown");
        assert_eq!(unknown.outcome().as_str(), "unknown");
        (
            request.workspace().clone(),
            request.actor().clone(),
            request.idempotency_key().clone(),
            action.preview_id,
            action.request_digest,
            action.receipt,
        )
    };
    let mut reopened = ReviewStore::open(private.path()).expect("reopen");
    let reconciled = reopened
        .receipt(&workspace, &actor, &key)
        .expect("lookup")
        .expect("receipt");
    assert_eq!(reconciled.outcome().as_str(), "unknown");
    assert_eq!(reconciled.receipt_id(), accepted.receipt_id());
    assert_eq!(
        reopened
            .mark_ambiguous(&preview_id, digest, 24)
            .expect("no replay"),
        reconciled
    );
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
            .reconcile_receipt(&preview_id, digest, &completed, 25)
            .expect("reconcile final"),
        completed
    );
    assert_eq!(
        reopened
            .reconcile_receipt(&preview_id, digest, &completed, 26)
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
        reopened.reconcile_receipt(&preview_id, digest, &refused, 27),
        Err(ReviewStoreError::Conflict("terminal_receipt"))
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
