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
    ApprovalPolicy, ReviewActionAdmission, ReviewApprovalDecision, ReviewApprovalDocument,
    ReviewStore, ReviewStoreError, ReviewWriteAdmission,
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
            "ALTER TABLE review_snapshots DROP COLUMN protocol_schema; PRAGMA user_version=1;",
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
        2
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
        2
    );
    let protocol_schema: String = raw
        .query_row("SELECT protocol_schema FROM review_snapshots", [], |row| {
            row.get(0)
        })
        .expect("schema projection");
    assert_eq!(protocol_schema, PLATFORM_REVIEW_SCHEMA_V2);
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
        let ReviewActionAdmission::New(prepared) = store
            .prepare_action(&request, ApprovalPolicy::NotRequired, 20 + index as i64)
            .expect("prepare")
        else {
            panic!("first admission must be new")
        };
        assert!(matches!(
            store
                .prepare_action(&request, ApprovalPolicy::NotRequired, 30 + index as i64)
                .expect("prepare replay"),
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
