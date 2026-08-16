// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use automonique_store::improvements::{
    ApprovalAttempt, ApprovalKind, IMPROVEMENT_STORE_SCHEMA_VERSION, ImprovementState,
    ImprovementStore, ImprovementStoreError, MAX_CI_EVIDENCE_BYTES, NewApprovalChallenge,
    NewImprovement, PlanSubmission, ReleaseSubmission, StateTransition,
};
use tempfile::TempDir;

/// A canonical evidence document of the shape the GitHub broker produces.
const CI_EVIDENCE: &str = r#"{"gates":[{"check_run_id":1,"completed_at":"2026-08-15T10:00:00Z","name":"workspace","url":"https://github.com/owner/repository/runs/1"}],"head_sha":"1111111111111111111111111111111111111111"}"#;

struct PrivateStore {
    _directory: TempDir,
    path: PathBuf,
}

impl PrivateStore {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let path = directory.path().join("improvements.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn store() -> (PrivateStore, ImprovementStore) {
    let private = PrivateStore::new();
    let store = ImprovementStore::open(private.path()).expect("open improvement store");
    (private, store)
}

fn create(store: &mut ImprovementStore) -> i64 {
    let record = store
        .create(NewImprovement {
            request_key: "telegram:update:42",
            actor_id: "telegram:user:7",
            chat_id: "telegram:chat:9",
            summary: "Teach Monique to explain a failed site check.",
            source_repo: "bext-stack/automonique",
            planning_repo: "bext-stack/automonique-plans",
            now_ms: 1_000,
        })
        .expect("create improvement");
    assert_eq!(record.public_id(), "IMP-000001");
    record.entry_id
}

fn plan(store: &mut ImprovementStore, id: i64) {
    store
        .prepare_plan(
            id,
            1,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "sha256:plan-one",
            "# Prepared plan\n",
            1_500,
        )
        .expect("prepare plan");
    let record = store
        .submit_plan(PlanSubmission {
            improvement_id: id,
            expected_revision: 1,
            actor: "automonique:planner",
            plan_digest: "sha256:plan-one",
            plan_head_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            source_base_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            issue_number: 12,
            issue_url: "https://github.com/bext-stack/automonique-plans/issues/12",
            plan_pr_number: 13,
            plan_pr_url: "https://github.com/bext-stack/automonique-plans/pull/13",
            now_ms: 2_000,
        })
        .expect("submit plan");
    assert_eq!(record.state, ImprovementState::PlanReview);
    assert_eq!(record.revision, 2);
}

fn challenge(store: &mut ImprovementStore, id: i64, revision: u64, kind: ApprovalKind, key: &str) {
    store
        .issue_challenge(NewApprovalChallenge {
            challenge_key: key,
            improvement_id: id,
            expected_revision: revision,
            kind,
            actor_id: "telegram:user:7",
            chat_id: "telegram:chat:9",
            created_at_ms: 3_000,
            expires_at_ms: 4_000,
        })
        .expect("issue challenge");
}

fn approve(store: &mut ImprovementStore, key: &str, now_ms: i64) {
    store
        .approve(ApprovalAttempt {
            challenge_key: key,
            actor_id: "telegram:user:7",
            chat_id: "telegram:chat:9",
            now_ms,
        })
        .expect("approve");
}

#[test]
fn full_two_gate_lifecycle_survives_restart_and_has_an_append_only_history() {
    let (private, mut store) = store();
    let id = create(&mut store);
    plan(&mut store, id);
    challenge(&mut store, id, 2, ApprovalKind::Plan, "approve:plan:nonce");
    approve(&mut store, "approve:plan:nonce", 3_500);

    let implementing = store
        .transition(StateTransition {
            improvement_id: id,
            expected_revision: 3,
            actor: "automonique:lab",
            to: ImprovementState::Implementing,
            failure_reason: None,
            active_release_digest: None,
            ci_evidence: None,
            now_ms: 5_000,
        })
        .expect("start implementation");
    assert_eq!(implementing.revision, 4);

    let release = store
        .submit_release(ReleaseSubmission {
            improvement_id: id,
            expected_revision: 4,
            actor: "automonique:lab",
            implementation_head_sha: "cccccccccccccccccccccccccccccccccccccccc",
            implementation_tree_sha: "dddddddddddddddddddddddddddddddddddddddd",
            release_manifest_digest: "sha256:release-one",
            implementation_pr_number: 21,
            implementation_pr_url: "https://github.com/bext-stack/automonique/pull/21",
            now_ms: 6_000,
        })
        .expect("submit release");
    assert_eq!(release.state, ImprovementState::ReleaseReview);

    challenge(
        &mut store,
        id,
        5,
        ApprovalKind::Release,
        "approve:release:nonce",
    );
    approve(&mut store, "approve:release:nonce", 3_900);
    let activating = store
        .transition(StateTransition {
            improvement_id: id,
            expected_revision: 6,
            actor: "automonique:activator",
            to: ImprovementState::Activating,
            failure_reason: None,
            active_release_digest: None,
            ci_evidence: Some(CI_EVIDENCE),
            now_ms: 7_000,
        })
        .expect("begin activation");
    assert_eq!(activating.ci_evidence.as_deref(), Some(CI_EVIDENCE));
    let completed = store
        .transition(StateTransition {
            improvement_id: id,
            expected_revision: 7,
            actor: "automonique:activator",
            to: ImprovementState::Completed,
            failure_reason: None,
            active_release_digest: Some("sha256:release-one"),
            ci_evidence: None,
            now_ms: 8_000,
        })
        .expect("complete activation");
    assert_eq!(completed.state, ImprovementState::Completed);
    assert_eq!(
        completed.active_release_digest.as_deref(),
        Some("sha256:release-one")
    );
    drop(store);

    let reopened = ImprovementStore::open(private.path()).expect("reopen");
    let durable = reopened.get(id).expect("read").expect("record");
    assert_eq!(durable, completed);
    let events = reopened.events(id).expect("events");
    assert_eq!(events.len(), 8);
    assert_eq!(
        events
            .iter()
            .map(|event| event.revision)
            .collect::<Vec<_>>(),
        (1..=8).collect::<Vec<_>>()
    );
}

#[test]
fn request_delivery_is_idempotent_but_payload_reuse_is_not() {
    let (_private, mut store) = store();
    let id = create(&mut store);
    let retry = store
        .create(NewImprovement {
            request_key: "telegram:update:42",
            actor_id: "telegram:user:7",
            chat_id: "telegram:chat:9",
            summary: "Teach Monique to explain a failed site check.",
            source_repo: "bext-stack/automonique",
            planning_repo: "bext-stack/automonique-plans",
            now_ms: 9_999,
        })
        .expect("idempotent retry");
    assert_eq!(retry.entry_id, id);
    assert_eq!(retry.created_at_ms, 1_000);

    let error = store
        .create(NewImprovement {
            request_key: "telegram:update:42",
            actor_id: "telegram:user:7",
            chat_id: "telegram:chat:9",
            summary: "Different request",
            source_repo: "bext-stack/automonique",
            planning_repo: "bext-stack/automonique-plans",
            now_ms: 10_000,
        })
        .expect_err("conflicting retry");
    assert!(matches!(error, ImprovementStoreError::IdempotencyConflict));
}

#[test]
fn owner_guidance_revises_only_a_draft_and_fences_the_old_planner() {
    let (_private, mut store) = store();
    let id = create(&mut store);
    let revised = store
        .revise_draft(
            id,
            1,
            "Keep the existing database schema unchanged.",
            "telegram:user:7",
            1_500,
        )
        .expect("revise draft");
    assert_eq!(revised.revision, 2);
    assert_eq!(revised.state, ImprovementState::Draft);
    assert!(matches!(
        store.prepare_plan(
            id,
            1,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "sha256:stale",
            "# stale\n",
            1_600,
        ),
        Err(ImprovementStoreError::StaleRevision {
            expected: 1,
            actual: 2
        })
    ));
}

#[test]
fn an_approval_is_bound_to_actor_chat_revision_digest_and_expiry() {
    let (_private, mut store) = store();
    let id = create(&mut store);
    plan(&mut store, id);
    challenge(&mut store, id, 2, ApprovalKind::Plan, "approve:plan:bound");

    let wrong_actor = store
        .approve(ApprovalAttempt {
            challenge_key: "approve:plan:bound",
            actor_id: "telegram:user:8",
            chat_id: "telegram:chat:9",
            now_ms: 3_500,
        })
        .expect_err("wrong actor");
    assert!(matches!(
        wrong_actor,
        ImprovementStoreError::ChallengeMismatch("actor_id")
    ));

    let expired = store
        .approve(ApprovalAttempt {
            challenge_key: "approve:plan:bound",
            actor_id: "telegram:user:7",
            chat_id: "telegram:chat:9",
            now_ms: 4_001,
        })
        .expect_err("expired");
    assert!(matches!(expired, ImprovementStoreError::ChallengeExpired));

    approve(&mut store, "approve:plan:bound", 4_000);
    let replay = store
        .approve(ApprovalAttempt {
            challenge_key: "approve:plan:bound",
            actor_id: "telegram:user:7",
            chat_id: "telegram:chat:9",
            now_ms: 4_000,
        })
        .expect_err("replay");
    assert!(matches!(replay, ImprovementStoreError::ChallengeConsumed));
}

#[test]
fn revisions_are_fences_and_approval_states_have_no_unguarded_transition() {
    let (_private, mut store) = store();
    let id = create(&mut store);
    plan(&mut store, id);

    let stale = store
        .transition(StateTransition {
            improvement_id: id,
            expected_revision: 1,
            actor: "automonique:planner",
            to: ImprovementState::Draft,
            failure_reason: None,
            active_release_digest: None,
            ci_evidence: None,
            now_ms: 3_000,
        })
        .expect_err("stale revision");
    assert!(matches!(
        stale,
        ImprovementStoreError::StaleRevision {
            expected: 1,
            actual: 2
        }
    ));

    let bypass = store
        .transition(StateTransition {
            improvement_id: id,
            expected_revision: 2,
            actor: "automonique:planner",
            to: ImprovementState::PlanApproved,
            failure_reason: None,
            active_release_digest: None,
            ci_evidence: None,
            now_ms: 3_000,
        })
        .expect_err("approval bypass");
    assert!(matches!(
        bypass,
        ImprovementStoreError::ApprovalRequired(ApprovalKind::Plan)
    ));
}

#[test]
fn requesting_a_plan_revision_clears_the_superseded_binding() {
    let (_private, mut store) = store();
    let id = create(&mut store);
    plan(&mut store, id);
    let draft = store
        .transition(StateTransition {
            improvement_id: id,
            expected_revision: 2,
            actor: "telegram:user:7",
            to: ImprovementState::Draft,
            failure_reason: None,
            active_release_digest: None,
            ci_evidence: None,
            now_ms: 3_000,
        })
        .expect("request revision");
    assert_eq!(draft.state, ImprovementState::Draft);
    assert_eq!(draft.plan_digest, None);
    assert_eq!(draft.plan_pr_number, None);
}

#[test]
fn the_request_changes_button_consumes_the_same_bound_challenge() {
    let (_private, mut store) = store();
    let id = create(&mut store);
    plan(&mut store, id);
    challenge(&mut store, id, 2, ApprovalKind::Plan, "revise:plan:bound");
    let draft = store
        .request_changes(ApprovalAttempt {
            challenge_key: "revise:plan:bound",
            actor_id: "telegram:user:7",
            chat_id: "telegram:chat:9",
            now_ms: 3_500,
        })
        .expect("request changes");
    assert_eq!(draft.state, ImprovementState::Draft);
    assert_eq!(draft.revision, 3);
    assert_eq!(draft.plan_digest, None);
    assert!(matches!(
        store.request_changes(ApprovalAttempt {
            challenge_key: "revise:plan:bound",
            actor_id: "telegram:user:7",
            chat_id: "telegram:chat:9",
            now_ms: 3_600,
        }),
        Err(ImprovementStoreError::ChallengeConsumed)
    ));
}

#[test]
fn release_changes_return_to_a_fresh_plan_approval() {
    let (_private, mut store) = store();
    let id = create(&mut store);
    plan(&mut store, id);
    challenge(
        &mut store,
        id,
        2,
        ApprovalKind::Plan,
        "approve:plan:release-revise",
    );
    approve(&mut store, "approve:plan:release-revise", 3_500);
    store
        .transition(StateTransition {
            improvement_id: id,
            expected_revision: 3,
            actor: "automonique:lab",
            to: ImprovementState::Implementing,
            failure_reason: None,
            active_release_digest: None,
            ci_evidence: None,
            now_ms: 5_000,
        })
        .expect("start implementation");
    store
        .submit_release(ReleaseSubmission {
            improvement_id: id,
            expected_revision: 4,
            actor: "automonique:lab",
            implementation_head_sha: "cccccccccccccccccccccccccccccccccccccccc",
            implementation_tree_sha: "dddddddddddddddddddddddddddddddddddddddd",
            release_manifest_digest: "sha256:release-revise",
            implementation_pr_number: 22,
            implementation_pr_url: "https://github.com/bext-stack/automonique/pull/22",
            now_ms: 6_000,
        })
        .expect("submit release");
    challenge(
        &mut store,
        id,
        5,
        ApprovalKind::Release,
        "revise:release:bound",
    );
    let draft = store
        .request_changes(ApprovalAttempt {
            challenge_key: "revise:release:bound",
            actor_id: "telegram:user:7",
            chat_id: "telegram:chat:9",
            now_ms: 3_500,
        })
        .expect("request release changes");
    assert_eq!(draft.state, ImprovementState::Draft);
    assert_eq!(draft.revision, 6);
    assert_eq!(draft.plan_digest, None);
    assert_eq!(draft.implementation_head_sha, None);
    assert_eq!(draft.release_manifest_digest, None);
}

#[test]
fn store_paths_must_remain_private() {
    let (private, store) = store();
    drop(store);
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o640))
        .expect("loosen database permissions");
    let error = ImprovementStore::open(private.path()).expect_err("privacy refusal");
    assert!(matches!(error, ImprovementStoreError::InsecurePath(_)));
}

/// Drive one improvement to `release_approved`, the state the CI gate guards.
fn release_approved(store: &mut ImprovementStore) -> i64 {
    let id = create(store);
    plan(store, id);
    challenge(store, id, 2, ApprovalKind::Plan, "approve:plan:gate");
    approve(store, "approve:plan:gate", 3_500);
    store
        .transition(StateTransition {
            improvement_id: id,
            expected_revision: 3,
            actor: "automonique:lab",
            to: ImprovementState::Implementing,
            failure_reason: None,
            active_release_digest: None,
            ci_evidence: None,
            now_ms: 5_000,
        })
        .expect("start implementation");
    store
        .submit_release(ReleaseSubmission {
            improvement_id: id,
            expected_revision: 4,
            actor: "automonique:lab",
            implementation_head_sha: "cccccccccccccccccccccccccccccccccccccccc",
            implementation_tree_sha: "dddddddddddddddddddddddddddddddddddddddd",
            release_manifest_digest: "sha256:release-gate",
            implementation_pr_number: 31,
            implementation_pr_url: "https://github.com/bext-stack/automonique/pull/31",
            now_ms: 6_000,
        })
        .expect("submit release");
    challenge(store, id, 5, ApprovalKind::Release, "approve:release:gate");
    approve(store, "approve:release:gate", 3_900);
    id
}

fn begin_activation(
    store: &mut ImprovementStore,
    id: i64,
    ci_evidence: Option<&str>,
) -> Result<(), ImprovementStoreError> {
    store
        .transition(StateTransition {
            improvement_id: id,
            expected_revision: 6,
            actor: "automonique:activator",
            to: ImprovementState::Activating,
            failure_reason: None,
            active_release_digest: None,
            ci_evidence,
            now_ms: 7_000,
        })
        .map(drop)
}

#[test]
fn activation_is_unreachable_without_recorded_ci_evidence() {
    let (_private, mut store) = store();
    let id = release_approved(&mut store);
    assert!(matches!(
        begin_activation(&mut store, id, None).expect_err("evidence is required"),
        ImprovementStoreError::InvalidField("ci_evidence")
    ));
    // The refusal must not have moved the record: a release that could not
    // prove its CI is still approved, not half-activated.
    let current = store.get(id).expect("read").expect("record");
    assert_eq!(current.state, ImprovementState::ReleaseApproved);
    assert_eq!(current.revision, 6);
    assert_eq!(current.ci_evidence, None);

    begin_activation(&mut store, id, Some(CI_EVIDENCE)).expect("green evidence activates");
    let current = store.get(id).expect("read").expect("record");
    assert_eq!(current.state, ImprovementState::Activating);
    assert_eq!(current.ci_evidence.as_deref(), Some(CI_EVIDENCE));
}

#[test]
fn ci_evidence_is_bounded_and_refused_outside_activation() {
    let (_private, mut store) = store();
    let id = release_approved(&mut store);
    for rejected in ["", "   ", "not-json"] {
        assert!(matches!(
            begin_activation(&mut store, id, Some(rejected)).expect_err("shape"),
            ImprovementStoreError::InvalidField("ci_evidence")
        ));
    }
    let oversized = format!("{{\"gates\":\"{}\"}}", "e".repeat(MAX_CI_EVIDENCE_BYTES));
    assert!(matches!(
        begin_activation(&mut store, id, Some(&oversized)).expect_err("bound"),
        ImprovementStoreError::InvalidField("ci_evidence")
    ));
    // Evidence on any other target is a caller confusion, not a harmless extra.
    let stray = store
        .transition(StateTransition {
            improvement_id: id,
            expected_revision: 6,
            actor: "automonique:controller",
            to: ImprovementState::Failed,
            failure_reason: Some("ci_red"),
            active_release_digest: None,
            ci_evidence: Some(CI_EVIDENCE),
            now_ms: 7_000,
        })
        .expect_err("evidence outside activation");
    assert!(matches!(
        stray,
        ImprovementStoreError::InvalidField("ci_evidence")
    ));
}

#[test]
fn an_approved_release_can_fail_without_ever_activating() {
    let (_private, mut store) = store();
    let id = release_approved(&mut store);
    let failed = store
        .transition(StateTransition {
            improvement_id: id,
            expected_revision: 6,
            actor: "automonique:controller",
            to: ImprovementState::Failed,
            failure_reason: Some("ci_red"),
            active_release_digest: None,
            ci_evidence: None,
            now_ms: 7_000,
        })
        .expect("release_approved has an exit other than activating");
    assert_eq!(failed.state, ImprovementState::Failed);
    assert_eq!(failed.failure_reason.as_deref(), Some("ci_red"));
    assert_eq!(failed.ci_evidence, None);
}

#[test]
fn a_v1_database_migrates_to_v2_with_its_journal_intact() {
    let private = PrivateStore::new();
    {
        let mut store = ImprovementStore::open(private.path()).expect("create");
        let id = release_approved(&mut store);
        assert_eq!(id, 1);
    }

    // Put the file back at V1: drop the column the migration adds and reset the
    // version, so what reopens is a database that has never seen this change.
    {
        let connection = rusqlite::Connection::open(private.path()).expect("open");
        connection
            .execute_batch("ALTER TABLE improvements DROP COLUMN ci_evidence;")
            .expect("undo the column");
        connection
            .pragma_update(None, "user_version", 1)
            .expect("undo the version");
    }

    let mut store = ImprovementStore::open(private.path()).expect("migrate v1 to v2");
    let record = store.get(1).expect("read").expect("record");
    assert_eq!(record.state, ImprovementState::ReleaseApproved);
    assert_eq!(record.revision, 6);
    assert_eq!(
        record.summary,
        "Teach Monique to explain a failed site check."
    );
    assert_eq!(
        record.implementation_head_sha.as_deref(),
        Some("cccccccccccccccccccccccccccccccccccccccc")
    );
    assert_eq!(record.ci_evidence, None);
    assert_eq!(store.events(1).expect("events").len(), 6);

    // And the migrated database is the same shape as a freshly created one:
    // the gate applies to it exactly as it does to a new install.
    begin_activation(&mut store, 1, Some(CI_EVIDENCE)).expect("gate applies after migration");
}

#[test]
fn an_unknown_future_schema_version_is_still_refused() {
    let private = PrivateStore::new();
    drop(ImprovementStore::open(private.path()).expect("create"));
    let connection = rusqlite::Connection::open(private.path()).expect("open");
    connection
        .pragma_update(None, "user_version", IMPROVEMENT_STORE_SCHEMA_VERSION + 1)
        .expect("future version");
    drop(connection);
    assert!(matches!(
        ImprovementStore::open(private.path()).expect_err("future schema"),
        ImprovementStoreError::SchemaVersion { .. }
    ));
}
