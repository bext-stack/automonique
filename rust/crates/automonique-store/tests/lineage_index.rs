// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use automonique_protocol::platform_v2::{
    AttemptWorkspaceId, NegotiatedPlatform, PaneId, PlatformVersionOffer, ProjectId,
    UserWorkspaceId, WorkSessionId, negotiate_platform_version,
};
use automonique_protocol::platform_v2_lineage::*;
use automonique_protocol::primitives::Revision;
use automonique_store::lineage_index::{
    IntentAuthorizationScope, LINEAGE_INDEX_SCHEMA_VERSION, LineageIndex,
    WorkspaceIntentExecutionReceipt, WriteAdmission,
};
use rusqlite::Connection;
use tempfile::TempDir;

struct PrivateIndex {
    _directory: TempDir,
    path: PathBuf,
}

impl PrivateIndex {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let path = directory.path().join("lineage.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }
    fn path(&self) -> &Path {
        &self.path
    }
}

fn workspace(value: &str) -> UserWorkspaceId {
    UserWorkspaceId::new(value).unwrap()
}
fn lineage_v2() -> NegotiatedPlatform {
    negotiate_platform_version(
        &PlatformVersionOffer::new(vec![2]).unwrap(),
        &PlatformVersionOffer::new(vec![2]).unwrap(),
    )
    .unwrap()
}
fn intent_scope(workspace: &UserWorkspaceId) -> IntentAuthorizationScope {
    IntentAuthorizationScope::new(
        "tenant-test".to_owned(),
        ProjectId::new("project-test").unwrap(),
        workspace.clone(),
    )
    .unwrap()
}
fn external_identity(
    provider: ExternalWorkProvider,
    scope: &str,
    key: &str,
) -> ExternalWorkIdentity {
    ExternalWorkIdentity::new(
        provider,
        ExternalWorkAuthorityId::new(format!("installation-{scope}")).unwrap(),
        ExternalWorkScope::new(scope).unwrap(),
        ExternalWorkKey::new(key).unwrap(),
    )
}
fn freshness(state: LineageFreshnessState, observed: u64) -> LineageFreshness {
    LineageFreshness::new(observed, 30_000, state).unwrap()
}
fn item(
    identity: ExternalWorkIdentity,
    workspace: UserWorkspaceId,
    revision: u64,
    state: ExternalWorkState,
    moved_to: Option<ExternalWorkIdentity>,
) -> ExternalWorkItem {
    ExternalWorkItem::new(
        identity,
        workspace,
        Revision::new(revision).unwrap(),
        state,
        moved_to,
        freshness(LineageFreshnessState::Fresh, 1_700_000_000_000 + revision),
        Some(
            LatestUsefulMessage::new(
                LineageMessage::new(format!("source revision {revision}")).unwrap(),
                1_700_000_000_000 + revision,
            )
            .unwrap(),
        ),
    )
    .unwrap()
}
fn run(value: &str) -> OrchestrationIdentity {
    OrchestrationIdentity::Run(OrchestrationRunId::new(value).unwrap())
}
fn task(value: &str) -> OrchestrationIdentity {
    OrchestrationIdentity::Task(OrchestrationTaskId::new(value).unwrap())
}
fn dispatch(value: &str) -> OrchestrationIdentity {
    OrchestrationIdentity::Dispatch(OrchestrationDispatchId::new(value).unwrap())
}
fn worker(value: &str) -> OrchestrationIdentity {
    OrchestrationIdentity::Worker(OrchestrationWorkerId::new(value).unwrap())
}
fn heartbeat(value: &str) -> OrchestrationIdentity {
    OrchestrationIdentity::Heartbeat(OrchestrationHeartbeatId::new(value).unwrap())
}
fn question(value: &str) -> OrchestrationIdentity {
    OrchestrationIdentity::Question(OrchestrationQuestionId::new(value).unwrap())
}
fn gate(value: &str) -> OrchestrationIdentity {
    OrchestrationIdentity::DecisionGate(OrchestrationDecisionGateId::new(value).unwrap())
}
fn record(
    identity: OrchestrationIdentity,
    workspace: &UserWorkspaceId,
    external: Option<&ExternalWorkIdentity>,
    parent: Option<OrchestrationIdentity>,
    status: LineageStatus,
    fresh: LineageFreshnessState,
) -> OrchestrationRecord {
    OrchestrationRecord::new(
        identity,
        workspace.clone(),
        external.cloned(),
        parent,
        status,
        freshness(fresh, 1_700_000_100_000),
        None,
    )
    .unwrap()
}

#[test]
fn schema_separates_identity_domains_and_stores_only_normalized_fields() {
    let private = PrivateIndex::new();
    let index = LineageIndex::open(private.path()).expect("open");
    assert_eq!(index.path(), private.path());
    drop(index);

    let raw = Connection::open(private.path()).expect("raw open");
    let version: u32 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, LINEAGE_INDEX_SCHEMA_VERSION);
    let tables: Vec<String> = {
        let mut statement = raw.prepare(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name LIKE 'lineage_%' ORDER BY name"
        ).unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert_eq!(
        tables,
        vec![
            "lineage_external_work",
            "lineage_orchestration",
            "lineage_workspace_intents"
        ]
    );
    let schema: String = raw
        .query_row(
            "SELECT group_concat(sql, ' ') FROM sqlite_schema WHERE name LIKE 'lineage_%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    for forbidden in [
        "raw_payload",
        "provider_payload",
        "host_path",
        "branch_name",
    ] {
        assert!(!schema.contains(forbidden));
    }
}

#[test]
fn duplicate_intake_replays_exactly_and_conflicts_without_identity_collapse() {
    let private = PrivateIndex::new();
    let mut index = LineageIndex::open(private.path()).unwrap();
    let identity = external_identity(ExternalWorkProvider::GitHub, "scope-1", "issue-1");
    let first = item(
        identity.clone(),
        workspace("workspace-1"),
        1,
        ExternalWorkState::Open,
        None,
    );
    assert_eq!(
        index.intake_external(&first).unwrap(),
        WriteAdmission::Inserted { revision: 1 }
    );
    assert_eq!(
        index.intake_external(&first).unwrap(),
        WriteAdmission::Replayed { revision: 1 }
    );

    let conflicting = item(
        identity,
        workspace("workspace-2"),
        1,
        ExternalWorkState::Open,
        None,
    );
    let error = index
        .intake_external(&conflicting)
        .expect_err("duplicate conflict");
    assert_eq!(error.category(), "duplicate_intake");
    assert_eq!(
        error.conflict(),
        Some(WorkspaceIntentConflict::DuplicateIntake)
    );
    let other_installation = ExternalWorkIdentity::new(
        ExternalWorkProvider::GitHub,
        ExternalWorkAuthorityId::new("installation-other").unwrap(),
        ExternalWorkScope::new("scope-1").unwrap(),
        ExternalWorkKey::new("issue-1").unwrap(),
    );
    index
        .intake_external(&item(
            other_installation,
            workspace("workspace-1"),
            1,
            ExternalWorkState::Open,
            None,
        ))
        .unwrap();
    assert_eq!(
        index
            .projection_authorized(&lineage_v2(), &workspace("workspace-1"), |_| true)
            .unwrap()
            .external_work_items()
            .len(),
        2
    );
    assert!(
        index
            .projection_authorized(&lineage_v2(), &workspace("workspace-2"), |_| true)
            .unwrap()
            .external_work_items()
            .is_empty()
    );
}

#[test]
fn moved_and_closed_sources_are_revisioned_and_survive_reopen() {
    let private = PrivateIndex::new();
    let mut index = LineageIndex::open(private.path()).unwrap();
    let moved_id = external_identity(ExternalWorkProvider::GitLab, "scope-1", "work-1");
    let replacement = ExternalWorkIdentity::new(
        ExternalWorkProvider::JiraCompatible,
        ExternalWorkAuthorityId::new("installation-replacement").unwrap(),
        ExternalWorkScope::new("scope-2").unwrap(),
        ExternalWorkKey::new("work-1").unwrap(),
    );
    let closed_id = external_identity(ExternalWorkProvider::Linear, "team-1", "lin-1");
    let ws = workspace("workspace-source");
    assert_eq!(
        index
            .intake_external(&item(
                moved_id.clone(),
                ws.clone(),
                1,
                ExternalWorkState::Moved,
                Some(replacement.clone()),
            ))
            .unwrap_err()
            .category(),
        "not_found"
    );
    index
        .intake_external(&item(
            moved_id.clone(),
            ws.clone(),
            1,
            ExternalWorkState::Open,
            None,
        ))
        .unwrap();
    index
        .intake_external(&item(
            closed_id.clone(),
            ws.clone(),
            1,
            ExternalWorkState::Open,
            None,
        ))
        .unwrap();
    let run_id = run("run-source");
    let task_id = task("task-source");
    index
        .record_orchestration(
            &record(
                run_id.clone(),
                &ws,
                Some(&moved_id),
                None,
                LineageStatus::Working,
                LineageFreshnessState::Fresh,
            ),
            None,
        )
        .unwrap();
    index
        .record_orchestration(
            &record(
                task_id,
                &ws,
                Some(&moved_id),
                Some(run_id),
                LineageStatus::Working,
                LineageFreshnessState::Fresh,
            ),
            None,
        )
        .unwrap();
    assert_eq!(
        index
            .update_external(
                &item(
                    moved_id.clone(),
                    ws.clone(),
                    2,
                    ExternalWorkState::Moved,
                    Some(replacement.clone()),
                ),
                Revision::FIRST,
            )
            .unwrap_err()
            .category(),
        "not_found"
    );
    assert_eq!(
        index
            .projection_authorized(&lineage_v2(), &ws, |_| true)
            .unwrap()
            .external_work_items()
            .iter()
            .find(|value| value.identity() == &moved_id)
            .unwrap()
            .state(),
        ExternalWorkState::Open
    );
    index
        .intake_external(&item(
            replacement.clone(),
            ws.clone(),
            1,
            ExternalWorkState::Open,
            None,
        ))
        .unwrap();
    index
        .update_external(
            &item(
                moved_id.clone(),
                ws.clone(),
                2,
                ExternalWorkState::Moved,
                Some(replacement.clone()),
            ),
            Revision::FIRST,
        )
        .unwrap();
    assert_eq!(
        index
            .update_external(
                &item(
                    replacement.clone(),
                    ws.clone(),
                    2,
                    ExternalWorkState::Moved,
                    Some(moved_id.clone()),
                ),
                Revision::FIRST,
            )
            .unwrap_err()
            .category(),
        "identity_conflict"
    );
    let create = WorkspaceIntent::Create(WorkspaceCreateIntent::new(
        WorkspaceIntentId::new("intent-moved").unwrap(),
        OrchestrationTaskId::new("task-source").unwrap(),
        moved_id,
        BaseSelectorId::new("base-source").unwrap(),
        BranchSelectorId::new("branch-source").unwrap(),
    ));
    assert_eq!(
        index
            .record_intent(&create, &WorkspaceIntentOutcome::Created(ws.clone()))
            .expect_err("moved source cannot create")
            .category(),
        "identity_conflict"
    );
    index
        .record_intent(
            &create,
            &WorkspaceIntentOutcome::Conflict(WorkspaceIntentConflict::ExternalWorkMoved),
        )
        .unwrap();
    index
        .update_external(
            &item(closed_id, ws.clone(), 2, ExternalWorkState::Closed, None),
            Revision::FIRST,
        )
        .unwrap();
    drop(index);

    let reopened = LineageIndex::open(private.path()).unwrap();
    let projection = reopened
        .projection_authorized(&lineage_v2(), &ws, |_| true)
        .unwrap();
    assert_eq!(projection.external_work_items().len(), 3);
    let moved = projection
        .external_work_items()
        .iter()
        .find(|value| value.state() == ExternalWorkState::Moved)
        .unwrap();
    assert_eq!(moved.revision().get(), 2);
    assert_eq!(moved.moved_to(), Some(&replacement));
    assert!(
        projection
            .external_work_items()
            .iter()
            .any(|value| value.state() == ExternalWorkState::Closed)
    );
}

#[test]
fn workspace_scoped_projection_refuses_to_truncate_past_the_protocol_bound() {
    let private = PrivateIndex::new();
    let mut index = LineageIndex::open(private.path()).unwrap();
    let ws = workspace("workspace-bounded");
    for number in 0..=MAX_LINEAGE_RECORDS {
        let identity = external_identity(
            ExternalWorkProvider::GitHub,
            "scope-bounded",
            &format!("issue-{number:03}"),
        );
        index
            .intake_external(&item(
                identity,
                ws.clone(),
                1,
                ExternalWorkState::Open,
                None,
            ))
            .unwrap();
    }
    assert_eq!(
        index
            .projection_authorized(&lineage_v2(), &ws, |_| true)
            .expect_err("projection must not truncate")
            .category(),
        "projection_too_large"
    );
}

#[test]
fn authority_seam_refuses_before_reading_workspace_projection() {
    let private = PrivateIndex::new();
    let index = LineageIndex::open(private.path()).unwrap();
    let ws = workspace("workspace-authority");
    let v1 = negotiate_platform_version(
        &PlatformVersionOffer::new(vec![1]).unwrap(),
        &PlatformVersionOffer::new(vec![1]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        index
            .projection_authorized(&v1, &ws, |_| panic!(
                "authorization must follow negotiation"
            ))
            .unwrap_err()
            .category(),
        "invalid_field"
    );
    assert_eq!(
        index
            .projection_authorized(&lineage_v2(), &ws, |_| false)
            .unwrap_err()
            .category(),
        "unauthorized"
    );
    assert!(
        index
            .projection_authorized(&lineage_v2(), &ws, |candidate| candidate == &ws)
            .unwrap()
            .external_work_items()
            .is_empty()
    );
}

#[test]
fn orphan_stale_heartbeat_question_and_cancelled_creation_recover_durably() {
    let private = PrivateIndex::new();
    let mut index = LineageIndex::open(private.path()).unwrap();
    let ws = workspace("workspace-recovery");
    let external = external_identity(ExternalWorkProvider::JiraCompatible, "project-1", "jira-1");
    index
        .intake_external(&item(
            external.clone(),
            ws.clone(),
            1,
            ExternalWorkState::Open,
            None,
        ))
        .unwrap();

    let run_id = run("run-1");
    let task_id = task("task-1");
    let dispatch_id = dispatch("dispatch-1");
    let dispatch_record = record(
        dispatch_id.clone(),
        &ws,
        Some(&external),
        Some(task_id.clone()),
        LineageStatus::Working,
        LineageFreshnessState::Fresh,
    );
    let orphan = index
        .record_orchestration(&dispatch_record, None)
        .expect_err("orphan");
    assert_eq!(
        orphan.conflict(),
        Some(WorkspaceIntentConflict::OrphanDispatch)
    );

    index
        .record_orchestration(
            &record(
                run_id.clone(),
                &ws,
                Some(&external),
                None,
                LineageStatus::Working,
                LineageFreshnessState::Fresh,
            ),
            None,
        )
        .unwrap();
    index
        .record_orchestration(
            &record(
                task_id.clone(),
                &ws,
                Some(&external),
                Some(run_id),
                LineageStatus::Working,
                LineageFreshnessState::Fresh,
            ),
            None,
        )
        .unwrap();
    index.record_orchestration(&dispatch_record, None).unwrap();
    let worker_id = worker("worker-1");
    index
        .record_orchestration(
            &record(
                worker_id.clone(),
                &ws,
                Some(&external),
                Some(dispatch_id),
                LineageStatus::Working,
                LineageFreshnessState::Fresh,
            ),
            None,
        )
        .unwrap();
    let heartbeat_id = heartbeat("heartbeat-1");
    let stale = record(
        heartbeat_id.clone(),
        &ws,
        Some(&external),
        Some(worker_id.clone()),
        LineageStatus::Waiting(LineageMessage::new("fresh observation required").unwrap()),
        LineageFreshnessState::Stale,
    );
    index.record_orchestration(&stale, None).unwrap();
    let recovered = OrchestrationRecord::new_with_origin(
        heartbeat_id,
        LineageOrigin::workspace_only(ws.clone()),
        Some(external.clone()),
        Some(worker_id),
        LineageStatus::Working,
        freshness(LineageFreshnessState::Fresh, 1_700_000_200_000),
        None,
        Revision::new(2).unwrap(),
    )
    .unwrap();
    assert_eq!(
        index
            .record_orchestration(&recovered, Some(Revision::FIRST))
            .unwrap()
            .revision(),
        2
    );

    let question_id = question("question-1");
    index
        .record_orchestration(
            &record(
                question_id.clone(),
                &ws,
                Some(&external),
                Some(task_id.clone()),
                LineageStatus::Waiting(LineageMessage::new("operator answer required").unwrap()),
                LineageFreshnessState::Fresh,
            ),
            None,
        )
        .unwrap();
    index
        .record_orchestration(
            &record(
                gate("gate-1"),
                &ws,
                Some(&external),
                Some(question_id.clone()),
                LineageStatus::Blocked(LineageMessage::new("decision pending").unwrap()),
                LineageFreshnessState::Fresh,
            ),
            None,
        )
        .unwrap();
    index
        .record_orchestration(
            &OrchestrationRecord::new_with_origin(
                question_id,
                LineageOrigin::workspace_only(ws.clone()),
                Some(external.clone()),
                Some(task_id),
                LineageStatus::Done(LineageMessage::new("answer recorded").unwrap()),
                freshness(LineageFreshnessState::Fresh, 1_700_000_200_000),
                None,
                Revision::new(2).unwrap(),
            )
            .unwrap(),
            Some(Revision::FIRST),
        )
        .unwrap();

    let create = WorkspaceIntent::Create(WorkspaceCreateIntent::new(
        WorkspaceIntentId::new("intent-cancelled-1").unwrap(),
        OrchestrationTaskId::new("task-1").unwrap(),
        external.clone(),
        BaseSelectorId::new("base-selector-1").unwrap(),
        BranchSelectorId::new("branch-selector-1").unwrap(),
    ));
    let cancelled = WorkspaceIntentOutcome::Conflict(WorkspaceIntentConflict::CreationCancelled);
    assert_eq!(
        index.record_intent(&create, &cancelled).unwrap(),
        WriteAdmission::Inserted { revision: 1 }
    );
    assert_eq!(
        index.record_intent(&create, &cancelled).unwrap(),
        WriteAdmission::Replayed { revision: 1 }
    );
    let resume = WorkspaceIntent::Resume(WorkspaceResumeIntent::new(
        WorkspaceIntentId::new("intent-resume-1").unwrap(),
        OrchestrationTaskId::new("task-1").unwrap(),
        ws.clone(),
        Revision::FIRST,
    ));
    assert_eq!(
        index
            .record_intent(&resume, &WorkspaceIntentOutcome::Resumed(ws.clone()))
            .unwrap(),
        WriteAdmission::Inserted { revision: 1 }
    );
    drop(index);

    let mut reopened = LineageIndex::open(private.path()).unwrap();
    assert_eq!(
        reopened.record_intent(&create, &cancelled).unwrap(),
        WriteAdmission::Replayed { revision: 1 }
    );
    assert_eq!(
        reopened
            .record_intent(&resume, &WorkspaceIntentOutcome::Resumed(ws.clone()))
            .unwrap(),
        WriteAdmission::Replayed { revision: 1 }
    );
    let projection = reopened
        .projection_authorized(&lineage_v2(), &ws, |_| true)
        .unwrap();
    assert_eq!(projection.external_work_items().len(), 1);
    assert_eq!(projection.orchestration().len(), 7);
    let heartbeat = projection
        .orchestration()
        .iter()
        .find(|value| value.identity().kind() == OrchestrationKind::Heartbeat)
        .unwrap();
    assert_eq!(heartbeat.freshness().state(), LineageFreshnessState::Fresh);
    let question = projection
        .orchestration()
        .iter()
        .find(|value| value.identity().kind() == OrchestrationKind::Question)
        .unwrap();
    assert_eq!(question.status().kind(), "done");
}

#[test]
fn two_handles_cannot_overwrite_a_revision_and_restart_rebuilds_the_winner() {
    let private = PrivateIndex::new();
    let mut first = LineageIndex::open(private.path()).unwrap();
    let mut second = LineageIndex::open(private.path()).unwrap();
    let ws = workspace("workspace-concurrent");
    let identity = external_identity(ExternalWorkProvider::GitHub, "scope-c", "issue-c");
    first
        .intake_external(&item(
            identity.clone(),
            ws.clone(),
            1,
            ExternalWorkState::Open,
            None,
        ))
        .unwrap();
    let winner = item(
        identity.clone(),
        ws.clone(),
        2,
        ExternalWorkState::Closed,
        None,
    );
    first.update_external(&winner, Revision::FIRST).unwrap();
    let stale_target = ExternalWorkIdentity::new(
        ExternalWorkProvider::GitHub,
        identity.authority().clone(),
        ExternalWorkScope::new("scope-next").unwrap(),
        ExternalWorkKey::new("issue-c").unwrap(),
    );
    let stale = item(
        identity,
        ws.clone(),
        2,
        ExternalWorkState::Moved,
        Some(stale_target),
    );
    let error = second
        .update_external(&stale, Revision::FIRST)
        .expect_err("stale writer");
    assert_eq!(error.category(), "revision_mismatch");
    drop(first);
    drop(second);
    let reopened = LineageIndex::open(private.path()).unwrap();
    assert_eq!(
        reopened
            .projection_authorized(&lineage_v2(), &ws, |_| true)
            .unwrap()
            .external_work_items()[0],
        winner
    );
}

#[test]
fn exact_origins_intent_receipts_and_terminal_revisions_survive_restart() {
    let private = PrivateIndex::new();
    let mut index = LineageIndex::open(private.path()).unwrap();
    let ws = workspace("workspace-exact");
    let attempt = AttemptWorkspaceId::new("attempt-exact").unwrap();
    let session = WorkSessionId::new("session-exact").unwrap();
    let pane = PaneId::new("pane-exact").unwrap();
    let source = external_identity(ExternalWorkProvider::GitLab, "scope-exact", "issue-exact");
    let source_origin = LineageOrigin::new(ws.clone(), Some(attempt.clone()), None, None).unwrap();
    let source_item = |revision, state, observed| {
        ExternalWorkItem::new_with_origin(
            source.clone(),
            source_origin.clone(),
            Revision::new(revision).unwrap(),
            state,
            None,
            freshness(LineageFreshnessState::Fresh, observed),
            None,
        )
        .unwrap()
    };
    index
        .intake_external(&source_item(1, ExternalWorkState::Open, 1_700_000_300_000))
        .unwrap();

    let run_id = run("run-exact");
    let task_id = task("task-exact");
    let invalid_first_revision = OrchestrationRecord::new_with_origin(
        run_id.clone(),
        source_origin.clone(),
        Some(source.clone()),
        None,
        LineageStatus::Working,
        freshness(LineageFreshnessState::Fresh, 1_700_000_300_000),
        None,
        Revision::new(2).unwrap(),
    )
    .unwrap();
    assert_eq!(
        index
            .record_orchestration(&invalid_first_revision, None)
            .unwrap_err()
            .category(),
        "invalid_field"
    );
    index
        .record_orchestration(
            &OrchestrationRecord::new_with_origin(
                run_id.clone(),
                source_origin.clone(),
                Some(source.clone()),
                None,
                LineageStatus::Working,
                freshness(LineageFreshnessState::Fresh, 1_700_000_300_000),
                None,
                Revision::FIRST,
            )
            .unwrap(),
            None,
        )
        .unwrap();
    let task_origin =
        LineageOrigin::new(ws.clone(), Some(attempt), Some(session), Some(pane)).unwrap();
    let task_record = |revision, status, observed| {
        OrchestrationRecord::new_with_origin(
            task_id.clone(),
            task_origin.clone(),
            Some(source.clone()),
            Some(run_id.clone()),
            status,
            freshness(LineageFreshnessState::Fresh, observed),
            None,
            Revision::new(revision).unwrap(),
        )
        .unwrap()
    };
    index
        .record_orchestration(
            &task_record(1, LineageStatus::Working, 1_700_000_300_000),
            None,
        )
        .unwrap();

    let create = WorkspaceIntent::Create(WorkspaceCreateIntent::new(
        WorkspaceIntentId::new("intent-exact").unwrap(),
        OrchestrationTaskId::new("task-exact").unwrap(),
        source.clone(),
        BaseSelectorId::new("base-exact").unwrap(),
        BranchSelectorId::new("branch-exact").unwrap(),
    ));
    index
        .record_intent(&create, &WorkspaceIntentOutcome::Accepted)
        .unwrap();
    index
        .update_external(
            &source_item(2, ExternalWorkState::Closed, 1_700_000_300_100),
            Revision::FIRST,
        )
        .unwrap();
    assert_eq!(
        index
            .record_intent(&create, &WorkspaceIntentOutcome::Unknown)
            .unwrap(),
        WriteAdmission::Replayed { revision: 1 }
    );
    let scope = intent_scope(&ws);
    assert!(
        index
            .intent_authorized(
                &lineage_v2(),
                &intent_scope(&workspace("workspace-other")),
                create.intent_id(),
                |_| true
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        index
            .intent_authorized(&lineage_v2(), &scope, create.intent_id(), |_| false)
            .unwrap_err()
            .category(),
        "unauthorized"
    );
    let stored = index
        .intent_authorized(&lineage_v2(), &scope, create.intent_id(), |_| true)
        .unwrap()
        .unwrap();
    assert_eq!(stored.intent, create);
    assert_eq!(stored.outcome, WorkspaceIntentOutcome::Accepted);
    assert_ne!(stored.request_digest, [0; 32]);
    // Execution was admitted while the source was open. A later source close
    // must not rewrite the immutable admitted snapshot into a false conflict.
    let final_outcome = WorkspaceIntentOutcome::Created(ws.clone());
    assert_eq!(
        index
            .reconcile_intent(&WorkspaceIntentExecutionReceipt {
                intent_id: create.intent_id().clone(),
                request_digest: stored.request_digest,
                outcome: final_outcome.clone()
            })
            .unwrap(),
        WriteAdmission::Updated { revision: 2 }
    );
    assert_eq!(
        index
            .intent_authorized(&lineage_v2(), &scope, create.intent_id(), |_| true)
            .unwrap()
            .unwrap()
            .outcome,
        final_outcome
    );
    assert_eq!(
        index
            .reconcile_intent(&WorkspaceIntentExecutionReceipt {
                intent_id: create.intent_id().clone(),
                request_digest: stored.request_digest,
                outcome: final_outcome.clone()
            })
            .unwrap(),
        WriteAdmission::Replayed { revision: 2 }
    );
    let changed = WorkspaceIntent::Create(WorkspaceCreateIntent::new(
        WorkspaceIntentId::new("intent-exact").unwrap(),
        OrchestrationTaskId::new("task-does-not-exist").unwrap(),
        source.clone(),
        BaseSelectorId::new("base-exact").unwrap(),
        BranchSelectorId::new("branch-exact").unwrap(),
    ));
    assert_eq!(
        index
            .record_intent(&changed, &WorkspaceIntentOutcome::Unknown)
            .unwrap_err()
            .category(),
        "identity_conflict"
    );

    assert_eq!(
        index
            .record_orchestration(
                &task_record(
                    2,
                    LineageStatus::Done(LineageMessage::new("complete").unwrap()),
                    1_700_000_300_100
                ),
                Some(Revision::FIRST)
            )
            .unwrap()
            .revision(),
        2
    );
    assert_eq!(
        index
            .record_orchestration(
                &task_record(
                    3,
                    LineageStatus::Done(LineageMessage::new("complete").unwrap()),
                    1_700_000_300_200
                ),
                Some(Revision::new(2).unwrap())
            )
            .unwrap()
            .revision(),
        3
    );
    assert_eq!(
        index
            .record_orchestration(
                &task_record(4, LineageStatus::Working, 1_700_000_300_300),
                Some(Revision::new(3).unwrap())
            )
            .unwrap_err()
            .category(),
        "identity_conflict"
    );
    drop(index);

    let reopened = LineageIndex::open(private.path()).unwrap();
    let projection = reopened
        .projection_authorized(&lineage_v2(), &ws, |_| true)
        .unwrap();
    assert_eq!(projection.external_work_items()[0].origin(), &source_origin);
    let task = projection
        .orchestration()
        .iter()
        .find(|record| record.identity() == &task_id)
        .unwrap();
    assert_eq!(task.origin(), &task_origin);
    assert_eq!(task.revision().get(), 3);
    drop(reopened);
    let db = Connection::open(private.path()).unwrap();
    db.execute(
        "UPDATE lineage_workspace_intents SET request_digest=zeroblob(32) WHERE intent_id='intent-exact'",
        [],
    )
    .unwrap();
    drop(db);
    assert_eq!(
        LineageIndex::open(private.path()).unwrap_err().category(),
        "corrupt"
    );
}

#[test]
fn populated_v1_index_migrates_without_losing_identity_or_intent() {
    let private = PrivateIndex::new();
    fs::File::create(private.path()).unwrap();
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o600)).unwrap();
    let db = Connection::open(private.path()).unwrap();
    db.execute_batch(r#"
CREATE TABLE lineage_external_work(provider TEXT,scope TEXT,work_key TEXT,workspace_id TEXT,revision INTEGER,external_state TEXT,moved_provider TEXT,moved_scope TEXT,moved_key TEXT,observed_at_ms INTEGER,stale_after_ms INTEGER,freshness_state TEXT,latest_message TEXT,latest_observed_at_ms INTEGER);
CREATE INDEX lineage_external_by_workspace ON lineage_external_work(workspace_id,provider,scope,work_key);
CREATE TABLE lineage_orchestration(orchestration_kind TEXT,orchestration_id TEXT,workspace_id TEXT,external_provider TEXT,external_scope TEXT,external_key TEXT,parent_kind TEXT,parent_id TEXT,status_kind TEXT,status_message TEXT,observed_at_ms INTEGER,stale_after_ms INTEGER,freshness_state TEXT,latest_message TEXT,latest_observed_at_ms INTEGER,revision INTEGER);
CREATE INDEX lineage_orchestration_by_workspace ON lineage_orchestration(workspace_id,orchestration_kind,orchestration_id);
CREATE TABLE lineage_workspace_intents(intent_id TEXT,intent_kind TEXT,task_kind TEXT,task_id TEXT,workspace_id TEXT,external_provider TEXT,external_scope TEXT,external_key TEXT,base_selector TEXT,branch_selector TEXT,expected_revision INTEGER,outcome_kind TEXT,outcome_conflict TEXT,outcome_workspace_id TEXT);
INSERT INTO lineage_external_work VALUES('gitlab','scope-v1','issue-v1','workspace-v1',1,'open',NULL,NULL,NULL,1700000000000,30000,'fresh',NULL,NULL);
INSERT INTO lineage_orchestration VALUES('run','run-v1','workspace-v1',NULL,NULL,NULL,NULL,NULL,'working',NULL,1700000000000,30000,'fresh',NULL,NULL,1);
INSERT INTO lineage_orchestration VALUES('task','task-v1','workspace-v1','gitlab','scope-v1','issue-v1','run','run-v1','working',NULL,1700000000000,30000,'fresh',NULL,NULL,1);
INSERT INTO lineage_workspace_intents VALUES('intent-v1','create','task','task-v1','workspace-v1','gitlab','scope-v1','issue-v1','base-v1','branch-v1',NULL,'created',NULL,'workspace-v1');
PRAGMA user_version=1;
"#).unwrap();
    drop(db);

    let index = LineageIndex::open(private.path()).unwrap();
    let projection = index
        .projection_authorized(&lineage_v2(), &workspace("workspace-v1"), |_| true)
        .unwrap();
    assert_eq!(projection.external_work_items().len(), 1);
    assert_eq!(
        projection.external_work_items()[0]
            .identity()
            .authority()
            .as_str(),
        "legacy-unqualified-gitlab"
    );
    let stored = index
        .intent_authorized(
            &lineage_v2(),
            &intent_scope(&workspace("workspace-v1")),
            &WorkspaceIntentId::new("intent-v1").unwrap(),
            |_| true,
        )
        .unwrap()
        .unwrap();
    assert_ne!(stored.request_digest, [0; 32]);
    assert_eq!(
        stored.outcome,
        WorkspaceIntentOutcome::Created(workspace("workspace-v1"))
    );
    drop(index);
    let db = Connection::open(private.path()).unwrap();
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .unwrap(),
        LINEAGE_INDEX_SCHEMA_VERSION
    );
    db.execute(
        "UPDATE lineage_workspace_intents SET request_digest=zeroblob(32) WHERE intent_id='intent-v1'",
        [],
    )
    .unwrap();
    drop(db);
    assert_eq!(
        LineageIndex::open(private.path()).unwrap_err().category(),
        "corrupt"
    );
}

#[test]
fn current_version_with_missing_schema_shape_refuses_on_open() {
    let private = PrivateIndex::new();
    drop(LineageIndex::open(private.path()).unwrap());
    let db = Connection::open(private.path()).unwrap();
    db.execute_batch("DROP INDEX lineage_external_by_workspace; CREATE INDEX lineage_external_by_workspace ON lineage_external_work(work_key);").unwrap();
    drop(db);
    assert_eq!(
        LineageIndex::open(private.path()).unwrap_err().category(),
        "corrupt"
    );
}

#[test]
fn current_version_with_stripped_constraints_or_trigger_refuses_on_open() {
    for mutation in [
        "PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql, ') STRICT', ')') WHERE name='lineage_external_work'; PRAGMA writable_schema=OFF; PRAGMA schema_version=99;",
        "CREATE TRIGGER unexpected_lineage_trigger AFTER INSERT ON lineage_external_work BEGIN SELECT 1; END;",
    ] {
        let private = PrivateIndex::new();
        drop(LineageIndex::open(private.path()).unwrap());
        let db = Connection::open(private.path()).unwrap();
        db.execute_batch(mutation).unwrap();
        drop(db);
        assert_eq!(
            LineageIndex::open(private.path()).unwrap_err().category(),
            "corrupt"
        );
    }
}

#[test]
fn reopen_refuses_dangling_and_cyclic_moved_chains() {
    for cyclic in [false, true] {
        let private = PrivateIndex::new();
        let mut index = LineageIndex::open(private.path()).unwrap();
        let ws = workspace("workspace-corrupt-move");
        let a = external_identity(ExternalWorkProvider::GitLab, "scope-a", "issue-a");
        let b = external_identity(ExternalWorkProvider::JiraCompatible, "scope-b", "issue-b");
        index
            .intake_external(&item(
                b.clone(),
                ws.clone(),
                1,
                ExternalWorkState::Open,
                None,
            ))
            .unwrap();
        index
            .intake_external(&item(a.clone(), ws, 1, ExternalWorkState::Open, None))
            .unwrap();
        index
            .update_external(
                &item(
                    a.clone(),
                    workspace("workspace-corrupt-move"),
                    2,
                    ExternalWorkState::Moved,
                    Some(b.clone()),
                ),
                Revision::FIRST,
            )
            .unwrap();
        drop(index);
        let db = Connection::open(private.path()).unwrap();
        if cyclic {
            db.execute(
                "UPDATE lineage_external_work SET revision=2,external_state='moved',moved_provider=?1,moved_authority_id=?2,moved_scope=?3,moved_key=?4 WHERE provider=?5 AND authority_id=?6 AND scope=?7 AND work_key=?8",
                rusqlite::params![a.provider().as_str(), a.authority().as_str(), a.scope().as_str(), a.key().as_str(), b.provider().as_str(), b.authority().as_str(), b.scope().as_str(), b.key().as_str()],
            ).unwrap();
        } else {
            db.execute(
                "DELETE FROM lineage_external_work WHERE provider=?1 AND authority_id=?2 AND scope=?3 AND work_key=?4",
                rusqlite::params![b.provider().as_str(), b.authority().as_str(), b.scope().as_str(), b.key().as_str()],
            ).unwrap();
        }
        drop(db);
        assert_eq!(
            LineageIndex::open(private.path()).unwrap_err().category(),
            "corrupt"
        );
    }
}

#[test]
fn attaching_to_a_chain_with_an_absent_descendant_is_refused() {
    let private = PrivateIndex::new();
    let mut index = LineageIndex::open(private.path()).unwrap();
    let ws = workspace("workspace-attach-dangling");
    let a = external_identity(ExternalWorkProvider::GitHub, "scope-a", "a");
    let b = external_identity(ExternalWorkProvider::GitLab, "scope-b", "b");
    let c = external_identity(ExternalWorkProvider::Linear, "scope-c", "c");
    for identity in [&a, &b, &c] {
        index
            .intake_external(&item(
                identity.clone(),
                ws.clone(),
                1,
                ExternalWorkState::Open,
                None,
            ))
            .unwrap();
    }
    index
        .update_external(
            &item(
                b.clone(),
                ws.clone(),
                2,
                ExternalWorkState::Moved,
                Some(c.clone()),
            ),
            Revision::FIRST,
        )
        .unwrap();
    let db = Connection::open(private.path()).unwrap();
    db.execute(
        "DELETE FROM lineage_external_work WHERE provider=?1 AND authority_id=?2 AND scope=?3 AND work_key=?4",
        rusqlite::params![c.provider().as_str(), c.authority().as_str(), c.scope().as_str(), c.key().as_str()],
    ).unwrap();
    drop(db);
    assert_eq!(
        index
            .update_external(
                &item(a, ws, 2, ExternalWorkState::Moved, Some(b)),
                Revision::FIRST
            )
            .unwrap_err()
            .category(),
        "not_found"
    );
}

#[test]
fn v1_migration_refuses_dangling_moved_data_without_partial_commit() {
    for cyclic in [false, true] {
        let private = PrivateIndex::new();
        fs::File::create(private.path()).unwrap();
        fs::set_permissions(private.path(), fs::Permissions::from_mode(0o600)).unwrap();
        let db = Connection::open(private.path()).unwrap();
        db.execute_batch(r#"
CREATE TABLE lineage_external_work(provider TEXT,scope TEXT,work_key TEXT,workspace_id TEXT,revision INTEGER,external_state TEXT,moved_provider TEXT,moved_scope TEXT,moved_key TEXT,observed_at_ms INTEGER,stale_after_ms INTEGER,freshness_state TEXT,latest_message TEXT,latest_observed_at_ms INTEGER);
CREATE INDEX lineage_external_by_workspace ON lineage_external_work(workspace_id,provider,scope,work_key);
CREATE TABLE lineage_orchestration(orchestration_kind TEXT,orchestration_id TEXT,workspace_id TEXT,external_provider TEXT,external_scope TEXT,external_key TEXT,parent_kind TEXT,parent_id TEXT,status_kind TEXT,status_message TEXT,observed_at_ms INTEGER,stale_after_ms INTEGER,freshness_state TEXT,latest_message TEXT,latest_observed_at_ms INTEGER,revision INTEGER);
CREATE INDEX lineage_orchestration_by_workspace ON lineage_orchestration(workspace_id,orchestration_kind,orchestration_id);
CREATE TABLE lineage_workspace_intents(intent_id TEXT,intent_kind TEXT,task_kind TEXT,task_id TEXT,workspace_id TEXT,external_provider TEXT,external_scope TEXT,external_key TEXT,base_selector TEXT,branch_selector TEXT,expected_revision INTEGER,outcome_kind TEXT,outcome_conflict TEXT,outcome_workspace_id TEXT);
PRAGMA user_version=1;
"#).unwrap();
        db.execute_batch(if cyclic {
        "INSERT INTO lineage_external_work VALUES('gitlab','scope-a','issue-a','workspace-v1-broken',1,'moved','jira_compatible','scope-b','issue-b',1700000000000,30000,'fresh',NULL,NULL); INSERT INTO lineage_external_work VALUES('jira_compatible','scope-b','issue-b','workspace-v1-broken',1,'moved','gitlab','scope-a','issue-a',1700000000000,30000,'fresh',NULL,NULL);"
    } else {
        "INSERT INTO lineage_external_work VALUES('gitlab','scope-a','issue-a','workspace-v1-broken',1,'moved','jira_compatible','scope-missing','issue-missing',1700000000000,30000,'fresh',NULL,NULL);"
    }).unwrap();
        drop(db);
        assert_eq!(
            LineageIndex::open(private.path()).unwrap_err().category(),
            "corrupt"
        );
        let db = Connection::open(private.path()).unwrap();
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM lineage_external_work", [], |row| row
                .get::<_, u32>(
                0
            ))
            .unwrap(),
            if cyclic { 2 } else { 1 }
        );
    }
}
