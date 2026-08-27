// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::codegen::generated_platform_v1_schema_digest;
use automonique_protocol::digest::Sha256;
use automonique_protocol::platform_v2::{
    PlatformVersionOffer, UserWorkspaceId, negotiate_platform_version,
};

fn lineage_v2() -> automonique_protocol::platform_v2::NegotiatedPlatform {
    negotiate_platform_version(
        &PlatformVersionOffer::new(vec![2]).unwrap(),
        &PlatformVersionOffer::new(vec![2]).unwrap(),
    )
    .unwrap()
}
use automonique_protocol::platform_v2_lineage::*;
use automonique_protocol::platform_v2_lineage_api::{
    decode_lineage_projection, decode_workspace_intent, decode_workspace_intent_outcome,
    encode_lineage_projection, encode_workspace_intent, encode_workspace_intent_outcome,
    require_lineage_v2,
};
use automonique_protocol::primitives::Revision;

fn opaque<T>(
    build: impl FnOnce(String) -> Result<T, automonique_protocol::primitives::ValueError>,
    value: &str,
) -> T {
    build(value.to_owned()).unwrap()
}

fn external(provider: ExternalWorkProvider, scope: &str, key: &str) -> ExternalWorkIdentity {
    ExternalWorkIdentity::new(
        provider,
        opaque(
            ExternalWorkAuthorityId::new,
            &format!("installation-{scope}"),
        ),
        opaque(ExternalWorkScope::new, scope),
        opaque(ExternalWorkKey::new, key),
    )
}

fn fresh() -> LineageFreshness {
    LineageFreshness::new(1_700_000_000_000, 30_000, LineageFreshnessState::Fresh).unwrap()
}

#[test]
fn freshness_counters_share_the_generated_signed_wire_ceiling() {
    assert!(
        LineageFreshness::new(
            MAX_LINEAGE_COUNTER,
            MAX_LINEAGE_COUNTER,
            LineageFreshnessState::Fresh
        )
        .is_ok()
    );
    assert_eq!(
        LineageFreshness::new(MAX_LINEAGE_COUNTER + 1, 1, LineageFreshnessState::Fresh),
        Err(LineageError::FreshnessInvalid)
    );
    assert_eq!(
        LatestUsefulMessage::new(
            LineageMessage::new("bounded").unwrap(),
            MAX_LINEAGE_COUNTER + 1
        ),
        Err(LineageError::FreshnessInvalid)
    );
}

#[test]
fn provider_qualified_work_identity_never_collapses_into_workspace_or_other_providers() {
    let github = external(ExternalWorkProvider::GitHub, "scope-01", "item-42");
    let gitlab = external(ExternalWorkProvider::GitLab, "scope-01", "item-42");
    assert_ne!(github, gitlab);
    let other_installation = ExternalWorkIdentity::new(
        ExternalWorkProvider::GitHub,
        opaque(ExternalWorkAuthorityId::new, "installation-other"),
        opaque(ExternalWorkScope::new, "scope-01"),
        opaque(ExternalWorkKey::new, "item-42"),
    );
    assert_ne!(github, other_installation);

    let workspace = opaque(UserWorkspaceId::new, "workspace-01");
    let item = ExternalWorkItem::new(
        github.clone(),
        workspace.clone(),
        Revision::FIRST,
        ExternalWorkState::Open,
        None,
        fresh(),
        Some(
            LatestUsefulMessage::new(
                LineageMessage::new("Ready for an exact task decision.").unwrap(),
                1_700_000_000_000,
            )
            .unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(item.identity(), &github);
    assert_eq!(item.workspace(), &workspace);
    assert_ne!(item.identity().key().as_str(), item.workspace().as_str());
    let projection =
        LineageProjection::new(workspace.clone(), vec![item.clone()], Vec::new()).unwrap();
    assert_eq!(projection.workspace(), &workspace);
    assert_eq!(projection.external_work_items().len(), 1);
    assert_eq!(
        LineageProjection::new(workspace.clone(), vec![item.clone(), item], Vec::new()),
        Err(LineageError::InventoryInvalid)
    );

    assert!(
        ExternalWorkItem::new(
            github.clone(),
            workspace.clone(),
            Revision::FIRST,
            ExternalWorkState::Moved,
            None,
            fresh(),
            None,
        )
        .is_err()
    );
    assert!(
        ExternalWorkItem::new(
            github.clone(),
            workspace,
            Revision::FIRST,
            ExternalWorkState::Open,
            Some(gitlab),
            fresh(),
            None,
        )
        .is_err()
    );

    let jira = ExternalWorkItem::new(
        external(ExternalWorkProvider::JiraCompatible, "scope-01", "item-42"),
        projection.workspace().clone(),
        Revision::FIRST,
        ExternalWorkState::Open,
        None,
        fresh(),
        None,
    )
    .unwrap();
    let linear = ExternalWorkItem::new(
        external(ExternalWorkProvider::Linear, "scope-01", "item-42"),
        projection.workspace().clone(),
        Revision::FIRST,
        ExternalWorkState::Open,
        None,
        fresh(),
        None,
    )
    .unwrap();
    let ordered = LineageProjection::new(
        projection.workspace().clone(),
        vec![linear, jira],
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        ordered.external_work_items()[0].identity().provider(),
        ExternalWorkProvider::JiraCompatible
    );
}

#[test]
fn orchestration_parentage_is_typed_and_orphans_are_refused() {
    let workspace = opaque(UserWorkspaceId::new, "workspace-02");
    let run = OrchestrationIdentity::Run(opaque(OrchestrationRunId::new, "run-01"));
    let task = OrchestrationIdentity::Task(opaque(OrchestrationTaskId::new, "task-01"));
    let dispatch =
        OrchestrationIdentity::Dispatch(opaque(OrchestrationDispatchId::new, "dispatch-01"));
    let worker = OrchestrationIdentity::Worker(opaque(OrchestrationWorkerId::new, "worker-01"));
    let heartbeat =
        OrchestrationIdentity::Heartbeat(opaque(OrchestrationHeartbeatId::new, "heartbeat-01"));
    let question =
        OrchestrationIdentity::Question(opaque(OrchestrationQuestionId::new, "question-01"));
    let gate =
        OrchestrationIdentity::DecisionGate(opaque(OrchestrationDecisionGateId::new, "gate-01"));

    let record = |identity, parent, status, freshness| {
        OrchestrationRecord::new(
            identity,
            workspace.clone(),
            None,
            parent,
            status,
            freshness,
            None,
        )
    };
    assert!(record(run.clone(), None, LineageStatus::Working, fresh()).is_ok());
    assert!(record(task.clone(), Some(run), LineageStatus::Working, fresh()).is_ok());
    assert!(
        record(
            dispatch.clone(),
            Some(task.clone()),
            LineageStatus::Working,
            fresh()
        )
        .is_ok()
    );
    assert!(
        record(
            worker.clone(),
            Some(dispatch.clone()),
            LineageStatus::Working,
            fresh()
        )
        .is_ok()
    );
    assert!(
        record(
            heartbeat,
            Some(worker),
            LineageStatus::Waiting(LineageMessage::new("Worker observation expired.").unwrap()),
            LineageFreshness::new(1_700_000_000_100, 15_000, LineageFreshnessState::Stale).unwrap()
        )
        .is_ok()
    );
    assert!(
        record(
            question.clone(),
            Some(task.clone()),
            LineageStatus::Waiting(LineageMessage::new("User answer required.").unwrap()),
            fresh()
        )
        .is_ok()
    );
    assert_eq!(
        record(
            task.clone(),
            Some(task.clone()),
            LineageStatus::Working,
            fresh()
        ),
        Err(LineageError::OrchestrationParentInvalid)
    );
    assert!(
        record(
            gate,
            Some(question),
            LineageStatus::Blocked(
                LineageMessage::new("Exact question decision required.").unwrap()
            ),
            fresh()
        )
        .is_ok()
    );
    assert_eq!(
        record(
            dispatch.clone(),
            None,
            LineageStatus::Blocked(LineageMessage::new("Missing task.").unwrap()),
            fresh()
        ),
        Err(LineageError::OrchestrationParentInvalid)
    );
    assert_eq!(
        record(
            dispatch,
            Some(task),
            LineageStatus::Done(LineageMessage::new("Dispatch settled.").unwrap()),
            fresh()
        )
        .unwrap()
        .status()
        .kind(),
        "done"
    );
}

#[test]
fn complete_projection_resolves_relations_and_rejects_cycles() {
    let workspace = opaque(UserWorkspaceId::new, "workspace-graph");
    let first = OrchestrationIdentity::Task(opaque(OrchestrationTaskId::new, "task-cycle-a"));
    let second = OrchestrationIdentity::Task(opaque(OrchestrationTaskId::new, "task-cycle-b"));
    let record = |identity, parent| {
        OrchestrationRecord::new(
            identity,
            workspace.clone(),
            None,
            Some(parent),
            LineageStatus::Working,
            fresh(),
            None,
        )
        .unwrap()
    };
    assert_eq!(
        LineageProjection::new(
            workspace.clone(),
            Vec::new(),
            vec![record(first.clone(), second.clone()), record(second, first)]
        ),
        Err(LineageError::OrchestrationCycle)
    );
    let missing = OrchestrationRecord::new(
        OrchestrationIdentity::Dispatch(opaque(OrchestrationDispatchId::new, "dispatch-missing")),
        workspace.clone(),
        None,
        Some(OrchestrationIdentity::Task(opaque(
            OrchestrationTaskId::new,
            "task-missing",
        ))),
        LineageStatus::Working,
        fresh(),
        None,
    )
    .unwrap();
    assert_eq!(
        LineageProjection::new(workspace, Vec::new(), vec![missing]),
        Err(LineageError::OrchestrationParentInvalid)
    );
}

#[test]
fn create_and_resume_intents_use_opaque_selectors_exact_revisions_and_typed_conflicts() {
    let task = opaque(OrchestrationTaskId::new, "task-03");
    let workspace = opaque(UserWorkspaceId::new, "workspace-03");
    let create = WorkspaceCreateIntent::new(
        opaque(WorkspaceIntentId::new, "intent-create-01"),
        task.clone(),
        external(ExternalWorkProvider::Linear, "scope-linear-01", "lin-7"),
        opaque(BaseSelectorId::new, "base-opaque-01"),
        opaque(BranchSelectorId::new, "branch-opaque-01"),
    );
    assert_eq!(create.task(), &task);
    assert_eq!(create.base_selector().as_str(), "base-opaque-01");
    assert_eq!(create.branch_selector().as_str(), "branch-opaque-01");

    let resume = WorkspaceResumeIntent::new(
        opaque(WorkspaceIntentId::new, "intent-resume-01"),
        task,
        workspace.clone(),
        Revision::new(4).unwrap(),
    );
    assert_eq!(resume.expected_revision().get(), 4);
    assert_eq!(
        WorkspaceIntentConflict::DuplicateIntake.as_str(),
        "duplicate_intake"
    );
    assert_eq!(
        WorkspaceIntentConflict::ExternalWorkMoved.as_str(),
        "external_work_moved"
    );
    assert_eq!(
        WorkspaceIntentConflict::ExternalWorkClosed.as_str(),
        "external_work_closed"
    );
    assert_eq!(
        WorkspaceIntentConflict::CreationCancelled.as_str(),
        "creation_cancelled"
    );
    assert_eq!(
        WorkspaceIntentOutcome::Resumed(workspace),
        WorkspaceIntentOutcome::Resumed(resume.workspace().clone())
    );
}

#[test]
fn shared_fixture_names_every_required_boundary_and_mixed_version_recovery() {
    assert_eq!(
        generated_platform_v1_schema_digest(),
        (
            "sha256",
            "1c3f561d137a14321cee480b8035341dd70b526ca501f2d5efd7f817a6e4b845".to_owned()
        )
    );
    let fixture = include_str!("../fixtures/platform-v2-lineage-v1.json");
    assert_eq!(
        Sha256::digest(fixture.as_bytes()).to_hex(),
        "d1b90d8145d0388bcd75bbba16ce464090235d17e31105e95adf0f4fa8d9ea3e"
    );
    for name in [
        "duplicate_intake",
        "moved_source",
        "closed_source",
        "orphan_dispatch",
        "stale_heartbeat",
        "question_and_gate",
        "cancelled_creation",
        "mixed_version_downgrade",
        "mixed_version_recovery",
    ] {
        assert!(
            fixture.contains(&format!("\"name\": \"{name}\"")),
            "missing {name}"
        );
    }
    for provider in ["github", "gitlab", "linear", "jira_compatible"] {
        assert!(fixture.contains(&format!("\"provider\":\"{provider}\"")));
    }
    for forbidden in ["/home/", "/Users/", "refs/heads/", "generic_authority"] {
        assert!(!fixture.contains(forbidden));
    }

    let future = PlatformVersionOffer::new(vec![1, 2, 3]).unwrap();
    let v1 = PlatformVersionOffer::new(vec![1]).unwrap();
    let recovered = PlatformVersionOffer::new(vec![1, 2, 4]).unwrap();
    assert_eq!(
        negotiate_platform_version(&future, &v1)
            .unwrap()
            .version()
            .number(),
        1
    );
    assert_eq!(
        negotiate_platform_version(&future, &recovered)
            .unwrap()
            .version()
            .number(),
        2
    );
}

#[test]
fn canonical_lineage_codec_is_exact_bidirectional_and_negotiation_gated() {
    let projection = LineageProjection::new(
        opaque(UserWorkspaceId::new, "workspace-codec"),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let exact = b"{\"platform_version\":2,\"schema\":\"automonique.platform/v2\",\"value\":{\"external_work_items\":[],\"orchestration\":[],\"schema\":\"automonique.platform/v2\",\"workspace\":\"workspace-codec\"}}";
    assert_eq!(
        encode_lineage_projection(&lineage_v2(), &projection).unwrap(),
        exact
    );
    assert_eq!(
        decode_lineage_projection(&lineage_v2(), exact).unwrap(),
        projection
    );

    let intent = WorkspaceIntent::Create(WorkspaceCreateIntent::new(
        WorkspaceIntentId::new("intent-codec").unwrap(),
        OrchestrationTaskId::new("task-codec").unwrap(),
        ExternalWorkIdentity::new(
            ExternalWorkProvider::GitLab,
            ExternalWorkAuthorityId::new("installation-codec").unwrap(),
            ExternalWorkScope::new("scope-codec").unwrap(),
            ExternalWorkKey::new("issue-codec").unwrap(),
        ),
        BaseSelectorId::new("base-codec").unwrap(),
        BranchSelectorId::new("branch-codec").unwrap(),
    ));
    let exact_intent = b"{\"platform_version\":2,\"schema\":\"automonique.platform/v2\",\"value\":{\"kind\":\"create\",\"request\":{\"base_selector\":\"base-codec\",\"branch_selector\":\"branch-codec\",\"external_work\":{\"authority\":\"installation-codec\",\"key\":\"issue-codec\",\"provider\":\"gitlab\",\"scope\":\"scope-codec\"},\"intent_id\":\"intent-codec\",\"task\":\"task-codec\"}}}";
    assert_eq!(
        encode_workspace_intent(&lineage_v2(), &intent).unwrap(),
        exact_intent
    );
    assert_eq!(
        decode_workspace_intent(&lineage_v2(), exact_intent).unwrap(),
        intent
    );
    let outcome = WorkspaceIntentOutcome::Accepted;
    let exact_outcome = b"{\"platform_version\":2,\"schema\":\"automonique.platform/v2\",\"value\":{\"kind\":\"accepted\"}}";
    assert_eq!(
        encode_workspace_intent_outcome(&lineage_v2(), &outcome).unwrap(),
        exact_outcome
    );
    assert_eq!(
        decode_workspace_intent_outcome(&lineage_v2(), exact_outcome).unwrap(),
        outcome
    );

    let v1 = negotiate_platform_version(
        &PlatformVersionOffer::new(vec![1]).unwrap(),
        &PlatformVersionOffer::new(vec![1, 2, 3]).unwrap(),
    )
    .unwrap();
    let v2 = negotiate_platform_version(
        &PlatformVersionOffer::new(vec![1, 2, 3]).unwrap(),
        &PlatformVersionOffer::new(vec![1, 2, 4]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        require_lineage_v2(&v1).unwrap_err().category(),
        "work_context_value_invalid"
    );
    require_lineage_v2(&v2).unwrap();
    assert_eq!(
        decode_lineage_projection(&v1, exact)
            .unwrap_err()
            .category(),
        "work_context_value_invalid"
    );

    let overflow = WorkspaceIntent::Resume(WorkspaceResumeIntent::new(
        WorkspaceIntentId::new("intent-overflow").unwrap(),
        OrchestrationTaskId::new("task-overflow").unwrap(),
        UserWorkspaceId::new("workspace-overflow").unwrap(),
        Revision::new(i64::MAX as u64 + 1).unwrap(),
    ));
    assert_eq!(
        encode_workspace_intent(&v2, &overflow)
            .unwrap_err()
            .category(),
        "work_context_counter_out_of_range"
    );

    let wrong = String::from_utf8(exact.to_vec())
        .unwrap()
        .replace("\"platform_version\":2", "\"platform_version\":1");
    assert_eq!(
        decode_lineage_projection(&v2, wrong.as_bytes())
            .unwrap_err()
            .category(),
        "work_context_value_invalid"
    );
    let negative_observation = b"{\"platform_version\":2,\"schema\":\"automonique.platform/v2\",\"value\":{\"external_work_items\":[{\"freshness\":{\"observed_at_ms\":-1,\"stale_after_ms\":30000,\"state\":\"fresh\"},\"identity\":{\"authority\":\"installation-codec\",\"key\":\"issue-codec\",\"provider\":\"gitlab\",\"scope\":\"scope-codec\"},\"latest_useful_message\":null,\"moved_to\":null,\"origin\":{\"attempt\":null,\"pane\":null,\"session\":null,\"workspace\":\"workspace-codec\"},\"revision\":1,\"state\":\"open\",\"workspace\":\"workspace-codec\"}],\"orchestration\":[],\"schema\":\"automonique.platform/v2\",\"workspace\":\"workspace-codec\"}}";
    assert_eq!(
        decode_lineage_projection(&v2, negative_observation)
            .unwrap_err()
            .category(),
        "work_context_counter_out_of_range"
    );
    let exact_moved = b"{\"platform_version\":2,\"schema\":\"automonique.platform/v2\",\"value\":{\"external_work_items\":[{\"freshness\":{\"observed_at_ms\":1700000000001,\"stale_after_ms\":30000,\"state\":\"fresh\"},\"identity\":{\"authority\":\"installation-self-hosted\",\"key\":\"issue-7\",\"provider\":\"gitlab\",\"scope\":\"scope-a\"},\"latest_useful_message\":null,\"moved_to\":{\"authority\":\"installation-self-hosted\",\"key\":\"issue-7\",\"provider\":\"gitlab\",\"scope\":\"scope-b\"},\"origin\":{\"attempt\":\"attempt-codec\",\"pane\":\"pane-codec\",\"session\":\"session-codec\",\"workspace\":\"workspace-codec\"},\"revision\":2,\"state\":\"moved\",\"workspace\":\"workspace-codec\"},{\"freshness\":{\"observed_at_ms\":1700000000000,\"stale_after_ms\":30000,\"state\":\"fresh\"},\"identity\":{\"authority\":\"installation-self-hosted\",\"key\":\"issue-7\",\"provider\":\"gitlab\",\"scope\":\"scope-b\"},\"latest_useful_message\":null,\"moved_to\":null,\"origin\":{\"attempt\":\"attempt-codec\",\"pane\":\"pane-codec\",\"session\":\"session-codec\",\"workspace\":\"workspace-codec\"},\"revision\":1,\"state\":\"open\",\"workspace\":\"workspace-codec\"}],\"orchestration\":[],\"schema\":\"automonique.platform/v2\",\"workspace\":\"workspace-codec\"}}";
    let moved_projection = decode_lineage_projection(&v2, exact_moved).unwrap();
    assert_eq!(moved_projection.external_work_items().len(), 2);
    assert!(
        moved_projection.external_work_items()[0]
            .origin()
            .pane()
            .is_some()
    );
    assert_eq!(
        encode_lineage_projection(&v2, &moved_projection).unwrap(),
        exact_moved
    );
}
