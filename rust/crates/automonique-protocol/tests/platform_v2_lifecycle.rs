// SPDX-License-Identifier: Elastic-2.0

use std::path::PathBuf;
use std::process::Command;

use automonique_protocol::identity::Actor;
use automonique_protocol::platform::{
    IdempotencyKey, ReceiptId, ReceiptOutcome, ResourceAuthority, ResourceCoordinate, ResourceId,
    ResourceKind,
};
use automonique_protocol::platform_v2::*;
use automonique_protocol::platform_v2_lifecycle::*;
use automonique_protocol::platform_v2_lifecycle_api::*;
use automonique_protocol::primitives::{EpochMillis, Revision};

fn grant(value: &str) -> AuthorityGrantId {
    AuthorityGrantId::new(value).unwrap()
}
fn authority(prefix: &str) -> WorkContextAuthority {
    WorkContextAuthority::new(
        vec![grant(&format!("{prefix}:fs"))],
        vec![grant(&format!("{prefix}:credential"))],
        vec![grant(&format!("{prefix}:network"))],
        vec![grant(&format!("{prefix}:tool"))],
        vec![grant(&format!("{prefix}:provider"))],
        vec![grant(&format!("{prefix}:model"))],
    )
    .unwrap()
}
fn identity(kind: WorkContextKind, id: &str) -> WorkContextIdentity {
    WorkContextIdentity::parse_local(kind.into(), id).unwrap()
}
fn expected(kind: WorkContextKind, id: &str, revision: u64) -> ExpectedWorkContext {
    ExpectedWorkContext::new(identity(kind, id), Revision::new(revision).unwrap())
}
fn label(value: &str) -> WorkContextLabel {
    WorkContextLabel::new(value).unwrap()
}
fn proposal(
    intent: WorkContextMutationIntent,
    actor_authority: WorkContextAuthority,
) -> WorkContextMutationProposal {
    WorkContextMutationProposal::new(
        Actor::new("tenant-1", "operator-1").unwrap(),
        ResourceAuthority::Automonique,
        actor_authority,
        IdempotencyKey::new("idem-lifecycle-1").unwrap(),
        intent,
    )
    .unwrap()
}
fn attempt_record(lifecycle: WorkContextLifecycle, revision: u64) -> WorkContextRecord {
    WorkContextRecord::new(
        identity(WorkContextKind::AttemptWorkspace, "attempt-1"),
        Revision::new(revision).unwrap(),
        lifecycle,
        label("Attempt"),
        WorkContextAttributes::EMPTY,
        vec![
            WorkContextRelation::new(
                WorkContextRelationKind::AttemptUserWorkspace,
                identity(WorkContextKind::UserWorkspace, "workspace-1"),
            )
            .unwrap(),
        ],
    )
    .unwrap()
}
fn session_record(lifecycle: WorkContextLifecycle, revision: u64) -> WorkContextRecord {
    WorkContextRecord::new(
        identity(WorkContextKind::Session, "session-1"),
        Revision::new(revision).unwrap(),
        lifecycle,
        label("Session"),
        WorkContextAttributes::EMPTY,
        vec![
            WorkContextRelation::new(
                WorkContextRelationKind::SessionAttemptWorkspace,
                identity(WorkContextKind::AttemptWorkspace, "attempt-1"),
            )
            .unwrap(),
            WorkContextRelation::new(
                WorkContextRelationKind::SessionPlatformSession,
                WorkContextIdentity::PlatformSession(
                    V1SessionRef::new(ResourceCoordinate::new(
                        ResourceAuthority::Automonique,
                        ResourceKind::Session,
                        ResourceId::new("platform-session-1").unwrap(),
                    ))
                    .unwrap(),
                ),
            )
            .unwrap(),
        ],
    )
    .unwrap()
}
fn resume_preview(requirement: MutationApprovalRequirement) -> MutationPreview {
    let effective = authority("narrow");
    let ceiling = WorkContextAuthority::new(
        vec![grant("narrow:fs"), grant("wide:fs")],
        vec![grant("narrow:credential"), grant("wide:credential")],
        vec![grant("narrow:network"), grant("wide:network")],
        vec![grant("narrow:tool"), grant("wide:tool")],
        vec![grant("narrow:provider"), grant("wide:provider")],
        vec![grant("narrow:model"), grant("wide:model")],
    )
    .unwrap();
    let intent = WorkContextMutationIntent::ResumeAttemptWorkspace(
        ResumeAttemptWorkspaceIntent::new(
            expected(WorkContextKind::AttemptWorkspace, "attempt-1", 7),
            effective.clone(),
        )
        .unwrap(),
    );
    MutationPreview::new(
        MutationPreviewRef::new(
            MutationPreviewId::new("preview-1").unwrap(),
            Revision::new(3).unwrap(),
        ),
        proposal(intent, ceiling.clone()),
        Some(attempt_record(WorkContextLifecycle::Hibernated, 7)),
        None,
        vec![],
        ceiling,
        effective,
        requirement,
        EpochMillis::from_millis(1_000),
        EpochMillis::from_millis(2_000),
    )
    .unwrap()
}
fn preview_digest(preview: &MutationPreview) -> MutationPreviewDigest {
    work_context_mutation_preview_digest(preview).unwrap()
}

#[test]
fn creation_parent_snapshots_refuse_archived_and_cross_project_graphs() {
    let project_identity = identity(WorkContextKind::Project, "project-1");
    let other_project = identity(WorkContextKind::Project, "project-2");
    let host_identity = identity(WorkContextKind::HostSetup, "host-1");
    let repository_identity = WorkContextIdentity::Repository(
        V1RepositoryRef::new(ResourceCoordinate::new(
            ResourceAuthority::GitHub,
            ResourceKind::Repository,
            ResourceId::new("repository-1").unwrap(),
        ))
        .unwrap(),
    );
    let project_record = |lifecycle| {
        WorkContextRecord::new(
            project_identity.clone(),
            Revision::FIRST,
            lifecycle,
            label("Project"),
            WorkContextAttributes::EMPTY,
            vec![
                WorkContextRelation::new(
                    WorkContextRelationKind::ProjectRepository,
                    repository_identity.clone(),
                )
                .unwrap(),
            ],
        )
        .unwrap()
    };
    let host_record = |project: WorkContextIdentity| {
        WorkContextRecord::new(
            host_identity.clone(),
            Revision::FIRST,
            WorkContextLifecycle::Active,
            label("Host"),
            WorkContextAttributes::host_setup(HostSetupKind::Local),
            vec![
                WorkContextRelation::new(WorkContextRelationKind::HostSetupProject, project)
                    .unwrap(),
            ],
        )
        .unwrap()
    };
    let intent = WorkContextMutationIntent::CreateCheckout(
        CreateCheckoutIntent::new(
            label("Checkout"),
            ExpectedWorkContext::new(project_identity.clone(), Revision::FIRST),
            ExpectedWorkContext::new(host_identity.clone(), Revision::FIRST),
            ExpectedWorkContext::new(repository_identity.clone(), Revision::FIRST),
            CheckoutKind::GitWorktree,
            WorkContextRegistrySelector::new("checkout-registry").unwrap(),
        )
        .unwrap(),
    );
    let WorkContextIdentity::Project(project_id) = &project_identity else {
        unreachable!()
    };
    let snapshots = |project: WorkContextRecord, host: WorkContextRecord| {
        vec![
            ResolvedParentSnapshot::WorkContext { record: project },
            ResolvedParentSnapshot::WorkContext { record: host },
            ResolvedParentSnapshot::External {
                identity: repository_identity.clone(),
                revision: Revision::FIRST,
                resolution: ExternalParentResolution::Available,
                owning_project: Some(project_id.clone()),
            },
        ]
    };
    let build = |parents| {
        MutationPreview::new(
            MutationPreviewRef::new(
                MutationPreviewId::new("preview-checkout").unwrap(),
                Revision::FIRST,
            ),
            proposal(intent.clone(), WorkContextAuthority::EMPTY),
            None,
            Some(issue_work_context_identity_from_random_nonce(
                WorkContextKind::Checkout,
                [7; 16],
            )),
            parents,
            WorkContextAuthority::EMPTY,
            WorkContextAuthority::EMPTY,
            MutationApprovalRequirement::NotRequired,
            EpochMillis::from_millis(1),
            EpochMillis::from_millis(2),
        )
    };
    assert_eq!(
        build(snapshots(
            project_record(WorkContextLifecycle::Archived),
            host_record(project_identity.clone())
        )),
        Err(LifecycleError::ParentLifecycleInvalid)
    );
    assert_eq!(
        build(snapshots(
            project_record(WorkContextLifecycle::Active),
            host_record(other_project)
        )),
        Err(LifecycleError::ParentProjectMismatch)
    );
}

#[test]
fn operation_specific_create_issues_identity_only_in_preview() {
    let repository = ExpectedWorkContext::new(
        WorkContextIdentity::Repository(
            V1RepositoryRef::new(ResourceCoordinate::new(
                ResourceAuthority::GitHub,
                ResourceKind::Repository,
                ResourceId::new("repository-1").unwrap(),
            ))
            .unwrap(),
        ),
        Revision::new(9).unwrap(),
    );
    let intent = WorkContextMutationIntent::CreateProject(
        CreateProjectIntent::new(label("Project"), vec![repository.clone()]).unwrap(),
    );
    let proposal = proposal(intent, WorkContextAuthority::EMPTY);
    let issued =
        issue_work_context_identity_from_random_nonce(WorkContextKind::Project, [0x5a; 16]);
    let preview = MutationPreview::new(
        MutationPreviewRef::new(
            MutationPreviewId::new("preview-create").unwrap(),
            Revision::FIRST,
        ),
        proposal,
        None,
        Some(issued.clone()),
        vec![ResolvedParentSnapshot::External {
            identity: repository.identity().clone(),
            revision: repository.revision(),
            resolution: ExternalParentResolution::Available,
            owning_project: None,
        }],
        WorkContextAuthority::EMPTY,
        WorkContextAuthority::EMPTY,
        MutationApprovalRequirement::NotRequired,
        EpochMillis::from_millis(10),
        EpochMillis::from_millis(20),
    )
    .unwrap();
    assert_eq!(preview.resulting().identity(), &issued);
    assert_eq!(preview.resulting().revision(), Revision::FIRST);
    assert_eq!(
        preview.resulting().lifecycle(),
        WorkContextLifecycle::Active
    );
    assert_eq!(preview.resulting().relations().len(), 1);
    assert_eq!(preview.current(), None);
}

#[test]
fn every_authority_axis_is_tighten_only_and_canonical() {
    let narrow = authority("narrow");
    for widened in [
        WorkContextAuthority::new(
            vec![grant("outside")],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        )
        .unwrap(),
        WorkContextAuthority::new(
            vec![],
            vec![grant("outside")],
            vec![],
            vec![],
            vec![],
            vec![],
        )
        .unwrap(),
        WorkContextAuthority::new(
            vec![],
            vec![],
            vec![grant("outside")],
            vec![],
            vec![],
            vec![],
        )
        .unwrap(),
        WorkContextAuthority::new(
            vec![],
            vec![],
            vec![],
            vec![grant("outside")],
            vec![],
            vec![],
        )
        .unwrap(),
        WorkContextAuthority::new(
            vec![],
            vec![],
            vec![],
            vec![],
            vec![grant("outside")],
            vec![],
        )
        .unwrap(),
        WorkContextAuthority::new(
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![grant("outside")],
        )
        .unwrap(),
    ] {
        assert!(!widened.is_subset_of(&narrow));
    }
    assert_eq!(
        WorkContextAuthority::new(
            vec![grant("z"), grant("a")],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![]
        ),
        Err(LifecycleError::AuthorityOrder {
            field: "filesystem"
        })
    );
    assert!(WorkContextRegistrySelector::new("registry:checkout_1").is_ok());
    assert!(WorkContextRegistrySelector::new("/srv/private").is_err());
    assert!(AuthorityGrantId::new("../secret").is_err());
}

#[test]
fn preview_rejects_widening_and_revision_or_lifecycle_drift() {
    let requested = authority("outside");
    let intent = WorkContextMutationIntent::ResumeAttemptWorkspace(
        ResumeAttemptWorkspaceIntent::new(
            expected(WorkContextKind::AttemptWorkspace, "attempt-1", 7),
            requested.clone(),
        )
        .unwrap(),
    );
    let result = MutationPreview::new(
        MutationPreviewRef::new(
            MutationPreviewId::new("preview-bad").unwrap(),
            Revision::FIRST,
        ),
        proposal(intent, authority("narrow")),
        Some(attempt_record(WorkContextLifecycle::Hibernated, 7)),
        None,
        vec![],
        authority("narrow"),
        requested,
        MutationApprovalRequirement::NotRequired,
        EpochMillis::from_millis(1),
        EpochMillis::from_millis(2),
    );
    assert_eq!(result, Err(LifecycleError::AuthorityWidening));

    let requested = authority("narrow");
    let intent = WorkContextMutationIntent::ResumeAttemptWorkspace(
        ResumeAttemptWorkspaceIntent::new(
            expected(WorkContextKind::AttemptWorkspace, "attempt-1", 8),
            requested.clone(),
        )
        .unwrap(),
    );
    let result = MutationPreview::new(
        MutationPreviewRef::new(
            MutationPreviewId::new("preview-stale").unwrap(),
            Revision::FIRST,
        ),
        proposal(intent, requested.clone()),
        Some(attempt_record(WorkContextLifecycle::Hibernated, 7)),
        None,
        vec![],
        requested.clone(),
        requested,
        MutationApprovalRequirement::NotRequired,
        EpochMillis::from_millis(1),
        EpochMillis::from_millis(2),
    );
    assert_eq!(result, Err(LifecycleError::ExpectedRevisionMismatch));
}

#[test]
fn lifecycle_matrix_is_explicit_and_user_workspace_archive_is_one_way() {
    let attempt = resume_preview(MutationApprovalRequirement::NotRequired);
    assert_eq!(
        attempt.resulting().lifecycle(),
        WorkContextLifecycle::Running
    );
    assert_eq!(attempt.resulting().revision().get(), 8);

    let grants = authority("narrow");
    let session_intent = WorkContextMutationIntent::ResumeSession(
        ResumeSessionIntent::new(
            expected(WorkContextKind::Session, "session-1", 4),
            grants.clone(),
        )
        .unwrap(),
    );
    let session = MutationPreview::new(
        MutationPreviewRef::new(
            MutationPreviewId::new("preview-session").unwrap(),
            Revision::FIRST,
        ),
        proposal(session_intent, grants.clone()),
        Some(session_record(WorkContextLifecycle::Hibernated, 4)),
        None,
        vec![],
        grants.clone(),
        grants,
        MutationApprovalRequirement::NotRequired,
        EpochMillis::from_millis(1),
        EpochMillis::from_millis(2),
    )
    .unwrap();
    assert_eq!(
        session.resulting().lifecycle(),
        WorkContextLifecycle::Active
    );

    for (kind, variant) in [
        (WorkContextKind::Project, 0),
        (WorkContextKind::HostSetup, 1),
        (WorkContextKind::Checkout, 2),
        (WorkContextKind::UserWorkspace, 3),
    ] {
        let target = expected(kind, &format!("target-{variant}"), 1);
        let archive = ArchiveIntent::new(target.clone()).unwrap();
        let intent = match variant {
            0 => WorkContextMutationIntent::ArchiveProject(archive),
            1 => WorkContextMutationIntent::ArchiveHostSetup(archive),
            2 => WorkContextMutationIntent::ArchiveCheckout(archive),
            _ => WorkContextMutationIntent::ArchiveUserWorkspace(archive),
        };
        assert!(intent.validate().is_ok());
    }
    assert!(
        ResumeAttemptWorkspaceIntent::new(
            expected(WorkContextKind::UserWorkspace, "workspace-1", 1),
            WorkContextAuthority::EMPTY
        )
        .is_err()
    );
}

#[test]
fn every_operation_specific_intent_round_trips_without_authoritative_create_fields() {
    let project = expected(WorkContextKind::Project, "project-1", 2);
    let host_setup = expected(WorkContextKind::HostSetup, "setup-1", 3);
    let checkout = expected(WorkContextKind::Checkout, "checkout-1", 4);
    let user_workspace = expected(WorkContextKind::UserWorkspace, "workspace-1", 5);
    let attempt = expected(WorkContextKind::AttemptWorkspace, "attempt-1", 7);
    let session = expected(WorkContextKind::Session, "session-1", 8);
    let repository = ExpectedWorkContext::new(
        WorkContextIdentity::Repository(
            V1RepositoryRef::new(ResourceCoordinate::new(
                ResourceAuthority::GitHub,
                ResourceKind::Repository,
                ResourceId::new("repository-1").unwrap(),
            ))
            .unwrap(),
        ),
        Revision::new(6).unwrap(),
    );
    let registry = || WorkContextRegistrySelector::new("registry-1").unwrap();
    let grants = authority("narrow");
    let intents = vec![
        WorkContextMutationIntent::CreateProject(
            CreateProjectIntent::new(label("Project"), vec![repository.clone()]).unwrap(),
        ),
        WorkContextMutationIntent::CreateHostSetup(
            CreateHostSetupIntent::new(
                label("Setup"),
                project.clone(),
                HostSetupKind::Local,
                registry(),
            )
            .unwrap(),
        ),
        WorkContextMutationIntent::CreateCheckout(
            CreateCheckoutIntent::new(
                label("Checkout"),
                project.clone(),
                host_setup.clone(),
                repository,
                CheckoutKind::GitWorktree,
                registry(),
            )
            .unwrap(),
        ),
        WorkContextMutationIntent::CreateUserWorkspace(
            CreateUserWorkspaceIntent::new(label("Workspace"), project.clone(), checkout.clone())
                .unwrap(),
        ),
        WorkContextMutationIntent::CreateAttemptWorkspace(
            CreateAttemptWorkspaceIntent::new(
                label("Attempt"),
                user_workspace.clone(),
                grants.clone(),
            )
            .unwrap(),
        ),
        WorkContextMutationIntent::ResumeAttemptWorkspace(
            ResumeAttemptWorkspaceIntent::new(attempt, grants.clone()).unwrap(),
        ),
        WorkContextMutationIntent::ResumeSession(
            ResumeSessionIntent::new(session, grants.clone()).unwrap(),
        ),
        WorkContextMutationIntent::ArchiveProject(ArchiveIntent::new(project).unwrap()),
        WorkContextMutationIntent::ArchiveHostSetup(ArchiveIntent::new(host_setup).unwrap()),
        WorkContextMutationIntent::ArchiveCheckout(ArchiveIntent::new(checkout).unwrap()),
        WorkContextMutationIntent::ArchiveUserWorkspace(
            ArchiveIntent::new(user_workspace).unwrap(),
        ),
    ];
    assert_eq!(intents.len(), 11);
    for intent in intents {
        let proposal = proposal(intent, grants.clone());
        let bytes = encode_work_context_mutation_proposal(&proposal).unwrap();
        assert_eq!(
            decode_work_context_mutation_proposal(&bytes).unwrap(),
            proposal
        );
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("resulting"));
        assert!(!text.contains("issued_identity"));
    }
}

#[test]
fn request_digest_binds_actor_authority_idempotency_and_intent() {
    let base = resume_preview(MutationApprovalRequirement::NotRequired)
        .proposal()
        .clone();
    let changed_key = WorkContextMutationProposal::new(
        base.actor().clone(),
        base.authority(),
        base.actor_authority().clone(),
        IdempotencyKey::new("another-key").unwrap(),
        base.intent().clone(),
    )
    .unwrap();
    let changed_actor = WorkContextMutationProposal::new(
        Actor::new("tenant-1", "operator-2").unwrap(),
        base.authority(),
        base.actor_authority().clone(),
        base.idempotency_key().clone(),
        base.intent().clone(),
    )
    .unwrap();
    let changed_authority = WorkContextMutationProposal::new(
        base.actor().clone(),
        ResourceAuthority::GitHub,
        base.actor_authority().clone(),
        base.idempotency_key().clone(),
        base.intent().clone(),
    )
    .unwrap();
    assert_ne!(base.request_digest(), changed_key.request_digest());
    assert_ne!(base.request_digest(), changed_actor.request_digest());
    assert_ne!(base.request_digest(), changed_authority.request_digest());
}

#[test]
fn approval_submission_and_receipt_bind_exact_preview_and_expiry() {
    let preview = resume_preview(MutationApprovalRequirement::Required);
    let approval = MutationApproval::new(
        MutationApprovalId::new("approval-1").unwrap(),
        &preview,
        preview_digest(&preview),
        MutationApprovalDecision::Granted,
        Actor::new("tenant-1", "approver-1").unwrap(),
        EpochMillis::from_millis(1_100),
        EpochMillis::from_millis(1_900),
    )
    .unwrap();
    let submission = MutationSubmission::new(
        &preview,
        preview_digest(&preview),
        Some(&approval),
        EpochMillis::from_millis(1_200),
    )
    .unwrap();
    let receipt = MutationReceipt::new(
        ReceiptId::new("receipt-1").unwrap(),
        &submission,
        &preview,
        preview_digest(&preview),
        ReceiptOutcome::Completed,
        EpochMillis::from_millis(1_300),
    )
    .unwrap();
    assert_eq!(
        receipt.resulting_revision(),
        Some(Revision::new(8).unwrap())
    );
    assert_eq!(
        MutationSubmission::new(
            &preview,
            preview_digest(&preview),
            None,
            EpochMillis::from_millis(1_200)
        ),
        Err(LifecycleError::ApprovalRequired)
    );
    assert_eq!(
        MutationSubmission::new(
            &preview,
            preview_digest(&preview),
            Some(&approval),
            EpochMillis::from_millis(1_950)
        ),
        Err(LifecycleError::ApprovalExpired)
    );
    assert_eq!(
        MutationReceipt::new(
            ReceiptId::new("receipt-2").unwrap(),
            &submission,
            &preview,
            preview_digest(&preview),
            ReceiptOutcome::Unknown,
            EpochMillis::from_millis(1_300)
        ),
        Err(LifecycleError::ReceiptOutcomeInvalid)
    );
}

#[test]
fn canonical_lifecycle_documents_round_trip_and_refuse_drift() {
    let preview = resume_preview(MutationApprovalRequirement::Required);
    let proposal_bytes = encode_work_context_mutation_proposal(preview.proposal()).unwrap();
    assert_eq!(
        decode_work_context_mutation_proposal(&proposal_bytes).unwrap(),
        *preview.proposal()
    );
    let preview_bytes = encode_work_context_mutation_preview(&preview).unwrap();
    let decoded_preview = decode_work_context_mutation_preview(&preview_bytes).unwrap();
    assert_eq!(decoded_preview, preview);
    let approval = MutationApproval::new(
        MutationApprovalId::new("approval-1").unwrap(),
        &preview,
        preview_digest(&preview),
        MutationApprovalDecision::Granted,
        Actor::new("tenant-1", "approver-1").unwrap(),
        EpochMillis::from_millis(1_100),
        EpochMillis::from_millis(1_900),
    )
    .unwrap();
    let approval_bytes = encode_work_context_mutation_approval(&approval).unwrap();
    assert_eq!(
        decode_work_context_mutation_approval(&approval_bytes, &preview).unwrap(),
        approval
    );
    let altered_preview_digest = String::from_utf8(approval_bytes.clone()).unwrap().replace(
        &approval.preview_digest().to_string(),
        &format!("sha256:{}", "0".repeat(64)),
    );
    assert!(
        decode_work_context_mutation_approval(altered_preview_digest.as_bytes(), &preview).is_err()
    );
    let submission_bytes = encode_work_context_mutation_submission(
        &preview,
        Some(&approval),
        EpochMillis::from_millis(1_200),
    )
    .unwrap();
    let submission = decode_work_context_mutation_submission(&submission_bytes, &preview).unwrap();
    let receipt = MutationReceipt::new(
        ReceiptId::new("receipt-1").unwrap(),
        &submission,
        &preview,
        preview_digest(&preview),
        ReceiptOutcome::Completed,
        EpochMillis::from_millis(1_300),
    )
    .unwrap();
    let receipt_bytes = encode_work_context_mutation_receipt(&receipt).unwrap();
    assert_eq!(
        decode_work_context_mutation_receipt(&receipt_bytes, &submission, &preview).unwrap(),
        receipt
    );
    let refusal = MutationRefusal::new(
        MutationRefusalCategory::StaleRevision,
        Some(preview.proposal().request_digest()),
        MutationExplanation::new("parent_revision_changed").unwrap(),
    );
    let refusal_bytes = encode_work_context_mutation_refusal(&refusal).unwrap();
    assert_eq!(
        decode_work_context_mutation_refusal(&refusal_bytes).unwrap(),
        refusal
    );

    let altered_digest = String::from_utf8(proposal_bytes)
        .unwrap()
        .replace("sha256:", "sha256:0");
    assert!(decode_work_context_mutation_proposal(altered_digest.as_bytes()).is_err());
    let extra = String::from_utf8(preview_bytes)
        .unwrap()
        .replace("\"approval\":", "\"host_path\":\"/tmp\",\"approval\":");
    assert!(decode_work_context_mutation_preview(extra.as_bytes()).is_err());
}

#[test]
fn platform_v1_generated_digest_remains_the_installed_pin() {
    assert_eq!(
        automonique_protocol::codegen::generated_platform_v1_schema_digest().1,
        "1c3f561d137a14321cee480b8035341dd70b526ca501f2d5efd7f817a6e4b845"
    );
}

#[test]
fn rust_and_typescript_exchange_exact_lifecycle_bytes_and_refusals() {
    if !Command::new("bun")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        return;
    }
    let package =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../sdk/typescript/packages/protocol");
    let fixture = package.join("conformance/work-context-runtime.ts");

    let preview = resume_preview(MutationApprovalRequirement::Required);
    let approval = MutationApproval::new(
        MutationApprovalId::new("approval-1").unwrap(),
        &preview,
        preview_digest(&preview),
        MutationApprovalDecision::Granted,
        Actor::new("tenant-1", "approver-1").unwrap(),
        EpochMillis::from_millis(1_100),
        EpochMillis::from_millis(1_900),
    )
    .unwrap();
    let submission_bytes = encode_work_context_mutation_submission(
        &preview,
        Some(&approval),
        EpochMillis::from_millis(1_200),
    )
    .unwrap();
    let submission = decode_work_context_mutation_submission(&submission_bytes, &preview).unwrap();
    let receipt = MutationReceipt::new(
        ReceiptId::new("receipt-1").unwrap(),
        &submission,
        &preview,
        preview_digest(&preview),
        ReceiptOutcome::Completed,
        EpochMillis::from_millis(1_300),
    )
    .unwrap();
    let refusal = MutationRefusal::new(
        MutationRefusalCategory::StaleRevision,
        Some(preview.proposal().request_digest()),
        MutationExplanation::new("parent_revision_changed").unwrap(),
    );
    let rust_documents = vec![
        encode_work_context_mutation_proposal(preview.proposal()).unwrap(),
        encode_work_context_mutation_preview(&preview).unwrap(),
        encode_work_context_mutation_approval(&approval).unwrap(),
        submission_bytes,
        encode_work_context_mutation_receipt(&receipt).unwrap(),
        encode_work_context_mutation_refusal(&refusal).unwrap(),
    ];
    const PINNED_PROPOSAL: &str = r#"{"actor":{"id":"operator-1","tenant":"tenant-1"},"actor_authority":{"credentials":["narrow:credential","wide:credential"],"filesystem":["narrow:fs","wide:fs"],"models":["narrow:model","wide:model"],"network":["narrow:network","wide:network"],"providers":["narrow:provider","wide:provider"],"tools":["narrow:tool","wide:tool"]},"authority":"automonique","idempotency_key":"idem-lifecycle-1","intent":{"kind":"resume_attempt_workspace","requested_authority":{"credentials":["narrow:credential"],"filesystem":["narrow:fs"],"models":["narrow:model"],"network":["narrow:network"],"providers":["narrow:provider"],"tools":["narrow:tool"]},"target":{"identity":{"id":"attempt-1","kind":"attempt_workspace"},"revision":7}},"request_digest":"sha256:de7a2babb4450d6f7813acf6cd135f9b655fbea91d6cc3713c4bc74b0c5307bb","schema":"automonique.platform/v2"}"#;
    assert_eq!(rust_documents[0], PINNED_PROPOSAL.as_bytes());

    let typescript = Command::new("bun")
        .arg(&fixture)
        .arg("encode-lifecycle-corpus")
        .current_dir(&package)
        .output()
        .expect("TypeScript lifecycle fixture starts");
    assert!(
        typescript.status.success(),
        "TypeScript lifecycle encode failed: {}",
        String::from_utf8_lossy(&typescript.stderr)
    );
    let typescript_documents: Vec<Vec<u8>> = String::from_utf8(typescript.stdout)
        .unwrap()
        .lines()
        .map(decode_hex)
        .collect();
    assert_eq!(
        typescript_documents, rust_documents,
        "Rust and TypeScript lifecycle bytes drifted"
    );

    assert_eq!(
        decode_work_context_mutation_proposal(&typescript_documents[0]).unwrap(),
        *preview.proposal()
    );
    let decoded_preview = decode_work_context_mutation_preview(&typescript_documents[1]).unwrap();
    let decoded_approval =
        decode_work_context_mutation_approval(&typescript_documents[2], &decoded_preview).unwrap();
    let decoded_submission =
        decode_work_context_mutation_submission(&typescript_documents[3], &decoded_preview)
            .unwrap();
    assert_eq!(decoded_approval, approval);
    assert_eq!(
        decode_work_context_mutation_receipt(
            &typescript_documents[4],
            &decoded_submission,
            &decoded_preview
        )
        .unwrap(),
        receipt
    );
    assert_eq!(
        decode_work_context_mutation_refusal(&typescript_documents[5]).unwrap(),
        refusal
    );

    let round_trip = Command::new("bun")
        .arg(&fixture)
        .arg("decode-lifecycle-corpus")
        .args(rust_documents.iter().map(|bytes| encode_hex(bytes)))
        .current_dir(&package)
        .output()
        .expect("TypeScript lifecycle fixture starts");
    assert!(
        round_trip.status.success(),
        "TypeScript lifecycle decode failed: {}",
        String::from_utf8_lossy(&round_trip.stderr)
    );
    assert_eq!(
        String::from_utf8(round_trip.stdout).unwrap(),
        rust_documents
            .iter()
            .map(|bytes| encode_hex(bytes))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    );

    let typescript_refusals = Command::new("bun")
        .arg(&fixture)
        .arg("encode-lifecycle-refusal-corpus")
        .current_dir(&package)
        .output()
        .expect("TypeScript lifecycle refusal fixture starts");
    assert!(
        typescript_refusals.status.success(),
        "TypeScript lifecycle refusal encode failed: {}",
        String::from_utf8_lossy(&typescript_refusals.stderr)
    );
    let mut refusal_count = 0;
    for line in String::from_utf8(typescript_refusals.stdout)
        .unwrap()
        .lines()
    {
        let mut fields = line.splitn(3, '\t');
        let decoder = fields.next().unwrap();
        let expected_category = fields.next().unwrap();
        let bytes = decode_hex(fields.next().unwrap());
        assert_eq!(
            lifecycle_refusal_category(decoder, &bytes),
            expected_category
        );
        refusal_count += 1;
    }
    assert_eq!(refusal_count, 4);

    let texts: Vec<String> = rust_documents
        .iter()
        .map(|bytes| String::from_utf8(bytes.clone()).unwrap())
        .collect();
    let rust_refusals = [
        (
            "proposal",
            texts[0]
                .replace(
                    preview.proposal().request_digest().to_string().as_str(),
                    &format!("sha256:{}", "0".repeat(64)),
                )
                .into_bytes(),
        ),
        (
            "preview",
            texts[1]
                .replace("[\"narrow:fs\",\"wide:fs\"]", "[\"wide:fs\",\"narrow:fs\"]")
                .into_bytes(),
        ),
        (
            "preview",
            texts[1]
                .replace("\"lifecycle\":\"running\"", "\"lifecycle\":\"active\"")
                .into_bytes(),
        ),
        (
            "refusal",
            texts[5]
                .replace("\"stale_revision\"", "\"future_refusal\"")
                .into_bytes(),
        ),
    ];
    let expected_categories = rust_refusals
        .iter()
        .map(|(decoder, bytes)| lifecycle_refusal_category(decoder, bytes))
        .collect::<Vec<_>>();
    let refused = Command::new("bun")
        .arg(&fixture)
        .arg("decode-lifecycle-refusal-corpus")
        .args(
            rust_refusals
                .iter()
                .map(|(decoder, bytes)| format!("{decoder}:{}", encode_hex(bytes))),
        )
        .current_dir(package)
        .output()
        .expect("TypeScript lifecycle refusal fixture starts");
    assert!(
        refused.status.success(),
        "TypeScript lifecycle refusal decode failed: {}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert_eq!(
        String::from_utf8(refused.stdout).unwrap(),
        expected_categories.join(",") + "\n"
    );
}

fn lifecycle_refusal_category(decoder: &str, bytes: &[u8]) -> &'static str {
    match decoder {
        "proposal" => decode_work_context_mutation_proposal(bytes)
            .unwrap_err()
            .category(),
        "preview" => decode_work_context_mutation_preview(bytes)
            .unwrap_err()
            .category(),
        "refusal" => decode_work_context_mutation_refusal(bytes)
            .unwrap_err()
            .category(),
        _ => panic!("unknown lifecycle refusal decoder {decoder}"),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("non-hex TypeScript corpus"),
            };
            digit(pair[0]) << 4 | digit(pair[1])
        })
        .collect()
}
