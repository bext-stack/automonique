// SPDX-License-Identifier: Apache-2.0

use automonique_platform_client::platform_v2_client::testing::{
    DeterministicPlatformV2Step, DeterministicPlatformV2Transport,
};
use automonique_platform_client::platform_v2_client::{
    AttentionReadResult, NegotiationResult, PlatformV2Client, PlatformV2ClientError as ClientError,
    ResourceListingResult, ReviewActionConfirmation, ReviewReceiptResult, WorkContextGetResult,
};
use automonique_protocol::identity::Actor;
use automonique_protocol::platform::{IdempotencyKey, ResourceAuthority};
use automonique_protocol::platform_v2::{
    NegotiatedPlatform, PLATFORM_SCHEMA_V2, PlatformVersion, PlatformVersionOffer, ProjectId,
    UserWorkspaceId, WorkContextAttributes, WorkContextAvailability, WorkContextCursor,
    WorkContextIdentity, WorkContextKind, WorkContextLabel, WorkContextLifecycle, WorkContextPage,
    WorkContextQuery, WorkContextRecord, WorkContextResync,
};
use automonique_protocol::platform_v2_attention::{
    AttentionSource, AttentionSourceId, AttentionSourceKind,
};
use automonique_protocol::platform_v2_attention_api::decode_attention_source_snapshot;
use automonique_protocol::platform_v2_inventory::{
    ResourceListingCursor, ResourceListingPage, ResourceListingQuery, ResourceListingResync,
};
use automonique_protocol::platform_v2_lifecycle::{
    CreateProjectIntent, MutationApproval, MutationApprovalDecision, MutationApprovalId,
    MutationApprovalRequirement, MutationPreview, MutationPreviewId, MutationPreviewRef,
    WorkContextAuthority, WorkContextMutationIntent, WorkContextMutationProposal,
};
use automonique_protocol::platform_v2_lifecycle_api::work_context_mutation_preview_digest;
use automonique_protocol::platform_v2_lineage::LineageProjection;
use automonique_protocol::platform_v2_review::{ReviewAction, ReviewCheckId};
use automonique_protocol::platform_v2_transport::{
    PlatformNegotiationResponse, PlatformV2Refusal, PlatformV2Response,
    RawMutationApprovalDocument, ReviewConfirmationDigest, ReviewReceiptCorrelationDigest,
};
use automonique_protocol::primitives::{EpochMillis, Revision};

fn negotiated(version: PlatformVersion) -> NegotiatedPlatform {
    NegotiatedPlatform::new(
        version,
        version.schema(),
        match version {
            PlatformVersion::V1 => WorkContextAvailability::V1ExistingResourcesOnly,
            PlatformVersion::V2 => WorkContextAvailability::V2Structured,
        },
    )
    .unwrap()
}

fn project(id: &str) -> WorkContextIdentity {
    WorkContextIdentity::Project(ProjectId::new(id).unwrap())
}

fn project_record(id: &str) -> WorkContextRecord {
    WorkContextRecord::new(
        project(id),
        Revision::new(1).unwrap(),
        WorkContextLifecycle::Active,
        WorkContextLabel::new("Project".to_owned()).unwrap(),
        WorkContextAttributes::EMPTY,
        vec![],
    )
    .unwrap()
}

fn v2_negotiation() -> DeterministicPlatformV2Step {
    DeterministicPlatformV2Step::Negotiation(PlatformNegotiationResponse::Negotiated(negotiated(
        PlatformVersion::V2,
    )))
}

#[test]
fn attention_reads_preserve_and_revalidate_the_exact_source_scope() {
    let snapshot = decode_attention_source_snapshot(include_bytes!(
        "../../../../rust/crates/automonique-protocol/fixtures/platform-v2-attention-v1.json"
    ))
    .unwrap();
    let transport = DeterministicPlatformV2Transport::new([
        v2_negotiation(),
        DeterministicPlatformV2Step::V2(Box::new(PlatformV2Response::AttentionSourceSnapshot(
            snapshot.clone(),
        ))),
    ]);
    let mut client = PlatformV2Client::new_testing(transport);
    client
        .negotiate(PlatformVersionOffer::new(vec![2]).unwrap())
        .unwrap();
    assert!(matches!(
        client
            .get_attention_source_snapshot(
                snapshot.source().clone(),
                snapshot.project().clone(),
                snapshot.user_workspace().clone(),
            )
            .unwrap(),
        AttentionReadResult::Snapshot(_)
    ));

    let transport = DeterministicPlatformV2Transport::new([
        v2_negotiation(),
        DeterministicPlatformV2Step::V2(Box::new(PlatformV2Response::AttentionSourceSnapshot(
            snapshot.clone(),
        ))),
    ]);
    let mut client = PlatformV2Client::new_testing(transport);
    client
        .negotiate(PlatformVersionOffer::new(vec![2]).unwrap())
        .unwrap();
    assert_eq!(
        client.get_attention_source_snapshot(
            AttentionSource::new(
                AttentionSourceKind::ProviderSession,
                AttentionSourceId::new("other-source").unwrap(),
            ),
            snapshot.project().clone(),
            snapshot.user_workspace().clone(),
        ),
        Err(ClientError::Protocol)
    );
}

#[test]
fn negotiates_v2_then_preserves_exact_request_coordinates() {
    let transport = DeterministicPlatformV2Transport::new([
        DeterministicPlatformV2Step::Negotiation(PlatformNegotiationResponse::Negotiated(
            negotiated(PlatformVersion::V2),
        )),
        DeterministicPlatformV2Step::V2(Box::new(PlatformV2Response::WorkContextRecord(
            project_record("project-a"),
        ))),
    ]);
    let mut client = PlatformV2Client::new_testing(transport);
    assert!(matches!(
        client
            .negotiate(PlatformVersionOffer::new(vec![1, 2]).unwrap())
            .unwrap(),
        NegotiationResult::V2(_)
    ));
    assert!(matches!(
        client.get_work_context(project("project-a")).unwrap(),
        WorkContextGetResult::Record(_)
    ));
    let requests = client.transport().requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].request(),
        &automonique_protocol::platform_v2_transport::PlatformV2Request::GetWorkContext(project(
            "project-a"
        ))
    );
}

#[test]
fn confirmed_review_action_preserves_the_bounded_confirmation_coordinates() {
    let workspace =
        WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("workspace-a").unwrap());
    let expected_revision = Revision::new(7).unwrap();
    let expected_workspace_revision = Revision::new(11).unwrap();
    let action = ReviewAction::RerunCheck {
        check_id: ReviewCheckId::new("check-1").unwrap(),
        expected_check_revision: Revision::new(5).unwrap(),
    };
    let idempotency_key = IdempotencyKey::new("rerun-check-once").unwrap();
    let confirmation_digest = ReviewConfirmationDigest::new("ab".repeat(32)).unwrap();
    let receipt_correlation_digest = ReviewReceiptCorrelationDigest::new("cd".repeat(32)).unwrap();
    let confirmation = ReviewActionConfirmation::new(
        confirmation_digest.clone(),
        expected_workspace_revision,
        receipt_correlation_digest.clone(),
    );
    assert_eq!(confirmation.confirmation_digest(), &confirmation_digest);
    assert_eq!(
        confirmation.expected_workspace_revision(),
        expected_workspace_revision
    );
    assert_eq!(
        confirmation.receipt_correlation_digest(),
        &receipt_correlation_digest
    );

    let transport = DeterministicPlatformV2Transport::new([
        v2_negotiation(),
        DeterministicPlatformV2Step::V2(Box::new(PlatformV2Response::Refused(
            PlatformV2Refusal::new("unavailable", "provider unavailable").unwrap(),
        ))),
    ]);
    let mut client = PlatformV2Client::new_testing(transport);
    client
        .negotiate(PlatformVersionOffer::new(vec![2]).unwrap())
        .unwrap();
    assert!(matches!(
        client
            .execute_confirmed_review_action(
                workspace.clone(),
                expected_revision,
                action.clone(),
                idempotency_key.clone(),
                confirmation,
            )
            .unwrap(),
        ReviewReceiptResult::Refused(_)
    ));

    let requests = client.transport().requests();
    assert_eq!(requests.len(), 1);
    let automonique_protocol::platform_v2_transport::PlatformV2Request::ExecuteReviewAction(
        request,
    ) = requests[0].request()
    else {
        panic!("confirmed review action request expected")
    };
    assert_eq!(request.workspace(), &workspace);
    assert_eq!(request.expected_revision(), expected_revision);
    assert_eq!(request.action(), &action);
    assert_eq!(request.idempotency_key(), &idempotency_key);
    assert_eq!(request.confirmation_digest(), Some(&confirmation_digest));
    assert_eq!(
        request.expected_workspace_revision(),
        Some(expected_workspace_revision)
    );
    assert_eq!(
        request.receipt_correlation_digest(),
        Some(&receipt_correlation_digest)
    );
}

#[test]
fn downgrade_and_refusal_never_enable_v2_requests() {
    for response in [
        PlatformNegotiationResponse::Negotiated(negotiated(PlatformVersion::V1)),
        PlatformNegotiationResponse::Refused(
            PlatformV2Refusal::new("unsupported", "major two is unavailable").unwrap(),
        ),
    ] {
        let transport =
            DeterministicPlatformV2Transport::new([DeterministicPlatformV2Step::Negotiation(
                response,
            )]);
        let mut client = PlatformV2Client::new_testing(transport);
        let result = client
            .negotiate(PlatformVersionOffer::new(vec![1, 2]).unwrap())
            .unwrap();
        assert!(matches!(
            result,
            NegotiationResult::Downgraded(_) | NegotiationResult::Refused(_)
        ));
        assert_eq!(
            client.get_work_context(project("project-a")),
            Err(ClientError::NotNegotiated)
        );
    }
}

#[test]
fn refuses_malformed_oversized_and_mismatched_negotiation_responses() {
    let mut malformed = PlatformV2Client::new_testing(DeterministicPlatformV2Transport::new([
        DeterministicPlatformV2Step::MalformedResponse,
    ]));
    assert_eq!(
        malformed.negotiate(PlatformVersionOffer::new(vec![2]).unwrap()),
        Err(ClientError::Protocol)
    );
    let mut oversized = PlatformV2Client::new_testing(DeterministicPlatformV2Transport::new([
        DeterministicPlatformV2Step::OversizedResponse,
    ]));
    assert_eq!(
        oversized.negotiate(PlatformVersionOffer::new(vec![2]).unwrap()),
        Err(ClientError::ResponseTooLarge)
    );

    let mut client = PlatformV2Client::new_testing(DeterministicPlatformV2Transport::new([
        DeterministicPlatformV2Step::UncorrelatedNegotiation(
            PlatformNegotiationResponse::Negotiated(
                NegotiatedPlatform::new(
                    PlatformVersion::V2,
                    PLATFORM_SCHEMA_V2,
                    WorkContextAvailability::V2Structured,
                )
                .unwrap(),
            ),
        ),
    ]));
    assert_eq!(
        client.negotiate(PlatformVersionOffer::new(vec![2]).unwrap()),
        Err(ClientError::Correlation)
    );
}

#[test]
fn rejects_a_valid_record_for_the_wrong_coordinate() {
    let transport = DeterministicPlatformV2Transport::new([
        DeterministicPlatformV2Step::Negotiation(PlatformNegotiationResponse::Negotiated(
            negotiated(PlatformVersion::V2),
        )),
        DeterministicPlatformV2Step::V2(Box::new(PlatformV2Response::WorkContextRecord(
            project_record("project-b"),
        ))),
    ]);
    let mut client = PlatformV2Client::new_testing(transport);
    client
        .negotiate(PlatformVersionOffer::new(vec![2]).unwrap())
        .unwrap();
    assert_eq!(
        client.get_work_context(project("project-a")),
        Err(ClientError::Protocol)
    );
}

#[test]
fn rejects_lineage_projected_for_another_workspace_coordinate() {
    use automonique_protocol::platform_v2::UserWorkspaceId;

    let requested = UserWorkspaceId::new("workspace-a").unwrap();
    let projection =
        LineageProjection::new(UserWorkspaceId::new("workspace-b").unwrap(), vec![], vec![])
            .unwrap();
    let transport = DeterministicPlatformV2Transport::new([
        v2_negotiation(),
        DeterministicPlatformV2Step::V2(Box::new(PlatformV2Response::LineageResult(projection))),
    ]);
    let mut client = PlatformV2Client::new_testing(transport);
    client
        .negotiate(PlatformVersionOffer::new(vec![2]).unwrap())
        .unwrap();
    assert_eq!(
        client.get_lineage(ProjectId::new("project-a").unwrap(), requested),
        Err(ClientError::Protocol)
    );
}

#[test]
fn rejects_pages_and_resyncs_for_other_request_coordinates() {
    let after = WorkContextCursor::new("cursor-1").unwrap();
    let query = WorkContextQuery::new(
        vec![WorkContextKind::Project],
        vec![],
        Some(ProjectId::new("project-a").unwrap()),
        None,
        Some(after.clone()),
        10,
    )
    .unwrap();
    let wrong_page = WorkContextPage::new(9, Some(after.clone()), None, false, vec![]).unwrap();
    let transport = DeterministicPlatformV2Transport::new([
        v2_negotiation(),
        DeterministicPlatformV2Step::V2(Box::new(PlatformV2Response::WorkContextPage(wrong_page))),
    ]);
    let mut client = PlatformV2Client::new_testing(transport);
    client
        .negotiate(PlatformVersionOffer::new(vec![2]).unwrap())
        .unwrap();
    assert_eq!(
        client.query_work_contexts(query.clone()),
        Err(ClientError::Protocol)
    );

    let transport = DeterministicPlatformV2Transport::new([
        v2_negotiation(),
        DeterministicPlatformV2Step::V2(Box::new(PlatformV2Response::WorkContextResync(
            WorkContextResync::new(WorkContextCursor::new("cursor-2").unwrap()),
        ))),
    ]);
    let mut client = PlatformV2Client::new_testing(transport);
    client
        .negotiate(PlatformVersionOffer::new(vec![2]).unwrap())
        .unwrap();
    assert_eq!(
        client.query_work_contexts(query),
        Err(ClientError::Protocol)
    );
}

#[test]
fn rejects_mutation_preview_for_a_substituted_intent() {
    let requested = WorkContextMutationIntent::CreateProject(
        CreateProjectIntent::new(WorkContextLabel::new("Requested").unwrap(), vec![]).unwrap(),
    );
    let substituted = WorkContextMutationIntent::CreateProject(
        CreateProjectIntent::new(WorkContextLabel::new("Substituted").unwrap(), vec![]).unwrap(),
    );
    let key = IdempotencyKey::new("mutation-1").unwrap();
    let proposal = WorkContextMutationProposal::new(
        Actor::new("tenant-1", "operator-1").unwrap(),
        ResourceAuthority::Automonique,
        WorkContextAuthority::EMPTY,
        key.clone(),
        substituted,
    )
    .unwrap();
    let preview = MutationPreview::new(
        MutationPreviewRef::new(
            MutationPreviewId::new("preview-1").unwrap(),
            Revision::FIRST,
        ),
        proposal,
        None,
        Some(project("created-project")),
        vec![],
        WorkContextAuthority::EMPTY,
        WorkContextAuthority::EMPTY,
        MutationApprovalRequirement::NotRequired,
        EpochMillis::from_millis(1_000),
        EpochMillis::from_millis(2_000),
    )
    .unwrap();
    let transport = DeterministicPlatformV2Transport::new([
        v2_negotiation(),
        DeterministicPlatformV2Step::V2(Box::new(PlatformV2Response::MutationPreview(preview))),
    ]);
    let mut client = PlatformV2Client::new_testing(transport);
    client
        .negotiate(PlatformVersionOffer::new(vec![2]).unwrap())
        .unwrap();
    assert_eq!(
        client.prepare_mutation(key, requested),
        Err(ClientError::Protocol)
    );
}

#[test]
fn rejects_a_mutation_approval_that_reverses_the_requested_decision() {
    let key = IdempotencyKey::new("mutation-decision-1").unwrap();
    let intent = WorkContextMutationIntent::CreateProject(
        CreateProjectIntent::new(WorkContextLabel::new("Requested").unwrap(), vec![]).unwrap(),
    );
    let proposal = WorkContextMutationProposal::new(
        Actor::new("tenant-1", "operator-1").unwrap(),
        ResourceAuthority::Automonique,
        WorkContextAuthority::EMPTY,
        key,
        intent,
    )
    .unwrap();
    let preview = MutationPreview::new(
        MutationPreviewRef::new(
            MutationPreviewId::new("preview-decision-1").unwrap(),
            Revision::FIRST,
        ),
        proposal,
        None,
        Some(project("created-project")),
        vec![],
        WorkContextAuthority::EMPTY,
        WorkContextAuthority::EMPTY,
        MutationApprovalRequirement::Required,
        EpochMillis::from_millis(1_000),
        EpochMillis::from_millis(2_000),
    )
    .unwrap();
    let digest = work_context_mutation_preview_digest(&preview).unwrap();
    let approval = MutationApproval::new(
        MutationApprovalId::new("approval-1").unwrap(),
        &preview,
        digest,
        MutationApprovalDecision::Denied,
        Actor::new("tenant-1", "operator-1").unwrap(),
        EpochMillis::from_millis(1_100),
        EpochMillis::from_millis(1_900),
    )
    .unwrap();
    let transport = DeterministicPlatformV2Transport::new([
        v2_negotiation(),
        DeterministicPlatformV2Step::V2(Box::new(PlatformV2Response::MutationApproval(
            RawMutationApprovalDocument::from_approval(&approval).unwrap(),
        ))),
    ]);
    let mut client = PlatformV2Client::new_testing(transport);
    client
        .negotiate(PlatformVersionOffer::new(vec![2]).unwrap())
        .unwrap();
    assert_eq!(
        client.decide_mutation(
            preview.preview().clone(),
            digest,
            MutationApprovalDecision::Granted,
        ),
        Err(ClientError::Protocol)
    );
}

fn listing_cursor(offset: usize) -> ResourceListingCursor {
    ResourceListingCursor::new(format!(
        "rl2.{}.{}.{offset}",
        "a".repeat(64),
        "b".repeat(64)
    ))
    .unwrap()
}

#[test]
fn a_listing_answer_must_carry_the_bound_this_caller_asked_to_be_held_to() {
    // Asking for more than the server's ceiling is admissible, and the answer
    // is the server's page. A client that accepted any `granted_limit` would
    // have no way to tell that page apart from a truncation.
    let asked = ResourceListingQuery::new(vec![], vec![], None, 4_096).unwrap();
    let honest = ResourceListingPage::new(4_096, 128, None, None, false, vec![]).unwrap();
    let transport = DeterministicPlatformV2Transport::new([
        v2_negotiation(),
        DeterministicPlatformV2Step::V2(Box::new(PlatformV2Response::ResourceListingPage(honest))),
    ]);
    let mut client = PlatformV2Client::new_testing(transport);
    client
        .negotiate(PlatformVersionOffer::new(vec![2]).unwrap())
        .unwrap();
    assert!(matches!(
        client.list_resources(asked.clone()).unwrap(),
        ResourceListingResult::Page(_)
    ));

    // The same page answering a request for four is a bound nobody asked for.
    let transport = DeterministicPlatformV2Transport::new([
        v2_negotiation(),
        DeterministicPlatformV2Step::V2(Box::new(PlatformV2Response::ResourceListingPage(
            ResourceListingPage::new(4_096, 128, None, None, false, vec![]).unwrap(),
        ))),
    ]);
    let mut client = PlatformV2Client::new_testing(transport);
    client
        .negotiate(PlatformVersionOffer::new(vec![2]).unwrap())
        .unwrap();
    assert_eq!(
        client.list_resources(ResourceListingQuery::new(vec![], vec![], None, 4).unwrap()),
        Err(ClientError::Protocol)
    );
}

#[test]
fn a_listing_resync_must_name_the_cursor_this_caller_presented() {
    let presented = listing_cursor(4);
    let transport = DeterministicPlatformV2Transport::new([
        v2_negotiation(),
        DeterministicPlatformV2Step::V2(Box::new(PlatformV2Response::ResourceListingResync(
            ResourceListingResync::new(presented.clone()),
        ))),
    ]);
    let mut client = PlatformV2Client::new_testing(transport);
    client
        .negotiate(PlatformVersionOffer::new(vec![2]).unwrap())
        .unwrap();
    assert!(matches!(
        client
            .list_resources(ResourceListingQuery::new(vec![], vec![], Some(presented), 8).unwrap())
            .unwrap(),
        ResourceListingResult::Resync(_)
    ));

    let transport = DeterministicPlatformV2Transport::new([
        v2_negotiation(),
        DeterministicPlatformV2Step::V2(Box::new(PlatformV2Response::ResourceListingResync(
            ResourceListingResync::new(listing_cursor(9)),
        ))),
    ]);
    let mut client = PlatformV2Client::new_testing(transport);
    client
        .negotiate(PlatformVersionOffer::new(vec![2]).unwrap())
        .unwrap();
    assert_eq!(
        client.list_resources(
            ResourceListingQuery::new(vec![], vec![], Some(listing_cursor(4)), 8).unwrap()
        ),
        Err(ClientError::Protocol)
    );
}
