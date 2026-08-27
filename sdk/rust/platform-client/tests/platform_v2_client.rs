// SPDX-License-Identifier: Apache-2.0

use automonique_platform_client::platform_v2_client::testing::{
    DeterministicPlatformV2Step, DeterministicPlatformV2Transport,
};
use automonique_platform_client::platform_v2_client::{
    NegotiationResult, PlatformV2Client, PlatformV2ClientError as ClientError, WorkContextGetResult,
};
use automonique_protocol::identity::Actor;
use automonique_protocol::platform::{IdempotencyKey, ResourceAuthority};
use automonique_protocol::platform_v2::{
    NegotiatedPlatform, PLATFORM_SCHEMA_V2, PlatformVersion, PlatformVersionOffer, ProjectId,
    WorkContextAttributes, WorkContextAvailability, WorkContextCursor, WorkContextIdentity,
    WorkContextKind, WorkContextLabel, WorkContextLifecycle, WorkContextPage, WorkContextQuery,
    WorkContextRecord, WorkContextResync,
};
use automonique_protocol::platform_v2_lifecycle::{
    CreateProjectIntent, MutationApproval, MutationApprovalDecision, MutationApprovalId,
    MutationApprovalRequirement, MutationPreview, MutationPreviewId, MutationPreviewRef,
    WorkContextAuthority, WorkContextMutationIntent, WorkContextMutationProposal,
};
use automonique_protocol::platform_v2_lifecycle_api::work_context_mutation_preview_digest;
use automonique_protocol::platform_v2_lineage::LineageProjection;
use automonique_protocol::platform_v2_transport::{
    PlatformNegotiationResponse, PlatformV2Refusal, PlatformV2Response, RawMutationApprovalDocument,
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
