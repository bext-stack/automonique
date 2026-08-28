// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::admin::{LocalRequest, LocalRequestError};
use automonique_protocol::codec::{
    CodecError, Envelope, MajorVersion, MessageKind, ProtocolName, RequestId,
};
use automonique_protocol::digest::Sha256;
use automonique_protocol::platform::{
    IdempotencyKey, PLATFORM_PROTOCOL, PlatformRequest, ReceiptId, ResourceAuthority,
    ResourceCoordinate, ResourceId, ResourceKind,
};
use automonique_protocol::platform_api::{PlatformApiError, PlatformRequestMessage};
use automonique_protocol::platform_v2::*;
use automonique_protocol::platform_v2_attention::*;
use automonique_protocol::platform_v2_attention_api::decode_attention_source_snapshot;
use automonique_protocol::platform_v2_lifecycle::*;
use automonique_protocol::platform_v2_lineage::*;
use automonique_protocol::platform_v2_review::*;
use automonique_protocol::platform_v2_review_api::decode_review_snapshot;
use automonique_protocol::platform_v2_transport::*;
use automonique_protocol::primitives::{OpaqueId, Revision};
use automonique_protocol::wire::{JsonValue, Message};

const _: () = assert!(
    MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES > automonique_protocol::codec::MAX_FRAME_BYTES
);

fn request_id(value: &str) -> RequestId {
    RequestId::new(value).unwrap()
}
fn project() -> ProjectId {
    ProjectId::new("project-1").unwrap()
}
fn workspace() -> WorkContextIdentity {
    WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("workspace-1").unwrap())
}
fn identity_for(kind: WorkContextTargetKind) -> WorkContextIdentity {
    WorkContextIdentity::parse_local(kind, format!("{}-1", kind.as_str()).as_str()).unwrap()
}
fn digest() -> MutationPreviewDigest {
    MutationPreviewDigest::from_digest(Sha256::digest(b"preview"))
}
fn preview_ref() -> MutationPreviewRef {
    MutationPreviewRef::new(
        MutationPreviewId::new("preview-1").unwrap(),
        Revision::FIRST,
    )
}
fn mutation_intent() -> WorkContextMutationIntent {
    WorkContextMutationIntent::CreateProject(
        CreateProjectIntent::new(WorkContextLabel::new("Project").unwrap(), vec![]).unwrap(),
    )
}
fn review_action() -> ReviewActionTransportRequest {
    ReviewActionTransportRequest::new_confirmed(
        workspace(),
        Revision::FIRST,
        ReviewAction::RerunCheck {
            check_id: OpaqueId::new("check-1").unwrap(),
            expected_check_revision: Revision::FIRST,
        },
        IdempotencyKey::new("review-action-1").unwrap(),
        ReviewConfirmationDigest::new("ab".repeat(32)).unwrap(),
    )
    .unwrap()
}

#[test]
fn review_action_transport_rejects_the_same_invalid_batch_shapes_as_typescript() {
    let request = |action| {
        ReviewActionTransportRequest::new(
            workspace(),
            Revision::FIRST,
            action,
            IdempotencyKey::new("review-action-batch").unwrap(),
        )
    };
    assert_eq!(
        request(ReviewAction::BatchSendCommentsToAgent { comments: vec![] }),
        Err(PlatformV2TransportError::InvalidBody)
    );

    let target = ReviewCommentTarget::new(OpaqueId::new("comment-1").unwrap(), Revision::FIRST);
    assert_eq!(
        request(ReviewAction::BatchSendCommentsToAgent {
            comments: vec![target.clone(), target],
        }),
        Err(PlatformV2TransportError::InvalidBody)
    );

    assert!(
        request(ReviewAction::BatchSendCommentsToAgent {
            comments: vec![ReviewCommentTarget::new(
                OpaqueId::new("comment-1").unwrap(),
                Revision::FIRST,
            )],
        })
        .is_ok()
    );

    let valid = PlatformV2RequestMessage::new(
        request_id("review-action-batch-wire"),
        PlatformV2Request::ExecuteReviewAction(
            request(ReviewAction::BatchSendCommentsToAgent {
                comments: vec![ReviewCommentTarget::new(
                    OpaqueId::new("comment-1").unwrap(),
                    Revision::FIRST,
                )],
            })
            .unwrap(),
        ),
    )
    .to_canonical_bytes()
    .unwrap();
    let valid = Message::from_canonical_bytes(&valid).unwrap();
    let first_target = valid
        .body()
        .get("action")
        .and_then(|value| value.get("payload"))
        .and_then(|value| value.get("comments"))
        .and_then(JsonValue::as_array)
        .and_then(|values| values.first())
        .unwrap()
        .clone();
    for comments in [vec![], vec![first_target.clone(), first_target]] {
        let mut body = valid.body().clone();
        let JsonValue::Object(fields) = &mut body else {
            panic!("review action body is an object");
        };
        let JsonValue::Object(action) = fields
            .iter_mut()
            .find(|(name, _)| name == "action")
            .map(|(_, value)| value)
            .unwrap()
        else {
            panic!("review action is an object");
        };
        let JsonValue::Object(payload) = action
            .iter_mut()
            .find(|(name, _)| name == "payload")
            .map(|(_, value)| value)
            .unwrap()
        else {
            panic!("review action payload is an object");
        };
        *payload
            .iter_mut()
            .find(|(name, _)| name == "comments")
            .map(|(_, value)| value)
            .unwrap() = JsonValue::Array(comments);
        let hostile = Message::new(valid.envelope().clone(), body).to_canonical_bytes();
        assert_eq!(
            PlatformV2RequestMessage::from_canonical_bytes(&hostile),
            Err(PlatformV2TransportError::InvalidBody)
        );
    }
}

#[test]
fn check_rerun_requires_an_exact_confirmation_digest_and_other_actions_refuse_it() {
    let rerun = ReviewAction::RerunCheck {
        check_id: OpaqueId::new("check-1").unwrap(),
        expected_check_revision: Revision::FIRST,
    };
    assert!(
        ReviewActionTransportRequest::new(
            workspace(),
            Revision::FIRST,
            rerun.clone(),
            IdempotencyKey::new("rerun-unconfirmed").unwrap(),
        )
        .is_err()
    );
    assert!(ReviewConfirmationDigest::new("AB".repeat(32)).is_err());
    assert!(ReviewConfirmationDigest::new("ab".repeat(31)).is_err());
    let digest = ReviewConfirmationDigest::new("ab".repeat(32)).unwrap();
    assert!(!format!("{digest:?}").contains("abababab"));
    assert!(
        ReviewActionTransportRequest::new_confirmed(
            workspace(),
            Revision::FIRST,
            ReviewAction::ApproveReview {
                expected_review_revision: Revision::FIRST,
            },
            IdempotencyKey::new("approval-must-not-carry-rerun-confirmation").unwrap(),
            digest.clone(),
        )
        .is_err()
    );
    assert!(
        ReviewActionTransportRequest::new_confirmed(
            workspace(),
            Revision::FIRST,
            rerun,
            IdempotencyKey::new("rerun-confirmed").unwrap(),
            digest,
        )
        .is_ok()
    );
}

#[test]
fn rust_transport_encoding_matches_the_shared_typescript_corpus() {
    let fixture = include_str!("../fixtures/platform-v2-transport-v1.txt")
        .trim_end()
        .lines()
        .collect::<Vec<_>>();
    assert_eq!(fixture.len(), 4);

    let negotiation = PlatformNegotiationRequestMessage::new(
        request_id("transport-negotiate"),
        PlatformNegotiationRequest::Negotiate(PlatformVersionOffer::new(vec![1, 2]).unwrap()),
    );
    assert_eq!(
        negotiation.to_canonical_bytes().unwrap(),
        fixture[0].as_bytes()
    );

    let v2 = PlatformV2RequestMessage::new(
        request_id("transport-v2"),
        PlatformV2Request::GetWorkContext(workspace()),
    );
    assert_eq!(v2.to_canonical_bytes().unwrap(), fixture[1].as_bytes());

    let capabilities = PlatformV2RequestMessage::new(
        request_id("transport-capabilities"),
        PlatformV2Request::GetLifecycleCapabilities,
    );
    assert_eq!(
        capabilities.to_canonical_bytes().unwrap(),
        fixture[2].as_bytes()
    );

    let capability_response = PlatformV2ResponseMessage::for_request(
        &capabilities,
        PlatformV2Response::LifecycleCapabilities(
            LifecycleCapabilities::new(
                std::collections::BTreeSet::from([project()]),
                LIFECYCLE_CAPABILITY_EFFECT_KINDS
                    .into_iter()
                    .map(|kind| {
                        if matches!(kind, "create_checkout" | "create_host_setup") {
                            LifecycleOperationCapability::available(project(), kind)
                        } else {
                            LifecycleOperationCapability::unavailable(
                                project(),
                                kind,
                                "platform_v2_lifecycle_adapter_pending",
                            )
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
            )
            .unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(
        capability_response.to_canonical_bytes().unwrap(),
        fixture[3].as_bytes()
    );
    assert_eq!(
        PlatformV2ResponseMessage::from_canonical_bytes(fixture[3].as_bytes(), &capabilities)
            .unwrap(),
        capability_response
    );

    let valid = Message::from_canonical_bytes(fixture[3].as_bytes()).unwrap();
    let mut duplicate_body = valid.body().clone();
    let JsonValue::Object(fields) = &mut duplicate_body else {
        panic!("capability response body is an object");
    };
    let JsonValue::Array(projects) = fields
        .iter_mut()
        .find(|(name, _)| name == "projects")
        .map(|(_, value)| value)
        .unwrap()
    else {
        panic!("capability projects are an array");
    };
    projects.push(JsonValue::String(String::from("project-1")));
    let duplicate = Message::new(valid.envelope().clone(), duplicate_body).to_canonical_bytes();
    assert_eq!(
        PlatformV2ResponseMessage::from_canonical_bytes(&duplicate, &capabilities),
        Err(PlatformV2TransportError::InvalidBody)
    );
}

#[test]
fn negotiation_is_a_separate_correlated_major_one_protocol() {
    let request = PlatformNegotiationRequestMessage::new(
        request_id("negotiate-1"),
        PlatformNegotiationRequest::Negotiate(PlatformVersionOffer::new(vec![1, 2]).unwrap()),
    );
    let bytes = request.to_canonical_bytes().unwrap();
    let message = Message::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(
        message.envelope().protocol().as_str(),
        PLATFORM_NEGOTIATION_PROTOCOL
    );
    assert_eq!(message.envelope().version().get(), 1);
    assert_eq!(message.envelope().kind().as_str(), "negotiate");
    assert_eq!(
        PlatformNegotiationRequestMessage::from_canonical_bytes(&bytes).unwrap(),
        request
    );

    let selected = negotiate_platform_version(
        &PlatformVersionOffer::new(vec![1, 2]).unwrap(),
        &PlatformVersionOffer::new(vec![2]).unwrap(),
    )
    .unwrap();
    let response = PlatformNegotiationResponseMessage::for_request(
        &request,
        PlatformNegotiationResponse::Negotiated(selected),
    )
    .unwrap();
    let bytes = response.to_canonical_bytes().unwrap();
    assert_eq!(
        PlatformNegotiationResponseMessage::from_canonical_bytes(&bytes, &request).unwrap(),
        response
    );
    assert_eq!(response.request_id(), request.request_id());
    assert_eq!(
        PlatformNegotiationRequestMessage::from_frame(&request.to_frame().unwrap()).unwrap(),
        request
    );
    assert_eq!(
        PlatformNegotiationResponseMessage::from_frame(&response.to_frame().unwrap(), &request)
            .unwrap(),
        response
    );

    let v1_only = PlatformNegotiationRequestMessage::new(
        request_id("same-correlation"),
        PlatformNegotiationRequest::Negotiate(PlatformVersionOffer::new(vec![1]).unwrap()),
    );
    let selected_v2 = negotiate_platform_version(
        &PlatformVersionOffer::new(vec![2]).unwrap(),
        &PlatformVersionOffer::new(vec![2]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        PlatformNegotiationResponseMessage::for_request(
            &v1_only,
            PlatformNegotiationResponse::Negotiated(selected_v2),
        ),
        Err(PlatformV2TransportError::NegotiationMismatch)
    );
    let v2_only = PlatformNegotiationRequestMessage::new(
        request_id("same-correlation"),
        PlatformNegotiationRequest::Negotiate(PlatformVersionOffer::new(vec![2]).unwrap()),
    );
    let hostile = PlatformNegotiationResponseMessage::for_request(
        &v2_only,
        PlatformNegotiationResponse::Negotiated(selected_v2),
    )
    .unwrap()
    .to_canonical_bytes()
    .unwrap();
    assert_eq!(
        PlatformNegotiationResponseMessage::from_canonical_bytes(&hostile, &v1_only),
        Err(PlatformV2TransportError::NegotiationMismatch)
    );
}

#[test]
fn every_platform_v2_request_kind_round_trips_without_server_owned_inputs() {
    let workspace_id = UserWorkspaceId::new("workspace-1").unwrap();
    let intent_id = WorkspaceIntentId::new("intent-1").unwrap();
    let intent = WorkspaceIntent::Resume(WorkspaceResumeIntent::new(
        intent_id.clone(),
        OrchestrationTaskId::new("task-1").unwrap(),
        workspace_id.clone(),
        Revision::FIRST,
    ));
    let query = WorkContextQuery::new(
        vec![WorkContextKind::UserWorkspace],
        vec![],
        Some(project()),
        None,
        None,
        8,
    )
    .unwrap();
    let requests = vec![
        PlatformV2Request::GetLifecycleCapabilities,
        PlatformV2Request::QueryWorkContexts(query),
        PlatformV2Request::GetWorkContext(workspace()),
        PlatformV2Request::PrepareMutation(MutationPrepareRequest::new(
            IdempotencyKey::new("mutation-1").unwrap(),
            mutation_intent(),
        )),
        PlatformV2Request::DecideMutation(MutationDecisionRequest::new(
            preview_ref(),
            digest(),
            MutationApprovalDecision::Granted,
        )),
        PlatformV2Request::SubmitMutation(MutationSubmitRequest::new(
            preview_ref(),
            digest(),
            Some(MutationApprovalId::new("approval-1").unwrap()),
        )),
        PlatformV2Request::GetMutationReceipt(MutationReceiptLookup::new(
            project(),
            ReceiptLookupKey::ReceiptId(ReceiptId::new("receipt-1").unwrap()),
        )),
        PlatformV2Request::GetLineage(LineageReadRequest::new(project(), workspace_id)),
        PlatformV2Request::SubmitWorkspaceIntent(WorkspaceIntentRequest::new(project(), intent)),
        PlatformV2Request::GetWorkspaceIntent(WorkspaceIntentLookup::new(project(), intent_id)),
        PlatformV2Request::GetReview(ReviewReadRequest::new(project(), workspace()).unwrap()),
        PlatformV2Request::GetAttentionSourceSnapshot(AttentionReadRequest::new(
            AttentionSource::new(
                AttentionSourceKind::ProviderSession,
                AttentionSourceId::new("provider-feed-1").unwrap(),
            ),
            project(),
            UserWorkspaceId::new("workspace-1").unwrap(),
        )),
        PlatformV2Request::GetReviewCapabilities(
            ReviewReadRequest::new(project(), workspace()).unwrap(),
        ),
        PlatformV2Request::ExecuteReviewAction(review_action()),
        PlatformV2Request::GetReviewReceipt(
            ReviewReceiptLookup::new(
                project(),
                workspace(),
                IdempotencyKey::new("review-action-1").unwrap(),
            )
            .unwrap(),
        ),
    ];
    for (index, request) in requests.into_iter().enumerate() {
        let message = PlatformV2RequestMessage::new(request_id(&format!("v2-{index}")), request);
        let bytes = message.to_canonical_bytes().unwrap();
        let wire = Message::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(wire.envelope().protocol().as_str(), PLATFORM_PROTOCOL);
        assert_eq!(wire.envelope().version().get(), 2);
        if wire.envelope().kind().as_str() == "prepare_mutation" {
            let encoded = wire.body().to_canonical_bytes();
            let encoded = std::str::from_utf8(&encoded).unwrap();
            for forbidden in [
                "actor",
                "actor_authority",
                "authority",
                "request_digest",
                "issued_at_ms",
                "preview",
            ] {
                assert!(!encoded.contains(&format!("\"{forbidden}\"")));
            }
        }
        if wire.envelope().kind().as_str() == "execute_review_action" {
            let encoded = wire.body().to_canonical_bytes();
            let encoded = std::str::from_utf8(&encoded).unwrap();
            for forbidden in ["actor", "authentication", "authority"] {
                assert!(!encoded.contains(&format!("\"{forbidden}\"")));
            }
        }
        assert_eq!(
            PlatformV2RequestMessage::from_canonical_bytes(&bytes).unwrap(),
            message
        );
        assert_eq!(
            PlatformV2RequestMessage::from_frame(&message.to_frame().unwrap()).unwrap(),
            message
        );
    }
}

#[test]
fn mutation_commands_and_receipt_lookups_refuse_server_owned_or_ambiguous_fields() {
    let decision = PlatformV2RequestMessage::new(
        request_id("decision-extra"),
        PlatformV2Request::DecideMutation(MutationDecisionRequest::new(
            preview_ref(),
            digest(),
            MutationApprovalDecision::Granted,
        )),
    )
    .to_canonical_bytes()
    .unwrap();
    let decision = Message::from_canonical_bytes(&decision).unwrap();
    let mut body = decision.body().clone();
    let JsonValue::Object(fields) = &mut body else {
        panic!("a decision body is an object");
    };
    fields.push(("decided_at_ms".to_owned(), JsonValue::Integer(1)));
    let hostile = Message::new(decision.envelope().clone(), body).to_canonical_bytes();
    assert!(PlatformV2RequestMessage::from_canonical_bytes(&hostile).is_err());

    let lookup = PlatformV2RequestMessage::new(
        request_id("lookup-ambiguous"),
        PlatformV2Request::GetMutationReceipt(MutationReceiptLookup::new(
            project(),
            ReceiptLookupKey::ReceiptId(ReceiptId::new("receipt-1").unwrap()),
        )),
    )
    .to_canonical_bytes()
    .unwrap();
    let lookup = Message::from_canonical_bytes(&lookup).unwrap();
    let mut body = lookup.body().clone();
    let JsonValue::Object(fields) = &mut body else {
        panic!("a lookup body is an object");
    };
    let (_, idempotency_key) = fields
        .iter_mut()
        .find(|(name, _)| name == "idempotency_key")
        .unwrap();
    *idempotency_key = JsonValue::String("second-key".to_owned());
    let hostile = Message::new(lookup.envelope().clone(), body).to_canonical_bytes();
    assert_eq!(
        PlatformV2RequestMessage::from_canonical_bytes(&hostile),
        Err(PlatformV2TransportError::InvalidBody)
    );
}

#[test]
fn response_documents_round_trip_and_review_envelope_fits_its_declared_ceiling() {
    let capability_request = PlatformV2RequestMessage::new(
        request_id("capabilities-response"),
        PlatformV2Request::GetLifecycleCapabilities,
    );
    let capability_response = PlatformV2ResponseMessage::for_request(
        &capability_request,
        PlatformV2Response::LifecycleCapabilities(
            LifecycleCapabilities::new(
                std::collections::BTreeSet::from([project()]),
                LIFECYCLE_CAPABILITY_EFFECT_KINDS
                    .into_iter()
                    .map(|kind| {
                        if matches!(kind, "create_checkout" | "create_host_setup") {
                            LifecycleOperationCapability::available(project(), kind)
                        } else {
                            LifecycleOperationCapability::unavailable(
                                project(),
                                kind,
                                "platform_v2_lifecycle_adapter_pending",
                            )
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
            )
            .unwrap(),
        ),
    )
    .unwrap();
    let bytes = capability_response.to_canonical_bytes().unwrap();
    assert_eq!(
        PlatformV2ResponseMessage::from_canonical_bytes(&bytes, &capability_request).unwrap(),
        capability_response
    );
    assert_eq!(
        LifecycleCapabilities::new(std::collections::BTreeSet::from([project()]), Vec::new()),
        Err(PlatformV2TransportError::InvalidBody)
    );
    assert_eq!(
        LifecycleOperationCapability::unavailable(
            project(),
            "generic_execute",
            "platform_v2_lifecycle_adapter_pending"
        ),
        Err(PlatformV2TransportError::InvalidBody)
    );

    let review_capability_request = PlatformV2RequestMessage::new(
        request_id("review-capabilities-response"),
        PlatformV2Request::GetReviewCapabilities(
            ReviewReadRequest::new(project(), workspace()).unwrap(),
        ),
    );
    let ci = ReviewAuthority::new(
        ReviewAuthorityKind::Ci,
        ReviewAuthorityId::new("ci-1").unwrap(),
    );
    let review_capability_response = PlatformV2ResponseMessage::for_request(
        &review_capability_request,
        PlatformV2Response::ReviewCapabilities(
            ReviewCapabilities::new(
                project(),
                workspace(),
                Revision::new(9).unwrap(),
                vec![
                    ReviewCheckRerunCapability::new(
                        ReviewCheckId::new("check-1").unwrap(),
                        Revision::new(7).unwrap(),
                        ci,
                        ReviewConfirmationDigest::new("ab".repeat(32)).unwrap(),
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
        ),
    )
    .unwrap();
    let bytes = review_capability_response.to_canonical_bytes().unwrap();
    assert_eq!(
        PlatformV2ResponseMessage::from_canonical_bytes(&bytes, &review_capability_request,)
            .unwrap(),
        review_capability_response
    );

    let query = WorkContextQuery::new(
        vec![WorkContextKind::Project],
        vec![],
        Some(project()),
        None,
        None,
        1,
    )
    .unwrap();
    let request = PlatformV2RequestMessage::new(
        request_id("response-1"),
        PlatformV2Request::QueryWorkContexts(query),
    );
    let page = WorkContextPage::new(1, None, None, false, vec![]).unwrap();
    assert_eq!(
        PlatformV2ResponseMessage::for_request(
            &PlatformV2RequestMessage::new(
                request_id("response-1"),
                PlatformV2Request::GetWorkContext(workspace()),
            ),
            PlatformV2Response::WorkContextPage(page.clone()),
        ),
        Err(PlatformV2TransportError::ResponseMismatch)
    );
    let response =
        PlatformV2ResponseMessage::for_request(&request, PlatformV2Response::WorkContextPage(page))
            .unwrap();
    let bytes = response.to_canonical_bytes().unwrap();
    assert_eq!(
        PlatformV2ResponseMessage::from_canonical_bytes(&bytes, &request).unwrap(),
        response
    );
    assert_eq!(response.request_id(), request.request_id());
    assert_eq!(
        PlatformV2ResponseMessage::from_frame(&response.to_frame().unwrap(), &request).unwrap(),
        response
    );

    let snapshot =
        decode_review_snapshot(include_bytes!("../fixtures/platform-v2-review-v1.json")).unwrap();
    let review_request = PlatformV2RequestMessage::new(
        request_id("review-response"),
        PlatformV2Request::GetReview(ReviewReadRequest::new(project(), workspace()).unwrap()),
    );
    let review = PlatformV2ResponseMessage::for_request(
        &review_request,
        PlatformV2Response::ReviewResult(snapshot),
    )
    .unwrap();
    let bytes = review.to_canonical_bytes().unwrap();
    assert!(bytes.len() <= MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES);
    assert_eq!(
        PlatformV2ResponseMessage::from_canonical_bytes(&bytes, &review_request).unwrap(),
        review
    );
    assert_eq!(
        PlatformV2ResponseMessage::from_canonical_bytes(
            &bytes,
            &PlatformV2RequestMessage::new(
                request_id("review-response"),
                PlatformV2Request::GetWorkContext(workspace()),
            ),
        ),
        Err(PlatformV2TransportError::ResponseMismatch)
    );

    let attention_snapshot = decode_attention_source_snapshot(include_bytes!(
        "../fixtures/platform-v2-attention-v1.json"
    ))
    .unwrap();
    let attention_request = PlatformV2RequestMessage::new(
        request_id("attention-response"),
        PlatformV2Request::GetAttentionSourceSnapshot(AttentionReadRequest::new(
            attention_snapshot.source().clone(),
            attention_snapshot.project().clone(),
            attention_snapshot.user_workspace().clone(),
        )),
    );
    let attention_response = PlatformV2ResponseMessage::for_request(
        &attention_request,
        PlatformV2Response::AttentionSourceSnapshot(attention_snapshot),
    )
    .unwrap();
    let attention_bytes = attention_response.to_canonical_bytes().unwrap();
    assert_eq!(
        PlatformV2ResponseMessage::from_canonical_bytes(&attention_bytes, &attention_request)
            .unwrap(),
        attention_response
    );
    assert_eq!(
        PlatformV2ResponseMessage::from_canonical_bytes(
            &attention_bytes,
            &PlatformV2RequestMessage::new(
                request_id("attention-response"),
                PlatformV2Request::GetReview(
                    ReviewReadRequest::new(project(), workspace()).unwrap()
                ),
            ),
        ),
        Err(PlatformV2TransportError::ResponseMismatch)
    );
    assert_eq!(
        MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES,
        automonique_protocol::platform_v2_review_api::MAX_REVIEW_SNAPSHOT_CANONICAL_BYTES
            + PLATFORM_V2_ENVELOPE_OVERHEAD_BYTES
    );
    assert_eq!(
        MAX_PLATFORM_V2_REQUEST_CANONICAL_BYTES,
        512 * 1024 + PLATFORM_V2_ENVELOPE_OVERHEAD_BYTES
    );
    assert!(matches!(
        PlatformV2RequestMessage::from_canonical_bytes(&vec![
            b'x';
            MAX_PLATFORM_V2_REQUEST_CANONICAL_BYTES
                + 1
        ]),
        Err(PlatformV2TransportError::FrameTooLarge { .. })
    ));
    assert!(matches!(
        PlatformV2ResponseMessage::from_canonical_bytes(
            &vec![b'x'; MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES + 1],
            &request,
        ),
        Err(PlatformV2TransportError::FrameTooLarge { .. })
    ));
}

#[test]
fn local_dispatch_routes_by_protocol_and_major_without_fallback() {
    let v1 = PlatformRequestMessage::new(request_id("v1-golden"), PlatformRequest::Capabilities)
        .to_message()
        .unwrap();
    let v1_bytes = v1.to_canonical_bytes();
    assert_eq!(
        v1_bytes,
        br#"{"body":{},"kind":"capabilities","protocol":"automonique.platform","request_id":"v1-golden","version":1}"#
    );
    assert!(matches!(
        LocalRequest::from_canonical_bytes(&v1_bytes).unwrap(),
        LocalRequest::Platform(_)
    ));

    let v1_body_at_v2 = Message::new(
        Envelope::new(
            ProtocolName::new(PLATFORM_PROTOCOL).unwrap(),
            MajorVersion::new(2).unwrap(),
            request_id("v1-at-v2"),
            MessageKind::new("capabilities").unwrap(),
        ),
        JsonValue::Object(vec![]),
    )
    .to_canonical_bytes();
    assert!(matches!(
        LocalRequest::from_canonical_bytes(&v1_body_at_v2),
        Err(LocalRequestError::PlatformV2(
            PlatformV2TransportError::UnknownKind
        ))
    ));

    let v2 = PlatformV2RequestMessage::new(
        request_id("v2-at-v1"),
        PlatformV2Request::GetWorkContext(workspace()),
    )
    .to_canonical_bytes()
    .unwrap();
    assert!(matches!(
        LocalRequest::from_canonical_bytes(&v2).unwrap(),
        LocalRequest::PlatformV2(_)
    ));
    let v2 = Message::from_canonical_bytes(&v2).unwrap();
    let wrong_major = Message::new(
        Envelope::new(
            ProtocolName::new(PLATFORM_PROTOCOL).unwrap(),
            MajorVersion::FIRST,
            v2.envelope().request_id().clone(),
            v2.envelope().kind().clone(),
        ),
        v2.body().clone(),
    )
    .to_canonical_bytes();
    assert!(matches!(
        LocalRequest::from_canonical_bytes(&wrong_major),
        Err(LocalRequestError::Platform(PlatformApiError::UnknownKind))
    ));

    let wrong_negotiation_major = Message::new(
        Envelope::new(
            ProtocolName::new(PLATFORM_NEGOTIATION_PROTOCOL).unwrap(),
            MajorVersion::new(2).unwrap(),
            request_id("negotiation-major-2"),
            MessageKind::new("negotiate").unwrap(),
        ),
        JsonValue::Object(vec![]),
    )
    .to_canonical_bytes();

    let negotiation = PlatformNegotiationRequestMessage::new(
        request_id("negotiation-local"),
        PlatformNegotiationRequest::Negotiate(PlatformVersionOffer::new(vec![2]).unwrap()),
    )
    .to_canonical_bytes()
    .unwrap();
    assert!(matches!(
        LocalRequest::from_canonical_bytes(&negotiation).unwrap(),
        LocalRequest::PlatformNegotiation(_)
    ));
    assert_eq!(
        LocalRequest::from_canonical_bytes(&wrong_negotiation_major).unwrap_err(),
        LocalRequestError::Envelope(CodecError::UnsupportedVersion {
            supported_min: 1,
            supported_max: 1,
            offered: 2,
        })
    );
}

#[test]
fn review_reads_and_receipts_accept_only_review_workspace_kinds() {
    let project = project();
    let key = IdempotencyKey::new("lookup-1").unwrap();
    for kind in [
        WorkContextTargetKind::UserWorkspace,
        WorkContextTargetKind::AttemptWorkspace,
        WorkContextTargetKind::Session,
    ] {
        let workspace = identity_for(kind);
        assert!(ReviewReadRequest::new(project.clone(), workspace.clone()).is_ok());
        assert!(ReviewReceiptLookup::new(project.clone(), workspace, key.clone()).is_ok());
    }

    for kind in [
        WorkContextTargetKind::Repository,
        WorkContextTargetKind::PlatformSession,
    ] {
        let coordinate_kind = match kind {
            WorkContextTargetKind::Repository => ResourceKind::Repository,
            WorkContextTargetKind::PlatformSession => ResourceKind::Session,
            _ => unreachable!(),
        };
        let coordinate = ResourceCoordinate::new(
            ResourceAuthority::Automonique,
            coordinate_kind,
            ResourceId::new(format!("{}-1", kind.as_str())).unwrap(),
        );
        let workspace = match kind {
            WorkContextTargetKind::Repository => {
                WorkContextIdentity::Repository(V1RepositoryRef::new(coordinate).unwrap())
            }
            WorkContextTargetKind::PlatformSession => {
                WorkContextIdentity::PlatformSession(V1SessionRef::new(coordinate).unwrap())
            }
            _ => unreachable!(),
        };
        assert_eq!(
            ReviewReadRequest::new(project.clone(), workspace.clone()),
            Err(PlatformV2TransportError::InvalidBody)
        );
        assert_eq!(
            ReviewReceiptLookup::new(project.clone(), workspace, key.clone()),
            Err(PlatformV2TransportError::InvalidBody)
        );
    }

    for kind in [
        WorkContextTargetKind::Project,
        WorkContextTargetKind::HostSetup,
        WorkContextTargetKind::Checkout,
        WorkContextTargetKind::Pane,
    ] {
        let workspace = identity_for(kind);
        assert_eq!(
            ReviewReadRequest::new(project.clone(), workspace.clone()),
            Err(PlatformV2TransportError::InvalidBody)
        );
        assert_eq!(
            ReviewReceiptLookup::new(project.clone(), workspace, key.clone()),
            Err(PlatformV2TransportError::InvalidBody)
        );
    }
}
