// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::codec::RequestId;
use automonique_protocol::platform::*;
use automonique_protocol::platform_api::{PlatformRequestMessage, PlatformResponseMessage};
use automonique_protocol::primitives::{EpochMillis, Revision, ValueError};

fn coordinate(authority: ResourceAuthority, kind: ResourceKind) -> ResourceCoordinate {
    ResourceCoordinate::new(authority, kind, ResourceId::new("resource-1").unwrap())
}

#[test]
fn authorities_remain_distinct_in_resource_identity() {
    let local = coordinate(ResourceAuthority::Automonique, ResourceKind::Run);
    let global = coordinate(ResourceAuthority::AiOperations, ResourceKind::Run);
    assert_ne!(local, global);
    assert_eq!(
        ResourceAuthority::ALL.map(ResourceAuthority::as_str),
        [
            "ai_operations",
            "automonique",
            "github",
            "provider",
            "client"
        ]
    );
}

#[test]
fn every_transport_advertises_one_semantic_method_set() {
    let capabilities = Capabilities::platform_v1();
    assert_eq!(capabilities.methods, PlatformMethod::ALL);
    assert_eq!(capabilities.transports, PlatformTransport::ALL);
    assert_eq!(capabilities.protocol, PLATFORM_PROTOCOL);
    assert_eq!(capabilities.schema, PLATFORM_SCHEMA_V1);
}

#[test]
fn action_authority_is_enforced_before_execution() {
    let result = ExecuteRequest::new(
        PlatformAction::SubmitJob,
        coordinate(ResourceAuthority::Automonique, ResourceKind::Job),
        IdempotencyKey::new("retry-1").unwrap(),
        None,
        None,
    );
    assert_eq!(result, Err(PlatformError::AuthorityMismatch));
}

#[test]
fn opaque_values_are_bounded_and_control_free() {
    assert_eq!(
        ResourceId::new("x".repeat(MAX_PLATFORM_FIELD_BYTES + 1)),
        Err(ValueError::TooLong {
            max_bytes: MAX_PLATFORM_FIELD_BYTES,
            actual_bytes: MAX_PLATFORM_FIELD_BYTES + 1,
        })
    );
    assert_eq!(
        ReceiptId::new("bad\nvalue"),
        Err(ValueError::ControlCharacter)
    );
}

#[test]
fn action_parameters_admit_multiline_prompts_without_widening_identifiers() {
    let prompt = "inspect the workspace\nthen explain the result";
    assert_eq!(PlatformParameter::new(prompt).unwrap().as_str(), prompt);
    assert_eq!(
        PlatformParameter::new("x".repeat(MAX_PLATFORM_PARAMETER_BYTES + 1)),
        Err(ValueError::TooLong {
            max_bytes: MAX_PLATFORM_PARAMETER_BYTES,
            actual_bytes: MAX_PLATFORM_PARAMETER_BYTES + 1,
        })
    );
    assert_eq!(
        PlatformParameter::new("bad\0prompt"),
        Err(ValueError::ControlCharacter)
    );
}

#[test]
fn snapshots_refuse_silent_truncation() {
    let resources = (0..=MAX_SNAPSHOT_RESOURCES)
        .map(|index| {
            ResourceCoordinate::new(
                ResourceAuthority::GitHub,
                ResourceKind::Issue,
                ResourceId::new(format!("issue-{index}")).unwrap(),
            )
        })
        .collect();
    assert_eq!(
        SnapshotRequest::new(resources),
        Err(PlatformError::TooManyResources)
    );
}

#[test]
fn receipt_outcomes_keep_unknown_and_rejection_separate() {
    assert_ne!(ReceiptOutcome::Unknown, ReceiptOutcome::Rejected);
    assert_eq!(
        ReceiptOutcome::ALL.map(ReceiptOutcome::as_str),
        [
            "accepted",
            "completed",
            "rejected",
            "conflict",
            "unknown",
            "resync_required",
        ]
    );

    let freshness = Freshness {
        state: FreshnessState::Fresh,
        observed_at: EpochMillis::EPOCH,
        revision: Revision::FIRST,
    };
    assert_eq!(freshness.revision, Revision::FIRST);
}

#[test]
fn security_sensitive_enums_fail_closed() {
    assert_eq!(
        ResourceAuthority::parse("dashboard"),
        Err(PlatformError::UnknownEnum {
            field: "resource_authority"
        })
    );
    assert_eq!(
        PlatformAction::parse("provider_direct_mutation"),
        Err(PlatformError::UnknownEnum {
            field: "platform_action"
        })
    );
}

#[test]
fn every_compatibility_adapter_names_consumers_and_removal_test() {
    for (index, adapter) in COMPATIBILITY_ADAPTERS.iter().enumerate() {
        assert!(!adapter.name.is_empty());
        assert!(!adapter.consumers.is_empty());
        assert!(!adapter.removal_test.is_empty());
        assert!(
            COMPATIBILITY_ADAPTERS[..index]
                .iter()
                .all(|earlier| earlier.name != adapter.name)
        );
    }
}

fn cursor(sequence: u64) -> PlatformCursor {
    PlatformCursor {
        authority: ResourceAuthority::Automonique,
        topic: CursorTopic::new("operator").unwrap(),
        sequence: Revision::new(sequence).unwrap(),
    }
}

fn record(kind: ResourceKind, id: &str, revision: u64) -> ResourceRecord {
    ResourceRecord {
        resource: ResourceCoordinate::new(
            ResourceAuthority::Automonique,
            kind,
            ResourceId::new(id).unwrap(),
        ),
        freshness: Freshness {
            state: FreshnessState::Fresh,
            observed_at: EpochMillis::from_millis(1_000),
            revision: Revision::new(revision).unwrap(),
        },
        summary: PlatformText::new("ready").unwrap(),
    }
}

#[test]
fn every_platform_request_has_one_canonical_round_trip() {
    let session = record(ResourceKind::Session, "session-1", 2).resource;
    let client = ClientId::new("client-1").unwrap();
    let key = IdempotencyKey::new("retry-1").unwrap();
    let requests = vec![
        PlatformRequest::Capabilities,
        PlatformRequest::Snapshot(SnapshotRequest::new(vec![session.clone()]).unwrap()),
        PlatformRequest::Subscribe(SubscribeRequest {
            cursor: Some(cursor(2)),
        }),
        PlatformRequest::Execute(
            ExecuteRequest::new(
                PlatformAction::StartRun,
                ResourceCoordinate::new(
                    ResourceAuthority::Automonique,
                    ResourceKind::Run,
                    ResourceId::new("run-1").unwrap(),
                ),
                key.clone(),
                Some(Revision::new(3).unwrap()),
                Some(PlatformText::new("interactive").unwrap()),
            )
            .unwrap(),
        ),
        PlatformRequest::Execute(
            ExecuteRequest::new_with_parameter(
                PlatformAction::SubmitRequest,
                ResourceCoordinate::new(
                    ResourceAuthority::Automonique,
                    ResourceKind::Node,
                    ResourceId::new("node-1").unwrap(),
                ),
                IdempotencyKey::new("retry-long-prompt-1").unwrap(),
                Some(Revision::new(5).unwrap()),
                Some(PlatformParameter::new("first line\nsecond line").unwrap()),
            )
            .unwrap(),
        ),
        PlatformRequest::Execute(
            ExecuteRequest::new(
                PlatformAction::Steer,
                ResourceCoordinate::new(
                    ResourceAuthority::Automonique,
                    ResourceKind::ControlLease,
                    ResourceId::new("lease-steer-1").unwrap(),
                ),
                IdempotencyKey::new("retry-steer-1").unwrap(),
                Some(Revision::new(4).unwrap()),
                Some(PlatformText::new("use the corrected input").unwrap()),
            )
            .unwrap(),
        ),
        PlatformRequest::GetReceipt(GetReceiptRequest::by_id(
            ReceiptId::new("receipt-1").unwrap(),
        )),
        PlatformRequest::GetReceipt(GetReceiptRequest::by_idempotency_key(
            IdempotencyKey::new("retry-lookup").unwrap(),
        )),
        PlatformRequest::ListSessions(ListSessionsRequest {
            authority: ResourceAuthority::Automonique,
            cursor: None,
        }),
        PlatformRequest::Attach(AttachRequest {
            session: session.clone(),
            client: client.clone(),
        }),
        PlatformRequest::Detach(DetachRequest {
            session: session.clone(),
            client: client.clone(),
        }),
        PlatformRequest::ClaimControl(ClaimControlRequest {
            session: session.clone(),
            client: client.clone(),
            idempotency_key: key.clone(),
        }),
        PlatformRequest::ReleaseControl(ReleaseControlRequest {
            session,
            client,
            lease: ControlLeaseId::new("lease-1").unwrap(),
            idempotency_key: key,
        }),
    ];
    for (index, request) in requests.into_iter().enumerate() {
        let framed = PlatformRequestMessage::new(
            RequestId::new(format!("platform-request-{index}")).unwrap(),
            request,
        );
        let bytes = framed.to_message().unwrap().to_canonical_bytes();
        assert_eq!(
            PlatformRequestMessage::from_canonical_bytes(&bytes).unwrap(),
            framed
        );
    }
}

#[test]
fn every_platform_response_has_one_canonical_round_trip() {
    let session_record = record(ResourceKind::Session, "session-1", 2);
    let session = session_record.resource.clone();
    let client = ClientId::new("client-1").unwrap();
    let receipt = ActionReceipt {
        id: ReceiptId::new("receipt-1").unwrap(),
        action: PlatformAction::StartRun,
        target: ResourceCoordinate::new(
            ResourceAuthority::Automonique,
            ResourceKind::Run,
            ResourceId::new("run-1").unwrap(),
        ),
        outcome: ReceiptOutcome::Accepted,
        revision: Revision::new(3).unwrap(),
        recorded_at: EpochMillis::from_millis(2_000),
        explanation: None,
    };
    let responses = vec![
        PlatformResponse::Capabilities(Capabilities::platform_v1()),
        PlatformResponse::Snapshot(Snapshot::new(vec![session_record.clone()], cursor(2)).unwrap()),
        PlatformResponse::Subscription(
            Subscription::new(
                vec![PlatformEvent {
                    cursor: cursor(2),
                    resource: session_record.clone(),
                }],
                cursor(2),
            )
            .unwrap(),
        ),
        PlatformResponse::Receipt(receipt),
        PlatformResponse::Sessions(
            SessionList::new(
                vec![SessionRecord {
                    session: session_record,
                    run: None,
                    attachable: true,
                    controllable: true,
                }],
                cursor(2),
            )
            .unwrap(),
        ),
        PlatformResponse::Attached(Attachment {
            session: session.clone(),
            client: client.clone(),
            cursor: cursor(2),
        }),
        PlatformResponse::Detached {
            session: session.clone(),
            client: client.clone(),
        },
        PlatformResponse::ControlClaimed(ControlLease {
            id: ControlLeaseId::new("lease-1").unwrap(),
            session: session.clone(),
            client: client.clone(),
            expires_at: EpochMillis::from_millis(30_000),
            revision: Revision::new(4).unwrap(),
        }),
        PlatformResponse::ControlReleased {
            session,
            client,
            lease: ControlLeaseId::new("lease-1").unwrap(),
        },
        PlatformResponse::Refused {
            outcome: ReceiptOutcome::ResyncRequired,
            explanation: PlatformText::new("fresh snapshot required").unwrap(),
        },
    ];
    for (index, response) in responses.into_iter().enumerate() {
        let framed = PlatformResponseMessage::new(
            RequestId::new(format!("platform-response-{index}")).unwrap(),
            response,
        );
        let bytes = framed.to_message().unwrap().to_canonical_bytes();
        assert_eq!(
            PlatformResponseMessage::from_canonical_bytes(&bytes).unwrap(),
            framed
        );
    }
}
