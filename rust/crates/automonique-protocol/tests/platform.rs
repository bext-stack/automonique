// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::codec::RequestId;
use automonique_protocol::platform::*;
use automonique_protocol::platform_api::{PlatformRequestMessage, PlatformResponseMessage};
use automonique_protocol::primitives::{EpochMillis, Revision, ValueError};
use automonique_protocol::wire::{JsonValue, Message};

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
    assert_eq!(
        PlatformParameter::new("x".repeat(MAX_PLATFORM_PARAMETER_BYTES))
            .unwrap()
            .as_str()
            .len(),
        MAX_PLATFORM_PARAMETER_BYTES
    );
}

#[test]
fn session_command_state_is_bounded_and_kind_safe() {
    let session = record(ResourceKind::Session, "session-command", 4);
    let approval = SessionCommandTarget {
        target: coordinate(ResourceAuthority::Automonique, ResourceKind::Approval),
        revision: Revision::new(5).unwrap(),
    };
    assert_eq!(
        SessionCommandState::new(
            session.clone(),
            None,
            vec![approval; MAX_SESSION_COMMAND_APPROVALS + 1],
        ),
        Err(PlatformError::TooManyCommandApprovals)
    );
    assert_eq!(
        SessionCommandState::new(
            session,
            Some(SessionCommandTarget {
                target: coordinate(ResourceAuthority::Automonique, ResourceKind::Approval),
                revision: Revision::new(5).unwrap(),
            }),
            Vec::new(),
        ),
        Err(PlatformError::CommandTargetInvalid)
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
    assert_eq!(
        SessionApprovalDecision::parse("approve"),
        Err(PlatformError::UnknownEnum {
            field: "session_approval_decision"
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
    let run = coordinate(ResourceAuthority::Automonique, ResourceKind::Run);
    let approval = coordinate(ResourceAuthority::Automonique, ResourceKind::Approval);
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
        PlatformRequest::SessionCommandState(SessionCommandStateRequest {
            session: session.clone(),
        }),
        PlatformRequest::SessionFollowUp(SessionFollowUpRequest {
            client: client.clone(),
            session: session.clone(),
            expected_session_revision: Revision::new(7).unwrap(),
            idempotency_key: IdempotencyKey::new("retry-follow-up").unwrap(),
            text: PlatformParameter::new("continue with the bounded task\nwithout raw output")
                .unwrap(),
        }),
        PlatformRequest::SessionRunStop(SessionRunStopRequest {
            client: client.clone(),
            session: session.clone(),
            expected_session_revision: Revision::new(7).unwrap(),
            run,
            expected_run_revision: Revision::new(8).unwrap(),
            idempotency_key: IdempotencyKey::new("retry-stop").unwrap(),
        }),
        PlatformRequest::SessionApprovalDecision(SessionApprovalDecisionRequest {
            client: client.clone(),
            session: session.clone(),
            expected_session_revision: Revision::new(7).unwrap(),
            approval,
            expected_approval_revision: Revision::new(9).unwrap(),
            idempotency_key: IdempotencyKey::new("retry-approval").unwrap(),
            decision: SessionApprovalDecision::Deny,
        }),
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
            session: session.clone(),
            client,
            lease: ControlLeaseId::new("lease-1").unwrap(),
            idempotency_key: key,
        }),
        PlatformRequest::SessionHistorySnapshot(
            SessionHistorySnapshotRequest::new(session.clone(), 2).unwrap(),
        ),
        PlatformRequest::SessionHistoryPage(
            SessionHistoryPageRequest::new(session.clone(), 9_007_199_254_740_993, 2).unwrap(),
        ),
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
fn session_command_requests_refuse_additional_fields() {
    let request = PlatformRequestMessage::new(
        RequestId::new("strict-session-command").unwrap(),
        PlatformRequest::SessionFollowUp(SessionFollowUpRequest {
            client: ClientId::new("client-1").unwrap(),
            session: coordinate(ResourceAuthority::Automonique, ResourceKind::Session),
            expected_session_revision: Revision::new(7).unwrap(),
            idempotency_key: IdempotencyKey::new("retry-follow-up").unwrap(),
            text: PlatformParameter::new("continue").unwrap(),
        }),
    )
    .to_message()
    .unwrap();
    let JsonValue::Object(mut entries) = request.body().clone() else {
        panic!("request body is an object");
    };
    entries.push((
        "provider_payload".to_owned(),
        JsonValue::String("raw".to_owned()),
    ));
    let malformed = Message::new(request.envelope().clone(), JsonValue::Object(entries));
    let error = PlatformRequestMessage::from_canonical_bytes(&malformed.to_canonical_bytes())
        .expect_err("an additional command field must be refused");
    assert_eq!(error.category(), "platform_invalid_body");
}

/// `client` was added to `execute` and `get_receipt` after v1 shipped. A
/// body without the key is the shape every earlier client sends and decodes
/// as `None`; an explicit `null` is the same; a string is the client; any
/// other value, and any unknown key, is still refused.
#[test]
fn execute_and_receipt_bodies_accept_an_absent_client_key() {
    let execute = PlatformRequestMessage::new(
        RequestId::new("pre-client-execute").unwrap(),
        PlatformRequest::Execute(
            ExecuteRequest::new(
                PlatformAction::SubmitRequest,
                coordinate(ResourceAuthority::Automonique, ResourceKind::Node),
                IdempotencyKey::new("submit-1").unwrap(),
                None,
                None,
            )
            .unwrap(),
        ),
    );
    let receipt = PlatformRequestMessage::new(
        RequestId::new("pre-client-receipt").unwrap(),
        PlatformRequest::GetReceipt(GetReceiptRequest {
            client: None,
            id: None,
            idempotency_key: Some(IdempotencyKey::new("submit-1").unwrap()),
        }),
    );
    for framed in [execute, receipt] {
        let message = framed.to_message().unwrap();
        let JsonValue::Object(entries) = message.body().clone() else {
            panic!("request body is an object");
        };
        assert!(
            entries
                .iter()
                .any(|(key, value)| key == "client" && *value == JsonValue::Null)
        );

        let without: Vec<_> = entries
            .iter()
            .filter(|(key, _)| key != "client")
            .cloned()
            .collect();
        let absent = Message::new(message.envelope().clone(), JsonValue::Object(without));
        assert_eq!(
            PlatformRequestMessage::from_canonical_bytes(&absent.to_canonical_bytes()).unwrap(),
            framed,
            "an absent client key is the pre-existing wire shape"
        );

        let mut named = entries.clone();
        for (key, value) in &mut named {
            if key == "client" {
                *value = JsonValue::String("client-9".to_owned());
            }
        }
        let with_client = Message::new(message.envelope().clone(), JsonValue::Object(named));
        let decoded =
            PlatformRequestMessage::from_canonical_bytes(&with_client.to_canonical_bytes())
                .unwrap();
        let client = match decoded.request() {
            PlatformRequest::Execute(request) => request.client.clone(),
            PlatformRequest::GetReceipt(request) => request.client.clone(),
            other => panic!("unexpected request {other:?}"),
        };
        assert_eq!(client, Some(ClientId::new("client-9").unwrap()));

        let mut wrong = entries.clone();
        for (key, value) in &mut wrong {
            if key == "client" {
                *value = JsonValue::Bool(true);
            }
        }
        let wrong = Message::new(message.envelope().clone(), JsonValue::Object(wrong));
        assert_eq!(
            PlatformRequestMessage::from_canonical_bytes(&wrong.to_canonical_bytes())
                .expect_err("a non-string client is refused")
                .category(),
            "platform_invalid_body"
        );

        let mut extra = entries.clone();
        extra.push(("actor".to_owned(), JsonValue::String("x".to_owned())));
        let extra = Message::new(message.envelope().clone(), JsonValue::Object(extra));
        assert_eq!(
            PlatformRequestMessage::from_canonical_bytes(&extra.to_canonical_bytes())
                .expect_err("an unknown key is still refused")
                .category(),
            "platform_invalid_body"
        );
    }
}

/// The AG-UI adapter's exact request set, as its own test suite emits it,
/// must decode here. The adapter test writes these canonical payloads from
/// its real request path; a change on either side breaks the build instead
/// of production (#130).
#[test]
fn the_ag_ui_adapter_request_set_decodes_on_this_wire() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../adapters/ag-ui/test/fixtures/platform-requests.json"
    );
    let text = std::fs::read_to_string(path).expect("adapter request fixtures are checked in");
    let JsonValue::Object(entries) =
        automonique_protocol::wire::parse_canonical(text.trim().as_bytes())
            .expect("fixture file is canonical JSON")
    else {
        panic!("fixture file is an object of kind -> canonical payload");
    };
    let expected = [
        "capabilities",
        "snapshot",
        "list_sessions",
        "execute",
        "get_receipt",
    ];
    for kind in expected {
        assert!(
            entries.iter().any(|(key, _)| key.starts_with(kind)),
            "the adapter fixture covers {kind}"
        );
    }
    for (label, payload) in &entries {
        let JsonValue::String(payload) = payload else {
            panic!("{label}: payload is the canonical request string");
        };
        let decoded = PlatformRequestMessage::from_canonical_bytes(payload.as_bytes())
            .unwrap_or_else(|error| panic!("{label}: {error}"));
        let kind = decoded
            .to_message()
            .expect("decoded request re-encodes")
            .envelope()
            .kind()
            .as_str()
            .to_owned();
        assert!(label.starts_with(&kind), "{label} decodes as {kind}");
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
        PlatformResponse::SessionCommandState(
            SessionCommandState::new(
                record(ResourceKind::Session, "session-command-1", 7),
                Some(SessionCommandTarget {
                    target: coordinate(ResourceAuthority::Automonique, ResourceKind::Run),
                    revision: Revision::new(8).unwrap(),
                }),
                vec![SessionCommandTarget {
                    target: coordinate(ResourceAuthority::Automonique, ResourceKind::Approval),
                    revision: Revision::new(9).unwrap(),
                }],
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
            session: session.clone(),
            client,
            lease: ControlLeaseId::new("lease-1").unwrap(),
        },
        PlatformResponse::SessionHistory(
            SessionHistoryPage::new(
                session.clone(),
                4,
                4,
                9_007_199_254_740_993,
                9_007_199_254_740_997,
                false,
                vec![
                    SessionHistoryEvent::Message {
                        cursor: 9_007_199_254_740_994,
                        at: EpochMillis::from_millis(1),
                        evidence: SessionHistoryEvidence::Authoritative,
                        role: SessionHistoryRole::User,
                        text: SessionHistoryText::new("hello").unwrap(),
                        truncated: false,
                    },
                    SessionHistoryEvent::ToolState {
                        cursor: 9_007_199_254_740_995,
                        at: EpochMillis::from_millis(2),
                        evidence: SessionHistoryEvidence::Synthetic,
                        state: SessionHistoryToolState::InProgress,
                        label: Some(SessionHistoryText::new("search").unwrap()),
                        truncated: false,
                    },
                    SessionHistoryEvent::RunState {
                        cursor: 9_007_199_254_740_996,
                        at: EpochMillis::from_millis(3),
                        state: SessionHistoryRunState::Completed,
                    },
                    SessionHistoryEvent::Unknown {
                        cursor: 9_007_199_254_740_997,
                        at: EpochMillis::from_millis(4),
                        source: SessionHistoryUnknownSource::AdapterEvent,
                    },
                ],
            )
            .unwrap(),
        ),
        PlatformResponse::SessionHistoryResync(SessionHistoryResync::new(session, 20, 40).unwrap()),
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
