// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::admin::{
    ADMIN_PROTOCOL, AdminCommand, AdminError, AdminInstanceId, AdminOutboxEvidence,
    AdminOutboxEvidenceParts, AdminReconciliationEvidence, AdminRefusalCategory, AdminRequest,
    AdminResponse, DaemonState, DaemonStatus, MAX_ADMIN_CANONICAL_BYTES, MAX_INSTANCE_ID_BYTES,
    MAX_SYNTHETIC_KEY_BYTES, MAX_SYNTHETIC_SCOPE_BYTES, MAX_SYNTHETIC_TASK_BYTES,
    OutboxReconciliation, OutboxReconciliationDecision, OutboxReconciliationParts,
    ReconciliationFailure, SyntheticSubmission,
};
use automonique_protocol::codec::{CodecError, FrameDecode, RequestId, decode_frame, encode_frame};

fn request_id() -> RequestId {
    RequestId::new("req-admin-1").expect("valid request ID")
}

#[test]
fn outbox_inspection_and_reconciliation_are_exact_correlated_and_redacted() {
    let inspect = AdminRequest::inspect_outbox(request_id(), 9).expect("inspect");
    let decoded = AdminRequest::from_canonical_bytes(
        &inspect.to_message().expect("encode").to_canonical_bytes(),
    )
    .expect("decode");
    assert_eq!(decoded.command(), AdminCommand::InspectOutbox);
    assert_eq!(decoded.outbox_id(), Some(9));

    for decision in [
        OutboxReconciliationDecision::Delivered {
            receipt_key: "provider:9".to_owned(),
        },
        OutboxReconciliationDecision::DeadLetter {
            reason: "operator_refused".to_owned(),
        },
    ] {
        let reconciliation = OutboxReconciliation::new(OutboxReconciliationParts {
            outbox_id: 9,
            expected_generation_id: "generation-old".to_owned(),
            expected_lease_epoch: 4,
            expected_lease_token: "lease:9".to_owned(),
            expected_attempt: 2,
            expected_revision: 7,
            decision,
        })
        .expect("coordinates");
        let request = AdminRequest::reconcile_outbox(request_id(), reconciliation.clone());
        let decoded = AdminRequest::from_canonical_bytes(
            &request.to_message().expect("encode").to_canonical_bytes(),
        )
        .expect("decode");
        assert_eq!(decoded.command(), AdminCommand::ReconcileOutbox);
        assert_eq!(decoded.outbox_reconciliation(), Some(&reconciliation));
    }

    let evidence = AdminOutboxEvidence::new(AdminOutboxEvidenceParts {
        outbox_id: 9,
        intent_key: "intent:9".to_owned(),
        transport: "telegram".to_owned(),
        kind: "telegram.reply".to_owned(),
        state: "in_flight".to_owned(),
        revision: 7,
        attempt: 2,
        lease_token: Some("lease:9".to_owned()),
        lease_generation_id: Some("generation-old".to_owned()),
        lease_holder: Some("holder-old".to_owned()),
        lease_epoch: Some(4),
        lease_expires_ms: Some(100),
        delivery_receipt_key: None,
    })
    .expect("redacted evidence");
    let response = AdminResponse::OutboxInspected {
        request_id: request_id(),
        evidence,
    };
    let bytes = response.to_message().expect("encode").to_canonical_bytes();
    assert!(!String::from_utf8_lossy(&bytes).contains("payload"));
    let debug = format!("{response:?}");
    assert!(!debug.contains("lease:9"));
    assert_eq!(
        AdminResponse::from_canonical_bytes(&bytes).expect("decode"),
        response
    );

    let response = AdminResponse::OutboxReconciled {
        request_id: request_id(),
        outbox_id: 9,
        state: "delivered".to_owned(),
        revision: 8,
        duplicate: true,
    };
    assert_eq!(
        AdminResponse::from_canonical_bytes(
            &response.to_message().expect("encode").to_canonical_bytes()
        )
        .expect("decode"),
        response,
    );

    let widened = br#"{"body":{"decision":"delivered","expected_attempt":2,"expected_generation_id":"generation-old","expected_lease_epoch":4,"expected_lease_token":"lease:9","expected_revision":7,"future":true,"outbox_id":9,"receipt_key":"provider:9"},"kind":"reconcile_outbox","protocol":"automonique.admin","request_id":"r","version":1}"#;
    assert_eq!(
        AdminRequest::from_canonical_bytes(widened).expect_err("extra field"),
        AdminError::InvalidBody
    );
    let partial_lease = br#"{"body":{"attempt":1,"delivery_receipt_key":null,"intent_key":"i","kind":"fake.receipt","lease_epoch":null,"lease_expires_ms":null,"lease_generation_id":"foreground","lease_holder":null,"lease_token":null,"outbox_id":1,"revision":1,"state":"in_flight","transport":"fake"},"kind":"outbox_inspected","protocol":"automonique.admin","request_id":"r","version":1}"#;
    assert_eq!(
        AdminResponse::from_canonical_bytes(partial_lease).expect_err("partial lease evidence"),
        AdminError::InvalidBody
    );
}

#[test]
fn reconciliation_requests_and_receipts_are_exact_and_correlated() {
    let inspect = AdminRequest::inspect_reconciliation(request_id(), 42).expect("inspect");
    let bytes = inspect.to_message().expect("message").to_canonical_bytes();
    let decoded = AdminRequest::from_canonical_bytes(&bytes).expect("decode inspect");
    assert_eq!(decoded.command(), AdminCommand::InspectReconciliation);
    assert_eq!(decoded.reconciliation_run_id(), Some(42));

    let failure = ReconciliationFailure::new(
        42,
        "generation-old",
        7,
        3,
        "operator:decision:42",
        "execution_outcome_unknown",
    )
    .expect("failure");
    let request = AdminRequest::fail_reconciliation(request_id(), failure.clone());
    let decoded = AdminRequest::from_canonical_bytes(
        &request.to_message().expect("message").to_canonical_bytes(),
    )
    .expect("decode failure");
    assert_eq!(decoded.command(), AdminCommand::FailReconciliation);
    assert_eq!(decoded.reconciliation_failure(), Some(&failure));

    let evidence =
        AdminReconciliationEvidence::new(42, "scope:one", "generation-old", 7, 3, false, 0)
            .expect("evidence");
    for response in [
        AdminResponse::ReconciliationInspected {
            request_id: request_id(),
            evidence,
        },
        AdminResponse::ReconciliationFailed {
            request_id: request_id(),
            run_event_id: 10,
            inbox_event_id: 11,
            outbox_id: 12,
            duplicate: false,
        },
        AdminResponse::Refused {
            request_id: request_id(),
            category: AdminRefusalCategory::new("stale_epoch").expect("category"),
        },
    ] {
        let bytes = response.to_message().expect("message").to_canonical_bytes();
        assert_eq!(
            AdminResponse::from_canonical_bytes(&bytes).expect("decode"),
            response
        );
    }
}

fn status() -> DaemonStatus {
    DaemonStatus::new(
        AdminInstanceId::new("daemon-7").expect("valid instance"),
        DaemonState::Ready,
        7,
        41,
        2,
        3,
        1,
        true,
    )
    .expect("wire-representable status")
}

#[test]
fn requests_round_trip_through_canonical_framing() {
    for command in [AdminCommand::Status, AdminCommand::Shutdown] {
        let request = AdminRequest::new(request_id(), command);
        let payload = request
            .to_message()
            .expect("known literals")
            .to_canonical_bytes();
        let mut frame = Vec::new();
        encode_frame(&payload, &mut frame).expect("small frame");
        let decoded_payload = match decode_frame(&frame).expect("valid frame") {
            FrameDecode::Frame { payload, consumed } => {
                assert_eq!(consumed, frame.len());
                payload
            }
            FrameDecode::NeedMore { .. } => panic!("complete request reported incomplete"),
        };
        assert_eq!(
            AdminRequest::from_canonical_bytes(decoded_payload).expect("admitted request"),
            request
        );
    }
}

#[test]
fn synthetic_intake_and_receipt_round_trip_exactly() {
    let submission = SyntheticSubmission::new("workspace:one", "telegram:update:7", "say hello")
        .expect("bounded synthetic work");
    let request = AdminRequest::submit(request_id(), submission.clone());
    let payload = request
        .to_message()
        .expect("encode submission")
        .to_canonical_bytes();
    let decoded = AdminRequest::from_canonical_bytes(&payload).expect("decode submission");
    assert_eq!(decoded, request);
    assert_eq!(decoded.command(), AdminCommand::SubmitSynthetic);
    assert_eq!(decoded.submission(), Some(&submission));

    let response = AdminResponse::SyntheticAccepted {
        request_id: request_id(),
        inbox_id: 42,
        duplicate: false,
    };
    let payload = response
        .to_message()
        .expect("encode receipt")
        .to_canonical_bytes();
    assert_eq!(
        AdminResponse::from_canonical_bytes(&payload).expect("decode receipt"),
        response
    );
}

#[test]
fn synthetic_intake_is_bounded_and_closed() {
    let worst_case = AdminRequest::submit(
        request_id(),
        SyntheticSubmission::new(
            "s".repeat(MAX_SYNTHETIC_SCOPE_BYTES),
            "k".repeat(MAX_SYNTHETIC_KEY_BYTES),
            "\u{1}".repeat(MAX_SYNTHETIC_TASK_BYTES),
        )
        .expect("exact maximum task"),
    )
    .to_message()
    .expect("maximum task encodes")
    .to_canonical_bytes();
    assert!(worst_case.len() <= MAX_ADMIN_CANONICAL_BYTES);
    assert_eq!(
        SyntheticSubmission::new("scope", "key", "x".repeat(MAX_SYNTHETIC_TASK_BYTES + 1))
            .expect_err("oversized task"),
        AdminError::InvalidBody
    );
    assert_eq!(
        SyntheticSubmission::new("bad\nscope", "key", "task").expect_err("control in scope"),
        AdminError::InvalidBody
    );
    for payload in [
        br#"{"body":{"idempotency_key":"key","scope":"scope"},"kind":"submit_synthetic","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"future":true,"idempotency_key":"key","scope":"scope","task":"work"},"kind":"submit_synthetic","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"idempotency_key":"key","scope":"scope","task":1},"kind":"submit_synthetic","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
    ] {
        assert_eq!(
            AdminRequest::from_canonical_bytes(payload).expect_err("invalid submission"),
            AdminError::InvalidBody
        );
    }
}

#[test]
fn status_response_is_exact_and_round_trips() {
    let response = AdminResponse::Status {
        request_id: request_id(),
        status: status(),
    };
    let payload = response
        .to_message()
        .expect("known literals")
        .to_canonical_bytes();
    let decoded = AdminResponse::from_canonical_bytes(&payload).expect("admitted response");
    assert_eq!(decoded, response);
    let AdminResponse::Status { status, .. } = decoded else {
        panic!("wrong response variant")
    };
    assert_eq!(status.instance_id().as_str(), "daemon-7");
    assert_eq!(status.state(), DaemonState::Ready);
    assert_eq!(status.generation(), 7);
    assert_eq!(status.event_cursor(), 41);
    assert_eq!(status.inbox_pending(), 2);
    assert_eq!(status.outbox_pending(), 3);
    assert_eq!(status.running(), 1);
    assert!(status.accepting_intake());
}

#[test]
fn shutdown_acknowledgement_round_trips_with_an_empty_body() {
    let response = AdminResponse::ShutdownAccepted {
        request_id: request_id(),
    };
    let payload = response
        .to_message()
        .expect("known literals")
        .to_canonical_bytes();
    assert_eq!(
        AdminResponse::from_canonical_bytes(&payload).expect("admitted response"),
        response
    );
}

#[test]
fn unknown_protocol_and_version_fail_closed() {
    for (payload, expected) in [
        (
            br#"{"body":{},"kind":"status","protocol":"other.admin","request_id":"r","version":1}"#.as_slice(),
            "unknown_protocol",
        ),
        (
            br#"{"body":{},"kind":"status","protocol":"automonique.admin","request_id":"r","version":2}"#.as_slice(),
            "unsupported_version",
        ),
    ] {
        assert_eq!(
            AdminRequest::from_canonical_bytes(payload)
                .expect_err("unsupported envelope")
                .category(),
            expected
        );
    }
}

#[test]
fn unknown_kinds_and_nonempty_command_bodies_are_refused() {
    let unknown = br#"{"body":{},"kind":"restart","protocol":"automonique.admin","request_id":"r","version":1}"#;
    assert_eq!(
        AdminRequest::from_canonical_bytes(unknown).expect_err("unknown command"),
        AdminError::UnknownKind
    );

    let widened = br#"{"body":{"force":true},"kind":"shutdown","protocol":"automonique.admin","request_id":"r","version":1}"#;
    assert_eq!(
        AdminRequest::from_canonical_bytes(widened).expect_err("widened command"),
        AdminError::InvalidBody
    );
}

#[test]
fn status_body_rejects_missing_extra_wrong_and_negative_fields() {
    for payload in [
        br#"{"body":{"accepting_intake":true,"event_cursor":1,"generation":1,"inbox_pending":0,"instance_id":"d","outbox_pending":0,"running":0},"kind":"status_result","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"accepting_intake":true,"event_cursor":1,"future":0,"generation":1,"inbox_pending":0,"instance_id":"d","outbox_pending":0,"running":0,"state":"ready"},"kind":"status_result","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"accepting_intake":"yes","event_cursor":1,"generation":1,"inbox_pending":0,"instance_id":"d","outbox_pending":0,"running":0,"state":"ready"},"kind":"status_result","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"accepting_intake":true,"event_cursor":1,"generation":-1,"inbox_pending":0,"instance_id":"d","outbox_pending":0,"running":0,"state":"ready"},"kind":"status_result","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
    ] {
        assert_eq!(
            AdminResponse::from_canonical_bytes(payload).expect_err("invalid status body"),
            AdminError::InvalidBody
        );
    }
}

#[test]
fn unknown_state_is_a_security_sensitive_refusal() {
    let payload = br#"{"body":{"accepting_intake":true,"event_cursor":1,"generation":1,"inbox_pending":0,"instance_id":"d","outbox_pending":0,"running":0,"state":"recovering"},"kind":"status_result","protocol":"automonique.admin","request_id":"r","version":1}"#;
    assert_eq!(
        AdminResponse::from_canonical_bytes(payload).expect_err("unknown state"),
        AdminError::UnknownState
    );
}

#[test]
fn identifiers_and_counters_are_bounded_before_encoding() {
    assert_eq!(
        AdminInstanceId::new("x".repeat(MAX_INSTANCE_ID_BYTES + 1)).expect_err("overlong instance"),
        AdminError::InvalidInstanceId
    );
    assert_eq!(
        DaemonStatus::new(
            AdminInstanceId::new("d").expect("valid"),
            DaemonState::Ready,
            i64::MAX as u64 + 1,
            0,
            0,
            0,
            0,
            true,
        )
        .expect_err("counter exceeds wire integer"),
        AdminError::CounterOutOfRange {
            field: "generation"
        }
    );
}

#[test]
fn refusals_do_not_echo_hostile_payloads() {
    let secret = "telegram-secret-123";
    let payload = format!(
        "{{\"body\":{{\"{secret}\":true}},\"kind\":\"status\",\"protocol\":\"{ADMIN_PROTOCOL}\",\"request_id\":\"r\",\"version\":1}}"
    );
    let error = AdminRequest::from_canonical_bytes(payload.as_bytes()).expect_err("invalid body");
    assert!(!error.to_string().contains(secret));
}

#[test]
fn malformed_canonical_json_keeps_the_shared_codec_category() {
    let error = AdminRequest::from_canonical_bytes(b"not-json").expect_err("malformed");
    assert!(matches!(
        error,
        AdminError::Codec(CodecError::MalformedJson)
    ));
}
