// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::admin::{
    ADMIN_PROTOCOL, AdminCommand, AdminError, AdminInstanceId, AdminOutboxEvidence,
    AdminOutboxEvidenceParts, AdminReconciliationEvidence, AdminRefusalCategory, AdminRequest,
    AdminResponse, DaemonState, DaemonStatus, IntakePause, IntakeResume, MAX_ADMIN_CANONICAL_BYTES,
    MAX_INSTANCE_ID_BYTES, MAX_INTAKE_ACTOR_BYTES, MAX_INTAKE_REASON_BYTES,
    MAX_RUN_SUBMISSION_KEY_BYTES, MAX_SUBMITTED_RUN_SPEC_BYTES, MAX_SYNTHETIC_KEY_BYTES,
    MAX_SYNTHETIC_SCOPE_BYTES, MAX_SYNTHETIC_TASK_BYTES, OperationalMetric, OperationalStatus,
    OperationalStatusParts, OutboxReconciliation, OutboxReconciliationDecision,
    OutboxReconciliationParts, ReconciliationFailure, SubmittedRunSpec, SyntheticSubmission,
};
use automonique_protocol::codec::{CodecError, FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_protocol::digest::Sha256;
use automonique_protocol::tools::RunId;

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
    .and_then(|status| {
        status.with_operational(
            OperationalStatus::new(OperationalStatusParts {
                observed_ms: 100,
                reconciliation_pending: 0,
                outbox_pending_ready: 2,
                outbox_pending_delayed: 1,
                outbox_in_flight_live: 4,
                outbox_in_flight_ambiguous: 0,
                outbox_delivered: 5,
                outbox_dead_lettered: 6,
                outbox_oldest_ready_age_ms: 7,
                telegram_pollers_live: 0,
                telegram_pollers_expired: 0,
                telegram_offset_lag: OperationalMetric::Unavailable,
                provider_available: OperationalMetric::Unavailable,
                sandbox_launch_refusals: OperationalMetric::Unavailable,
            })
            .expect("operational status"),
        )
    })
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
    assert_eq!(
        status.telegram_state(),
        automonique_protocol::admin::TelegramState::DisabledNoClient
    );
    assert_eq!(status.telegram_poller_epoch(), None);
    let operational = status.operational().expect("operational projection");
    assert_eq!(operational.observed_ms(), 100);
    assert_eq!(operational.outbox_in_flight_ambiguous(), 0);
    assert_eq!(
        operational.provider_available(),
        OperationalMetric::Unavailable
    );
}

#[test]
fn status_without_a_real_operational_projection_cannot_be_encoded() {
    let status = DaemonStatus::new(
        AdminInstanceId::new("daemon-without-projection").expect("instance"),
        DaemonState::Ready,
        1,
        1,
        0,
        0,
        0,
        true,
    )
    .expect("base status");
    assert_eq!(status.operational(), None);
    assert_eq!(
        AdminResponse::Status {
            request_id: request_id(),
            status,
        }
        .to_message()
        .expect_err("missing projection must fail closed"),
        AdminError::InvalidBody
    );
    assert_eq!(
        OperationalStatus::new(OperationalStatusParts {
            observed_ms: 0,
            reconciliation_pending: 0,
            outbox_pending_ready: 0,
            outbox_pending_delayed: 0,
            outbox_in_flight_live: 0,
            outbox_in_flight_ambiguous: 0,
            outbox_delivered: 0,
            outbox_dead_lettered: 0,
            outbox_oldest_ready_age_ms: 0,
            telegram_pollers_live: 0,
            telegram_pollers_expired: 0,
            telegram_offset_lag: OperationalMetric::Unavailable,
            provider_available: OperationalMetric::Unavailable,
            sandbox_launch_refusals: OperationalMetric::Unavailable,
        })
        .expect_err("zero observation cannot look measured"),
        AdminError::InvalidBody
    );
}

#[test]
fn contradictory_operational_health_is_refused_on_construction_and_decode() {
    assert_eq!(
        OperationalStatus::new(OperationalStatusParts {
            observed_ms: 1,
            reconciliation_pending: 0,
            outbox_pending_ready: 0,
            outbox_pending_delayed: 0,
            outbox_in_flight_live: 0,
            outbox_in_flight_ambiguous: 0,
            outbox_delivered: 0,
            outbox_dead_lettered: 0,
            outbox_oldest_ready_age_ms: 0,
            telegram_pollers_live: 0,
            telegram_pollers_expired: 0,
            telegram_offset_lag: OperationalMetric::Unavailable,
            provider_available: OperationalMetric::measured(2).expect("wire integer"),
            sandbox_launch_refusals: OperationalMetric::Unavailable,
        })
        .expect_err("availability is boolean-valued"),
        AdminError::InvalidBody
    );

    let response = AdminResponse::Status {
        request_id: request_id(),
        status: status(),
    };
    let payload = String::from_utf8(response.to_message().expect("message").to_canonical_bytes())
        .expect("canonical UTF-8");
    let contradictory = payload.replacen(
        "\"reconciliation_pending\":0",
        "\"reconciliation_pending\":1",
        1,
    );
    assert_eq!(
        AdminResponse::from_canonical_bytes(contradictory.as_bytes())
            .expect_err("ready status cannot carry reconciliation debt"),
        AdminError::InvalidBody
    );

    let mismatched_queue = payload.replacen(
        "\"outbox_pending_ready\":2",
        "\"outbox_pending_ready\":1",
        1,
    );
    assert_eq!(
        AdminResponse::from_canonical_bytes(mismatched_queue.as_bytes())
            .expect_err("queue aggregate must match its projection"),
        AdminError::InvalidBody
    );
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
    let payload = String::from_utf8(
        AdminResponse::Status {
            request_id: request_id(),
            status: status(),
        }
        .to_message()
        .expect("status message")
        .to_canonical_bytes(),
    )
    .expect("UTF-8")
    .replace("\"state\":\"ready\"", "\"state\":\"recovering\"");
    assert_eq!(
        AdminResponse::from_canonical_bytes(payload.as_bytes()).expect_err("unknown state"),
        AdminError::UnknownState
    );
}

#[test]
fn telegram_status_is_closed_and_epoch_coherent() {
    let owned = DaemonStatus::new(
        AdminInstanceId::new("daemon-telegram").expect("instance"),
        DaemonState::Ready,
        1,
        1,
        0,
        0,
        0,
        true,
    )
    .and_then(|status| {
        status.with_telegram(
            automonique_protocol::admin::TelegramState::LeaseOwnedNoClient,
            Some(9),
        )
    })
    .expect("owned no-client state");
    assert_eq!(owned.telegram_poller_epoch(), Some(9));
    for (state, epoch) in [
        (
            automonique_protocol::admin::TelegramState::DisabledNoClient,
            Some(1),
        ),
        (
            automonique_protocol::admin::TelegramState::LeaseOwnedNoClient,
            None,
        ),
    ] {
        assert_eq!(
            DaemonStatus::new(
                AdminInstanceId::new("d").expect("instance"),
                DaemonState::Ready,
                1,
                1,
                0,
                0,
                0,
                true,
            )
            .and_then(|status| status.with_telegram(state, epoch))
            .expect_err("incoherent state"),
            AdminError::InvalidBody
        );
    }
    let unknown = String::from_utf8(
        AdminResponse::Status {
            request_id: request_id(),
            status: status(),
        }
        .to_message()
        .expect("status message")
        .to_canonical_bytes(),
    )
    .expect("UTF-8")
    .replace("disabled_no_client", "enabled");
    assert_eq!(
        AdminResponse::from_canonical_bytes(unknown.as_bytes())
            .expect_err("unknown telegram state"),
        AdminError::InvalidBody
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

#[test]
fn run_spec_custody_requests_and_receipts_round_trip_exactly() {
    let document = br#"{"schema":"automonique.run-spec/v1"}"#.to_vec();
    let submission =
        SubmittedRunSpec::sealed(document.clone(), "operator:run:7").expect("bounded document");
    assert_eq!(submission.spec_digest(), &Sha256::digest(&document));

    let request = AdminRequest::submit_run(request_id(), submission.clone());
    let payload = request
        .to_message()
        .expect("encode submission")
        .to_canonical_bytes();
    let decoded = AdminRequest::from_canonical_bytes(&payload).expect("decode submission");
    assert_eq!(decoded, request);
    assert_eq!(decoded.command(), AdminCommand::SubmitRun);
    assert_eq!(decoded.run_submission(), Some(&submission));
    assert_eq!(
        decoded.run_submission().expect("carried").document(),
        document
    );

    let response = AdminResponse::RunAccepted {
        request_id: request_id(),
        run_id: RunId::new("run-1").expect("run identity"),
        spec_digest: Sha256::digest(&document),
        submission_id: 3,
        replay: true,
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
fn a_maximal_run_submission_fits_one_admin_frame() {
    // Worst case on every axis the bound was computed for: a maximal request
    // identifier, a maximal idempotency key made entirely of bytes that
    // JSON-escapes to two, and a maximal document.
    let worst_case = AdminRequest::submit_run(
        RequestId::new("r".repeat(128)).expect("maximal request identifier"),
        SubmittedRunSpec::sealed(
            vec![b'x'; MAX_SUBMITTED_RUN_SPEC_BYTES],
            "\"".repeat(MAX_RUN_SUBMISSION_KEY_BYTES),
        )
        .expect("exact maximum document"),
    )
    .to_message()
    .expect("maximal document encodes")
    .to_canonical_bytes();
    assert!(worst_case.len() > 2 * MAX_SUBMITTED_RUN_SPEC_BYTES);
    assert!(worst_case.len() <= MAX_ADMIN_CANONICAL_BYTES);

    let mut frame = Vec::new();
    encode_frame(&worst_case, &mut frame).expect("maximal submission frames");
    let FrameDecode::Frame { payload, .. } = decode_frame(&frame).expect("valid frame") else {
        panic!("complete submission reported incomplete")
    };
    assert_eq!(
        AdminRequest::from_canonical_bytes(payload)
            .expect("admitted submission")
            .run_submission()
            .expect("carried document")
            .document()
            .len(),
        MAX_SUBMITTED_RUN_SPEC_BYTES
    );
}

#[test]
fn oversized_run_spec_documents_are_refused_at_encode_and_decode() {
    let oversized = MAX_SUBMITTED_RUN_SPEC_BYTES + 1;
    assert_eq!(
        SubmittedRunSpec::sealed(vec![b'x'; oversized], "key").expect_err("oversized document"),
        AdminError::DocumentTooLarge {
            max_bytes: MAX_SUBMITTED_RUN_SPEC_BYTES,
            actual_bytes: oversized,
        }
    );
    assert_eq!(
        SubmittedRunSpec::sealed(Vec::new(), "key").expect_err("empty document"),
        AdminError::InvalidBody
    );

    // The wire is refused on the same bound. The two payloads below pin the
    // *order* of the decode checks, not only their outcome: the second is
    // oversized and not hexadecimal and not even-length, and the bound still
    // wins. That is what makes the ceiling a check on the encoded text rather
    // than on a buffer already expanded from it.
    let oversized_body = |document_hex: String| {
        format!(
            "{{\"body\":{{\"document_hex\":\"{document_hex}\",\"idempotency_key\":\"key\",\"spec_digest\":\"sha256:{}\"}},\"kind\":\"submit_run\",\"protocol\":\"{ADMIN_PROTOCOL}\",\"request_id\":\"r\",\"version\":1}}",
            "0".repeat(64)
        )
    };
    for payload in [
        oversized_body("78".repeat(oversized)),
        oversized_body(format!("{}z", "78".repeat(oversized))),
    ] {
        assert_eq!(
            AdminRequest::from_canonical_bytes(payload.as_bytes())
                .expect_err("oversized document")
                .category(),
            "admin_document_too_large"
        );
    }
}

#[test]
fn malformed_document_hex_and_digests_are_refused() {
    let body = |document_hex: &str, digest: &str| {
        format!(
            "{{\"body\":{{\"document_hex\":\"{document_hex}\",\"idempotency_key\":\"key\",\"spec_digest\":\"{digest}\"}},\"kind\":\"submit_run\",\"protocol\":\"{ADMIN_PROTOCOL}\",\"request_id\":\"r\",\"version\":1}}"
        )
    };
    let digest = format!("sha256:{}", "0".repeat(64));
    for payload in [
        // Odd length is refused rather than padded.
        body("7b7", &digest),
        // Uppercase is refused rather than folded: one byte string, one spelling.
        body("7B", &digest),
        body("zz", &digest),
        // A digest without its algorithm name is not a digest.
        body("7b", &"0".repeat(64)),
        body("7b", "sha256:0"),
        body("7b", &format!("sha256:{}", "A".repeat(64))),
    ] {
        assert_eq!(
            AdminRequest::from_canonical_bytes(payload.as_bytes()).expect_err("malformed field"),
            AdminError::InvalidBody
        );
    }

    for payload in [
        br#"{"body":{"document_hex":"7b","spec_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"kind":"submit_run","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"document_hex":"7b","future":true,"idempotency_key":"key","spec_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"kind":"submit_run","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"document_hex":123,"idempotency_key":"key","spec_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"kind":"submit_run","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
    ] {
        assert_eq!(
            AdminRequest::from_canonical_bytes(payload).expect_err("inexact body"),
            AdminError::InvalidBody
        );
    }
}

#[test]
fn a_declared_digest_is_carried_without_being_verified_or_echoed() {
    // The carrier does not compare the pair: an inconsistent submission is on
    // the wire whether or not this constructor admits one, and the daemon is
    // the layer that must answer it with a correlated refusal.
    let document = b"secret-argv-and-environment".to_vec();
    let lying = SubmittedRunSpec::declared(
        document.clone(),
        Sha256::digest(b"different bytes"),
        "operator:run:8",
    )
    .expect("inconsistent pair is representable");
    assert_ne!(lying.spec_digest(), &Sha256::digest(&document));
    let payload = AdminRequest::submit_run(request_id(), lying.clone())
        .to_message()
        .expect("encode")
        .to_canonical_bytes();
    assert_eq!(
        AdminRequest::from_canonical_bytes(&payload)
            .expect("carried unverified")
            .run_submission(),
        Some(&lying)
    );

    // Neither the debug rendering nor a refusal grows the document.
    let secret = "secret-argv-and-environment";
    assert!(!format!("{lying:?}").contains(secret));
    assert!(
        !format!(
            "{:?}",
            AdminRequest::submit_run(request_id(), lying.clone())
        )
        .contains(secret)
    );
    let error = SubmittedRunSpec::sealed(
        secret.repeat(MAX_SUBMITTED_RUN_SPEC_BYTES).into_bytes(),
        "key",
    )
    .expect_err("oversized");
    assert!(!error.to_string().contains(secret));
}

#[test]
fn run_acceptance_receipts_are_exact_and_bounded() {
    let response = |submission_id| AdminResponse::RunAccepted {
        request_id: request_id(),
        run_id: RunId::new("run-1").expect("run identity"),
        spec_digest: Sha256::digest(b"document"),
        submission_id,
        replay: false,
    };
    // An unwritten row must not be reportable as accepted.
    assert_eq!(
        response(0).to_message().expect_err("zero row identity"),
        AdminError::InvalidBody
    );
    let payload = String::from_utf8(
        response(4)
            .to_message()
            .expect("encode")
            .to_canonical_bytes(),
    )
    .expect("canonical UTF-8");
    for broken in [
        payload.replacen("\"submission_id\":4", "\"submission_id\":0", 1),
        payload.replacen("\"submission_id\":4", "\"submission_id\":-1", 1),
        payload.replacen("\"replay\":false", "\"replay\":\"no\"", 1),
        payload.replacen("\"run_id\":\"run-1\"", "\"run_id\":\"\"", 1),
        payload.replacen("\"spec_digest\":\"sha256:", "\"spec_digest\":\"sha512:", 1),
    ] {
        assert_eq!(
            AdminResponse::from_canonical_bytes(broken.as_bytes()).expect_err("invalid receipt"),
            AdminError::InvalidBody
        );
    }
}

/// A status snapshot with intake closed by an operator rather than by damage.
fn paused_status() -> DaemonStatus {
    DaemonStatus::new(
        AdminInstanceId::new("daemon-7").expect("valid instance"),
        DaemonState::Ready,
        7,
        41,
        2,
        3,
        1,
        false,
    )
    .and_then(|status| status.with_intake_pause(true))
    .and_then(|status| {
        status.with_operational(
            OperationalStatus::new(OperationalStatusParts {
                observed_ms: 100,
                reconciliation_pending: 0,
                outbox_pending_ready: 2,
                outbox_pending_delayed: 1,
                outbox_in_flight_live: 4,
                outbox_in_flight_ambiguous: 0,
                outbox_delivered: 5,
                outbox_dead_lettered: 6,
                outbox_oldest_ready_age_ms: 7,
                telegram_pollers_live: 0,
                telegram_pollers_expired: 0,
                telegram_offset_lag: OperationalMetric::Unavailable,
                provider_available: OperationalMetric::Unavailable,
                sandbox_launch_refusals: OperationalMetric::Unavailable,
            })
            .expect("operational status"),
        )
    })
    .expect("wire-representable paused status")
}

#[test]
fn intake_pause_and_resume_commands_are_exact_bounded_and_round_trip() {
    let pause = IntakePause::new("operator:ada", "provider incident 4417").expect("pause body");
    let request = AdminRequest::pause_intake(request_id(), pause.clone());
    let decoded = AdminRequest::from_canonical_bytes(
        &request.to_message().expect("encode").to_canonical_bytes(),
    )
    .expect("decode pause");
    assert_eq!(decoded.command(), AdminCommand::PauseIntake);
    assert_eq!(decoded.intake_pause(), Some(&pause));
    assert_eq!(decoded.intake_resume(), None);
    assert_eq!(decoded, request);

    let resume = IntakeResume::new("operator:bo").expect("resume body");
    let request = AdminRequest::resume_intake(request_id(), resume.clone());
    let decoded = AdminRequest::from_canonical_bytes(
        &request.to_message().expect("encode").to_canonical_bytes(),
    )
    .expect("decode resume");
    assert_eq!(decoded.command(), AdminCommand::ResumeIntake);
    assert_eq!(decoded.intake_resume(), Some(&resume));
    assert_eq!(decoded.intake_pause(), None);
    assert_eq!(decoded, request);

    // Exact bodies: no missing field, no extra field, no borrowed field from
    // the sibling command.
    for payload in [
        br#"{"body":{"actor":"operator:ada"},"kind":"pause_intake","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"actor":"operator:ada","future":true,"reason":"x"},"kind":"pause_intake","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"reason":"x"},"kind":"pause_intake","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"actor":1,"reason":"x"},"kind":"pause_intake","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{},"kind":"pause_intake","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"actor":"operator:bo","reason":"x"},"kind":"resume_intake","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{},"kind":"resume_intake","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
    ] {
        assert_eq!(
            AdminRequest::from_canonical_bytes(payload).expect_err("inexact intake body"),
            AdminError::InvalidBody,
            "{}",
            String::from_utf8_lossy(payload)
        );
    }

    // Bounds are checked on the constructor and therefore on decode too.
    let actor = "a".repeat(MAX_INTAKE_ACTOR_BYTES);
    let reason = "r".repeat(MAX_INTAKE_REASON_BYTES);
    IntakePause::new(actor.clone(), reason.clone()).expect("maximal pause");
    IntakeResume::new(actor.clone()).expect("maximal resume");
    for (actor, reason) in [
        (format!("{actor}a"), reason.clone()),
        (actor.clone(), format!("{reason}r")),
        (String::new(), reason.clone()),
        (actor.clone(), String::new()),
        ("operator:\u{7}ada".to_owned(), reason),
    ] {
        assert_eq!(
            IntakePause::new(actor, reason).expect_err("unbounded pause"),
            AdminError::InvalidBody
        );
    }
    assert_eq!(
        IntakeResume::new(format!("{actor}a")).expect_err("overlong actor"),
        AdminError::InvalidBody
    );
    assert_eq!(
        IntakeResume::new("").expect_err("empty actor"),
        AdminError::InvalidBody
    );
}

#[test]
fn intake_pause_receipts_are_correlated_and_refuse_unwritten_rows() {
    for response in [
        AdminResponse::IntakePaused {
            request_id: request_id(),
            pause_id: 4,
            revision: 1,
        },
        AdminResponse::IntakeResumed {
            request_id: request_id(),
            pause_id: 4,
            revision: 2,
        },
    ] {
        let bytes = response.to_message().expect("encode").to_canonical_bytes();
        assert_eq!(
            AdminResponse::from_canonical_bytes(&bytes).expect("decode"),
            response
        );
        assert_eq!(response.request_id(), &request_id());
    }

    // The two receipts are distinct messages, not one message with a flag: a
    // pause must never decode as the resume that undoes it.
    let paused = AdminResponse::IntakePaused {
        request_id: request_id(),
        pause_id: 4,
        revision: 1,
    };
    let resumed = AdminResponse::IntakeResumed {
        request_id: request_id(),
        pause_id: 4,
        revision: 1,
    };
    assert_ne!(
        paused.to_message().expect("encode").to_canonical_bytes(),
        resumed.to_message().expect("encode").to_canonical_bytes()
    );

    for response in [
        AdminResponse::IntakePaused {
            request_id: request_id(),
            pause_id: 0,
            revision: 1,
        },
        AdminResponse::IntakeResumed {
            request_id: request_id(),
            pause_id: 4,
            revision: 0,
        },
    ] {
        assert_eq!(
            response.to_message().expect_err("unwritten row"),
            AdminError::InvalidBody
        );
    }
    for payload in [
        br#"{"body":{"pause_id":0,"revision":1},"kind":"intake_paused","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"pause_id":4,"revision":0},"kind":"intake_resumed","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"pause_id":4},"kind":"intake_paused","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"future":1,"pause_id":4,"revision":1},"kind":"intake_paused","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
    ] {
        assert_eq!(
            AdminResponse::from_canonical_bytes(payload).expect_err("unwritten receipt"),
            AdminError::InvalidBody
        );
    }
}

#[test]
fn a_reported_pause_cannot_claim_intake_is_still_open() {
    // The coherence rule: paused implies intake is closed.
    let open = DaemonStatus::new(
        AdminInstanceId::new("daemon-7").expect("instance"),
        DaemonState::Ready,
        7,
        41,
        2,
        3,
        1,
        true,
    )
    .expect("base status");
    assert!(!open.intake_paused(), "a fresh status reports no pause");
    assert_eq!(
        open.clone()
            .with_intake_pause(true)
            .expect_err("paused while accepting intake"),
        AdminError::InvalidBody
    );
    // The builder is not a one-way door, and the converse is not required:
    // intake closes for a degraded generation with no pause at all.
    assert!(
        !open
            .with_intake_pause(false)
            .expect("no pause")
            .intake_paused()
    );

    let closed = paused_status();
    assert!(closed.intake_paused());
    assert!(!closed.accepting_intake());
    assert_eq!(closed.state(), DaemonState::Ready, "a pause is not damage");

    let payload = AdminResponse::Status {
        request_id: request_id(),
        status: closed.clone(),
    }
    .to_message()
    .expect("encode")
    .to_canonical_bytes();
    let AdminResponse::Status {
        status: decoded, ..
    } = AdminResponse::from_canonical_bytes(&payload).expect("decode")
    else {
        panic!("wrong response variant")
    };
    assert_eq!(decoded, closed);
    assert!(decoded.intake_paused());
    assert!(!decoded.accepting_intake());

    // The rule is enforced on the wire, not only in the constructor: a peer
    // that hand-writes the incoherent pair is refused rather than believed.
    let incoherent = String::from_utf8(payload)
        .expect("utf-8 body")
        .replace("\"accepting_intake\":false", "\"accepting_intake\":true");
    assert_eq!(
        AdminResponse::from_canonical_bytes(incoherent.as_bytes())
            .expect_err("paused status claiming open intake"),
        AdminError::InvalidBody
    );

    // A status body that predates the field is not silently defaulted.
    let missing = String::from_utf8(
        AdminResponse::Status {
            request_id: request_id(),
            status: status(),
        }
        .to_message()
        .expect("encode")
        .to_canonical_bytes(),
    )
    .expect("utf-8 body")
    .replace("\"intake_paused\":false,", "");
    assert_eq!(
        AdminResponse::from_canonical_bytes(missing.as_bytes())
            .expect_err("status body without the pause field"),
        AdminError::InvalidBody
    );
}
