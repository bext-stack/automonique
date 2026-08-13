// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::admin::{
    ADMIN_PROTOCOL, AdminCommand, AdminError, AdminInstanceId, AdminOutboxEvidence,
    AdminOutboxEvidenceParts, AdminReconciliationEvidence, AdminRefusalCategory, AdminRequest,
    AdminResponse, DaemonState, DaemonStatus, DurableStateCounts, DurableStateCountsParts,
    IntakePause, IntakeResume, MAX_ADMIN_CANONICAL_BYTES, MAX_INSTANCE_ID_BYTES,
    MAX_INTAKE_ACTOR_BYTES, MAX_INTAKE_REASON_BYTES, MAX_RUN_SUBMISSION_KEY_BYTES,
    MAX_SUBMITTED_RUN_SPEC_BYTES, MAX_SYNTHETIC_KEY_BYTES, MAX_SYNTHETIC_SCOPE_BYTES,
    MAX_SYNTHETIC_TASK_BYTES, OperationalMetric, OperationalStatus, OperationalStatusParts,
    OutboxReconciliation, OutboxReconciliationDecision, OutboxReconciliationParts,
    ReconciliationFailure, SubmittedRunSpec, SyntheticSubmission,
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
    .and_then(|status| status.with_durable_state(durable_state()))
    .expect("wire-representable status")
}

/// The durable counts a complete status carries, with one store unreadable.
///
/// `tenures_recorded` is [`OperationalMetric::Unavailable`] on purpose: the
/// fixture every status test shares must exercise both arms of the metric, or
/// the unavailable arm would only ever be encoded by the test that asks for it.
fn durable_state() -> DurableStateCounts {
    DurableStateCounts::new(parts()).expect("coherent durable counts")
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
    let durable = status.durable_state().expect("durable-state counts");
    assert_eq!(durable.runs_registered(), OperationalMetric::Measured(2));
    assert_eq!(durable.approvals_recorded(), OperationalMetric::Measured(4));
    // Zero automations is a measurement, and it survives the wire as one.
    assert_eq!(
        durable.automations_registered(),
        OperationalMetric::Measured(0)
    );
    assert_eq!(durable.open_tenures(), OperationalMetric::Measured(1));
    assert_eq!(durable.open_tenure_epoch(), OperationalMetric::Measured(7));
    assert_eq!(durable.tenures_recorded(), OperationalMetric::Unavailable);
}

/// An unread store and an empty store are different facts, and stay different
/// after a round trip.
///
/// The whole point of spending a union on a count is that `Measured(0)` and
/// `Unavailable` never collapse into each other. This asserts it where it would
/// actually be lost: on the wire, in both directions, and in the bytes.
#[test]
fn an_unavailable_count_never_decodes_as_a_measured_zero() {
    let unread = |counts: DurableStateCounts| {
        let response = AdminResponse::Status {
            request_id: request_id(),
            status: status()
                .with_durable_state(counts)
                .expect("coherent tenure observation"),
        };
        let payload = response
            .to_message()
            .expect("known literals")
            .to_canonical_bytes();
        let AdminResponse::Status { status, .. } =
            AdminResponse::from_canonical_bytes(&payload).expect("admitted response")
        else {
            panic!("wrong response variant")
        };
        (
            String::from_utf8(payload).expect("canonical UTF-8"),
            status
                .durable_state()
                .expect("durable-state counts")
                .runs_registered(),
        )
    };

    let (unavailable_bytes, unavailable) = unread(
        DurableStateCounts::new(DurableStateCountsParts {
            runs_registered: OperationalMetric::Unavailable,
            ..parts()
        })
        .expect("coherent counts"),
    );
    let (measured_bytes, measured) = unread(
        DurableStateCounts::new(DurableStateCountsParts {
            runs_registered: OperationalMetric::Measured(0),
            ..parts()
        })
        .expect("coherent counts"),
    );

    assert_eq!(unavailable, OperationalMetric::Unavailable);
    assert_eq!(measured, OperationalMetric::Measured(0));
    assert_ne!(unavailable, measured);
    assert_ne!(
        unavailable_bytes, measured_bytes,
        "an unread store and an empty store must not encode to the same bytes"
    );
    assert!(
        unavailable_bytes.contains(r#""runs_registered":{"state":"unavailable","value":null}"#)
    );
    assert!(
        measured_bytes.contains(r#""runs_registered":{"state":"measured","value":0}"#),
        "a measured zero must stay a measurement"
    );
    assert_eq!(unavailable.value(), None);
    assert_eq!(measured.value(), Some(0));
}

/// Every durable count is named in the decoder's field set, so a field the
/// encoder writes and the decoder forgot refuses instead of being dropped.
#[test]
fn a_durable_count_missing_from_the_status_body_refuses_the_whole_decode() {
    let payload = String::from_utf8(
        AdminResponse::Status {
            request_id: request_id(),
            status: status(),
        }
        .to_message()
        .expect("known literals")
        .to_canonical_bytes(),
    )
    .expect("canonical UTF-8");

    // Each replacement keeps the key's length and its place in the canonical
    // key order, so the body stays canonical JSON of the same size and the only
    // thing wrong with it is the name. A missing field caught by a length check
    // would prove much less.
    for (field, renamed_to) in [
        ("approvals_recorded", "approvals_recordex"),
        ("automations_registered", "automations_registerex"),
        ("open_tenure_epoch", "open_tenure_epocx"),
        ("open_tenures", "open_tenurex"),
        ("runs_registered", "runs_registerex"),
        ("tenures_recorded", "tenures_recordex"),
    ] {
        let renamed = payload.replacen(&format!("\"{field}\""), &format!("\"{renamed_to}\""), 1);
        assert_ne!(renamed, payload, "the body never carried {field}");
        assert_eq!(renamed.len(), payload.len(), "the rename resized the body");
        assert_eq!(
            AdminResponse::from_canonical_bytes(renamed.as_bytes())
                .expect_err("a renamed durable count must refuse"),
            AdminError::InvalidBody,
            "{field} was decoded without being required"
        );
    }

    // The whole sub-object is required, not merely its contents. `durable_stat`
    // sorts where `durable_state` did, between `accepting_intake` and
    // `event_cursor`, so this too is a well-formed body missing one name.
    let without = payload.replacen("\"durable_state\"", "\"durable_statx\"", 1);
    assert_eq!(
        AdminResponse::from_canonical_bytes(without.as_bytes())
            .expect_err("status without durable counts must refuse"),
        AdminError::InvalidBody
    );
}

/// A tenure observation that contradicts itself, or the generation it sits
/// beside, is refused on construction and on decode.
#[test]
fn an_incoherent_tenure_observation_is_refused_both_ways() {
    for (open_tenures, open_tenure_epoch, why) in [
        (
            OperationalMetric::Measured(0),
            OperationalMetric::Measured(7),
            "an epoch with no open tenure belongs to nothing",
        ),
        (
            OperationalMetric::Measured(1),
            OperationalMetric::Unavailable,
            "a tenure read without its epoch was not read",
        ),
        (
            OperationalMetric::Unavailable,
            OperationalMetric::Measured(7),
            "an unread audit cannot produce an epoch",
        ),
        (
            OperationalMetric::Measured(2),
            OperationalMetric::Measured(7),
            "a generation has at most one open tenure",
        ),
        (
            OperationalMetric::Measured(1),
            OperationalMetric::Measured(0),
            "no lease is ever held at epoch zero",
        ),
    ] {
        assert_eq!(
            DurableStateCounts::new(DurableStateCountsParts {
                open_tenures,
                open_tenure_epoch,
                ..parts()
            })
            .expect_err(why),
            AdminError::InvalidBody,
            "{why}"
        );
    }

    // Coherent on its own, and still wrong beside a status: the fixture's
    // generation is seven, so a tenure open at six says the lease and the audit
    // describe different histories.
    let disagreeing = DurableStateCounts::new(DurableStateCountsParts {
        open_tenures: OperationalMetric::Measured(1),
        open_tenure_epoch: OperationalMetric::Measured(6),
        ..parts()
    })
    .expect("coherent in isolation");
    assert_eq!(
        status()
            .with_durable_state(disagreeing)
            .expect_err("the audit and the lease must agree on the generation"),
        AdminError::InvalidBody
    );

    let payload = String::from_utf8(
        AdminResponse::Status {
            request_id: request_id(),
            status: status(),
        }
        .to_message()
        .expect("known literals")
        .to_canonical_bytes(),
    )
    .expect("canonical UTF-8");
    let regressed = payload.replacen(
        r#""open_tenure_epoch":{"state":"measured","value":7}"#,
        r#""open_tenure_epoch":{"state":"measured","value":6}"#,
        1,
    );
    assert_ne!(regressed, payload, "the fixture lost its tenure epoch");
    assert_eq!(
        AdminResponse::from_canonical_bytes(regressed.as_bytes())
            .expect_err("a status cannot carry a tenure from another generation"),
        AdminError::InvalidBody
    );
}

/// A status that never counted its stores cannot be encoded at all.
///
/// The counts are not an optional embellishment a daemon may skip when a store
/// is inconvenient: skipping is what [`OperationalMetric::Unavailable`] is for.
/// A snapshot that carries neither has said nothing about its durable state,
/// and it fails closed rather than reaching a client as a status with a hole.
#[test]
fn status_without_durable_counts_cannot_be_encoded() {
    let status = DaemonStatus::new(
        AdminInstanceId::new("daemon-without-counts").expect("instance"),
        DaemonState::Ready,
        1,
        1,
        0,
        0,
        0,
        true,
    )
    .and_then(|status| {
        status.with_operational(
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
                provider_available: OperationalMetric::Unavailable,
                sandbox_launch_refusals: OperationalMetric::Unavailable,
            })
            .expect("operational status"),
        )
    })
    .expect("complete but for the counts");
    assert_eq!(status.durable_state(), None);
    assert_eq!(
        AdminResponse::Status {
            request_id: request_id(),
            status,
        }
        .to_message()
        .expect_err("missing durable counts must fail closed"),
        AdminError::InvalidBody
    );
}

/// The coherent counts the tests above vary one field of.
fn parts() -> DurableStateCountsParts {
    DurableStateCountsParts {
        approvals_recorded: OperationalMetric::Measured(4),
        automations_registered: OperationalMetric::Measured(0),
        open_tenure_epoch: OperationalMetric::Measured(7),
        open_tenures: OperationalMetric::Measured(1),
        runs_registered: OperationalMetric::Measured(2),
        tenures_recorded: OperationalMetric::Unavailable,
    }
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
    .expect("base status")
    // Everything else this snapshot owes the wire is present, so the refusal
    // below can only be the missing projection.
    .with_durable_state(
        DurableStateCounts::new(DurableStateCountsParts {
            open_tenures: OperationalMetric::Measured(0),
            open_tenure_epoch: OperationalMetric::Unavailable,
            ..parts()
        })
        .expect("coherent counts"),
    )
    .expect("no tenure to disagree with");
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
    // A live poller owns the same lease and is held to the same pairing: it
    // must name the epoch that fences it.
    let live = DaemonStatus::new(
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
            automonique_protocol::admin::TelegramState::PollingLive,
            Some(9),
        )
    })
    .expect("live polling state");
    assert_eq!(
        live.telegram_state(),
        automonique_protocol::admin::TelegramState::PollingLive
    );
    assert_eq!(live.telegram_poller_epoch(), Some(9));
    for (state, epoch) in [
        (
            automonique_protocol::admin::TelegramState::DisabledNoClient,
            Some(1),
        ),
        (
            automonique_protocol::admin::TelegramState::LeaseOwnedNoClient,
            None,
        ),
        (
            automonique_protocol::admin::TelegramState::PollingLive,
            None,
        ),
        (
            automonique_protocol::admin::TelegramState::PollingLive,
            Some(0),
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

    // Every state survives the wire as itself. A live poller that decoded as an
    // owned-but-clientless one would be the exact misreport this field exists
    // to prevent, so the round trip is asserted rather than assumed.
    for state in [
        automonique_protocol::admin::TelegramState::DisabledNoClient,
        automonique_protocol::admin::TelegramState::LeaseOwnedNoClient,
        automonique_protocol::admin::TelegramState::PollingLive,
    ] {
        let epoch = match state {
            automonique_protocol::admin::TelegramState::DisabledNoClient => None,
            automonique_protocol::admin::TelegramState::LeaseOwnedNoClient
            | automonique_protocol::admin::TelegramState::PollingLive => Some(4),
        };
        let payload = AdminResponse::Status {
            request_id: request_id(),
            status: status()
                .with_telegram(state, epoch)
                .expect("coherent telegram pair"),
        }
        .to_message()
        .expect("status message")
        .to_canonical_bytes();
        assert!(
            String::from_utf8(payload.clone())
                .expect("UTF-8")
                .contains(&format!("\"telegram_state\":\"{}\"", state.as_str())),
            "{state:?} did not encode as its own spelling"
        );
        let AdminResponse::Status { status, .. } =
            AdminResponse::from_canonical_bytes(&payload).expect("admitted response")
        else {
            panic!("wrong response variant")
        };
        assert_eq!(status.telegram_state(), state);
        assert_eq!(status.telegram_poller_epoch(), epoch);
    }
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
    .and_then(|status| status.with_durable_state(durable_state()))
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

// ---------------------------------------------------------------------------
// One socket, five protocols.
//
// A local endpoint serves administration, the native Runs API read surface, the
// native Automation control surface, the native Approval decision surface *and*
// the native Batch control surface. `LocalRequest` is the only thing that
// decides which, and it decides by the protocol name the frame itself declares.
// These pin that the decision is made once, before any lane reads a body, and
// that no lane can be reached through another's decoder.
// ---------------------------------------------------------------------------

mod local_dispatch {
    use super::*;

    use automonique_protocol::admin::{LocalRequest, LocalRequestError};
    use automonique_protocol::approval_api::{
        APPROVAL_PROTOCOL, ApprovalApiError, ApprovalCursor, ApprovalDecision, ApprovalKey,
        ApprovalPageSize, ApprovalRequest, ApprovalSubject, ApprovalsBySubject, Decider,
        ListApprovals, MAX_APPROVAL_CANONICAL_BYTES, RecordApproval,
    };
    use automonique_protocol::automation::{AutomationActor, EnablementState};
    use automonique_protocol::automation_api::{
        AUTOMATION_PROTOCOL, AutomationApiError, AutomationCursor, AutomationId,
        AutomationPageSize, AutomationRequest, AutomationStateFilter, ListAutomations,
        MAX_AUTOMATION_CANONICAL_BYTES, PauseReason, RegisterAutomation, SetEnablement,
    };
    use automonique_protocol::batch_api::{
        AdvanceMember, BATCH_CONTROL_PROTOCOL, BatchApiError, BatchCursor, BatchPageSize,
        BatchRequest, ListBatches, MAX_BATCH_CONTROL_CANONICAL_BYTES, MAX_BATCH_CONTROL_MEMBERS,
        RegisterBatch,
    };
    use automonique_protocol::batch_runner::{
        BatchId, BatchLabel, BatchMemberKey, ConcurrencyPolicy, MemberProgress,
    };
    use automonique_protocol::runs_api::{
        ListRuns, MAX_RUNS_CANONICAL_BYTES, PageSize, RUNS_PROTOCOL, RunStateFilter, RunsApiError,
        RunsRequest,
    };

    fn admin_payload() -> Vec<u8> {
        AdminRequest::new(request_id(), AdminCommand::Status)
            .to_message()
            .expect("encode admin request")
            .to_canonical_bytes()
    }

    fn listing() -> RunsRequest {
        RunsRequest::ListRuns {
            request_id: request_id(),
            query: ListRuns::new(RunStateFilter::any(), None, PageSize::MAX),
        }
    }

    fn runs_payload(request: &RunsRequest) -> Vec<u8> {
        request
            .to_message()
            .expect("encode runs request")
            .to_canonical_bytes()
    }

    fn automation_id(value: &str) -> AutomationId {
        AutomationId::new(value).expect("automation identity")
    }

    fn automation_listing() -> AutomationRequest {
        AutomationRequest::ListAutomations {
            request_id: request_id(),
            query: ListAutomations::new(
                AutomationStateFilter::any(),
                AutomationCursor::START,
                AutomationPageSize::MAX,
            ),
        }
    }

    fn automation_payload(request: &AutomationRequest) -> Vec<u8> {
        request
            .to_message()
            .expect("encode automation request")
            .to_canonical_bytes()
    }

    fn approval_listing() -> ApprovalRequest {
        ApprovalRequest::ListApprovals {
            request_id: request_id(),
            query: ListApprovals::new(ApprovalCursor::START, ApprovalPageSize::MAX),
        }
    }

    fn approval_payload(request: &ApprovalRequest) -> Vec<u8> {
        request
            .to_message()
            .expect("encode approval request")
            .to_canonical_bytes()
    }

    fn batch_listing() -> BatchRequest {
        BatchRequest::ListBatches {
            request_id: request_id(),
            query: ListBatches::new(BatchCursor::START, BatchPageSize::MAX),
        }
    }

    fn batch_payload(request: &BatchRequest) -> Vec<u8> {
        request
            .to_message()
            .expect("encode batch request")
            .to_canonical_bytes()
    }

    #[test]
    fn a_local_frame_is_placed_by_the_protocol_it_declares() {
        let placed =
            LocalRequest::from_canonical_bytes(&admin_payload()).expect("an admin frame is placed");
        assert_eq!(placed.protocol(), ADMIN_PROTOCOL);
        let LocalRequest::Admin(request) = placed else {
            panic!("an admin frame reached another lane")
        };
        assert_eq!(request.command(), AdminCommand::Status);

        for request in [
            listing(),
            RunsRequest::RunDetail {
                request_id: request_id(),
                run_id: RunId::new("run-1").expect("run identity"),
            },
        ] {
            let placed = LocalRequest::from_canonical_bytes(&runs_payload(&request))
                .expect("a runs frame is placed");
            assert_eq!(placed.protocol(), RUNS_PROTOCOL);
            assert_eq!(placed, LocalRequest::Runs(request));
        }

        for request in [
            automation_listing(),
            AutomationRequest::RegisterAutomation {
                request_id: request_id(),
                registration: RegisterAutomation::new(
                    automation_id("nightly-report"),
                    AutomationActor::new("ben").expect("actor"),
                ),
            },
            AutomationRequest::SetEnablement {
                request_id: request_id(),
                transition: SetEnablement::new(
                    automation_id("nightly-report"),
                    1,
                    EnablementState::Paused,
                    AutomationActor::new("ben").expect("actor"),
                    Some(PauseReason::new("provider outage").expect("cause")),
                )
                .expect("coupled transition"),
            },
            AutomationRequest::AutomationDetail {
                request_id: request_id(),
                automation_id: automation_id("nightly-report"),
            },
        ] {
            let placed = LocalRequest::from_canonical_bytes(&automation_payload(&request))
                .expect("an automation frame is placed");
            assert_eq!(placed.protocol(), AUTOMATION_PROTOCOL);
            assert_eq!(placed, LocalRequest::Automation(Box::new(request)));
        }

        for request in [
            approval_listing(),
            ApprovalRequest::RecordApproval {
                request_id: request_id(),
                decision: RecordApproval::new(
                    ApprovalKey::new("deploy-1").expect("approval key"),
                    ApprovalSubject::new("command:shutdown").expect("subject"),
                    ApprovalDecision::Granted,
                    Decider::new("ben").expect("decider"),
                ),
            },
            ApprovalRequest::ApprovalDetail {
                request_id: request_id(),
                approval_key: ApprovalKey::new("deploy-1").expect("approval key"),
            },
            ApprovalRequest::ApprovalsBySubject {
                request_id: request_id(),
                query: ApprovalsBySubject::new(
                    ApprovalSubject::new("command:shutdown").expect("subject"),
                    ApprovalCursor::new(3),
                    ApprovalPageSize::MAX,
                ),
            },
        ] {
            let placed = LocalRequest::from_canonical_bytes(&approval_payload(&request))
                .expect("an approval frame is placed");
            assert_eq!(placed.protocol(), APPROVAL_PROTOCOL);
            assert_eq!(placed, LocalRequest::Approval(Box::new(request)));
        }

        for request in [
            batch_listing(),
            BatchRequest::RegisterBatch {
                request_id: request_id(),
                registration: RegisterBatch::new(
                    BatchId::new("nightly-eval").expect("batch identity"),
                    Some(BatchLabel::new("nightly").expect("label")),
                    ConcurrencyPolicy::bounded_parallel(4).expect("ceiling"),
                    vec![
                        BatchMemberKey::new("record-1").expect("member key"),
                        BatchMemberKey::new("record-2").expect("member key"),
                    ],
                )
                .expect("registration"),
            },
            BatchRequest::AdvanceMember {
                request_id: request_id(),
                advance: AdvanceMember::new(
                    BatchId::new("nightly-eval").expect("batch identity"),
                    BatchMemberKey::new("record-1").expect("member key"),
                    2,
                    MemberProgress::Run(automonique_protocol::runs_api::RunState::Running),
                    7,
                )
                .expect("advance"),
            },
            BatchRequest::BatchDetail {
                request_id: request_id(),
                batch_id: BatchId::new("nightly-eval").expect("batch identity"),
            },
        ] {
            let placed = LocalRequest::from_canonical_bytes(&batch_payload(&request))
                .expect("a batch frame is placed");
            assert_eq!(placed.protocol(), BATCH_CONTROL_PROTOCOL);
            assert_eq!(placed, LocalRequest::Batch(Box::new(request)));
        }
    }

    #[test]
    fn a_protocol_this_socket_does_not_serve_is_refused_before_a_body_is_read() {
        // Each of these carries a body one lane or the other would have
        // accepted. The refusal is the envelope's, so no body was read.
        for payload in [
            br#"{"body":{},"kind":"status","protocol":"automonique.runner","request_id":"r","version":1}"#.as_slice(),
            br#"{"body":{"page_size":64,"since":null,"states":null},"kind":"list_runs","protocol":"automonique.runs.v2","request_id":"r","version":1}"#.as_slice(),
        ] {
            let error =
                LocalRequest::from_canonical_bytes(payload).expect_err("unserved protocol");
            assert_eq!(
                error,
                LocalRequestError::Envelope(CodecError::UnknownProtocol)
            );
            assert_eq!(error.category(), "unknown_protocol");
        }

        // Bytes that are not an envelope at all are also the socket's refusal
        // and not a lane's, because there is no declared name to place them by.
        assert!(matches!(
            LocalRequest::from_canonical_bytes(b"{").expect_err("not an envelope"),
            LocalRequestError::Envelope(_)
        ));
    }

    #[test]
    fn each_lane_refuses_its_own_frames_and_never_the_other_lane_s() {
        // A widened administration body is the admin lane's refusal, spelled
        // in the admin lane's vocabulary.
        let widened = br#"{"body":{"force":true},"kind":"shutdown","protocol":"automonique.admin","request_id":"r","version":1}"#;
        let error = LocalRequest::from_canonical_bytes(widened).expect_err("widened admin body");
        assert_eq!(error, LocalRequestError::Admin(AdminError::InvalidBody));
        assert_eq!(error.category(), "admin_invalid_body");

        // A listing missing a declared field is the Runs lane's refusal, in
        // the Runs lane's vocabulary. The two categories differ, which is what
        // lets one metric label say which lane refused.
        let short = br#"{"body":{"page_size":64,"since":null},"kind":"list_runs","protocol":"automonique.runs","request_id":"r","version":1}"#;
        let error = LocalRequest::from_canonical_bytes(short).expect_err("short listing body");
        assert_eq!(error, LocalRequestError::Runs(RunsApiError::InvalidBody));
        assert_eq!(error.category(), "runs_invalid_body");

        // A Runs kind inside an administration envelope is refused by the
        // admin lane, which owns that envelope's closed kind set. It is not
        // retried against the Runs lane.
        let smuggled = br#"{"body":{"page_size":64,"since":null,"states":null},"kind":"list_runs","protocol":"automonique.admin","request_id":"r","version":1}"#;
        assert_eq!(
            LocalRequest::from_canonical_bytes(smuggled).expect_err("smuggled runs kind"),
            LocalRequestError::Admin(AdminError::UnknownKind)
        );

        // And the reverse: an administration kind inside a Runs envelope.
        let inverted = br#"{"body":{},"kind":"status","protocol":"automonique.runs","request_id":"r","version":1}"#;
        assert_eq!(
            LocalRequest::from_canonical_bytes(inverted).expect_err("smuggled admin kind"),
            LocalRequestError::Runs(RunsApiError::UnknownKind)
        );

        // The third lane refuses in its own vocabulary too. A listing body
        // missing its declared `states` member is the Automation lane's
        // `automation_invalid_body`, which no other lane can produce.
        let short = br#"{"body":{"page_size":4,"since":0},"kind":"list_automations","protocol":"automonique.automation","request_id":"r","version":1}"#;
        let error = LocalRequest::from_canonical_bytes(short).expect_err("short listing body");
        assert_eq!(
            error,
            LocalRequestError::Automation(AutomationApiError::InvalidBody)
        );
        assert_eq!(error.category(), "automation_invalid_body");

        // An automation kind inside an administration envelope stays the admin
        // lane's refusal, and an admin kind inside an automation envelope stays
        // the automation lane's. Neither falls through to the other.
        let smuggled = br#"{"body":{"actor":"ben","automation_id":"a"},"kind":"register_automation","protocol":"automonique.admin","request_id":"r","version":1}"#;
        assert_eq!(
            LocalRequest::from_canonical_bytes(smuggled).expect_err("smuggled automation kind"),
            LocalRequestError::Admin(AdminError::UnknownKind)
        );
        let inverted = br#"{"body":{},"kind":"shutdown","protocol":"automonique.automation","request_id":"r","version":1}"#;
        assert_eq!(
            LocalRequest::from_canonical_bytes(inverted).expect_err("smuggled admin kind"),
            LocalRequestError::Automation(AutomationApiError::UnknownKind)
        );

        // A runs kind inside an automation envelope, and the reverse: the two
        // newer lanes do not fall through to one another either.
        let crossed = br#"{"body":{"page_size":64,"since":null,"states":null},"kind":"list_runs","protocol":"automonique.automation","request_id":"r","version":1}"#;
        assert_eq!(
            LocalRequest::from_canonical_bytes(crossed).expect_err("smuggled runs kind"),
            LocalRequestError::Automation(AutomationApiError::UnknownKind)
        );
        let crossed = br#"{"body":{"actor":"ben","automation_id":"a"},"kind":"register_automation","protocol":"automonique.runs","request_id":"r","version":1}"#;
        assert_eq!(
            LocalRequest::from_canonical_bytes(crossed).expect_err("smuggled automation kind"),
            LocalRequestError::Runs(RunsApiError::UnknownKind)
        );

        // The fourth lane refuses in its own vocabulary too. A recording body
        // missing its declared `subject` is the Approval lane's
        // `approval_invalid_body`, which no other lane can produce.
        let short = br#"{"body":{"approval_key":"deploy-1","decider":"ben","decision":"granted"},"kind":"record_approval","protocol":"automonique.approval","request_id":"r","version":1}"#;
        let error = LocalRequest::from_canonical_bytes(short).expect_err("short recording body");
        assert_eq!(
            error,
            LocalRequestError::Approval(ApprovalApiError::InvalidBody)
        );
        assert_eq!(error.category(), "approval_invalid_body");

        // An approval kind inside each of the other three envelopes stays that
        // lane's refusal, and each of their kinds inside an approval envelope
        // stays the approval lane's. Four lanes, and none falls through to
        // another.
        let approval_body =
            br#"{"approval_key":"deploy-1","decider":"ben","decision":"granted","subject":"s"}"#;
        for (protocol, expected) in [
            (
                "automonique.admin",
                LocalRequestError::Admin(AdminError::UnknownKind),
            ),
            (
                "automonique.runs",
                LocalRequestError::Runs(RunsApiError::UnknownKind),
            ),
            (
                "automonique.automation",
                LocalRequestError::Automation(AutomationApiError::UnknownKind),
            ),
        ] {
            let smuggled = [
                br#"{"body":"#.as_slice(),
                approval_body.as_slice(),
                format!(
                    r#","kind":"record_approval","protocol":"{protocol}","request_id":"r","version":1}}"#
                )
                .as_bytes(),
            ]
            .concat();
            assert_eq!(
                LocalRequest::from_canonical_bytes(&smuggled).expect_err("smuggled approval kind"),
                expected,
                "an approval kind inside a {protocol} envelope",
            );
        }
        for kind in ["shutdown", "list_runs", "register_automation"] {
            let inverted = format!(
                r#"{{"body":{{}},"kind":"{kind}","protocol":"automonique.approval","request_id":"r","version":1}}"#
            );
            assert_eq!(
                LocalRequest::from_canonical_bytes(inverted.as_bytes())
                    .expect_err("smuggled foreign kind"),
                LocalRequestError::Approval(ApprovalApiError::UnknownKind),
                "a {kind} inside an approval envelope",
            );
        }

        // The fifth lane refuses in its own vocabulary too. A registration body
        // missing its declared `label` is the Batch lane's
        // `batch_control_invalid_body`, which no other lane can produce.
        let short = br#"{"body":{"batch_id":"b","concurrency":{"kind":"sequential","max_in_flight":null},"members":["m"]},"kind":"register_batch","protocol":"automonique.batch.control","request_id":"r","version":1}"#;
        let error = LocalRequest::from_canonical_bytes(short).expect_err("short registration body");
        assert_eq!(error, LocalRequestError::Batch(BatchApiError::InvalidBody));
        assert_eq!(error.category(), "batch_control_invalid_body");

        // A batch kind inside each of the other four envelopes stays that lane's
        // refusal, and each of their kinds inside a batch envelope stays the
        // batch lane's. Five lanes, and none falls through to another.
        let batch_body = br#"{"batch_id":"b","concurrency":{"kind":"sequential","max_in_flight":null},"label":null,"members":["m"]}"#;
        for (protocol, expected) in [
            (
                "automonique.admin",
                LocalRequestError::Admin(AdminError::UnknownKind),
            ),
            (
                "automonique.runs",
                LocalRequestError::Runs(RunsApiError::UnknownKind),
            ),
            (
                "automonique.automation",
                LocalRequestError::Automation(AutomationApiError::UnknownKind),
            ),
            (
                "automonique.approval",
                LocalRequestError::Approval(ApprovalApiError::UnknownKind),
            ),
        ] {
            let smuggled = [
                br#"{"body":"#.as_slice(),
                batch_body.as_slice(),
                format!(
                    r#","kind":"register_batch","protocol":"{protocol}","request_id":"r","version":1}}"#
                )
                .as_bytes(),
            ]
            .concat();
            assert_eq!(
                LocalRequest::from_canonical_bytes(&smuggled).expect_err("smuggled batch kind"),
                expected,
                "a batch kind inside a {protocol} envelope",
            );
        }
        for kind in [
            "shutdown",
            "list_runs",
            "register_automation",
            "record_approval",
        ] {
            let inverted = format!(
                r#"{{"body":{{}},"kind":"{kind}","protocol":"automonique.batch.control","request_id":"r","version":1}}"#
            );
            assert_eq!(
                LocalRequest::from_canonical_bytes(inverted.as_bytes())
                    .expect_err("smuggled foreign kind"),
                LocalRequestError::Batch(BatchApiError::UnknownKind),
                "a {kind} inside a batch envelope",
            );
        }
    }

    #[test]
    fn no_decoder_admits_another_protocol_s_frames() {
        // Placement is not the only thing keeping the lanes apart: each lane's
        // own decoder refuses the others' bytes outright, so a caller that
        // bypassed `LocalRequest` could not mix them either.
        let automation = automation_payload(&automation_listing());
        let approval = approval_payload(&approval_listing());
        let batch = batch_payload(&batch_listing());
        for (label, category) in [
            (
                "a batch frame is not an admin request",
                AdminRequest::from_canonical_bytes(&batch)
                    .expect_err("batch into admin")
                    .category(),
            ),
            (
                "a batch frame is not a runs request",
                RunsRequest::from_canonical_bytes(&batch)
                    .expect_err("batch into runs")
                    .category(),
            ),
            (
                "a batch frame is not an automation request",
                AutomationRequest::from_canonical_bytes(&batch)
                    .expect_err("batch into automation")
                    .category(),
            ),
            (
                "a batch frame is not an approval request",
                ApprovalRequest::from_canonical_bytes(&batch)
                    .expect_err("batch into approval")
                    .category(),
            ),
            (
                "an admin frame is not a batch request",
                BatchRequest::from_canonical_bytes(&admin_payload())
                    .expect_err("admin into batch")
                    .category(),
            ),
            (
                "a runs frame is not a batch request",
                BatchRequest::from_canonical_bytes(&runs_payload(&listing()))
                    .expect_err("runs into batch")
                    .category(),
            ),
            (
                "an automation frame is not a batch request",
                BatchRequest::from_canonical_bytes(&automation)
                    .expect_err("automation into batch")
                    .category(),
            ),
            (
                "an approval frame is not a batch request",
                BatchRequest::from_canonical_bytes(&approval)
                    .expect_err("approval into batch")
                    .category(),
            ),
            (
                "a runs frame is not an admin request",
                AdminRequest::from_canonical_bytes(&runs_payload(&listing()))
                    .expect_err("runs into admin")
                    .category(),
            ),
            (
                "an approval frame is not an admin request",
                AdminRequest::from_canonical_bytes(&approval)
                    .expect_err("approval into admin")
                    .category(),
            ),
            (
                "an approval frame is not a runs request",
                RunsRequest::from_canonical_bytes(&approval)
                    .expect_err("approval into runs")
                    .category(),
            ),
            (
                "an approval frame is not an automation request",
                AutomationRequest::from_canonical_bytes(&approval)
                    .expect_err("approval into automation")
                    .category(),
            ),
            (
                "an admin frame is not an approval request",
                ApprovalRequest::from_canonical_bytes(&admin_payload())
                    .expect_err("admin into approval")
                    .category(),
            ),
            (
                "a runs frame is not an approval request",
                ApprovalRequest::from_canonical_bytes(&runs_payload(&listing()))
                    .expect_err("runs into approval")
                    .category(),
            ),
            (
                "an automation frame is not an approval request",
                ApprovalRequest::from_canonical_bytes(&automation)
                    .expect_err("automation into approval")
                    .category(),
            ),
            (
                "an automation frame is not an admin request",
                AdminRequest::from_canonical_bytes(&automation)
                    .expect_err("automation into admin")
                    .category(),
            ),
            (
                "an admin frame is not a runs request",
                RunsRequest::from_canonical_bytes(&admin_payload())
                    .expect_err("admin into runs")
                    .category(),
            ),
            (
                "an automation frame is not a runs request",
                RunsRequest::from_canonical_bytes(&automation)
                    .expect_err("automation into runs")
                    .category(),
            ),
            (
                "an admin frame is not an automation request",
                AutomationRequest::from_canonical_bytes(&admin_payload())
                    .expect_err("admin into automation")
                    .category(),
            ),
            (
                "a runs frame is not an automation request",
                AutomationRequest::from_canonical_bytes(&runs_payload(&listing()))
                    .expect_err("runs into automation")
                    .category(),
            ),
        ] {
            assert_eq!(category, "unknown_protocol", "{label}");
        }
    }

    #[test]
    fn a_maximal_automation_frame_fits_the_local_administration_read_bound() {
        // The relation between the ceilings is a compile-time assertion in
        // `admin.rs`, so this build could not have linked if it stopped
        // holding. What is measured here is the consequence: a real Automation
        // message, framed the way this socket frames it, fits the bound the
        // local endpoint reads under.
        const LOCAL_READ_BOUND: usize = MAX_ADMIN_CANONICAL_BYTES;
        let payload = automation_payload(&AutomationRequest::SetEnablement {
            request_id: request_id(),
            transition: SetEnablement::new(
                automation_id(&"\"".repeat(AutomationId::MAX_BYTES)),
                u64::MAX >> 1,
                EnablementState::Archived,
                AutomationActor::new(&"\"".repeat(AutomationId::MAX_BYTES)).expect("actor"),
                Some(PauseReason::new("\"".repeat(PauseReason::MAX_BYTES)).expect("cause")),
            )
            .expect("maximal transition"),
        });
        let mut frame = Vec::new();
        encode_frame(&payload, &mut frame).expect("a maximal transition fits one frame");
        assert!(
            frame.len() < MAX_AUTOMATION_CANONICAL_BYTES && frame.len() < LOCAL_READ_BOUND,
            "a maximal transition framed to {} bytes",
            frame.len(),
        );
    }

    #[test]
    fn a_maximal_approval_frame_fits_the_local_administration_read_bound() {
        // The relation between the ceilings is a compile-time assertion in
        // `admin.rs`, so this build could not have linked if it stopped
        // holding. What is measured here is the consequence: a real Approval
        // message, framed the way this socket frames it, fits the bound the
        // local endpoint reads under.
        const LOCAL_READ_BOUND: usize = MAX_ADMIN_CANONICAL_BYTES;
        let worst = "\"".repeat(ApprovalKey::MAX_BYTES);
        let payload = approval_payload(&ApprovalRequest::RecordApproval {
            request_id: request_id(),
            decision: RecordApproval::new(
                ApprovalKey::new(&worst).expect("approval key"),
                ApprovalSubject::new(&worst).expect("subject"),
                ApprovalDecision::Granted,
                Decider::new(&worst).expect("decider"),
            ),
        });
        let mut frame = Vec::new();
        encode_frame(&payload, &mut frame).expect("a maximal recording fits one frame");
        assert!(
            frame.len() < MAX_APPROVAL_CANONICAL_BYTES && frame.len() < LOCAL_READ_BOUND,
            "a maximal recording framed to {} bytes",
            frame.len(),
        );
    }

    #[test]
    fn a_maximal_batch_frame_fits_the_local_administration_read_bound() {
        // The relation between the ceilings is a compile-time assertion in
        // `admin.rs`, so this build could not have linked if it stopped holding.
        // What is measured here is the consequence, and this lane is the one it
        // actually binds on: a maximal registration carries a whole membership,
        // which is the largest body any lane on this socket sends. The measured
        // frame is what pins `batch_api`'s member ceiling to something real
        // rather than to arithmetic nobody ran.
        const LOCAL_READ_BOUND: usize = MAX_ADMIN_CANONICAL_BYTES;
        let worst = "\"".repeat(BatchMemberKey::MAX_BYTES);
        let members: Vec<BatchMemberKey> = (0..MAX_BATCH_CONTROL_MEMBERS)
            .map(|index| {
                BatchMemberKey::new(format!("{index:03}{}", &worst[..worst.len() - 3]))
                    .expect("member key")
            })
            .collect();
        let payload = batch_payload(&BatchRequest::RegisterBatch {
            request_id: request_id(),
            registration: RegisterBatch::new(
                BatchId::new("\"".repeat(BatchId::MAX_BYTES)).expect("batch identity"),
                Some(BatchLabel::new("\"".repeat(BatchLabel::MAX_BYTES)).expect("label")),
                ConcurrencyPolicy::bounded_parallel(256).expect("ceiling"),
                members,
            )
            .expect("maximal registration"),
        });
        let mut frame = Vec::new();
        encode_frame(&payload, &mut frame).expect("a maximal registration fits one frame");
        assert!(
            frame.len() < MAX_BATCH_CONTROL_CANONICAL_BYTES && frame.len() < LOCAL_READ_BOUND,
            "a maximal registration framed to {} bytes",
            frame.len(),
        );
    }

    #[test]
    fn a_maximal_runs_frame_fits_the_local_administration_read_bound() {
        // The relation between the two ceilings is a compile-time assertion in
        // `admin.rs`, so this build could not have linked if it stopped
        // holding. What is measured here is the consequence that assertion
        // exists for: a real Runs message, framed the way this socket frames
        // it, fits inside the bound the local endpoint reads under — with
        // headroom, rather than sitting on the limit.
        const LOCAL_READ_BOUND: usize = MAX_ADMIN_CANONICAL_BYTES;
        let payload = runs_payload(&listing());
        let mut frame = Vec::new();
        encode_frame(&payload, &mut frame).expect("a listing fits one frame");
        assert!(
            frame.len() < MAX_RUNS_CANONICAL_BYTES && frame.len() < LOCAL_READ_BOUND,
            "a maximal listing framed to {} bytes",
            frame.len(),
        );
    }
}
