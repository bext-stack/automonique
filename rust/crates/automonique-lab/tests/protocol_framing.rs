// SPDX-License-Identifier: Elastic-2.0

use automonique_lab::framing::{
    ABSOLUTE_MAX_FRAME_BYTES, CodecError, FRAME_PREFIX_BYTES, FrameError, FrameLimits,
    PayloadCodec, decode_frame, decode_with, encode_frame, encode_with,
};
use automonique_lab::protocol::{
    ActionCoordinates, ActionOperation, ActionOutcome, ActionReceipt, ActionResponse, ActionStatus,
    BoundedText, BudgetEnforcement, CancelReason, CancelRequest, Capability, EventType, Execution,
    GitSha1, InventoryTrust, JsUInt, LabBudget, LabBudgetValues, LabEvent, LabRequest, LabResponse,
    MAX_JS_SAFE_INTEGER, ObserveRequest, ObservedResponse, OpaqueId, ProviderPolicy, ResumeRequest,
    SelectRequest, Sha256Digest, SyntheticProviderPolicy, UnitSnapshot, UnitState,
    UntrustedInventoryPolicy, ValidationKind,
};

fn id(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("test identifier is valid")
}

fn unit(state: UnitState, revision: u64, checkpoint: Option<&str>, sequence: u64) -> UnitSnapshot {
    unit_at(
        "unit-1",
        "R0-19-synthetic",
        state,
        revision,
        checkpoint,
        sequence,
    )
}

fn unit_at(
    unit_id: &str,
    objective_id: &str,
    state: UnitState,
    revision: u64,
    checkpoint: Option<&str>,
    sequence: u64,
) -> UnitSnapshot {
    UnitSnapshot::new(
        id(unit_id),
        id(objective_id),
        state,
        revision,
        checkpoint.map(id),
        sequence,
    )
    .expect("test snapshot is valid")
}

fn event_at(objective_id: &str, unit_id: &str, sequence: u64, revision: u64) -> LabEvent {
    LabEvent::new(
        EventType::from_wire("unit.resumed").unwrap(),
        id(objective_id),
        id(unit_id),
        sequence,
        revision,
    )
    .unwrap()
}

fn resume_receipt(
    operation: ActionOperation,
    objective_id: &str,
    unit_id: &str,
    checkpoint_id: Option<&str>,
    expected_revision: u64,
    idempotency_key: &str,
) -> ActionReceipt {
    ActionReceipt::new(
        ActionCoordinates {
            action_id: id("action-1"),
            operation,
            objective_id: id(objective_id),
            unit_id: id(unit_id),
            checkpoint_id: checkpoint_id.map(id),
            expected_revision,
            idempotency_key: id(idempotency_key),
        },
        ActionOutcome {
            status: ActionStatus::Accepted,
            effect_count: 1,
            reason: None,
        },
    )
    .unwrap()
}

fn resume_request() -> ResumeRequest {
    ResumeRequest::new(
        id("resume"),
        id("R0-19-synthetic"),
        id("unit-1"),
        id("checkpoint-1"),
        2,
        id("resume-key"),
    )
    .expect("test request is valid")
}

#[test]
fn identifiers_digests_and_coordinates_are_bounded() {
    assert!(OpaqueId::new("a").is_ok());
    assert!(OpaqueId::new("A0._:-z").is_ok());
    for invalid in ["", "bad/id", "bad id", "é"] {
        assert!(OpaqueId::new(invalid).is_err(), "accepted {invalid:?}");
    }
    assert!(OpaqueId::new("a".repeat(128)).is_ok());
    assert!(OpaqueId::new("a".repeat(129)).is_err());

    assert!(GitSha1::new("a".repeat(40)).is_ok());
    assert!(GitSha1::new("A".repeat(40)).is_err());
    assert!(GitSha1::new("a".repeat(39)).is_err());
    assert!(Sha256Digest::new("0".repeat(64)).is_ok());
    assert!(Sha256Digest::new("g".repeat(64)).is_err());

    assert_eq!(
        MAX_JS_SAFE_INTEGER,
        JsUInt::new(MAX_JS_SAFE_INTEGER, "value").unwrap().get()
    );
    assert_eq!(
        ValidationKind::OutOfRange,
        JsUInt::new(MAX_JS_SAFE_INTEGER + 1, "value")
            .unwrap_err()
            .kind
    );
    assert!(JsUInt::positive(0, "positive").is_err());
}

#[test]
fn bounded_text_counts_typescript_utf16_code_units() {
    assert!(BoundedText::new("a😀", 3, "text").is_ok());
    assert_eq!(
        ValidationKind::TooLong,
        BoundedText::new("a😀", 2, "text").unwrap_err().kind
    );
    assert!(BoundedText::new("😀".repeat(512), 1_024, "text").is_ok());
    assert!(BoundedText::new("😀".repeat(513), 1_024, "text").is_err());
}

#[test]
fn wire_inventory_coordinates_are_not_provider_authority() {
    let fabricated = UntrustedInventoryPolicy::new(
        id("provider"),
        id("mode"),
        Sha256Digest::new("1".repeat(64)).unwrap(),
        Sha256Digest::new("2".repeat(64)).unwrap(),
        vec![Capability::Create],
        automonique_lab::protocol::EvidenceLevel::Advertised,
        vec![],
    )
    .unwrap();
    assert_eq!(InventoryTrust::UntrustedWireCoordinates, fabricated.trust());

    // Inventory selection accepts only the distinct VerifiedInventoryPolicy
    // variant, for which this public wire type exposes no conversion.
    let budget = LabBudget::new(LabBudgetValues {
        max_wall_ms: 1,
        max_cpu_ms: 1,
        max_disk_bytes: 1,
        max_output_bytes: 1,
        max_pids: 1,
        max_model_calls: 1,
        max_cost_microunits: 1,
        enforcement: BudgetEnforcement::HostBrokerRequired,
    })
    .unwrap();
    assert_eq!(
        ValidationKind::Incoherent,
        SelectRequest::new(
            id("select"),
            id("objective"),
            GitSha1::new("1".repeat(40)).unwrap(),
            Execution::Inventory,
            ProviderPolicy::Synthetic(SyntheticProviderPolicy),
            budget,
        )
        .unwrap_err()
        .kind
    );
}

#[test]
fn budgets_and_select_policy_must_be_coherent() {
    let synthetic_budget = LabBudget::new(LabBudgetValues {
        max_wall_ms: 1_000,
        max_cpu_ms: 500,
        max_disk_bytes: 16_384,
        max_output_bytes: 4_096,
        max_pids: 1,
        max_model_calls: 0,
        max_cost_microunits: 0,
        enforcement: BudgetEnforcement::SyntheticInProcess,
    })
    .unwrap();
    let request = SelectRequest::new(
        id("select"),
        id("R0-19"),
        GitSha1::new("1".repeat(40)).unwrap(),
        Execution::Synthetic,
        ProviderPolicy::Synthetic(SyntheticProviderPolicy),
        synthetic_budget.clone(),
    )
    .unwrap();
    assert_eq!(Execution::Synthetic, request.execution());
    assert_eq!(
        automonique_lab::protocol::Operation::Select,
        LabRequest::Select(request).operation()
    );

    let wrong_execution = SelectRequest::new(
        id("select"),
        id("R0-19"),
        GitSha1::new("1".repeat(40)).unwrap(),
        Execution::Inventory,
        ProviderPolicy::Synthetic(SyntheticProviderPolicy),
        synthetic_budget,
    );
    assert_eq!(
        ValidationKind::Incoherent,
        wrong_execution.unwrap_err().kind
    );
    assert!(
        LabBudget::new(LabBudgetValues {
            max_wall_ms: 0,
            max_cpu_ms: 1,
            max_disk_bytes: 1,
            max_output_bytes: 1,
            max_pids: 1,
            max_model_calls: 0,
            max_cost_microunits: 0,
            enforcement: BudgetEnforcement::SyntheticInProcess,
        })
        .is_err()
    );
    assert!(
        LabBudget::new(LabBudgetValues {
            max_wall_ms: 1,
            max_cpu_ms: 1,
            max_disk_bytes: 1,
            max_output_bytes: 1,
            max_pids: 1,
            max_model_calls: MAX_JS_SAFE_INTEGER + 1,
            max_cost_microunits: 0,
            enforcement: BudgetEnforcement::SyntheticInProcess,
        })
        .is_err()
    );
}

#[test]
fn every_operation_is_typed_and_ranges_are_closed() {
    let observe = ObserveRequest::new(id("observe"), id("objective"), id("unit"), 0, 1)
        .expect("observe request");
    assert_eq!(
        automonique_lab::protocol::Operation::Observe,
        LabRequest::Observe(observe).operation()
    );
    assert!(ObserveRequest::new(id("observe"), id("objective"), id("unit"), 0, 0).is_err());
    assert!(ObserveRequest::new(id("observe"), id("objective"), id("unit"), 0, 1_001).is_err());

    let resume = resume_request();
    assert_eq!(
        automonique_lab::protocol::Operation::Resume,
        LabRequest::Resume(resume).operation()
    );
    let cancel = CancelRequest::new(
        id("cancel"),
        id("objective"),
        id("unit"),
        0,
        id("cancel-key"),
        CancelReason::OperatorRequest,
    )
    .unwrap();
    assert_eq!(
        automonique_lab::protocol::Operation::Cancel,
        LabRequest::Cancel(cancel).operation()
    );

    assert_eq!(
        "unit.resumed",
        EventType::from_wire("unit.resumed").unwrap().as_wire()
    );
    assert_eq!(
        "future.event",
        EventType::from_wire("future.event").unwrap().as_wire()
    );
    assert!(EventType::from_wire("").is_err());
}

#[test]
fn observed_response_requires_contiguous_matching_coordinates() {
    let request = LabRequest::Observe(
        ObserveRequest::new(id("observe"), id("R0-19-synthetic"), id("unit-1"), 5, 10).unwrap(),
    );
    let event = LabEvent::new(
        EventType::from_wire("unit.resumed").unwrap(),
        id("R0-19-synthetic"),
        id("unit-1"),
        6,
        3,
    )
    .unwrap();
    let response = LabResponse::Observed(
        ObservedResponse::new(
            id("observe"),
            unit(UnitState::Running, 3, None, 6),
            vec![event],
            6,
        )
        .unwrap(),
    );
    response.validate_for(&request).unwrap();

    let gap = LabEvent::new(
        EventType::from_wire("unit.resumed").unwrap(),
        id("R0-19-synthetic"),
        id("unit-1"),
        7,
        3,
    )
    .unwrap();
    let response = LabResponse::Observed(
        ObservedResponse::new(
            id("observe"),
            unit(UnitState::Running, 3, None, 7),
            vec![gap],
            7,
        )
        .unwrap(),
    );
    assert_eq!(
        ValidationKind::Incoherent,
        response.validate_for(&request).unwrap_err().kind
    );

    let mismatches = [
        LabResponse::Observed(
            ObservedResponse::new(
                id("other-request"),
                unit(UnitState::Running, 3, None, 6),
                vec![event_at("R0-19-synthetic", "unit-1", 6, 3)],
                6,
            )
            .unwrap(),
        ),
        LabResponse::Observed(
            ObservedResponse::new(
                id("observe"),
                unit_at("unit-1", "other-objective", UnitState::Running, 3, None, 6),
                vec![event_at("R0-19-synthetic", "unit-1", 6, 3)],
                6,
            )
            .unwrap(),
        ),
        LabResponse::Observed(
            ObservedResponse::new(
                id("observe"),
                unit_at(
                    "other-unit",
                    "R0-19-synthetic",
                    UnitState::Running,
                    3,
                    None,
                    6,
                ),
                vec![event_at("R0-19-synthetic", "unit-1", 6, 3)],
                6,
            )
            .unwrap(),
        ),
        LabResponse::Observed(
            ObservedResponse::new(
                id("observe"),
                unit(UnitState::Running, 3, None, 6),
                vec![event_at("other-objective", "unit-1", 6, 3)],
                6,
            )
            .unwrap(),
        ),
        LabResponse::Observed(
            ObservedResponse::new(
                id("observe"),
                unit(UnitState::Running, 3, None, 6),
                vec![event_at("R0-19-synthetic", "other-unit", 6, 3)],
                6,
            )
            .unwrap(),
        ),
        LabResponse::Observed(
            ObservedResponse::new(
                id("observe"),
                unit(UnitState::Running, 3, None, 7),
                vec![
                    event_at("R0-19-synthetic", "unit-1", 6, 3),
                    event_at("R0-19-synthetic", "unit-1", 7, 2),
                ],
                7,
            )
            .unwrap(),
        ),
        LabResponse::Observed(
            ObservedResponse::new(
                id("observe"),
                unit(UnitState::Running, 3, None, 6),
                vec![event_at("R0-19-synthetic", "unit-1", 6, 4)],
                6,
            )
            .unwrap(),
        ),
        LabResponse::Observed(
            ObservedResponse::new(
                id("observe"),
                unit(UnitState::Running, 3, None, 6),
                vec![event_at("R0-19-synthetic", "unit-1", 6, 3)],
                5,
            )
            .unwrap(),
        ),
        LabResponse::Observed(
            ObservedResponse::new(
                id("observe"),
                unit(UnitState::Running, 3, None, 4),
                vec![],
                5,
            )
            .unwrap(),
        ),
    ];
    for mismatch in mismatches {
        assert!(mismatch.validate_for(&request).is_err());
    }

    let one_event_request = LabRequest::Observe(
        ObserveRequest::new(id("observe"), id("R0-19-synthetic"), id("unit-1"), 5, 1).unwrap(),
    );
    let overfull_page = LabResponse::Observed(
        ObservedResponse::new(
            id("observe"),
            unit(UnitState::Running, 3, None, 7),
            vec![
                event_at("R0-19-synthetic", "unit-1", 6, 2),
                event_at("R0-19-synthetic", "unit-1", 7, 3),
            ],
            7,
        )
        .unwrap(),
    );
    assert!(overfull_page.validate_for(&one_event_request).is_err());
}

#[test]
fn action_receipts_enforce_effect_and_request_coordinates() {
    let coordinates = || ActionCoordinates {
        action_id: id("action-1"),
        operation: ActionOperation::Resume,
        objective_id: id("R0-19-synthetic"),
        unit_id: id("unit-1"),
        checkpoint_id: Some(id("checkpoint-1")),
        expected_revision: 2,
        idempotency_key: id("resume-key"),
    };
    assert!(
        ActionReceipt::new(
            coordinates(),
            ActionOutcome {
                status: ActionStatus::Accepted,
                effect_count: 0,
                reason: None,
            },
        )
        .is_err()
    );
    assert!(
        ActionReceipt::new(
            coordinates(),
            ActionOutcome {
                status: ActionStatus::Conflict,
                effect_count: 0,
                reason: None,
            },
        )
        .is_err()
    );

    let receipt = ActionReceipt::new(
        coordinates(),
        ActionOutcome {
            status: ActionStatus::Accepted,
            effect_count: 1,
            reason: None,
        },
    )
    .unwrap();
    let response = LabResponse::Action(ActionResponse::new(
        id("resume"),
        receipt.clone(),
        unit(UnitState::Running, 3, None, 6),
    ));
    response
        .validate_for(&LabRequest::Resume(resume_request()))
        .unwrap();

    let stale = LabResponse::Action(ActionResponse::new(
        id("resume"),
        receipt,
        unit(UnitState::Running, 2, None, 6),
    ));
    assert_eq!(
        ValidationKind::Incoherent,
        stale
            .validate_for(&LabRequest::Resume(resume_request()))
            .unwrap_err()
            .kind
    );

    let request = LabRequest::Resume(resume_request());
    let mismatches = [
        LabResponse::Action(ActionResponse::new(
            id("other-request"),
            resume_receipt(
                ActionOperation::Resume,
                "R0-19-synthetic",
                "unit-1",
                Some("checkpoint-1"),
                2,
                "resume-key",
            ),
            unit(UnitState::Running, 3, None, 6),
        )),
        LabResponse::Action(ActionResponse::new(
            id("resume"),
            resume_receipt(
                ActionOperation::Cancel,
                "R0-19-synthetic",
                "unit-1",
                Some("checkpoint-1"),
                2,
                "resume-key",
            ),
            unit(UnitState::CancelRequested, 3, None, 6),
        )),
        LabResponse::Action(ActionResponse::new(
            id("resume"),
            resume_receipt(
                ActionOperation::Resume,
                "other-objective",
                "unit-1",
                Some("checkpoint-1"),
                2,
                "resume-key",
            ),
            unit(UnitState::Running, 3, None, 6),
        )),
        LabResponse::Action(ActionResponse::new(
            id("resume"),
            resume_receipt(
                ActionOperation::Resume,
                "R0-19-synthetic",
                "other-unit",
                Some("checkpoint-1"),
                2,
                "resume-key",
            ),
            unit(UnitState::Running, 3, None, 6),
        )),
        LabResponse::Action(ActionResponse::new(
            id("resume"),
            resume_receipt(
                ActionOperation::Resume,
                "R0-19-synthetic",
                "unit-1",
                Some("other-checkpoint"),
                2,
                "resume-key",
            ),
            unit(UnitState::Running, 3, None, 6),
        )),
        LabResponse::Action(ActionResponse::new(
            id("resume"),
            resume_receipt(
                ActionOperation::Resume,
                "R0-19-synthetic",
                "unit-1",
                Some("checkpoint-1"),
                1,
                "resume-key",
            ),
            unit(UnitState::Running, 3, None, 6),
        )),
        LabResponse::Action(ActionResponse::new(
            id("resume"),
            resume_receipt(
                ActionOperation::Resume,
                "R0-19-synthetic",
                "unit-1",
                Some("checkpoint-1"),
                2,
                "other-key",
            ),
            unit(UnitState::Running, 3, None, 6),
        )),
        LabResponse::Action(ActionResponse::new(
            id("resume"),
            resume_receipt(
                ActionOperation::Resume,
                "R0-19-synthetic",
                "unit-1",
                Some("checkpoint-1"),
                2,
                "resume-key",
            ),
            unit(UnitState::Paused, 3, Some("checkpoint-1"), 6),
        )),
    ];
    for mismatch in mismatches {
        assert!(mismatch.validate_for(&request).is_err());
    }
}

const OBSERVE_BODY: &[u8] = br#"{"afterSequence":0,"limit":10,"objectiveId":"R0-19-synthetic","op":"observe","protocol":"automonique.lab-scenario/v1","requestId":"request","unitId":"unit-1"}"#;

#[test]
fn framing_matches_the_canonical_observe_golden() {
    assert_eq!(158, OBSERVE_BODY.len());
    let limits = FrameLimits::new(65_536).unwrap();
    let frame = encode_frame(OBSERVE_BODY, limits).unwrap();
    assert_eq!([0x00, 0x00, 0x00, 0x9e], frame[..4]);
    assert_eq!(OBSERVE_BODY, decode_frame(&frame, limits).unwrap());
}

#[test]
fn framing_denies_zero_oversize_truncation_and_extra_data() {
    let limits = FrameLimits::new(4).unwrap();
    assert_eq!(FrameError::InvalidMaximum, FrameLimits::new(0).unwrap_err());
    assert_eq!(
        FrameError::InvalidMaximum,
        FrameLimits::new(ABSOLUTE_MAX_FRAME_BYTES + 1).unwrap_err()
    );
    let absolute = FrameLimits::new(ABSOLUTE_MAX_FRAME_BYTES).unwrap();
    assert_eq!(ABSOLUTE_MAX_FRAME_BYTES, absolute.maximum_payload_bytes());
    assert!(
        usize::try_from(ABSOLUTE_MAX_FRAME_BYTES)
            .unwrap()
            .checked_add(FRAME_PREFIX_BYTES)
            .is_some()
    );
    assert!(matches!(
        decode_frame(&u32::MAX.to_be_bytes(), absolute),
        Err(FrameError::FrameTooLarge { .. })
    ));
    assert!(matches!(
        encode_frame(&[], limits),
        Err(FrameError::FrameTooLarge { length: 0, .. })
    ));
    assert!(matches!(
        encode_frame(b"12345", limits),
        Err(FrameError::FrameTooLarge { length: 5, .. })
    ));
    assert_eq!(
        FrameError::TruncatedPrefix { available: 2 },
        decode_frame(&[0, 0], limits).unwrap_err()
    );
    assert!(matches!(
        decode_frame(&[0, 0, 0, 0], limits),
        Err(FrameError::FrameTooLarge { length: 0, .. })
    ));
    assert_eq!(
        FrameError::TruncatedPayload {
            expected: 4,
            available: 2,
        },
        decode_frame(&[0, 0, 0, 4, b'o', b'k'], limits).unwrap_err()
    );
    assert_eq!(
        FrameError::ExtraData {
            expected_total: 6,
            actual_total: 7,
        },
        decode_frame(&[0, 0, 0, 2, b'o', b'k', b'!'], limits).unwrap_err()
    );
    assert!(matches!(
        decode_frame(&[0, 0, 0, 5, b'1', b'2', b'3', b'4', b'5'], limits),
        Err(FrameError::FrameTooLarge { length: 5, .. })
    ));
}

#[derive(Clone, Copy)]
struct Utf8Codec;

impl PayloadCodec for Utf8Codec {
    type Value = String;
    type Error = &'static str;

    fn encode_payload(&self, value: &Self::Value) -> Result<Vec<u8>, Self::Error> {
        Ok(value.as_bytes().to_vec())
    }

    fn decode_payload(&self, payload: &[u8]) -> Result<Self::Value, Self::Error> {
        std::str::from_utf8(payload)
            .map(str::to_owned)
            .map_err(|_| "invalid utf-8")
    }
}

#[test]
fn payload_codec_boundary_is_independent_of_frame_semantics() {
    let limits = FrameLimits::new(32).unwrap();
    let frame = encode_with(&Utf8Codec, &"payload".to_owned(), limits).unwrap();
    assert_eq!("payload", decode_with(&Utf8Codec, &frame, limits).unwrap());
    assert!(matches!(
        decode_with(&Utf8Codec, &[0, 0, 0, 1, 0xff], limits),
        Err(CodecError::Payload("invalid utf-8"))
    ));
}
