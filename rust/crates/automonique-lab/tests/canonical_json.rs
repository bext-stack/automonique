// SPDX-License-Identifier: Elastic-2.0

use automonique_lab::canonical_json::{
    CanonicalJsonError, CanonicalRequestCodec, CanonicalResponseCodec,
    CanonicalTransportErrorCodec, TransportErrorCode, TransportErrorDocument, decode_request,
    decode_response_for, decode_transport_error, encode_request, encode_response,
    encode_transport_error,
};
use automonique_lab::framing::{FrameLimits, decode_with, encode_with};
use automonique_lab::protocol::{
    ActionCoordinates, ActionOperation, ActionOutcome, ActionReceipt, ActionResponse, ActionStatus,
    BudgetEnforcement, CancelReason, CancelRequest, DeniedResponse, EventType, Execution, GitSha1,
    LabBudget, LabBudgetValues, LabEvent, LabRequest, LabResponse, ObserveRequest,
    ObservedResponse, OpaqueId, ProviderPolicy, ResumeRequest, SelectRequest, SelectedResponse,
    SyntheticProviderPolicy, UnitSnapshot, UnitState, ValidationKind,
};

fn id(value: &str) -> OpaqueId {
    OpaqueId::new(value).unwrap()
}

fn budget() -> LabBudget {
    LabBudget::new(LabBudgetValues {
        max_wall_ms: 1_000,
        max_cpu_ms: 500,
        max_disk_bytes: 16_384,
        max_output_bytes: 4_096,
        max_pids: 1,
        max_model_calls: 0,
        max_cost_microunits: 0,
        enforcement: BudgetEnforcement::SyntheticInProcess,
    })
    .unwrap()
}

fn select() -> LabRequest {
    LabRequest::Select(
        SelectRequest::new(
            id("select"),
            id("R0-19-synthetic"),
            GitSha1::new("1".repeat(40)).unwrap(),
            Execution::Synthetic,
            ProviderPolicy::Synthetic(SyntheticProviderPolicy),
            budget(),
        )
        .unwrap(),
    )
}

fn observe() -> LabRequest {
    LabRequest::Observe(
        ObserveRequest::new(id("request"), id("R0-19-synthetic"), id("unit-1"), 0, 10).unwrap(),
    )
}

fn resume() -> LabRequest {
    LabRequest::Resume(
        ResumeRequest::new(
            id("resume"),
            id("R0-19-synthetic"),
            id("unit-1"),
            id("checkpoint-1"),
            2,
            id("resume-key"),
        )
        .unwrap(),
    )
}

fn cancel() -> LabRequest {
    LabRequest::Cancel(
        CancelRequest::new(
            id("cancel"),
            id("R0-19-synthetic"),
            id("unit-1"),
            3,
            id("cancel-key"),
            CancelReason::OperatorRequest,
        )
        .unwrap(),
    )
}

fn unit(state: UnitState, revision: u64, checkpoint: Option<&str>, sequence: u64) -> UnitSnapshot {
    UnitSnapshot::new(
        id("unit-1"),
        id("R0-19-synthetic"),
        state,
        revision,
        checkpoint.map(id),
        sequence,
    )
    .unwrap()
}

#[test]
fn request_goldens_match_typescript_and_python_wire_shapes() {
    const OBSERVE: &[u8] = br#"{"afterSequence":0,"limit":10,"objectiveId":"R0-19-synthetic","op":"observe","protocol":"automonique.lab-scenario/v1","requestId":"request","unitId":"unit-1"}"#;
    assert_eq!(OBSERVE, encode_request(&observe()).unwrap());
    assert_eq!(observe(), decode_request(OBSERVE).unwrap());

    let requests = [select(), observe(), resume(), cancel()];
    for request in requests {
        let encoded = encode_request(&request).unwrap();
        assert_eq!(request, decode_request(&encoded).unwrap());
        assert!(!encoded.contains(&b' '));
    }
    assert_eq!(
        br#"{"checkpointId":"checkpoint-1","expectedRevision":2,"idempotencyKey":"resume-key","objectiveId":"R0-19-synthetic","op":"resume","protocol":"automonique.lab-scenario/v1","requestId":"resume","unitId":"unit-1"}"#,
        encode_request(&resume()).unwrap().as_slice()
    );
    assert_eq!(
        br#"{"expectedRevision":3,"idempotencyKey":"cancel-key","objectiveId":"R0-19-synthetic","op":"cancel","protocol":"automonique.lab-scenario/v1","reason":"operator_request","requestId":"cancel","unitId":"unit-1"}"#,
        encode_request(&cancel()).unwrap().as_slice()
    );
}

#[test]
fn every_response_variant_round_trips_with_request_coordinates() {
    let selected = LabResponse::Selected(SelectedResponse::new(
        id("select"),
        unit(UnitState::Selected, 1, Some("checkpoint-1"), 1),
    ));
    assert_eq!(
        br#"{"kind":"selected","protocol":"automonique.lab-scenario/v1","requestId":"select","unit":{"checkpointId":"checkpoint-1","lastSequence":1,"objectiveId":"R0-19-synthetic","revision":1,"state":"selected","unitId":"unit-1"}}"#,
        encode_response(&selected).unwrap().as_slice()
    );
    let unknown = LabEvent::new(
        EventType::from_wire("future.event").unwrap(),
        id("R0-19-synthetic"),
        id("unit-1"),
        1,
        1,
    )
    .unwrap();
    let observed = LabResponse::Observed(
        ObservedResponse::new(
            id("request"),
            unit(UnitState::Selected, 1, Some("checkpoint-1"), 1),
            vec![unknown],
            1,
        )
        .unwrap(),
    );
    let receipt = ActionReceipt::new(
        ActionCoordinates {
            action_id: id("action-resume"),
            operation: ActionOperation::Resume,
            objective_id: id("R0-19-synthetic"),
            unit_id: id("unit-1"),
            checkpoint_id: Some(id("checkpoint-1")),
            expected_revision: 2,
            idempotency_key: id("resume-key"),
        },
        ActionOutcome {
            status: ActionStatus::Accepted,
            effect_count: 1,
            reason: None,
        },
    )
    .unwrap();
    let action = LabResponse::Action(ActionResponse::new(
        id("resume"),
        receipt,
        unit(UnitState::Running, 3, None, 2),
    ));
    let denied = LabResponse::Denied(
        DeniedResponse::new(id("cancel"), id("policy_denied"), "denied").unwrap(),
    );

    for (request, response) in [
        (select(), selected),
        (observe(), observed),
        (resume(), action),
        (cancel(), denied),
    ] {
        let encoded = encode_response(&response).unwrap();
        assert_eq!(response, decode_response_for(&encoded, &request).unwrap());
    }

    let observed_wire = encode_response(&LabResponse::Observed(
        ObservedResponse::new(
            id("request"),
            unit(UnitState::Selected, 1, Some("checkpoint-1"), 1),
            vec![
                LabEvent::new(
                    EventType::from_wire("future.event").unwrap(),
                    id("R0-19-synthetic"),
                    id("unit-1"),
                    1,
                    1,
                )
                .unwrap(),
            ],
            1,
        )
        .unwrap(),
    ))
    .unwrap();
    assert!(
        std::str::from_utf8(&observed_wire)
            .unwrap()
            .contains("\"type\":\"future.event\"")
    );
}

#[test]
fn payload_codecs_preserve_frame_semantics() {
    let limits = FrameLimits::new(65_536).unwrap();
    let request = observe();
    let frame = encode_with(&CanonicalRequestCodec, &request, limits).unwrap();
    assert_eq!(
        request,
        decode_with(&CanonicalRequestCodec, &frame, limits).unwrap()
    );

    let response =
        LabResponse::Denied(DeniedResponse::new(id("request"), id("busy"), "try later").unwrap());
    let response_codec = CanonicalResponseCodec::new(&request);
    let frame = encode_with(&response_codec, &response, limits).unwrap();
    assert_eq!(
        response,
        decode_with(&response_codec, &frame, limits).unwrap()
    );
}

#[test]
fn transport_error_is_closed_and_canonical() {
    let error = TransportErrorDocument::new(TransportErrorCode::MalformedJson, "bad JSON").unwrap();
    let golden = br#"{"code":"malformed_json","protocol":"automonique.lab-transport-error/v1","reason":"bad JSON"}"#;
    assert_eq!(golden, encode_transport_error(&error).unwrap().as_slice());
    assert_eq!(error, decode_transport_error(golden).unwrap());
    assert!(matches!(
        decode_transport_error(
            br#"{"code":"future","protocol":"automonique.lab-transport-error/v1","reason":"bad"}"#
        ),
        Err(CanonicalJsonError::UnknownEnum("code"))
    ));
    let codec = CanonicalTransportErrorCodec;
    let frame = encode_with(&codec, &error, FrameLimits::new(1_024).unwrap()).unwrap();
    assert_eq!(
        error,
        decode_with(&codec, &frame, FrameLimits::new(1_024).unwrap()).unwrap()
    );
}

#[test]
fn malformed_noncanonical_duplicate_and_schema_mutations_are_denied() {
    let canonical = encode_request(&observe()).unwrap();
    let mut whitespace = canonical.clone();
    whitespace.insert(1, b' ');
    assert_eq!(
        CanonicalJsonError::Noncanonical,
        decode_request(&whitespace).unwrap_err()
    );
    assert_eq!(
        CanonicalJsonError::InvalidUtf8,
        decode_request(&[0xff]).unwrap_err()
    );
    assert_eq!(
        CanonicalJsonError::MalformedJson,
        decode_request(b"{").unwrap_err()
    );

    let duplicate = br#"{"afterSequence":0,"limit":10,"limit":10,"objectiveId":"R0-19-synthetic","op":"observe","protocol":"automonique.lab-scenario/v1","requestId":"request","unitId":"unit-1"}"#;
    assert_eq!(
        CanonicalJsonError::Noncanonical,
        decode_request(duplicate).unwrap_err()
    );
    let unknown = br#"{"afterSequence":0,"limit":10,"objectiveId":"R0-19-synthetic","op":"observe","protocol":"automonique.lab-scenario/v1","requestId":"request","unitId":"unit-1","zz":0}"#;
    assert_eq!(
        CanonicalJsonError::UnknownField("zz".into()),
        decode_request(unknown).unwrap_err()
    );
    let missing = br#"{"afterSequence":0,"objectiveId":"R0-19-synthetic","op":"observe","protocol":"automonique.lab-scenario/v1","requestId":"request","unitId":"unit-1"}"#;
    assert_eq!(
        CanonicalJsonError::MissingField("limit"),
        decode_request(missing).unwrap_err()
    );
}

#[test]
fn floats_depth_wrong_version_and_unknown_enums_are_denied() {
    let floating = br#"{"afterSequence":0.0,"limit":10,"objectiveId":"R0-19-synthetic","op":"observe","protocol":"automonique.lab-scenario/v1","requestId":"request","unitId":"unit-1"}"#;
    assert_eq!(
        CanonicalJsonError::FloatingPoint,
        decode_request(floating).unwrap_err()
    );

    let mut nested = serde_json::Value::Null;
    for _ in 0..18 {
        nested = serde_json::Value::Array(vec![nested]);
    }
    let mut deep: serde_json::Value =
        serde_json::from_slice(&encode_request(&select()).unwrap()).unwrap();
    deep.as_object_mut()
        .unwrap()
        .insert("budget".into(), nested);
    assert_eq!(
        CanonicalJsonError::DepthExceeded,
        decode_request(&serde_json::to_vec(&deep).unwrap()).unwrap_err()
    );

    let wrong_version = br#"{"afterSequence":0,"limit":10,"objectiveId":"R0-19-synthetic","op":"observe","protocol":"automonique.lab-scenario/v2","requestId":"request","unitId":"unit-1"}"#;
    assert_eq!(
        CanonicalJsonError::UnsupportedVersion,
        decode_request(wrong_version).unwrap_err()
    );
    let unknown_op = br#"{"op":"launch"}"#;
    assert_eq!(
        CanonicalJsonError::UnknownEnum("op"),
        decode_request(unknown_op).unwrap_err()
    );
}

#[test]
fn response_coordinate_mismatch_is_rejected_after_structural_decode() {
    let response =
        LabResponse::Denied(DeniedResponse::new(id("other-request"), id("denied"), "no").unwrap());
    let error = decode_response_for(&encode_response(&response).unwrap(), &observe()).unwrap_err();
    assert!(matches!(
        error,
        CanonicalJsonError::Domain(ref domain)
            if domain.kind == ValidationKind::CoordinateMismatch
    ));
}

#[test]
fn inventory_wire_policy_cannot_mint_verified_authority() {
    let inventory = format!(
        "{{\"budget\":{{\"enforcement\":\"host_broker_required\",\"maxCostMicrounits\":1,\"maxCpuMs\":1,\"maxDiskBytes\":1,\"maxModelCalls\":1,\"maxOutputBytes\":1,\"maxPids\":1,\"maxWallMs\":1}},\"execution\":\"inventory\",\"expectedBase\":\"{}\",\"objectiveId\":\"objective\",\"op\":\"select\",\"protocol\":\"automonique.lab-scenario/v1\",\"providerPolicy\":{{\"explicitFallbacks\":[],\"inventoryDigest\":\"{}\",\"kind\":\"inventory\",\"minimumEvidence\":\"advertised\",\"mode\":\"mode\",\"provider\":\"provider\",\"requiredCapabilities\":[\"create\"],\"surfaceDigest\":\"{}\"}},\"requestId\":\"select\"}}",
        "1".repeat(40),
        "2".repeat(64),
        "3".repeat(64)
    );
    assert_eq!(
        CanonicalJsonError::UntrustedInventoryPolicy,
        decode_request(inventory.as_bytes()).unwrap_err()
    );
}
