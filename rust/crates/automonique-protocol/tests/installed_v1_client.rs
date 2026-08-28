// SPDX-License-Identifier: Elastic-2.0

#[path = "support/installed_v1_client_2e428e44.rs"]
mod installed_v1_client_2e428e44;

use automonique_protocol::codec::RequestId;
use automonique_protocol::platform::{
    ActionReceipt, Capabilities, CursorTopic, Freshness, FreshnessState, PlatformAction,
    PlatformCursor, PlatformResponse, PlatformText, ReceiptId, ReceiptOutcome, ResourceAuthority,
    ResourceCoordinate, ResourceId, ResourceKind, ResourceRecord, SessionList, SessionRecord,
    Snapshot,
};
use automonique_protocol::platform_api::PlatformResponseMessage;
use automonique_protocol::platform_v2::{
    PlatformVersion, PlatformVersionOffer, WorkContextAvailability, negotiate_platform_version,
};
use automonique_protocol::primitives::{EpochMillis, Revision};
use automonique_protocol::wire::{JsonValue, parse_canonical};
use installed_v1_client_2e428e44::decode;
use sha2::{Digest as _, Sha256};

const TRANSCRIPTS: &[u8] =
    include_bytes!("../fixtures/platform-v1-installed-client-responses-2e428e44.json");
const FROZEN_DECODER_SOURCE: &[u8] = include_bytes!("support/installed_v1_client_2e428e44.rs");
const TRANSCRIPT_SHA256: &str = "37039d1bce74e67a8d5a526073cecf61b269ccc7348a300b8ccabd042ab7f7dd";
const FROZEN_DECODER_SHA256: &str =
    "3e40b9d9d4f457a3b1737e9f905bdabf1bc62a4d45e0419e166e7e1f0af5d6de";

fn coordinate(kind: ResourceKind, id: &str) -> ResourceCoordinate {
    ResourceCoordinate::new(
        ResourceAuthority::Automonique,
        kind,
        ResourceId::new(id).unwrap(),
    )
}

fn cursor() -> PlatformCursor {
    PlatformCursor {
        authority: ResourceAuthority::Automonique,
        topic: CursorTopic::new("operator").unwrap(),
        sequence: Revision::new(2).unwrap(),
    }
}

fn session_record() -> ResourceRecord {
    ResourceRecord {
        resource: coordinate(ResourceKind::Session, "session-1"),
        freshness: Freshness {
            state: FreshnessState::Fresh,
            observed_at: EpochMillis::from_millis(1_000),
            revision: Revision::new(2).unwrap(),
        },
        summary: PlatformText::new("ready").unwrap(),
    }
}

fn current_server_responses() -> Vec<(&'static str, PlatformResponse)> {
    let session = session_record();
    vec![
        (
            "capabilities",
            PlatformResponse::Capabilities(Capabilities::platform_v1()),
        ),
        (
            "receipt",
            PlatformResponse::Receipt(ActionReceipt {
                id: ReceiptId::new("receipt-1").unwrap(),
                action: PlatformAction::StartRun,
                target: coordinate(ResourceKind::Run, "run-1"),
                outcome: ReceiptOutcome::Accepted,
                revision: Revision::new(3).unwrap(),
                recorded_at: EpochMillis::from_millis(2_000),
                explanation: None,
            }),
        ),
        (
            "refused",
            PlatformResponse::Refused {
                outcome: ReceiptOutcome::ResyncRequired,
                explanation: PlatformText::new("fresh snapshot required").unwrap(),
            },
        ),
        (
            "sessions",
            PlatformResponse::Sessions(
                SessionList::new(
                    vec![SessionRecord {
                        session: session.clone(),
                        run: None,
                        attachable: true,
                        controllable: true,
                    }],
                    cursor(),
                )
                .unwrap(),
            ),
        ),
        (
            "snapshot",
            PlatformResponse::Snapshot(Snapshot::new(vec![session], cursor()).unwrap()),
        ),
    ]
}

#[test]
fn frozen_pre_v2_client_decodes_current_server_v1_responses_after_v1_negotiation() {
    assert_eq!(
        format!("{:x}", Sha256::digest(TRANSCRIPTS)),
        TRANSCRIPT_SHA256
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(FROZEN_DECODER_SOURCE)),
        FROZEN_DECODER_SHA256
    );

    let installed_client = PlatformVersionOffer::new(vec![1]).unwrap();
    let current_server = PlatformVersionOffer::new(vec![1, 2]).unwrap();
    let negotiated = negotiate_platform_version(&installed_client, &current_server).unwrap();
    assert_eq!(negotiated.version(), PlatformVersion::V1);
    assert_eq!(
        negotiated.schema(),
        automonique_protocol::platform::PLATFORM_SCHEMA_V1
    );
    assert_eq!(
        negotiated.work_context(),
        WorkContextAvailability::V1ExistingResourcesOnly
    );

    let corpus = TRANSCRIPTS.strip_suffix(b"\n").unwrap_or(TRANSCRIPTS);
    let JsonValue::Object(transcripts) =
        parse_canonical(corpus).expect("frozen transcript corpus is canonical JSON")
    else {
        panic!("frozen transcript corpus must be an object");
    };
    let responses = current_server_responses();
    assert_eq!(transcripts.len(), responses.len());

    for (label, response) in responses {
        let expected = transcripts
            .iter()
            .find_map(|(fixture_label, value)| (fixture_label == label).then_some(value))
            .unwrap_or_else(|| panic!("missing frozen {label} transcript"));
        let JsonValue::String(expected) = expected else {
            panic!("{label}: transcript must be a canonical response string");
        };
        let request_id = format!("installed-v1-{label}");
        let emitted =
            PlatformResponseMessage::new(RequestId::new(request_id.clone()).unwrap(), response)
                .to_message()
                .unwrap()
                .to_canonical_bytes();
        assert_eq!(
            emitted,
            expected.as_bytes(),
            "{label}: current server v1 response drifted from the immutable transcript"
        );

        let historical = decode(expected.as_bytes())
            .unwrap_or_else(|error| panic!("{label}: frozen pre-v2 client refused: {error}"));
        assert_eq!(historical.request_id, request_id);
        assert_eq!(historical.kind.as_str(), label);
    }
}
