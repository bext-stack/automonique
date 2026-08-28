// SPDX-License-Identifier: Elastic-2.0

#[path = "support/platform_v1_reference.rs"]
mod platform_v1_reference;

use std::collections::BTreeMap;

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
use automonique_protocol::platform_v2_api::decode_platform_version_offer;
use automonique_protocol::primitives::{EpochMillis, Revision};
use platform_v1_reference::{ResponseKind, decode_response, transcript_corpus};

const INSTALLED_CLIENT_V1_ONLY_OFFER: &[u8] =
    br#"{"schema":"automonique.platform/negotiation/v1","versions":[1]}"#;
const CURRENT_SERVER_TRANSCRIPTS: &[u8] =
    include_bytes!("../fixtures/platform-v1-current-server-responses.json");

#[test]
fn literal_installed_client_v1_only_offer_negotiates_v1_with_current_server() {
    let installed_client = decode_platform_version_offer(INSTALLED_CLIENT_V1_ONLY_OFFER)
        .expect("the literal installed-client offer is valid");
    assert_eq!(installed_client.versions(), [1]);

    let current_server = PlatformVersionOffer::new(vec![1, 2]).expect("current server offer");
    let negotiated = negotiate_platform_version(&installed_client, &current_server)
        .expect("current server retains v1 overlap");
    assert_eq!(negotiated.version(), PlatformVersion::V1);
    assert_eq!(negotiated.schema(), "automonique.platform/v1");
    assert_eq!(
        negotiated.work_context(),
        WorkContextAvailability::V1ExistingResourcesOnly
    );
}

#[test]
fn current_v1_encoder_is_byte_identical_and_independent_decoder_accepts_transcripts() {
    let transcripts = transcript_corpus(CURRENT_SERVER_TRANSCRIPTS)
        .expect("the immutable current-server transcript corpus is valid");
    let responses = current_server_responses();
    assert_eq!(transcripts.len(), responses.len());

    for (label, (expected_kind, response)) in responses {
        let transcript = transcripts
            .get(label)
            .unwrap_or_else(|| panic!("{label}: transcript is absent"));
        let encoded = response
            .to_message()
            .expect("current v1 response encodes")
            .to_canonical_bytes();
        assert_eq!(
            encoded, *transcript,
            "{label}: current server changed the pinned v1 response bytes"
        );

        let decoded = decode_response(transcript)
            .unwrap_or_else(|error| panic!("{label}: independent v1 decoder refused: {error}"));
        assert_eq!(decoded.kind, expected_kind);
        assert_eq!(decoded.request_id, format!("installed-v1-{label}"));
    }
}

#[test]
fn independent_installed_v1_decoder_refuses_v2_and_additional_shape() {
    let transcripts = transcript_corpus(CURRENT_SERVER_TRANSCRIPTS).expect("transcript corpus");
    let capabilities = String::from_utf8(
        transcripts
            .get("capabilities")
            .expect("capabilities transcript")
            .clone(),
    )
    .expect("fixture response is UTF-8");

    let v2 = capabilities.replacen("\"version\":1}", "\"version\":2}", 1);
    assert_ne!(v2, capabilities);
    assert!(
        decode_response(v2.as_bytes()).is_err(),
        "an installed v1-only decoder must refuse a v2 envelope"
    );

    let additional = capabilities.replacen(
        "\"transports\":[\"local_unix\",\"remote_https\",\"remote_websocket\"]}",
        "\"transports\":[\"local_unix\",\"remote_https\",\"remote_websocket\"],\"work_context\":{}}",
        1,
    );
    assert_ne!(additional, capabilities);
    assert!(
        decode_response(additional.as_bytes()).is_err(),
        "an installed strict decoder must refuse an additive response body"
    );
}

fn current_server_responses() -> BTreeMap<&'static str, (ResponseKind, PlatformResponseMessage)> {
    let session_record = synthetic_session_record();
    let session = session_record.resource.clone();
    BTreeMap::from([
        (
            "capabilities",
            (
                ResponseKind::Capabilities,
                response(
                    "capabilities",
                    PlatformResponse::Capabilities(Capabilities::platform_v1()),
                ),
            ),
        ),
        (
            "snapshot",
            (
                ResponseKind::Snapshot,
                response(
                    "snapshot",
                    PlatformResponse::Snapshot(
                        Snapshot::new(vec![session_record.clone()], cursor(11))
                            .expect("bounded snapshot"),
                    ),
                ),
            ),
        ),
        (
            "sessions",
            (
                ResponseKind::Sessions,
                response(
                    "sessions",
                    PlatformResponse::Sessions(
                        SessionList::new(
                            vec![SessionRecord {
                                session: session_record,
                                run: Some(coordinate(ResourceKind::Run, "run-synthetic-1")),
                                attachable: true,
                                controllable: false,
                            }],
                            cursor(12),
                        )
                        .expect("bounded session list"),
                    ),
                ),
            ),
        ),
        (
            "receipt",
            (
                ResponseKind::Receipt,
                response(
                    "receipt",
                    PlatformResponse::Receipt(ActionReceipt {
                        id: ReceiptId::new("receipt-synthetic-1").expect("synthetic receipt id"),
                        action: PlatformAction::FollowUp,
                        target: session,
                        outcome: ReceiptOutcome::Completed,
                        revision: Revision::new(8).expect("revision"),
                        recorded_at: EpochMillis::from_millis(1_700_000_000_123),
                        explanation: Some(
                            PlatformText::new("synthetic follow-up completed")
                                .expect("synthetic explanation"),
                        ),
                    }),
                ),
            ),
        ),
        (
            "refusal",
            (
                ResponseKind::Refusal,
                response(
                    "refusal",
                    PlatformResponse::Refused {
                        outcome: ReceiptOutcome::ResyncRequired,
                        explanation: PlatformText::new("synthetic cursor is outside retention")
                            .expect("synthetic explanation"),
                    },
                ),
            ),
        ),
    ])
}

fn response(label: &str, response: PlatformResponse) -> PlatformResponseMessage {
    PlatformResponseMessage::new(
        RequestId::new(format!("installed-v1-{label}")).expect("synthetic request id"),
        response,
    )
}

fn coordinate(kind: ResourceKind, id: &str) -> ResourceCoordinate {
    ResourceCoordinate::new(
        ResourceAuthority::Automonique,
        kind,
        ResourceId::new(id).expect("synthetic resource id"),
    )
}

fn cursor(sequence: u64) -> PlatformCursor {
    PlatformCursor {
        authority: ResourceAuthority::Automonique,
        topic: CursorTopic::new("platform-v1-fixture").expect("synthetic cursor topic"),
        sequence: Revision::new(sequence).expect("cursor sequence"),
    }
}

fn synthetic_session_record() -> ResourceRecord {
    ResourceRecord {
        resource: coordinate(ResourceKind::Session, "session-synthetic-1"),
        freshness: Freshness {
            state: FreshnessState::Fresh,
            observed_at: EpochMillis::from_millis(1_700_000_000_000),
            revision: Revision::new(7).expect("resource revision"),
        },
        summary: PlatformText::new("active synthetic session").expect("synthetic summary"),
    }
}
