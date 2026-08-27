// SPDX-License-Identifier: Apache-2.0

use automonique_platform_client::ClientError;
use automonique_platform_client::platform_v2_client::testing::{
    DeterministicPlatformV2Step, DeterministicPlatformV2Transport,
};
use automonique_platform_client::platform_v2_client::{
    NegotiationResult, PlatformV2Client, PlatformV2Lane, PlatformV2Transport, WorkContextGetResult,
};
use automonique_protocol::codec::RequestId;
use automonique_protocol::platform_v2::{
    NegotiatedPlatform, PLATFORM_SCHEMA_V2, PlatformVersion, PlatformVersionOffer, ProjectId,
    WorkContextAttributes, WorkContextAvailability, WorkContextIdentity, WorkContextLabel,
    WorkContextLifecycle, WorkContextRecord,
};
use automonique_protocol::platform_v2_transport::{
    MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES, PlatformNegotiationRequest,
    PlatformNegotiationRequestMessage, PlatformNegotiationResponse,
    PlatformNegotiationResponseMessage, PlatformV2Refusal, PlatformV2Response,
};
use automonique_protocol::primitives::Revision;

fn negotiated(version: PlatformVersion) -> NegotiatedPlatform {
    NegotiatedPlatform::new(
        version,
        version.schema(),
        match version {
            PlatformVersion::V1 => WorkContextAvailability::V1ExistingResourcesOnly,
            PlatformVersion::V2 => WorkContextAvailability::V2Structured,
        },
    )
    .unwrap()
}

fn project(id: &str) -> WorkContextIdentity {
    WorkContextIdentity::Project(ProjectId::new(id).unwrap())
}

fn project_record(id: &str) -> WorkContextRecord {
    WorkContextRecord::new(
        project(id),
        Revision::new(1).unwrap(),
        WorkContextLifecycle::Active,
        WorkContextLabel::new("Project".to_owned()).unwrap(),
        WorkContextAttributes::EMPTY,
        vec![],
    )
    .unwrap()
}

#[test]
fn negotiates_v2_then_preserves_exact_request_coordinates() {
    let transport = DeterministicPlatformV2Transport::new([
        DeterministicPlatformV2Step::Negotiation(PlatformNegotiationResponse::Negotiated(
            negotiated(PlatformVersion::V2),
        )),
        DeterministicPlatformV2Step::V2(Box::new(PlatformV2Response::WorkContextRecord(
            project_record("project-a"),
        ))),
    ]);
    let mut client = PlatformV2Client::new(transport);
    assert!(matches!(
        client
            .negotiate(PlatformVersionOffer::new(vec![1, 2]).unwrap())
            .unwrap(),
        NegotiationResult::V2(_)
    ));
    assert!(matches!(
        client.get_work_context(project("project-a")).unwrap(),
        WorkContextGetResult::Record(_)
    ));
    let requests = client.transport().requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].request(),
        &automonique_protocol::platform_v2_transport::PlatformV2Request::GetWorkContext(project(
            "project-a"
        ))
    );
}

#[test]
fn downgrade_and_refusal_never_enable_v2_requests() {
    for response in [
        PlatformNegotiationResponse::Negotiated(negotiated(PlatformVersion::V1)),
        PlatformNegotiationResponse::Refused(
            PlatformV2Refusal::new("unsupported", "major two is unavailable").unwrap(),
        ),
    ] {
        let transport =
            DeterministicPlatformV2Transport::new([DeterministicPlatformV2Step::Negotiation(
                response,
            )]);
        let mut client = PlatformV2Client::new(transport);
        let result = client
            .negotiate(PlatformVersionOffer::new(vec![1, 2]).unwrap())
            .unwrap();
        assert!(matches!(
            result,
            NegotiationResult::Downgraded(_) | NegotiationResult::Refused(_)
        ));
        assert_eq!(
            client.get_work_context(project("project-a")),
            Err(ClientError::NotNegotiated)
        );
    }
}

struct ResponseBytes(Vec<u8>);
impl PlatformV2Transport for ResponseBytes {
    fn exchange(
        &mut self,
        _lane: PlatformV2Lane,
        _canonical_request: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        Ok(self.0.clone())
    }
}

#[test]
fn refuses_malformed_oversized_and_mismatched_negotiation_responses() {
    let mut malformed = PlatformV2Client::new(ResponseBytes(b"not-json".to_vec()));
    assert_eq!(
        malformed.negotiate(PlatformVersionOffer::new(vec![2]).unwrap()),
        Err(ClientError::Protocol)
    );
    let mut oversized = PlatformV2Client::new(ResponseBytes(vec![
        b'x';
        MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES
            + 1
    ]));
    assert_eq!(
        oversized.negotiate(PlatformVersionOffer::new(vec![2]).unwrap()),
        Err(ClientError::ResponseTooLarge)
    );

    let other = PlatformNegotiationRequestMessage::new(
        RequestId::new("other-request").unwrap(),
        PlatformNegotiationRequest::Negotiate(PlatformVersionOffer::new(vec![2]).unwrap()),
    );
    let bytes = PlatformNegotiationResponseMessage::for_request(
        &other,
        PlatformNegotiationResponse::Negotiated(
            NegotiatedPlatform::new(
                PlatformVersion::V2,
                PLATFORM_SCHEMA_V2,
                WorkContextAvailability::V2Structured,
            )
            .unwrap(),
        ),
    )
    .unwrap()
    .to_canonical_bytes()
    .unwrap();
    let mut client = PlatformV2Client::new(ResponseBytes(bytes));
    assert_eq!(
        client.negotiate(PlatformVersionOffer::new(vec![2]).unwrap()),
        Err(ClientError::Correlation)
    );
}

#[test]
fn rejects_a_valid_record_for_the_wrong_coordinate() {
    let transport = DeterministicPlatformV2Transport::new([
        DeterministicPlatformV2Step::Negotiation(PlatformNegotiationResponse::Negotiated(
            negotiated(PlatformVersion::V2),
        )),
        DeterministicPlatformV2Step::V2(Box::new(PlatformV2Response::WorkContextRecord(
            project_record("project-b"),
        ))),
    ]);
    let mut client = PlatformV2Client::new(transport);
    client
        .negotiate(PlatformVersionOffer::new(vec![2]).unwrap())
        .unwrap();
    assert_eq!(
        client.get_work_context(project("project-a")),
        Err(ClientError::Protocol)
    );
}
