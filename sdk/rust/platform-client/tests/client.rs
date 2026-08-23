// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use automonique_platform_client::{
    ActionResult, BearerToken, ClientError, ControlClaimResult, HttpsTransport,
    PLATFORM_CONTENT_TYPE, PlatformClient, PlatformTransport, PlatformView, SessionListResult,
    SubscriptionApply, SubscriptionResult,
};
use automonique_protocol::codec::RequestId;
use automonique_protocol::platform::{
    ActionReceipt, Attachment, Capabilities, ClientId, CursorTopic, ExecuteRequest, IdempotencyKey,
    PlatformAction, PlatformCursor, PlatformEvent, PlatformRequest, PlatformResponse, PlatformText,
    ReceiptId, ReceiptOutcome, ResourceAuthority, ResourceCoordinate, ResourceId, ResourceKind,
    ResourceRecord, SessionList, Snapshot, Subscription,
};
use automonique_protocol::platform_api::{PlatformRequestMessage, PlatformResponseMessage};
use automonique_protocol::primitives::{EpochMillis, Revision};

struct FakeTransport {
    calls: usize,
}

impl PlatformTransport for FakeTransport {
    fn request(
        &mut self,
        request_id: RequestId,
        request: PlatformRequest,
    ) -> Result<PlatformResponse, ClientError> {
        assert_eq!(
            request_id.as_str(),
            format!("platform-client-{}", self.calls + 1)
        );
        self.calls += 1;
        assert!(matches!(request, PlatformRequest::Capabilities));
        Ok(PlatformResponse::Capabilities(Capabilities::platform_v1()))
    }
}

#[test]
fn facade_correlates_semantic_calls_without_transport_specific_models() {
    let mut client = PlatformClient::new(FakeTransport { calls: 0 });
    let capabilities = client.capabilities().expect("capabilities");
    assert_eq!(capabilities, Capabilities::platform_v1());
    assert_eq!(client.transport().calls, 1);
}

#[test]
fn https_transport_carries_the_canonical_frame_and_redacts_the_bearer() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("client connection");
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut chunk).expect("request bytes");
            assert!(read > 0, "request ended before headers");
            bytes.extend_from_slice(&chunk[..read]);
            if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = std::str::from_utf8(&bytes[..header_end]).expect("request headers");
        assert!(headers.starts_with("POST /platform HTTP/1.1\r\n"));
        assert!(
            headers
                .to_ascii_lowercase()
                .contains(&format!("content-type: {PLATFORM_CONTENT_TYPE}\r\n"))
        );
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("authorization: bearer fixture-token\r\n")
        );
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .expect("content length");
        while bytes.len() < header_end + content_length {
            let read = stream.read(&mut chunk).expect("request body");
            assert!(read > 0, "request ended before body");
            bytes.extend_from_slice(&chunk[..read]);
        }
        let request = PlatformRequestMessage::from_canonical_bytes(
            &bytes[header_end..header_end + content_length],
        )
        .expect("canonical platform request");
        assert!(matches!(request.request(), PlatformRequest::Capabilities));
        let response = PlatformResponseMessage::new(
            request.request_id().clone(),
            PlatformResponse::Capabilities(Capabilities::platform_v1()),
        )
        .to_message()
        .expect("response frame")
        .to_canonical_bytes();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: {PLATFORM_CONTENT_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        )
        .expect("response headers");
        stream.write_all(&response).expect("response body");
    });

    let token = BearerToken::new("fixture-token").expect("bounded token");
    let transport = HttpsTransport::new(format!("http://{address}/platform"), token)
        .expect("loopback endpoint");
    assert!(!format!("{transport:?}").contains("fixture-token"));
    let mut client = PlatformClient::new(transport);
    assert_eq!(
        client.capabilities().expect("remote capabilities"),
        Capabilities::platform_v1()
    );
    server.join().expect("server thread");
}

#[test]
fn https_transport_refuses_cleartext_remote_and_embedded_credentials() {
    let token = || BearerToken::new("fixture-token").expect("token");
    assert!(matches!(
        HttpsTransport::new("http://example.com/platform", token()),
        Err(ClientError::Endpoint)
    ));
    assert!(matches!(
        HttpsTransport::new("https://user@example.com/platform", token()),
        Err(ClientError::Endpoint)
    ));
    assert!(BearerToken::new("contains space").is_err());
}

#[test]
fn https_transport_preserves_http_authorization_refusals() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("client connection");
        let mut bytes = [0_u8; 4096];
        let _ = stream.read(&mut bytes).expect("request bytes");
        stream
            .write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .expect("refusal response");
    });

    let token = BearerToken::new("rejected-token").expect("bounded token");
    let transport = HttpsTransport::new(format!("http://{address}/platform"), token)
        .expect("loopback endpoint");
    let mut client = PlatformClient::new(transport);
    assert_eq!(client.capabilities(), Err(ClientError::Unauthorized));
    server.join().expect("server thread");
}

struct ResyncTransport;

impl PlatformTransport for ResyncTransport {
    fn request(
        &mut self,
        _request_id: RequestId,
        request: PlatformRequest,
    ) -> Result<PlatformResponse, ClientError> {
        assert!(matches!(request, PlatformRequest::Subscribe(_)));
        Ok(PlatformResponse::Refused {
            outcome: ReceiptOutcome::ResyncRequired,
            explanation: text("cursor expired"),
        })
    }
}

#[test]
fn recoverable_subscription_preserves_resnapshot_outcome() {
    let mut client = PlatformClient::new(ResyncTransport);
    assert_eq!(
        client
            .subscribe_recoverable(Some(cursor("session:a", 4)))
            .expect("typed response"),
        SubscriptionResult::ResyncRequired {
            explanation: text("cursor expired")
        }
    );
}

struct TypedRefusalTransport;

impl PlatformTransport for TypedRefusalTransport {
    fn request(
        &mut self,
        _request_id: RequestId,
        request: PlatformRequest,
    ) -> Result<PlatformResponse, ClientError> {
        match request {
            PlatformRequest::ListSessions(_) => Ok(PlatformResponse::Refused {
                outcome: ReceiptOutcome::ResyncRequired,
                explanation: text("directory cursor expired"),
            }),
            PlatformRequest::Execute(_) => Ok(PlatformResponse::Refused {
                outcome: ReceiptOutcome::Conflict,
                explanation: text("revision changed"),
            }),
            PlatformRequest::ClaimControl(_) => Ok(PlatformResponse::Refused {
                outcome: ReceiptOutcome::Conflict,
                explanation: text("controller held"),
            }),
            _ => panic!("unexpected request"),
        }
    }
}

#[test]
fn session_refresh_and_mutation_keep_typed_refusals() {
    let mut client = PlatformClient::new(TypedRefusalTransport);
    assert_eq!(
        client
            .list_sessions_recoverable(ResourceAuthority::Automonique, Some(cursor("sessions", 9)),)
            .expect("typed session response"),
        SessionListResult::ResyncRequired {
            explanation: text("directory cursor expired")
        }
    );
    let run = ResourceCoordinate::new(
        ResourceAuthority::Automonique,
        ResourceKind::Run,
        ResourceId::new("run-1").expect("run id"),
    );
    let request = ExecuteRequest::new(
        PlatformAction::StopRun,
        run,
        IdempotencyKey::new("stop-run-1").expect("idempotency key"),
        Some(revision(4)),
        None,
    )
    .expect("execute request");
    assert_eq!(
        client
            .execute_outcome(request)
            .expect("typed action response"),
        ActionResult::Refused {
            outcome: ReceiptOutcome::Conflict,
            explanation: text("revision changed")
        }
    );
    assert_eq!(
        client
            .claim_control_outcome(
                coordinate("session-controlled"),
                ClientId::new("shelldeck-test").expect("client"),
                IdempotencyKey::new("claim-control-1").expect("idempotency key"),
            )
            .expect("typed control response"),
        ControlClaimResult::Refused {
            outcome: ReceiptOutcome::Conflict,
            explanation: text("controller held")
        }
    );
}

#[test]
fn platform_view_tracks_independent_attachments_and_reconciles_receipts() {
    let session_a = coordinate("session-a");
    let session_b = coordinate("session-b");
    let mut view = PlatformView::default();
    view.apply_snapshot(Snapshot {
        resources: vec![record(session_a.clone(), 1, "waiting")],
        cursor: cursor("platform", 7),
    });
    view.apply_session_list(&SessionList {
        sessions: Vec::new(),
        cursor: cursor("sessions", 5),
    });
    assert_eq!(
        view.cursor(&cursor("sessions", 1))
            .expect("directory cursor")
            .sequence,
        revision(5)
    );

    let attachment_a = attachment(session_a.clone(), "sessions", 10);
    let attachment_b = attachment(session_b, "sessions", 20);
    view.track_attachment(&attachment_a);
    view.track_attachment(&attachment_b);

    let running = record(session_a.clone(), 2, "running");
    let update = Subscription {
        events: vec![PlatformEvent {
            cursor: cursor("sessions", 11),
            resource: running.clone(),
        }],
        cursor: cursor("sessions", 11),
    };
    assert_eq!(
        view.apply_attachment_subscription(&attachment_a, update.clone()),
        SubscriptionApply::Applied { events: 1 }
    );
    assert_eq!(
        view.apply_attachment_subscription(&attachment_a, update),
        SubscriptionApply::Applied { events: 0 }
    );
    assert_eq!(view.resource(&session_a), Some(&running));
    assert_eq!(view.resources().len(), 1);
    assert_eq!(
        view.attachment_cursor(&attachment_a)
            .expect("attachment cursor")
            .sequence,
        revision(11)
    );
    assert_eq!(
        view.attachment_cursor(&attachment_b)
            .expect("independent cursor")
            .sequence,
        revision(20)
    );
    assert_eq!(
        view.apply_attachment_subscription(
            &attachment_b,
            Subscription {
                events: vec![PlatformEvent {
                    cursor: cursor("sessions", 21),
                    resource: running.clone(),
                }],
                cursor: cursor("sessions", 21),
            },
        ),
        SubscriptionApply::Applied { events: 1 }
    );
    assert_eq!(
        view.attachment_cursor(&attachment_a)
            .expect("first attachment remains independent")
            .sequence,
        revision(11)
    );
    assert_eq!(
        view.attachment_cursor(&attachment_b)
            .expect("second attachment advances")
            .sequence,
        revision(21)
    );

    let receipt = ActionReceipt {
        id: ReceiptId::new("receipt-1").expect("receipt id"),
        action: PlatformAction::StopRun,
        target: session_a,
        outcome: ReceiptOutcome::Completed,
        revision: revision(3),
        recorded_at: EpochMillis::from_millis(100),
        explanation: Some(text("stopped")),
    };
    view.apply_receipt(receipt.clone());
    assert_eq!(view.receipt(&receipt.id), Some(&receipt));
    assert_eq!(view.receipts().len(), 1);

    view.forget_attachment(&attachment_a);
    assert!(view.attachment_cursor(&attachment_a).is_none());
    assert!(view.attachment_cursor(&attachment_b).is_some());
}

#[test]
fn platform_view_refuses_gaps_without_mutating_the_projection() {
    let session = coordinate("session-gap");
    let attachment = attachment(session.clone(), "session:gap", 5);
    let initial = record(session.clone(), 1, "waiting");
    let mut view = PlatformView::default();
    view.apply_snapshot(Snapshot {
        resources: vec![initial.clone()],
        cursor: cursor("platform", 1),
    });
    view.track_attachment(&attachment);

    assert_eq!(
        view.apply_attachment_subscription(
            &attachment,
            Subscription {
                events: vec![PlatformEvent {
                    cursor: cursor("session:gap", 7),
                    resource: record(session.clone(), 2, "running"),
                }],
                cursor: cursor("session:gap", 7),
            }
        ),
        SubscriptionApply::ResyncRequired
    );
    assert_eq!(view.resource(&session), Some(&initial));
    assert!(view.attachment_needs_resync(&attachment));
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("non-zero revision")
}

fn text(value: &str) -> PlatformText {
    PlatformText::new(value).expect("bounded text")
}

fn cursor(topic: &str, sequence: u64) -> PlatformCursor {
    PlatformCursor {
        authority: ResourceAuthority::Automonique,
        topic: CursorTopic::new(topic).expect("cursor topic"),
        sequence: revision(sequence),
    }
}

fn coordinate(id: &str) -> ResourceCoordinate {
    ResourceCoordinate::new(
        ResourceAuthority::Automonique,
        ResourceKind::Session,
        ResourceId::new(id).expect("resource id"),
    )
}

fn record(resource: ResourceCoordinate, revision_value: u64, summary: &str) -> ResourceRecord {
    ResourceRecord {
        resource,
        freshness: automonique_protocol::platform::Freshness {
            state: automonique_protocol::platform::FreshnessState::Fresh,
            observed_at: EpochMillis::from_millis(i64::from(revision_value as u32)),
            revision: revision(revision_value),
        },
        summary: text(summary),
    }
}

fn attachment(session: ResourceCoordinate, topic: &str, sequence: u64) -> Attachment {
    Attachment {
        session,
        client: ClientId::new("shelldeck-test").expect("client id"),
        cursor: cursor(topic, sequence),
    }
}
