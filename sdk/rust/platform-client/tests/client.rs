// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use automonique_platform_client::{
    ActionResult, BasicCredential, BearerToken, ClientError, ControlClaimResult, HttpsTransport,
    PLATFORM_CONTENT_TYPE, PlatformClient, PlatformTransport, PlatformView,
    SessionCommandStateResult, SessionHistoryResult, SessionListResult, SubscriptionApply,
    SubscriptionResult,
};
use automonique_protocol::codec::RequestId;
use automonique_protocol::platform::{
    ActionReceipt, Attachment, Capabilities, ClientId, CursorTopic, ExecuteRequest, IdempotencyKey,
    PlatformAction, PlatformCursor, PlatformEvent, PlatformParameter, PlatformRequest,
    PlatformResponse, PlatformText, ReceiptId, ReceiptOutcome, ResourceAuthority,
    ResourceCoordinate, ResourceId, ResourceKind, ResourceRecord, SessionCommandState,
    SessionFollowUpRequest, SessionHistoryEvent, SessionHistoryPage, SessionHistoryResync,
    SessionList, Snapshot, Subscription,
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
fn explicit_basic_https_transport_is_canonical_and_redacts_material() {
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
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("authorization: basic b3bzomzpehr1cmutcgfzc3dvcmq=\r\n")
        );
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .unwrap();
        while bytes.len() < header_end + content_length {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0);
            bytes.extend_from_slice(&chunk[..read]);
        }
        let request = PlatformRequestMessage::from_canonical_bytes(
            &bytes[header_end..header_end + content_length],
        )
        .unwrap();
        let response = PlatformResponseMessage::new(
            request.request_id().clone(),
            PlatformResponse::Capabilities(Capabilities::platform_v1()),
        )
        .to_message()
        .unwrap()
        .to_canonical_bytes();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: {PLATFORM_CONTENT_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        )
        .unwrap();
        stream.write_all(&response).unwrap();
    });

    let credential = BasicCredential::new("ops", "fixture-password").unwrap();
    assert_eq!(format!("{credential:?}"), "BasicCredential(<redacted>)");
    let transport = HttpsTransport::new_basic(format!("http://{address}/platform"), credential)
        .expect("loopback endpoint");
    let rendered = format!("{transport:?}");
    assert!(!rendered.contains("fixture-password"));
    assert!(!rendered.contains("b3Bz"));
    let mut client = PlatformClient::new(transport);
    assert!(client.capabilities().is_ok());
    server.join().unwrap();
}

#[test]
fn basic_credential_refuses_unbounded_or_ambiguous_usernames() {
    assert!(BasicCredential::new("", "password").is_err());
    assert!(BasicCredential::new("ops:admin", "password").is_err());
    assert!(BasicCredential::new("ops", "").is_err());
    assert!(BasicCredential::new("ops", "x".repeat(509)).is_err());
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

const LOSSLESS_CURSOR: u64 = 9_007_199_254_740_993;

struct RetainedSessionTransport {
    calls: usize,
    session: ResourceCoordinate,
    client: ClientId,
}

impl PlatformTransport for RetainedSessionTransport {
    fn request(
        &mut self,
        _request_id: RequestId,
        request: PlatformRequest,
    ) -> Result<PlatformResponse, ClientError> {
        let response = match self.calls {
            0 => {
                let PlatformRequest::Attach(request) = request else {
                    panic!("expected attach")
                };
                assert_eq!(request.session, self.session);
                assert_eq!(request.client, self.client);
                PlatformResponse::Attached(Attachment {
                    session: self.session.clone(),
                    client: self.client.clone(),
                    cursor: cursor("attachment:fixture", 7),
                })
            }
            1 => {
                let PlatformRequest::SessionHistorySnapshot(request) = request else {
                    panic!("expected history snapshot")
                };
                assert_eq!(request.session, self.session);
                assert_eq!(request.limit, 2);
                PlatformResponse::SessionHistory(
                    SessionHistoryPage::new(
                        self.session.clone(),
                        2,
                        2,
                        LOSSLESS_CURSOR,
                        LOSSLESS_CURSOR + 1,
                        false,
                        vec![SessionHistoryEvent::Unknown {
                            cursor: LOSSLESS_CURSOR + 1,
                            at: EpochMillis::from_millis(100),
                            source: automonique_protocol::platform::SessionHistoryUnknownSource::AdapterEvent,
                        }],
                    )
                    .expect("history page"),
                )
            }
            2 => {
                let PlatformRequest::SessionHistoryPage(request) = request else {
                    panic!("expected history page")
                };
                assert_eq!(request.session, self.session);
                assert_eq!(request.after, LOSSLESS_CURSOR + 1);
                assert_eq!(request.limit, 2);
                PlatformResponse::SessionHistoryResync(
                    SessionHistoryResync::new(
                        self.session.clone(),
                        LOSSLESS_CURSOR + 4,
                        LOSSLESS_CURSOR + 8,
                    )
                    .expect("history replacement"),
                )
            }
            3 => {
                let PlatformRequest::SessionCommandState(request) = request else {
                    panic!("expected command state")
                };
                assert_eq!(request.session, self.session);
                PlatformResponse::SessionCommandState(
                    SessionCommandState::new(
                        record(self.session.clone(), LOSSLESS_CURSOR + 10, "open"),
                        None,
                        Vec::new(),
                    )
                    .expect("command state"),
                )
            }
            4 => {
                let PlatformRequest::SessionFollowUp(request) = request else {
                    panic!("expected session follow-up")
                };
                assert_eq!(request.client, self.client);
                assert_eq!(request.session, self.session);
                assert_eq!(
                    request.expected_session_revision.get(),
                    LOSSLESS_CURSOR + 10
                );
                assert_eq!(request.idempotency_key.as_str(), "fixture-follow-up");
                assert_eq!(request.text.as_str(), "continue exactly once");
                PlatformResponse::Receipt(follow_up_receipt(
                    &self.session,
                    ReceiptOutcome::Accepted,
                    1,
                ))
            }
            5 => {
                let PlatformRequest::GetReceipt(request) = request else {
                    panic!("expected receipt reconciliation")
                };
                assert_eq!(request.client.as_ref(), Some(&self.client));
                assert!(request.id.is_none());
                assert_eq!(
                    request.idempotency_key.as_ref().map(IdempotencyKey::as_str),
                    Some("fixture-follow-up")
                );
                PlatformResponse::Receipt(follow_up_receipt(
                    &self.session,
                    ReceiptOutcome::Completed,
                    2,
                ))
            }
            6 => {
                let PlatformRequest::GetReceipt(request) = request else {
                    panic!("expected receipt-id reconciliation")
                };
                assert_eq!(request.client.as_ref(), Some(&self.client));
                assert_eq!(
                    request.id.as_ref().map(ReceiptId::as_str),
                    Some("fixture-follow-up-receipt")
                );
                assert!(request.idempotency_key.is_none());
                PlatformResponse::Receipt(follow_up_receipt(
                    &self.session,
                    ReceiptOutcome::Completed,
                    2,
                ))
            }
            _ => panic!("unexpected retained-session request"),
        };
        self.calls += 1;
        Ok(response)
    }
}

#[test]
fn retained_session_helpers_preserve_identity_lossless_revisions_and_independent_cursors() {
    let session = coordinate("fixture-session");
    let client_id = ClientId::new("fixture-client").expect("client");
    let mut client = PlatformClient::new(RetainedSessionTransport {
        calls: 0,
        session: session.clone(),
        client: client_id.clone(),
    });

    let attachment = client
        .attach(session.clone(), client_id.clone())
        .expect("attachment");
    assert_eq!(attachment.cursor.topic.as_str(), "attachment:fixture");
    assert_eq!(attachment.cursor.sequence.get(), 7);

    let SessionHistoryResult::Page(history) = client
        .session_history_snapshot(session.clone(), 2)
        .expect("history snapshot")
    else {
        panic!("expected retained history")
    };
    assert_eq!(history.from_cursor, LOSSLESS_CURSOR);
    assert_eq!(history.terminal_cursor, LOSSLESS_CURSOR + 1);
    assert!(matches!(
        history.events.as_slice(),
        [SessionHistoryEvent::Unknown { .. }]
    ));
    assert_ne!(attachment.cursor.sequence.get(), history.terminal_cursor);

    let SessionHistoryResult::ReplaceWithSnapshot(replacement) = client
        .session_history_page(session.clone(), history.terminal_cursor, 2)
        .expect("typed history gap")
    else {
        panic!("expected explicit snapshot replacement")
    };
    assert_eq!(replacement.snapshot_from, LOSSLESS_CURSOR + 4);
    assert_eq!(replacement.snapshot_to, LOSSLESS_CURSOR + 8);

    let state = client
        .session_command_state(session.clone())
        .expect("command state");
    assert_eq!(state.session.freshness.revision.get(), LOSSLESS_CURSOR + 10);
    let follow_up = SessionFollowUpRequest {
        client: client_id.clone(),
        session: session.clone(),
        expected_session_revision: state.session.freshness.revision,
        idempotency_key: IdempotencyKey::new("fixture-follow-up").expect("key"),
        text: PlatformParameter::new("continue exactly once").expect("text"),
    };
    let ActionResult::Receipt(admitted) = client
        .session_follow_up_outcome(follow_up)
        .expect("follow-up outcome")
    else {
        panic!("expected admitted follow-up")
    };
    assert_eq!(admitted.outcome, ReceiptOutcome::Accepted);

    let settled = client
        .reconcile_receipt_by_idempotency_key(
            client_id.clone(),
            IdempotencyKey::new("fixture-follow-up").expect("key"),
            PlatformAction::FollowUp,
            session.clone(),
        )
        .expect("settled receipt");
    assert_eq!(settled.outcome, ReceiptOutcome::Completed);
    assert_eq!(
        client
            .reconcile_receipt_by_id(
                client_id,
                settled.id.clone(),
                PlatformAction::FollowUp,
                session,
            )
            .expect("receipt-id reconciliation"),
        settled
    );
    assert_eq!(client.transport().calls, 7);
}

struct AmbiguousFollowUpTransport {
    calls: usize,
    session: ResourceCoordinate,
    client: ClientId,
}

impl PlatformTransport for AmbiguousFollowUpTransport {
    fn request(
        &mut self,
        _request_id: RequestId,
        request: PlatformRequest,
    ) -> Result<PlatformResponse, ClientError> {
        self.calls += 1;
        match request {
            PlatformRequest::SessionFollowUp(request) if self.calls == 1 => {
                assert_eq!(request.session, self.session);
                assert_eq!(request.client, self.client);
                Err(ClientError::Io)
            }
            PlatformRequest::GetReceipt(request) if self.calls == 2 => {
                assert_eq!(request.client.as_ref(), Some(&self.client));
                assert_eq!(
                    request.idempotency_key.as_ref().map(IdempotencyKey::as_str),
                    Some("ambiguous-follow-up")
                );
                Ok(PlatformResponse::Receipt(follow_up_receipt(
                    &self.session,
                    ReceiptOutcome::Completed,
                    3,
                )))
            }
            _ => panic!("follow-up was replayed or reconciliation was malformed"),
        }
    }
}

#[test]
fn ambiguous_follow_up_reconciles_by_client_and_key_without_replay() {
    let session = coordinate("ambiguous-session");
    let client_id = ClientId::new("ambiguous-client").expect("client");
    let mut client = PlatformClient::new(AmbiguousFollowUpTransport {
        calls: 0,
        session: session.clone(),
        client: client_id.clone(),
    });
    let request = SessionFollowUpRequest {
        client: client_id.clone(),
        session: session.clone(),
        expected_session_revision: revision(4),
        idempotency_key: IdempotencyKey::new("ambiguous-follow-up").expect("key"),
        text: PlatformParameter::new("continue once").expect("text"),
    };
    assert_eq!(
        client.session_follow_up_outcome(request),
        Err(ClientError::Io)
    );

    let receipt = client
        .reconcile_receipt_by_idempotency_key(
            client_id,
            IdempotencyKey::new("ambiguous-follow-up").expect("key"),
            PlatformAction::FollowUp,
            session,
        )
        .expect("reconciled receipt");
    assert_eq!(receipt.outcome, ReceiptOutcome::Completed);
    assert_eq!(client.transport().calls, 2);
}

struct SessionRefusalTransport;

impl PlatformTransport for SessionRefusalTransport {
    fn request(
        &mut self,
        _request_id: RequestId,
        request: PlatformRequest,
    ) -> Result<PlatformResponse, ClientError> {
        match request {
            PlatformRequest::SessionCommandState(_) => Ok(PlatformResponse::Refused {
                outcome: ReceiptOutcome::Rejected,
                explanation: text("session unavailable"),
            }),
            PlatformRequest::SessionFollowUp(_) => Ok(PlatformResponse::Refused {
                outcome: ReceiptOutcome::Conflict,
                explanation: text("stale revision"),
            }),
            _ => panic!("unexpected refusal request"),
        }
    }
}

#[test]
fn retained_session_helpers_keep_command_and_stale_revision_refusals_typed() {
    let session = coordinate("stale-session");
    let client_id = ClientId::new("stale-client").expect("client");
    let mut client = PlatformClient::new(SessionRefusalTransport);
    assert_eq!(
        client
            .session_command_state_outcome(session.clone())
            .expect("command refusal"),
        SessionCommandStateResult::Refused {
            outcome: ReceiptOutcome::Rejected,
            explanation: text("session unavailable")
        }
    );
    assert_eq!(
        client
            .session_follow_up_outcome(SessionFollowUpRequest {
                client: client_id,
                session,
                expected_session_revision: revision(1),
                idempotency_key: IdempotencyKey::new("stale-follow-up").expect("key"),
                text: PlatformParameter::new("continue").expect("text"),
            })
            .expect("follow-up refusal"),
        ActionResult::Refused {
            outcome: ReceiptOutcome::Conflict,
            explanation: text("stale revision")
        }
    );
}

struct MismatchedSessionTransport {
    calls: usize,
}

impl PlatformTransport for MismatchedSessionTransport {
    fn request(
        &mut self,
        _request_id: RequestId,
        request: PlatformRequest,
    ) -> Result<PlatformResponse, ClientError> {
        let response = match (self.calls, request) {
            (0, PlatformRequest::SessionCommandState(_)) => PlatformResponse::SessionCommandState(
                SessionCommandState::new(
                    record(coordinate("wrong-session"), 1, "open"),
                    None,
                    Vec::new(),
                )
                .expect("wrong command state"),
            ),
            (1, PlatformRequest::SessionFollowUp(_)) => PlatformResponse::Receipt(
                follow_up_receipt(&coordinate("wrong-session"), ReceiptOutcome::Completed, 1),
            ),
            (2, PlatformRequest::GetReceipt(_)) => PlatformResponse::Receipt(ActionReceipt {
                action: PlatformAction::StopRun,
                ..follow_up_receipt(
                    &coordinate("expected-session"),
                    ReceiptOutcome::Completed,
                    2,
                )
            }),
            _ => panic!("unexpected mismatch request"),
        };
        self.calls += 1;
        Ok(response)
    }
}

#[test]
fn retained_session_helpers_reject_mismatched_state_and_receipt_bindings() {
    let session = coordinate("expected-session");
    let client_id = ClientId::new("expected-client").expect("client");
    let mut client = PlatformClient::new(MismatchedSessionTransport { calls: 0 });
    assert_eq!(
        client.session_command_state(session.clone()),
        Err(ClientError::Protocol)
    );
    assert_eq!(
        client.session_follow_up_outcome(SessionFollowUpRequest {
            client: client_id.clone(),
            session: session.clone(),
            expected_session_revision: revision(1),
            idempotency_key: IdempotencyKey::new("mismatched-follow-up").expect("key"),
            text: PlatformParameter::new("continue").expect("text"),
        }),
        Err(ClientError::Protocol)
    );
    assert_eq!(
        client.reconcile_receipt_by_idempotency_key(
            client_id,
            IdempotencyKey::new("mismatched-follow-up").expect("key"),
            PlatformAction::FollowUp,
            session,
        ),
        Err(ClientError::Protocol)
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
    view.track_attachment(&attachment_a);
    assert_eq!(
        view.attachment_cursor(&attachment_a)
            .expect("stale registration cannot rewind the cursor")
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

fn follow_up_receipt(
    session: &ResourceCoordinate,
    outcome: ReceiptOutcome,
    revision_value: u64,
) -> ActionReceipt {
    ActionReceipt {
        id: ReceiptId::new("fixture-follow-up-receipt").expect("receipt id"),
        action: PlatformAction::FollowUp,
        target: session.clone(),
        outcome,
        revision: revision(revision_value),
        recorded_at: EpochMillis::from_millis(i64::from(revision_value as u32)),
        explanation: None,
    }
}
