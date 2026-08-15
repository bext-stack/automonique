// SPDX-License-Identifier: Elastic-2.0

//! End-to-end proofs for the fleet client, against a fake support API on
//! loopback.
//!
//! Nothing here touches an external network. Every destination is a
//! `TcpListener` this test owns and binds on `127.0.0.1:0`, so a run is
//! hermetic, no fleet credential is real, and a failure is the connector's
//! rather than the internet's. The production origin never appears as a base:
//! every client is built from the plaintext-loopback shape, and
//! [`fleet_client`] asserts that before returning.
//!
//! Every socket carries a five-second read and write deadline, and the client
//! under test is given a one-second budget, so a stuck peer fails an assertion
//! instead of hanging the suite.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use automonique_support_connector::{
    FleetBase, FleetClient, FleetFailure, FleetInstanceId, FleetOutcome, FleetRequest, FleetToken,
    MAX_FLEET_RESPONSE_BYTES, MAX_SUPPORT_ISSUES, ServerMessage, SupportDelivery,
    SupportEmailRequest, SupportIssuesRequest, SupportReplyRequest, SupportScope,
    SupportThreadNoteRequest, SupportThreadResolveRequest, TicketDecision, TicketDecisionOutcome,
    TicketDecisionReceipt, TicketDecisionRequest, TicketJobStatus,
};

/// Bound on every server-side wait. A test that would otherwise hang fails here.
const SERVER_TIMEOUT: Duration = Duration::from_secs(5);
/// Budget the client under test is given, so a deadline assertion is quick.
const CLIENT_BUDGET: Duration = Duration::from_secs(1);
/// Largest request head the fake will buffer before giving up.
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// The fixture credential. It is not a real token and addresses nothing: the
/// only server that ever sees it is the one in this file.
const TOKEN: &str = "sd_fixture-secret-never-print";
const INSTANCE: &str = "sd-instance-01";
const MESSAGE_ID: &str = "a1b2c3d4-e5f6-7890-abcd-ef0123456789";
const THREAD_ID: &str = "0123456789abcdef";

/// One request the fake observed, recorded verbatim.
#[derive(Clone, Debug)]
struct Captured {
    request_line: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// What the fake answers with.
#[derive(Clone)]
enum Canned {
    /// A 200 with `application/json` and this body.
    Json(String),
    /// An exact status, content type and body.
    Exact {
        status: u16,
        content_type: &'static str,
        body: Vec<u8>,
    },
    /// Accept the connection and never answer, so the client's deadline is the
    /// only thing that can end the call.
    Silent,
}

impl Canned {
    fn json(body: &str) -> Self {
        Self::Json(body.to_owned())
    }
}

/// A fake support fleet on loopback that records what it was asked.
struct FakeFleet {
    address: SocketAddr,
    captured: Arc<Mutex<Vec<Captured>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeFleet {
    /// Answer each successive request with the next canned response, reusing
    /// the last one once the script is exhausted.
    fn spawn(script: Vec<Canned>) -> Self {
        assert!(!script.is_empty(), "a fake needs at least one response");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake fleet");
        let address = listener.local_addr().expect("fake fleet address");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");

        let captured = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let captured = Arc::clone(&captured);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let mut served = 0_usize;
                let mut held = Vec::new();
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((socket, _)) => {
                            socket.set_nonblocking(false).expect("blocking socket");
                            socket
                                .set_read_timeout(Some(SERVER_TIMEOUT))
                                .expect("server read deadline");
                            socket
                                .set_write_timeout(Some(SERVER_TIMEOUT))
                                .expect("server write deadline");
                            let canned = script[served.min(script.len() - 1)].clone();
                            served += 1;
                            // A silent connection is held rather than
                            // dropped: dropping would close it, which is not
                            // what "silent" means.
                            if let Some(socket) = serve(socket, &canned, &captured) {
                                held.push(socket);
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Self {
            address,
            captured,
            stop,
            thread: Some(thread),
        }
    }

    fn port(&self) -> u16 {
        self.address.port()
    }

    fn captured(&self) -> Vec<Captured> {
        self.captured.lock().expect("captured lock").clone()
    }

    /// The single request this fake was asked, failing the test if it saw a
    /// different number.
    fn only_request(&self) -> Captured {
        let captured = self.captured();
        assert_eq!(captured.len(), 1, "expected exactly one request");
        captured.into_iter().next().expect("one request")
    }
}

impl Drop for FakeFleet {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Read one request, record it, and write the canned answer.
///
/// Returns the socket when the canned behaviour is to stay silent, so the
/// caller can hold it open.
fn serve(
    mut socket: TcpStream,
    canned: &Canned,
    captured: &Arc<Mutex<Vec<Captured>>>,
) -> Option<TcpStream> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match socket.read(&mut byte) {
            Ok(0) => return None,
            Ok(_) => head.push(byte[0]),
            Err(_) => return None,
        }
        if head.len() > MAX_HEAD_BYTES {
            return None;
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    let length: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0_u8; length];
    if length > 0 && socket.read_exact(&mut body).is_err() {
        return None;
    }
    captured.lock().expect("captured lock").push(Captured {
        request_line,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    });

    let (status, content_type, payload) = match canned {
        Canned::Json(body) => (200_u16, "application/json", body.clone().into_bytes()),
        Canned::Exact {
            status,
            content_type,
            body,
        } => (*status, *content_type, body.clone()),
        Canned::Silent => return Some(socket),
    };
    let mut response = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        payload.len()
    )
    .into_bytes();
    response.extend_from_slice(&payload);
    let _ = socket.write_all(&response);
    let _ = socket.flush();
    None
}

/// A client pointed at the fake, proven to be loopback-only before it is used.
fn fleet_client(fake: &FakeFleet) -> FleetClient {
    let base = FleetBase::new(&format!("http://127.0.0.1:{}", fake.port())).expect("loopback base");
    assert!(
        base.is_plaintext_loopback(),
        "every hermetic client must be loopback-only"
    );
    FleetClient::with_request_timeout(
        base,
        FleetInstanceId::new(INSTANCE).expect("instance"),
        FleetToken::new(TOKEN.as_bytes().to_vec()).expect("token"),
        CLIENT_BUDGET,
    )
}

/// One complete support issue row, carrying every field the contract names.
fn issue_row() -> String {
    String::from(
        r#"{"id":"iss-1","title":"Panne de paiement","tenant_name":"Boulangerie Milo",
           "site_label":"milo.invalid","status":"triaging","priority":"high","source":"email",
           "requested_by":"Claire","comment_count":3,
           "created_at":"2026-08-10T09:12:00.000Z","updated_at":"2026-08-13T17:04:11.000Z"}"#,
    )
}

fn issues_page() -> String {
    format!(
        r#"{{"ok":true,"scope":"staff","issues":[{}]}}"#,
        issue_row()
    )
}

/// Every request must be the one POST this connector is allowed to make.
fn assert_wire_shape(captured: &Captured, expected_action: &str) {
    assert_eq!(
        captured.request_line, "POST /api/manage/shelldeck/fleet HTTP/1.1",
        "the connector must address exactly one path with exactly one verb"
    );
    assert_eq!(
        captured.header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str()),
        "the bearer header must reach the wire exactly once, exactly as configured"
    );
    assert_eq!(captured.header("content-type"), Some("application/json"));
    assert_eq!(captured.header("accept"), Some("application/json"));

    let body: serde_json::Value = serde_json::from_str(&captured.body).expect("body is JSON");
    assert_eq!(
        body["action"], expected_action,
        "the envelope must name the action the caller asked for"
    );
    assert_eq!(body["id"], INSTANCE, "every action carries the instance id");
}

#[test]
fn the_support_issues_action_sends_its_envelope_and_parses_every_field_back() {
    let fake = FakeFleet::spawn(vec![Canned::json(&issues_page())]);
    let client = fleet_client(&fake);

    let outcome = client
        .support_issues(&SupportIssuesRequest::new(10).expect("limit"))
        .expect("call");

    let captured = fake.only_request();
    assert_wire_shape(&captured, "support-issues");
    assert_eq!(
        captured.body,
        r#"{"action":"support-issues","id":"sd-instance-01","limit":10}"#
    );

    let page = outcome.accepted().expect("accepted page");
    assert_eq!(page.scope, SupportScope::Staff);
    assert_eq!(page.issues.len(), 1);
    let issue = &page.issues[0];
    assert_eq!(issue.id, "iss-1");
    assert_eq!(issue.title, "Panne de paiement");
    assert_eq!(issue.tenant_name, "Boulangerie Milo");
    assert_eq!(issue.site_label.as_deref(), Some("milo.invalid"));
    assert_eq!(issue.status, "triaging");
    assert_eq!(issue.priority, "high");
    assert_eq!(issue.source, "email");
    assert_eq!(issue.requested_by, "Claire");
    assert_eq!(issue.comment_count, 3);
    assert_eq!(issue.created_at, "2026-08-10T09:12:00.000Z");
    assert_eq!(issue.updated_at, "2026-08-13T17:04:11.000Z");
}

#[test]
fn the_thread_resolve_action_sends_its_envelope_and_parses_the_thread_back() {
    let fake = FakeFleet::spawn(vec![Canned::json(
        r#"{"ok":true,"thread":{"id":"0123456789ab","channel":"email","status":"open",
            "subject":"Facture en double","contact_email":"claire@exemple.invalid"}}"#,
    )]);
    let client = fleet_client(&fake);

    let outcome = client
        .resolve_thread(&SupportThreadResolveRequest::new(MESSAGE_ID).expect("resolve"))
        .expect("call");

    let captured = fake.only_request();
    assert_wire_shape(&captured, "support-thread-resolve");
    assert_eq!(
        captured.body,
        format!(
            r#"{{"action":"support-thread-resolve","id":"sd-instance-01","message_id":"{MESSAGE_ID}"}}"#
        )
    );

    let thread = outcome.accepted().expect("accepted thread");
    assert_eq!(thread.id, "0123456789ab");
    assert_eq!(thread.channel, "email");
    assert_eq!(thread.status, "open");
    assert_eq!(thread.subject, "Facture en double");
    assert_eq!(thread.contact_email, "claire@exemple.invalid");
}

#[test]
fn the_thread_note_action_sends_its_envelope_and_reads_the_bare_acceptance() {
    let fake = FakeFleet::spawn(vec![Canned::json(r#"{"ok":true}"#)]);
    let client = fleet_client(&fake);

    let outcome = client
        .add_thread_note(
            &SupportThreadNoteRequest::new(THREAD_ID, "  vu avec l'equipe  ").expect("note"),
        )
        .expect("call");

    let captured = fake.only_request();
    assert_wire_shape(&captured, "support-thread-note");
    assert_eq!(
        captured.body,
        format!(
            r#"{{"action":"support-thread-note","id":"sd-instance-01","thread_id":"{THREAD_ID}","text":"vu avec l'equipe"}}"#
        )
    );
    assert_eq!(outcome, FleetOutcome::Accepted(()));
}

#[test]
fn the_thread_reply_action_sends_its_envelope_and_treats_ok_as_queued() {
    let fake = FakeFleet::spawn(vec![Canned::json(r#"{"ok":true}"#)]);
    let client = fleet_client(&fake);

    let request =
        SupportReplyRequest::new("act-77", THREAD_ID, "Bonjour,\nc'est regle.").expect("reply");
    let outcome = client.reply_thread(&request).expect("call");

    let captured = fake.only_request();
    assert_wire_shape(&captured, "support-thread-reply");
    assert_eq!(
        captured.body,
        format!(
            "{{\"action\":\"support-thread-reply\",\"id\":\"sd-instance-01\",\
             \"action_id\":\"act-77\",\"thread_id\":\"{THREAD_ID}\",\
             \"text\":\"Bonjour,\\nc'est regle.\"}}"
        )
    );
    assert_eq!(
        outcome,
        FleetOutcome::Accepted(SupportDelivery {
            queued: true,
            duplicate: false
        })
    );
}

#[test]
fn the_email_action_sends_its_envelope_and_carries_the_duplicate_signal() {
    let fake = FakeFleet::spawn(vec![Canned::json(
        r#"{"ok":true,"queued":true,"duplicate":true}"#,
    )]);
    let client = fleet_client(&fake);

    let request = SupportEmailRequest::new(
        "act-88",
        "claire@exemple.invalid",
        "Votre demande",
        "Bonjour, c'est regle.",
    )
    .expect("email");
    let outcome = client.send_email(&request).expect("call");

    let captured = fake.only_request();
    assert_wire_shape(&captured, "support-email");
    assert_eq!(
        captured.body,
        "{\"action\":\"support-email\",\"id\":\"sd-instance-01\",\"action_id\":\"act-88\",\
         \"to\":\"claire@exemple.invalid\",\"subject\":\"Votre demande\",\
         \"text\":\"Bonjour, c'est regle.\"}"
    );
    assert_eq!(
        outcome,
        FleetOutcome::Accepted(SupportDelivery {
            queued: true,
            duplicate: true
        }),
        "a retried confirmed action must report duplicate rather than send twice"
    );
}

#[test]
fn the_credential_reaches_the_wire_and_nothing_else() {
    let fake = FakeFleet::spawn(vec![Canned::json(&issues_page())]);
    let client = fleet_client(&fake);
    let request = FleetRequest::SupportEmail(
        SupportEmailRequest::new("act-1", "claire@exemple.invalid", "Sujet", "Corps")
            .expect("email"),
    );

    client
        .support_issues(&SupportIssuesRequest::new(1).expect("limit"))
        .expect("call");

    // Everything a host could observe or log about this client.
    let rendered = format!(
        "{client:?}|{}|{}|{:?}|{}|{:?}|{}",
        client.endpoint(),
        client.canonical_body(&request),
        FleetFailure::Unauthorized,
        FleetFailure::Unauthorized,
        client.base(),
        client.instance().as_str()
    );
    assert!(!rendered.contains(TOKEN), "rendered: {rendered}");
    assert!(!rendered.contains("sd_fixture"), "rendered: {rendered}");
    assert!(rendered.contains("<redacted>"));

    // The one place it legitimately appears is the header the fake received,
    // and it appears there exactly once.
    let captured = fake.only_request();
    assert_eq!(
        captured.header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    assert!(
        !captured.body.contains(TOKEN),
        "the credential must never ride in a body"
    );
    assert!(
        !captured.request_line.contains(TOKEN),
        "the credential must never ride in a path"
    );
    assert_eq!(
        captured
            .headers
            .iter()
            .filter(|(_, value)| value.contains(TOKEN))
            .count(),
        1,
        "exactly one header carries the credential"
    );
}

#[test]
fn a_malformed_response_is_a_typed_refusal_rather_than_a_panic() {
    let cases: [(&str, FleetFailure); 6] = [
        (
            r#"{"ok":true,"scope":"staff","issues":["#,
            FleetFailure::InvalidResponse,
        ),
        ("<html>maintenance</html>", FleetFailure::InvalidResponse),
        (
            r#"{"scope":"staff","issues":[]}"#,
            FleetFailure::MissingField,
        ),
        (
            r#"{"ok":true,"scope":"admin","issues":[]}"#,
            FleetFailure::FieldOutOfBounds,
        ),
        (
            r#"{"ok":true,"ok":false,"scope":"staff","issues":[]}"#,
            FleetFailure::InvalidResponse,
        ),
        (r#"{"ok":true,"scope":"staff"}"#, FleetFailure::MissingField),
    ];
    for (body, expected) in cases {
        let fake = FakeFleet::spawn(vec![Canned::json(body)]);
        let client = fleet_client(&fake);
        assert_eq!(
            client.support_issues(&SupportIssuesRequest::new(1).expect("limit")),
            Err(expected),
            "body {body:?}"
        );
    }
}

#[test]
fn a_response_missing_a_contract_field_is_refused_rather_than_shortened() {
    for key in [
        "id",
        "title",
        "tenant_name",
        "status",
        "priority",
        "source",
        "requested_by",
        "comment_count",
        "created_at",
        "updated_at",
    ] {
        let mut row: serde_json::Value = serde_json::from_str(&issue_row()).expect("row");
        row.as_object_mut().expect("object").remove(key);
        let page = format!(r#"{{"ok":true,"scope":"staff","issues":[{row}]}}"#);

        let fake = FakeFleet::spawn(vec![Canned::json(&page)]);
        let client = fleet_client(&fake);
        assert_eq!(
            client.support_issues(&SupportIssuesRequest::new(1).expect("limit")),
            Err(FleetFailure::MissingField),
            "dropping {key} must be a refusal, never a quietly shorter board"
        );
    }
}

#[test]
fn an_oversized_response_is_refused_rather_than_buffered() {
    let padding = "a".repeat(MAX_FLEET_RESPONSE_BYTES);
    let body = format!(r#"{{"ok":true,"scope":"staff","issues":[],"pad":"{padding}"}}"#);
    assert!(body.len() > MAX_FLEET_RESPONSE_BYTES);

    let fake = FakeFleet::spawn(vec![Canned::Exact {
        status: 200,
        content_type: "application/json",
        body: body.into_bytes(),
    }]);
    let client = fleet_client(&fake);
    assert_eq!(
        client.support_issues(&SupportIssuesRequest::new(1).expect("limit")),
        Err(FleetFailure::ResponseTooLarge)
    );
}

#[test]
fn a_page_over_the_row_ceiling_is_refused_rather_than_truncated() {
    let rows: Vec<String> = (0..=MAX_SUPPORT_ISSUES).map(|_| issue_row()).collect();
    let page = format!(
        r#"{{"ok":true,"scope":"staff","issues":[{}]}}"#,
        rows.join(",")
    );
    let fake = FakeFleet::spawn(vec![Canned::json(&page)]);
    let client = fleet_client(&fake);
    assert_eq!(
        client.support_issues(&SupportIssuesRequest::new(1).expect("limit")),
        Err(FleetFailure::TooManyIssues)
    );
}

#[test]
fn a_duplicate_shaped_email_response_is_read_exactly_and_never_coerced() {
    // A truthy non-boolean must not be read as "already delivered".
    let fake = FakeFleet::spawn(vec![Canned::json(
        r#"{"ok":true,"queued":true,"duplicate":"yes"}"#,
    )]);
    let client = fleet_client(&fake);
    let request = SupportEmailRequest::new("act-1", "claire@exemple.invalid", "Sujet", "Corps")
        .expect("email");
    assert_eq!(
        client.send_email(&request),
        Err(FleetFailure::FieldOutOfBounds)
    );

    // The email contract names `queued`, so its absence is a contract break
    // even though the reply contract accepts the same body.
    let fake = FakeFleet::spawn(vec![Canned::json(r#"{"ok":true}"#)]);
    let client = fleet_client(&fake);
    let request = SupportEmailRequest::new("act-1", "claire@exemple.invalid", "Sujet", "Corps")
        .expect("email");
    assert_eq!(client.send_email(&request), Err(FleetFailure::MissingField));
}

#[test]
fn a_fleet_refusal_is_a_parsed_outcome_and_carries_a_bounded_reason() {
    let fake = FakeFleet::spawn(vec![Canned::json(
        r#"{"ok":false,"error":"API support indisponible"}"#,
    )]);
    let client = fleet_client(&fake);
    let outcome = client
        .support_issues(&SupportIssuesRequest::new(1).expect("limit"))
        .expect("a refusal is a well-formed answer, not a failure");
    assert_eq!(
        outcome.rejected().map(ServerMessage::as_str),
        Some("API support indisponible")
    );
}

#[test]
fn a_revoked_credential_is_named_apart_from_every_other_status() {
    for (status, expected) in [
        (401_u16, FleetFailure::Unauthorized),
        (403, FleetFailure::Unauthorized),
        (500, FleetFailure::UnexpectedStatus),
        (302, FleetFailure::UnexpectedStatus),
        (429, FleetFailure::UnexpectedStatus),
    ] {
        let fake = FakeFleet::spawn(vec![Canned::Exact {
            status,
            content_type: "application/json",
            body: br#"{"ok":true,"scope":"staff","issues":[]}"#.to_vec(),
        }]);
        let client = fleet_client(&fake);
        assert_eq!(
            client.support_issues(&SupportIssuesRequest::new(1).expect("limit")),
            Err(expected),
            "status {status}"
        );
    }
}

#[test]
fn a_non_json_response_is_refused_before_it_is_parsed() {
    for content_type in ["text/html", "text/json", "application/json; charset=latin1"] {
        let fake = FakeFleet::spawn(vec![Canned::Exact {
            status: 200,
            content_type,
            body: br#"{"ok":true,"scope":"staff","issues":[]}"#.to_vec(),
        }]);
        let client = fleet_client(&fake);
        assert_eq!(
            client.support_issues(&SupportIssuesRequest::new(1).expect("limit")),
            Err(FleetFailure::UnexpectedContentType),
            "content type {content_type}"
        );
    }
}

#[test]
fn a_silent_fleet_ends_the_call_at_the_clients_deadline_rather_than_hanging() {
    let fake = FakeFleet::spawn(vec![Canned::Silent]);
    let client = fleet_client(&fake);

    let started = Instant::now();
    let result = client.support_issues(&SupportIssuesRequest::new(1).expect("limit"));
    let elapsed = started.elapsed();

    assert_eq!(result, Err(FleetFailure::TimedOut));
    assert!(
        elapsed < Duration::from_secs(5),
        "the request budget must fire, not hang: took {elapsed:?}"
    );
    assert!(
        elapsed >= CLIENT_BUDGET,
        "the budget must actually be waited out: took {elapsed:?}"
    );
    // The request still reached the fake; only the answer never came.
    assert_eq!(fake.captured().len(), 1);
}

#[test]
fn a_refused_connection_is_a_typed_failure_rather_than_a_panic() {
    // Bind and immediately drop, so the port is almost certainly closed.
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("address").port()
    };
    let base = FleetBase::new(&format!("http://127.0.0.1:{port}")).expect("base");
    let client = FleetClient::with_request_timeout(
        base,
        FleetInstanceId::new(INSTANCE).expect("instance"),
        FleetToken::new(TOKEN.as_bytes().to_vec()).expect("token"),
        CLIENT_BUDGET,
    );
    assert!(matches!(
        client.support_issues(&SupportIssuesRequest::new(1).expect("limit")),
        Err(FleetFailure::Unavailable | FleetFailure::TimedOut)
    ));
}

#[test]
fn hostile_ticket_content_survives_one_round_trip_byte_exactly() {
    // A note whose text is full of JSON metacharacters must arrive at the fake
    // as the same text, not as a broken envelope.
    let hostile = "quote\" slash\\ brace} newline\nend";
    let fake = FakeFleet::spawn(vec![Canned::json(r#"{"ok":true}"#)]);
    let client = fleet_client(&fake);
    client
        .add_thread_note(&SupportThreadNoteRequest::new(THREAD_ID, hostile).expect("note"))
        .expect("call");

    let captured = fake.only_request();
    let body: serde_json::Value = serde_json::from_str(&captured.body).expect("body is JSON");
    assert_eq!(body["action"], "support-thread-note");
    assert_eq!(body["text"], hostile);
}

#[test]
fn ticket_rejection_is_one_exact_idempotent_decision_call() {
    let fake = FakeFleet::spawn(vec![Canned::json(
        r#"{"ok":true,"decision":{"job_id":"job-1","job_status":"cancelled","value":"reject","duplicate":false}}"#,
    )]);
    let client = fleet_client(&fake);
    let request = TicketDecisionRequest::new(
        "job-1",
        "slack:A1:T1:C1:123.4",
        "slack-action:T1:C1:124.5:U1:reject",
        "slack:T1:U1",
        TicketDecision::reject("Not approved for release").expect("reason"),
    )
    .expect("request");
    assert_eq!(
        client.decide_ticket(&request).expect("decision"),
        FleetOutcome::Accepted(TicketDecisionReceipt {
            job_id: String::from("job-1"),
            job_status: TicketJobStatus::Cancelled,
            decision: TicketDecisionOutcome::Rejected,
            duplicate: false,
        })
    );
    let body: serde_json::Value = serde_json::from_str(&fake.only_request().body).expect("body");
    assert_eq!(body["action"], "automonique-ticket-decision");
    assert_eq!(body["decision"], "reject");
    assert_eq!(body["reason"], "Not approved for release");
    assert_eq!(body["decision_key"], "slack-action:T1:C1:124.5:U1:reject");
}
