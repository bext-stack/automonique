// SPDX-License-Identifier: Elastic-2.0

//! End-to-end proofs for identity-bound egress, against a fake provider on
//! loopback.
//!
//! The acceptance these tests exist for is one sentence: *a workload holding a
//! foreign credential cannot exfiltrate through the allowlisted provider
//! endpoint.* Two properties together make that true, and each is asserted
//! separately here.
//!
//! 1. A request carrying a credential the supervisor did not issue is refused,
//!    and the provider records **zero** accepted connections — the refusal
//!    precedes the dial, so the attempt does not even produce a packet.
//! 2. While an identity is bound, a `CONNECT` naming the provider host is
//!    refused. Without this the first property would be decoration: a workload
//!    would tunnel to the provider and negotiate its own TLS inside, carrying
//!    whatever credential it liked past a substitution that never ran.
//!
//! Nothing here touches an external network. The provider is a `TcpListener`
//! this test owns, reached over a loopback-scoped destination, so no
//! certificate is needed and a failure is the broker's rather than the
//! internet's.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use automonique_egress_broker::{
    AddressScope, BrokerConfig, BrokerError, CredentialScheme, Destination, DestinationAllowlist,
    EgressBroker, IdentityRefusal, ProviderCredential, ProviderIdentity, SessionSentinel,
};

/// Bound on every client-side wait. A test that would otherwise hang fails here.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

/// The credential the supervisor holds and the sandbox never sees.
const REAL_CREDENTIAL: &str = "sk-supervisor-held-not-in-the-sandbox";

/// A credential an injected instruction brought with it.
const FOREIGN_CREDENTIAL: &str = "sk-attacker-supplied-foreign-key";

/// Gap between streamed events. Long enough that a buffering proxy is visible.
const STREAM_GAP: Duration = Duration::from_millis(400);

/// What the fake provider does with a request it accepts.
#[derive(Clone, Copy)]
enum Answer {
    /// Reply once, in full, and close.
    Once,
    /// Reply with a server-sent-event stream, one event per [`STREAM_GAP`].
    Stream,
}

/// A provider the broker can forward to, which records what it received and
/// whether it was ever reached at all.
struct FakeProvider {
    address: SocketAddr,
    accepts: Arc<AtomicUsize>,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeProvider {
    fn spawn(answer: Answer) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake provider");
        let address = listener.local_addr().expect("fake provider address");
        listener
            .set_nonblocking(true)
            .expect("nonblocking fake provider");
        let accepts = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let thread = {
            let accepts = Arc::clone(&accepts);
            let received = Arc::clone(&received);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((socket, _)) => {
                            accepts.fetch_add(1, Ordering::SeqCst);
                            socket.set_nonblocking(false).expect("blocking socket");
                            serve(socket, answer, &received);
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
            accepts,
            received,
            stop,
            thread: Some(thread),
        }
    }

    /// The destination the broker's identity points at.
    fn destination(&self) -> Destination {
        Destination::new("127.0.0.1", self.address.port(), AddressScope::Loopback)
            .expect("loopback provider destination")
    }

    /// How many connections the provider has accepted. `0` after a refusal is
    /// the proof that the broker never dialled.
    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// Everything the provider was sent, one entry per connection.
    fn received(&self) -> Vec<Vec<u8>> {
        self.received.lock().expect("received lock").clone()
    }
}

impl Drop for FakeProvider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Read one request, record it, and answer it.
fn serve(mut socket: TcpStream, answer: Answer, received: &Arc<Mutex<Vec<Vec<u8>>>>) {
    socket
        .set_read_timeout(Some(CLIENT_TIMEOUT))
        .expect("provider read timeout");
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    // Read the head, then exactly the body its `Content-Length` framed.
    loop {
        let Ok(read) = socket.read(&mut chunk) else {
            break;
        };
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if let Some(end) = find(&request, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if request.len() >= end + 4 + length {
                break;
            }
        }
    }
    received.lock().expect("received lock").push(request);

    match answer {
        Answer::Once => {
            let body = br#"{"ok":true}"#;
            let _ = socket.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = socket.write_all(body);
            let _ = socket.flush();
        }
        Answer::Stream => {
            let _ = socket.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
            );
            let _ = socket.flush();
            for index in 0..3 {
                let _ = socket.write_all(format!("event: delta\ndata: {index}\n\n").as_bytes());
                let _ = socket.flush();
                if index < 2 {
                    thread::sleep(STREAM_GAP);
                }
            }
        }
    }
    let _ = socket.shutdown(std::net::Shutdown::Both);
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Start a broker bound to `provider`, with the given `CONNECT` allowlist.
fn broker_for(provider: &FakeProvider, allowlist: DestinationAllowlist) -> (EgressBroker, String) {
    let sentinel = SessionSentinel::generate().expect("mint a sentinel");
    let token = sentinel.token().to_owned();
    let identity = ProviderIdentity::new(
        provider.destination(),
        sentinel,
        ProviderCredential::new(CredentialScheme::ApiKeyHeader, REAL_CREDENTIAL)
            .expect("a real credential"),
    );
    let broker = EgressBroker::start(
        BrokerConfig::new(allowlist)
            .with_provider_identity(identity)
            .with_head_timeout(Duration::from_secs(2))
            .with_connect_timeout(Duration::from_secs(2))
            .with_idle_timeout(Duration::from_secs(3)),
    )
    .expect("start a broker with an identity");
    (broker, token)
}

/// Send one raw request to the broker's provider endpoint and read the whole
/// answer.
fn request(broker: &EgressBroker, head_and_body: &str) -> String {
    let (response, _) = request_timed(broker, head_and_body);
    response
}

/// As [`request`], also reporting when the first response byte arrived.
fn request_timed(broker: &EgressBroker, head_and_body: &str) -> (String, Duration) {
    let address = broker
        .provider_addr()
        .expect("a broker with an identity binds a provider endpoint");
    let mut socket =
        TcpStream::connect_timeout(&address, CLIENT_TIMEOUT).expect("reach the provider endpoint");
    socket
        .set_read_timeout(Some(CLIENT_TIMEOUT))
        .expect("client read timeout");
    socket
        .write_all(head_and_body.as_bytes())
        .expect("send the request");
    socket.flush().expect("flush the request");

    let started = Instant::now();
    let mut first_byte = None;
    let mut response = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match socket.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                first_byte.get_or_insert_with(|| started.elapsed());
                response.extend_from_slice(&chunk[..read]);
            }
        }
    }
    (
        String::from_utf8_lossy(&response).into_owned(),
        first_byte.unwrap_or_else(|| started.elapsed()),
    )
}

/// Ask the `CONNECT` proxy for a tunnel and read its answer.
fn connect_tunnel(broker: &EgressBroker, authority: &str) -> String {
    let mut socket = TcpStream::connect_timeout(&broker.local_addr(), CLIENT_TIMEOUT)
        .expect("reach the tunnel endpoint");
    socket
        .set_read_timeout(Some(CLIENT_TIMEOUT))
        .expect("client read timeout");
    socket
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .expect("send the CONNECT");
    socket.flush().expect("flush the CONNECT");
    let mut response = Vec::new();
    let _ = socket.read_to_end(&mut response);
    String::from_utf8_lossy(&response).into_owned()
}

/// The `x-automonique-egress-refusal` header line an answer carries.
fn refusal_header(response: &str) -> Option<String> {
    response
        .lines()
        .find_map(|line| line.strip_prefix("x-automonique-egress-refusal: "))
        .map(str::trim)
        .map(str::to_owned)
}

#[test]
fn a_sentinel_bound_request_reaches_the_provider_with_the_real_credential_substituted() {
    let provider = FakeProvider::spawn(Answer::Once);
    let (broker, sentinel) = broker_for(&provider, DestinationAllowlist::deny_all());

    let body = r#"{"model":"m","messages":[]}"#;
    let response = request(
        &broker,
        &format!(
            "POST /v1/messages HTTP/1.1\r\n\
             Host: 127.0.0.1:1\r\n\
             X-Api-Key: {sentinel}\r\n\
             Anthropic-Version: 2023-06-01\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    );

    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.contains(r#"{"ok":true}"#), "{response}");

    let seen = provider.received();
    assert_eq!(seen.len(), 1, "exactly one request reached the provider");
    let seen = String::from_utf8_lossy(&seen[0]).into_owned();

    // The substitution happened.
    assert!(
        seen.contains(&format!("x-api-key: {REAL_CREDENTIAL}\r\n")),
        "the provider must receive the supervisor's credential: {seen}"
    );
    // The sentinel is worth nothing off this host, and it does not get there.
    assert!(
        !seen.contains(&sentinel),
        "the sentinel must not leave the host: {seen}"
    );
    // Exactly one credential, not the client's beside the supervisor's.
    assert_eq!(
        seen.to_ascii_lowercase().matches("x-api-key").count(),
        1,
        "{seen}"
    );
    // The request itself is carried through intact.
    assert!(seen.starts_with("POST /v1/messages HTTP/1.1\r\n"), "{seen}");
    assert!(seen.contains("anthropic-version: 2023-06-01\r\n"), "{seen}");
    assert!(seen.ends_with(body), "the body must arrive intact: {seen}");
    // The `Host` names the destination the broker chose, not the one the
    // workload wrote.
    assert!(
        seen.contains(&format!("host: 127.0.0.1:{}\r\n", provider.address.port())),
        "{seen}"
    );
    assert!(!seen.contains("127.0.0.1:1"), "{seen}");

    let stats = broker.stats();
    assert_eq!(stats.provider_forwarded, 1);
    assert_eq!(stats.provider_refused_identity, 0);
    assert!(stats.bytes_from_provider > 0);
    assert!(broker.refusals().is_empty());
}

#[test]
fn a_foreign_credential_is_refused_with_a_typed_error_and_never_dials_the_provider() {
    let provider = FakeProvider::spawn(Answer::Once);
    let (broker, _sentinel) = broker_for(&provider, DestinationAllowlist::deny_all());

    let body = r#"{"exfiltrated":"the whole workspace"}"#;
    let response = request(
        &broker,
        &format!(
            "POST /v1/messages HTTP/1.1\r\n\
             Host: 127.0.0.1:1\r\n\
             X-Api-Key: {FOREIGN_CREDENTIAL}\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    );

    assert!(response.starts_with("HTTP/1.1 403 Forbidden"), "{response}");
    assert_eq!(
        refusal_header(&response).as_deref(),
        Some(IdentityRefusal::ForeignCredential.as_str()),
        "{response}"
    );

    // The property the acceptance names: no packet, not merely no answer.
    assert_eq!(
        provider.accepts(),
        0,
        "a foreign credential must not produce a connection to the provider"
    );
    assert!(provider.received().is_empty());

    let stats = broker.stats();
    assert_eq!(stats.provider_refused_identity, 1);
    assert_eq!(stats.provider_forwarded, 0);
    assert_eq!(stats.bytes_to_provider, 0);

    let ledger = broker.refusals();
    assert_eq!(ledger.len(), 1, "{ledger:?}");
    assert_eq!(ledger[0].refusal, IdentityRefusal::ForeignCredential);
    assert!(ledger[0].before_any_dial);
}

#[test]
fn a_request_with_no_credential_at_all_is_refused_before_any_dial() {
    let provider = FakeProvider::spawn(Answer::Once);
    let (broker, _sentinel) = broker_for(&provider, DestinationAllowlist::deny_all());

    let response = request(
        &broker,
        "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:1\r\nContent-Length: 0\r\n\r\n",
    );

    assert!(
        response.starts_with("HTTP/1.1 401 Unauthorized"),
        "{response}"
    );
    assert_eq!(
        refusal_header(&response).as_deref(),
        Some(IdentityRefusal::MissingCredential.as_str()),
        "{response}"
    );
    assert_eq!(provider.accepts(), 0);
    assert_eq!(broker.stats().provider_refused_identity, 1);
    assert_eq!(
        broker.refusals()[0].refusal,
        IdentityRefusal::MissingCredential
    );
}

#[test]
fn a_sentinel_beside_a_foreign_credential_is_refused_rather_than_resolved() {
    let provider = FakeProvider::spawn(Answer::Once);
    let (broker, sentinel) = broker_for(&provider, DestinationAllowlist::deny_all());

    let response = request(
        &broker,
        &format!(
            "POST /v1/messages HTTP/1.1\r\n\
             X-Api-Key: {sentinel}\r\n\
             Authorization: Bearer {FOREIGN_CREDENTIAL}\r\n\
             Content-Length: 0\r\n\r\n"
        ),
    );

    assert!(response.starts_with("HTTP/1.1 403 Forbidden"), "{response}");
    assert_eq!(
        refusal_header(&response).as_deref(),
        Some(IdentityRefusal::AmbiguousCredential.as_str()),
        "{response}"
    );
    assert_eq!(provider.accepts(), 0);
}

#[test]
fn a_connect_tunnel_to_the_provider_host_is_refused_while_an_identity_is_bound() {
    let provider = FakeProvider::spawn(Answer::Once);
    // A non-empty allowlist naming a different host, so the refusal below is
    // the identity's and not merely "the allowlist is empty".
    let allowlist = DestinationAllowlist::deny_all()
        .allowing("chatgpt.com", 443, AddressScope::Public)
        .expect("an unrelated allowlist entry");
    let (broker, _sentinel) = broker_for(&provider, allowlist);

    let response = connect_tunnel(&broker, &format!("127.0.0.1:{}", provider.address.port()));
    assert!(response.starts_with("HTTP/1.1 403 Forbidden"), "{response}");
    assert_eq!(
        refusal_header(&response).as_deref(),
        Some(IdentityRefusal::TunnelToProviderRefused.as_str()),
        "{response}"
    );

    // Any port on that host, not only the provider's own: a tunnel to the host
    // is the thing being refused.
    let response = connect_tunnel(&broker, "127.0.0.1:443");
    assert_eq!(
        refusal_header(&response).as_deref(),
        Some(IdentityRefusal::TunnelToProviderRefused.as_str()),
        "{response}"
    );

    assert_eq!(provider.accepts(), 0);
    let stats = broker.stats();
    assert_eq!(stats.refused_provider_tunnel, 2);
    assert_eq!(
        stats.denied_destination, 0,
        "the identity refusal must precede the allowlist decision"
    );
    assert!(broker.refusals().iter().all(|record| record.refusal
        == IdentityRefusal::TunnelToProviderRefused
        && record.before_any_dial));
}

#[test]
fn an_allowlist_naming_the_identity_host_is_refused_before_the_broker_binds() {
    let provider = FakeProvider::spawn(Answer::Once);
    let sentinel = SessionSentinel::generate().expect("mint a sentinel");
    let identity = ProviderIdentity::new(
        provider.destination(),
        sentinel,
        ProviderCredential::new(CredentialScheme::ApiKeyHeader, REAL_CREDENTIAL).unwrap(),
    );
    let allowlist = DestinationAllowlist::deny_all()
        .allowing("127.0.0.1", 9443, AddressScope::Loopback)
        .expect("a loopback entry on the identity's host");

    let error = EgressBroker::start(BrokerConfig::new(allowlist).with_provider_identity(identity))
        .expect_err("a contradictory configuration must not start");
    assert!(matches!(error, BrokerError::IdentityHostAlsoTunnelled));
}

#[test]
fn an_empty_allowlist_still_refuses_every_tunnel_while_an_identity_is_bound() {
    let provider = FakeProvider::spawn(Answer::Once);
    let (broker, _sentinel) = broker_for(&provider, DestinationAllowlist::deny_all());
    assert!(broker.allowlist().denies_everything());

    // An unrelated host: the empty allowlist is what refuses this one, and it
    // refuses before any resolution or dial.
    let response = connect_tunnel(&broker, "chatgpt.com:443");
    assert!(response.starts_with("HTTP/1.1 403 Forbidden"), "{response}");
    assert_eq!(refusal_header(&response), None, "{response}");

    let stats = broker.stats();
    assert_eq!(stats.denied_destination, 1);
    assert_eq!(stats.established, 0);
    assert_eq!(stats.destination_unreachable, 0, "nothing was resolved");
    assert_eq!(stats.refused_provider_tunnel, 0);
    assert_eq!(provider.accepts(), 0);
}

#[test]
fn a_streaming_response_reaches_the_workload_chunk_by_chunk_rather_than_at_the_end() {
    let provider = FakeProvider::spawn(Answer::Stream);
    let (broker, sentinel) = broker_for(&provider, DestinationAllowlist::deny_all());

    let started = Instant::now();
    let (response, first_byte) = request_timed(
        &broker,
        &format!(
            "POST /v1/messages HTTP/1.1\r\nX-Api-Key: {sentinel}\r\nContent-Length: 0\r\n\r\n"
        ),
    );
    let total = started.elapsed();

    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.contains("text/event-stream"), "{response}");
    for index in 0..3 {
        assert!(
            response.contains(&format!("data: {index}\n")),
            "event {index} is missing: {response}"
        );
    }

    // The provider spent two gaps producing this. If the broker had buffered
    // the response, the first byte would have arrived only at the end.
    assert!(
        first_byte < STREAM_GAP,
        "the first byte arrived after {first_byte:?}, which means the response was buffered"
    );
    assert!(
        total >= STREAM_GAP * 2,
        "the stream finished in {total:?}, so the provider cannot have produced it"
    );
    assert_eq!(broker.stats().provider_forwarded, 1);
}

#[test]
fn a_head_the_forwarder_cannot_read_is_refused_without_reaching_the_provider() {
    let provider = FakeProvider::spawn(Answer::Once);
    let (broker, sentinel) = broker_for(&provider, DestinationAllowlist::deny_all());

    for (head, expected) in [
        (
            format!("CONNECT 127.0.0.1:443 HTTP/1.1\r\nX-Api-Key: {sentinel}\r\n\r\n"),
            IdentityRefusal::MethodRejected,
        ),
        (
            format!("POST https://elsewhere.example/v1 HTTP/1.1\r\nX-Api-Key: {sentinel}\r\n\r\n"),
            IdentityRefusal::TargetRejected,
        ),
        (
            format!("POST /v1 HTTP/1.0\r\nX-Api-Key: {sentinel}\r\n\r\n"),
            IdentityRefusal::VersionUnsupported,
        ),
        (
            format!(
                "POST /v1 HTTP/1.1\r\nX-Api-Key: {sentinel}\r\nTransfer-Encoding: chunked\r\n\r\n"
            ),
            IdentityRefusal::RequestFramingRejected,
        ),
    ] {
        let response = request(&broker, &head);
        assert_eq!(
            refusal_header(&response).as_deref(),
            Some(expected.as_str()),
            "{head:?} produced {response}"
        );
    }

    assert_eq!(provider.accepts(), 0);
    assert_eq!(broker.stats().provider_forwarded, 0);
    assert!(
        broker
            .refusals()
            .iter()
            .all(|record| record.before_any_dial)
    );
}

#[test]
fn a_broker_with_no_identity_binds_no_provider_endpoint_and_behaves_as_it_always_did() {
    let broker = EgressBroker::start(BrokerConfig::default()).expect("start a plain broker");
    assert_eq!(broker.provider_addr(), None);
    assert_eq!(broker.provider_base_url(), None);
    assert_eq!(broker.sentinel_token(), None);
    assert!(broker.refusals().is_empty());
    assert_eq!(broker.stats().provider_forwarded, 0);
}

#[test]
fn the_workload_is_given_a_loopback_base_url_and_a_sentinel_rather_than_a_credential() {
    let provider = FakeProvider::spawn(Answer::Once);
    let (broker, sentinel) = broker_for(&provider, DestinationAllowlist::deny_all());

    let base_url = broker.provider_base_url().expect("a provider base URL");
    let port = broker.provider_addr().expect("a provider address").port();
    assert_eq!(base_url, format!("http://127.0.0.1:{port}"));
    assert_ne!(
        port,
        broker.local_addr().port(),
        "the two endpoints are separate ports, each granted separately"
    );
    assert_eq!(broker.sentinel_token(), Some(sentinel.as_str()));
    assert!(!sentinel.contains(REAL_CREDENTIAL));
    assert!(
        SessionSentinel::from_token(&sentinel).is_ok(),
        "the token handed to the workload is a well-formed sentinel"
    );
}
