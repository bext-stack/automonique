// SPDX-License-Identifier: Apache-2.0

//! What the HTTPS transport puts on the wire, and what it remembers of the
//! answer.
//!
//! Both facts were once invisible, and each one cost a real diagnosis. A probe
//! addressed to `127.0.0.1` reaches a web entry that answers only for its
//! canonical name, which refuses it — and the refusal category the client
//! reported, `unexpected_status`, is the same word it uses for a deployment
//! whose daemon is restarting. So a harness could not tell "I addressed it
//! wrongly" from "the deployment is down" from "the lane is refused", and read
//! a healthy deployment as one refusing to serve.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use automonique_platform_client::platform_v2_client::PlatformV2Client;
use automonique_platform_client::{BasicCredential, HttpsTransport};
use automonique_protocol::platform_v2::PlatformVersionOffer;

/// One request, answered by a canned response, with the request head handed
/// back to the test. Deliberately the smallest thing that can observe headers.
struct Stub {
    port: u16,
    head: mpsc::Receiver<String>,
}

fn stub(response: &'static str) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local address").port();
    let (sender, head) = mpsc::channel();
    thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let mut reader = BufReader::new(stream);
        let mut request = String::new();
        let mut length = 0_usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            if let Some(value) = line
                .to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(str::trim)
                .and_then(|value| value.parse::<usize>().ok())
            {
                length = value;
            }
            let done = line == "\r\n";
            request.push_str(&line);
            if done {
                break;
            }
        }
        let mut body = vec![0_u8; length];
        let _ = reader.read_exact(&mut body);
        let _ = sender.send(request);
        let mut stream: TcpStream = reader.into_inner();
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    });
    Stub { port, head }
}

fn client(port: u16, loopback: Option<(&str, &str)>) -> PlatformV2Client<HttpsTransport> {
    let endpoint = format!("http://127.0.0.1:{port}/api/platform/v2");
    let credential = BasicCredential::new("operator", "secret").expect("credential");
    let mut transport = HttpsTransport::new_basic(endpoint, credential).expect("transport");
    if let Some((host, proto)) = loopback {
        transport = transport
            .with_loopback_origin(host, proto)
            .expect("loopback origin");
    }
    PlatformV2Client::new_https(transport)
}

fn negotiate(client: &mut PlatformV2Client<HttpsTransport>) {
    let offer = PlatformVersionOffer::new(vec![1, 2]).expect("offer");
    // The stub never answers a negotiation, so this always errs. What is under
    // test is the request that went out and the answer that was remembered.
    let _ = client.negotiate(offer);
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().to_owned())
}

const SERVICE_UNAVAILABLE: &str = concat!(
    "HTTP/1.1 503 Service Unavailable\r\n",
    "content-type: application/json\r\n",
    "content-length: 2\r\n",
    "connection: close\r\n",
    "\r\n",
    "{}",
);

#[test]
fn without_a_loopback_origin_the_request_is_addressed_to_the_loopback_socket() {
    let stub = stub(SERVICE_UNAVAILABLE);
    let mut client = client(stub.port, None);
    negotiate(&mut client);
    let head = stub.head.recv().expect("request head");
    assert_eq!(
        header(&head, "host").as_deref(),
        Some(format!("127.0.0.1:{}", stub.port).as_str())
    );
    assert_eq!(header(&head, "x-forwarded-proto"), None);
}

#[test]
fn a_loopback_origin_presents_the_canonical_host_and_the_forwarded_scheme() {
    let stub = stub(SERVICE_UNAVAILABLE);
    let mut client = client(stub.port, Some(("entry.example", "https")));
    negotiate(&mut client);
    let head = stub.head.recv().expect("request head");
    assert_eq!(header(&head, "host").as_deref(), Some("entry.example"));
    assert_eq!(header(&head, "x-forwarded-proto").as_deref(), Some("https"));
}

#[test]
fn the_status_the_deployment_answered_is_remembered_beside_the_category() {
    let stub = stub(SERVICE_UNAVAILABLE);
    let mut client = client(stub.port, None);
    negotiate(&mut client);
    let _ = stub.head.recv();
    let exchange = client
        .transport()
        .last_exchange()
        .expect("an answered request records its status");
    assert_eq!(exchange.status(), 503);
}

#[test]
fn a_credential_refusal_is_remembered_as_its_own_status() {
    let stub = stub(concat!(
        "HTTP/1.1 401 Unauthorized\r\n",
        "content-length: 0\r\n",
        "connection: close\r\n",
        "\r\n",
    ));
    let mut client = client(stub.port, None);
    negotiate(&mut client);
    let _ = stub.head.recv();
    assert_eq!(
        client
            .transport()
            .last_exchange()
            .map(automonique_platform_client::HttpExchange::status),
        Some(401)
    );
}

#[test]
fn a_request_that_reached_nothing_records_no_status() {
    // Nothing is listening on this port, so there is no answer to remember.
    // "No status at all" is itself the finding, and must not be confused with
    // a status the deployment gave.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local address").port();
    drop(listener);
    let mut client = client(port, None);
    negotiate(&mut client);
    assert!(client.transport().last_exchange().is_none());
}

#[test]
fn a_public_endpoint_cannot_be_told_which_host_it_is() {
    // A `Host` a client chose for itself is a claim about which deployment it
    // is talking to. On a public origin that is name spoofing, and the client
    // has no business offering it.
    let credential = BasicCredential::new("operator", "secret").expect("credential");
    let transport = HttpsTransport::new_basic("https://entry.example/api/platform/v2", credential)
        .expect("transport");
    assert!(
        transport
            .with_loopback_origin("elsewhere.example", "https")
            .is_err()
    );
}

#[test]
fn a_loopback_origin_refuses_a_host_that_could_end_the_header() {
    let credential = BasicCredential::new("operator", "secret").expect("credential");
    let transport = HttpsTransport::new_basic("http://127.0.0.1:1/api/platform/v2", credential)
        .expect("transport");
    assert!(
        transport
            .with_loopback_origin("entry.example\r\nx: y", "https")
            .is_err()
    );
}

#[test]
fn a_loopback_origin_refuses_a_scheme_that_is_not_a_scheme() {
    let credential = BasicCredential::new("operator", "secret").expect("credential");
    let transport = HttpsTransport::new_basic("http://127.0.0.1:1/api/platform/v2", credential)
        .expect("transport");
    assert!(
        transport
            .with_loopback_origin("entry.example", "gopher")
            .is_err()
    );
}
