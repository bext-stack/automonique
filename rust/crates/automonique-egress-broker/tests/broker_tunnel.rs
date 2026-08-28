// SPDX-License-Identifier: Elastic-2.0

//! End-to-end proofs for the broker, against a fake destination on loopback.
//!
//! Nothing here touches an external network: every destination is a
//! `TcpListener` this test owns, so a run is hermetic and a failure is the
//! broker's rather than the internet's.
//!
//! Every client socket carries a read timeout, and every assertion about a
//! deadline is written as "this finished inside a bound" rather than "this
//! eventually finished" — so a broker that lost a deadline fails these tests
//! instead of hanging them.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use automonique_egress_broker::{
    AddressScope, BrokerConfig, DestinationAllowlist, EgressBroker, RefusedDestinationWindow,
};

/// Bound on every client-side wait. A test that would otherwise hang fails here.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

/// The short deadlines the deadline tests configure the broker with.
const SHORT_DEADLINE: Duration = Duration::from_millis(300);

/// What a fake destination does with a connection it accepts.
#[derive(Clone, Copy)]
enum Behaviour {
    /// Echo every chunk straight back, then mirror the client's half-close.
    Echo,
    /// Accept and then say nothing, holding the connection open.
    Silent,
}

/// A destination the broker can dial, which records whether it ever was.
struct FakeDestination {
    address: SocketAddr,
    accepts: Arc<AtomicUsize>,
    received: Arc<Mutex<Vec<u8>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeDestination {
    fn spawn(behaviour: Behaviour) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake destination");
        let address = listener.local_addr().expect("fake destination address");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let accepts = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let thread = {
            let accepts = Arc::clone(&accepts);
            let received = Arc::clone(&received);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let mut held = Vec::new();
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((socket, _)) => {
                            accepts.fetch_add(1, Ordering::SeqCst);
                            socket.set_nonblocking(false).expect("blocking socket");
                            match behaviour {
                                Behaviour::Echo => echo(socket, &received),
                                // Held rather than dropped: dropping would close
                                // the socket, which is not what "silent" means.
                                Behaviour::Silent => held.push(socket),
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
            accepts,
            received,
            stop,
            thread: Some(thread),
        }
    }

    fn port(&self) -> u16 {
        self.address.port()
    }

    /// How many connections this destination has accepted. `0` after a refusal
    /// is the proof that the broker never dialled.
    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    fn received(&self) -> Vec<u8> {
        self.received.lock().expect("received lock").clone()
    }
}

impl Drop for FakeDestination {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn echo(mut socket: TcpStream, received: &Arc<Mutex<Vec<u8>>>) {
    socket
        .set_read_timeout(Some(CLIENT_TIMEOUT))
        .expect("destination read timeout");
    let mut buffer = [0u8; 4096];
    loop {
        match socket.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                received
                    .lock()
                    .expect("received lock")
                    .extend_from_slice(&buffer[..read]);
                if socket.write_all(&buffer[..read]).is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
    let _ = socket.shutdown(Shutdown::Write);
}

/// A broker permitting exactly `destination` on loopback, with default bounds.
fn broker_allowing(host: &str, port: u16, scope: AddressScope) -> EgressBroker {
    let allowlist = DestinationAllowlist::deny_all()
        .allowing(host, port, scope)
        .expect("allowlist entry");
    EgressBroker::start(BrokerConfig::new(allowlist)).expect("broker start")
}

/// Connect to the broker as a workload would, with every wait bounded.
fn client(broker: &EgressBroker) -> TcpStream {
    let stream = TcpStream::connect_timeout(&broker.local_addr(), CLIENT_TIMEOUT)
        .expect("connect to broker");
    stream
        .set_read_timeout(Some(CLIENT_TIMEOUT))
        .expect("client read timeout");
    stream
        .set_write_timeout(Some(CLIENT_TIMEOUT))
        .expect("client write timeout");
    stream
}

/// Read one HTTP response head and return its status line.
fn read_status(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => head.push(byte[0]),
            Err(error) => panic!("reading the broker's response: {error}"),
        }
        assert!(head.len() < 4096, "response head is unbounded");
    }
    String::from_utf8_lossy(&head)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn refuse_destination(broker: &EgressBroker, host: &str, port: u16) {
    let mut stream = client(broker);
    write!(stream, "CONNECT {host}:{port} HTTP/1.1\r\n\r\n").expect("send CONNECT");
    assert_eq!(read_status(&mut stream), "HTTP/1.1 403 Forbidden");
}

/// Poll the broker's counters until `settled` holds, or the client bound
/// elapses.
///
/// A tunnel's byte totals are recorded once the relay ends, which is ordered
/// after the client observes end of stream rather than before it. Waiting for
/// the value keeps the assertion's teeth — a broker that never counts still
/// fails, one bound later — without turning a scheduling order into a flake.
fn eventually(
    broker: &EgressBroker,
    settled: impl Fn(automonique_egress_broker::BrokerStats) -> bool,
) -> automonique_egress_broker::BrokerStats {
    let deadline = Instant::now() + CLIENT_TIMEOUT;
    loop {
        let stats = broker.stats();
        if settled(stats) || Instant::now() >= deadline {
            return stats;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// A payload spanning several relay buffers and covering every byte value.
fn payload(seed: u8) -> Vec<u8> {
    (0..40_000)
        .map(|index| (index as u8).wrapping_add(seed))
        .collect()
}

#[test]
fn an_allowlisted_destination_tunnels_bytes_both_ways_byte_exact() {
    let destination = FakeDestination::spawn(Behaviour::Echo);
    let broker = broker_allowing("127.0.0.1", destination.port(), AddressScope::Loopback);

    let mut stream = client(&broker);
    write!(
        stream,
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        destination.port(),
        destination.port()
    )
    .expect("send CONNECT");
    assert_eq!(
        read_status(&mut stream),
        "HTTP/1.1 200 Connection Established"
    );

    let sent = payload(0);
    let writer = {
        let mut writing = stream.try_clone().expect("clone client");
        let sent = sent.clone();
        thread::spawn(move || {
            writing.write_all(&sent).expect("client write");
            writing
                .shutdown(Shutdown::Write)
                .expect("client half-close");
        })
    };
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).expect("read the echo back");
    writer.join().expect("writer thread");

    assert_eq!(
        echoed, sent,
        "the destination-to-client direction must be byte-exact"
    );
    assert_eq!(
        destination.received(),
        sent,
        "the client-to-destination direction must be byte-exact"
    );
    assert_eq!(destination.accepts(), 1);

    let stats = eventually(&broker, |stats| stats.bytes_to_client == sent.len() as u64);
    assert_eq!(stats.accepted, 1);
    assert_eq!(stats.established, 1);
    assert_eq!(stats.denied_destination, 0);
    assert_eq!(stats.bytes_to_destination, sent.len() as u64);
    assert_eq!(stats.bytes_to_client, sent.len() as u64);
}

#[test]
fn a_destination_that_is_not_allowlisted_is_refused_and_never_dialled() {
    let allowed = FakeDestination::spawn(Behaviour::Echo);
    let forbidden = FakeDestination::spawn(Behaviour::Echo);
    let broker = broker_allowing("127.0.0.1", allowed.port(), AddressScope::Loopback);

    let observer = broker.refused_destination_observer();
    let mut cursor = observer.cursor().expect("initial refusal cursor");

    // Same host, different port.
    let mut stream = client(&broker);
    write!(
        stream,
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n",
        forbidden.port()
    )
    .expect("send CONNECT");
    assert_eq!(read_status(&mut stream), "HTTP/1.1 403 Forbidden");

    // A name that is not the allowlisted literal, on the allowlisted port.
    let mut stream = client(&broker);
    write!(
        stream,
        "CONNECT localhost:{} HTTP/1.1\r\n\r\n",
        allowed.port()
    )
    .expect("send CONNECT");
    assert_eq!(read_status(&mut stream), "HTTP/1.1 403 Forbidden");

    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        forbidden.accepts(),
        0,
        "a refused destination must never be dialled"
    );
    assert_eq!(
        allowed.accepts(),
        0,
        "an allowlisted destination must not be dialled for a request that did not name it"
    );
    assert_eq!(broker.stats().denied_destination, 2);
    assert_eq!(broker.stats().established, 0);
    assert_eq!(
        observer.take_since(&mut cursor),
        RefusedDestinationWindow::Ambiguous,
        "two different coordinates cannot be attributed to one provider fault"
    );
    assert_eq!(
        observer.take_since(&mut cursor),
        RefusedDestinationWindow::Empty,
        "taking a refusal interval advances its cursor"
    );
}

#[test]
fn a_refusal_cursor_excludes_stale_events_and_accepts_repeated_coordinates() {
    let broker = EgressBroker::start(BrokerConfig::default()).expect("deny-all broker starts");
    let observer = broker.refused_destination_observer();
    refuse_destination(&broker, "stale.example", 443);
    let mut cursor = observer.cursor().expect("cursor after stale refusal");
    assert_eq!(
        observer.take_since(&mut cursor),
        RefusedDestinationWindow::Empty
    );

    refuse_destination(&broker, "retry.example", 443);
    refuse_destination(&broker, "RETRY.example", 443);
    let RefusedDestinationWindow::Unambiguous(refused) = observer.take_since(&mut cursor) else {
        panic!("retries of one normalized coordinate must remain unambiguous")
    };
    assert_eq!(refused.host().to_string(), "retry.example");
    assert_eq!(refused.port(), 443);
    assert_eq!(
        observer.take_since(&mut cursor),
        RefusedDestinationWindow::Empty
    );
}

#[test]
fn a_cursor_is_bound_to_its_originating_broker_and_cannot_be_replayed() {
    let first = EgressBroker::start(BrokerConfig::default()).expect("first deny-all broker starts");
    let second =
        EgressBroker::start(BrokerConfig::default()).expect("second deny-all broker starts");
    let first_observer = first.refused_destination_observer();
    let second_observer = second.refused_destination_observer();
    let mut first_cursor = first_observer.cursor().expect("first broker cursor");
    assert_eq!(
        format!("{first_cursor:?}"),
        "RefusedDestinationCursor { state: \"bound\" }"
    );

    refuse_destination(&second, "second.example", 443);
    assert_eq!(
        second_observer.take_since(&mut first_cursor),
        RefusedDestinationWindow::Ambiguous,
        "a numerically valid cursor from another broker must fail closed"
    );

    refuse_destination(&first, "first.example", 443);
    let RefusedDestinationWindow::Unambiguous(refused) =
        first_observer.take_since(&mut first_cursor)
    else {
        panic!("the cursor must remain usable only with its originating broker")
    };
    assert_eq!(refused.host().to_string(), "first.example");
    assert_eq!(refused.port(), 443);
    assert_eq!(
        first_observer.take_since(&mut first_cursor),
        RefusedDestinationWindow::Empty,
        "an advanced cursor cannot replay an already consumed refusal"
    );
}

#[test]
fn concurrent_different_refusals_are_ambiguous_whatever_arrival_order_wins() {
    let broker =
        Arc::new(EgressBroker::start(BrokerConfig::default()).expect("deny-all broker starts"));
    let observer = broker.refused_destination_observer();
    let mut cursor = observer.cursor().expect("initial refusal cursor");
    let clients: Vec<_> = [("first.example", 443), ("second.example", 8443)]
        .into_iter()
        .map(|(host, port)| {
            let broker = Arc::clone(&broker);
            thread::spawn(move || refuse_destination(&broker, host, port))
        })
        .collect();
    for client in clients {
        client.join().expect("refusal client");
    }
    assert_eq!(
        observer.take_since(&mut cursor),
        RefusedDestinationWindow::Ambiguous
    );
}

#[test]
fn a_malformed_request_is_refused_without_a_dial() {
    let destination = FakeDestination::spawn(Behaviour::Echo);
    let broker = broker_allowing("127.0.0.1", destination.port(), AddressScope::Loopback);
    let authority = format!("127.0.0.1:{}", destination.port());

    let malformed = [
        // Not CONNECT: a proxy that forwarded this would be reading plaintext.
        format!("GET http://{authority}/ HTTP/1.1\r\nHost: x\r\n\r\n"),
        format!("POST http://{authority}/ HTTP/1.1\r\n\r\n"),
        format!("connect {authority} HTTP/1.1\r\n\r\n"),
        // Malformed request lines.
        format!("CONNECT  {authority} HTTP/1.1\r\n\r\n"),
        format!("CONNECT {authority} HTTP/1.0\r\n\r\n"),
        format!("CONNECT {authority}\r\n\r\n"),
        "CONNECT 127.0.0.1 HTTP/1.1\r\n\r\n".to_owned(),
        "CONNECT 127.0.0.1:0 HTTP/1.1\r\n\r\n".to_owned(),
        "CONNECT 127.0.0.1:99999 HTTP/1.1\r\n\r\n".to_owned(),
        // Line-ending and header shapes two parsers could disagree about.
        format!("CONNECT {authority} HTTP/1.1\nHost: x\r\n\r\n"),
        format!("CONNECT {authority} HTTP/1.1\r\nHost x\r\n\r\n"),
        format!("CONNECT {authority} HTTP/1.1\r\n Host: x\r\n\r\n"),
        // Not HTTP at all: a TLS ClientHello sent straight at the broker.
        "\u{16}\u{3}\u{1}\u{0}\u{5}hello\r\n\r\n".to_owned(),
    ];
    for request in &malformed {
        let mut stream = client(&broker);
        stream.write_all(request.as_bytes()).expect("send request");
        assert_eq!(
            read_status(&mut stream),
            "HTTP/1.1 400 Bad Request",
            "request {request:?} must be refused"
        );
    }

    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        destination.accepts(),
        0,
        "a malformed request must never reach a dial"
    );
    assert_eq!(
        broker.stats().refused_malformed,
        malformed.len() as u64,
        "every malformed request is counted as one"
    );
}

#[test]
fn an_empty_allowlist_refuses_every_destination_without_dialling() {
    let destination = FakeDestination::spawn(Behaviour::Echo);
    let broker = EgressBroker::start(BrokerConfig::new(DestinationAllowlist::deny_all()))
        .expect("broker start");

    let mut stream = client(&broker);
    write!(
        stream,
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n",
        destination.port()
    )
    .expect("send CONNECT");
    assert_eq!(read_status(&mut stream), "HTTP/1.1 403 Forbidden");

    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        destination.accepts(),
        0,
        "deny-all must refuse before any dial"
    );
    assert_eq!(broker.stats().denied_destination, 1);
    assert_eq!(broker.stats().established, 0);
}

#[test]
fn an_oversized_request_head_is_refused_rather_than_buffered() {
    let destination = FakeDestination::spawn(Behaviour::Echo);
    let broker = broker_allowing("127.0.0.1", destination.port(), AddressScope::Loopback);

    let mut stream = client(&broker);
    let head = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nX-Pad: {}\r\n\r\n",
        destination.port(),
        "v".repeat(16 * 1024)
    );
    // The broker may close mid-write once the bound is exceeded, which is the
    // point: it is not obliged to read an unbounded head to say no.
    let _ = stream.write_all(head.as_bytes());
    let status = read_status(&mut stream);
    assert!(
        status.starts_with("HTTP/1.1 400") || status.is_empty(),
        "an oversized head must be refused or dropped, got {status:?}"
    );
    assert_eq!(destination.accepts(), 0);
}

#[test]
fn a_client_that_sends_nothing_is_closed_at_the_head_deadline() {
    let destination = FakeDestination::spawn(Behaviour::Echo);
    let allowlist = DestinationAllowlist::deny_all()
        .allowing("127.0.0.1", destination.port(), AddressScope::Loopback)
        .expect("allowlist entry");
    let broker =
        EgressBroker::start(BrokerConfig::new(allowlist).with_head_timeout(SHORT_DEADLINE))
            .expect("broker start");

    let started = Instant::now();
    let mut stream = client(&broker);
    let status = read_status(&mut stream);
    let elapsed = started.elapsed();

    assert_eq!(status, "HTTP/1.1 408 Request Timeout");
    assert!(
        elapsed < Duration::from_secs(2),
        "the head deadline must fire, not hang: took {elapsed:?}"
    );
    assert_eq!(broker.stats().refused_malformed, 1);
}

#[test]
fn a_silent_destination_ends_the_tunnel_at_the_idle_deadline_rather_than_hanging() {
    let destination = FakeDestination::spawn(Behaviour::Silent);
    let allowlist = DestinationAllowlist::deny_all()
        .allowing("127.0.0.1", destination.port(), AddressScope::Loopback)
        .expect("allowlist entry");
    let broker =
        EgressBroker::start(BrokerConfig::new(allowlist).with_idle_timeout(SHORT_DEADLINE))
            .expect("broker start");

    let mut stream = client(&broker);
    write!(
        stream,
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n",
        destination.port()
    )
    .expect("send CONNECT");
    assert_eq!(
        read_status(&mut stream),
        "HTTP/1.1 200 Connection Established"
    );
    stream.write_all(b"anybody there?").expect("client write");

    let started = Instant::now();
    let mut buffer = Vec::new();
    stream
        .read_to_end(&mut buffer)
        .expect("the tunnel must close rather than stay open");
    let elapsed = started.elapsed();

    assert!(buffer.is_empty(), "a silent destination sends nothing back");
    assert!(
        elapsed < Duration::from_secs(2),
        "the idle deadline must tear the tunnel down: took {elapsed:?}"
    );
    assert_eq!(destination.accepts(), 1);
}

#[test]
fn early_data_pipelined_behind_the_head_reaches_the_destination_in_order() {
    let destination = FakeDestination::spawn(Behaviour::Echo);
    let broker = broker_allowing("127.0.0.1", destination.port(), AddressScope::Loopback);

    let mut stream = client(&broker);
    // Head and first payload in a single write, as a client that does not wait
    // for the 200 would send them.
    let mut request =
        format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", destination.port()).into_bytes();
    request.extend_from_slice(b"EARLY");
    stream
        .write_all(&request)
        .expect("send CONNECT and early data");

    assert_eq!(
        read_status(&mut stream),
        "HTTP/1.1 200 Connection Established"
    );
    stream.write_all(b"LATE").expect("client write");
    stream.shutdown(Shutdown::Write).expect("client half-close");

    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).expect("read the echo back");
    assert_eq!(
        echoed, b"EARLYLATE",
        "early data must be forwarded before anything the relay carries"
    );
    assert_eq!(destination.received(), b"EARLYLATE");
    let stats = eventually(&broker, |stats| stats.bytes_to_destination == 9);
    assert_eq!(
        stats.bytes_to_destination, 9,
        "the early bytes are counted towards the destination like any other"
    );
}

/// The allowlist names a *name*; the resolver decides what it points at. A
/// public destination that resolves onto this host is a rebinding attempt and
/// must be refused after resolution and before the dial.
#[test]
fn a_public_destination_that_resolves_onto_this_host_is_refused_before_dialling() {
    let destination = FakeDestination::spawn(Behaviour::Echo);
    let broker = broker_allowing("localhost", destination.port(), AddressScope::Public);

    let mut stream = client(&broker);
    write!(
        stream,
        "CONNECT localhost:{} HTTP/1.1\r\n\r\n",
        destination.port()
    )
    .expect("send CONNECT");
    assert_eq!(read_status(&mut stream), "HTTP/1.1 403 Forbidden");

    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        destination.accepts(),
        0,
        "a rebound name must be refused before the dial, not after"
    );
    assert_eq!(broker.stats().denied_scope, 1);
    assert_eq!(broker.stats().denied_destination, 0, "the name did match");
}

#[test]
fn the_connection_cap_answers_rather_than_growing_without_bound() {
    let destination = FakeDestination::spawn(Behaviour::Echo);
    let allowlist = DestinationAllowlist::deny_all()
        .allowing("127.0.0.1", destination.port(), AddressScope::Loopback)
        .expect("allowlist entry");
    let broker = EgressBroker::start(
        BrokerConfig::new(allowlist)
            .with_max_connections(1)
            .with_head_timeout(Duration::from_secs(3)),
    )
    .expect("broker start");

    // The first client takes the only slot by connecting and staying quiet.
    let _holder = client(&broker);
    // Give the handler time to register before the second client arrives.
    thread::sleep(Duration::from_millis(200));

    let mut second = client(&broker);
    assert_eq!(read_status(&mut second), "HTTP/1.1 503 Service Unavailable");
    assert_eq!(broker.stats().refused_saturated, 1);
}

#[test]
fn shutdown_tears_down_an_established_tunnel() {
    let destination = FakeDestination::spawn(Behaviour::Echo);
    let broker = broker_allowing("127.0.0.1", destination.port(), AddressScope::Loopback);

    let mut stream = client(&broker);
    write!(
        stream,
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n",
        destination.port()
    )
    .expect("send CONNECT");
    assert_eq!(
        read_status(&mut stream),
        "HTTP/1.1 200 Connection Established"
    );

    let started = Instant::now();
    broker.shutdown();
    let mut buffer = Vec::new();
    // The client's own read timeout is the bound: if shutdown did not reach the
    // tunnel, this returns a timeout error rather than end of stream.
    let read = stream.read_to_end(&mut buffer);
    let elapsed = started.elapsed();

    assert!(
        read.is_ok(),
        "shutdown must close the tunnel, not leave the client waiting: {read:?}"
    );
    assert!(buffer.is_empty(), "a torn-down tunnel carries nothing");
    assert!(
        elapsed < Duration::from_secs(2),
        "shutdown must reach in-flight tunnels: took {elapsed:?}"
    );
    assert!(
        TcpStream::connect_timeout(&broker.local_addr(), Duration::from_millis(500)).is_err(),
        "the listener must be closed after shutdown"
    );
}
