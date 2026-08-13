// SPDX-License-Identifier: Elastic-2.0

//! Exercised proof of the runner control socket.
//!
//! These tests speak the real wire protocol over a real Unix socket in a
//! private temporary directory, against a server bound to real [`Spool`]s with
//! real appended events. Nothing is simulated: no in-process shortcut around
//! `accept`, no fake spool and no stubbed framing.
//!
//! Byte-exactness is deliberate. Several tests compare the whole response
//! against literal bytes rather than asserting that "some lines came back", so
//! dropping a cursor filter, reordering a field or changing a state spelling
//! fails a test instead of quietly changing the protocol.
//!
//! # Honest limit on the authentication proof
//!
//! Connecting to the socket as a *different* UID needs privilege this test
//! process does not have, so the end-to-end tests can only prove the positive
//! half: a same-UID peer is admitted and greeted. The negative half is proved
//! at the unit level instead — [`admit_peer`] is called directly with
//! synthetic [`PeerIdentity`] values for a foreign UID, root and an
//! implausible PID. That is a real proof about the exact function the server
//! calls before it reads a request byte, but it is not a proof that the kernel
//! reports what we think it reports; the same-UID connect tests cover that
//! side. A privileged integration test that connects as another user would be
//! needed to close the gap, and is not attempted here rather than being
//! silently claimed.
//!
//! The server refuses to exist under a root effective UID, so a root test run
//! fails loudly at `bind` rather than silently admitting root peers.

use automonique_runner::control::{
    CONTROL_GREETING, CancelSink, CancelUnavailable, ControlError, ControlServer, MAX_BINDINGS,
    MAX_CANCEL_LEDGER_ENTRIES, MAX_REQUEST_LINE_BYTES, MAX_SUBSCRIBE_PAGE_EVENTS, PeerIdentity,
    PeerRefusal, Refusal, Served, admit_peer,
};
use automonique_runner::{Authority, CancellationToken, EventKind, Spool};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

const SPOOL_MAX_BYTES: u64 = 1024 * 1024;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        // Short by construction: the socket path must fit `sun_path`.
        let path = std::env::temp_dir().join(format!("amq-c-{label}-{serial}"));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A cancel sink that flips a real [`CancellationToken`] and counts how many
/// times the server actually called it.
///
/// The count is what makes the idempotency test have teeth: a replay must not
/// merely return `already_delivered`, it must not reach the sink at all.
struct TokenSink {
    token: CancellationToken,
    deliveries: Arc<AtomicUsize>,
    refs: Arc<std::sync::Mutex<Vec<String>>>,
    available: bool,
}

impl CancelSink for TokenSink {
    fn deliver(&self, _attempt_id: &str, request_ref: &str) -> Result<(), CancelUnavailable> {
        if !self.available {
            return Err(CancelUnavailable);
        }
        self.deliveries.fetch_add(1, Ordering::Release);
        self.refs.lock().unwrap().push(request_ref.to_owned());
        self.token.cancel();
        Ok(())
    }
}

/// Observation handles kept by the test after the sink is moved into a binding.
#[derive(Clone)]
struct SinkProbe {
    token: CancellationToken,
    deliveries: Arc<AtomicUsize>,
    refs: Arc<std::sync::Mutex<Vec<String>>>,
}

impl SinkProbe {
    fn new(available: bool) -> (Box<dyn CancelSink>, Self) {
        let probe = Self {
            token: CancellationToken::new(),
            deliveries: Arc::new(AtomicUsize::new(0)),
            refs: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let sink = TokenSink {
            token: probe.token.clone(),
            deliveries: Arc::clone(&probe.deliveries),
            refs: Arc::clone(&probe.refs),
            available,
        };
        (Box::new(sink), probe)
    }

    fn deliveries(&self) -> usize {
        self.deliveries.load(Ordering::Acquire)
    }

    fn delivered_refs(&self) -> Vec<String> {
        self.refs.lock().unwrap().clone()
    }
}

/// A server running on a thread this harness owns and joins.
///
/// `stop` is checked between accepts, so the thread always terminates and the
/// server is dropped on that thread — which is what unlinks the socket inode.
/// No test may leak a thread or a socket.
struct Harness {
    socket_path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Harness {
    fn spawn(server: ControlServer) -> Self {
        let socket_path = server.socket_path().to_path_buf();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            let mut server = server;
            while !flag.load(Ordering::Acquire) {
                if server.serve_once(Duration::from_millis(20)).is_err() {
                    break;
                }
            }
        });
        Self {
            socket_path,
            stop,
            thread: Some(thread),
        }
    }

    fn path(&self) -> &Path {
        &self.socket_path
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Send one request line and read the whole response, returning the greeting
/// and the body separately.
fn exchange(socket_path: &Path, request: &str) -> (String, String) {
    exchange_bytes(socket_path, request.as_bytes())
}

fn exchange_bytes(socket_path: &Path, request: &[u8]) -> (String, String) {
    let mut stream = UnixStream::connect(socket_path).unwrap();
    stream.set_read_timeout(Some(CLIENT_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(CLIENT_TIMEOUT)).unwrap();
    stream.write_all(request).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (greeting, body) = response
        .split_once('\n')
        .expect("server must greet before answering");
    (greeting.to_owned(), body.to_owned())
}

/// Body of one exchange, asserting the versioned greeting arrived first.
fn body(socket_path: &Path, request: &str) -> String {
    let (greeting, body) = exchange(socket_path, request);
    assert_eq!(greeting, CONTROL_GREETING);
    body
}

fn spool_with(root: &Path, run_id: &str, events: &[(EventKind, Authority, &[u8])]) -> Spool {
    let mut spool = Spool::open(root.join(run_id), run_id, SPOOL_MAX_BYTES).unwrap();
    for (kind, authority, payload) in events {
        spool.append(*kind, *authority, payload).unwrap();
    }
    spool
}

fn empty_spool(root: &Path, run_id: &str) -> Spool {
    spool_with(root, run_id, &[])
}

// --- authentication -------------------------------------------------------

#[test]
fn admit_peer_refuses_a_foreign_uid() {
    // Synthetic credentials: this process cannot connect as another UID, so
    // the refusal is proved against the exact function the server calls.
    let admitted = 1000;
    assert_eq!(
        admit_peer(PeerIdentity::new(1001, 1001, 4242), admitted),
        Err(PeerRefusal::ForeignUid)
    );
    assert_eq!(
        admit_peer(PeerIdentity::new(0, 0, 4242), admitted),
        Err(PeerRefusal::RootPeer)
    );
    // A root server would have to admit root, so it is refused from both sides.
    assert_eq!(
        admit_peer(PeerIdentity::new(1000, 1000, 4242), 0),
        Err(PeerRefusal::RootPeer)
    );
    assert_eq!(
        admit_peer(PeerIdentity::new(admitted, 1000, 0), admitted),
        Err(PeerRefusal::ImplausiblePid)
    );
    // GID is diagnostic only: a wildly different GID changes no decision.
    assert_eq!(
        admit_peer(PeerIdentity::new(admitted, 65534, 7), admitted),
        Ok(())
    );
}

#[test]
fn same_uid_peer_is_admitted_and_greeted() {
    let dir = TempDir::new("greet");
    let server = ControlServer::bind(dir.path().join("run/control.sock")).unwrap();
    assert_eq!(server.admitted_uid(), nix::unistd::geteuid().as_raw());
    let mut harness = Harness::spawn(server);

    let (greeting, body) = exchange(harness.path(), "heartbeat\n");
    assert_eq!(greeting, CONTROL_GREETING);
    assert!(body.starts_with("heartbeat "), "unexpected body: {body}");

    harness.stop();
}

// --- inspect --------------------------------------------------------------

#[test]
fn inspect_reflects_real_appended_events_byte_for_byte() {
    let dir = TempDir::new("inspect");
    let spools = TempDir::new("inspect-spools");
    let mut server = ControlServer::bind(dir.path().join("run/control.sock")).unwrap();
    let (sink, _probe) = SinkProbe::new(true);
    let spool = spool_with(
        spools.path(),
        "run-alpha",
        &[
            (EventKind::Started, Authority::Authoritative, b""),
            (EventKind::AdapterEvent, Authority::Synthetic, b"hello"),
        ],
    );
    server.register("attempt-1", spool, sink).unwrap();
    let mut harness = Harness::spawn(server);

    assert_eq!(
        body(harness.path(), "inspect attempt-1\n"),
        "status attempt-1 run-alpha running 2\n"
    );

    harness.stop();
}

#[test]
fn inspect_reports_an_empty_spool_as_ready_and_a_terminal_spool_exactly() {
    let dir = TempDir::new("states");
    let spools = TempDir::new("states-spools");
    let mut server = ControlServer::bind(dir.path().join("run/control.sock")).unwrap();
    let (empty_sink, _empty_probe) = SinkProbe::new(true);
    let (done_sink, _done_probe) = SinkProbe::new(true);
    server
        .register(
            "attempt-empty",
            empty_spool(spools.path(), "run-empty"),
            empty_sink,
        )
        .unwrap();
    server
        .register(
            "attempt-done",
            spool_with(
                spools.path(),
                "run-done",
                &[
                    (EventKind::Started, Authority::Authoritative, b"go"),
                    (EventKind::Terminal, Authority::Authoritative, b"cancelled"),
                ],
            ),
            done_sink,
        )
        .unwrap();
    let mut harness = Harness::spawn(server);

    assert_eq!(
        body(harness.path(), "inspect attempt-empty\n"),
        "status attempt-empty run-empty ready 0\n"
    );
    assert_eq!(
        body(harness.path(), "inspect attempt-done\n"),
        "status attempt-done run-done cancelled 2\n"
    );

    harness.stop();
}

#[test]
fn unknown_and_malformed_attempts_are_typed_refusals() {
    let dir = TempDir::new("unknown");
    let spools = TempDir::new("unknown-spools");
    let mut server = ControlServer::bind(dir.path().join("run/control.sock")).unwrap();
    let (sink, _probe) = SinkProbe::new(true);
    server
        .register("attempt-1", empty_spool(spools.path(), "run-alpha"), sink)
        .unwrap();
    let mut harness = Harness::spawn(server);

    assert_eq!(
        body(harness.path(), "inspect attempt-missing\n"),
        "refused target_unknown\n"
    );
    assert_eq!(
        body(harness.path(), "subscribe attempt-missing 0\n"),
        "refused target_unknown\n"
    );
    // An out-of-grammar spelling is refused before the registry is consulted,
    // so a probe cannot use the refusal to learn which attempts exist.
    assert_eq!(
        body(harness.path(), "inspect attempt/../1\n"),
        "refused field_invalid\n"
    );
    assert_eq!(
        body(harness.path(), &format!("inspect {}\n", "a".repeat(65))),
        "refused field_invalid\n"
    );
    assert_eq!(
        body(harness.path(), "explode\n"),
        "refused unknown_operation\n"
    );
    assert_eq!(
        body(harness.path(), "inspect attempt-1 extra\n"),
        "refused unknown_operation\n"
    );

    harness.stop();
}

// --- subscribe ------------------------------------------------------------

#[test]
fn subscribe_from_zero_replays_every_event_byte_for_byte() {
    let dir = TempDir::new("sub0");
    let spools = TempDir::new("sub0-spools");
    let mut server = ControlServer::bind(dir.path().join("run/control.sock")).unwrap();
    let (sink, _probe) = SinkProbe::new(true);
    server
        .register(
            "attempt-1",
            spool_with(
                spools.path(),
                "run-alpha",
                &[
                    (EventKind::Started, Authority::Authoritative, b""),
                    (EventKind::AdapterEvent, Authority::Synthetic, b"hello"),
                    (
                        EventKind::CancelRequested,
                        Authority::Authoritative,
                        b"\x00\xff",
                    ),
                ],
            ),
            sink,
        )
        .unwrap();
    let mut harness = Harness::spawn(server);

    // Anti-vacuity: the entire page is compared to literal bytes.
    let expected = "event 1 started authoritative -\n\
                    event 2 adapter_event synthetic 68656c6c6f\n\
                    event 3 cancel_requested authoritative 00ff\n\
                    end 3 false\n";
    assert_eq!(body(harness.path(), "subscribe attempt-1 0\n"), expected);

    // Two independent subscribers observe identical pages.
    assert_eq!(body(harness.path(), "subscribe attempt-1 0\n"), expected);

    // A mid-cursor resumes strictly after that sequence.
    assert_eq!(
        body(harness.path(), "subscribe attempt-1 2\n"),
        "event 3 cancel_requested authoritative 00ff\nend 3 false\n"
    );
    // The last sequence is an empty, non-advancing page.
    assert_eq!(
        body(harness.path(), "subscribe attempt-1 3\n"),
        "end 3 false\n"
    );
    // Ahead of the spool is a typed refusal, never a silent empty page.
    assert_eq!(
        body(harness.path(), "subscribe attempt-1 4\n"),
        "refused cursor_ahead\n"
    );
    // Noncanonical cursors never reach the spool.
    assert_eq!(
        body(harness.path(), "subscribe attempt-1 01\n"),
        "refused field_invalid\n"
    );
    assert_eq!(
        body(harness.path(), "subscribe attempt-1 -1\n"),
        "refused field_invalid\n"
    );

    harness.stop();
}

#[test]
fn subscribe_pages_are_bounded_and_report_continuation() {
    let dir = TempDir::new("page");
    let spools = TempDir::new("page-spools");
    let mut server = ControlServer::bind(dir.path().join("run/control.sock")).unwrap();
    let (sink, _probe) = SinkProbe::new(true);
    let total = MAX_SUBSCRIBE_PAGE_EVENTS + 2;
    let mut spool =
        Spool::open(spools.path().join("run-page"), "run-page", SPOOL_MAX_BYTES).unwrap();
    for index in 0..total {
        spool
            .append(
                EventKind::SimulationEvent,
                Authority::Synthetic,
                format!("step{index}").as_bytes(),
            )
            .unwrap();
    }
    server.register("attempt-1", spool, sink).unwrap();
    let mut harness = Harness::spawn(server);

    let first = body(harness.path(), "subscribe attempt-1 0\n");
    let lines: Vec<&str> = first.lines().collect();
    assert_eq!(lines.len(), MAX_SUBSCRIBE_PAGE_EVENTS + 1);
    assert_eq!(lines[0], "event 1 simulation_event synthetic 7374657030");
    assert_eq!(
        *lines.last().unwrap(),
        format!("end {MAX_SUBSCRIBE_PAGE_EVENTS} true")
    );

    // Resuming from the reported cursor yields exactly the tail, once.
    let second = body(
        harness.path(),
        &format!("subscribe attempt-1 {MAX_SUBSCRIBE_PAGE_EVENTS}\n"),
    );
    assert_eq!(
        second,
        format!(
            "event {} simulation_event synthetic {}\nevent {} simulation_event synthetic {}\nend {total} false\n",
            total - 1,
            hex(format!("step{}", total - 2).as_bytes()),
            total,
            hex(format!("step{}", total - 1).as_bytes()),
        )
    );

    harness.stop();
}

// --- cancel ---------------------------------------------------------------

#[test]
fn cancel_delivers_once_and_replays_idempotently() {
    let dir = TempDir::new("cancel");
    let spools = TempDir::new("cancel-spools");
    let mut server = ControlServer::bind(dir.path().join("run/control.sock")).unwrap();
    let (sink, probe) = SinkProbe::new(true);
    server
        .register("attempt-1", empty_spool(spools.path(), "run-alpha"), sink)
        .unwrap();
    let mut harness = Harness::spawn(server);

    assert!(!probe.token.is_cancelled());
    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-a\n"),
        "cancel_result delivered\n"
    );
    // The sink observably fired: a real cancellation token flipped.
    assert!(probe.token.is_cancelled());
    assert_eq!(probe.deliveries(), 1);
    assert_eq!(probe.delivered_refs(), vec!["ref-a".to_owned()]);

    // Exact replay is already-delivered and must not reach the sink again.
    for _ in 0..3 {
        assert_eq!(
            body(harness.path(), "cancel attempt-1 ref-a\n"),
            "cancel_result already_delivered\n"
        );
    }
    assert_eq!(probe.deliveries(), 1);

    // A distinct reference against the same attempt is a real second delivery.
    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-b\n"),
        "cancel_result delivered\n"
    );
    assert_eq!(probe.deliveries(), 2);

    // Delivery is not exit evidence: the spool never moved.
    assert_eq!(
        body(harness.path(), "inspect attempt-1\n"),
        "status attempt-1 run-alpha ready 0\n"
    );

    harness.stop();
}

#[test]
fn reusing_a_request_reference_across_attempts_conflicts() {
    let dir = TempDir::new("conflict");
    let spools = TempDir::new("conflict-spools");
    let mut server = ControlServer::bind(dir.path().join("run/control.sock")).unwrap();
    let (first_sink, first) = SinkProbe::new(true);
    let (second_sink, second) = SinkProbe::new(true);
    server
        .register(
            "attempt-1",
            empty_spool(spools.path(), "run-one"),
            first_sink,
        )
        .unwrap();
    server
        .register(
            "attempt-2",
            empty_spool(spools.path(), "run-two"),
            second_sink,
        )
        .unwrap();
    let mut harness = Harness::spawn(server);

    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-shared\n"),
        "cancel_result delivered\n"
    );
    assert_eq!(
        body(harness.path(), "cancel attempt-2 ref-shared\n"),
        "refused cancel_conflict\n"
    );
    // The conflict signalled nothing: the second attempt was never cancelled.
    assert_eq!(second.deliveries(), 0);
    assert!(!second.token.is_cancelled());
    assert_eq!(first.deliveries(), 1);

    harness.stop();
}

#[test]
fn cancel_refuses_unknown_targets_and_unavailable_sinks() {
    let dir = TempDir::new("cancel-neg");
    let spools = TempDir::new("cancel-neg-spools");
    let mut server = ControlServer::bind(dir.path().join("run/control.sock")).unwrap();
    let (sink, probe) = SinkProbe::new(false);
    server
        .register("attempt-1", empty_spool(spools.path(), "run-alpha"), sink)
        .unwrap();
    let mut harness = Harness::spawn(server);

    assert_eq!(
        body(harness.path(), "cancel attempt-missing ref-a\n"),
        "refused target_unknown\n"
    );
    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref with spaces\n"),
        "refused unknown_operation\n"
    );
    assert_eq!(
        body(
            harness.path(),
            &format!("cancel attempt-1 {}\n", "r".repeat(65))
        ),
        "refused field_invalid\n"
    );
    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-a\n"),
        "refused cancel_unavailable\n"
    );
    assert_eq!(probe.deliveries(), 0);
    // An unavailable delivery is not recorded, so a retry is a real attempt
    // rather than a false `already_delivered`.
    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-a\n"),
        "refused cancel_unavailable\n"
    );

    harness.stop();
}

#[test]
fn the_cancel_ledger_refuses_beyond_its_bound() {
    let dir = TempDir::new("ledger");
    let spools = TempDir::new("ledger-spools");
    let mut server = ControlServer::bind(dir.path().join("run/control.sock")).unwrap();
    let (sink, probe) = SinkProbe::new(true);
    server
        .register("attempt-1", empty_spool(spools.path(), "run-alpha"), sink)
        .unwrap();
    let mut harness = Harness::spawn(server);

    for index in 0..MAX_CANCEL_LEDGER_ENTRIES {
        assert_eq!(
            body(harness.path(), &format!("cancel attempt-1 ref-{index}\n")),
            "cancel_result delivered\n"
        );
    }
    assert_eq!(probe.deliveries(), MAX_CANCEL_LEDGER_ENTRIES);
    // Beyond the bound the server refuses instead of delivering something it
    // cannot deduplicate later.
    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-overflow\n"),
        "refused ledger_full\n"
    );
    assert_eq!(probe.deliveries(), MAX_CANCEL_LEDGER_ENTRIES);
    // Already-recorded references still replay.
    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-0\n"),
        "cancel_result already_delivered\n"
    );

    harness.stop();
}

// --- heartbeat ------------------------------------------------------------

#[test]
fn heartbeat_reports_only_server_liveness_and_binding_count() {
    let dir = TempDir::new("beat");
    let spools = TempDir::new("beat-spools");
    let mut server = ControlServer::bind(dir.path().join("run/control.sock")).unwrap();
    let (first_sink, _first) = SinkProbe::new(true);
    let (second_sink, _second) = SinkProbe::new(true);
    server
        .register(
            "attempt-1",
            spool_with(
                spools.path(),
                "run-one",
                &[(
                    EventKind::Started,
                    Authority::Authoritative,
                    b"secret-payload",
                )],
            ),
            first_sink,
        )
        .unwrap();
    server
        .register(
            "attempt-2",
            empty_spool(spools.path(), "run-two"),
            second_sink,
        )
        .unwrap();
    let mut harness = Harness::spawn(server);

    let before = body(harness.path(), "inspect attempt-1\n");
    let first = body(harness.path(), "heartbeat\n");
    let fields: Vec<&str> = first.trim_end().split(' ').collect();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0], "heartbeat");
    let first_uptime: u64 = fields[1].parse().unwrap();
    assert_eq!(fields[2], "2");

    // No attempt, run or payload identity leaks into liveness.
    for sentinel in [
        "attempt-1",
        "attempt-2",
        "run-one",
        "secret-payload",
        "73656372",
    ] {
        assert!(
            !first.contains(sentinel),
            "heartbeat leaked {sentinel}: {first}"
        );
    }

    std::thread::sleep(Duration::from_millis(15));
    let second = body(harness.path(), "heartbeat\n");
    let second_uptime: u64 = second
        .trim_end()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    assert!(second_uptime > first_uptime, "uptime did not advance");

    // Heartbeats mutate nothing: status and cursor are unchanged.
    assert_eq!(body(harness.path(), "inspect attempt-1\n"), before);
    assert_eq!(
        body(harness.path(), "subscribe attempt-1 0\n"),
        "event 1 started authoritative 7365637265742d7061796c6f6164\nend 1 false\n"
    );

    harness.stop();
}

// --- bounds and lifecycle -------------------------------------------------

#[test]
fn an_oversized_request_line_is_refused() {
    let dir = TempDir::new("big");
    let server = ControlServer::bind(dir.path().join("run/control.sock")).unwrap();
    let mut harness = Harness::spawn(server);

    let mut request = Vec::with_capacity(MAX_REQUEST_LINE_BYTES + 2);
    request.extend(std::iter::repeat_n(b'a', MAX_REQUEST_LINE_BYTES + 1));
    request.push(b'\n');
    let (greeting, refusal) = exchange_bytes(harness.path(), &request);
    assert_eq!(greeting, CONTROL_GREETING);
    assert_eq!(refusal, "refused request_too_large\n");

    // A line exactly at the ceiling still reaches the parser, which refuses it
    // for its content rather than its size.
    let mut exact = Vec::with_capacity(MAX_REQUEST_LINE_BYTES + 1);
    exact.extend(std::iter::repeat_n(b'a', MAX_REQUEST_LINE_BYTES));
    exact.push(b'\n');
    let (_, refusal) = exchange_bytes(harness.path(), &exact);
    assert_eq!(refusal, "refused unknown_operation\n");

    // Exactly one request per connection: trailing bytes are refused.
    let (_, refusal) = exchange_bytes(harness.path(), b"heartbeat\nheartbeat\n");
    assert_eq!(refusal, "refused malformed_request\n");

    // Invalid UTF-8 never reaches the router.
    let (_, refusal) = exchange_bytes(harness.path(), b"inspect \xff\xfe\n");
    assert_eq!(refusal, "refused malformed_request\n");

    harness.stop();
}

#[test]
fn a_request_that_never_terminates_is_bounded_before_the_terminator() {
    // The ceiling must hold on the *unterminated* path too. A peer that just
    // keeps writing without a newline would otherwise make the server buffer
    // without limit; the refusal has to arrive from the accumulated length
    // alone, never from finding a terminator.
    let dir = TempDir::new("noeol");
    let server = ControlServer::bind(dir.path().join("run/control.sock")).unwrap();
    let mut harness = Harness::spawn(server);

    let flood = vec![b'a'; MAX_REQUEST_LINE_BYTES * 2];
    assert!(!flood.contains(&b'\n'));
    let (greeting, refusal) = exchange_bytes(harness.path(), &flood);
    assert_eq!(greeting, CONTROL_GREETING);
    assert_eq!(refusal, "refused request_too_large\n");

    // The server survived the flood and still answers.
    assert!(body(harness.path(), "heartbeat\n").starts_with("heartbeat "));

    harness.stop();
}

#[test]
fn the_binding_registry_is_bounded_and_never_replaces_a_live_binding() {
    let dir = TempDir::new("bindings");
    let spools = TempDir::new("bindings-spools");
    let mut server = ControlServer::bind(dir.path().join("run/control.sock")).unwrap();
    for index in 0..MAX_BINDINGS {
        let (sink, _probe) = SinkProbe::new(true);
        let run_id = format!("run-{index}");
        server
            .register(&run_id, empty_spool(spools.path(), &run_id), sink)
            .unwrap();
    }
    assert_eq!(server.binding_count(), MAX_BINDINGS);

    let (sink, _probe) = SinkProbe::new(true);
    let overflow = empty_spool(spools.path(), "run-overflow");
    assert!(matches!(
        server.register("run-overflow", overflow, sink),
        Err(ControlError::BindingLimit)
    ));
    assert_eq!(server.binding_count(), MAX_BINDINGS);

    // A duplicate is refused before the limit is even consulted.
    let (sink, _probe) = SinkProbe::new(true);
    let duplicate = empty_spool(spools.path(), "run-duplicate");
    assert!(matches!(
        server.register("run-0", duplicate, sink),
        Err(ControlError::DuplicateAttempt)
    ));

    // Unregistering returns the observer and makes room again.
    let returned = server.unregister("run-0").unwrap();
    assert_eq!(returned.status().run_id(), "run-0");
    assert_eq!(server.binding_count(), MAX_BINDINGS - 1);
    assert!(matches!(
        server.unregister("run-0"),
        Err(ControlError::UnknownAttempt)
    ));
}

#[test]
fn registration_refuses_identifiers_outside_the_wire_grammar() {
    let dir = TempDir::new("ids");
    let spools = TempDir::new("ids-spools");
    let mut server = ControlServer::bind(dir.path().join("run/control.sock")).unwrap();

    let (sink, _probe) = SinkProbe::new(true);
    assert!(matches!(
        server.register("attempt one", empty_spool(spools.path(), "run-a"), sink),
        Err(ControlError::InvalidIdentifier("attempt id"))
    ));
    // A run identifier that could not be spelled on the wire is refused at
    // registration rather than producing an ambiguous status line.
    let (sink, _probe) = SinkProbe::new(true);
    let odd = Spool::open(
        spools.path().join("odd"),
        "run with spaces",
        SPOOL_MAX_BYTES,
    )
    .unwrap();
    assert!(matches!(
        server.register("attempt-1", odd, sink),
        Err(ControlError::InvalidIdentifier("run id"))
    ));
    assert_eq!(server.binding_count(), 0);
}

#[test]
fn socket_paths_and_directories_are_validated_before_bind() {
    let dir = TempDir::new("paths");

    // `sun_path` overflow refuses before any filesystem call.
    let long = dir.path().join("x".repeat(200));
    assert!(matches!(
        ControlServer::bind(&long),
        Err(ControlError::SocketPathTooLong)
    ));
    assert!(!long.exists());

    assert!(matches!(
        ControlServer::bind(PathBuf::from("relative.sock")),
        Err(ControlError::SocketPathNotAbsolute)
    ));

    // A group-writable directory is not private.
    let loose = dir.path().join("loose");
    fs::create_dir(&loose).unwrap();
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(matches!(
        ControlServer::bind(loose.join("control.sock")),
        Err(ControlError::UnsafeDirectory)
    ));

    // A non-socket squatting on the name is never unlinked.
    let occupied = dir.path().join("occupied");
    fs::create_dir(&occupied).unwrap();
    fs::set_permissions(&occupied, fs::Permissions::from_mode(0o700)).unwrap();
    let squatter = occupied.join("control.sock");
    fs::write(&squatter, b"not a socket").unwrap();
    assert!(matches!(
        ControlServer::bind(&squatter),
        Err(ControlError::UnsafeSocket)
    ));
    assert_eq!(fs::read(&squatter).unwrap(), b"not a socket");
}

#[test]
fn a_live_socket_refuses_a_second_bind_and_shutdown_removes_only_its_own_inode() {
    let dir = TempDir::new("life");
    let socket_path = dir.path().join("run/control.sock");
    let server = ControlServer::bind(&socket_path).unwrap();
    assert!(socket_path.exists());
    let mut harness = Harness::spawn(server);

    // A live listener is not stale, so the path is never unlinked from under it.
    assert!(matches!(
        ControlServer::bind(&socket_path),
        Err(ControlError::SocketInUse)
    ));
    // The original endpoint still answers.
    assert!(body(harness.path(), "heartbeat\n").starts_with("heartbeat "));

    harness.stop();
    assert!(
        !socket_path.exists(),
        "shutdown must remove the socket inode it created"
    );

    // Rebinding after a clean shutdown succeeds, with a fresh uptime and no
    // inherited bindings or ledger.
    let restarted = ControlServer::bind(&socket_path).unwrap();
    let mut restarted = Harness::spawn(restarted);
    let beat = body(restarted.path(), "heartbeat\n");
    let fields: Vec<&str> = beat.trim_end().split(' ').collect();
    assert_eq!(fields[0], "heartbeat");
    assert!(fields[1].parse::<u64>().unwrap() < 5_000);
    assert_eq!(fields[2], "0");
    restarted.stop();
}

#[test]
fn the_refusal_category_set_is_closed_and_stable() {
    // Every category a client can observe, pinned by spelling. Renaming one is
    // a wire change and must fail here rather than in a caller.
    let categories = [
        (Refusal::FieldInvalid, "field_invalid"),
        (Refusal::UnknownOperation, "unknown_operation"),
        (Refusal::MalformedRequest, "malformed_request"),
        (Refusal::RequestTooLarge, "request_too_large"),
        (Refusal::TargetUnknown, "target_unknown"),
        (Refusal::CursorAhead, "cursor_ahead"),
        (Refusal::CancelConflict, "cancel_conflict"),
        (Refusal::CancelUnavailable, "cancel_unavailable"),
        (Refusal::LedgerFull, "ledger_full"),
        (Refusal::Internal, "internal"),
    ];
    for (refusal, spelling) in categories {
        assert_eq!(refusal.as_str(), spelling);
        assert_eq!(
            refusal.to_string(),
            format!("control request refused: {spelling}")
        );
    }
    for (refusal, spelling) in [
        (
            PeerRefusal::CredentialsUnavailable,
            "credentials_unavailable",
        ),
        (PeerRefusal::ForeignUid, "foreign_uid"),
        (PeerRefusal::RootPeer, "root_peer"),
        (PeerRefusal::ImplausiblePid, "implausible_pid"),
    ] {
        assert_eq!(refusal.as_str(), spelling);
    }
}

#[test]
fn serve_once_reports_an_idle_wait_without_a_peer() {
    let dir = TempDir::new("idle");
    let mut server = ControlServer::bind(dir.path().join("run/control.sock")).unwrap();
    assert_eq!(
        server.serve_once(Duration::from_millis(5)).unwrap(),
        Served::Idle
    );
    // A `Debug` rendering carries counts only, never identifiers.
    let rendered = format!("{server:?}");
    assert!(
        rendered.contains("bindings: 0"),
        "unexpected debug: {rendered}"
    );
    assert!(
        !rendered.contains("control.sock"),
        "debug leaked the path: {rendered}"
    );
}

#[test]
fn refusals_never_echo_request_bytes() {
    let dir = TempDir::new("echo");
    let spools = TempDir::new("echo-spools");
    let mut server = ControlServer::bind(dir.path().join("run/control.sock")).unwrap();
    let (sink, _probe) = SinkProbe::new(true);
    server
        .register(
            "attempt-1",
            spool_with(
                spools.path(),
                "run-alpha",
                &[(
                    EventKind::Started,
                    Authority::Authoritative,
                    b"sentinel-bytes",
                )],
            ),
            sink,
        )
        .unwrap();
    let mut harness = Harness::spawn(server);

    for request in [
        "inspect sentinel-attempt\n",
        "subscribe attempt-1 99\n",
        "cancel sentinel-attempt sentinel-ref\n",
        "sentinel-operation\n",
    ] {
        let refusal = body(harness.path(), request);
        assert!(refusal.starts_with("refused "), "not a refusal: {refusal}");
        assert!(
            !refusal.contains("sentinel"),
            "refusal echoed request bytes: {refusal}"
        );
        assert!(
            !refusal.contains(dir.path().to_str().unwrap()),
            "refusal echoed the socket path: {refusal}"
        );
    }

    // Allowed event bytes appear only in a subscription body.
    let page = body(harness.path(), "subscribe attempt-1 0\n");
    assert!(page.contains(&hex(b"sentinel-bytes")));

    harness.stop();
}

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push_str(&format!("{byte:02x}"));
    }
    result
}
