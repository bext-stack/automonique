// SPDX-License-Identifier: Elastic-2.0

//! Exercised proof of the operator's attempt-inspection commands.
//!
//! These tests drive the real command dispatch — `run(["attempt", ...])` — over
//! a real Unix socket against a real [`ControlServer`] bound to real [`Spool`]s
//! with real appended events. Nothing is simulated: no in-process shortcut
//! around `connect`, no fake protocol for the success paths, and no stubbed
//! rendering.
//!
//! Byte-exactness is deliberate. The rendered pages are compared against
//! literal bytes, so dropping a cursor filter, reordering a field, changing a
//! state spelling or losing the hex fallback fails a test instead of quietly
//! changing what an operator reads.
//!
//! Two properties need a server that does *not* speak the protocol, so those
//! tests bind a plain listener instead: one greets with the wrong version and
//! records how many request bytes it received, the other floods past the
//! response ceiling. Both are about what the client refuses to do, which a
//! well-behaved server cannot demonstrate.

use automonique_cli::run;
use automonique_runner::control::{
    CONTROL_GREETING, CancelSink, CancelUnavailable, ControlServer, MAX_IDENTIFIER_BYTES,
    MAX_RESPONSE_BYTES, MAX_SUBSCRIBE_PAGE_EVENTS, Served,
};
use automonique_runner::{Authority, EventKind, Spool};
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

const SPOOL_MAX_BYTES: u64 = 1024 * 1024;
const SERVER_TIMEOUT: Duration = Duration::from_secs(10);

// --- harness --------------------------------------------------------------

/// Counts how many times the endpoint actually reached a connected peer.
///
/// This is what gives the "refused before connecting" tests teeth: a client
/// that validated after `connect` would leave a non-zero count behind.
type Reached = Arc<AtomicUsize>;

struct CountingSink {
    deliveries: Arc<AtomicUsize>,
}

impl CancelSink for CountingSink {
    fn deliver(&self, _attempt_id: &str, _request_ref: &str) -> Result<(), CancelUnavailable> {
        self.deliveries.fetch_add(1, Ordering::Release);
        Ok(())
    }
}

struct EndpointBuilder {
    directory: tempfile::TempDir,
    spools: tempfile::TempDir,
    server: ControlServer,
}

impl EndpointBuilder {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("endpoint directory");
        let spools = tempfile::tempdir().expect("spool directory");
        let server =
            ControlServer::bind(directory.path().join("run/control.sock")).expect("control server");
        Self {
            directory,
            spools,
            server,
        }
    }

    /// Register one attempt backed by a real spool with real appended events,
    /// answering with the sink's delivery counter.
    fn attempt(
        &mut self,
        attempt_id: &str,
        run_id: &str,
        events: &[(EventKind, Authority, &[u8])],
    ) -> Arc<AtomicUsize> {
        let mut spool = Spool::open(self.spools.path().join(run_id), run_id, SPOOL_MAX_BYTES)
            .expect("spool opens");
        for (kind, authority, payload) in events {
            spool.append(*kind, *authority, payload).expect("append");
        }
        let deliveries = Arc::new(AtomicUsize::new(0));
        self.server
            .register(
                attempt_id,
                spool,
                Box::new(CountingSink {
                    deliveries: Arc::clone(&deliveries),
                }),
            )
            .expect("binding registers");
        deliveries
    }

    fn start(self) -> Endpoint {
        let socket_path = self.server.socket_path().to_path_buf();
        let stop = Arc::new(AtomicBool::new(false));
        let reached: Reached = Arc::new(AtomicUsize::new(0));
        let flag = Arc::clone(&stop);
        let counter = Arc::clone(&reached);
        let mut server = self.server;
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::Acquire) {
                match server.serve_once(Duration::from_millis(20)) {
                    Ok(Served::Idle) => {}
                    Ok(_) => {
                        counter.fetch_add(1, Ordering::Release);
                    }
                    Err(_) => break,
                }
            }
        });
        Endpoint {
            _directory: self.directory,
            _spools: self.spools,
            socket_path,
            stop,
            reached,
            thread: Some(thread),
        }
    }
}

struct Endpoint {
    _directory: tempfile::TempDir,
    _spools: tempfile::TempDir,
    socket_path: PathBuf,
    stop: Arc<AtomicBool>,
    reached: Reached,
    thread: Option<JoinHandle<()>>,
}

impl Endpoint {
    fn path(&self) -> &Path {
        &self.socket_path
    }

    /// Connections the server accepted. Read after [`Endpoint::stop`], so the
    /// serving thread has joined and the count is final.
    fn reached(&self) -> usize {
        self.reached.load(Ordering::Acquire)
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("serving thread");
        }
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.stop();
    }
}

/// One `attempt` invocation with the socket path in its usual position.
fn invocation(operation: &str, socket_path: &Path, rest: &[&str]) -> Vec<OsString> {
    let mut argv = vec![
        OsString::from("attempt"),
        OsString::from(operation),
        socket_path.as_os_str().to_owned(),
    ];
    argv.extend(rest.iter().map(OsString::from));
    argv
}

fn cli<I, S>(arguments: I) -> (u8, String, String)
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run(arguments, &mut stdout, &mut stderr);
    (
        exit,
        String::from_utf8(stdout).expect("stdout is UTF-8"),
        String::from_utf8(stderr).expect("stderr is UTF-8"),
    )
}

fn assert_bounded_usage(stderr: &str) {
    assert!(
        stderr.starts_with("usage: automonique doctor [--json]\n"),
        "not the usage string: {stderr}"
    );
    assert!(stderr.ends_with("       automonique shutdown\n"));
    // A ceiling on the usage text, not a ceiling on the command set: the
    // property is that a malformed invocation answers with a bounded usage
    // string rather than an unbounded dump. It rises when the product gains a
    // verb group, and every line the assertions below enumerate has to survive.
    assert!(stderr.len() <= 4 * 1024, "usage is {} bytes", stderr.len());
    for line in [
        "       automonique attempt heartbeat <socket-path>\n",
        "       automonique attempt inspect <socket-path> <attempt-id>\n",
        "       automonique attempt events <socket-path> <attempt-id> [cursor]\n",
        "       automonique attempt cancel <socket-path> <attempt-id> <request-ref>\n",
        "       automonique parity score <database> <scope>\n",
        "       automonique parity gate <database> <scope> <decision-key> <decider> [--registry <path>]\n",
    ] {
        assert!(stderr.contains(line), "usage lost {line:?}: {stderr}");
    }
}

/// A listener that is not this protocol, used to prove what the client refuses.
///
/// It accepts exactly one connection, writes `greeting` verbatim, optionally
/// answers with `flood` bytes once a request line arrives, and records how many
/// request bytes it received.
struct FakeEndpoint {
    _directory: tempfile::TempDir,
    socket_path: PathBuf,
    received: Arc<std::sync::Mutex<Vec<u8>>>,
    thread: Option<JoinHandle<()>>,
}

impl FakeEndpoint {
    fn spawn(greeting: Vec<u8>, flood: usize) -> Self {
        let directory = tempfile::tempdir().expect("fake directory");
        // The client requires the endpoint's directory to be private, exactly
        // as the real server's own `bind` does.
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private fake directory");
        let socket_path = directory.path().join("control.sock");
        let listener = UnixListener::bind(&socket_path).expect("fake listener");
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
            .expect("private fake socket");
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("fake accept");
            // An empty greeting means "close without speaking at all".
            if greeting.is_empty() {
                return;
            }
            stream
                .set_read_timeout(Some(SERVER_TIMEOUT))
                .expect("read deadline");
            stream
                .set_write_timeout(Some(SERVER_TIMEOUT))
                .expect("write deadline");
            let _ = stream.write_all(&greeting);
            let mut request = Vec::new();
            let mut chunk = [0_u8; 512];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        request.extend_from_slice(&chunk[..read]);
                        if request.contains(&b'\n') {
                            break;
                        }
                    }
                }
            }
            *sink.lock().expect("request sink") = request;
            if flood > 0 {
                let block = vec![b'x'; 64 * 1024];
                let mut written = 0;
                while written < flood {
                    if stream.write_all(&block).is_err() {
                        break;
                    }
                    written += block.len();
                }
            }
        });
        Self {
            _directory: directory,
            socket_path,
            received,
            thread: Some(thread),
        }
    }

    fn path(&self) -> &Path {
        &self.socket_path
    }

    fn join(&mut self) -> Vec<u8> {
        if let Some(thread) = self.thread.take() {
            thread.join().expect("fake server thread");
        }
        self.received.lock().expect("request sink").clone()
    }
}

impl Drop for FakeEndpoint {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// --- round trips against the real endpoint --------------------------------

#[test]
fn heartbeat_inspect_and_events_round_trip_byte_for_byte() {
    let mut builder = EndpointBuilder::new();
    builder.attempt(
        "attempt-1",
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
    );
    let mut endpoint = builder.start();

    let (exit, stdout, stderr) = cli(invocation("heartbeat", endpoint.path(), &[]));
    assert_eq!(exit, 0, "heartbeat stderr: {stderr}");
    assert!(stderr.is_empty());
    // Uptime is a live measurement, so only its spelling is pinned.
    let uptime = stdout
        .strip_prefix("Automonique attempt endpoint: uptime_ms=")
        .and_then(|rest| rest.strip_suffix(" bindings=1\n"))
        .unwrap_or_else(|| panic!("unexpected heartbeat rendering: {stdout:?}"));
    assert!(
        uptime.parse::<u64>().is_ok() && (uptime == "0" || !uptime.starts_with('0')),
        "uptime is not canonical decimal: {uptime:?}"
    );

    let (exit, stdout, stderr) = cli(invocation("inspect", endpoint.path(), &["attempt-1"]));
    assert_eq!(exit, 0, "inspect stderr: {stderr}");
    assert!(stderr.is_empty());
    assert_eq!(
        stdout,
        "Automonique attempt: attempt_id=attempt-1 run_id=run-alpha state=running last_sequence=3\n"
    );

    // The whole page is compared to literal bytes: a printable payload is text,
    // a payload with a NUL and a high byte keeps its hex spelling, and an empty
    // payload stays the endpoint's `-`.
    let (exit, stdout, stderr) = cli(invocation("events", endpoint.path(), &["attempt-1"]));
    assert_eq!(exit, 0, "events stderr: {stderr}");
    assert!(stderr.is_empty());
    assert_eq!(
        stdout,
        "Automonique attempt events: attempt_id=attempt-1 cursor=0\n\
         - seq=1 kind=started authority=authoritative payload=-\n\
         - seq=2 kind=adapter_event authority=synthetic payload=text:hello\n\
         - seq=3 kind=cancel_requested authority=authoritative payload=hex:00ff\n\
         next cursor: 3 more: false\n"
    );
    assert!(
        !stdout.contains('\u{0}') && stdout.is_ascii(),
        "payload bytes reached the terminal: {stdout:?}"
    );

    // A mid-cursor resumes strictly after that sequence.
    let (exit, stdout, _) = cli(invocation("events", endpoint.path(), &["attempt-1", "2"]));
    assert_eq!(exit, 0);
    assert_eq!(
        stdout,
        "Automonique attempt events: attempt_id=attempt-1 cursor=2\n\
         - seq=3 kind=cancel_requested authority=authoritative payload=hex:00ff\n\
         next cursor: 3 more: false\n"
    );

    endpoint.stop();
}

#[test]
fn a_page_is_bounded_and_the_printed_cursor_resumes_it() {
    let payloads: Vec<Vec<u8>> = (1..=10)
        .map(|index| format!("p{index}").into_bytes())
        .collect();
    let events: Vec<(EventKind, Authority, &[u8])> = payloads
        .iter()
        .map(|payload| {
            (
                EventKind::AdapterEvent,
                Authority::Synthetic,
                payload.as_slice(),
            )
        })
        .collect();
    let mut builder = EndpointBuilder::new();
    builder.attempt("attempt-page", "run-page", &events);
    let mut endpoint = builder.start();

    let mut expected =
        String::from("Automonique attempt events: attempt_id=attempt-page cursor=0\n");
    for sequence in 1..=MAX_SUBSCRIBE_PAGE_EVENTS {
        expected.push_str(&format!(
            "- seq={sequence} kind=adapter_event authority=synthetic payload=text:p{sequence}\n"
        ));
    }
    expected.push_str(&format!(
        "next cursor: {MAX_SUBSCRIBE_PAGE_EVENTS} more: true\n"
    ));
    let (exit, first_page, stderr) = cli(invocation("events", endpoint.path(), &["attempt-page"]));
    assert_eq!(exit, 0, "first page stderr: {stderr}");
    assert_eq!(first_page, expected);

    // The operator re-runs with exactly the cursor that was printed.
    let next_cursor = first_page
        .lines()
        .next_back()
        .and_then(|line| line.strip_prefix("next cursor: "))
        .and_then(|rest| rest.split(' ').next())
        .expect("continuation line")
        .to_owned();
    let (exit, second_page, _) = cli(invocation(
        "events",
        endpoint.path(),
        &["attempt-page", &next_cursor],
    ));
    assert_eq!(exit, 0);
    assert_eq!(
        second_page,
        "Automonique attempt events: attempt_id=attempt-page cursor=8\n\
         - seq=9 kind=adapter_event authority=synthetic payload=text:p9\n\
         - seq=10 kind=adapter_event authority=synthetic payload=text:p10\n\
         next cursor: 10 more: false\n"
    );

    endpoint.stop();
}

#[test]
fn cancel_delivers_once_and_a_reused_reference_conflicts() {
    let mut builder = EndpointBuilder::new();
    let first = builder.attempt("attempt-1", "run-alpha", &[]);
    let second = builder.attempt("attempt-2", "run-beta", &[]);
    let mut endpoint = builder.start();

    let (exit, stdout, stderr) = cli(invocation(
        "cancel",
        endpoint.path(),
        &["attempt-1", "ref-1"],
    ));
    assert_eq!(exit, 0, "cancel stderr: {stderr}");
    assert_eq!(
        stdout,
        "Automonique attempt cancel: attempt_id=attempt-1 request_ref=ref-1 outcome=delivered\n"
    );
    assert_eq!(first.load(Ordering::Acquire), 1);

    // A replay is evidence of the first delivery, not a second one.
    let (exit, stdout, _) = cli(invocation(
        "cancel",
        endpoint.path(),
        &["attempt-1", "ref-1"],
    ));
    assert_eq!(exit, 0);
    assert_eq!(
        stdout,
        "Automonique attempt cancel: attempt_id=attempt-1 request_ref=ref-1 outcome=already_delivered\n"
    );
    assert_eq!(first.load(Ordering::Acquire), 1);

    // The same reference against another attempt is a conflict, and nothing is
    // delivered to that attempt's sink.
    let (exit, stdout, stderr) = cli(invocation(
        "cancel",
        endpoint.path(),
        &["attempt-2", "ref-1"],
    ));
    assert_eq!(exit, 1);
    assert!(stdout.is_empty());
    assert_eq!(stderr, "automonique attempt refused: cancel_conflict\n");
    assert_eq!(second.load(Ordering::Acquire), 0);

    endpoint.stop();
}

#[test]
fn endpoint_refusals_are_reported_by_category_with_no_output() {
    let mut builder = EndpointBuilder::new();
    builder.attempt(
        "attempt-1",
        "run-alpha",
        &[(EventKind::Started, Authority::Authoritative, b"go")],
    );
    let mut endpoint = builder.start();

    for (arguments, category) in [
        (
            invocation("inspect", endpoint.path(), &["attempt-missing"]),
            "target_unknown",
        ),
        (
            invocation("events", endpoint.path(), &["attempt-missing"]),
            "target_unknown",
        ),
        (
            invocation("cancel", endpoint.path(), &["attempt-missing", "ref-1"]),
            "target_unknown",
        ),
        (
            invocation("events", endpoint.path(), &["attempt-1", "99"]),
            "cursor_ahead",
        ),
    ] {
        let (exit, stdout, stderr) = cli(arguments);
        assert_eq!(exit, 1);
        assert!(stdout.is_empty(), "refusal printed a record: {stdout:?}");
        assert_eq!(stderr, format!("automonique attempt refused: {category}\n"));
    }

    endpoint.stop();
}

// --- client-side discipline ------------------------------------------------

#[test]
fn a_wrong_greeting_is_refused_without_sending_the_request() {
    for greeting in [
        // Right shape, wrong version.
        b"automonique.control/v0\n".to_vec(),
        // No terminator inside the greeting bound.
        vec![b'x'; 4096],
        // Nothing at all.
        Vec::new(),
    ] {
        let mut fake = FakeEndpoint::spawn(greeting, 0);
        let (exit, stdout, stderr) = cli(invocation("inspect", fake.path(), &["attempt-1"]));
        assert_eq!(exit, 1);
        assert!(stdout.is_empty());
        assert_eq!(stderr, "automonique attempt refused: greeting_mismatch\n");
        assert_eq!(
            fake.join(),
            Vec::<u8>::new(),
            "the client sent a request to a server that did not greet it"
        );
    }
}

#[test]
fn a_response_past_the_ceiling_is_refused_rather_than_buffered() {
    let mut greeting = CONTROL_GREETING.as_bytes().to_vec();
    greeting.push(b'\n');
    let mut fake = FakeEndpoint::spawn(greeting, MAX_RESPONSE_BYTES + 512 * 1024);
    let (exit, stdout, stderr) = cli(invocation("heartbeat", fake.path(), &[]));
    assert_eq!(exit, 1);
    assert!(stdout.is_empty());
    assert_eq!(stderr, "automonique attempt refused: response_too_large\n");
    // Exactly one request line, and it is the operation that was asked for.
    assert_eq!(fake.join(), b"heartbeat\n".to_vec());
}

#[test]
fn socket_paths_are_judged_before_any_connection() {
    let directory = tempfile::tempdir().expect("directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private directory");
    let regular = directory.path().join("regular");
    fs::write(&regular, b"not a socket").expect("regular file");
    let missing = directory.path().join("missing.sock");
    let long = PathBuf::from(format!("/{}", "a".repeat(200)));

    for (path, exit_code, category) in [
        (
            PathBuf::from("relative/control.sock"),
            2,
            "invalid_socket_path",
        ),
        (PathBuf::from("/"), 2, "invalid_socket_path"),
        (
            directory.path().join("../escape.sock"),
            2,
            "invalid_socket_path",
        ),
        (long, 2, "invalid_socket_path"),
        (missing, 1, "socket_unavailable"),
        (regular, 1, "insecure_socket"),
    ] {
        let (exit, stdout, stderr) = cli(invocation("heartbeat", &path, &[]));
        assert_eq!(exit, exit_code, "{path:?} exited {exit}");
        assert!(stdout.is_empty());
        assert_eq!(stderr, format!("automonique attempt refused: {category}\n"));
    }
}

#[test]
fn a_world_writable_socket_is_refused_without_reaching_the_endpoint() {
    let builder = EndpointBuilder::new();
    let mut endpoint = builder.start();
    // The endpoint is live and answering; only its mode is wrong.
    fs::set_permissions(endpoint.path(), fs::Permissions::from_mode(0o666))
        .expect("widen socket mode");

    let (exit, stdout, stderr) = cli(invocation("heartbeat", endpoint.path(), &[]));
    assert_eq!(exit, 1);
    assert!(stdout.is_empty());
    assert_eq!(stderr, "automonique attempt refused: insecure_socket\n");

    // The endpoint was live the whole time: restoring the mode makes the very
    // same invocation succeed, so the refusal above was the client's decision
    // about the inode and not a dead listener.
    fs::set_permissions(endpoint.path(), fs::Permissions::from_mode(0o600))
        .expect("restore socket mode");
    let (exit, stdout, stderr) = cli(invocation("heartbeat", endpoint.path(), &[]));
    assert_eq!(exit, 0, "heartbeat stderr: {stderr}");
    assert!(stdout.ends_with(" bindings=0\n"), "{stdout:?}");

    endpoint.stop();
    assert_eq!(
        endpoint.reached(),
        1,
        "only the invocation made after the mode was restored may reach the endpoint"
    );
}

#[test]
fn out_of_grammar_fields_are_refused_before_the_endpoint_is_contacted() {
    let mut builder = EndpointBuilder::new();
    builder.attempt("attempt-1", "run-alpha", &[]);
    let mut endpoint = builder.start();

    let oversized = "a".repeat(MAX_IDENTIFIER_BYTES + 1);
    for (arguments, category) in [
        (
            invocation("inspect", endpoint.path(), &["attempt/../1"]),
            "invalid_attempt_id",
        ),
        (
            invocation("inspect", endpoint.path(), &[&oversized]),
            "invalid_attempt_id",
        ),
        (
            invocation("inspect", endpoint.path(), &[""]),
            "invalid_attempt_id",
        ),
        (
            invocation("events", endpoint.path(), &["attempt-1", "01"]),
            "invalid_cursor",
        ),
        (
            invocation("events", endpoint.path(), &["attempt-1", "-1"]),
            "invalid_cursor",
        ),
        (
            invocation("cancel", endpoint.path(), &["attempt-1", "ref 1"]),
            "invalid_request_ref",
        ),
        (
            invocation("cancel", endpoint.path(), &["attempt-1", &oversized]),
            "invalid_request_ref",
        ),
    ] {
        let (exit, stdout, stderr) = cli(arguments);
        assert_eq!(exit, 2);
        assert!(stdout.is_empty());
        assert_eq!(stderr, format!("automonique attempt refused: {category}\n"));
    }

    endpoint.stop();
    assert_eq!(
        endpoint.reached(),
        0,
        "a field the client could refuse itself still opened a connection"
    );
}

// --- argv grammar ----------------------------------------------------------

#[test]
fn malformed_attempt_invocations_are_bounded_usage_errors() {
    let socket = Path::new("/run/automonique/control.sock");
    let mut invocations: Vec<Vec<OsString>> = vec![
        vec![OsString::from("attempt")],
        vec![OsString::from("attempt"), OsString::from("heartbeat")],
        vec![OsString::from("attempt"), OsString::from("inspect")],
        invocation("heartbeat", socket, &["extra"]),
        invocation("inspect", socket, &[]),
        invocation("inspect", socket, &["attempt-1", "extra"]),
        invocation("events", socket, &[]),
        invocation("events", socket, &["attempt-1", "0", "extra"]),
        invocation("cancel", socket, &["attempt-1"]),
        invocation("cancel", socket, &["attempt-1", "ref-1", "extra"]),
        invocation("bogus", socket, &["attempt-1"]),
    ];
    // A non-UTF-8 operation is a usage error, not a panic and not a connection.
    invocations.push(vec![
        OsString::from("attempt"),
        OsString::from_vec(vec![0xff]),
        socket.as_os_str().to_owned(),
        OsString::from("attempt-1"),
    ]);

    for arguments in invocations {
        let (exit, stdout, stderr) = cli(arguments.clone());
        assert_eq!(exit, 2, "{arguments:?} exited {exit}");
        assert!(stdout.is_empty());
        assert_bounded_usage(&stderr);
    }
}
