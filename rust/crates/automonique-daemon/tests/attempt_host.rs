// SPDX-License-Identifier: Elastic-2.0

//! The daemon's single host-wide cancellation host, proved by composition.
//!
//! Two claims are under test and they are different claims:
//!
//! 1. **Durability.** A reference delivered through the host is answered
//!    `already_delivered` by a *different* host object, over the same ledger
//!    file, after the first was disposed. Every restart test here tears the
//!    host down and reopens the file; none of them clears a map.
//! 2. **One owner.** One reference reaches one sink once, however many callers
//!    race for it — including a caller on a real control socket racing a caller
//!    holding the host directly.
//!
//! [`two_hosts_over_one_ledger_file_double_deliver`] is the negative control
//! for the second claim, and it is why the racing tests mean anything: it opens
//! *two* hosts over one file, races them identically, and asserts the double
//! delivery **is** observable. The file does not serialise anything; the
//! daemon's decision to hold exactly one host does. A harness that could not
//! see the failure would not be evidence that the failure is absent.
//!
//! Refusals are asserted by exact category throughout. Two guards that both
//! refuse are not interchangeable: `attempt_host_ledger_insecure_path` says
//! this host's storage is unusable, and `attempt_host_poisoned` says a
//! delivery's fate is unknown.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use automonique_daemon::attempt_host::{
    AttemptHostError, DaemonAttemptHost, MAX_ATTEMPT_REGISTRATIONS,
};
use automonique_daemon::{Daemon, DaemonConfig, DaemonError};
use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_runner::Spool;
use automonique_runner::control::{
    CONTROL_GREETING, CancelDelivery, CancelSink, CancelSinkError, ControlServer,
};
use automonique_runner::dispatch::DispatchOutcome;
use automonique_store::cancel_ledger::CancelLedger;

const SPOOL_MAX_BYTES: u64 = 1024 * 1024;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);
/// Iterations for the racing tests. High enough that an interleaving the
/// scheduler only sometimes produces is seen many times over.
const RACE_ITERATIONS: usize = 64;
/// Iterations for the racing test that crosses a real socket per round.
const WIRE_RACE_ITERATIONS: usize = 24;

// --- roots ----------------------------------------------------------------

/// A private root whose ledger path is stable across host reopens.
///
/// Stable on purpose: "the same file" is the claim under test, so the test must
/// not be able to accidentally prove it against two different databases.
struct PrivateRoot {
    directory: tempfile::TempDir,
}

impl PrivateRoot {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary root");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private root");
        Self { directory }
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }

    fn ledger_path(&self) -> PathBuf {
        self.directory.path().join("run-cancel-ledger.sqlite3")
    }

    fn host(&self) -> DaemonAttemptHost {
        DaemonAttemptHost::open(self.ledger_path()).expect("open attempt host")
    }

    fn spool_root(&self) -> PathBuf {
        let root = self.directory.path().join("spools");
        if !root.exists() {
            fs::create_dir(&root).expect("spool root");
        }
        root
    }
}

// --- a sink that counts, and panics on demand -----------------------------

/// The sink every test observes.
///
/// The delivery count is the whole point: an idempotent *answer* that still
/// reaches the sink twice is exactly the bug one host-wide owner exists to
/// remove, and only a count can tell those two apart.
struct CountingSink {
    attempt_id: String,
    deliveries: Arc<AtomicUsize>,
    refs: Arc<Mutex<Vec<String>>>,
    panic_on_deliver: bool,
}

impl CancelSink for CountingSink {
    fn deliver(
        &self,
        attempt_id: &str,
        request_ref: &str,
    ) -> Result<CancelDelivery, CancelSinkError> {
        assert_eq!(
            attempt_id, self.attempt_id,
            "a dispatch must only ever reach its own registration's sink"
        );
        assert!(
            !self.panic_on_deliver,
            "cancel sink panicked inside the serialized section"
        );
        // Deliberate amplification, applied identically to the single-host and
        // the two-host cases: it widens the classify-to-record window that
        // exists in both, so the scheduler is given a real chance to interleave
        // rather than being trusted to.
        std::thread::yield_now();
        self.refs.lock().expect("refs").push(request_ref.to_owned());
        self.deliveries.fetch_add(1, Ordering::Release);
        Ok(CancelDelivery::Accepted)
    }
}

/// What the test keeps after the sink is handed to the host.
#[derive(Clone)]
struct SinkProbe {
    deliveries: Arc<AtomicUsize>,
    refs: Arc<Mutex<Vec<String>>>,
}

impl SinkProbe {
    fn boxed(attempt_id: &str) -> (Box<dyn CancelSink>, Self) {
        let probe = Self {
            deliveries: Arc::new(AtomicUsize::new(0)),
            refs: Arc::new(Mutex::new(Vec::new())),
        };
        (probe.sink(attempt_id, false), probe)
    }

    /// A second sink reporting into this same probe, for the two-host control.
    fn sink(&self, attempt_id: &str, panic_on_deliver: bool) -> Box<dyn CancelSink> {
        Box::new(CountingSink {
            attempt_id: attempt_id.to_owned(),
            deliveries: Arc::clone(&self.deliveries),
            refs: Arc::clone(&self.refs),
            panic_on_deliver,
        })
    }

    fn deliveries(&self) -> usize {
        self.deliveries.load(Ordering::Acquire)
    }

    fn delivered_refs(&self) -> Vec<String> {
        self.refs.lock().expect("refs").clone()
    }
}

/// Serialises the test that deliberately panics, and swallows its output.
///
/// The panic hook is process-global, so without this the panicking test leaks a
/// `panicked at` line into an otherwise passing run.
static PANIC_HOOK: Mutex<()> = Mutex::new(());

fn catch_silent_panic<R>(work: impl FnOnce() -> R) -> std::thread::Result<R> {
    let _guard = PANIC_HOOK.lock().unwrap_or_else(|error| error.into_inner());
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
    std::panic::set_hook(previous);
    outcome
}

// --- control server plumbing ----------------------------------------------

/// A control server on a thread this harness owns and joins.
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
            thread.join().expect("server thread");
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop();
    }
}

/// One wire exchange, asserting the versioned greeting arrived first.
fn body(socket_path: &Path, request: &str) -> String {
    let mut stream = UnixStream::connect(socket_path).expect("connect");
    stream
        .set_read_timeout(Some(CLIENT_TIMEOUT))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(CLIENT_TIMEOUT))
        .expect("write timeout");
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    let (greeting, body) = response
        .split_once('\n')
        .expect("server must greet before answering");
    assert_eq!(greeting, CONTROL_GREETING);
    body.to_owned()
}

/// A control server seated on `host`, already serving `attempt_id` through it.
fn seated_server(
    host: &DaemonAttemptHost,
    root: &PrivateRoot,
    attempt_id: &str,
    run_id: &str,
    sink: Box<dyn CancelSink>,
) -> (
    ControlServer,
    automonique_runner::dispatch::RegistrationHandle,
) {
    let seat = host.seat();
    let handle = host.register(attempt_id, sink).expect("register");
    let mut server = ControlServer::bind(root.path().join("run/control.sock"), seat.custody())
        .expect("bind control socket");
    server
        .register(
            handle.attempt_id(),
            Spool::open(root.spool_root().join(run_id), run_id, SPOOL_MAX_BYTES).expect("spool"),
            seat.sink(&handle),
        )
        .expect("bind attempt");
    (server, handle)
}

// --- daemon plumbing ------------------------------------------------------

fn fixture() -> (tempfile::TempDir, DaemonConfig) {
    let root = tempfile::tempdir().expect("temporary root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    let runtime = root.path().join("runtime");
    let state = root.path().join("state");
    fs::create_dir(&runtime).expect("runtime root");
    fs::create_dir(&state).expect("state root");
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).expect("private runtime");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("private state");
    (
        root,
        DaemonConfig {
            runtime_root: runtime,
            state_root: state,
        },
    )
}

fn call(config: &DaemonConfig, command: AdminCommand) -> AdminResponse {
    let request = AdminRequest::new(
        RequestId::new("attempt-host-1").expect("request ID"),
        command,
    );
    let mut stream = UnixStream::connect(config.admin_socket()).expect("connect to daemon");
    let payload = request
        .to_message()
        .expect("encode request")
        .to_canonical_bytes();
    let mut frame = Vec::new();
    encode_frame(&payload, &mut frame).expect("frame request");
    stream.write_all(&frame).expect("write request");
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).expect("response prefix");
    let length = u32::from_be_bytes(prefix) as usize;
    let mut response = vec![0_u8; length + 4];
    response[..4].copy_from_slice(&prefix);
    stream
        .read_exact(&mut response[4..])
        .expect("response body");
    let FrameDecode::Frame { payload, .. } = decode_frame(&response).expect("response frame")
    else {
        panic!("complete response was incomplete")
    };
    AdminResponse::from_canonical_bytes(payload).expect("admitted response")
}

fn wait_for_socket(config: &DaemonConfig) {
    // Generous on purpose. Everything before the bind is disk-bound — several
    // SQLite databases opened `synchronous = FULL`, each fsyncing its own WAL —
    // so a short deadline here measures the test host under concurrent load
    // rather than the daemon.
    let deadline = Instant::now() + Duration::from_secs(15);
    while !config.admin_socket().exists() {
        assert!(Instant::now() < deadline, "daemon did not bind");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Serve `daemon` on its own thread, request shutdown over the real socket, and
/// return what `serve` decided.
fn serve_then_shutdown(daemon: Daemon, config: &DaemonConfig) -> Result<(), DaemonError> {
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&thread_stop));
    wait_for_socket(config);
    assert!(matches!(
        call(config, AdminCommand::Shutdown),
        AdminResponse::ShutdownAccepted { .. }
    ));
    thread.join().expect("daemon thread")
}

/// The error from a registration that must be refused.
///
/// `Result::unwrap_err` is unavailable: the success value is a
/// `RegistrationHandle`, which has no `PartialEq` and deliberately never will —
/// a registration is a live cancellation path, not a comparable value.
fn refused_registration(
    host: &DaemonAttemptHost,
    attempt_id: &str,
    probe: &SinkProbe,
) -> AttemptHostError {
    match host.register(attempt_id, probe.sink(attempt_id, false)) {
        Ok(_) => panic!("registration of {attempt_id} must have been refused"),
        Err(error) => error,
    }
}

/// The error from a host construction that must be refused.
fn open_refusal(ledger_path: &Path) -> AttemptHostError {
    match DaemonAttemptHost::open(ledger_path) {
        Ok(_) => panic!("{} must not have opened a host", ledger_path.display()),
        Err(error) => error,
    }
}

fn recorded(ledger_path: &Path, attempt_id: &str) -> Vec<(String, u64)> {
    let ledger = CancelLedger::open(ledger_path).expect("open ledger for reading");
    ledger
        .attempt_requests(attempt_id)
        .expect("read attempt")
        .into_iter()
        .map(|entry| (entry.request_ref, entry.observed_sequence))
        .collect()
}

// --- durability through the daemon's own composition ----------------------

#[test]
fn a_delivered_reference_replays_across_a_host_teardown_and_reopen() {
    let root = PrivateRoot::new();

    let (sink, first) = SinkProbe::boxed("attempt-1");
    {
        let host = root.host();
        let handle = host.register("attempt-1", sink).expect("register");
        assert_eq!(
            host.cancel("attempt-1", "ref-a", 7),
            DispatchOutcome::Delivered
        );
        assert_eq!(first.deliveries(), 1);
        // Within one host it already replays, and the sink is not touched.
        assert_eq!(
            host.cancel("attempt-1", "ref-a", 7),
            DispatchOutcome::AlreadyDelivered
        );
        assert_eq!(first.deliveries(), 1);
        drop(handle);
        host.dispose().expect("clean disposal");
    }

    // Everything above is gone: the dispatcher, its custody, its SQLite
    // connection, its registration and its sink. Only the file remains.
    let (sink, second) = SinkProbe::boxed("attempt-1");
    let host = root.host();
    let _handle = host.register("attempt-1", sink).expect("re-register");

    assert_eq!(
        host.cancel("attempt-1", "ref-a", 7),
        DispatchOutcome::AlreadyDelivered,
        "a reopened host must recognise what its predecessor delivered"
    );
    // A real replay, not a polite answer: the new sink was never called.
    assert_eq!(second.deliveries(), 0);
    // The recorded observed sequence still binds the reference across the
    // teardown, so this is memory of one binding rather than a blanket answer.
    assert_eq!(
        host.cancel("attempt-1", "ref-a", 8),
        DispatchOutcome::Conflict
    );
    assert_eq!(second.deliveries(), 0);
    // And an unseen reference still delivers.
    assert_eq!(
        host.cancel("attempt-1", "ref-b", 8),
        DispatchOutcome::Delivered
    );
    assert_eq!(second.deliveries(), 1);
    assert_eq!(second.delivered_refs(), vec!["ref-b".to_owned()]);

    host.dispose().expect("clean disposal");
    // Both deliveries are durable and readable by anyone holding the file.
    assert_eq!(
        recorded(&root.ledger_path(), "attempt-1"),
        vec![("ref-a".to_owned(), 7), ("ref-b".to_owned(), 8)]
    );
}

#[test]
fn terminal_attempt_pruning_releases_only_that_attempts_capacity() {
    let root = PrivateRoot::new();
    let host = root.host();

    let (first_sink, first) = SinkProbe::boxed("attempt-1");
    let first_handle = host
        .register("attempt-1", first_sink)
        .expect("register first");
    let (second_sink, second) = SinkProbe::boxed("attempt-2");
    let _second_handle = host
        .register("attempt-2", second_sink)
        .expect("register second");

    assert_eq!(
        host.cancel("attempt-1", "ref-terminal", 7),
        DispatchOutcome::Delivered
    );
    assert_eq!(
        host.cancel("attempt-2", "ref-live", 8),
        DispatchOutcome::Delivered
    );
    assert_eq!(first.deliveries(), 1);
    assert_eq!(second.deliveries(), 1);

    // Terminality is asserted only after the registration is unreachable.
    drop(first_handle);
    let outcome = host
        .prune_terminal_attempt("attempt-1")
        .expect("prune terminal attempt");
    assert_eq!(outcome.removed, 1);
    assert_eq!(outcome.remaining, 1);
    assert!(recorded(&root.ledger_path(), "attempt-1").is_empty());
    assert_eq!(
        recorded(&root.ledger_path(), "attempt-2"),
        vec![("ref-live".to_owned(), 8)]
    );
}

// --- the same host, through a real control socket -------------------------

#[test]
fn a_seated_control_server_delivers_once_and_replays_over_the_real_socket() {
    let root = PrivateRoot::new();
    let (sink, probe) = SinkProbe::boxed("attempt-1");
    let host = root.host();
    let (server, _handle) = seated_server(&host, &root, "attempt-1", "run-alpha", sink);
    let socket_path = server.socket_path().to_path_buf();
    let mut harness = Harness::spawn(server);

    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-a 7\n"),
        "cancel_result delivered\n"
    );
    assert_eq!(probe.deliveries(), 1);

    // A replay over the wire is answered without the sink being reached.
    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-a 7\n"),
        "cancel_result already_delivered\n"
    );
    assert_eq!(probe.deliveries(), 1);

    // The two callers share one custody, so a direct cancel of the reference
    // the socket delivered is a replay rather than a second delivery. This is
    // the composition: the wire and the direct API are not separate lanes.
    assert_eq!(
        host.cancel("attempt-1", "ref-a", 7),
        DispatchOutcome::AlreadyDelivered
    );
    assert_eq!(probe.deliveries(), 1);

    // Refusal categories are the control endpoint's own and are unchanged by
    // being seated on the host.
    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-a 8\n"),
        "refused cancel_conflict\n"
    );
    assert_eq!(
        body(harness.path(), "cancel attempt-absent ref-z 0\n"),
        "refused target_unknown\n"
    );
    assert_eq!(probe.deliveries(), 1);

    // A new reference still reaches the sink, exactly once.
    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-b 8\n"),
        "cancel_result delivered\n"
    );
    assert_eq!(probe.deliveries(), 2);

    harness.stop();
    assert!(!socket_path.exists(), "shutdown must unlink its socket");
    host.dispose().expect("clean disposal");

    // Durability through the whole composition: a brand new host over the same
    // ledger file answers `already_delivered` for what the socket delivered.
    let host = root.host();
    let (sink, successor) = SinkProbe::boxed("attempt-1");
    let _handle = host.register("attempt-1", sink).expect("re-register");
    assert_eq!(
        host.cancel("attempt-1", "ref-a", 7),
        DispatchOutcome::AlreadyDelivered
    );
    assert_eq!(
        host.cancel("attempt-1", "ref-b", 8),
        DispatchOutcome::AlreadyDelivered
    );
    assert_eq!(successor.deliveries(), 0);
    assert_eq!(
        recorded(&root.ledger_path(), "attempt-1"),
        vec![("ref-a".to_owned(), 7), ("ref-b".to_owned(), 8)]
    );
}

// --- one owner, proved by racing ------------------------------------------

#[test]
fn concurrent_cancels_of_one_reference_through_one_host_deliver_once() {
    let root = PrivateRoot::new();
    let host = root.host();
    let (sink, probe) = SinkProbe::boxed("attempt-race");
    let _handle = host.register("attempt-race", sink).expect("register");

    for iteration in 0..RACE_ITERATIONS {
        let request_ref = format!("ref-{iteration}");
        let barrier = Barrier::new(2);
        let outcomes = std::thread::scope(|scope| {
            let left = scope.spawn(|| {
                barrier.wait();
                host.cancel("attempt-race", &request_ref, 7)
            });
            let right = scope.spawn(|| {
                barrier.wait();
                host.cancel("attempt-race", &request_ref, 7)
            });
            [left.join().expect("left"), right.join().expect("right")]
        });

        // Exactly one of the two took the reference; which one is the
        // scheduler's business, that there is exactly one is not.
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == DispatchOutcome::Delivered)
                .count(),
            1,
            "iteration {iteration} answered {outcomes:?}"
        );
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.is_delivery_evidence()),
            "iteration {iteration} answered {outcomes:?}"
        );
        // The sink is the authority, not the answer.
        assert_eq!(probe.deliveries(), iteration + 1);
    }

    let mut refs = probe.delivered_refs();
    refs.sort();
    refs.dedup();
    assert_eq!(
        refs.len(),
        RACE_ITERATIONS,
        "every reference delivered once"
    );
}

#[test]
fn a_wire_cancel_racing_a_direct_cancel_of_one_reference_delivers_once() {
    let root = PrivateRoot::new();
    let host = root.host();
    let (sink, probe) = SinkProbe::boxed("attempt-wire");
    let (server, _handle) = seated_server(&host, &root, "attempt-wire", "run-wire", sink);
    let mut harness = Harness::spawn(server);

    for iteration in 0..WIRE_RACE_ITERATIONS {
        let request_ref = format!("ref-{iteration}");
        let before = probe.deliveries();
        let barrier = Barrier::new(2);
        let (wire, direct) = std::thread::scope(|scope| {
            let wire = scope.spawn(|| {
                barrier.wait();
                body(
                    harness.path(),
                    &format!("cancel attempt-wire {request_ref} 7\n"),
                )
            });
            let direct = scope.spawn(|| {
                barrier.wait();
                host.cancel("attempt-wire", &request_ref, 7)
            });
            (wire.join().expect("wire"), direct.join().expect("direct"))
        });

        // Both callers are told the request reached the sink. Which of them
        // took it there is the documented residue of the seat composition and
        // is deliberately not asserted; that the sink fired once is.
        assert!(
            wire == "cancel_result delivered\n" || wire == "cancel_result already_delivered\n",
            "iteration {iteration} answered {wire:?} over the wire"
        );
        assert!(
            direct.is_delivery_evidence(),
            "iteration {iteration} answered {direct:?} directly"
        );
        assert_eq!(
            probe.deliveries() - before,
            1,
            "iteration {iteration}: one reference reached the sink more than once"
        );
    }

    harness.stop();
    assert_eq!(probe.deliveries(), WIRE_RACE_ITERATIONS);
}

#[test]
fn two_hosts_over_one_ledger_file_double_deliver() {
    let root = PrivateRoot::new();
    // Exactly what the daemon refuses to compose: two owners, one file.
    let first = root.host();
    let second = root.host();
    let (sink, probe) = SinkProbe::boxed("attempt-two");
    let _first_handle = first.register("attempt-two", sink).expect("register first");
    let _second_handle = second
        .register("attempt-two", probe.sink("attempt-two", false))
        .expect("register second");

    let mut double_delivered = 0_usize;
    for iteration in 0..RACE_ITERATIONS {
        let request_ref = format!("ref-{iteration}");
        let before = probe.deliveries();
        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            let left = scope.spawn(|| {
                barrier.wait();
                first.cancel("attempt-two", &request_ref, 7)
            });
            let right = scope.spawn(|| {
                barrier.wait();
                second.cancel("attempt-two", &request_ref, 7)
            });
            let _ = (left.join().expect("left"), right.join().expect("right"));
        });
        if probe.deliveries() - before > 1 {
            double_delivered += 1;
        }
    }

    // Reported rather than merely asserted: a rate this test cannot observe is
    // a harness that has stopped proving anything about the single-host tests.
    eprintln!(
        "two hosts over one ledger: {double_delivered}/{RACE_ITERATIONS} iterations \
         double-delivered"
    );
    assert!(
        double_delivered > 0,
        "two hosts over one ledger never raced in {RACE_ITERATIONS} iterations, so the \
         single-host tests' passing means nothing; raise the iteration count"
    );
    // The tell that this is the real bug: the sink fired more often than there
    // are references. The durable file deduplicates nothing on its own.
    assert!(probe.deliveries() > RACE_ITERATIONS);
}

// --- registration lifecycle and bounds ------------------------------------

#[test]
fn a_dropped_handle_unregisters_and_registration_is_bounded() {
    let root = PrivateRoot::new();
    let host = root.host();
    assert_eq!(host.registration_capacity(), MAX_ATTEMPT_REGISTRATIONS);
    assert_eq!(host.registration_count().expect("count"), 0);

    let (sink, probe) = SinkProbe::boxed("attempt-1");
    let handle = host.register("attempt-1", sink).expect("register");
    assert_eq!(handle.attempt_id(), "attempt-1");
    assert_eq!(host.registration_count().expect("count"), 1);

    // Registration never replaces a live one, and the grammar is the control
    // endpoint's.
    assert_eq!(
        refused_registration(&host, "attempt-1", &probe),
        AttemptHostError::DuplicateAttempt
    );
    assert_eq!(
        refused_registration(&host, "attempt one", &probe),
        AttemptHostError::InvalidAttemptId
    );
    assert_eq!(
        AttemptHostError::DuplicateAttempt.category(),
        "attempt_host_duplicate_attempt"
    );
    assert_eq!(
        AttemptHostError::InvalidAttemptId.category(),
        "attempt_host_invalid_attempt_id"
    );

    drop(handle);
    assert_eq!(host.registration_count().expect("count"), 0);
    // With nothing registered there is nothing to deliver to, and custody is
    // not consulted at all: an unknown attempt cannot mint a durable row.
    assert_eq!(
        host.cancel("attempt-1", "ref-a", 7),
        DispatchOutcome::UnknownAttempt
    );
    assert_eq!(probe.deliveries(), 0);
    assert!(recorded(&root.ledger_path(), "attempt-1").is_empty());

    // The bound is the dispatcher's and this host does not widen it.
    let mut handles = Vec::with_capacity(MAX_ATTEMPT_REGISTRATIONS);
    for index in 0..MAX_ATTEMPT_REGISTRATIONS {
        let attempt_id = format!("attempt-{index}");
        let sink = probe.sink(&attempt_id, false);
        handles.push(host.register(&attempt_id, sink).expect("register"));
    }
    assert_eq!(
        host.registration_count().expect("count"),
        MAX_ATTEMPT_REGISTRATIONS
    );
    assert_eq!(
        refused_registration(&host, "attempt-overflow", &probe),
        AttemptHostError::RegistrationLimit
    );
    assert_eq!(
        AttemptHostError::RegistrationLimit.category(),
        "attempt_host_registration_limit"
    );
    // The refused registration did not displace a live one.
    assert_eq!(
        host.registration_count().expect("count"),
        MAX_ATTEMPT_REGISTRATIONS
    );
    handles.clear();
    assert_eq!(host.registration_count().expect("count"), 0);
}

// --- fail-closed construction ---------------------------------------------

#[test]
fn an_unopenable_ledger_path_refuses_host_construction() {
    let root = PrivateRoot::new();

    // A directory where a database must be.
    let occupied = root.path().join("occupied.sqlite3");
    fs::create_dir(&occupied).expect("occupying directory");
    assert_eq!(
        open_refusal(&occupied),
        AttemptHostError::LedgerUnavailable("attempt_host_ledger_insecure_path")
    );

    // A parent directory anyone on the host can read.
    let leaky = root.path().join("leaky");
    fs::create_dir(&leaky).expect("leaky directory");
    fs::set_permissions(&leaky, fs::Permissions::from_mode(0o755)).expect("group readable");
    let error = open_refusal(&leaky.join("run-cancel-ledger.sqlite3"));
    assert_eq!(error.category(), "attempt_host_ledger_insecure_path");
    assert!(
        !leaky.join("run-cancel-ledger.sqlite3").exists(),
        "a refused host must not leave a ledger file behind"
    );

    // A relative path is refused before anything touches the filesystem.
    assert_eq!(
        open_refusal(Path::new("run-cancel-ledger.sqlite3")).category(),
        "attempt_host_ledger_insecure_path"
    );
}

// --- the daemon's own composition -----------------------------------------

#[test]
fn daemon_open_constructs_one_attempt_host_over_its_own_ledger() {
    let (_root, config) = fixture();
    let daemon = Daemon::open(&config).expect("daemon opens");

    let host = daemon
        .attempt_host()
        .expect("an opened daemon owns its attempt host");
    assert_eq!(host.ledger_path(), config.run_cancel_ledger_path());
    assert!(
        config.run_cancel_ledger_path().exists(),
        "opening the host must create its durable ledger"
    );
    assert_eq!(host.registration_capacity(), MAX_ATTEMPT_REGISTRATIONS);
    // A daemon that has been asked to run nothing has registered nothing, so
    // the registry is empty here. The execution lane is what fills it.
    assert_eq!(host.registration_count().expect("count"), 0);
    assert_eq!(
        host.cancel("attempt-absent", "ref-a", 0),
        DispatchOutcome::UnknownAttempt
    );

    // The daemon's host is a live dispatcher, not a constructed shell.
    let (sink, probe) = SinkProbe::boxed("attempt-daemon");
    let handle = host.register("attempt-daemon", sink).expect("register");
    assert_eq!(
        host.cancel("attempt-daemon", "ref-a", 3),
        DispatchOutcome::Delivered
    );
    assert_eq!(
        host.cancel("attempt-daemon", "ref-a", 3),
        DispatchOutcome::AlreadyDelivered
    );
    assert_eq!(probe.deliveries(), 1);
    drop(handle);

    // Serving and shutting down is clean: disposal of a sound host is not an
    // error, so the poisoned case below is a real classification.
    serve_then_shutdown(daemon, &config).expect("clean stop");
    assert!(!config.admin_socket().exists());

    // The delivery is durable in the daemon's own ledger file, readable after
    // the daemon that wrote it is gone.
    assert_eq!(
        recorded(&config.run_cancel_ledger_path(), "attempt-daemon"),
        vec![("ref-a".to_owned(), 3)]
    );
}

#[test]
fn a_broken_cancel_ledger_path_refuses_startup_without_publishing_a_socket() {
    let (_root, config) = fixture();
    fs::create_dir(config.state_dir()).expect("state directory");
    fs::set_permissions(config.state_dir(), fs::Permissions::from_mode(0o700))
        .expect("private state directory");
    // A directory where the cancel ledger must be. Everything the daemon opens
    // before this one succeeds, so the refusal is this guard and not another.
    fs::create_dir(config.run_cancel_ledger_path()).expect("invalid ledger directory");

    let error = Daemon::open(&config)
        .err()
        .expect("an unopenable cancel ledger must refuse startup");
    assert!(
        matches!(error, DaemonError::AttemptHostFailed(_)),
        "expected AttemptHostFailed, got {error:?}"
    );
    assert_eq!(error.category(), "attempt_host_ledger_insecure_path");
    assert!(
        !config.admin_socket().exists(),
        "a refused startup must not leave the admin socket bound"
    );
}

#[test]
fn a_poisoned_attempt_host_is_reported_at_shutdown_rather_than_exiting_clean() {
    let (_root, config) = fixture();
    let daemon = Daemon::open(&config).expect("daemon opens");
    let host = daemon.attempt_host().expect("attempt host");

    let probe = SinkProbe {
        deliveries: Arc::new(AtomicUsize::new(0)),
        refs: Arc::new(Mutex::new(Vec::new())),
    };
    let _handle = host
        .register("attempt-panic", probe.sink("attempt-panic", true))
        .expect("register");

    // A sink that panics inside the serialized section leaves the host unable
    // to say whether that delivery happened.
    let panicked = catch_silent_panic(|| host.cancel("attempt-panic", "ref-a", 0));
    assert!(panicked.is_err(), "the sink was supposed to panic");
    assert_eq!(
        host.registration_count(),
        Err(AttemptHostError::Poisoned),
        "a panicking sink must poison the host"
    );
    assert_eq!(probe.deliveries(), 0);

    // Shutdown disposes of the host and reports what it found. A shutdown that
    // merely dropped the field would return `Ok` and claim a clean stop it
    // cannot account for.
    let error =
        serve_then_shutdown(daemon, &config).expect_err("a poisoned host must not stop clean");
    assert!(
        matches!(error, DaemonError::AttemptHostFailed(_)),
        "expected AttemptHostFailed, got {error:?}"
    );
    assert_eq!(error.category(), "attempt_host_poisoned");
    // Reported, not repaired: the rest of shutdown still ran.
    assert!(!config.admin_socket().exists());
}

#[test]
fn a_second_daemon_over_one_state_directory_cannot_open_a_second_host() {
    let (_root, config) = fixture();
    let first = Daemon::open(&config).expect("first daemon");
    let ledger_path = first
        .attempt_host()
        .expect("attempt host")
        .ledger_path()
        .to_path_buf();

    // This is the whole cross-process argument: the dispatcher requires one
    // instance per ledger file, and the daemon supplies it with exclusion that
    // already existed rather than a new lock. A second daemon over this state
    // directory never reaches the point of opening a second host.
    let error = Daemon::open(&config)
        .err()
        .expect("a second daemon must be refused");
    assert_eq!(error.category(), "already_running");
    assert_eq!(ledger_path, config.run_cancel_ledger_path());

    // The refusal left the first daemon's endpoint and host untouched.
    assert_eq!(
        first
            .attempt_host()
            .expect("attempt host")
            .registration_count()
            .expect("count"),
        0
    );
    serve_then_shutdown(first, &config).expect("clean stop");
}
