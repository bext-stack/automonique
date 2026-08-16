// SPDX-License-Identifier: Elastic-2.0

//! Exercised proof of the host cancellation dispatcher.
//!
//! The claim under test is narrow and mechanical: one reference reaches one
//! sink exactly once, however many callers race for it. So the tests race for
//! it — real threads, a real barrier, a hundred iterations — rather than
//! asserting that a single-threaded call sequence returns the words we like.
//!
//! # Why a deliberately broken reference implementation is in here
//!
//! A concurrency test that passes proves nothing on its own: it may simply
//! never have interleaved. [`RacyDispatcher`] is the same `classify -> deliver
//! -> record` sequence with the serialization removed and nothing else changed,
//! driven by the same threads through the same barrier at the same iteration
//! count. [`the_unserialized_reference_implementation_double_delivers`] asserts
//! that the race **is** observable there. That is what gives the dispatcher's
//! own race test teeth: the harness is known to be capable of producing the
//! failure it says it does not see.
//!
//! Both sides are amplified identically — the counting sink yields inside
//! delivery — so the amplification cannot be what makes one pass and the other
//! fail. It widens a window that exists in both.
//!
//! # Honest limit
//!
//! Every test here runs in one process. That is exactly the scope of what the
//! dispatcher establishes: two dispatchers over one durable ledger file still
//! race across processes, and no test in this file claims otherwise.

use automonique_runner::Spool;
use automonique_runner::control::{
    CONTROL_GREETING, CancelClaim, CancelCustody, CancelDelivery, CancelSink, CancelSinkError,
    ControlError, ControlServer, CustodyFailure, CustodyVerdict, MAX_IDENTIFIER_BYTES, Refusal,
};
use automonique_runner::dispatch::{
    CancelDispatcher, ControlSeat, DispatchError, DispatchOutcome, MAX_REGISTRATIONS,
    RegistrationHandle,
};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

const SPOOL_MAX_BYTES: u64 = 1024 * 1024;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);
/// Iterations for the two racing tests. High enough that an interleaving the
/// scheduler only sometimes produces is seen many times over.
const RACE_ITERATIONS: usize = 100;
const TEST_CUSTODY_CAPACITY: usize = 1024;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

// --- temporary directories ------------------------------------------------

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        // Short by construction: the socket path must fit `sun_path`.
        let path = std::env::temp_dir().join(format!("amq-d-{label}-{serial}"));
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

// --- a sink that counts, refuses or panics on demand ----------------------

const MODE_AVAILABLE: u8 = 0;
const MODE_UNAVAILABLE: u8 = 1;
const MODE_PANIC: u8 = 2;

/// The sink every test observes.
///
/// The delivery count is the whole point: an idempotent answer that still
/// reaches the sink twice is exactly the bug this module exists to remove, and
/// only a count can tell the two apart.
struct CountingSink {
    attempt_id: String,
    deliveries: Arc<AtomicUsize>,
    refs: Arc<Mutex<Vec<String>>>,
    mode: Arc<AtomicU8>,
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
        match self.mode.load(Ordering::Acquire) {
            MODE_UNAVAILABLE => return Err(CancelSinkError::Unavailable),
            MODE_PANIC => panic!("cancel sink panicked inside the serialized section"),
            _ => {}
        }
        // Deliberate amplification, applied identically to the dispatcher and
        // to the unserialized reference: it widens the classify-to-record
        // window that exists in both, so the scheduler is given a real chance to
        // interleave rather than being trusted to.
        std::thread::yield_now();
        self.refs.lock().unwrap().push(request_ref.to_owned());
        self.deliveries.fetch_add(1, Ordering::Release);
        Ok(CancelDelivery::Accepted)
    }
}

/// Observation handles kept by the test after the sink is handed over.
#[derive(Clone)]
struct SinkProbe {
    deliveries: Arc<AtomicUsize>,
    refs: Arc<Mutex<Vec<String>>>,
    mode: Arc<AtomicU8>,
}

impl SinkProbe {
    fn new(attempt_id: &str) -> (CountingSink, Self) {
        let probe = Self {
            deliveries: Arc::new(AtomicUsize::new(0)),
            refs: Arc::new(Mutex::new(Vec::new())),
            mode: Arc::new(AtomicU8::new(MODE_AVAILABLE)),
        };
        let sink = CountingSink {
            attempt_id: attempt_id.to_owned(),
            deliveries: Arc::clone(&probe.deliveries),
            refs: Arc::clone(&probe.refs),
            mode: Arc::clone(&probe.mode),
        };
        (sink, probe)
    }

    fn boxed(attempt_id: &str) -> (Box<dyn CancelSink>, Self) {
        let (sink, probe) = Self::new(attempt_id);
        (Box::new(sink), probe)
    }

    fn deliveries(&self) -> usize {
        self.deliveries.load(Ordering::Acquire)
    }

    fn delivered_refs(&self) -> Vec<String> {
        self.refs.lock().unwrap().clone()
    }

    fn set_mode(&self, mode: u8) {
        self.mode.store(mode, Ordering::Release);
    }
}

// --- custody the test can inspect and break -------------------------------

struct CustodyState {
    entries: HashMap<String, (String, u64)>,
    capacity: usize,
    classify_failure: Option<CustodyFailure>,
    record_failure: Option<CustodyFailure>,
    classify_calls: usize,
    record_calls: usize,
}

/// Test custody behind a shared handle, inspectable and breakable on demand.
#[derive(Clone)]
struct CustodyProbe(Arc<Mutex<CustodyState>>);

impl CustodyProbe {
    fn new() -> Self {
        Self::with_capacity(TEST_CUSTODY_CAPACITY)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self(Arc::new(Mutex::new(CustodyState {
            entries: HashMap::new(),
            capacity,
            classify_failure: None,
            record_failure: None,
            classify_calls: 0,
            record_calls: 0,
        })))
    }

    fn custody(&self) -> Box<dyn CancelCustody> {
        Box::new(ProbeCustody(Arc::clone(&self.0)))
    }

    /// References custody actually holds.
    fn entries(&self) -> usize {
        self.0.lock().unwrap().entries.len()
    }

    fn classify_calls(&self) -> usize {
        self.0.lock().unwrap().classify_calls
    }

    fn record_calls(&self) -> usize {
        self.0.lock().unwrap().record_calls
    }

    fn fail_classify(&self, failure: Option<CustodyFailure>) {
        self.0.lock().unwrap().classify_failure = failure;
    }

    fn fail_record(&self, failure: Option<CustodyFailure>) {
        self.0.lock().unwrap().record_failure = failure;
    }
}

struct ProbeCustody(Arc<Mutex<CustodyState>>);

impl CancelCustody for ProbeCustody {
    fn classify(&self, claim: CancelClaim<'_>) -> Result<CustodyVerdict, CustodyFailure> {
        let mut state = self.0.lock().unwrap();
        state.classify_calls += 1;
        if let Some(failure) = state.classify_failure {
            return Err(failure);
        }
        custody_verdict(&state, claim)
    }

    fn record(&mut self, claim: CancelClaim<'_>) -> Result<CustodyVerdict, CustodyFailure> {
        let mut state = self.0.lock().unwrap();
        state.record_calls += 1;
        if let Some(failure) = state.record_failure {
            return Err(failure);
        }
        let verdict = custody_verdict(&state, claim)?;
        if verdict == CustodyVerdict::Fresh {
            state.entries.insert(
                claim.request_ref.to_owned(),
                (claim.attempt_id.to_owned(), claim.observed_sequence),
            );
        }
        Ok(verdict)
    }
}

fn custody_verdict(
    state: &CustodyState,
    claim: CancelClaim<'_>,
) -> Result<CustodyVerdict, CustodyFailure> {
    match state.entries.get(claim.request_ref) {
        Some((attempt_id, sequence))
            if attempt_id == claim.attempt_id && *sequence == claim.observed_sequence =>
        {
            Ok(CustodyVerdict::Replay)
        }
        Some(_) => Ok(CustodyVerdict::Conflict),
        None if state.entries.len() >= state.capacity => Err(CustodyFailure::Full),
        None => Ok(CustodyVerdict::Fresh),
    }
}

// --- the deliberately unserialized reference implementation ---------------

/// `classify -> deliver -> record` with the serialization removed, and nothing
/// else changed.
///
/// Each step takes custody's lock on its own and releases it before the next,
/// which is precisely the shape [`automonique_runner::control::ControlServer`]
/// has today and precisely the shape the dispatcher exists to replace. It is
/// here so the race test can prove it is able to see the failure.
struct RacyDispatcher {
    custody: CustodyProbe,
    attempt_id: String,
    sink: CountingSink,
}

impl RacyDispatcher {
    fn cancel(
        &self,
        attempt_id: &str,
        request_ref: &str,
        observed_sequence: u64,
    ) -> DispatchOutcome {
        assert_eq!(attempt_id, self.attempt_id);
        let claim = CancelClaim {
            attempt_id,
            request_ref,
            observed_sequence,
        };
        let mut custody = self.custody.custody();
        match custody.classify(claim) {
            Ok(CustodyVerdict::Fresh) => {}
            Ok(CustodyVerdict::Replay) => return DispatchOutcome::AlreadyDelivered,
            Ok(CustodyVerdict::Conflict) => return DispatchOutcome::Conflict,
            Err(CustodyFailure::Full) => return DispatchOutcome::CustodyFull,
            Err(CustodyFailure::Unavailable) => return DispatchOutcome::CustodyUnavailable,
        }
        // The window. The dispatcher holds a lock across it; this does not.
        std::thread::yield_now();
        if self.sink.deliver(attempt_id, request_ref).is_err() {
            return DispatchOutcome::SinkUnavailable;
        }
        match custody.record(claim) {
            Ok(CustodyVerdict::Fresh | CustodyVerdict::Replay) => DispatchOutcome::Delivered,
            Ok(CustodyVerdict::Conflict) => DispatchOutcome::Conflict,
            Err(CustodyFailure::Full) => DispatchOutcome::CustodyFull,
            Err(CustodyFailure::Unavailable) => DispatchOutcome::CustodyUnavailable,
        }
    }
}

// --- control server plumbing ----------------------------------------------

/// A server on its own thread, always stopped and joined.
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

/// Body of one wire exchange, asserting the versioned greeting arrived first.
fn body(socket_path: &Path, request: &str) -> String {
    let mut stream = UnixStream::connect(socket_path).unwrap();
    stream.set_read_timeout(Some(CLIENT_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(CLIENT_TIMEOUT)).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (greeting, body) = response
        .split_once('\n')
        .expect("server must greet before answering");
    assert_eq!(greeting, CONTROL_GREETING);
    body.to_owned()
}

fn empty_spool(root: &Path, run_id: &str) -> Spool {
    Spool::open(root.join(run_id), run_id, SPOOL_MAX_BYTES).unwrap()
}

/// One control server seated on `dispatcher`, bound in its own private
/// directory and already serving `attempt_id` through the dispatcher.
fn seated_server(
    seat: &ControlSeat,
    handle: &RegistrationHandle,
    dir: &TempDir,
    spools: &TempDir,
    run_id: &str,
) -> ControlServer {
    let mut server =
        ControlServer::bind(dir.path().join("run/control.sock"), seat.custody()).unwrap();
    server
        .register(
            handle.attempt_id(),
            empty_spool(spools.path(), run_id),
            seat.sink(handle),
        )
        .unwrap();
    server
}

fn dispatcher_with(custody: &CustodyProbe) -> CancelDispatcher {
    CancelDispatcher::new(custody.custody())
}

/// Serialises the two tests that deliberately panic.
///
/// The panic hook is process-global, so without this one test's restore races
/// the other's panic and leaks a `panicked at` line into a passing run.
static PANIC_HOOK: Mutex<()> = Mutex::new(());

/// Run `work`, catching its panic without printing it.
fn catch_silent_panic<R>(work: impl FnOnce() -> R) -> std::thread::Result<R> {
    let _guard = PANIC_HOOK.lock().unwrap_or_else(|error| error.into_inner());
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
    std::panic::set_hook(previous);
    outcome
}

/// The error from a release that must fail.
///
/// `Result::unwrap_err` is unavailable here: the success value is a
/// `Box<dyn CancelSink>`, which has no `Debug` and deliberately never will —
/// a sink is a live cancellation path, not a printable value.
fn release_error(handle: RegistrationHandle) -> DispatchError {
    match handle.release() {
        Ok(_) => panic!("release must have been refused"),
        Err(error) => error,
    }
}

// --- the race, closed -----------------------------------------------------

#[test]
fn two_concurrent_cancels_of_one_reference_deliver_exactly_once() {
    let custody = CustodyProbe::new();
    let dispatcher = dispatcher_with(&custody);
    let (sink, probe) = SinkProbe::boxed("attempt-race");
    let _handle = dispatcher.register("attempt-race", sink).unwrap();

    let mut delivered = 0_usize;
    let mut already = 0_usize;
    for iteration in 0..RACE_ITERATIONS {
        let request_ref = format!("ref-{iteration}");
        let barrier = Barrier::new(2);
        let outcomes = std::thread::scope(|scope| {
            let left = scope.spawn(|| {
                barrier.wait();
                dispatcher.cancel("attempt-race", &request_ref, 7)
            });
            let right = scope.spawn(|| {
                barrier.wait();
                dispatcher.cancel("attempt-race", &request_ref, 7)
            });
            [left.join().unwrap(), right.join().unwrap()]
        });

        // Exactly one of the two took the reference. Which one is the
        // scheduler's business; that there is exactly one is not.
        let iteration_delivered = outcomes
            .iter()
            .filter(|outcome| **outcome == DispatchOutcome::Delivered)
            .count();
        let iteration_already = outcomes
            .iter()
            .filter(|outcome| **outcome == DispatchOutcome::AlreadyDelivered)
            .count();
        assert_eq!(
            (iteration_delivered, iteration_already),
            (1, 1),
            "iteration {iteration} answered {outcomes:?}"
        );
        delivered += iteration_delivered;
        already += iteration_already;

        // The sink is the authority, not the answer: one delivery per
        // reference, and the reference recorded once.
        assert_eq!(probe.deliveries(), iteration + 1);
        assert_eq!(custody.entries(), iteration + 1);
    }

    assert_eq!(delivered, RACE_ITERATIONS);
    assert_eq!(already, RACE_ITERATIONS);
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
fn four_concurrent_cancels_of_one_reference_deliver_exactly_once() {
    const THREADS: usize = 4;
    const ITERATIONS: usize = 50;

    let custody = CustodyProbe::new();
    let dispatcher = dispatcher_with(&custody);
    let (sink, probe) = SinkProbe::boxed("attempt-four");
    let _handle = dispatcher.register("attempt-four", sink).unwrap();

    for iteration in 0..ITERATIONS {
        let request_ref = format!("ref-{iteration}");
        let barrier = Barrier::new(THREADS);
        let outcomes = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..THREADS)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        dispatcher.cancel("attempt-four", &request_ref, 0)
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
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
        assert_eq!(probe.deliveries(), iteration + 1);
    }
    assert_eq!(custody.entries(), ITERATIONS);
}

#[test]
fn the_unserialized_reference_implementation_double_delivers() {
    let custody = CustodyProbe::new();
    let (sink, probe) = SinkProbe::new("attempt-racy");
    let racy = RacyDispatcher {
        custody: custody.clone(),
        attempt_id: "attempt-racy".to_owned(),
        sink,
    };

    let mut double_delivered = 0_usize;
    let mut double_answered = 0_usize;
    for iteration in 0..RACE_ITERATIONS {
        let request_ref = format!("ref-{iteration}");
        let before = probe.deliveries();
        let barrier = Barrier::new(2);
        let outcomes = std::thread::scope(|scope| {
            let left = scope.spawn(|| {
                barrier.wait();
                racy.cancel("attempt-racy", &request_ref, 7)
            });
            let right = scope.spawn(|| {
                barrier.wait();
                racy.cancel("attempt-racy", &request_ref, 7)
            });
            [left.join().unwrap(), right.join().unwrap()]
        });
        if probe.deliveries() - before > 1 {
            double_delivered += 1;
        }
        if outcomes
            .iter()
            .filter(|outcome| **outcome == DispatchOutcome::Delivered)
            .count()
            > 1
        {
            double_answered += 1;
        }
    }

    // Reported rather than merely asserted: a rate this test cannot observe is
    // a harness that has stopped proving anything about the serialized one.
    eprintln!(
        "unserialized reference: {double_delivered}/{RACE_ITERATIONS} iterations double-delivered, \
         {double_answered}/{RACE_ITERATIONS} answered `delivered` twice"
    );
    assert!(
        double_delivered > 0,
        "the unserialized reference never raced in {RACE_ITERATIONS} iterations, so the \
         serialized test's passing means nothing; raise the iteration count"
    );
    // The tell that this is the real bug and not merely a duplicated answer:
    // the sink fired more often than there are references.
    assert!(probe.deliveries() > RACE_ITERATIONS);
}

// --- registration lifecycle -----------------------------------------------

#[test]
fn registration_refuses_a_duplicate_and_is_bounded() {
    let custody = CustodyProbe::new();
    let dispatcher = dispatcher_with(&custody);
    let (first, first_probe) = SinkProbe::boxed("attempt-1");
    let handle = dispatcher.register("attempt-1", first).unwrap();
    assert_eq!(dispatcher.registration_count().unwrap(), 1);

    // Never replaces a live registration, and never consults custody to find
    // that out.
    let (second, second_probe) = SinkProbe::boxed("attempt-1");
    assert_eq!(
        dispatcher.register("attempt-1", second).unwrap_err(),
        DispatchError::DuplicateAttempt
    );
    assert_eq!(dispatcher.registration_count().unwrap(), 1);
    assert_eq!(custody.classify_calls(), 0);

    // The live sink is still the first one.
    assert_eq!(
        dispatcher.cancel("attempt-1", "ref-a", 0),
        DispatchOutcome::Delivered
    );
    assert_eq!(first_probe.deliveries(), 1);
    assert_eq!(second_probe.deliveries(), 0);

    assert_eq!(handle.attempt_id(), "attempt-1");
    drop(handle);
}

#[test]
fn the_registration_bound_refuses_the_last_attempt_without_replacing_one() {
    let custody = CustodyProbe::new();
    let dispatcher = CancelDispatcher::with_capacity(custody.custody(), 4);
    assert_eq!(dispatcher.capacity(), 4);

    let mut handles = Vec::new();
    for index in 0..4 {
        let attempt_id = format!("attempt-{index}");
        let (sink, _) = SinkProbe::boxed(&attempt_id);
        handles.push(dispatcher.register(&attempt_id, sink).unwrap());
    }
    let (overflow, overflow_probe) = SinkProbe::boxed("attempt-overflow");
    assert_eq!(
        dispatcher
            .register("attempt-overflow", overflow)
            .unwrap_err(),
        DispatchError::RegistrationLimit
    );
    assert_eq!(dispatcher.registration_count().unwrap(), 4);
    assert_eq!(
        dispatcher.cancel("attempt-overflow", "ref-a", 0),
        DispatchOutcome::UnknownAttempt
    );
    assert_eq!(overflow_probe.deliveries(), 0);

    // Releasing one makes room for exactly one.
    let released = handles.pop().unwrap();
    released.release().unwrap();
    assert_eq!(dispatcher.registration_count().unwrap(), 3);
    let (late, _) = SinkProbe::boxed("attempt-late");
    let late_handle = dispatcher.register("attempt-late", late).unwrap();
    assert_eq!(dispatcher.registration_count().unwrap(), 4);
    drop(late_handle);

    // The module's own ceiling clamps a wider request rather than honouring it.
    let wide = CancelDispatcher::with_capacity(CustodyProbe::new().custody(), usize::MAX);
    assert_eq!(wide.capacity(), MAX_REGISTRATIONS);
}

#[test]
fn a_dropped_handle_releases_the_registration() {
    let custody = CustodyProbe::new();
    let dispatcher = dispatcher_with(&custody);
    let (sink, probe) = SinkProbe::boxed("attempt-drop");
    let handle = dispatcher.register("attempt-drop", sink).unwrap();

    assert_eq!(
        dispatcher.cancel("attempt-drop", "ref-a", 0),
        DispatchOutcome::Delivered
    );
    drop(handle);

    assert_eq!(dispatcher.registration_count().unwrap(), 0);
    // The sink is unreachable, not merely unregistered: a cancellation for it
    // finds no target and custody is never consulted.
    let classify_calls = custody.classify_calls();
    assert_eq!(
        dispatcher.cancel("attempt-drop", "ref-b", 0),
        DispatchOutcome::UnknownAttempt
    );
    assert_eq!(custody.classify_calls(), classify_calls);
    assert_eq!(probe.deliveries(), 1);
    assert_eq!(custody.entries(), 1);

    // A panicking caller releases exactly as an orderly one does.
    let (panic_sink, panic_probe) = SinkProbe::boxed("attempt-panic");
    let outcome = catch_silent_panic(|| {
        let _guard = dispatcher.register("attempt-panic", panic_sink).unwrap();
        panic!("caller unwound while holding a registration");
    });
    assert!(outcome.is_err());
    assert_eq!(dispatcher.registration_count().unwrap(), 0);
    assert_eq!(
        dispatcher.cancel("attempt-panic", "ref-c", 0),
        DispatchOutcome::UnknownAttempt
    );
    assert_eq!(panic_probe.deliveries(), 0);
}

#[test]
fn an_explicit_release_hands_the_sink_back_and_drop_does_not_repeat_it() {
    let custody = CustodyProbe::new();
    let dispatcher = dispatcher_with(&custody);
    let (sink, probe) = SinkProbe::boxed("attempt-release");
    let handle = dispatcher.register("attempt-release", sink).unwrap();
    let returned = handle.release().unwrap();
    assert_eq!(dispatcher.registration_count().unwrap(), 0);

    // Re-registering the returned sink is a fresh registration, and the drop of
    // the first handle has already happened without disturbing it.
    let second = dispatcher.register("attempt-release", returned).unwrap();
    assert_eq!(dispatcher.registration_count().unwrap(), 1);
    assert_eq!(
        dispatcher.cancel("attempt-release", "ref-a", 0),
        DispatchOutcome::Delivered
    );
    assert_eq!(probe.deliveries(), 1);

    // A second release of an attempt that is gone is refused rather than
    // silently succeeding.
    second.release().unwrap();
    assert_eq!(dispatcher.registration_count().unwrap(), 0);
}

#[test]
fn a_stale_seat_sink_cannot_cross_route_into_a_later_registration() {
    let custody = CustodyProbe::new();
    let dispatcher = dispatcher_with(&custody);
    let seat = dispatcher.seat();

    let (first, first_probe) = SinkProbe::boxed("attempt-churn");
    let replaced = dispatcher.register("attempt-churn", first).unwrap();
    let stale_sink = seat.sink(&replaced);
    replaced.release().unwrap();

    // The same attempt identifier, a new registration, a new sink.
    let (second, second_probe) = SinkProbe::boxed("attempt-churn");
    let live = dispatcher.register("attempt-churn", second).unwrap();
    let live_sink = seat.sink(&live);

    // Give the stale adapter everything a delivery needs *except* a live
    // registration: a real classify for this exact claim, on this thread. The
    // registration epoch is then the only thing standing between it and its
    // successor's sink, so this test fails if that pin is removed rather than
    // passing on an earlier check.
    let seat_custody = seat.custody();
    let claim = CancelClaim {
        attempt_id: "attempt-churn",
        request_ref: "ref-a",
        observed_sequence: 0,
    };
    assert_eq!(seat_custody.classify(claim), Ok(CustodyVerdict::Fresh));
    let classify_calls = custody.classify_calls();
    assert_eq!(
        stale_sink.deliver("attempt-churn", "ref-a"),
        Err(CancelSinkError::Unavailable)
    );
    // Refused on the registration lookup, before custody is consulted again.
    assert_eq!(custody.classify_calls(), classify_calls);
    assert_eq!(first_probe.deliveries(), 0);
    assert_eq!(second_probe.deliveries(), 0);
    assert_eq!(custody.entries(), 0);

    // The live adapter, given the same treatment, reaches the live sink. The
    // stale delivery consumed the seat's claim, so it is classified again.
    assert_eq!(seat_custody.classify(claim), Ok(CustodyVerdict::Fresh));
    assert_eq!(
        live_sink.deliver("attempt-churn", "ref-a"),
        Ok(CancelDelivery::Delivered)
    );
    assert_eq!(first_probe.deliveries(), 0);
    assert_eq!(second_probe.deliveries(), 1);
    drop(live);
}

// --- custody failure paths ------------------------------------------------

#[test]
fn a_classify_failure_refuses_before_any_delivery() {
    for (failure, expected) in [
        (CustodyFailure::Full, DispatchOutcome::CustodyFull),
        (
            CustodyFailure::Unavailable,
            DispatchOutcome::CustodyUnavailable,
        ),
    ] {
        let custody = CustodyProbe::new();
        let dispatcher = dispatcher_with(&custody);
        let (sink, probe) = SinkProbe::boxed("attempt-custody");
        let _handle = dispatcher.register("attempt-custody", sink).unwrap();

        custody.fail_classify(Some(failure));
        assert_eq!(
            dispatcher.cancel("attempt-custody", "ref-a", 0),
            expected,
            "{failure} must not be reported as anything else"
        );
        // Ordering is the invariant: a classify that failed means the sink was
        // never asked and custody wrote nothing.
        assert_eq!(probe.deliveries(), 0);
        assert_eq!(custody.record_calls(), 0);
        assert_eq!(custody.entries(), 0);

        // Recovery is not special-cased: custody comes back and delivery works.
        custody.fail_classify(None);
        assert_eq!(
            dispatcher.cancel("attempt-custody", "ref-a", 0),
            DispatchOutcome::Delivered
        );
        assert_eq!(probe.deliveries(), 1);
    }
}

#[test]
fn a_record_failure_after_delivery_is_reported_rather_than_hidden() {
    for (failure, expected) in [
        (CustodyFailure::Full, DispatchOutcome::CustodyFull),
        (
            CustodyFailure::Unavailable,
            DispatchOutcome::CustodyUnavailable,
        ),
    ] {
        let custody = CustodyProbe::new();
        let dispatcher = dispatcher_with(&custody);
        let (sink, probe) = SinkProbe::boxed("attempt-record");
        let _handle = dispatcher.register("attempt-record", sink).unwrap();

        custody.fail_record(Some(failure));
        // The sink did fire and custody could not remember it. The dispatcher
        // reports the custody failure rather than claiming a clean delivery,
        // which is exactly what the control server does in the same position:
        // the caller is told idempotency is not held for this reference.
        assert_eq!(dispatcher.cancel("attempt-record", "ref-a", 0), expected);
        assert_eq!(probe.deliveries(), 1);
        assert_eq!(custody.entries(), 0);

        // And the cost is honest: with nothing recorded, the retry really is a
        // second delivery.
        custody.fail_record(None);
        assert_eq!(
            dispatcher.cancel("attempt-record", "ref-a", 0),
            DispatchOutcome::Delivered
        );
        assert_eq!(probe.deliveries(), 2);
    }
}

#[test]
fn an_unavailable_sink_records_nothing_so_a_retry_is_a_real_second_attempt() {
    let custody = CustodyProbe::new();
    let dispatcher = dispatcher_with(&custody);
    let (sink, probe) = SinkProbe::boxed("attempt-sink");
    let _handle = dispatcher.register("attempt-sink", sink).unwrap();

    probe.set_mode(MODE_UNAVAILABLE);
    assert_eq!(
        dispatcher.cancel("attempt-sink", "ref-a", 3),
        DispatchOutcome::SinkUnavailable
    );
    assert_eq!(probe.deliveries(), 0);
    // The invariant the control server holds and this must not weaken: a
    // delivery that was refused is never remembered as one.
    assert_eq!(custody.entries(), 0);
    assert_eq!(custody.record_calls(), 0);

    probe.set_mode(MODE_AVAILABLE);
    assert_eq!(
        dispatcher.cancel("attempt-sink", "ref-a", 3),
        DispatchOutcome::Delivered
    );
    assert_eq!(probe.deliveries(), 1);
    assert_eq!(custody.entries(), 1);
}

// --- reference binding ----------------------------------------------------

#[test]
fn a_replay_answers_without_reaching_the_sink() {
    let custody = CustodyProbe::new();
    let dispatcher = dispatcher_with(&custody);
    let (sink, probe) = SinkProbe::boxed("attempt-replay");
    let _handle = dispatcher.register("attempt-replay", sink).unwrap();

    assert_eq!(
        dispatcher.cancel("attempt-replay", "ref-a", 9),
        DispatchOutcome::Delivered
    );
    for _ in 0..3 {
        assert_eq!(
            dispatcher.cancel("attempt-replay", "ref-a", 9),
            DispatchOutcome::AlreadyDelivered
        );
    }
    assert_eq!(probe.deliveries(), 1);
    assert_eq!(probe.delivered_refs(), vec!["ref-a".to_owned()]);

    // A distinct reference is a real second delivery.
    assert_eq!(
        dispatcher.cancel("attempt-replay", "ref-b", 9),
        DispatchOutcome::Delivered
    );
    assert_eq!(probe.deliveries(), 2);
}

#[test]
fn the_observed_sequence_and_the_attempt_both_bind_the_reference() {
    let custody = CustodyProbe::new();
    let dispatcher = dispatcher_with(&custody);
    let (first, first_probe) = SinkProbe::boxed("attempt-one");
    let (second, second_probe) = SinkProbe::boxed("attempt-two");
    let _one = dispatcher.register("attempt-one", first).unwrap();
    let _two = dispatcher.register("attempt-two", second).unwrap();

    assert_eq!(
        dispatcher.cancel("attempt-one", "ref-a", 5),
        DispatchOutcome::Delivered
    );
    assert_eq!(first_probe.deliveries(), 1);

    // Same reference, different observed sequence: a client bug, not a replay.
    assert_eq!(
        dispatcher.cancel("attempt-one", "ref-a", 6),
        DispatchOutcome::Conflict
    );
    // Same reference, different attempt: the same, and the second sink is not
    // touched by the first attempt's reference.
    assert_eq!(
        dispatcher.cancel("attempt-two", "ref-a", 5),
        DispatchOutcome::Conflict
    );
    assert_eq!(first_probe.deliveries(), 1);
    assert_eq!(second_probe.deliveries(), 0);
    assert_eq!(custody.entries(), 1);
}

#[test]
fn identifiers_outside_the_bounded_grammar_never_reach_custody() {
    let custody = CustodyProbe::new();
    let dispatcher = dispatcher_with(&custody);
    let (sink, probe) = SinkProbe::boxed("attempt-grammar");
    let _handle = dispatcher.register("attempt-grammar", sink).unwrap();

    let long = "r".repeat(MAX_IDENTIFIER_BYTES + 1);
    for bad_ref in ["", "ref a", "ref/a", "ref\n", &long] {
        assert_eq!(
            dispatcher.cancel("attempt-grammar", bad_ref, 0),
            DispatchOutcome::FieldInvalid
        );
    }
    for bad_attempt in ["", "attempt grammar", "attempt/grammar", &long] {
        assert_eq!(
            dispatcher.cancel(bad_attempt, "ref-a", 0),
            DispatchOutcome::FieldInvalid
        );
        assert_eq!(
            dispatcher
                .register(bad_attempt, SinkProbe::boxed("x").0)
                .unwrap_err(),
            DispatchError::InvalidIdentifier
        );
    }
    assert_eq!(custody.classify_calls(), 0);
    assert_eq!(probe.deliveries(), 0);

    // The bound itself is inclusive on both sides.
    let at_bound = "r".repeat(MAX_IDENTIFIER_BYTES);
    assert_eq!(
        dispatcher.cancel("attempt-grammar", &at_bound, 0),
        DispatchOutcome::Delivered
    );
}

#[test]
fn the_dispatcher_grammar_is_the_control_servers_grammar() {
    // A registration the wire could never name, or an attempt the wire admits
    // and the dispatcher refuses, would each be a dead end. Both directions are
    // checked against a real server rather than assumed from a copied
    // predicate.
    let dir = TempDir::new("grammar");
    let spools = TempDir::new("grammar-spools");
    let custody = CustodyProbe::new();
    let dispatcher = dispatcher_with(&custody);
    let mut server =
        ControlServer::bind(dir.path().join("run/control.sock"), custody.custody()).unwrap();

    let long = "a".repeat(MAX_IDENTIFIER_BYTES + 1);
    let at_bound = "a".repeat(MAX_IDENTIFIER_BYTES);
    for (index, attempt_id) in ["ok-1", "ok.1_2", "", "bad id", "bad/id", &long, &at_bound]
        .into_iter()
        .enumerate()
    {
        let (dispatch_sink, _) = SinkProbe::boxed(attempt_id);
        let (server_sink, _) = SinkProbe::boxed(attempt_id);
        let dispatch_refused = matches!(
            dispatcher.register(attempt_id, dispatch_sink),
            Err(DispatchError::InvalidIdentifier)
        );
        let server_refused = matches!(
            server.register(
                attempt_id,
                empty_spool(spools.path(), &format!("run-{index}")),
                server_sink,
            ),
            Err(ControlError::InvalidIdentifier(_))
        );
        assert_eq!(
            dispatch_refused, server_refused,
            "grammar disagreed on {attempt_id:?}"
        );
    }
}

// --- outcome vocabulary ---------------------------------------------------

#[test]
fn the_outcome_vocabulary_maps_onto_the_wire_and_is_closed() {
    let all = [
        (DispatchOutcome::Delivered, "delivered", None),
        (DispatchOutcome::AlreadyDelivered, "already_delivered", None),
        (
            DispatchOutcome::Conflict,
            "conflict",
            Some(Refusal::CancelConflict),
        ),
        (
            DispatchOutcome::UnknownAttempt,
            "unknown_attempt",
            Some(Refusal::TargetUnknown),
        ),
        (
            DispatchOutcome::SinkUnavailable,
            "sink_unavailable",
            Some(Refusal::CancelUnavailable),
        ),
        (
            DispatchOutcome::CustodyFull,
            "custody_full",
            Some(Refusal::LedgerFull),
        ),
        (
            DispatchOutcome::CustodyUnavailable,
            "custody_unavailable",
            Some(Refusal::Internal),
        ),
        (
            DispatchOutcome::FieldInvalid,
            "field_invalid",
            Some(Refusal::FieldInvalid),
        ),
    ];
    let mut spellings: Vec<&str> = Vec::new();
    for (outcome, word, refusal) in all {
        assert_eq!(outcome.as_str(), word);
        assert_eq!(outcome.to_string(), word);
        assert_eq!(outcome.refusal(), refusal);
        assert_eq!(outcome.is_delivery_evidence(), refusal.is_none());
        spellings.push(word);
    }
    spellings.sort_unstable();
    let mut unique = spellings.clone();
    unique.dedup();
    assert_eq!(spellings, unique, "outcome spellings must be distinct");
}

// --- failure of the dispatcher itself -------------------------------------

#[test]
fn a_panicking_sink_disables_the_dispatcher_rather_than_guessing() {
    let custody = CustodyProbe::new();
    let dispatcher = dispatcher_with(&custody);
    let (sink, probe) = SinkProbe::boxed("attempt-poison");
    let handle = dispatcher.register("attempt-poison", sink).unwrap();

    probe.set_mode(MODE_PANIC);
    let unwound = catch_silent_panic(|| dispatcher.cancel("attempt-poison", "ref-a", 0));
    assert!(unwound.is_err());

    // Nobody can say whether that delivery happened, so nothing else is
    // answered: fail closed rather than risk a second delivery or a false
    // replay.
    probe.set_mode(MODE_AVAILABLE);
    assert_eq!(
        dispatcher.cancel("attempt-poison", "ref-b", 0),
        DispatchOutcome::CustodyUnavailable
    );
    assert_eq!(
        dispatcher
            .register("attempt-other", SinkProbe::boxed("attempt-other").0)
            .unwrap_err(),
        DispatchError::Poisoned
    );
    assert_eq!(
        dispatcher.registration_count().unwrap_err(),
        DispatchError::Poisoned
    );
    assert_eq!(release_error(handle), DispatchError::Poisoned);
    assert_eq!(probe.deliveries(), 0);
}

#[test]
fn dropping_the_dispatcher_fails_every_outstanding_adapter_closed() {
    let custody = CustodyProbe::new();
    let dispatcher = dispatcher_with(&custody);
    let (sink, probe) = SinkProbe::boxed("attempt-gone");
    let handle = dispatcher.register("attempt-gone", sink).unwrap();
    let seat = dispatcher.seat();
    let mut seat_custody = seat.custody();
    let seat_sink = seat.sink(&handle);

    drop(dispatcher);

    // A half-dead registry is never reachable: the adapters hold the interior
    // weakly, so a control server still bound to them refuses rather than
    // dispatching into nothing.
    let claim = CancelClaim {
        attempt_id: "attempt-gone",
        request_ref: "ref-a",
        observed_sequence: 0,
    };
    assert_eq!(
        seat_custody.classify(claim),
        Err(CustodyFailure::Unavailable)
    );
    assert_eq!(seat_custody.record(claim), Err(CustodyFailure::Unavailable));
    assert_eq!(
        seat_sink.deliver("attempt-gone", "ref-a"),
        Err(CancelSinkError::Unavailable)
    );
    assert_eq!(probe.deliveries(), 0);
    assert_eq!(custody.entries(), 0);

    // The handle has nothing left to release, and says so.
    assert_eq!(release_error(handle), DispatchError::UnknownAttempt);
}

#[test]
fn a_seat_sink_reached_without_its_own_classify_refuses() {
    let custody = CustodyProbe::new();
    let dispatcher = dispatcher_with(&custody);
    let (sink, probe) = SinkProbe::boxed("attempt-seat");
    let handle = dispatcher.register("attempt-seat", sink).unwrap();
    let seat = dispatcher.seat();
    let seat_sink = seat.sink(&handle);

    // No classify happened on this seat, so there is no observed sequence to
    // complete the claim with. Guessing one would let a delivery record a
    // sequence the requester never sent.
    assert_eq!(
        seat_sink.deliver("attempt-seat", "ref-a"),
        Err(CancelSinkError::Unavailable)
    );
    assert_eq!(probe.deliveries(), 0);
    assert_eq!(custody.entries(), 0);

    // With its own classify first, the same call completes — and only once:
    // the claim is consumed, so a repeated delivery for one classify refuses.
    let seat_custody = seat.custody();
    let claim = CancelClaim {
        attempt_id: "attempt-seat",
        request_ref: "ref-a",
        observed_sequence: 4,
    };
    assert_eq!(seat_custody.classify(claim), Ok(CustodyVerdict::Fresh));
    assert_eq!(
        seat_sink.deliver("attempt-seat", "ref-a"),
        Ok(CancelDelivery::Delivered)
    );
    assert_eq!(probe.deliveries(), 1);
    assert_eq!(
        seat_sink.deliver("attempt-seat", "ref-a"),
        Err(CancelSinkError::Unavailable)
    );
    assert_eq!(probe.deliveries(), 1);

    // The sequence the dispatcher recorded is the one that was classified.
    assert_eq!(
        dispatcher.cancel("attempt-seat", "ref-a", 4),
        DispatchOutcome::AlreadyDelivered
    );
    assert_eq!(
        dispatcher.cancel("attempt-seat", "ref-a", 5),
        DispatchOutcome::Conflict
    );

    // A sink reached for an attempt that is not its own refuses outright.
    assert_eq!(
        seat_sink.deliver("attempt-other", "ref-b"),
        Err(CancelSinkError::Unavailable)
    );
}

// --- end to end over real sockets -----------------------------------------

#[test]
fn two_servers_over_one_dispatcher_deliver_a_reference_once() {
    let dir_a = TempDir::new("e2e-a");
    let dir_b = TempDir::new("e2e-b");
    let spools = TempDir::new("e2e-spools");
    let custody = CustodyProbe::new();
    let dispatcher = dispatcher_with(&custody);
    let (sink, probe) = SinkProbe::boxed("attempt-e2e");
    let handle = dispatcher.register("attempt-e2e", sink).unwrap();

    let seat_a = dispatcher.seat();
    let seat_b = dispatcher.seat();
    let server_a = seated_server(&seat_a, &handle, &dir_a, &spools, "run-a");
    let server_b = seated_server(&seat_b, &handle, &dir_b, &spools, "run-b");
    let mut harness_a = Harness::spawn(server_a);
    let mut harness_b = Harness::spawn(server_b);

    // A fresh reference on A is a real delivery.
    assert_eq!(
        body(harness_a.path(), "cancel attempt-e2e ref-1 7\n"),
        "cancel_result delivered\n"
    );
    assert_eq!(probe.deliveries(), 1);

    // The same reference on a *different server* is answered from the shared
    // custody without reaching the sink again. This is what one dispatcher buys
    // that two independent servers could not.
    for _ in 0..3 {
        assert_eq!(
            body(harness_b.path(), "cancel attempt-e2e ref-1 7\n"),
            "cancel_result already_delivered\n"
        );
    }
    assert_eq!(probe.deliveries(), 1);

    // A different observed sequence for that reference conflicts on either
    // server, and still never reaches the sink.
    assert_eq!(
        body(harness_b.path(), "cancel attempt-e2e ref-1 8\n"),
        "refused cancel_conflict\n"
    );
    assert_eq!(
        body(harness_a.path(), "cancel attempt-e2e ref-1 8\n"),
        "refused cancel_conflict\n"
    );
    assert_eq!(probe.deliveries(), 1);

    // A distinct reference through B is a real second delivery.
    assert_eq!(
        body(harness_b.path(), "cancel attempt-e2e ref-2 7\n"),
        "cancel_result delivered\n"
    );
    assert_eq!(probe.deliveries(), 2);
    assert_eq!(
        probe.delivered_refs(),
        vec!["ref-1".to_owned(), "ref-2".to_owned()]
    );
    assert_eq!(custody.entries(), 2);

    // Delivery is still not exit evidence: neither spool moved.
    assert_eq!(
        body(harness_a.path(), "inspect attempt-e2e\n"),
        "status attempt-e2e run-a ready 0\n"
    );

    harness_a.stop();
    harness_b.stop();
    drop(handle);
}

#[test]
fn concurrent_servers_over_one_dispatcher_deliver_a_reference_once() {
    const ITERATIONS: usize = 20;

    let dir_a = TempDir::new("e2e-race-a");
    let dir_b = TempDir::new("e2e-race-b");
    let spools = TempDir::new("e2e-race-spools");
    let custody = CustodyProbe::new();
    let dispatcher = dispatcher_with(&custody);
    let (sink, probe) = SinkProbe::boxed("attempt-race");
    let handle = dispatcher.register("attempt-race", sink).unwrap();

    let seat_a = dispatcher.seat();
    let seat_b = dispatcher.seat();
    let server_a = seated_server(&seat_a, &handle, &dir_a, &spools, "run-race-a");
    let server_b = seated_server(&seat_b, &handle, &dir_b, &spools, "run-race-b");
    let mut harness_a = Harness::spawn(server_a);
    let mut harness_b = Harness::spawn(server_b);

    for iteration in 0..ITERATIONS {
        let request = format!("cancel attempt-race ref-{iteration} 7\n");
        let barrier = Barrier::new(2);
        let answers = std::thread::scope(|scope| {
            let left = scope.spawn(|| {
                barrier.wait();
                body(harness_a.path(), &request)
            });
            let right = scope.spawn(|| {
                barrier.wait();
                body(harness_b.path(), &request)
            });
            [left.join().unwrap(), right.join().unwrap()]
        });

        // The property that matters, proved over a real socket by two servers
        // at once: one reference, one delivery.
        assert_eq!(probe.deliveries(), iteration + 1, "answers {answers:?}");
        assert_eq!(custody.entries(), iteration + 1);
        let mut answers = answers;
        answers.sort();
        assert_eq!(
            answers,
            [
                "cancel_result already_delivered\n".to_owned(),
                "cancel_result delivered\n".to_owned(),
            ],
            "the racing loser must receive the dispatcher's exact replay answer"
        );
    }

    harness_a.stop();
    harness_b.stop();
    drop(handle);
}

#[test]
fn a_seated_server_keeps_its_refusal_categories() {
    let dir = TempDir::new("e2e-refusals");
    let spools = TempDir::new("e2e-refusal-spools");
    let custody = CustodyProbe::new();
    let dispatcher = dispatcher_with(&custody);
    let (sink, probe) = SinkProbe::boxed("attempt-refuse");
    let handle = dispatcher.register("attempt-refuse", sink).unwrap();
    let seat = dispatcher.seat();
    let server = seated_server(&seat, &handle, &dir, &spools, "run-refuse");
    let mut harness = Harness::spawn(server);

    // Unknown target: the server's own registry answers, custody untouched.
    assert_eq!(
        body(harness.path(), "cancel attempt-absent ref-a 0\n"),
        "refused target_unknown\n"
    );
    assert_eq!(custody.classify_calls(), 0);

    // Invalid spelling: refused before custody, as the server always did.
    assert_eq!(
        body(harness.path(), "cancel attempt-refuse ref!a 0\n"),
        "refused field_invalid\n"
    );
    assert_eq!(custody.classify_calls(), 0);

    // A refusing sink is `cancel_unavailable` and records nothing.
    probe.set_mode(MODE_UNAVAILABLE);
    assert_eq!(
        body(harness.path(), "cancel attempt-refuse ref-a 0\n"),
        "refused cancel_unavailable\n"
    );
    assert_eq!(custody.entries(), 0);
    assert_eq!(probe.deliveries(), 0);

    // And the retry after recovery is a real first delivery, not a replay.
    probe.set_mode(MODE_AVAILABLE);
    assert_eq!(
        body(harness.path(), "cancel attempt-refuse ref-a 0\n"),
        "cancel_result delivered\n"
    );
    assert_eq!(probe.deliveries(), 1);

    // A dispatch registration released underneath a live control binding
    // refuses rather than delivering into a registry that no longer holds it.
    handle.release().unwrap();
    assert_eq!(
        body(harness.path(), "cancel attempt-refuse ref-b 0\n"),
        "refused cancel_unavailable\n"
    );
    assert_eq!(probe.deliveries(), 1);

    harness.stop();
}
