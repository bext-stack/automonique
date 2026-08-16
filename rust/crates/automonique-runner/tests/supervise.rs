// SPDX-License-Identifier: Elastic-2.0

//! Exercised proof that supervision composes a real sandboxed run with a real
//! control socket: a peer inspects a live attempt and cancels it over the wire,
//! and the cancellation kills a `setsid`-escaped descendant for real.
//!
//! Nothing here is simulated. The workload is busybox under the full composed
//! sandbox, the control requests travel over a Unix socket through `accept`,
//! and every lifecycle assertion is made against the durable spool re-opened
//! from disk — `Spool::open` re-verifies the hash chain — rather than against
//! the supervisor's in-memory belief.
//!
//! # Anti-vacuity
//!
//! `a_wire_cancel_kills_the_tree_and_records_cancelled` and
//! `an_unrequested_run_reaches_its_natural_end_and_records_completed` drive the
//! **same workload script** with the same grants and the same deadline. The
//! only difference is what the peer does: one sends `cancel`, the other writes
//! the release file the script polls for. One records `cancelled`, the other
//! `completed`. So the kill in the first proof came from the wire request, not
//! from the harness, the deadline, or the end of the test.
//!
//! Like the containment, launch and backend proofs, this needs a delegated
//! cgroup v2 domain. Outside one, each test asserts the exact fail-closed
//! refusal, and `AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1` turns that
//! degradation into a failure so a verifying host cannot quietly skip it:
//!
//! ```sh
//! systemd-run --user --scope -p Delegate=yes \
//!   --setenv=AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1 \
//!   cargo test --manifest-path rust/Cargo.toml -p automonique-runner \
//!   --test supervise -- --test-threads=1
//! ```

use automonique_runner::backend::{
    BackendError, DirectProcessBackend, ExecutionOutcome, STARTED_PAYLOAD_PREFIX,
    TERMINAL_CANCELLED, TERMINAL_COMPLETED, TERMINAL_FAILED,
};
use automonique_runner::control::{
    CancelClaim, CancelCustody, CancelDelivery, CancelSink, CancelSinkError, ControlError,
    ControlServer, CustodyFailure, CustodyVerdict, Refusal,
};
use automonique_runner::filesystem::PathIntent;
use automonique_runner::supervise::{AttemptSupervisor, SuperviseError, VIEW_LIVE_PAYLOAD};
use automonique_runner::{
    Authority, CancellationToken, ContainmentDomain, ContainmentError, ContainmentLimits, Event,
    EventKind, LaunchPlan, RunState, Spool, process_is_live,
};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const HELPER: &str = env!("CARGO_BIN_EXE_automonique-launch-enter");
const BUSYBOX: &str = "/usr/bin/busybox";
const REQUIRE_ENFORCED_ENV: &str = "AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT";
const MAX_SPOOL_BYTES: u64 = 1024 * 1024;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);
/// Deadline handed to every supervised attempt here. It is deliberately below
/// the workload script's own 30-second ceiling, so a proof whose cancellation
/// never arrives fails as `timed_out` inside a bounded test run instead of
/// passing because the workload happened to end by itself.
const ATTEMPT_DEADLINE: Duration = Duration::from_secs(20);
/// Bound on a peer waiting for the workload to prove it is running.
const PEER_DEADLINE: Duration = Duration::from_secs(25);
/// Bound on the whole supervised call, well above `ATTEMPT_DEADLINE`.
const BOUNDED_RUN: Duration = Duration::from_secs(60);

fn busybox_sha256() -> String {
    format!("{:x}", Sha256::digest(fs::read(BUSYBOX).unwrap()))
}

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

/// A private temporary tree holding every location one proof needs.
///
/// The names are short by construction: the control socket path must fit
/// `sockaddr_un::sun_path`.
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("amq-sv-{label}-{serial}"));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        // The workload's writable scratch is a subdirectory of its own, so its
        // filesystem grant never reaches the spools or the control socket.
        fs::create_dir(path.join("work")).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn work(&self) -> PathBuf {
        self.0.join("work")
    }

    fn spool_root(&self) -> PathBuf {
        self.0.join("spool")
    }

    fn view_root(&self) -> PathBuf {
        self.0.join("view")
    }

    fn socket_path(&self) -> PathBuf {
        self.0.join("ctl.sock")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn identifier(prefix: char, label: &str) -> String {
    let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}{}-{label}-{serial}", std::process::id())
}

/// The delegated domain, or a loud, contract-checked degradation.
fn enforcement_domain(proof: &str) -> Option<ContainmentDomain> {
    match ContainmentDomain::discover() {
        Ok(found) => {
            eprintln!(
                "[supervise] ENFORCED  {proof}: domain {}",
                found.root().display()
            );
            Some(found)
        }
        Err(error) => {
            eprintln!("[supervise] NOT PROVEN {proof}: {error}");
            assert!(
                matches!(
                    error,
                    ContainmentError::DomainNotDelegated
                        | ContainmentError::NotUnifiedCgroupV2
                        | ContainmentError::MissingAtomicKill
                ),
                "undelegated environments must refuse with a typed reason, got {error:?}"
            );
            assert!(
                std::env::var_os(REQUIRE_ENFORCED_ENV).is_none(),
                "{REQUIRE_ENFORCED_ENV} is set, so {proof} must run against a \
                 delegated cgroup v2 domain, but none was available: {error}"
            );
            None
        }
    }
}

fn backend() -> DirectProcessBackend {
    DirectProcessBackend::new(HELPER).expect("the test helper path is absolute")
}

fn supervisor(temporary: &TempDir, attempt_id: &str, run_id: &str) -> AttemptSupervisor {
    AttemptSupervisor::new(
        backend(),
        attempt_id,
        run_id,
        temporary.spool_root(),
        temporary.view_root(),
        MAX_SPOOL_BYTES,
    )
    .expect("distinct absolute roots are accepted")
}

/// A plan running `script` under busybox sh with the standard test grants.
fn busybox_plan(script: &str, extra: impl FnOnce(LaunchPlan) -> LaunchPlan) -> LaunchPlan {
    let plan = LaunchPlan::new(BUSYBOX, busybox_sha256())
        .unwrap()
        .argument("sh")
        .unwrap()
        .argument("-c")
        .unwrap()
        .argument(script)
        .unwrap()
        .filesystem_grant(PathIntent::ReadExecute, BUSYBOX)
        .unwrap();
    extra(plan)
}

/// The workload both live-attempt proofs run, byte for byte.
///
/// It reports a `setsid` descendant's pid — the classic escape from a process
/// group, which only cgroup containment can reap — and then polls for a release
/// file the peer may or may not write. The iteration cap means a broken proof
/// ends by itself rather than hanging a test run.
fn observable_plan(temporary: &TempDir, pid_file: &Path, release_file: &Path) -> LaunchPlan {
    let script = format!(
        "{bb} setsid {bb} sh -c 'echo $$ > {pid}; exec {bb} sleep 300' & \
         i=0; while [ ! -f {release} ] && [ $i -lt 30 ]; do {bb} sleep 1; i=$((i+1)); done; exit 0",
        bb = BUSYBOX,
        pid = pid_file.display(),
        release = release_file.display()
    );
    busybox_plan(&script, |plan| {
        plan.filesystem_grant(PathIntent::ReadWrite, temporary.work())
            .unwrap()
            // A shell reopens a background job's stdin from /dev/null, and a
            // Landlock policy contains exactly what it names.
            .filesystem_grant(PathIntent::Read, "/dev/null")
            .unwrap()
    })
}

/// A cancel sink for records-phase bindings, counting what reaches it.
struct CountingSink {
    token: CancellationToken,
    deliveries: Arc<AtomicUsize>,
}

impl CancelSink for CountingSink {
    fn deliver(
        &self,
        _attempt_id: &str,
        _request_ref: &str,
    ) -> Result<CancelDelivery, CancelSinkError> {
        self.deliveries.fetch_add(1, Ordering::Release);
        self.token.cancel();
        Ok(CancelDelivery::Accepted)
    }
}

#[derive(Default)]
struct TestCustody(HashMap<String, (String, u64)>);

impl TestCustody {
    fn verdict(&self, claim: CancelClaim<'_>) -> CustodyVerdict {
        match self.0.get(claim.request_ref) {
            Some((attempt, sequence))
                if attempt == claim.attempt_id && *sequence == claim.observed_sequence =>
            {
                CustodyVerdict::Replay
            }
            Some(_) => CustodyVerdict::Conflict,
            None => CustodyVerdict::Fresh,
        }
    }
}

impl CancelCustody for TestCustody {
    fn classify(&self, claim: CancelClaim<'_>) -> Result<CustodyVerdict, CustodyFailure> {
        Ok(self.verdict(claim))
    }

    fn record(&mut self, claim: CancelClaim<'_>) -> Result<CustodyVerdict, CustodyFailure> {
        let verdict = self.verdict(claim);
        if verdict == CustodyVerdict::Fresh {
            self.0.insert(
                claim.request_ref.to_owned(),
                (claim.attempt_id.to_owned(), claim.observed_sequence),
            );
        }
        Ok(verdict)
    }
}

fn control_server(path: impl Into<PathBuf>) -> Result<ControlServer, ControlError> {
    ControlServer::bind(path, Box::<TestCustody>::default())
}

fn counting_sink() -> (Box<dyn CancelSink>, Arc<AtomicUsize>) {
    let deliveries = Arc::new(AtomicUsize::new(0));
    let sink = CountingSink {
        token: CancellationToken::new(),
        deliveries: Arc::clone(&deliveries),
    };
    (Box::new(sink), deliveries)
}

/// A control server running on a thread this harness owns and joins, handing
/// the server back so a test can keep registering against the same socket.
struct Harness {
    socket_path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<ControlServer>>,
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
            server
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

    fn stop(&mut self) -> Option<ControlServer> {
        self.stop.store(true, Ordering::Release);
        self.thread.take().map(|thread| thread.join().unwrap())
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        drop(self.stop());
    }
}

/// Send one request line and read the whole response body.
fn body(socket_path: &Path, request: &str) -> String {
    let mut stream = UnixStream::connect(socket_path).unwrap();
    stream.set_read_timeout(Some(CLIENT_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(CLIENT_TIMEOUT)).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (_greeting, body) = response
        .split_once('\n')
        .expect("server must greet before answering");
    body.to_owned()
}

fn wait_for_file(path: &Path, deadline: Duration) {
    let until = Instant::now() + deadline;
    while !path.exists() {
        assert!(
            Instant::now() < until,
            "the workload never produced {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Re-open a spool from disk, re-verifying its hash chain, and replay it.
fn replay(root: &Path, run_id: &str) -> Vec<Event> {
    let spool = Spool::open(root, run_id, MAX_SPOOL_BYTES)
        .expect("the recorded spool re-opens and its chain verifies");
    spool.events_after(0).expect("the whole record replays")
}

/// Assert the exact two-event lifecycle the backend records authoritatively.
fn assert_run_record(events: &[Event], run_id: &str, pid: nix::unistd::Pid, terminal: &[u8]) {
    assert_eq!(
        events.len(),
        2,
        "one attempt records exactly Started then Terminal, saw {events:?}"
    );
    assert_eq!(events[0].kind(), EventKind::Started);
    assert_eq!(events[0].authority(), Authority::Authoritative);
    assert_eq!(events[0].run_id(), run_id);
    assert_eq!(events[0].sequence(), 1);
    assert_eq!(
        events[0].payload(),
        started_payload(pid).as_bytes(),
        "the Started payload names the pid the supervisor actually spawned"
    );
    assert_eq!(events[1].kind(), EventKind::Terminal);
    assert_eq!(events[1].authority(), Authority::Authoritative);
    assert_eq!(events[1].sequence(), 2);
    assert_eq!(events[1].payload(), terminal);
}

/// Assert the supervisor's own view record: two synthetic events, the second
/// naming the same terminal class the run reached.
fn assert_view_record(events: &[Event], terminal: &[u8]) {
    assert_eq!(
        events.len(),
        2,
        "a view record is exactly live then terminal, saw {events:?}"
    );
    assert_eq!(events[0].kind(), EventKind::Started);
    assert_eq!(
        events[0].authority(),
        Authority::Synthetic,
        "a supervision view event must never claim authority over the run"
    );
    assert_eq!(events[0].payload(), VIEW_LIVE_PAYLOAD);
    assert_eq!(events[1].kind(), EventKind::Terminal);
    assert_eq!(events[1].authority(), Authority::Synthetic);
    assert_eq!(
        events[1].payload(),
        terminal,
        "the view must not name a different terminal class than the run"
    );
}

fn started_payload(pid: nix::unistd::Pid) -> String {
    format!("{STARTED_PAYLOAD_PREFIX}{}", pid.as_raw())
}

fn reported_descendant(pid_file: &Path) -> nix::unistd::Pid {
    let raw: i32 = fs::read_to_string(pid_file)
        .unwrap_or_else(|error| {
            panic!(
                "the workload never reported its descendant pid at {}: {error}",
                pid_file.display()
            )
        })
        .trim()
        .parse()
        .expect("pid parses");
    nix::unistd::Pid::from_raw(raw)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// What a peer observed over the wire while an attempt was live.
struct LiveObservations {
    heartbeat: String,
    inspect: String,
    subscribe: String,
    cancel: Option<String>,
}

/// Drive one live attempt from a peer thread: wait until the workload has
/// proven it is running, then exercise the socket. `cancel_ref` sends a real
/// cancellation; `None` instead releases the workload so it ends by itself.
fn live_peer(
    socket_path: PathBuf,
    attempt_id: String,
    pid_file: PathBuf,
    release_file: PathBuf,
    cancel_ref: Option<&'static str>,
) -> JoinHandle<LiveObservations> {
    std::thread::spawn(move || {
        wait_for_file(&pid_file, PEER_DEADLINE);
        let heartbeat = body(&socket_path, "heartbeat\n");
        let inspect = body(&socket_path, &format!("inspect {attempt_id}\n"));
        let subscribe = body(&socket_path, &format!("subscribe {attempt_id} 0\n"));
        let cancel = match cancel_ref {
            Some(request_ref) => Some(body(
                &socket_path,
                &format!("cancel {attempt_id} {request_ref}\n"),
            )),
            None => {
                fs::write(&release_file, b"go").unwrap();
                None
            }
        };
        LiveObservations {
            heartbeat,
            inspect,
            subscribe,
            cancel,
        }
    })
}

fn assert_live_observations(observed: &LiveObservations, attempt_id: &str, run_id: &str) {
    let (word, rest) = observed
        .heartbeat
        .split_once(' ')
        .expect("a heartbeat answer has fixed arity");
    assert_eq!(word, "heartbeat");
    let (uptime, bindings) = rest
        .trim_end_matches('\n')
        .split_once(' ')
        .expect("a heartbeat answer carries uptime and binding count");
    uptime.parse::<u64>().expect("uptime is canonical decimal");
    assert_eq!(
        bindings, "1",
        "exactly one attempt is bound while it is supervised"
    );
    assert_eq!(
        observed.inspect,
        format!("status {attempt_id} {run_id} running 1\n"),
        "a live attempt inspects as running"
    );
    assert_eq!(
        observed.subscribe,
        format!(
            "event 1 started synthetic {}\nend 1 false\n",
            hex(VIEW_LIVE_PAYLOAD)
        ),
        "a live subscription is the supervisor's synthetic view, never a claim \
         to be the run's authoritative log"
    );
}

#[test]
fn a_wire_cancel_kills_the_tree_and_records_cancelled() {
    let Some(domain) = enforcement_domain("a_wire_cancel_kills_the_tree_and_records_cancelled")
    else {
        return;
    };
    let temporary = TempDir::new("cancel");
    let attempt_id = identifier('a', "cancel");
    let run_id = identifier('r', "cancel");
    let pid_file = temporary.work().join("descendant.pid");
    let release_file = temporary.work().join("release");
    let cgroup = domain.root().join(format!("run-{run_id}"));

    let mut server = control_server(temporary.socket_path()).expect("the endpoint binds");
    let peer = live_peer(
        temporary.socket_path(),
        attempt_id.clone(),
        pid_file.clone(),
        release_file.clone(),
        Some("ref-cancel-1"),
    );

    let started = Instant::now();
    let supervised = supervisor(&temporary, &attempt_id, &run_id)
        .run(
            &mut server,
            &domain,
            ContainmentLimits::none(),
            observable_plan(&temporary, &pid_file, &release_file),
            ATTEMPT_DEADLINE,
        )
        .expect("cancellation is an outcome, not a supervisor failure");
    let elapsed = started.elapsed();
    let observed = peer.join().expect("the peer thread finishes");

    assert!(
        elapsed < BOUNDED_RUN,
        "supervision must be bounded; the attempt held the caller for {elapsed:?}"
    );
    assert_live_observations(&observed, &attempt_id, &run_id);
    assert_eq!(
        observed.cancel.as_deref(),
        Some("cancel_result delivered\n"),
        "a first cancellation for a bound attempt is delivered"
    );
    assert_eq!(
        supervised.cancel_deliveries(),
        1,
        "the wire request reached this attempt's sink exactly once"
    );

    // The kill is real, and it is descendant-complete.
    let escaped = reported_descendant(&pid_file);
    assert!(
        !process_is_live(escaped),
        "a setsid descendant must die with the attempt cancelled over the wire"
    );
    let pid = supervised
        .execution()
        .supervised_pid()
        .expect("a workload process existed");
    assert!(!process_is_live(pid), "the supervised process must be dead");
    assert!(
        !cgroup.exists(),
        "disposal must leave no kernel residue at {}",
        cgroup.display()
    );
    assert_eq!(
        supervised.execution().outcome(),
        ExecutionOutcome::Cancelled
    );
    assert_eq!(supervised.execution().status().state(), RunState::Cancelled);
    assert_eq!(
        supervised.spool().status().state(),
        RunState::Cancelled,
        "the returned spool is the run's own record, re-opened and re-verified"
    );
    assert_eq!(
        server.binding_count(),
        0,
        "a finished attempt leaves no live binding"
    );
    assert_view_record(&replay(&temporary.view_root(), &run_id), TERMINAL_CANCELLED);

    // Records phase: the authoritative spool answers for the same attempt, and
    // the server's cancel ledger survived the intervening unregister.
    let (sink, deliveries) = counting_sink();
    server
        .register(&attempt_id, supervised.into_spool(), sink)
        .expect("the authoritative spool binds after the run");
    let other_attempt = identifier('a', "other");
    let other_run = identifier('r', "other");
    let (other_sink, other_deliveries) = counting_sink();
    server
        .register(
            &other_attempt,
            Spool::open(temporary.path().join("other"), &other_run, MAX_SPOOL_BYTES).unwrap(),
            other_sink,
        )
        .expect("a second attempt binds");
    let mut harness = Harness::spawn(server);

    assert_eq!(
        body(harness.path(), &format!("inspect {attempt_id}\n")),
        format!("status {attempt_id} {run_id} cancelled 2\n"),
        "after the run the binding projects the durable record"
    );
    assert_eq!(
        body(harness.path(), &format!("subscribe {attempt_id} 0\n")),
        format!(
            "event 1 started authoritative {}\nevent 2 terminal authoritative {}\nend 2 false\n",
            hex(started_payload(pid).as_bytes()),
            hex(TERMINAL_CANCELLED)
        ),
        "the recorded lifecycle replays byte for byte"
    );
    assert_eq!(
        body(
            harness.path(),
            &format!("cancel {attempt_id} ref-cancel-1\n")
        ),
        "cancel_result already_delivered\n",
        "a replayed reference is idempotent across the binding swap"
    );
    assert_eq!(
        deliveries.load(Ordering::Acquire),
        0,
        "a replay must not reach a sink at all"
    );
    assert_eq!(
        body(
            harness.path(),
            &format!("cancel {other_attempt} ref-cancel-1\n")
        ),
        format!("refused {}\n", Refusal::CancelConflict.as_str()),
        "reusing a reference against another attempt conflicts rather than \
         delivering"
    );
    assert_eq!(other_deliveries.load(Ordering::Acquire), 0);

    let socket_path = temporary.socket_path();
    drop(harness.stop());
    assert!(
        !socket_path.exists(),
        "the server must unlink its own socket inode"
    );
    // The bindings are gone with the server, so the durable record can be
    // re-opened and replayed from disk one last time.
    assert_run_record(
        &replay(&temporary.spool_root(), &run_id),
        &run_id,
        pid,
        TERMINAL_CANCELLED,
    );
}

#[test]
fn an_unrequested_run_reaches_its_natural_end_and_records_completed() {
    let Some(domain) =
        enforcement_domain("an_unrequested_run_reaches_its_natural_end_and_records_completed")
    else {
        return;
    };
    let temporary = TempDir::new("natural");
    let attempt_id = identifier('a', "natural");
    let run_id = identifier('r', "natural");
    let pid_file = temporary.work().join("descendant.pid");
    let release_file = temporary.work().join("release");
    let cgroup = domain.root().join(format!("run-{run_id}"));

    let mut server = control_server(temporary.socket_path()).expect("the endpoint binds");
    let peer = live_peer(
        temporary.socket_path(),
        attempt_id.clone(),
        pid_file.clone(),
        release_file.clone(),
        None,
    );

    let supervised = supervisor(&temporary, &attempt_id, &run_id)
        .run(
            &mut server,
            &domain,
            ContainmentLimits::none(),
            observable_plan(&temporary, &pid_file, &release_file),
            ATTEMPT_DEADLINE,
        )
        .expect("an uncancelled run is not a supervisor failure");
    let observed = peer.join().expect("the peer thread finishes");

    // Identical workload, identical inspection, no cancel request: the outcome
    // is the opposite one, so the cancelled proof's kill came from the wire.
    assert_live_observations(&observed, &attempt_id, &run_id);
    assert!(observed.cancel.is_none());
    assert_eq!(
        supervised.execution().outcome(),
        ExecutionOutcome::Completed,
        "the same workload ends by itself when nothing cancels it"
    );
    assert_eq!(supervised.execution().status().state(), RunState::Completed);
    assert_eq!(
        supervised.cancel_deliveries(),
        0,
        "no cancellation was delivered to this attempt"
    );
    assert!(!cgroup.exists(), "disposal must leave no kernel residue");

    let pid = supervised
        .execution()
        .supervised_pid()
        .expect("a workload process existed");
    let escaped = reported_descendant(&pid_file);
    assert!(
        !process_is_live(escaped),
        "disposal reaps the escaped descendant even on a successful run"
    );
    assert_view_record(&replay(&temporary.view_root(), &run_id), TERMINAL_COMPLETED);

    // The binding is gone the moment the run ends, so the attempt is unknown to
    // the wire until the caller republishes it.
    assert_eq!(server.binding_count(), 0);
    let mut released = Harness::spawn(server);
    assert_eq!(
        body(
            released.path(),
            &format!("cancel {attempt_id} ref-late-1\n")
        ),
        format!("refused {}\n", Refusal::TargetUnknown.as_str()),
        "cancelling a released attempt is refused, not silently accepted"
    );
    assert_eq!(
        body(released.path(), &format!("inspect {attempt_id}\n")),
        format!("refused {}\n", Refusal::TargetUnknown.as_str())
    );
    let mut server = released.stop().expect("the harness returns its server");

    let (sink, _deliveries) = counting_sink();
    server
        .register(&attempt_id, supervised.into_spool(), sink)
        .expect("the authoritative spool binds after the run");
    let mut harness = Harness::spawn(server);
    assert_eq!(
        body(harness.path(), &format!("inspect {attempt_id}\n")),
        format!("status {attempt_id} {run_id} completed 2\n")
    );
    assert_eq!(
        body(harness.path(), &format!("subscribe {attempt_id} 0\n")),
        format!(
            "event 1 started authoritative {}\nevent 2 terminal authoritative {}\nend 2 false\n",
            hex(started_payload(pid).as_bytes()),
            hex(TERMINAL_COMPLETED)
        ),
        "a completed run replays byte for byte"
    );
    drop(harness.stop());
    assert_run_record(
        &replay(&temporary.spool_root(), &run_id),
        &run_id,
        pid,
        TERMINAL_COMPLETED,
    );
}

#[test]
fn a_second_supervisor_for_a_bound_attempt_is_refused_before_any_cgroup() {
    let Some(domain) =
        enforcement_domain("a_second_supervisor_for_a_bound_attempt_is_refused_before_any_cgroup")
    else {
        return;
    };
    let temporary = TempDir::new("dup");
    let attempt_id = identifier('a', "dup");
    let run_id = identifier('r', "dup");
    let held_run = identifier('r', "held");
    let cgroup = domain.root().join(format!("run-{run_id}"));

    let mut server = control_server(temporary.socket_path()).expect("the endpoint binds");
    let (sink, deliveries) = counting_sink();
    server
        .register(
            &attempt_id,
            Spool::open(temporary.path().join("held"), &held_run, MAX_SPOOL_BYTES).unwrap(),
            sink,
        )
        .expect("the incumbent binding registers");

    let refusal = supervisor(&temporary, &attempt_id, &run_id)
        .run(
            &mut server,
            &domain,
            ContainmentLimits::none(),
            busybox_plan("exit 0", |plan| plan),
            ATTEMPT_DEADLINE,
        )
        .expect_err("an attempt identifier that is already bound is refused");
    assert!(
        matches!(
            refusal,
            SuperviseError::Control(ControlError::DuplicateAttempt)
        ),
        "expected DuplicateAttempt, got {refusal}"
    );

    // No cgroup, and no run spool at all: the binding is attempted before any
    // kernel or durable run state exists.
    assert!(
        !cgroup.exists(),
        "a refused binding must create no cgroup at {}",
        cgroup.display()
    );
    assert!(
        !temporary.spool_root().exists(),
        "a refused binding must not open the run's spool"
    );
    assert_eq!(
        server.binding_count(),
        1,
        "the incumbent binding must survive untouched"
    );
    assert_view_record(&replay(&temporary.view_root(), &run_id), TERMINAL_FAILED);
    assert_eq!(
        Spool::open(temporary.view_root(), &run_id, MAX_SPOOL_BYTES)
            .unwrap()
            .status()
            .state(),
        RunState::Failed,
        "a view record must never be left claiming a live attempt"
    );

    // The incumbent still answers, and its sink was never touched.
    let mut harness = Harness::spawn(server);
    assert_eq!(
        body(harness.path(), &format!("inspect {attempt_id}\n")),
        format!("status {attempt_id} {held_run} ready 0\n")
    );
    assert_eq!(deliveries.load(Ordering::Acquire), 0);
    let socket_path = temporary.socket_path();
    drop(harness.stop());
    assert!(!socket_path.exists(), "no socket inode is left behind");
}

#[test]
fn a_refused_preparation_releases_the_binding_and_leaves_no_residue() {
    let Some(domain) =
        enforcement_domain("a_refused_preparation_releases_the_binding_and_leaves_no_residue")
    else {
        return;
    };
    let temporary = TempDir::new("reuse");
    let run_id = identifier('r', "reuse");
    let cgroup = domain.root().join(format!("run-{run_id}"));
    let mut server = control_server(temporary.socket_path()).expect("the endpoint binds");

    let first = supervisor(&temporary, &identifier('a', "first"), &run_id)
        .run(
            &mut server,
            &domain,
            ContainmentLimits::none(),
            busybox_plan("exit 0", |plan| plan),
            ATTEMPT_DEADLINE,
        )
        .expect("a clean run");
    assert_eq!(first.execution().outcome(), ExecutionOutcome::Completed);
    // Releasing the returned spool releases its exclusive lock, so a later
    // attempt reaches the freshness refusal rather than a lock refusal.
    drop(first.into_spool());
    assert_eq!(server.binding_count(), 0);

    // A view root already carrying a closed record is refused before anything
    // is bound: one attempt, one view record.
    let reused_view = supervisor(&temporary, &identifier('a', "second"), &run_id)
        .run(
            &mut server,
            &domain,
            ContainmentLimits::none(),
            busybox_plan("exit 0", |plan| plan),
            ATTEMPT_DEADLINE,
        )
        .expect_err("a terminal view record is never continued");
    assert!(
        matches!(reused_view, SuperviseError::Spool(_)),
        "expected a spool refusal, got {reused_view}"
    );
    assert_eq!(server.binding_count(), 0);
    assert!(!cgroup.exists());

    // With a fresh view root the binding is taken, and then preparation refuses
    // the already-terminal run spool. The release path must still run.
    let attempt_id = identifier('a', "third");
    let fresh_view = temporary.path().join("view2");
    let refusal = AttemptSupervisor::new(
        backend(),
        &attempt_id,
        &run_id,
        temporary.spool_root(),
        &fresh_view,
        MAX_SPOOL_BYTES,
    )
    .unwrap()
    .run(
        &mut server,
        &domain,
        ContainmentLimits::none(),
        busybox_plan("exit 0", |plan| plan),
        ATTEMPT_DEADLINE,
    )
    .expect_err("a used run spool is refused");
    assert!(
        matches!(
            refusal,
            SuperviseError::Backend(BackendError::SpoolNotFresh)
        ),
        "expected SpoolNotFresh, got {refusal}"
    );
    assert_eq!(
        server.binding_count(),
        0,
        "a refused preparation must not leak a live binding"
    );
    assert!(
        !cgroup.exists(),
        "a refused preparation must leave no cgroup at {}",
        cgroup.display()
    );
    assert_view_record(&replay(&fresh_view, &run_id), TERMINAL_FAILED);
    assert_eq!(
        replay(&temporary.spool_root(), &run_id).len(),
        2,
        "a refused preparation must append nothing to the durable record"
    );

    // The released attempt is unknown to the wire, and the socket goes with the
    // server it belongs to.
    let mut harness = Harness::spawn(server);
    assert_eq!(
        body(harness.path(), &format!("cancel {attempt_id} ref-x-1\n")),
        format!("refused {}\n", Refusal::TargetUnknown.as_str())
    );
    let socket_path = temporary.socket_path();
    drop(harness.stop());
    assert!(!socket_path.exists(), "no socket inode is left behind");
}

#[test]
fn supervision_roots_are_refused_before_anything_is_recorded() {
    // No delegated domain needed: a supervisor that could write its view record
    // into the run's own spool directory must not be constructible anywhere.
    let temporary = TempDir::new("roots");
    let conflict = AttemptSupervisor::new(
        backend(),
        "a-roots",
        "r-roots",
        temporary.spool_root(),
        temporary.spool_root(),
        MAX_SPOOL_BYTES,
    )
    .expect_err("one directory cannot hold both records");
    assert!(
        matches!(conflict, SuperviseError::ViewRootConflict),
        "expected ViewRootConflict, got {conflict}"
    );

    let relative = AttemptSupervisor::new(
        backend(),
        "a-roots",
        "r-roots",
        "spool",
        temporary.view_root(),
        MAX_SPOOL_BYTES,
    )
    .expect_err("a relative root is refused");
    assert!(
        matches!(relative, SuperviseError::RootNotAbsolute),
        "expected RootNotAbsolute, got {relative}"
    );

    assert!(
        !temporary.spool_root().exists() && !temporary.view_root().exists(),
        "a refused supervisor must create no record directory"
    );
}

#[test]
fn cancelling_an_unbound_attempt_is_refused() {
    // The composition never widens the endpoint's own rule: an attempt no
    // supervisor has bound cannot be cancelled, and the refusal names only its
    // category.
    let temporary = TempDir::new("unbound");
    let server = control_server(temporary.socket_path()).expect("the endpoint binds");
    let mut harness = Harness::spawn(server);
    assert_eq!(
        body(harness.path(), "cancel a-unbound ref-unbound-1\n"),
        format!("refused {}\n", Refusal::TargetUnknown.as_str())
    );
    assert!(
        body(harness.path(), "heartbeat\n").ends_with(" 0\n"),
        "an endpoint with no supervised attempt holds no binding"
    );
    let socket_path = temporary.socket_path();
    drop(harness.stop());
    assert!(!socket_path.exists());
}
