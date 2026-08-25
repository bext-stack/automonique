// SPDX-License-Identifier: Elastic-2.0

//! Durable cancel custody, proved against a real ledger file.
//!
//! The restart tests here close the ledger and reopen the *file*; the
//! wire-level test drops a whole `ControlServer` and binds a new one with fresh
//! custody over that same file. Neither can pass against in-memory
//! idempotency, which is the entire reason this seam exists — an assertion that
//! survived a mere `clear()` would prove nothing.
//!
//! Refusals are asserted by category, never by message text, so a mutation that
//! reaches a different guard fails instead of slipping through a neighbouring
//! one. In particular a fatal ledger failure and a reused reference must never
//! be interchangeable: one says our storage is unsound and the other says the
//! client sent the same reference twice.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use automonique_daemon::cancel_custody::StoreCancelCustody;
use automonique_runner::control::{
    CONTROL_GREETING, CancelClaim, CancelCustody, CancelDelivery, CancelSink, CancelSinkError,
    ControlServer, CustodyFailure, CustodyVerdict,
};
use automonique_runner::{CancellationToken, Spool};
use automonique_store::cancel_ledger::CancelLedger;
use rusqlite::{Connection, params};

const SPOOL_MAX_BYTES: u64 = 1024 * 1024;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// A private root that outlives every ledger handle opened inside it.
///
/// The ledger path is stable across reopens on purpose: "the same file" is the
/// claim under test, so the test must not be able to accidentally prove it
/// against two different databases.
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
        self.directory.path().join("cancel-ledger.sqlite3")
    }

    /// Fresh custody over this root's one ledger file.
    fn custody(&self) -> StoreCancelCustody {
        StoreCancelCustody::new(CancelLedger::open(self.ledger_path()).expect("open ledger"))
    }
}

fn claim<'a>(attempt_id: &'a str, request_ref: &'a str, observed_sequence: u64) -> CancelClaim<'a> {
    CancelClaim {
        attempt_id,
        request_ref,
        observed_sequence,
    }
}

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_millis(),
    )
    .expect("clock in range")
}

// --- the trait against a real ledger --------------------------------------

#[test]
fn a_recorded_reference_replays_across_a_ledger_reopen() {
    let root = PrivateRoot::new();

    let before = now_ms();
    {
        let mut custody = root.custody();
        assert_eq!(
            custody.classify(claim("attempt-1", "ref-a", 7)),
            Ok(CustodyVerdict::Fresh)
        );
        assert_eq!(
            custody.record(claim("attempt-1", "ref-a", 7)),
            Ok(CustodyVerdict::Fresh)
        );
        // Within one handle it already replays.
        assert_eq!(
            custody.classify(claim("attempt-1", "ref-a", 7)),
            Ok(CustodyVerdict::Replay)
        );
    }
    let after = now_ms();

    // Everything above is gone: the handle, its connection, its process-local
    // state. Only the file remains.
    let mut custody = root.custody();
    assert_eq!(
        custody.classify(claim("attempt-1", "ref-a", 7)),
        Ok(CustodyVerdict::Replay),
        "a reopened ledger must recognise what its predecessor recorded"
    );
    // Recording the replay writes nothing and says so.
    assert_eq!(
        custody.record(claim("attempt-1", "ref-a", 7)),
        Ok(CustodyVerdict::Replay)
    );
    assert_eq!(custody.ledger().entry_count().expect("count"), 1);

    // A different reference is still new after the reopen, so the replay above
    // is memory of that one binding rather than a blanket answer.
    assert_eq!(
        custody.classify(claim("attempt-1", "ref-b", 7)),
        Ok(CustodyVerdict::Fresh)
    );

    // The timestamp came from the custody implementation's own clock. There is
    // no wire field for it, so it cannot have come from a caller.
    let entry = custody
        .ledger()
        .entry("ref-a")
        .expect("read entry")
        .expect("entry exists");
    assert_eq!(entry.attempt_id, "attempt-1");
    assert_eq!(entry.observed_sequence, 7);
    assert!(
        (before..=after).contains(&entry.requested_at_ms),
        "requested_at_ms {} is outside the window [{before}, {after}]",
        entry.requested_at_ms
    );
}

#[test]
fn reusing_a_reference_conflicts_on_either_bound_coordinate() {
    let root = PrivateRoot::new();
    let mut custody = root.custody();
    assert_eq!(
        custody.classify(claim("attempt-1", "ref-a", 7)),
        Ok(CustodyVerdict::Fresh)
    );
    assert_eq!(
        custody.record(claim("attempt-1", "ref-a", 7)),
        Ok(CustodyVerdict::Fresh)
    );

    // A different attempt under the same reference.
    assert_eq!(
        custody.classify(claim("attempt-2", "ref-a", 7)),
        Ok(CustodyVerdict::Conflict)
    );
    assert_eq!(
        custody.record(claim("attempt-2", "ref-a", 7)),
        Ok(CustodyVerdict::Conflict)
    );
    // A different observed sequence under the same reference and attempt.
    assert_eq!(
        custody.classify(claim("attempt-1", "ref-a", 8)),
        Ok(CustodyVerdict::Conflict)
    );
    assert_eq!(
        custody.record(claim("attempt-1", "ref-a", 8)),
        Ok(CustodyVerdict::Conflict)
    );

    // A conflict is an answer, not a write: the original binding is intact and
    // still replays, and no second row appeared.
    assert_eq!(custody.ledger().entry_count().expect("count"), 1);
    assert_eq!(
        custody.classify(claim("attempt-1", "ref-a", 7)),
        Ok(CustodyVerdict::Replay)
    );
    let entry = custody
        .ledger()
        .entry("ref-a")
        .expect("read entry")
        .expect("entry exists");
    assert_eq!(entry.attempt_id, "attempt-1");
    assert_eq!(entry.observed_sequence, 7);

    // And it survives a reopen as a conflict, not as a fresh claim.
    drop(custody);
    let mut custody = root.custody();
    assert_eq!(
        custody.classify(claim("attempt-2", "ref-a", 7)),
        Ok(CustodyVerdict::Conflict)
    );
}

#[test]
fn a_fatal_ledger_failure_is_a_custody_failure_and_never_a_conflict() {
    let root = PrivateRoot::new();
    // Establish the schema through the real API first, so the corruption below
    // is a bad row in a valid ledger rather than a malformed database.
    drop(root.custody());

    // A row this API could not have written: a control character in an
    // identifier fails the ledger's own re-validation on every read.
    let raw = Connection::open(root.ledger_path()).expect("raw connection");
    raw.execute(
        "INSERT INTO cancel_requests
         (request_ref, attempt_id, observed_sequence, requested_at_ms)
         VALUES (?1, ?2, ?3, ?4)",
        params!["ref-corrupt", "attempt\u{1}one", 7_i64, 1_000_i64],
    )
    .expect("insert corrupt row");
    drop(raw);

    let mut custody = root.custody();
    // Both halves of the pair refuse, and they refuse as *custody* failures.
    // A conflict here would tell the caller it reused a reference when in fact
    // this host's storage is unsound.
    assert_eq!(
        custody.classify(claim("attempt-1", "ref-corrupt", 7)),
        Err(CustodyFailure::Unavailable)
    );
    assert_eq!(
        custody.record(claim("attempt-1", "ref-corrupt", 7)),
        Err(CustodyFailure::Unavailable)
    );
    // The corruption is scoped to the row that carries it: an untouched
    // reference still works, so `Unavailable` is a real classification rather
    // than a blanket failure mode.
    assert_eq!(
        custody.classify(claim("attempt-1", "ref-sound", 7)),
        Ok(CustodyVerdict::Fresh)
    );
}

#[test]
fn a_full_ledger_refuses_a_new_binding_before_delivery_and_still_replays() {
    let root = PrivateRoot::new();
    let mut custody = StoreCancelCustody::new(
        CancelLedger::open_with_capacity(root.ledger_path(), 1).expect("open bounded ledger"),
    );

    assert_eq!(
        custody.classify(claim("attempt-1", "ref-a", 7)),
        Ok(CustodyVerdict::Fresh)
    );
    assert_eq!(
        custody.record(claim("attempt-1", "ref-a", 7)),
        Ok(CustodyVerdict::Fresh)
    );
    // Full is its own category: a bound the caller can see, not a conflict and
    // not an unsound ledger.
    assert_eq!(
        custody.classify(claim("attempt-1", "ref-b", 7)),
        Err(CustodyFailure::Full)
    );
    assert_eq!(
        custody.record(claim("attempt-1", "ref-b", 7)),
        Err(CustodyFailure::Full)
    );
    // A replay writes nothing, so a full ledger must never degrade it into a
    // refusal.
    assert_eq!(
        custody.classify(claim("attempt-1", "ref-a", 7)),
        Ok(CustodyVerdict::Replay)
    );
    // Nor may fullness mask a reuse: that is a client bug however full we are.
    assert_eq!(
        custody.classify(claim("attempt-2", "ref-a", 7)),
        Ok(CustodyVerdict::Conflict)
    );
    assert_eq!(custody.ledger().entry_count().expect("count"), 1);
}

// --- the same thing over the real wire ------------------------------------

/// A cancel sink over a real [`CancellationToken`], counting deliveries.
struct TokenSink {
    token: CancellationToken,
    deliveries: Arc<AtomicUsize>,
}

impl CancelSink for TokenSink {
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
            // Dropping here closes the listener, unlinks the socket inode and
            // — the part that matters for this test — closes the ledger
            // connection custody was holding.
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

/// Send one request line and return the response body, asserting the greeting.
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

#[test]
fn a_control_server_answers_already_delivered_after_a_full_restart() {
    let root = PrivateRoot::new();
    let socket_path = root.path().join("run/control.sock");
    let spools = root.path().join("spools");
    fs::create_dir(&spools).expect("spool root");

    let first_token = CancellationToken::new();
    let first_deliveries = Arc::new(AtomicUsize::new(0));
    let mut server = ControlServer::bind(&socket_path, Box::new(root.custody())).expect("bind");
    server
        .register(
            "attempt-1",
            Spool::open(spools.join("run-alpha"), "run-alpha", SPOOL_MAX_BYTES).expect("spool"),
            Box::new(TokenSink {
                token: first_token.clone(),
                deliveries: Arc::clone(&first_deliveries),
            }),
        )
        .expect("register");
    let mut harness = Harness::spawn(server);

    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-a 7\n"),
        "cancel_result delivered\n"
    );
    assert!(first_token.is_cancelled());
    assert_eq!(first_deliveries.load(Ordering::Acquire), 1);
    // Same server, same custody: an exact replay.
    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-a 7\n"),
        "cancel_result already_delivered\n"
    );
    assert_eq!(first_deliveries.load(Ordering::Acquire), 1);

    // Tear the whole endpoint down: listener, socket inode, bindings, spool
    // handle and the ledger connection all go away.
    harness.stop();
    assert!(!socket_path.exists(), "shutdown must unlink its socket");

    // A genuinely new server, a genuinely new sink, a genuinely new
    // `StoreCancelCustody` — over the same ledger file.
    let second_token = CancellationToken::new();
    let second_deliveries = Arc::new(AtomicUsize::new(0));
    let mut server = ControlServer::bind(&socket_path, Box::new(root.custody())).expect("rebind");
    server
        .register(
            "attempt-1",
            Spool::open(spools.join("run-alpha"), "run-alpha", SPOOL_MAX_BYTES).expect("reopen"),
            Box::new(TokenSink {
                token: second_token.clone(),
                deliveries: Arc::clone(&second_deliveries),
            }),
        )
        .expect("re-register");
    let mut harness = Harness::spawn(server);

    // The whole point: idempotency crossed a process-lifetime boundary.
    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-a 7\n"),
        "cancel_result already_delivered\n",
        "durable custody must recognise the predecessor's delivery"
    );
    // And it is a real replay, not a polite answer: the new sink was never
    // called and the new token never flipped.
    assert_eq!(second_deliveries.load(Ordering::Acquire), 0);
    assert!(!second_token.is_cancelled());

    // The recorded observed sequence still binds across the restart.
    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-a 8\n"),
        "refused cancel_conflict\n"
    );
    assert_eq!(second_deliveries.load(Ordering::Acquire), 0);

    // An unseen reference is still deliverable, so the server did not simply
    // start answering `already_delivered` to everything.
    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-b 8\n"),
        "cancel_result delivered\n"
    );
    assert_eq!(second_deliveries.load(Ordering::Acquire), 1);
    assert!(second_token.is_cancelled());

    harness.stop();

    // Both deliveries are durable and readable by anyone holding the file.
    let ledger = CancelLedger::open(root.ledger_path()).expect("final open");
    let entries = ledger.attempt_requests("attempt-1").expect("read attempt");
    let recorded: Vec<(&str, u64)> = entries
        .iter()
        .map(|entry| (entry.request_ref.as_str(), entry.observed_sequence))
        .collect();
    assert_eq!(recorded, vec![("ref-a", 7), ("ref-b", 8)]);
}

#[test]
fn a_broken_ledger_refuses_cancel_as_internal_without_taking_the_endpoint_down() {
    let root = PrivateRoot::new();
    let socket_path = root.path().join("run/control.sock");
    let spools = root.path().join("spools");
    fs::create_dir(&spools).expect("spool root");
    drop(root.custody());

    let raw = Connection::open(root.ledger_path()).expect("raw connection");
    raw.execute(
        "INSERT INTO cancel_requests
         (request_ref, attempt_id, observed_sequence, requested_at_ms)
         VALUES (?1, ?2, ?3, ?4)",
        params!["ref-corrupt", "attempt\u{1}one", 7_i64, 1_000_i64],
    )
    .expect("insert corrupt row");
    drop(raw);

    let deliveries = Arc::new(AtomicUsize::new(0));
    let mut server = ControlServer::bind(&socket_path, Box::new(root.custody())).expect("bind");
    server
        .register(
            "attempt-1",
            Spool::open(spools.join("run-alpha"), "run-alpha", SPOOL_MAX_BYTES).expect("spool"),
            Box::new(TokenSink {
                token: CancellationToken::new(),
                deliveries: Arc::clone(&deliveries),
            }),
        )
        .expect("register");
    let mut harness = Harness::spawn(server);

    // Our storage is unsound, so the category says so. `cancel_conflict` would
    // blame a caller that did nothing wrong.
    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-corrupt 7\n"),
        "refused internal\n"
    );
    assert_eq!(deliveries.load(Ordering::Acquire), 0);

    // A broken ledger takes down `cancel` for the affected reference and
    // nothing else: the endpoint still inspects, subscribes and beats.
    assert_eq!(
        body(harness.path(), "inspect attempt-1\n"),
        "status attempt-1 run-alpha ready 0\n"
    );
    assert_eq!(
        body(harness.path(), "subscribe attempt-1 0\n"),
        "provenance 854a69b1c40d31f741e320be2150acd6 attempt:attempt-1 run:run-alpha\nend 0 false\n"
    );
    assert!(body(harness.path(), "heartbeat\n").starts_with("heartbeat "));
    // And a sound reference still cancels.
    assert_eq!(
        body(harness.path(), "cancel attempt-1 ref-sound 7\n"),
        "cancel_result delivered\n"
    );
    assert_eq!(deliveries.load(Ordering::Acquire), 1);

    harness.stop();
}
