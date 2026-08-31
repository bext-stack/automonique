// SPDX-License-Identifier: Elastic-2.0

//! Support-board intake against a fake fleet.
//!
//! NOTHING HERE TOUCHES THE NETWORK. Every page is canned and handed back by a
//! [`FakeBoard`] that implements the same [`SupportBoard`] seam
//! `automonique_support_connector::FleetClient` does, so no socket is opened, no
//! credential exists and no fleet is contacted. That is not an incidental
//! property of these tests — it is the reason the seam is a trait.
//!
//! The durable half is real: every assertion below reads back through
//! `automonique_store::support_tickets::SupportTicketStore` on a real SQLite
//! file in a private temporary directory.

use automonique_daemon::shutdown_signal::ShutdownSignal;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use automonique_daemon::ticket_intake::{
    IntakeHalt, PollOutcome, SupportBoard, TicketIntake, TicketIntakeHost, TicketIntakeParams,
};
use automonique_store::support_tickets::{SupportTicketStore, TicketLifecycle};
use automonique_support_connector::{
    FleetFailure, FleetOutcome, ServerMessage, SupportIssue, SupportIssues, SupportScope,
};
use tempfile::TempDir;

/// One answer the fake fleet will give, in order.
enum Answer {
    Page(Vec<SupportIssue>),
    Refused(&'static str),
    Failed(FleetFailure),
}

/// A fleet that answers from a script and counts how often it was asked.
struct FakeBoard {
    answers: Mutex<Vec<Answer>>,
    calls: AtomicUsize,
    limits: Mutex<Vec<usize>>,
}

impl FakeBoard {
    fn new(answers: Vec<Answer>) -> Self {
        Self {
            answers: Mutex::new(answers),
            calls: AtomicUsize::new(0),
            limits: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl SupportBoard for FakeBoard {
    fn support_issues(&self, limit: usize) -> Result<FleetOutcome<SupportIssues>, FleetFailure> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.limits.lock().expect("limits").push(limit);
        let mut answers = self.answers.lock().expect("answers");
        // The last scripted answer repeats, so a loop test does not have to
        // guess how many iterations it will get.
        let answer = if answers.len() > 1 {
            answers.remove(0)
        } else {
            match answers.first() {
                Some(Answer::Page(issues)) => Answer::Page(issues.clone()),
                Some(Answer::Refused(reason)) => Answer::Refused(reason),
                Some(Answer::Failed(failure)) => Answer::Failed(*failure),
                None => Answer::Page(Vec::new()),
            }
        };
        match answer {
            Answer::Page(issues) => Ok(FleetOutcome::Accepted(SupportIssues {
                scope: SupportScope::Staff,
                issues,
            })),
            Answer::Refused(reason) => Ok(FleetOutcome::Rejected(ServerMessage::sanitized(reason))),
            Answer::Failed(failure) => Err(failure),
        }
    }
}

/// One issue exactly as the connector's decoder would have produced it.
fn issue(id: &str, status: &str) -> SupportIssue {
    SupportIssue {
        id: id.to_owned(),
        title: format!("Demande {id}"),
        tenant_name: "Boulangerie Milo".to_owned(),
        site_label: Some("milo.invalid".to_owned()),
        status: status.to_owned(),
        priority: "normal".to_owned(),
        source: "email".to_owned(),
        requested_by: "Claire".to_owned(),
        comment_count: 1,
        created_at: "2026-08-10T09:12:00.000Z".to_owned(),
        updated_at: "2026-08-13T17:04:11.000Z".to_owned(),
    }
}

struct PrivateState {
    _directory: TempDir,
}

impl PrivateState {
    fn new() -> (Self, std::path::PathBuf) {
        let directory = tempfile::tempdir().expect("temporary directory");
        std::fs::set_permissions(
            directory.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private permissions");
        let path = directory.path().join("support-tickets.sqlite3");
        (
            Self {
                _directory: directory,
            },
            path,
        )
    }
}

/// A worker over a scripted fleet and a real store on a private path.
fn intake(answers: Vec<Answer>) -> (PrivateState, std::path::PathBuf, TicketIntake<FakeBoard>) {
    let (state, path) = PrivateState::new();
    let store = SupportTicketStore::open(&path).expect("store opens");
    let worker = TicketIntake::new(FakeBoard::new(answers), store, 0);
    (state, path, worker)
}

fn reopen(path: &Path) -> SupportTicketStore {
    SupportTicketStore::open(path).expect("reopen store")
}

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

#[test]
fn a_first_poll_records_every_issue_the_fleet_returned() {
    let (_state, path, mut worker) = intake(vec![Answer::Page(vec![
        issue("iss-1", "open"),
        issue("iss-2", "triaging"),
        issue("iss-3", "in_progress"),
    ])]);

    let PollOutcome::Recorded(report) = worker.poll_once(1_000).expect("poll") else {
        panic!("a scripted page must be recorded");
    };
    assert_eq!(report.recorded, 3);
    assert_eq!(report.updated, 0);
    assert_eq!(report.unchanged, 0);
    assert_eq!(report.transitioned, 0);
    assert_eq!(report.refused, 0);
    assert_eq!(report.seen(), 3);

    let metrics = worker.metrics();
    assert_eq!(metrics.polls(), 1);
    assert_eq!(metrics.tickets_recorded(), 3);
    assert!(metrics.halt().is_none());

    let store = reopen(&path);
    assert_eq!(store.ticket_count().expect("count"), 3);
    let recorded = store.ticket("iss-2").expect("read").expect("present");
    assert_eq!(recorded.title, "Demande iss-2");
    assert_eq!(recorded.tenant_name, "Boulangerie Milo");
    assert_eq!(recorded.site_label.as_deref(), Some("milo.invalid"));
    // The fleet's own status is stored verbatim beside a lifecycle that is not
    // it: intake records what the board said, and separately what this host did.
    assert_eq!(recorded.fleet_status, "triaging");
    assert_eq!(recorded.lifecycle, TicketLifecycle::New);
    assert_eq!(recorded.first_seen_ms, 1_000);
    assert_eq!(recorded.last_synced_ms, 1_000);
}

/// THE DEDUP PROOF. Polling the same board again is an update, never a second
/// row.
#[test]
fn a_re_poll_updates_the_rows_it_already_has_and_never_duplicates_them() {
    let mut moved = issue("iss-1", "in_progress");
    moved.comment_count = 7;
    let (_state, path, mut worker) = intake(vec![
        Answer::Page(vec![issue("iss-1", "open"), issue("iss-2", "open")]),
        Answer::Page(vec![moved, issue("iss-2", "open")]),
    ]);

    let PollOutcome::Recorded(first) = worker.poll_once(1_000).expect("first poll") else {
        panic!("expected a page");
    };
    assert_eq!(first.recorded, 2);

    let PollOutcome::Recorded(second) = worker.poll_once(2_000).expect("second poll") else {
        panic!("expected a page");
    };
    assert_eq!(second.recorded, 0, "nothing on the board is new");
    assert_eq!(second.updated, 1, "one row's fleet fields moved");
    assert_eq!(second.unchanged, 1, "the other said the same thing");

    let store = reopen(&path);
    assert_eq!(
        store.ticket_count().expect("count"),
        2,
        "a re-poll must not duplicate a row"
    );
    let updated = store.ticket("iss-1").expect("read").expect("present");
    assert_eq!(updated.comment_count, 7);
    assert_eq!(updated.fleet_status, "in_progress");
    assert_eq!(
        updated.first_seen_ms, 1_000,
        "first_seen_ms is written once"
    );
    assert_eq!(updated.last_synced_ms, 2_000);
    assert_eq!(updated.revision, 2);

    let untouched = store.ticket("iss-2").expect("read").expect("present");
    assert_eq!(
        untouched.revision, 1,
        "a poll that learned nothing is not a change"
    );
    assert_eq!(untouched.last_synced_ms, 2_000, "but it was still observed");

    let metrics = worker.metrics();
    assert_eq!(metrics.tickets_recorded(), 2);
    assert_eq!(metrics.tickets_updated(), 1);
}

// ---------------------------------------------------------------------------
// The one lifecycle fact the fleet owns
// ---------------------------------------------------------------------------

#[test]
fn an_issue_the_fleet_closed_transitions_to_the_local_terminal_state() {
    let (_state, path, mut worker) = intake(vec![
        Answer::Page(vec![issue("iss-1", "open"), issue("iss-2", "open")]),
        Answer::Page(vec![issue("iss-1", "done"), issue("iss-2", "open")]),
    ]);

    worker.poll_once(1_000).expect("first poll");
    let store = reopen(&path);
    assert_eq!(
        store
            .ticket("iss-1")
            .expect("read")
            .expect("present")
            .lifecycle,
        TicketLifecycle::New
    );
    drop(store);

    let PollOutcome::Recorded(report) = worker.poll_once(2_000).expect("second poll") else {
        panic!("expected a page");
    };
    assert_eq!(report.transitioned, 1);
    assert_eq!(report.updated, 1, "the status field moved too");
    assert_eq!(report.refused, 0);

    let store = reopen(&path);
    let closed = store.ticket("iss-1").expect("read").expect("present");
    assert_eq!(closed.lifecycle, TicketLifecycle::Closed);
    assert_eq!(closed.fleet_status, "done");
    // The other row is untouched: closing one ticket closes one ticket.
    assert_eq!(
        store
            .ticket("iss-2")
            .expect("read")
            .expect("present")
            .lifecycle,
        TicketLifecycle::New
    );
    assert_eq!(worker.metrics().transitions(), 1);
}

#[test]
fn an_issue_already_closed_on_the_board_closes_on_its_first_sighting() {
    let (_state, path, mut worker) = intake(vec![Answer::Page(vec![issue("iss-1", "closed")])]);
    let PollOutcome::Recorded(report) = worker.poll_once(1_000).expect("poll") else {
        panic!("expected a page");
    };
    assert_eq!(report.recorded, 1);
    assert_eq!(report.transitioned, 1);
    assert_eq!(
        reopen(&path)
            .ticket("iss-1")
            .expect("read")
            .expect("present")
            .lifecycle,
        TicketLifecycle::Closed
    );
}

/// A closed ticket that keeps appearing on the board is not re-closed, and the
/// refusal that would have caused is never earned.
#[test]
fn a_ticket_already_closed_here_is_not_transitioned_again() {
    let (_state, path, mut worker) = intake(vec![Answer::Page(vec![issue("iss-1", "closed")])]);
    worker.poll_once(1_000).expect("first poll");
    let PollOutcome::Recorded(second) = worker.poll_once(2_000).expect("second poll") else {
        panic!("expected a page");
    };
    assert_eq!(second.transitioned, 0);
    assert_eq!(
        second.refused, 0,
        "the worker must not spend an illegal transition on every poll"
    );
    let record = reopen(&path)
        .ticket("iss-1")
        .expect("read")
        .expect("present");
    assert_eq!(record.lifecycle, TicketLifecycle::Closed);
    assert_eq!(record.revision, 2, "recorded once, closed once, then quiet");
    assert_eq!(worker.metrics().transitions(), 1);
}

// ---------------------------------------------------------------------------
// Survivable failures
// ---------------------------------------------------------------------------

/// A fleet that is down is not a daemon that is down.
#[test]
fn a_fleet_transport_failure_is_survived_and_the_next_poll_still_records() {
    let (_state, path, mut worker) = intake(vec![
        Answer::Failed(FleetFailure::Unavailable),
        Answer::Failed(FleetFailure::TimedOut),
        Answer::Page(vec![issue("iss-1", "open")]),
    ]);

    assert_eq!(
        worker.poll_once(1_000).expect("a failure is not fatal"),
        PollOutcome::Unavailable(FleetFailure::Unavailable)
    );
    assert_eq!(
        worker
            .poll_once(2_000)
            .expect("a second failure is not fatal"),
        PollOutcome::Unavailable(FleetFailure::TimedOut)
    );
    assert_eq!(reopen(&path).ticket_count().expect("count"), 0);

    let PollOutcome::Recorded(report) = worker.poll_once(3_000).expect("recovery poll") else {
        panic!("expected a page");
    };
    assert_eq!(report.recorded, 1);

    let metrics = worker.metrics();
    assert_eq!(metrics.polls(), 3);
    assert_eq!(metrics.fleet_failures(), 2);
    assert!(
        metrics.halt().is_none(),
        "a fleet failure must never halt the worker"
    );
}

/// A revoked credential reads as its own failure rather than as a quiet outage,
/// and is still survivable: the operator, not the worker, fixes it.
#[test]
fn an_unauthorized_fleet_is_survived_and_named() {
    let (_state, _path, mut worker) = intake(vec![Answer::Failed(FleetFailure::Unauthorized)]);
    let PollOutcome::Unavailable(failure) = worker.poll_once(1_000).expect("not fatal") else {
        panic!("expected a transport failure");
    };
    assert_eq!(failure, FleetFailure::Unauthorized);
    assert_eq!(failure.category(), "unauthorized");
    assert!(worker.metrics().halt().is_none());
}

#[test]
fn a_fleet_refusal_is_a_parsed_answer_carrying_a_bounded_reason() {
    let (_state, path, mut worker) = intake(vec![
        Answer::Refused("API support indisponible"),
        Answer::Page(vec![issue("iss-1", "open")]),
    ]);
    let PollOutcome::Refused(reason) = worker.poll_once(1_000).expect("not fatal") else {
        panic!("expected a fleet refusal");
    };
    assert_eq!(reason.as_str(), "API support indisponible");
    assert_eq!(reopen(&path).ticket_count().expect("count"), 0);

    worker.poll_once(2_000).expect("recovery poll");
    assert_eq!(reopen(&path).ticket_count().expect("count"), 1);
    let metrics = worker.metrics();
    assert_eq!(metrics.fleet_refusals(), 1);
    assert_eq!(metrics.fleet_failures(), 0);
    assert!(metrics.halt().is_none());
}

/// One row the store will not accept costs that row and nothing else.
#[test]
fn a_row_outside_the_stores_grammar_is_skipped_rather_than_costing_the_page() {
    let mut hostile = issue("iss-hostile", "open");
    hostile.title = String::new();
    let mut control = issue("iss-control", "open");
    control.title = "Panne\u{1b}[2J".to_owned();
    let (_state, path, mut worker) = intake(vec![Answer::Page(vec![
        issue("iss-1", "open"),
        hostile,
        control,
        issue("iss-2", "open"),
    ])]);

    let PollOutcome::Recorded(report) = worker.poll_once(1_000).expect("poll") else {
        panic!("expected a page");
    };
    assert_eq!(report.recorded, 2, "the two good rows still land");
    assert_eq!(report.refused, 2);
    assert_eq!(report.seen(), 4);

    let store = reopen(&path);
    assert_eq!(store.ticket_count().expect("count"), 2);
    assert!(store.ticket("iss-1").expect("read").is_some());
    assert!(store.ticket("iss-2").expect("read").is_some());
    assert!(store.ticket("iss-control").expect("read").is_none());
    assert_eq!(worker.metrics().rows_refused(), 2);
    assert!(
        worker.metrics().halt().is_none(),
        "one bad row is not a durable-state failure"
    );
}

// ---------------------------------------------------------------------------
// Fail-closed
// ---------------------------------------------------------------------------

/// The other side of the line: a store that cannot take another ticket stops
/// the worker rather than spinning on the same refusal forever.
#[test]
fn a_full_ticket_store_halts_the_worker_instead_of_spinning() {
    let (_state, path) = PrivateState::new();
    let store = SupportTicketStore::open_with_capacity(&path, 1).expect("store opens");
    let mut worker = TicketIntake::new(
        FakeBoard::new(vec![Answer::Page(vec![
            issue("iss-1", "open"),
            issue("iss-2", "open"),
        ])]),
        store,
        0,
    );

    let halt = worker
        .poll_once(1_000)
        .expect_err("capacity is fail-closed");
    assert_eq!(halt, IntakeHalt::StoreFull);
    assert_eq!(halt.category(), "ticket_store_full");
    // Nothing evicted: the row that fitted is still there.
    let store = reopen(&path);
    assert_eq!(store.ticket_count().expect("count"), 1);
    assert!(store.ticket("iss-1").expect("read").is_some());

    let metrics = worker.metrics();
    assert_eq!(metrics.halt(), Some(IntakeHalt::StoreFull));
    assert_eq!(
        metrics.tickets_recorded(),
        1,
        "what did land before the halt is still counted"
    );
}

#[test]
fn every_halt_category_is_distinct() {
    let halts = [
        IntakeHalt::StoreFull,
        IntakeHalt::StoreCorrupt,
        IntakeHalt::SchemaVersion,
        IntakeHalt::InsecurePath,
        IntakeHalt::StoreUnavailable,
    ];
    let mut categories: Vec<&str> = halts.iter().map(|halt| halt.category()).collect();
    categories.sort_unstable();
    let total = categories.len();
    categories.dedup();
    assert_eq!(categories.len(), total);
}

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

/// A worker parked between polls leaves when it is told, not when it next
/// looks.
///
/// [`the_loop_polls_until_it_is_stopped_and_joins_promptly`] already proves the
/// join does not wait out the cadence. It does not distinguish *how* — waking
/// often enough to notice would satisfy it too, and that is exactly what this
/// loop used to do: slice a five-minute cadence into hundred-millisecond naps,
/// about three thousand of them, and still leave up to one nap late.
///
/// So this measures the leaving. Each worker is given time to be parked before
/// it is stopped, and only the interval between the stop and the join is
/// counted. A napping worker owes most of a nap on each of those; a worker that
/// waits on the stop owes nothing.
#[test]
fn a_parked_worker_leaves_on_the_stop_rather_than_at_its_next_look() {
    /// Drains to measure. One would be a coin flip against a nap boundary;
    /// this many makes the two implementations differ by more than the noise.
    const DRAINS: u32 = 10;
    /// The slice length this loop used to nap in, mirrored. Mirrored rather
    /// than imported because it is private — and because it no longer exists,
    /// which is the point.
    const FORMER_SLICE: Duration = Duration::from_millis(100);
    /// Long enough that no implementation can drain by reaching it.
    const CADENCE: Duration = Duration::from_secs(300);

    let mut drained = Duration::ZERO;
    for _ in 0..DRAINS {
        let (_state, path) = PrivateState::new();
        let store = SupportTicketStore::open(&path).expect("store opens");
        let mut worker = TicketIntake::new(
            FakeBoard::new(vec![Answer::Page(vec![issue("iss-1", "open")])]),
            store,
            0,
        );
        let metrics = worker.metrics();
        let stop = ShutdownSignal::new();
        let clock = AtomicI64::new(1_000);
        let now = || Some(clock.fetch_add(1_000, Ordering::Relaxed));

        std::thread::scope(|scope| {
            let running = scope.spawn(|| worker.run(&stop, CADENCE, &now));
            let deadline = Instant::now() + Duration::from_secs(5);
            while metrics.polls() == 0 {
                assert!(Instant::now() < deadline, "the worker never polled");
                std::thread::yield_now();
            }
            // Well inside the first former slice, so a napping worker is
            // provably mid-nap and owes the remainder rather than happening to
            // be at a boundary.
            std::thread::sleep(FORMER_SLICE / 5);

            let signalled = Instant::now();
            stop.stop();
            assert_eq!(running.join().expect("worker joins"), None);
            drained += signalled.elapsed();
        });
    }

    let napping_cost = FORMER_SLICE * DRAINS;
    assert!(
        drained < napping_cost / 4,
        "{DRAINS} drains cost {drained:?} between the stop and the join. A worker waiting on the \
         stop leaves at once; one napping in {FORMER_SLICE:?} slices owes most of a slice each \
         time, which is the {napping_cost:?} this is within reach of"
    );
}

/// The loop polls repeatedly and ends when it is asked to, well inside a
/// cadence — which is what makes a daemon shutdown a join rather than a wait.
#[test]
fn the_loop_polls_until_it_is_stopped_and_joins_promptly() {
    let (_state, path) = PrivateState::new();
    let store = SupportTicketStore::open(&path).expect("store opens");
    let mut worker = TicketIntake::new(
        FakeBoard::new(vec![Answer::Page(vec![issue("iss-1", "open")])]),
        store,
        0,
    );
    let metrics = worker.metrics();

    let stop = ShutdownSignal::new();
    let clock = AtomicI64::new(1_000);
    let now = || Some(clock.fetch_add(1_000, Ordering::Relaxed));
    let started = Instant::now();
    std::thread::scope(|scope| {
        let running = scope.spawn(|| worker.run(&stop, Duration::from_secs(30), &now));

        // Wait for at least one poll, then ask it to stop.
        let deadline = Instant::now() + Duration::from_secs(5);
        while metrics.polls() == 0 {
            assert!(Instant::now() < deadline, "the worker never polled");
            std::thread::sleep(Duration::from_millis(5));
        }
        stop.stop();
        assert_eq!(
            running.join().expect("worker joins"),
            None,
            "a stopped worker halted for no reason, because it did not halt"
        );
    });
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the join must wait on shutdown latency, not on the cadence"
    );
    assert!(metrics.polls() >= 1);
    assert_eq!(metrics.tickets_recorded(), 1);
    assert_eq!(reopen(&path).ticket_count().expect("count"), 1);
}

/// A worker asked to stop before it ever polls does not poll.
#[test]
fn a_worker_stopped_before_it_starts_never_asks_the_fleet_anything() {
    let (_state, path) = PrivateState::new();
    let store = SupportTicketStore::open(&path).expect("store opens");
    let board = FakeBoard::new(vec![Answer::Page(vec![issue("iss-1", "open")])]);
    let mut worker = TicketIntake::new(board, store, 0);

    let stop = ShutdownSignal::new();
    stop.stop();
    assert_eq!(
        worker.run(&stop, Duration::from_secs(1), &|| Some(1_000)),
        None
    );
    assert_eq!(worker.metrics().polls(), 0);
    assert_eq!(reopen(&path).ticket_count().expect("count"), 0);
}

/// The loop ends on a halt rather than looping past it.
///
/// Run under a watchdog on purpose. A worker that failed to halt would sleep its
/// whole cadence and poll again forever, so without the watchdog this test would
/// *hang* rather than fail — and a test that hangs on a regression is a test
/// nobody can read the result of.
#[test]
fn the_loop_returns_the_halt_that_ended_it() {
    let (_state, path) = PrivateState::new();
    let store = SupportTicketStore::open_with_capacity(&path, 1).expect("store opens");
    let mut worker = TicketIntake::new(
        FakeBoard::new(vec![Answer::Page(vec![
            issue("iss-1", "open"),
            issue("iss-2", "open"),
        ])]),
        store,
        0,
    );
    let metrics = worker.metrics();
    let stop = ShutdownSignal::new();
    let returned = AtomicBool::new(false);

    std::thread::scope(|scope| {
        let running = scope.spawn(|| {
            let halt = worker.run(&stop, Duration::from_secs(600), &|| Some(1_000));
            returned.store(true, Ordering::Release);
            halt
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !returned.load(Ordering::Acquire) {
            if Instant::now() >= deadline {
                // The watchdog fires only when the worker did not halt. It stops
                // the loop so the assertion below reports `None` — the failure —
                // instead of this test never finishing.
                stop.stop();
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            running.join().expect("worker joins"),
            Some(IntakeHalt::StoreFull),
            "a halted worker returns rather than sleeping a cadence and retrying"
        );
    });
    assert_eq!(metrics.polls(), 1);
    assert_eq!(metrics.halt(), Some(IntakeHalt::StoreFull));
}

/// A clock that cannot be read costs a poll, not the worker.
#[test]
fn an_unreadable_clock_skips_a_poll_rather_than_ending_intake() {
    let (_state, path) = PrivateState::new();
    let store = SupportTicketStore::open(&path).expect("store opens");
    let mut worker = TicketIntake::new(
        FakeBoard::new(vec![Answer::Page(vec![issue("iss-1", "open")])]),
        store,
        0,
    );
    let metrics = worker.metrics();
    let stop = ShutdownSignal::new();
    let ticks = AtomicUsize::new(0);
    // The clock fails once, then works; the worker is asked to stop as soon as
    // it has recorded something.
    let now = || {
        if ticks.fetch_add(1, Ordering::Relaxed) == 0 {
            None
        } else {
            Some(1_000)
        }
    };
    std::thread::scope(|scope| {
        let running = scope.spawn(|| worker.run(&stop, Duration::from_millis(10), &now));
        let deadline = Instant::now() + Duration::from_secs(5);
        while metrics.tickets_recorded() == 0 {
            assert!(Instant::now() < deadline, "the worker never recovered");
            std::thread::sleep(Duration::from_millis(5));
        }
        stop.stop();
        assert_eq!(running.join().expect("worker joins"), None);
    });
    assert_eq!(metrics.tickets_recorded(), 1);
    assert_eq!(reopen(&path).ticket_count().expect("count"), 1);
}

// ---------------------------------------------------------------------------
// The enablement gate
// ---------------------------------------------------------------------------

/// THE GATE. Without a fleet configuration the host is disabled, nothing starts,
/// and no ticket store file is even created.
#[test]
fn an_unconfigured_state_directory_starts_no_worker_and_creates_no_store() {
    let directory = tempfile::tempdir().expect("temporary directory");
    std::fs::set_permissions(
        directory.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("private permissions");
    let store_path = directory.path().join("support-tickets.sqlite3");

    let mut host = TicketIntakeHost::open(&TicketIntakeParams {
        state_dir: directory.path(),
        ticket_store_path: &store_path,
    })
    .expect("an absent configuration is not an error");

    assert!(!host.is_configured());
    assert!(host.metrics().is_none());
    host.start().expect("there is nothing to start");
    assert!(!host.is_configured());
    assert!(
        !store_path.exists(),
        "a disabled host must not create a durable file"
    );
    host.shutdown();
}

/// A present-but-wrong configuration refuses rather than being ignored: an
/// operator error must not hide behind an honest-looking disabled state.
#[test]
fn a_present_but_malformed_configuration_refuses_the_host() {
    let directory = tempfile::tempdir().expect("temporary directory");
    std::fs::set_permissions(
        directory.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("private permissions");
    let support = directory.path().join("support");
    std::fs::create_dir(&support).expect("support directory");
    std::fs::set_permissions(
        &support,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("private support directory");
    let config = support.join("fleet.conf");
    std::fs::write(
        &config,
        "schema=automonique.support-fleet/v1\nbase=nonsense\n",
    )
    .expect("configuration written");
    std::fs::set_permissions(&config, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("private configuration");

    let error = TicketIntakeHost::open(&TicketIntakeParams {
        state_dir: directory.path(),
        ticket_store_path: &directory.path().join("support-tickets.sqlite3"),
    })
    .expect_err("a present configuration must be believed or refused");
    assert_eq!(error.category(), "support_config_base");

    // And a world-readable one is refused before a byte of it is parsed.
    std::fs::set_permissions(&config, std::os::unix::fs::PermissionsExt::from_mode(0o644))
        .expect("group-readable configuration");
    let error = TicketIntakeHost::open(&TicketIntakeParams {
        state_dir: directory.path(),
        ticket_store_path: &directory.path().join("support-tickets.sqlite3"),
    })
    .expect_err("an exposed credential file is refused");
    assert_eq!(error.category(), "support_config_insecure");
}

/// The board's page ceiling is asked for, never exceeded.
#[test]
fn the_worker_never_asks_the_fleet_for_more_than_one_page() {
    let (_state, _path, mut worker) = intake(vec![Answer::Page(Vec::new())]);
    worker.poll_once(1_000).expect("poll");
    worker.poll_once(2_000).expect("poll");
    // Asserted through the board rather than the worker, because what matters is
    // the number that reached the fleet.
    assert_eq!(
        automonique_support_connector::MAX_SUPPORT_ISSUES,
        50,
        "the connector's page ceiling is pinned here too"
    );
}

/// A board that is asked and answers nothing is not a failure.
#[test]
fn an_empty_board_records_nothing_and_is_not_a_refusal() {
    let (_state, path, mut worker) = intake(vec![Answer::Page(Vec::new())]);
    let PollOutcome::Recorded(report) = worker.poll_once(1_000).expect("poll") else {
        panic!("an empty page is still a page");
    };
    assert_eq!(report.seen(), 0);
    assert_eq!(report, Default::default());
    assert_eq!(reopen(&path).ticket_count().expect("count"), 0);
    assert!(worker.metrics().halt().is_none());
}

/// The fake fleet is the only fleet these tests know about.
#[test]
fn every_poll_in_this_file_went_to_the_fake_board() {
    let board = FakeBoard::new(vec![Answer::Page(vec![issue("iss-1", "open")])]);
    assert_eq!(board.calls(), 0);
    let (_state, path) = PrivateState::new();
    let store = SupportTicketStore::open(&path).expect("store opens");
    let mut worker = TicketIntake::new(board, store, 7);
    worker.poll_once(1_000).expect("poll");
    worker.poll_once(2_000).expect("poll");
    assert_eq!(worker.metrics().polls(), 2);
    assert_eq!(reopen(&path).ticket_count().expect("count"), 1);
}
