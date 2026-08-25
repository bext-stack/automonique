// SPDX-License-Identifier: Elastic-2.0

//! The automation scheduler worker, driven one tick at a time under a fake
//! clock.
//!
//! Every test here opens the worker against real files — the product store,
//! the automation registry and the scheduler core's database — and drives
//! [`AutomationSchedulerWorker::tick_at`] directly, so what is proved is what
//! the daemon's thread does on each pass, without a thread and without waiting
//! for a wall clock. The synthetic lane's controller is the daemon's own
//! (`automonique_daemon::synthetic::StoreScheduler` under
//! `automonique_core::Controller`), so an occurrence completes exactly the way
//! `automonique submit` work completes: one claim, one terminal commit, one
//! outbox intent.
//!
//! What the live socket tests in `automation_live.rs` add is the wire and the
//! thread; what these add is determinism — the three safety properties and the
//! restart cases are asserted at the instants they are decided.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use automonique_core::scheduler_conformance::{WorkId, WorkState};
use automonique_core::{Controller, SchedulerFence, TickOutcome};
use automonique_daemon::automation_scheduler::{
    AUTOMATION_PARALLELISM_LIMIT, AutomationClock, AutomationSchedulerError,
    AutomationSchedulerParams, AutomationSchedulerWorker, OCCURRENCE_TRANSPORT, TickReport,
};
use automonique_daemon::synthetic::StoreScheduler;
use automonique_protocol::automation_api::{AutomationId, AutomationOccurrenceKey};
use automonique_protocol::primitives::EpochMillis;
use automonique_store::automation_store::{
    AutomationJob, AutomationJobSpec, AutomationRegistration, AutomationSchedule, AutomationStore,
    EnablementState, EnablementTransition,
};
use automonique_store::durable_scheduler::DurableSchedulerStore;
use automonique_store::{InboxState, LeaseRequest, LeaseTimeSource, Store};

const GENERATION: &str = "generation";
const T0: i64 = 1_700_000_000_000;
const MINUTE: i64 = 60_000;
const LEASE_TTL_MS: i64 = 1_000_000_000;

/// One clock for everything: the worker's `now`, the product store's lease
/// authority, and the controller's audit and lease time.
struct FakeClock(AtomicI64);

impl FakeClock {
    fn set(&self, now_ms: i64) {
        self.0.store(now_ms, Ordering::Release);
    }

    fn get(&self) -> i64 {
        self.0.load(Ordering::Acquire)
    }
}

impl AutomationClock for FakeClock {
    fn now_ms(&self) -> Result<i64, &'static str> {
        Ok(self.get())
    }
}

impl LeaseTimeSource for FakeClock {
    fn now_boottime_ms(&self) -> Result<i64, &'static str> {
        Ok(self.get())
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    state: PathBuf,
    clock: Arc<FakeClock>,
    /// The daemon's own store handle: the one the serve loop's controller
    /// ticks with.
    store: Store,
    holder: String,
    epoch: u64,
    lease_expires_ms: i64,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temporary root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let state = root.path().join("state");
        std::fs::create_dir(&state).expect("state dir");
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
            .expect("private state");
        let clock = Arc::new(FakeClock(AtomicI64::new(T0)));
        let mut store = Store::open_with_lease_time_source(
            state.join("product.sqlite3"),
            Arc::clone(&clock) as Arc<dyn LeaseTimeSource>,
        )
        .expect("open product store");
        let lease = store
            .acquire_generation_lease(LeaseRequest {
                generation_id: GENERATION,
                holder_id: "holder-1",
                now_ms: T0,
                ttl_ms: LEASE_TTL_MS,
            })
            .expect("acquire the generation");
        Self {
            _root: root,
            state,
            clock,
            store,
            holder: "holder-1".to_owned(),
            epoch: lease.epoch,
            lease_expires_ms: lease.expires_ms,
        }
    }

    fn database_path(&self) -> PathBuf {
        self.state.join("product.sqlite3")
    }

    fn registry_path(&self) -> PathBuf {
        self.state.join("automations.sqlite3")
    }

    fn scheduler_path(&self) -> PathBuf {
        self.state.join("automation-scheduler.sqlite3")
    }

    /// A fresh registry handle: the daemon's control lane writes through one
    /// of these, and the worker reads through its own.
    fn registry(&self) -> AutomationStore {
        AutomationStore::open(self.registry_path()).expect("open registry")
    }

    fn worker_with_limit(&self, limit: u32) -> AutomationSchedulerWorker {
        AutomationSchedulerWorker::open(&AutomationSchedulerParams {
            database_path: &self.database_path(),
            registry_path: &self.registry_path(),
            scheduler_path: &self.scheduler_path(),
            generation_id: GENERATION,
            holder_id: &self.holder,
            lease_epoch: self.epoch,
            parallelism_limit: limit,
            lease_time_source: Arc::clone(&self.clock) as Arc<dyn LeaseTimeSource>,
            clock: Arc::clone(&self.clock) as Arc<dyn AutomationClock>,
        })
        .expect("open the worker")
    }

    fn worker(&self) -> AutomationSchedulerWorker {
        self.worker_with_limit(AUTOMATION_PARALLELISM_LIMIT)
    }

    /// Register one fixed-interval automation, first due one minute after
    /// `registered_at`.
    fn register_every(&self, automation_id: &str, scope: &str, registered_at: i64) {
        self.registry()
            .register(AutomationRegistration {
                automation_id,
                actor: "ben",
                now_ms: registered_at,
                job: AutomationJobSpec {
                    schedule: AutomationSchedule::Every {
                        interval_ms: MINUTE,
                    },
                    scope,
                    prompt: "summarize the night",
                    first_fire_at_ms: registered_at + MINUTE,
                },
            })
            .expect("register");
    }

    /// Register one one-shot automation due at `at`.
    fn register_once(&self, automation_id: &str, scope: &str, at: i64) {
        self.registry()
            .register(AutomationRegistration {
                automation_id,
                actor: "ben",
                now_ms: T0,
                job: AutomationJobSpec {
                    schedule: AutomationSchedule::Once { at_ms: at },
                    scope,
                    prompt: "summarize once",
                    first_fire_at_ms: at,
                },
            })
            .expect("register");
    }

    fn transition(&self, automation_id: &str, revision: u64, to: EnablementState) {
        let cause = to.requires_cause().then_some("held");
        self.registry()
            .transition(EnablementTransition {
                automation_id,
                expected_revision: revision,
                new_enablement: to,
                actor: "dana",
                cause,
                now_ms: self.clock.get(),
            })
            .expect("transition");
    }

    fn job(&self, automation_id: &str) -> AutomationJob {
        self.registry()
            .entry(automation_id)
            .expect("entry")
            .expect("registered")
            .job
            .expect("a job")
    }

    /// One controller tick on the synthetic lane, the daemon's own executor.
    fn run_lane_once(&mut self) -> TickOutcome {
        let now = self.clock.get();
        let fence =
            SchedulerFence::new(GENERATION, self.holder.as_str(), self.epoch).expect("fence");
        let mut adapter = StoreScheduler::new(
            &mut self.store,
            now,
            now,
            LEASE_TTL_MS,
            &mut self.lease_expires_ms,
        );
        Controller::new()
            .tick(&mut adapter, &fence)
            .expect("the lane's invariants hold")
    }

    /// Run the lane until it has nothing claimable, counting completions.
    fn drain_lane(&mut self) -> usize {
        let mut completed = 0;
        loop {
            match self.run_lane_once() {
                TickOutcome::Completed(_) => completed += 1,
                TickOutcome::Idle => return completed,
                other => panic!("the lane reported {other:?}"),
            }
        }
    }

    fn key(automation_id: &str, at: i64) -> String {
        AutomationOccurrenceKey::derive(
            &AutomationId::new(automation_id).expect("identity"),
            EpochMillis::from_millis(at),
        )
        .expect("key")
        .as_str()
        .to_owned()
    }

    fn lane_state(&self, automation_id: &str, at: i64) -> Option<InboxState> {
        self.store
            .inbox_disposition(OCCURRENCE_TRANSPORT, &Self::key(automation_id, at))
            .expect("read the lane")
            .map(|disposition| disposition.state)
    }

    /// The scheduler core's own view, through a second handle under the same
    /// fence — installing an equal fence changes nothing.
    fn core_state(&self, automation_id: &str, at: i64) -> Option<WorkState> {
        let fence =
            SchedulerFence::new(GENERATION, self.holder.as_str(), self.epoch).expect("fence");
        DurableSchedulerStore::open(self.scheduler_path(), AUTOMATION_PARALLELISM_LIMIT, fence)
            .expect("open the core")
            .state(&WorkId::new(Self::key(automation_id, at)).expect("work id"))
            .expect("read the core")
    }

    fn core_running(&self) -> Vec<String> {
        let fence =
            SchedulerFence::new(GENERATION, self.holder.as_str(), self.epoch).expect("fence");
        DurableSchedulerStore::open(self.scheduler_path(), AUTOMATION_PARALLELISM_LIMIT, fence)
            .expect("open the core")
            .running()
            .expect("read running")
            .into_iter()
            .map(|work_id| work_id.as_str().to_owned())
            .collect()
    }

    fn outbox_count(&self) -> u64 {
        self.store.outbox_count().expect("outbox count")
    }
}

fn report(admitted: usize, started: usize, settled: usize, cancelled: usize) -> TickReport {
    TickReport {
        admitted,
        started,
        settled,
        cancelled,
    }
}

fn exists(path: &Path) -> bool {
    path.exists()
}

#[test]
fn a_due_automation_fires_once_as_a_synthetic_run_and_advances() {
    let mut fixture = Fixture::new();
    fixture.register_every("nightly", "workspace:reports", T0);
    let mut worker = fixture.worker();
    assert!(
        exists(&fixture.scheduler_path()),
        "the core opened its database"
    );

    // Before its instant: nothing is due, nothing is admitted.
    assert_eq!(worker.tick_at(T0).expect("tick"), TickReport::default());
    assert_eq!(
        worker.tick_at(T0 + MINUTE - 1).expect("tick"),
        TickReport::default()
    );
    assert_eq!(fixture.lane_state("nightly", T0 + MINUTE), None);

    // At its instant: admitted to the core, started, and on the lane under
    // the derived key. The registry has advanced past the instant already,
    // and holds the occurrence active until the lane finishes with it.
    let at = T0 + MINUTE;
    assert_eq!(worker.tick_at(at).expect("tick"), report(1, 1, 0, 0));
    assert_eq!(fixture.lane_state("nightly", at), Some(InboxState::Pending));
    assert_eq!(fixture.core_state("nightly", at), Some(WorkState::Running));
    let job = fixture.job("nightly");
    assert_eq!(job.active_occurrence_ms, Some(at));
    assert_eq!(job.next_fire_at_ms, Some(at + MINUTE));
    assert_eq!(job.last_fired_at_ms, None);

    // A second tick at the same instant changes nothing: the occurrence is in
    // flight, and the same key is neither re-admitted nor resubmitted.
    assert_eq!(worker.tick_at(at).expect("tick"), TickReport::default());
    assert_eq!(fixture.outbox_count(), 0);

    // The daemon's own controller runs it: one claim, one terminal commit,
    // one outbox intent — exactly what a `submit` produces.
    assert_eq!(fixture.drain_lane(), 1);
    assert_eq!(fixture.outbox_count(), 1);
    assert_eq!(
        fixture.lane_state("nightly", at),
        Some(InboxState::Completed)
    );

    // The worker notices, frees the slot and records the firing.
    assert_eq!(worker.tick_at(at + 1).expect("tick"), report(0, 0, 1, 0));
    assert_eq!(
        fixture.core_state("nightly", at),
        Some(WorkState::Completed)
    );
    let job = fixture.job("nightly");
    assert_eq!(job.active_occurrence_ms, None);
    assert_eq!(job.last_fired_at_ms, Some(at));
    assert_eq!(job.next_fire_at_ms, Some(at + MINUTE));
    assert!(fixture.core_running().is_empty());

    // Nothing more until the next instant, where the next key fires.
    assert_eq!(
        worker.tick_at(at + MINUTE - 1).expect("tick"),
        TickReport::default()
    );
    assert_eq!(
        worker.tick_at(at + MINUTE).expect("tick"),
        report(1, 1, 0, 0)
    );
    assert_eq!(
        fixture.lane_state("nightly", at + MINUTE),
        Some(InboxState::Pending)
    );
    assert_eq!(fixture.drain_lane(), 1);
    assert_eq!(
        worker.tick_at(at + MINUTE + 1).expect("tick"),
        report(0, 0, 1, 0)
    );
    assert_eq!(fixture.outbox_count(), 2);
}

#[test]
fn a_one_shot_fires_once_and_is_then_exhausted() {
    let mut fixture = Fixture::new();
    let at = T0 + 5_000;
    fixture.register_once("once", "workspace:reports", at);
    let mut worker = fixture.worker();
    assert_eq!(worker.tick_at(at - 1).expect("tick"), TickReport::default());
    assert_eq!(worker.tick_at(at).expect("tick"), report(1, 1, 0, 0));
    assert_eq!(
        fixture.job("once").next_fire_at_ms,
        None,
        "a started one-shot has nothing further due"
    );
    assert_eq!(fixture.drain_lane(), 1);
    assert_eq!(worker.tick_at(at + 1).expect("tick"), report(0, 0, 1, 0));
    let job = fixture.job("once");
    assert_eq!(job.last_fired_at_ms, Some(at));
    assert_eq!(job.active_occurrence_ms, None);
    // Far into the future, nothing fires again.
    assert_eq!(
        worker.tick_at(at + 365 * 24 * 60 * MINUTE).expect("tick"),
        TickReport::default()
    );
    assert_eq!(fixture.outbox_count(), 1);
}

/// A fixed interval that fell behind fires its oldest due instant once and
/// continues from the first instant after `now`, never a burst.
#[test]
fn a_late_worker_fires_the_oldest_due_instant_once_and_skips_the_rest() {
    let mut fixture = Fixture::new();
    fixture.register_every("nightly", "workspace:reports", T0);
    let mut worker = fixture.worker();
    // Ten minutes late: one occurrence, keyed by the instant that was due.
    let late = T0 + 10 * MINUTE + 500;
    assert_eq!(worker.tick_at(late).expect("tick"), report(1, 1, 0, 0));
    assert_eq!(
        fixture.lane_state("nightly", T0 + MINUTE),
        Some(InboxState::Pending)
    );
    let job = fixture.job("nightly");
    assert_eq!(job.active_occurrence_ms, Some(T0 + MINUTE));
    assert_eq!(
        job.next_fire_at_ms,
        Some(T0 + 11 * MINUTE),
        "the successor is the first grid instant after now"
    );
    assert_eq!(fixture.drain_lane(), 1);
    assert_eq!(worker.tick_at(late + 1).expect("tick"), report(0, 0, 1, 0));
    // Nothing else was derived for the nine instants in between.
    assert_eq!(
        worker.tick_at(late + 2).expect("tick"),
        TickReport::default()
    );
    assert_eq!(fixture.outbox_count(), 1);
    for missed in 2..=10 {
        assert_eq!(fixture.lane_state("nightly", T0 + missed * MINUTE), None);
    }
}

/// Bounded parallelism and per-scope serialization, observed at the core and
/// on the lane at every step.
#[test]
fn the_core_bounds_parallelism_and_serializes_each_scope() {
    let mut fixture = Fixture::new();
    // Three in one scope, two in another, one on its own: six due at once
    // under a bound of two.
    for (automation_id, scope) in [
        ("a1", "scope:a"),
        ("a2", "scope:a"),
        ("a3", "scope:a"),
        ("b1", "scope:b"),
        ("b2", "scope:b"),
        ("c1", "scope:c"),
    ] {
        fixture.register_every(automation_id, scope, T0);
    }
    let mut worker = fixture.worker_with_limit(2);
    let at = T0 + MINUTE;
    fn scope_of(fixture: &Fixture, key: &str) -> String {
        let (automation_id, _) = AutomationOccurrenceKey::parse(key).expect("a derived key");
        fixture.job(automation_id.as_str()).scope
    }

    // Everything due is admitted; only two start, in two different scopes.
    let first = worker.tick_at(at).expect("tick");
    assert_eq!(first.admitted, 6);
    assert_eq!(first.started, 2, "the bound is a bound");
    let running = fixture.core_running();
    assert_eq!(running.len(), 2);
    assert_ne!(
        scope_of(&fixture, &running[0]),
        scope_of(&fixture, &running[1])
    );
    // Admission order is registration order: a1 and b1 went first.
    assert_eq!(
        running,
        vec![Fixture::key("a1", at), Fixture::key("b1", at)]
    );
    assert_eq!(fixture.lane_state("a1", at), Some(InboxState::Pending));
    assert_eq!(fixture.lane_state("a2", at), None, "a2 waits on its scope");
    assert_eq!(fixture.lane_state("c1", at), None, "c1 waits on a slot");
    // Waiting is not a second admission.
    assert_eq!(worker.tick_at(at).expect("tick"), TickReport::default());

    // Each completion frees one slot and admits exactly one item, never two
    // of one scope, until everything has run once.
    let mut fired: Vec<String> = Vec::new();
    let mut ticks = 0;
    while fired.len() < 6 {
        ticks += 1;
        assert!(ticks < 20, "the lane stalled with {fired:?} fired");
        let completed = fixture.drain_lane();
        assert!(completed >= 1);
        let report = worker.tick_at(at + ticks).expect("tick");
        assert_eq!(report.settled, completed);
        let running = fixture.core_running();
        assert!(running.len() <= 2, "more than two ran at once: {running:?}");
        let mut scopes: Vec<String> = running.iter().map(|key| scope_of(&fixture, key)).collect();
        scopes.sort();
        scopes.dedup();
        assert_eq!(
            scopes.len(),
            running.len(),
            "one scope ran twice: {running:?}"
        );
        for automation_id in ["a1", "a2", "a3", "b1", "b2", "c1"] {
            if fixture.job(automation_id).last_fired_at_ms == Some(at)
                && !fired.contains(&automation_id.to_owned())
            {
                fired.push(automation_id.to_owned());
            }
        }
    }
    assert_eq!(fixture.outbox_count(), 6, "each fired exactly once");
    // The scope's items started in submission order.
    let mut by_scope_a: Vec<&str> = fired
        .iter()
        .map(String::as_str)
        .filter(|id| id.starts_with('a'))
        .collect();
    assert_eq!(by_scope_a, vec!["a1", "a2", "a3"]);
    by_scope_a.clear();
}

#[test]
fn a_paused_automation_derives_nothing_and_its_queued_occurrence_never_starts() {
    let mut fixture = Fixture::new();
    for automation_id in ["s1", "s2", "s3"] {
        fixture.register_every(automation_id, "scope:shared", T0);
    }
    let mut worker = fixture.worker();
    let at = T0 + MINUTE;
    // One scope: s1 starts, s2 and s3 queue behind it.
    assert_eq!(worker.tick_at(at).expect("tick"), report(3, 1, 0, 0));
    assert_eq!(fixture.core_state("s2", at), Some(WorkState::Queued));

    // Pause s2 while it is queued: the core's cancel says it never started,
    // and the instant is skipped rather than kept due.
    fixture.transition("s2", 1, EnablementState::Paused);
    assert_eq!(worker.tick_at(at + 1).expect("tick"), report(0, 0, 0, 1));
    assert_eq!(fixture.core_state("s2", at), Some(WorkState::Cancelled));
    assert_eq!(
        fixture.lane_state("s2", at),
        None,
        "nothing reached the lane"
    );
    let paused = fixture.job("s2");
    assert_eq!(paused.active_occurrence_ms, None);
    assert_eq!(paused.last_fired_at_ms, None);
    assert_eq!(paused.next_fire_at_ms, Some(at + MINUTE));

    // s1 finishes, s3 starts: the pause disturbed nothing else.
    assert_eq!(fixture.drain_lane(), 1);
    assert_eq!(worker.tick_at(at + 2).expect("tick"), report(0, 1, 1, 0));
    assert_eq!(fixture.lane_state("s3", at), Some(InboxState::Pending));
    assert_eq!(fixture.drain_lane(), 1);
    assert_eq!(worker.tick_at(at + 3).expect("tick"), report(0, 0, 1, 0));

    // While paused, the next instant derives nothing for s2.
    assert_eq!(
        worker.tick_at(at + MINUTE).expect("tick"),
        report(2, 1, 0, 0)
    );
    assert_eq!(fixture.lane_state("s2", at + MINUTE), None);
    assert_eq!(fixture.drain_lane(), 1);
    assert_eq!(
        worker.tick_at(at + MINUTE + 1).expect("tick"),
        report(0, 1, 1, 0)
    );
    assert_eq!(fixture.drain_lane(), 1);
    assert_eq!(
        worker.tick_at(at + MINUTE + 2).expect("tick"),
        report(0, 0, 1, 0)
    );

    // Resumed: s2 fires at its next instant, and nothing was fired for the
    // instants it spent paused.
    fixture.transition("s2", 2, EnablementState::Enabled);
    let resumed_at = T0 + 3 * MINUTE;
    let report_at_resume = worker.tick_at(resumed_at).expect("tick");
    assert_eq!(report_at_resume.admitted, 3);
    // The skipped instant stays skipped.
    assert_eq!(fixture.lane_state("s2", at), None);
    // s2's next instant after the skip was `at + MINUTE`, which is the oldest
    // instant due at the resume — so it is admitted first and, the scope
    // being free, is the one the core starts.
    assert_eq!(report_at_resume.started, 1);
    assert_eq!(
        fixture.lane_state("s2", at + MINUTE),
        Some(InboxState::Pending)
    );
    let mut fired_s2 = false;
    for step in 1..12 {
        fixture.drain_lane();
        worker.tick_at(resumed_at + step).expect("tick");
        if fixture.job("s2").last_fired_at_ms.is_some() {
            fired_s2 = true;
            break;
        }
    }
    assert!(fired_s2, "a resumed automation fires again");
    assert_eq!(fixture.job("s2").last_fired_at_ms, Some(at + MINUTE));
}

#[test]
fn an_archived_automation_requests_a_stop_and_custody_stays_until_terminal() {
    let mut fixture = Fixture::new();
    fixture.register_every("doomed", "scope:x", T0);
    let mut worker = fixture.worker();
    let at = T0 + MINUTE;
    assert_eq!(worker.tick_at(at).expect("tick"), report(1, 1, 0, 0));
    assert_eq!(fixture.lane_state("doomed", at), Some(InboxState::Pending));

    // Archived while the lane holds it: the core records a stop request and
    // keeps the slot; nothing is duplicated and nothing is dropped.
    fixture.transition("doomed", 1, EnablementState::Archived);
    assert_eq!(worker.tick_at(at + 1).expect("tick"), TickReport::default());
    assert_eq!(
        fixture.core_state("doomed", at),
        Some(WorkState::StopRequested)
    );
    assert_eq!(
        fixture.core_running().len(),
        1,
        "a stop request frees nothing"
    );
    assert_eq!(fixture.lane_state("doomed", at), Some(InboxState::Pending));

    // The lane finishes; the core commits the terminal as cancelled, the
    // registry records the firing that did happen, and the slot is free.
    assert_eq!(fixture.drain_lane(), 1);
    assert_eq!(worker.tick_at(at + 2).expect("tick"), report(0, 0, 1, 0));
    assert_eq!(fixture.core_state("doomed", at), Some(WorkState::Cancelled));
    assert!(fixture.core_running().is_empty());
    let job = fixture.job("doomed");
    assert_eq!(job.last_fired_at_ms, Some(at));
    assert_eq!(job.active_occurrence_ms, None);
    // And nothing further, ever.
    assert_eq!(
        worker.tick_at(at + 10 * MINUTE).expect("tick"),
        TickReport::default()
    );
    assert_eq!(fixture.outbox_count(), 1);
}

// ---------------------------------------------------------------------------
// Restart
// ---------------------------------------------------------------------------

#[test]
fn a_due_but_unfired_occurrence_fires_once_after_restart() {
    let mut fixture = Fixture::new();
    fixture.register_every("nightly", "workspace:reports", T0);
    let at = T0 + MINUTE;
    {
        // The first worker never reached the instant.
        let mut first = fixture.worker();
        assert_eq!(first.tick_at(T0).expect("tick"), TickReport::default());
    }
    fixture.clock.set(at + 30_000);
    let mut second = fixture.worker();
    assert_eq!(
        second.tick().expect("tick from the clock"),
        report(1, 1, 0, 0)
    );
    assert_eq!(fixture.lane_state("nightly", at), Some(InboxState::Pending));
    assert_eq!(fixture.drain_lane(), 1);
    assert_eq!(
        second.tick_at(at + 30_001).expect("tick"),
        report(0, 0, 1, 0)
    );
    assert_eq!(fixture.outbox_count(), 1);
    // A third restart derives nothing for the same instant.
    let mut third = fixture.worker();
    assert_eq!(
        third.tick_at(at + 30_002).expect("tick"),
        TickReport::default()
    );
    assert_eq!(fixture.outbox_count(), 1);
}

#[test]
fn a_running_occurrence_is_waited_on_after_restart_never_duplicated() {
    let mut fixture = Fixture::new();
    fixture.register_every("nightly", "workspace:reports", T0);
    let at = T0 + MINUTE;
    let inbox_id = {
        let mut first = fixture.worker();
        assert_eq!(first.tick_at(at).expect("tick"), report(1, 1, 0, 0));
        fixture
            .store
            .inbox_disposition(OCCURRENCE_TRANSPORT, &Fixture::key("nightly", at))
            .expect("read")
            .expect("on the lane")
            .inbox_id
    };
    // The lane still holds it, the core still runs it, the registry still
    // has it active. A new worker finds all three and resubmits nothing.
    let mut second = fixture.worker();
    assert_eq!(second.tick_at(at + 1).expect("tick"), TickReport::default());
    assert_eq!(
        fixture
            .store
            .inbox_disposition(OCCURRENCE_TRANSPORT, &Fixture::key("nightly", at))
            .expect("read")
            .expect("still on the lane")
            .inbox_id,
        inbox_id,
        "the same delivery, not a second one"
    );
    assert_eq!(fixture.core_running().len(), 1);
    assert_eq!(fixture.drain_lane(), 1);
    assert_eq!(second.tick_at(at + 2).expect("tick"), report(0, 0, 1, 0));
    assert_eq!(fixture.outbox_count(), 1);
}

/// The crash window between the core's start and the lane's submission is
/// simulated through the core's own API: the second worker finds an
/// occurrence running in the core with nothing on the lane, and hands it to
/// the lane exactly once.
#[test]
fn an_occurrence_started_in_the_core_but_not_on_the_lane_is_submitted_after_restart() {
    let mut fixture = Fixture::new();
    fixture.register_every("nightly", "workspace:reports", T0);
    let at = T0 + MINUTE;
    let key = Fixture::key("nightly", at);
    {
        let fence =
            SchedulerFence::new(GENERATION, fixture.holder.as_str(), fixture.epoch).expect("fence");
        let mut core = DurableSchedulerStore::open(
            fixture.scheduler_path(),
            AUTOMATION_PARALLELISM_LIMIT,
            fence.clone(),
        )
        .expect("open the core");
        core.submit(&automonique_core::scheduler_conformance::QueuedWork::new(
            WorkId::new(key.as_str()).expect("work id"),
            automonique_core::scheduler_conformance::ScopeId::new("workspace:reports")
                .expect("scope"),
        ))
        .expect("admit");
        assert_eq!(core.tick(&fence).expect("start").len(), 1);
        fixture
            .registry()
            .admit_occurrence("nightly", at)
            .expect("mark active");
    }
    assert_eq!(fixture.lane_state("nightly", at), None);
    let mut worker = fixture.worker();
    assert_eq!(worker.tick_at(at).expect("tick"), report(0, 1, 0, 0));
    assert_eq!(fixture.lane_state("nightly", at), Some(InboxState::Pending));
    assert_eq!(fixture.job("nightly").next_fire_at_ms, Some(at + MINUTE));
    assert_eq!(fixture.drain_lane(), 1);
    assert_eq!(worker.tick_at(at + 1).expect("tick"), report(0, 0, 1, 0));
    assert_eq!(fixture.outbox_count(), 1);
}

#[test]
fn a_paused_automation_stays_paused_across_restart() {
    let fixture = Fixture::new();
    fixture.register_every("nightly", "workspace:reports", T0);
    fixture.transition("nightly", 1, EnablementState::Paused);
    {
        let mut first = fixture.worker();
        assert_eq!(
            first.tick_at(T0 + MINUTE).expect("tick"),
            TickReport::default()
        );
    }
    let mut second = fixture.worker();
    assert_eq!(
        second.tick_at(T0 + 5 * MINUTE).expect("tick"),
        TickReport::default()
    );
    assert_eq!(fixture.lane_state("nightly", T0 + MINUTE), None);
    assert_eq!(fixture.outbox_count(), 0);
    // Resumed, it fires the oldest due instant once and moves on.
    fixture.transition("nightly", 2, EnablementState::Enabled);
    assert_eq!(
        second.tick_at(T0 + 5 * MINUTE + 1).expect("tick"),
        report(1, 1, 0, 0)
    );
    assert_eq!(
        fixture.lane_state("nightly", T0 + MINUTE),
        Some(InboxState::Pending)
    );
    assert_eq!(
        fixture.job("nightly").next_fire_at_ms,
        Some(T0 + 6 * MINUTE)
    );
}

#[test]
fn a_stale_fence_ticks_nothing() {
    let mut fixture = Fixture::new();
    fixture.register_every("nightly", "workspace:reports", T0);
    let mut worker = fixture.worker();
    // Authority moves to a successor.
    fixture
        .store
        .release_generation_lease(GENERATION, "holder-1", fixture.epoch, T0)
        .expect("release");
    let successor = fixture
        .store
        .acquire_generation_lease(LeaseRequest {
            generation_id: GENERATION,
            holder_id: "holder-2",
            now_ms: T0,
            ttl_ms: LEASE_TTL_MS,
        })
        .expect("successor");
    assert!(successor.epoch > fixture.epoch);
    assert!(matches!(
        worker.tick_at(T0 + MINUTE),
        Err(AutomationSchedulerError::StaleFence)
    ));
    assert_eq!(fixture.lane_state("nightly", T0 + MINUTE), None);
    assert_eq!(fixture.job("nightly").active_occurrence_ms, None);
    // The successor's worker fires it.
    fixture.holder = "holder-2".to_owned();
    fixture.epoch = successor.epoch;
    fixture.lease_expires_ms = successor.expires_ms;
    let mut next = fixture.worker();
    assert_eq!(next.tick_at(T0 + MINUTE).expect("tick"), report(1, 1, 0, 0));
    // And the old worker's core handle is fenced out for good.
    assert!(matches!(
        worker.tick_at(T0 + MINUTE + 1),
        Err(AutomationSchedulerError::StaleFence)
    ));
}

#[test]
fn a_registration_from_before_jobs_existed_is_never_due() {
    let fixture = Fixture::new();
    // Written the way the previous build wrote it: no job columns at all.
    {
        let registry_path = fixture.registry_path();
        drop(fixture.registry());
        let raw = rusqlite::Connection::open(&registry_path).expect("raw");
        raw.execute(
            "INSERT INTO automations
             (automation_id, revision, enablement, actor, cause, created_at_ms, updated_at_ms)
             VALUES ('legacy', 1, 'enabled', 'ben', NULL, 1, 1)",
            [],
        )
        .expect("a legacy row");
    }
    let mut worker = fixture.worker();
    assert_eq!(
        worker.tick_at(T0 + 100 * MINUTE).expect("tick"),
        TickReport::default()
    );
    assert_eq!(fixture.outbox_count(), 0);
}
