// SPDX-License-Identifier: Elastic-2.0

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use automonique_core::SchedulerFence;
use automonique_core::scheduler_conformance::{
    CancelDisposition, QueuedWork, ReferenceScheduler, SchedulerCore, SchedulerRefusal, ScopeId,
    WorkId, WorkState, verify_scheduler_core,
};
use automonique_store::durable_scheduler::{DurableSchedulerError, DurableSchedulerStore};

fn fence(epoch: u64) -> SchedulerFence {
    SchedulerFence::new("generation", "holder", epoch).expect("valid fixture fence")
}

fn private_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private temporary directory");
    directory
}

fn work(id: &str, scope: &str) -> QueuedWork {
    QueuedWork::new(
        WorkId::new(id).expect("valid work ID"),
        ScopeId::new(scope).expect("valid scope ID"),
    )
}

fn as_refusal<T>(result: Result<T, DurableSchedulerError>) -> Result<T, SchedulerRefusal> {
    result.map_err(|error| {
        error
            .refusal()
            .unwrap_or_else(|| panic!("unexpected durable scheduler failure: {error}"))
    })
}

struct ConformanceAdapter(DurableSchedulerStore);

impl ConformanceAdapter {
    fn open(path: &Path, limit: u32, fence: SchedulerFence) -> Self {
        Self(DurableSchedulerStore::open(path, limit, fence).expect("open durable scheduler"))
    }
}

impl SchedulerCore for ConformanceAdapter {
    fn parallelism_limit(&self) -> u32 {
        self.0.parallelism_limit()
    }

    fn fence(&self) -> SchedulerFence {
        self.0.fence().clone()
    }

    fn submit(&mut self, work: &QueuedWork) -> Result<(), SchedulerRefusal> {
        as_refusal(self.0.submit(work))
    }

    fn tick(&mut self, fence: &SchedulerFence) -> Result<Vec<WorkId>, SchedulerRefusal> {
        as_refusal(self.0.tick(fence))
    }

    fn complete(&mut self, work_id: &WorkId) -> Result<WorkState, SchedulerRefusal> {
        as_refusal(self.0.complete(work_id))
    }

    fn pause(&mut self, scope: &ScopeId) {
        self.0.set_paused(scope, true).expect("persist pause");
    }

    fn resume(&mut self, scope: &ScopeId) {
        self.0.set_paused(scope, false).expect("persist resume");
    }

    fn cancel(&mut self, work_id: &WorkId) -> Result<CancelDisposition, SchedulerRefusal> {
        as_refusal(self.0.cancel(work_id))
    }

    fn running(&self) -> Vec<WorkId> {
        self.0.running().expect("read running work")
    }

    fn state(&self, work_id: &WorkId) -> Option<WorkState> {
        self.0.state(work_id).expect("read work state")
    }
}

#[test]
fn production_store_passes_scheduler_core_conformance() {
    let directory = private_tempdir();
    let next = AtomicU64::new(1);
    let report = verify_scheduler_core(|| {
        let id = next.fetch_add(1, Ordering::Relaxed);
        let path = directory.path().join(format!("scheduler-{id}.sqlite3"));
        ConformanceAdapter::open(&path, 4, fence(1))
    })
    .expect("durable scheduler conforms");
    assert_eq!(report.cases().len(), 10);
}

#[test]
fn restart_preserves_queue_pause_running_and_stop_request_without_restarting_work() {
    let directory = private_tempdir();
    let path = directory.path().join("scheduler.sqlite3");
    let first_fence = fence(1);
    let mut first = DurableSchedulerStore::open(&path, 2, first_fence.clone()).expect("open first");
    let a1 = work("a-1", "scope-a");
    let a2 = work("a-2", "scope-a");
    let b1 = work("b-1", "scope-b");
    first.submit(&a1).expect("submit a1");
    first.submit(&a2).expect("submit a2");
    first.submit(&b1).expect("submit b1");
    first
        .set_paused(a1.scope(), true)
        .expect("persist scope pause");
    assert_eq!(
        first.tick(&first_fence).expect("first tick"),
        vec![b1.work_id().clone()]
    );
    first.cancel(b1.work_id()).expect("persist stop request");

    let second_fence = SchedulerFence::new("generation", "successor", 2).expect("successor fence");
    let mut second =
        DurableSchedulerStore::open(&path, 2, second_fence.clone()).expect("reopen after restart");
    assert_eq!(
        second.state(a1.work_id()).expect("a1 state"),
        Some(WorkState::Queued)
    );
    assert_eq!(
        second.state(a2.work_id()).expect("a2 state"),
        Some(WorkState::Queued)
    );
    assert_eq!(
        second.state(b1.work_id()).expect("b1 state"),
        Some(WorkState::StopRequested)
    );
    assert_eq!(
        second.running().expect("running after restart"),
        vec![b1.work_id().clone()]
    );
    assert!(second.tick(&second_fence).expect("paused tick").is_empty());
    assert_eq!(
        first
            .state(a1.work_id())
            .expect_err("old handle is fenced")
            .category(),
        "stale_fence"
    );

    assert_eq!(
        second.complete(b1.work_id()).expect("terminal stop"),
        WorkState::Cancelled
    );
    second
        .set_paused(a1.scope(), false)
        .expect("persist resume");
    assert_eq!(
        second.tick(&second_fence).expect("resume tick"),
        vec![a1.work_id().clone()]
    );
    assert_eq!(
        second.complete(a1.work_id()).expect("complete a1"),
        WorkState::Completed
    );
    assert_eq!(
        second.tick(&second_fence).expect("next FIFO tick"),
        vec![a2.work_id().clone()]
    );
}

#[test]
fn generated_operation_sequences_match_the_reference_model_across_reopens() {
    let directory = private_tempdir();
    let path = directory.path().join("scheduler.sqlite3");
    let held = fence(7);
    let mut durable = ConformanceAdapter::open(&path, 4, held.clone());
    let mut reference = ReferenceScheduler::new(4, held.clone());
    let work: Vec<QueuedWork> = (0..24)
        .map(|index| work(&format!("work-{index}"), &format!("scope-{}", index % 6)))
        .collect();
    let scopes: Vec<ScopeId> = (0..6)
        .map(|index| ScopeId::new(format!("scope-{index}")).expect("valid scope"))
        .collect();
    let mut state = 0x4d59_5df4_d0f3_3173_u64;

    for step in 0..1_024 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let target = (state as usize) % work.len();
        let scope = ((state >> 16) as usize) % scopes.len();
        match (state >> 32) % 6 {
            0 => assert_eq!(
                durable.submit(&work[target]),
                reference.submit(&work[target])
            ),
            1 => assert_eq!(durable.tick(&held), reference.tick(&held)),
            2 => {
                durable.pause(&scopes[scope]);
                reference.pause(&scopes[scope]);
            }
            3 => {
                durable.resume(&scopes[scope]);
                reference.resume(&scopes[scope]);
            }
            4 => assert_eq!(
                durable.cancel(work[target].work_id()),
                reference.cancel(work[target].work_id())
            ),
            _ => assert_eq!(
                durable.complete(work[target].work_id()),
                reference.complete(work[target].work_id())
            ),
        }
        assert_eq!(
            durable.running(),
            reference.running(),
            "running set at step {step}"
        );
        for candidate in &work {
            assert_eq!(
                durable.state(candidate.work_id()),
                reference.state(candidate.work_id()),
                "state for {} at step {step}",
                candidate.work_id()
            );
        }
        if step % 97 == 0 {
            durable = ConformanceAdapter::open(&path, 4, held.clone());
        }
    }
}

#[test]
fn parallelism_one_is_valid_operationally_but_above_the_bound_is_refused() {
    let directory = private_tempdir();
    DurableSchedulerStore::open(directory.path().join("serial.sqlite3"), 1, fence(1))
        .expect("one slot is an operational setting");
    let error =
        DurableSchedulerStore::open(directory.path().join("unbounded.sqlite3"), 1_025, fence(1))
            .expect_err("unbounded setting refused");
    assert_eq!(error.category(), "invalid_field");
}

#[test]
fn database_path_is_stable_and_private() {
    let directory = private_tempdir();
    let path = PathBuf::from(directory.path()).join("scheduler.sqlite3");
    let store = DurableSchedulerStore::open(&path, 2, fence(1)).expect("open scheduler");
    assert_eq!(store.path(), path);
    let mode = std::fs::metadata(store.path())
        .expect("scheduler metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}
