// SPDX-License-Identifier: Elastic-2.0

//! M2 #13 verification: the scheduler core, the fourth safety property.
//!
//! The other three are verified in
//! `automonique-protocol/tests/safety_conformance.rs`. This one lives here
//! because the suite it drives is admitted under this crate's
//! [`SchedulerFence`], and a copy of that vocabulary somewhere else would be a
//! second authority rather than a shared one.
//!
//! Same discipline as the other three: the reference model must pass every
//! case, and a family of mutants — each one the reference model with exactly one
//! guarantee removed — must fail at the named case that describes what was
//! removed. A mutant here does not reimplement scheduling; it wraps the
//! reference model and lies about one thing, which is how these failures
//! actually arrive.

use automonique_core::SchedulerFence;
use automonique_core::scheduler_conformance as conformance;
use automonique_core::scheduler_conformance::{
    CancelDisposition, MAX_PARALLELISM_LIMIT, MIN_PARALLELISM_LIMIT, QueuedWork,
    ReferenceScheduler, SchedulerCore, SchedulerRefusal, ScopeId, WorkId, WorkState,
    verify_scheduler_core,
};

fn fence() -> SchedulerFence {
    SchedulerFence::new("generation-1", "holder-1", 1).expect("valid fence")
}

fn work(id: &str) -> WorkId {
    WorkId::new(id).expect("valid work id")
}

fn scope(id: &str) -> ScopeId {
    ScopeId::new(id).expect("valid scope id")
}

#[test]
fn the_reference_scheduler_passes_every_case() {
    let report = verify_scheduler_core(ReferenceScheduler::fixture).expect("reference conforms");
    assert_eq!(report.cases(), conformance::CASES.as_slice());
    assert_eq!(conformance::CASES.len(), 10);
}

/// The reference model is deliberately at the suite's minimum. A wider one has
/// to pass the same suite, or the suite only describes narrow schedulers.
#[test]
fn a_wider_scheduler_passes_the_same_suite() {
    let report = verify_scheduler_core(|| ReferenceScheduler::new(8, fence()))
        .expect("a wider scheduler conforms");
    assert_eq!(report.cases(), conformance::CASES.as_slice());
}

#[test]
fn identities_are_bounded_and_control_free() {
    assert!(WorkId::new("").is_err());
    assert!(WorkId::new("work\u{7}id").is_err());
    assert!(ScopeId::new("a".repeat(1_000)).is_err());
    assert_eq!(work("work-1").as_str(), "work-1");
    assert_eq!(scope("scope-1").to_string(), "scope-1");
}

#[test]
fn admitting_the_same_work_twice_is_refused() {
    let mut subject = ReferenceScheduler::fixture();
    let item = QueuedWork::new(work("once"), scope("scope-1"));
    subject.submit(&item).expect("first admission");
    assert_eq!(subject.submit(&item), Err(SchedulerRefusal::DuplicateWork));
}

#[test]
fn verbs_on_unknown_or_terminal_work_refuse_by_name() {
    let mut subject = ReferenceScheduler::fixture();
    let missing = work("never-submitted");
    assert_eq!(subject.cancel(&missing), Err(SchedulerRefusal::UnknownWork));
    assert_eq!(
        subject.complete(&missing),
        Err(SchedulerRefusal::UnknownWork)
    );
    assert_eq!(subject.state(&missing), None);

    let queued = work("queued");
    subject
        .submit(&QueuedWork::new(queued.clone(), scope("scope-1")))
        .expect("admission");
    assert_eq!(subject.complete(&queued), Err(SchedulerRefusal::NotRunning));
    assert_eq!(subject.cancel(&queued), Ok(CancelDisposition::NeverStarted));
    assert_eq!(
        subject.cancel(&queued),
        Err(SchedulerRefusal::AlreadyTerminal)
    );
    assert!(
        subject
            .state(&queued)
            .expect("admitted work has a state")
            .is_terminal()
    );
}

/// Cancelling running work twice is not an escalation. The first request
/// already moved custody to "stopping"; the second says the same thing.
#[test]
fn a_repeated_stop_request_says_the_same_thing() {
    let mut subject = ReferenceScheduler::fixture();
    let running = work("running");
    subject
        .submit(&QueuedWork::new(running.clone(), scope("scope-1")))
        .expect("admission");
    subject.tick(&fence()).expect("a valid tick");
    assert_eq!(subject.state(&running), Some(WorkState::Running));
    assert_eq!(
        subject.cancel(&running),
        Ok(CancelDisposition::StopRequested)
    );
    assert_eq!(
        subject.cancel(&running),
        Ok(CancelDisposition::StopRequested)
    );
    assert_eq!(subject.state(&running), Some(WorkState::StopRequested));
    assert!(
        subject.running().contains(&running),
        "custody is still held"
    );
    assert_eq!(subject.complete(&running), Ok(WorkState::Cancelled));
    assert!(subject.running().is_empty());
}

#[test]
fn the_scheduler_reports_the_scope_it_admitted_work_into() {
    let mut subject = ReferenceScheduler::fixture();
    let item = work("scoped");
    subject
        .submit(&QueuedWork::new(item.clone(), scope("a-scope")))
        .expect("admission");
    assert_eq!(subject.scope(&item), Some(&scope("a-scope")));
    assert_eq!(subject.scope(&work("elsewhere")), None);
}

/// The mutants. Each wraps the reference model and removes one guarantee.
mod mutants {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Fault {
        /// Declares a bound it does not enforce.
        LiesAboutItsLimit,
        /// Gives every item its own scope, so nothing is ever serialized.
        IgnoresScopes,
        /// Accepts a pause and keeps admitting.
        IgnoresPause,
        /// Frees the slot the moment a stop is requested.
        DropsCustodyOnCancel,
        /// Reports a cancellation it did not perform.
        CancelsQueuedWorkInName,
        /// Ticks under whatever fence it holds, not the one presented.
        IgnoresTheFence,
    }

    struct MutantScheduler {
        inner: ReferenceScheduler,
        fault: Fault,
        declared: u32,
        renames: u32,
    }

    impl MutantScheduler {
        fn new(fault: Fault) -> Self {
            // A mutant has to reach the case it breaks, so every fault except
            // the parallelism one enforces the limit it declares.
            let enforced = if fault == Fault::LiesAboutItsLimit {
                MIN_PARALLELISM_LIMIT * 2
            } else {
                MIN_PARALLELISM_LIMIT
            };
            Self {
                inner: ReferenceScheduler::new(enforced, fence()),
                fault,
                declared: MIN_PARALLELISM_LIMIT,
                renames: 0,
            }
        }
    }

    impl SchedulerCore for MutantScheduler {
        fn parallelism_limit(&self) -> u32 {
            self.declared
        }

        fn fence(&self) -> SchedulerFence {
            self.inner.fence()
        }

        fn submit(&mut self, work: &QueuedWork) -> Result<(), SchedulerRefusal> {
            if self.fault == Fault::IgnoresScopes {
                self.renames += 1;
                let unique = ScopeId::new(format!("private-scope-{}", self.renames))
                    .expect("valid scope id");
                return self
                    .inner
                    .submit(&QueuedWork::new(work.work_id().clone(), unique));
            }
            self.inner.submit(work)
        }

        fn tick(&mut self, fence: &SchedulerFence) -> Result<Vec<WorkId>, SchedulerRefusal> {
            if self.fault == Fault::IgnoresTheFence {
                let held = self.inner.fence();
                return self.inner.tick(&held);
            }
            self.inner.tick(fence)
        }

        fn complete(&mut self, work_id: &WorkId) -> Result<WorkState, SchedulerRefusal> {
            self.inner.complete(work_id)
        }

        fn pause(&mut self, scope: &ScopeId) {
            if self.fault == Fault::IgnoresPause {
                return;
            }
            self.inner.pause(scope);
        }

        fn resume(&mut self, scope: &ScopeId) {
            self.inner.resume(scope);
        }

        fn cancel(&mut self, work_id: &WorkId) -> Result<CancelDisposition, SchedulerRefusal> {
            match self.fault {
                Fault::CancelsQueuedWorkInName
                    if self.inner.state(work_id) == Some(WorkState::Queued) =>
                {
                    Ok(CancelDisposition::NeverStarted)
                }
                Fault::DropsCustodyOnCancel => {
                    let disposition = self.inner.cancel(work_id)?;
                    if disposition == CancelDisposition::StopRequested {
                        self.inner.complete(work_id)?;
                    }
                    Ok(disposition)
                }
                _ => self.inner.cancel(work_id),
            }
        }

        fn running(&self) -> Vec<WorkId> {
            self.inner.running()
        }

        fn state(&self, work_id: &WorkId) -> Option<WorkState> {
            self.inner.state(work_id)
        }
    }

    fn verify(fault: Fault) -> &'static str {
        verify_scheduler_core(|| MutantScheduler::new(fault))
            .expect_err("a mutant is not conformance")
            .case()
    }

    #[test]
    fn a_scheduler_that_lies_about_its_limit_fails_the_parallelism_case() {
        assert_eq!(
            verify(Fault::LiesAboutItsLimit),
            conformance::CASE_PARALLELISM_NEVER_EXCEEDS_THE_LIMIT
        );
    }

    #[test]
    fn a_scheduler_that_does_not_serialize_scopes_fails_the_scope_case() {
        assert_eq!(
            verify(Fault::IgnoresScopes),
            conformance::CASE_ONE_ITEM_PER_SCOPE
        );
    }

    #[test]
    fn a_scheduler_that_ignores_a_pause_fails_the_pause_case() {
        assert_eq!(
            verify(Fault::IgnoresPause),
            conformance::CASE_PAUSE_STARTS_NOTHING_NEW
        );
    }

    #[test]
    fn a_scheduler_that_drops_custody_on_cancel_fails_the_custody_case() {
        assert_eq!(
            verify(Fault::DropsCustodyOnCancel),
            conformance::CASE_CANCELLED_RUNNING_WORK_KEEPS_ITS_SLOT
        );
    }

    #[test]
    fn a_scheduler_that_only_says_it_cancelled_fails_the_queued_cancel_case() {
        assert_eq!(
            verify(Fault::CancelsQueuedWorkInName),
            conformance::CASE_CANCELLED_QUEUED_WORK_NEVER_RUNS
        );
    }

    #[test]
    fn a_scheduler_that_ignores_the_fence_fails_the_fence_case() {
        assert_eq!(
            verify(Fault::IgnoresTheFence),
            conformance::CASE_A_STALE_FENCE_STARTS_NOTHING
        );
    }

    /// A limit outside the suite's band is refused before any case runs, so a
    /// scheduler cannot pass by declaring "unbounded" as a large number.
    #[test]
    fn a_limit_outside_the_band_fails_before_anything_else() {
        for limit in [0, 1, MAX_PARALLELISM_LIMIT + 1] {
            let violation = verify_scheduler_core(|| ReferenceScheduler::new(limit, fence()))
                .expect_err("an unusable limit is not conformance");
            assert_eq!(violation.case(), conformance::CASE_LIMIT_IS_BOUNDED);
        }
    }
}
