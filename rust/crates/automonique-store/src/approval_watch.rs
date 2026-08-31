// SPDX-License-Identifier: Elastic-2.0

//! A bell a waiting run listens to, so a decision reaches it instead of being
//! discovered.
//!
//! [`crate::approval_requests`] is the durable authority on what was decided,
//! and nothing here changes that: a waiter still reads the row, still trusts
//! only the row, and still decides nothing from a wake-up. What this adds is
//! *when* the waiter looks. A run paused on a provider permission used to sleep
//! a fixed interval and ask the table again, which made the delay between an
//! operator answering and the run resuming a property of the sleep rather than
//! of the answer.
//!
//! # What an announcement means, and what it does not
//!
//! An announcement means "something a waiter cares about may have changed —
//! read your conditions again". It carries no payload, names no key, and is not
//! evidence of anything. Two consequences follow, and both are deliberate:
//!
//! - A **spurious** announcement is harmless. The waiter re-reads the durable
//!   row, finds it unchanged, and waits again. Announcing too often costs a
//!   read; announcing too rarely is what the bound below exists for.
//! - An announcement is **never** the decision. A waiter that woke because the
//!   bell rang and a waiter that woke because its bound elapsed run exactly the
//!   same code, so a missed ring cannot change an outcome — only its timing.
//!
//! # Why the count, rather than a flag
//!
//! A waiter reads the count *before* it reads the table, and then waits for the
//! count to move past what it read. A decision committed in the window between
//! those two steps therefore bumps a count the waiter has already observed, and
//! the wait returns immediately rather than sleeping through an answer that had
//! already arrived. A boolean flag cannot express that window: whoever cleared
//! it would race whoever set it.
//!
//! The count saturates rather than wrapping. At one announcement per
//! nanosecond a `u64` still takes five centuries to reach the ceiling, so the
//! saturation is a statement that the number is a sequence and not an amount,
//! not a case anything is expected to reach.
//!
//! # This is process-local, which is why the wait stays bounded
//!
//! The bell is an [`std::sync::Condvar`]. It reaches the threads of one
//! process, which is where every in-process decider lives — the admin handler
//! that records an operator's answer, the sweeper that expires an unanswered
//! one, and the repair pass that completes a decision a dead generation left
//! half-written. It does not reach another process writing the same database
//! file directly.
//!
//! That gap is the entire reason [`ApprovalWatch::wait_beyond`] takes a bound
//! and every caller keeps one. A missed announcement must cost a waiter the
//! remainder of its bound, never its liveness, so the bound is not a tuning
//! knob to be raised until the bell "seems reliable" — it is the guarantee that
//! the bell is an optimization. Callers also keep whatever periodic work their
//! loop already did at that cadence, which is the second reason the bound may
//! not grow: it is somebody else's timer too.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// A wake-up shared by the writers and the waiters of one approval table.
///
/// Created by whoever owns the table for a generation and handed to both
/// sides. Two handles that are not the same `Arc` are two different bells, and
/// a waiter listening to the wrong one degrades to its bound — which is why
/// this is passed explicitly rather than looked up.
#[derive(Debug)]
pub struct ApprovalWatch {
    /// Announcements so far. Only ever read under the mutex, so a waiter's
    /// comparison and a writer's increment cannot interleave.
    announced: Mutex<u64>,
    changed: Condvar,
}

impl ApprovalWatch {
    /// A bell nobody has rung yet.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            announced: Mutex::new(0),
            changed: Condvar::new(),
        })
    }

    /// The count to present to [`ApprovalWatch::wait_beyond`] after reading
    /// the durable state.
    ///
    /// Read this *first*, then the table, then wait beyond what was read.
    #[must_use]
    pub fn observed(&self) -> u64 {
        *self.guard()
    }

    /// Wake every waiter so it reads its conditions again.
    ///
    /// Called after a durable write commits, never before: a waiter woken by an
    /// uncommitted change would read the old row and wait again, which is
    /// correct but pointless.
    pub fn announce(&self) {
        let mut announced = self.guard();
        *announced = announced.saturating_add(1);
        drop(announced);
        self.changed.notify_all();
    }

    /// Block until the count moves past `observed`, or until `bound` elapses.
    ///
    /// Returns the count now, which the caller presents to its next wait. A
    /// return says only that the caller should look again; it never says what
    /// it will find.
    ///
    /// The bound is honoured across spurious wake-ups: the remaining time is
    /// recomputed each pass, so a storm of unrelated notifications cannot
    /// extend the wait, and an exhausted bound returns rather than waiting
    /// again.
    pub fn wait_beyond(&self, observed: u64, bound: Duration) -> u64 {
        let deadline = Instant::now() + bound;
        let mut announced = self.guard();
        while *announced <= observed {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            if remaining.is_zero() {
                break;
            }
            let (next, _) = self
                .changed
                .wait_timeout(announced, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            announced = next;
        }
        *announced
    }

    /// The counter, recovered if a panic poisoned the mutex.
    ///
    /// Nothing but an increment and a comparison happens under this lock, so
    /// there is no half-applied state a panic could leave behind and nothing a
    /// later reader could be misled by. Refusing to ring — or worse, refusing
    /// to *wait* — because an unrelated thread panicked would turn a bounded
    /// optimization into a liveness failure, which is the one thing this type
    /// must never be.
    fn guard(&self) -> std::sync::MutexGuard<'_, u64> {
        self.announced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
