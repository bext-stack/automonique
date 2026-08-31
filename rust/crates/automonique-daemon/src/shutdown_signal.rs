// SPDX-License-Identifier: Elastic-2.0

//! A stop a worker is told about, rather than one it keeps checking for.
//!
//! Every long-lived worker in this daemon has the same two obligations: do its
//! own work on its own cadence, and stop promptly when the generation is
//! draining. An [`AtomicBool`](std::sync::atomic::AtomicBool) discharges the
//! first and not the second, because a flag has no way to wake anybody — so
//! each worker resolved the conflict the same way, by sleeping in slices short
//! enough to notice a stop and re-reading the flag between them.
//!
//! `ticket_intake` states the consequence plainly, in the comment above the
//! loop this replaces: the slicing is "so a join waits on shutdown latency
//! rather than on the cadence, which is minutes". Its cadence is five minutes
//! and its slice is a hundred milliseconds, so it woke about three thousand
//! times per cadence to read one boolean, and still noticed a stop up to a
//! slice late.
//!
//! This is the same flag with a bell on it. A waiter blocks until the stop is
//! set or its own bound elapses, whichever comes first; a stop wakes every
//! waiter at once.
//!
//! # What it is not
//!
//! It is not a cadence, and it is not a way to make a cadence shorter. A
//! caller passes the interval it already used and gets the same interval back
//! when nothing stops it — the only thing that changes is that the interval can
//! now *end early*, and it ends early for exactly one reason. Nothing else may
//! be signalled through this type: a worker woken for a reason it cannot name
//! would be back to re-reading state on a timer, which is what this removes.
//!
//! It is not a substitute for joining, either. A stop is a request; the worker
//! is still running until its handle is joined, and `begin_shutdown` still
//! hands that handle out. Waking a worker sooner changes when the join returns,
//! never whether the caller has to wait for it.
//!
//! # Once set, always set
//!
//! There is no `resume`. A generation stops once, and a flag that could be
//! cleared would let a worker that read it early keep running against a daemon
//! that has already released its lease. Every host here creates its signal with
//! its worker and drops it with the same, so the lifetime of the signal is the
//! lifetime of the intent.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// A one-way stop that a worker can wait on.
#[derive(Debug)]
pub struct ShutdownSignal {
    /// Whether a stop has been requested. Read only under the mutex, so a
    /// waiter's check and a stopper's write cannot interleave and leave a
    /// waiter parked on a stop that has already happened.
    stopped: Mutex<bool>,
    changed: Condvar,
}

impl ShutdownSignal {
    /// A signal nobody has stopped.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            stopped: Mutex::new(false),
            changed: Condvar::new(),
        })
    }

    /// Whether a stop has been requested.
    ///
    /// The replacement for the flag read at the top of a worker's loop, and it
    /// means exactly what that read meant.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        *self.guard()
    }

    /// Request the stop, and wake every waiter.
    ///
    /// Idempotent: a second stop wakes waiters that are, by then, already
    /// leaving.
    pub fn stop(&self) {
        let mut stopped = self.guard();
        *stopped = true;
        drop(stopped);
        self.changed.notify_all();
    }

    /// Wait up to `bound`, and report whether a stop is what ended the wait.
    ///
    /// `true` means stop now — the caller's loop condition is already answered,
    /// so it does not need to read the flag again. `false` means the bound
    /// elapsed and the caller's own cadence is due.
    ///
    /// The bound is honoured across spurious wake-ups: the remaining time is
    /// recomputed on each pass, so unrelated notifications cannot stretch a
    /// cadence, and an exhausted bound returns rather than waiting again.
    pub fn stopped_within(&self, bound: Duration) -> bool {
        let deadline = Instant::now() + bound;
        let mut stopped = self.guard();
        while !*stopped {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            if remaining.is_zero() {
                break;
            }
            let (next, _) = self
                .changed
                .wait_timeout(stopped, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            stopped = next;
        }
        *stopped
    }

    /// The flag, recovered if a panic poisoned the mutex.
    ///
    /// Nothing but a boolean write and a boolean read happens under this lock,
    /// so a panic can leave no half-applied state behind. Refusing to stop — or
    /// refusing to *wait* — because an unrelated thread panicked would turn a
    /// shutdown aid into a shutdown hazard, which is the one thing this type
    /// must never be.
    fn guard(&self) -> std::sync::MutexGuard<'_, bool> {
        self.stopped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
