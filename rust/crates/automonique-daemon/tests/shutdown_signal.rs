// SPDX-License-Identifier: Elastic-2.0

//! A stop a worker is told about.
//!
//! Three properties, and the third is the one that keeps the other two honest:
//! a stop ends a wait, a wait that nobody stops still ends, and a stop that
//! already happened is never waited through. The last is what a worker's loop
//! depends on — it checks the flag, does its work, and only then waits, so a
//! stop landing inside that window must not park it for a cadence.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use automonique_daemon::shutdown_signal::ShutdownSignal;

/// Long enough that reaching it is a failure rather than a slow machine.
const CADENCE: Duration = Duration::from_secs(10);

/// Generous enough for a loaded runner to schedule a woken thread, short enough
/// that it cannot be mistaken for [`CADENCE`].
const WOKEN: Duration = Duration::from_secs(2);

/// The property the type exists for: a stop ends a wait it did not start.
#[test]
fn a_stop_ends_a_wait_in_progress() {
    let signal = ShutdownSignal::new();
    let waiter = {
        let signal = Arc::clone(&signal);
        thread::spawn(move || {
            let started = Instant::now();
            let stopped = signal.stopped_within(CADENCE);
            (stopped, started.elapsed())
        })
    };

    // Long enough that the waiter is inside the wait rather than approaching
    // it, so this is a wake-up and not the window case below.
    thread::sleep(Duration::from_millis(50));
    signal.stop();

    let (stopped, waited) = waiter.join().expect("the waiting thread");
    assert!(
        stopped,
        "the wait ended without reporting the stop that ended it"
    );
    assert!(
        waited < WOKEN,
        "the wait ran for {waited:?}, which is its own {CADENCE:?} bound rather than the stop"
    );
}

/// A stop that landed before the wait started is not waited through.
///
/// This is the window every worker loop is in on every pass: it reads the flag,
/// does its work, and waits afterwards. A stop arriving during the work would
/// be slept through by anything that only listened for a *change*.
#[test]
fn a_stop_that_already_happened_is_not_waited_through() {
    let signal = ShutdownSignal::new();
    signal.stop();

    let started = Instant::now();
    let stopped = signal.stopped_within(CADENCE);
    let waited = started.elapsed();

    assert!(stopped);
    assert!(
        waited < WOKEN,
        "a stop already requested was slept through for {waited:?}"
    );
}

/// With nobody to stop it the wait still ends, at its bound.
///
/// The bound is what makes this an aid rather than a hazard: a worker whose
/// cadence is its own business must get that cadence back when nothing else
/// happens.
#[test]
fn an_unstopped_wait_ends_at_its_bound() {
    let signal = ShutdownSignal::new();

    let bound = Duration::from_millis(120);
    let started = Instant::now();
    let stopped = signal.stopped_within(bound);
    let waited = started.elapsed();

    assert!(!stopped, "nothing stopped it, and it said something had");
    assert!(
        waited >= bound,
        "the wait returned after {waited:?}, short of its own {bound:?} bound"
    );
    assert!(
        waited < bound * 20,
        "the wait took {waited:?} against a {bound:?} bound, so the bound is not bounding it"
    );
}

/// The stop is one-way, and every waiter sees it.
#[test]
fn one_stop_releases_every_waiter_and_stays_stopped() {
    let signal = ShutdownSignal::new();
    assert!(!signal.is_stopped());

    let waiters: Vec<_> = (0..8)
        .map(|_| {
            let signal = Arc::clone(&signal);
            thread::spawn(move || signal.stopped_within(CADENCE))
        })
        .collect();

    thread::sleep(Duration::from_millis(50));
    let started = Instant::now();
    signal.stop();
    for waiter in waiters {
        assert!(waiter.join().expect("a waiting thread"));
    }
    let waited = started.elapsed();

    assert!(
        waited < WOKEN,
        "releasing eight waiters took {waited:?}; one of them waited out its bound"
    );
    assert!(signal.is_stopped());
    // Idempotent, and still stopped afterwards.
    signal.stop();
    assert!(signal.is_stopped());
}
