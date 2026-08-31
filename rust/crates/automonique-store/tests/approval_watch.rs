// SPDX-License-Identifier: Elastic-2.0

//! A decision reaches a waiting run, rather than being discovered by it.
//!
//! Every assertion here is about *timing*, which is the only thing the watch
//! changes: the durable row is still the authority, and a case that passed by
//! reading a different row than the table holds would be measuring the wrong
//! thing. So each case reads the row too, and asserts both that the wait ended
//! early and that what it then read is the decision that ended it.
//!
//! The bound used throughout is deliberately far longer than any of these cases
//! should take. A case that "passes" by timing out is the exact failure the
//! watch exists to remove, so the bound is set where a timeout is unambiguous
//! rather than where it is plausible.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use automonique_store::approval_requests::{
    ApprovalContext, ApprovalOutcome, ApprovalProposal, ApprovalRequests, ApprovalState,
};
use automonique_store::approval_watch::ApprovalWatch;
use tempfile::TempDir;

const SPEC_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const PROGRAM_SHA: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PROMPT_SHA: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const KEY: &str = "apr-000102030405060708090a0b0c0d0e0f";
const LEDGER_KEY: &str = "apr-000102030405060708090a0b0c0d0e0f";

/// Long enough that reaching it is a failure rather than a slow machine.
const BOUND: Duration = Duration::from_secs(10);

/// The waits below must end far inside [`BOUND`]. A machine under load can
/// still take a while to schedule a woken thread, so the ceiling is generous —
/// it only has to separate "the bell rang" from "the bound elapsed".
const WOKEN_BY_THE_BELL: Duration = Duration::from_secs(2);

struct PrivateTable {
    _directory: TempDir,
    path: PathBuf,
}

impl PrivateTable {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let path = directory.path().join("approval-requests.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn propose(store: &mut ApprovalRequests) {
    store
        .propose(ApprovalProposal {
            request_key: KEY,
            subject: "provider-permission:one",
            run_id: "run-watch",
            context: ApprovalContext {
                spec_digest: SPEC_DIGEST,
                program_path: "/usr/bin/true",
                program_sha256: PROGRAM_SHA,
                prompt_sha256: PROMPT_SHA,
                cwd_token: "cwd-token",
            },
            requested_by: "test",
            requested_at_ms: 1_000,
            expires_at_ms: 9_000_000_000_000,
        })
        .expect("propose");
}

fn revision_of(store: &ApprovalRequests) -> u64 {
    store
        .entry(KEY)
        .expect("entry")
        .expect("proposed row")
        .revision
}

fn state_of(store: &ApprovalRequests) -> ApprovalState {
    store
        .entry(KEY)
        .expect("entry")
        .expect("proposed row")
        .state
}

/// The case the whole mechanism exists for: a decision written by another
/// thread ends the wait instead of the wait ending on its own.
///
/// Without the announcement in `ApprovalRequests::decide` this case still
/// *passes its assertion about the row* — the decision is durable either way —
/// and fails on the clock, which is the honest place for it to fail.
#[test]
fn a_decision_on_another_handle_ends_a_wait() {
    let private = PrivateTable::new();
    let watch = ApprovalWatch::new();

    let mut waiter = ApprovalRequests::open(private.path()).expect("open waiter");
    propose(&mut waiter);

    let mut decider = ApprovalRequests::open(private.path()).expect("open decider");
    decider.announce_to(Arc::clone(&watch));
    let revision = revision_of(&waiter);

    // The waiter reads the count first, then the row, then waits beyond what it
    // read — the order the module documents.
    let observed = watch.observed();
    assert_eq!(state_of(&waiter), ApprovalState::Pending);

    let ready = Arc::new(AtomicBool::new(false));
    let decided = {
        let ready = Arc::clone(&ready);
        thread::spawn(move || {
            // Give the waiter time to be inside the wait, so this is a wake-up
            // and not a decision that had already landed.
            while !ready.load(Ordering::Acquire) {
                thread::yield_now();
            }
            thread::sleep(Duration::from_millis(50));
            decider
                .decide(KEY, revision, ApprovalOutcome::Granted, LEDGER_KEY, 2_000)
                .expect("decide");
        })
    };

    ready.store(true, Ordering::Release);
    let started = Instant::now();
    watch.wait_beyond(observed, BOUND);
    let waited = started.elapsed();
    decided.join().expect("decider");

    assert!(
        waited < WOKEN_BY_THE_BELL,
        "the wait ended after {waited:?}, which is the {BOUND:?} bound rather than the decision \
         that should have ended it"
    );
    assert_eq!(
        state_of(&waiter),
        ApprovalState::Granted,
        "the wait ended, but the durable row is not the decision it should have ended for"
    );
}

/// A decision committed between reading the count and starting the wait must
/// not be slept through.
///
/// This is what the count buys over a flag, and it is the window a real waiter
/// is in on every pass: it reads `observed()`, reads the row, finds it pending,
/// and only then waits.
#[test]
fn a_decision_inside_the_read_window_does_not_wait() {
    let private = PrivateTable::new();
    let watch = ApprovalWatch::new();

    let mut waiter = ApprovalRequests::open(private.path()).expect("open waiter");
    propose(&mut waiter);
    let mut decider = ApprovalRequests::open(private.path()).expect("open decider");
    decider.announce_to(Arc::clone(&watch));

    let observed = watch.observed();
    assert_eq!(state_of(&waiter), ApprovalState::Pending);

    // The decision lands here — after the count was read, before the wait
    // starts. Nothing is blocked on it, so a waiter that waited for the *next*
    // announcement would wait for one that is never coming.
    decider
        .decide(
            KEY,
            revision_of(&waiter),
            ApprovalOutcome::Granted,
            LEDGER_KEY,
            2_000,
        )
        .expect("decide");

    let started = Instant::now();
    watch.wait_beyond(observed, BOUND);
    let waited = started.elapsed();

    assert!(
        waited < WOKEN_BY_THE_BELL,
        "an announcement already made was slept through for {waited:?}"
    );
    assert_eq!(state_of(&waiter), ApprovalState::Granted);
}

/// An expiry is not a decision, but it is still a reason to look again: a
/// sweeper that expired the row a run is waiting on has ended that wait, and
/// the run must learn it now rather than at its own deadline.
#[test]
fn an_expiry_ends_a_wait_too() {
    let private = PrivateTable::new();
    let watch = ApprovalWatch::new();

    let mut waiter = ApprovalRequests::open(private.path()).expect("open waiter");
    propose(&mut waiter);
    let mut sweeper = ApprovalRequests::open(private.path()).expect("open sweeper");
    sweeper.announce_to(Arc::clone(&watch));
    let revision = revision_of(&waiter);

    let observed = watch.observed();
    assert_eq!(state_of(&waiter), ApprovalState::Pending);

    let ready = Arc::new(AtomicBool::new(false));
    let swept = {
        let ready = Arc::clone(&ready);
        thread::spawn(move || {
            while !ready.load(Ordering::Acquire) {
                thread::yield_now();
            }
            thread::sleep(Duration::from_millis(50));
            sweeper.expire(KEY, revision, 3_000).expect("expire");
        })
    };

    ready.store(true, Ordering::Release);
    let started = Instant::now();
    watch.wait_beyond(observed, BOUND);
    let waited = started.elapsed();
    swept.join().expect("sweeper");

    assert!(
        waited < WOKEN_BY_THE_BELL,
        "the wait ran to {waited:?} instead of ending on the expiry"
    );
    assert_eq!(state_of(&waiter), ApprovalState::Expired);
}

/// The bound is the guarantee, not the mechanism: with nobody to ring the bell
/// the wait still ends, and it ends at the bound rather than early or never.
///
/// This is the case that keeps a missed announcement — from another process, or
/// from a handle nobody attached a watch to — costing timing and not liveness.
#[test]
fn a_silent_watch_still_ends_the_wait_at_its_bound() {
    let watch = ApprovalWatch::new();
    let observed = watch.observed();

    let bound = Duration::from_millis(120);
    let started = Instant::now();
    watch.wait_beyond(observed, bound);
    let waited = started.elapsed();

    assert!(
        waited >= bound,
        "the wait returned after {waited:?}, short of its own {bound:?} bound"
    );
    assert!(
        waited < bound * 20,
        "the wait took {waited:?} against a {bound:?} bound, so the bound is not bounding it"
    );
}

/// A handle nobody attached a watch to writes the same rows and rings nothing.
///
/// The point is that attaching is a decision, not a default: a store opened by
/// some other lane cannot wake waiters that were never listening to it, and it
/// must not fail because of that.
#[test]
fn an_unwatched_handle_decides_without_announcing() {
    let private = PrivateTable::new();
    let watch = ApprovalWatch::new();

    let mut waiter = ApprovalRequests::open(private.path()).expect("open waiter");
    propose(&mut waiter);
    let mut silent = ApprovalRequests::open(private.path()).expect("open silent");

    let observed = watch.observed();
    silent
        .decide(
            KEY,
            revision_of(&waiter),
            ApprovalOutcome::Denied,
            LEDGER_KEY,
            2_000,
        )
        .expect("decide");

    assert_eq!(
        watch.observed(),
        observed,
        "a handle with no watch rang a bell it was never given"
    );
    assert_eq!(
        state_of(&waiter),
        ApprovalState::Denied,
        "the decision is durable whether or not anything was announced"
    );
}

/// Announcements are a sequence, so a waiter can tell "nothing since I looked"
/// from "something, twice".
#[test]
fn the_count_moves_once_per_announcement() {
    let watch = ApprovalWatch::new();
    let first = watch.observed();
    watch.announce();
    let second = watch.observed();
    watch.announce();
    let third = watch.observed();

    assert!(second > first, "an announcement did not move the count");
    assert!(
        third > second,
        "the second announcement did not move the count"
    );
}
