// SPDX-License-Identifier: Elastic-2.0

//! Process-level proofs for the reload protocol's failure matrix.
//!
//! Each test drives a real source daemon, a real candidate process spawned
//! from an installed release of this binary, and the product CLI, and injects
//! one real external fault at one named point of the handoff through the
//! typed `reload-fault-injection` hook. The hook can kill the candidate,
//! abort or hang the source, or hold the main database's write lock; it can
//! never make a phase report an outcome it did not reach. What each test
//! asserts is what the matrix in `docs/product-plan/requirements/
//! reload-protocol.md` requires for its row, read back from the durable
//! lease, the reload audit and the sockets an operator would use.
//!
//! Two rows need the source to be a separate process, because the fault is
//! the source itself dying or being terminated: those run the product binary
//! as `daemon --foreground` and script the fault through
//! `AUTOMONIQUE_RELOAD_FAULT`, which only a test build honours.

mod handoff_support;

use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use automonique_daemon::reload_faults::{ReloadFaultAction, ReloadFaultPoint};
use automonique_daemon::{Daemon, DaemonConfig, RELOAD_FAULT_ENV};
use automonique_protocol::execute_api::{CancelRunOutcome, ExecuteRefusal, ExecuteResponse};
use automonique_runner::control::{CancelDelivery, CancelSink, CancelSinkError};
use automonique_store::{Store, TelegramPollerLeaseRequest};
use handoff_support::{
    ProcBootTime, Serving, attempt_id_of, cancel, candidate_processes, cli, cli_command, fixture,
    install_code_release, install_releases, process_exited, read_source_lease, reload_id_for,
    reload_phase, reload_status, run_spec, stderr_text, stdout_text, submit, unix_millis,
    wait_for_generation, wait_for_reload_phase, wait_for_sockets_removed, wait_until,
};
use rusqlite::Connection;

/// Bound on one CLI `--wait`, below the CLI's own 60-second deadline.
const WAIT_BOUND: Duration = Duration::from_secs(45);

/// The reload's head line names `category` as its failure.
fn assert_failure(config: &DaemonConfig, reload_id: &str, phase: &str, category: &str) {
    let status = reload_status(config, reload_id).expect("reload status");
    let head = status.lines().next().expect("head line");
    assert!(
        head.contains(&format!(" phase={phase} ")),
        "{reload_id}: {head}"
    );
    assert!(
        head.ends_with(&format!(" failure={category}")),
        "{reload_id}: {head}"
    );
}

/// A reload that must succeed over the same socket, proving the source is
/// fully active after the fault it survived; the committed successor is then
/// shut down.
fn reload_succeeds_then_shutdown(config: &DaemonConfig, source: Serving, next_digest: &str) {
    let lease = read_source_lease(&config.database_path());
    let reload = cli(
        config,
        &["reload", &format!("sha256:{next_digest}"), "--wait"],
    );
    assert!(
        reload.status.success(),
        "the recovered source hands off: {}",
        stderr_text(&reload)
    );
    assert_eq!(
        stdout_text(&reload),
        format!(
            "reload {} succeeded\n",
            reload_id_for("reload", lease.epoch, next_digest)
        )
    );
    source.join().expect("the source retires cleanly");
    let shutdown = cli(config, &["shutdown"]);
    assert!(shutdown.status.success());
    wait_for_sockets_removed(config);
}

/// Row: target verification fails → N stays active; the target never starts
/// and no reload epoch is created.
#[test]
fn an_unverifiable_target_is_refused_before_any_epoch_exists() {
    let (_root, config) = fixture();
    let releases = install_releases(&config);
    let source = Serving::start(Daemon::open(&config).expect("source daemon"), &config);
    let before = read_source_lease(&config.database_path());

    // A digest nothing was installed under: verification fails before a
    // candidate, an epoch or a lease transition exists.
    let unknown = "f".repeat(64);
    let reload = cli(&config, &["reload", &format!("sha256:{unknown}"), "--wait"]);
    assert!(!reload.status.success());
    assert_eq!(
        stderr_text(&reload),
        "automonique reload refused: release_verification_failed\n"
    );
    let reload_id = reload_id_for("reload", before.epoch, &unknown);
    let status = cli(&config, &["reload-status", &reload_id]);
    assert!(!status.status.success());
    assert_eq!(
        stderr_text(&status),
        "automonique reload-status refused: reload_not_found\n"
    );
    assert!(candidate_processes(&reload_id).is_empty());
    let after = read_source_lease(&config.database_path());
    assert_eq!(after.holder_id, before.holder_id);
    assert_eq!(after.epoch, before.epoch);
    assert_eq!(after.revision, before.revision);

    reload_succeeds_then_shutdown(&config, source, &releases.next);
}

/// Row: candidate crashes before lease transfer → N stays active.
#[test]
fn a_candidate_that_dies_before_transfer_leaves_the_source_active() {
    let (_root, config) = fixture();
    let releases = install_releases(&config);
    let next = releases.next.clone();
    let mut daemon = Daemon::open(&config).expect("source daemon");
    let mut armed = true;
    daemon.install_reload_fault_hook(Box::new(move |point| {
        if armed && point == ReloadFaultPoint::CandidateWarm {
            armed = false;
            ReloadFaultAction::KillCandidate
        } else {
            ReloadFaultAction::Continue
        }
    }));
    let source = Serving::start(daemon, &config);
    let before = read_source_lease(&config.database_path());

    let reload = cli(&config, &["reload", &format!("sha256:{next}"), "--wait"]);
    assert!(!reload.status.success());
    let reload_id = reload_id_for("reload", before.epoch, &next);
    assert_eq!(
        stderr_text(&reload),
        format!("reload {reload_id} failed: candidate_exited\n")
    );
    assert_failure(&config, &reload_id, "failed", "candidate_exited");

    // The lease never moved: same holder, same epoch, same revision.
    let after = read_source_lease(&config.database_path());
    assert_eq!(after.holder_id, before.holder_id);
    assert_eq!(after.epoch, before.epoch);
    assert_eq!(after.revision, before.revision);
    assert!(candidate_processes(&reload_id).is_empty());
    let status = cli(&config, &["status", "--json"]);
    assert!(status.status.success());
    assert!(stdout_text(&status).contains(&before.holder_id));

    reload_succeeds_then_shutdown(&config, source, &releases.retry);
}

/// Row: N crashes before transfer → ordinary startup elects a live
/// generation; the candidate never acquires anything.
#[test]
fn a_source_that_dies_before_transfer_is_succeeded_by_ordinary_startup() {
    let (_root, config) = fixture();
    let releases = install_releases(&config);
    let next = releases.next.clone();
    let mut source = cli_command(&config)
        .args(["daemon", "--foreground"])
        .env(RELOAD_FAULT_ENV, "candidate_warm:abort_source")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("source daemon process");
    let before = wait_for_generation(&config);
    assert_eq!(before.pid, source.id());

    let reload = cli(&config, &["reload", &format!("sha256:{next}")]);
    assert!(
        reload.status.success(),
        "the reload is accepted before the source dies: {}",
        stderr_text(&reload)
    );
    let reload_id = reload_id_for("reload", before.epoch, &next);
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = source.try_wait().expect("source status") {
            break status;
        }
        assert!(Instant::now() < deadline, "the source did not abort");
        std::thread::sleep(Duration::from_millis(25));
    };
    assert!(!status.success(), "the source aborted: {status}");
    // The candidate loses its channel and its parent, and exits without ever
    // having held a lease: no process, and the durable lease still names the
    // dead source.
    wait_until(
        "the orphaned candidate to exit",
        Duration::from_secs(20),
        || candidate_processes(&reload_id).is_empty(),
    );
    let orphaned = read_source_lease(&config.database_path());
    assert_eq!(orphaned.holder_id, before.holder_id);
    assert_eq!(orphaned.epoch, before.epoch);

    // Ordinary startup: the acquirer proves the recorded owner is dead,
    // expires its lease under durable checks, and closes the epoch the dead
    // source left open.
    let daemon = Daemon::open(&config).expect("a fresh generation acquires the lease");
    let fresh = Serving::start(daemon, &config);
    let elected = read_source_lease(&config.database_path());
    assert_ne!(elected.holder_id, before.holder_id);
    assert_eq!(elected.epoch, before.epoch + 1);
    assert_failure(&config, &reload_id, "failed", "source_generation_lost");
    let status = cli(&config, &["status", "--json"]);
    assert!(status.status.success());
    assert!(stdout_text(&status).contains(&elected.holder_id));

    reload_succeeds_then_shutdown(&config, fresh, &releases.retry);
}

/// Row: transactional lease transfer fails → N resumes; candidate remains
/// non-owning and exits.
#[test]
fn a_refused_lease_transfer_leaves_the_source_serving_and_the_candidate_gone() {
    let (_root, config) = fixture();
    let releases = install_releases(&config);
    let next = releases.next.clone();
    let mut daemon = Daemon::open(&config).expect("source daemon");
    let database = config.database_path();
    let mut armed = true;
    daemon.install_reload_fault_hook(Box::new(move |point| {
        if armed && point == ReloadFaultPoint::BeforeLeaseTransfer {
            armed = false;
            // A live transport lease under the source's authority: exactly
            // the durable state the transfer transaction refuses to move
            // without its own handshake. Acquired through the store, so it is
            // a real row the transfer's own predicate reads.
            let lease = read_source_lease(&database);
            let mut store = Store::open_with_lease_time_source(&database, Arc::new(ProcBootTime))
                .expect("second store handle");
            store
                .acquire_telegram_poller_lease(TelegramPollerLeaseRequest {
                    bot_id: 424_242,
                    generation_id: "foreground",
                    holder_id: &lease.holder_id,
                    authority_lease_epoch: lease.epoch,
                    now_ms: unix_millis(),
                    ttl_ms: 3_000,
                })
                .expect("poller lease under the source's authority");
        }
        ReloadFaultAction::Continue
    }));
    let source = Serving::start(daemon, &config);
    let before = read_source_lease(&config.database_path());

    let reload = cli(&config, &["reload", &format!("sha256:{next}"), "--wait"]);
    assert!(!reload.status.success());
    let reload_id = reload_id_for("reload", before.epoch, &next);
    assert_eq!(
        stderr_text(&reload),
        format!("reload {reload_id} failed: handoff_blocked\n")
    );
    assert_failure(&config, &reload_id, "failed", "handoff_blocked");
    let after = read_source_lease(&config.database_path());
    assert_eq!(after.holder_id, before.holder_id);
    assert_eq!(after.epoch, before.epoch);
    assert_eq!(
        after.revision, before.revision,
        "the transaction rolled back whole"
    );
    assert!(candidate_processes(&reload_id).is_empty());
    let status = cli(&config, &["status", "--json"]);
    assert!(status.status.success());
    assert!(stdout_text(&status).contains(&before.holder_id));

    // The injected poller lease lapses on its own TTL; the resumed source
    // then hands off normally.
    std::thread::sleep(Duration::from_millis(3_500));
    reload_succeeds_then_shutdown(&config, source, &releases.retry);
}

/// Row: N+1 fails after transfer but before active proof → leases return to
/// N, which is alive.
#[test]
fn a_candidate_that_dies_after_transfer_returns_authority_to_the_source() {
    let (_root, config) = fixture();
    let releases = install_releases(&config);
    let next = releases.next.clone();
    let mut daemon = Daemon::open(&config).expect("source daemon");
    let mut armed = true;
    daemon.install_reload_fault_hook(Box::new(move |point| {
        if armed && point == ReloadFaultPoint::AfterLeaseTransfer {
            armed = false;
            ReloadFaultAction::KillCandidate
        } else {
            ReloadFaultAction::Continue
        }
    }));
    let source = Serving::start(daemon, &config);
    let before = read_source_lease(&config.database_path());

    let reload = cli(&config, &["reload", &format!("sha256:{next}"), "--wait"]);
    assert!(!reload.status.success());
    let reload_id = reload_id_for("reload", before.epoch, &next);
    assert_eq!(
        stderr_text(&reload),
        format!("reload {reload_id} failed: candidate_io\n")
    );
    assert_failure(&config, &reload_id, "rolled_back", "candidate_io");

    // Authority came back to the same process at a fresh fence: two epochs
    // on, because the transfer out and the return in are both durable.
    let after = read_source_lease(&config.database_path());
    assert_eq!(after.holder_id, before.holder_id);
    assert_eq!(after.epoch, before.epoch + 2);
    assert_eq!(after.pid, before.pid);
    assert!(candidate_processes(&reload_id).is_empty());
    let status = cli(&config, &["status", "--json"]);
    assert!(status.status.success());
    assert!(stdout_text(&status).contains(&before.holder_id));

    reload_succeeds_then_shutdown(&config, source, &releases.retry);
}

/// Row: old generation refuses to drain → it is terminated once its leases
/// are invalid and active effects are durable; the successor keeps serving.
#[test]
fn a_source_that_refuses_to_drain_does_not_hold_the_active_successor() {
    let (_root, config) = fixture();
    let releases = install_releases(&config);
    let next = releases.next.clone();
    let mut source = cli_command(&config)
        .args(["daemon", "--foreground"])
        .env(RELOAD_FAULT_ENV, "before_source_drain:hang_source")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("source daemon process");
    let before = wait_for_generation(&config);

    let current_link = releases.root.join("current");
    let current_before = std::fs::read_link(&current_link).expect("current release link");
    assert_eq!(
        current_before,
        std::path::Path::new("releases").join(&releases.previous)
    );

    let reload = cli(&config, &["reload", &format!("sha256:{next}")]);
    assert!(reload.status.success(), "{}", stderr_text(&reload));
    let reload_id = reload_id_for("reload", before.epoch, &next);
    wait_for_reload_phase(&config, &reload_id, &["active_proven"], WAIT_BOUND);

    // The successor proved active and owns the lease; the source's authority
    // is invalid while it sits in its drain, and every operator surface
    // already answers from the successor.
    let successor = read_source_lease(&config.database_path());
    assert_ne!(successor.holder_id, before.holder_id);
    assert_eq!(successor.epoch, before.epoch + 1);
    assert_ne!(successor.pid, source.id());
    let status = cli(&config, &["status", "--json"]);
    assert!(status.status.success());
    assert!(stdout_text(&status).contains(&successor.holder_id));
    assert!(
        source.try_wait().expect("source status").is_none(),
        "the source is still alive, refusing to drain"
    );

    // The lifecycle owner terminates the old generation. The successor is
    // unaffected: it keeps the lease it holds, keeps answering, and closes
    // the epoch nobody can finish under its own category.
    source.kill().expect("terminate the old generation");
    source.wait().expect("reap the old generation");
    wait_until(
        "the successor to record the lost source",
        WAIT_BOUND,
        || reload_phase(&config, &reload_id).as_deref() == Some("failed"),
    );
    assert_failure(&config, &reload_id, "failed", "source_generation_lost");
    let status = cli(&config, &["status", "--json"]);
    assert!(status.status.success(), "the successor survives the source");
    assert!(stdout_text(&status).contains(&successor.holder_id));
    let held = read_source_lease(&config.database_path());
    assert_eq!(held.holder_id, successor.holder_id);
    assert_eq!(held.epoch, successor.epoch);
    // The release links stay where the source left them: activation is the
    // source's step, after its drain, and it never got there. The successor
    // does not move them on the source's behalf.
    assert_eq!(
        std::fs::read_link(&current_link).expect("current release link"),
        current_before,
        "the successor left the current link as the source left it"
    );

    let shutdown = cli(&config, &["shutdown"]);
    assert!(shutdown.status.success());
    wait_for_sockets_removed(&config);
    wait_until("the successor to exit", Duration::from_secs(10), || {
        process_exited(successor.pid)
    });
}

/// Row: database becomes busy → bounded retry, lease atomicity intact, and
/// the reload aborts on its deadline.
#[test]
fn a_busy_database_aborts_the_transfer_within_its_bound_without_moving_the_lease() {
    let (_root, config) = fixture();
    let releases = install_releases(&config);
    let next = releases.next.clone();
    let mut daemon = Daemon::open(&config).expect("source daemon");
    let mut armed = true;
    daemon.install_reload_fault_hook(Box::new(move |point| {
        if armed && point == ReloadFaultPoint::BeforeLeaseTransfer {
            armed = false;
            ReloadFaultAction::HoldMainDatabaseWriteLock(Duration::from_millis(3_000))
        } else {
            ReloadFaultAction::Continue
        }
    }));
    let source = Serving::start(daemon, &config);
    let before = read_source_lease(&config.database_path());

    let started = Instant::now();
    let reload = cli(&config, &["reload", &format!("sha256:{next}"), "--wait"]);
    let elapsed = started.elapsed();
    assert!(!reload.status.success());
    let reload_id = reload_id_for("reload", before.epoch, &next);
    assert_eq!(
        stderr_text(&reload),
        format!("reload {reload_id} failed: sqlite\n")
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "the transfer gave up on its busy deadline rather than waiting out the lock: {elapsed:?}"
    );
    assert_failure(&config, &reload_id, "failed", "sqlite");
    // Holder, epoch and revision: the fields a transfer would have moved.
    // The row's renewal timestamps keep advancing under the live source, so
    // the whole row is not what is compared.
    let after = read_source_lease(&config.database_path());
    assert_eq!(after.holder_id, before.holder_id);
    assert_eq!(after.epoch, before.epoch);
    assert_eq!(
        after.revision, before.revision,
        "nothing partial was written"
    );
    assert!(candidate_processes(&reload_id).is_empty());
    let status = cli(&config, &["status", "--json"]);
    assert!(status.status.success());
    assert!(stdout_text(&status).contains(&before.holder_id));

    reload_succeeds_then_shutdown(&config, source, &releases.retry);
}

/// Row: new schema breaks rollback → the incompatible target is refused. The
/// manifest declares no schema range, so the refusal happens at candidate
/// warm-up rather than before spawn; the candidate exits without owning
/// anything and the source stays active.
#[test]
fn a_schema_the_candidate_cannot_read_is_refused_at_warm_up() {
    let (_root, config) = fixture();
    let releases = install_releases(&config);
    let next = releases.next.clone();
    let source = Serving::start(Daemon::open(&config).expect("source daemon"), &config);
    let before = read_source_lease(&config.database_path());

    // A migration this release does not know: the durable schema moves one
    // version past what the candidate's read-only warm-up accepts.
    let connection = Connection::open(config.database_path()).expect("main database");
    let version: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("schema version");
    connection
        .pragma_update(None, "user_version", version + 1)
        .expect("advance the schema");
    drop(connection);

    let reload = cli(&config, &["reload", &format!("sha256:{next}"), "--wait"]);
    assert!(!reload.status.success());
    let reload_id = reload_id_for("reload", before.epoch, &next);
    assert_eq!(
        stderr_text(&reload),
        format!("reload {reload_id} failed: candidate_schema_mismatch\n")
    );
    assert_failure(&config, &reload_id, "failed", "candidate_schema_mismatch");
    let after = read_source_lease(&config.database_path());
    assert_eq!(after.holder_id, before.holder_id);
    assert_eq!(after.epoch, before.epoch);
    assert!(candidate_processes(&reload_id).is_empty());
    let status = cli(&config, &["status", "--json"]);
    assert!(status.status.success());
    assert!(stdout_text(&status).contains(&before.holder_id));

    let connection = Connection::open(config.database_path()).expect("main database");
    connection
        .pragma_update(None, "user_version", version)
        .expect("restore the schema");
    drop(connection);
    reload_succeeds_then_shutdown(&config, source, &releases.retry);
}

/// A release whose candidate speaks the previous channel schema is refused
/// under its own category at warm-up, and the source resumes.
///
/// The channel schema has moved twice: to `v7` with the attempt inventory the
/// handoff carries, and to `v8` with the admin pathname's owner the
/// activation control carries. A source of this release that spawns a
/// candidate stamped with an older schema sees that in its warm-up identity;
/// this is the rollback-to-the-previous-release case, and it is what makes
/// the first deployment of a release that moves the version, and any rollback
/// across it, restart-based.
/// The candidate here is a script that answers the inherited channel exactly
/// as a `v6` binary's warm-up would, so the source's judgement is exercised
/// against a real child process rather than a crafted line.
#[test]
fn a_candidate_speaking_another_channel_schema_is_refused_at_warm_up() {
    let (_root, config) = fixture();
    let releases = install_releases(&config);
    let previous_schema_candidate = install_code_release(
        &releases.root,
        concat!(
            "#!/bin/sh\n",
            "# A candidate of the previous release: it answers the warm-up on the\n",
            "# inherited channel in the previous channel schema and waits.\n",
            "printf '%s\\n' '{\"schema\":\"automonique.reload-candidate/v6\",",
            "\"event\":\"warm\",\"reload_id\":\"reload\",",
            "\"target_generation_id\":\"foreground\",",
            "\"manifest_digest\":\"sha256:",
            "0000000000000000000000000000000000000000000000000000000000000000\",",
            "\"binary_sha256\":",
            "\"0000000000000000000000000000000000000000000000000000000000000000\",",
            "\"attempt_count\":0,\"attempt_inventory_sha256\":",
            "\"0000000000000000000000000000000000000000000000000000000000000000\",",
            "\"target_holder_id\":\"daemon-1-reload-0000000000000000\",",
            "\"boot_id\":\"00000000-0000-0000-0000-000000000000\",",
            "\"starttime\":1,\"pid\":1}'\n",
            "exec sleep 60\n",
        )
        .as_bytes(),
        '1',
    );
    let source = Serving::start(Daemon::open(&config).expect("source daemon"), &config);
    let before = read_source_lease(&config.database_path());

    let reload = cli(
        &config,
        &[
            "reload",
            &format!("sha256:{previous_schema_candidate}"),
            "--wait",
        ],
    );
    assert!(!reload.status.success());
    let reload_id = reload_id_for("reload", before.epoch, &previous_schema_candidate);
    assert_eq!(
        stderr_text(&reload),
        format!("reload {reload_id} failed: candidate_channel_schema_mismatch\n")
    );
    assert_failure(
        &config,
        &reload_id,
        "failed",
        "candidate_channel_schema_mismatch",
    );
    let after = read_source_lease(&config.database_path());
    assert_eq!(after.holder_id, before.holder_id);
    assert_eq!(after.epoch, before.epoch);
    assert_eq!(after.revision, before.revision);
    assert!(candidate_processes(&reload_id).is_empty());
    let status = cli(&config, &["status", "--json"]);
    assert!(status.status.success());
    assert!(stdout_text(&status).contains(&before.holder_id));

    reload_succeeds_then_shutdown(&config, source, &releases.next);
}

struct CountingSink {
    attempt_id: String,
    deliveries: Arc<AtomicUsize>,
}

impl CancelSink for CountingSink {
    fn deliver(
        &self,
        attempt_id: &str,
        _request_ref: &str,
    ) -> Result<CancelDelivery, CancelSinkError> {
        if attempt_id != self.attempt_id {
            return Err(CancelSinkError::Unavailable);
        }
        self.deliveries.fetch_add(1, Ordering::Release);
        Ok(CancelDelivery::Accepted)
    }
}

/// A cancellation presented to the successor for an attempt the source still
/// hosts reaches the source's sink exactly once, its replay is answered
/// without a second delivery, and once the source has retired the successor
/// says truthfully that no live attempt exists.
#[test]
fn a_successor_forwards_cancellation_to_the_source_hosted_attempt_exactly_once() {
    let run = "handoff-cancel-c";
    let attempt_id = attempt_id_of(run);
    let (_root, config) = fixture();
    let releases = install_releases(&config);
    let next = releases.next.clone();
    let mut daemon = Daemon::open(&config).expect("source daemon");
    let deliveries = Arc::new(AtomicUsize::new(0));
    // The attempt is hosted the way the execution lane hosts one: registered
    // on the source's attempt host, with a sink that counts deliveries. No
    // workload runs; what is under test is custody, not containment.
    let registration = daemon
        .attempt_host()
        .expect("an opened daemon owns its attempt host")
        .register(
            &attempt_id,
            Box::new(CountingSink {
                attempt_id: attempt_id.clone(),
                deliveries: Arc::clone(&deliveries),
            }),
        )
        .expect("register the source-hosted attempt");
    let hook_config = config.clone();
    let hook_deliveries = Arc::clone(&deliveries);
    let mut armed = true;
    daemon.install_reload_fault_hook(Box::new(move |point| {
        // Not a fault: the successor is active and the source is about to
        // drain. This is the window in which an operator's cancellation
        // arrives at the successor for an attempt only the source can stop.
        if armed && point == ReloadFaultPoint::BeforeSourceDrain {
            armed = false;
            let first = cancel(&hook_config, "cancel-forward-1", run, "ref-1", 1);
            assert!(
                matches!(
                    first,
                    ExecuteResponse::Cancelled {
                        outcome: CancelRunOutcome::Delivered,
                        ..
                    }
                ),
                "forwarded once: {first:?}"
            );
            assert_eq!(hook_deliveries.load(Ordering::Acquire), 1);
            let replay = cancel(&hook_config, "cancel-forward-2", run, "ref-1", 1);
            assert!(
                matches!(
                    replay,
                    ExecuteResponse::Cancelled {
                        outcome: CancelRunOutcome::AlreadyDelivered,
                        ..
                    }
                ),
                "the replay is answered from custody: {replay:?}"
            );
            assert_eq!(
                hook_deliveries.load(Ordering::Acquire),
                1,
                "the replay reached no sink"
            );
        }
        ReloadFaultAction::Continue
    }));
    let source = Serving::start(daemon, &config);
    submit(&config, &run_spec(run, "true"), "handoff-cancel-submit");
    let before = read_source_lease(&config.database_path());

    let reload = cli(&config, &["reload", &format!("sha256:{next}"), "--wait"]);
    assert!(reload.status.success(), "{}", stderr_text(&reload));
    let reload_id = reload_id_for("reload", before.epoch, &next);
    assert_eq!(
        stdout_text(&reload),
        format!("reload {reload_id} succeeded\n")
    );
    source.join().expect("the source retires");
    assert_eq!(deliveries.load(Ordering::Acquire), 1);
    drop(registration);

    // The source's route is gone with the source. The successor no longer
    // claims to host what it cannot reach, and nothing was delivered twice.
    let after = cancel(&config, "cancel-forward-3", run, "ref-2", 1);
    assert!(
        matches!(
            after,
            ExecuteResponse::Refused {
                refusal: ExecuteRefusal::NoLiveAttempt,
                ..
            }
        ),
        "after the source retired: {after:?}"
    );
    assert_eq!(deliveries.load(Ordering::Acquire), 1);

    let shutdown = cli(&config, &["shutdown"]);
    assert!(shutdown.status.success());
    wait_for_sockets_removed(&config);
}

/// The hook's grammar is closed. A script the parser does not accept is a
/// refusal before the daemon opens — nothing durable is created and no
/// socket is bound — never a handoff that silently runs without the fault it
/// was asked for. The build without the feature refuses any script at all:
/// `automonique-daemon/tests/reload_fault_refusal.rs`.
#[test]
fn a_malformed_fault_script_is_refused_before_the_daemon_opens() {
    let (_root, config) = fixture();
    let output = cli_command(&config)
        .args(["daemon", "--foreground"])
        .env(RELOAD_FAULT_ENV, "candidate_warm:explode")
        .stdin(Stdio::null())
        .output()
        .expect("daemon process");
    assert!(!output.status.success());
    assert_eq!(
        stderr_text(&output),
        "automonique daemon refused: protocol_refused\n"
    );
    // The fixture placed the prompt slot; the daemon added nothing beside it.
    let mut state_entries: Vec<String> = std::fs::read_dir(config.state_dir())
        .expect("state directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    state_entries.sort();
    assert_eq!(state_entries, ["prompts"], "nothing durable was created");
    assert!(!config.database_path().exists());
    assert!(!config.admin_socket().exists());
    assert!(!config.runtime_dir().exists(), "no endpoint was bound");
}
