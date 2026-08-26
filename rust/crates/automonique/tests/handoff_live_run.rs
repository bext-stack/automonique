// SPDX-License-Identifier: Elastic-2.0

//! A live contained attempt survives the N → N+1 generation handoff.
//!
//! The source daemon runs a real workload — busybox, launched through the
//! execution lane and the entry helper under the composed sandbox — and the
//! authenticated `reload --wait` is issued while that attempt is running. The
//! proof then reads back, from the durable stores and over the successor's
//! inherited socket:
//!
//! - the successor's warm-up inventory counts exactly the live attempt
//!   (observed directly through a warm candidate spawned beside the reload,
//!   and implied by the reload succeeding: the source's registry at transfer
//!   time must be covered by that inventory or authority is refused);
//! - the successor refuses a second attempt for the run while the source
//!   still hosts it, and the run finishes exactly once — one read-model row
//!   advanced to `completed`, one `Started` and one `Terminal` in the spool,
//!   the witness the workload wrote, and nothing in the cancel ledger;
//! - the terminal advance is recorded after the lease moved and before the
//!   source recorded its drain, so the run finished under the successor's
//!   epoch, hosted to completion by the retiring source;
//! - the source retires, and the successor serves as the committed generation;
//! - a `rollback --wait` issued while the successor hosts its own running
//!   attempt hands custody back the same way, and the successor exits.
//!
//! # Gating
//!
//! The execution lane needs a delegated cgroup v2 domain that can distribute
//! the `pids`, `memory` and `cpu` controllers, the Landlock and seccomp
//! mechanisms the capability probe requires, the built entry helper, and a
//! static busybox. Outside such a host the test prints `NOT PROVEN` and
//! returns; `AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1` turns that into a
//! failure. The scope must wrap the test binary rather than `cargo test`:
//!
//! ```sh
//! cd rust
//! cargo build -p automonique-runner --bin automonique-launch-enter
//! cargo test -p automonique --test handoff_live_run --no-run
//! systemd-run --user --scope -p Delegate=yes --quiet \
//!   --setenv=XDG_RUNTIME_DIR=/run/user/$(id -u) \
//!   --setenv=AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1 \
//!   --setenv=AUTOMONIQUE_LAUNCH_HELPER=$PWD/target/debug/automonique-launch-enter \
//!   "$(ls -t target/debug/deps/handoff_live_run-* | grep -v '\.d$' | head -1)" \
//!   --test-threads=1 --nocapture
//! ```
//!
//! # One deliberate harness step
//!
//! The source generation is this test process. Preparing the delegated
//! domain moves it into the domain's `supervisor` leaf, and the candidate it
//! spawns inherits that leaf. cgroup v2 lets a cgroup distribute controllers
//! to its children only while it holds no process of its own, so before the
//! successor can prepare *its* domain for the rollback half, the retired
//! source has to leave the leaf — which in production it does by exiting.
//! Here it moves itself into a sibling leaf instead. Nothing about the daemon
//! is touched by that step; it stands in for a process exit the test cannot
//! perform on itself.

mod handoff_support;

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use automonique_daemon::Daemon;
use automonique_daemon::attempt_adoption::inventory_digest;
use automonique_daemon::candidate::{CandidateSpec, spawn_warm_candidate};
use automonique_daemon::execute::{ENFORCED_PROPERTIES, locate_launch_helper};
use automonique_daemon::release_activation::{CodeReleaseActivator, SystemdUserSupervisor};
use automonique_protocol::execute_api::{ExecuteRefusal, ExecuteResponse};
use automonique_protocol::runs_api::RunState;
use automonique_runner::{Authority, ContainmentDomain, EventKind, Spool};
use automonique_store::cancel_ledger::CancelLedger;
use automonique_store::reload_audit::{ReloadAudit, ReloadPhase};
use automonique_store::run_index::{RunIndex, RunIndexRecord, RunSpoolState};
use handoff_support::{
    BUSYBOX, InstalledReleases, PROMPT, READ_SPOOL_BYTES, Serving, attempt_id_of, cli, execute,
    fixture, install_releases, listed_state, process_exited, read_source_lease, reload_id_for,
    reload_phase, run_spec, spawn_cli, stderr_text, stdout_text, submit, wait_for_reload_phase,
    wait_for_sockets_removed, wait_until, workspace_root,
};

const REQUIRE_ENFORCED_ENV: &str = "AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT";
const RUN_A: &str = "handoff-live-a";
const RUN_B: &str = "handoff-live-b";
/// Long enough that the attempt is still running after the candidate has
/// hashed the binary, read the stores and been handed the lease.
const RELOAD_SLEEP_SECONDS: u64 = 12;
const ROLLBACK_SLEEP_SECONDS: u64 = 8;
/// Bound on one whole handoff, above the sleep it must wait out.
const HANDOFF_TIMEOUT: Duration = Duration::from_secs(50);

fn not_proven(test: &str, reason: &str) {
    assert!(
        std::env::var_os(REQUIRE_ENFORCED_ENV).is_none(),
        "{test}: {REQUIRE_ENFORCED_ENV} is set but this host cannot prove it: {reason}"
    );
    eprintln!("[handoff_live_run] NOT PROVEN: {test}: {reason}");
}

/// The first gate this host fails, in the order the lane consults them.
fn first_failing_gate() -> Option<&'static str> {
    if !std::path::Path::new(BUSYBOX).exists() {
        return Some("no static busybox at /usr/bin/busybox");
    }
    if automonique_daemon::execute::probe_host()
        .select_mode(&ENFORCED_PROPERTIES)
        .is_err()
    {
        return Some("the composed sandbox is not enforceable here");
    }
    if locate_launch_helper().is_none() {
        return Some("no launch helper (set AUTOMONIQUE_LAUNCH_HELPER)");
    }
    if ContainmentDomain::discover().is_err() {
        return Some("no delegated cgroup domain");
    }
    None
}

/// Leave the domain's `supervisor` leaf for a sibling leaf. See the module
/// documentation for why the retired source has to do this here.
fn vacate_supervisor_leaf() {
    let own = fs::read_to_string("/proc/self/cgroup").expect("own cgroup");
    let relative = own
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("unified cgroup entry")
        .trim()
        .trim_start_matches('/');
    let leaf = PathBuf::from("/sys/fs/cgroup").join(relative);
    assert_eq!(
        leaf.file_name().and_then(|name| name.to_str()),
        Some("supervisor"),
        "the source prepared its domain, so this process is in its supervisor leaf"
    );
    let harness = leaf.parent().expect("domain root").join("handoff-harness");
    match fs::create_dir(&harness) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => panic!("harness leaf: {error}"),
    }
    fs::write(harness.join("cgroup.procs"), b"0").expect("move the retired source out");
}

/// When the reload recorded `phase`, from the durable transition history.
fn transition_at(audit: &ReloadAudit, reload_id: &str, phase: ReloadPhase) -> i64 {
    audit
        .history(reload_id, 0, 32)
        .expect("reload history")
        .transitions
        .into_iter()
        .find(|transition| transition.phase == phase)
        .unwrap_or_else(|| panic!("{reload_id} never recorded {phase:?}"))
        .observed_at_ms
}

/// The run finished exactly once, and the evidence agrees from every side.
fn assert_completed_once(
    config: &automonique_daemon::DaemonConfig,
    run: &str,
    witness: &std::path::Path,
) -> RunIndexRecord {
    let rows = RunIndex::open(config.run_index_path())
        .expect("run index")
        .by_run_id(run)
        .expect("index rows");
    assert_eq!(rows.len(), 1, "one submission, one row: {rows:?}");
    let row = rows.into_iter().next().expect("one row");
    assert_eq!(row.spool_state, RunSpoolState::Completed);
    assert_eq!(
        row.revision, 3,
        "registered, then running, then completed: one advance per state"
    );
    let spool = Spool::open(
        config.state_dir().join("runs").join(run).join("spool"),
        run,
        READ_SPOOL_BYTES,
    )
    .expect("the run's spool re-opens");
    let events = spool.events_after(0).expect("the spool replays");
    assert_eq!(events.len(), 2, "one Started and one Terminal: {events:?}");
    assert_eq!(events[0].kind(), EventKind::Started);
    assert_eq!(events[1].kind(), EventKind::Terminal);
    assert_eq!(events[1].authority(), Authority::Authoritative);
    assert_eq!(events[1].payload(), b"completed");
    assert_eq!(
        fs::read(witness).expect("the workload wrote its witness"),
        PROMPT,
        "the workload ran to completion with the admitted prompt"
    );
    let ledger = CancelLedger::open(config.run_cancel_ledger_path()).expect("cancel ledger");
    assert!(
        ledger
            .attempt_requests(&attempt_id_of(run))
            .expect("ledger read")
            .is_empty(),
        "nothing cancelled {run}, ambiguously or otherwise"
    );
    row
}

#[test]
fn a_live_contained_attempt_survives_reload_and_rollback() {
    let test = "a_live_contained_attempt_survives_reload_and_rollback";
    if let Some(reason) = first_failing_gate() {
        not_proven(test, reason);
        return;
    }

    let (_root, config) = fixture();
    let InstalledReleases {
        root: release_root,
        previous: previous_digest,
        next: next_digest,
        ..
    } = install_releases(&config);
    let source = Serving::start(Daemon::open(&config).expect("source daemon"), &config);

    // A CONTAINED ATTEMPT IS RUNNING WHEN THE RELOAD IS ISSUED.
    let witness_a = workspace_root(&config, RUN_A).join("witness.txt");
    let script_a = format!(
        "{BUSYBOX} sleep {RELOAD_SLEEP_SECONDS} && {BUSYBOX} cat > {}",
        witness_a.display()
    );
    submit(&config, &run_spec(RUN_A, &script_a), "handoff-submit-a");
    let started = execute(&config, "execute-a", RUN_A);
    assert!(
        matches!(started, ExecuteResponse::Accepted { .. }),
        "the source starts the attempt: {started:?}"
    );

    // THE SUCCESSOR'S INVENTORY PROOF COUNTS EXACTLY THAT ATTEMPT.
    //
    // Observed directly: a warm candidate of the target release, spawned the
    // way the reload spawns one, reports what it found through the source's
    // pinned route. It is stopped again without ever holding anything.
    let source_lease = read_source_lease(&config.database_path());
    let activator =
        CodeReleaseActivator::new(&release_root, "automonique.service", SystemdUserSupervisor)
            .expect("activator");
    let release = activator
        .verify(&format!("sha256:{next_digest}"))
        .expect("verified release");
    let mut probe = spawn_warm_candidate(
        &config,
        &release,
        &CandidateSpec {
            reload_id: "handoff-live-probe".to_owned(),
            source_holder_id: source_lease.holder_id.clone(),
            source_lease_epoch: source_lease.epoch,
            target_generation_id: "foreground-probe".to_owned(),
            warm_timeout: Duration::from_secs(20),
        },
    )
    .expect("warm probe candidate");
    let proof = probe.attempt_inventory_proof();
    assert_eq!(proof.count, 1, "exactly the live attempt");
    assert_eq!(
        proof.sha256,
        inventory_digest(&[attempt_id_of(RUN_A)]),
        "and exactly its identity"
    );
    probe.stop().expect("probe candidate stops");
    drop(probe);

    // THE AUTHENTICATED RELOAD, WAITED ON, WHILE THE ATTEMPT RUNS.
    let reload_id = reload_id_for("reload", source_lease.epoch, &next_digest);
    let reload = spawn_cli(
        &config,
        &["reload", &format!("sha256:{next_digest}"), "--wait"],
    );
    let reached = wait_for_reload_phase(
        &config,
        &reload_id,
        &["active_proven", "draining"],
        HANDOFF_TIMEOUT,
    );
    // The successor is active and answering on the inherited socket; the
    // source is draining the attempt it still hosts. A second attempt for
    // that run is refused as already executing — not started, and not
    // mistaken for a run that is ready because its row has not moved yet.
    let repeat = execute(&config, "execute-a-again", RUN_A);
    assert!(
        matches!(
            repeat,
            ExecuteResponse::Refused {
                refusal: ExecuteRefusal::AlreadyExecuting,
                ..
            }
        ),
        "during {reached}, the successor refuses a second attempt: {repeat:?}"
    );
    assert_eq!(
        listed_state(&config, "during-drain", RUN_A),
        RunState::Ready,
        "the read model moves only when the source's worker ends the attempt"
    );

    let reload = reload.wait_with_output().expect("reload command");
    assert!(
        reload.status.success(),
        "reload --wait failed: {}",
        stderr_text(&reload)
    );
    assert_eq!(
        stdout_text(&reload),
        format!("reload {reload_id} succeeded\n")
    );
    source
        .join()
        .expect("the source retires without releasing transferred authority");

    // THE RUN FINISHED EXACTLY ONCE, UNDER THE SUCCESSOR'S EPOCH.
    let row_a = assert_completed_once(&config, RUN_A, &witness_a);
    let audit = ReloadAudit::open(config.reload_audit_path()).expect("reload audit");
    let transferred_at = transition_at(&audit, &reload_id, ReloadPhase::Transferred);
    let draining_at = transition_at(&audit, &reload_id, ReloadPhase::Draining);
    assert!(
        transferred_at <= row_a.updated_at_ms && row_a.updated_at_ms <= draining_at,
        "the terminal advance ({}) falls after the lease moved ({transferred_at}) and \
         before the source recorded its drain ({draining_at})",
        row_a.updated_at_ms
    );
    assert_eq!(
        reload_phase(&config, &reload_id).as_deref(),
        Some("succeeded")
    );
    let successor = read_source_lease(&config.database_path());
    assert_eq!(successor.epoch, source_lease.epoch + 1);
    assert_ne!(successor.holder_id, source_lease.holder_id);
    assert!(successor.holder_id.contains("-reload-"));
    assert_eq!(
        fs::read_link(release_root.join("current")).expect("selected release link"),
        std::path::Path::new("releases").join(&next_digest)
    );
    let status = cli(&config, &["status", "--json"]);
    assert!(status.status.success(), "the successor serves status");
    assert!(stdout_text(&status).contains(&successor.holder_id));

    // ROLLBACK WITH A STILL-RUNNING ATTEMPT HANDS CUSTODY BACK THE SAME WAY.
    vacate_supervisor_leaf();
    let witness_b = workspace_root(&config, RUN_B).join("witness.txt");
    let script_b = format!(
        "{BUSYBOX} sleep {ROLLBACK_SLEEP_SECONDS} && {BUSYBOX} cat > {}",
        witness_b.display()
    );
    submit(&config, &run_spec(RUN_B, &script_b), "handoff-submit-b");
    let started = execute(&config, "execute-b", RUN_B);
    assert!(
        matches!(started, ExecuteResponse::Accepted { .. }),
        "the successor starts its own contained attempt: {started:?}"
    );
    let rollback_id = reload_id_for("rollback", successor.epoch, &previous_digest);
    let rollback = spawn_cli(&config, &["rollback", "--wait"]);
    let reached = wait_for_reload_phase(
        &config,
        &rollback_id,
        &["active_proven", "draining"],
        HANDOFF_TIMEOUT,
    );
    let repeat = execute(&config, "execute-b-again", RUN_B);
    assert!(
        matches!(
            repeat,
            ExecuteResponse::Refused {
                refusal: ExecuteRefusal::AlreadyExecuting,
                ..
            }
        ),
        "during {reached}, the rollback target refuses a second attempt: {repeat:?}"
    );
    let rollback = rollback.wait_with_output().expect("rollback command");
    assert!(
        rollback.status.success(),
        "rollback --wait failed: {}",
        stderr_text(&rollback)
    );
    assert_eq!(
        stdout_text(&rollback),
        format!("rollback {rollback_id} succeeded\n")
    );

    let row_b = assert_completed_once(&config, RUN_B, &witness_b);
    let transferred_at = transition_at(&audit, &rollback_id, ReloadPhase::Transferred);
    let draining_at = transition_at(&audit, &rollback_id, ReloadPhase::Draining);
    assert!(
        transferred_at <= row_b.updated_at_ms && row_b.updated_at_ms <= draining_at,
        "the rollback target held the lease while the successor finished its attempt"
    );
    let rolled_back = read_source_lease(&config.database_path());
    assert_eq!(rolled_back.epoch, source_lease.epoch + 2);
    assert_ne!(rolled_back.holder_id, successor.holder_id);
    assert_eq!(
        fs::read_link(release_root.join("current")).expect("rolled back release link"),
        std::path::Path::new("releases").join(&previous_digest)
    );
    wait_until(
        "the retired successor to exit",
        Duration::from_secs(10),
        || process_exited(successor.pid),
    );
    let status = cli(&config, &["status", "--json"]);
    assert!(status.status.success(), "the rollback target serves status");
    assert!(stdout_text(&status).contains(&rolled_back.holder_id));

    let shutdown = cli(&config, &["shutdown"]);
    assert!(shutdown.status.success());
    wait_for_sockets_removed(&config);
    eprintln!(
        "[handoff_live_run] PROVEN: {test}: {reload_id} carried {RUN_A} across epochs {}->{} \
         (terminal advance at {} between transferred {transferred_at} and draining {draining_at}); \
         {rollback_id} carried {RUN_B} across epochs {}->{}",
        source_lease.epoch,
        successor.epoch,
        row_b.updated_at_ms,
        successor.epoch,
        rolled_back.epoch,
    );
}
