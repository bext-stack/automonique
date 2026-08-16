// SPDX-License-Identifier: Elastic-2.0

//! Exercised proof that the direct-process backend supervises a real workload
//! and durably records exactly what happened to it.
//!
//! Every proof here drives a real sandboxed busybox workload through the public
//! backend API and then re-opens the spool file from disk, so what is asserted
//! is the durable record — `Spool::open` re-verifies the hash chain — and not
//! merely the supervisor's in-memory belief.
//!
//! Like the containment and launch proofs, this needs a delegated cgroup v2
//! domain. Outside one, each test asserts the exact fail-closed refusal, and
//! `AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1` turns that degradation into a
//! failure so a verifying host cannot quietly skip the proof:
//!
//! ```sh
//! systemd-run --user --scope -p Delegate=yes \
//!   --setenv=AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1 \
//!   cargo test --manifest-path rust/Cargo.toml -p automonique-runner \
//!   --test backend -- --test-threads=1
//! ```

use automonique_runner::backend::{
    BackendError, DirectProcessBackend, ExecutionOutcome, STARTED_PAYLOAD_PREFIX,
    TERMINAL_CANCELLED, TERMINAL_COMPLETED, TERMINAL_FAILED, TERMINAL_TIMED_OUT,
};
use automonique_runner::filesystem::PathIntent;
use automonique_runner::{
    Authority, CancellationToken, ContainmentDomain, ContainmentError, ContainmentLimits, Event,
    EventKind, LaunchPlan, RunState, Spool, process_is_live,
};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const HELPER: &str = env!("CARGO_BIN_EXE_automonique-launch-enter");
const BUSYBOX: &str = "/usr/bin/busybox";
const REQUIRE_ENFORCED_ENV: &str = "AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT";
const MAX_SPOOL_BYTES: u64 = 1024 * 1024;
/// Generous bound on any supervised run here: every proof must finish far
/// inside it, so a workload that outlives its supervisor fails the test rather
/// than hanging it.
const BOUNDED_RUN: Duration = Duration::from_secs(30);

fn busybox_sha256() -> String {
    format!("{:x}", Sha256::digest(fs::read(BUSYBOX).unwrap()))
}

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "automonique-backend-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn spool_root(&self) -> PathBuf {
        self.0.join("spool")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_id(label: &str) -> String {
    let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    format!("b{}-{label}-{serial}", std::process::id())
}

/// The delegated domain, or a loud, contract-checked degradation.
fn enforcement_domain(proof: &str) -> Option<ContainmentDomain> {
    match ContainmentDomain::discover() {
        Ok(found) => {
            eprintln!(
                "[backend] ENFORCED  {proof}: domain {}",
                found.root().display()
            );
            Some(found)
        }
        Err(error) => {
            eprintln!("[backend] NOT PROVEN {proof}: {error}");
            assert!(
                matches!(
                    error,
                    ContainmentError::DomainNotDelegated
                        | ContainmentError::NotUnifiedCgroupV2
                        | ContainmentError::MissingAtomicKill
                ),
                "undelegated environments must refuse with a typed reason, got {error:?}"
            );
            assert!(
                std::env::var_os(REQUIRE_ENFORCED_ENV).is_none(),
                "{REQUIRE_ENFORCED_ENV} is set, so {proof} must run against a \
                 delegated cgroup v2 domain, but none was available: {error}"
            );
            None
        }
    }
}

fn backend() -> DirectProcessBackend {
    DirectProcessBackend::new(HELPER).expect("the test helper path is absolute")
}

fn fresh_spool(temporary: &TempDir, id: &str) -> Spool {
    Spool::open(temporary.spool_root(), id, MAX_SPOOL_BYTES).expect("a fresh spool opens")
}

/// A plan running `script` under busybox sh with the standard test grants.
///
/// Busybox is statically linked, so a single read-execute file grant makes it
/// runnable without granting any loader or library directory.
fn busybox_plan(script: &str, extra: impl FnOnce(LaunchPlan) -> LaunchPlan) -> LaunchPlan {
    let plan = LaunchPlan::new(BUSYBOX, busybox_sha256())
        .unwrap()
        .argument("sh")
        .unwrap()
        .argument("-c")
        .unwrap()
        .argument(script)
        .unwrap()
        .filesystem_grant(PathIntent::ReadExecute, BUSYBOX)
        .unwrap();
    extra(plan)
}

/// A workload that reports a `setsid` descendant's pid and then lingers.
///
/// `setsid` is the classic escape from a process group, so a supervisor that
/// only killed its direct child would leave this descendant alive. Absolute
/// busybox paths keep every spawned program inside the read-execute grant.
fn lingering_plan(temporary: &TempDir, pid_file: &Path) -> LaunchPlan {
    let script = format!(
        "{bb} setsid {bb} sh -c 'echo $$ > {pid}; exec {bb} sleep 300' & exec {bb} sleep 300",
        bb = BUSYBOX,
        pid = pid_file.display()
    );
    busybox_plan(&script, |plan| {
        plan.filesystem_grant(PathIntent::ReadWrite, temporary.path())
            .unwrap()
            // The shell reopens a background job's stdin from /dev/null, and a
            // Landlock policy contains exactly what it names — so the plan must
            // say so, or the background subtree never starts.
            .filesystem_grant(PathIntent::Read, "/dev/null")
            .unwrap()
    })
}

/// Re-open the spool from disk, re-verifying its hash chain, and replay it.
fn replay(temporary: &TempDir, id: &str) -> Vec<Event> {
    let spool = Spool::open(temporary.spool_root(), id, MAX_SPOOL_BYTES)
        .expect("the recorded spool re-opens and its chain verifies");
    spool.events_after(0).expect("the whole run replays")
}

/// Assert the exact two-event lifecycle every supervised workload records.
fn assert_lifecycle(events: &[Event], id: &str, pid: nix::unistd::Pid, terminal: &[u8]) {
    assert_eq!(
        events.len(),
        2,
        "one attempt records exactly Started then Terminal, saw {events:?}"
    );
    let started = &events[0];
    let ended = &events[1];
    assert_eq!(started.kind(), EventKind::Started);
    assert_eq!(started.authority(), Authority::Authoritative);
    assert_eq!(started.run_id(), id);
    assert_eq!(started.sequence(), 1);
    assert_eq!(
        started.payload(),
        format!("{STARTED_PAYLOAD_PREFIX}{}", pid.as_raw()).as_bytes(),
        "the Started payload names the pid the supervisor actually spawned"
    );
    assert_eq!(ended.kind(), EventKind::Terminal);
    assert_eq!(ended.authority(), Authority::Authoritative);
    assert_eq!(ended.run_id(), id);
    assert_eq!(ended.sequence(), 2, "sequences are contiguous");
    assert_eq!(ended.payload(), terminal);
    assert!(
        started.at_millis() <= ended.at_millis(),
        "Started must not be recorded after Terminal"
    );
}

/// The descendant pid the lingering workload reported.
fn reported_descendant(pid_file: &Path) -> nix::unistd::Pid {
    let raw: i32 = fs::read_to_string(pid_file)
        .unwrap_or_else(|error| {
            panic!(
                "the workload never reported its descendant pid at {}: {error}",
                pid_file.display()
            )
        })
        .trim()
        .parse()
        .expect("pid parses");
    nix::unistd::Pid::from_raw(raw)
}

#[test]
fn a_completed_workload_records_started_then_completed() {
    let Some(domain) = enforcement_domain("a_completed_workload_records_started_then_completed")
    else {
        return;
    };
    let temporary = TempDir::new("completed");
    let id = run_id("completed");
    let prepared = backend()
        .prepare(
            &domain,
            &id,
            ContainmentLimits::none(),
            busybox_plan("exit 0", |plan| plan),
            fresh_spool(&temporary, &id),
        )
        .expect("preparation creates the run cgroup");
    let cgroup = prepared.containment_path().to_path_buf();
    assert!(cgroup.is_dir(), "the run cgroup exists before execution");

    let report = prepared
        .execute(&CancellationToken::new(), BOUNDED_RUN)
        .expect("a clean run reports no supervisor failure");

    assert_eq!(report.outcome(), ExecutionOutcome::Completed);
    assert!(report.outcome().is_success());
    assert_eq!(report.status().state(), RunState::Completed);
    assert_eq!(report.status().last_sequence(), 2);
    assert_eq!(report.status().run_id(), id);
    assert!(
        !cgroup.exists(),
        "disposal must leave no kernel residue at {}",
        cgroup.display()
    );

    let pid = report.supervised_pid().expect("a workload process existed");
    assert_lifecycle(&replay(&temporary, &id), &id, pid, TERMINAL_COMPLETED);
}

#[test]
fn a_failing_workload_is_recorded_as_failed_with_its_code() {
    let Some(domain) = enforcement_domain("a_failing_workload_is_recorded_as_failed_with_its_code")
    else {
        return;
    };
    let temporary = TempDir::new("failing");
    let id = run_id("failing");
    let prepared = backend()
        .prepare(
            &domain,
            &id,
            ContainmentLimits::none(),
            busybox_plan("exit 7", |plan| plan),
            fresh_spool(&temporary, &id),
        )
        .expect("preparation creates the run cgroup");
    let cgroup = prepared.containment_path().to_path_buf();

    let report = prepared
        .execute(&CancellationToken::new(), BOUNDED_RUN)
        .expect("a workload that fails is not a supervisor failure");

    assert_eq!(report.outcome(), ExecutionOutcome::Failed { exit_code: 7 });
    assert!(!report.outcome().is_success());
    assert_eq!(report.status().state(), RunState::Failed);
    assert!(!cgroup.exists());

    let pid = report.supervised_pid().expect("a workload process existed");
    let events = replay(&temporary, &id);
    assert_lifecycle(&events, &id, pid, TERMINAL_FAILED);
    assert_ne!(
        events[1].payload(),
        TERMINAL_COMPLETED,
        "a failing workload must never be recorded as completed"
    );
}

#[test]
fn cancellation_kills_the_tree_and_records_cancelled() {
    let Some(domain) = enforcement_domain("cancellation_kills_the_tree_and_records_cancelled")
    else {
        return;
    };
    let temporary = TempDir::new("cancel");
    let id = run_id("cancel");
    let pid_file = temporary.path().join("descendant.pid");
    let prepared = backend()
        .prepare(
            &domain,
            &id,
            ContainmentLimits::none(),
            lingering_plan(&temporary, &pid_file),
            fresh_spool(&temporary, &id),
        )
        .expect("preparation creates the run cgroup");
    let cgroup = prepared.containment_path().to_path_buf();

    // Cancellation arrives from another thread, mid-run, once the workload has
    // proven it is really running by reporting its escaped descendant.
    let token = CancellationToken::new();
    let canceller = {
        let token = token.clone();
        let pid_file = pid_file.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            while !pid_file.is_file() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            token.cancel();
        })
    };

    let started = Instant::now();
    let report = prepared
        .execute(&token, Duration::from_secs(120))
        .expect("cancellation is an outcome, not a supervisor failure");
    let elapsed = started.elapsed();
    canceller.join().expect("the cancelling thread finishes");

    assert!(
        elapsed < BOUNDED_RUN,
        "cancellation must be bounded; the 300s workload held the supervisor for {elapsed:?}"
    );
    assert_eq!(report.outcome(), ExecutionOutcome::Cancelled);
    assert_eq!(report.status().state(), RunState::Cancelled);

    let escaped = reported_descendant(&pid_file);
    assert!(
        !process_is_live(escaped),
        "a setsid descendant must die with the cancelled run"
    );
    let pid = report.supervised_pid().expect("a workload process existed");
    assert!(!process_is_live(pid), "the supervised process must be dead");
    assert!(!cgroup.exists(), "disposal must leave no kernel residue");

    assert_lifecycle(&replay(&temporary, &id), &id, pid, TERMINAL_CANCELLED);
}

#[test]
fn an_exceeded_deadline_kills_the_tree_and_records_timed_out() {
    let Some(domain) =
        enforcement_domain("an_exceeded_deadline_kills_the_tree_and_records_timed_out")
    else {
        return;
    };
    let temporary = TempDir::new("deadline");
    let id = run_id("deadline");
    let pid_file = temporary.path().join("descendant.pid");
    let prepared = backend()
        .prepare(
            &domain,
            &id,
            ContainmentLimits::none(),
            lingering_plan(&temporary, &pid_file),
            fresh_spool(&temporary, &id),
        )
        .expect("preparation creates the run cgroup");
    let cgroup = prepared.containment_path().to_path_buf();

    // The token is never set: the deadline alone must stop a 300s workload.
    let started = Instant::now();
    let report = prepared
        .execute(&CancellationToken::new(), Duration::from_secs(3))
        .expect("a deadline is an outcome, not a supervisor failure");
    let elapsed = started.elapsed();

    assert!(
        elapsed < BOUNDED_RUN,
        "the deadline must be enforced, not merely noticed; took {elapsed:?}"
    );
    assert_eq!(report.outcome(), ExecutionOutcome::TimedOut);
    assert_eq!(report.status().state(), RunState::TimedOut);

    let escaped = reported_descendant(&pid_file);
    assert!(
        !process_is_live(escaped),
        "a setsid descendant must die with the timed-out run"
    );
    let pid = report.supervised_pid().expect("a workload process existed");
    assert!(!process_is_live(pid), "the supervised process must be dead");
    assert!(!cgroup.exists(), "disposal must leave no kernel residue");

    assert_lifecycle(&replay(&temporary, &id), &id, pid, TERMINAL_TIMED_OUT);
}

#[test]
fn a_sandbox_refusal_is_not_a_workload_failure() {
    let Some(domain) = enforcement_domain("a_sandbox_refusal_is_not_a_workload_failure") else {
        return;
    };
    let temporary = TempDir::new("refused");
    let id = run_id("refused");
    let witness = temporary.path().join("executed");

    // The plan grants write access to the witness directory but never grants
    // execute on the program itself, so the helper's own Landlock domain denies
    // the final execve: a refusal after enforcement, before any workload byte.
    let plan = LaunchPlan::new(BUSYBOX, busybox_sha256())
        .unwrap()
        .argument("sh")
        .unwrap()
        .argument("-c")
        .unwrap()
        .argument(format!("echo ran > {}", witness.display()))
        .unwrap()
        .filesystem_grant(PathIntent::ReadWrite, temporary.path())
        .unwrap();

    let prepared = backend()
        .prepare(
            &domain,
            &id,
            ContainmentLimits::none(),
            plan,
            fresh_spool(&temporary, &id),
        )
        .expect("preparation creates the run cgroup");
    let cgroup = prepared.containment_path().to_path_buf();

    let report = prepared
        .execute(&CancellationToken::new(), BOUNDED_RUN)
        .expect("a refused launch is an outcome, not a supervisor failure");

    assert_eq!(
        report.outcome(),
        ExecutionOutcome::LaunchRefused,
        "the reserved helper exit code means the sandbox refused, not that the \
         workload failed"
    );
    assert!(!report.outcome().is_success());
    assert!(
        !witness.exists(),
        "no workload instruction may run behind a refused launch"
    );
    assert_eq!(
        report.status().state(),
        RunState::Failed,
        "a refusal is recorded as a failure, never as a completion"
    );
    assert!(!cgroup.exists());

    let pid = report.supervised_pid().expect("the helper process existed");
    let events = replay(&temporary, &id);
    assert_lifecycle(&events, &id, pid, TERMINAL_FAILED);
    assert_ne!(events[1].payload(), TERMINAL_COMPLETED);
}

#[test]
fn a_finished_run_cannot_be_attempted_again() {
    let Some(domain) = enforcement_domain("a_finished_run_cannot_be_attempted_again") else {
        return;
    };
    let temporary = TempDir::new("reuse");
    let id = run_id("reuse");
    let report = backend()
        .prepare(
            &domain,
            &id,
            ContainmentLimits::none(),
            busybox_plan("exit 0", |plan| plan),
            fresh_spool(&temporary, &id),
        )
        .expect("preparation creates the run cgroup")
        .execute(&CancellationToken::new(), BOUNDED_RUN)
        .expect("a clean run");
    assert_eq!(report.outcome(), ExecutionOutcome::Completed);

    // The spool from a finished attempt is terminal on disk, so a second
    // attempt against it is refused before any cgroup is created.
    let used = Spool::open(temporary.spool_root(), &id, MAX_SPOOL_BYTES).expect("re-opens");
    assert!(used.is_terminal());
    let refusal = backend()
        .prepare(
            &domain,
            &id,
            ContainmentLimits::none(),
            busybox_plan("exit 0", |plan| plan),
            used,
        )
        .expect_err("a used spool is refused");
    assert!(
        matches!(refusal, BackendError::SpoolNotFresh),
        "expected SpoolNotFresh, got {refusal}"
    );
    assert!(
        !domain.root().join(format!("run-{id}")).exists(),
        "a refused preparation must create no cgroup"
    );
    assert_eq!(
        replay(&temporary, &id).len(),
        2,
        "a refused preparation must append nothing to the durable record"
    );
}

#[test]
fn a_spool_for_another_run_is_refused() {
    let Some(domain) = enforcement_domain("a_spool_for_another_run_is_refused") else {
        return;
    };
    let temporary = TempDir::new("mismatch");
    let recorded = run_id("recorded");
    let requested = run_id("requested");
    let refusal = backend()
        .prepare(
            &domain,
            &requested,
            ContainmentLimits::none(),
            busybox_plan("exit 0", |plan| plan),
            fresh_spool(&temporary, &recorded),
        )
        .expect_err("a spool belonging to another run is refused");
    assert!(
        matches!(refusal, BackendError::SpoolRunIdMismatch),
        "expected SpoolRunIdMismatch, got {refusal}"
    );
    assert!(
        !domain.root().join(format!("run-{requested}")).exists(),
        "a refused preparation must create no cgroup"
    );
}

#[test]
fn a_relative_helper_path_is_refused() {
    // No delegated domain needed: a backend that would search `PATH` for its
    // trusted entry helper must not be constructible anywhere.
    let refusal = DirectProcessBackend::new("automonique-launch-enter")
        .expect_err("a relative helper path is refused");
    assert!(
        matches!(refusal, BackendError::HelperRejected),
        "expected HelperRejected, got {refusal}"
    );
    assert_eq!(
        backend().helper(),
        Path::new(HELPER),
        "an absolute helper path is kept exactly"
    );
}
