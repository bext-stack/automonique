// SPDX-License-Identifier: Elastic-2.0

//! Exercised proof that cgroup v2 containment is descendant-complete.
//!
//! These tests do not assert that kernel interfaces are visible. They launch
//! real processes, have one of them escape its process group with `setsid`, and
//! then require that the atomic cgroup kill still reaps it. That is the exact
//! property `ContainmentEvidence::ProcessGroupOnly` cannot provide.
//!
//! Placing a process in a cgroup requires a delegated domain. cgroup v2
//! delegation containment permits migration only within the subtree the caller
//! owns, so an interactive SSH session scope — which systemd owns — cannot run
//! the enforcement proofs. Where the domain is unavailable, each test instead
//! asserts the exact fail-closed refusal, so nothing is silently skipped.
//!
//! To run the enforcement proofs, use a delegated scope:
//!
//! ```sh
//! systemd-run --user --scope -p Delegate=yes \
//!   cargo test --manifest-path rust/Cargo.toml -p automonique-runner --test containment
//! ```

use automonique_runner::{
    BoundaryRequirement, CGROUP_DIR_ENV, CPU_MAX_PERIOD_MICROS, ContainmentDomain,
    ContainmentError, ContainmentEvidence, ContainmentLimits, Controller, RunContainment, Runner,
    process_is_live,
};
use nix::unistd::Pid;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const HELPER: &str = env!("CARGO_BIN_EXE_automonique-cgroup-enter");
const DRAIN_DEADLINE: Duration = Duration::from_secs(10);
/// Set this on any host that is expected to prove enforcement, so that a
/// missing delegated domain fails the run instead of quietly weakening it.
const REQUIRE_ENFORCED_ENV: &str = "AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "automonique-containment-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A run identifier unique to one test, kept inside the safe cgroup alphabet.
fn run_id(label: &str) -> String {
    let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    format!("t{}-{label}-{serial}", std::process::id())
}

/// The delegated domain, or the exact refusal explaining its absence.
fn domain() -> Result<ContainmentDomain, ContainmentError> {
    ContainmentDomain::discover()
}

/// Resolve the domain for an enforcement proof, reporting which path ran.
///
/// The report is deliberately loud. A proof that quietly degrades into a
/// refusal check would let an unenforced boundary look tested.
fn enforcement_domain(proof: &str) -> Option<ContainmentDomain> {
    match domain() {
        Ok(found) => {
            eprintln!(
                "[containment] ENFORCED  {proof}: domain {}",
                found.root().display()
            );
            Some(found)
        }
        Err(error) => {
            eprintln!("[containment] NOT PROVEN {proof}: {error}");
            assert_refuses_closed(&error);
            // A host that claims to verify enforcement must actually verify it.
            // Without this, a CI runner without cgroup delegation would report
            // the whole suite green while proving nothing about the boundary.
            assert!(
                std::env::var_os(REQUIRE_ENFORCED_ENV).is_none(),
                "{REQUIRE_ENFORCED_ENV} is set, so {proof} must run against a \
                 delegated cgroup v2 domain, but none was available: {error}"
            );
            None
        }
    }
}

/// Assert the fail-closed contract when no domain can be used.
///
/// This is a real assertion, not a skip: an environment that cannot delegate
/// must refuse with a typed reason and must never report usable containment.
fn assert_refuses_closed(error: &ContainmentError) {
    assert!(
        matches!(
            error,
            ContainmentError::DomainNotDelegated
                | ContainmentError::NotUnifiedCgroupV2
                | ContainmentError::MissingAtomicKill
        ),
        "undelegated environments must refuse with a typed containment reason, got {error:?}"
    );
}

/// Launch `script` under `sh` inside `containment` through the entry helper.
fn launch_in(containment: &RunContainment, script: &str) -> Child {
    Command::new(HELPER)
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(script)
        .env(CGROUP_DIR_ENV, containment.path())
        .spawn()
        .expect("entry helper spawns")
}

/// Wait, bounded, for a condition the workload signals through the filesystem.
fn wait_for(deadline: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    condition()
}

fn read_pid(path: &Path) -> Option<Pid> {
    let raw = fs::read_to_string(path).ok()?;
    raw.trim().parse::<i32>().ok().map(Pid::from_raw)
}

fn cpu_stat(path: &Path, field: &str) -> Option<u64> {
    fs::read_to_string(path.join("cpu.stat"))
        .ok()?
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(' ')?;
            (name == field).then(|| value.parse::<u64>().ok()).flatten()
        })
}

/// Reap the direct child without trusting containment to have killed it.
///
/// A plain `wait` would block for the workload's whole lifetime if containment
/// ever regressed, turning a failed proof into a hung suite. This bounds the
/// wait and then terminates the child directly, so a regression fails fast and
/// still leaves no process behind.
fn reap_bounded(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => return,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn a_setsid_grandchild_cannot_escape_the_atomic_cgroup_kill() {
    let Some(domain) =
        enforcement_domain("a_setsid_grandchild_cannot_escape_the_atomic_cgroup_kill")
    else {
        return;
    };
    let temporary = TempDir::new("escape");
    let containment =
        RunContainment::create(&domain, &run_id("escape"), ContainmentLimits::none()).unwrap();

    // The grandchild leaves the process group and session, which defeats
    // `killpg`, and then re-parents away from the direct child.
    let child_pid_file = temporary.path().join("child.pid");
    let grandchild_pid_file = temporary.path().join("grandchild.pid");
    let script = format!(
        "setsid /bin/sh -c 'echo $$ > {grandchild}; exec sleep 60' & \
         echo $$ > {child}; \
         exec sleep 60",
        grandchild = grandchild_pid_file.display(),
        child = child_pid_file.display()
    );
    let mut child = launch_in(&containment, &script);

    assert!(
        wait_for(Duration::from_secs(10), || child_pid_file.is_file()
            && grandchild_pid_file.is_file()),
        "workload did not report both process identities"
    );
    let child_pid = read_pid(&child_pid_file).expect("child pid");
    let grandchild_pid = read_pid(&grandchild_pid_file).expect("grandchild pid");

    assert!(process_is_live(child_pid), "child must be running");
    assert!(
        process_is_live(grandchild_pid),
        "grandchild must be running"
    );

    // The escaped grandchild is nonetheless a kernel member of the boundary.
    let members = containment.member_pids().unwrap();
    assert!(
        members.contains(&grandchild_pid),
        "a setsid grandchild remains a cgroup member; members were {members:?}"
    );

    // The distinguishing property: process-group termination is not enough.
    assert_ne!(
        nix::unistd::getpgid(Some(grandchild_pid)).unwrap(),
        nix::unistd::getpgid(Some(child_pid)).unwrap(),
        "the grandchild must have left the child's process group"
    );

    containment.kill_and_drain(DRAIN_DEADLINE).unwrap();
    reap_bounded(&mut child);

    assert!(
        !process_is_live(grandchild_pid),
        "the escaped grandchild must be killed by the atomic cgroup kill"
    );
    assert!(
        containment.is_empty().unwrap(),
        "the boundary must hold no process after draining"
    );
    containment.dispose(DRAIN_DEADLINE).unwrap();
}

#[test]
fn disposal_removes_the_cgroup_and_leaves_no_kernel_residue() {
    let Some(domain) =
        enforcement_domain("disposal_removes_the_cgroup_and_leaves_no_kernel_residue")
    else {
        return;
    };
    let containment =
        RunContainment::create(&domain, &run_id("residue"), ContainmentLimits::none()).unwrap();
    let path = containment.path().to_path_buf();
    assert!(path.is_dir(), "the run cgroup exists while the run is live");

    let mut child = launch_in(&containment, "exec sleep 60");
    assert!(
        wait_for(Duration::from_secs(10), || !containment
            .is_empty()
            .unwrap_or(false)),
        "workload never entered the boundary"
    );

    containment.dispose(DRAIN_DEADLINE).unwrap();
    reap_bounded(&mut child);
    assert!(!path.exists(), "disposal must remove the cgroup directory");
}

#[test]
fn dropping_the_containment_kills_a_live_tree() {
    let Some(domain) = enforcement_domain("dropping_the_containment_kills_a_live_tree") else {
        return;
    };
    let temporary = TempDir::new("drop");
    let pid_file = temporary.path().join("workload.pid");
    let path;
    let workload_pid;
    let mut child;
    {
        let containment =
            RunContainment::create(&domain, &run_id("drop"), ContainmentLimits::none()).unwrap();
        path = containment.path().to_path_buf();
        child = launch_in(
            &containment,
            &format!("echo $$ > {}; exec sleep 60", pid_file.display()),
        );
        assert!(
            wait_for(Duration::from_secs(10), || pid_file.is_file()),
            "workload did not start"
        );
        workload_pid = read_pid(&pid_file).expect("workload pid");
        assert!(process_is_live(workload_pid));
    }
    reap_bounded(&mut child);

    assert!(
        !process_is_live(workload_pid),
        "dropping the containment must not leak a live process tree"
    );
    assert!(!path.exists(), "drop must remove the cgroup directory");
}

#[test]
fn the_entry_helper_refuses_to_execute_outside_a_boundary() {
    // No target cgroup is named, so the helper must not execute the workload.
    let marker = TempDir::new("no-exec");
    let witness = marker.path().join("executed");
    let status = Command::new(HELPER)
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(format!("echo ran > {}", witness.display()))
        .env_remove(CGROUP_DIR_ENV)
        .status()
        .expect("helper runs");

    assert!(
        !status.success(),
        "the helper must refuse without a boundary"
    );
    assert!(
        !witness.exists(),
        "no workload may execute when placement is unconfirmed"
    );
}

#[test]
fn the_entry_helper_refuses_a_cgroup_it_cannot_join() {
    let marker = TempDir::new("bad-target");
    let witness = marker.path().join("executed");
    // A plain directory is not a cgroup, so self-migration cannot be confirmed.
    let status = Command::new(HELPER)
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(format!("echo ran > {}", witness.display()))
        .env(CGROUP_DIR_ENV, marker.path())
        .status()
        .expect("helper runs");

    assert!(
        !status.success(),
        "the helper must refuse an unusable target"
    );
    assert!(
        !witness.exists(),
        "no workload may execute when placement is unconfirmed"
    );
}

#[test]
fn run_identifiers_outside_the_safe_alphabet_are_refused() {
    let Some(domain) = enforcement_domain("run_identifiers_outside_the_safe_alphabet_are_refused")
    else {
        return;
    };
    for rejected in ["", "../escape", "has space", "has/slash", "dot.dot"] {
        let error = RunContainment::create(&domain, rejected, ContainmentLimits::none())
            .expect_err("unsafe run identifier must be refused");
        assert!(
            matches!(error, ContainmentError::RunIdRejected),
            "{rejected:?} must be refused as an unsafe name, got {error:?}"
        );
    }
    let oversized = "a".repeat(automonique_runner::MAX_RUN_ID_BYTES + 1);
    assert!(matches!(
        RunContainment::create(&domain, &oversized, ContainmentLimits::none()).unwrap_err(),
        ContainmentError::RunIdRejected
    ));
}

#[test]
fn a_run_cgroup_is_never_reused() {
    let Some(domain) = enforcement_domain("a_run_cgroup_is_never_reused") else {
        return;
    };
    let identifier = run_id("exclusive");
    let first = RunContainment::create(&domain, &identifier, ContainmentLimits::none()).unwrap();
    let error = RunContainment::create(&domain, &identifier, ContainmentLimits::none())
        .expect_err("an existing run cgroup must not be adopted");
    assert!(matches!(error, ContainmentError::RunCgroupExists));
    first.dispose(DRAIN_DEADLINE).unwrap();
}

#[test]
fn a_requested_ceiling_without_its_controller_is_refused_not_downgraded() {
    let Some(domain) =
        enforcement_domain("a_requested_ceiling_without_its_controller_is_refused_not_downgraded")
    else {
        return;
    };
    // Ceilings need the controller enabled for the domain's children. When the
    // domain has not been prepared, the request must fail rather than run the
    // workload unbounded.
    let enabled = domain.enabled_controllers().unwrap();
    if enabled.contains(&Controller::Pids) {
        return;
    }
    let error = RunContainment::create(
        &domain,
        &run_id("nolimit"),
        ContainmentLimits::none().with_pids_max(16),
    )
    .expect_err("an unavailable ceiling must be refused");
    assert!(
        matches!(
            error,
            ContainmentError::ControllerUnavailable(Controller::Pids)
        ),
        "got {error:?}"
    );
}

#[test]
fn a_prepared_domain_enforces_a_process_ceiling() {
    let Some(domain) = enforcement_domain("a_prepared_domain_enforces_a_process_ceiling") else {
        return;
    };
    if domain.prepare(&[Controller::Pids]).is_err() {
        // Preparation moves this process into a supervisor leaf; where that is
        // refused the ceiling genuinely cannot be enforced.
        return;
    }
    let containment = RunContainment::create(
        &domain,
        &run_id("pidsmax"),
        ContainmentLimits::none().with_pids_max(4),
    )
    .unwrap();
    let written = fs::read_to_string(containment.path().join("pids.max")).unwrap();
    assert_eq!(written.trim(), "4", "the ceiling must reach the kernel");

    let temporary = TempDir::new("pidsmax");
    let refused = temporary.path().join("refused");
    // Far more processes than the ceiling permits; the kernel must refuse some.
    let script = format!(
        "i=0; while [ $i -lt 40 ]; do /bin/sleep 30 & i=$((i+1)); done 2>{}; exec sleep 60",
        refused.display()
    );
    let mut child = launch_in(&containment, &script);
    assert!(
        wait_for(Duration::from_secs(10), || containment
            .member_pids()
            .map(|members| members.len() >= 2)
            .unwrap_or(false)),
        "workload never entered the boundary"
    );
    // Membership can never exceed the ceiling, whatever the workload attempts.
    let members = containment.member_pids().unwrap();
    assert!(
        members.len() <= 4,
        "pids.max must bound the subtree; saw {} members",
        members.len()
    );

    containment.dispose(DRAIN_DEADLINE).unwrap();
    reap_bounded(&mut child);
}

#[test]
fn a_prepared_domain_enforces_an_exact_cpu_ceiling() {
    let Some(domain) = enforcement_domain("a_prepared_domain_enforces_an_exact_cpu_ceiling") else {
        return;
    };
    if domain.prepare(&[Controller::Cpu]).is_err() {
        return;
    }
    const MILLICORES: u64 = 10;
    let containment = RunContainment::create(
        &domain,
        &run_id("cpumax"),
        ContainmentLimits::none().with_cpu_max_millicores(MILLICORES),
    )
    .unwrap();
    let written = fs::read_to_string(containment.path().join("cpu.max")).unwrap();
    assert_eq!(
        written.trim(),
        format!(
            "{} {CPU_MAX_PERIOD_MICROS}",
            MILLICORES * (CPU_MAX_PERIOD_MICROS / 1_000)
        ),
        "the exact millicore ceiling must reach the kernel"
    );

    let before = cpu_stat(containment.path(), "nr_throttled").unwrap_or(0);
    let mut child = launch_in(&containment, "while :; do :; done");
    assert!(
        wait_for(Duration::from_secs(5), || {
            cpu_stat(containment.path(), "nr_throttled").is_some_and(|count| count > before)
        }),
        "a CPU-bound workload was never throttled by cpu.max"
    );

    containment.dispose(DRAIN_DEADLINE).unwrap();
    reap_bounded(&mut child);
}

#[test]
fn an_installed_containment_discharges_the_containment_requirement() {
    // A bare runner still has no boundary, whatever the host kernel offers.
    assert!(!ContainmentEvidence::ProcessGroupOnly.is_descendant_complete());
    assert!(ContainmentEvidence::CgroupV2Descendant.is_descendant_complete());

    // Containment and cleanup are the two requirements a run cgroup
    // establishes, so a contained runner must no longer cite them.
    let remaining = Runner::REMAINING_REQUIREMENTS;
    assert!(
        !remaining.contains(&BoundaryRequirement::DescendantCompleteContainment),
        "an installed cgroup boundary discharges descendant-complete containment"
    );
    assert!(
        !remaining.contains(&BoundaryRequirement::CompleteCleanup),
        "disposal kills the tree and removes the cgroup"
    );
    // The rest genuinely remain unbuilt, and must stay visible.
    assert!(remaining.contains(&BoundaryRequirement::DescriptorClosure));
    assert!(remaining.contains(&BoundaryRequirement::FilesystemIsolation));
    assert!(remaining.contains(&BoundaryRequirement::NetworkDenial));
}

#[test]
fn a_live_containment_reports_descendant_complete_evidence() {
    let Some(domain) =
        enforcement_domain("a_live_containment_reports_descendant_complete_evidence")
    else {
        return;
    };
    let containment =
        RunContainment::create(&domain, &run_id("evidence"), ContainmentLimits::none()).unwrap();
    assert!(
        Runner::containment_evidence(&containment).is_descendant_complete(),
        "a live run cgroup is descendant-complete containment"
    );
    containment.dispose(DRAIN_DEADLINE).unwrap();
}

#[test]
fn discovery_reports_a_domain_only_when_placement_is_possible() {
    match domain() {
        Ok(found) => {
            // A reported domain must be writable and expose the atomic kill.
            assert!(found.root().join("cgroup.kill").is_file());
            assert!(
                found.root().starts_with("/sys/fs/cgroup"),
                "a domain must live under the unified hierarchy"
            );
            assert!(automonique_runner::domain_is_owned(&found).unwrap_or(false));
        }
        Err(error) => assert_refuses_closed(&error),
    }
}
