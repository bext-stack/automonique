// SPDX-License-Identifier: Elastic-2.0

//! Exercised proof that the composed sandboxed launch works end to end.
//!
//! One workload runs under all four mechanisms at once — cgroup containment,
//! descriptor closure, Landlock filesystem allowlist, Landlock TCP denial —
//! and the test reads the workload's own observations from inside the sandbox
//! to prove each boundary held simultaneously, not just in isolation.
//!
//! Like the containment proofs, the full launch needs a delegated cgroup v2
//! domain. Outside one, each test asserts the exact fail-closed refusal, and
//! `AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1` turns that degradation into a
//! failure so a verifying host cannot quietly skip the proof:
//!
//! ```sh
//! systemd-run --user --scope -p Delegate=yes \
//!   --setenv=AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1 \
//!   cargo test --manifest-path rust/Cargo.toml -p automonique-runner --test launch
//! ```

use automonique_runner::filesystem::PathIntent;
use automonique_runner::{
    ContainmentDomain, ContainmentError, ContainmentLimits, HELPER_REFUSED_EXIT, LaunchPlan,
    RunContainment, SocketGrant, spawn_sandboxed,
};
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const HELPER: &str = env!("CARGO_BIN_EXE_automonique-launch-enter");
const BUSYBOX: &str = "/usr/bin/busybox";
const DRAIN_DEADLINE: Duration = Duration::from_secs(10);
const REQUIRE_ENFORCED_ENV: &str = "AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "automonique-launch-{label}-{}-{serial}",
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

fn run_id(label: &str) -> String {
    let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    format!("l{}-{label}-{serial}", std::process::id())
}

/// The delegated domain, or a loud, contract-checked degradation.
fn enforcement_domain(proof: &str) -> Option<ContainmentDomain> {
    match ContainmentDomain::discover() {
        Ok(found) => {
            eprintln!(
                "[launch] ENFORCED  {proof}: domain {}",
                found.root().display()
            );
            Some(found)
        }
        Err(error) => {
            eprintln!("[launch] NOT PROVEN {proof}: {error}");
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

/// A plan running `script` under busybox sh with the standard test grants.
///
/// Busybox is statically linked, so a single read-execute file grant makes it
/// runnable without granting any loader or library directory.
fn busybox_plan(script: &str, extra: impl FnOnce(LaunchPlan) -> LaunchPlan) -> LaunchPlan {
    let plan = LaunchPlan::new(BUSYBOX)
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

/// Launch `plan`, capture the workload's stdout+stderr, and reap bounded.
fn launch_and_capture(plan: &LaunchPlan, containment: &RunContainment) -> (i32, String, String) {
    let frame = plan.encode().unwrap();
    let mut child = Command::new(HELPER)
        .env_clear()
        .env(automonique_runner::CGROUP_DIR_ENV, containment.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("helper spawns");
    use std::io::Write as _;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&frame)
        .expect("frame written");

    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        match child.try_wait().expect("wait") {
            Some(status) => break status,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("sandboxed workload did not exit within the deadline");
            }
        }
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (status.code().unwrap_or(-1), stdout, stderr)
}

#[test]
fn one_workload_is_confined_by_all_boundaries_at_once() {
    let Some(domain) = enforcement_domain("one_workload_is_confined_by_all_boundaries_at_once")
    else {
        return;
    };
    let temporary = TempDir::new("composed");
    let allowed = temporary.path().join("allowed");
    fs::create_dir(&allowed).unwrap();
    fs::write(allowed.join("data.txt"), "sandbox-visible").unwrap();

    let containment =
        RunContainment::create(&domain, &run_id("composed"), ContainmentLimits::none()).unwrap();

    // The workload reports its own observations, one `key=value` per line.
    //
    // Every external command is the granted busybox binary by absolute path.
    // Bare names would resolve through `PATH` to dynamically linked binaries
    // whose exec the policy denies — which is correct enforcement, but it
    // would make these probes measure exec-denial of `/usr/bin/cat` instead
    // of the read-denial they exist to prove, and the /etc probe would then
    // pass vacuously.
    let script = format!(
        r#"
echo started=yes
echo cgroup=$({bb} cat /proc/self/cgroup)
echo fds=$({bb} ls /proc/self/fd | {bb} tr '\n' ',')
if read -t 1 line; then echo stdin=readable; else echo stdin=eof; fi
echo allowed=$({bb} cat {allowed}/data.txt 2>&1)
echo etc=$({bb} cat /etc/hostname 2>&1)
echo cgdir=${{AUTOMONIQUE_CGROUP_DIR:-ABSENT}}
echo tcp=$({bb} nc -w 1 127.0.0.1 9 2>&1)
echo udp=$({bb} nslookup example.invalid 127.0.0.1 2>&1 | {bb} head -1)
echo done=yes
"#,
        bb = BUSYBOX,
        allowed = allowed.display()
    );
    let plan = busybox_plan(&script, |plan| {
        plan.filesystem_grant(PathIntent::Read, &allowed)
            .unwrap()
            // /proc lets the workload report its own cgroup and descriptors.
            .filesystem_grant(PathIntent::Read, "/proc")
            .unwrap()
            // TCP socket creation is granted so the TCP probe reaches the
            // Landlock layer and is denied THERE (EACCES at connect). UDP has
            // no grant, so its probe dies earlier, at socket(2), with EPERM
            // from the seccomp layer. The two distinct errnos in one workload
            // prove the two layers separately.
            .socket_grant(SocketGrant::Tcp)
            .unwrap()
        // /dev/null backs the workload's replaced stdin; reads need it? No:
        // stdin is already open. /etc deliberately has no grant.
    });

    let (code, stdout, stderr) = launch_and_capture(&plan, &containment);
    let observed = |key: &str| -> String {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| {
                panic!("workload never reported {key}; stdout={stdout:?} stderr={stderr:?}")
            })
            .to_owned()
    };

    assert_eq!(observed("started"), "yes", "workload must have run");
    assert_eq!(observed("done"), "yes", "workload must have finished");
    assert_eq!(code, 0, "workload exit propagates; stderr={stderr:?}");

    // Cgroup: the workload saw itself inside the run cgroup.
    let cgroup = observed("cgroup");
    let expected_suffix = containment
        .path()
        .strip_prefix("/sys/fs/cgroup")
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(
        cgroup.ends_with(&expected_suffix),
        "workload must observe membership of {expected_suffix}, saw {cgroup}"
    );

    // Descriptors: exactly 0,1,2 plus the transient fd `ls` uses to read the
    // directory itself, which busybox reports with a trailing comma.
    let fds = observed("fds");
    let mut listed = fds
        .split(',')
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>();
    listed.sort_unstable();
    assert!(
        listed.len() <= 4 && ["0", "1", "2"].iter().all(|fd| listed.contains(fd)),
        "workload must hold only the standard streams plus the lister's own \
         transient descriptor, saw {fds}"
    );

    // Plan channel: stdin is /dev/null, not the frame pipe.
    assert_eq!(observed("stdin"), "eof");

    // Filesystem: the grant is readable, everything else is denied. The /etc
    // probe must fail with the kernel's permission error, not any weaker way:
    // busybox itself demonstrably executes, so the denial is the read itself.
    assert_eq!(observed("allowed"), "sandbox-visible");
    let etc = observed("etc");
    assert!(
        etc.contains("Permission denied"),
        "reading /etc must be denied by the Landlock domain, saw {etc:?}"
    );

    // Environment: nothing inherited from the supervisor or helper. The shell
    // synthesizes its own PATH/PWD/SHLVL, so counting variables would prove
    // nothing; the helper's one distinctive variable being absent does.
    assert_eq!(observed("cgdir"), "ABSENT");

    // TCP: denied by policy — EACCES, not ECONNREFUSED. Port 9 has no
    // listener, so without the policy the same probe reports refusal; seeing
    // "Permission denied" is therefore the Landlock domain speaking.
    let tcp = observed("tcp");
    assert!(
        tcp.contains("Permission denied"),
        "TCP must be denied by policy, not merely refused; saw {tcp:?}"
    );

    // UDP: the socket cannot even be created — EPERM from the seccomp filter,
    // a different failure at a different syscall than the TCP denial above.
    let udp = observed("udp");
    assert!(
        udp.contains("Operation not permitted"),
        "UDP socket creation must be denied by the socket filter; saw {udp:?}"
    );

    containment.dispose(DRAIN_DEADLINE).unwrap();
}

#[test]
fn contradictory_tcp_layers_are_refused_at_the_plan() {
    // A connect exception without the tcp socket grant would make one layer
    // promise what another forbids; the plan refuses instead of picking a
    // winner silently.
    let plan = busybox_plan("true", |plan| plan.allow_connect_port(443).unwrap());
    assert!(matches!(
        plan.encode(),
        Err(automonique_runner::LaunchPlanError::PolicyRejected(_))
    ));
}

#[test]
fn a_truncated_frame_refuses_before_any_workload_runs() {
    let Some(domain) = enforcement_domain("a_truncated_frame_refuses_before_any_workload_runs")
    else {
        return;
    };
    let temporary = TempDir::new("truncated");
    let witness = temporary.path().join("executed");
    let containment =
        RunContainment::create(&domain, &run_id("truncated"), ContainmentLimits::none()).unwrap();

    let plan = busybox_plan(&format!("echo ran > {}", witness.display()), |plan| {
        plan.filesystem_grant(PathIntent::ReadWrite, temporary.path())
            .unwrap()
    });
    let mut frame = plan.encode().unwrap();
    // Drop the terminator line: the frame is now truncated mid-delivery.
    let terminator_start = frame.len() - automonique_runner::FRAME_TERMINATOR.len() - 1;
    frame.truncate(terminator_start);

    let mut child = Command::new(HELPER)
        .env_clear()
        .env(automonique_runner::CGROUP_DIR_ENV, containment.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("helper spawns");
    use std::io::Write as _;
    child.stdin.take().unwrap().write_all(&frame).unwrap();
    let status = child.wait().expect("helper exits");

    assert_eq!(
        status.code(),
        Some(HELPER_REFUSED_EXIT),
        "a truncated frame must be refused with the helper's refusal code"
    );
    assert!(
        !witness.exists(),
        "no workload may run from a truncated frame"
    );
    containment.dispose(DRAIN_DEADLINE).unwrap();
}

#[test]
fn the_helper_refuses_without_a_containment_target() {
    // No delegated domain needed: the refusal must fire before the cgroup is
    // touched at all, so this proof runs everywhere.
    let temporary = TempDir::new("no-target");
    let witness = temporary.path().join("executed");
    let plan = busybox_plan(&format!("echo ran > {}", witness.display()), |plan| {
        plan.filesystem_grant(PathIntent::ReadWrite, temporary.path())
            .unwrap()
    });
    let frame = plan.encode().unwrap();

    let mut child = Command::new(HELPER)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("helper spawns");
    use std::io::Write as _;
    child.stdin.take().unwrap().write_all(&frame).unwrap();
    let status = child.wait().expect("helper exits");

    assert_eq!(status.code(), Some(HELPER_REFUSED_EXIT));
    assert!(!witness.exists());
}

#[test]
fn a_launched_tree_is_killed_by_containment_disposal() {
    let Some(domain) = enforcement_domain("a_launched_tree_is_killed_by_containment_disposal")
    else {
        return;
    };
    let temporary = TempDir::new("kill");
    let pid_file = temporary.path().join("workload.pid");
    let containment =
        RunContainment::create(&domain, &run_id("kill"), ContainmentLimits::none()).unwrap();

    // The workload daemonises with setsid, the classic escape from process
    // groups, and then lingers. Disposal must reap it anyway. Absolute busybox
    // paths keep every spawned program inside the read-execute grant.
    let script = format!(
        "{bb} setsid {bb} sh -c 'echo $$ > {pid}; exec {bb} sleep 60' & exec {bb} sleep 60",
        bb = BUSYBOX,
        pid = pid_file.display()
    );
    let plan = busybox_plan(&script, |plan| {
        plan.filesystem_grant(PathIntent::ReadWrite, temporary.path())
            .unwrap()
            // The shell reopens a background job's stdin from /dev/null, and a
            // Landlock policy contains exactly what it names — so the plan
            // must say so. Without this grant the background subtree never
            // starts, which is enforcement working, not a test flake.
            .filesystem_grant(PathIntent::Read, "/dev/null")
            .unwrap()
    });
    let mut child = Command::new(HELPER)
        .env_clear()
        .env(automonique_runner::CGROUP_DIR_ENV, containment.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("helper spawns");
    use std::io::Write as _;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&plan.encode().unwrap())
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    while !pid_file.is_file() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let escaped: i32 = fs::read_to_string(&pid_file)
        .expect("workload reported its pid")
        .trim()
        .parse()
        .expect("pid parses");
    let escaped = nix::unistd::Pid::from_raw(escaped);
    assert!(automonique_runner::process_is_live(escaped));

    containment.dispose(DRAIN_DEADLINE).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match child.try_wait().expect("wait") {
            Some(_) => break,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("direct child survived containment disposal");
            }
        }
    }
    assert!(
        !automonique_runner::process_is_live(escaped),
        "a setsid descendant of a sandboxed launch must die with the cgroup"
    );
}

#[test]
fn spawn_sandboxed_delivers_the_same_confinement() {
    let Some(domain) = enforcement_domain("spawn_sandboxed_delivers_the_same_confinement") else {
        return;
    };
    let containment =
        RunContainment::create(&domain, &run_id("api"), ContainmentLimits::none()).unwrap();
    let plan = busybox_plan("true", |plan| plan);

    // The library entry point inherits this test's stdout, so the proof here
    // is the exit path and confinement, not captured output.
    let mut child = spawn_sandboxed(Path::new(HELPER), &plan, &containment).expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        match child.try_wait().expect("wait") {
            Some(status) => break status,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("spawned workload did not exit");
            }
        }
    };
    assert_eq!(status.code(), Some(0));
    containment.dispose(DRAIN_DEADLINE).unwrap();
}

#[test]
fn frames_round_trip_and_refuse_corruption() {
    let plan = busybox_plan("true", |plan| {
        plan.allow_connect_port(443)
            .unwrap()
            .allow_bind_port(8080)
            .unwrap()
            .socket_grant(SocketGrant::Tcp)
            .unwrap()
            .socket_grant(SocketGrant::Unix)
            .unwrap()
    });
    let frame = plan.encode().unwrap();
    let decoded = LaunchPlan::decode(&frame).expect("round trip");
    assert_eq!(decoded, plan);

    // Truncation, trailing content, and unknown keys are each refused.
    let no_terminator = &frame[..frame.len() - 5];
    assert!(LaunchPlan::decode(no_terminator).is_err());
    let mut trailing = frame.clone();
    trailing.extend_from_slice(b"extra=1\n");
    assert!(LaunchPlan::decode(&trailing).is_err());
    let unknown = String::from_utf8(frame.clone())
        .unwrap()
        .replace("program=", "programme=");
    assert!(LaunchPlan::decode(unknown.as_bytes()).is_err());
}
