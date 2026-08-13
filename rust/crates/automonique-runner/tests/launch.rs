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
    LaunchPlanError, RunContainment, SocketGrant, spawn_sandboxed,
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

/// A plan running one busybox applet directly, with no shell in between.
///
/// The environment proof needs this: busybox `sh` synthesizes `PATH`, `PWD`
/// and `SHLVL` for itself, so a variable count taken through a shell measures
/// the shell, not the launch. Exec'ing `busybox env` as the workload itself
/// makes the observed set exactly the delivered set.
fn busybox_applet_plan(applet: &str, extra: impl FnOnce(LaunchPlan) -> LaunchPlan) -> LaunchPlan {
    let plan = LaunchPlan::new(BUSYBOX)
        .unwrap()
        .argument(applet)
        .unwrap()
        .filesystem_grant(PathIntent::ReadExecute, BUSYBOX)
        .unwrap();
    extra(plan)
}

/// Launch `plan`, capture the workload's stdout+stderr as text, reap bounded.
fn launch_and_capture(plan: &LaunchPlan, containment: &RunContainment) -> (i32, String, String) {
    let (code, stdout, stderr) = launch_and_capture_bytes(plan, containment);
    (
        code,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

/// The same launch, with the workload's bytes left exactly as it wrote them.
///
/// A prompt may hold any byte, so the proof that it arrives unaltered cannot
/// go through a lossy text conversion.
fn launch_and_capture_bytes(
    plan: &LaunchPlan,
    containment: &RunContainment,
) -> (i32, Vec<u8>, Vec<u8>) {
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
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
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

// The bounds below are the module's own constants, written out rather than
// imported: `launch::MAX_LAUNCH_ENV_*` and `MAX_LAUNCH_PROMPT_BYTES` are not
// re-exported from the crate root, and pinning the numbers here means a
// widened ceiling fails this file instead of silently following it.
const ENV_ENTRIES: usize = 32;
const ENV_NAME_BYTES: usize = 128;
const ENV_VALUE_BYTES: usize = 4096;
const PROMPT_BYTES: usize = 16 * 1024;

#[test]
fn the_workload_receives_exactly_the_environment_the_plan_names() {
    let Some(domain) =
        enforcement_domain("the_workload_receives_exactly_the_environment_the_plan_names")
    else {
        return;
    };
    let containment =
        RunContainment::create(&domain, &run_id("env"), ContainmentLimits::none()).unwrap();

    // `busybox env` is the workload itself, so what it prints is the process
    // environment the helper built and nothing a shell added to it.
    let plan = busybox_applet_plan("env", |plan| {
        plan.environment("CODEX_HOME", "/opaque/config")
            .unwrap()
            .environment("SSL_CERT_FILE", "/opaque/cert")
            .unwrap()
    });
    let (code, stdout, stderr) = launch_and_capture(&plan, &containment);
    assert_eq!(code, 0, "workload must run; stderr={stderr:?}");

    // Count discipline: exactly the two named entries, in frame order, and
    // no third line of any kind. `PATH` is absent because nothing supplies
    // one, which is the whole point of an execve with a built environment.
    let lines = stdout.lines().collect::<Vec<_>>();
    assert_eq!(
        lines,
        ["CODEX_HOME=/opaque/config", "SSL_CERT_FILE=/opaque/cert"],
        "the workload must observe exactly the plan's environment, saw {stdout:?}"
    );

    // The helper's own variable is not inherited: it configures the helper,
    // never the workload.
    assert!(
        !stdout.contains("AUTOMONIQUE_CGROUP_DIR"),
        "the helper's containment variable must not reach the workload, saw {stdout:?}"
    );
    containment.dispose(DRAIN_DEADLINE).unwrap();
}

#[test]
fn prompt_bytes_reach_the_workload_byte_exact() {
    let Some(domain) = enforcement_domain("prompt_bytes_reach_the_workload_byte_exact") else {
        return;
    };
    let containment =
        RunContainment::create(&domain, &run_id("prompt"), ContainmentLimits::none()).unwrap();

    // Bytes a frame could plausibly mangle: newlines, an interior NUL, a
    // non-UTF-8 byte, the frame's own separators, and its terminator spelling.
    let mut prompt = Vec::new();
    prompt.extend_from_slice(b"first line\nsecond=line:with separators\n");
    prompt.push(0);
    prompt.push(0xff);
    prompt.extend_from_slice(b"\nend=automonique.launch/v1\ntrailing without newline");

    // `busybox cat` copies stdin to stdout with no shell to reinterpret it.
    let plan = busybox_applet_plan("cat", |plan| plan.prompt(&prompt).unwrap());
    assert_eq!(plan.prompt_len(), Some(prompt.len()));

    let (code, stdout, stderr) = launch_and_capture_bytes(&plan, &containment);
    assert_eq!(
        code,
        0,
        "workload must run; stderr={:?}",
        String::from_utf8_lossy(&stderr)
    );
    assert_eq!(
        stdout, prompt,
        "the workload's stdin must be the plan's prompt, byte for byte"
    );
    containment.dispose(DRAIN_DEADLINE).unwrap();
}

#[test]
fn stdin_is_the_named_prompt_and_is_dev_null_without_one() {
    let Some(domain) = enforcement_domain("stdin_is_the_named_prompt_and_is_dev_null_without_one")
    else {
        return;
    };
    let containment =
        RunContainment::create(&domain, &run_id("stdin"), ContainmentLimits::none()).unwrap();

    // One script, two launches. The only difference between them is whether
    // the plan names a prompt, so the two stdin outcomes are attributable to
    // that line and to nothing else in the composition.
    //
    // The script reports what stdin *is*, not only how it behaves. Reading
    // alone cannot tell `/dev/null` from a plan pipe whose writer has already
    // closed — both EOF immediately — so a broken fallback that left the frame
    // channel in place would read as success. The `/proc/self/fd/0` link names
    // the open file description and separates the three cases outright.
    let script = format!(
        r#"
if read -t 1 line; then echo stdin=readable; else echo stdin=eof; fi
echo first=$line
echo rest=$({bb} cat)
echo stdin_is=$({bb} readlink /proc/self/fd/0)
echo home=${{CODEX_HOME:-ABSENT}}
echo cgdir=${{AUTOMONIQUE_CGROUP_DIR:-ABSENT}}
if printf x >&0; then echo tamper=accepted; else echo tamper=refused; fi
echo done=yes
"#,
        bb = BUSYBOX
    );
    let observe = |stdout: &str, key: &str| -> String {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("workload never reported {key}; stdout={stdout:?}"))
            .to_owned()
    };

    let with_prompt = busybox_plan(&script, |plan| {
        plan.prompt("prompt-first-line\nprompt-second-line")
            .unwrap()
            .environment("CODEX_HOME", "/opaque/config")
            .unwrap()
            // Only so the workload can name its own stdin; the prompt itself
            // needs no grant, which is the point of the anonymous descriptor.
            .filesystem_grant(PathIntent::Read, "/proc")
            .unwrap()
    });
    let (code, stdout, stderr) = launch_and_capture(&with_prompt, &containment);
    assert_eq!(code, 0, "workload must run; stderr={stderr:?}");
    assert_eq!(observe(&stdout, "done"), "yes");
    assert_eq!(
        observe(&stdout, "stdin"),
        "readable",
        "a named prompt must make stdin readable under full enforcement"
    );
    assert_eq!(observe(&stdout, "first"), "prompt-first-line");
    assert_eq!(observe(&stdout, "rest"), "prompt-second-line");
    // Identity, not just behaviour: an anonymous memory file, which no
    // directory entry names and no filesystem grant could have reached.
    let stdin_is = observe(&stdout, "stdin_is");
    assert!(
        stdin_is.starts_with("/memfd:automonique-prompt"),
        "stdin must be the anonymous prompt descriptor, saw {stdin_is:?}"
    );
    // The prompt is delivered alongside the environment, not instead of it.
    assert_eq!(observe(&stdout, "home"), "/opaque/config");
    assert_eq!(observe(&stdout, "cgdir"), "ABSENT");
    // The memfd is sealed before the workload exists, so its own stdin is
    // immutable: an unsealed memory file takes this write happily. The probe
    // is the shell's *builtin* printf on purpose — busybox's standalone
    // `printf` applet exits 0 whether or not its write reached anything, so
    // running it here would report success against a sealed descriptor and
    // prove nothing. Its stderr is left unredirected for the same reason: a
    // `2>/dev/null` would need a `/dev/null` grant this plan does not carry,
    // and the failed redirection alone would make every probe say "refused".
    assert_eq!(
        observe(&stdout, "tamper"),
        "refused",
        "the prompt descriptor must be sealed against the workload's own writes"
    );

    // Same script, no prompt line: stdin is /dev/null and EOFs at once, which
    // is exactly the behaviour every plan had before `prompt_hex=` existed.
    let without_prompt = busybox_plan(&script, |plan| {
        plan.filesystem_grant(PathIntent::Read, "/proc").unwrap()
    });
    let (code, stdout, stderr) = launch_and_capture(&without_prompt, &containment);
    assert_eq!(code, 0, "workload must run; stderr={stderr:?}");
    assert_eq!(observe(&stdout, "done"), "yes");
    assert_eq!(
        observe(&stdout, "stdin"),
        "eof",
        "without a prompt line stdin must still be /dev/null"
    );
    assert_eq!(observe(&stdout, "first"), "");
    assert_eq!(observe(&stdout, "rest"), "");
    // The exact device, not merely something that EOFs: the plan channel is a
    // pipe, and a pipe whose writer has closed also EOFs.
    assert_eq!(
        observe(&stdout, "stdin_is"),
        "/dev/null",
        "without a prompt the workload's stdin must be /dev/null itself"
    );
    assert_eq!(observe(&stdout, "home"), "ABSENT");
    assert_eq!(observe(&stdout, "cgdir"), "ABSENT");

    containment.dispose(DRAIN_DEADLINE).unwrap();
}

#[test]
fn environment_bounds_are_refused_at_the_plan() {
    use automonique_runner::LaunchPlanError::EnvironmentRejected;

    let base = busybox_plan("true", |plan| plan);
    let rejected = |result: Result<LaunchPlan, LaunchPlanError>, what: &str| {
        assert!(
            matches!(result, Err(EnvironmentRejected(_))),
            "{what} must be refused as an environment entry"
        );
    };

    // One more entry than the ceiling allows.
    let mut filled = base.clone();
    for index in 0..ENV_ENTRIES {
        filled = filled.environment(format!("VAR_{index}"), "value").unwrap();
    }
    rejected(filled.clone().environment("ONE_TOO_MANY", "v"), "entry 33");

    // Value and name at the ceiling are accepted; one byte more is not.
    let at_value_ceiling = base
        .clone()
        .environment("BIG", vec![b'v'; ENV_VALUE_BYTES])
        .expect("a value at the ceiling is accepted");
    assert_eq!(at_value_ceiling.environment_names().count(), 1);
    rejected(
        base.clone()
            .environment("BIG", vec![b'v'; ENV_VALUE_BYTES + 1]),
        "an oversized value",
    );
    let long_name = "N".repeat(ENV_NAME_BYTES);
    base.clone()
        .environment(&long_name, "v")
        .expect("a name at the ceiling is accepted");
    rejected(
        base.clone()
            .environment("N".repeat(ENV_NAME_BYTES + 1), "v"),
        "an oversized name",
    );

    // A repeated name has no correct resolution, so there is no resolution.
    rejected(
        base.clone()
            .environment("CODEX_HOME", "/one")
            .unwrap()
            .environment("CODEX_HOME", "/two"),
        "a duplicate name",
    );

    // The name grammar is exact: lowercase, leading digits, punctuation, an
    // embedded `=`, and an empty name are all outside it.
    for bad in [
        "codex_home",
        "Codex_Home",
        "1LEADING",
        "WITH-DASH",
        "WITH.DOT",
        "WITH=EQUALS",
        "WITH SPACE",
        "",
    ] {
        rejected(base.clone().environment(bad, "v"), bad);
    }

    // A NUL in a value cannot survive execve, so it is refused where it is
    // written rather than where it would fail.
    rejected(
        base.clone().environment("HAS_NUL", b"a\0b".as_slice()),
        "a NUL value",
    );
}

#[test]
fn environment_and_prompt_bounds_are_refused_at_decode_too() {
    let plan = busybox_plan("true", |plan| {
        plan.environment("CODEX_HOME", "/opaque/config").unwrap()
    });
    let frame = String::from_utf8(plan.encode().unwrap()).unwrap();
    let env_line = frame
        .lines()
        .find(|line| line.starts_with("env="))
        .expect("the frame carries the entry")
        .to_owned();

    let swap =
        |replacement: &str| -> Vec<u8> { frame.replace(&env_line, replacement).into_bytes() };

    // Hex corruption in either half: odd length, a non-hex digit, and a
    // missing separator are each framing errors, not silent truncations. Each
    // corruption is derived from the honest encoding so it differs from it in
    // exactly the one way named.
    let name_hex = hex_of(b"CODEX_HOME");
    let value_hex = hex_of(b"/opaque/config");
    let odd_name = &name_hex[..name_hex.len() - 1];
    assert!(LaunchPlan::decode(&swap(&format!("env={odd_name}:{value_hex}"))).is_err());
    let non_hex = format!("{}zz", &value_hex[..value_hex.len() - 2]);
    assert!(LaunchPlan::decode(&swap(&format!("env={name_hex}:{non_hex}"))).is_err());
    assert!(LaunchPlan::decode(&swap(&format!("env={name_hex}{value_hex}"))).is_err());
    // A lowercase name is hex-clean and still refused: the grammar is checked
    // after decoding, on the bytes the name actually has.
    let lowercase = format!("env={}:{}", hex_of(b"codex_home"), hex_of(b"/opaque"));
    assert!(matches!(
        LaunchPlan::decode(&swap(&lowercase)),
        Err(LaunchPlanError::EnvironmentRejected(_))
    ));
    // Two lines binding one name refuse on the second.
    let duplicated = format!("{env_line}\n{env_line}");
    assert!(matches!(
        LaunchPlan::decode(&swap(&duplicated)),
        Err(LaunchPlanError::EnvironmentRejected(_))
    ));

    // The prompt line: at most one, never empty, never past the ceiling.
    let prompted = busybox_plan("true", |plan| plan.prompt("bytes").unwrap());
    let prompt_frame = String::from_utf8(prompted.encode().unwrap()).unwrap();
    let prompt_line = prompt_frame
        .lines()
        .find(|line| line.starts_with("prompt_hex="))
        .expect("the frame carries the prompt")
        .to_owned();
    let swap_prompt = |replacement: &str| -> Vec<u8> {
        prompt_frame.replace(&prompt_line, replacement).into_bytes()
    };
    assert!(matches!(
        LaunchPlan::decode(&swap_prompt(&format!("{prompt_line}\n{prompt_line}"))),
        Err(LaunchPlanError::PromptRejected)
    ));
    assert!(matches!(
        LaunchPlan::decode(&swap_prompt("prompt_hex=")),
        Err(LaunchPlanError::PromptRejected)
    ));
    let oversized = format!("prompt_hex={}", hex_of(&vec![b'p'; PROMPT_BYTES + 1]));
    assert!(matches!(
        LaunchPlan::decode(&swap_prompt(&oversized)),
        Err(LaunchPlanError::PromptRejected)
    ));
    assert!(LaunchPlan::decode(&swap_prompt("prompt_hex=abc")).is_err());
}

#[test]
fn the_prompt_ceiling_leaves_room_for_the_rest_of_the_frame() {
    // The module's arithmetic, exercised: a maximal prompt line costs
    // 11 + 2*16384 + 1 = 32780 of the 65536-byte budget, and a maximal
    // environment entry costs 4 + 256 + 1 + 8192 + 1 = 8454. Three fit
    // beside a maximal prompt; the fourth does not, and encode says so
    // instead of truncating the frame.
    let prompt = vec![b'p'; PROMPT_BYTES];
    let name = |index: usize| format!("{}{index:02}", "N".repeat(ENV_NAME_BYTES - 2));
    let value = vec![b'v'; ENV_VALUE_BYTES];

    let mut plan = busybox_plan("true", |plan| plan.prompt(&prompt).unwrap());
    for index in 0..3 {
        plan = plan.environment(name(index), &value).unwrap();
    }
    let frame = plan
        .encode()
        .expect("a maximal prompt plus three entries fit");
    assert!(
        frame.len() <= 64 * 1024,
        "the encoded frame must respect the budget, saw {}",
        frame.len()
    );
    assert_eq!(LaunchPlan::decode(&frame).unwrap(), plan);

    let overflowing = plan.environment(name(3), &value).unwrap();
    assert!(
        matches!(overflowing.encode(), Err(LaunchPlanError::FrameTooLarge)),
        "the fourth maximal entry must overflow the frame budget"
    );

    // The prompt builder holds its own ceiling, independent of the frame.
    assert!(matches!(
        busybox_plan("true", |plan| plan).prompt(vec![b'p'; PROMPT_BYTES + 1]),
        Err(LaunchPlanError::PromptRejected)
    ));
    assert!(matches!(
        busybox_plan("true", |plan| plan).prompt(b""),
        Err(LaunchPlanError::PromptRejected)
    ));
    assert!(matches!(
        busybox_plan("true", |plan| plan)
            .prompt("one")
            .unwrap()
            .prompt("two"),
        Err(LaunchPlanError::PromptRejected)
    ));
}

#[test]
fn frames_round_trip_with_environment_and_prompt() {
    let plan = busybox_plan("true", |plan| {
        plan.socket_grant(SocketGrant::Tcp)
            .unwrap()
            .allow_connect_port(443)
            .unwrap()
            .environment("CODEX_HOME", "/opaque/config")
            .unwrap()
            .environment("SSL_CERT_FILE", "/opaque/cert")
            .unwrap()
            // A value may hold any byte but NUL, including the frame's own
            // separators and newlines.
            .environment("AWKWARD", b"line\nbreak:colon=equals\xff".as_slice())
            .unwrap()
            .prompt("prompt bytes\nwith a newline")
            .unwrap()
    });
    let frame = plan.encode().unwrap();
    let decoded = LaunchPlan::decode(&frame).expect("round trip");
    assert_eq!(decoded, plan);
    assert_eq!(
        decoded.environment_names().collect::<Vec<_>>(),
        ["CODEX_HOME", "SSL_CERT_FILE", "AWKWARD"],
        "entries keep their frame order"
    );
    assert_eq!(
        decoded.prompt_len(),
        Some("prompt bytes\nwith a newline".len())
    );
}

#[test]
fn secrets_stay_out_of_argv_out_of_the_frame_text_and_out_of_debug() {
    let plan = busybox_plan("true", |plan| {
        plan.environment("CODEX_HOME", "/opaque/config")
            .unwrap()
            .prompt("the secret prompt")
            .unwrap()
    });
    let frame = plan.encode().unwrap();
    let text = String::from_utf8(frame).unwrap();

    // Hex encoding is what keeps values out of the frame's readable text; the
    // names are not secret and stay legible only in their hex form too.
    assert!(!text.contains("/opaque/config"));
    assert!(!text.contains("the secret prompt"));
    assert!(text.contains(&hex_of(b"/opaque/config")));
    assert!(text.contains(&hex_of(b"the secret prompt")));

    // A derived Debug would print both. This one prints names and a length.
    let debug = format!("{plan:?}");
    assert!(
        !debug.contains("/opaque/config"),
        "debug leaked a value: {debug}"
    );
    assert!(
        !debug.contains("the secret prompt"),
        "debug leaked the prompt: {debug}"
    );
    assert!(debug.contains("CODEX_HOME"));
    assert!(
        debug.contains("17"),
        "debug reports the prompt length: {debug}"
    );
}

/// Lowercase hex, the frame's own encoding, for building exact test lines.
fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
