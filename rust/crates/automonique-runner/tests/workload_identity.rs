// SPDX-License-Identifier: Elastic-2.0

//! The identity proof: a workload launched through the real entry helper runs
//! as a host uid that is not the supervisor's, and a process of the
//! supervisor's uid can no longer read its environment or open its prompt.
//!
//! These are kernel observations, not configuration claims: the workload's
//! `/proc/<pid>/status` is read from outside its namespace, the environment
//! and descriptor reads are attempted by this test process and by a sibling
//! process of the same uid, and the refusals asserted are the kernel's own.
//!
//! The proofs need a delegated cgroup v2 domain, the built entry helper, and
//! a host whose identity probe succeeds — subordinate ranges, setuid
//! `newuidmap`/`newgidmap`, and an AppArmor profile granting the helper
//! `userns` where the host restricts unprivileged user namespaces. Without
//! any of those each proof prints `NOT PROVEN` and passes vacuously, and
//! `AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1` turns that into a failure:
//!
//! ```sh
//! (cd rust && cargo build -p automonique-runner --bin automonique-launch-enter)
//! cargo test -p automonique-runner --test workload_identity --no-run
//! systemd-run --user --scope -p Delegate=yes --quiet \
//!   --setenv=XDG_RUNTIME_DIR=/run/user/$(id -u) \
//!   --setenv=AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1 \
//!   "$(ls -t rust/target/debug/deps/workload_identity-* | grep -v '\.d$' | head -1)" \
//!   --test-threads=1 --nocapture
//! ```

use automonique_runner::filesystem::PathIntent;
use automonique_runner::identity::{self, WorkloadIdentity};
use automonique_runner::{
    ContainmentDomain, ContainmentError, ContainmentLimits, LaunchPlan, RunContainment,
    StdoutCapture, spawn_sandboxed, spawn_sandboxed_with_stdout,
};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::io::{ErrorKind, Read as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const HELPER: &str = env!("CARGO_BIN_EXE_automonique-launch-enter");
const BUSYBOX: &str = "/usr/bin/busybox";
const REQUIRE_ENFORCED_ENV: &str = "AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT";
const START_DEADLINE: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(20);
/// A variable whose value must stay unreadable to a supervisor-uid observer.
const SECRET_NAME: &str = "AUTOMONIQUE_TEST_SECRET";
const SECRET_VALUE: &[u8] = b"observer-must-not-read-this";
const PROMPT: &[u8] = b"the prompt bytes on fd 0";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "automonique-workload-identity-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        // Owner-only, as every run directory is: the workload reaches it
        // through the discretionary-access capabilities it keeps over the
        // supervisor's inodes, not through mode bits.
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
    format!("wi{}-{label}-{serial}", std::process::id())
}

fn busybox_sha256() -> String {
    format!("{:x}", Sha256::digest(fs::read(BUSYBOX).unwrap()))
}

struct Proof {
    domain: ContainmentDomain,
    identity: WorkloadIdentity,
}

fn proof_or_not_proven(proof: &str) -> Option<Proof> {
    let required = std::env::var_os(REQUIRE_ENFORCED_ENV).is_some();
    let not_proven = |reason: String| {
        eprintln!("[workload-identity] NOT PROVEN {proof}: {reason}");
        assert!(
            !required,
            "{REQUIRE_ENFORCED_ENV} is set, so {proof} must run, but: {reason}"
        );
    };
    let domain = match ContainmentDomain::discover() {
        Ok(domain) => domain,
        Err(error) => {
            assert!(
                matches!(
                    error,
                    ContainmentError::DomainNotDelegated
                        | ContainmentError::NotUnifiedCgroupV2
                        | ContainmentError::MissingAtomicKill
                ),
                "undelegated environments must refuse with a typed reason, got {error:?}"
            );
            not_proven(format!("no delegated cgroup v2 domain: {error}"));
            return None;
        }
    };
    if !Path::new(HELPER).is_file() {
        not_proven(format!("the launch helper is not built at {HELPER}"));
        return None;
    }
    if !Path::new(BUSYBOX).is_file() {
        not_proven(format!("no static busybox at {BUSYBOX}"));
        return None;
    }
    let identity = match identity::probe_with_launch_helper(Path::new(HELPER)) {
        Ok(identity) => identity,
        Err(denial) => {
            not_proven(format!("workload identity unavailable: {denial}"));
            return None;
        }
    };
    eprintln!(
        "[workload-identity] ENFORCED {proof}: domain {}, identity {identity}",
        domain.root().display()
    );
    Some(Proof { domain, identity })
}

/// The supervisor's own uid: what the workload must not run as.
fn supervisor_uid() -> u32 {
    nix::unistd::getuid().as_raw()
}

/// One field of a `/proc/<pid>/status`, trimmed.
fn status_field(status: &str, field: &str) -> Option<String> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .map(|value| value.trim().to_owned())
}

/// Four ids from a `Uid:`/`Gid:` line.
fn four_ids(value: &str) -> Vec<u32> {
    value
        .split_ascii_whitespace()
        .map(|id| id.parse().expect("an id"))
        .collect()
}

/// Wait for the workload to create `marker`, or report how the child ended.
fn wait_for_marker(child: &mut Child, marker: &Path) {
    let started = Instant::now();
    while started.elapsed() < START_DEADLINE {
        if marker.exists() {
            return;
        }
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "the workload ended with {status} before creating {}",
                marker.display()
            );
        }
        std::thread::sleep(POLL);
    }
    panic!("the workload did not create {} in time", marker.display());
}

/// A plan that runs `script` under busybox `sh`, with the grants it needs and
/// the two things an observer must not be able to read: a secret in the
/// environment and a prompt on fd 0.
fn observed_plan(script: &str, workspace: &Path) -> LaunchPlan {
    LaunchPlan::new(BUSYBOX, busybox_sha256())
        .unwrap()
        .argument("sh")
        .unwrap()
        .argument("-c")
        .unwrap()
        .argument(script)
        .unwrap()
        .filesystem_grant(PathIntent::ReadExecute, BUSYBOX)
        .unwrap()
        .filesystem_grant(PathIntent::ReadWrite, workspace)
        .unwrap()
        .filesystem_grant(PathIntent::Read, "/dev/null")
        .unwrap()
        .environment(SECRET_NAME, SECRET_VALUE)
        .unwrap()
        .prompt(PROMPT)
        .unwrap()
}

/// Launch a long-lived, observable workload and wait until it has started.
fn launch_observed(proof: &Proof, label: &str, workspace: &Path) -> (RunContainment, Child) {
    let marker = workspace.join("started");
    let script = format!(
        "{bb} touch \"$WORKSPACE/started\"; exec {bb} sleep 30",
        bb = BUSYBOX
    );
    let plan = observed_plan(&script, workspace)
        .environment("WORKSPACE", workspace.as_os_str().as_encoded_bytes())
        .unwrap();
    let containment =
        RunContainment::create(&proof.domain, &run_id(label), ContainmentLimits::none()).unwrap();
    let mut child = spawn_sandboxed(Path::new(HELPER), &plan, &containment).unwrap();
    wait_for_marker(&mut child, &marker);
    (containment, child)
}

/// End a workload through its cgroup — a signal from the supervisor's uid to
/// the workload's pid is `EPERM` now, which is part of what is being proven.
fn end(containment: RunContainment, mut child: Child) {
    containment.kill().unwrap();
    let status = child.wait().unwrap();
    assert!(
        !status.success(),
        "a killed workload must not report success: {status}"
    );
    containment.dispose(Duration::from_secs(10)).unwrap();
}

#[test]
fn the_workload_runs_as_a_host_uid_outside_the_supervisor_uid() {
    let Some(proof) =
        proof_or_not_proven("the_workload_runs_as_a_host_uid_outside_the_supervisor_uid")
    else {
        return;
    };
    let workspace = TempDir::new("uid");
    let (containment, child) = launch_observed(&proof, "uid", workspace.path());
    let pid = child.id();

    // `/proc/<pid>/status` is world-readable and reports ids in the reader's
    // namespace: this process's, the host's.
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let uid = four_ids(&status_field(&status, "Uid:").unwrap());
    let gid = four_ids(&status_field(&status, "Gid:").unwrap());
    eprintln!("[workload-identity] pid {pid} Uid {uid:?} Gid {gid:?}");
    assert_eq!(
        uid,
        vec![proof.identity.host_uid(); 4],
        "real, effective, saved and filesystem uids are all the workload's host uid"
    );
    assert!(
        uid.iter().all(|&id| id != supervisor_uid()),
        "no uid of the workload is the supervisor's ({})",
        supervisor_uid()
    );
    assert_eq!(gid, vec![proof.identity.host_gid(); 4]);
    assert_eq!(
        status_field(&status, "NoNewPrivs:").as_deref(),
        Some("1"),
        "the identity switch did not remove no_new_privs"
    );
    assert_eq!(
        status_field(&status, "Seccomp:").as_deref(),
        Some("2"),
        "the identity switch did not remove the seccomp filter"
    );

    // Inside its namespace the workload is the supervisor's uid *number*,
    // and the namespace maps that number to the host uid observed above.
    let uid_map = fs::read_to_string(format!("/proc/{pid}/uid_map")).unwrap();
    let mapped = uid_map.lines().find_map(|line| {
        let mut fields = line.split_ascii_whitespace();
        let inner: u32 = fields.next()?.parse().ok()?;
        let outer: u32 = fields.next()?.parse().ok()?;
        (inner == proof.identity.namespace_uid()).then_some(outer)
    });
    assert_eq!(
        mapped,
        Some(proof.identity.host_uid()),
        "uid_map:\n{uid_map}"
    );

    // Containment is intact: the cgroup the supervisor created is the one
    // the kernel reports for the workload.
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
    let expected = containment
        .path()
        .strip_prefix("/sys/fs/cgroup")
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(
        cgroup.trim() == format!("0::/{expected}"),
        "the workload's cgroup is {} rather than {expected}",
        cgroup.trim()
    );

    // The workload created its marker inside a supervisor-owned, owner-only
    // directory: discretionary access over the supervisor's inodes survived
    // the switch, and what it created belongs to the workload.
    let marker = fs::metadata(workspace.path().join("started")).unwrap();
    use std::os::unix::fs::MetadataExt as _;
    assert_eq!(marker.uid(), proof.identity.host_uid());
    assert_eq!(marker.gid(), proof.identity.host_gid());
    assert_eq!(
        marker.mode() & 0o777,
        0o664,
        "the workload's umask keeps group write for the supervisor"
    );

    end(containment, child);
}

#[test]
fn a_same_uid_observer_cannot_read_the_workload_environ_or_stdin() {
    let Some(proof) =
        proof_or_not_proven("a_same_uid_observer_cannot_read_the_workload_environ_or_stdin")
    else {
        return;
    };
    let workspace = TempDir::new("observer");
    let (containment, child) = launch_observed(&proof, "observer", workspace.path());
    let pid = child.id();

    // Positive control first: the status read works, so the pid is right and
    // a refusal below is a refusal, not a vanished process.
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    assert_eq!(
        four_ids(&status_field(&status, "Uid:").unwrap())[0],
        proof.identity.host_uid()
    );

    // This process is the supervisor's uid, and is the workload's parent.
    // Neither gets it anything: `environ` and every `fd/<n>` answer with the
    // kernel's ptrace-access refusal.
    let environ = fs::read(format!("/proc/{pid}/environ"));
    match environ {
        Err(error) => assert_eq!(
            error.kind(),
            ErrorKind::PermissionDenied,
            "environ must be refused with EACCES, got {error}"
        ),
        Ok(bytes) => panic!(
            "the supervisor uid read the workload's environ ({} bytes){}",
            bytes.len(),
            if bytes
                .windows(SECRET_VALUE.len())
                .any(|window| window == SECRET_VALUE)
            {
                ", including the secret"
            } else {
                ""
            }
        ),
    }
    let stdin = fs::File::open(format!("/proc/{pid}/fd/0"));
    match stdin {
        Err(error) => assert_eq!(
            error.kind(),
            ErrorKind::PermissionDenied,
            "fd/0 must be refused with EACCES, got {error}"
        ),
        Ok(mut file) => {
            let mut bytes = Vec::new();
            let _ = file.read_to_end(&mut bytes);
            panic!(
                "the supervisor uid opened the workload's fd 0 ({} bytes{})",
                bytes.len(),
                if bytes == PROMPT { ", the prompt" } else { "" }
            );
        }
    }
    let link = fs::read_link(format!("/proc/{pid}/fd/0"));
    assert!(
        matches!(&link, Err(error) if error.kind() == ErrorKind::PermissionDenied),
        "even the descriptor's name is refused: {link:?}"
    );
    let listing = fs::read_dir(format!("/proc/{pid}/fd"));
    assert!(
        matches!(&listing, Err(error) if error.kind() == ErrorKind::PermissionDenied),
        "the descriptor table cannot be listed: {listing:?}"
    );

    // A sibling of the same uid — not the parent, not in the cgroup — is
    // refused the same way. `cat` reports failure and prints nothing.
    for target in [format!("/proc/{pid}/environ"), format!("/proc/{pid}/fd/0")] {
        let output = Command::new(BUSYBOX)
            .arg("cat")
            .arg(&target)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "a same-uid sibling read {target}: {output:?}"
        );
        assert!(
            output.stdout.is_empty(),
            "a same-uid sibling got bytes from {target}: {output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Permission denied"),
            "the sibling's refusal for {target} is not a permission refusal: {stderr}"
        );
    }

    // Signalling is deliberately NOT asserted blocked. The supervisor's uid
    // is the owner of the workload's user namespace, so it keeps CAP_KILL
    // over that namespace — which the supervisor needs to manage its runs,
    // and which the cgroup kill path relies on. The read protection above
    // does not come from the uid comparison a signal uses; it comes from the
    // process being marked non-dumpable by its credential change, which makes
    // its `/proc` files root-owned and closes environ and fd 0 to every uid
    // but real root. That distinction is the acceptance: reading the prompt
    // and the environment is closed; ending the run is not.
    end(containment, child);
}

#[test]
fn the_workload_cannot_open_a_nested_namespace_to_become_root() {
    let Some(proof) =
        proof_or_not_proven("the_workload_cannot_open_a_nested_namespace_to_become_root")
    else {
        return;
    };
    let workspace = TempDir::new("nested");
    // `unshare -U` is the one-step way back to a namespace with every
    // capability; the syscall filter answers EPERM. `id -u` afterwards shows
    // the namespace uid the workload sees itself as.
    let script = format!(
        "{bb} unshare -U {bb} true; echo unshare=$?; {bb} id -u; {bb} id -g",
        bb = BUSYBOX
    );
    let plan = observed_plan(&script, workspace.path());
    let containment =
        RunContainment::create(&proof.domain, &run_id("nested"), ContainmentLimits::none())
            .unwrap();
    let mut child =
        spawn_sandboxed_with_stdout(Path::new(HELPER), &plan, &containment, StdoutCapture::Piped)
            .unwrap();
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    let status = child.wait().unwrap();
    let text = String::from_utf8_lossy(&stdout);
    eprintln!("[workload-identity] nested namespace attempt:\n{text}");
    assert!(
        status.success(),
        "the script itself must complete: {status}"
    );
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.first().copied(),
        Some("unshare=1"),
        "unshare must fail"
    );
    assert_eq!(
        lines.get(1).and_then(|line| line.parse::<u32>().ok()),
        Some(proof.identity.namespace_uid()),
        "inside the namespace the workload is the supervisor's uid number"
    );
    assert_eq!(
        lines.get(2).copied(),
        Some("0"),
        "inside the namespace the supervisor's group is the root group"
    );
    containment.dispose(Duration::from_secs(10)).unwrap();
}
