// SPDX-License-Identifier: Elastic-2.0

//! The proof the spike exists for: a busybox workload launched through the
//! runner's real composed containment — cgroup, descriptor closure, Landlock
//! filesystem allowlist carrying a read-write grant on the FUSE mountpoint,
//! TCP denial and the socket filter — exceeds each ceiling from inside, reads
//! the ceilings back through `statfs`, and the filesystem's own ledger records
//! the refusals independently of anything the workload printed.
//!
//! It needs three things, and prints `NOT PROVEN` without any of them: a
//! delegated cgroup v2 domain, the entry helper named by
//! `AUTOMONIQUE_LAUNCH_HELPER`, and a usable FUSE stack.
//! `AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1` turns `NOT PROVEN` into a
//! failure so a verifying host cannot skip the proof quietly. The recipe:
//!
//! ```sh
//! (cd rust && cargo build -p automonique-runner --bin automonique-launch-enter)
//! cargo test --test contained --no-run
//! systemd-run --user --scope -p Delegate=yes --quiet \
//!   --setenv=XDG_RUNTIME_DIR=/run/user/$(id -u) \
//!   --setenv=AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1 \
//!   --setenv=AUTOMONIQUE_LAUNCH_HELPER=<repo>/rust/target/debug/automonique-launch-enter \
//!   <repo>/spikes/tempfs-quota/target/debug/deps/contained-<hash> \
//!   --test-threads=1 --nocapture
//! ```

use automonique_runner::filesystem::PathIntent;
use automonique_runner::{
    CGROUP_DIR_ENV, ContainmentDomain, ContainmentError, ContainmentLimits, LaunchPlan,
    RunContainment,
};
use automonique_tempfs_quota_spike::{
    Ceilings, FS_SUBTYPE, FusePrerequisites, MountedTempfs, Resource, STATFS_BLOCK_BYTES,
    VerifiedFuse,
};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const BUSYBOX: &str = "/usr/bin/busybox";
const HELPER_ENV: &str = "AUTOMONIQUE_LAUNCH_HELPER";
const REQUIRE_ENFORCED_ENV: &str = "AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT";
const DRAIN_DEADLINE: Duration = Duration::from_secs(10);
const RUN_DEADLINE: Duration = Duration::from_secs(60);

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "automonique-tempfs-contained-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn subdir(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir(&path).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_id(label: &str) -> String {
    let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    format!("tq{}-{label}-{serial}", std::process::id())
}

fn busybox_sha256() -> String {
    format!("{:x}", Sha256::digest(fs::read(BUSYBOX).unwrap()))
}

/// Everything the proof needs, or a loud, contract-checked degradation.
struct Proof {
    domain: ContainmentDomain,
    helper: PathBuf,
    fuse: VerifiedFuse,
}

fn proof_or_not_proven(proof: &str) -> Option<Proof> {
    let required = std::env::var_os(REQUIRE_ENFORCED_ENV).is_some();
    let not_proven = |reason: String| {
        eprintln!("[contained] NOT PROVEN {proof}: {reason}");
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
    let Some(helper) = std::env::var_os(HELPER_ENV).map(PathBuf::from) else {
        not_proven(format!("{HELPER_ENV} is not set"));
        return None;
    };
    if !helper.is_file() {
        not_proven(format!("{HELPER_ENV} names no file: {}", helper.display()));
        return None;
    }
    let fuse = match FusePrerequisites::host_default().verify() {
        Ok(fuse) => fuse,
        Err(error) => {
            not_proven(format!("FUSE unavailable: {error}"));
            return None;
        }
    };
    eprintln!(
        "[contained] ENFORCED  {proof}: domain {} helper {}",
        domain.root().display(),
        helper.display()
    );
    Some(Proof {
        domain,
        helper,
        fuse,
    })
}

/// A plan running `script` under busybox sh. Busybox is statically linked,
/// so one read-execute file grant makes it runnable.
fn busybox_plan(script: &str) -> LaunchPlan {
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
}

struct Captured {
    code: i32,
    stdout: String,
    stderr: String,
    elapsed: Duration,
}

impl Captured {
    fn observed(&self, key: &str) -> String {
        self.stdout
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| {
                panic!(
                    "workload never reported {key}; stdout={:?} stderr={:?}",
                    self.stdout, self.stderr
                )
            })
            .to_owned()
    }
}

/// Launch through the real entry helper and capture what the workload wrote.
fn launch(proof: &Proof, plan: &LaunchPlan, containment: &RunContainment) -> Captured {
    let frame = plan.encode().unwrap();
    let start = Instant::now();
    let mut child = Command::new(&proof.helper)
        .env_clear()
        .env(CGROUP_DIR_ENV, containment.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("helper spawns");
    child.stdin.take().unwrap().write_all(&frame).unwrap();
    let mut stdout_pipe = child.stdout.take().unwrap();
    let mut stderr_pipe = child.stderr.take().unwrap();
    let stdout_reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buffer);
        buffer
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buffer);
        buffer
    });
    let deadline = Instant::now() + RUN_DEADLINE;
    let status = loop {
        match child.try_wait().expect("wait") {
            Some(status) => break status,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            None => {
                let _ = containment.kill();
                let _ = child.wait();
                panic!("sandboxed workload did not exit within the deadline");
            }
        }
    };
    let elapsed = start.elapsed();
    Captured {
        code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout_reader.join().unwrap()).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_reader.join().unwrap()).into_owned(),
        elapsed,
    }
}

fn print_transcript(label: &str, captured: &Captured) {
    eprintln!(
        "[contained] --- {label}: exit {} in {:?} ---",
        captured.code, captured.elapsed
    );
    eprintln!("[contained] --- {label}: stdout ---\n{}", captured.stdout);
    eprintln!("[contained] --- {label}: stderr ---\n{}", captured.stderr);
}

#[test]
fn a_contained_workload_hits_both_ceilings_and_reads_them_back() {
    let Some(proof) =
        proof_or_not_proven("a_contained_workload_hits_both_ceilings_and_reads_them_back")
    else {
        return;
    };
    let temp = TempDir::new("ceilings");
    let mountpoint = temp.subdir("mnt");
    let ceiling_bytes = 256 * STATFS_BLOCK_BYTES;
    let ceiling_objects = 16;
    let ceilings = Ceilings::new(ceiling_bytes, ceiling_objects).unwrap();
    let mounted = MountedTempfs::mount(&proof.fuse, &mountpoint, ceilings).unwrap();
    eprintln!("[contained] mount evidence: {}", mounted.evidence());
    let mnt = mounted.mountpoint().to_path_buf();
    let containment = RunContainment::create(
        &proof.domain,
        &run_id("ceilings"),
        ContainmentLimits::none(),
    )
    .unwrap();

    // The workload reports its own observations, one `key=value` per line.
    // Every external command is the granted busybox binary by absolute path,
    // including the `true` behind each create: a redirection that fails on a
    // *special* builtin such as `:` makes a non-interactive POSIX shell exit,
    // which would end the probe at the first refusal it exists to observe.
    // `dd` asks for more blocks than the ceiling holds; the shell loop asks
    // for more objects than the ceiling holds; both readbacks are the
    // kernel's `statfs` as seen from inside the Landlock domain.
    let script = format!(
        r#"
echo started=yes
echo statfs_before=$({bb} stat -f -c 'bsize=%s blocks=%b bfree=%f bavail=%a files=%c ffree=%d namelen=%l' {mnt})
{bb} df -k {mnt}
{bb} df -i {mnt}
{bb} dd if=/dev/zero of={mnt}/fill bs=4096 count=300
echo dd_exit=$?
echo fill_bytes=$({bb} stat -c %s {mnt}/fill)
echo statfs_full=$({bb} stat -f -c 'blocks=%b bfree=%f bavail=%a files=%c ffree=%d' {mnt})
i=1
while [ $i -le 32 ]; do
  if {bb} true > {mnt}/obj$i; then i=$((i+1)); else echo create_refused_at=$i; break; fi
done
{bb} mkdir {mnt}/dir || echo mkdir_exit=$?
echo objects=$({bb} ls {mnt} | {bb} wc -l)
echo statfs_objects=$({bb} stat -f -c 'files=%c ffree=%d' {mnt})
{bb} rm {mnt}/obj1 && {bb} true > {mnt}/reused && echo reuse=ok
{bb} rm {mnt}/fill
echo statfs_after_release=$({bb} stat -f -c 'blocks=%b bfree=%f bavail=%a files=%c ffree=%d' {mnt})
echo mountinfo=$({bb} grep " {mnt} " /proc/self/mountinfo)
echo done=yes
"#,
        bb = BUSYBOX,
        mnt = mnt.display()
    );
    let plan = busybox_plan(&script)
        // The grant under test: read-write on the FUSE mountpoint itself.
        .filesystem_grant(PathIntent::ReadWrite, &mnt)
        .unwrap()
        // `dd`'s source, and `/proc` so the workload can show its own view
        // of the mount table.
        .filesystem_grant(PathIntent::Read, "/dev/zero")
        .unwrap()
        .filesystem_grant(PathIntent::Read, "/proc")
        .unwrap();

    let captured = launch(&proof, &plan, &containment);
    print_transcript("ceilings", &captured);
    let observed = |key: &str| captured.observed(key);

    assert_eq!(observed("started"), "yes", "workload must have run");
    assert_eq!(observed("done"), "yes", "workload must have finished");
    assert_eq!(captured.code, 0, "stderr={:?}", captured.stderr);

    // Before anything: the ceilings, empty, from inside containment.
    let statfs_before = observed("statfs_before");
    assert_eq!(
        statfs_before,
        format!(
            "bsize=4096 blocks=256 bfree=256 bavail=256 files={ceiling_objects} \
             ffree={ceiling_objects} namelen=255"
        )
    );

    // Bytes: dd stops at exactly the ceiling with ENOSPC, and the file holds
    // exactly the ceiling.
    assert_eq!(observed("dd_exit"), "1");
    assert!(
        captured.stderr.contains("No space left on device"),
        "dd must report ENOSPC, saw {:?}",
        captured.stderr
    );
    assert_eq!(observed("fill_bytes"), ceiling_bytes.to_string());
    assert_eq!(
        observed("statfs_full"),
        format!(
            "blocks=256 bfree=0 bavail=0 files={ceiling_objects} ffree={}",
            ceiling_objects - 1
        )
    );

    // Objects: `fill` is the first; the ceiling admits fifteen more; the
    // sixteenth create and a directory are both EDQUOT.
    assert_eq!(observed("create_refused_at"), ceiling_objects.to_string());
    assert!(
        captured.stderr.contains("Disk quota exceeded"),
        "the shell must report EDQUOT, saw {:?}",
        captured.stderr
    );
    assert_eq!(observed("mkdir_exit"), "1");
    assert_eq!(observed("objects"), ceiling_objects.to_string());
    assert_eq!(
        observed("statfs_objects"),
        format!("files={ceiling_objects} ffree=0")
    );

    // Release: an unlinked object is reusable, and removing the fill file
    // returns every block.
    assert_eq!(observed("reuse"), "ok");
    assert_eq!(
        observed("statfs_after_release"),
        format!("blocks=256 bfree=256 bavail=256 files={ceiling_objects} ffree=1")
    );

    // The workload's own view of the mount table names this crate's subtype
    // and the mount owner's uid.
    let mountinfo = observed("mountinfo");
    assert!(
        mountinfo.contains(&format!("fuse.{FS_SUBTYPE}")),
        "workload must see the FUSE mount, saw {mountinfo:?}"
    );
    assert!(
        mountinfo.contains(&format!(
            "user_id={}",
            mounted.evidence().user_id().unwrap()
        )),
        "workload must see the owner uid, saw {mountinfo:?}"
    );

    containment.dispose(DRAIN_DEADLINE).unwrap();

    // The filesystem's own record, independent of the transcript above.
    let outcome = mounted.unmount().unwrap();
    eprintln!("[contained] outcome:\n{outcome}");
    assert!(outcome.unmount_confirmed);
    assert_eq!(outcome.ledger.refused_bytes, 1);
    assert_eq!(outcome.ledger.refused_objects, 2);
    assert_eq!(outcome.ledger.peak_bytes, ceiling_bytes);
    assert_eq!(outcome.ledger.peak_objects, ceiling_objects);
    assert_eq!(outcome.ledger.used_bytes, 0);
    assert_eq!(outcome.ledger.used_objects, ceiling_objects - 1);
    let first = outcome.ledger.recorded[0];
    assert_eq!(first.resource, Resource::Bytes);
    assert_eq!(first.requested, 4096);
    assert_eq!(first.used, ceiling_bytes);
    assert_eq!(first.ceiling, ceiling_bytes);
    assert!(
        outcome.ledger.recorded[1..]
            .iter()
            .all(|exceedance| exceedance.resource == Resource::Objects
                && exceedance.used == ceiling_objects)
    );
    let before = outcome.statfs_before_unmount.expect("the server was live");
    assert_eq!(before.used_bytes(), 0);
    assert_eq!(before.used_objects(), ceiling_objects - 1);
}

#[test]
fn without_a_grant_on_the_mountpoint_the_fuse_tree_is_denied_before_the_server_sees_it() {
    let Some(proof) = proof_or_not_proven(
        "without_a_grant_on_the_mountpoint_the_fuse_tree_is_denied_before_the_server_sees_it",
    ) else {
        return;
    };
    let temp = TempDir::new("denied");
    let mountpoint = temp.subdir("mnt");
    let elsewhere = temp.subdir("elsewhere");
    let ceilings = Ceilings::new(STATFS_BLOCK_BYTES, 4).unwrap();
    let mounted = MountedTempfs::mount(&proof.fuse, &mountpoint, ceilings).unwrap();
    let mnt = mounted.mountpoint().to_path_buf();
    let containment =
        RunContainment::create(&proof.domain, &run_id("denied"), ContainmentLimits::none())
            .unwrap();

    // The plan grants a sibling directory read-write and the mountpoint
    // nothing. If Landlock did not apply to the FUSE mount, the create would
    // reach the server and the ledger would count it.
    let script = format!(
        r#"
echo started=yes
{bb} true > {elsewhere}/allowed && echo elsewhere=ok
{bb} true > {mnt}/denied; echo create_exit=$?
{bb} ls {mnt}; echo ls_exit=$?
{bb} stat -f -c 'blocks=%b' {mnt}; echo statfs_exit=$?
echo done=yes
"#,
        bb = BUSYBOX,
        mnt = mnt.display(),
        elsewhere = elsewhere.display()
    );
    let plan = busybox_plan(&script)
        .filesystem_grant(PathIntent::ReadWrite, &elsewhere)
        .unwrap();
    let captured = launch(&proof, &plan, &containment);
    print_transcript("denied", &captured);
    let observed = |key: &str| captured.observed(key);

    assert_eq!(observed("started"), "yes");
    assert_eq!(observed("done"), "yes");
    assert_eq!(
        observed("elsewhere"),
        "ok",
        "the granted sibling is writable"
    );
    assert_eq!(observed("create_exit"), "1");
    assert_eq!(observed("ls_exit"), "1");
    assert!(
        captured.stderr.matches("Permission denied").count() >= 2,
        "both the create and the listing must be denied by the Landlock domain, saw {:?}",
        captured.stderr
    );
    // `statfs` is not a path-resolution access Landlock governs, so the
    // workload can still read the ceilings of a mount it cannot touch. That
    // is a Landlock property, recorded rather than hidden.
    assert_eq!(observed("statfs_exit"), "0");

    containment.dispose(DRAIN_DEADLINE).unwrap();
    let outcome = mounted.unmount().unwrap();
    eprintln!("[contained] outcome:\n{outcome}");
    // The server never saw a create: Landlock refused in the workload's own
    // path resolution, before any FUSE request existed.
    assert_eq!(outcome.ledger.peak_objects, 0);
    assert_eq!(outcome.ledger.refused_objects, 0);
    assert_eq!(outcome.ledger.refused_bytes, 0);
    assert!(fs::read_dir(&elsewhere).unwrap().next().is_some());
}

/// The cost of a small write loop from inside containment: the same shell
/// loop against the FUSE mount and against a host directory, each launched
/// through the full boundary, plus an empty launch for the fixed cost.
///
/// A measurement, not an assertion of a bound: the numbers are printed under
/// `--nocapture`, and the checks are that each loop did what it claims.
#[test]
fn overhead_of_a_contained_write_loop() {
    let Some(proof) = proof_or_not_proven("overhead_of_a_contained_write_loop") else {
        return;
    };
    const FILES: u64 = 256;
    let temp = TempDir::new("overhead");
    let mountpoint = temp.subdir("mnt");
    let native = temp.subdir("native");
    let ceilings = Ceilings::new(16 * 1024 * 1024, 4096).unwrap();
    let mounted = MountedTempfs::mount(&proof.fuse, &mountpoint, ceilings).unwrap();
    let mnt = mounted.mountpoint().to_path_buf();

    // A 4 KiB line from the shell's own `echo`, so no process is spawned per
    // file and the loop measures the filesystem rather than fork+exec.
    let loop_script = |dir: &Path| {
        format!(
            r#"
blob=$({bb} head -c 4095 /dev/zero | {bb} tr '\0' x)
i=0
while [ $i -lt {FILES} ]; do echo "$blob" > {dir}/f$i; i=$((i+1)); done
echo done=yes
"#,
            bb = BUSYBOX,
            dir = dir.display()
        )
    };
    let grants = |plan: LaunchPlan| {
        plan.filesystem_grant(PathIntent::ReadWrite, &mnt)
            .unwrap()
            .filesystem_grant(PathIntent::ReadWrite, &native)
            .unwrap()
            .filesystem_grant(PathIntent::Read, "/dev/zero")
            .unwrap()
    };
    let mut results = Vec::new();
    for (label, script) in [
        ("empty", "echo done=yes".to_owned()),
        ("native", loop_script(&native)),
        ("fuse", loop_script(&mnt)),
    ] {
        let containment =
            RunContainment::create(&proof.domain, &run_id(label), ContainmentLimits::none())
                .unwrap();
        let captured = launch(&proof, &grants(busybox_plan(&script)), &containment);
        assert_eq!(captured.code, 0, "{label}: stderr={:?}", captured.stderr);
        assert_eq!(captured.observed("done"), "yes");
        containment.dispose(DRAIN_DEADLINE).unwrap();
        results.push((label, captured.elapsed));
    }
    assert_eq!(fs::read_dir(&native).unwrap().count() as u64, FILES);
    let snapshot = mounted.snapshot();
    assert_eq!(snapshot.used_objects, FILES);
    assert_eq!(snapshot.used_bytes, FILES * 4096);
    for (label, elapsed) in &results {
        eprintln!("[contained] overhead launch {label}: {elapsed:?}");
    }
    mounted.unmount().unwrap();
}
