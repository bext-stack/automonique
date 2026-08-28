// SPDX-License-Identifier: Elastic-2.0

//! Delegated proof for the bounded runner primitive that mounts temporary
//! storage inside a separated workload's user+mount namespace.
//!
//! This does not remove the daemon admission conflict. It proves the composed
//! kernel path that must replace the supervisor-owned mount first: the helper
//! opens `/dev/fuse` and mounts as namespace root, the supervisor serves the
//! transferred descriptor, the switched workload writes and reads its TMPDIR,
//! and restart readback comes from the filesystem ledger checkpoint.

use automonique_runner::filesystem::PathIntent;
use automonique_runner::identity;
use automonique_runner::{
    Checkpoint, CheckpointPhase, ContainmentDomain, ContainmentError, ContainmentLimits,
    FusePrerequisites, LaunchPlan, RunContainment, STATFS_BLOCK_BYTES, StatfsReadback,
    StdoutCapture, TemporaryStorageBudget, spawn_sandboxed_with_namespaced_temporary_storage,
};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const HELPER: &str = env!("CARGO_BIN_EXE_automonique-launch-enter");
const BUSYBOX: &str = "/usr/bin/busybox";
const REQUIRE_ENFORCED_ENV: &str = "AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "automonique-namespaced-tempfs-{}-{serial}",
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

fn not_proven(reason: impl std::fmt::Display) {
    eprintln!("[namespaced-tempfs] NOT PROVEN: {reason}");
    assert!(
        std::env::var_os(REQUIRE_ENFORCED_ENV).is_none(),
        "{REQUIRE_ENFORCED_ENV} requires the delegated proof: {reason}"
    );
}

fn prerequisites() -> Option<ContainmentDomain> {
    let domain = match ContainmentDomain::discover() {
        Ok(domain) => domain,
        Err(
            error @ (ContainmentError::DomainNotDelegated
            | ContainmentError::NotUnifiedCgroupV2
            | ContainmentError::MissingAtomicKill),
        ) => {
            not_proven(error);
            return None;
        }
        Err(error) => panic!("unexpected containment refusal: {error}"),
    };
    if !Path::new(BUSYBOX).is_file() {
        not_proven("static busybox is unavailable");
        return None;
    }
    if let Err(error) = FusePrerequisites::host_default().verify() {
        not_proven(error);
        return None;
    }
    if let Err(error) = identity::probe_with_launch_helper(Path::new(HELPER)) {
        not_proven(format!("workload identity unavailable: {error}"));
        return None;
    }
    Some(domain)
}

fn digest(path: &Path) -> String {
    format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
}

#[test]
fn separated_workload_uses_in_namespace_tempfs_and_restart_reads_exact_ledger() {
    let Some(domain) = prerequisites() else {
        return;
    };
    let temporary = TempDir::new();
    let mountpoint = temporary.subdir("tmp");
    let checkpoint = temporary.0.join("tempfs-ledger");
    let budget = TemporaryStorageBudget::from_bytes(2 * STATFS_BLOCK_BYTES).unwrap();
    let script = format!(
        "set -e; printf roundtrip > \"$TMPDIR/exact\"; \
         test \"$({bb} cat \"$TMPDIR/exact\")\" = roundtrip; \
         {bb} rm \"$TMPDIR/exact\"; \
         {bb} dd if=/dev/zero of=\"$TMPDIR/full\" bs=4096 count=2; \
         if printf x >> \"$TMPDIR/full\"; then exit 91; fi; \
         printf composed-ready; {bb} sleep 1; printf composed-ok",
        bb = BUSYBOX
    );
    let plan = LaunchPlan::new(BUSYBOX, digest(Path::new(BUSYBOX)))
        .unwrap()
        .argument("sh")
        .unwrap()
        .argument("-c")
        .unwrap()
        .argument(script)
        .unwrap()
        .filesystem_grant(PathIntent::ReadExecute, BUSYBOX)
        .unwrap()
        .filesystem_grant(PathIntent::Read, "/dev/null")
        .unwrap()
        .filesystem_grant(PathIntent::Read, "/dev/zero")
        .unwrap()
        .filesystem_grant(PathIntent::ReadWrite, &mountpoint)
        .unwrap()
        .environment("TMPDIR", mountpoint.as_os_str().as_encoded_bytes())
        .unwrap()
        .separate_workload_identity()
        .unwrap();
    let run_id = format!(
        "nstmp{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    );
    let containment = RunContainment::create(&domain, &run_id, ContainmentLimits::none()).unwrap();
    let mut child = spawn_sandboxed_with_namespaced_temporary_storage(
        Path::new(HELPER),
        &plan,
        &containment,
        &mountpoint,
        budget,
        &checkpoint,
        StdoutCapture::Piped,
    )
    .unwrap();
    let mut stdout_pipe = child.take_stdout().unwrap();
    let mut ready = [0_u8; 14];
    stdout_pipe.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"composed-ready");
    child.checkpoint_temporary_storage().unwrap();
    let live = Checkpoint::read(&checkpoint).unwrap();
    assert_eq!(live.phase, CheckpointPhase::Live);
    assert_eq!(live.snapshot.used_bytes, budget.bytes());
    assert_eq!(live.snapshot.refused_bytes, 1);

    let mut stdout = String::new();
    stdout_pipe.read_to_string(&mut stdout).unwrap();
    let (status, outcome) = child.wait().unwrap();
    assert!(status.success(), "workload failed with {status}");
    assert_eq!(stdout, "composed-ok");
    assert!(outcome.unmount_confirmed);
    assert_eq!(outcome.ledger.used_bytes, budget.bytes());
    assert_eq!(outcome.ledger.used_objects, 1);
    assert_eq!(outcome.ledger.peak_bytes, budget.bytes());
    assert_eq!(outcome.ledger.refused_bytes, 1);
    assert_eq!(outcome.statfs_from_ledger.used_bytes(), budget.bytes());
    assert_eq!(outcome.statfs_from_ledger.used_objects(), 1);

    // A new reader with no process-local state reconstructs the same usage
    // from the private, schema-checked checkpoint.
    let restarted = Checkpoint::read(&checkpoint).unwrap();
    assert_eq!(restarted.phase, CheckpointPhase::Final);
    assert_eq!(restarted.snapshot, outcome.ledger);
    assert_eq!(
        StatfsReadback::from_ledger(&restarted.snapshot).unwrap(),
        outcome.statfs_from_ledger
    );
    assert_eq!(
        restarted
            .final_record
            .as_ref()
            .and_then(|record| record.statfs_before_unmount),
        Some(outcome.statfs_from_ledger)
    );
    containment.dispose(Duration::from_secs(10)).unwrap();
}
