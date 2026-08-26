// SPDX-License-Identifier: Elastic-2.0

//! Same-uid proofs that the temporary-storage FUSE filesystem enforces exact
//! byte and object ceilings, reads them back through the kernel, publishes the
//! first refusal, survives a supervisor crash through a checkpoint, and leaves
//! a detachable stale mount its reaper clears.
//!
//! These do not need a delegated cgroup domain: the mount owner is this uid, so
//! `std::fs` reaches the tree directly. They need `/dev/fuse` and a setuid
//! `fusermount3`. Without them each test prints `NOT PROVEN` and passes
//! vacuously, and `AUTOMONIQUE_REQUIRE_FUSE=1` turns that into a failure so a
//! host expected to prove enforcement cannot skip it quietly.
//!
//! ```sh
//! AUTOMONIQUE_REQUIRE_FUSE=1 cargo test -p automonique-runner \
//!   --test tempfs_mount -- --test-threads=1 --nocapture
//! ```

use automonique_runner::tempfs::{FusePrerequisites, MountedTempfs, reap_stale_mounts};
use automonique_runner::tempfs_checkpoint::{Checkpoint, Phase};
use automonique_runner::{
    CheckpointPhase, FS_SUBTYPE, STATFS_BLOCK_BYTES, TemporaryStorageBudget,
    TemporaryStorageResource, VerifiedFuse, abort_connection,
};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const REQUIRE_FUSE_ENV: &str = "AUTOMONIQUE_REQUIRE_FUSE";
const DEADLINE: Duration = Duration::from_secs(5);

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "automonique-tempfs-mount-{label}-{}-{serial}",
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

/// The verified FUSE stack, or a loud, contract-checked degradation.
fn fuse_or_not_proven(proof: &str) -> Option<VerifiedFuse> {
    match FusePrerequisites::host_default().verify() {
        Ok(verified) => Some(verified),
        Err(error) => {
            eprintln!("[tempfs] NOT PROVEN {proof}: {error}");
            assert!(
                std::env::var_os(REQUIRE_FUSE_ENV).is_none(),
                "{REQUIRE_FUSE_ENV} is set, so {proof} must run, but FUSE is unavailable: {error}"
            );
            None
        }
    }
}

fn budget(blocks: u64, objects: u64) -> TemporaryStorageBudget {
    TemporaryStorageBudget::new(blocks * STATFS_BLOCK_BYTES, objects).unwrap()
}

fn is_enospc(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(nix::errno::Errno::ENOSPC as i32)
}

fn is_edquot(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(nix::errno::Errno::EDQUOT as i32)
}

#[test]
fn the_mount_reads_back_exactly_the_budget_and_the_byte_ceiling_is_exact() {
    let Some(verified) =
        fuse_or_not_proven("the_mount_reads_back_exactly_the_budget_and_the_byte_ceiling_is_exact")
    else {
        return;
    };
    let temp = TempDir::new("bytes");
    let mountpoint = temp.subdir("tmp");
    // Four blocks, four objects.
    let mounted = MountedTempfs::mount(&verified, &mountpoint, budget(4, 4)).unwrap();

    // The mount table names this crate's subtype, owned by this uid.
    let evidence = mounted.evidence();
    assert!(evidence.is_fuse_subtype(FS_SUBTYPE), "{evidence}");
    assert_eq!(evidence.user_id(), Some(nix::unistd::getuid().as_raw()));

    // `statfs` at mount reports the ceilings, empty.
    let at_mount = mounted.statfs_at_mount();
    assert_eq!(at_mount.ceiling_bytes(), 4 * STATFS_BLOCK_BYTES);
    assert_eq!(at_mount.files, 4);
    assert_eq!(at_mount.used_bytes(), 0);
    assert_eq!(at_mount.used_objects(), 0);

    // Write exactly the byte ceiling into one file, then one more byte fails
    // with ENOSPC and the ledger records it.
    let file_path = mountpoint.join("fill");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&file_path)
        .unwrap();
    file.write_all(&vec![0u8; (4 * STATFS_BLOCK_BYTES) as usize])
        .expect("exactly the ceiling is admitted");
    file.flush().unwrap();
    let refused = file
        .write_all(&[0u8])
        .expect_err("one byte past the ceiling");
    assert!(is_enospc(&refused), "expected ENOSPC, got {refused:?}");

    let channel = mounted.exceedance_channel();
    let first = channel.first().expect("the first refusal was published");
    assert_eq!(first.resource, TemporaryStorageResource::Bytes);
    assert_eq!(first.ceiling, 4 * STATFS_BLOCK_BYTES);

    // The kernel readback agrees the filesystem is full.
    let full = automonique_runner::tempfs_readback::statfs_readback(&mountpoint).unwrap();
    assert_eq!(full.blocks_free, 0);
    assert_eq!(full.used_bytes(), 4 * STATFS_BLOCK_BYTES);

    // Production kills and drains the run tree before reconcile, so no
    // descriptor is open when the non-lazy unmount runs; the test drops its
    // own handle to match that ordering.
    drop(file);
    let outcome = mounted.reconcile(DEADLINE).unwrap();
    assert!(outcome.unmount_confirmed);
    assert!(!outcome.aborted);
    assert_eq!(outcome.ledger.refused_bytes, 1);
    assert_eq!(outcome.ledger.peak_bytes, 4 * STATFS_BLOCK_BYTES);
    let before = outcome
        .statfs_before_unmount
        .expect("the server answered the reconcile readback");
    assert_eq!(before.used_bytes(), 4 * STATFS_BLOCK_BYTES);
}

#[test]
fn the_object_ceiling_is_exact_and_edquot_beyond_it() {
    let Some(verified) = fuse_or_not_proven("the_object_ceiling_is_exact_and_edquot_beyond_it")
    else {
        return;
    };
    let temp = TempDir::new("objects");
    let mountpoint = temp.subdir("tmp");
    // Plenty of bytes, three objects.
    let mounted = MountedTempfs::mount(&verified, &mountpoint, budget(64, 3)).unwrap();

    for index in 0..3 {
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(mountpoint.join(format!("obj{index}")))
            .expect("each object up to the ceiling is admitted");
    }
    let refused = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(mountpoint.join("obj3"))
        .expect_err("the fourth object crosses the ceiling");
    assert!(is_edquot(&refused), "expected EDQUOT, got {refused:?}");
    // A directory is refused the same way.
    let refused_dir = fs::create_dir(mountpoint.join("dir")).expect_err("a directory too");
    assert!(
        is_edquot(&refused_dir),
        "expected EDQUOT, got {refused_dir:?}"
    );

    let statfs = automonique_runner::tempfs_readback::statfs_readback(&mountpoint).unwrap();
    assert_eq!(statfs.files_free, 0);
    assert_eq!(statfs.used_objects(), 3);

    let outcome = mounted.reconcile(DEADLINE).unwrap();
    assert_eq!(outcome.ledger.refused_objects, 2);
    assert_eq!(outcome.ledger.peak_objects, 3);
    assert_eq!(
        outcome.ledger.first_exceedance().unwrap().resource,
        TemporaryStorageResource::Objects
    );
}

#[test]
fn an_oversized_single_write_is_refused_whole_and_charges_nothing() {
    let Some(verified) =
        fuse_or_not_proven("an_oversized_single_write_is_refused_whole_and_charges_nothing")
    else {
        return;
    };
    let temp = TempDir::new("oversized");
    let mountpoint = temp.subdir("tmp");
    // Two blocks. One write of three blocks in a single buffer fits in one FUSE
    // request (well under `max_write`), so it is one reservation: it crosses
    // the ceiling and is refused whole, charging nothing.
    let mounted = MountedTempfs::mount(&verified, &mountpoint, budget(2, 4)).unwrap();
    let path = mountpoint.join("big");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .unwrap();
    let refused = file
        .write_all(&vec![0u8; (3 * STATFS_BLOCK_BYTES) as usize])
        .expect_err("a single oversized write is refused whole");
    assert!(is_enospc(&refused), "expected ENOSPC, got {refused:?}");
    file.flush().ok();

    // Nothing was charged: the file is empty and the readback is untouched.
    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.len(), 0, "a refused request writes no bytes");
    let statfs = automonique_runner::tempfs_readback::statfs_readback(&mountpoint).unwrap();
    // Only the empty file's object is charged; no bytes are.
    assert_eq!(statfs.used_bytes(), 0);
    assert_eq!(statfs.used_objects(), 1);

    drop(file);
    mounted.reconcile(DEADLINE).unwrap();
}

#[test]
fn sequential_writes_each_land_whole_or_fail_whole() {
    let Some(verified) = fuse_or_not_proven("sequential_writes_each_land_whole_or_fail_whole")
    else {
        return;
    };
    let temp = TempDir::new("sequential");
    let mountpoint = temp.subdir("tmp");
    // Two blocks. Three block-sized writes at successive offsets: the first two
    // land whole, the third crosses the ceiling and fails whole, leaving the
    // file at exactly the ceiling — a block boundary, nothing partial.
    let mounted = MountedTempfs::mount(&verified, &mountpoint, budget(2, 4)).unwrap();
    let path = mountpoint.join("seq");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .unwrap();
    let block = vec![0u8; STATFS_BLOCK_BYTES as usize];
    file.write_all(&block).expect("first block lands whole");
    file.write_all(&block).expect("second block lands whole");
    let refused = file.write_all(&block).expect_err("third block fails whole");
    assert!(is_enospc(&refused), "expected ENOSPC, got {refused:?}");
    file.flush().ok();

    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(
        metadata.len(),
        2 * STATFS_BLOCK_BYTES,
        "the file ends on the ceiling's block boundary, with no partial write"
    );
    drop(file);
    mounted.reconcile(DEADLINE).unwrap();
}

#[test]
fn a_checkpoint_survives_a_supervisor_crash_and_the_reaper_detaches_the_stale_mount() {
    let Some(verified) = fuse_or_not_proven(
        "a_checkpoint_survives_a_supervisor_crash_and_the_reaper_detaches_the_stale_mount",
    ) else {
        return;
    };
    // The reaper's shape: a mountpoint at `<runs_root>/<run_id>/tmp` and its
    // checkpoint at `<runs_root>/<run_id>/tempfs-ledger`.
    let temp = TempDir::new("reaper");
    let runs_root = temp.subdir("runs");
    let run_dir = runs_root.join("run-crash");
    fs::create_dir(&run_dir).unwrap();
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let mountpoint = run_dir.join("tmp");
    fs::create_dir(&mountpoint).unwrap();
    let checkpoint_path = run_dir.join("tempfs-ledger");

    let mut mounted = MountedTempfs::mount(&verified, &mountpoint, budget(8, 8))
        .unwrap()
        .with_checkpoint(&checkpoint_path)
        .unwrap();
    // Consume some budget, then checkpoint it — the record a crash must keep.
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(mountpoint.join("obj0"))
        .unwrap()
        .write_all(&vec![0u8; STATFS_BLOCK_BYTES as usize])
        .unwrap();
    mounted.checkpoint(Phase::Live).unwrap();

    // Simulate the supervisor crashing: abort the FUSE connection (which the
    // owner uid may always do through `fusectl`), then forget the handle so its
    // Drop does not clean up — exactly the stale ENOTCONN mount a SIGKILLed
    // supervisor leaves. `auto_unmount` does not clear it on this host.
    let evidence = mounted.evidence().clone();
    abort_connection(&evidence).unwrap();
    std::mem::forget(mounted);

    // The mount is now disconnected: access answers ENOTCONN, not a hang.
    let stale = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(mountpoint.join("after-crash"))
        .expect_err("a disconnected mount refuses further writes");
    assert_eq!(
        stale.raw_os_error(),
        Some(nix::errno::Errno::ENOTCONN as i32),
        "a crashed supervisor's mount answers ENOTCONN"
    );

    // The reaper finds this uid's disconnected mount under the runs root,
    // detaches it, and reads back the checkpoint the dead supervisor wrote.
    let reaped = reap_stale_mounts(&verified, &runs_root, DEADLINE).unwrap();
    let ours = reaped
        .iter()
        .find(|entry| entry.run_id == "run-crash")
        .expect("the stale mount is reaped");
    assert!(ours.detached, "the reaper must detach the stale mount");
    assert_eq!(ours.mountpoint, fs::canonicalize(&mountpoint).unwrap());
    let checkpoint = ours
        .checkpoint
        .as_ref()
        .expect("the checkpoint survived the crash");
    assert_eq!(checkpoint.phase, CheckpointPhase::Live);
    assert_eq!(checkpoint.snapshot.used_objects, 1);
    assert_eq!(checkpoint.snapshot.used_bytes, STATFS_BLOCK_BYTES);

    // The reaper left the directory an ordinary empty directory again.
    assert!(fs::read_dir(&mountpoint).unwrap().next().is_none());

    // And the checkpoint on disk is re-readable independently.
    let on_disk = Checkpoint::read(&checkpoint_path).unwrap();
    assert_eq!(on_disk.snapshot.used_bytes, STATFS_BLOCK_BYTES);
}

#[test]
fn a_reconcile_writes_a_final_checkpoint() {
    let Some(verified) = fuse_or_not_proven("a_reconcile_writes_a_final_checkpoint") else {
        return;
    };
    let temp = TempDir::new("final");
    let run_dir = temp.subdir("run");
    let mountpoint = run_dir.join("tmp");
    fs::create_dir(&mountpoint).unwrap();
    let checkpoint_path = run_dir.join("tempfs-ledger");
    let mounted = MountedTempfs::mount(&verified, &mountpoint, budget(4, 4))
        .unwrap()
        .with_checkpoint(&checkpoint_path)
        .unwrap();
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(mountpoint.join("obj0"))
        .unwrap();
    let outcome = mounted.reconcile(DEADLINE).unwrap();
    assert!(outcome.unmount_confirmed);

    let checkpoint = Checkpoint::read(&checkpoint_path).unwrap();
    assert_eq!(checkpoint.phase, CheckpointPhase::Final);
    let record = checkpoint
        .final_record
        .expect("a final checkpoint has a record");
    assert!(record.unmount_confirmed);
    assert!(!record.aborted);
    assert!(record.statfs_before_unmount.is_some());
}
