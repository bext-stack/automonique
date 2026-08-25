// SPDX-License-Identifier: Elastic-2.0

//! Same-uid proofs against a live mount: exact ceilings, kernel readback,
//! clean unmount, the stale mount a crashed server leaves, and the cost of a
//! small write loop.
//!
//! Every mounting test needs `/dev/fuse` and a setuid-root `fusermount3`.
//! Without them a test prints `NOT PROVEN` and passes vacuously, unless
//! `AUTOMONIQUE_REQUIRE_FUSE=1` turns that into a failure so a verifying host
//! cannot skip the proof quietly. The prerequisite test itself runs anywhere.

use automonique_tempfs_quota_spike::{
    Ceilings, DEFAULT_FUSERMOUNT3, FS_SUBTYPE, FusePrerequisites, MountStatus, MountedTempfs,
    PrerequisiteError, Resource, STATFS_BLOCK_BYTES, VerifiedFuse, detach_stale, inspect,
    probe_auto_unmount,
};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const REQUIRE_FUSE_ENV: &str = "AUTOMONIQUE_REQUIRE_FUSE";
const SERVE_BINARY: &str = env!("CARGO_BIN_EXE_automonique-tempfs-quota");
const ENOSPC: i32 = 28;
const ENOTCONN: i32 = 107;
const EDQUOT: i32 = 122;
const SETTLE_DEADLINE: Duration = Duration::from_secs(5);

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "automonique-tempfs-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn mountpoint(&self) -> PathBuf {
        let mountpoint = self.0.join("mnt");
        fs::create_dir(&mountpoint).unwrap();
        mountpoint
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
        Ok(verified) => {
            eprintln!(
                "[tempfs] AVAILABLE  {proof}: {} via {}",
                verified.dev_fuse().display(),
                verified.fusermount().display()
            );
            Some(verified)
        }
        Err(error) => {
            eprintln!("[tempfs] NOT PROVEN {proof}: {error}");
            assert!(
                std::env::var_os(REQUIRE_FUSE_ENV).is_none(),
                "{REQUIRE_FUSE_ENV} is set, so {proof} must run against a usable FUSE \
                 stack, but none was available: {error}"
            );
            None
        }
    }
}

/// Wait for an asynchronous kernel `RELEASE` to reach the ledger.
fn settle(description: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + SETTLE_DEADLINE;
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "{description} did not settle within {SETTLE_DEADLINE:?}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn prerequisites_fail_closed_with_a_typed_reason() {
    let temp = TempDir::new("prereq");
    let absent = temp.path().join("absent");
    let regular = temp.path().join("regular");
    fs::write(&regular, b"not a device").unwrap();

    assert!(matches!(
        FusePrerequisites::at(&absent, DEFAULT_FUSERMOUNT3).verify(),
        Err(PrerequisiteError::DevFuseMissing(_))
    ));
    assert!(matches!(
        FusePrerequisites::at(&regular, DEFAULT_FUSERMOUNT3).verify(),
        Err(PrerequisiteError::DevFuseNotCharacterDevice(_))
    ));
    // `/dev/null` is a character device every uid can open, so the device
    // checks pass and the helper checks are what refuse below.
    assert!(matches!(
        FusePrerequisites::at("/dev/null", &absent).verify(),
        Err(PrerequisiteError::FusermountMissing(_))
    ));
    assert!(matches!(
        FusePrerequisites::at("/dev/null", temp.path()).verify(),
        Err(PrerequisiteError::FusermountNotRegularFile(_))
    ));
    // A file this uid owns is by construction not setuid root.
    assert!(matches!(
        FusePrerequisites::at("/dev/null", &regular).verify(),
        Err(PrerequisiteError::FusermountNotSetuidRoot(_))
    ));
}

#[test]
fn the_mountpoint_is_validated_before_the_helper_runs() {
    let Some(verified) = fuse_or_not_proven("the_mountpoint_is_validated_before_the_helper_runs")
    else {
        return;
    };
    let temp = TempDir::new("mountpoint");
    let ceilings = Ceilings::new(STATFS_BLOCK_BYTES, 1).unwrap();
    let relative = Path::new("relative/path");
    assert!(MountedTempfs::mount(&verified, relative, ceilings).is_err());
    let missing = temp.path().join("missing");
    assert!(MountedTempfs::mount(&verified, &missing, ceilings).is_err());
    let occupied = temp.mountpoint();
    fs::write(occupied.join("entry"), b"x").unwrap();
    assert!(MountedTempfs::mount(&verified, &occupied, ceilings).is_err());
    let file = temp.path().join("file");
    fs::write(&file, b"x").unwrap();
    assert!(MountedTempfs::mount(&verified, &file, ceilings).is_err());
}

#[test]
fn the_ceilings_are_exact_and_read_back_from_the_kernel() {
    let Some(verified) = fuse_or_not_proven("the_ceilings_are_exact_and_read_back_from_the_kernel")
    else {
        return;
    };
    let temp = TempDir::new("exact");
    let mountpoint = temp.mountpoint();
    let ceiling_bytes = 4 * STATFS_BLOCK_BYTES;
    let ceilings = Ceilings::new(ceiling_bytes, 3).unwrap();
    let mounted = MountedTempfs::mount(&verified, &mountpoint, ceilings).unwrap();

    // Mount evidence: the kernel's table names this crate's subtype and this
    // uid, and statfs already reports the ceilings, empty.
    assert_eq!(mounted.mountpoint(), fs::canonicalize(&mountpoint).unwrap());
    let evidence = mounted.evidence();
    assert!(evidence.is_fuse_subtype(FS_SUBTYPE), "{evidence}");
    assert_eq!(
        evidence.user_id(),
        Some(fs::metadata(&mountpoint).unwrap().uid()),
        "{evidence}"
    );
    let at_mount = mounted.statfs_at_mount();
    assert_eq!(at_mount.ceiling_bytes(), ceiling_bytes);
    assert_eq!(at_mount.files, 3);
    assert_eq!(at_mount.used_bytes(), 0);
    eprintln!("[tempfs] evidence: {evidence}");
    eprintln!("[tempfs] statfs at mount: {at_mount}");

    // Bytes: exactly the ceiling is admitted, one byte more is ENOSPC, and
    // nothing of the refused write lands.
    let fill = mountpoint.join("fill");
    let mut file = File::create(&fill).unwrap();
    file.write_all(&vec![b'a'; (ceiling_bytes - 1) as usize])
        .unwrap();
    file.write_all(b"b")
        .expect("exactly the ceiling is admitted");
    let refused = file.write_all(b"c").unwrap_err();
    assert_eq!(refused.raw_os_error(), Some(ENOSPC), "{refused}");
    drop(file);
    assert_eq!(fs::metadata(&fill).unwrap().len(), ceiling_bytes);
    let statfs = mounted.statfs().unwrap();
    eprintln!("[tempfs] statfs full: {statfs}");
    assert_eq!(statfs.blocks_available, 0);
    assert_eq!(statfs.used_bytes(), ceiling_bytes);

    // Objects: the file is one; two more are admitted; the fourth is EDQUOT
    // whether it is a file or a directory.
    File::create(mountpoint.join("two")).unwrap();
    File::create(mountpoint.join("three")).unwrap();
    let refused = File::create(mountpoint.join("four")).unwrap_err();
    assert_eq!(refused.raw_os_error(), Some(EDQUOT), "{refused}");
    let refused = fs::create_dir(mountpoint.join("dir")).unwrap_err();
    assert_eq!(refused.raw_os_error(), Some(EDQUOT), "{refused}");
    let statfs = mounted.statfs().unwrap();
    assert_eq!(statfs.files_free, 0);
    assert_eq!(statfs.used_objects(), 3);

    // Releasing returns capacity: unlink frees an object, truncate frees
    // bytes, and both are visible through statfs at once.
    fs::remove_file(mountpoint.join("two")).unwrap();
    fs::create_dir(mountpoint.join("dir")).unwrap();
    OpenOptions::new()
        .write(true)
        .open(&fill)
        .unwrap()
        .set_len(STATFS_BLOCK_BYTES)
        .unwrap();
    let statfs = mounted.statfs().unwrap();
    assert_eq!(statfs.used_bytes(), STATFS_BLOCK_BYTES);
    assert_eq!(statfs.blocks_available, 3);

    // An unlinked-but-open file still costs its bytes until the last
    // descriptor closes: the storage is still consumed. The kernel sends the
    // final RELEASE asynchronously, so the ledger is polled rather than read
    // once.
    let held = File::open(&fill).unwrap();
    fs::remove_file(&fill).unwrap();
    assert_eq!(mounted.snapshot().used_bytes, STATFS_BLOCK_BYTES);
    drop(held);
    settle("release of an unlinked file", || {
        mounted.snapshot().used_bytes == 0
    });

    // Rename across directories keeps the count and the bytes where they are.
    fs::rename(mountpoint.join("three"), mountpoint.join("dir/three")).unwrap();
    assert_eq!(mounted.snapshot().used_objects, 2);

    // Unmount: a typed outcome assembled from the ledger and the kernel.
    let outcome = mounted.unmount().unwrap();
    eprintln!("[tempfs] outcome:\n{outcome}");
    assert!(outcome.unmount_confirmed);
    assert_eq!(outcome.ledger.refused_bytes, 1);
    assert_eq!(outcome.ledger.refused_objects, 2);
    assert_eq!(outcome.ledger.peak_bytes, ceiling_bytes);
    assert_eq!(outcome.ledger.peak_objects, 3);
    assert_eq!(outcome.ledger.used_objects, 2);
    assert_eq!(outcome.ledger.recorded[0].resource, Resource::Bytes);
    assert_eq!(outcome.ledger.recorded[0].requested, 1);
    assert_eq!(outcome.ledger.recorded[0].used, ceiling_bytes);
    assert_eq!(outcome.ledger.recorded[1].resource, Resource::Objects);
    assert_eq!(outcome.ledger.recorded[2].resource, Resource::Objects);
    let before = outcome.statfs_before_unmount.expect("the server was live");
    assert_eq!(before.used_objects(), 2);
    assert_eq!(before.used_bytes(), 0);
    assert_eq!(
        inspect(&mountpoint, FS_SUBTYPE).unwrap(),
        MountStatus::NotMounted
    );
    // The directory underneath is empty and ordinary again.
    assert!(fs::read_dir(&mountpoint).unwrap().next().is_none());
}

#[test]
fn dropping_the_mount_detaches_it() {
    let Some(verified) = fuse_or_not_proven("dropping_the_mount_detaches_it") else {
        return;
    };
    let temp = TempDir::new("drop");
    let mountpoint = temp.mountpoint();
    let ceilings = Ceilings::new(STATFS_BLOCK_BYTES, 1).unwrap();
    let mounted = MountedTempfs::mount(&verified, &mountpoint, ceilings).unwrap();
    assert!(matches!(
        inspect(&mountpoint, FS_SUBTYPE).unwrap(),
        MountStatus::Live { .. }
    ));
    drop(mounted);
    assert_eq!(
        inspect(&mountpoint, FS_SUBTYPE).unwrap(),
        MountStatus::NotMounted
    );
}

#[test]
fn a_killed_server_leaves_a_detectable_stale_mount_that_detach_clears() {
    let Some(verified) =
        fuse_or_not_proven("a_killed_server_leaves_a_detectable_stale_mount_that_detach_clears")
    else {
        return;
    };
    let temp = TempDir::new("crash");
    let mountpoint = temp.mountpoint();

    // A separate server process, so it can die without taking the test with
    // it — the same shape as a supervisor crashing under a run.
    let mut server = Command::new(SERVE_BINARY)
        .arg("serve")
        .arg(&mountpoint)
        .arg((4 * STATFS_BLOCK_BYTES).to_string())
        .arg("3")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("serve binary spawns");
    let mut lines = BufReader::new(server.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        let read = lines.read_line(&mut line).unwrap();
        assert!(read > 0, "serve exited before reporting ready");
        eprint!("[tempfs] serve: {line}");
        if line.trim() == "ready=yes" {
            break;
        }
    }
    fs::write(mountpoint.join("before"), b"x").unwrap();
    assert!(matches!(
        inspect(&mountpoint, FS_SUBTYPE).unwrap(),
        MountStatus::Live { .. }
    ));

    server.kill().unwrap();
    let status = server.wait().unwrap();
    assert!(!status.success());

    // The kernel keeps the mount but has no server behind it: every access
    // answers ENOTCONN, and the table still names this crate's subtype.
    let stale = inspect(&mountpoint, FS_SUBTYPE).unwrap();
    eprintln!("[tempfs] after SIGKILL: {stale}");
    match &stale {
        MountStatus::Disconnected { evidence, errno } => {
            assert!(evidence.is_fuse_subtype(FS_SUBTYPE));
            assert_eq!(*errno as i32, ENOTCONN);
        }
        other => panic!("expected a disconnected mount, saw {other}"),
    }
    let refused = fs::write(mountpoint.join("after"), b"x").unwrap_err();
    assert_eq!(refused.raw_os_error(), Some(ENOTCONN), "{refused}");

    // The owner's uid can always detach its own stale mount.
    let cleared = detach_stale(&verified, &mountpoint).unwrap();
    assert_eq!(cleared, MountStatus::NotMounted);
    assert!(fs::read_dir(&mountpoint).unwrap().next().is_none());
}

/// `auto_unmount` is libfuse's own answer to a dying owner. Whether it works
/// for a same-uid mount without `allow_other` is a fact about this host's
/// helper, measured here and recorded in the README rather than assumed by
/// the design.
#[test]
fn auto_unmount_is_measured_rather_than_assumed() {
    let Some(verified) = fuse_or_not_proven("auto_unmount_is_measured_rather_than_assumed") else {
        return;
    };
    let temp = TempDir::new("auto-unmount");
    let mountpoint = temp.mountpoint();
    let probe = probe_auto_unmount(&verified, &mountpoint).unwrap();
    eprintln!("[tempfs] {probe}");
    assert!(
        probe.mounted,
        "the helper must accept auto_unmount: {probe}"
    );
    // Whatever the host did, the probe leaves nothing behind.
    assert_eq!(
        inspect(&mountpoint, FS_SUBTYPE).unwrap(),
        MountStatus::NotMounted
    );
    assert!(fs::read_dir(&mountpoint).unwrap().next().is_none());
}

/// The cost of a small write loop, in-process and uncontained: the FUSE
/// round trip alone, against the same loop on the host filesystem.
///
/// A measurement, not an assertion of a bound: it prints the numbers under
/// `--nocapture`, and only checks that both loops did what they claim.
#[test]
fn overhead_of_a_small_write_loop() {
    let Some(verified) = fuse_or_not_proven("overhead_of_a_small_write_loop") else {
        return;
    };
    const FILES: usize = 256;
    const APPENDS: usize = 1024;
    const CHUNK: usize = 4096;

    let temp = TempDir::new("overhead");
    let mountpoint = temp.mountpoint();
    let native = temp.path().join("native");
    fs::create_dir(&native).unwrap();
    let ceilings = Ceilings::new(16 * 1024 * 1024, 4096).unwrap();
    let mounted = MountedTempfs::mount(&verified, &mountpoint, ceilings).unwrap();

    let create_loop = |dir: &Path| -> Duration {
        let chunk = vec![b'x'; CHUNK];
        let start = Instant::now();
        for index in 0..FILES {
            let mut file = File::create(dir.join(format!("f{index}"))).unwrap();
            file.write_all(&chunk).unwrap();
        }
        start.elapsed()
    };
    let append_loop = |dir: &Path| -> Duration {
        let chunk = vec![b'y'; CHUNK];
        let mut file = File::create(dir.join("append")).unwrap();
        let start = Instant::now();
        for _ in 0..APPENDS {
            file.write_all(&chunk).unwrap();
        }
        start.elapsed()
    };

    let native_create = create_loop(&native);
    let fuse_create = create_loop(&mountpoint);
    let native_append = append_loop(&native);
    let fuse_append = append_loop(&mountpoint);

    assert_eq!(fs::read_dir(&native).unwrap().count(), FILES + 1);
    assert_eq!(mounted.snapshot().used_objects as usize, FILES + 1);
    assert_eq!(
        mounted.snapshot().used_bytes as usize,
        FILES * CHUNK + APPENDS * CHUNK
    );

    let ratio = |fuse: Duration, native: Duration| {
        fuse.as_secs_f64() / native.as_secs_f64().max(f64::EPSILON)
    };
    eprintln!(
        "[tempfs] overhead create+write+close x{FILES} ({CHUNK} B each): fuse={fuse_create:?} \
         native={native_create:?} ratio={:.1}",
        ratio(fuse_create, native_create)
    );
    eprintln!(
        "[tempfs] overhead append x{APPENDS} ({CHUNK} B each): fuse={fuse_append:?} \
         native={native_append:?} ratio={:.1}",
        ratio(fuse_append, native_append)
    );
    mounted.unmount().unwrap();
}
