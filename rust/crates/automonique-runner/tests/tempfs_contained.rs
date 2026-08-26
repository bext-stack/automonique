// SPDX-License-Identifier: Elastic-2.0

//! The composed proof: a busybox workload launched through the runner's real
//! direct-process backend — cgroup containment, descriptor closure, the
//! Landlock filesystem allowlist carrying a read-write grant on the FUSE
//! mountpoint, TCP denial and the syscall filter — writes past its
//! temporary-storage budget, is contained the first time the ledger refuses a
//! write, and terminates with [`ExecutionOutcome::TemporaryStorageExceeded`].
//! The filesystem's own `statfs`, read by the supervisor after the tree is
//! disposed, is the kernel evidence that the ceiling held.
//!
//! It needs a delegated cgroup v2 domain, the built entry helper, and a usable
//! FUSE stack; without any it prints `NOT PROVEN` and passes vacuously, and
//! `AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1` turns that into a failure:
//!
//! ```sh
//! (cd rust && cargo build -p automonique-runner --bin automonique-launch-enter)
//! cargo test -p automonique-runner --test tempfs_contained --no-run
//! systemd-run --user --scope -p Delegate=yes --quiet \
//!   --setenv=XDG_RUNTIME_DIR=/run/user/$(id -u) \
//!   --setenv=AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1 \
//!   "$(ls -t rust/target/debug/deps/tempfs_contained-* | grep -v '\.d$' | head -1)" \
//!   --test-threads=1 --nocapture
//! ```

use automonique_protocol::event::{EventKind as FrameKind, RetryCategory, RetryContext};
use automonique_protocol::progress_api::{ProgressFrame, ProgressText};
use automonique_runner::backend::{
    DirectProcessBackend, ExecutionOutcome, TEMPORARY_STORAGE_EXCEEDED_WARNING,
};
use automonique_runner::filesystem::PathIntent;
use automonique_runner::identity::{self, WorkloadIdentity};
use automonique_runner::tempfs::{FusePrerequisites, MountedTempfs, WorkloadTempfs};
use automonique_runner::tempfs_readback::mount_evidence;
use automonique_runner::{
    CancellationToken, Checkpoint, CheckpointPhase, ContainmentDomain, ContainmentError,
    ContainmentLimits, Event, EventKind, LaunchPlan, STATFS_BLOCK_BYTES, Spool,
    TemporaryStorageBudget, TemporaryStorageResource, VerifiedFuse,
};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const HELPER: &str = env!("CARGO_BIN_EXE_automonique-launch-enter");
const BUSYBOX: &str = "/usr/bin/busybox";
const REQUIRE_ENFORCED_ENV: &str = "AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT";
const READBACK_DEADLINE: Duration = Duration::from_secs(5);
const RUN_DEADLINE: Duration = Duration::from_secs(30);

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
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
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
    format!("tc{}-{label}-{serial}", std::process::id())
}

fn busybox_sha256() -> String {
    format!("{:x}", Sha256::digest(fs::read(BUSYBOX).unwrap()))
}

struct Proof {
    domain: ContainmentDomain,
    fuse: VerifiedFuse,
}

fn proof_or_not_proven(proof: &str) -> Option<Proof> {
    let required = std::env::var_os(REQUIRE_ENFORCED_ENV).is_some();
    let not_proven = |reason: String| {
        eprintln!("[tempfs-contained] NOT PROVEN {proof}: {reason}");
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
    let fuse = match FusePrerequisites::host_default().verify() {
        Ok(fuse) => fuse,
        Err(error) => {
            not_proven(format!("FUSE unavailable: {error}"));
            return None;
        }
    };
    eprintln!(
        "[tempfs-contained] ENFORCED {proof}: domain {}",
        domain.root().display()
    );
    Some(Proof { domain, fuse })
}

/// The same gate, plus a host that can actually separate a workload identity.
///
/// Both features have to be real for the composed proof to mean anything: a
/// host that cannot mount proves nothing about the budget, and a host that
/// cannot separate proves nothing about the composition.
fn separated_proof_or_not_proven(proof: &str) -> Option<(Proof, WorkloadIdentity)> {
    let required = std::env::var_os(REQUIRE_ENFORCED_ENV).is_some();
    let base = proof_or_not_proven(proof)?;
    match identity::probe_with_launch_helper(Path::new(HELPER)) {
        Ok(identity) => {
            eprintln!("[tempfs-contained] ENFORCED {proof}: identity {identity}");
            Some((base, identity))
        }
        Err(denial) => {
            eprintln!("[tempfs-contained] NOT PROVEN {proof}: identity unavailable: {denial}");
            assert!(
                !required,
                "{REQUIRE_ENFORCED_ENV} is set, so {proof} must run, but the workload identity \
                 is unavailable: {denial}"
            );
            None
        }
    }
}

#[test]
fn a_contained_workload_that_overflows_its_budget_is_killed_with_a_typed_outcome() {
    let Some(proof) = proof_or_not_proven(
        "a_contained_workload_that_overflows_its_budget_is_killed_with_a_typed_outcome",
    ) else {
        return;
    };
    let temp = TempDir::new("overflow");
    let run_root = temp.subdir("run");
    let mountpoint = run_root.join("tmp");
    fs::create_dir(&mountpoint).unwrap();
    let spool_root = temp.subdir("spool");

    // Eight blocks of scratch, eight objects.
    let budget = TemporaryStorageBudget::new(8 * STATFS_BLOCK_BYTES, 8).unwrap();
    let mounted = MountedTempfs::mount(&proof.fuse, &mountpoint, budget)
        .unwrap()
        .with_checkpoint(run_root.join("tempfs-ledger"))
        .unwrap();
    let mnt = mounted.mountpoint().to_path_buf();

    // The workload writes far past the ceiling into $TMPDIR — the grant and the
    // variable are exactly what admission attaches — then sleeps, so it is
    // still alive when the supervisor observes the first refusal and kills it.
    // Without the sleep the workload could exit on its own before the poll and
    // the outcome would be an ordinary failure rather than the budget one.
    let script = format!(
        "{bb} dd if=/dev/zero of=\"$TMPDIR/fill\" bs=4096 count=64; {bb} sleep 30",
        bb = BUSYBOX
    );
    let plan = LaunchPlan::new(BUSYBOX, busybox_sha256())
        .unwrap()
        .argument("sh")
        .unwrap()
        .argument("-c")
        .unwrap()
        .argument(&script)
        .unwrap()
        .filesystem_grant(PathIntent::ReadExecute, BUSYBOX)
        .unwrap()
        .filesystem_grant(PathIntent::ReadWrite, &mnt)
        .unwrap()
        .filesystem_grant(PathIntent::Read, "/dev/zero")
        .unwrap()
        .environment("TMPDIR", mnt.as_os_str().as_encoded_bytes())
        .unwrap();

    let backend = DirectProcessBackend::new(HELPER).unwrap();
    let id = run_id("overflow");
    let spool_budget = 64 * 1024;
    let spool = Spool::open(&spool_root, &id, spool_budget).unwrap();
    let prepared = backend
        .prepare(
            &proof.domain,
            &run_id_for(&spool),
            ContainmentLimits::none(),
            plan,
            spool,
        )
        .unwrap()
        .with_temporary_storage(mounted.watch());
    let report = prepared
        .execute(&CancellationToken::new(), RUN_DEADLINE)
        .unwrap();

    // The typed budget outcome, naming the ceiling that tripped — the
    // filesystem's own record, not a configuration claim.
    let exceedance = match report.outcome() {
        ExecutionOutcome::TemporaryStorageExceeded { exceedance } => {
            assert_eq!(exceedance.resource, TemporaryStorageResource::Bytes);
            assert_eq!(exceedance.ceiling, 8 * STATFS_BLOCK_BYTES);
            exceedance
        }
        other => panic!("expected a temporary-storage budget outcome, got {other}"),
    };
    assert_eq!(report.outcome().terminal_payload(), b"failed");

    // The supervisor's own readback, taken once the tree was dead: the kernel
    // says the filesystem stands exactly at its ceiling.
    let readback = report
        .temporary_storage_readback()
        .expect("the server answered the supervisor's readback after the kill");
    assert_eq!(readback.ceiling_bytes(), 8 * STATFS_BLOCK_BYTES);
    assert_eq!(readback.blocks_free, 0, "the ceiling held: no free blocks");

    // THE DURABLE RECORD NAMES THE BUDGET, NOT JUST `failed`.
    //
    // The spool re-opens and its chain verifies; its last event is the
    // `failed` terminal, and the event right before it is the one synthetic
    // `provider_warning` that names the exceedance as the ledger spelled it
    // and carries the `statvfs` above. A reader of the record alone can tell
    // this run from one that failed for any other reason.
    let spool = Spool::open(&spool_root, &id, spool_budget).unwrap();
    let events = spool.events_after(0).unwrap();
    assert_eq!(events.last().map(Event::kind), Some(EventKind::Terminal));
    assert_eq!(events.last().map(Event::payload), Some(b"failed".as_ref()));
    let warnings: Vec<ProgressFrame> = events
        .iter()
        .filter(|event| event.kind() == EventKind::AdapterEvent)
        .filter_map(|event| ProgressFrame::from_canonical_bytes(event.payload()).ok())
        .filter(|frame| frame.kind() == FrameKind::ProviderWarning)
        .collect();
    assert_eq!(warnings.len(), 1, "the exceedance is recorded exactly once");
    let warning = &warnings[0];
    let text = warning
        .body()
        .text()
        .map(ProgressText::as_str)
        .expect("the warning has a text");
    eprintln!("[tempfs-contained] spool warning before the terminal event: {text}");
    let expected = format!("{TEMPORARY_STORAGE_EXCEEDED_WARNING}: {exceedance}; statfs {readback}");
    assert_eq!(
        text, expected,
        "the frame names the refusal and the readback"
    );
    assert_eq!(
        warning.body().retry().map(RetryContext::retryable),
        Some(false)
    );
    assert_eq!(
        warning.body().retry().map(RetryContext::category),
        Some(RetryCategory::Internal)
    );
    let warning_sequence = events
        .iter()
        .position(|event| {
            event.kind() == EventKind::AdapterEvent
                && ProgressFrame::from_canonical_bytes(event.payload())
                    .is_ok_and(|frame| frame.kind() == FrameKind::ProviderWarning)
        })
        .expect("the warning is in the record");
    assert_eq!(
        warning_sequence + 1,
        events.len() - 1,
        "the warning is the last word before the terminal event"
    );

    // The kernel evidence: the reconcile's `statfs`, read after the tree is
    // gone, shows the filesystem was filled to exactly its ceiling.
    let outcome = mounted.reconcile(READBACK_DEADLINE).unwrap();
    assert!(outcome.exceeded());
    assert!(outcome.unmount_confirmed);
    let statfs = outcome
        .statfs_before_unmount
        .expect("the server answered the reconcile readback");
    assert_eq!(statfs.blocks_free, 0, "the ceiling held: no free blocks");
    assert_eq!(statfs.used_bytes(), 8 * STATFS_BLOCK_BYTES);
    assert_eq!(outcome.ledger.peak_bytes, 8 * STATFS_BLOCK_BYTES);
    assert!(outcome.ledger.refused_bytes >= 1);
}

/// One separated, contained run: the plan asks for both, the launch mounts
/// inside its own namespaces, and the supervisor serves and reconciles it.
struct SeparatedRun {
    report: automonique_runner::backend::ExecutionReport,
    outcome: automonique_runner::tempfs::Outcome,
    run_root: PathBuf,
    spool_root: PathBuf,
    run_id: String,
    spool_budget: u64,
}

/// Run `script` under a plan that separates the workload's identity *and*
/// mounts `budget` at its own `$TMPDIR`, then reconcile.
fn run_separated(
    proof: &Proof,
    temp: &TempDir,
    label: &str,
    budget: TemporaryStorageBudget,
    script: &str,
) -> SeparatedRun {
    let run_root = temp.subdir("run");
    let mountpoint = run_root.join("tmp");
    fs::create_dir(&mountpoint).unwrap();
    let spool_root = temp.subdir("spool");

    // The filesystem exists before the launch does; the mount does not. The
    // supervisor holds the ledger, the exceedance channel and the checkpoint
    // from here, and the launch hands back the connection it mounted with.
    let mut pending = WorkloadTempfs::prepare(&mountpoint, budget)
        .unwrap()
        .with_checkpoint(run_root.join("tempfs-ledger"));
    let watch = pending.watch();
    let rendezvous = pending.rendezvous().expect("the launch takes it once");
    let mnt = pending.mountpoint().to_path_buf();

    let plan = LaunchPlan::new(BUSYBOX, busybox_sha256())
        .unwrap()
        .argument("sh")
        .unwrap()
        .argument("-c")
        .unwrap()
        .argument(script)
        .unwrap()
        .separate_workload_identity()
        .unwrap()
        .mount_temporary_storage(pending.request())
        .unwrap()
        .filesystem_grant(PathIntent::ReadExecute, BUSYBOX)
        .unwrap()
        .filesystem_grant(PathIntent::ReadWrite, &mnt)
        .unwrap()
        .filesystem_grant(PathIntent::Read, "/dev/zero")
        .unwrap()
        .environment("TMPDIR", mnt.as_os_str().as_encoded_bytes())
        .unwrap();

    let backend = DirectProcessBackend::new(HELPER).unwrap();
    let id = run_id(label);
    let spool_budget = 64 * 1024;
    let spool = Spool::open(&spool_root, &id, spool_budget).unwrap();
    let prepared = backend
        .prepare(
            &proof.domain,
            &run_id_for(&spool),
            ContainmentLimits::none(),
            plan,
            spool,
        )
        .unwrap()
        .with_temporary_storage(watch)
        .with_temporary_storage_mount(rendezvous);
    let report = prepared
        .execute(&CancellationToken::new(), RUN_DEADLINE)
        .unwrap();

    // THE MOUNT WAS NEVER IN THIS MOUNT NAMESPACE.
    //
    // The supervisor served the filesystem for the whole run and still has no
    // entry for it in its own table: the `mount(2)` happened inside the
    // workload's namespaces, which is the whole point of the change.
    assert!(
        mount_evidence(&mnt).unwrap().is_none(),
        "a launch-performed mount must never appear in the supervisor's mount table"
    );

    let outcome = pending.reconcile(READBACK_DEADLINE).unwrap();
    SeparatedRun {
        report,
        outcome,
        run_root,
        spool_root,
        run_id: id,
        spool_budget,
    }
}

#[test]
fn a_separated_workload_is_contained_at_its_byte_ceiling() {
    let Some((proof, identity)) =
        separated_proof_or_not_proven("a_separated_workload_is_contained_at_its_byte_ceiling")
    else {
        return;
    };
    let temp = TempDir::new("separated-bytes");
    // Eight blocks of scratch, eight objects.
    let budget = TemporaryStorageBudget::new(8 * STATFS_BLOCK_BYTES, 8).unwrap();
    let script = format!(
        "{bb} dd if=/dev/zero of=\"$TMPDIR/fill\" bs=4096 count=64; {bb} sleep 30",
        bb = BUSYBOX
    );
    let run = run_separated(&proof, &temp, "sepbytes", budget, &script);

    // The typed budget outcome, from a workload that was not the supervisor.
    match run.report.outcome() {
        ExecutionOutcome::TemporaryStorageExceeded { exceedance } => {
            assert_eq!(exceedance.resource, TemporaryStorageResource::Bytes);
            assert_eq!(exceedance.ceiling, 8 * STATFS_BLOCK_BYTES);
        }
        other => panic!("expected a temporary-storage budget outcome, got {other}"),
    }
    assert_eq!(run.report.outcome().terminal_payload(), b"failed");

    // THE KERNEL'S OWN ACCOUNT OF WHERE THE MOUNT LIVED.
    //
    // `user_id=0` is namespace-root, which no supervisor-performed mount can
    // ever show — the supervisor's own mounts carry its host uid — and
    // `allow_other` is what admits the workload once it drops namespace-root.
    let evidence = &run.outcome.evidence;
    assert!(
        evidence.is_fuse_subtype("automonique-tempfs"),
        "the launch mounted this crate's filesystem: {evidence}"
    );
    assert_eq!(
        evidence.user_id(),
        Some(0),
        "an in-namespace mount is namespace-root's: {evidence}"
    );
    assert!(
        evidence.super_options.contains("allow_other"),
        "the workload is not the mounter, so allow_other is necessary: {evidence}"
    );
    assert_ne!(
        identity.host_uid(),
        nix::unistd::getuid().as_raw(),
        "the workload ran as a host uid that is not the supervisor's"
    );

    // The ceiling held, and the filesystem says so.
    let readback = run
        .report
        .temporary_storage_readback()
        .expect("the server answered the supervisor's readback after the kill");
    assert_eq!(readback.ceiling_bytes(), 8 * STATFS_BLOCK_BYTES);
    assert_eq!(readback.blocks_free, 0, "the ceiling held: no free blocks");
    assert!(run.outcome.exceeded());
    assert!(run.outcome.unmount_confirmed);
    assert!(!run.outcome.aborted);
    let statfs = run
        .outcome
        .statfs_before_unmount
        .expect("the reconcile records the filesystem's own statfs");
    assert_eq!(statfs.used_bytes(), 8 * STATFS_BLOCK_BYTES);
    assert_eq!(run.outcome.ledger.peak_bytes, 8 * STATFS_BLOCK_BYTES);
    assert!(run.outcome.ledger.refused_bytes >= 1);
    // The mount's own readback, taken in the namespace by the process that
    // became the workload: the budget, empty.
    assert_eq!(
        run.outcome.statfs_at_mount.ceiling_bytes(),
        8 * STATFS_BLOCK_BYTES
    );
    assert_eq!(run.outcome.statfs_at_mount.used_bytes(), 0);

    // The durable record names the budget, not just `failed`.
    let spool = Spool::open(&run.spool_root, &run.run_id, run.spool_budget).unwrap();
    let events = spool.events_after(0).unwrap();
    assert_eq!(events.last().map(Event::kind), Some(EventKind::Terminal));
    let warnings: Vec<ProgressFrame> = events
        .iter()
        .filter(|event| event.kind() == EventKind::AdapterEvent)
        .filter_map(|event| ProgressFrame::from_canonical_bytes(event.payload()).ok())
        .filter(|frame| frame.kind() == FrameKind::ProviderWarning)
        .collect();
    assert_eq!(warnings.len(), 1, "the exceedance is recorded exactly once");
    let text = warnings[0]
        .body()
        .text()
        .map(ProgressText::as_str)
        .expect("the warning has a text");
    assert!(
        text.starts_with(TEMPORARY_STORAGE_EXCEEDED_WARNING),
        "the frame names the refusal: {text}"
    );
}

#[test]
fn a_separated_workload_is_contained_at_its_object_ceiling() {
    let Some((proof, _identity)) =
        separated_proof_or_not_proven("a_separated_workload_is_contained_at_its_object_ceiling")
    else {
        return;
    };
    let temp = TempDir::new("separated-objects");
    // Room for plenty of bytes and four objects, so the object ceiling is what
    // refuses first and `EDQUOT` is what the workload sees.
    let budget = TemporaryStorageBudget::new(64 * STATFS_BLOCK_BYTES, 4).unwrap();
    let script = format!(
        "for n in 1 2 3 4 5 6 7 8 9 10; do {bb} touch \"$TMPDIR/f$n\"; done; {bb} sleep 30",
        bb = BUSYBOX
    );
    let run = run_separated(&proof, &temp, "sepobjects", budget, &script);

    match run.report.outcome() {
        ExecutionOutcome::TemporaryStorageExceeded { exceedance } => {
            assert_eq!(exceedance.resource, TemporaryStorageResource::Objects);
            assert_eq!(exceedance.ceiling, 4);
        }
        other => panic!("expected an object-ceiling outcome, got {other}"),
    }
    assert!(run.outcome.exceeded());
    assert!(run.outcome.ledger.refused_objects >= 1);
    assert_eq!(run.outcome.ledger.peak_objects, 4);
    let statfs = run
        .outcome
        .statfs_before_unmount
        .expect("the reconcile records the filesystem's own statfs");
    assert_eq!(statfs.files, 4);
    assert_eq!(statfs.files_free, 0, "the ceiling held: no free objects");
}

#[test]
fn the_consumed_budget_of_a_separated_run_survives_a_supervisor_restart() {
    let Some((proof, _identity)) = separated_proof_or_not_proven(
        "the_consumed_budget_of_a_separated_run_survives_a_supervisor_restart",
    ) else {
        return;
    };
    let temp = TempDir::new("separated-checkpoint");
    let budget = TemporaryStorageBudget::new(8 * STATFS_BLOCK_BYTES, 8).unwrap();
    let script = format!(
        "{bb} dd if=/dev/zero of=\"$TMPDIR/fill\" bs=4096 count=64; {bb} sleep 30",
        bb = BUSYBOX
    );
    let run = run_separated(&proof, &temp, "sepckpt", budget, &script);

    // THE RECORD IS ON DISK, NOT IN THE SUPERVISOR'S MEMORY.
    //
    // Read back through the ordinary checkpoint reader, which is exactly what
    // a restarted supervisor's reaper uses: nothing of this process is
    // consulted, so a supervisor that died instead of reconciling would find
    // the same consumed budget here.
    let checkpoint = Checkpoint::read(&run.run_root.join("tempfs-ledger"))
        .expect("the final checkpoint is readable after the run");
    assert_eq!(checkpoint.phase, CheckpointPhase::Final);
    assert_eq!(checkpoint.snapshot.budget, budget);
    assert_eq!(checkpoint.snapshot.peak_bytes, 8 * STATFS_BLOCK_BYTES);
    assert!(checkpoint.snapshot.refused_bytes >= 1);
    assert!(
        checkpoint.snapshot.exceeded(),
        "the checkpoint carries the exceedance the run ended on"
    );
    assert!(
        checkpoint.mount_evidence.contains("user_id=0"),
        "the checkpoint carries the in-namespace mount evidence: {}",
        checkpoint.mount_evidence
    );
    let final_record = checkpoint
        .final_record
        .expect("the final phase carries the reconcile's own readbacks");
    assert!(final_record.unmount_confirmed);
    assert_eq!(
        final_record
            .statfs_before_unmount
            .expect("the readback is recorded")
            .used_bytes(),
        8 * STATFS_BLOCK_BYTES
    );
}

/// The spool names the run it belongs to; the backend requires the two to
/// agree, so the plan and the containment take the spool's own run id.
fn run_id_for(spool: &Spool) -> String {
    spool.status().run_id().to_owned()
}
