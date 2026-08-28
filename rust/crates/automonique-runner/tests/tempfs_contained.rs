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
use automonique_runner::tempfs::FusePrerequisites;
use automonique_runner::{
    CancellationToken, ContainmentDomain, ContainmentError, ContainmentLimits, Event, EventKind,
    LaunchPlan, STATFS_BLOCK_BYTES, Spool, TemporaryStorageBudget, TemporaryStorageResource,
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
    match FusePrerequisites::host_default().verify() {
        Ok(_) => {}
        Err(error) => {
            not_proven(format!("FUSE unavailable: {error}"));
            return None;
        }
    };
    eprintln!(
        "[tempfs-contained] ENFORCED {proof}: domain {}",
        domain.root().display()
    );
    Some(Proof { domain })
}

#[test]
fn an_immediately_exiting_workload_keeps_a_typed_budget_outcome() {
    let Some(proof) =
        proof_or_not_proven("an_immediately_exiting_workload_keeps_a_typed_budget_outcome")
    else {
        return;
    };
    let temp = TempDir::new("overflow");
    let run_root = temp.subdir("run");
    let mountpoint = run_root.join("tmp");
    fs::create_dir(&mountpoint).unwrap();
    let spool_root = temp.subdir("spool");

    // Eight blocks of scratch, eight objects.
    let budget = TemporaryStorageBudget::new(8 * STATFS_BLOCK_BYTES, 8).unwrap();
    let checkpoint = run_root.join("tempfs-ledger");
    let mnt = mountpoint;

    // The workload writes far past the ceiling into $TMPDIR — the grant and the
    // variable are exactly what admission attaches — and exits immediately
    // after `dd` receives ENOSPC. The final owner reconciliation must retain the
    // typed quota outcome even when no live supervision poll observed it.
    let script = format!(
        "{bb} dd if=/dev/zero of=\"$TMPDIR/fill\" bs=4096 count=64",
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
        .unwrap()
        .separate_workload_identity()
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
        .with_namespaced_temporary_storage(&mnt, budget, &checkpoint);
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

    // The private namespace mount's exact ledger is reconciled by the backend
    // after the workload tree is gone. No supervisor-visible path walk is
    // involved, and the final checkpoint is independently readable.
    let outcome = report
        .namespaced_temporary_storage()
        .expect("the namespaced mount reconciles with the run");
    assert!(outcome.ledger.exceeded());
    assert!(outcome.unmount_confirmed);
    let statfs = outcome.statfs_from_ledger;
    assert_eq!(statfs.blocks_free, 0, "the ceiling held: no free blocks");
    assert_eq!(statfs.used_bytes(), 8 * STATFS_BLOCK_BYTES);
    assert_eq!(outcome.ledger.peak_bytes, 8 * STATFS_BLOCK_BYTES);
    assert!(outcome.ledger.refused_bytes >= 1);
    let restarted = automonique_runner::Checkpoint::read(&checkpoint).unwrap();
    assert_eq!(restarted.phase, automonique_runner::CheckpointPhase::Final);
    assert_eq!(restarted.snapshot, outcome.ledger);
}

/// The spool names the run it belongs to; the backend requires the two to
/// agree, so the plan and the containment take the spool's own run id.
fn run_id_for(spool: &Spool) -> String {
    spool.status().run_id().to_owned()
}
