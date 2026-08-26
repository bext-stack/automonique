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

use automonique_runner::backend::{DirectProcessBackend, ExecutionOutcome};
use automonique_runner::filesystem::PathIntent;
use automonique_runner::tempfs::{FusePrerequisites, MountedTempfs};
use automonique_runner::{
    CancellationToken, ContainmentDomain, ContainmentError, ContainmentLimits, LaunchPlan,
    STATFS_BLOCK_BYTES, Spool, TemporaryStorageBudget, TemporaryStorageResource, VerifiedFuse,
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
    let channel = mounted.exceedance_channel();

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
    let spool = Spool::open(&spool_root, &run_id("overflow"), 64 * 1024).unwrap();
    let prepared = backend
        .prepare(
            &proof.domain,
            &run_id_for(&spool),
            ContainmentLimits::none(),
            plan,
            spool,
        )
        .unwrap()
        .with_temporary_storage_channel(channel);
    let report = prepared
        .execute(&CancellationToken::new(), RUN_DEADLINE)
        .unwrap();

    // The typed budget outcome, naming the ceiling that tripped — the
    // filesystem's own record, not a configuration claim.
    match report.outcome() {
        ExecutionOutcome::TemporaryStorageExceeded { exceedance } => {
            assert_eq!(exceedance.resource, TemporaryStorageResource::Bytes);
            assert_eq!(exceedance.ceiling, 8 * STATFS_BLOCK_BYTES);
        }
        other => panic!("expected a temporary-storage budget outcome, got {other}"),
    }
    assert_eq!(report.outcome().terminal_payload(), b"failed");

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

/// The spool names the run it belongs to; the backend requires the two to
/// agree, so the plan and the containment take the spool's own run id.
fn run_id_for(spool: &Spool) -> String {
    spool.status().run_id().to_owned()
}
