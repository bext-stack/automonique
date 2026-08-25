// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use automonique_daemon::attempt_adoption::AttemptAdoptionClient;
use automonique_daemon::candidate::{CandidateSpec, spawn_warm_candidate};
use automonique_daemon::release_activation::{CodeReleaseActivator, SystemdUserSupervisor};
use automonique_daemon::{Daemon, DaemonConfig};
use automonique_store::{LeaseOwnerIdentity, LeaseTimeSource, LeaseTransferRequest, Store};
use nix::sys::time::TimeValLike;
use nix::time::ClockId;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

#[test]
fn exact_release_candidate_proves_transfer_and_clean_lease_return() {
    let root = tempfile::tempdir().expect("temporary root");
    private_directory(root.path());
    let runtime_root = root.path().join("runtime");
    let state_root = root.path().join("state");
    private_directory(&runtime_root);
    private_directory(&state_root);
    let config = DaemonConfig {
        runtime_root,
        state_root,
    };

    let mut source = Daemon::open(&config).expect("source daemon");
    source
        .start_candidate_warmup_route()
        .expect("source attempt route");
    let transfer_descriptors = source
        .candidate_transfer_descriptors()
        .expect("transfer descriptors");
    let source_lease = read_source_lease(&config.database_path());

    let release_root = root.path().join("code-releases");
    private_directory(&release_root);
    private_directory(&release_root.join("releases"));
    let executable = fs::read(env!("CARGO_BIN_EXE_automonique")).expect("candidate binary");
    let binary_sha256 = hex(&Sha256::digest(&executable));
    let manifest = serde_json::json!({
        "schema": "automonique.code-release/v1",
        "source_sha": "a".repeat(40),
        "plan_digest": format!("sha256:{}", "b".repeat(64)),
        "binary_path": "bin/automonique",
        "binary_sha256": binary_sha256,
        "changed_paths": ["rust/crates/automonique-daemon/src/candidate.rs"]
    });
    let manifest = serde_json::to_vec(&manifest).expect("manifest");
    let manifest_digest = hex(&Sha256::digest(&manifest));
    let release_dir = release_root.join("releases").join(&manifest_digest);
    private_directory(&release_dir);
    private_directory(&release_dir.join("bin"));
    fs::write(release_dir.join("manifest.json"), manifest).expect("manifest file");
    fs::write(release_dir.join("bin/automonique"), executable).expect("binary file");
    fs::set_permissions(
        release_dir.join("manifest.json"),
        fs::Permissions::from_mode(0o600),
    )
    .expect("manifest mode");
    fs::set_permissions(
        release_dir.join("bin/automonique"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("binary mode");

    let activator =
        CodeReleaseActivator::new(&release_root, "automonique.service", SystemdUserSupervisor)
            .expect("activator");
    let digest = format!("sha256:{manifest_digest}");
    let release = activator.verify(&digest).expect("verified release");
    let candidate = spawn_warm_candidate(
        &config,
        &release,
        &CandidateSpec {
            reload_id: "reload-process-test".to_owned(),
            source_holder_id: source_lease.holder_id.clone(),
            source_lease_epoch: source_lease.epoch,
            target_generation_id: "foreground-next".to_owned(),
            warm_timeout: Duration::from_secs(20),
        },
    )
    .expect("warm candidate");
    let mut candidate = candidate;
    assert_ne!(candidate.pid(), std::process::id());
    let lease_target = candidate.lease_target();
    assert_eq!(lease_target.pid, candidate.pid());
    assert!(lease_target.starttime > 0);
    assert!(lease_target.holder_id.starts_with("daemon-"));
    let attempt_inventory = candidate.attempt_inventory_proof();
    assert_eq!(attempt_inventory.count, 0);
    assert_eq!(
        attempt_inventory.sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "candidate proved the empty live source-host inventory"
    );
    candidate
        .prepare_transfer(transfer_descriptors)
        .expect("candidate validates transferred listener and lock");
    assert!(candidate.is_transfer_ready());

    let target = candidate.lease_target();
    let mut store =
        Store::open_with_lease_time_source(config.database_path(), Arc::new(ProcBootTime))
            .expect("handoff store");
    let transferred = store
        .transfer_generation_lease(LeaseTransferRequest {
            generation_id: "foreground",
            source_holder_id: &source_lease.holder_id,
            source_epoch: source_lease.epoch,
            target_holder_id: &target.holder_id,
            target_owner: LeaseOwnerIdentity {
                boot_id: &target.boot_id,
                pid: target.pid,
                starttime: target.starttime,
            },
            now_ms: unix_millis(),
            ttl_ms: 30_000,
        })
        .expect("transfer generation lease");
    candidate
        .confirm_authority(&transferred.lease, transferred.adopted_runs)
        .expect("candidate renews transferred authority");
    let candidate_tenure: (String, u64) = Connection::open(config.generation_audit_path())
        .expect("generation audit")
        .query_row(
            "SELECT holder_id, lease_epoch FROM generation_tenures
             WHERE generation_id = 'foreground' AND end_kind IS NULL",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("candidate tenure");
    assert_eq!(
        candidate_tenure,
        (target.holder_id.clone(), transferred.lease.epoch)
    );
    assert_eq!(
        candidate
            .stop()
            .expect_err("authority cannot stop before return")
            .category(),
        "candidate_protocol"
    );
    let cleanup = source
        .relinquish_endpoint_cleanup()
        .expect("source transfers exact socket cleanup");
    candidate
        .activate_serving(cleanup)
        .expect("candidate starts inherited endpoints and workers");
    let status = Command::new(env!("CARGO_BIN_EXE_automonique"))
        .args(["status", "--json"])
        .env("XDG_RUNTIME_DIR", &config.runtime_root)
        .env("XDG_STATE_HOME", &config.state_root)
        .output()
        .expect("candidate status");
    assert!(status.status.success(), "candidate serves admin status");
    let status = String::from_utf8(status.stdout).expect("status UTF-8");
    assert!(status.contains(&target.holder_id));
    candidate
        .quiesce()
        .expect("candidate drains while retaining authority");

    let returned = store
        .transfer_generation_lease(LeaseTransferRequest {
            generation_id: "foreground",
            source_holder_id: &transferred.lease.holder_id,
            source_epoch: transferred.lease.epoch,
            target_holder_id: &source_lease.holder_id,
            target_owner: LeaseOwnerIdentity {
                boot_id: &source_lease.boot_id,
                pid: source_lease.pid,
                starttime: source_lease.starttime,
            },
            now_ms: unix_millis(),
            ttl_ms: 30_000,
        })
        .expect("return generation lease");
    candidate
        .confirm_relinquished(&returned.lease)
        .expect("candidate observes returned authority");
    source
        .accept_returned_authority(&returned.lease)
        .expect("source records and projects returned authority");
    let returned_route = source
        .attempt_adoption_route()
        .expect("returned source attempt route");
    assert_eq!(returned_route.holder_id, source_lease.holder_id);
    assert_eq!(returned_route.lease_epoch, returned.lease.epoch);
    let returned_inventory = AttemptAdoptionClient::new(
        returned_route.socket_path,
        &returned_route.holder_id,
        returned_route.lease_epoch,
    )
    .expect("returned source route client")
    .inventory()
    .expect("returned source route inventory");
    assert!(returned_inventory.attempt_ids.is_empty());
    let returned_tenure: (String, u64) = Connection::open(config.generation_audit_path())
        .expect("generation audit")
        .query_row(
            "SELECT holder_id, lease_epoch FROM generation_tenures
             WHERE generation_id = 'foreground' AND end_kind IS NULL",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("returned source tenure");
    assert_eq!(
        returned_tenure,
        (source_lease.holder_id.clone(), returned.lease.epoch)
    );
    source
        .resume_endpoint_cleanup()
        .expect("source resumes exact socket cleanup");
    candidate.stop().expect("candidate stopped");
    assert!(config.admin_socket().exists());
    assert!(config.progress_socket().exists());
    drop(source);
    assert!(!config.admin_socket().exists());
    assert!(!config.progress_socket().exists());
}

struct SourceLease {
    holder_id: String,
    epoch: u64,
    boot_id: String,
    pid: u32,
    starttime: u64,
}

fn read_source_lease(path: &Path) -> SourceLease {
    let connection = Connection::open(path).expect("main database");
    connection
        .query_row(
            "SELECT lease_holder, lease_epoch, boot_id, holder_pid, holder_starttime
             FROM generations
             WHERE generation_id = 'foreground'",
            [],
            |row| {
                Ok(SourceLease {
                    holder_id: row.get(0)?,
                    epoch: row.get(1)?,
                    boot_id: row.get(2)?,
                    pid: row.get(3)?,
                    starttime: row.get(4)?,
                })
            },
        )
        .expect("source lease")
}

struct ProcBootTime;

impl LeaseTimeSource for ProcBootTime {
    fn now_boottime_ms(&self) -> Result<i64, &'static str> {
        ClockId::CLOCK_BOOTTIME
            .now()
            .map(|value| value.num_milliseconds())
            .map_err(|_| "clock_gettime")
    }
}

fn unix_millis() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis(),
    )
    .expect("Unix milliseconds fit i64")
}

fn private_directory(path: &Path) {
    fs::create_dir_all(path).expect("private directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}
