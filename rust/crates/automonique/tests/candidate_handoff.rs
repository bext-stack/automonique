// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::io::OwnedFd;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use automonique_daemon::attempt_adoption::AttemptAdoptionClient;
use automonique_daemon::candidate::{CandidateSpec, spawn_warm_candidate};
use automonique_daemon::release_activation::{CodeReleaseActivator, SystemdUserSupervisor};
use automonique_daemon::{Daemon, DaemonConfig};
use automonique_store::reload_audit::ReloadPhase;
use automonique_store::{LeaseOwnerIdentity, LeaseTimeSource, LeaseTransferRequest, Store};
use nix::sys::signal::kill;
use nix::sys::time::TimeValLike;
use nix::time::ClockId;
use nix::unistd::Pid;
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
    source
        .quiesce_for_handoff()
        .expect("source stops intake while retaining attempts");

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
        .confirm_authority(&transferred.lease, transferred.adopted_runs, &[])
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
    source
        .retire_after_handoff()
        .expect("source drains before injected post-drain failure");
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
    source
        .resume_endpoint_cleanup()
        .expect("source resumes exact socket cleanup");
    source
        .resume_after_handoff()
        .expect("source rebuilds stopped workers at returned epoch");
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
    candidate.stop().expect("candidate stopped");
    assert!(config.admin_socket().exists());
    assert!(config.progress_socket().exists());

    let committed = source
        .handoff_to_verified_release("reload-process-commit", release)
        .expect("ten-phase process handoff succeeds");
    assert_eq!(committed.phase, ReloadPhase::Succeeded);
    assert_eq!(
        fs::read_link(release_root.join("current")).expect("selected release link"),
        Path::new("releases").join(&manifest_digest)
    );
    let committed_holder = read_source_lease(&config.database_path()).holder_id;
    drop(source);

    let committed_status = Command::new(env!("CARGO_BIN_EXE_automonique"))
        .args(["status", "--json"])
        .env("XDG_RUNTIME_DIR", &config.runtime_root)
        .env("XDG_STATE_HOME", &config.state_root)
        .output()
        .expect("committed candidate status");
    assert!(
        committed_status.status.success(),
        "committed candidate survives source and handle drop"
    );
    assert!(
        String::from_utf8(committed_status.stdout)
            .expect("committed status UTF-8")
            .contains(&committed_holder)
    );
    let shutdown = Command::new(env!("CARGO_BIN_EXE_automonique"))
        .arg("shutdown")
        .env("XDG_RUNTIME_DIR", &config.runtime_root)
        .env("XDG_STATE_HOME", &config.state_root)
        .output()
        .expect("committed candidate shutdown");
    assert!(shutdown.status.success());
    let deadline = Instant::now() + Duration::from_secs(5);
    while (config.admin_socket().exists() || config.progress_socket().exists())
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!config.admin_socket().exists());
    assert!(!config.progress_socket().exists());
}

#[test]
fn authenticated_reload_command_hands_off_and_retires_the_source() {
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
    let daemon = Daemon::open(&config).expect("source daemon");

    let release_root = config.state_dir().join("improvement-code");
    private_directory(&release_root);
    private_directory(&release_root.join("releases"));
    let executable = fs::read(env!("CARGO_BIN_EXE_automonique")).expect("candidate binary");
    let previous_digest = install_code_release(&release_root, &executable, 'a');
    let manifest_digest = install_code_release(&release_root, &executable, 'c');
    std::os::unix::fs::symlink(
        Path::new("releases").join(&previous_digest),
        release_root.join("current"),
    )
    .expect("initial current release");

    let stop = Arc::new(AtomicBool::new(false));
    let serve_stop = Arc::clone(&stop);
    let source = std::thread::spawn(move || daemon.serve(&serve_stop));
    let digest = format!("sha256:{manifest_digest}");
    let reload = Command::new(env!("CARGO_BIN_EXE_automonique"))
        .args(["reload", &digest])
        .env("XDG_RUNTIME_DIR", &config.runtime_root)
        .env("XDG_STATE_HOME", &config.state_root)
        .output()
        .expect("reload command");
    assert!(
        reload.status.success(),
        "reload command failed: {}",
        String::from_utf8_lossy(&reload.stderr)
    );
    let output = String::from_utf8(reload.stdout).expect("reload output UTF-8");
    assert!(output.starts_with("reload reload-1-"));
    assert!(output.ends_with(" accepted\n"));
    let reload_id = output
        .strip_prefix("reload ")
        .and_then(|output| output.strip_suffix(" accepted\n"))
        .expect("accepted reload ID");
    source
        .join()
        .expect("source serve thread")
        .expect("source retires without releasing transferred authority");

    let reload_status = Command::new(env!("CARGO_BIN_EXE_automonique"))
        .args(["reload-status", reload_id])
        .env("XDG_RUNTIME_DIR", &config.runtime_root)
        .env("XDG_STATE_HOME", &config.state_root)
        .output()
        .expect("reload status command");
    assert!(
        reload_status.status.success(),
        "reload status failed: {}",
        String::from_utf8_lossy(&reload_status.stderr)
    );
    assert!(
        String::from_utf8(reload_status.stdout)
            .expect("reload status UTF-8")
            .contains(" phase=succeeded ")
    );

    assert_eq!(
        fs::read_link(release_root.join("current")).expect("selected release link"),
        Path::new("releases").join(&manifest_digest)
    );
    assert_eq!(
        fs::read_link(release_root.join("previous")).expect("retained release link"),
        Path::new("releases").join(&previous_digest)
    );
    let rollback = Command::new(env!("CARGO_BIN_EXE_automonique"))
        .args(["rollback", "--wait"])
        .env("XDG_RUNTIME_DIR", &config.runtime_root)
        .env("XDG_STATE_HOME", &config.state_root)
        .output()
        .expect("rollback command");
    assert!(
        rollback.status.success(),
        "rollback command failed: {}",
        String::from_utf8_lossy(&rollback.stderr)
    );
    assert!(
        String::from_utf8(rollback.stdout)
            .expect("rollback output UTF-8")
            .starts_with("rollback rollback-2-")
    );
    assert_eq!(
        fs::read_link(release_root.join("current")).expect("rolled back release link"),
        Path::new("releases").join(&previous_digest)
    );
    let repeated = Command::new(env!("CARGO_BIN_EXE_automonique"))
        .arg("rollback")
        .env("XDG_RUNTIME_DIR", &config.runtime_root)
        .env("XDG_STATE_HOME", &config.state_root)
        .output()
        .expect("repeated rollback command");
    assert!(!repeated.status.success());
    assert_eq!(
        String::from_utf8(repeated.stderr).expect("refusal UTF-8"),
        "automonique rollback refused: rollback_unavailable\n"
    );

    let status = Command::new(env!("CARGO_BIN_EXE_automonique"))
        .args(["status", "--json"])
        .env("XDG_RUNTIME_DIR", &config.runtime_root)
        .env("XDG_STATE_HOME", &config.state_root)
        .output()
        .expect("candidate status");
    assert!(
        status.status.success(),
        "candidate owns the inherited endpoint"
    );

    let shutdown = Command::new(env!("CARGO_BIN_EXE_automonique"))
        .arg("shutdown")
        .env("XDG_RUNTIME_DIR", &config.runtime_root)
        .env("XDG_STATE_HOME", &config.state_root)
        .output()
        .expect("candidate shutdown");
    assert!(shutdown.status.success());
    let deadline = Instant::now() + Duration::from_secs(5);
    while (config.admin_socket().exists() || config.progress_socket().exists())
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!config.admin_socket().exists());
    assert!(!config.progress_socket().exists());
}

/// A socket-activated generation, and the generation adopted from it by a hot
/// reload, both answer on a pathname neither of them created — and neither
/// removes it.
///
/// The pathname belongs to the socket unit. It is bound before any daemon
/// starts, it stays bound while the unit is loaded, and it is what every
/// socket-activated start validates. A generation that unlinked it would
/// leave the unit listening on an inode no client can reach and every later
/// start refusing on a path that is gone; the reload's cleanup transfer is
/// where that duty could wrongly be handed to a successor, so the successor
/// is what this drives to a full stop.
///
/// The activation is real rather than simulated: the test binds the pathname
/// itself and hands the daemon that descriptor as `LISTEN_FDS=1`, the way the
/// socket unit does. Everything lives under this test's own private roots.
#[test]
fn an_adopted_candidate_leaves_the_socket_units_admin_path_in_place() {
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

    // What `RuntimeDirectory=` and `ListenStream=` leave behind before the
    // service is ever started: a private runtime directory and a bound
    // pathname nothing in the daemon's process tree created.
    private_directory(&config.runtime_dir());
    let admin = config.admin_socket();
    let unit_listener = UnixListener::bind(&admin).expect("the socket unit binds the admin path");
    fs::set_permissions(&admin, fs::Permissions::from_mode(0o600)).expect("private admin path");
    let unit_inode = inode_of(&admin);

    // The state directory is the daemon's to create, and it refuses one that
    // is not private. Here the release tree is installed before any daemon has
    // run, so the test creates the parent the way the daemon would.
    private_directory(&config.state_dir());
    let release_root = config.state_dir().join("improvement-code");
    private_directory(&release_root);
    private_directory(&release_root.join("releases"));
    let executable = fs::read(env!("CARGO_BIN_EXE_automonique")).expect("candidate binary");
    let previous_digest = install_code_release(&release_root, &executable, 'a');
    let next_digest = install_code_release(&release_root, &executable, 'c');
    std::os::unix::fs::symlink(
        Path::new("releases").join(&previous_digest),
        release_root.join("current"),
    )
    .expect("initial current release");

    let mut source = spawn_activated_daemon(&config, &unit_listener);
    let source_pid = source.id();
    wait_until(
        "the activated daemon to answer",
        Duration::from_secs(30),
        || cli(&config, &["status", "--json"]).status.success(),
    );
    let before = read_source_lease(&config.database_path());
    assert_eq!(
        before.pid, source_pid,
        "the generation is the process the test handed the listener to"
    );
    assert_eq!(
        inode_of(&admin),
        unit_inode,
        "the activated daemon adopted the pathname rather than rebinding it"
    );

    let reload = cli(
        &config,
        &["reload", &format!("sha256:{next_digest}"), "--wait"],
    );
    assert!(
        reload.status.success(),
        "the activated source hands off: {}",
        String::from_utf8_lossy(&reload.stderr)
    );
    let retired = source.wait().expect("source status");
    assert!(retired.success(), "the source retires cleanly: {retired}");
    let adopted = read_source_lease(&config.database_path());
    assert_ne!(adopted.holder_id, before.holder_id);
    assert_ne!(adopted.pid, source_pid);
    let status = cli(&config, &["status", "--json"]);
    assert!(
        status.status.success(),
        "the adopted candidate answers on the inherited endpoint"
    );

    // The stop that took the unit down in the field: the adopted candidate is
    // the last generation, and its drop path is the one that reaches the
    // admin pathname.
    let shutdown = cli(&config, &["shutdown"]);
    assert!(
        shutdown.status.success(),
        "the adopted candidate stops: {}",
        String::from_utf8_lossy(&shutdown.stderr)
    );
    wait_until(
        "the adopted candidate to exit",
        Duration::from_secs(20),
        || !process_is_live(adopted.pid),
    );
    wait_until(
        "the progress endpoint to be removed",
        Duration::from_secs(10),
        || !config.progress_socket().exists(),
    );
    assert!(
        admin.exists(),
        "the socket unit's pathname survives the generation adopted from it"
    );
    assert_eq!(
        inode_of(&admin),
        unit_inode,
        "the pathname is still the socket unit's own inode"
    );

    // What the crash loop could never reach: the socket unit's next
    // activation, on the descriptor it has been holding all along.
    let mut restarted = spawn_activated_daemon(&config, &unit_listener);
    wait_until(
        "the next socket-activated start to answer",
        Duration::from_secs(30),
        || cli(&config, &["status", "--json"]).status.success(),
    );
    let restarted_lease = read_source_lease(&config.database_path());
    assert_eq!(restarted_lease.pid, restarted.id());
    let shutdown = cli(&config, &["shutdown"]);
    assert!(shutdown.status.success());
    let stopped = restarted.wait().expect("restarted daemon status");
    assert!(stopped.success(), "the restarted daemon stops cleanly");
    assert!(admin.exists());
    assert_eq!(inode_of(&admin), unit_inode);
    drop(unit_listener);
}

/// Start the product binary the way the socket unit starts it: with the
/// unit's already-bound listener as the one activated descriptor.
///
/// A shell stands between the test and the binary because `LISTEN_PID` must
/// name the daemon's own process, and that value is only knowable after the
/// fork — `exec` then keeps the pid the shell reported. The script is a fixed
/// literal; the binary and its arguments arrive as positional parameters
/// rather than as interpolated text.
fn spawn_activated_daemon(config: &DaemonConfig, listener: &UnixListener) -> Child {
    let inherited = listener.try_clone().expect("duplicate the unit listener");
    Command::new("/bin/sh")
        .arg("-c")
        .arg("exec 3<&0 0</dev/null; export LISTEN_PID=$$; exec \"$0\" \"$@\"")
        .arg(env!("CARGO_BIN_EXE_automonique"))
        .arg("daemon")
        .arg("--foreground")
        .env("XDG_RUNTIME_DIR", &config.runtime_root)
        .env("XDG_STATE_HOME", &config.state_root)
        .env("LISTEN_FDS", "1")
        .env("LISTEN_FDNAMES", "admin")
        .stdin(Stdio::from(OwnedFd::from(inherited)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("activated daemon process")
}

fn cli(config: &DaemonConfig, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_automonique"))
        .args(args)
        .env("XDG_RUNTIME_DIR", &config.runtime_root)
        .env("XDG_STATE_HOME", &config.state_root)
        .output()
        .expect("product binary runs")
}

fn inode_of(path: &Path) -> (u64, u64) {
    let metadata = fs::symlink_metadata(path).expect("admin path metadata");
    (metadata.dev(), metadata.ino())
}

fn process_is_live(pid: u32) -> bool {
    i32::try_from(pid).is_ok_and(|raw| kill(Pid::from_raw(raw), None).is_ok())
}

fn wait_until(what: &str, timeout: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(25));
    }
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

fn install_code_release(root: &Path, executable: &[u8], source: char) -> String {
    let binary_sha256 = hex(&Sha256::digest(executable));
    let manifest = serde_json::json!({
        "schema": "automonique.code-release/v1",
        "source_sha": source.to_string().repeat(40),
        "plan_digest": format!("sha256:{}", source.to_string().repeat(64)),
        "binary_path": "bin/automonique",
        "binary_sha256": binary_sha256,
        "changed_paths": ["rust/crates/automonique-cli/src/lib.rs"]
    });
    let manifest = serde_json::to_vec(&manifest).expect("manifest");
    let manifest_digest = hex(&Sha256::digest(&manifest));
    let release_dir = root.join("releases").join(&manifest_digest);
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
    manifest_digest
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
