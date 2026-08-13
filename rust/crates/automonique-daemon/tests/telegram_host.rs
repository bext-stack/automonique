// SPDX-License-Identifier: Elastic-2.0

//! Daemon Telegram host: explicit configuration, durable bot lease, refusals.
//!
//! These tests drive the whole daemon over its real admin socket. A valid
//! configuration file must surface as `lease_owned_no_client` with a durable
//! poller lease in the store; an absent file must remain `disabled_no_client`;
//! and a present-but-wrong file must refuse startup rather than degrade into
//! an honest-looking disabled state. No test involves the network: the whole
//! point of this state is that HTTP stays deliberately unavailable.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use automonique_daemon::{Daemon, DaemonConfig, DaemonError};
use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse, TelegramState};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_store::Store;

fn fixture() -> (tempfile::TempDir, DaemonConfig) {
    let root = tempfile::tempdir().expect("temporary root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private root");
    let runtime = root.path().join("runtime");
    let state = root.path().join("state");
    std::fs::create_dir(&runtime).expect("runtime root");
    std::fs::create_dir(&state).expect("state root");
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
        .expect("private runtime");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
        .expect("private state");
    (
        root,
        DaemonConfig {
            runtime_root: runtime,
            state_root: state,
        },
    )
}

/// Write a bot configuration with exact content and permissions.
///
/// Every directory level is made private explicitly: the daemon refuses a
/// state tree whose intermediate directories carry group or other bits, and
/// that refusal must not be what these tests accidentally measure.
fn write_config(config: &DaemonConfig, content: &str, mode: u32) {
    let mut directory = config.state_root.clone();
    for level in ["automonique", "telegram"] {
        directory = directory.join(level);
        match std::fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("config directory: {error}"),
        }
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("private config directory");
    }
    let path = directory.join("bot.conf");
    std::fs::write(&path, content).expect("config written");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("config mode");
}

fn valid_config() -> String {
    [
        "schema=automonique.telegram-bot/v1",
        "bot_id=123456",
        "token=123456:AAExampleExampleExampleExample",
        "end=automonique.telegram-bot/v1",
        "",
    ]
    .join("\n")
}

fn call(config: &DaemonConfig, command: AdminCommand) -> AdminResponse {
    let request = AdminRequest::new(
        RequestId::new("telegram-test-1").expect("request ID"),
        command,
    );
    let mut stream = UnixStream::connect(config.admin_socket()).expect("connect to daemon");
    let payload = request
        .to_message()
        .expect("encode request")
        .to_canonical_bytes();
    let mut frame = Vec::new();
    encode_frame(&payload, &mut frame).expect("frame request");
    stream.write_all(&frame).expect("write request");
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).expect("response prefix");
    let length = u32::from_be_bytes(prefix) as usize;
    let mut response = vec![0_u8; length + 4];
    response[..4].copy_from_slice(&prefix);
    stream
        .read_exact(&mut response[4..])
        .expect("response body");
    let FrameDecode::Frame { payload, .. } = decode_frame(&response).expect("response frame")
    else {
        panic!("complete response was incomplete")
    };
    AdminResponse::from_canonical_bytes(payload).expect("admitted response")
}

fn wait_for_socket(config: &DaemonConfig) {
    // Generous on purpose. Everything before the bind is disk-bound — several
    // SQLite databases opened `synchronous = FULL`, each fsyncing its own WAL —
    // so a short deadline here measures the test host under concurrent load
    // rather than the daemon.
    let deadline = Instant::now() + Duration::from_secs(15);
    while !config.admin_socket().exists() {
        assert!(Instant::now() < deadline, "daemon did not bind");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn a_valid_configuration_owns_the_durable_bot_lease() {
    let (_root, config) = fixture();
    write_config(&config, &valid_config(), 0o600);

    let daemon = Daemon::open(&config).expect("daemon opens with valid telegram config");
    let stop = Arc::new(AtomicBool::new(false));
    let serve_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&serve_stop));
    wait_for_socket(&config);

    let AdminResponse::Status { status, .. } = call(&config, AdminCommand::Status) else {
        panic!("status response expected")
    };
    assert_eq!(status.telegram_state(), TelegramState::LeaseOwnedNoClient);
    let epoch = status
        .telegram_poller_epoch()
        .expect("owned lease must report its epoch");
    assert!(epoch >= 1);

    assert!(matches!(
        call(&config, AdminCommand::Shutdown),
        AdminResponse::ShutdownAccepted { .. }
    ));
    thread.join().expect("daemon thread").expect("clean stop");

    // Clean shutdown released the durable lease: a fresh holder can acquire
    // the same bot under a new generation without contesting a live owner.
    let mut store = Store::open(config.database_path()).expect("store reopens");
    let now_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("time fits");
    let lease = store
        .acquire_generation_lease(automonique_store::LeaseRequest {
            generation_id: "successor",
            holder_id: "successor-holder",
            now_ms,
            ttl_ms: 30_000,
        })
        .expect("successor generation");
    store
        .acquire_telegram_poller_lease(automonique_store::TelegramPollerLeaseRequest {
            bot_id: 123_456,
            generation_id: "successor",
            holder_id: "successor-holder",
            authority_lease_epoch: lease.epoch,
            now_ms,
            ttl_ms: 30_000,
        })
        .expect("released bot lease is acquirable by a successor");
}

#[test]
fn an_absent_configuration_stays_honestly_disabled() {
    let (_root, config) = fixture();
    let daemon = Daemon::open(&config).expect("daemon opens without telegram config");
    let stop = Arc::new(AtomicBool::new(false));
    let serve_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&serve_stop));
    wait_for_socket(&config);

    let AdminResponse::Status { status, .. } = call(&config, AdminCommand::Status) else {
        panic!("status response expected")
    };
    assert_eq!(status.telegram_state(), TelegramState::DisabledNoClient);
    assert_eq!(status.telegram_poller_epoch(), None);

    assert!(matches!(
        call(&config, AdminCommand::Shutdown),
        AdminResponse::ShutdownAccepted { .. }
    ));
    thread.join().expect("daemon thread").expect("clean stop");
}

/// Every refused-configuration case must stop the daemon with the exact
/// category, and must not leave a bound admin socket behind.
fn assert_open_refuses(config: &DaemonConfig, category: &str) {
    match Daemon::open(config) {
        Err(DaemonError::TelegramRefused(refused)) => assert_eq!(refused, category),
        Err(other) => panic!("expected TelegramRefused({category}), got {other:?}"),
        Ok(_) => panic!("a refused telegram configuration must not open the daemon"),
    }
    assert!(
        !config.admin_socket().exists(),
        "a refused startup must not leave the admin socket bound"
    );
}

#[test]
fn a_group_readable_token_file_refuses_startup() {
    let (_root, config) = fixture();
    write_config(&config, &valid_config(), 0o640);
    assert_open_refuses(&config, "telegram_config_insecure");
}

#[test]
fn a_truncated_configuration_refuses_startup() {
    let (_root, config) = fixture();
    let truncated = valid_config().replace("end=automonique.telegram-bot/v1\n", "");
    write_config(&config, &truncated, 0o600);
    assert_open_refuses(&config, "telegram_config_malformed");
}

#[test]
fn a_token_for_a_different_bot_refuses_startup() {
    let (_root, config) = fixture();
    let mismatched = valid_config().replace("token=123456:", "token=999999:");
    write_config(&config, &mismatched, 0o600);
    assert_open_refuses(&config, "telegram_config_token");
}

#[test]
fn an_unknown_key_refuses_startup() {
    let (_root, config) = fixture();
    let widened = valid_config().replace(
        "bot_id=123456",
        "bot_id=123456\nwebhook_url=https://attacker.invalid",
    );
    write_config(&config, &widened, 0o600);
    assert_open_refuses(&config, "telegram_config_malformed");
}

#[test]
fn a_crashed_predecessors_lease_is_fenced_out_by_expiry_not_contested() {
    let (_root, config) = fixture();
    write_config(&config, &valid_config(), 0o600);

    // A predecessor generation owns the same bot's lease and never released
    // it. The new daemon must refuse startup while that lease is live rather
    // than seize it: expiry, not preemption, is the only path to takeover.
    {
        let mut store = Store::open(config.database_path()).expect("pre-seeded store");
        let now_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_millis(),
        )
        .expect("time fits");
        let lease = store
            .acquire_generation_lease(automonique_store::LeaseRequest {
                generation_id: "predecessor",
                holder_id: "crashed-holder",
                now_ms,
                ttl_ms: 60_000,
            })
            .expect("predecessor generation");
        store
            .acquire_telegram_poller_lease(automonique_store::TelegramPollerLeaseRequest {
                bot_id: 123_456,
                generation_id: "predecessor",
                holder_id: "crashed-holder",
                authority_lease_epoch: lease.epoch,
                now_ms,
                ttl_ms: 60_000,
            })
            .expect("predecessor bot lease");
    }

    match Daemon::open(&config) {
        Err(DaemonError::TelegramRefused(category)) => {
            assert_eq!(category, "telegram_lease_refused");
        }
        Err(other) => panic!("expected telegram_lease_refused, got {other:?}"),
        Ok(_) => panic!("a live foreign bot lease must not be seized"),
    }
}
