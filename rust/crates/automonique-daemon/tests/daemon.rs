// SPDX-License-Identifier: Elastic-2.0

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use automonique_daemon::{Daemon, DaemonConfig, DaemonError, run_foreground};
use automonique_protocol::admin::{
    AdminCommand, AdminRequest, AdminResponse, DaemonState, ReconciliationFailure,
};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_store::{InboxSubmission, LeaseRequest, SchedulerClaim, Store, WorkClaim};
use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};

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

fn call(config: &DaemonConfig, command: AdminCommand) -> AdminResponse {
    let request = AdminRequest::new(
        RequestId::new("integration-1").expect("request ID"),
        command,
    );
    call_request(config, request)
}

fn call_request(config: &DaemonConfig, request: AdminRequest) -> AdminResponse {
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
    let deadline = Instant::now() + Duration::from_secs(2);
    while !config.admin_socket().exists() {
        assert!(Instant::now() < deadline, "daemon did not bind");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn foreground_daemon_reports_durable_status_and_shuts_down_over_rpc() {
    let (_root, config) = fixture();
    let daemon = Daemon::open(&config).expect("daemon opens");
    let stop = Arc::new(AtomicBool::new(false));
    let serve_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&serve_stop));
    wait_for_socket(&config);

    let AdminResponse::Status { status, .. } = call(&config, AdminCommand::Status) else {
        panic!("status response expected")
    };
    assert_eq!(status.state(), DaemonState::Ready);
    assert!(status.accepting_intake());
    assert_eq!(status.inbox_pending(), 0);
    assert_eq!(status.outbox_pending(), 0);
    assert_eq!(status.running(), 0);
    assert!(status.generation() >= 1);
    assert!(status.event_cursor() >= 1);

    assert!(matches!(
        call(&config, AdminCommand::Shutdown),
        AdminResponse::ShutdownAccepted { .. }
    ));
    thread.join().expect("daemon thread").expect("clean stop");
    assert!(!config.admin_socket().exists());
    assert!(config.database_path().is_file());
}

#[test]
fn status_polling_does_not_rewrite_the_durable_lease() {
    let (_root, config) = fixture();
    let daemon = Daemon::open(&config).expect("daemon opens");
    let stop = Arc::new(AtomicBool::new(false));
    let serve_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&serve_stop));
    wait_for_socket(&config);
    let before = Store::open(config.database_path())
        .expect("inspect before")
        .status_snapshot("foreground")
        .expect("snapshot before")
        .generation
        .expect("generation before");
    for _ in 0..40 {
        assert!(matches!(
            call(&config, AdminCommand::Status),
            AdminResponse::Status { .. }
        ));
    }
    let after = Store::open(config.database_path())
        .expect("inspect after")
        .status_snapshot("foreground")
        .expect("snapshot after")
        .generation
        .expect("generation after");
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.lease_expires_ms, before.lease_expires_ms);
    assert!(matches!(
        call(&config, AdminCommand::Shutdown),
        AdminResponse::ShutdownAccepted { .. }
    ));
    thread.join().expect("daemon thread").expect("clean stop");
}

#[test]
fn an_active_endpoint_refuses_a_second_daemon() {
    let (_root, config) = fixture();
    let first = Daemon::open(&config).expect("first daemon");
    let before = Store::open(config.database_path())
        .expect("inspect store")
        .status_snapshot("foreground")
        .expect("status before")
        .event_cursor;
    assert!(matches!(
        Daemon::open(&config),
        Err(DaemonError::AlreadyRunning)
    ));
    let after = Store::open(config.database_path())
        .expect("inspect store")
        .status_snapshot("foreground")
        .expect("status after")
        .event_cursor;
    assert_eq!(
        after, before,
        "refused bind must not mutate generation state"
    );
    drop(first);
}

#[test]
fn orderly_shutdown_releases_the_fence_for_immediate_restart() {
    let (_root, config) = fixture();
    for _ in 0..2 {
        let daemon = Daemon::open(&config).expect("daemon opens");
        let stop = Arc::new(AtomicBool::new(false));
        let serve_stop = Arc::clone(&stop);
        let thread = std::thread::spawn(move || daemon.serve(&serve_stop));
        wait_for_socket(&config);
        assert!(matches!(
            call(&config, AdminCommand::Shutdown),
            AdminResponse::ShutdownAccepted { .. }
        ));
        thread.join().expect("daemon thread").expect("clean stop");
    }
}

#[test]
fn losing_the_durable_fence_ends_serving_without_false_ready() {
    let (_root, config) = fixture();
    let daemon = Daemon::open(&config).expect("daemon opens");
    let stop = Arc::new(AtomicBool::new(false));
    let serve_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&serve_stop));
    wait_for_socket(&config);
    let AdminResponse::Status { status, .. } = call(&config, AdminCommand::Status) else {
        panic!("status response expected")
    };
    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_millis(),
    )
    .expect("bounded time");
    Store::open(config.database_path())
        .expect("competing store")
        .release_generation_lease(
            "foreground",
            status.instance_id().as_str(),
            status.generation(),
            now_ms,
        )
        .expect("release durable fence");

    let mut stream = UnixStream::connect(config.admin_socket()).expect("connect after loss");
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("timeout");
    let request = AdminRequest::new(
        RequestId::new("after-fence-loss").expect("request ID"),
        AdminCommand::Status,
    );
    let mut frame = Vec::new();
    encode_frame(
        &request.to_message().expect("request").to_canonical_bytes(),
        &mut frame,
    )
    .expect("frame");
    stream.write_all(&frame).expect("write");
    let mut byte = [0_u8; 1];
    assert!(matches!(stream.read(&mut byte), Ok(0) | Err(_)));
    let error = thread
        .join()
        .expect("daemon thread")
        .expect_err("lost fence terminates serving");
    assert_eq!(error.category(), "stale_epoch");
}

#[test]
fn an_ambiguous_claim_degrades_until_an_exact_operator_failure() {
    let (_root, config) = fixture();
    std::fs::create_dir(config.state_dir()).expect("state directory");
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("state mode");
    let mut store = Store::open(config.database_path()).expect("seed store");
    let lease = store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "foreground",
            holder_id: "crashed-daemon",
            now_ms: 1,
            ttl_ms: 1,
        })
        .expect("old lease");
    store
        .submit_inbox(InboxSubmission {
            transport: "local.synthetic",
            transport_key: "ambiguous:1",
            scope: "workspace:ambiguous",
            payload: b"synthetic task",
            received_ms: 1,
        })
        .expect("durable input");
    let first_claim = store
        .claim_next(SchedulerClaim {
            transport: "local.synthetic",
            generation_id: "foreground",
            holder_id: "crashed-daemon",
            lease_epoch: lease.epoch,
            now_ms: 1,
        })
        .expect("claim")
        .expect("claimed run");
    let second_inbox = store
        .submit_inbox(InboxSubmission {
            transport: "local.synthetic",
            transport_key: "ambiguous:2",
            scope: "workspace:ambiguous:second",
            payload: b"second synthetic task",
            received_ms: 1,
        })
        .expect("second durable input");
    let second_claim = store
        .claim_work(WorkClaim {
            claim_key: "manual:ambiguous:2",
            inbox_id: second_inbox.inbox_id,
            scope: "workspace:ambiguous:second",
            generation_id: "foreground",
            holder_id: "crashed-daemon",
            lease_epoch: lease.epoch,
            now_ms: 1,
        })
        .expect("second ambiguous claim");
    drop(store);

    let daemon = Daemon::open(&config).expect("new generation opens");
    let stop = Arc::new(AtomicBool::new(false));
    let serve_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&serve_stop));
    wait_for_socket(&config);

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let AdminResponse::Status { status, .. } = call(&config, AdminCommand::Status) else {
            panic!("status response")
        };
        if status.state() == DaemonState::Failed {
            assert!(!status.accepting_intake());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not expose reconciliation state"
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    let inspected = call_request(
        &config,
        AdminRequest::inspect_reconciliation(
            RequestId::new("inspect-ambiguous").expect("request"),
            u64::try_from(first_claim.run_id).expect("run id"),
        )
        .expect("inspect request"),
    );
    let AdminResponse::ReconciliationInspected { evidence, .. } = inspected else {
        panic!("inspection response")
    };
    assert_eq!(evidence.run_id(), 1);
    assert!(!evidence.terminal_payload_present());
    assert_eq!(evidence.outbox_count(), 0);

    let failure = ReconciliationFailure::new(
        evidence.run_id(),
        evidence.generation_id(),
        evidence.lease_epoch(),
        evidence.run_revision(),
        "operator:ambiguous:1",
        "execution_outcome_unknown",
    )
    .expect("failure request");
    let wrong = ReconciliationFailure::new(
        evidence.run_id(),
        "wrong-generation",
        evidence.lease_epoch(),
        evidence.run_revision(),
        "operator:wrong:1",
        "execution_outcome_unknown",
    )
    .expect("wrong failure request");
    assert!(matches!(
        call_request(
            &config,
            AdminRequest::fail_reconciliation(
                RequestId::new("wrong-fail-ambiguous").expect("request"),
                wrong,
            ),
        ),
        AdminResponse::Refused { ref category, .. } if category.as_str() == "stale_epoch"
    ));
    let AdminResponse::Status { status, .. } = call(&config, AdminCommand::Status) else {
        panic!("status after refusal")
    };
    assert_eq!(status.state(), DaemonState::Failed);
    assert!(matches!(
        call_request(
            &config,
            AdminRequest::fail_reconciliation(
                RequestId::new("fail-ambiguous").expect("request"),
                failure.clone(),
            ),
        ),
        AdminResponse::ReconciliationFailed {
            duplicate: false,
            ..
        }
    ));
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let AdminResponse::Status { status, .. } = call(&config, AdminCommand::Status) else {
            panic!("status response")
        };
        if status.state() == DaemonState::Failed {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "second ambiguity was not discovered"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(matches!(
        call_request(
            &config,
            AdminRequest::fail_reconciliation(
                RequestId::new("retry-fail-ambiguous").expect("request"),
                failure,
            ),
        ),
        AdminResponse::ReconciliationFailed {
            duplicate: true,
            ..
        }
    ));
    let second = call_request(
        &config,
        AdminRequest::inspect_reconciliation(
            RequestId::new("inspect-second-ambiguous").expect("request"),
            u64::try_from(second_claim.run_id).expect("run id"),
        )
        .expect("inspect request"),
    );
    let AdminResponse::ReconciliationInspected { evidence, .. } = second else {
        panic!("second inspection response")
    };
    let second_failure = ReconciliationFailure::new(
        evidence.run_id(),
        evidence.generation_id(),
        evidence.lease_epoch(),
        evidence.run_revision(),
        "operator:ambiguous:2",
        "execution_outcome_unknown",
    )
    .expect("second failure request");
    assert!(matches!(
        call_request(
            &config,
            AdminRequest::fail_reconciliation(
                RequestId::new("fail-second-ambiguous").expect("request"),
                second_failure,
            ),
        ),
        AdminResponse::ReconciliationFailed {
            duplicate: false,
            ..
        }
    ));
    let AdminResponse::Status { status, .. } = call(&config, AdminCommand::Status) else {
        panic!("status response")
    };
    assert_eq!(status.state(), DaemonState::Ready);
    assert!(status.accepting_intake());
    assert!(matches!(
        call(&config, AdminCommand::Shutdown),
        AdminResponse::ShutdownAccepted { .. }
    ));
    thread.join().expect("join").expect("orderly serve");
}

#[test]
fn drop_never_unlinks_a_replacement_socket_inode() {
    let (_root, config) = fixture();
    let daemon = Daemon::open(&config).expect("daemon opens");
    std::fs::remove_file(config.admin_socket()).expect("unlink original name");
    let replacement = UnixListener::bind(config.admin_socket()).expect("replacement socket");
    std::fs::set_permissions(
        config.admin_socket(),
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("replacement mode");
    drop(daemon);
    assert!(config.admin_socket().exists());
    drop(replacement);
}

#[test]
fn a_stale_owned_socket_is_replaced_and_serves_status() {
    let (_root, config) = fixture();
    std::fs::create_dir(config.runtime_dir()).expect("runtime directory");
    std::fs::set_permissions(config.runtime_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("runtime mode");
    let stale = UnixListener::bind(config.admin_socket()).expect("stale socket");
    drop(stale);
    assert!(config.admin_socket().exists());

    let daemon = Daemon::open(&config).expect("replace stale socket");
    let stop = Arc::new(AtomicBool::new(false));
    let serve_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&serve_stop));
    assert!(matches!(
        call(&config, AdminCommand::Shutdown),
        AdminResponse::ShutdownAccepted { .. }
    ));
    thread.join().expect("daemon thread").expect("clean stop");
}

#[test]
fn a_symlinked_root_ancestor_is_refused() {
    let (root, mut config) = fixture();
    let linked = root.path().join("linked-runtime");
    std::os::unix::fs::symlink(&config.runtime_root, &linked).expect("runtime symlink");
    config.runtime_root = linked;
    let error = Daemon::open(&config).err().expect("symlink refused");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn rpc_shutdown_restores_the_calling_threads_signal_mask() {
    let (_root, config) = fixture();
    let worker_config = config.clone();
    let worker = std::thread::spawn(move || {
        let mut before = SigSet::empty();
        pthread_sigmask(SigmaskHow::SIG_BLOCK, None, Some(&mut before)).expect("read mask");
        run_foreground(&worker_config).expect("foreground run");
        let mut after = SigSet::empty();
        pthread_sigmask(SigmaskHow::SIG_BLOCK, None, Some(&mut after)).expect("read mask");
        (
            before.contains(Signal::SIGINT),
            before.contains(Signal::SIGTERM),
            after.contains(Signal::SIGINT),
            after.contains(Signal::SIGTERM),
        )
    });
    wait_for_socket(&config);
    assert!(matches!(
        call(&config, AdminCommand::Shutdown),
        AdminResponse::ShutdownAccepted { .. }
    ));
    let (before_int, before_term, after_int, after_term) = worker.join().expect("worker");
    assert_eq!((after_int, after_term), (before_int, before_term));
}

#[test]
fn insecure_roots_are_refused_without_creating_product_paths() {
    let (_root, config) = fixture();
    std::fs::set_permissions(&config.runtime_root, std::fs::Permissions::from_mode(0o755))
        .expect("make insecure");
    let error = match Daemon::open(&config) {
        Ok(_) => panic!("insecure runtime admitted"),
        Err(error) => error,
    };
    assert_eq!(error.category(), "insecure_path");
    assert!(!config.runtime_dir().exists());
}

#[test]
fn store_open_failure_never_publishes_an_admin_socket() {
    let (_root, config) = fixture();
    std::fs::create_dir(config.state_dir()).expect("state directory");
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("private state directory");
    std::fs::create_dir(config.database_path()).expect("invalid database directory");
    let error = Daemon::open(&config).err().expect("store failure");
    assert!(matches!(error, DaemonError::Store(_)));
    assert!(!config.admin_socket().exists());
}

#[test]
fn oversized_admin_prefix_is_closed_without_stopping_the_daemon() {
    let (_root, config) = fixture();
    let daemon = Daemon::open(&config).expect("daemon opens");
    let stop = Arc::new(AtomicBool::new(false));
    let serve_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&serve_stop));
    wait_for_socket(&config);

    let mut hostile = UnixStream::connect(config.admin_socket()).expect("connect hostile peer");
    hostile
        .write_all(&(70_000_u32).to_be_bytes())
        .expect("write prefix");
    hostile
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("timeout");
    let mut byte = [0_u8; 1];
    assert_eq!(hostile.read(&mut byte).expect("connection closes"), 0);

    assert!(matches!(
        call(&config, AdminCommand::Shutdown),
        AdminResponse::ShutdownAccepted { .. }
    ));
    thread.join().expect("daemon thread").expect("clean stop");
}
