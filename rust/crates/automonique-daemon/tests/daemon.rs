// SPDX-License-Identifier: Elastic-2.0

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use automonique_daemon::{
    Daemon, DaemonConfig, DaemonError, MAX_ADMIN_PAYLOAD_BYTES, run_foreground,
};
use automonique_protocol::admin::{
    AdminCommand, AdminRequest, AdminResponse, DaemonState, OutboxReconciliation,
    OutboxReconciliationDecision, OutboxReconciliationParts, ReconciliationFailure,
    SyntheticSubmission,
};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_store::{
    InboxSubmission, LeaseOwnerIdentity, LeaseRequest, LeaseTimeSource, OutboxClaimRequest,
    SchedulerClaim, Store, TelegramPollerLeaseIdentity, TelegramPollerLeaseRequest, TerminalRun,
    TerminalState, WorkClaim,
};
use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};
use nix::sys::time::TimeValLike;
use nix::time::ClockId;

#[path = "support/isolation.rs"]
mod test_isolation;

struct BootClock;

impl LeaseTimeSource for BootClock {
    fn now_boottime_ms(&self) -> Result<i64, &'static str> {
        ClockId::CLOCK_BOOTTIME
            .now()
            .map(|value| value.num_milliseconds())
            .map_err(|_| "clock_gettime")
    }
}

fn fixture() -> (tempfile::TempDir, DaemonConfig) {
    let root = tempfile::tempdir().expect("temporary root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private root");
    let runtime = root.path().join("runtime");
    test_isolation::assert_isolated_runtime_root(&runtime);
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

fn current_lease_owner() -> (String, u64) {
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .expect("boot identity")
        .trim()
        .to_owned();
    let stat = std::fs::read_to_string("/proc/self/stat").expect("process stat");
    let close = stat.rfind(')').expect("process name boundary");
    let starttime = stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .expect("process starttime field")
        .parse::<u64>()
        .expect("numeric process starttime");
    (boot_id, starttime)
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

fn seed_expired_outbox(config: &DaemonConfig) -> (u64, String, u64, u64, u64) {
    std::fs::create_dir(config.state_dir()).expect("state directory");
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("state mode");
    let mut store = Store::open(config.database_path()).expect("seed store");
    let generation = store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "foreground",
            holder_id: "crashed-outbox",
            now_ms: 1,
            ttl_ms: 100,
        })
        .expect("old generation");
    store
        .submit_inbox(InboxSubmission {
            transport: "local.synthetic",
            transport_key: "outbox:ambiguous",
            scope: "workspace:outbox",
            payload: b"never exposed",
            received_ms: 2,
        })
        .expect("inbox");
    let run = store
        .claim_next(SchedulerClaim {
            transport: "local.synthetic",
            generation_id: "foreground",
            holder_id: "crashed-outbox",
            lease_epoch: generation.epoch,
            now_ms: 3,
        })
        .expect("claim")
        .expect("run");
    store
        .finish_run(TerminalRun {
            run_id: run.run_id,
            generation_id: "foreground",
            holder_id: "crashed-outbox",
            lease_epoch: generation.epoch,
            expected_revision: 1,
            now_ms: 4,
            state: TerminalState::Succeeded,
            event_kind: "run.succeeded",
            event_payload: b"synthetic",
            outbox_intent_key: "fake:ambiguous",
            outbox_kind: "fake.receipt",
            outbox_payload: b"secret-effect-payload",
        })
        .expect("terminal outbox");
    let lease = store
        .claim_outbox(OutboxClaimRequest {
            transport: "fake",
            kind: "fake.receipt",
            generation_id: "foreground",
            holder_id: "crashed-outbox",
            lease_epoch: generation.epoch,
            now_ms: 5,
            ttl_ms: 10,
        })
        .expect("claim outbox")
        .expect("effect");
    (
        u64::try_from(lease.outbox_id).expect("outbox id"),
        lease.lease_token,
        generation.epoch,
        lease.attempt,
        lease.revision,
    )
}

#[test]
fn expired_outbox_requires_exact_fenced_operator_reconciliation_and_replays_after_restart() {
    let (_root, config) = fixture();
    let (outbox_id, token, old_epoch, attempt, revision) = seed_expired_outbox(&config);
    let daemon = Daemon::open(&config).expect("successor daemon");
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&thread_stop));
    wait_for_socket(&config);

    let AdminResponse::Status { status, .. } = call(&config, AdminCommand::Status) else {
        panic!("status response")
    };
    assert_eq!(status.state(), DaemonState::Failed);
    assert!(!status.accepting_intake());
    let operational = status.operational().expect("operational projection");
    assert_eq!(operational.outbox_in_flight_ambiguous(), 1);
    assert_eq!(operational.reconciliation_pending(), 1);
    assert_eq!(
        operational.provider_available(),
        automonique_protocol::admin::OperationalMetric::Measured(0)
    );
    let blocked_submission = SyntheticSubmission::new(
        "workspace:blocked",
        "outbox-ambiguity-blocks-intake",
        "must not be admitted",
    )
    .expect("synthetic submission");
    assert!(matches!(
        call_request(
            &config,
            AdminRequest::submit(
                RequestId::new("blocked-outbox-intake").expect("request"),
                blocked_submission,
            ),
        ),
        AdminResponse::Refused { ref category, .. }
            if category.as_str() == "reconciliation_required"
    ));

    let inspected = call_request(
        &config,
        AdminRequest::inspect_outbox(
            RequestId::new("inspect-outbox").expect("request"),
            outbox_id,
        )
        .expect("inspect"),
    );
    let AdminResponse::OutboxInspected { evidence, .. } = inspected else {
        panic!("inspection")
    };
    assert_eq!(evidence.state(), "in_flight");
    assert_eq!(evidence.lease_token(), Some(token.as_str()));
    assert_eq!(evidence.lease_generation_id(), Some("foreground"));
    assert_eq!(evidence.attempt(), attempt);
    assert_eq!(evidence.revision(), revision);

    let wrong = OutboxReconciliation::new(OutboxReconciliationParts {
        outbox_id,
        expected_generation_id: "wrong-generation".to_owned(),
        expected_lease_epoch: old_epoch,
        expected_lease_token: token.clone(),
        expected_attempt: attempt,
        expected_revision: revision,
        decision: OutboxReconciliationDecision::Delivered {
            receipt_key: "operator:receipt:1".to_owned(),
        },
    })
    .expect("wrong request");
    assert!(matches!(
        call_request(&config, AdminRequest::reconcile_outbox(RequestId::new("wrong-outbox").expect("request"), wrong)),
        AdminResponse::Refused { ref category, .. } if category.as_str() == "stale_epoch"
    ));
    let unchanged = call_request(
        &config,
        AdminRequest::inspect_outbox(
            RequestId::new("inspect-unchanged").expect("request"),
            outbox_id,
        )
        .expect("inspect"),
    );
    assert!(
        matches!(unchanged, AdminResponse::OutboxInspected { ref evidence, .. } if evidence.state() == "in_flight" && evidence.revision() == revision)
    );

    let exact = OutboxReconciliation::new(OutboxReconciliationParts {
        outbox_id,
        expected_generation_id: "foreground".to_owned(),
        expected_lease_epoch: old_epoch,
        expected_lease_token: token,
        expected_attempt: attempt,
        expected_revision: revision,
        decision: OutboxReconciliationDecision::Delivered {
            receipt_key: "operator:receipt:1".to_owned(),
        },
    })
    .expect("exact request");
    assert!(matches!(
        call_request(&config, AdminRequest::reconcile_outbox(RequestId::new("resolve-outbox").expect("request"), exact.clone())),
        AdminResponse::OutboxReconciled { state, duplicate: false, .. } if state == "delivered"
    ));
    assert!(matches!(
        call(&config, AdminCommand::Shutdown),
        AdminResponse::ShutdownAccepted { .. }
    ));
    thread.join().expect("join").expect("shutdown");

    let daemon = Daemon::open(&config).expect("restart");
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&thread_stop));
    wait_for_socket(&config);
    assert!(matches!(
        call_request(&config, AdminRequest::reconcile_outbox(RequestId::new("replay-outbox").expect("request"), exact)),
        AdminResponse::OutboxReconciled { state, duplicate: true, .. } if state == "delivered"
    ));
    assert!(matches!(
        call(&config, AdminCommand::Shutdown),
        AdminResponse::ShutdownAccepted { .. }
    ));
    thread.join().expect("join").expect("shutdown");
}

#[test]
fn clean_telegram_release_does_not_invent_reconciliation_debt() {
    let (_root, config) = fixture();
    std::fs::create_dir(config.state_dir()).expect("state directory");
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("state mode");
    let mut store = Store::open(config.database_path()).expect("seed store");
    let generation = store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "foreground",
            holder_id: "crashed-telegram",
            now_ms: 1,
            ttl_ms: 20,
        })
        .expect("old generation");
    let poller = store
        .acquire_telegram_poller_lease(TelegramPollerLeaseRequest {
            bot_id: 7,
            generation_id: "foreground",
            holder_id: "crashed-telegram",
            authority_lease_epoch: generation.epoch,
            now_ms: 1,
            ttl_ms: 10,
        })
        .expect("old telegram poller");
    store
        .release_telegram_poller_lease(TelegramPollerLeaseIdentity {
            bot_id: poller.bot_id,
            generation_id: &poller.generation_id,
            holder_id: &poller.holder_id,
            poller_epoch: poller.epoch,
            expected_expires_ms: poller.expires_ms,
            now_ms: 2,
        })
        .expect("clean poller release");
    drop(store);

    let daemon = Daemon::open(&config).expect("successor daemon");
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&thread_stop));
    wait_for_socket(&config);

    let AdminResponse::Status { status, .. } = call(&config, AdminCommand::Status) else {
        panic!("status response")
    };
    assert_eq!(status.state(), DaemonState::Ready);
    assert!(status.accepting_intake());
    assert!(matches!(
        call_request(
            &config,
            AdminRequest::submit(
                RequestId::new("released-telegram-intake").expect("request"),
                SyntheticSubmission::new(
                    "workspace:released",
                    "released-telegram-does-not-block",
                    "admitted fixture",
                )
                .expect("synthetic submission"),
            ),
        ),
        AdminResponse::SyntheticAccepted {
            duplicate: false,
            ..
        }
    ));
    assert!(matches!(
        call(&config, AdminCommand::Shutdown),
        AdminResponse::ShutdownAccepted { .. }
    ));
    thread.join().expect("join").expect("shutdown");
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
    assert_eq!(
        status.telegram_state(),
        automonique_protocol::admin::TelegramState::DisabledNoClient
    );
    assert_eq!(status.telegram_poller_epoch(), None);
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
    let before_snapshot = Store::open(config.database_path())
        .expect("inspect before")
        .status_snapshot("foreground")
        .expect("snapshot before");
    let before = before_snapshot.generation().expect("generation before");
    for _ in 0..40 {
        assert!(matches!(
            call(&config, AdminCommand::Status),
            AdminResponse::Status { .. }
        ));
    }
    let after_snapshot = Store::open(config.database_path())
        .expect("inspect after")
        .status_snapshot("foreground")
        .expect("snapshot after");
    let after = after_snapshot.generation().expect("generation after");
    assert_eq!(after.revision(), before.revision());
    assert_eq!(after.lease_expires_ms(), before.lease_expires_ms());
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
        .event_cursor();
    assert!(matches!(
        Daemon::open(&config),
        Err(DaemonError::AlreadyRunning)
    ));
    let after = Store::open(config.database_path())
        .expect("inspect store")
        .status_snapshot("foreground")
        .expect("status after")
        .event_cursor();
    assert_eq!(
        after, before,
        "refused bind must not mutate generation state"
    );
    drop(first);
}

#[test]
fn one_state_root_refuses_a_second_daemon_even_with_another_runtime_socket() {
    let (root, config) = fixture();
    let first = Daemon::open(&config).expect("first daemon");
    let other_runtime = root.path().join("other-runtime");
    std::fs::create_dir(&other_runtime).expect("second runtime root");
    std::fs::set_permissions(&other_runtime, std::fs::Permissions::from_mode(0o700))
        .expect("private second runtime");
    let second_config = DaemonConfig {
        runtime_root: other_runtime,
        state_root: config.state_root.clone(),
    };

    assert!(matches!(
        Daemon::open(&second_config),
        Err(DaemonError::AlreadyRunning)
    ));
    assert!(
        !second_config.admin_socket().exists(),
        "state exclusion must happen before a competing endpoint is published"
    );
    drop(first);
}

#[test]
fn startup_never_sweeps_an_exact_owner_the_kernel_still_reports_live() {
    let (_root, config) = fixture();
    std::fs::create_dir(config.state_dir()).expect("state directory");
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("private state directory");
    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("forward clock")
            .as_millis(),
    )
    .expect("millisecond clock fits");
    let (boot_id, starttime) = current_lease_owner();
    let mut store = Store::open(config.database_path()).expect("seed store");
    let lease = store
        .acquire_generation_lease_owned(
            LeaseRequest {
                generation_id: "foreground",
                holder_id: "live-owner",
                now_ms,
                ttl_ms: 60_000,
            },
            LeaseOwnerIdentity {
                boot_id: &boot_id,
                pid: std::process::id(),
                starttime,
            },
        )
        .expect("live lease");
    drop(store);

    assert!(matches!(
        Daemon::open(&config),
        Err(DaemonError::AlreadyRunning)
    ));
    assert!(
        !config.admin_socket().exists(),
        "refused startup cleans its socket"
    );

    let mut store = Store::open(config.database_path()).expect("inspect store");
    let snapshot = store
        .status_snapshot_at("foreground", now_ms + 1)
        .expect("snapshot");
    let generation = snapshot.generation().expect("generation remains");
    assert_eq!(generation.holder_id(), "live-owner");
    assert_eq!(generation.lease_epoch(), lease.epoch);
    assert_eq!(generation.lease_expires_ms(), lease.expires_ms);
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
    Store::open_with_lease_time_source(config.database_path(), Arc::new(BootClock))
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

/// THE SLACK GATE, AT STARTUP. A present-but-wrong `slack.conf` refuses the
/// daemon rather than being ignored, and no admin socket is published — an
/// operator error about which channels are reachable must not hide behind a
/// daemon that came up looking healthy.
#[test]
fn a_refused_slack_configuration_refuses_startup_and_publishes_no_socket() {
    /// Write one `slack.conf` into a fresh fixture and try to open a daemon
    /// over it. A fixture each, because a refused open leaves a durable
    /// generation lease behind and the next one would be refused for holding
    /// it rather than for the configuration.
    fn open_with(
        body: &str,
        mode: u32,
    ) -> (tempfile::TempDir, DaemonConfig, Result<(), DaemonError>) {
        let (root, config) = fixture();
        let slack = config.state_dir().join("slack");
        std::fs::create_dir_all(&slack).expect("slack directory");
        std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
            .expect("private state directory");
        std::fs::set_permissions(&slack, std::fs::Permissions::from_mode(0o700))
            .expect("private slack directory");
        let path = slack.join("slack.conf");
        std::fs::write(&path, body).expect("configuration written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("configuration permissions");
        let opened = Daemon::open(&config).map(drop);
        (root, config, opened)
    }

    const VALID: &str = "schema=automonique.slack/v1\n\
                         token=xoxb-0000000000-fixture-secret-never-print\n\
                         channel=ops:C0RESERVED01\n\
                         end=automonique.slack/v1\n";

    // A channel map naming an id that is not one.
    let (_root, config, opened) = open_with(
        "schema=automonique.slack/v1\n\
         token=xoxb-0000000000-fixture-secret-never-print\n\
         channel=ops:not-an-id\n\
         end=automonique.slack/v1\n",
        0o600,
    );
    let error = opened.expect_err("bad channel map refused");
    assert!(matches!(error, DaemonError::SlackRefused(_)));
    assert_eq!(error.category(), "slack_config_channel");
    assert!(!config.admin_socket().exists());

    // A credential anybody on the host can read is refused before it is parsed.
    let (_root, config, opened) = open_with(VALID, 0o644);
    let error = opened.expect_err("exposed credential refused");
    assert_eq!(error.category(), "slack_config_insecure");
    assert!(!config.admin_socket().exists());

    // The same file, private, is the configured state — and this daemon opens.
    let (_root, _config, opened) = open_with(VALID, 0o600);
    opened.expect("a valid configuration opens");

    // And an absent file is the disabled state, which is not an error at all.
    let (_root, config) = fixture();
    Daemon::open(&config).expect("an absent configuration is deliberate");
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
    let oversized = u32::try_from(MAX_ADMIN_PAYLOAD_BYTES + 1).expect("payload ceiling fits u32");
    hostile
        .write_all(&oversized.to_be_bytes())
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
