// SPDX-License-Identifier: Elastic-2.0

//! Deterministic authority-side preparation for the cross-client retained-session gate.
//!
//! This fixture deliberately uses three independently scoped client identities
//! against one real daemon socket and one durable session. It is necessary
//! acceptance preparation, not a substitute for the authorized live GUI flow
//! tracked by issue #169.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use automonique_daemon::managed_sessions::{ManagedHistorySource, ManagedSessionStore};
use automonique_daemon::{Daemon, DaemonConfig};
use automonique_platform_client::{
    ActionResult, ControlClaimResult, PlatformClient, SessionHistoryResult, UnixTransport,
};
use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_protocol::platform::{
    ActionReceipt, ClientId, GetReceiptRequest, IdempotencyKey, PlatformAction, PlatformParameter,
    PlatformRequest, PlatformResponse, ReceiptOutcome, ResourceAuthority, ResourceCoordinate,
    ResourceId, ResourceKind, SessionFollowUpRequest, SessionHistoryEvent,
};
use automonique_protocol::platform_api::{PlatformRequestMessage, PlatformResponseMessage};
use automonique_protocol::primitives::Revision;
use automonique_runner::backend::TERMINAL_COMPLETED;
use automonique_runner::{Authority, EventKind, Spool};
use automonique_store::run_index::{RunIndex, RunIndexEntry};
use rusqlite::Connection;

#[path = "support/isolation.rs"]
mod test_isolation;

const SESSION_ID: &str = "retained-acceptance-session";
const RUN_ID: &str = "retained-acceptance-run";
const SHELLDECK_CLIENT: &str = "shelldeck-acceptance";
const HOSTED_CLIENT: &str = "automonique-web-retained-session";
const MOBILE_CLIENT: &str = "mobile-credential-acceptance";
const FORBIDDEN_OUTPUTS: [&str; 6] = [
    "RAW_PROVIDER_PAYLOAD_SENTINEL",
    "TOOL_INPUT_SENTINEL",
    "TOOL_OUTPUT_SENTINEL",
    "CREDENTIAL_SENTINEL",
    "HIDDEN_REASONING_SENTINEL",
    "REPOSITORY_AUTHORITY_SENTINEL",
];

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

fn write_fixture_provider(config: &DaemonConfig) {
    let home = config.state_dir().join("acceptance-provider-home");
    std::fs::create_dir_all(&home).expect("provider home");
    let binary = config.state_dir().join("acceptance-provider");
    std::fs::write(
        &binary,
        "#!/bin/sh\nprintf '%s\\n' '{\"id\":2,\"result\":{\"data\":[{\"id\":\"fixture-model\",\"model\":\"fixture-model\",\"hidden\":false,\"isDefault\":true}],\"nextCursor\":null}}'\n",
    )
    .expect("fixture provider");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
        .expect("executable provider");
    let provider = config
        .state_dir()
        .join(automonique_daemon::compose::PROVIDER_CONFIG_NAME);
    std::fs::write(
        &provider,
        format!(
            "binary={}\nhome={}\nversion=acceptance-fixture\narg={{answer}}\n",
            binary.display(),
            home.display(),
        ),
    )
    .expect("provider configuration");
    std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o600))
        .expect("private provider configuration");
}

fn exchange(config: &DaemonConfig, payload: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(config.admin_socket()).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("deadline");
    let mut frame = Vec::new();
    encode_frame(payload, &mut frame).expect("frame");
    stream.write_all(&frame).expect("write");
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).expect("response prefix");
    let length = u32::from_be_bytes(prefix) as usize;
    let mut response = vec![0_u8; length + 4];
    response[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut response[4..]).expect("response");
    let FrameDecode::Frame { payload, .. } = decode_frame(&response).expect("decode") else {
        panic!("complete response was incomplete")
    };
    payload.to_vec()
}

fn raw_platform(
    config: &DaemonConfig,
    label: &str,
    request: PlatformRequest,
) -> (PlatformResponse, Vec<u8>) {
    let request_id = RequestId::new(label).expect("request id");
    let payload = PlatformRequestMessage::new(request_id.clone(), request)
        .to_message()
        .expect("request")
        .to_canonical_bytes();
    let bytes = exchange(config, &payload);
    let response =
        PlatformResponseMessage::from_canonical_bytes(&bytes).expect("platform response");
    assert_eq!(response.request_id(), &request_id);
    (response.response().clone(), bytes)
}

struct Serving {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<(), automonique_daemon::DaemonError>>>,
}

fn serve(config: &DaemonConfig) -> Serving {
    let daemon = Daemon::open(config).expect("daemon opens");
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&thread_stop));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !config.admin_socket().exists() {
        assert!(Instant::now() < deadline, "socket did not appear");
        std::thread::sleep(Duration::from_millis(10));
    }
    Serving {
        stop,
        thread: Some(thread),
    }
}

impl Serving {
    fn shutdown(mut self, config: &DaemonConfig) {
        let request = AdminRequest::new(
            RequestId::new("acceptance-shutdown").expect("request id"),
            AdminCommand::Shutdown,
        );
        let response = AdminResponse::from_canonical_bytes(&exchange(
            config,
            &request.to_message().expect("request").to_canonical_bytes(),
        ))
        .expect("shutdown response");
        assert!(matches!(response, AdminResponse::ShutdownAccepted { .. }));
        self.thread
            .take()
            .expect("thread")
            .join()
            .expect("join")
            .expect("clean stop");
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.stop.store(true, Ordering::Release);
            let _ = thread.join();
        }
    }
}

fn session() -> ResourceCoordinate {
    ResourceCoordinate::new(
        ResourceAuthority::Automonique,
        ResourceKind::Session,
        ResourceId::new(SESSION_ID).expect("session id"),
    )
}

fn scoped_client(id: &str) -> ClientId {
    ClientId::new(id).expect("client id")
}

fn client(config: &DaemonConfig) -> PlatformClient<UnixTransport> {
    PlatformClient::new(UnixTransport::new(config.admin_socket()))
}

fn follow_up(client_id: &str, key: &str, text: &str) -> SessionFollowUpRequest {
    SessionFollowUpRequest {
        client: scoped_client(client_id),
        session: session(),
        expected_session_revision: Revision::FIRST,
        idempotency_key: IdempotencyKey::new(key).expect("idempotency key"),
        text: PlatformParameter::new(text).expect("follow-up text"),
    }
}

fn terminal_receipt(
    client: &mut PlatformClient<UnixTransport>,
    client_id: &str,
    key: &str,
) -> ActionReceipt {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let receipt = client
            .reconcile_receipt_by_idempotency_key(
                scoped_client(client_id),
                IdempotencyKey::new(key).expect("idempotency key"),
                PlatformAction::FollowUp,
                session(),
            )
            .expect("scoped receipt");
        if !matches!(
            receipt.outcome,
            ReceiptOutcome::Accepted | ReceiptOutcome::Unknown
        ) {
            return receipt;
        }
        assert!(Instant::now() < deadline, "receipt did not become terminal");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn history_page(
    result: SessionHistoryResult,
) -> automonique_protocol::platform::SessionHistoryPage {
    let SessionHistoryResult::Page(page) = result else {
        panic!("expected retained history page")
    };
    page
}

#[test]
fn one_retained_session_survives_three_scoped_clients_ambiguity_and_reconnect() {
    let (root, config) = fixture();
    std::fs::create_dir(config.state_dir()).expect("product state");
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("private product state");
    write_fixture_provider(&config);

    let mut run_index = RunIndex::open(config.run_index_path()).expect("run index");
    run_index
        .register(RunIndexEntry {
            submission_id: 1,
            run_id: RUN_ID,
            registered_at_ms: 90,
        })
        .expect("acceptance run");
    drop(run_index);

    let mut sessions =
        ManagedSessionStore::open(config.managed_sessions_path()).expect("managed sessions");
    let binding = sessions
        .observe_terminal(SESSION_ID, RUN_ID, 100)
        .expect("retained session binding");
    assert_eq!(binding.revision, 1);

    let mut spool =
        Spool::open(root.path().join("history-spool"), RUN_ID, 1_000_000).expect("history spool");
    let forbidden = FORBIDDEN_OUTPUTS.join("|");
    spool
        .append(
            EventKind::Started,
            Authority::Authoritative,
            forbidden.as_bytes(),
        )
        .expect("started event");
    spool
        .append(
            EventKind::AdapterEvent,
            Authority::Authoritative,
            forbidden.as_bytes(),
        )
        .expect("opaque adapter event");
    spool
        .append(
            EventKind::Terminal,
            Authority::Authoritative,
            TERMINAL_COMPLETED,
        )
        .expect("terminal event");
    drop(spool);
    let spool_events = automonique_runner::read_events(root.path().join("history-spool"), RUN_ID)
        .expect("history events");
    sessions
        .record_completed_turn(
            SESSION_ID,
            ManagedHistorySource::PlatformV1("acceptance-turn-1"),
            "operator follow-up\0normalized",
            "bounded sanitized answer",
            &spool_events,
            110,
        )
        .expect("retained history");
    drop(sessions);

    let serving = serve(&config);
    let clients = [SHELLDECK_CLIENT, HOSTED_CLIENT, MOBILE_CLIENT];
    let mut sockets = [client(&config), client(&config), client(&config)];
    let mut attachments = Vec::new();
    let mut histories = Vec::new();
    for (index, client_id) in clients.iter().enumerate() {
        let sessions = sockets[index]
            .list_sessions(ResourceAuthority::Automonique, None)
            .expect("session directory");
        let listed = sessions
            .sessions
            .iter()
            .find(|listed| listed.session.resource == session())
            .expect("same retained session");
        assert_eq!(listed.run.as_ref().map(|run| run.id.as_str()), Some(RUN_ID));
        assert_eq!(listed.session.freshness.revision, Revision::FIRST);

        let attachment = sockets[index]
            .attach(session(), scoped_client(client_id))
            .expect("observer attachment");
        assert_eq!(attachment.session, session());
        assert_eq!(attachment.client.as_str(), *client_id);
        attachments.push(attachment);

        let command = sockets[index]
            .session_command_state(session())
            .expect("exact command state");
        assert_eq!(command.session.resource, session());
        assert_eq!(command.session.freshness.revision, Revision::FIRST);
        assert_eq!(
            command.run.as_ref().map(|run| run.target.id.as_str()),
            Some(RUN_ID)
        );

        histories.push(history_page(
            sockets[index]
                .session_history_snapshot(session(), 32)
                .expect("history snapshot"),
        ));
    }
    assert!(histories.windows(2).all(|pair| pair[0] == pair[1]));
    let initial_history = histories.first().expect("initial history");
    assert_eq!(initial_history.session, session());
    assert!(
        initial_history
            .events
            .windows(2)
            .all(|pair| pair[0].cursor() < pair[1].cursor())
    );
    for event in &initial_history.events {
        if let SessionHistoryEvent::Message { text, .. } = event {
            assert!(!text.as_str().chars().any(char::is_control));
        }
    }
    let (_, history_bytes) = raw_platform(
        &config,
        "acceptance-redaction-audit",
        PlatformRequest::SessionHistorySnapshot(
            automonique_protocol::platform::SessionHistorySnapshotRequest::new(session(), 32)
                .expect("history request"),
        ),
    );
    for forbidden in FORBIDDEN_OUTPUTS {
        assert!(
            !history_bytes
                .windows(forbidden.len())
                .any(|window| window == forbidden.as_bytes()),
            "history exposed {forbidden}"
        );
    }

    let shell_control = sockets[0]
        .claim_control(
            session(),
            scoped_client(SHELLDECK_CLIENT),
            IdempotencyKey::new("shelldeck-control").expect("key"),
        )
        .expect("exclusive controller");
    assert_eq!(shell_control.client.as_str(), SHELLDECK_CLIENT);
    let ControlClaimResult::Refused { outcome, .. } = sockets[1]
        .claim_control_outcome(
            session(),
            scoped_client(HOSTED_CLIENT),
            IdempotencyKey::new("hosted-control-conflict").expect("key"),
        )
        .expect("typed control conflict")
    else {
        panic!("observer attachment must not grant control")
    };
    assert_eq!(outcome, ReceiptOutcome::Conflict);

    let shell_request = follow_up(
        SHELLDECK_CLIENT,
        "shelldeck-follow-up",
        "continue from ShellDeck",
    );
    let mobile_request = follow_up(MOBILE_CLIENT, "mobile-follow-up", "continue from mobile");
    for (index, request) in [(0, shell_request), (2, mobile_request)] {
        let ActionResult::Receipt(receipt) = sockets[index]
            .session_follow_up_outcome(request)
            .expect("dedicated follow-up")
        else {
            panic!("exact follow-up was refused")
        };
        assert_eq!(receipt.outcome, ReceiptOutcome::Accepted);
    }

    // Simulate the hosted client losing the response after the authority has
    // processed it. The returned bytes are intentionally discarded and the
    // request is never submitted again; only its original key is reconciled.
    let hosted = follow_up(
        HOSTED_CLIENT,
        "hosted-follow-up-ambiguous",
        "continue from hosted cockpit",
    );
    let request_id = RequestId::new("hosted-response-lost").expect("request id");
    let payload = PlatformRequestMessage::new(request_id, PlatformRequest::SessionFollowUp(hosted))
        .to_message()
        .expect("request")
        .to_canonical_bytes();
    drop(exchange(&config, &payload));

    let stale_key = IdempotencyKey::new("stale-follow-up").expect("key");
    let ActionResult::Refused {
        outcome,
        explanation,
    } = sockets[1]
        .session_follow_up_outcome(SessionFollowUpRequest {
            client: scoped_client(HOSTED_CLIENT),
            session: session(),
            expected_session_revision: Revision::new(2).expect("stale revision"),
            idempotency_key: stale_key.clone(),
            text: PlatformParameter::new("must be refused").expect("text"),
        })
        .expect("typed stale refusal")
    else {
        panic!("stale revision was admitted")
    };
    assert_eq!(outcome, ReceiptOutcome::Rejected);
    assert_eq!(explanation.as_str(), "stale_revision");
    assert!(
        sockets[1]
            .get_receipt(
                GetReceiptRequest::by_idempotency_key(stale_key)
                    .with_client(scoped_client(HOSTED_CLIENT)),
            )
            .is_err(),
        "a refused stale command must not write a receipt"
    );

    for (index, client_id) in clients.iter().enumerate() {
        sockets[index]
            .detach(session(), scoped_client(client_id))
            .expect("detach observer");
    }
    serving.shutdown(&config);

    // New client objects and a restarted daemon are the deterministic
    // disconnect/reconnect boundary. Receipt ownership and history survive it.
    let serving = serve(&config);
    let mut reconnected = [client(&config), client(&config), client(&config)];
    for (index, client_id) in clients.iter().enumerate() {
        let attachment = reconnected[index]
            .attach(session(), scoped_client(client_id))
            .expect("reattach observer");
        assert_eq!(attachment.session, attachments[index].session);
        let resumed = history_page(
            reconnected[index]
                .session_history_page(session(), initial_history.terminal_cursor, 32)
                .expect("resume history"),
        );
        assert!(resumed.events.is_empty());
        assert_eq!(resumed.from_cursor, initial_history.terminal_cursor);
        assert_eq!(resumed.terminal_cursor, initial_history.terminal_cursor);
    }

    let shell_receipt =
        terminal_receipt(&mut reconnected[0], SHELLDECK_CLIENT, "shelldeck-follow-up");
    let hosted_receipt = terminal_receipt(
        &mut reconnected[1],
        HOSTED_CLIENT,
        "hosted-follow-up-ambiguous",
    );
    let mobile_receipt = terminal_receipt(&mut reconnected[2], MOBILE_CLIENT, "mobile-follow-up");
    assert_eq!(shell_receipt.action, PlatformAction::FollowUp);
    assert_eq!(hosted_receipt.action, PlatformAction::FollowUp);
    assert_eq!(mobile_receipt.action, PlatformAction::FollowUp);
    assert_ne!(shell_receipt.id, hosted_receipt.id);
    assert_ne!(hosted_receipt.id, mobile_receipt.id);
    assert!(
        reconnected[0]
            .reconcile_receipt_by_idempotency_key(
                scoped_client(SHELLDECK_CLIENT),
                IdempotencyKey::new("hosted-follow-up-ambiguous").expect("key"),
                PlatformAction::FollowUp,
                session(),
            )
            .is_err(),
        "one scoped client must not read another client's receipt"
    );
    serving.shutdown(&config);

    // Advance retention out from under the clients, then prove an old cursor
    // returns only a replacement window and a fresh snapshot replaces it.
    let connection = Connection::open(config.managed_sessions_path()).expect("history database");
    connection
        .execute(
            "DELETE FROM managed_session_history WHERE provider_session_id=?1 AND sequence=1",
            [SESSION_ID],
        )
        .expect("advance retention floor");
    drop(connection);
    let serving = serve(&config);
    let mut after_gap = client(&config);
    let SessionHistoryResult::ReplaceWithSnapshot(replacement) = after_gap
        .session_history_page(session(), 0, 32)
        .expect("typed retention gap")
    else {
        panic!("stale history cursor returned a partial page")
    };
    assert_eq!(replacement.session, session());
    assert_eq!(replacement.snapshot_from, 1);
    assert_eq!(replacement.snapshot_to, initial_history.terminal_cursor);
    let replacement_page = history_page(
        after_gap
            .session_history_snapshot(session(), 32)
            .expect("replacement snapshot"),
    );
    assert_eq!(replacement_page.from_cursor, replacement.snapshot_from);
    assert_eq!(replacement_page.terminal_cursor, replacement.snapshot_to);
    assert_eq!(
        replacement_page
            .events
            .first()
            .map(SessionHistoryEvent::cursor),
        Some(2)
    );
    serving.shutdown(&config);
}
