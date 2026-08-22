// SPDX-License-Identifier: Elastic-2.0

//! Platform-v1 framing and durable controller semantics over the real socket.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use automonique_daemon::{Daemon, DaemonConfig};
use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_protocol::platform::{
    ClaimControlRequest, ClientId, IdempotencyKey, ListSessionsRequest, PlatformRequest,
    PlatformResponse, ResourceAuthority, ResourceCoordinate, ResourceId, ResourceKind,
    SnapshotRequest,
};
use automonique_protocol::platform_api::{PlatformRequestMessage, PlatformResponseMessage};
use automonique_store::provider_journal::{ProcessSpawn, ProviderJournal, SessionOpening};

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

fn platform(config: &DaemonConfig, label: &str, request: PlatformRequest) -> PlatformResponse {
    let request_id = RequestId::new(label).expect("request id");
    let payload = PlatformRequestMessage::new(request_id.clone(), request)
        .to_message()
        .expect("request")
        .to_canonical_bytes();
    let response = PlatformResponseMessage::from_canonical_bytes(&exchange(config, &payload))
        .expect("platform response");
    assert_eq!(response.request_id(), &request_id);
    response.response().clone()
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
            RequestId::new("shutdown").expect("request id"),
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
        ResourceId::new("platform-live-session").expect("session id"),
    )
}

#[test]
fn platform_capabilities_snapshot_and_controller_are_live_and_durable() {
    let (_root, config) = fixture();
    std::fs::create_dir(config.state_dir()).expect("product state");
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("private product state");
    let mut journal = ProviderJournal::open(config.provider_journal_path()).expect("journal");
    let process = journal
        .record_process(ProcessSpawn {
            spawn_key: "platform-live-spawn",
            attempt_id: "platform-live-attempt",
            provider_kind: "fake",
            executable_digest: "abababababababababababababababababababababababababababababababab",
            spawned_ms: 10,
        })
        .expect("process");
    journal
        .open_session(SessionOpening {
            process_id: process.process_id,
            provider_session_key: "platform-live-session",
            opened_ms: 20,
        })
        .expect("session");
    drop(journal);
    let serving = serve(&config);

    let PlatformResponse::Capabilities(capabilities) =
        platform(&config, "capabilities", PlatformRequest::Capabilities)
    else {
        panic!("capabilities response")
    };
    assert_eq!(capabilities.methods.len(), 10);
    assert_eq!(capabilities.transports.len(), 1);

    let PlatformResponse::Snapshot(snapshot) = platform(
        &config,
        "snapshot",
        PlatformRequest::Snapshot(SnapshotRequest::new(Vec::new()).expect("snapshot request")),
    ) else {
        panic!("snapshot response")
    };
    assert!(snapshot.resources.iter().any(|resource| {
        resource.resource.authority == ResourceAuthority::Automonique
            && resource.resource.kind == ResourceKind::Node
    }));

    let PlatformResponse::Sessions(sessions) = platform(
        &config,
        "sessions",
        PlatformRequest::ListSessions(ListSessionsRequest {
            authority: ResourceAuthority::Automonique,
            cursor: None,
        }),
    ) else {
        panic!("sessions response")
    };
    assert_eq!(sessions.sessions.len(), 1);
    assert_eq!(
        sessions.sessions[0].session.resource.id.as_str(),
        "platform-live-session"
    );
    assert!(sessions.sessions[0].attachable);

    let request = ClaimControlRequest {
        session: session(),
        client: ClientId::new("client-a").expect("client"),
        idempotency_key: IdempotencyKey::new("claim-live-1").expect("key"),
    };
    let PlatformResponse::ControlClaimed(first) = platform(
        &config,
        "claim-1",
        PlatformRequest::ClaimControl(request.clone()),
    ) else {
        panic!("control lease")
    };
    let PlatformResponse::ControlClaimed(replay) =
        platform(&config, "claim-2", PlatformRequest::ClaimControl(request))
    else {
        panic!("replayed control lease")
    };
    assert_eq!(replay, first);

    serving.shutdown(&config);
    let serving = serve(&config);
    let PlatformResponse::ControlClaimed(restarted_replay) = platform(
        &config,
        "claim-3",
        PlatformRequest::ClaimControl(ClaimControlRequest {
            session: session(),
            client: ClientId::new("client-a").expect("client"),
            idempotency_key: IdempotencyKey::new("claim-live-1").expect("key"),
        }),
    ) else {
        panic!("restart replay")
    };
    assert_eq!(restarted_replay, first);
    serving.shutdown(&config);
}
