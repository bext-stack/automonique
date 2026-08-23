// SPDX-License-Identifier: Elastic-2.0

//! Platform-v1 framing and durable controller semantics over the real socket.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use automonique_daemon::{Daemon, DaemonConfig};
use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_protocol::platform::{
    ClaimControlRequest, ClientId, ExecuteRequest, GetReceiptRequest, IdempotencyKey,
    ListSessionsRequest, PlatformAction, PlatformRequest, PlatformResponse, PlatformText,
    ReceiptOutcome, ResourceAuthority, ResourceCoordinate, ResourceId, ResourceKind,
    SnapshotRequest,
};
use automonique_protocol::platform_api::{PlatformRequestMessage, PlatformResponseMessage};
use automonique_store::approval_requests::{ApprovalContext, ApprovalProposal, ApprovalRequests};
use automonique_store::provider_journal::{ProcessSpawn, ProviderJournal, SessionOpening};
use automonique_store::run_index::{RunIndex, RunIndexEntry};

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

fn write_catalog_provider(config: &DaemonConfig, model: &str, is_default: bool) -> PathBuf {
    let home = config.state_dir().join("platform-provider-home");
    std::fs::create_dir_all(&home).expect("provider home");
    let binary = config.state_dir().join("platform-provider");
    rewrite_catalog_provider(&binary, model, is_default);
    let provider = config
        .state_dir()
        .join(automonique_daemon::compose::PROVIDER_CONFIG_NAME);
    std::fs::write(
        &provider,
        format!(
            "binary={}\nhome={}\nversion=platform-fixture\narg={{answer}}\n",
            binary.display(),
            home.display(),
        ),
    )
    .expect("provider configuration");
    std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o600))
        .expect("private provider configuration");
    binary
}

fn rewrite_catalog_provider(binary: &Path, model: &str, is_default: bool) {
    std::fs::write(
        binary,
        format!(
            "#!/bin/sh\nprintf '%s\\n' '{{\"id\":2,\"result\":{{\"data\":[{{\"id\":\"{model}\",\"model\":\"{model}\",\"hidden\":false,\"isDefault\":{is_default}}}],\"nextCursor\":null}}}}'\n"
        ),
    )
    .expect("fixture provider");
    std::fs::set_permissions(binary, std::fs::Permissions::from_mode(0o700))
        .expect("executable provider");
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
    let catalog_provider = write_catalog_provider(&config, "gpt-5.6-sol", true);
    let mut run_index = RunIndex::open(config.run_index_path()).expect("run index");
    run_index
        .register(RunIndexEntry {
            submission_id: 1,
            run_id: "platform-live-session",
            registered_at_ms: 9,
        })
        .expect("session run");
    drop(run_index);
    let mut approval_requests =
        ApprovalRequests::open(config.approval_requests_path()).expect("approval requests");
    approval_requests
        .propose(ApprovalProposal {
            request_key: "apr-000102030405060708090a0b0c0d0e0f",
            subject: "runspec:platform-live",
            run_id: "platform-live-session",
            context: ApprovalContext {
                spec_digest: "1111111111111111111111111111111111111111111111111111111111111111",
                program_path: "/usr/bin/platform-live",
                program_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
                prompt_sha256: "3333333333333333333333333333333333333333333333333333333333333333",
                cwd_token: "platform-live-cwd",
            },
            requested_by: "platform-live",
            requested_at_ms: 1,
            expires_at_ms: 9_000_000_000_000,
        })
        .expect("pending approval");
    drop(approval_requests);
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
    let first_node = snapshot
        .resources
        .iter()
        .find(|resource| {
            resource.resource.authority == ResourceAuthority::Automonique
                && resource.resource.kind == ResourceKind::Node
        })
        .expect("active node is projected")
        .clone();
    let mut actions = snapshot
        .resources
        .iter()
        .filter(|resource| {
            resource.resource.authority == ResourceAuthority::Automonique
                && resource.resource.kind == ResourceKind::Client
                && resource
                    .resource
                    .id
                    .as_str()
                    .starts_with("platform-action-")
        })
        .map(|resource| resource.resource.id.as_str())
        .collect::<Vec<_>>();
    actions.sort_unstable();
    assert_eq!(
        actions,
        [
            "platform-action-decide_approval",
            "platform-action-follow_up",
            "platform-action-start_run",
            "platform-action-stop_run",
            "platform-action-submit_request",
        ]
    );
    let model = snapshot
        .resources
        .iter()
        .find(|resource| resource.resource.kind == ResourceKind::Model)
        .expect("provider model is projected");
    assert_eq!(model.resource.authority, ResourceAuthority::Provider);
    assert_eq!(model.resource.id.as_str(), "gpt-5.6-sol");
    assert_eq!(model.freshness.state.as_str(), "fresh");
    assert_eq!(
        model.summary.as_str(),
        "source=codex_model_list; scope=configured_account; available=true; default=true; configured_route=false"
    );
    let approval = snapshot
        .resources
        .iter()
        .find(|resource| resource.resource.kind == ResourceKind::Approval)
        .expect("pending approval is projected");
    assert_eq!(
        approval.resource.id.as_str(),
        "apr-000102030405060708090a0b0c0d0e0f"
    );
    assert_eq!(approval.freshness.state.as_str(), "fresh");
    assert!(approval.summary.as_str().starts_with("state=pending;"));

    let PlatformResponse::Receipt(approval_receipt) = platform(
        &config,
        "approve",
        PlatformRequest::Execute(
            ExecuteRequest::new(
                PlatformAction::DecideApproval,
                approval.resource.clone(),
                IdempotencyKey::new("approval-live-decision").expect("key"),
                Some(approval.freshness.revision),
                Some(PlatformText::new("grant").expect("decision")),
            )
            .expect("approval action"),
        ),
    ) else {
        panic!("approval receipt")
    };
    assert_eq!(approval_receipt.outcome, ReceiptOutcome::Completed);

    let PlatformResponse::Snapshot(after_approval) = platform(
        &config,
        "snapshot-after-approval",
        PlatformRequest::Snapshot(SnapshotRequest::new(Vec::new()).expect("snapshot request")),
    ) else {
        panic!("snapshot after approval")
    };
    let resolved = after_approval
        .resources
        .iter()
        .find(|resource| resource.resource.id.as_str() == "apr-000102030405060708090a0b0c0d0e0f")
        .expect("resolved approval remains explicit");
    assert_eq!(resolved.freshness.state.as_str(), "stale");
    assert_eq!(resolved.summary.as_str(), "state=granted");

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
    assert_eq!(
        sessions.sessions[0]
            .run
            .as_ref()
            .expect("matching run")
            .id
            .as_str(),
        "platform-live-session"
    );

    let follow_up_key = IdempotencyKey::new("follow-up-live-1").expect("key");
    let PlatformResponse::Receipt(follow_up) = platform(
        &config,
        "follow-up",
        PlatformRequest::Execute(
            ExecuteRequest::new(
                PlatformAction::FollowUp,
                sessions.sessions[0].session.resource.clone(),
                follow_up_key.clone(),
                Some(sessions.sessions[0].session.freshness.revision),
                Some(PlatformText::new("continue with the verified next step").expect("body")),
            )
            .expect("follow-up action"),
        ),
    ) else {
        panic!("follow-up receipt")
    };
    assert_eq!(follow_up.outcome, ReceiptOutcome::Accepted);
    let PlatformResponse::Receipt(reconciled_follow_up) = platform(
        &config,
        "follow-up-reconcile",
        PlatformRequest::GetReceipt(GetReceiptRequest::by_idempotency_key(follow_up_key)),
    ) else {
        panic!("reconciled follow-up receipt")
    };
    assert_eq!(reconciled_follow_up, follow_up);

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
    rewrite_catalog_provider(&catalog_provider, "gpt-5.6-terra", false);
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
    let PlatformResponse::Snapshot(restarted_snapshot) = platform(
        &config,
        "snapshot-after-catalog-change",
        PlatformRequest::Snapshot(SnapshotRequest::new(Vec::new()).expect("snapshot request")),
    ) else {
        panic!("snapshot after catalog change")
    };
    let old_model = restarted_snapshot
        .resources
        .iter()
        .find(|resource| resource.resource.id.as_str() == "gpt-5.6-sol")
        .expect("removed model remains explicit");
    assert_eq!(old_model.freshness.state.as_str(), "stale");
    assert_eq!(
        old_model.summary.as_str(),
        "source=codex_model_list; scope=configured_account; available=false"
    );
    let current_model = restarted_snapshot
        .resources
        .iter()
        .find(|resource| resource.resource.id.as_str() == "gpt-5.6-terra")
        .expect("replacement model is projected");
    assert_eq!(current_model.freshness.state.as_str(), "fresh");
    assert_eq!(
        current_model.summary.as_str(),
        "source=codex_model_list; scope=configured_account; available=true; default=false; configured_route=false"
    );
    let retired_node = restarted_snapshot
        .resources
        .iter()
        .find(|resource| resource.resource == first_node.resource)
        .expect("retired node remains explicit");
    assert_eq!(retired_node.freshness.state.as_str(), "stale");
    assert_eq!(retired_node.summary.as_str(), "daemon retired");
    let PlatformResponse::Refused {
        outcome,
        explanation,
    } = platform(
        &config,
        "retired-node-submit",
        PlatformRequest::Execute(
            ExecuteRequest::new(
                PlatformAction::SubmitRequest,
                first_node.resource,
                IdempotencyKey::new("retired-node-submit").expect("key"),
                Some(first_node.freshness.revision),
                Some(PlatformText::new("must not enter intake").expect("body")),
            )
            .expect("submit request"),
        ),
    )
    else {
        panic!("retired node must be refused")
    };
    assert_eq!(outcome, ReceiptOutcome::Rejected);
    assert_eq!(explanation.as_str(), "target_not_active_node");
    serving.shutdown(&config);
}
