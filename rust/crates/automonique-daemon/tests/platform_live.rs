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
    ListSessionsRequest, PlatformAction, PlatformParameter, PlatformRequest, PlatformResponse,
    PlatformText, ReceiptOutcome, ResourceAuthority, ResourceCoordinate, ResourceId, ResourceKind,
    SessionApprovalDecision, SessionApprovalDecisionRequest, SessionCommandStateRequest,
    SessionFollowUpRequest, SessionRunStopRequest, SnapshotRequest,
};
use automonique_protocol::platform_api::{PlatformRequestMessage, PlatformResponseMessage};
use automonique_protocol::platform_v2::{
    PlatformVersion, PlatformVersionOffer, UserWorkspaceId, WorkContextIdentity,
};
use automonique_protocol::platform_v2_transport::{
    PlatformNegotiationRequest, PlatformNegotiationRequestMessage, PlatformNegotiationResponse,
    PlatformNegotiationResponseMessage, PlatformV2Request, PlatformV2RequestMessage,
    PlatformV2Response, PlatformV2ResponseMessage,
};
use automonique_protocol::primitives::Revision;
use automonique_store::approval_requests::{
    ApprovalContext, ApprovalProposal, ApprovalRequests, ApprovalState,
};
use automonique_store::provider_journal::{ProcessSpawn, ProviderJournal, SessionOpening};
use automonique_store::run_index::{RunIndex, RunIndexEntry, RunSpoolState, StateAdvance};

#[path = "support/isolation.rs"]
mod test_isolation;

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

#[test]
fn negotiation_advertises_only_v1_and_v2_fails_closed_until_host_wiring() {
    let (_root, config) = fixture();
    let serving = serve(&config);

    let negotiation = PlatformNegotiationRequestMessage::new(
        RequestId::new("negotiate-v1").unwrap(),
        PlatformNegotiationRequest::Negotiate(PlatformVersionOffer::new(vec![1, 2]).unwrap()),
    );
    let response = PlatformNegotiationResponseMessage::from_canonical_bytes(
        &exchange(&config, &negotiation.to_canonical_bytes().unwrap()),
        &negotiation,
    )
    .unwrap();
    assert!(matches!(
        response.response(),
        PlatformNegotiationResponse::Negotiated(selected)
            if selected.version() == PlatformVersion::V1
    ));

    let v2_only = PlatformNegotiationRequestMessage::new(
        RequestId::new("negotiate-v2-only").unwrap(),
        PlatformNegotiationRequest::Negotiate(PlatformVersionOffer::new(vec![2]).unwrap()),
    );
    let response = PlatformNegotiationResponseMessage::from_canonical_bytes(
        &exchange(&config, &v2_only.to_canonical_bytes().unwrap()),
        &v2_only,
    )
    .unwrap();
    assert!(matches!(
        response.response(),
        PlatformNegotiationResponse::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_unavailable"
    ));

    let v2 = PlatformV2RequestMessage::new(
        RequestId::new("v2-unavailable").unwrap(),
        PlatformV2Request::GetWorkContext(WorkContextIdentity::UserWorkspace(
            UserWorkspaceId::new("workspace-1").unwrap(),
        )),
    );
    let response = PlatformV2ResponseMessage::from_canonical_bytes(
        &exchange(&config, &v2.to_canonical_bytes().unwrap()),
        &v2,
    )
    .unwrap();
    assert!(matches!(
        response.response(),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_unavailable"
    ));

    serving.shutdown(&config);
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

fn automonique_coordinate(kind: ResourceKind, id: &str) -> ResourceCoordinate {
    ResourceCoordinate::new(
        ResourceAuthority::Automonique,
        kind,
        ResourceId::new(id).expect("resource id"),
    )
}

fn approval_proposal<'a>(key: &'a str, run_id: &'a str) -> ApprovalProposal<'a> {
    ApprovalProposal {
        request_key: key,
        subject: "runspec:session-command-test",
        run_id,
        context: ApprovalContext {
            spec_digest: "1111111111111111111111111111111111111111111111111111111111111111",
            program_path: "/usr/bin/session-command-test",
            program_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
            prompt_sha256: "3333333333333333333333333333333333333333333333333333333333333333",
            cwd_token: "session-command-cwd",
        },
        requested_by: "session-command-test",
        requested_at_ms: 1,
        expires_at_ms: 9_000_000_000_000,
    }
}

#[test]
fn session_commands_are_fenced_to_the_managed_owner_before_receipt_admission() {
    let (_root, config) = fixture();
    std::fs::create_dir(config.state_dir()).expect("product state");
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("private product state");

    let mut run_index = RunIndex::open(config.run_index_path()).expect("run index");
    for (submission_id, run_id) in [
        (1, "owned-run"),
        (2, "foreign-run"),
        (3, "old-run"),
        (4, "new-run"),
    ] {
        run_index
            .register(RunIndexEntry {
                submission_id,
                run_id,
                registered_at_ms: submission_id + 10,
            })
            .expect("register run");
    }
    drop(run_index);

    let mut sessions = automonique_daemon::managed_sessions::ManagedSessionStore::open(
        config.managed_sessions_path(),
    )
    .expect("managed sessions");
    sessions
        .observe_terminal("owned-session", "owned-run", 100)
        .expect("owned binding");
    sessions
        .observe_terminal("foreign-session", "foreign-run", 101)
        .expect("foreign binding");
    sessions
        .observe_terminal("rebound-session", "old-run", 102)
        .expect("old binding");
    let rebound = sessions
        .observe_terminal("rebound-session", "new-run", 103)
        .expect("rebound binding");
    assert_eq!(rebound.revision, 2);
    drop(sessions);

    let owned_approval = "apr-11111111111111111111111111111111";
    let foreign_approval = "apr-22222222222222222222222222222222";
    let rebound_approval = "apr-33333333333333333333333333333333";
    let mut approvals =
        ApprovalRequests::open(config.approval_requests_path()).expect("approval requests");
    for (key, run_id) in [
        (owned_approval, "owned-run"),
        (foreign_approval, "foreign-run"),
        (rebound_approval, "old-run"),
    ] {
        approvals
            .propose(approval_proposal(key, run_id))
            .expect("approval proposal");
    }
    drop(approvals);

    let serving = serve(&config);
    let client = ClientId::new("mobile-credential-1").expect("client");
    let owned_session = automonique_coordinate(ResourceKind::Session, "owned-session");
    let PlatformResponse::SessionCommandState(state) = platform(
        &config,
        "owned-command-state",
        PlatformRequest::SessionCommandState(SessionCommandStateRequest {
            session: owned_session.clone(),
        }),
    ) else {
        panic!("command state")
    };
    assert_eq!(state.session.freshness.revision.get(), 1);
    assert_eq!(
        state.run.as_ref().expect("owned run").target.id.as_str(),
        "owned-run"
    );
    assert_eq!(state.pending_approvals.len(), 1);
    assert_eq!(
        state.pending_approvals[0].target.id.as_str(),
        owned_approval
    );

    let follow_up_request = SessionFollowUpRequest {
        client: client.clone(),
        session: owned_session.clone(),
        expected_session_revision: Revision::FIRST,
        idempotency_key: IdempotencyKey::new("owned-follow-up").expect("key"),
        text: PlatformParameter::new("continue with the bounded next step").expect("text"),
    };
    let PlatformResponse::Receipt(follow_up) = platform(
        &config,
        "owned-follow-up",
        PlatformRequest::SessionFollowUp(follow_up_request.clone()),
    ) else {
        panic!("owned follow-up receipt")
    };
    assert_eq!(follow_up.action, PlatformAction::FollowUp);
    assert_eq!(follow_up.target, owned_session);
    let PlatformResponse::Receipt(follow_up_replay) = platform(
        &config,
        "owned-follow-up-replay",
        PlatformRequest::SessionFollowUp(follow_up_request),
    ) else {
        panic!("owned follow-up replay")
    };
    assert_eq!(follow_up_replay.id, follow_up.id);

    let stale_key = IdempotencyKey::new("stale-follow-up").expect("key");
    let PlatformResponse::Refused {
        outcome,
        explanation,
    } = platform(
        &config,
        "stale-follow-up",
        PlatformRequest::SessionFollowUp(SessionFollowUpRequest {
            client: client.clone(),
            session: owned_session.clone(),
            expected_session_revision: Revision::new(2).expect("revision"),
            idempotency_key: stale_key.clone(),
            text: PlatformParameter::new("must not be submitted").expect("text"),
        }),
    )
    else {
        panic!("stale refusal")
    };
    assert_eq!(outcome, ReceiptOutcome::Rejected);
    assert_eq!(explanation.as_str(), "stale_revision");
    let PlatformResponse::Refused { explanation, .. } = platform(
        &config,
        "stale-follow-up-receipt",
        PlatformRequest::GetReceipt(
            GetReceiptRequest::by_idempotency_key(stale_key).with_client(client.clone()),
        ),
    ) else {
        panic!("missing receipt refusal")
    };
    assert_eq!(explanation.as_str(), "not_found");

    for (label, session, session_revision, approval) in [
        (
            "foreign-approval",
            owned_session.clone(),
            1,
            foreign_approval,
        ),
        (
            "rebound-approval",
            automonique_coordinate(ResourceKind::Session, "rebound-session"),
            2,
            rebound_approval,
        ),
    ] {
        let PlatformResponse::Refused { explanation, .. } = platform(
            &config,
            label,
            PlatformRequest::SessionApprovalDecision(SessionApprovalDecisionRequest {
                client: client.clone(),
                session,
                expected_session_revision: Revision::new(session_revision).expect("revision"),
                approval: automonique_coordinate(ResourceKind::Approval, approval),
                expected_approval_revision: Revision::FIRST,
                idempotency_key: IdempotencyKey::new(label).expect("key"),
                decision: SessionApprovalDecision::Grant,
            }),
        ) else {
            panic!("ownership refusal")
        };
        assert_eq!(explanation.as_str(), "target_not_owned");
    }

    let approval_request = SessionApprovalDecisionRequest {
        client: client.clone(),
        session: owned_session.clone(),
        expected_session_revision: Revision::FIRST,
        approval: automonique_coordinate(ResourceKind::Approval, owned_approval),
        expected_approval_revision: Revision::FIRST,
        idempotency_key: IdempotencyKey::new("owned-approval-decision").expect("key"),
        decision: SessionApprovalDecision::Grant,
    };
    let PlatformResponse::Receipt(first) = platform(
        &config,
        "owned-approval-decision",
        PlatformRequest::SessionApprovalDecision(approval_request.clone()),
    ) else {
        panic!("owned approval receipt")
    };
    assert_eq!(first.outcome, ReceiptOutcome::Completed);
    let PlatformResponse::Receipt(replay) = platform(
        &config,
        "owned-approval-replay",
        PlatformRequest::SessionApprovalDecision(approval_request),
    ) else {
        panic!("owned approval replay")
    };
    assert_eq!(replay, first);

    let stop_request = SessionRunStopRequest {
        client: client.clone(),
        session: owned_session.clone(),
        expected_session_revision: Revision::FIRST,
        run: automonique_coordinate(ResourceKind::Run, "owned-run"),
        expected_run_revision: Revision::FIRST,
        idempotency_key: IdempotencyKey::new("owned-run-stop").expect("key"),
    };
    let PlatformResponse::Receipt(stop) = platform(
        &config,
        "owned-run-stop",
        PlatformRequest::SessionRunStop(stop_request.clone()),
    ) else {
        panic!("owned stop receipt")
    };
    assert_eq!(stop.action, PlatformAction::StopRun);
    assert_eq!(stop.target.id.as_str(), "owned-run");
    let PlatformResponse::Receipt(stop_replay) = platform(
        &config,
        "owned-run-stop-replay",
        PlatformRequest::SessionRunStop(stop_request),
    ) else {
        panic!("owned stop replay")
    };
    assert_eq!(stop_replay, stop);

    let PlatformResponse::Refused { explanation, .. } = platform(
        &config,
        "foreign-run-stop",
        PlatformRequest::SessionRunStop(SessionRunStopRequest {
            client,
            session: owned_session,
            expected_session_revision: Revision::FIRST,
            run: automonique_coordinate(ResourceKind::Run, "foreign-run"),
            expected_run_revision: Revision::FIRST,
            idempotency_key: IdempotencyKey::new("foreign-run-stop").expect("key"),
        }),
    ) else {
        panic!("foreign run refusal")
    };
    assert_eq!(explanation.as_str(), "target_not_owned");
    serving.shutdown(&config);
}

/// Register one run and, when asked, drive its read-model row to a terminal
/// state the way a finished worker does.
fn register_run(config: &DaemonConfig, submission_id: i64, run_id: &str, terminal: bool) {
    let mut index = RunIndex::open(config.run_index_path()).expect("run index");
    index
        .register(RunIndexEntry {
            submission_id,
            run_id,
            registered_at_ms: submission_id + 10,
        })
        .expect("register run");
    if !terminal {
        return;
    }
    let running = index
        .advance_state(StateAdvance {
            submission_id,
            expected_revision: 1,
            new_state: RunSpoolState::Running,
            last_sequence: 1,
            now_ms: submission_id + 20,
        })
        .expect("run starts");
    index
        .advance_state(StateAdvance {
            submission_id,
            expected_revision: running.revision,
            new_state: RunSpoolState::Completed,
            last_sequence: 2,
            now_ms: submission_id + 30,
        })
        .expect("run completes");
}

fn command_state(
    config: &DaemonConfig,
    label: &str,
    session: &ResourceCoordinate,
) -> automonique_protocol::platform::SessionCommandState {
    let PlatformResponse::SessionCommandState(state) = platform(
        config,
        label,
        PlatformRequest::SessionCommandState(SessionCommandStateRequest {
            session: session.clone(),
        }),
    ) else {
        panic!("{label}: expected a command state")
    };
    state
}

/// The turn in flight is the turn the session can act on.
///
/// This is the whole of #145 stated as a proof. The session has taken one
/// completed turn on `settled-run` and is now taking another on `live-run`,
/// which is where a provider permission request is raised — during the run that
/// raised it, exactly as `execute.rs` proposes one. What is asserted is that the
/// live run is the one the session names, that its approval is the one the
/// session projects, and that a decision on it is admitted and lands in the
/// durable row.
///
/// The last assertion is the anti-vacuity one: `granted` in
/// `ApprovalRequests::entry` is the precise condition the execute lane's
/// approval-wait loop breaks on, so a decision that reaches this row is a
/// decision that releases the turn. That the loop then hands the permission
/// back to the provider is `automonique-daemon`'s JCode host proof and the live
/// non-production exercise; it needs a delegated cgroup domain and a workload,
/// and neither is what this file proves.
#[test]
fn a_live_turns_approval_is_projected_and_decidable_by_its_own_session() {
    let (_root, config) = fixture();
    std::fs::create_dir(config.state_dir()).expect("product state");
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("private product state");
    register_run(&config, 1, "settled-run", true);
    register_run(&config, 2, "live-run", false);

    let mut sessions = automonique_daemon::managed_sessions::ManagedSessionStore::open(
        config.managed_sessions_path(),
    )
    .expect("managed sessions");
    let settled = sessions
        .observe_terminal("live-session", "settled-run", 100)
        .expect("first turn settles");
    assert_eq!(settled.revision, 1);
    let live = sessions
        .observe_active("live-session", "live-run", 101)
        .expect("second turn starts");
    assert_eq!(live.revision, 2, "turn start advances the binding");
    drop(sessions);

    let settled_approval = "apr-44444444444444444444444444444444";
    let live_approval = "apr-55555555555555555555555555555555";
    let mut approvals =
        ApprovalRequests::open(config.approval_requests_path()).expect("approval requests");
    for (key, run_id) in [
        (settled_approval, "settled-run"),
        (live_approval, "live-run"),
    ] {
        approvals
            .propose(approval_proposal(key, run_id))
            .expect("approval proposal");
    }
    drop(approvals);

    let serving = serve(&config);
    let client = ClientId::new("mobile-credential-live").expect("client");
    let session = automonique_coordinate(ResourceKind::Session, "live-session");

    let state = command_state(&config, "live-command-state", &session);
    assert_eq!(state.session.freshness.revision.get(), 2);
    assert_eq!(
        state.run.as_ref().expect("live run").target.id.as_str(),
        "live-run",
        "the in-flight run is the one the session names"
    );
    assert_eq!(state.pending_approvals.len(), 1);
    assert_eq!(state.pending_approvals[0].target.id.as_str(), live_approval);

    // The previous turn's approval is still pending in the store, and is still
    // refused: settling a turn does not hand its approvals to the next one.
    let PlatformResponse::Refused { explanation, .. } = platform(
        &config,
        "stale-run-approval",
        PlatformRequest::SessionApprovalDecision(SessionApprovalDecisionRequest {
            client: client.clone(),
            session: session.clone(),
            expected_session_revision: Revision::new(2).expect("revision"),
            approval: automonique_coordinate(ResourceKind::Approval, settled_approval),
            expected_approval_revision: Revision::FIRST,
            idempotency_key: IdempotencyKey::new("stale-run-approval").expect("key"),
            decision: SessionApprovalDecision::Grant,
        }),
    ) else {
        panic!("a decision on the session's previous run must be refused")
    };
    assert_eq!(explanation.as_str(), "target_not_owned");

    let decision = SessionApprovalDecisionRequest {
        client: client.clone(),
        session: session.clone(),
        expected_session_revision: Revision::new(2).expect("revision"),
        approval: automonique_coordinate(ResourceKind::Approval, live_approval),
        expected_approval_revision: Revision::FIRST,
        idempotency_key: IdempotencyKey::new("live-run-approval").expect("key"),
        decision: SessionApprovalDecision::Grant,
    };
    let PlatformResponse::Receipt(receipt) = platform(
        &config,
        "live-run-approval",
        PlatformRequest::SessionApprovalDecision(decision.clone()),
    ) else {
        panic!("a decision on the live run must be admitted")
    };
    assert_eq!(receipt.outcome, ReceiptOutcome::Completed);
    let PlatformResponse::Receipt(replay) = platform(
        &config,
        "live-run-approval-replay",
        PlatformRequest::SessionApprovalDecision(decision),
    ) else {
        panic!("replay receipt")
    };
    assert_eq!(replay, receipt, "the decision is idempotent by key");

    // The turn no longer has a pending approval to wait on, and the stale one
    // is untouched.
    let after = command_state(&config, "live-command-state-decided", &session);
    assert!(after.pending_approvals.is_empty());
    serving.shutdown(&config);

    let approvals =
        ApprovalRequests::open(config.approval_requests_path()).expect("approval requests");
    let decided = approvals
        .entry(live_approval)
        .expect("read")
        .expect("live approval row");
    assert_eq!(decided.state, ApprovalState::Granted);
    assert!(!decided.is_answerable_at(200), "the wait is over");
    assert_eq!(
        approvals
            .entry(settled_approval)
            .expect("read")
            .expect("stale approval row")
            .state,
        ApprovalState::Pending,
        "a refused decision wrote nothing"
    );
}

/// A binding is a session's own, in flight exactly as much as at rest.
///
/// Turn-start binding widens what a session can address, so the fence is
/// re-proved on the wider surface: another session's live run is refused, and
/// so is an approval owned by it, with no receipt written for either.
#[test]
fn a_foreign_sessions_live_run_and_approval_are_refused() {
    let (_root, config) = fixture();
    std::fs::create_dir(config.state_dir()).expect("product state");
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("private product state");
    register_run(&config, 1, "mine-run", false);
    register_run(&config, 2, "theirs-run", false);

    let mut sessions = automonique_daemon::managed_sessions::ManagedSessionStore::open(
        config.managed_sessions_path(),
    )
    .expect("managed sessions");
    sessions
        .observe_active("mine-session", "mine-run", 100)
        .expect("my turn");
    sessions
        .observe_active("theirs-session", "theirs-run", 101)
        .expect("their turn");
    drop(sessions);

    let theirs_approval = "apr-66666666666666666666666666666666";
    let mut approvals =
        ApprovalRequests::open(config.approval_requests_path()).expect("approval requests");
    approvals
        .propose(approval_proposal(theirs_approval, "theirs-run"))
        .expect("approval proposal");
    drop(approvals);

    let serving = serve(&config);
    let client = ClientId::new("mobile-credential-mine").expect("client");
    let mine = automonique_coordinate(ResourceKind::Session, "mine-session");

    let state = command_state(&config, "mine-command-state", &mine);
    assert_eq!(
        state.run.as_ref().expect("my run").target.id.as_str(),
        "mine-run"
    );
    assert!(
        state.pending_approvals.is_empty(),
        "another session's approval is not mine to see"
    );

    let stop_key = IdempotencyKey::new("foreign-live-run-stop").expect("key");
    let PlatformResponse::Refused { explanation, .. } = platform(
        &config,
        "foreign-live-run-stop",
        PlatformRequest::SessionRunStop(SessionRunStopRequest {
            client: client.clone(),
            session: mine.clone(),
            expected_session_revision: Revision::FIRST,
            run: automonique_coordinate(ResourceKind::Run, "theirs-run"),
            expected_run_revision: Revision::FIRST,
            idempotency_key: stop_key.clone(),
        }),
    ) else {
        panic!("a stop on another session's run must be refused")
    };
    assert_eq!(explanation.as_str(), "target_not_owned");

    let approval_key = IdempotencyKey::new("foreign-live-approval").expect("key");
    let PlatformResponse::Refused { explanation, .. } = platform(
        &config,
        "foreign-live-approval",
        PlatformRequest::SessionApprovalDecision(SessionApprovalDecisionRequest {
            client: client.clone(),
            session: mine,
            expected_session_revision: Revision::FIRST,
            approval: automonique_coordinate(ResourceKind::Approval, theirs_approval),
            expected_approval_revision: Revision::FIRST,
            idempotency_key: approval_key.clone(),
            decision: SessionApprovalDecision::Grant,
        }),
    ) else {
        panic!("a decision on another session's approval must be refused")
    };
    assert_eq!(explanation.as_str(), "target_not_owned");

    for key in [stop_key, approval_key] {
        let PlatformResponse::Refused { explanation, .. } = platform(
            &config,
            "foreign-receipt",
            PlatformRequest::GetReceipt(
                GetReceiptRequest::by_idempotency_key(key).with_client(client.clone()),
            ),
        ) else {
            panic!("a refused command writes no receipt")
        };
        assert_eq!(explanation.as_str(), "not_found");
    }
    serving.shutdown(&config);

    let approvals =
        ApprovalRequests::open(config.approval_requests_path()).expect("approval requests");
    assert_eq!(
        approvals
            .entry(theirs_approval)
            .expect("read")
            .expect("their approval row")
            .state,
        ApprovalState::Pending
    );
}

/// A settled turn projects exactly what it projected before turn-start binding,
/// and a binding whose worker died mid-turn settles the first time anyone looks.
///
/// The two halves are one test because they are the same guarantee from either
/// side: the projection names a terminal run, whether the worker said so or the
/// read model did.
#[test]
fn a_settled_turn_projects_as_before_and_an_abandoned_binding_heals_on_read() {
    let (_root, config) = fixture();
    std::fs::create_dir(config.state_dir()).expect("product state");
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("private product state");
    register_run(&config, 1, "done-run", true);
    register_run(&config, 2, "abandoned-run", true);
    register_run(&config, 3, "unretired-run", false);

    let mut sessions = automonique_daemon::managed_sessions::ManagedSessionStore::open(
        config.managed_sessions_path(),
    )
    .expect("managed sessions");
    sessions
        .observe_active("done-session", "done-run", 100)
        .expect("turn starts");
    let settled = sessions
        .observe_terminal("done-session", "done-run", 101)
        .expect("turn settles");
    assert_eq!(settled.revision, 2, "settling a turn moves the revision");
    // A generation that died mid-turn leaves these two behind: one whose run
    // the read model calls terminal, and one whose run is still going.
    sessions
        .observe_active("abandoned-session", "abandoned-run", 102)
        .expect("abandoned turn");
    sessions
        .observe_active("unretired-session", "unretired-run", 103)
        .expect("live turn");
    drop(sessions);

    let serving = serve(&config);
    let done = automonique_coordinate(ResourceKind::Session, "done-session");
    let state = command_state(&config, "done-command-state", &done);
    assert_eq!(state.session.freshness.revision.get(), 2);
    assert_eq!(
        state.run.as_ref().expect("run").target.id.as_str(),
        "done-run"
    );
    assert!(state.pending_approvals.is_empty());
    assert_eq!(
        command_state(&config, "done-command-state-again", &done)
            .session
            .freshness
            .revision
            .get(),
        2,
        "reading a settled binding writes nothing"
    );

    let abandoned = automonique_coordinate(ResourceKind::Session, "abandoned-session");
    assert_eq!(
        command_state(&config, "abandoned-command-state", &abandoned)
            .session
            .freshness
            .revision
            .get(),
        2,
        "the abandoned binding is settled by the read"
    );

    let unretired = automonique_coordinate(ResourceKind::Session, "unretired-session");
    assert_eq!(
        command_state(&config, "unretired-command-state", &unretired)
            .session
            .freshness
            .revision
            .get(),
        1,
        "a run the read model has not called terminal is left alone"
    );
    serving.shutdown(&config);

    let sessions = automonique_daemon::managed_sessions::ManagedSessionStore::open(
        config.managed_sessions_path(),
    )
    .expect("managed sessions");
    let healed = sessions
        .by_id("abandoned-session")
        .expect("read")
        .expect("row");
    assert_eq!(
        healed.run_id, "abandoned-run",
        "the run named does not change"
    );
    assert!(!healed.run_state.is_in_flight());
    assert!(
        sessions
            .by_id("unretired-session")
            .expect("read")
            .expect("row")
            .run_state
            .is_in_flight()
    );
}

/// #130: the adapter's pre-#118 `execute` body (no `client` key) is accepted,
/// and a body the lane refuses is answered with the typed `refused` frame
/// carrying the request id, never a bare EOF.
#[test]
fn platform_decode_failures_are_typed_refusals_and_absent_client_is_accepted() {
    use automonique_protocol::wire::{JsonValue, Message};

    let (_root, config) = fixture();
    let serving = serve(&config);

    let node = ResourceCoordinate::new(
        ResourceAuthority::Automonique,
        ResourceKind::Node,
        ResourceId::new("node-not-this-daemon").expect("id"),
    );
    let execute = PlatformRequestMessage::new(
        RequestId::new("execute-without-client").expect("request id"),
        PlatformRequest::Execute(
            ExecuteRequest::new(
                PlatformAction::SubmitRequest,
                node,
                IdempotencyKey::new("submit-without-client").expect("key"),
                None,
                None,
            )
            .expect("request"),
        ),
    )
    .to_message()
    .expect("message");
    let JsonValue::Object(entries) = execute.body().clone() else {
        panic!("execute body is an object");
    };
    let without_client: Vec<_> = entries
        .iter()
        .filter(|(key, _)| key != "client")
        .cloned()
        .collect();
    let absent = Message::new(
        execute.envelope().clone(),
        JsonValue::Object(without_client),
    );
    let response = PlatformResponseMessage::from_canonical_bytes(&exchange(
        &config,
        &absent.to_canonical_bytes(),
    ))
    .expect("a body without client is a platform response, not an EOF");
    assert_eq!(response.request_id().as_str(), "execute-without-client");
    // The body decoded: the daemon evaluated the target (not its node) and
    // answered with its typed rejection rather than a decode refusal.
    match response.response() {
        PlatformResponse::Refused { explanation, .. } => {
            assert_eq!(explanation.as_str(), "target_not_active_node");
        }
        other => panic!("unexpected response {other:?}"),
    }

    let mut extra = entries.clone();
    extra.push(("actor".to_owned(), JsonValue::String("x".to_owned())));
    let malformed = Message::new(execute.envelope().clone(), JsonValue::Object(extra));
    let response = PlatformResponseMessage::from_canonical_bytes(&exchange(
        &config,
        &malformed.to_canonical_bytes(),
    ))
    .expect("a malformed body is answered with a typed refusal frame");
    assert_eq!(response.request_id().as_str(), "execute-without-client");
    match response.response() {
        PlatformResponse::Refused {
            outcome,
            explanation,
        } => {
            assert_eq!(*outcome, ReceiptOutcome::Rejected);
            assert_eq!(
                explanation.as_str(),
                "invalid_request:platform_invalid_body"
            );
        }
        other => panic!("unexpected response {other:?}"),
    }

    // #131: `node/current` names the live generation's node without the
    // client knowing the holder id.
    let response = platform(
        &config,
        "snapshot-current-node",
        PlatformRequest::Snapshot(
            SnapshotRequest::new(vec![automonique_coordinate(
                ResourceKind::Node,
                automonique_daemon::CURRENT_NODE_ALIAS,
            )])
            .expect("request"),
        ),
    );
    let PlatformResponse::Snapshot(snapshot) = response else {
        panic!("unexpected response {response:?}");
    };
    let nodes: Vec<_> = snapshot
        .resources
        .iter()
        .filter(|record| record.resource.kind == ResourceKind::Node)
        .collect();
    assert_eq!(nodes.len(), 1, "exactly the live node: {snapshot:?}");
    assert_ne!(
        nodes[0].resource.id.as_str(),
        automonique_daemon::CURRENT_NODE_ALIAS
    );
    assert!(nodes[0].resource.id.as_str().starts_with("daemon-"));
    assert_eq!(
        nodes[0].freshness.state,
        automonique_protocol::platform::FreshnessState::Fresh
    );

    serving.shutdown(&config);
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
            prompt_version: "prompt-v1",
            tool_schema_version: "tools-v1",
            model_id: "model-a",
            force_version_change: false,
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
    assert_eq!(capabilities.methods.len(), 16);
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
            "platform-action-steer",
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
    let PlatformResponse::Refused {
        outcome,
        explanation,
    } = platform(
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
    )
    else {
        panic!("non-managed session follow-up refusal")
    };
    assert_eq!(outcome, ReceiptOutcome::Rejected);
    assert_eq!(explanation.as_str(), "session_not_resumable");

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

#[test]
fn managed_request_worker_reconciles_a_typed_provider_refusal() {
    let (_root, config) = fixture();
    std::fs::create_dir(config.state_dir()).expect("product state");
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("private product state");
    write_catalog_provider(&config, "gpt-5.6-sol", true);
    let serving = serve(&config);
    let PlatformResponse::Snapshot(snapshot) = platform(
        &config,
        "managed-refusal-snapshot",
        PlatformRequest::Snapshot(SnapshotRequest::new(Vec::new()).expect("snapshot request")),
    ) else {
        panic!("snapshot response")
    };
    let node = snapshot
        .resources
        .into_iter()
        .find(|resource| resource.resource.kind == ResourceKind::Node)
        .expect("active node");
    let key = IdempotencyKey::new("managed-refusal-request").expect("key");
    let PlatformResponse::Receipt(accepted) = platform(
        &config,
        "managed-refusal-submit",
        PlatformRequest::Execute(
            ExecuteRequest::new(
                PlatformAction::SubmitRequest,
                node.resource,
                key.clone(),
                Some(node.freshness.revision),
                Some(PlatformText::new("bounded request").expect("body")),
            )
            .expect("request"),
        ),
    ) else {
        panic!("accepted receipt")
    };
    assert_eq!(accepted.outcome, ReceiptOutcome::Accepted);

    let deadline = Instant::now() + Duration::from_secs(5);
    let completed = loop {
        let PlatformResponse::Receipt(receipt) = platform(
            &config,
            "managed-refusal-reconcile",
            PlatformRequest::GetReceipt(GetReceiptRequest::by_idempotency_key(key.clone())),
        ) else {
            panic!("receipt response")
        };
        if receipt.outcome != ReceiptOutcome::Accepted {
            break receipt;
        }
        assert!(Instant::now() < deadline, "managed receipt stayed accepted");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(completed.outcome, ReceiptOutcome::Rejected);
    assert_eq!(
        completed
            .explanation
            .as_ref()
            .expect("typed explanation")
            .as_str(),
        "run_not_configured"
    );
    serving.shutdown(&config);
}
