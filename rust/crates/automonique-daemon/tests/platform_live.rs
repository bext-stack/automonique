// SPDX-License-Identifier: Elastic-2.0

//! Platform-v1 framing and durable controller semantics over the real socket.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use automonique_daemon::platform_v2_host::{
    PlatformV2Host, PlatformV2ReviewDelivery, PlatformV2ReviewDeliveryCoordinate,
    PlatformV2ReviewDeliveryError, PlatformV2ReviewDeliveryState,
};
use automonique_daemon::{Daemon, DaemonConfig};
use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_protocol::digest::Sha256;
use automonique_protocol::platform::{
    AttachRequest, ClaimControlRequest, ClientId, ExecuteRequest, GetReceiptRequest,
    IdempotencyKey, ListSessionsRequest, PlatformAction, PlatformParameter, PlatformRequest,
    PlatformResponse, PlatformText, ReceiptId, ReceiptOutcome, ResourceAuthority,
    ResourceCoordinate, ResourceId, ResourceKind, SessionApprovalDecision,
    SessionApprovalDecisionRequest, SessionCommandStateRequest, SessionFollowUpRequest,
    SessionRunStopRequest, SnapshotRequest,
};
use automonique_protocol::platform_api::{PlatformRequestMessage, PlatformResponseMessage};
use automonique_protocol::platform_v2::{
    AttemptWorkspaceId, CheckoutId, CheckoutKind, HostSetupKind, PaneId, PlatformVersion,
    PlatformVersionOffer, ProjectId, UserWorkspaceId, V1RepositoryRef, V1SessionRef,
    WorkContextAttributes, WorkContextIdentity, WorkContextLabel, WorkContextLifecycle,
    WorkContextRecord, WorkContextRelation, WorkContextRelationKind, WorkContextTargetKind,
    WorkSessionId,
};
use automonique_protocol::platform_v2_attention::{
    AttentionReadRequest, AttentionSource, AttentionSourceId, AttentionSourceKind,
};
use automonique_protocol::platform_v2_lifecycle::{
    AuthorityGrantId, CreateAttemptWorkspaceIntent, CreateCheckoutIntent,
    CreateUserWorkspaceIntent, ExpectedWorkContext, ExternalParentResolution,
    MutationApprovalDecision, MutationApprovalRequirement, MutationPreviewDigest,
    WorkContextAuthority, WorkContextMutationIntent, WorkContextRegistrySelector,
};
use automonique_protocol::platform_v2_lifecycle_api::{
    decode_work_context_mutation_submission, encode_work_context_mutation_submission,
    work_context_mutation_preview_digest,
};
use automonique_protocol::platform_v2_lineage::{
    BaseSelectorId, BranchSelectorId, ExternalWorkAuthorityId, ExternalWorkIdentity,
    ExternalWorkItem, ExternalWorkKey, ExternalWorkProvider, ExternalWorkScope, ExternalWorkState,
    LineageFreshness, LineageFreshnessState, LineageStatus, OrchestrationIdentity,
    OrchestrationRecord, OrchestrationRunId, OrchestrationTaskId, WorkspaceCancelIntent,
    WorkspaceCreateIntent, WorkspaceIntent, WorkspaceIntentId, WorkspaceIntentOutcome,
    WorkspaceResumeIntent,
};
use automonique_protocol::platform_v2_review::{
    CommentAgentState, ReviewAction, ReviewActionRequest, ReviewActorId, ReviewAuthentication,
    ReviewAuthority, ReviewAuthorityId, ReviewAuthorityKind, ReviewComment, ReviewCommentId,
    ReviewCommentTarget, ReviewFile, ReviewProposal, ReviewProposalId, ReviewProposalKind,
    ReviewReceiptOutcome, ReviewSnapshot, ReviewText, WorktreeFileState,
};
use automonique_protocol::platform_v2_review_api::{
    decode_review_action_request, decode_review_snapshot,
};
use automonique_protocol::platform_v2_transport::{
    LineageReadRequest, MutationDecisionRequest, MutationPrepareRequest, MutationReceiptLookup,
    MutationSubmitRequest, PlatformNegotiationRequest, PlatformNegotiationRequestMessage,
    PlatformNegotiationResponse, PlatformNegotiationResponseMessage, PlatformV2Request,
    PlatformV2RequestMessage, PlatformV2Response, PlatformV2ResponseMessage, ReceiptLookupKey,
    ReviewActionTransportRequest, ReviewConfirmationDigest, ReviewReadRequest, ReviewReceiptLookup,
    WorkspaceIntentLookup, WorkspaceIntentRequest,
};
use automonique_protocol::primitives::{EpochMillis, Revision};
use automonique_store::approval_requests::{
    ApprovalContext, ApprovalProposal, ApprovalRequests, ApprovalState,
};
use automonique_store::lineage_index::LineageIndex;
use automonique_store::provider_journal::{ProcessSpawn, ProviderJournal, SessionOpening};
use automonique_store::review_store::{ApprovalPolicy, ReviewExternalEffectPlan, ReviewStore};
use automonique_store::run_index::{RunIndex, RunIndexEntry, RunSpoolState, StateAdvance};
use automonique_store::work_context_store::{MutationPolicyDecision, WorkContextStore};
use automonique_store::{InboxSubmission, Store};

#[path = "support/isolation.rs"]
mod test_isolation;

const REVIEW_SNAPSHOT: &[u8] =
    include_bytes!("../../automonique-protocol/fixtures/platform-v2-review-v2.json");
const REVIEW_ACTION: &[u8] =
    include_bytes!("../../automonique-protocol/fixtures/platform-v2-review-action-v1.json");
const ATTENTION_SNAPSHOT: &[u8] =
    include_bytes!("../../automonique-protocol/fixtures/platform-v2-attention-v1.json");

static FULL_DAEMON_TEST_GUARD: Mutex<()> = Mutex::new(());

fn full_daemon_test_guard() -> MutexGuard<'static, ()> {
    match FULL_DAEMON_TEST_GUARD.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            FULL_DAEMON_TEST_GUARD.clear_poison();
            poisoned.into_inner()
        }
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

fn platform_v2(
    config: &DaemonConfig,
    label: &str,
    request: PlatformV2Request,
) -> PlatformV2Response {
    let request = PlatformV2RequestMessage::new(RequestId::new(label).unwrap(), request);
    PlatformV2ResponseMessage::from_canonical_bytes(
        &exchange(config, &request.to_canonical_bytes().unwrap()),
        &request,
    )
    .unwrap()
    .response()
    .clone()
}

fn configure_v2(config: &DaemonConfig) {
    std::fs::create_dir(config.state_dir()).expect("product state");
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("private product state");
    let uid = nix::unistd::geteuid().as_raw();
    let policy = serde_json::json!({
        "version": 1,
        "principals": [{
            "uid": uid,
            "tenant": "tenant-live",
            "actor": "operator-live",
            "serving_authority": "automonique",
            "projects": ["project-live"],
            "workspaces": [
                {"project": "project-live", "kind": "project", "id": "project-live",
                 "inherited_authority": {"filesystem": [], "credentials": [], "network": [], "tools": [], "providers": [], "models": []}},
                {"project": "project-live", "kind": "host_setup", "id": "host-live",
                 "inherited_authority": {"filesystem": [], "credentials": [], "network": [], "tools": [], "providers": [], "models": []}},
                {"project": "project-live", "kind": "checkout", "id": "checkout-live",
                 "inherited_authority": {"filesystem": [], "credentials": [], "network": [], "tools": [], "providers": [], "models": []}},
                {"project": "project-live", "kind": "user_workspace", "id": "workspace-live",
                 "inherited_authority": {"filesystem": [], "credentials": [], "network": [], "tools": [], "providers": [], "models": []}},
                {"project": "project-live", "kind": "user_workspace", "id": "wc_user_1",
                 "inherited_authority": {"filesystem": [], "credentials": [], "network": [], "tools": [], "providers": [], "models": []}},
                {"project": "project-live", "kind": "attempt_workspace", "id": "attempt-live",
                 "inherited_authority": {"filesystem": [], "credentials": [], "network": [], "tools": [], "providers": [], "models": []}},
                {"project": "project-live", "kind": "session", "id": "session-live",
                 "inherited_authority": {"filesystem": [], "credentials": [], "network": [], "tools": [], "providers": [], "models": []}},
                {"project": "project-live", "kind": "pane", "id": "pane-live",
                 "inherited_authority": {"filesystem": [], "credentials": [], "network": [], "tools": [], "providers": [], "models": []}}
            ],
            "authority": {
                "filesystem": [], "credentials": [], "network": [],
                "tools": [], "providers": [], "models": []
            },
            "review_authorities": {"ci": "authority-1", "review": "authority-1"},
            "resource_reads": [
                {"authority": "automonique", "kind": "client"},
                {"authority": "automonique", "kind": "node"}
            ]
        }]
    });
    let path = config.platform_v2_policy_path();
    std::fs::write(&path, serde_json::to_vec(&policy).unwrap()).expect("v2 policy");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("private v2 policy");

    let mut store = WorkContextStore::open(config.platform_v2_work_context_path())
        .expect("v2 work context store");
    let repository = live_repository("repo-live");
    store
        .put_external_snapshot(
            "tenant-live",
            &ExpectedWorkContext::new(repository.clone(), Revision::FIRST),
            ExternalParentResolution::Available,
            Some(&ProjectId::new("project-live").unwrap()),
        )
        .unwrap();
    let unrelated_repository = live_repository("repo-unrelated");
    store
        .put_external_snapshot(
            "tenant-live",
            &ExpectedWorkContext::new(unrelated_repository, Revision::FIRST),
            ExternalParentResolution::Available,
            Some(&ProjectId::new("project-live").unwrap()),
        )
        .unwrap();
    let project = WorkContextRecord::new(
        WorkContextIdentity::Project(ProjectId::new("project-live").unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        WorkContextLabel::new("Live project").unwrap(),
        WorkContextAttributes::EMPTY,
        vec![
            WorkContextRelation::new(
                WorkContextRelationKind::ProjectRepository,
                repository.clone(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    store
        .put_authoritative_record("tenant-live", &project)
        .expect("seed project");
    let host = WorkContextRecord::new(
        WorkContextIdentity::parse_local(
            automonique_protocol::platform_v2::WorkContextTargetKind::HostSetup,
            "host-live",
        )
        .unwrap(),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        WorkContextLabel::new("Live host").unwrap(),
        WorkContextAttributes::host_setup(HostSetupKind::Local),
        vec![
            WorkContextRelation::new(
                WorkContextRelationKind::HostSetupProject,
                project.identity().clone(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    store
        .put_authoritative_record("tenant-live", &host)
        .unwrap();
    let checkout = WorkContextRecord::new(
        WorkContextIdentity::parse_local(
            automonique_protocol::platform_v2::WorkContextTargetKind::Checkout,
            "checkout-live",
        )
        .unwrap(),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        WorkContextLabel::new("Live checkout").unwrap(),
        WorkContextAttributes::checkout(CheckoutKind::AuthorizedFolder),
        vec![
            WorkContextRelation::new(
                WorkContextRelationKind::CheckoutProject,
                project.identity().clone(),
            )
            .unwrap(),
            WorkContextRelation::new(
                WorkContextRelationKind::CheckoutHostSetup,
                host.identity().clone(),
            )
            .unwrap(),
            WorkContextRelation::new(WorkContextRelationKind::CheckoutRepository, repository)
                .unwrap(),
        ],
    )
    .unwrap();
    store
        .put_authoritative_record("tenant-live", &checkout)
        .unwrap();
    for id in ["workspace-live", "wc_user_1"] {
        let workspace = live_workspace(id, Revision::FIRST, WorkContextLifecycle::Active);
        store
            .put_authoritative_record("tenant-live", &workspace)
            .unwrap();
    }
    let attempt = WorkContextRecord::new(
        WorkContextIdentity::AttemptWorkspace(AttemptWorkspaceId::new("attempt-live").unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Running,
        WorkContextLabel::new("Live attempt").unwrap(),
        WorkContextAttributes::EMPTY,
        vec![
            WorkContextRelation::new(
                WorkContextRelationKind::AttemptUserWorkspace,
                WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("workspace-live").unwrap()),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    store
        .put_authoritative_record("tenant-live", &attempt)
        .unwrap();
    let platform_session = WorkContextIdentity::PlatformSession(
        V1SessionRef::new(ResourceCoordinate::new(
            ResourceAuthority::Automonique,
            ResourceKind::Session,
            ResourceId::new("platform-session-live").unwrap(),
        ))
        .unwrap(),
    );
    let session = WorkContextRecord::new(
        WorkContextIdentity::Session(WorkSessionId::new("session-live").unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        WorkContextLabel::new("Live session").unwrap(),
        WorkContextAttributes::EMPTY,
        vec![
            WorkContextRelation::new(
                WorkContextRelationKind::SessionAttemptWorkspace,
                attempt.identity().clone(),
            )
            .unwrap(),
            WorkContextRelation::new(
                WorkContextRelationKind::SessionPlatformSession,
                platform_session,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    store
        .put_authoritative_record("tenant-live", &session)
        .unwrap();
    let pane = WorkContextRecord::new(
        WorkContextIdentity::Pane(PaneId::new("pane-live").unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        WorkContextLabel::new("Live pane").unwrap(),
        WorkContextAttributes::EMPTY,
        vec![
            WorkContextRelation::new(
                WorkContextRelationKind::PaneSession,
                session.identity().clone(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    store
        .put_authoritative_record("tenant-live", &pane)
        .unwrap();
    store
        .bind_private_selector(
            "tenant-live",
            &WorkContextRegistrySelector::new("checkout-live-selector").unwrap(),
            b"live checkout binding",
        )
        .unwrap();
    drop(store);

    let mut reviews = ReviewStore::open_scoped(config.platform_v2_review_path(), "tenant-live")
        .expect("v2 review store");
    reviews
        .put_snapshot(&decode_review_snapshot(REVIEW_SNAPSHOT).unwrap(), 10)
        .expect("seed review snapshot");
    drop(reviews);

    let mut lineage =
        LineageIndex::open(config.platform_v2_lineage_path()).expect("v2 lineage store");
    let workspace = UserWorkspaceId::new("workspace-live").unwrap();
    let freshness =
        LineageFreshness::new(1_800_000_000_000, 30_000, LineageFreshnessState::Fresh).unwrap();
    let run = OrchestrationIdentity::Run(OrchestrationRunId::new("run-live").unwrap());
    lineage
        .record_orchestration(
            "tenant-live",
            &OrchestrationRecord::new(
                run.clone(),
                workspace.clone(),
                None,
                None,
                LineageStatus::Working,
                freshness,
                None,
            )
            .unwrap(),
            None,
        )
        .unwrap();
    lineage
        .record_orchestration(
            "tenant-live",
            &OrchestrationRecord::new(
                OrchestrationIdentity::Task(OrchestrationTaskId::new("task-live").unwrap()),
                workspace,
                None,
                Some(run),
                LineageStatus::Working,
                freshness,
                None,
            )
            .unwrap(),
            None,
        )
        .unwrap();
}

fn configure_retained_review_delivery(config: &DaemonConfig) -> ReviewSnapshot {
    let policy_path = config.platform_v2_policy_path();
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy_path).unwrap()).unwrap();
    let empty = serde_json::json!({
        "filesystem": [], "credentials": [], "network": [],
        "tools": [], "providers": [], "models": []
    });
    policy["principals"][0]["workspaces"]
        .as_array_mut()
        .unwrap()
        .extend([
            serde_json::json!({"project":"project-live","kind":"user_workspace","id":"review-workspace-live","inherited_authority":empty.clone()}),
            serde_json::json!({"project":"project-live","kind":"attempt_workspace","id":"review-attempt-live","inherited_authority":empty.clone()}),
            serde_json::json!({"project":"project-live","kind":"session","id":"review-session-live","inherited_authority":empty}),
        ]);
    std::fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();

    let workspace =
        WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("review-workspace-live").unwrap());
    let attempt = WorkContextRecord::new(
        WorkContextIdentity::AttemptWorkspace(
            AttemptWorkspaceId::new("review-attempt-live").unwrap(),
        ),
        Revision::FIRST,
        WorkContextLifecycle::Running,
        WorkContextLabel::new("Review attempt").unwrap(),
        WorkContextAttributes::EMPTY,
        vec![
            WorkContextRelation::new(
                WorkContextRelationKind::AttemptUserWorkspace,
                workspace.clone(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let session = WorkContextRecord::new(
        WorkContextIdentity::Session(WorkSessionId::new("review-session-live").unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        WorkContextLabel::new("Review session").unwrap(),
        WorkContextAttributes::EMPTY,
        vec![
            WorkContextRelation::new(
                WorkContextRelationKind::SessionAttemptWorkspace,
                attempt.identity().clone(),
            )
            .unwrap(),
            WorkContextRelation::new(
                WorkContextRelationKind::SessionPlatformSession,
                WorkContextIdentity::PlatformSession(
                    V1SessionRef::new(ResourceCoordinate::new(
                        ResourceAuthority::Automonique,
                        ResourceKind::Session,
                        ResourceId::new("review-provider-session-live").unwrap(),
                    ))
                    .unwrap(),
                ),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let mut contexts = WorkContextStore::open(config.platform_v2_work_context_path()).unwrap();
    for record in [
        live_workspace(
            "review-workspace-live",
            Revision::FIRST,
            WorkContextLifecycle::Active,
        ),
        attempt,
        session,
    ] {
        contexts
            .put_authoritative_record("tenant-live", &record)
            .unwrap();
    }
    drop(contexts);

    let base = decode_review_snapshot(REVIEW_SNAPSHOT).unwrap();
    let original = &base.comments()[0];
    let comment = ReviewComment::new(
        original.id().clone(),
        original.revision(),
        original.actor().clone(),
        original.body().clone(),
        original.anchor().clone(),
        CommentAgentState::NotSent,
        original.unread(),
    );
    let snapshot = ReviewSnapshot::new(
        workspace,
        base.revision(),
        base.files().to_vec(),
        vec![comment],
        base.proposals().to_vec(),
        base.checks().to_vec(),
        base.review().clone(),
        base.pull_request().clone(),
        base.delivery().clone(),
        base.attention_events().to_vec(),
    )
    .unwrap();
    ReviewStore::open_scoped(config.platform_v2_review_path(), "tenant-live")
        .unwrap()
        .put_snapshot(&snapshot, 20)
        .unwrap();

    let registry = serde_json::json!({
        "version": 1,
        "generation": "review-live-generation-1",
        "bindings": [{
            "project": "project-live",
            "workspace_kind": "user_workspace",
            "workspace_id": "review-workspace-live",
            "authority_kind": "review",
            "authority_id": "authority-1",
            "target": {
                "kind": "retained_session",
                "provider": "jcode",
                "session_id": "review-provider-session-live",
                "work_session_id": "review-session-live"
            }
        }]
    });
    let registry_path = config.state_dir().join("platform-v2-review-registry.json");
    std::fs::write(&registry_path, serde_json::to_vec(&registry).unwrap()).unwrap();
    std::fs::set_permissions(&registry_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    automonique_daemon::managed_sessions::ManagedSessionStore::open(config.managed_sessions_path())
        .unwrap()
        .observe_active(
            "review-provider-session-live",
            "review-provider-run-live",
            21,
        )
        .unwrap();
    snapshot
}

/// Seed the exact crash window after durable plan reservation and before
/// write admission. Recovery must re-open every mutable fence before it lets
/// the scheduler take custody.
fn reserve_unadmitted_retained_review(
    config: &DaemonConfig,
    snapshot: &ReviewSnapshot,
    idempotency_key: &str,
) -> IdempotencyKey {
    let comment = &snapshot.comments()[0];
    let key = IdempotencyKey::new(idempotency_key).unwrap();
    let actor = ReviewActorId::new("operator-live").unwrap();
    let authority = ReviewAuthority::new(
        ReviewAuthorityKind::Review,
        ReviewAuthorityId::new("authority-1").unwrap(),
    );
    let request = ReviewActionRequest::new(
        snapshot.workspace().clone(),
        snapshot.revision(),
        actor.clone(),
        ReviewAuthentication::UserSession,
        authority.clone(),
        key.clone(),
        ReviewAction::SendCommentToAgent {
            comment_id: comment.id().clone(),
            expected_comment_revision: comment.revision(),
        },
    )
    .unwrap();
    let request_digest = ReviewStore::action_request_digest(&request, ApprovalPolicy::NotRequired)
        .expect("request digest");
    let registry = std::fs::read(config.state_dir().join("platform-v2-review-registry.json"))
        .expect("registry");
    let registry_generation = *Sha256::digest(&registry).as_bytes();
    let contexts = WorkContextStore::open(config.platform_v2_work_context_path()).unwrap();
    let work_revision = contexts
        .validate_retained_session_lineage(
            "tenant-live",
            &ProjectId::new("project-live").unwrap(),
            snapshot.workspace(),
            &WorkSessionId::new("review-session-live").unwrap(),
            "review-provider-session-live",
        )
        .unwrap();
    let sessions = automonique_daemon::managed_sessions::ManagedSessionStore::open(
        config.managed_sessions_path(),
    )
    .unwrap();
    let provider_revision = Revision::new(
        sessions
            .by_id("review-provider-session-live")
            .unwrap()
            .unwrap()
            .revision,
    )
    .unwrap();
    let transport_key = format!(
        "v2-review-{}",
        request_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": "automonique.platform/review-agent-delivery/v1",
        "comment_id": comment.id().as_str(),
        "body": comment.body().as_str(),
    }))
    .unwrap();
    let plan = ReviewExternalEffectPlan::retained_session(
        request_digest,
        registry_generation,
        "jcode",
        "review-session-live",
        "review-provider-session-live",
        work_revision,
        provider_revision,
        &transport_key,
        payload,
    )
    .unwrap();
    let mut reviews =
        ReviewStore::open_scoped(config.platform_v2_review_path(), "tenant-live").unwrap();
    reviews
        .grant_authority(
            snapshot.workspace(),
            &actor,
            ReviewAuthentication::UserSession,
            &authority,
            0,
        )
        .unwrap();
    reviews
        .prepare_external_action(&request, ApprovalPolicy::NotRequired, &plan, 22)
        .unwrap();
    key
}

fn advance_retained_work_session(config: &DaemonConfig) {
    let mut contexts = WorkContextStore::open(config.platform_v2_work_context_path()).unwrap();
    let identity = WorkContextIdentity::Session(WorkSessionId::new("review-session-live").unwrap());
    let current = contexts
        .validate_policy_mapping(
            "tenant-live",
            &ProjectId::new("project-live").unwrap(),
            &identity,
        )
        .unwrap();
    let advanced = WorkContextRecord::new(
        current.identity().clone(),
        current.revision().checked_next().unwrap(),
        WorkContextLifecycle::Hibernated,
        current.label().clone(),
        current.attributes(),
        current.relations().to_vec(),
    )
    .unwrap();
    contexts
        .put_authoritative_record("tenant-live", &advanced)
        .unwrap();
}

fn advance_retained_review_with_unrelated_comment(
    config: &DaemonConfig,
    snapshot: &ReviewSnapshot,
) {
    let original = &snapshot.comments()[0];
    let unrelated = ReviewComment::new(
        ReviewCommentId::new("review-unrelated-live").unwrap(),
        Revision::FIRST,
        original.actor().clone(),
        ReviewText::new("unrelated review activity").unwrap(),
        original.anchor().clone(),
        CommentAgentState::NotSent,
        false,
    );
    let advanced = ReviewSnapshot::new(
        snapshot.workspace().clone(),
        snapshot.revision().checked_next().unwrap(),
        snapshot.files().to_vec(),
        vec![original.clone(), unrelated],
        snapshot.proposals().to_vec(),
        snapshot.checks().to_vec(),
        snapshot.review().clone(),
        snapshot.pull_request().clone(),
        snapshot.delivery().clone(),
        snapshot.attention_events().to_vec(),
    )
    .unwrap();
    ReviewStore::open_scoped(config.platform_v2_review_path(), "tenant-live")
        .unwrap()
        .put_snapshot(&advanced, 23)
        .unwrap();
}

struct ScriptedRetainedDelivery {
    provider_revision: Revision,
    submitted: bool,
    state: PlatformV2ReviewDeliveryState,
}

impl PlatformV2ReviewDelivery for ScriptedRetainedDelivery {
    fn inspect_target(
        &self,
        provider: &str,
        provider_session_id: &str,
    ) -> Result<Revision, &'static str> {
        assert_eq!(provider, "jcode");
        assert_eq!(provider_session_id, "review-provider-session-live");
        Ok(self.provider_revision)
    }

    fn reconcile(
        &mut self,
        coordinate: &PlatformV2ReviewDeliveryCoordinate<'_>,
    ) -> Result<PlatformV2ReviewDeliveryState, PlatformV2ReviewDeliveryError> {
        assert_eq!(coordinate.fence().provider(), "jcode");
        assert_eq!(
            coordinate.fence().provider_session_id(),
            "review-provider-session-live"
        );
        assert!(!coordinate.payload().is_empty());
        Ok(if self.submitted {
            self.state
        } else {
            PlatformV2ReviewDeliveryState::NotStarted
        })
    }

    fn submit(
        &mut self,
        coordinate: &PlatformV2ReviewDeliveryCoordinate<'_>,
        _now_ms: i64,
    ) -> Result<PlatformV2ReviewDeliveryState, PlatformV2ReviewDeliveryError> {
        assert!(!self.submitted);
        assert!(coordinate.transport_key().starts_with("v2-review-"));
        self.submitted = true;
        self.state = PlatformV2ReviewDeliveryState::Pending;
        Ok(self.state)
    }
}

fn live_repository(id: &str) -> WorkContextIdentity {
    WorkContextIdentity::Repository(
        V1RepositoryRef::new(ResourceCoordinate::new(
            ResourceAuthority::GitHub,
            ResourceKind::Repository,
            ResourceId::new(id).unwrap(),
        ))
        .unwrap(),
    )
}

fn live_workspace(
    id: &str,
    revision: Revision,
    lifecycle: WorkContextLifecycle,
) -> WorkContextRecord {
    WorkContextRecord::new(
        WorkContextIdentity::UserWorkspace(UserWorkspaceId::new(id).unwrap()),
        revision,
        lifecycle,
        WorkContextLabel::new(id).unwrap(),
        WorkContextAttributes::EMPTY,
        vec![
            WorkContextRelation::new(
                WorkContextRelationKind::UserWorkspaceProject,
                WorkContextIdentity::Project(ProjectId::new("project-live").unwrap()),
            )
            .unwrap(),
            WorkContextRelation::new(
                WorkContextRelationKind::UserWorkspaceCheckout,
                WorkContextIdentity::parse_local(
                    automonique_protocol::platform_v2::WorkContextTargetKind::Checkout,
                    "checkout-live",
                )
                .unwrap(),
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

fn set_tool_authority(config: &DaemonConfig, narrow_workspace_live: bool) {
    let path = config.platform_v2_policy_path();
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let principal = &mut policy["principals"][0];
    principal["authority"]["tools"] = serde_json::json!(["tool-live"]);
    for workspace in principal["workspaces"].as_array_mut().unwrap() {
        let narrowed_subtree = (workspace["kind"] == "user_workspace"
            && workspace["id"] == "workspace-live")
            || workspace["kind"] == "attempt_workspace"
            || workspace["kind"] == "session"
            || workspace["kind"] == "pane";
        workspace["inherited_authority"]["tools"] = if narrow_workspace_live && narrowed_subtree {
            serde_json::json!([])
        } else {
            serde_json::json!(["tool-live"])
        };
    }
    std::fs::write(path, serde_json::to_vec(&policy).unwrap()).unwrap();
}

fn remove_policy_scope(config: &DaemonConfig, kind: &str, id: &str) {
    let path = config.platform_v2_policy_path();
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    policy["principals"][0]["workspaces"]
        .as_array_mut()
        .unwrap()
        .retain(|workspace| workspace["kind"] != kind || workspace["id"] != id);
    std::fs::write(path, serde_json::to_vec(&policy).unwrap()).unwrap();
}

fn set_scope_tools(config: &DaemonConfig, kind: &str, id: &str, tools: &[&str]) {
    let path = config.platform_v2_policy_path();
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let scope = policy["principals"][0]["workspaces"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|scope| scope["kind"] == kind && scope["id"] == id)
        .unwrap();
    scope["inherited_authority"]["tools"] = serde_json::json!(tools);
    std::fs::write(path, serde_json::to_vec(&policy).unwrap()).unwrap();
}

#[test]
fn negotiation_advertises_only_v1_and_v2_fails_closed_until_host_wiring() {
    let _guard = full_daemon_test_guard();
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

#[test]
fn multi_tenant_policy_fails_closed_without_changing_v1() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    std::fs::create_dir(config.state_dir()).unwrap();
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = nix::unistd::geteuid().as_raw();
    let principal = |uid: u32, tenant: &str| {
        serde_json::json!({
            "uid": uid,
            "tenant": tenant,
            "actor": "operator",
            "serving_authority": "automonique",
            "projects": ["project-live"],
            "workspaces": [],
            "authority": {
                "filesystem": [], "credentials": [], "network": [],
                "tools": [], "providers": [], "models": []
            },
            "review_authorities": {}
        })
    };
    let policy = serde_json::json!({
        "version": 1,
        "principals": [principal(uid, "tenant-one"), principal(uid.saturating_add(1), "tenant-two")]
    });
    let path = config.platform_v2_policy_path();
    std::fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let serving = serve(&config);
    let negotiation = PlatformNegotiationRequestMessage::new(
        RequestId::new("negotiate-invalid-v2-policy").unwrap(),
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
    assert!(matches!(
        platform_v2(
            &config,
            "v2-invalid-policy-refusal",
            PlatformV2Request::GetWorkContext(WorkContextIdentity::Project(
                ProjectId::new("project-live").unwrap()
            ))
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_policy_invalid"
    ));
    serving.shutdown(&config);

    std::fs::set_permissions(
        config.platform_v2_policy_path(),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let serving = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-insecure-policy-refusal",
            PlatformV2Request::GetWorkContext(WorkContextIdentity::Project(
                ProjectId::new("project-live").unwrap()
            ))
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_policy_insecure"
    ));
    serving.shutdown(&config);

    std::fs::set_permissions(
        config.platform_v2_policy_path(),
        std::fs::Permissions::from_mode(0o4600),
    )
    .unwrap();
    let serving = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-special-mode-policy-refusal",
            PlatformV2Request::GetWorkContext(WorkContextIdentity::Project(
                ProjectId::new("project-live").unwrap()
            ))
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_policy_insecure"
    ));
    serving.shutdown(&config);

    let target = config.state_dir().join("policy-target.json");
    std::fs::rename(config.platform_v2_policy_path(), &target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&target, config.platform_v2_policy_path()).unwrap();
    let serving = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-symlink-policy-refusal",
            PlatformV2Request::GetWorkContext(WorkContextIdentity::Project(
                ProjectId::new("project-live").unwrap()
            ))
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_policy_insecure"
    ));
    serving.shutdown(&config);
}

#[test]
fn configured_v2_attention_reads_only_persisted_registry_owned_snapshots() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let mut snapshot: serde_json::Value = serde_json::from_slice(ATTENTION_SNAPSHOT).unwrap();
    snapshot["project"] = serde_json::json!("project-live");
    snapshot["user_workspace"] = serde_json::json!("workspace-live");
    let registry = serde_json::json!({
        "version": 1,
        "generation": "attention-live-generation-1",
        "snapshots": [snapshot],
    });
    let registry_path = config
        .state_dir()
        .join(automonique_daemon::platform_v2_host::ATTENTION_REGISTRY_NAME);
    std::fs::write(&registry_path, serde_json::to_vec(&registry).unwrap()).unwrap();
    std::fs::set_permissions(&registry_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let serving = serve(&config);
    let source = AttentionSource::new(
        AttentionSourceKind::ProviderSession,
        AttentionSourceId::new("provider-feed-1").unwrap(),
    );
    let response = platform_v2(
        &config,
        "attention-live-exact",
        PlatformV2Request::GetAttentionSourceSnapshot(AttentionReadRequest::new(
            source.clone(),
            ProjectId::new("project-live").unwrap(),
            UserWorkspaceId::new("workspace-live").unwrap(),
        )),
    );
    let PlatformV2Response::AttentionSourceSnapshot(snapshot) = response else {
        panic!("expected authoritative attention snapshot")
    };
    assert_eq!(snapshot.project().as_str(), "project-live");
    assert_eq!(snapshot.user_workspace().as_str(), "workspace-live");
    assert_eq!(snapshot.revision(), Revision::new(7).unwrap());
    assert_eq!(snapshot.observed_at_ms(), 2_000);

    for (request_id, project, workspace) in [
        (
            "attention-live-foreign-project",
            "foreign-project",
            "workspace-live",
        ),
        (
            "attention-live-foreign-workspace",
            "project-live",
            "foreign-workspace",
        ),
    ] {
        let unauthorized = platform_v2(
            &config,
            request_id,
            PlatformV2Request::GetAttentionSourceSnapshot(AttentionReadRequest::new(
                source.clone(),
                ProjectId::new(project).unwrap(),
                UserWorkspaceId::new(workspace).unwrap(),
            )),
        );
        assert!(
            matches!(unauthorized, PlatformV2Response::Refused(refusal) if refusal.category().as_str() == "platform_v2_scope_denied")
        );
    }

    let missing = platform_v2(
        &config,
        "attention-live-missing",
        PlatformV2Request::GetAttentionSourceSnapshot(AttentionReadRequest::new(
            source.clone(),
            ProjectId::new("project-live").unwrap(),
            UserWorkspaceId::new("wc_user_1").unwrap(),
        )),
    );
    assert!(
        matches!(missing, PlatformV2Response::Refused(refusal) if refusal.category().as_str() == "platform_v2_attention_not_found")
    );

    let mut drifted = registry;
    drifted["generation"] = serde_json::json!("attention-live-generation-2");
    std::fs::write(&registry_path, serde_json::to_vec(&drifted).unwrap()).unwrap();
    let changed = platform_v2(
        &config,
        "attention-live-drift",
        PlatformV2Request::GetAttentionSourceSnapshot(AttentionReadRequest::new(
            source,
            ProjectId::new("project-live").unwrap(),
            UserWorkspaceId::new("workspace-live").unwrap(),
        )),
    );
    assert!(
        matches!(changed, PlatformV2Response::Refused(refusal) if refusal.category().as_str() == "platform_v2_attention_registry_changed")
    );
    serving.shutdown(&config);
}

#[test]
fn configured_v2_attention_refuses_when_registry_is_absent() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let serving = serve(&config);
    let response = platform_v2(
        &config,
        "attention-live-absent",
        PlatformV2Request::GetAttentionSourceSnapshot(AttentionReadRequest::new(
            AttentionSource::new(
                AttentionSourceKind::Review,
                AttentionSourceId::new("review-source").unwrap(),
            ),
            ProjectId::new("project-live").unwrap(),
            UserWorkspaceId::new("workspace-live").unwrap(),
        )),
    );
    assert!(
        matches!(response, PlatformV2Response::Refused(refusal) if refusal.category().as_str() == "platform_v2_attention_registry_unavailable")
    );
    serving.shutdown(&config);
}

#[test]
fn configured_v2_uses_kernel_principal_scope_and_durable_idempotency() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let serving = serve(&config);

    let negotiation = PlatformNegotiationRequestMessage::new(
        RequestId::new("negotiate-v2-live").unwrap(),
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
            if selected.version() == PlatformVersion::V2
    ));

    let project = WorkContextIdentity::Project(ProjectId::new("project-live").unwrap());
    assert!(matches!(
        platform_v2(
            &config,
            "v2-authorized-read",
            PlatformV2Request::GetWorkContext(project)
        ),
        PlatformV2Response::WorkContextRecord(record)
            if record.identity().id() == "project-live"
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-denied-read",
            PlatformV2Request::GetWorkContext(WorkContextIdentity::Project(
                ProjectId::new("project-other").unwrap()
            ))
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_scope_denied"
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-denied-cross-project-lineage",
            PlatformV2Request::GetLineage(LineageReadRequest::new(
                ProjectId::new("project-other").unwrap(),
                UserWorkspaceId::new("workspace-live").unwrap(),
            ))
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_scope_denied"
    ));

    let resume = WorkspaceIntent::Resume(WorkspaceResumeIntent::new(
        WorkspaceIntentId::new("intent-resume-live").unwrap(),
        OrchestrationTaskId::new("task-live").unwrap(),
        UserWorkspaceId::new("workspace-live").unwrap(),
        Revision::FIRST,
    ));
    let resume_request =
        WorkspaceIntentRequest::new(ProjectId::new("project-live").unwrap(), resume.clone());
    let stale_resume = WorkspaceIntent::Resume(WorkspaceResumeIntent::new(
        WorkspaceIntentId::new("intent-resume-stale").unwrap(),
        OrchestrationTaskId::new("task-live").unwrap(),
        UserWorkspaceId::new("workspace-live").unwrap(),
        Revision::new(2).unwrap(),
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-resume-stale",
            PlatformV2Request::SubmitWorkspaceIntent(WorkspaceIntentRequest::new(
                ProjectId::new("project-live").unwrap(),
                stale_resume,
            ))
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_resume_stale_revision"
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-resume-refuses-without-adapter",
            PlatformV2Request::SubmitWorkspaceIntent(resume_request)
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_resume_adapter_pending"
    ));
    let wrong_workspace = WorkspaceIntent::Resume(WorkspaceResumeIntent::new(
        WorkspaceIntentId::new("intent-resume-wrong-workspace").unwrap(),
        OrchestrationTaskId::new("task-live").unwrap(),
        UserWorkspaceId::new("wc_user_1").unwrap(),
        Revision::FIRST,
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-resume-task-workspace-mismatch",
            PlatformV2Request::SubmitWorkspaceIntent(WorkspaceIntentRequest::new(
                ProjectId::new("project-live").unwrap(),
                wrong_workspace,
            )),
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_resume_scope_denied"
    ));
    let create = WorkspaceIntent::Create(WorkspaceCreateIntent::new(
        WorkspaceIntentId::new("intent-create-without-private-registry").unwrap(),
        OrchestrationTaskId::new("task-live").unwrap(),
        ExternalWorkIdentity::new(
            ExternalWorkProvider::GitHub,
            ExternalWorkAuthorityId::new("authority-live").unwrap(),
            ExternalWorkScope::new("scope-live").unwrap(),
            ExternalWorkKey::new("work-live").unwrap(),
        ),
        BaseSelectorId::new("base-live").unwrap(),
        BranchSelectorId::new("branch-live").unwrap(),
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-create-needs-private-selector-registry",
            PlatformV2Request::SubmitWorkspaceIntent(WorkspaceIntentRequest::new(
                ProjectId::new("project-live").unwrap(),
                create.clone(),
            )),
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str()
                == "platform_v2_create_selector_registry_unavailable"
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-create-without-registry-not-stored",
            PlatformV2Request::GetWorkspaceIntent(WorkspaceIntentLookup::new(
                ProjectId::new("project-live").unwrap(),
                create.intent_id().clone(),
            )),
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_not_found"
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-resume-without-adapter-not-stored",
            PlatformV2Request::GetWorkspaceIntent(WorkspaceIntentLookup::new(
                ProjectId::new("project-live").unwrap(),
                resume.intent_id().clone(),
            ))
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_not_found"
    ));

    let prepare = MutationPrepareRequest::new(
        IdempotencyKey::new("create-manual-workspace-once").unwrap(),
        WorkContextMutationIntent::CreateUserWorkspace(
            CreateUserWorkspaceIntent::new(
                WorkContextLabel::new("Manual existing-folder workspace").unwrap(),
                ExpectedWorkContext::new(
                    WorkContextIdentity::Project(ProjectId::new("project-live").unwrap()),
                    Revision::FIRST,
                ),
                ExpectedWorkContext::new(
                    WorkContextIdentity::parse_local(
                        WorkContextTargetKind::Checkout,
                        "checkout-live",
                    )
                    .unwrap(),
                    Revision::FIRST,
                ),
            )
            .unwrap(),
        ),
    );
    let PlatformV2Response::MutationPreview(first) = platform_v2(
        &config,
        "v2-prepare-first",
        PlatformV2Request::PrepareMutation(prepare.clone()),
    ) else {
        panic!("first preview")
    };
    let PlatformV2Response::MutationPreview(replay) = platform_v2(
        &config,
        "v2-prepare-replay",
        PlatformV2Request::PrepareMutation(prepare),
    ) else {
        panic!("preview replay")
    };
    assert_eq!(replay, first);

    let decision = MutationDecisionRequest::new(
        first.preview().clone(),
        work_context_mutation_preview_digest(&first).unwrap(),
        MutationApprovalDecision::Granted,
    );
    let PlatformV2Response::MutationApproval(approval) = platform_v2(
        &config,
        "v2-decision-first",
        PlatformV2Request::DecideMutation(decision.clone()),
    ) else {
        panic!("first decision")
    };
    let PlatformV2Response::MutationApproval(approval_replay) = platform_v2(
        &config,
        "v2-decision-replay",
        PlatformV2Request::DecideMutation(decision),
    ) else {
        panic!("decision replay")
    };
    assert_eq!(approval_replay, approval);

    let decoded_approval = approval.decode(&first).unwrap();
    let wrong_digest = MutationPreviewDigest::from_digest(
        automonique_protocol::digest::Sha256::digest(b"not-the-preview"),
    );
    assert!(matches!(
        platform_v2(
            &config,
            "v2-submit-wrong-preview-digest",
            PlatformV2Request::SubmitMutation(MutationSubmitRequest::new(
                first.preview().clone(),
                wrong_digest,
                Some(decoded_approval.id().clone()),
            )),
        ),
        PlatformV2Response::MutationRefused(refusal)
            if refusal.category()
                == automonique_protocol::platform_v2_lifecycle::MutationRefusalCategory::ApprovalMismatch
    ));
    let submit = MutationSubmitRequest::new(
        first.preview().clone(),
        work_context_mutation_preview_digest(&first).unwrap(),
        Some(decoded_approval.id().clone()),
    );
    let PlatformV2Response::MutationReceipt(raw_receipt) = platform_v2(
        &config,
        "v2-submit-logical-lifecycle",
        PlatformV2Request::SubmitMutation(submit.clone()),
    ) else {
        panic!("approved logical lifecycle mutation must be durably completed")
    };
    assert!(matches!(
        platform_v2(
            &config,
            "v2-submit-logical-lifecycle-replay",
            PlatformV2Request::SubmitMutation(submit),
        ),
        PlatformV2Response::MutationReceipt(replay) if replay == raw_receipt
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-submit-logical-lifecycle-lookup",
            PlatformV2Request::GetMutationReceipt(MutationReceiptLookup::new(
                ProjectId::new("project-live").unwrap(),
                ReceiptLookupKey::IdempotencyKey(
                    IdempotencyKey::new("create-manual-workspace-once").unwrap(),
                ),
            )),
        ),
        PlatformV2Response::MutationReceipt(found) if found == raw_receipt
    ));

    let fixture_action = decode_review_action_request(REVIEW_ACTION).unwrap();
    let action = ReviewActionTransportRequest::new_confirmed_correlated(
        fixture_action.workspace().clone(),
        fixture_action.expected_revision(),
        fixture_action.action().clone(),
        fixture_action.idempotency_key().clone(),
        ReviewConfirmationDigest::new("ab".repeat(32)).unwrap(),
        Revision::new(1).unwrap(),
        automonique_protocol::platform_v2_transport::ReviewReceiptCorrelationDigest::new(
            "cd".repeat(32),
        )
        .unwrap(),
    )
    .unwrap();
    let client_document = PlatformV2RequestMessage::new(
        RequestId::new("v2-review-client-shape").unwrap(),
        PlatformV2Request::ExecuteReviewAction(action.clone()),
    )
    .to_canonical_bytes()
    .unwrap();
    let client_document = std::str::from_utf8(&client_document).unwrap();
    assert!(!client_document.contains("\"actor\""));
    assert!(!client_document.contains("\"tenant\""));
    assert!(!client_document.contains("\"authentication\""));
    assert!(!client_document.contains("\"authority\""));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-review-no-adapter",
            PlatformV2Request::ExecuteReviewAction(action.clone()),
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_review_ci_adapter_unavailable"
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-review-no-custody-receipt",
            PlatformV2Request::GetReviewReceipt(
                ReviewReceiptLookup::new(
                    ProjectId::new("project-live").unwrap(),
                    action.workspace().clone(),
                    action.idempotency_key().clone(),
                )
                .unwrap()
            )
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_not_found"
    ));

    let review_snapshot = decode_review_snapshot(REVIEW_SNAPSHOT).unwrap();
    let comment_action = ReviewActionTransportRequest::new(
        review_snapshot.workspace().clone(),
        review_snapshot.revision(),
        ReviewAction::AddComment {
            comment_id: ReviewCommentId::new("comment-live-local").unwrap(),
            anchor: review_snapshot.comments()[0].anchor().clone(),
            body: ReviewText::new("A durable local review comment.").unwrap(),
        },
        IdempotencyKey::new("review-comment-live-once").unwrap(),
    )
    .unwrap();
    let PlatformV2Response::ReviewReceipt(comment_receipt) = platform_v2(
        &config,
        "v2-review-local-comment",
        PlatformV2Request::ExecuteReviewAction(comment_action.clone()),
    ) else {
        panic!("local comment receipt")
    };
    assert_eq!(comment_receipt.outcome(), ReviewReceiptOutcome::Completed);
    assert_eq!(comment_receipt.revision(), Some(Revision::new(10).unwrap()));
    assert_eq!(comment_receipt.actor().as_str(), "operator-live");
    assert!(matches!(
        platform_v2(
            &config,
            "v2-review-local-comment-replay",
            PlatformV2Request::ExecuteReviewAction(comment_action.clone()),
        ),
        PlatformV2Response::ReviewReceipt(replay) if replay == comment_receipt
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-review-local-comment-lookup",
            PlatformV2Request::GetReviewReceipt(
                ReviewReceiptLookup::new(
                    ProjectId::new("project-live").unwrap(),
                    comment_action.workspace().clone(),
                    comment_action.idempotency_key().clone(),
                )
                .unwrap()
            )
        ),
        PlatformV2Response::ReviewReceipt(found) if found == comment_receipt
    ));

    serving.shutdown(&config);

    // The v2 records are sibling durable stores and survive a daemon restart;
    // Platform v1 startup and shutdown continue to use the same socket.
    let serving = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-read-after-restart",
            PlatformV2Request::GetWorkContext(WorkContextIdentity::Project(
                ProjectId::new("project-live").unwrap()
            ))
        ),
        PlatformV2Response::WorkContextRecord(_)
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-resume-remains-absent-after-restart",
            PlatformV2Request::GetWorkspaceIntent(WorkspaceIntentLookup::new(
                ProjectId::new("project-live").unwrap(),
                resume.intent_id().clone(),
            ))
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_not_found"
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-review-still-no-custody-after-restart",
            PlatformV2Request::GetReviewReceipt(
                ReviewReceiptLookup::new(
                    ProjectId::new("project-live").unwrap(),
                    action.workspace().clone(),
                    action.idempotency_key().clone(),
                )
                .unwrap(),
            )
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_not_found"
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-review-local-comment-after-restart",
            PlatformV2Request::GetReviewReceipt(
                ReviewReceiptLookup::new(
                    ProjectId::new("project-live").unwrap(),
                    comment_action.workspace().clone(),
                    comment_action.idempotency_key().clone(),
                )
                .unwrap(),
            )
        ),
        PlatformV2Response::ReviewReceipt(found) if found == comment_receipt
    ));
    serving.shutdown(&config);
}

#[test]
fn retained_review_replay_reconciles_after_unrelated_snapshot_advance() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let snapshot = configure_retained_review_delivery(&config);
    let uid = nix::unistd::geteuid().as_raw();
    let mut host = PlatformV2Host::open(
        &config.platform_v2_policy_path(),
        &config.platform_v2_work_context_path(),
        &config.platform_v2_lineage_path(),
        &config.platform_v2_review_path(),
        uid,
    );
    let provider_revision = Revision::new(
        automonique_daemon::managed_sessions::ManagedSessionStore::open(
            config.managed_sessions_path(),
        )
        .unwrap()
        .by_id("review-provider-session-live")
        .unwrap()
        .unwrap()
        .revision,
    )
    .unwrap();
    let mut delivery = ScriptedRetainedDelivery {
        provider_revision,
        submitted: false,
        state: PlatformV2ReviewDeliveryState::NotStarted,
    };
    let comment = &snapshot.comments()[0];
    let action = ReviewActionTransportRequest::new(
        snapshot.workspace().clone(),
        snapshot.revision(),
        ReviewAction::SendCommentToAgent {
            comment_id: comment.id().clone(),
            expected_comment_revision: comment.revision(),
        },
        IdempotencyKey::new("review-retained-rebase-live").unwrap(),
    )
    .unwrap();
    assert!(matches!(
        host.handle_with_review_delivery(
            uid,
            &PlatformV2Request::ExecuteReviewAction(action.clone()),
            22,
            &mut delivery,
        ),
        PlatformV2Response::ReviewReceipt(receipt)
            if receipt.outcome() == ReviewReceiptOutcome::Accepted
    ));

    advance_retained_review_with_unrelated_comment(&config, &snapshot);
    delivery.state = PlatformV2ReviewDeliveryState::Completed;
    let completed = host.handle_with_review_delivery(
        uid,
        &PlatformV2Request::ExecuteReviewAction(action),
        24,
        &mut delivery,
    );
    assert!(matches!(
        completed,
        PlatformV2Response::ReviewReceipt(receipt)
            if receipt.outcome() == ReviewReceiptOutcome::Completed
    ));
    let current = ReviewStore::open_scoped(config.platform_v2_review_path(), "tenant-live")
        .unwrap()
        .snapshot(snapshot.workspace())
        .unwrap()
        .unwrap();
    assert_eq!(
        current.revision(),
        snapshot
            .revision()
            .checked_next()
            .unwrap()
            .checked_next()
            .unwrap()
    );
    assert_eq!(
        current
            .comments()
            .iter()
            .find(|candidate| candidate.id() == comment.id())
            .unwrap()
            .agent_state(),
        CommentAgentState::Sent
    );
    assert_eq!(
        current
            .comments()
            .iter()
            .find(|candidate| candidate.id().as_str() == "review-unrelated-live")
            .unwrap()
            .agent_state(),
        CommentAgentState::NotSent
    );
}

#[test]
fn retained_review_escaping_heavy_envelope_refuses_before_write_and_replays_terminally() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let snapshot = configure_retained_review_delivery(&config);
    let original = &snapshot.comments()[0];
    let mut comments = vec![original.clone()];
    let mut targets = Vec::new();
    for index in 0..100 {
        let id = ReviewCommentId::new(format!("escaping-comment-{index:03}")).unwrap();
        comments.push(ReviewComment::new(
            id.clone(),
            Revision::FIRST,
            original.actor().clone(),
            ReviewText::new("\\".repeat(4096)).unwrap(),
            original.anchor().clone(),
            CommentAgentState::NotSent,
            false,
        ));
        targets.push(ReviewCommentTarget::new(id, Revision::FIRST));
    }
    comments.sort_by(|left, right| left.id().as_str().cmp(right.id().as_str()));
    let oversized_snapshot = ReviewSnapshot::new(
        snapshot.workspace().clone(),
        snapshot.revision().checked_next().unwrap(),
        snapshot.files().to_vec(),
        comments,
        snapshot.proposals().to_vec(),
        snapshot.checks().to_vec(),
        snapshot.review().clone(),
        snapshot.pull_request().clone(),
        snapshot.delivery().clone(),
        snapshot.attention_events().to_vec(),
    )
    .unwrap();
    ReviewStore::open_scoped(config.platform_v2_review_path(), "tenant-live")
        .unwrap()
        .put_snapshot(&oversized_snapshot, 22)
        .unwrap();

    let action = ReviewActionTransportRequest::new(
        oversized_snapshot.workspace().clone(),
        oversized_snapshot.revision(),
        ReviewAction::BatchSendCommentsToAgent { comments: targets },
        IdempotencyKey::new("review-retained-envelope-boundary-live").unwrap(),
    )
    .unwrap();
    let serving = serve(&config);
    let first = platform_v2(
        &config,
        "v2-review-retained-envelope-boundary",
        PlatformV2Request::ExecuteReviewAction(action.clone()),
    );
    let PlatformV2Response::ReviewReceipt(first_receipt) = first else {
        panic!("oversized envelope must produce a durable review receipt");
    };
    assert_eq!(first_receipt.outcome(), ReviewReceiptOutcome::Refused);
    let replay = platform_v2(
        &config,
        "v2-review-retained-envelope-boundary-replay",
        PlatformV2Request::ExecuteReviewAction(action.clone()),
    );
    assert!(matches!(
        replay,
        PlatformV2Response::ReviewReceipt(receipt) if receipt == first_receipt
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-review-retained-envelope-boundary-lookup",
            PlatformV2Request::GetReviewReceipt(
                ReviewReceiptLookup::new(
                    ProjectId::new("project-live").unwrap(),
                    oversized_snapshot.workspace().clone(),
                    action.idempotency_key().clone(),
                )
                .unwrap(),
            ),
        ),
        PlatformV2Response::ReviewReceipt(receipt) if receipt == first_receipt
    ));
    serving.shutdown(&config);

    let custody = rusqlite::Connection::open(config.platform_v2_review_path()).unwrap();
    let (outcome, write_admitted_at_ms): (String, Option<i64>) = custody
        .query_row(
            "SELECT r.outcome,p.write_admitted_at_ms
             FROM review_action_previews p JOIN review_action_receipts r USING(preview_id)
             WHERE p.idempotency_key='review-retained-envelope-boundary-live'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(outcome, "refused");
    assert_eq!(write_admitted_at_ms, None);
    assert_eq!(
        custody
            .query_row(
                "SELECT COUNT(*) FROM review_external_effect_targets",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0,
        "pre-write refusal must release every reserved comment target"
    );
    assert_eq!(
        custody
            .query_row(
                "SELECT COUNT(*) FROM review_external_effect_plans",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1,
        "the exact plan remains retained for terminal replay validation"
    );
    let scheduler = rusqlite::Connection::open(config.database_path()).unwrap();
    assert_eq!(
        scheduler
            .query_row(
                "SELECT COUNT(*) FROM inbox WHERE transport='platform_v2.retained_review'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0,
        "an oversized envelope must never enter scheduler custody"
    );
}

/// Agent delivery is advertised only when a send would really be admitted,
/// and the advertisement retracts itself once the note has been delivered.
///
/// This is the whole argument for shipping batch-send without a confirmation
/// digest. A rerun needs one because the effect fires in a system the daemon
/// does not own. Here the target is registry-owned rather than client-named,
/// and exactly-once falls out of the domain state machine instead: settling a
/// delivery bumps both the snapshot revision and the delivered note's
/// revision, and moves the note out of the sendable agent states. So a second
/// send of the same batch cannot be constructed from the advertisement that
/// authorized the first one, whatever idempotency key it carries.
///
/// The final replay is what gives that claim teeth. It reuses the exact
/// advertised revision under a fresh idempotency key, which is precisely the
/// request a duplicate-delivery bug would have to make, and it is refused as
/// stale rather than accepted.
/// Seed a real private repository, a review projection describing it, and a
/// registry binding that grants index writes and nothing else.
fn configure_git_staging_review(config: &DaemonConfig) -> (ReviewSnapshot, PathBuf) {
    let policy_path = config.platform_v2_policy_path();
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy_path).unwrap()).unwrap();
    policy["principals"][0]["workspaces"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "project": "project-live",
            "kind": "user_workspace",
            "id": "git-workspace-live",
            "inherited_authority": {
                "filesystem": [], "credentials": [], "network": [],
                "tools": [], "providers": [], "models": []
            }
        }));
    policy["principals"][0]["review_authorities"]["git"] =
        serde_json::Value::String("authority-1".to_owned());
    std::fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();

    let workspace =
        WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("git-workspace-live").unwrap());
    let mut contexts = WorkContextStore::open(config.platform_v2_work_context_path()).unwrap();
    contexts
        .put_authoritative_record(
            "tenant-live",
            &live_workspace(
                "git-workspace-live",
                Revision::FIRST,
                WorkContextLifecycle::Active,
            ),
        )
        .unwrap();
    drop(contexts);

    // A real repository, in the exact private shape the registry admits.
    let repository = config.state_root.join("git-staging-live");
    std::fs::create_dir_all(&repository).unwrap();
    std::fs::set_permissions(&repository, std::fs::Permissions::from_mode(0o700)).unwrap();
    let run = |arguments: &[&str]| {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    run(&["init", "--quiet", "--initial-branch=main", "."]);
    run(&["config", "user.email", "review@example.invalid"]);
    run(&["config", "user.name", "Review"]);
    std::fs::create_dir_all(repository.join("src")).unwrap();
    std::fs::write(repository.join("src/review.rs"), "base\n").unwrap();
    run(&["add", "--", "src/review.rs"]);
    run(&["commit", "--quiet", "-m", "base"]);
    // The change the projection describes, left unstaged so a stage proposal
    // has something to perform.
    std::fs::write(repository.join("src/review.rs"), "reviewed\n").unwrap();
    std::fs::set_permissions(
        repository.join(".git"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let canonical = std::fs::canonicalize(&repository).unwrap();

    let base = decode_review_snapshot(REVIEW_SNAPSHOT).unwrap();
    let original = &base.files()[0];
    let file = ReviewFile::new(
        original.id().clone(),
        original.path().clone(),
        original.change(),
        WorktreeFileState::Unstaged,
        original.preview().clone(),
        original.conflict(),
        original.hunks().to_vec(),
    )
    .unwrap();
    let proposal = ReviewProposal::new(
        ReviewProposalId::new("proposal-stage-live").unwrap(),
        ReviewProposalKind::Stage,
        ReviewAuthority::new(
            ReviewAuthorityKind::Git,
            ReviewAuthorityId::new("authority-1").unwrap(),
        ),
        vec![file.id().clone()],
        None,
    )
    .unwrap();
    let snapshot = ReviewSnapshot::new(
        workspace,
        base.revision(),
        vec![file],
        Vec::new(),
        vec![proposal],
        base.checks().to_vec(),
        base.review().clone(),
        base.pull_request().clone(),
        base.delivery().clone(),
        base.attention_events().to_vec(),
    )
    .unwrap();
    ReviewStore::open_scoped(config.platform_v2_review_path(), "tenant-live")
        .unwrap()
        .put_snapshot(&snapshot, 20)
        .unwrap();

    let registry = serde_json::json!({
        "version": 1,
        "generation": "git-live-generation-1",
        "bindings": [{
            "project": "project-live",
            "workspace_kind": "user_workspace",
            "workspace_id": "git-workspace-live",
            "authority_kind": "git",
            "authority_id": "authority-1",
            "target": {
                "kind": "local_repository",
                "canonical_root": canonical,
                // Index writes only. Committing and conflict resolution stay
                // withheld, and the response has to show that.
                "index_write": true
            }
        }]
    });
    let registry_path = config.state_dir().join("platform-v2-review-registry.json");
    std::fs::write(&registry_path, serde_json::to_vec(&registry).unwrap()).unwrap();
    std::fs::set_permissions(&registry_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    (snapshot, canonical)
}

/// The whole staging vertical, against a repository that really exists.
///
/// This is what PR #221 could not have: the server reads the worktree, mints a
/// control fenced on what it read, admits exactly that control once, performs
/// it with git, and then stops advertising it because the repository no longer
/// supports it.
#[test]
fn advertised_git_staging_is_earned_from_a_read_admitted_once_and_then_withdrawn() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let (snapshot, repository) = configure_git_staging_review(&config);
    let _serving = serve(&config);

    let read = || {
        let response = platform_v2(
            &config,
            "v2-review-git-capabilities",
            PlatformV2Request::GetReviewCapabilities(
                ReviewReadRequest::new(
                    ProjectId::new("project-live").unwrap(),
                    snapshot.workspace().clone(),
                )
                .unwrap(),
            ),
        );
        match response {
            PlatformV2Response::ReviewCapabilities(capabilities) => capabilities,
            other => panic!("expected review capabilities, got {other:?}"),
        }
    };

    let advertised = read();
    let staging = advertised.staging();
    assert_eq!(
        staging.len(),
        1,
        "one proposal, one grant, one control: {staging:?}"
    );
    let control = &staging[0];
    assert_eq!(control.proposal_id().as_str(), "proposal-stage-live");
    assert_eq!(control.kind(), ReviewProposalKind::Stage);
    assert_eq!(control.authority().kind(), ReviewAuthorityKind::Git);
    assert!(
        advertised.conflict_resolutions().is_empty(),
        "nothing is conflicted, so nothing may be resolved",
    );
    // The fence is what the server read, not what an operator declared.
    let head = std::process::Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args(["rev-parse", "HEAD"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert_eq!(
        control.expected_head_revision().as_str(),
        String::from_utf8(head.stdout).unwrap().trim(),
        "the advertised head is the commit the repository is really on",
    );

    // Send exactly what was advertised. Nothing here is a client string: the
    // files, the paths and the observation all came from the server.
    let action = ReviewActionTransportRequest::new_confirmed_correlated(
        snapshot.workspace().clone(),
        advertised.snapshot_revision(),
        ReviewAction::Stage {
            proposal_id: control.proposal_id().clone(),
        },
        IdempotencyKey::new("advertised-stage-once").unwrap(),
        control.confirmation_digest().clone(),
        advertised.workspace_revision(),
        control.receipt_correlation_digest().clone(),
    )
    .unwrap();
    let receipt = match platform_v2(
        &config,
        "v2-review-git-stage",
        PlatformV2Request::ExecuteReviewAction(action.clone()),
    ) {
        PlatformV2Response::ReviewReceipt(receipt) => receipt,
        other => panic!("expected a receipt, got {other:?}"),
    };
    assert_eq!(
        receipt.outcome(),
        ReviewReceiptOutcome::Accepted,
        "the write is acknowledged before it is reconciled",
    );

    // The repository really moved: the file is staged.
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args(["status", "--porcelain=v2", "--", "src/review.rs"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    let status = String::from_utf8(status.stdout).unwrap();
    assert!(
        status.starts_with("1 M."),
        "the named file must be staged and clean in the worktree: {status:?}",
    );

    // The receipt is polled through its correlation, never by re-sending the
    // action: the action's confirmation was minted over an observation the
    // write itself invalidated.
    let polled = match platform_v2(
        &config,
        "v2-review-git-receipt",
        PlatformV2Request::GetReviewReceipt(
            ReviewReceiptLookup::new_correlated(
                ProjectId::new("project-live").unwrap(),
                snapshot.workspace().clone(),
                IdempotencyKey::new("advertised-stage-once").unwrap(),
                control.receipt_correlation_digest().clone(),
            )
            .unwrap(),
        ),
    ) {
        PlatformV2Response::ReviewReceipt(receipt) => receipt,
        other => panic!("expected a receipt, got {other:?}"),
    };
    assert_eq!(
        polled.outcome(),
        ReviewReceiptOutcome::Completed,
        "reconciling an acknowledged write against the effect it produced completes it",
    );

    // And the control is gone, because the repository no longer supports it:
    // there is nothing left to stage.
    let after = read();
    assert!(
        after.staging().is_empty(),
        "a performed proposal must not still be advertised: {:?}",
        after.staging(),
    );

    // Replaying the original confirmation is refused rather than performed
    // twice. The worktree it was minted over is gone.
    assert!(
        matches!(
            platform_v2(
                &config,
                "v2-review-git-stage-replay",
                PlatformV2Request::ExecuteReviewAction(action),
            ),
            PlatformV2Response::Refused(_)
        ),
        "a confirmation outlives neither its snapshot nor its worktree",
    );
}

#[test]
fn advertised_agent_delivery_is_admitted_once_and_then_withdrawn() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let snapshot = configure_retained_review_delivery(&config);
    let _serving = serve(&config);
    let comment = &snapshot.comments()[0];

    let read = || {
        let response = platform_v2(
            &config,
            "v2-review-agent-capabilities",
            PlatformV2Request::GetReviewCapabilities(
                ReviewReadRequest::new(
                    ProjectId::new("project-live").unwrap(),
                    snapshot.workspace().clone(),
                )
                .unwrap(),
            ),
        );
        match response {
            PlatformV2Response::ReviewCapabilities(capabilities) => capabilities,
            other => panic!("expected review capabilities, got {other:?}"),
        }
    };

    let advertised = read();
    let deliverable = advertised.agent_deliverable_comments();
    assert_eq!(
        deliverable.len(),
        1,
        "the seeded not_sent note is the only deliverable one"
    );
    assert_eq!(deliverable[0].comment_id(), comment.id());
    assert_eq!(
        deliverable[0].expected_comment_revision(),
        comment.revision()
    );
    assert_eq!(
        deliverable[0].authority().kind(),
        ReviewAuthorityKind::Review,
        "delivery is advertised under the review authority the snapshot names"
    );
    assert_eq!(advertised.snapshot_revision(), snapshot.revision());

    // Send exactly what was advertised, and nothing the client invented.
    let batch = ReviewAction::BatchSendCommentsToAgent {
        comments: vec![ReviewCommentTarget::new(
            deliverable[0].comment_id().clone(),
            deliverable[0].expected_comment_revision(),
        )],
    };
    let action = ReviewActionTransportRequest::new(
        snapshot.workspace().clone(),
        advertised.snapshot_revision(),
        batch.clone(),
        IdempotencyKey::new("advertised-batch-once").unwrap(),
    )
    .unwrap();
    assert!(
        matches!(
            platform_v2(
                &config,
                "v2-review-agent-batch",
                PlatformV2Request::ExecuteReviewAction(action.clone()),
            ),
            PlatformV2Response::ReviewReceipt(ref receipt)
                if receipt.outcome() == ReviewReceiptOutcome::Accepted
        ),
        "the advertised batch is admitted"
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let response = platform_v2(
            &config,
            "v2-review-agent-batch-lookup",
            PlatformV2Request::GetReviewReceipt(
                ReviewReceiptLookup::new(
                    ProjectId::new("project-live").unwrap(),
                    snapshot.workspace().clone(),
                    action.idempotency_key().clone(),
                )
                .unwrap(),
            ),
        );
        if let PlatformV2Response::ReviewReceipt(receipt) = response
            && matches!(
                receipt.outcome(),
                ReviewReceiptOutcome::Completed
                    | ReviewReceiptOutcome::Refused
                    | ReviewReceiptOutcome::Unknown
            )
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "retained delivery did not settle"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    // Settling moved the snapshot on. Whatever the provider decided, the
    // exact advertisement that authorized the first send is gone: a delivered
    // note leaves the sendable states entirely, and a refused one is only
    // re-offered at a strictly higher revision.
    let after = read();
    assert!(
        after.snapshot_revision() > advertised.snapshot_revision(),
        "settling a delivery advances the snapshot revision"
    );
    assert!(
        after.agent_deliverable_comments().iter().all(|capability| {
            capability.comment_id() != comment.id()
                || capability.expected_comment_revision() > comment.revision()
        }),
        "the settled note is never re-advertised at the revision already sent"
    );

    // The request a duplicate-delivery bug would have to make: the same
    // batch, at the same advertised revision, under a key the store has never
    // seen. Without a confirmation digest anywhere in sight, it is still
    // refused, because the revision fence alone is sufficient.
    let replay = ReviewActionTransportRequest::new(
        snapshot.workspace().clone(),
        advertised.snapshot_revision(),
        batch,
        IdempotencyKey::new("advertised-batch-duplicate").unwrap(),
    )
    .unwrap();
    let refusal = platform_v2(
        &config,
        "v2-review-agent-batch-duplicate",
        PlatformV2Request::ExecuteReviewAction(replay),
    );
    let PlatformV2Response::Refused(refusal) = refusal else {
        panic!("a second delivery of an already sent batch must be refused, got {refusal:?}");
    };
    assert_eq!(refusal.category().as_str(), "platform_v2_review_stale");
}

/// An installed registry binding is not, by itself, a capability.
///
/// This is the rule that keeps the advertisement honest: the client is told a
/// send will be admitted, so the server has to have proven it, not merely
/// found an operator's binding on disk. The check-rerun path earns that right
/// with a mutation-free provider observation before it advertises; the
/// retained-session path earns it by resolving the session lineage and
/// probing the bound target.
///
/// Here the binding is complete and valid but names a provider session that
/// was never observed, which is what an operator typo or a session that has
/// since gone looks like. Advertising it would hand the client a control that
/// always refuses, which is strictly worse than the fail-closed refusal it
/// already gets. The response must still be a well-formed capability
/// document, because an unreachable agent is not a broken workspace: the
/// rerun family and the read itself keep working.
#[test]
fn an_unreachable_retained_session_advertises_nothing_and_still_answers() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let snapshot = configure_retained_review_delivery(&config);

    // Same operator binding, valid in every structural way, pointing at a
    // session the daemon has never seen.
    let registry = serde_json::json!({
        "version": 1,
        "generation": "review-live-generation-1",
        "bindings": [{
            "project": "project-live",
            "workspace_kind": "user_workspace",
            "workspace_id": "review-workspace-live",
            "authority_kind": "review",
            "authority_id": "authority-1",
            "target": {
                "kind": "retained_session",
                "provider": "jcode",
                "session_id": "review-provider-session-absent",
                "work_session_id": "review-session-live"
            }
        }]
    });
    let registry_path = config.state_dir().join("platform-v2-review-registry.json");
    std::fs::write(&registry_path, serde_json::to_vec(&registry).unwrap()).unwrap();
    std::fs::set_permissions(&registry_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let _serving = serve(&config);
    let response = platform_v2(
        &config,
        "v2-review-agent-unreachable",
        PlatformV2Request::GetReviewCapabilities(
            ReviewReadRequest::new(
                ProjectId::new("project-live").unwrap(),
                snapshot.workspace().clone(),
            )
            .unwrap(),
        ),
    );
    let PlatformV2Response::ReviewCapabilities(capabilities) = response else {
        panic!("an unreachable agent session must not break the capability read, got {response:?}");
    };
    assert!(
        capabilities.agent_deliverable_comments().is_empty(),
        "an installed binding whose session cannot be resolved advertises nothing"
    );
    assert_eq!(capabilities.snapshot_revision(), snapshot.revision());

    // And the client's own fail-closed path still tells it the truth if it
    // sends anyway, which is why the empty list needs no explanation.
    let comment = &snapshot.comments()[0];
    let refusal = platform_v2(
        &config,
        "v2-review-agent-unreachable-send",
        PlatformV2Request::ExecuteReviewAction(
            ReviewActionTransportRequest::new(
                snapshot.workspace().clone(),
                snapshot.revision(),
                ReviewAction::BatchSendCommentsToAgent {
                    comments: vec![ReviewCommentTarget::new(
                        comment.id().clone(),
                        comment.revision(),
                    )],
                },
                IdempotencyKey::new("unreachable-batch").unwrap(),
            )
            .unwrap(),
        ),
    );
    assert!(
        matches!(refusal, PlatformV2Response::Refused(_)),
        "an unadvertised send is refused, got {refusal:?}"
    );
}

#[test]
fn retained_review_comment_is_planned_once_and_submitted_to_the_exact_live_session() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let snapshot = configure_retained_review_delivery(&config);
    let serving = serve(&config);
    let comment = &snapshot.comments()[0];
    let action = ReviewActionTransportRequest::new(
        snapshot.workspace().clone(),
        snapshot.revision(),
        ReviewAction::SendCommentToAgent {
            comment_id: comment.id().clone(),
            expected_comment_revision: comment.revision(),
        },
        IdempotencyKey::new("review-retained-live-once").unwrap(),
    )
    .unwrap();
    let first = platform_v2(
        &config,
        "v2-review-retained-live",
        PlatformV2Request::ExecuteReviewAction(action.clone()),
    );
    assert!(matches!(
        first,
        PlatformV2Response::ReviewReceipt(ref receipt)
            if receipt.outcome() == ReviewReceiptOutcome::Accepted
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-review-retained-live-replay",
            PlatformV2Request::ExecuteReviewAction(action.clone()),
        ),
        PlatformV2Response::ReviewReceipt(_)
    ));
    let deadline = Instant::now() + Duration::from_secs(5);
    let terminal = loop {
        let response = platform_v2(
            &config,
            "v2-review-retained-live-lookup",
            PlatformV2Request::GetReviewReceipt(
                ReviewReceiptLookup::new(
                    ProjectId::new("project-live").unwrap(),
                    snapshot.workspace().clone(),
                    action.idempotency_key().clone(),
                )
                .unwrap(),
            ),
        );
        if let PlatformV2Response::ReviewReceipt(receipt) = response
            && matches!(
                receipt.outcome(),
                ReviewReceiptOutcome::Completed
                    | ReviewReceiptOutcome::Refused
                    | ReviewReceiptOutcome::Unknown
            )
        {
            break receipt;
        }
        assert!(
            Instant::now() < deadline,
            "retained delivery did not leave the scheduler pending state"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    serving.shutdown(&config);

    let serving = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-review-retained-live-after-restart",
            PlatformV2Request::GetReviewReceipt(
                ReviewReceiptLookup::new(
                    ProjectId::new("project-live").unwrap(),
                    snapshot.workspace().clone(),
                    action.idempotency_key().clone(),
                )
                .unwrap(),
            ),
        ),
        PlatformV2Response::ReviewReceipt(receipt) if receipt == terminal
    ));
    serving.shutdown(&config);

    let scheduler = rusqlite::Connection::open(config.database_path()).unwrap();
    let deliveries: i64 = scheduler
        .query_row(
            "SELECT COUNT(*) FROM inbox WHERE transport='platform_v2.retained_review' AND scope='review-provider-session-live'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(deliveries, 1);
    let (transport_key, payload): (String, Vec<u8>) = scheduler
        .query_row(
            "SELECT transport_key,payload FROM inbox WHERE transport='platform_v2.retained_review' AND scope='review-provider-session-live'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let payload_text = std::str::from_utf8(&payload).unwrap();
    assert!(payload_text.contains("automonique.platform/review-agent-delivery/v1"));
    assert!(payload_text.contains(comment.id().as_str()));
    assert!(payload_text.contains(comment.body().as_str()));
    assert!(payload_text.contains("review-workspace-live"));

    let custody = rusqlite::Connection::open(config.platform_v2_review_path()).unwrap();
    let (planned_key, planned_payload): (String, Vec<u8>) = custody
        .query_row(
            "SELECT transport_key,payload FROM review_external_effect_plans",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(planned_key, transport_key);
    let envelope: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(envelope["tenant"], "tenant-live");
    assert_eq!(envelope["project"], "project-live");
    assert_eq!(envelope["review_workspace_kind"], "user_workspace");
    assert_eq!(envelope["review_workspace_id"], "review-workspace-live");
    let registry_generation = Sha256::digest(
        &std::fs::read(config.state_dir().join("platform-v2-review-registry.json")).unwrap(),
    );
    let registry_generation = registry_generation
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        envelope["expected_registry_generation"],
        registry_generation
    );
    assert_eq!(envelope["work_session_id"], "review-session-live");
    assert_eq!(envelope["expected_work_session_revision"], 1);
    assert_eq!(envelope["provider"], "jcode");
    assert_eq!(
        envelope["provider_session_id"],
        "review-provider-session-live"
    );
    assert_eq!(envelope["expected_provider_session_revision"], 1);
    assert_eq!(
        envelope["payload"].as_str().unwrap().as_bytes(),
        planned_payload
    );
}

#[test]
fn retained_review_recovery_refuses_before_custody_when_work_session_revision_changed() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let snapshot = configure_retained_review_delivery(&config);
    let key = reserve_unadmitted_retained_review(&config, &snapshot, "review-work-fence-live");
    advance_retained_work_session(&config);

    let serving = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-review-work-fence-recovery",
            PlatformV2Request::GetReviewReceipt(
                ReviewReceiptLookup::new(
                    ProjectId::new("project-live").unwrap(),
                    snapshot.workspace().clone(),
                    key,
                )
                .unwrap(),
            ),
        ),
        PlatformV2Response::ReviewReceipt(receipt)
            if receipt.outcome() == ReviewReceiptOutcome::Refused
    ));
    serving.shutdown(&config);

    let scheduler = rusqlite::Connection::open(config.database_path()).unwrap();
    let deliveries: i64 = scheduler
        .query_row(
            "SELECT COUNT(*) FROM inbox WHERE transport='platform_v2.retained_review'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(deliveries, 0, "a stale work fence never reaches custody");
}

#[test]
fn retained_review_recovery_refuses_before_custody_when_write_admission_is_stale() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let snapshot = configure_retained_review_delivery(&config);
    let key = reserve_unadmitted_retained_review(&config, &snapshot, "review-write-stale-live");
    advance_retained_review_with_unrelated_comment(&config, &snapshot);

    let serving = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-review-write-stale-recovery",
            PlatformV2Request::GetReviewReceipt(
                ReviewReceiptLookup::new(
                    ProjectId::new("project-live").unwrap(),
                    snapshot.workspace().clone(),
                    key,
                )
                .unwrap(),
            ),
        ),
        PlatformV2Response::ReviewReceipt(receipt)
            if receipt.outcome() == ReviewReceiptOutcome::Refused
    ));
    serving.shutdown(&config);

    let scheduler = rusqlite::Connection::open(config.database_path()).unwrap();
    let deliveries: i64 = scheduler
        .query_row(
            "SELECT COUNT(*) FROM inbox WHERE transport='platform_v2.retained_review'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        deliveries, 0,
        "a stale write admission never reaches custody"
    );
}

#[test]
fn retained_review_recovery_refuses_before_custody_when_provider_revision_changed() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let snapshot = configure_retained_review_delivery(&config);
    let key = reserve_unadmitted_retained_review(&config, &snapshot, "review-provider-fence-live");
    automonique_daemon::managed_sessions::ManagedSessionStore::open(config.managed_sessions_path())
        .unwrap()
        .observe_terminal(
            "review-provider-session-live",
            "review-provider-run-live",
            23,
        )
        .unwrap();

    let serving = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-review-provider-fence-recovery",
            PlatformV2Request::GetReviewReceipt(
                ReviewReceiptLookup::new(
                    ProjectId::new("project-live").unwrap(),
                    snapshot.workspace().clone(),
                    key,
                )
                .unwrap(),
            ),
        ),
        PlatformV2Response::ReviewReceipt(receipt)
            if receipt.outcome() == ReviewReceiptOutcome::Refused
    ));
    serving.shutdown(&config);

    let scheduler = rusqlite::Connection::open(config.database_path()).unwrap();
    let deliveries: i64 = scheduler
        .query_row(
            "SELECT COUNT(*) FROM inbox WHERE transport='platform_v2.retained_review'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        deliveries, 0,
        "a stale provider fence never reaches custody"
    );
}

#[test]
fn retained_review_recovery_refuses_before_custody_when_registry_generation_changed() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let snapshot = configure_retained_review_delivery(&config);
    let key = reserve_unadmitted_retained_review(&config, &snapshot, "review-registry-fence-live");
    let registry_path = config.state_dir().join("platform-v2-review-registry.json");
    let mut registry: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&registry_path).unwrap()).unwrap();
    registry["generation"] = serde_json::json!("review-live-generation-2");
    std::fs::write(&registry_path, serde_json::to_vec(&registry).unwrap()).unwrap();

    let serving = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-review-registry-fence-recovery",
            PlatformV2Request::GetReviewReceipt(
                ReviewReceiptLookup::new(
                    ProjectId::new("project-live").unwrap(),
                    snapshot.workspace().clone(),
                    key,
                )
                .unwrap(),
            ),
        ),
        PlatformV2Response::ReviewReceipt(receipt)
            if receipt.outcome() == ReviewReceiptOutcome::Refused
    ));
    serving.shutdown(&config);

    let scheduler = rusqlite::Connection::open(config.database_path()).unwrap();
    let deliveries: i64 = scheduler
        .query_row(
            "SELECT COUNT(*) FROM inbox WHERE transport='platform_v2.retained_review'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        deliveries, 0,
        "a stale registry fence never reaches custody"
    );
}

#[test]
fn retained_review_recovery_refuses_wrong_coordinate_key_preemption() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let snapshot = configure_retained_review_delivery(&config);
    let key = reserve_unadmitted_retained_review(&config, &snapshot, "review-key-preempt-live");
    let custody = rusqlite::Connection::open(config.platform_v2_review_path()).unwrap();
    let transport_key: String = custody
        .query_row(
            "SELECT transport_key FROM review_external_effect_plans",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(custody);
    Store::open(config.database_path())
        .unwrap()
        .submit_inbox(InboxSubmission {
            transport: "platform_v2.retained_review",
            transport_key: &transport_key,
            scope: "wrong-provider-session",
            payload: br#"{"wrong":"coordinate"}"#,
            received_ms: 23,
        })
        .unwrap();

    let serving = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-review-key-preempt-recovery",
            PlatformV2Request::GetReviewReceipt(
                ReviewReceiptLookup::new(
                    ProjectId::new("project-live").unwrap(),
                    snapshot.workspace().clone(),
                    key,
                )
                .unwrap(),
            ),
        ),
        PlatformV2Response::ReviewReceipt(receipt)
            if receipt.outcome() == ReviewReceiptOutcome::Refused
    ));
    serving.shutdown(&config);

    let scheduler = rusqlite::Connection::open(config.database_path()).unwrap();
    let (deliveries, scope): (i64, String) = scheduler
        .query_row(
            "SELECT COUNT(*),MIN(scope) FROM inbox WHERE transport='platform_v2.retained_review' AND transport_key=?1",
            [&transport_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(deliveries, 1);
    assert_eq!(scope, "wrong-provider-session");
}

#[test]
fn production_workspace_effect_adopts_resumes_and_reopens_exact_local_binding() {
    let _guard = full_daemon_test_guard();
    let (root, config) = fixture();
    configure_v2(&config);
    let workspace_root = root.path().join("workspace-effect");
    std::fs::create_dir(&workspace_root).unwrap();
    std::fs::set_permissions(&workspace_root, std::fs::Permissions::from_mode(0o700)).unwrap();

    let external = ExternalWorkIdentity::new(
        ExternalWorkProvider::GitHub,
        ExternalWorkAuthorityId::new("authority-workspace-live").unwrap(),
        ExternalWorkScope::new("scope-workspace-live").unwrap(),
        ExternalWorkKey::new("work-workspace-live").unwrap(),
    );
    let freshness =
        LineageFreshness::new(1_800_000_000_100, 30_000, LineageFreshnessState::Fresh).unwrap();
    let workspace = UserWorkspaceId::new("workspace-live").unwrap();
    let mut lineage = LineageIndex::open(config.platform_v2_lineage_path()).unwrap();
    lineage
        .intake_external(
            "tenant-live",
            &ExternalWorkItem::new(
                external.clone(),
                workspace.clone(),
                Revision::FIRST,
                ExternalWorkState::Open,
                None,
                freshness,
                None,
            )
            .unwrap(),
        )
        .unwrap();
    lineage
        .record_orchestration(
            "tenant-live",
            &OrchestrationRecord::new(
                OrchestrationIdentity::Task(
                    OrchestrationTaskId::new("task-workspace-live").unwrap(),
                ),
                workspace.clone(),
                Some(external.clone()),
                Some(OrchestrationIdentity::Run(
                    OrchestrationRunId::new("run-live").unwrap(),
                )),
                LineageStatus::Working,
                freshness,
                None,
            )
            .unwrap(),
            None,
        )
        .unwrap();
    drop(lineage);

    let registry = serde_json::json!({
        "version": 1,
        "generation": "workspace-live-generation-one",
        "host_setups": [{
            "selector": "host-live-selector", "host_setup": "host-live",
            "project": "project-live", "setup_kind": "local",
            "canonical_root": workspace_root
        }],
        "checkouts": [{
            "selector": "checkout-live-selector", "checkout": "checkout-live",
            "project": "project-live", "host_setup": "host-live",
            "repository_authority": "github", "repository": "repo-live",
            "checkout_kind": "authorized_folder", "canonical_root": workspace_root,
            "repository_root": null, "base_commit": null, "branch_ref": null
        }],
        "workspaces": [{
            "workspace": "workspace-live", "project": "project-live",
            "checkout": "checkout-live", "canonical_root": workspace_root
        }],
        "task_selectors": [{
            "base_selector": "base-workspace-live",
            "branch_selector": "branch-workspace-live",
            "project": "project-live", "workspace": "workspace-live",
            "checkout": "checkout-live", "task": "task-workspace-live",
            "external_provider": "github",
            "external_authority": "authority-workspace-live",
            "external_scope": "scope-workspace-live",
            "external_key": "work-workspace-live"
        }]
    });
    let registry_path = config
        .state_dir()
        .join(automonique_daemon::platform_v2_lifecycle_adapter::LIFECYCLE_REGISTRY_FILE_NAME);
    std::fs::write(&registry_path, serde_json::to_vec(&registry).unwrap()).unwrap();
    std::fs::set_permissions(&registry_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let create = WorkspaceIntent::Create(WorkspaceCreateIntent::new(
        WorkspaceIntentId::new("intent-workspace-live-create").unwrap(),
        OrchestrationTaskId::new("task-workspace-live").unwrap(),
        external,
        BaseSelectorId::new("base-workspace-live").unwrap(),
        BranchSelectorId::new("branch-workspace-live").unwrap(),
    ));
    let serving = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-production-workspace-create",
            PlatformV2Request::SubmitWorkspaceIntent(WorkspaceIntentRequest::new(
                ProjectId::new("project-live").unwrap(),
                create.clone(),
            )),
        ),
        PlatformV2Response::WorkspaceIntentResult(WorkspaceIntentOutcome::Created(value))
            if value == workspace
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-production-workspace-create-replay",
            PlatformV2Request::SubmitWorkspaceIntent(WorkspaceIntentRequest::new(
                ProjectId::new("project-live").unwrap(),
                create.clone(),
            )),
        ),
        PlatformV2Response::WorkspaceIntentResult(WorkspaceIntentOutcome::Created(value))
            if value == workspace
    ));
    let resume = WorkspaceIntent::Resume(WorkspaceResumeIntent::new(
        WorkspaceIntentId::new("intent-workspace-live-resume").unwrap(),
        OrchestrationTaskId::new("task-workspace-live").unwrap(),
        workspace.clone(),
        Revision::FIRST,
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-production-workspace-resume",
            PlatformV2Request::SubmitWorkspaceIntent(WorkspaceIntentRequest::new(
                ProjectId::new("project-live").unwrap(),
                resume.clone(),
            )),
        ),
        PlatformV2Response::WorkspaceIntentResult(WorkspaceIntentOutcome::Resumed(value))
            if value == workspace
    ));

    // Simulate a crash after the adapter atomically completed its effects but
    // before either lineage receipt transaction committed.
    let lineage_connection = rusqlite::Connection::open(config.platform_v2_lineage_path()).unwrap();
    lineage_connection
        .execute_batch("PRAGMA foreign_keys=OFF;")
        .unwrap();
    lineage_connection
        .execute_batch(
            "CREATE TEMP TABLE saved_workspace_task AS
             SELECT * FROM lineage_orchestration
             WHERE tenant='tenant-live'
               AND orchestration_kind='task'
               AND orchestration_id='task-workspace-live';",
        )
        .unwrap();
    assert_eq!(
        lineage_connection
            .execute(
                "UPDATE lineage_workspace_intents
                 SET revision=1,outcome_kind='accepted',outcome_conflict=NULL,
                     outcome_workspace_id=NULL,reconciliation='poll_receipt'
                 WHERE tenant='tenant-live' AND intent_id IN (
                     'intent-workspace-live-create',
                     'intent-workspace-live-resume'
                 )",
                [],
            )
            .unwrap(),
        2
    );
    assert_eq!(
        lineage_connection
            .execute(
                "UPDATE lineage_orchestration
                 SET workspace_id='wc_user_1'
                 WHERE tenant='tenant-live'
                   AND orchestration_kind='task'
                   AND orchestration_id='task-workspace-live'",
                [],
            )
            .unwrap(),
        1
    );
    let mut work_contexts = WorkContextStore::open(config.platform_v2_work_context_path()).unwrap();
    let project = ProjectId::new("project-live").unwrap();
    let workspace_identity = WorkContextIdentity::UserWorkspace(workspace.clone());
    let active = work_contexts
        .validate_policy_mapping("tenant-live", &project, &workspace_identity)
        .unwrap();
    let archived = WorkContextRecord::new(
        workspace_identity,
        Revision::new(active.revision().get() + 1).unwrap(),
        WorkContextLifecycle::Archived,
        active.label().clone(),
        active.attributes(),
        active.relations().to_vec(),
    )
    .unwrap();
    work_contexts
        .put_authoritative_record("tenant-live", &archived)
        .unwrap();
    drop(work_contexts);
    let mut drifted_registry = registry.clone();
    drifted_registry["task_selectors"] = serde_json::json!([]);
    std::fs::write(
        &registry_path,
        serde_json::to_vec(&drifted_registry).unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(&workspace_root, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(matches!(
        platform_v2(
            &config,
            "v2-production-workspace-create-read-after-lineage-drift",
            PlatformV2Request::GetWorkspaceIntent(WorkspaceIntentLookup::new(
                ProjectId::new("project-live").unwrap(),
                create.intent_id().clone(),
            )),
        ),
        PlatformV2Response::WorkspaceIntentResult(WorkspaceIntentOutcome::Created(value))
            if value == workspace
    ));
    assert_eq!(
        lineage_connection
            .execute(
                "DELETE FROM lineage_orchestration
                 WHERE tenant='tenant-live'
                   AND orchestration_kind='task'
                   AND orchestration_id='task-workspace-live'",
                [],
            )
            .unwrap(),
        1
    );
    assert!(matches!(
        platform_v2(
            &config,
            "v2-production-workspace-resume-final-after-work-context-drift",
            PlatformV2Request::SubmitWorkspaceIntent(WorkspaceIntentRequest::new(
                ProjectId::new("project-live").unwrap(),
                resume.clone(),
            )),
        ),
        PlatformV2Response::WorkspaceIntentResult(WorkspaceIntentOutcome::Resumed(value))
            if value == workspace
    ));
    assert_eq!(
        lineage_connection
            .execute(
                "INSERT INTO lineage_orchestration
                 SELECT * FROM saved_workspace_task",
                [],
            )
            .unwrap(),
        1
    );
    drop(lineage_connection);
    std::fs::set_permissions(&workspace_root, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(&registry_path, serde_json::to_vec(&registry).unwrap()).unwrap();
    std::fs::set_permissions(&registry_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    serving.shutdown(&config);

    let serving = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-production-workspace-resume-after-restart",
            PlatformV2Request::GetWorkspaceIntent(WorkspaceIntentLookup::new(
                ProjectId::new("project-live").unwrap(),
                resume.intent_id().clone(),
            )),
        ),
        PlatformV2Response::WorkspaceIntentResult(WorkspaceIntentOutcome::Resumed(value))
            if value == workspace
    ));
    serving.shutdown(&config);

    let mut narrowed_policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(config.platform_v2_policy_path()).unwrap()).unwrap();
    narrowed_policy["principals"][0]["workspaces"]
        .as_array_mut()
        .unwrap()
        .retain(|entry| {
            !matches!(
                entry["id"].as_str(),
                Some("workspace-live" | "attempt-live" | "session-live" | "pane-live")
            )
        });
    std::fs::write(
        config.platform_v2_policy_path(),
        serde_json::to_vec(&narrowed_policy).unwrap(),
    )
    .unwrap();
    let serving = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-production-workspace-receipt-does-not-widen-authority",
            PlatformV2Request::SubmitWorkspaceIntent(WorkspaceIntentRequest::new(
                ProjectId::new("project-live").unwrap(),
                create,
            )),
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_scope_denied"
    ));
    serving.shutdown(&config);
}

struct CrashBeforeWorkspaceCustodyAdapter {
    cancellations: Arc<AtomicUsize>,
}

impl automonique_daemon::platform_v2_host::PlatformV2LifecycleEffectAdapter
    for CrashBeforeWorkspaceCustodyAdapter
{
    fn supported_effect_kinds(&self) -> BTreeSet<String> {
        BTreeSet::new()
    }

    fn workspace_intents_supported(&self) -> bool {
        true
    }

    fn workspace_intent_custody_installed(&self) -> bool {
        true
    }

    fn preflight_workspace_intent(
        &self,
        _intent: &WorkspaceIntent,
        _project: &ProjectId,
        _workspace: &UserWorkspaceId,
        _checkout: &CheckoutId,
        _workspace_revision: Revision,
        _policy_generation: automonique_protocol::digest::Sha256Digest,
    ) -> Result<(), &'static str> {
        Ok(())
    }

    fn execute_workspace_intent(
        &mut self,
        _intent: &WorkspaceIntent,
        _project: &ProjectId,
        _workspace: &UserWorkspaceId,
        _checkout: &CheckoutId,
        _workspace_revision: Revision,
        _policy_generation: automonique_protocol::digest::Sha256Digest,
    ) -> Result<WorkspaceIntentOutcome, &'static str> {
        Err("platform_v2_test_crash_before_workspace_prepare")
    }

    fn cancel_workspace_intent(
        &mut self,
        _target: &WorkspaceIntent,
        _project: &ProjectId,
        _workspace: &UserWorkspaceId,
        _policy_generation: automonique_protocol::digest::Sha256Digest,
    ) -> Result<(), &'static str> {
        self.cancellations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn execute(
        &mut self,
        _intent: &WorkContextMutationIntent,
        _resulting_identity: &WorkContextIdentity,
        _idempotency_key: &IdempotencyKey,
    ) -> automonique_daemon::platform_v2_host::PlatformV2EffectExecution {
        automonique_daemon::platform_v2_host::PlatformV2EffectExecution::NotStarted
    }

    fn reconcile(
        &mut self,
        _intent: &WorkContextMutationIntent,
        _resulting_identity: &WorkContextIdentity,
        _idempotency_key: &IdempotencyKey,
    ) -> automonique_daemon::platform_v2_host::PlatformV2EffectReconciliation {
        automonique_daemon::platform_v2_host::PlatformV2EffectReconciliation::VerifiedNotStarted(
            b"test adapter owns no work-context effect custody".to_vec(),
        )
    }
}

#[test]
fn accepted_workspace_intent_without_effect_custody_remains_cancellable() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let external = ExternalWorkIdentity::new(
        ExternalWorkProvider::GitHub,
        ExternalWorkAuthorityId::new("authority-no-custody").unwrap(),
        ExternalWorkScope::new("scope-no-custody").unwrap(),
        ExternalWorkKey::new("work-no-custody").unwrap(),
    );
    let freshness =
        LineageFreshness::new(1_800_000_000_000, 30_000, LineageFreshnessState::Fresh).unwrap();
    let workspace = UserWorkspaceId::new("workspace-live").unwrap();
    let mut lineage = LineageIndex::open(config.platform_v2_lineage_path()).unwrap();
    lineage
        .intake_external(
            "tenant-live",
            &ExternalWorkItem::new(
                external.clone(),
                workspace.clone(),
                Revision::FIRST,
                ExternalWorkState::Open,
                None,
                freshness,
                None,
            )
            .unwrap(),
        )
        .unwrap();
    lineage
        .record_orchestration(
            "tenant-live",
            &OrchestrationRecord::new(
                OrchestrationIdentity::Task(OrchestrationTaskId::new("task-no-custody").unwrap()),
                workspace.clone(),
                Some(external.clone()),
                Some(OrchestrationIdentity::Run(
                    OrchestrationRunId::new("run-live").unwrap(),
                )),
                LineageStatus::Working,
                freshness,
                None,
            )
            .unwrap(),
            None,
        )
        .unwrap();
    drop(lineage);
    let cancellations = Arc::new(AtomicUsize::new(0));
    let uid = nix::unistd::geteuid().as_raw();
    let mut host =
        automonique_daemon::platform_v2_host::PlatformV2Host::open_with_lifecycle_adapter(
            &config.platform_v2_policy_path(),
            &config.platform_v2_work_context_path(),
            &config.platform_v2_lineage_path(),
            &config.platform_v2_review_path(),
            uid,
            Box::new(CrashBeforeWorkspaceCustodyAdapter {
                cancellations: Arc::clone(&cancellations),
            }),
        );
    let create = WorkspaceIntent::Create(WorkspaceCreateIntent::new(
        WorkspaceIntentId::new("intent-accepted-no-custody").unwrap(),
        OrchestrationTaskId::new("task-no-custody").unwrap(),
        external,
        BaseSelectorId::new("base-no-custody").unwrap(),
        BranchSelectorId::new("branch-no-custody").unwrap(),
    ));
    let response = host.handle(
        uid,
        &PlatformV2Request::SubmitWorkspaceIntent(WorkspaceIntentRequest::new(
            ProjectId::new("project-live").unwrap(),
            create.clone(),
        )),
        1_800_000_000_000,
    );
    assert!(
        matches!(
            &response,
            PlatformV2Response::Refused(refusal)
                if refusal.category().as_str() == "platform_v2_test_crash_before_workspace_prepare"
        ),
        "{response:?}"
    );
    assert!(matches!(
        host.handle(
            uid,
            &PlatformV2Request::GetWorkspaceIntent(WorkspaceIntentLookup::new(
                ProjectId::new("project-live").unwrap(),
                create.intent_id().clone(),
            )),
            1_800_000_000_001,
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_test_crash_before_workspace_prepare"
    ));
    let cancel = WorkspaceIntent::Cancel(
        WorkspaceCancelIntent::new(
            WorkspaceIntentId::new("intent-cancel-no-custody").unwrap(),
            create.intent_id().clone(),
            workspace,
            Revision::FIRST,
        )
        .unwrap(),
    );
    assert!(matches!(
        host.handle(
            uid,
            &PlatformV2Request::SubmitWorkspaceIntent(WorkspaceIntentRequest::new(
                ProjectId::new("project-live").unwrap(),
                cancel,
            )),
            1_800_000_000_002,
        ),
        PlatformV2Response::WorkspaceIntentResult(WorkspaceIntentOutcome::Cancelled(value))
            if value == *create.intent_id()
    ));
    assert_eq!(cancellations.load(Ordering::SeqCst), 1);
}

struct RecoveringLifecycleAdapter {
    executions: Arc<AtomicUsize>,
    reconciliations: Arc<AtomicUsize>,
    scenario: LifecycleRecoveryScenario,
}

#[derive(Clone, Copy)]
enum LifecycleRecoveryScenario {
    CrashBefore,
    CrashAfter,
    ExpiredLease,
    GenerationChanged,
}

impl automonique_daemon::platform_v2_host::PlatformV2LifecycleEffectAdapter
    for RecoveringLifecycleAdapter
{
    fn supported_effect_kinds(&self) -> BTreeSet<String> {
        BTreeSet::from(["create_attempt_workspace".to_owned()])
    }

    fn execute(
        &mut self,
        _intent: &WorkContextMutationIntent,
        _resulting_identity: &WorkContextIdentity,
        _idempotency_key: &IdempotencyKey,
    ) -> automonique_daemon::platform_v2_host::PlatformV2EffectExecution {
        let execution = self.executions.fetch_add(1, Ordering::SeqCst);
        match (self.scenario, execution) {
            (LifecycleRecoveryScenario::CrashBefore, 0) => {
                automonique_daemon::platform_v2_host::PlatformV2EffectExecution::NotStarted
            }
            (LifecycleRecoveryScenario::CrashBefore, _) => {
                automonique_daemon::platform_v2_host::PlatformV2EffectExecution::Completed
            }
            (LifecycleRecoveryScenario::CrashAfter, _) => {
                automonique_daemon::platform_v2_host::PlatformV2EffectExecution::Unknown
            }
            (LifecycleRecoveryScenario::ExpiredLease, _) => {
                automonique_daemon::platform_v2_host::PlatformV2EffectExecution::Completed
            }
            (LifecycleRecoveryScenario::GenerationChanged, _) => {
                automonique_daemon::platform_v2_host::PlatformV2EffectExecution::Completed
            }
        }
    }

    fn reconcile(
        &mut self,
        _intent: &WorkContextMutationIntent,
        _resulting_identity: &WorkContextIdentity,
        _idempotency_key: &IdempotencyKey,
    ) -> automonique_daemon::platform_v2_host::PlatformV2EffectReconciliation {
        self.reconciliations.fetch_add(1, Ordering::SeqCst);
        match self.scenario {
            LifecycleRecoveryScenario::CrashBefore => automonique_daemon::platform_v2_host::PlatformV2EffectReconciliation::VerifiedNotStarted(
                b"typed provider verified the original effect did not start".to_vec(),
            ),
            LifecycleRecoveryScenario::CrashAfter => automonique_daemon::platform_v2_host::PlatformV2EffectReconciliation::Completed(
                b"typed provider proved the original effect completed".to_vec(),
            ),
            LifecycleRecoveryScenario::ExpiredLease => automonique_daemon::platform_v2_host::PlatformV2EffectReconciliation::Completed(
                b"typed provider proved the over-lease effect completed".to_vec(),
            ),
            LifecycleRecoveryScenario::GenerationChanged => automonique_daemon::platform_v2_host::PlatformV2EffectReconciliation::Completed(
                b"stale adapter generation must not complete custody".to_vec(),
            ),
        }
    }

    fn verify_generation(&self) -> Result<(), &'static str> {
        if matches!(self.scenario, LifecycleRecoveryScenario::GenerationChanged) {
            Err("platform_v2_lifecycle_registry_changed")
        } else {
            Ok(())
        }
    }
}

struct FixedPlatformV2Clock(i64);

impl automonique_daemon::platform_v2_host::PlatformV2Clock for FixedPlatformV2Clock {
    fn now_ms(&mut self) -> Result<i64, &'static str> {
        Ok(self.0)
    }
}

#[test]
fn lifecycle_effect_claim_recovers_crash_boundaries_without_blind_replay() {
    run_lifecycle_recovery_scenario(LifecycleRecoveryScenario::CrashBefore);
    run_lifecycle_recovery_scenario(LifecycleRecoveryScenario::CrashAfter);
    run_lifecycle_recovery_scenario(LifecycleRecoveryScenario::ExpiredLease);
    run_lifecycle_recovery_scenario(LifecycleRecoveryScenario::GenerationChanged);
}

fn run_lifecycle_recovery_scenario(scenario: LifecycleRecoveryScenario) {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let executions = Arc::new(AtomicUsize::new(0));
    let reconciliations = Arc::new(AtomicUsize::new(0));
    let adapter = RecoveringLifecycleAdapter {
        executions: Arc::clone(&executions),
        reconciliations: Arc::clone(&reconciliations),
        scenario,
    };
    let uid = nix::unistd::geteuid().as_raw();
    let issued_at = 1_800_000_000_000_i64;
    let adapter: Box<dyn automonique_daemon::platform_v2_host::PlatformV2LifecycleEffectAdapter> =
        Box::new(adapter);
    let mut host = if matches!(scenario, LifecycleRecoveryScenario::ExpiredLease) {
        automonique_daemon::platform_v2_host::PlatformV2Host::open_with_lifecycle_adapter_and_clock(
            &config.platform_v2_policy_path(),
            &config.platform_v2_work_context_path(),
            &config.platform_v2_lineage_path(),
            &config.platform_v2_review_path(),
            uid,
            adapter,
            Box::new(FixedPlatformV2Clock(issued_at + 30_004)),
        )
    } else {
        automonique_daemon::platform_v2_host::PlatformV2Host::open_with_lifecycle_adapter(
            &config.platform_v2_policy_path(),
            &config.platform_v2_work_context_path(),
            &config.platform_v2_lineage_path(),
            &config.platform_v2_review_path(),
            uid,
            adapter,
        )
    };
    let key = IdempotencyKey::new(match scenario {
        LifecycleRecoveryScenario::CrashBefore => "attempt-recover-not-started",
        LifecycleRecoveryScenario::CrashAfter => "attempt-recover-completed",
        LifecycleRecoveryScenario::ExpiredLease => "attempt-recover-expired-lease",
        LifecycleRecoveryScenario::GenerationChanged => "attempt-generation-changed",
    })
    .unwrap();
    let prepare = MutationPrepareRequest::new(
        key.clone(),
        WorkContextMutationIntent::CreateAttemptWorkspace(
            CreateAttemptWorkspaceIntent::new(
                WorkContextLabel::new("Recoverable attempt").unwrap(),
                ExpectedWorkContext::new(
                    WorkContextIdentity::UserWorkspace(
                        UserWorkspaceId::new("workspace-live").unwrap(),
                    ),
                    Revision::FIRST,
                ),
                WorkContextAuthority::EMPTY,
            )
            .unwrap(),
        ),
    );
    let PlatformV2Response::MutationPreview(preview) =
        host.handle(uid, &PlatformV2Request::PrepareMutation(prepare), issued_at)
    else {
        panic!("attempt preview")
    };
    let PlatformV2Response::MutationApproval(raw_approval) = host.handle(
        uid,
        &PlatformV2Request::DecideMutation(MutationDecisionRequest::new(
            preview.preview().clone(),
            work_context_mutation_preview_digest(&preview).unwrap(),
            MutationApprovalDecision::Granted,
        )),
        issued_at + 1,
    ) else {
        panic!("attempt approval")
    };
    let approval = raw_approval.decode(&preview).unwrap();
    let submitted_at = issued_at + 2;
    let submission_document = encode_work_context_mutation_submission(
        &preview,
        Some(&approval),
        EpochMillis::from_millis(submitted_at),
    )
    .unwrap();
    let submission =
        decode_work_context_mutation_submission(&submission_document, &preview).unwrap();
    let submit = MutationSubmitRequest::new(
        preview.preview().clone(),
        work_context_mutation_preview_digest(&preview).unwrap(),
        Some(approval.id().clone()),
    );
    let PlatformV2Response::MutationReceipt(accepted) = host.handle(
        uid,
        &PlatformV2Request::SubmitMutation(submit),
        submitted_at,
    ) else {
        panic!("attempt accepted")
    };
    assert_eq!(
        accepted.decode(&submission, &preview).unwrap().outcome(),
        ReceiptOutcome::Accepted
    );

    let lookup = PlatformV2Request::GetMutationReceipt(MutationReceiptLookup::new(
        ProjectId::new("project-live").unwrap(),
        ReceiptLookupKey::IdempotencyKey(key),
    ));
    let first_claim_at = submitted_at + 1;
    let first_lookup = host.handle(uid, &lookup, first_claim_at);
    if matches!(scenario, LifecycleRecoveryScenario::GenerationChanged) {
        assert!(matches!(
            first_lookup,
            PlatformV2Response::Refused(refusal)
                if refusal.category().as_str() == "platform_v2_lifecycle_registry_changed"
        ));
        assert_eq!(executions.load(Ordering::SeqCst), 1);
        assert_eq!(reconciliations.load(Ordering::SeqCst), 0);
        assert!(matches!(
            host.handle(uid, &lookup, first_claim_at + 30_000),
            PlatformV2Response::Refused(refusal)
                if refusal.category().as_str() == "platform_v2_lifecycle_registry_changed"
        ));
        assert_eq!(executions.load(Ordering::SeqCst), 1);
        assert_eq!(reconciliations.load(Ordering::SeqCst), 1);
        return;
    }
    let PlatformV2Response::MutationReceipt(still_accepted) = first_lookup else {
        panic!("claimed receipt")
    };
    assert_eq!(
        still_accepted
            .decode(&submission, &preview)
            .unwrap()
            .outcome(),
        ReceiptOutcome::Accepted
    );
    assert_eq!(executions.load(Ordering::SeqCst), 1);
    assert_eq!(reconciliations.load(Ordering::SeqCst), 0);

    let PlatformV2Response::MutationReceipt(completed) =
        host.handle(uid, &lookup, first_claim_at + 30_000)
    else {
        panic!("reconciled receipt")
    };
    assert_eq!(
        completed.decode(&submission, &preview).unwrap().outcome(),
        ReceiptOutcome::Completed
    );
    assert_eq!(
        executions.load(Ordering::SeqCst),
        match scenario {
            LifecycleRecoveryScenario::CrashBefore => 2,
            LifecycleRecoveryScenario::CrashAfter | LifecycleRecoveryScenario::ExpiredLease => 1,
            LifecycleRecoveryScenario::GenerationChanged => unreachable!(),
        }
    );
    assert_eq!(reconciliations.load(Ordering::SeqCst), 1);
}

#[test]
fn production_default_adapter_refuses_before_external_effect_custody() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let uid = nix::unistd::geteuid().as_raw();
    let mut host = automonique_daemon::platform_v2_host::PlatformV2Host::open(
        &config.platform_v2_policy_path(),
        &config.platform_v2_work_context_path(),
        &config.platform_v2_lineage_path(),
        &config.platform_v2_review_path(),
        uid,
    );
    let issued_at = 1_800_000_000_000_i64;
    let prepare = MutationPrepareRequest::new(
        IdempotencyKey::new("attempt-no-production-adapter").unwrap(),
        WorkContextMutationIntent::CreateAttemptWorkspace(
            CreateAttemptWorkspaceIntent::new(
                WorkContextLabel::new("Unavailable attempt").unwrap(),
                ExpectedWorkContext::new(
                    WorkContextIdentity::UserWorkspace(
                        UserWorkspaceId::new("workspace-live").unwrap(),
                    ),
                    Revision::FIRST,
                ),
                WorkContextAuthority::EMPTY,
            )
            .unwrap(),
        ),
    );
    let PlatformV2Response::MutationPreview(preview) =
        host.handle(uid, &PlatformV2Request::PrepareMutation(prepare), issued_at)
    else {
        panic!("preview")
    };
    let PlatformV2Response::MutationApproval(raw_approval) = host.handle(
        uid,
        &PlatformV2Request::DecideMutation(MutationDecisionRequest::new(
            preview.preview().clone(),
            work_context_mutation_preview_digest(&preview).unwrap(),
            MutationApprovalDecision::Granted,
        )),
        issued_at + 1,
    ) else {
        panic!("approval")
    };
    let approval = raw_approval.decode(&preview).unwrap();
    assert!(matches!(
        host.handle(
            uid,
            &PlatformV2Request::SubmitMutation(MutationSubmitRequest::new(
                preview.preview().clone(),
                work_context_mutation_preview_digest(&preview).unwrap(),
                Some(approval.id().clone()),
            )),
            issued_at + 2,
        ),
        PlatformV2Response::MutationRefused(refusal)
            if refusal.category()
                == automonique_protocol::platform_v2_lifecycle::MutationRefusalCategory::Unavailable
    ));
    let connection = rusqlite::Connection::open(config.platform_v2_work_context_path()).unwrap();
    let receipts: i64 = connection
        .query_row("SELECT count(*) FROM work_context_receipts", [], |row| {
            row.get(0)
        })
        .unwrap();
    let outbox: i64 = connection
        .query_row("SELECT count(*) FROM work_context_outbox", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!((receipts, outbox), (0, 0));
}

#[test]
fn changed_policy_refuses_negotiation_and_requests_until_restart() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    set_tool_authority(&config, false);
    let serving = serve(&config);

    set_tool_authority(&config, true);
    let negotiation = PlatformNegotiationRequestMessage::new(
        RequestId::new("negotiate-stale-policy").unwrap(),
        PlatformNegotiationRequest::Negotiate(PlatformVersionOffer::new(vec![2]).unwrap()),
    );
    let response = PlatformNegotiationResponseMessage::from_canonical_bytes(
        &exchange(&config, &negotiation.to_canonical_bytes().unwrap()),
        &negotiation,
    )
    .unwrap();
    assert!(matches!(
        response.response(),
        PlatformNegotiationResponse::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_policy_changed"
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-stale-policy-refusal",
            PlatformV2Request::GetWorkContext(WorkContextIdentity::Project(
                ProjectId::new("project-live").unwrap()
            ))
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_policy_changed"
    ));
    serving.shutdown(&config);

    let restarted = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-narrowed-policy-after-restart",
            PlatformV2Request::GetWorkContext(WorkContextIdentity::Project(
                ProjectId::new("project-live").unwrap()
            ))
        ),
        PlatformV2Response::WorkContextRecord(_)
    ));
    restarted.shutdown(&config);
}

#[test]
fn resume_requires_live_durable_workspace_before_intent_custody() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let mut store = WorkContextStore::open(config.platform_v2_work_context_path()).unwrap();
    store
        .put_authoritative_record(
            "tenant-live",
            &live_workspace(
                "workspace-live",
                Revision::new(2).unwrap(),
                WorkContextLifecycle::Archived,
            ),
        )
        .unwrap();
    drop(store);
    let serving = serve(&config);
    let intent = WorkspaceIntent::Resume(WorkspaceResumeIntent::new(
        WorkspaceIntentId::new("intent-archived").unwrap(),
        OrchestrationTaskId::new("task-live").unwrap(),
        UserWorkspaceId::new("workspace-live").unwrap(),
        Revision::new(2).unwrap(),
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-resume-archived",
            PlatformV2Request::SubmitWorkspaceIntent(WorkspaceIntentRequest::new(
                ProjectId::new("project-live").unwrap(),
                intent.clone(),
            ))
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_resume_not_resumable"
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-archived-resume-not-stored",
            PlatformV2Request::GetWorkspaceIntent(WorkspaceIntentLookup::new(
                ProjectId::new("project-live").unwrap(),
                intent.intent_id().clone(),
            ))
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_not_found"
    ));
    let create = WorkspaceIntent::Create(WorkspaceCreateIntent::new(
        WorkspaceIntentId::new("intent-create-archived").unwrap(),
        OrchestrationTaskId::new("task-live").unwrap(),
        ExternalWorkIdentity::new(
            ExternalWorkProvider::GitHub,
            ExternalWorkAuthorityId::new("authority-archived").unwrap(),
            ExternalWorkScope::new("scope-archived").unwrap(),
            ExternalWorkKey::new("work-archived").unwrap(),
        ),
        BaseSelectorId::new("base-archived").unwrap(),
        BranchSelectorId::new("branch-archived").unwrap(),
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-create-archived",
            PlatformV2Request::SubmitWorkspaceIntent(WorkspaceIntentRequest::new(
                ProjectId::new("project-live").unwrap(),
                create.clone(),
            ))
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_workspace_not_active"
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-archived-create-not-stored",
            PlatformV2Request::GetWorkspaceIntent(WorkspaceIntentLookup::new(
                ProjectId::new("project-live").unwrap(),
                create.intent_id().clone(),
            ))
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_not_found"
    ));
    serving.shutdown(&config);
}

#[test]
fn durable_mapping_drift_disables_v2_actions_fail_closed() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let serving = serve(&config);
    let connection = rusqlite::Connection::open(config.platform_v2_work_context_path()).unwrap();
    connection
        .execute(
            "DELETE FROM work_context_records WHERE tenant='tenant-live' AND identity_id='workspace-live'",
            [],
        )
        .unwrap();
    drop(connection);
    let intent = WorkspaceIntent::Resume(WorkspaceResumeIntent::new(
        WorkspaceIntentId::new("intent-deleted-workspace").unwrap(),
        OrchestrationTaskId::new("task-live").unwrap(),
        UserWorkspaceId::new("workspace-live").unwrap(),
        Revision::FIRST,
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-resume-deleted-workspace",
            PlatformV2Request::SubmitWorkspaceIntent(WorkspaceIntentRequest::new(
                ProjectId::new("project-live").unwrap(),
                intent,
            ))
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_policy_incoherent"
    ));
    serving.shutdown(&config);
    let serving = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-startup-incoherent-mapping",
            PlatformV2Request::GetWorkContext(WorkContextIdentity::Project(
                ProjectId::new("project-live").unwrap(),
            ))
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_policy_incoherent"
    ));
    serving.shutdown(&config);
}

#[test]
fn policy_requires_the_complete_durable_inheritance_chain() {
    let _guard = full_daemon_test_guard();
    for (kind, id, label) in [
        ("host_setup", "host-live", "v2-missing-host-parent"),
        ("checkout", "checkout-live", "v2-missing-checkout-parent"),
        (
            "user_workspace",
            "workspace-live",
            "v2-missing-attempt-parent",
        ),
        (
            "attempt_workspace",
            "attempt-live",
            "v2-missing-session-parent",
        ),
        ("session", "session-live", "v2-missing-pane-parent"),
    ] {
        let (_root, config) = fixture();
        configure_v2(&config);
        remove_policy_scope(&config, kind, id);
        let serving = serve(&config);
        assert!(matches!(
            platform_v2(
                &config,
                label,
                PlatformV2Request::GetWorkContext(WorkContextIdentity::UserWorkspace(
                    UserWorkspaceId::new("workspace-live").unwrap(),
                ))
            ),
            PlatformV2Response::Refused(refusal)
                if refusal.category().as_str() == "platform_v2_policy_incoherent"
        ));
        serving.shutdown(&config);
    }
}

#[test]
fn complete_durable_inheritance_chain_enables_v2_reads() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let serving = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-complete-policy-chain",
            PlatformV2Request::GetWorkContext(WorkContextIdentity::Pane(
                PaneId::new("pane-live").unwrap(),
            ))
        ),
        PlatformV2Response::WorkContextRecord(record)
            if record.identity().id() == "pane-live"
    ));
    serving.shutdown(&config);
}

#[test]
fn session_and_pane_ceilings_cannot_exceed_their_direct_parents() {
    let _guard = full_daemon_test_guard();
    for (parent_kind, parent_id, label) in [
        (
            "attempt_workspace",
            "attempt-live",
            "v2-session-exceeds-attempt-ceiling",
        ),
        ("session", "session-live", "v2-pane-exceeds-session-ceiling"),
    ] {
        let (_root, config) = fixture();
        configure_v2(&config);
        set_tool_authority(&config, false);
        set_scope_tools(&config, parent_kind, parent_id, &[]);
        let serving = serve(&config);
        assert!(matches!(
            platform_v2(
                &config,
                label,
                PlatformV2Request::GetWorkContext(WorkContextIdentity::Pane(
                    PaneId::new("pane-live").unwrap(),
                ))
            ),
            PlatformV2Response::Refused(refusal)
                if refusal.category().as_str() == "platform_v2_policy_incoherent"
        ));
        serving.shutdown(&config);
    }
}

#[test]
fn checkout_creation_refuses_until_a_typed_private_selector_registry_exists() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let serving = serve(&config);
    let create_checkout = |checkout_kind, key: &str| {
        MutationPrepareRequest::new(
            IdempotencyKey::new(key).unwrap(),
            WorkContextMutationIntent::CreateCheckout(
                CreateCheckoutIntent::new(
                    WorkContextLabel::new("New live checkout").unwrap(),
                    ExpectedWorkContext::new(
                        WorkContextIdentity::Project(ProjectId::new("project-live").unwrap()),
                        Revision::FIRST,
                    ),
                    ExpectedWorkContext::new(
                        WorkContextIdentity::parse_local(
                            WorkContextTargetKind::HostSetup,
                            "host-live",
                        )
                        .unwrap(),
                        Revision::FIRST,
                    ),
                    ExpectedWorkContext::new(live_repository("repo-live"), Revision::FIRST),
                    checkout_kind,
                    WorkContextRegistrySelector::new("checkout-live-selector").unwrap(),
                )
                .unwrap(),
            ),
        )
    };
    for (kind, key) in [
        (CheckoutKind::GitWorktree, "checkout-git-unavailable"),
        (
            CheckoutKind::AuthorizedFolder,
            "checkout-folder-unavailable",
        ),
    ] {
        assert!(matches!(
            platform_v2(
                &config,
                key,
                PlatformV2Request::PrepareMutation(create_checkout(kind, key)),
            ),
            PlatformV2Response::Refused(refusal)
                if refusal.category().as_str() == "platform_v2_selector_registry_unavailable"
        ));
    }
    serving.shutdown(&config);
}

#[test]
fn restart_narrowing_revokes_old_preview_decision_and_receipt_reads() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    set_tool_authority(&config, false);
    let serving = serve(&config);
    let grant = AuthorityGrantId::new("tool-live").unwrap();
    let authority =
        WorkContextAuthority::new(vec![], vec![], vec![], vec![grant], vec![], vec![]).unwrap();
    let key = IdempotencyKey::new("attempt-before-narrowing").unwrap();
    let prepare = MutationPrepareRequest::new(
        key.clone(),
        WorkContextMutationIntent::CreateAttemptWorkspace(
            CreateAttemptWorkspaceIntent::new(
                WorkContextLabel::new("Attempt before narrowing").unwrap(),
                ExpectedWorkContext::new(
                    WorkContextIdentity::UserWorkspace(
                        UserWorkspaceId::new("workspace-live").unwrap(),
                    ),
                    Revision::FIRST,
                ),
                authority.clone(),
            )
            .unwrap(),
        ),
    );
    let PlatformV2Response::MutationPreview(preview) = platform_v2(
        &config,
        "v2-preview-before-narrowing",
        PlatformV2Request::PrepareMutation(prepare),
    ) else {
        panic!("preview before narrowing")
    };
    let decision = MutationDecisionRequest::new(
        preview.preview().clone(),
        work_context_mutation_preview_digest(&preview).unwrap(),
        MutationApprovalDecision::Granted,
    );
    let PlatformV2Response::MutationApproval(raw_approval) = platform_v2(
        &config,
        "v2-approval-before-narrowing",
        PlatformV2Request::DecideMutation(decision.clone()),
    ) else {
        panic!("approval before narrowing")
    };
    serving.shutdown(&config);

    // Seed the kind of accepted pre-adapter receipt an upgraded deployment
    // may already contain. The daemon itself never admits this effect today.
    let approval = raw_approval.decode(&preview).unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let submission = encode_work_context_mutation_submission(
        &preview,
        Some(&approval),
        EpochMillis::from_millis(now_ms),
    )
    .unwrap();
    let targets = BTreeSet::from([WorkContextIdentity::UserWorkspace(
        UserWorkspaceId::new("workspace-live").unwrap(),
    )]);
    let policy = MutationPolicyDecision::new(
        preview.proposal().actor().clone(),
        preview.proposal().authority(),
        authority.clone(),
        authority,
        Some(ProjectId::new("project-live").unwrap()),
        targets,
        preview.proposal().request_digest(),
        MutationApprovalRequirement::Required,
    );
    let receipt_id = ReceiptId::new("receipt-before-narrowing").unwrap();
    let mut store = WorkContextStore::open(config.platform_v2_work_context_path()).unwrap();
    store
        .submit_mutation(
            preview.preview(),
            &submission,
            &policy,
            receipt_id.clone(),
            now_ms.saturating_add(1),
        )
        .unwrap();
    drop(store);

    let prior_executions = Arc::new(AtomicUsize::new(0));
    let prior_reconciliations = Arc::new(AtomicUsize::new(0));
    let uid = nix::unistd::geteuid().as_raw();
    let mut prior_host =
        automonique_daemon::platform_v2_host::PlatformV2Host::open_with_lifecycle_adapter(
            &config.platform_v2_policy_path(),
            &config.platform_v2_work_context_path(),
            &config.platform_v2_lineage_path(),
            &config.platform_v2_review_path(),
            uid,
            Box::new(RecoveringLifecycleAdapter {
                executions: Arc::clone(&prior_executions),
                reconciliations: Arc::clone(&prior_reconciliations),
                scenario: LifecycleRecoveryScenario::CrashAfter,
            }),
        );
    assert!(matches!(
        prior_host.handle(
            uid,
            &PlatformV2Request::GetWorkContext(WorkContextIdentity::Project(
                ProjectId::new("project-live").unwrap(),
            )),
            now_ms.saturating_add(2),
        ),
        PlatformV2Response::WorkContextRecord(_)
    ));
    assert_eq!(prior_executions.load(Ordering::SeqCst), 1);
    assert_eq!(prior_reconciliations.load(Ordering::SeqCst), 0);
    drop(prior_host);

    let serving = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-old-preview-same-policy-after-restart",
            PlatformV2Request::DecideMutation(decision.clone()),
        ),
        PlatformV2Response::MutationApproval(value) if value == raw_approval
    ));
    assert!(matches!(
        platform_v2(
            &config,
            "v2-old-receipt-same-policy-after-restart",
            PlatformV2Request::GetMutationReceipt(MutationReceiptLookup::new(
                ProjectId::new("project-live").unwrap(),
                ReceiptLookupKey::ReceiptId(receipt_id.clone()),
            )),
        ),
        PlatformV2Response::MutationReceipt(_)
    ));
    serving.shutdown(&config);

    set_tool_authority(&config, true);
    let serving = serve(&config);
    assert!(matches!(
        platform_v2(
            &config,
            "v2-old-preview-after-narrowing",
            PlatformV2Request::DecideMutation(decision),
        ),
        PlatformV2Response::Refused(refusal)
            if refusal.category().as_str() == "platform_v2_decision_refused"
    ));
    for (label, lookup) in [
        (
            "v2-old-receipt-id-after-narrowing",
            ReceiptLookupKey::ReceiptId(receipt_id),
        ),
        (
            "v2-old-receipt-key-after-narrowing",
            ReceiptLookupKey::IdempotencyKey(key),
        ),
    ] {
        assert!(matches!(
            platform_v2(
                &config,
                label,
                PlatformV2Request::GetMutationReceipt(MutationReceiptLookup::new(
                    ProjectId::new("project-live").unwrap(),
                    lookup,
                )),
            ),
            PlatformV2Response::Refused(refusal)
                if refusal.category().as_str() == "platform_v2_not_found"
        ));
    }
    serving.shutdown(&config);

    let executions = Arc::new(AtomicUsize::new(0));
    let reconciliations = Arc::new(AtomicUsize::new(0));
    let adapter = RecoveringLifecycleAdapter {
        executions: Arc::clone(&executions),
        reconciliations: Arc::clone(&reconciliations),
        scenario: LifecycleRecoveryScenario::CrashAfter,
    };
    let mut host =
        automonique_daemon::platform_v2_host::PlatformV2Host::open_with_lifecycle_adapter(
            &config.platform_v2_policy_path(),
            &config.platform_v2_work_context_path(),
            &config.platform_v2_lineage_path(),
            &config.platform_v2_review_path(),
            uid,
            Box::new(adapter),
        );
    assert!(matches!(
        host.handle(
            uid,
            &PlatformV2Request::GetWorkContext(WorkContextIdentity::Project(
                ProjectId::new("project-live").unwrap(),
            )),
            now_ms.saturating_add(30_003),
        ),
        PlatformV2Response::WorkContextRecord(_)
    ));
    assert_eq!(executions.load(Ordering::SeqCst), 0);
    assert_eq!(reconciliations.load(Ordering::SeqCst), 0);
    let connection = rusqlite::Connection::open(config.platform_v2_work_context_path()).unwrap();
    let outbox_state: String = connection
        .query_row(
            "SELECT state FROM work_context_outbox WHERE preview_id=?1",
            [preview.preview().id().as_str()],
            |row| row.get(0),
        )
        .unwrap();
    let leases: i64 = connection
        .query_row(
            "SELECT count(*) FROM work_context_effect_leases",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let recovery_audits: i64 = connection
        .query_row(
            "SELECT count(*) FROM work_context_effect_recovery_audit",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(outbox_state, "ambiguous");
    assert_eq!(leases, 1);
    assert_eq!(recovery_audits, 0);
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
    let _guard = full_daemon_test_guard();
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
    let _guard = full_daemon_test_guard();
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
    let _guard = full_daemon_test_guard();
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
    let _guard = full_daemon_test_guard();
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

/// A listing offers attach and control only where something was observed live,
/// and withholds both from a binding whose run the index has already seen end.
///
/// This is the production shape of #-orphaned TUI sessions: a generation died
/// mid-turn, so the binding is still `in_flight` and still `open`, while the run
/// it names reached `completed` days ago. Nothing ever falsifies the binding's
/// `open`, so projecting it as `fresh`/`attachable` advertised dozens of dead
/// sessions as live. Resumability survives — `summary` still reads `open`, which
/// is exactly what the follow-up guard requires — but liveness is not asserted
/// without an observation, and the guards refuse what the listing withheld.
#[test]
fn a_listing_earns_attach_from_a_live_run_and_withholds_it_from_an_orphaned_binding() {
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    std::fs::create_dir(config.state_dir()).expect("product state");
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("private product state");
    register_run(&config, 1, "tui-orphaned-run", true);
    register_run(&config, 2, "tui-live-run", false);

    let mut sessions = automonique_daemon::managed_sessions::ManagedSessionStore::open(
        config.managed_sessions_path(),
    )
    .expect("managed sessions");
    sessions
        .observe_active("orphaned-session", "tui-orphaned-run", 100)
        .expect("turn starts and never settles");
    sessions
        .observe_active("live-session", "tui-live-run", 101)
        .expect("live turn");
    drop(sessions);

    let serving = serve(&config);
    let PlatformResponse::Sessions(listing) = platform(
        &config,
        "orphan-listing",
        PlatformRequest::ListSessions(ListSessionsRequest {
            authority: ResourceAuthority::Automonique,
            cursor: None,
        }),
    ) else {
        panic!("sessions response")
    };
    let find = |id: &str| {
        listing
            .sessions
            .iter()
            .find(|record| record.session.resource.id.as_str() == id)
            .unwrap_or_else(|| panic!("{id} is listed"))
    };

    let orphaned = find("orphaned-session");
    assert_eq!(
        orphaned.session.freshness.state.as_str(),
        "unknown",
        "a binding whose run ended is not a current observation of a session"
    );
    assert!(
        !orphaned.attachable,
        "attach is offered only where a session was observed live"
    );
    assert!(
        !orphaned.controllable,
        "control is offered only where a session was observed live"
    );
    assert_eq!(
        orphaned.session.summary.as_str(),
        "open",
        "the binding still proves the session can be resumed, which is what the \
         follow-up guard reads"
    );

    let live = find("live-session");
    assert_eq!(live.session.freshness.state.as_str(), "fresh");
    assert!(live.attachable, "a run the index has not seen end is live");
    assert!(live.controllable);

    let orphaned_coordinate = automonique_coordinate(ResourceKind::Session, "orphaned-session");
    let PlatformResponse::Refused {
        outcome,
        explanation,
    } = platform(
        &config,
        "attach-orphan",
        PlatformRequest::Attach(AttachRequest {
            session: orphaned_coordinate.clone(),
            client: ClientId::new("client-orphan").expect("client"),
        }),
    )
    else {
        panic!("attaching to an unobserved session is refused")
    };
    assert_eq!(outcome, ReceiptOutcome::Rejected);
    assert_eq!(explanation.as_str(), "session_not_attachable");

    let PlatformResponse::Refused {
        outcome,
        explanation,
    } = platform(
        &config,
        "control-orphan",
        PlatformRequest::ClaimControl(ClaimControlRequest {
            session: orphaned_coordinate,
            client: ClientId::new("client-orphan").expect("client"),
            idempotency_key: IdempotencyKey::new("claim-orphan-1").expect("key"),
        }),
    )
    else {
        panic!("claiming control of an unobserved session is refused")
    };
    assert_eq!(outcome, ReceiptOutcome::Rejected);
    assert_eq!(explanation.as_str(), "session_not_controllable");

    let PlatformResponse::Attached(attachment) = platform(
        &config,
        "attach-live",
        PlatformRequest::Attach(AttachRequest {
            session: automonique_coordinate(ResourceKind::Session, "live-session"),
            client: ClientId::new("client-live").expect("client"),
        }),
    ) else {
        panic!("a live session still attaches")
    };
    assert_eq!(attachment.session.id.as_str(), "live-session");
    serving.shutdown(&config);
}

/// #130: the adapter's pre-#118 `execute` body (no `client` key) is accepted,
/// and a body the lane refuses is answered with the typed `refused` frame
/// carrying the request id, never a bare EOF.
#[test]
fn platform_decode_failures_are_typed_refusals_and_absent_client_is_accepted() {
    let _guard = full_daemon_test_guard();
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
    let _guard = full_daemon_test_guard();
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
    let _guard = full_daemon_test_guard();
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

#[test]
fn a_live_listing_pages_the_granted_classes_and_withholds_the_rest() {
    // End to end over the real socket: the daemon refreshes every projected
    // class, the policy grant decides per record what this principal sees, and
    // the walk is bounded by the server rather than by what the caller could
    // name. This is the primitive Platform v1 never had (#220).
    let _guard = full_daemon_test_guard();
    let (_root, config) = fixture();
    configure_v2(&config);
    let serving = serve(&config);

    let mut seen: Vec<automonique_protocol::platform::ResourceCoordinate> = Vec::new();
    let mut after = None;
    let mut pages = 0_usize;
    for index in 0..16 {
        let request = automonique_protocol::platform_v2_inventory::ResourceListingQuery::new(
            Vec::new(),
            Vec::new(),
            after.clone(),
            2,
        )
        .unwrap();
        let PlatformV2Response::ResourceListingPage(page) = platform_v2(
            &config,
            &format!("v2-listing-{index}"),
            PlatformV2Request::ListResources(request),
        ) else {
            panic!("expected a bounded listing page");
        };
        pages += 1;
        assert_eq!(page.requested_limit(), 2);
        assert_eq!(
            page.granted_limit(),
            2,
            "under the ceiling nothing is clamped"
        );
        assert!(page.items().len() <= 2);
        seen.extend(page.items().iter().map(|item| item.resource.clone()));
        match page.next_cursor() {
            Some(cursor) => after = Some(cursor.clone()),
            None => break,
        }
    }
    assert!(pages > 1, "a bounded page walked rather than one snapshot");
    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), seen.len(), "no record was served twice");
    assert!(
        seen.iter()
            .any(|resource| resource.kind == automonique_protocol::platform::ResourceKind::Node),
        "the refresh ran for a class the caller never named"
    );
    assert!(
        seen.iter()
            .any(|resource| resource.kind == automonique_protocol::platform::ResourceKind::Client),
        "the action catalogue is a granted class"
    );
    assert!(
        seen.iter().all(|resource| resource.authority
            == automonique_protocol::platform::ResourceAuthority::Automonique
            && matches!(
                resource.kind,
                automonique_protocol::platform::ResourceKind::Client
                    | automonique_protocol::platform::ResourceKind::Node
            )),
        "an ungranted class reached the page: {seen:?}"
    );

    // A class the policy withholds answers with nothing, which is the same
    // answer as a granted class that happens to be empty.
    let PlatformV2Response::ResourceListingPage(withheld) = platform_v2(
        &config,
        "v2-listing-withheld",
        PlatformV2Request::ListResources(
            automonique_protocol::platform_v2_inventory::ResourceListingQuery::new(
                Vec::new(),
                vec![automonique_protocol::platform::ResourceKind::Approval],
                None,
                8,
            )
            .unwrap(),
        ),
    ) else {
        panic!("expected a bounded listing page");
    };
    assert!(withheld.items().is_empty());
    assert!(!withheld.has_more());

    // Over the ceiling is admissible and answered with the server's page.
    let PlatformV2Response::ResourceListingPage(clamped) = platform_v2(
        &config,
        "v2-listing-clamped",
        PlatformV2Request::ListResources(
            automonique_protocol::platform_v2_inventory::ResourceListingQuery::new(
                Vec::new(),
                Vec::new(),
                None,
                4_096,
            )
            .unwrap(),
        ),
    ) else {
        panic!("expected a bounded listing page");
    };
    assert_eq!(clamped.requested_limit(), 4_096);
    assert_eq!(
        usize::from(clamped.granted_limit()),
        automonique_protocol::platform_v2_inventory::MAX_RESOURCE_LISTING_PAGE_ITEMS,
    );

    serving.shutdown(&config);
}
