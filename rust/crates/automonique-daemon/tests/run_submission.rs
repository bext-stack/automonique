// SPDX-License-Identifier: Elastic-2.0

//! Run submission over the real local administration socket.
//!
//! Every document here is a real RunSpec built through the runner's own
//! constructors and encoded by its own canonical codec — never a hand-written
//! blob that happens to parse — so a change to the codec breaks these tests
//! rather than passing through them. Refusals are asserted by exact category:
//! two different guards that both refuse would otherwise be interchangeable,
//! and they are not.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use automonique_daemon::{Daemon, DaemonConfig};
use automonique_protocol::admin::{
    AdminCommand, AdminRequest, AdminResponse, DaemonState, MAX_SUBMITTED_RUN_SPEC_BYTES,
    SubmittedRunSpec,
};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_protocol::context::{ContextManifest, TokenBudget};
use automonique_protocol::digest::Sha256;
use automonique_protocol::host::{AttemptId, HostId, HostLifetime, WorkId};
use automonique_protocol::identity::Actor;
use automonique_protocol::models::{ExecutorClass, ProviderAccountId};
use automonique_protocol::primitives::Revision;
use automonique_protocol::provider::BinaryProvenance;
use automonique_protocol::sandbox::{
    BudgetQuantities, Budgets, CredentialDescriptors, ExecutionAllowlists, ExecutionBackendId,
    FilesystemAccess, ImplementationDigest, IsolationRequirement, NestedIsolation, NetworkAccess,
    PathGrants, PolicyDigest, ProhibitedCapabilities, ProviderControlEgress, RequiredFeature,
    RequiredFeatures, SandboxProfile, SandboxSpec, SandboxSpecParts, ToolWorkloadEgress,
    WorkspaceContextHash,
};
use automonique_protocol::tools::RunId;
use automonique_protocol::wire::JsonValue;
use automonique_protocol::workspace::{
    AttemptWorkspaceRegistration, AttemptWorkspaceToken, IsolationKind,
};
use automonique_runner::{
    AdmissionFields, AdmissionFieldsParts, ArtifactGrantBindings, AttemptWorkspaceRegistryId,
    CwdToken, ExecutionPlanDigest, ExtensionSetDigest, FallbackEligibility, IntegrationMode,
    IoReservation, ModelRoutingDigest, PersonaDigest, PortabilityPolicy, ProfileDigest,
    PromptDeliveryPlan, RemoteAttestationPolicy, RequiredCapabilities, RunCoordinates, RunOrigin,
    RunSpec, RunSpecParts, RunnerEventDialect, SchedulerDecisionDigest,
    SchedulerReservationBinding, SchedulerReservationId, SkillsetDigest, ToolsetDigest,
    WorkspaceReservation,
};
use automonique_store::run_submissions::{RunSubmissionLog, RunSubmissionState};

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

fn call(config: &DaemonConfig, command: AdminCommand) -> AdminResponse {
    call_request(
        config,
        AdminRequest::new(
            RequestId::new("run-submission-1").expect("request ID"),
            command,
        ),
    )
}

fn submit(config: &DaemonConfig, label: &str, submission: SubmittedRunSpec) -> AdminResponse {
    call_request(
        config,
        AdminRequest::submit_run(RequestId::new(label).expect("request ID"), submission),
    )
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

struct Serving {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<(), automonique_daemon::DaemonError>>>,
}

fn serve(config: &DaemonConfig) -> Serving {
    let daemon = Daemon::open(config).expect("daemon opens");
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&thread_stop));
    wait_for_socket(config);
    Serving {
        stop,
        thread: Some(thread),
    }
}

impl Serving {
    fn shutdown(mut self, config: &DaemonConfig) {
        assert!(matches!(
            call(config, AdminCommand::Shutdown),
            AdminResponse::ShutdownAccepted { .. }
        ));
        self.thread
            .take()
            .expect("running")
            .join()
            .expect("daemon thread")
            .expect("clean stop");
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.stop.store(true, std::sync::atomic::Ordering::Release);
            let _ = thread.join();
        }
    }
}

// --- A real RunSpec, built the way the runner's own tests build one. ---

fn digest_text(digit: char) -> String {
    format!("sha256:{}", digit.to_string().repeat(64))
}

fn provider_binary() -> BinaryProvenance {
    BinaryProvenance::new("1.2.3", &digest_text('1'), Some(digest_text('2').as_str()))
        .expect("pinned provider binary")
}

fn attempt_workspace() -> AttemptWorkspaceRegistration {
    AttemptWorkspaceRegistration::new(
        "acme",
        "source-1",
        Revision::new(7).expect("revision"),
        "snapshot-1",
        IsolationKind::ReadOnlySnapshot,
        AttemptWorkspaceToken::new("workspace-token-1").expect("token"),
    )
    .expect("registered workspace")
}

fn sandbox() -> SandboxSpec {
    let implementation = ImplementationDigest::parse(&digest_text('3')).expect("implementation");
    SandboxSpec::compile(SandboxSpecParts {
        profile: SandboxProfile::new(
            "test-profile",
            1,
            FilesystemAccess::ReadOnlySnapshot,
            ToolWorkloadEgress::denied(),
        )
        .expect("profile"),
        policy_digest: PolicyDigest::parse(&digest_text('4')).expect("policy digest"),
        actor: Actor::new("acme", "actor-1").expect("actor"),
        provider_account: ProviderAccountId::new("provider-account-1").expect("account"),
        workspace_context: WorkspaceContextHash::parse(&digest_text('5')).expect("context"),
        base_revision: Revision::new(7).expect("revision"),
        path_grants: PathGrants::declare(&[]).expect("grants"),
        allowlists: ExecutionAllowlists::declare(&[]).expect("allowlists"),
        provider_control_egress: ProviderControlEgress::brokered(NetworkAccess::BrokeredNamed),
        tool_workload_egress: ToolWorkloadEgress::denied(),
        credentials: CredentialDescriptors::declare(&[]).expect("credentials"),
        budgets: Budgets::declare(BudgetQuantities {
            cgroup_memory_bytes: 128 * 1024 * 1024,
            cgroup_cpu_millicores: 1_000,
            rlimit_processes: 64,
            rlimit_descriptors: 256,
            timeout_millis: 5_000,
            temporary_storage_bytes: 1024 * 1024,
            spool_bytes: 1024 * 1024,
            artifact_bytes: 1024 * 1024,
        })
        .expect("budgets"),
        required_features: RequiredFeatures::declare(&[RequiredFeature::new(
            "process_boundary",
            &[implementation],
        )
        .expect("feature")])
        .expect("features"),
        nested_isolation: NestedIsolation::new(
            IsolationRequirement::SeparateChildBoundary,
            IsolationRequirement::SeparateChildBoundary,
        ),
        approval_revision: Revision::FIRST,
        prohibited_capabilities: ProhibitedCapabilities::declare(&[]).expect("prohibited"),
    })
    .expect("compiled sandbox")
}

fn admission() -> AdmissionFields {
    let mode = IntegrationMode::new("native").expect("mode");
    AdmissionFields::new(AdmissionFieldsParts {
        io_reservation: IoReservation::new(1024, 1024).expect("io"),
        workspace_reservation: WorkspaceReservation::new(0).expect("workspace bytes"),
        session_binding: None,
        fallback_eligibility: FallbackEligibility::declare(&mode, Vec::new()).expect("fallback"),
        integration_mode: mode,
        required_capabilities: RequiredCapabilities::declare(Vec::new()).expect("capabilities"),
        context_manifest: ContextManifest::new(
            Revision::FIRST,
            TokenBudget::new(0),
            Vec::new(),
            Vec::new(),
        ),
        profile_digest: ProfileDigest::parse(&digest_text('6')).expect("profile digest"),
        model_routing_digest: ModelRoutingDigest::parse(&digest_text('7')).expect("routing"),
        toolset_digest: ToolsetDigest::parse(&digest_text('8')).expect("toolset"),
        skillset_digest: SkillsetDigest::parse(&digest_text('9')).expect("skillset"),
        extension_set_digest: ExtensionSetDigest::parse(&digest_text('a')).expect("extensions"),
        origin: RunOrigin::Interactive,
        executor_class: ExecutorClass::Local,
        portability_policy: PortabilityPolicy::Pinned,
        remote_attestation_policy: RemoteAttestationPolicy::NotRequired,
        persona_digest: PersonaDigest::parse(&digest_text('b')).expect("persona"),
        execution_plan_digest: ExecutionPlanDigest::parse(&digest_text('c')).expect("plan"),
        scheduler_reservation: SchedulerReservationBinding::new(
            SchedulerReservationId::new("reservation-1").expect("reservation"),
            Revision::FIRST,
            SchedulerDecisionDigest::parse(&digest_text('d')).expect("decision"),
        ),
        artifact_grants: ArtifactGrantBindings::declare(Vec::new()).expect("grants"),
        credential_bindings: Vec::new(),
        event_dialect: RunnerEventDialect::AutomoniqueRunnerV1,
    })
}

fn run_spec(run: &str) -> RunSpec {
    RunSpec::new(RunSpecParts {
        protocol_version: 1,
        coordinates: RunCoordinates::new(
            WorkId::new("work-1").expect("work"),
            RunId::new(run).expect("run"),
            AttemptId::new("attempt-1").expect("attempt"),
            HostId::new("host-1").expect("host"),
            HostLifetime::Attempt,
            ExecutionBackendId::new("local-direct").expect("backend"),
        ),
        executable: PathBuf::from("/bin/true"),
        arguments: Vec::new(),
        cwd_token: CwdToken::new("cwd-1").expect("cwd"),
        environment: Vec::new(),
        prompt: PromptDeliveryPlan::Stdin,
        attempt_workspace_registry_id: AttemptWorkspaceRegistryId::new("workspace-registry-1")
            .expect("registry"),
        attempt_workspace: attempt_workspace(),
        provider_binary: provider_binary(),
        sandbox: sandbox(),
        admission: admission(),
    })
    .expect("valid run specification")
}

fn document(run: &str) -> Vec<u8> {
    run_spec(run)
        .to_canonical_bytes()
        .expect("canonical encoding")
}

fn refusal(response: &AdminResponse) -> &str {
    match response {
        AdminResponse::Refused { category, .. } => category.as_str(),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_real_run_spec_is_accepted_verified_and_replays_across_a_restart() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let document = document("run-1");
    // The lane's ceiling is not theoretical headroom: a real document has to
    // fit inside it with room to spare, or this lane stops working for the
    // documents it exists to carry before anyone notices.
    assert!(
        document.len() < MAX_SUBMITTED_RUN_SPEC_BYTES / 2,
        "canonical document is {} bytes",
        document.len()
    );
    let expected_digest = Sha256::digest(&document);
    let submission = SubmittedRunSpec::sealed(document.clone(), "operator:submit:1")
        .expect("bounded submission");

    let accepted = submit(&config, "accept-run", submission.clone());
    let AdminResponse::RunAccepted {
        run_id,
        spec_digest,
        submission_id,
        replay,
        ..
    } = accepted
    else {
        panic!("expected acceptance, got {accepted:?}")
    };
    assert_eq!(run_id.as_str(), "run-1");
    assert_eq!(spec_digest, expected_digest);
    assert!(submission_id > 0);
    assert!(!replay);

    // An exact resubmission answers from the row it already wrote.
    let replayed = submit(&config, "replay-run", submission.clone());
    assert!(matches!(
        replayed,
        AdminResponse::RunAccepted {
            submission_id: replayed_id,
            spec_digest: ref replayed_digest,
            replay: true,
            ..
        } if replayed_id == submission_id && *replayed_digest == expected_digest
    ));

    // Custody is not work: nothing was scheduled, claimed or queued.
    let AdminResponse::Status { status, .. } = call(&config, AdminCommand::Status) else {
        panic!("status response")
    };
    assert_eq!(status.state(), DaemonState::Ready);
    assert!(status.accepting_intake());
    assert_eq!(status.inbox_pending(), 0);
    assert_eq!(status.running(), 0);
    assert_eq!(status.outbox_pending(), 0);
    serving.shutdown(&config);

    // The document itself is durable, byte for byte, in its own database.
    let log = RunSubmissionLog::open(config.run_submissions_path()).expect("open custody log");
    let entry = log
        .submission("operator:submit:1")
        .expect("read")
        .expect("row exists");
    assert_eq!(entry.document, document);
    assert_eq!(entry.spec_digest, expected_digest.to_hex());
    assert_eq!(entry.run_id, "run-1");
    assert_eq!(entry.state, RunSubmissionState::Accepted);
    assert_eq!(entry.submission_id, i64::try_from(submission_id).unwrap());
    assert_eq!(log.submission_count().expect("count"), 1);
    drop(log);

    // A new generation answers the same retry with the same durable identity.
    let serving = serve(&config);
    let after_restart = submit(&config, "replay-after-restart", submission);
    assert!(matches!(
        after_restart,
        AdminResponse::RunAccepted {
            submission_id: replayed_id,
            replay: true,
            ..
        } if replayed_id == submission_id
    ));
    serving.shutdown(&config);
}

#[test]
fn a_digest_that_does_not_name_the_document_is_refused_before_it_is_parsed() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let document = document("run-1");

    // A well-formed document under somebody else's digest.
    let lying = SubmittedRunSpec::declared(
        document.clone(),
        Sha256::digest(b"a different document"),
        "operator:lying:1",
    )
    .expect("bounded submission");
    assert_eq!(
        refusal(&submit(&config, "lying-digest", lying)),
        "run_spec_digest_mismatch"
    );

    // The same document with one byte of the payload altered, still carrying
    // the digest of the original bytes.
    let mut tampered = document.clone();
    let position = tampered
        .windows(7)
        .position(|window| window == b"\"run-1\"".as_slice())
        .expect("run identity appears in the canonical document");
    tampered[position + 4] = b'2';
    assert_ne!(tampered, document);
    let altered = SubmittedRunSpec::declared(
        tampered.clone(),
        Sha256::digest(&document),
        "operator:tampered:1",
    )
    .expect("bounded submission");
    assert_eq!(
        refusal(&submit(&config, "tampered-bytes", altered)),
        "run_spec_digest_mismatch"
    );

    // Nothing above reached storage: the first real submission is not a replay.
    assert!(matches!(
        submit(
            &config,
            "after-refusals",
            SubmittedRunSpec::sealed(document, "operator:lying:1").expect("bounded"),
        ),
        AdminResponse::RunAccepted { replay: false, .. }
    ));
    serving.shutdown(&config);
}

#[test]
fn a_document_that_is_not_a_run_spec_is_refused_by_the_strict_decoder() {
    let (_root, config) = fixture();
    let serving = serve(&config);

    // Consistently sealed rubbish: the digest is right, so only the decoder
    // can refuse this one.
    assert_eq!(
        refusal(&submit(
            &config,
            "not-json",
            SubmittedRunSpec::sealed(b"not a document at all".to_vec(), "operator:junk:1")
                .expect("bounded"),
        )),
        "run_spec_invalid_canonical_json"
    );

    // Canonical JSON that is simply not this document.
    let plausible = JsonValue::Object(vec![(
        "schema".to_owned(),
        JsonValue::String("automonique.run-spec/v1".to_owned()),
    )])
    .to_canonical_bytes();
    assert_eq!(
        refusal(&submit(
            &config,
            "wrong-shape",
            SubmittedRunSpec::sealed(plausible, "operator:junk:2").expect("bounded"),
        )),
        "run_spec_object_shape"
    );

    // A real document mutated inside a typed field, then re-sealed so the
    // digest check passes and the decoder is the only guard left.
    let document = document("run-1");
    let mutated = String::from_utf8(document)
        .expect("canonical UTF-8")
        .replace(
            "\"host_lifetime\":\"attempt\"",
            "\"host_lifetime\":\"forever\"",
        )
        .into_bytes();
    assert_eq!(
        refusal(&submit(
            &config,
            "unknown-enum",
            SubmittedRunSpec::sealed(mutated, "operator:junk:3").expect("bounded"),
        )),
        "run_spec_field_invalid"
    );

    let log = RunSubmissionLog::open(config.run_submissions_path()).expect("open custody log");
    assert_eq!(
        log.submission_count().expect("count"),
        0,
        "a refused document must not reach durable custody"
    );
    drop(log);
    serving.shutdown(&config);
}

#[test]
fn reusing_a_key_for_a_different_document_is_a_typed_conflict() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    assert!(matches!(
        submit(
            &config,
            "first-run",
            SubmittedRunSpec::sealed(document("run-1"), "operator:key:1").expect("bounded"),
        ),
        AdminResponse::RunAccepted { replay: false, .. }
    ));
    assert_eq!(
        refusal(&submit(
            &config,
            "reused-key",
            SubmittedRunSpec::sealed(document("run-2"), "operator:key:1").expect("bounded"),
        )),
        "conflict"
    );

    // The conflict left the first custody row exactly as it was, and the
    // second document is still submittable under its own key.
    assert!(matches!(
        submit(
            &config,
            "second-run",
            SubmittedRunSpec::sealed(document("run-2"), "operator:key:2").expect("bounded"),
        ),
        AdminResponse::RunAccepted { replay: false, .. }
    ));
    serving.shutdown(&config);

    let log = RunSubmissionLog::open(config.run_submissions_path()).expect("open custody log");
    assert_eq!(log.submission_count().expect("count"), 2);
    assert_eq!(
        log.submission("operator:key:1")
            .expect("read")
            .expect("row")
            .document,
        document("run-1")
    );
}
