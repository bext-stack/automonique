// SPDX-License-Identifier: Elastic-2.0

//! What a status says the daemon is holding, measured against what it holds.
//!
//! The counts in a status snapshot are worth exactly as much as their coupling
//! to the stores they claim to describe, so nothing here asserts a number in
//! isolation. Every assertion is a *movement*: a real submission over the real
//! socket, then the count that must have changed and the counts that must not
//! have. A daemon that answered plausible constants would pass a fixed-value
//! test and fail every test in this file.
//!
//! The second test is the one that separates a count from a memory. The daemon
//! is stopped and a successor is started over the same state directory, and the
//! successor reports the same durable totals plus its own new tenure — which an
//! in-process counter, however honestly maintained, could not do.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use automonique_daemon::{Daemon, DaemonConfig};
use automonique_protocol::admin::{
    AdminCommand, AdminRequest, AdminResponse, DaemonStatus, DurableStateCounts, OperationalMetric,
    SubmittedRunSpec,
};
use automonique_protocol::approval_api::{
    ApprovalDecision, ApprovalKey, ApprovalRequest, ApprovalResponse, ApprovalSubject, Decider,
    RecordApproval,
};
use automonique_protocol::automation::AutomationActor;
use automonique_protocol::automation_api::{
    AutomationId, AutomationPrompt, AutomationRequest, AutomationResponse, AutomationSchedule,
    AutomationScope, RegisterAutomation,
};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_protocol::context::{ContextManifest, TokenBudget};
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
use automonique_protocol::workspace::{IsolationKind, WorkspaceRegistration, WorkspaceToken};

#[path = "support/isolation.rs"]
mod test_isolation;
use automonique_runner::{
    AdmissionFields, AdmissionFieldsParts, ArtifactGrantBindings, CwdToken, ExecutionPlanDigest,
    ExtensionSetDigest, FallbackEligibility, IntegrationMode, IoReservation, ModelRoutingDigest,
    PersonaDigest, PortabilityPolicy, ProfileDigest, PromptDeliveryPlan, RemoteAttestationPolicy,
    RequiredCapabilities, RunCoordinates, RunOrigin, RunSpec, RunSpecParts, RunnerEventDialect,
    SchedulerDecisionDigest, SchedulerReservationBinding, SchedulerReservationId, SkillsetDigest,
    ToolsetDigest, WorkspaceRegistryId, WorkspaceReservation,
};

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

fn exchange(config: &DaemonConfig, payload: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(config.admin_socket()).expect("connect to daemon");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read deadline");
    let mut frame = Vec::new();
    encode_frame(payload, &mut frame).expect("frame request");
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
    payload.to_vec()
}

fn admin(config: &DaemonConfig, request: &AdminRequest) -> AdminResponse {
    let payload = request
        .to_message()
        .expect("encode request")
        .to_canonical_bytes();
    AdminResponse::from_canonical_bytes(&exchange(config, &payload)).expect("admitted response")
}

fn request_id(label: &str) -> RequestId {
    RequestId::new(label).expect("request ID")
}

/// One status snapshot, decoded by the protocol's own decoder.
///
/// The decoder matters here: it enforces the same field set and the same tenure
/// coherence a client would, so a daemon that answered an incoherent status
/// would fail on the way in rather than in an assertion below.
fn status(config: &DaemonConfig, label: &str) -> DaemonStatus {
    let answer = admin(
        config,
        &AdminRequest::new(request_id(label), AdminCommand::Status),
    );
    let AdminResponse::Status { status, .. } = answer else {
        panic!("expected a status, got {answer:?}")
    };
    status
}

/// The durable counts a status carries, with the tenure cross-check the wire
/// already made asserted again in the open.
fn counts(status: &DaemonStatus) -> DurableStateCounts {
    let counts = status
        .durable_state()
        .expect("a decoded status carries its durable counts")
        .clone();
    assert_eq!(
        counts.open_tenures(),
        OperationalMetric::Measured(1),
        "a serving daemon holds exactly one open tenure"
    );
    assert_eq!(
        counts.open_tenure_epoch(),
        OperationalMetric::Measured(status.generation()),
        "the audited tenure and the generation lease must name the same epoch"
    );
    assert_eq!(
        counts.automation_scheduler_workers(),
        OperationalMetric::Measured(1),
        "a serving daemon has its automation scheduler worker on its thread"
    );
    counts
}

fn measured(metric: OperationalMetric, field: &str) -> u64 {
    match metric {
        OperationalMetric::Measured(value) => value,
        OperationalMetric::Unavailable => {
            panic!("{field} was unavailable, but every store in this fixture is readable")
        }
    }
}

fn wait_for_socket(config: &DaemonConfig) {
    // Generous on purpose, as in the sibling suites: everything before the bind
    // is disk-bound — several SQLite databases opened `synchronous = FULL` —
    // so a short deadline measures the test host under load, not the daemon.
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
            admin(
                config,
                &AdminRequest::new(request_id("durable-shutdown"), AdminCommand::Shutdown),
            ),
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

// --- The three mutations a status is supposed to notice. ---

fn submit_run(config: &DaemonConfig, label: &str, run: &str) {
    let submission = SubmittedRunSpec::sealed(document(run), format!("operator:{label}"))
        .expect("bounded submission");
    let answer = admin(
        config,
        &AdminRequest::submit_run(request_id(label), submission),
    );
    let AdminResponse::RunAccepted { run_id, .. } = answer else {
        panic!("expected an accepted run, got {answer:?}")
    };
    assert_eq!(run_id.as_str(), run);
}

fn register_automation(config: &DaemonConfig, label: &str, automation: &str) {
    let request = AutomationRequest::RegisterAutomation {
        request_id: request_id(label),
        // A job that will not fire during the test: one occurrence a minute.
        registration: RegisterAutomation::new(
            AutomationId::new(automation).expect("automation identity"),
            AutomationActor::new("operator:durable-state").expect("actor"),
            AutomationSchedule::every(60_000).expect("interval"),
            AutomationScope::new("workspace:reports").expect("scope"),
            AutomationPrompt::new("summarize the night").expect("prompt"),
        )
        .expect("a registration within its bounds"),
    };
    let payload = request
        .to_message()
        .expect("encode automation request")
        .to_canonical_bytes();
    let answer = AutomationResponse::from_canonical_bytes(&exchange(config, &payload))
        .expect("admitted automation response");
    let AutomationResponse::Accepted { receipt, .. } = answer else {
        panic!("expected an accepted registration, got {answer:?}")
    };
    assert_eq!(receipt.automation_id().as_str(), automation);
}

fn record_approval(config: &DaemonConfig, label: &str, key: &str) {
    let request = ApprovalRequest::RecordApproval {
        request_id: request_id(label),
        decision: RecordApproval::new(
            ApprovalKey::new(key).expect("approval key"),
            ApprovalSubject::new("subject:durable-state").expect("subject"),
            ApprovalDecision::Granted,
            Decider::new("operator:durable-state").expect("decider"),
        ),
    };
    let payload = request
        .to_message()
        .expect("encode approval request")
        .to_canonical_bytes();
    let answer = ApprovalResponse::from_canonical_bytes(&exchange(config, &payload))
        .expect("admitted approval response");
    let ApprovalResponse::Recorded { receipt, .. } = answer else {
        panic!("expected a recorded decision, got {answer:?}")
    };
    assert_eq!(receipt.approval_key().as_str(), key);
}

// --- A real RunSpec, built the way the runner's own tests build one. ---

fn digest_text(digit: char) -> String {
    format!("sha256:{}", digit.to_string().repeat(64))
}

fn provider_binary() -> BinaryProvenance {
    BinaryProvenance::new("1.2.3", &digest_text('1'), Some(digest_text('2').as_str()))
        .expect("pinned provider binary")
}

fn workspace() -> WorkspaceRegistration {
    WorkspaceRegistration::new(
        "acme",
        "source-1",
        Revision::new(7).expect("revision"),
        "snapshot-1",
        IsolationKind::ReadOnlySnapshot,
        WorkspaceToken::new("workspace-token-1").expect("token"),
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

fn document(run: &str) -> Vec<u8> {
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
        workspace_registry_id: WorkspaceRegistryId::new("workspace-registry-1").expect("registry"),
        workspace: workspace(),
        provider_binary: provider_binary(),
        sandbox: sandbox(),
        admission: admission(),
    })
    .expect("valid run specification")
    .to_canonical_bytes()
    .expect("canonical encoding")
}

#[test]
fn every_durable_count_moves_only_when_its_own_store_does() {
    let (_root, config) = fixture();
    let serving = serve(&config);

    // A daemon that has just opened holds three empty stores and one tenure it
    // wrote itself. Empty is a count here, not an absence.
    let empty = counts(&status(&config, "durable-empty"));
    assert_eq!(empty.runs_registered(), OperationalMetric::Measured(0));
    assert_eq!(
        empty.automations_registered(),
        OperationalMetric::Measured(0)
    );
    assert_eq!(empty.approvals_recorded(), OperationalMetric::Measured(0));
    assert_eq!(empty.tenures_recorded(), OperationalMetric::Measured(1));

    // One submission moves one count. The other two staying put is the whole
    // assertion: a status that reported the same number under three names would
    // pass the first line and fail the next two.
    submit_run(&config, "durable-run-1", "run-1");
    let after_run = counts(&status(&config, "durable-after-run"));
    assert_eq!(after_run.runs_registered(), OperationalMetric::Measured(1));
    assert_eq!(
        after_run.automations_registered(),
        OperationalMetric::Measured(0)
    );
    assert_eq!(
        after_run.approvals_recorded(),
        OperationalMetric::Measured(0)
    );

    register_automation(&config, "durable-automation-1", "automation-1");
    let after_automation = counts(&status(&config, "durable-after-automation"));
    assert_eq!(
        after_automation.runs_registered(),
        OperationalMetric::Measured(1)
    );
    assert_eq!(
        after_automation.automations_registered(),
        OperationalMetric::Measured(1)
    );
    assert_eq!(
        after_automation.approvals_recorded(),
        OperationalMetric::Measured(0)
    );

    record_approval(&config, "durable-approval-1", "approval-1");
    let after_approval = counts(&status(&config, "durable-after-approval"));
    assert_eq!(
        after_approval.runs_registered(),
        OperationalMetric::Measured(1)
    );
    assert_eq!(
        after_approval.automations_registered(),
        OperationalMetric::Measured(1)
    );
    assert_eq!(
        after_approval.approvals_recorded(),
        OperationalMetric::Measured(1)
    );

    // A second run moves the run count and nothing else, so the first move was
    // not a one-off transition from zero.
    submit_run(&config, "durable-run-2", "run-2");
    let after_second = counts(&status(&config, "durable-after-second-run"));
    assert_eq!(
        after_second.runs_registered(),
        OperationalMetric::Measured(2)
    );
    assert_eq!(
        after_second.automations_registered(),
        OperationalMetric::Measured(1)
    );
    assert_eq!(
        after_second.approvals_recorded(),
        OperationalMetric::Measured(1)
    );

    // Reading the status neither wrote anything nor changed anything.
    let again = counts(&status(&config, "durable-repeat"));
    assert_eq!(again, after_second, "a status read moved a durable count");

    serving.shutdown(&config);
}

#[test]
fn the_counts_and_the_tenure_outlive_the_process_that_wrote_them() {
    let (_root, config) = fixture();

    let first = serve(&config);
    submit_run(&config, "restart-run-1", "run-1");
    register_automation(&config, "restart-automation-1", "automation-1");
    record_approval(&config, "restart-approval-1", "approval-1");
    let before = status(&config, "restart-before");
    let before_counts = counts(&before);
    assert_eq!(
        measured(before_counts.tenures_recorded(), "tenures_recorded"),
        1,
        "the first daemon over a fresh state directory records one tenure"
    );
    first.shutdown(&config);

    // A successor over the same state directory. Nothing is carried across in
    // memory, so whatever it reports it read from disk.
    let second = serve(&config);
    let after = status(&config, "restart-after");
    let after_counts = counts(&after);

    assert_eq!(
        after_counts.runs_registered(),
        before_counts.runs_registered(),
        "the run index did not survive the process that wrote it"
    );
    assert_eq!(
        after_counts.automations_registered(),
        before_counts.automations_registered(),
        "the automation registry did not survive the process that wrote it"
    );
    assert_eq!(
        after_counts.approvals_recorded(),
        before_counts.approvals_recorded(),
        "the approval ledger did not survive the process that wrote it"
    );

    // The tenure is the count that must *not* be the same: a successor is a new
    // tenure over the same generation, and the audit records both.
    assert_eq!(
        measured(after_counts.tenures_recorded(), "tenures_recorded"),
        2,
        "the successor's tenure was not recorded"
    );
    assert!(
        after.generation() > before.generation(),
        "a successor holds a later generation lease: {} then {}",
        before.generation(),
        after.generation()
    );
    assert_eq!(
        after_counts.open_tenure_epoch(),
        OperationalMetric::Measured(after.generation()),
        "the successor reported its predecessor's epoch as the open one"
    );

    // One more write lands on top of what the predecessor left, rather than
    // starting a fresh count.
    submit_run(&config, "restart-run-2", "run-2");
    let grown = counts(&status(&config, "restart-grown"));
    assert_eq!(
        measured(grown.runs_registered(), "runs_registered"),
        measured(before_counts.runs_registered(), "runs_registered") + 1
    );

    second.shutdown(&config);
}
