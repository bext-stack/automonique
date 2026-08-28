// SPDX-License-Identifier: Elastic-2.0

//! Operator pause and resume for the intake lane.
//!
//! The properties under test are the ones an operator relies on: both intake
//! lanes close, the status says so and says why, the decision and its
//! attribution survive a restart, and repeats get an answer rather than a
//! second effect.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use automonique_daemon::{Daemon, DaemonConfig};
use automonique_protocol::admin::{
    AdminCommand, AdminRequest, AdminResponse, DaemonState, DaemonStatus, IntakePause,
    IntakeResume, SubmittedRunSpec, SyntheticSubmission,
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
use rusqlite::Connection;

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

fn request_id(label: &str) -> RequestId {
    RequestId::new(label).expect("request ID")
}

fn status(config: &DaemonConfig) -> DaemonStatus {
    let AdminResponse::Status { status, .. } = call_request(
        config,
        AdminRequest::new(request_id("pause-status"), AdminCommand::Status),
    ) else {
        panic!("status response")
    };
    status
}

fn pause(config: &DaemonConfig, actor: &str, reason: &str) -> AdminResponse {
    call_request(
        config,
        AdminRequest::pause_intake(
            request_id("pause-1"),
            IntakePause::new(actor, reason).expect("pause body"),
        ),
    )
}

fn resume(config: &DaemonConfig, actor: &str) -> AdminResponse {
    call_request(
        config,
        AdminRequest::resume_intake(
            request_id("resume-1"),
            IntakeResume::new(actor).expect("resume body"),
        ),
    )
}

fn submit_synthetic(config: &DaemonConfig, key: &str) -> AdminResponse {
    call_request(
        config,
        AdminRequest::submit(
            request_id("pause-synthetic"),
            SyntheticSubmission::new("workspace:pause", key, "synthetic task")
                .expect("synthetic submission"),
        ),
    )
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

fn run_spec_document(run: &str) -> Vec<u8> {
    run_spec(run)
        .to_canonical_bytes()
        .expect("canonical encoding")
}

fn submit_run(config: &DaemonConfig, key: &str, run_id: &str) -> AdminResponse {
    call_request(
        config,
        AdminRequest::submit_run(
            request_id("pause-run"),
            SubmittedRunSpec::sealed(run_spec_document(run_id), key).expect("run submission"),
        ),
    )
}

fn refusal_category(response: &AdminResponse) -> &str {
    let AdminResponse::Refused { category, .. } = response else {
        panic!("expected a refusal, got {response:?}")
    };
    category.as_str()
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

/// Run one daemon for the duration of `body`, stopping it afterwards.
fn with_daemon<T>(config: &DaemonConfig, body: impl FnOnce() -> T) -> T {
    let daemon = Daemon::open(config).expect("daemon");
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&thread_stop));
    wait_for_socket(config);
    let result = body();
    stop.store(true, std::sync::atomic::Ordering::Release);
    thread.join().expect("daemon thread").expect("clean serve");
    result
}

#[test]
fn a_pause_closes_both_intake_lanes_and_a_resume_reopens_them() {
    let (_root, config) = fixture();
    with_daemon(&config, || {
        // Baseline: intake is open and no pause is reported.
        let open = status(&config);
        assert_eq!(open.state(), DaemonState::Ready);
        assert!(open.accepting_intake());
        assert!(!open.intake_paused());
        assert!(matches!(
            submit_synthetic(&config, "before-pause"),
            AdminResponse::SyntheticAccepted { .. }
        ));
        assert!(matches!(
            submit_run(&config, "run-before-pause", "run-before-pause"),
            AdminResponse::RunAccepted { .. }
        ));

        let AdminResponse::IntakePaused {
            pause_id, revision, ..
        } = pause(&config, "operator:ada", "provider incident 4417")
        else {
            panic!("pause receipt")
        };
        assert!(pause_id > 0);
        assert_eq!(revision, 1);

        // Both lanes refuse with the pause's own category — not the degraded
        // generation's, which would send an operator looking for damage.
        assert_eq!(
            refusal_category(&submit_synthetic(&config, "during-pause")),
            "intake_paused"
        );
        assert_eq!(
            refusal_category(&submit_run(&config, "run-during-pause", "run-during-pause")),
            "intake_paused"
        );

        // The gate runs before the document is verified. A document that would
        // be refused on its own merits is still refused as paused, so the lane
        // is closed rather than merely failing for some other reason — and the
        // same document changes answer once intake reopens, which is what
        // proves the lane was reachable all along.
        let junk = || {
            call_request(
                &config,
                AdminRequest::submit_run(
                    request_id("pause-junk"),
                    SubmittedRunSpec::sealed(b"not a run specification".to_vec(), "operator:junk")
                        .expect("bounded document"),
                ),
            )
        };
        assert_eq!(refusal_category(&junk()), "intake_paused");

        // The status says intake is closed, says a pause is why, and does not
        // claim the generation is damaged.
        let paused = status(&config);
        assert!(paused.intake_paused());
        assert!(!paused.accepting_intake());
        assert_eq!(paused.state(), DaemonState::Ready);

        let AdminResponse::IntakeResumed {
            pause_id: resumed_id,
            revision: resumed_revision,
            ..
        } = resume(&config, "operator:bo")
        else {
            panic!("resume receipt")
        };
        assert_eq!(resumed_id, pause_id, "a resume closes the live pause");
        assert_eq!(resumed_revision, 2);

        let reopened = status(&config);
        assert!(!reopened.intake_paused());
        assert!(reopened.accepting_intake());
        assert!(matches!(
            submit_synthetic(&config, "after-resume"),
            AdminResponse::SyntheticAccepted { .. }
        ));
        assert!(matches!(
            submit_run(&config, "run-after-resume", "run-after-resume"),
            AdminResponse::RunAccepted { .. }
        ));
        assert_eq!(
            refusal_category(&junk()),
            "run_spec_invalid_canonical_json",
            "once intake reopens, a bad document is judged on its own merits"
        );
    });
}

#[test]
fn a_repeated_pause_or_resume_gets_a_typed_answer_and_no_second_effect() {
    let (_root, config) = fixture();
    with_daemon(&config, || {
        // Resuming what was never paused is refused, not silently accepted.
        assert_eq!(
            refusal_category(&resume(&config, "operator:bo")),
            "intake_not_paused"
        );

        let AdminResponse::IntakePaused { pause_id, .. } = pause(&config, "operator:ada", "first")
        else {
            panic!("pause receipt")
        };
        assert_eq!(
            refusal_category(&pause(&config, "operator:bo", "second")),
            "intake_already_paused"
        );
        // The refused second pause left the first one exactly as it was.
        assert!(status(&config).intake_paused());

        let AdminResponse::IntakeResumed {
            pause_id: resumed_id,
            ..
        } = resume(&config, "operator:bo")
        else {
            panic!("resume receipt")
        };
        assert_eq!(resumed_id, pause_id);
        assert_eq!(
            refusal_category(&resume(&config, "operator:bo")),
            "intake_not_paused"
        );
        assert!(status(&config).accepting_intake());
    });

    // Exactly one pause episode was ever written.
    let rows: i64 = Connection::open(config.database_path())
        .expect("raw open")
        .query_row("SELECT count(*) FROM intake_pauses", [], |row| row.get(0))
        .expect("pause rows");
    assert_eq!(rows, 1, "refused repeats must not write a second episode");
}

#[test]
fn a_pause_and_its_attribution_survive_a_daemon_restart() {
    let (_root, config) = fixture();
    let pause_id = with_daemon(&config, || {
        let AdminResponse::IntakePaused { pause_id, .. } =
            pause(&config, "operator:ada", "provider incident 4417")
        else {
            panic!("pause receipt")
        };
        pause_id
    });

    // A new daemon process takes the same named generation at a new lease
    // epoch. The pause is scoped to the generation, so it comes back closed.
    with_daemon(&config, || {
        let restarted = status(&config);
        assert!(
            restarted.intake_paused(),
            "a pause must not be undone by the recovery that follows it"
        );
        assert!(!restarted.accepting_intake());
        assert_eq!(
            refusal_category(&submit_synthetic(&config, "after-restart")),
            "intake_paused"
        );
        assert_eq!(
            refusal_category(&submit_run(
                &config,
                "run-after-restart",
                "run-after-restart"
            )),
            "intake_paused"
        );

        // The successor resumes under its own epoch, and both actors are
        // recorded: the pause row is history, not a flag that gets cleared.
        assert!(matches!(
            resume(&config, "operator:bo"),
            AdminResponse::IntakeResumed { .. }
        ));
        assert!(status(&config).accepting_intake());
        assert!(matches!(
            submit_synthetic(&config, "after-restart-resume"),
            AdminResponse::SyntheticAccepted { .. }
        ));
    });

    let row: (String, String, Option<String>, Option<i64>, i64) =
        Connection::open(config.database_path())
            .expect("raw open")
            .query_row(
                "SELECT actor, reason, resume_actor, resumed_at_ms, revision
                 FROM intake_pauses WHERE pause_id = ?1",
                [i64::try_from(pause_id).expect("pause id")],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("durable pause row");
    assert_eq!(row.0, "operator:ada");
    assert_eq!(row.1, "provider incident 4417");
    assert_eq!(
        row.2,
        Some("operator:bo".to_owned()),
        "the resuming actor is recorded beside, never over, the pausing one"
    );
    assert!(row.3.is_some(), "the resume instant is durable");
    assert_eq!(row.4, 2);
}

#[test]
fn a_pause_written_by_a_dead_generation_is_still_the_live_generations_pause() {
    let (_root, config) = fixture();

    // Seed a pause under a generation lease this daemon will never hold, the
    // way a crashed predecessor would leave one behind.
    std::fs::create_dir(config.state_dir()).expect("state directory");
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("state mode");
    {
        let mut store = automonique_store::Store::open(config.database_path()).expect("seed store");
        let lease = store
            .acquire_generation_lease(automonique_store::LeaseRequest {
                generation_id: "foreground",
                holder_id: "crashed-operator-console",
                now_ms: 1,
                ttl_ms: 100,
            })
            .expect("predecessor lease");
        store
            .pause_intake(automonique_store::IntakePauseRequest {
                generation_id: "foreground",
                holder_id: "crashed-operator-console",
                authority_lease_epoch: lease.epoch,
                actor: "operator:ada",
                reason: "paused before the crash",
                now_ms: 2,
            })
            .expect("predecessor pause");
    }

    with_daemon(&config, || {
        let inherited = status(&config);
        assert!(
            inherited.intake_paused(),
            "the successor of a paused generation starts paused"
        );
        assert!(!inherited.accepting_intake());
        assert_eq!(
            refusal_category(&submit_synthetic(&config, "inherited-pause")),
            "intake_paused"
        );
        // The successor holds a different lease epoch and can still resume:
        // the pause is fenced by generation authority, not by the exact epoch
        // that wrote it.
        assert!(matches!(
            resume(&config, "operator:bo"),
            AdminResponse::IntakeResumed { .. }
        ));
        assert!(status(&config).accepting_intake());
    });
}
