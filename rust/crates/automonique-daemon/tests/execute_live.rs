// SPDX-License-Identifier: Elastic-2.0

//! The execution lane, live over the real local socket.
//!
//! Nothing here is a unit test of the lane's types. What is proved is the whole
//! path a run takes through a *running daemon*: a real `RunSpec` submitted
//! through the administration lane, started through the Execute lane, and the
//! outcome read back through the Runs lane — every message encoded and decoded
//! by the protocol's own codecs, over the socket the daemon bound.
//!
//! # The two proofs, and why both are gated
//!
//! [`an_executed_run_reaches_a_terminal_state_the_runs_lane_reports`] needs a
//! host that can actually enforce the composed sandbox: a delegated cgroup v2
//! domain that can distribute the `pids` and `memory` controllers, the Landlock
//! and seccomp mechanisms the capability probe requires, and the built entry
//! helper. Outside such a host it reports what is missing and returns, and
//! `AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1` turns that into a failure so a
//! verifying host cannot quietly skip it:
//!
//! ```sh
//! cd rust
//! cargo build -p automonique-runner --bin automonique-launch-enter
//! cargo test -p automonique-daemon --test execute_live --no-run
//! systemd-run --user --scope -p Delegate=yes \
//!   --setenv=AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1 \
//!   "$(ls -t target/debug/deps/execute_live-* | grep -v '\.d$' | head -1)" \
//!   --test-threads=1 --nocapture
//! ```
//!
//! Two things about that command are not incidental, and both were established
//! by running it:
//!
//! - **The helper is built separately.** Cargo builds a dependency's *library*
//!   for this crate's tests and never its binaries, so
//!   `automonique-launch-enter` — the process that installs the sandbox and
//!   becomes the workload — must be asked for by name. Without it the lane has
//!   no helper and refuses `launch_helper_unavailable`.
//! - **The scope wraps the test binary, not `cargo test`.** Wrapping cargo
//!   leaves cargo itself a direct member of the delegated scope, and cgroup v2
//!   forbids enabling `subtree_control` on a cgroup that holds member
//!   processes. The daemon's domain preparation then fails and every request
//!   answers `containment_unavailable`, so the proof would silently degrade to
//!   the fail-closed one. (The same limitation is why
//!   `automonique-runner`'s own `admission` proof reports "the domain cannot
//!   distribute pids, memory and CPU" when it is run through cargo under a scope.)
//!
//! `--test-threads=1` is required for a third reason: preparing a delegated
//! domain moves *this process* into a supervisor leaf, and two daemons doing
//! that concurrently would race over one cgroup tree.
//!
//! [`a_host_that_cannot_contain_refuses_and_executes_nothing`] is the mirror
//! image and is gated the *other* way: it proves the fail-closed refusal, so it
//! is meaningful exactly on a host that cannot execute, and it skips loudly on
//! one that can. Between them the two tests cover every host — and neither can
//! pass by accident on the other's, because each asserts a different answer to
//! the same request.
//!
//! # Anti-vacuity
//!
//! Both tests submit the same document and send the same request. The enforced
//! proof asserts a `completed` run whose workload left a witness file
//! containing the exact prompt bytes; the fail-closed proof asserts a typed
//! refusal, a read-model row still at `ready`, and **no spool directory at
//! all**. A lane that answered the same way in both cases would fail one of
//! them.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use automonique_daemon::execute::{
    DAEMON_WORKSPACE_REGISTRY, locate_launch_helper, offered_host_features,
};
use automonique_daemon::{Daemon, DaemonConfig};
use automonique_protocol::admin::{
    AdminCommand, AdminRequest, AdminResponse, IntakePause, SubmittedRunSpec,
};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_protocol::context::{ContextManifest, TokenBudget};
use automonique_protocol::digest::Sha256;
use automonique_protocol::execute_api::{CancelRequestRef, CancelRunOutcome};
use automonique_protocol::execute_api::{ExecuteRefusal, ExecuteRequest, ExecuteResponse};
use automonique_protocol::host::{AttemptId, HostId, HostLifetime, WorkId};
use automonique_protocol::identity::Actor;
use automonique_protocol::models::{ExecutorClass, ProviderAccountId};
use automonique_protocol::platform::{
    ClientId, IdempotencyKey, PlatformAction, PlatformRequest, PlatformResponse, ReceiptOutcome,
    ResourceAuthority, ResourceCoordinate, ResourceId, ResourceKind, SessionCommandStateRequest,
    SessionRunStopRequest,
};
use automonique_protocol::platform_api::{PlatformRequestMessage, PlatformResponseMessage};
use automonique_protocol::primitives::Revision;
use automonique_protocol::provider::BinaryProvenance;
use automonique_protocol::runs_api::{
    LifecycleCoverage, ListRuns, PageSize, RunState, RunStateFilter, RunsRequest, RunsResponse,
    SpoolEventKind,
};
use automonique_protocol::sandbox::{
    BudgetQuantities, Budgets, CredentialDescriptors, ExecutionAllowlists, ExecutionBackendId,
    FilesystemAccess, ImplementationDigest, IsolationRequirement, NestedIsolation, PathGrants,
    PolicyDigest, ProhibitedCapabilities, ProviderControlEgress, RequiredFeature, RequiredFeatures,
    SandboxProfile, SandboxSpec, SandboxSpecParts, ToolWorkloadEgress, WorkspaceContextHash,
};
use automonique_protocol::tools::RunId;
use automonique_protocol::workspace::{IsolationKind, WorkspaceRegistration, WorkspaceToken};
use automonique_runner::capability::HostCapabilities;
use automonique_runner::control::{CancelDelivery, CancelSink, CancelSinkError};
use automonique_runner::dispatch::RegistrationHandle;
use automonique_runner::{
    AdmissionFields, AdmissionFieldsParts, ArtifactGrantBindings, Authority, ContainmentDomain,
    CwdToken, EventKind, ExecutionPlanDigest, ExtensionSetDigest, FallbackEligibility,
    IntegrationMode, IoReservation, ModelRoutingDigest, PersonaDigest, PortabilityPolicy,
    ProfileDigest, PromptDeliveryPlan, ProtectedPromptReference, RemoteAttestationPolicy,
    RequiredCapabilities, RunCoordinates, RunOrigin, RunSpec, RunSpecParts, RunnerEventDialect,
    SchedulerDecisionDigest, SchedulerReservationBinding, SchedulerReservationId, SkillsetDigest,
    Spool, ToolsetDigest, WorkspaceRegistryId, WorkspaceReservation,
};
use automonique_store::cancel_ledger::CancelLedger;

const BUSYBOX: &str = "/usr/bin/busybox";
const REQUIRE_ENFORCED_ENV: &str = "AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT";
const PROMPT_SLOT: &str = "execute-prompt-slot";
const PROMPT: &[u8] = b"the prompt the workload copies\n";
const MEMORY_BYTES: u64 = 128 * 1024 * 1024;
const PROCESSES: u64 = 64;
const TIMEOUT_MILLIS: u64 = 30_000;
const SPOOL_BYTES: u64 = 1024 * 1024;
/// Ceiling the test re-opens a finished spool under; well above `SPOOL_BYTES`.
const READ_SPOOL_BYTES: u64 = 8 * 1024 * 1024;
/// Bound on waiting for a run to reach a terminal state, comfortably above the
/// document's own 30-second timeout, which the backend enforces.
const TERMINAL_DEADLINE: Duration = Duration::from_secs(90);

// --- host gating ----------------------------------------------------------

/// Whether the capability probe says this host can enforce the composed
/// sandbox.
///
/// Exactly the four properties `Daemon::measure_execution_state` asks for, so
/// this test agrees with the daemon by asking the same question rather than by
/// assuming the answer.
fn sandbox_enforceable() -> bool {
    HostCapabilities::probe()
        .select_mode(&automonique_daemon::execute::ENFORCED_PROPERTIES)
        .is_ok()
}

/// The first gate this host fails, or `None` when it fails none.
///
/// Derived from the same public surfaces the lane consults, in the same order,
/// so the fail-closed proof asserts the *exact* refusal rather than any refusal.
fn first_failing_gate() -> Option<ExecuteRefusal> {
    if !sandbox_enforceable() {
        return Some(ExecuteRefusal::SandboxUnenforceable);
    }
    if locate_launch_helper().is_none() {
        return Some(ExecuteRefusal::LaunchHelperUnavailable);
    }
    if ContainmentDomain::discover().is_err() {
        return Some(ExecuteRefusal::ContainmentUnavailable);
    }
    None
}

/// Report a proof that could not run, and fail when the host promised it could.
fn not_proven(test: &str, reason: &str) {
    assert!(
        std::env::var_os(REQUIRE_ENFORCED_ENV).is_none(),
        "{test}: {REQUIRE_ENFORCED_ENV} is set but this host cannot prove it: {reason}"
    );
    eprintln!("[execute_live] NOT PROVEN: {test}: {reason}");
}

// --- daemon harness -------------------------------------------------------

/// A private root, with the daemon's state directory and its prompt slot
/// already in place.
///
/// The slot is written before the daemon opens because there is no lane that
/// writes one: prompt slots are the daemon's own protected input, and this test
/// stands in for whatever fills them.
fn fixture() -> (tempfile::TempDir, DaemonConfig) {
    let root = tempfile::tempdir().expect("temporary root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private root");
    let runtime = root.path().join("runtime");
    let state = root.path().join("state");
    for directory in [&runtime, &state] {
        std::fs::create_dir(directory).expect("root");
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .expect("private root");
    }
    let state_dir = state.join("automonique");
    let prompts = state_dir.join("prompts");
    std::fs::create_dir(&state_dir).expect("state directory");
    std::fs::create_dir(&prompts).expect("prompt directory");
    for directory in [&state_dir, &prompts] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
    }
    std::fs::write(prompts.join(PROMPT_SLOT), PROMPT).expect("prompt slot");
    std::fs::set_permissions(
        prompts.join(PROMPT_SLOT),
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("private slot");
    (
        root,
        DaemonConfig {
            runtime_root: runtime,
            state_root: state,
        },
    )
}

fn exchange(config: &DaemonConfig, payload: &[u8]) -> Option<Vec<u8>> {
    let mut stream = UnixStream::connect(config.admin_socket()).expect("connect to daemon");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("read deadline");
    let mut frame = Vec::new();
    encode_frame(payload, &mut frame).expect("frame request");
    stream.write_all(&frame).expect("write request");
    let mut prefix = [0_u8; 4];
    if stream.read_exact(&mut prefix).is_err() {
        return None;
    }
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
    Some(payload.to_vec())
}

fn admin(config: &DaemonConfig, request: AdminRequest) -> AdminResponse {
    let payload = request
        .to_message()
        .expect("encode request")
        .to_canonical_bytes();
    let response = exchange(config, &payload).expect("the admin lane answered");
    AdminResponse::from_canonical_bytes(&response).expect("admitted response")
}

/// Ask the Execute lane to start one run, over the same socket.
///
/// The answer is required to carry the request's own correlation identifier: an
/// answer to somebody else's question would otherwise pass every assertion.
fn execute(config: &DaemonConfig, label: &str, run: &str) -> ExecuteResponse {
    let request = ExecuteRequest::ExecuteRun {
        request_id: RequestId::new(label).expect("request ID"),
        run_id: RunId::new(run).expect("run identity"),
    };
    let payload = request
        .to_message()
        .expect("encode execute request")
        .to_canonical_bytes();
    let response = exchange(config, &payload).expect("the execute lane answered");
    let response =
        ExecuteResponse::from_canonical_bytes(&response).expect("admitted execute response");
    assert_eq!(
        response.request_id().as_str(),
        request.request_id().as_str(),
        "the answer was not correlated to the question",
    );
    response
}

fn runs(config: &DaemonConfig, request: &RunsRequest) -> RunsResponse {
    let payload = request
        .to_message()
        .expect("encode runs request")
        .to_canonical_bytes();
    let response = exchange(config, &payload).expect("the runs lane answered");
    RunsResponse::from_canonical_bytes(&response).expect("admitted runs response")
}

/// The state the Runs listing reports for one run right now.
fn listed_state(config: &DaemonConfig, label: &str, run: &str) -> RunState {
    let response = runs(
        config,
        &RunsRequest::ListRuns {
            request_id: RequestId::new(label).expect("request ID"),
            query: ListRuns::new(RunStateFilter::any(), None, PageSize::MAX),
        },
    );
    let RunsResponse::RunList { page, .. } = response else {
        panic!("expected a page, got {response:?}")
    };
    page.runs()
        .iter()
        .find(|summary| summary.run_id().as_str() == run)
        .unwrap_or_else(|| panic!("{run} is not listed"))
        .state()
}

/// Poll the Runs lane until the run has ended, or fail on the deadline.
///
/// The listing is the poll target on purpose: it never opens a spool, so it
/// answers while the attempt still holds the spool's exclusive lock.
fn await_terminal(config: &DaemonConfig, run: &str) -> RunState {
    let deadline = Instant::now() + TERMINAL_DEADLINE;
    loop {
        let state = listed_state(config, "await-terminal", run);
        if state.is_terminal() {
            return state;
        }
        assert!(
            Instant::now() < deadline,
            "{run} did not reach a terminal state; last seen {state}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_socket(config: &DaemonConfig) {
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
                AdminRequest::new(
                    RequestId::new("shutdown").expect("request ID"),
                    AdminCommand::Shutdown,
                ),
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

// --- a document this daemon's admission accepts ---------------------------

fn digest_text(digit: char) -> String {
    format!("sha256:{}", digit.to_string().repeat(64))
}

/// The pin the document carries for the program it runs.
///
/// Hashed from the file on disk, because the lane hashes the same file and
/// compares. A hard-coded digest would make the document unrunnable on any host
/// whose busybox differs, and — worse — would make the comparison untestable.
fn provider_binary() -> BinaryProvenance {
    let bytes = std::fs::read(BUSYBOX).expect("busybox is readable");
    BinaryProvenance::new(
        "busybox",
        &format!("sha256:{}", Sha256::digest(&bytes).to_hex()),
        // No schema digest: this daemon speaks no provider protocol, so it can
        // observe none, and a document that pinned one would be refused.
        None,
    )
    .expect("observed provenance")
}

/// What the document requires of the host's enforcement.
///
/// Pinned from what this daemon actually offers, which is what a reviewing
/// client does: it records the composition it reviewed. A hard-coded digest
/// would be a different test — of this file's copy of the derivation rather
/// than of the negotiation — and
/// [`a_document_pinning_another_composition_is_refused`] is where the negative
/// is proved.
///
/// On a host that offers nothing, one placeholder is required instead: the
/// document must still declare a feature (`RequiredFeatures` refuses an empty
/// set), and on such a host the request never reaches the negotiation because
/// a host-wide gate refuses first.
fn required_features() -> RequiredFeatures {
    let offered = offered_host_features();
    if offered.is_empty() {
        return RequiredFeatures::declare(&[RequiredFeature::new(
            "descendant_containment",
            &[ImplementationDigest::parse(&digest_text('3')).expect("digest")],
        )
        .expect("feature")])
        .expect("features");
    }
    let required: Vec<RequiredFeature> = offered
        .iter()
        .map(|feature| {
            RequiredFeature::new(
                feature.name(),
                std::slice::from_ref(feature.implementation()),
            )
            .expect("feature")
        })
        .collect();
    RequiredFeatures::declare(&required).expect("features")
}

fn sandbox() -> SandboxSpec {
    sandbox_requiring(required_features())
}

fn sandbox_requiring(required_features: RequiredFeatures) -> SandboxSpec {
    SandboxSpec::compile(SandboxSpecParts {
        profile: SandboxProfile::new(
            "execute-profile",
            1,
            FilesystemAccess::IsolatedWritable,
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
        // Both egress axes denied: admission refuses anything else, because the
        // broker that would carry brokered egress does not exist.
        provider_control_egress: ProviderControlEgress::denied(),
        tool_workload_egress: ToolWorkloadEgress::denied(),
        credentials: CredentialDescriptors::declare(&[]).expect("credentials"),
        budgets: Budgets::declare(BudgetQuantities {
            cgroup_memory_bytes: MEMORY_BYTES,
            cgroup_cpu_millicores: 1_000,
            rlimit_processes: PROCESSES,
            rlimit_descriptors: 256,
            timeout_millis: TIMEOUT_MILLIS,
            temporary_storage_bytes: 1024 * 1024,
            spool_bytes: SPOOL_BYTES,
            artifact_bytes: 1024 * 1024,
        })
        .expect("budgets"),
        required_features,
        nested_isolation: NestedIsolation::new(
            IsolationRequirement::HostBoundary,
            IsolationRequirement::HostBoundary,
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
        workspace_reservation: WorkspaceReservation::new(8_192).expect("workspace bytes"),
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

/// One document naming `run`, whose workload runs `script`.
fn run_spec(run: &str, script: &str) -> RunSpec {
    run_spec_with_sandbox(run, script, sandbox())
}

fn run_spec_with_sandbox(run: &str, script: &str, sandbox: SandboxSpec) -> RunSpec {
    RunSpec::new(RunSpecParts {
        protocol_version: 1,
        coordinates: RunCoordinates::new(
            WorkId::new("work-1").expect("work"),
            RunId::new(run).expect("run"),
            AttemptId::new(format!("{run}-attempt-1")).expect("attempt"),
            HostId::new("host-1").expect("host"),
            HostLifetime::Attempt,
            ExecutionBackendId::new("local-direct").expect("backend"),
        ),
        executable: PathBuf::from(BUSYBOX),
        arguments: vec!["sh".into(), "-c".into(), script.into()],
        cwd_token: CwdToken::new("cwd-1").expect("cwd"),
        environment: Vec::new(),
        prompt: PromptDeliveryPlan::ProtectedReference(
            ProtectedPromptReference::new(PROMPT_SLOT).expect("slot"),
        ),
        // The one registry identity this daemon resolves. Any other is refused.
        workspace_registry_id: WorkspaceRegistryId::new(DAEMON_WORKSPACE_REGISTRY)
            .expect("registry"),
        workspace: WorkspaceRegistration::new(
            "acme",
            "source-1",
            Revision::new(7).expect("revision"),
            "snapshot-1",
            IsolationKind::AttemptCopy,
            WorkspaceToken::new("workspace-token-1").expect("token"),
        )
        .expect("registered workspace"),
        provider_binary: provider_binary(),
        sandbox,
        admission: admission(),
    })
    .expect("valid run specification")
}

/// Submit one document and return the durable identity custody assigned.
fn submit(config: &DaemonConfig, spec: &RunSpec, key: &str) -> u64 {
    let document = spec.to_canonical_bytes().expect("canonical encoding");
    let submission = SubmittedRunSpec::sealed(document, key).expect("bounded submission");
    let response = admin(
        config,
        AdminRequest::submit_run(RequestId::new(key).expect("request ID"), submission),
    );
    let AdminResponse::RunAccepted {
        submission_id,
        replay,
        ..
    } = response
    else {
        panic!("expected acceptance, got {response:?}")
    };
    assert!(!replay, "{key} was already held");
    submission_id
}

/// Where the daemon keeps one run's authoritative spool.
fn spool_root(config: &DaemonConfig, run: &str) -> PathBuf {
    config.state_dir().join("runs").join(run).join("spool")
}

/// Where the daemon resolves one run's workspace.
fn workspace_root(config: &DaemonConfig, run: &str) -> PathBuf {
    config.state_dir().join("runs").join(run).join("workspace")
}

// --- the proofs -----------------------------------------------------------

/// A submitted document, started over the wire, runs contained and ends.
#[test]
fn an_executed_run_reaches_a_terminal_state_the_runs_lane_reports() {
    let test = "an_executed_run_reaches_a_terminal_state_the_runs_lane_reports";
    if !Path::new(BUSYBOX).exists() {
        not_proven(test, "no static busybox at /usr/bin/busybox");
        return;
    }
    if let Some(gate) = first_failing_gate() {
        not_proven(test, &format!("this host refuses at {gate}"));
        return;
    }

    let (_root, config) = fixture();
    let run = "execlive1";
    // The workload copies its own stdin — which is the admitted prompt — into
    // the workspace the daemon resolved for it. Every command is the granted
    // busybox by absolute path: the admitted plan grants execute on exactly the
    // program the document named and on nothing else.
    let witness = workspace_root(&config, run).join("witness.txt");
    let script = format!("{BUSYBOX} cat > {}", witness.display());
    let spec = run_spec(run, &script);

    let serving = serve(&config);
    let submission_id = submit(&config, &spec, "execute-submit-1");
    assert_eq!(
        listed_state(&config, "before", run),
        RunState::Ready,
        "custody alone must not move the read model"
    );

    let response = execute(&config, "execute-1", run);
    let ExecuteResponse::Accepted {
        run_id,
        submission_id: accepted_submission,
        ..
    } = &response
    else {
        panic!("expected the run to start, got {response:?}")
    };
    assert_eq!(run_id.as_str(), run);
    assert_eq!(
        *accepted_submission, submission_id,
        "the answer must name the custody row the attempt was started from"
    );

    let terminal = await_terminal(&config, run);
    assert_eq!(
        terminal,
        RunState::Completed,
        "the workload exited zero, so the run completed"
    );

    // THE WORKLOAD REALLY RAN, AND THE PROMPT REALLY REACHED IT.
    //
    // The witness is written by the contained process itself, inside the
    // workspace grant, and its content is the prompt the daemon resolved from
    // its slot and admission delivered on stdin.
    assert_eq!(
        std::fs::read(&witness).expect("the workload wrote its witness"),
        PROMPT,
        "the admitted prompt must reach the workload unaltered"
    );

    // THE DURABLE RECORD IS THE RUNNER'S, RE-VERIFIED FROM DISK.
    //
    // Re-opening re-parses and re-checks the hash chain, so these assertions
    // are made against a record that was intact after the run rather than
    // against the daemon's belief about it.
    let spool = Spool::open(spool_root(&config, run), run, READ_SPOOL_BYTES)
        .expect("the run's spool re-opens");
    let events = spool.events_after(0).expect("the spool replays");
    assert_eq!(events.len(), 2, "one Started and one Terminal: {events:?}");
    assert_eq!(events[0].kind(), EventKind::Started);
    assert_eq!(events[0].authority(), Authority::Authoritative);
    assert_eq!(events[1].kind(), EventKind::Terminal);
    assert_eq!(events[1].authority(), Authority::Authoritative);
    assert_eq!(events[1].payload(), b"completed");
    drop(spool);

    // The Runs detail lane serves that same lifecycle back over the socket.
    let detail = runs(
        &config,
        &RunsRequest::RunDetail {
            request_id: RequestId::new("detail-1").expect("request ID"),
            run_id: RunId::new(run).expect("run identity"),
        },
    );
    let RunsResponse::RunDetail { view, .. } = detail else {
        panic!("expected a detail view, got {detail:?}")
    };
    assert_eq!(view.summary().state(), RunState::Completed);
    assert_eq!(view.summary().submission_id(), submission_id);
    assert_eq!(view.last_sequence(), 2);
    assert_eq!(view.coverage(), LifecycleCoverage::Complete);
    assert_eq!(
        view.lifecycle()
            .iter()
            .map(|event| event.kind())
            .collect::<Vec<_>>(),
        vec![SpoolEventKind::Started, SpoolEventKind::Terminal],
    );

    // ONE ATTEMPT PER SUBMISSION, AND THE ROW IS WHAT ENFORCES IT.
    //
    // The read model has moved off `ready`, so a second request for the same
    // run is refused rather than starting a second attempt over the same spool.
    let repeat = execute(&config, "execute-2", run);
    assert!(
        matches!(
            repeat,
            ExecuteResponse::Refused {
                refusal: ExecuteRefusal::RunNotReady,
                ..
            }
        ),
        "expected run_not_ready, got {repeat:?}"
    );

    serving.shutdown(&config);
}

/// A document that pins an enforcement composition this host does not provide
/// is refused, on the very host that would otherwise have run it.
///
/// The negative control for [`required_features`]: without it, the enforced
/// proof would pass just as well against a daemon that ignored the document's
/// enforcement negotiation entirely.
#[test]
fn a_document_pinning_another_composition_is_refused() {
    let test = "a_document_pinning_another_composition_is_refused";
    if !Path::new(BUSYBOX).exists() {
        not_proven(test, "no static busybox at /usr/bin/busybox");
        return;
    }
    if let Some(gate) = first_failing_gate() {
        not_proven(test, &format!("this host refuses at {gate}"));
        return;
    }

    let (_root, config) = fixture();
    let run = "execpinned1";
    let witness = workspace_root(&config, run).join("witness.txt");
    let script = format!("{BUSYBOX} cat > {}", witness.display());
    // The same feature *name* this host offers, pinned to an implementation
    // digest it does not publish. Everything else about the document is the one
    // the enforced proof runs.
    let stranger = RequiredFeatures::declare(&[RequiredFeature::new(
        "descendant_containment",
        &[ImplementationDigest::parse(&digest_text('e')).expect("digest")],
    )
    .expect("feature")])
    .expect("features");
    let spec = run_spec_with_sandbox(run, &script, sandbox_requiring(stranger));

    let serving = serve(&config);
    submit(&config, &spec, "execute-pinned-1");
    let response = execute(&config, "execute-pinned-1", run);
    assert!(
        matches!(
            &response,
            ExecuteResponse::Refused {
                refusal: ExecuteRefusal::AdmissionRefused,
                ..
            }
        ),
        "expected admission_refused, got {response:?}"
    );
    assert!(
        !spool_root(&config, run).exists(),
        "a refused admission must leave no spool"
    );
    assert!(
        !witness.exists(),
        "a refused admission must run no workload"
    );
    assert_eq!(
        listed_state(&config, "after-pin-refusal", run),
        RunState::Ready
    );

    serving.shutdown(&config);
}

/// A configured approval requirement stops a headless launch and says why.
///
/// Not gated on the host, because both branches are proofs of the same
/// composition and the composition is the thing under test:
///
/// - on a host that can enforce the sandbox, the configured
///   `approval_required` is the strictest source, no operator surface is live
///   in this fixture — no Telegram poller, no Slack, and the CLI peer is gone
///   by the time the gate runs — so the answer is `approval_unreachable`;
/// - on a host that cannot, the *measured* source is `Forbidden` and outranks
///   the configured one, so the answer is the lane's own word for that host.
///
/// A build that read the configuration and skipped the measurement would pass
/// the first branch and fail the second; one that read the measurement and
/// ignored the configuration would fail the first. Neither branch can pass by
/// accident on the other's host.
#[test]
fn a_configured_approval_requirement_refuses_a_headless_launch_and_records_it() {
    let (_root, config) = fixture();
    let approvals = config.state_dir().join("approvals");
    std::fs::create_dir(&approvals).expect("approval configuration directory");
    std::fs::set_permissions(&approvals, std::fs::Permissions::from_mode(0o700))
        .expect("private directory");
    let policy = approvals.join("approvals.conf");
    std::fs::write(
        &policy,
        "schema=automonique.approvals/v1\n\
         requirement=approval_required\n\
         end=automonique.approvals/v1\n",
    )
    .expect("approval configuration");
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600))
        .expect("private configuration");

    let run = "execappr1";
    let witness = workspace_root(&config, run).join("witness.txt");
    let script = format!("{BUSYBOX} cat > {}", witness.display());
    let spec = run_spec(run, &script);
    let digest = Sha256::digest(&spec.to_canonical_bytes().expect("canonical encoding")).to_hex();

    let serving = serve(&config);
    submit(&config, &spec, "execute-approval-1");

    let expected = if sandbox_enforceable() {
        ExecuteRefusal::ApprovalUnreachable
    } else {
        ExecuteRefusal::SandboxUnenforceable
    };
    let response = execute(&config, "execute-approval-1", run);
    assert!(
        matches!(
            &response,
            ExecuteResponse::Refused { refusal, .. } if *refusal == expected
        ),
        "expected {expected}, got {response:?}"
    );

    // Nothing started, and the read model did not move.
    assert_eq!(
        listed_state(&config, "after-approval-refusal", run),
        RunState::Ready,
        "a refused request must not move the read model"
    );
    assert!(
        !spool_root(&config, run).exists(),
        "a refused request must leave no spool"
    );
    assert!(!witness.exists(), "a refused request must run no workload");

    serving.shutdown(&config);

    // The refusal is in the hash chain, as a denial about the document rather
    // than about the run identifier that named it: two runs of the same bytes
    // are one thing to approve.
    let chain = automonique_store::audit_chain::AuditChain::open(config.audit_chain_path())
        .expect("audit chain opens");
    let page = chain.page(0, 16).expect("a page of records");
    let record = page
        .entries
        .iter()
        .find(|entry| entry.subject == format!("runspec:{digest}"))
        .expect("a record about the document that was refused");
    assert_eq!(record.category, "approval");
    assert_eq!(record.outcome, "denied");
    assert_eq!(record.surface, expected.as_str());
    assert_eq!(
        chain
            .verify_structure()
            .expect("a structurally sound chain"),
        u64::try_from(page.entries.len()).expect("a small chain"),
    );
}

/// A host that cannot contain refuses, and starts nothing at all.
#[test]
fn a_host_that_cannot_contain_refuses_and_executes_nothing() {
    let test = "a_host_that_cannot_contain_refuses_and_executes_nothing";
    if !Path::new(BUSYBOX).exists() {
        not_proven(test, "no static busybox at /usr/bin/busybox");
        return;
    }
    let Some(expected) = first_failing_gate() else {
        // Gated the other way round from the enforced proof: this one is
        // meaningful exactly where execution is impossible. A host that can
        // execute proves it in the other test, and there is nothing to assert
        // here — so this reports and returns, and it does so even under
        // `AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT`, which asks for the
        // *enforced* proof rather than this one.
        eprintln!(
            "[execute_live] NOT PROVEN: {test}: this host can execute, so no fail-closed \
             refusal is reachable"
        );
        return;
    };
    assert!(
        expected.is_host_wide(),
        "a gate that stops every run must be a host-wide refusal, not {expected}"
    );

    let (_root, config) = fixture();
    let run = "execclosed1";
    let witness = workspace_root(&config, run).join("witness.txt");
    let script = format!("{BUSYBOX} cat > {}", witness.display());
    let spec = run_spec(run, &script);

    let serving = serve(&config);
    submit(&config, &spec, "execute-closed-1");

    let response = execute(&config, "execute-closed-1", run);
    assert!(
        matches!(
            &response,
            ExecuteResponse::Refused { refusal, .. } if *refusal == expected
        ),
        "expected {expected}, got {response:?}"
    );

    // NOTHING RAN, AND NOTHING WAS WRITTEN.
    //
    // Three independent witnesses, because a refusal that had still created
    // kernel or filesystem state would be a partial execution wearing a
    // refusal's answer.
    assert_eq!(
        listed_state(&config, "after-refusal", run),
        RunState::Ready,
        "a refused request must not move the read model"
    );
    assert!(
        !spool_root(&config, run).exists(),
        "a refused request must leave no spool"
    );
    assert!(!witness.exists(), "a refused request must run no workload");

    serving.shutdown(&config);
}

// --- the cancel verb ------------------------------------------------------
//
// These proofs are **not** host-gated, unlike the two above, and that is the
// point of how they are built. `Daemon::cancel_run` resolves a run to the
// attempt its custodied document declares and hands the request to the host's
// one dispatcher; none of that needs a delegated cgroup domain, a sandbox, or a
// workload. So the attempt is registered directly against the daemon's own
// attempt host before the daemon starts serving — the same host
// `execute::ExecutionLane` registers against — and every one of these tests
// runs on every host.
//
// What that costs is stated rather than hidden: these prove the *lane*, not the
// kill. That a delivered cancellation reaches a real process tree is
// `automonique-runner`'s containment proof, and that the run then reaches a
// terminal state is `an_executed_run_reaches_a_terminal_state_the_runs_lane_reports`.

/// A cancellation sink that counts what reached it.
struct CountingSink {
    attempt_id: String,
    deliveries: Arc<AtomicUsize>,
}

impl CancelSink for CountingSink {
    fn deliver(
        &self,
        attempt_id: &str,
        _request_ref: &str,
    ) -> Result<CancelDelivery, CancelSinkError> {
        assert_eq!(
            attempt_id, self.attempt_id,
            "a dispatch must only ever reach its own registration's sink"
        );
        self.deliveries.fetch_add(1, Ordering::Release);
        Ok(CancelDelivery::Accepted)
    }
}

/// Serve a daemon with one attempt already registered on its host.
///
/// The registration is taken before the daemon is moved onto the serve thread,
/// which is possible because a `RegistrationHandle` holds the dispatcher weakly
/// rather than borrowing the host. Dropping the handle unregisters, so the
/// caller keeps it for as long as the attempt is meant to be live.
fn serve_with_attempt(
    config: &DaemonConfig,
    attempt_id: &str,
) -> (Serving, Arc<AtomicUsize>, RegistrationHandle) {
    let daemon = Daemon::open(config).expect("daemon opens");
    let deliveries = Arc::new(AtomicUsize::new(0));
    let registration = daemon
        .attempt_host()
        .expect("an opened daemon owns its attempt host")
        .register(
            attempt_id,
            Box::new(CountingSink {
                attempt_id: attempt_id.to_owned(),
                deliveries: Arc::clone(&deliveries),
            }),
        )
        .expect("register the attempt");
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&thread_stop));
    wait_for_socket(config);
    (
        Serving {
            stop,
            thread: Some(thread),
        },
        deliveries,
        registration,
    )
}

/// Ask the Execute lane to cancel one run, over the same socket.
fn cancel(
    config: &DaemonConfig,
    label: &str,
    run: &str,
    request_ref: &str,
    observed_sequence: u64,
) -> ExecuteResponse {
    let request = ExecuteRequest::CancelRun {
        request_id: RequestId::new(label).expect("request ID"),
        run_id: RunId::new(run).expect("run identity"),
        request_ref: CancelRequestRef::new(request_ref).expect("reference"),
        observed_sequence,
    };
    let payload = request
        .to_message()
        .expect("encode cancel request")
        .to_canonical_bytes();
    let response = exchange(config, &payload).expect("the execute lane answered");
    let response =
        ExecuteResponse::from_canonical_bytes(&response).expect("admitted execute response");
    assert_eq!(
        response.request_id().as_str(),
        request.request_id().as_str(),
        "the answer was not correlated to the question",
    );
    response
}

/// The outcome of a cancellation that must have reached the ledger.
fn delivered(response: ExecuteResponse) -> CancelRunOutcome {
    match response {
        ExecuteResponse::Cancelled { outcome, .. } => outcome,
        other => panic!("expected a cancellation result, got {other:?}"),
    }
}

/// The refusal of a cancellation that must not have reached the ledger.
fn refusal(response: ExecuteResponse) -> ExecuteRefusal {
    match response {
        ExecuteResponse::Refused { refusal, .. } => refusal,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Every recorded reference for one attempt, read from the durable ledger with
/// the daemon stopped.
fn recorded(config: &DaemonConfig, attempt_id: &str) -> Vec<(String, u64)> {
    let ledger = CancelLedger::open(config.run_cancel_ledger_path()).expect("open ledger");
    ledger
        .attempt_requests(attempt_id)
        .expect("read")
        .into_iter()
        .map(|entry| (entry.request_ref, entry.observed_sequence))
        .collect()
}

/// A cancellation is delivered once, and every replay of its reference is
/// answered without a second delivery.
///
/// The three answers are asserted from both sides: what the lane said, and what
/// the sink and the durable ledger hold afterwards. An implementation that
/// answered `already_delivered` while calling the sink again would satisfy only
/// the first half.
#[test]
fn a_cancellation_is_delivered_once_and_its_replays_deliver_nothing() {
    let (_root, config) = fixture();
    let run = "run-cancel-once";
    let attempt = format!("{run}-attempt-1");
    let spec = run_spec(run, "true");

    let (serving, deliveries, registration) = serve_with_attempt(&config, &attempt);
    submit(&config, &spec, "cancel-once");

    let first = delivered(cancel(&config, "cancel-1", run, "ref-a", 3));
    assert_eq!(first, CancelRunOutcome::Delivered);
    assert_eq!(deliveries.load(Ordering::Acquire), 1);

    // An exact retry: same reference, same claimed sequence.
    let replay = delivered(cancel(&config, "cancel-2", run, "ref-a", 3));
    assert_eq!(replay, CancelRunOutcome::AlreadyDelivered);
    assert_eq!(
        deliveries.load(Ordering::Acquire),
        1,
        "a replay must not reach the sink a second time"
    );

    // The same reference against a different claimed sequence is a conflict.
    // Nothing is delivered and nothing is rewritten.
    let conflict = delivered(cancel(&config, "cancel-3", run, "ref-a", 9));
    assert_eq!(conflict, CancelRunOutcome::Conflict);
    assert_eq!(deliveries.load(Ordering::Acquire), 1);

    drop(registration);
    serving.shutdown(&config);

    assert_eq!(
        recorded(&config, &attempt),
        vec![("ref-a".to_owned(), 3)],
        "one reference, recorded once, at the sequence the first delivery claimed"
    );
}

/// A mobile stop names the run of the turn that is running, and it is delivered.
///
/// #145: before turn-start binding, a managed session's binding advanced only
/// when a run *finished*, so the only run a session could ever name was one that
/// had already ended and every exact-run stop was answered `rejected`. Here the
/// binding names the run while it is in flight, and the stop travels the whole
/// admitted path — session ownership, exact run, both revisions, idempotency
/// key — into the same dispatcher a `CancelRun` reaches.
///
/// It is proved in this file rather than beside the other session-surface
/// proofs because delivery is what is at stake: the assertion is that the sink
/// registered for this run's attempt was called, and that the durable cancel
/// ledger holds the reference. As with every proof in this section, that a
/// delivered cancellation ends a real process tree is `automonique-runner`'s
/// containment proof, not this one.
#[test]
fn a_session_stop_reaches_the_in_flight_runs_attempt_and_is_idempotent() {
    let (_root, config) = fixture();
    let run = "run-session-stop";
    let attempt = format!("{run}-attempt-1");
    let spec = run_spec(run, "true");
    let session_id = "session-stop-1";

    let (serving, deliveries, registration) = serve_with_attempt(&config, &attempt);
    submit(&config, &spec, "session-stop");

    let mut sessions = automonique_daemon::managed_sessions::ManagedSessionStore::open(
        config.managed_sessions_path(),
    )
    .expect("managed sessions");
    sessions
        .observe_active(session_id, run, 100)
        .expect("the turn binds its run at start");
    drop(sessions);

    let session = platform_coordinate(ResourceKind::Session, session_id);
    let state = command_state(&config, "stop-command-state", &session);
    assert_eq!(
        state
            .run
            .as_ref()
            .expect("in-flight run")
            .target
            .id
            .as_str(),
        run,
        "the session names the run it is running"
    );

    let request = SessionRunStopRequest {
        client: ClientId::new("mobile-credential-stop").expect("client"),
        session: session.clone(),
        expected_session_revision: Revision::FIRST,
        run: platform_coordinate(ResourceKind::Run, run),
        expected_run_revision: Revision::FIRST,
        idempotency_key: IdempotencyKey::new("session-run-stop").expect("key"),
    };
    let PlatformResponse::Receipt(receipt) = platform(
        &config,
        "session-run-stop",
        PlatformRequest::SessionRunStop(request.clone()),
    ) else {
        panic!("a stop on the in-flight run must be admitted")
    };
    assert_eq!(receipt.action, PlatformAction::StopRun);
    assert_eq!(receipt.target.id.as_str(), run);
    assert_eq!(
        receipt.outcome,
        ReceiptOutcome::Completed,
        "the stop was delivered, not rejected as a terminal run"
    );
    assert_eq!(
        deliveries.load(Ordering::Acquire),
        1,
        "the cancellation reached the running attempt's sink"
    );

    let PlatformResponse::Receipt(replay) = platform(
        &config,
        "session-run-stop-replay",
        PlatformRequest::SessionRunStop(request),
    ) else {
        panic!("replay receipt")
    };
    assert_eq!(replay, receipt);
    assert_eq!(
        deliveries.load(Ordering::Acquire),
        1,
        "a replay must not reach the sink a second time"
    );

    drop(registration);
    serving.shutdown(&config);
    assert_eq!(
        recorded(&config, &attempt).len(),
        1,
        "one reference, recorded once"
    );
}

fn platform_coordinate(kind: ResourceKind, id: &str) -> ResourceCoordinate {
    ResourceCoordinate::new(
        ResourceAuthority::Automonique,
        kind,
        ResourceId::new(id).expect("resource id"),
    )
}

fn platform(config: &DaemonConfig, label: &str, request: PlatformRequest) -> PlatformResponse {
    let request_id = RequestId::new(label).expect("request id");
    let payload = PlatformRequestMessage::new(request_id.clone(), request)
        .to_message()
        .expect("request")
        .to_canonical_bytes();
    let response = PlatformResponseMessage::from_canonical_bytes(
        &exchange(config, &payload).expect("the platform lane answered"),
    )
    .expect("platform response");
    assert_eq!(response.request_id(), &request_id);
    response.response().clone()
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

/// A replay presented to a daemon that restarted in between is still a replay.
///
/// This is the property an in-memory custody cannot have, and the whole reason
/// the cancel ledger is durable. The second daemon shares nothing with the
/// first but the file.
#[test]
fn a_replay_across_a_daemon_restart_is_still_already_delivered() {
    let (_root, config) = fixture();
    let run = "run-cancel-restart";
    let attempt = format!("{run}-attempt-1");
    let spec = run_spec(run, "true");

    {
        let (serving, deliveries, registration) = serve_with_attempt(&config, &attempt);
        submit(&config, &spec, "cancel-restart");
        assert_eq!(
            delivered(cancel(&config, "cancel-1", run, "ref-b", 5)),
            CancelRunOutcome::Delivered
        );
        assert_eq!(deliveries.load(Ordering::Acquire), 1);
        drop(registration);
        serving.shutdown(&config);
    }

    // A second daemon, a second dispatcher, a second registration — and the
    // same ledger file.
    let (serving, deliveries, registration) = serve_with_attempt(&config, &attempt);
    assert_eq!(
        delivered(cancel(&config, "cancel-2", run, "ref-b", 5)),
        CancelRunOutcome::AlreadyDelivered
    );
    assert_eq!(
        deliveries.load(Ordering::Acquire),
        0,
        "the replay must not have reached the restarted daemon's sink at all"
    );
    drop(registration);
    serving.shutdown(&config);

    assert_eq!(recorded(&config, &attempt), vec![("ref-b".to_owned(), 5)]);
}

/// A run with no live attempt is a typed refusal, and records nothing.
///
/// This is the case an operator hits after a run has finished, and it must not
/// read as a cancellation that worked. Custody is never consulted for an
/// attempt no registration holds, so a reference spent here is still available
/// afterwards — asserted, because a ledger row written for an undelivered
/// cancellation would make the reference unusable for a real one.
#[test]
fn cancelling_a_run_with_no_live_attempt_refuses_and_records_nothing() {
    let (_root, config) = fixture();
    let run = "run-cancel-finished";
    let attempt = format!("{run}-attempt-1");
    let spec = run_spec(run, "true");

    let serving = serve(&config);
    submit(&config, &spec, "cancel-finished");

    assert_eq!(
        refusal(cancel(&config, "cancel-1", run, "ref-c", 0)),
        ExecuteRefusal::NoLiveAttempt
    );
    serving.shutdown(&config);

    assert!(
        recorded(&config, &attempt).is_empty(),
        "an undelivered cancellation must not spend its reference"
    );
}

/// A run this daemon has never held is `unknown_run`, not `no_live_attempt`.
///
/// The two are different repairs — check the reference, versus check whether it
/// already ended — so they are different answers.
#[test]
fn cancelling_an_unknown_run_names_that_exact_refusal() {
    let (_root, config) = fixture();
    let serving = serve(&config);

    assert_eq!(
        refusal(cancel(&config, "cancel-1", "run-never-held", "ref-d", 0)),
        ExecuteRefusal::UnknownRun
    );
    serving.shutdown(&config);
}

/// The cancel verb answers while intake is paused.
///
/// Deliberately the opposite gate from `execute_run`. An operator who closed
/// intake still needs to stop what is running — that is usually *why* they
/// closed it — so a cancel that refused with `intake_paused` would make the
/// pause a hazard rather than a repair.
#[test]
fn a_cancellation_is_answered_while_intake_is_paused() {
    let (_root, config) = fixture();
    let run = "run-cancel-paused";
    let attempt = format!("{run}-attempt-1");
    let spec = run_spec(run, "true");

    let (serving, deliveries, registration) = serve_with_attempt(&config, &attempt);
    submit(&config, &spec, "cancel-paused");

    let paused = admin(
        &config,
        AdminRequest::pause_intake(
            RequestId::new("pause-1").expect("request ID"),
            IntakePause::new("operator:ada", "stopping a runaway run").expect("pause body"),
        ),
    );
    assert!(
        matches!(paused, AdminResponse::IntakePaused { .. }),
        "expected the pause to be accepted, got {paused:?}"
    );

    // Starting is refused while paused; cancelling is not. Both assertions
    // matter: the first shows the pause is really in force.
    assert!(matches!(
        execute(&config, "start-while-paused", run),
        ExecuteResponse::Refused {
            refusal: ExecuteRefusal::IntakePaused,
            ..
        }
    ));
    assert_eq!(
        delivered(cancel(&config, "cancel-1", run, "ref-e", 0)),
        CancelRunOutcome::Delivered
    );
    assert_eq!(deliveries.load(Ordering::Acquire), 1);

    drop(registration);
    serving.shutdown(&config);
}
