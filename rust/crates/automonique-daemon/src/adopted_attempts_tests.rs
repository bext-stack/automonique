// SPDX-License-Identifier: Elastic-2.0

//! The successor's view of the attempts its source still hosts fails closed.
//!
//! A transferred daemon keeps a snapshot of the attempts its source still
//! hosted at authority confirmation and consults the source's private route
//! before it starts or cancels one of them. These tests put a real daemon in
//! that position without a handoff — the snapshot is installed directly,
//! which is what a test inside the crate is for — and stand up one source
//! route per failure class the probe can meet:
//!
//! - a route that accepts and never answers (the client's I/O timeout);
//! - a route that answers under another identity (a protocol violation);
//! - a route that answers with a refusal;
//! - a socket that is absent (`ENOENT`, what retirement leaves behind);
//! - a socket nobody listens on (`ECONNREFUSED`, what a dead source leaves);
//! - a real endpoint that hosts the attempt.
//!
//! What is asserted is what an operator sees from `execute` and `cancel` in
//! each case, whether anything was started here, and whether the snapshot
//! survived. Only the two connect failures are allowed to spend it.

use std::fs;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use automonique_protocol::admin::{AdminRequest, SubmittedRunSpec};
use automonique_protocol::codec::RequestId;
use automonique_protocol::context::{ContextManifest, TokenBudget};
use automonique_protocol::digest::Sha256 as ProtocolSha256;
use automonique_protocol::execute_api::{CancelRunOutcome, ExecuteRefusal};
use automonique_protocol::host::{AttemptId, HostId, HostLifetime, WorkId};
use automonique_protocol::identity::Actor;
use automonique_protocol::models::{ExecutorClass, ProviderAccountId};
use automonique_protocol::primitives::Revision;
use automonique_protocol::provider::BinaryProvenance;
use automonique_protocol::sandbox::{
    BudgetQuantities, Budgets, CredentialDescriptors, ExecutionAllowlists, ExecutionBackendId,
    FilesystemAccess, ImplementationDigest, IsolationRequirement, NestedIsolation, PathGrants,
    PolicyDigest, ProhibitedCapabilities, ProviderControlEgress, RequiredFeature, RequiredFeatures,
    SandboxProfile, SandboxSpec, SandboxSpecParts, ToolWorkloadEgress, WorkspaceContextHash,
};
use automonique_protocol::tools::RunId;
use automonique_protocol::workspace::{IsolationKind, WorkspaceRegistration, WorkspaceToken};
use automonique_runner::control::{CancelDelivery, CancelSink, CancelSinkError};
use automonique_runner::{
    AdmissionFields, AdmissionFieldsParts, ArtifactGrantBindings, CwdToken, ExecutionPlanDigest,
    ExtensionSetDigest, FallbackEligibility, IntegrationMode, IoReservation, ModelRoutingDigest,
    PersonaDigest, PortabilityPolicy, ProfileDigest, PromptDeliveryPlan, ProtectedPromptReference,
    RemoteAttestationPolicy, RequiredCapabilities, RunCoordinates, RunOrigin, RunSpec,
    RunSpecParts, RunnerEventDialect, SchedulerDecisionDigest, SchedulerReservationBinding,
    SchedulerReservationId, SkillsetDigest, ToolsetDigest, WorkspaceRegistryId,
    WorkspaceReservation,
};

use super::attempt_adoption::{
    AdoptedSourceAttempts, AttemptAdoptionEndpoint, AttemptHostRoute, socket_path,
};
use super::attempt_host::DaemonAttemptHost;
use super::execute::{DAEMON_WORKSPACE_REGISTRY, offered_host_features};
use super::{Daemon, DaemonConfig, unix_millis};

const RUN: &str = "adopted-run";
const SOURCE_HOLDER: &str = "source-daemon-1";
const SOURCE_EPOCH: u64 = 7;
const PROMPT_SLOT: &str = "adopted-prompt-slot";
const BUSYBOX: &str = "/usr/bin/busybox";

// --- fixture ----------------------------------------------------------------

fn private_directory(path: &Path) {
    if !path.exists() {
        fs::create_dir(path).expect("private directory");
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
}

/// A private root with the daemon's state directory and prompt slot in place.
fn fixture() -> (tempfile::TempDir, DaemonConfig) {
    let root = tempfile::tempdir().expect("temporary root");
    private_directory(root.path());
    let runtime_root = root.path().join("runtime");
    let state_root = root.path().join("state");
    private_directory(&runtime_root);
    private_directory(&state_root);
    let state_dir = state_root.join("automonique");
    let prompts = state_dir.join("prompts");
    private_directory(&state_dir);
    private_directory(&prompts);
    fs::write(prompts.join(PROMPT_SLOT), b"prompt\n").expect("prompt slot");
    fs::set_permissions(prompts.join(PROMPT_SLOT), fs::Permissions::from_mode(0o600))
        .expect("private slot");
    (
        root,
        DaemonConfig {
            runtime_root,
            state_root,
        },
    )
}

fn attempt_id() -> String {
    format!("{RUN}-attempt-1")
}

fn run_id() -> RunId {
    RunId::new(RUN).expect("run id")
}

/// The route the snapshot pins: the source's socket in this daemon's runtime
/// directory, under a holder and epoch nothing else here uses.
fn source_route(config: &DaemonConfig) -> AttemptHostRoute {
    AttemptHostRoute {
        socket_path: socket_path(&config.runtime_dir(), SOURCE_HOLDER).expect("route path"),
        holder_id: SOURCE_HOLDER.to_owned(),
        lease_epoch: SOURCE_EPOCH,
    }
}

/// Install the snapshot a transfer would have handed this daemon.
fn adopt(daemon: &mut Daemon, route: &AttemptHostRoute) {
    daemon.adopted_source_attempts = Some(AdoptedSourceAttempts {
        route: route.clone(),
        attempt_ids: vec![attempt_id()],
    });
}

/// Nothing was started on this daemon's own host.
fn assert_nothing_started_here(daemon: &Daemon) {
    let registered = daemon
        .attempt_host
        .as_ref()
        .expect("an opened daemon owns its attempt host")
        .registered_attempts()
        .expect("registry read");
    assert!(registered.is_empty(), "started locally: {registered:?}");
}

// --- a document this daemon's admission accepts ---------------------------

fn digest_text(digit: char) -> String {
    format!("sha256:{}", digit.to_string().repeat(64))
}

fn provider_binary() -> BinaryProvenance {
    let bytes = fs::read(BUSYBOX).expect("busybox is readable");
    BinaryProvenance::new(
        "busybox",
        &format!("sha256:{}", ProtocolSha256::digest(&bytes).to_hex()),
        None,
    )
    .expect("observed provenance")
}

/// A containment feature at an implementation digest no host offers.
///
/// Custody accepts the document; the execution lane refuses it at admission
/// on every host, delegated or not, so a run that passes the source gate in
/// these tests never actually starts anything. Which host-side refusal the
/// lane answers with is the host's business and is not asserted.
fn required_features() -> RequiredFeatures {
    let unoffered = ImplementationDigest::parse(&digest_text('3')).expect("digest");
    assert!(
        offered_host_features()
            .iter()
            .all(|feature| feature.implementation() != &unoffered),
        "the digest must be one no host offers"
    );
    RequiredFeatures::declare(&[
        RequiredFeature::new("descendant_containment", &[unoffered]).expect("feature")
    ])
    .expect("features")
}

/// The run went past the source gate and reached the lane, which refused it
/// on this host's own grounds. Only the gate's two words would say the
/// source was consulted, and neither may appear.
fn assert_admitted_past_the_source_gate(outcome: Result<u64, ExecuteRefusal>) {
    match outcome {
        Ok(submission_id) => panic!("an attempt was started: submission {submission_id}"),
        Err(ExecuteRefusal::SourceRouteUnavailable | ExecuteRefusal::AlreadyExecuting) => {
            panic!("the source gate refused a run the source no longer hosts: {outcome:?}")
        }
        Err(_) => {}
    }
}

fn sandbox() -> SandboxSpec {
    SandboxSpec::compile(SandboxSpecParts {
        profile: SandboxProfile::new(
            "adopted-profile",
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
        provider_control_egress: ProviderControlEgress::denied(),
        tool_workload_egress: ToolWorkloadEgress::denied(),
        credentials: CredentialDescriptors::declare(&[]).expect("credentials"),
        budgets: Budgets::declare(BudgetQuantities {
            cgroup_memory_bytes: 128 * 1024 * 1024,
            cgroup_cpu_millicores: 1_000,
            rlimit_processes: 64,
            rlimit_descriptors: 256,
            timeout_millis: 60_000,
            temporary_storage_bytes: 1024 * 1024,
            spool_bytes: 1024 * 1024,
            artifact_bytes: 1024 * 1024,
        })
        .expect("budgets"),
        required_features: required_features(),
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

/// One document naming [`RUN`] under the attempt [`attempt_id`] declares.
fn run_spec() -> RunSpec {
    RunSpec::new(RunSpecParts {
        protocol_version: 1,
        coordinates: RunCoordinates::new(
            WorkId::new("work-1").expect("work"),
            run_id(),
            AttemptId::new(attempt_id()).expect("attempt"),
            HostId::new("host-1").expect("host"),
            HostLifetime::Attempt,
            ExecutionBackendId::new("local-direct").expect("backend"),
        ),
        executable: PathBuf::from(BUSYBOX),
        arguments: vec!["true".into()],
        cwd_token: CwdToken::new("cwd-1").expect("cwd"),
        environment: Vec::new(),
        prompt: PromptDeliveryPlan::ProtectedReference(
            ProtectedPromptReference::new(PROMPT_SLOT).expect("slot"),
        ),
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
        sandbox: sandbox(),
        admission: admission(),
    })
    .expect("valid run specification")
}

/// Take custody of the document through the admin lane, exactly as a client
/// over the socket would, and require the index row that proves it.
fn submit(daemon: &mut Daemon) {
    let document = run_spec().to_canonical_bytes().expect("canonical encoding");
    let submission = SubmittedRunSpec::sealed(document, "adopted-submit").expect("submission");
    let request = AdminRequest::submit_run(
        RequestId::new("adopted-submit").expect("request id"),
        submission,
    );
    let (mut daemon_end, _client_end) = UnixStream::pair().expect("socket pair");
    let stop = AtomicBool::new(false);
    daemon
        .handle_admin(&mut daemon_end, &request, &stop)
        .expect("submission handled");
    let records = daemon.run_index.by_run_id(RUN).expect("index read");
    assert_eq!(records.len(), 1, "custody row: {records:?}");
}

// --- source routes, one per failure class ---------------------------------

/// How a scripted source answers the successor's probe.
#[derive(Clone, Copy)]
enum SourceAnswer {
    /// Accept, read the request, and never answer: the successor's I/O
    /// timeout is the failure it meets.
    Silent,
    /// Answer an inventory pinned to a holder this successor never adopted.
    ForeignIdentity,
    /// Answer a refusal in the source's own identity.
    Refused,
}

/// A source route scripted to fail in one way, at the exact path the
/// snapshot pins.
struct ScriptedSource {
    socket_path: PathBuf,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl ScriptedSource {
    fn bind(route: &AttemptHostRoute, answer: SourceAnswer) -> Self {
        let listener = UnixListener::bind(&route.socket_path).expect("scripted source socket");
        listener.set_nonblocking(true).expect("non-blocking accept");
        let response = match answer {
            SourceAnswer::Silent => None,
            SourceAnswer::ForeignIdentity => Some(format!(
                "{{\"schema\":\"automonique.attempt-adoption/v1\",\"holder_id\":\"someone-else\",\
                 \"lease_epoch\":{},\"answer\":{{\"answer\":\"inventory\",\"attempt_ids\":[]}}}}\n",
                route.lease_epoch
            )),
            SourceAnswer::Refused => Some(format!(
                "{{\"schema\":\"automonique.attempt-adoption/v1\",\"holder_id\":\"{}\",\
                 \"lease_epoch\":{},\"answer\":{{\"answer\":\"refused\",\
                 \"category\":\"attempt_adoption_host_unavailable\"}}}}\n",
                route.holder_id, route.lease_epoch
            )),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let accept_stop = Arc::clone(&stop);
        let accept = std::thread::spawn(move || {
            // Streams a silent source holds open until it is told to stop,
            // so the successor's read times out rather than seeing a close.
            let mut held = Vec::new();
            while !accept_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let mut request = String::new();
                        let _ = BufReader::new(stream.try_clone().expect("stream clone"))
                            .read_line(&mut request);
                        match &response {
                            Some(response) => {
                                let _ = stream.write_all(response.as_bytes());
                            }
                            None => held.push(stream),
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
            drop(held);
        });
        Self {
            socket_path: route.socket_path.clone(),
            stop,
            accept: Some(accept),
        }
    }
}

impl Drop for ScriptedSource {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        let _ = fs::remove_file(&self.socket_path);
    }
}

struct CountingSink {
    deliveries: Arc<AtomicUsize>,
}

impl CancelSink for CountingSink {
    fn deliver(
        &self,
        _attempt_id: &str,
        _request_ref: &str,
    ) -> Result<CancelDelivery, CancelSinkError> {
        self.deliveries.fetch_add(1, Ordering::Release);
        Ok(CancelDelivery::Accepted)
    }
}

// --- the proofs -----------------------------------------------------------

/// The three ways a route can fail to answer without being gone. Each keeps
/// the snapshot, refuses a second attempt with the route's own word, and
/// never lets a cancellation be answered "no live attempt".
fn a_route_that_does_not_answer_is_not_a_retirement(answer: SourceAnswer) {
    let (_root, config) = fixture();
    let mut daemon = Daemon::open(&config).expect("daemon opens");
    submit(&mut daemon);
    let route = source_route(&config);
    let _source = ScriptedSource::bind(&route, answer);
    adopt(&mut daemon, &route);
    let now_ms = unix_millis().expect("clock");

    assert_eq!(
        daemon.start_run(&run_id(), false, false, now_ms),
        Err(ExecuteRefusal::SourceRouteUnavailable),
        "a second attempt is refused with the route's own word"
    );
    assert!(
        daemon.adopted_source_attempts.is_some(),
        "the snapshot is kept: nothing proved the source retired"
    );
    assert_nothing_started_here(&daemon);

    assert_eq!(
        daemon.cancel_run(&run_id(), "ref-1", 1, now_ms),
        Err(ExecuteRefusal::SourceRouteUnavailable),
        "a cancellation is not answered 'no live attempt' while the source may hold the sink"
    );
    assert!(daemon.adopted_source_attempts.is_some());
}

#[test]
fn a_source_route_that_times_out_keeps_the_snapshot_and_refuses_both_verbs() {
    a_route_that_does_not_answer_is_not_a_retirement(SourceAnswer::Silent);
}

#[test]
fn a_source_route_answering_under_another_identity_keeps_the_snapshot_and_refuses_both_verbs() {
    a_route_that_does_not_answer_is_not_a_retirement(SourceAnswer::ForeignIdentity);
}

#[test]
fn a_source_route_that_refuses_keeps_the_snapshot_and_refuses_both_verbs() {
    a_route_that_does_not_answer_is_not_a_retirement(SourceAnswer::Refused);
}

/// A route that stopped answering and then answers again is adopted again:
/// the snapshot survived the fault, so the next probe finds the attempt
/// hosted and the second attempt is still refused.
#[test]
fn a_source_route_that_recovers_is_probed_again_and_still_hosts_the_attempt() {
    let (_root, config) = fixture();
    let mut daemon = Daemon::open(&config).expect("daemon opens");
    submit(&mut daemon);
    let route = source_route(&config);
    adopt(&mut daemon, &route);
    let now_ms = unix_millis().expect("clock");

    let silent = ScriptedSource::bind(&route, SourceAnswer::Silent);
    assert_eq!(
        daemon.start_run(&run_id(), false, false, now_ms),
        Err(ExecuteRefusal::SourceRouteUnavailable)
    );
    drop(silent);

    let host = Arc::new(
        DaemonAttemptHost::open(config.state_dir().join("source-cancel-ledger.sqlite3"))
            .expect("source host"),
    );
    let deliveries = Arc::new(AtomicUsize::new(0));
    let _registration = host
        .register(
            &attempt_id(),
            Box::new(CountingSink {
                deliveries: Arc::clone(&deliveries),
            }),
        )
        .expect("source-hosted attempt");
    let mut endpoint = AttemptAdoptionEndpoint::bind(
        route.socket_path.clone(),
        &route.holder_id,
        route.lease_epoch,
        Arc::clone(&host),
    )
    .expect("source endpoint");
    endpoint.start().expect("source accept loop");

    assert_eq!(
        daemon.start_run(&run_id(), false, false, now_ms),
        Err(ExecuteRefusal::AlreadyExecuting),
        "once the route answers, the run is already executing — at the source"
    );
    assert!(daemon.adopted_source_attempts.is_some());
    assert_nothing_started_here(&daemon);
}

/// The one route that hosts the attempt: a second attempt is refused as
/// already executing, a cancellation reaches the source's sink exactly once
/// and its replay is answered from the source's ledger, and the snapshot
/// stands until the source removes its socket — at which point, and not
/// before, the successor says no live attempt exists.
#[test]
fn a_hosted_attempt_is_refused_a_second_attempt_and_cancelled_through_the_source_once() {
    let (_root, config) = fixture();
    let mut daemon = Daemon::open(&config).expect("daemon opens");
    submit(&mut daemon);
    let route = source_route(&config);
    let host = Arc::new(
        DaemonAttemptHost::open(config.state_dir().join("source-cancel-ledger.sqlite3"))
            .expect("source host"),
    );
    let deliveries = Arc::new(AtomicUsize::new(0));
    let registration = host
        .register(
            &attempt_id(),
            Box::new(CountingSink {
                deliveries: Arc::clone(&deliveries),
            }),
        )
        .expect("source-hosted attempt");
    let mut endpoint = AttemptAdoptionEndpoint::bind(
        route.socket_path.clone(),
        &route.holder_id,
        route.lease_epoch,
        Arc::clone(&host),
    )
    .expect("source endpoint");
    endpoint.start().expect("source accept loop");
    adopt(&mut daemon, &route);
    let now_ms = unix_millis().expect("clock");

    assert_eq!(
        daemon.start_run(&run_id(), false, false, now_ms),
        Err(ExecuteRefusal::AlreadyExecuting)
    );
    assert_nothing_started_here(&daemon);
    assert_eq!(
        daemon.cancel_run(&run_id(), "ref-1", 1, now_ms),
        Ok(CancelRunOutcome::Delivered)
    );
    assert_eq!(deliveries.load(Ordering::Acquire), 1);
    assert_eq!(
        daemon.cancel_run(&run_id(), "ref-1", 1, now_ms),
        Ok(CancelRunOutcome::AlreadyDelivered),
        "the replay is answered from the source's custody"
    );
    assert_eq!(deliveries.load(Ordering::Acquire), 1, "no second delivery");
    assert!(daemon.adopted_source_attempts.is_some());

    // The source retires: its worker released the registration and its
    // endpoint removed the socket. Only now is there nothing to cancel.
    drop(registration);
    drop(endpoint);
    assert!(!route.socket_path.exists(), "retirement removes the socket");
    assert_eq!(
        daemon.cancel_run(&run_id(), "ref-2", 1, now_ms),
        Err(ExecuteRefusal::NoLiveAttempt)
    );
    assert!(
        daemon.adopted_source_attempts.is_none(),
        "a removed socket is the proof that spends the snapshot"
    );
    assert_eq!(deliveries.load(Ordering::Acquire), 1);
}

/// The two connect failures that prove the route gone. Each spends the
/// snapshot: a new attempt is admitted past the source gate, and a
/// cancellation is truthfully answered "no live attempt".
fn a_route_that_is_provably_gone_spends_the_snapshot(config: &DaemonConfig, daemon: &mut Daemon) {
    let now_ms = unix_millis().expect("clock");
    assert_admitted_past_the_source_gate(daemon.start_run(&run_id(), false, false, now_ms));
    assert!(
        daemon.adopted_source_attempts.is_none(),
        "a route that is gone spends the snapshot"
    );
    assert_nothing_started_here(daemon);

    adopt(daemon, &source_route(config));
    assert_eq!(
        daemon.cancel_run(&run_id(), "ref-1", 1, now_ms),
        Err(ExecuteRefusal::NoLiveAttempt)
    );
    assert!(daemon.adopted_source_attempts.is_none());
}

#[test]
fn a_source_socket_that_is_absent_spends_the_snapshot_and_admits_the_run() {
    let (_root, config) = fixture();
    let mut daemon = Daemon::open(&config).expect("daemon opens");
    submit(&mut daemon);
    let route = source_route(&config);
    assert!(!route.socket_path.exists(), "nothing was ever bound there");
    adopt(&mut daemon, &route);
    a_route_that_is_provably_gone_spends_the_snapshot(&config, &mut daemon);
}

#[test]
fn a_source_socket_nobody_listens_on_spends_the_snapshot_and_admits_the_run() {
    let (_root, config) = fixture();
    let mut daemon = Daemon::open(&config).expect("daemon opens");
    submit(&mut daemon);
    let route = source_route(&config);
    // A socket file whose listener is gone: what a source killed without
    // retiring leaves behind. Connecting to it is refused by the kernel.
    let listener = UnixListener::bind(&route.socket_path).expect("bind then abandon");
    drop(listener);
    assert!(route.socket_path.exists(), "the file outlives the listener");
    assert_eq!(
        UnixStream::connect(&route.socket_path)
            .expect_err("no listener")
            .kind(),
        std::io::ErrorKind::ConnectionRefused
    );
    adopt(&mut daemon, &route);
    a_route_that_is_provably_gone_spends_the_snapshot(&config, &mut daemon);
    let _ = fs::remove_file(&route.socket_path);
}

/// An attempt the snapshot never named is nobody's but this daemon's: the
/// route is not consulted, so even a route that would time out costs
/// nothing and refuses nothing.
#[test]
fn an_attempt_outside_the_snapshot_never_consults_the_route() {
    let (_root, config) = fixture();
    let mut daemon = Daemon::open(&config).expect("daemon opens");
    submit(&mut daemon);
    let route = source_route(&config);
    let _source = ScriptedSource::bind(&route, SourceAnswer::Silent);
    daemon.adopted_source_attempts = Some(AdoptedSourceAttempts {
        route: route.clone(),
        attempt_ids: vec!["some-other-attempt".to_owned()],
    });
    let now_ms = unix_millis().expect("clock");
    let started = std::time::Instant::now();
    assert_admitted_past_the_source_gate(daemon.start_run(&run_id(), false, false, now_ms));
    assert_nothing_started_here(&daemon);
    assert_eq!(
        daemon.cancel_run(&run_id(), "ref-1", 1, now_ms),
        Err(ExecuteRefusal::NoLiveAttempt)
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the silent route was never probed"
    );
    assert!(daemon.adopted_source_attempts.is_some());
}
