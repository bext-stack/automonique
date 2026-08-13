// SPDX-License-Identifier: Elastic-2.0

//! The native Runs API read surface, live over the real local socket.
//!
//! Nothing here is a unit test of the listing types — `automonique-protocol`
//! owns those. What is proved here is the join those types deliberately left
//! open: a document submitted through the administration lane becomes a row in
//! the derived read model, and a listing carried under the Runs protocol on
//! the *same* socket answers from that model joined against the custody it
//! derives from.
//!
//! Every document is a real `RunSpec` built through the runner's own
//! constructors, submitted through the real admin command, and every answer is
//! decoded by the Runs protocol's own decoder. A page that no decoder admitted,
//! or a summary assembled by this file rather than by the daemon, would prove
//! nothing.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use automonique_daemon::{Daemon, DaemonConfig};
use automonique_protocol::admin::{
    AdminCommand, AdminRequest, AdminResponse, DaemonState, SubmittedRunSpec,
};
use automonique_protocol::codec::{
    Envelope, FrameDecode, MajorVersion, MessageKind, ProtocolName, RequestId, decode_frame,
    encode_frame,
};
use automonique_protocol::context::{ContextManifest, TokenBudget};
use automonique_protocol::digest::Sha256;
use automonique_protocol::host::{AttemptId, HostId, HostLifetime, WorkId};
use automonique_protocol::identity::Actor;
use automonique_protocol::models::{ExecutorClass, ProviderAccountId};
use automonique_protocol::primitives::Revision;
use automonique_protocol::provider::BinaryProvenance;
use automonique_protocol::runs_api::{
    Continuation, LifecycleCoverage, ListRuns, PageSize, RunCursor, RunListPage, RunState,
    RunStateFilter, RunSummary, RunsRefusal, RunsRequest, RunsResponse, SubmissionState,
};
use automonique_protocol::sandbox::{
    BudgetQuantities, Budgets, CredentialDescriptors, ExecutionAllowlists, ExecutionBackendId,
    FilesystemAccess, ImplementationDigest, IsolationRequirement, NestedIsolation, NetworkAccess,
    PathGrants, PolicyDigest, ProhibitedCapabilities, ProviderControlEgress, RequiredFeature,
    RequiredFeatures, SandboxProfile, SandboxSpec, SandboxSpecParts, ToolWorkloadEgress,
    WorkspaceContextHash,
};
use automonique_protocol::tools::RunId;
use automonique_protocol::wire::{JsonValue, Message};
use automonique_protocol::workspace::{IsolationKind, WorkspaceRegistration, WorkspaceToken};
use automonique_runner::{
    AdmissionFields, AdmissionFieldsParts, ArtifactGrantBindings, CwdToken, ExecutionPlanDigest,
    ExtensionSetDigest, FallbackEligibility, IntegrationMode, IoReservation, ModelRoutingDigest,
    PersonaDigest, PortabilityPolicy, ProfileDigest, PromptDeliveryPlan, RemoteAttestationPolicy,
    RequiredCapabilities, RunCoordinates, RunOrigin, RunSpec, RunSpecParts, RunnerEventDialect,
    SchedulerDecisionDigest, SchedulerReservationBinding, SchedulerReservationId, SkillsetDigest,
    ToolsetDigest, WorkspaceRegistryId, WorkspaceReservation,
};
use automonique_store::run_index::RunIndex;

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

/// Send one canonical payload and read one back, or report that the daemon
/// closed the connection without answering.
///
/// Both outcomes are legitimate and they are different: a placed frame earns a
/// typed answer, and a frame this socket cannot place earns silence. Collapsing
/// them into a panic would make the second untestable.
fn exchange(config: &DaemonConfig, payload: &[u8]) -> Option<Vec<u8>> {
    let mut stream = UnixStream::connect(config.admin_socket()).expect("connect to daemon");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
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

fn call_request(config: &DaemonConfig, request: AdminRequest) -> AdminResponse {
    let payload = request
        .to_message()
        .expect("encode request")
        .to_canonical_bytes();
    let response = exchange(config, &payload).expect("the admin lane answered");
    AdminResponse::from_canonical_bytes(&response).expect("admitted response")
}

fn call(config: &DaemonConfig, command: AdminCommand) -> AdminResponse {
    call_request(
        config,
        AdminRequest::new(RequestId::new("runs-live-1").expect("request ID"), command),
    )
}

/// Ask the Runs lane one question over the same socket the admin lane uses.
///
/// The answer is required to carry the request's own correlation identifier:
/// a listing that answered somebody else's question would otherwise pass every
/// content assertion below.
fn runs(config: &DaemonConfig, request: &RunsRequest) -> RunsResponse {
    let payload = request
        .to_message()
        .expect("encode runs request")
        .to_canonical_bytes();
    let response = exchange(config, &payload).expect("the runs lane answered");
    let response = RunsResponse::from_canonical_bytes(&response).expect("admitted runs response");
    assert_eq!(
        response.request_id().as_str(),
        request.request_id().as_str(),
        "the answer was not correlated to the question",
    );
    response
}

fn list_request(label: &str, query: ListRuns) -> RunsRequest {
    RunsRequest::ListRuns {
        request_id: RequestId::new(label).expect("request ID"),
        query,
    }
}

fn detail_request(label: &str, run: &str) -> RunsRequest {
    RunsRequest::RunDetail {
        request_id: RequestId::new(label).expect("request ID"),
        run_id: RunId::new(run).expect("run identity"),
    }
}

/// Every run the daemon lists, under no filter and the largest page.
fn listed(config: &DaemonConfig, label: &str) -> RunListPage {
    match runs(
        config,
        &list_request(
            label,
            ListRuns::new(RunStateFilter::any(), None, PageSize::MAX),
        ),
    ) {
        RunsResponse::RunList { page, .. } => page,
        other => panic!("expected a page, got {other:?}"),
    }
}

fn page_of(config: &DaemonConfig, label: &str, query: ListRuns) -> RunListPage {
    match runs(config, &list_request(label, query)) {
        RunsResponse::RunList { page, .. } => page,
        other => panic!("expected a page, got {other:?}"),
    }
}

fn submit(config: &DaemonConfig, label: &str, submission: SubmittedRunSpec) -> AdminResponse {
    call_request(
        config,
        AdminRequest::submit_run(RequestId::new(label).expect("request ID"), submission),
    )
}

/// Submit one real document and return the durable identity custody assigned.
fn submit_run(config: &DaemonConfig, run: &str, key: &str) -> u64 {
    let submission = SubmittedRunSpec::sealed(document(run), key).expect("bounded submission");
    let response = submit(config, "submit-run", submission);
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

fn wait_for_socket(config: &DaemonConfig) {
    let deadline = Instant::now() + Duration::from_secs(2);
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

fn run_spec(run: &str, attempt: &str) -> RunSpec {
    RunSpec::new(RunSpecParts {
        protocol_version: 1,
        coordinates: RunCoordinates::new(
            WorkId::new("work-1").expect("work"),
            RunId::new(run).expect("run"),
            AttemptId::new(attempt).expect("attempt"),
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
}

/// The canonical document for one run, submitted under its first attempt.
fn document(run: &str) -> Vec<u8> {
    attempt_document(run, "attempt-1")
}

/// A second, genuinely different document naming the same run.
///
/// Two submissions may name one run — custody admits it and so does the index —
/// and the two documents then differ everywhere except that identity. That is
/// what makes them useful here: a join keyed on the run rather than on the
/// submission would attach one document's digest to the other's row and no
/// assertion about the run identity would notice.
fn attempt_document(run: &str, attempt: &str) -> Vec<u8> {
    run_spec(run, attempt)
        .to_canonical_bytes()
        .expect("canonical encoding")
}

/// Assert that a summary is the daemon's own account of one submitted run.
///
/// Both states are checked on every summary: `state` comes from the index and
/// `submission_state` from custody, and a listing that reported one of them
/// while inventing the other would still be wrong.
fn assert_summary(summary: &RunSummary, run: &str, submission_id: u64) {
    assert_attempt_summary(summary, run, "attempt-1", submission_id);
}

fn assert_attempt_summary(summary: &RunSummary, run: &str, attempt: &str, submission_id: u64) {
    assert_eq!(summary.run_id().as_str(), run);
    assert_eq!(summary.submission_id(), submission_id);
    assert_eq!(
        summary.spec_digest(),
        &Sha256::digest(&attempt_document(run, attempt)),
    );
    assert_eq!(summary.state(), RunState::Ready);
    assert_eq!(summary.submission_state(), SubmissionState::Accepted);
    assert!(
        summary.accepted_at().as_millis() > 0,
        "acceptance instant was not recorded",
    );
}

#[test]
fn a_submitted_run_is_listed_and_readable_in_full() {
    let (_root, config) = fixture();
    let serving = serve(&config);

    // Before anything is submitted the index retains nothing. That is an empty
    // *complete* page, not a resync: a log nothing was ever removed from has
    // lost no position, and answering "the positions you wanted are gone"
    // about it would be false.
    let empty = listed(&config, "list-empty");
    assert!(empty.runs().is_empty());
    assert_eq!(empty.continuation(), Continuation::Complete);

    let submission_id = submit_run(&config, "run-1", "operator:runs:1");

    let page = listed(&config, "list-one");
    assert_eq!(page.runs().len(), 1);
    assert_eq!(page.continuation(), Continuation::Complete);
    assert_summary(&page.runs()[0], "run-1", submission_id);

    // The detail view is the same summary plus the lifecycle statement. No
    // execution lane writes a spool in this build, so a ready run at sequence
    // zero carries no events and says so with `complete` — an honest empty
    // answer rather than a truncation nobody could resume.
    let RunsResponse::RunDetail { view, .. } = runs(&config, &detail_request("detail-1", "run-1"))
    else {
        panic!("expected a detail view")
    };
    assert_summary(view.summary(), "run-1", submission_id);
    assert_eq!(view.last_sequence(), 0);
    assert_eq!(view.coverage(), LifecycleCoverage::Complete);
    assert!(view.lifecycle().is_empty());
    assert_eq!(view.resume_cursor(), None);

    // Listing is a read: it took no custody and scheduled no work.
    let AdminResponse::Status { status, .. } = call(&config, AdminCommand::Status) else {
        panic!("status response")
    };
    assert_eq!(status.state(), DaemonState::Ready);
    assert_eq!(status.inbox_pending(), 0);
    assert_eq!(status.running(), 0);
    serving.shutdown(&config);
}

#[test]
fn a_short_page_continues_and_the_next_page_returns_the_rest() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let first = submit_run(&config, "run-1", "operator:runs:1");
    let second = submit_run(&config, "run-2", "operator:runs:2");
    let third = submit_run(&config, "run-3", "operator:runs:3");
    assert!(first < second && second < third, "custody is monotonic");

    let two = PageSize::new(2).expect("page size");
    let head = page_of(
        &config,
        "page-head",
        ListRuns::new(RunStateFilter::any(), None, two),
    );
    assert_eq!(head.runs().len(), 2);
    assert_summary(&head.runs()[0], "run-1", first);
    assert_summary(&head.runs()[1], "run-2", second);

    // The continuation names the next identity the caller will receive, which
    // is one past the last one served — not the last one served, which would
    // hand the same row back on the next page.
    let Continuation::More(cursor) = head.continuation() else {
        panic!("a page that left a row behind reported itself complete")
    };
    assert_eq!(cursor.position(), second + 1);

    let tail = page_of(
        &config,
        "page-tail",
        ListRuns::new(RunStateFilter::any(), Some(cursor), two),
    );
    assert_eq!(tail.runs().len(), 1, "the tail repeated or dropped a row");
    assert_summary(&tail.runs()[0], "run-3", third);
    assert_eq!(tail.continuation(), Continuation::Complete);

    // A cursor exactly one past everything retained is caught up, which is a
    // complete empty page and not a resync.
    let caught_up = page_of(
        &config,
        "page-caught-up",
        ListRuns::new(RunStateFilter::any(), Some(RunCursor::new(third + 1)), two),
    );
    assert!(caught_up.runs().is_empty());
    assert_eq!(caught_up.continuation(), Continuation::Complete);
    serving.shutdown(&config);
}

#[test]
fn a_cursor_outside_retention_earns_a_resync_and_never_a_partial_page() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let first = submit_run(&config, "run-1", "operator:runs:1");
    let last = submit_run(&config, "run-2", "operator:runs:2");

    // Below the floor and above the caught-up position are both outside the
    // resumable set. Each answers with the window a fresh snapshot must cover,
    // and carries no rows at all.
    for (label, position) in [
        ("resync-below", first - 1),
        ("resync-above", last + 2),
        ("resync-far", last + 1_000),
    ] {
        let answer = runs(
            &config,
            &list_request(
                label,
                ListRuns::new(
                    RunStateFilter::any(),
                    Some(RunCursor::new(position)),
                    PageSize::MAX,
                ),
            ),
        );
        let RunsResponse::Resync {
            snapshot_from,
            snapshot_to,
            ..
        } = answer
        else {
            panic!("cursor {position} was served instead of resynced: {answer:?}")
        };
        assert_eq!(snapshot_from, first);
        assert_eq!(snapshot_to, last);
    }

    // The boundary positions are inside the set and are served normally, so
    // the refusal above is a retention judgement rather than a listing that
    // refuses every cursor it is given.
    let floor = page_of(
        &config,
        "resync-floor",
        ListRuns::new(
            RunStateFilter::any(),
            Some(RunCursor::new(first)),
            PageSize::MAX,
        ),
    );
    assert_eq!(floor.runs().len(), 2);
    serving.shutdown(&config);
}

#[test]
fn an_empty_index_answers_every_cursor_with_a_complete_empty_page() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    for (label, cursor) in [
        ("empty-none", None),
        ("empty-one", Some(RunCursor::new(1))),
        ("empty-far", Some(RunCursor::new(4_096))),
    ] {
        let page = page_of(
            &config,
            label,
            ListRuns::new(RunStateFilter::any(), cursor, PageSize::MAX),
        );
        assert!(page.runs().is_empty(), "{label} produced rows");
        assert_eq!(page.continuation(), Continuation::Complete);
    }
    serving.shutdown(&config);
}

#[test]
fn an_unknown_run_is_refused_by_name_rather_than_answered_emptily() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    submit_run(&config, "run-1", "operator:runs:1");

    // A grammatical run identity nobody submitted.
    assert_eq!(
        runs(&config, &detail_request("detail-missing", "run-absent")),
        RunsResponse::Refused {
            request_id: RequestId::new("detail-missing").expect("request ID"),
            refusal: RunsRefusal::UnknownRun,
        },
    );

    // The run that *was* submitted still reads, so the refusal above is about
    // that identity and not about this handler.
    assert!(matches!(
        runs(&config, &detail_request("detail-present", "run-1")),
        RunsResponse::RunDetail { .. }
    ));
    serving.shutdown(&config);
}

#[test]
fn the_state_filter_selects_without_hiding_or_inventing_rows() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let submission_id = submit_run(&config, "run-1", "operator:runs:1");

    let ready = page_of(
        &config,
        "filter-ready",
        ListRuns::new(
            RunStateFilter::only([RunState::Ready]).expect("filter"),
            None,
            PageSize::MAX,
        ),
    );
    assert_eq!(ready.runs().len(), 1);
    assert_summary(&ready.runs()[0], "run-1", submission_id);

    // Nothing in this build advances a run, so every other state selects
    // nothing — and does so as a complete page rather than a refusal.
    for state in [
        RunState::Running,
        RunState::Completed,
        RunState::Failed,
        RunState::Cancelled,
        RunState::TimedOut,
    ] {
        let page = page_of(
            &config,
            "filter-other",
            ListRuns::new(
                RunStateFilter::only([state]).expect("filter"),
                None,
                PageSize::MAX,
            ),
        );
        assert!(page.runs().is_empty(), "{state} selected a row");
        assert_eq!(page.continuation(), Continuation::Complete);
    }
    serving.shutdown(&config);
}

#[test]
fn a_replayed_submission_adds_no_second_row_to_the_read_model() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let document = document("run-1");
    let submission = SubmittedRunSpec::sealed(document, "operator:runs:1").expect("bounded");

    let accepted = submit(&config, "first", submission.clone());
    let AdminResponse::RunAccepted {
        submission_id,
        replay: false,
        ..
    } = accepted
    else {
        panic!("expected a first acceptance, got {accepted:?}")
    };

    // The same key and the same bytes, twice more. Custody answers from the
    // row it already wrote; the read model must not grow.
    for label in ["replay-1", "replay-2"] {
        let replayed = submit(&config, label, submission.clone());
        assert!(
            matches!(
                replayed,
                AdminResponse::RunAccepted {
                    submission_id: id,
                    replay: true,
                    ..
                } if id == submission_id
            ),
            "{label} was not answered as a replay: {replayed:?}",
        );
    }

    let page = listed(&config, "list-after-replay");
    assert_eq!(page.runs().len(), 1, "a replay was listed as a second run");
    assert_summary(&page.runs()[0], "run-1", submission_id);
    serving.shutdown(&config);

    // And the durable table itself holds one row, so the single entry above is
    // not a page that merely happened to deduplicate.
    let index = RunIndex::open(config.run_index_path()).expect("open run index");
    assert_eq!(index.entry_count().expect("count"), 1);
}

#[test]
fn submitted_runs_are_still_listable_after_a_restart() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let first = submit_run(&config, "run-1", "operator:runs:1");
    let second = submit_run(&config, "run-2", "operator:runs:2");
    serving.shutdown(&config);

    // A new generation opens both databases and answers from them. Neither the
    // index nor the custody it joins against was rebuilt in memory.
    let serving = serve(&config);
    let page = listed(&config, "list-after-restart");
    assert_eq!(page.runs().len(), 2);
    assert_summary(&page.runs()[0], "run-1", first);
    assert_summary(&page.runs()[1], "run-2", second);

    let RunsResponse::RunDetail { view, .. } = runs(&config, &detail_request("detail-2", "run-2"))
    else {
        panic!("expected a detail view")
    };
    assert_summary(view.summary(), "run-2", second);

    // A third run submitted after the restart continues the same order, so the
    // read model resumed rather than restarted.
    let third = submit_run(&config, "run-3", "operator:runs:3");
    let page = listed(&config, "list-after-third");
    assert_eq!(page.runs().len(), 3);
    assert_summary(&page.runs()[2], "run-3", third);
    serving.shutdown(&config);
}

#[test]
fn one_socket_places_each_frame_by_the_protocol_it_declares() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let submission_id = submit_run(&config, "run-1", "operator:runs:1");

    // A frame naming a protocol this socket does not serve is placed by
    // nobody. It earns no answer at all — not an admin refusal, which would
    // mean the admin lane had read a body it does not own.
    let stranger = Message::new(
        Envelope::new(
            ProtocolName::new("automonique.stranger").expect("protocol name"),
            MajorVersion::new(1).expect("version"),
            RequestId::new("stranger-1").expect("request ID"),
            MessageKind::new("list_runs").expect("kind"),
        ),
        JsonValue::Object(Vec::new()),
    )
    .to_canonical_bytes();
    assert!(
        exchange(&config, &stranger).is_none(),
        "an unplaceable frame was answered",
    );

    // A Runs kind spelled inside an *admin* envelope is refused by the admin
    // lane, which owns that envelope's kind set — the two lanes do not fall
    // through to one another.
    let misplaced = Message::new(
        Envelope::new(
            ProtocolName::new("automonique.admin").expect("protocol name"),
            MajorVersion::new(1).expect("version"),
            RequestId::new("misplaced-1").expect("request ID"),
            MessageKind::new("list_runs").expect("kind"),
        ),
        JsonValue::Object(Vec::new()),
    )
    .to_canonical_bytes();
    assert!(
        exchange(&config, &misplaced).is_none(),
        "an admin frame naming a runs kind was answered",
    );

    // Both lanes still work, in either order, on the same live daemon.
    assert_eq!(listed(&config, "list-mixed").runs().len(), 1);
    assert!(matches!(
        call(&config, AdminCommand::Status),
        AdminResponse::Status { .. }
    ));
    let page = listed(&config, "list-mixed-again");
    assert_summary(&page.runs()[0], "run-1", submission_id);
    serving.shutdown(&config);
}

#[test]
fn two_submissions_of_one_run_are_joined_by_submission_and_not_by_run() {
    let (_root, config) = fixture();
    let serving = serve(&config);

    // One run identity, two genuinely different documents, two custody rows.
    let first = submit_run(&config, "run-1", "operator:runs:1");
    let second = {
        let submission =
            SubmittedRunSpec::sealed(attempt_document("run-1", "attempt-2"), "operator:runs:2")
                .expect("bounded submission");
        let response = submit(&config, "submit-second-attempt", submission);
        let AdminResponse::RunAccepted {
            run_id,
            submission_id,
            replay: false,
            ..
        } = response
        else {
            panic!("expected a second acceptance, got {response:?}")
        };
        assert_eq!(run_id.as_str(), "run-1");
        submission_id
    };
    assert_ne!(first, second);

    // Both are listed, each carrying the digest of *its own* document. A join
    // that matched on the run identity alone would report one document twice.
    let page = listed(&config, "list-two-attempts");
    assert_eq!(page.runs().len(), 2);
    assert_attempt_summary(&page.runs()[0], "run-1", "attempt-1", first);
    assert_attempt_summary(&page.runs()[1], "run-1", "attempt-2", second);
    assert_ne!(page.runs()[0].spec_digest(), page.runs()[1].spec_digest());

    // A detail read of an identity two submissions claim answers with the most
    // recently registered of them, and says which one by carrying its exact
    // submission identity rather than leaving a caller to assume there was one.
    let RunsResponse::RunDetail { view, .. } = runs(&config, &detail_request("detail-1", "run-1"))
    else {
        panic!("expected a detail view")
    };
    assert_attempt_summary(view.summary(), "run-1", "attempt-2", second);
    serving.shutdown(&config);
}
