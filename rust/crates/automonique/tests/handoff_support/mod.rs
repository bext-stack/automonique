// SPDX-License-Identifier: Elastic-2.0

//! Shared harness for the process-level generation-handoff proofs.
//!
//! Everything here talks to a daemon the way an operator or a client does:
//! the product binary for `reload`, `rollback`, `reload-status`, `status` and
//! `shutdown`; the admin, Execute and Runs lanes over the socket the daemon
//! bound. Nothing reaches into a daemon's memory. The durable stores are read
//! back through the store crate's own readers, so what a test asserts is what
//! the next generation would find on disk.

#![allow(dead_code)]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use automonique_daemon::execute::{DAEMON_WORKSPACE_REGISTRY, offered_host_features};
use automonique_daemon::{Daemon, DaemonConfig, DaemonError};
use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse, SubmittedRunSpec};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_protocol::context::{ContextManifest, TokenBudget};
use automonique_protocol::digest::Sha256 as ProtocolSha256;
use automonique_protocol::execute_api::{CancelRequestRef, ExecuteRequest, ExecuteResponse};
use automonique_protocol::host::{AttemptId, HostId, HostLifetime, WorkId};
use automonique_protocol::identity::Actor;
use automonique_protocol::models::{ExecutorClass, ProviderAccountId};
use automonique_protocol::primitives::Revision;
use automonique_protocol::provider::BinaryProvenance;
use automonique_protocol::runs_api::{
    ListRuns, PageSize, RunState, RunStateFilter, RunsRequest, RunsResponse,
};
use automonique_protocol::sandbox::{
    BudgetQuantities, Budgets, CredentialDescriptors, ExecutionAllowlists, ExecutionBackendId,
    FilesystemAccess, ImplementationDigest, IsolationRequirement, NestedIsolation, PathGrants,
    PolicyDigest, ProhibitedCapabilities, ProviderControlEgress, RequiredFeature, RequiredFeatures,
    SandboxProfile, SandboxSpec, SandboxSpecParts, ToolWorkloadEgress, WorkspaceContextHash,
};
use automonique_protocol::tools::RunId;
use automonique_protocol::workspace::{IsolationKind, WorkspaceRegistration, WorkspaceToken};
use automonique_runner::{
    AdmissionFields, AdmissionFieldsParts, ArtifactGrantBindings, CwdToken, ExecutionPlanDigest,
    ExtensionSetDigest, FallbackEligibility, IntegrationMode, IoReservation, ModelRoutingDigest,
    PersonaDigest, PortabilityPolicy, ProfileDigest, PromptDeliveryPlan, ProtectedPromptReference,
    RemoteAttestationPolicy, RequiredCapabilities, RunCoordinates, RunOrigin, RunSpec,
    RunSpecParts, RunnerEventDialect, SchedulerDecisionDigest, SchedulerReservationBinding,
    SchedulerReservationId, SkillsetDigest, ToolsetDigest, WorkspaceRegistryId,
    WorkspaceReservation,
};
use nix::sys::signal::kill;
use nix::unistd::Pid;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

pub const BUSYBOX: &str = "/usr/bin/busybox";
pub const PROMPT_SLOT: &str = "handoff-prompt-slot";
pub const PROMPT: &[u8] = b"the prompt the workload copies\n";
pub const MEMORY_BYTES: u64 = 128 * 1024 * 1024;
pub const PROCESSES: u64 = 64;
/// The document's own timeout, comfortably above any sleep a proof uses.
pub const TIMEOUT_MILLIS: u64 = 60_000;
pub const SPOOL_BYTES: u64 = 1024 * 1024;
/// Ceiling a proof re-opens a finished spool under; well above `SPOOL_BYTES`.
pub const READ_SPOOL_BYTES: u64 = 8 * 1024 * 1024;

// --- filesystem -----------------------------------------------------------

pub fn private_directory(path: &Path) {
    fs::create_dir_all(path).expect("private directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// A private root with the daemon's state directory and prompt slot in place.
pub fn fixture() -> (tempfile::TempDir, DaemonConfig) {
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
    fs::write(prompts.join(PROMPT_SLOT), PROMPT).expect("prompt slot");
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

// --- releases -------------------------------------------------------------

/// Install one immutable code release whose binary is this very executable,
/// distinguished from its siblings by the source digit and from every other
/// fixture's releases by a plan digest derived from the release root.
///
/// The per-fixture plan digest matters when tests run in parallel: a reload
/// identifier is derived from the manifest digest, and the proofs scan
/// `/proc` for candidate processes by that identifier, so two fixtures
/// installing byte-identical releases would see each other's candidates.
pub fn install_code_release(root: &Path, executable: &[u8], source: char) -> String {
    let binary_sha256 = hex(&Sha256::digest(executable));
    let mut plan = Sha256::new();
    plan.update(root.as_os_str().as_encoded_bytes());
    plan.update([u8::try_from(source).expect("ASCII source digit")]);
    let manifest = serde_json::json!({
        "schema": "automonique.code-release/v1",
        "source_sha": source.to_string().repeat(40),
        "plan_digest": format!("sha256:{}", hex(&plan.finalize())),
        "binary_path": "bin/automonique",
        "binary_sha256": binary_sha256,
        "changed_paths": ["rust/crates/automonique-daemon/src/candidate.rs"]
    });
    let manifest = serde_json::to_vec(&manifest).expect("manifest");
    let manifest_digest = hex(&Sha256::digest(&manifest));
    let release_dir = root.join("releases").join(&manifest_digest);
    private_directory(&release_dir);
    private_directory(&release_dir.join("bin"));
    fs::write(release_dir.join("manifest.json"), manifest).expect("manifest file");
    fs::write(release_dir.join("bin/automonique"), executable).expect("binary file");
    fs::set_permissions(
        release_dir.join("manifest.json"),
        fs::Permissions::from_mode(0o600),
    )
    .expect("manifest mode");
    fs::set_permissions(
        release_dir.join("bin/automonique"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("binary mode");
    manifest_digest
}

/// The release root the daemon's `reload` and `rollback` verbs read.
pub fn release_root(config: &DaemonConfig) -> PathBuf {
    config.state_dir().join("improvement-code")
}

/// Installed releases of this executable, with `current` on `previous`.
pub struct InstalledReleases {
    pub root: PathBuf,
    /// The release `current` starts on; a reload to `next` leaves it as the
    /// rollback target.
    pub previous: String,
    /// The reload target.
    pub next: String,
    /// A further release for a second reload after a failed one. A reload's
    /// identifier is derived from the source epoch and the target digest, and
    /// an exact retry of a terminal reload is answered with its recorded
    /// outcome rather than started again, so a proof that reloads twice from
    /// one epoch needs two targets.
    pub retry: String,
}

pub fn install_releases(config: &DaemonConfig) -> InstalledReleases {
    let root = release_root(config);
    private_directory(&root);
    private_directory(&root.join("releases"));
    let executable = fs::read(env!("CARGO_BIN_EXE_automonique")).expect("candidate binary");
    let previous = install_code_release(&root, &executable, 'a');
    let next = install_code_release(&root, &executable, 'c');
    let retry = install_code_release(&root, &executable, 'e');
    std::os::unix::fs::symlink(Path::new("releases").join(&previous), root.join("current"))
        .expect("initial current release");
    InstalledReleases {
        root,
        previous,
        next,
        retry,
    }
}

/// The reload identifier the daemon derives for one operation.
pub fn reload_id_for(kind: &str, source_epoch: u64, manifest_digest: &str) -> String {
    format!("{kind}-{source_epoch}-{}", &manifest_digest[..16])
}

// --- the product binary ---------------------------------------------------

pub fn cli_command(config: &DaemonConfig) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_automonique"));
    command
        .env("XDG_RUNTIME_DIR", &config.runtime_root)
        .env("XDG_STATE_HOME", &config.state_root);
    command
}

pub fn cli(config: &DaemonConfig, args: &[&str]) -> Output {
    cli_command(config)
        .args(args)
        .output()
        .expect("product binary runs")
}

pub fn spawn_cli(config: &DaemonConfig, args: &[&str]) -> Child {
    cli_command(config)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("product binary spawns")
}

pub fn stdout_text(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout UTF-8")
}

pub fn stderr_text(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr UTF-8")
}

/// `reload-status` as the CLI prints it, or `None` while nobody answers.
pub fn reload_status(config: &DaemonConfig, reload_id: &str) -> Option<String> {
    let output = cli(config, &["reload-status", reload_id]);
    output.status.success().then(|| stdout_text(&output))
}

/// The `phase=` field of the reload's head line.
pub fn reload_phase(config: &DaemonConfig, reload_id: &str) -> Option<String> {
    let status = reload_status(config, reload_id)?;
    let head = status.lines().next()?;
    head.split_whitespace()
        .find_map(|field| field.strip_prefix("phase="))
        .map(str::to_owned)
}

/// Poll until the reload reports one of `phases`, returning the one seen.
pub fn wait_for_reload_phase(
    config: &DaemonConfig,
    reload_id: &str,
    phases: &[&str],
    timeout: Duration,
) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(phase) = reload_phase(config, reload_id)
            && phases.contains(&phase.as_str())
        {
            return phase;
        }
        assert!(
            Instant::now() < deadline,
            "{reload_id} did not reach any of {phases:?}; last status {:?}",
            reload_status(config, reload_id)
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

// --- durable lease --------------------------------------------------------

pub struct SourceLease {
    pub holder_id: String,
    pub epoch: u64,
    pub boot_id: String,
    pub pid: u32,
    pub starttime: u64,
    pub revision: u64,
}

pub fn read_source_lease(path: &Path) -> SourceLease {
    try_read_source_lease(path).expect("source lease")
}

/// The generation row, or `None` while no daemon has written one yet.
///
/// A foreground daemon binds its socket before it acquires the lease, so a
/// caller that only waited for the socket can be here before the row exists.
pub fn try_read_source_lease(path: &Path) -> Option<SourceLease> {
    let connection = Connection::open(path).ok()?;
    // A daemon is writing beside this reader; wait for it rather than
    // reporting its checkpoint as a missing row.
    connection
        .busy_timeout(Duration::from_secs(10))
        .expect("busy timeout");
    connection
        .query_row(
            "SELECT lease_holder, lease_epoch, boot_id, holder_pid, holder_starttime, revision
             FROM generations
             WHERE generation_id = 'foreground'",
            [],
            |row| {
                Ok(SourceLease {
                    holder_id: row.get(0)?,
                    epoch: row.get(1)?,
                    boot_id: row.get(2)?,
                    pid: row.get(3)?,
                    starttime: row.get(4)?,
                    revision: row.get(5)?,
                })
            },
        )
        .ok()
}

/// Wait until a daemon at `config` holds the generation, and return its lease.
pub fn wait_for_generation(config: &DaemonConfig) -> SourceLease {
    wait_for_socket(config);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(lease) = try_read_source_lease(&config.database_path()) {
            return lease;
        }
        assert!(
            Instant::now() < deadline,
            "no daemon acquired the generation"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub fn process_is_live(pid: u32) -> bool {
    i32::try_from(pid).is_ok_and(|raw| kill(Pid::from_raw(raw), None).is_ok())
}

/// Whether a process is gone or is a zombie nobody has reaped yet.
///
/// A committed candidate is a child of the generation that spawned it; when
/// the spawner is this test process the exited child stays a zombie, which
/// `kill(pid, 0)` still counts as present.
pub fn process_exited(pid: u32) -> bool {
    if !process_is_live(pid) {
        return true;
    }
    fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit(')')
            .next()
            .is_some_and(|rest| rest.trim_start().starts_with('Z'))
    })
}

/// PIDs of live reload-candidate processes spawned for `reload_id`.
pub fn candidate_processes(reload_id: &str) -> Vec<u32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|cmdline| {
                let words: Vec<&[u8]> = cmdline.split(|byte| *byte == 0).collect();
                words.contains(&b"__reload-candidate".as_slice())
                    && words.contains(&reload_id.as_bytes())
            }) && !process_exited(*pid)
        })
        .collect()
}

/// The lease clock the daemon itself uses, for a store handle a test opens
/// beside a running daemon.
pub struct ProcBootTime;

impl automonique_store::LeaseTimeSource for ProcBootTime {
    fn now_boottime_ms(&self) -> Result<i64, &'static str> {
        use nix::sys::time::TimeValLike as _;
        nix::time::ClockId::CLOCK_BOOTTIME
            .now()
            .map(|value| value.num_milliseconds())
            .map_err(|_| "clock_gettime")
    }
}

pub fn unix_millis() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_millis(),
    )
    .expect("Unix milliseconds fit i64")
}

pub fn wait_until(what: &str, timeout: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

// --- an in-process source daemon -----------------------------------------

pub struct Serving {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<(), DaemonError>>>,
}

impl Serving {
    /// Put an opened daemon on a thread and wait for its socket.
    pub fn start(daemon: Daemon, config: &DaemonConfig) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::spawn(move || daemon.serve(&thread_stop));
        wait_for_socket(config);
        Self {
            stop,
            thread: Some(thread),
        }
    }

    /// Wait for the serve loop to return on its own.
    pub fn join(mut self) -> Result<(), DaemonError> {
        self.thread
            .take()
            .expect("serving")
            .join()
            .expect("serve thread")
    }

    /// Ask the daemon to stop over its socket and wait for a clean return.
    pub fn shutdown(mut self, config: &DaemonConfig) {
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
            self.stop.store(true, Ordering::Release);
            let _ = thread.join();
        }
    }
}

pub fn wait_for_socket(config: &DaemonConfig) {
    wait_until("the admin socket", Duration::from_secs(15), || {
        config.admin_socket().exists()
    });
}

pub fn wait_for_sockets_removed(config: &DaemonConfig) {
    wait_until(
        "the endpoints to be removed",
        Duration::from_secs(10),
        || !config.admin_socket().exists() && !config.progress_socket().exists(),
    );
}

// --- lanes over the socket -----------------------------------------------

pub fn exchange(config: &DaemonConfig, payload: &[u8]) -> Option<Vec<u8>> {
    let mut stream = UnixStream::connect(config.admin_socket()).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("read deadline");
    let mut frame = Vec::new();
    encode_frame(payload, &mut frame).expect("frame request");
    stream.write_all(&frame).ok()?;
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).ok()?;
    let length = u32::from_be_bytes(prefix) as usize;
    let mut response = vec![0_u8; length + 4];
    response[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut response[4..]).ok()?;
    let FrameDecode::Frame { payload, .. } = decode_frame(&response).expect("response frame")
    else {
        panic!("complete response was incomplete")
    };
    Some(payload.to_vec())
}

pub fn admin(config: &DaemonConfig, request: AdminRequest) -> AdminResponse {
    let payload = request
        .to_message()
        .expect("encode request")
        .to_canonical_bytes();
    let response = exchange(config, &payload).expect("the admin lane answered");
    AdminResponse::from_canonical_bytes(&response).expect("admitted response")
}

pub fn execute(config: &DaemonConfig, label: &str, run: &str) -> ExecuteResponse {
    let request = ExecuteRequest::ExecuteRun {
        request_id: RequestId::new(label).expect("request ID"),
        run_id: RunId::new(run).expect("run identity"),
    };
    execute_exchange(config, &request)
}

pub fn cancel(
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
    execute_exchange(config, &request)
}

fn execute_exchange(config: &DaemonConfig, request: &ExecuteRequest) -> ExecuteResponse {
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

pub fn runs(config: &DaemonConfig, request: &RunsRequest) -> RunsResponse {
    let payload = request
        .to_message()
        .expect("encode runs request")
        .to_canonical_bytes();
    let response = exchange(config, &payload).expect("the runs lane answered");
    RunsResponse::from_canonical_bytes(&response).expect("admitted runs response")
}

pub fn listed_state(config: &DaemonConfig, label: &str, run: &str) -> RunState {
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

/// Submit one document and return the durable custody identity assigned.
pub fn submit(config: &DaemonConfig, spec: &RunSpec, key: &str) -> u64 {
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

pub fn spool_root(config: &DaemonConfig, run: &str) -> PathBuf {
    config.state_dir().join("runs").join(run).join("spool")
}

pub fn workspace_root(config: &DaemonConfig, run: &str) -> PathBuf {
    config.state_dir().join("runs").join(run).join("workspace")
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
    SandboxSpec::compile(SandboxSpecParts {
        profile: SandboxProfile::new(
            "handoff-profile",
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

/// The attempt identifier [`run_spec`] declares for `run`.
pub fn attempt_id_of(run: &str) -> String {
    format!("{run}-attempt-1")
}

/// One document naming `run`, whose busybox workload runs `script`.
pub fn run_spec(run: &str, script: &str) -> RunSpec {
    RunSpec::new(RunSpecParts {
        protocol_version: 1,
        coordinates: RunCoordinates::new(
            WorkId::new("work-1").expect("work"),
            RunId::new(run).expect("run"),
            AttemptId::new(attempt_id_of(run)).expect("attempt"),
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
