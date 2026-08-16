// SPDX-License-Identifier: Elastic-2.0

//! Exact-grant proofs for provider launch planning.
//!
//! These tests assert the *encoded frame* wherever they can, because the frame
//! is what the runner's entry helper actually enforces. A plan that merely
//! "exists" proves nothing; a plan whose bytes are pinned proves that no grant
//! appeared, disappeared, or widened.
//!
//! Nothing here executes a provider. The candidate files are fixture bytes with
//! no interpreter and no execute path taken.

use automonique_agents::{
    AdapterEnvironment, ExecutionMode, PromptDelivery, ProviderExecutable, ProviderKind,
    ProviderNetwork, ProviderSpawnRequest, ResumeBinding, RunCoordinates, RunRequest, SessionScope,
    SpawnPlanError,
};
use automonique_runner::SocketGrant;
use automonique_runner::filesystem::PathIntent;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

const EXECUTABLE_BYTES: &[u8] = b"fixture provider bytes; never executed by this test file\n";
const LOADER_BYTES: &[u8] = b"fixture loader bytes\n";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn scope() -> SessionScope {
    SessionScope::new("tenant-a", "codex-account", "codex-cli").expect("scope")
}

fn coordinates() -> RunCoordinates {
    RunCoordinates::new("run-1", "turn-1", scope()).expect("coordinates")
}

fn request(mode: ExecutionMode, environment: AdapterEnvironment) -> RunRequest {
    RunRequest::new(coordinates(), mode, b"prompt bytes".as_slice(), environment).expect("request")
}

/// A candidate file with fixed bytes and a safe mode, plus its digest.
fn candidate(directory: &Path, name: &str, bytes: &[u8]) -> (PathBuf, String) {
    let path = directory.join(name);
    fs::write(&path, bytes).expect("candidate bytes");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).expect("candidate mode");
    (path, digest(bytes))
}

struct Fixture {
    _directory: tempfile::TempDir,
    executable: PathBuf,
    executable_digest: String,
    loader: PathBuf,
    workspace: PathBuf,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (executable, executable_digest) = candidate(directory.path(), "provider", EXECUTABLE_BYTES);
    let (loader, _) = candidate(directory.path(), "loader", LOADER_BYTES);
    let workspace = directory.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    Fixture {
        _directory: directory,
        executable,
        executable_digest,
        loader,
        workspace,
    }
}

fn spawn_request(fixture: &Fixture, network: ProviderNetwork) -> ProviderSpawnRequest {
    ProviderSpawnRequest {
        kind: ProviderKind::Codex,
        executable: ProviderExecutable::pinned(
            fixture.executable.clone(),
            fixture.executable_digest.clone(),
        )
        .expect("pinned executable"),
        loader_grants: vec![fixture.loader.clone()],
        workspace_root: fixture.workspace.clone(),
        network,
    }
}

#[test]
fn a_plan_grants_exactly_what_it_names_and_nothing_else() {
    let fixture = fixture();
    let plan = spawn_request(&fixture, ProviderNetwork::NoNetwork)
        .plan(&request(
            ExecutionMode::NewSession,
            AdapterEnvironment::empty(),
        ))
        .expect("plan");

    assert_eq!(plan.kind(), ProviderKind::Codex);
    assert_eq!(plan.program(), fixture.executable);
    assert_eq!(plan.arguments(), ["exec", "--json", "-"]);
    assert_eq!(plan.verified_sha256(), fixture.executable_digest);
    assert_eq!(
        plan.prompt_delivery(),
        PromptDelivery::UnresolvedProviderStdin {
            prompt_bytes: b"prompt bytes".len()
        },
        "a plan must say out loud that it cannot deliver the prompt"
    );

    // The exact allowlist, in the exact order the frame carries it.
    assert_eq!(
        plan.grants(),
        [
            (PathIntent::ReadExecute, fixture.executable.clone()),
            (PathIntent::ReadExecute, fixture.loader.clone()),
            (PathIntent::ReadWrite, fixture.workspace.clone()),
            (PathIntent::Read, PathBuf::from("/dev/null")),
        ]
    );
    assert!(
        plan.socket_grants().is_empty(),
        "no network means no socket"
    );
    assert!(plan.connect_ports().is_empty());

    // The frame is what the entry helper enforces, so pin it byte for byte.
    let expected = format!(
        "schema=automonique.launch/v1\n\
         program={executable}\n\
         arg={exec}\n\
         arg={json}\n\
         arg={dash}\n\
         grant=read-execute:{executable}\n\
         grant=read-execute:{loader}\n\
         grant=read-write:{workspace}\n\
         grant=read:{devnull}\n\
         end=automonique.launch/v1\n",
        executable = hex(fixture.executable.as_os_str().as_encoded_bytes()),
        exec = hex(b"exec"),
        json = hex(b"--json"),
        dash = hex(b"-"),
        loader = hex(fixture.loader.as_os_str().as_encoded_bytes()),
        workspace = hex(fixture.workspace.as_os_str().as_encoded_bytes()),
        devnull = hex(b"/dev/null"),
    );
    assert_eq!(
        String::from_utf8(plan.encode_frame().expect("frame")).expect("ascii frame"),
        expected
    );
    // No socket line at all: the frame cannot silently carry one.
    assert!(!expected.contains("socket="));
    assert!(!expected.contains("connect_port="));
    assert!(!expected.contains("bind_port="));
}

#[test]
fn a_resume_plan_carries_the_provider_session_in_argv() {
    let fixture = fixture();
    let binding = ResumeBinding::new(scope(), "fixture-session").expect("binding");
    let plan = spawn_request(&fixture, ProviderNetwork::NoNetwork)
        .plan(&request(
            ExecutionMode::Resume(binding),
            AdapterEnvironment::empty(),
        ))
        .expect("plan");
    assert_eq!(
        plan.arguments(),
        ["exec", "resume", "fixture-session", "--json", "-"]
    );
    // Resuming changes argv only; the allowlist is identical.
    assert_eq!(plan.grants().len(), 4);
    assert!(plan.socket_grants().is_empty());
}

#[test]
fn a_session_plan_has_one_closed_long_lived_argv_shape_and_no_prompt() {
    let fixture = fixture();
    let request = request(ExecutionMode::NewSession, AdapterEnvironment::empty());
    let planned = spawn_request(&fixture, ProviderNetwork::NoNetwork)
        .plan_session(&request)
        .expect("session plan");
    assert_eq!(planned.arguments(), &["app-server"]);
    assert_eq!(
        planned.prompt_delivery(),
        automonique_agents::PromptDelivery::SessionNdjson
    );
    assert_eq!(planned.launch_plan().prompt_len(), None);
}

#[test]
fn a_tcp_plan_grants_exactly_tcp_and_exactly_the_named_ports() {
    let fixture = fixture();
    let plan = spawn_request(
        &fixture,
        ProviderNetwork::TcpWithPorts {
            connect_ports: vec![443, 8443],
        },
    )
    .plan(&request(
        ExecutionMode::NewSession,
        AdapterEnvironment::empty(),
    ))
    .expect("plan");

    // ProviderNetwork has no spelling for AF_UNIX, SOCK_SEQPACKET, UDP, raw
    // sockets, or a bind port, so this is the widest grant any caller can ask
    // for. The assertion pins that the mapping did not add anything either.
    assert_eq!(plan.socket_grants(), [SocketGrant::Tcp]);
    assert_eq!(plan.connect_ports(), [443, 8443]);

    let frame = String::from_utf8(plan.encode_frame().expect("frame")).expect("ascii frame");
    let socket_lines = frame
        .lines()
        .filter(|line| line.starts_with("socket="))
        .collect::<Vec<_>>();
    assert_eq!(socket_lines, ["socket=tcp"]);
    let port_lines = frame
        .lines()
        .filter(|line| line.starts_with("connect_port=") || line.starts_with("bind_port="))
        .collect::<Vec<_>>();
    assert_eq!(port_lines, ["connect_port=443", "connect_port=8443"]);
}

#[test]
fn an_empty_tcp_grant_is_refused_rather_than_treated_as_no_network() {
    let fixture = fixture();
    let error = spawn_request(
        &fixture,
        ProviderNetwork::TcpWithPorts {
            connect_ports: Vec::new(),
        },
    )
    .plan(&request(
        ExecutionMode::NewSession,
        AdapterEnvironment::empty(),
    ))
    .expect_err("empty port list refused");
    assert_eq!(error.category(), "empty_tcp_grant");
}

#[test]
fn the_ephemeral_port_is_refused_by_the_runners_own_policy() {
    let fixture = fixture();
    let error = spawn_request(
        &fixture,
        ProviderNetwork::TcpWithPorts {
            connect_ports: vec![0],
        },
    )
    .plan(&request(
        ExecutionMode::NewSession,
        AdapterEnvironment::empty(),
    ))
    .expect_err("port 0 refused");
    // Delegated, not re-implemented: the refusal comes from the runner.
    assert_eq!(error.category(), "plan_rejected");
    assert!(
        error.to_string().contains("port"),
        "refusal must name the port policy, got {error}"
    );
}

#[test]
fn a_digest_that_does_not_match_the_file_is_refused_at_plan_time() {
    let fixture = fixture();
    let mut spawn = spawn_request(&fixture, ProviderNetwork::NoNetwork);
    let wrong = digest(b"different bytes entirely");
    spawn.executable =
        ProviderExecutable::pinned(fixture.executable.clone(), wrong.clone()).expect("pinned");
    let error = spawn
        .plan(&request(
            ExecutionMode::NewSession,
            AdapterEnvironment::empty(),
        ))
        .expect_err("digest mismatch refused");
    assert_eq!(error.category(), "digest_mismatch");
    let message = error.to_string();
    assert!(message.contains(&wrong), "refusal names the pin: {message}");
    assert!(
        message.contains(&fixture.executable_digest),
        "refusal names what was observed: {message}"
    );
}

#[test]
fn the_file_is_hashed_at_plan_time_not_trusted_from_the_pin() {
    let fixture = fixture();
    let spawn = spawn_request(&fixture, ProviderNetwork::NoNetwork);
    spawn
        .plan(&request(
            ExecutionMode::NewSession,
            AdapterEnvironment::empty(),
        ))
        .expect("plan while the bytes still match");

    // Replace the executable's contents behind the same pin. A planner that
    // trusted the caller's digest would keep succeeding.
    fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(0o700))
        .expect("temporarily writable");
    fs::write(&fixture.executable, b"swapped bytes\n").expect("swap");
    fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(0o500))
        .expect("restore mode");

    let error = spawn
        .plan(&request(
            ExecutionMode::NewSession,
            AdapterEnvironment::empty(),
        ))
        .expect_err("swapped bytes refused");
    assert_eq!(error.category(), "digest_mismatch");
    assert!(error.to_string().contains(&digest(b"swapped bytes\n")));
}

#[test]
fn relative_paths_are_refused_for_every_coordinate() {
    let fixture = fixture();
    let error = ProviderExecutable::pinned("relative/provider", fixture.executable_digest.clone())
        .expect_err("relative executable refused");
    assert_eq!(error.category(), "path_not_absolute");
    assert!(error.to_string().contains("provider executable"));

    let mut spawn = spawn_request(&fixture, ProviderNetwork::NoNetwork);
    spawn.workspace_root = PathBuf::from("relative/workspace");
    let error = spawn
        .plan(&request(
            ExecutionMode::NewSession,
            AdapterEnvironment::empty(),
        ))
        .expect_err("relative workspace refused");
    assert_eq!(error.category(), "path_not_absolute");
    assert!(error.to_string().contains("workspace root"));

    let mut spawn = spawn_request(&fixture, ProviderNetwork::NoNetwork);
    spawn.loader_grants = vec![PathBuf::from("relative/loader")];
    let error = spawn
        .plan(&request(
            ExecutionMode::NewSession,
            AdapterEnvironment::empty(),
        ))
        .expect_err("relative loader grant refused");
    assert_eq!(error.category(), "path_not_absolute");
    assert!(error.to_string().contains("loader grant"));
}

#[test]
fn missing_symlinked_and_duplicated_grant_paths_are_refused() {
    let fixture = fixture();

    let mut spawn = spawn_request(&fixture, ProviderNetwork::NoNetwork);
    spawn.workspace_root = fixture.workspace.join("absent");
    assert_eq!(
        spawn
            .plan(&request(
                ExecutionMode::NewSession,
                AdapterEnvironment::empty()
            ))
            .expect_err("missing workspace refused")
            .category(),
        "workspace_root_unusable"
    );

    // A symlinked grant would open its target's hierarchy, not the written
    // path; the runner refuses that at enforcement time, so refuse it here
    // while the refusal can still name the path.
    let linked = fixture.workspace.join("linked-workspace");
    symlink(&fixture.workspace, &linked).expect("workspace symlink");
    let mut spawn = spawn_request(&fixture, ProviderNetwork::NoNetwork);
    spawn.workspace_root = linked;
    assert_eq!(
        spawn
            .plan(&request(
                ExecutionMode::NewSession,
                AdapterEnvironment::empty()
            ))
            .expect_err("symlinked workspace refused")
            .category(),
        "workspace_root_unusable"
    );

    let mut spawn = spawn_request(&fixture, ProviderNetwork::NoNetwork);
    spawn.loader_grants = vec![fixture.workspace.join("absent-loader")];
    assert_eq!(
        spawn
            .plan(&request(
                ExecutionMode::NewSession,
                AdapterEnvironment::empty()
            ))
            .expect_err("missing loader grant refused")
            .category(),
        "grant_path_unusable"
    );

    // Two grants naming the same path have an ambiguous effective intent.
    let mut spawn = spawn_request(&fixture, ProviderNetwork::NoNetwork);
    spawn.loader_grants = vec![fixture.executable.clone()];
    let error = spawn
        .plan(&request(
            ExecutionMode::NewSession,
            AdapterEnvironment::empty(),
        ))
        .expect_err("duplicate grant refused");
    assert_eq!(error.category(), "plan_rejected");
    assert!(
        error.to_string().contains("same path"),
        "refusal must name the duplication, got {error}"
    );
}

#[test]
fn an_unsafe_or_malformed_executable_pin_is_refused() {
    let fixture = fixture();

    assert_eq!(
        ProviderExecutable::pinned(fixture.executable.clone(), "0123abc")
            .expect_err("short digest refused")
            .category(),
        "digest_malformed"
    );
    assert_eq!(
        ProviderExecutable::pinned(
            fixture.executable.clone(),
            fixture.executable_digest.to_uppercase(),
        )
        .expect_err("uppercase digest refused")
        .category(),
        "digest_malformed"
    );

    // Group-writable: anyone in the group could swap the bytes after the hash.
    fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(0o520))
        .expect("group writable");
    let error = spawn_request(&fixture, ProviderNetwork::NoNetwork)
        .plan(&request(
            ExecutionMode::NewSession,
            AdapterEnvironment::empty(),
        ))
        .expect_err("group-writable executable refused");
    assert_eq!(error.category(), "executable_rejected");
    assert!(error.to_string().contains("unsafe_executable"));
}

#[test]
fn too_many_loader_grants_are_refused() {
    let fixture = fixture();
    let mut spawn = spawn_request(&fixture, ProviderNetwork::NoNetwork);
    spawn.loader_grants = (0..=automonique_agents::MAX_LOADER_GRANTS)
        .map(|index| fixture.workspace.join(format!("loader-{index}")))
        .collect();
    let error = spawn
        .plan(&request(
            ExecutionMode::NewSession,
            AdapterEnvironment::empty(),
        ))
        .expect_err("too many loader grants refused");
    assert_eq!(error.category(), "too_many_loader_grants");
}

#[test]
fn an_undeliverable_environment_is_refused_not_dropped() {
    let fixture = fixture();
    let environment = AdapterEnvironment::new([
        ("CODEX_HOME".to_owned(), "/opaque/config".to_owned()),
        ("SSL_CERT_FILE".to_owned(), "/opaque/cert".to_owned()),
    ])
    .expect("allowlisted names");
    let error = spawn_request(&fixture, ProviderNetwork::NoNetwork)
        .plan(&request(ExecutionMode::NewSession, environment))
        .expect_err("environment refused");
    assert_eq!(error.category(), "environment_not_deliverable");
    let message = error.to_string();
    assert!(message.contains("CODEX_HOME"), "names the keys: {message}");
    assert!(message.contains("SSL_CERT_FILE"));
    // The keys are named; the values are never touched by the planner.
    assert!(!message.contains("/opaque/config"));
    assert!(!message.contains("/opaque/cert"));
}

#[test]
fn planning_starts_no_process_and_the_adapter_still_refuses_to() {
    // The candidate would create a marker if anything ever executed it.
    let directory = tempfile::tempdir().expect("temporary directory");
    let marker = directory.path().join("must-not-exist");
    let script = format!("#!/bin/sh\ntouch '{}'\n", marker.display());
    let (executable, executable_digest) =
        candidate(directory.path(), "provider", script.as_bytes());
    let workspace = directory.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");

    let spawn = ProviderSpawnRequest {
        kind: ProviderKind::Codex,
        executable: ProviderExecutable::pinned(executable, executable_digest).expect("pinned"),
        loader_grants: Vec::new(),
        workspace_root: workspace,
        network: ProviderNetwork::NoNetwork,
    };
    let run_request = request(ExecutionMode::NewSession, AdapterEnvironment::empty());
    let plan = spawn.plan(&run_request).expect("plan");
    assert!(!plan.encode_frame().expect("frame").is_empty());
    assert!(
        !marker.exists(),
        "planning must never execute the candidate"
    );

    // Planning a launch did not become permission to perform one.
    let inspection =
        automonique_agents::ExecutableInspection::inspect(plan.program()).expect("inspection");
    let invocation = automonique_agents::CodexInvocationPlan::new(inspection, &run_request);
    assert_eq!(
        automonique_agents::CodexAdapter::open(&invocation)
            .err()
            .expect("adapter still refuses")
            .category(),
        "execution_unavailable"
    );
    assert!(!marker.exists());
}

#[test]
fn error_categories_are_stable_spellings() {
    // A refusal a caller cannot match on is a refusal that gets logged and
    // ignored; pin the vocabulary.
    let categories = [
        SpawnPlanError::DigestMalformed.category(),
        SpawnPlanError::EmptyTcpGrant.category(),
        SpawnPlanError::TooManyLoaderGrants(99).category(),
        SpawnPlanError::GrantPathUnusable(PathBuf::from("/absent")).category(),
        SpawnPlanError::EnvironmentNotDeliverable(vec!["CODEX_HOME".to_owned()]).category(),
    ];
    assert_eq!(
        categories,
        [
            "digest_malformed",
            "empty_tcp_grant",
            "too_many_loader_grants",
            "grant_path_unusable",
            "environment_not_deliverable",
        ]
    );
}
