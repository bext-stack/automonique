// SPDX-License-Identifier: Elastic-2.0

//! `/run` end to end, with no provider and no network: what a composed document
//! is admitted to, and that the answer a contained run writes comes back.
//!
//! # The claim, and the proofs under it
//!
//! The claim is that an operator's `/run <task>` becomes one contained run whose
//! answer is the reply — composed by this daemon, admitted by the Wave-4
//! brokered execute lane, run under the real containment, and read back out of
//! the run's own attempt workspace.
//!
//! 1. [`a_composed_document_is_admitted_and_carries_unix_plus_the_broker_grants`]
//!    pins the composition to the byte. The composed document is decoded,
//!    admitted against the context this daemon builds, attached to a *running*
//!    broker, and the encoded launch frame is asserted to carry `socket=tcp`,
//!    `socket=unix`, one `connect_port` equal to that broker's own, and the two
//!    proxy variables — and to carry no UDP grant, no port 443, no bind port and
//!    no resolver file.
//! 2. [`the_answer_path_is_the_attempt_workspace_the_lane_will_resolve`] is the seam the
//!    whole answer-capture design rests on: the path in the argv is the path
//!    [`automonique_daemon::execute::run_attempt_workspace`] resolves, absolute, inside
//!    the attempt workspace, and named in the document rather than patched in later.
//! 3. [`the_task_reaches_the_prompt_and_nothing_else`] is the containment of the
//!    *operator's* input: the task is the prompt, and it is in no argument, no
//!    environment value and no path.
//! 4. [`an_unconfigured_deployment_composes_nothing`] is the gate: no provider,
//!    or no destination policy, is a refusal an operator can read, never a panic
//!    and never a partial document.
//!
//! Those four are pure. They run everywhere, need no host capability, and start
//! no workload.
//!
//! # The contained proof
//!
//! [`a_contained_run_answers_through_the_real_lane`] is the one that closes the
//! gap, and it needs the enforced host every execution proof needs: a delegated
//! cgroup v2 domain, the Landlock and seccomp mechanisms, busybox, and the built
//! entry helper. It drives the **production** [`SocketRunLane`] against a
//! **serving daemon** — so the composer, the prompt slot, the admin socket, the
//! execute lane, the broker, the containment, the read model and the answer read
//! are all the real ones — and asserts that the string the contained workload
//! wrote is the string the lane hands back for the reply.
//!
//! ```sh
//! cd rust
//! cargo build -p automonique-runner --bin automonique-launch-enter
//! cargo test -p automonique-daemon --test run_compose --no-run
//! systemd-run --user --scope -p Delegate=yes \
//!   --setenv=AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1 \
//!   "$(ls -t target/debug/deps/run_compose-* | grep -v '\.d$' | head -1)" \
//!   --test-threads=1 --nocapture
//! ```
//!
//! The scope must wrap the **test binary** rather than `cargo test`: cgroup v2
//! forbids enabling `subtree_control` on a cgroup that holds member processes,
//! so wrapping cargo makes every request answer `containment_unavailable`.
//!
//! # Non-vacuity
//!
//! Two runs in one test write two *different* tokens, and each reply is asserted
//! to carry its own run's token and not the other's — so a lane that read a
//! fixed path, cached an answer, or reported the wrong run's attempt workspace fails.
//! Beside them, a workload that writes no answer is asserted to reach
//! [`RunFailure::NoAnswer`] and one that exits nonzero to reach
//! [`RunFailure::Failed`], so "the answer came back" is not something this
//! harness says about every run.
//!
//! # What none of this establishes
//!
//! **No real provider runs here.** The workload is busybox copying its own
//! prompt into the file the document named. That a real provider honours
//! `HTTPS_PROXY`, tunnels a model round trip through this broker, and writes its
//! final message where `-o` told it to is an owner-run, paid, networked proof,
//! and nothing in this file stands in for it.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use automonique_daemon::compose::{
    ANSWER_LEAF, ANSWER_PLACEHOLDER, ATTEMPT_WORKSPACE_PLACEHOLDER, COMPOSE_MEMORY_BYTES,
    ComposeRefusal, Composition, CompositionInputs, DEFAULT_ARGV, ManagedSessionMode,
    PROVIDER_CONFIG_NAME, ProviderConfig, ProviderEngine, ProviderRunProfile,
    QUESTION_MEMORY_BYTES, QUESTION_MODEL_CONFIG, QUESTION_REASONING_CONFIG, compose,
    compose_managed, compose_with_profile,
};
use automonique_daemon::execute::{
    DAEMON_ATTEMPT_WORKSPACE_REGISTRY, DAEMON_BACKEND_ID, DAEMON_DRAINING_REASON,
    JCODE_INTEGRATION_MODE, JCODE_RESUME_ENV, locate_launch_helper, offered_host_features,
    run_attempt_workspace,
};
use automonique_daemon::run_lane::{
    CONVERSATION_PROVIDER_CONFIG_NAME, PROVIDER_DEPLOYMENTS_NAME, SocketRunLane,
};
use automonique_daemon::telegram_bridge::{QuestionProfile, QuestionRuntime, RunFailure, RunLane};
use automonique_daemon::{Daemon, DaemonConfig, RUN_INDEX_NAME};
use automonique_egress_broker::{BrokerConfig, EgressBroker};
use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse};
use automonique_protocol::approval_api::{
    ApprovalDecision, ApprovalKey, ApprovalRequest, ApprovalResponse, DecideRequest, Decider,
};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_protocol::digest::Sha256;
use automonique_protocol::platform::{
    ClaimControlRequest, ClientId, ExecuteRequest as PlatformExecuteRequest, IdempotencyKey,
    PlatformAction, PlatformRequest, PlatformResponse, PlatformText, ReceiptOutcome,
    ReleaseControlRequest, ResourceAuthority, ResourceCoordinate, ResourceId, ResourceKind,
};
use automonique_protocol::platform_api::{PlatformRequestMessage, PlatformResponseMessage};
use automonique_protocol::progress_api::ProgressFrame;
use automonique_protocol::sandbox::{
    Digest, ExecutionBackendId, HostFeature, ImplementationDigest, PathAccess,
};
use automonique_runner::admission::{
    AdmissionContext, AdmissionContextParts, AdmittedLaunch, BrokeredDestination, BrokeredScope,
    PromptSource, ProviderIdentityPolicy, ResolvedPrompt, TemporaryStorageEnforcement,
    UnenforcedBudget, admit,
};
use automonique_runner::capability::HostCapabilities;
use automonique_runner::{
    AttemptWorkspaceRegistryId, ContainmentDomain, LaunchPlan, PromptDeliveryPlan,
    ProtectedPromptReference, RunSpec,
};
use automonique_store::approval_requests::{ApprovalRequests, ApprovalState};
use automonique_store::provider_deployments::{DeploymentRegistration, ProviderDeployments};

#[path = "support/isolation.rs"]
mod test_isolation;

const BUSYBOX: &str = "/usr/bin/busybox";
const REQUIRE_ENFORCED_ENV: &str = "AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT";
/// What a contained run's answer file is prefixed with, so a reply that carries
/// it cannot have come from anywhere but the workload.
const ANSWER_PREFIX: &str = "AUTOMONIQUE-ANSWER:";
const LANE_DEADLINE: Duration = Duration::from_secs(120);

// --- fixtures -------------------------------------------------------------

/// A private state tree with the daemon's directories and both policy files.
///
/// Both are written before the daemon opens, because both are read once at
/// open: what a run is composed and admitted against is the policy this daemon
/// started with.
struct Fixture {
    _root: tempfile::TempDir,
    config: DaemonConfig,
}

impl Fixture {
    /// Build the tree. `provider` and `policy` are written only when given, so a
    /// test can prove what an unconfigured deployment does.
    fn new(provider: Option<&str>, policy: Option<&str>) -> Self {
        let root = tempfile::tempdir().expect("temporary root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let runtime = root.path().join("runtime");
        test_isolation::assert_isolated_runtime_root(&runtime);
        let state = root.path().join("state");
        for directory in [&runtime, &state] {
            std::fs::create_dir(directory).expect("root");
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .expect("private root");
        }
        let state_dir = state.join("automonique");
        std::fs::create_dir(&state_dir).expect("state directory");
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))
            .expect("private state directory");
        if let Some(body) = provider {
            write_private(&state_dir.join(PROVIDER_CONFIG_NAME), body);
        }
        if let Some(body) = policy {
            write_private(&state_dir.join("egress-destinations"), body);
        }
        Self {
            _root: root,
            config: DaemonConfig {
                runtime_root: runtime,
                state_root: state,
            },
        }
    }

    fn state_dir(&self) -> PathBuf {
        self.config.state_dir()
    }

    /// The provider home every fixture grants, created so a grant on it can be
    /// enforced rather than refused for naming nothing.
    fn provider_home(&self) -> PathBuf {
        let home = self.state_dir().join("provider-home");
        if !home.exists() {
            std::fs::create_dir(&home).expect("provider home");
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
                .expect("private provider home");
        }
        home
    }

    fn provider(&self) -> ProviderConfig {
        ProviderConfig::load(&self.state_dir().join(PROVIDER_CONFIG_NAME))
            .expect("the provider configuration parses")
            .expect("a provider is configured")
    }
}

fn write_private(path: &Path, body: &str) {
    std::fs::write(path, body).expect("configuration written");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("private configuration");
}

/// A provider configuration naming busybox and one invocation.
///
/// `argv` is the whole override, so what runs is exactly what a test wrote.
fn busybox_provider(home: &Path, argv: &[&str]) -> String {
    let mut body = format!(
        "binary={BUSYBOX}\nhome={}\nversion=busybox-hermetic\n",
        home.display()
    );
    for argument in argv {
        body.push_str(&format!("arg={argument}\n"));
    }
    body
}

/// The invocation that copies this run's prompt into this run's answer file.
///
/// Everything it executes is the granted busybox by absolute path, and the
/// redirection lands in the workspace the launch granted read-write. `cat` with
/// no operand reads the workload's stdin, which is where the launch delivers the
/// prompt — so the answer is a function of the task, and a lane that lost the
/// task produces an answer that does not match.
fn echo_prompt_argv() -> Vec<String> {
    vec![
        String::from("sh"),
        String::from("-c"),
        format!(
            "{{ {BUSYBOX} printf '%s' '{ANSWER_PREFIX}'; {BUSYBOX} cat; }} > {ANSWER_PLACEHOLDER}"
        ),
    ]
}

/// A synthetic feature the pure proofs negotiate against, so they assert the
/// same composition on every machine.
fn synthetic_feature() -> HostFeature {
    HostFeature::new(
        "descendant_containment",
        ImplementationDigest::parse(&format!("sha256:{}", "3".repeat(64))).expect("digest"),
    )
    .expect("feature")
}

/// What this host really offers, or the synthetic stand-in on a host that offers
/// nothing.
fn features() -> Vec<HostFeature> {
    let offered = offered_host_features();
    if offered.is_empty() {
        vec![synthetic_feature()]
    } else {
        offered
    }
}

fn compose_for(fixture: &Fixture, run_id: &str, task: &str) -> Composition {
    compose(
        task,
        &CompositionInputs {
            state_dir: &fixture.state_dir(),
            run_id,
            provider: &fixture.provider(),
            offered_features: &features(),
            egress_configured: true,
        },
    )
    .expect("the task composes")
}

// --- reading a launch frame ----------------------------------------------

/// The lines of an encoded launch frame — the exact bytes the entry helper
/// consumes, so a grant that is in the frame is a grant the workload gets.
fn frame_lines(plan: &LaunchPlan) -> Vec<String> {
    String::from_utf8(plan.encode().expect("the plan encodes"))
        .expect("the frame is text")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn frame_environment(lines: &[String], name: &str) -> Option<String> {
    let wanted = hex(name.as_bytes());
    lines.iter().find_map(|line| {
        let entry = line.strip_prefix("env=")?;
        let (encoded_name, encoded_value) = entry.split_once(':')?;
        (encoded_name == wanted).then(|| unhex(encoded_value))
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(value: &str) -> String {
    let bytes: Vec<u8> = value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex pair"), 16).expect("hex byte")
        })
        .collect();
    String::from_utf8(bytes).expect("the value is text")
}

/// Admit a composed document exactly as the execution lane would.
fn admit_composed(
    fixture: &Fixture,
    composition: &Composition,
    destinations: &[BrokeredDestination],
) -> AdmittedLaunch {
    let spec = RunSpec::from_canonical_bytes(composition.document()).expect("the document decodes");
    let workspace = run_attempt_workspace(&fixture.state_dir(), composition.run_id());
    let prompt = composition.prompt().to_vec();
    let declared = Digest::parse(&format!("sha256:{}", Sha256::digest(&prompt).to_hex()))
        .expect("prompt digest");
    let PromptDeliveryPlan::ProtectedReference(slot) = spec.prompt_delivery().clone() else {
        panic!("a composed document must route its prompt through a protected slot")
    };
    let context = AdmissionContext::new(AdmissionContextParts {
        backend: ExecutionBackendId::new(DAEMON_BACKEND_ID).expect("backend"),
        attempt_workspace_registry_id: AttemptWorkspaceRegistryId::new(
            DAEMON_ATTEMPT_WORKSPACE_REGISTRY,
        )
        .expect("registry"),
        attempt_workspace_root: workspace.clone(),
        working_directory: workspace,
        observed_provider_binary: spec.provider_binary().clone(),
        host_features: features(),
        prompt: Some(
            ResolvedPrompt::new(
                PromptSource::ProtectedReference(
                    ProtectedPromptReference::new(slot.as_str()).expect("slot"),
                ),
                prompt,
                declared,
            )
            .expect("resolved prompt"),
        ),
        unenforced_budgets: UnenforcedBudget::ALL.to_vec(),
        brokered_destinations: destinations.to_vec(),
        provider_identity: ProviderIdentityPolicy::Disabled,
        temporary_storage: TemporaryStorageEnforcement::Available,
    })
    .expect("a valid context");
    admit(&spec, &context).expect("a composed document must be admissible")
}

// --- the pure proofs ------------------------------------------------------

/// A composed document is admitted, and the launch it produces carries the
/// `AF_UNIX` grant a real provider needs plus the broker grants and nothing
/// wider.
#[test]
fn a_composed_document_is_admitted_and_carries_unix_plus_the_broker_grants() {
    let fixture = Fixture::new(None, None);
    let home = fixture.provider_home();
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &busybox_provider(&home, &[]),
    );
    let composition = compose_for(&fixture, "composed1", "say something");
    let destinations = [
        BrokeredDestination::new("chatgpt.com", 443, BrokeredScope::Public).expect("destination"),
    ];
    let admitted = admit_composed(&fixture, &composition, &destinations);

    // ADMISSION NAMES THE DESTINATIONS AND STARTS NO BROKER.
    let requirement = admitted
        .broker_requirement()
        .expect("a composed document declares brokered egress");
    assert_eq!(requirement.destinations(), &destinations);
    let bare = frame_lines(admitted.plan());
    assert!(
        !bare.iter().any(|line| line.starts_with("socket=")),
        "an unattached plan must carry no socket grant at all, not even AF_UNIX: {bare:?}"
    );

    // A REAL BROKER, AND THE COMPOSITION IT PRODUCES.
    let broker = EgressBroker::start(BrokerConfig::default()).expect("the broker binds");
    let port = broker.local_addr().port();
    let admitted = admitted.with_broker(broker.local_addr()).expect("attached");
    let lines = frame_lines(admitted.plan());

    // WHAT THE WORKLOAD GETS.
    for grant in ["socket=tcp", "socket=unix"] {
        assert!(
            lines.iter().any(|line| line == grant),
            "a brokered provider launch must carry {grant}: {lines:?}"
        );
    }
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("connect_port="))
            .collect::<Vec<_>>(),
        vec![&format!("connect_port={port}")],
        "exactly one connect port, and it is this broker's own"
    );
    for name in ["HTTPS_PROXY", "HTTP_PROXY"] {
        assert_eq!(
            frame_environment(&lines, name).as_deref(),
            Some(broker.proxy_url().as_str()),
            "{name} must be the broker's own proxy URL"
        );
    }

    // WHAT IT DOES NOT GET. `AF_UNIX` is local IPC, and adding it must not have
    // dragged the pre-broker relaxation along with it.
    assert!(
        !lines.iter().any(|line| line == "socket=inet-datagram"),
        "no UDP socket: a brokered workload does no DNS at all: {lines:?}"
    );
    assert!(
        !lines.iter().any(|line| line == "socket=unix-seqpacket"),
        "only the two grants the composition names: {lines:?}"
    );
    assert!(
        !lines.iter().any(|line| line == "connect_port=443"),
        "no direct HTTPS egress: {lines:?}"
    );
    assert!(
        !lines.iter().any(|line| line.starts_with("bind_port=")),
        "no bind port, so the workload cannot impersonate its broker: {lines:?}"
    );
    for resolver_file in ["/etc/resolv.conf", "/etc/hosts"] {
        assert!(
            !lines
                .iter()
                .any(|line| line.starts_with("grant=")
                    && line.contains(&hex(resolver_file.as_bytes()))),
            "a brokered workload needs no resolver file: {resolver_file}"
        );
    }

    // AND THE PROVIDER'S OWN GRANTS ARE THERE, BECAUSE A PROVIDER NEEDS THEM.
    for granted in [home.to_str().expect("home is text"), "/etc/ssl/certs"] {
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("grant=") && line.contains(&hex(granted.as_bytes()))),
            "the composition must grant {granted}: {lines:?}"
        );
    }
}

/// The answer path in the document is the path the lane will resolve — absolute,
/// inside the run's own workspace, and named by the argv rather than patched in
/// afterwards.
#[test]
fn the_answer_path_is_the_attempt_workspace_the_lane_will_resolve() {
    let fixture = Fixture::new(None, None);
    let home = fixture.provider_home();
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &busybox_provider(&home, &[]),
    );
    let composition = compose_for(&fixture, "answerpath1", "say something");

    let attempt_workspace = run_attempt_workspace(&fixture.state_dir(), "answerpath1");
    assert_eq!(
        composition.answer_path(),
        attempt_workspace.join(ANSWER_LEAF),
        "the answer must live in the attempt workspace the execution lane resolves"
    );
    assert!(
        composition.answer_path().is_absolute(),
        "a relative answer path would be written wherever the daemon happened to be"
    );

    // THE DOCUMENT SAYS IT, so its canonical digest covers it and a reviewer
    // reads it there.
    let spec = RunSpec::from_canonical_bytes(composition.document()).expect("the document decodes");
    let arguments: Vec<String> = spec
        .arguments()
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    assert!(
        arguments.contains(&composition.answer_path().display().to_string()),
        "the argv must name the answer file absolutely: {arguments:?}"
    );
    assert!(
        arguments.contains(&attempt_workspace.display().to_string()),
        "the argv must point the provider at the resolved attempt workspace: {arguments:?}"
    );
    assert!(
        !arguments
            .iter()
            .any(|argument| argument.contains(ATTEMPT_WORKSPACE_PLACEHOLDER)
                || argument.contains(ANSWER_PLACEHOLDER)),
        "no placeholder may survive into the document: {arguments:?}"
    );
    // The reviewed default is what a deployment that configured no argv gets.
    assert!(
        DEFAULT_ARGV.contains(&"--json")
            && DEFAULT_ARGV.contains(&"--ephemeral")
            && DEFAULT_ARGV.contains(&ANSWER_PLACEHOLDER),
        "the reviewed invocation must stream JSONL and name its answer file"
    );
}

#[test]
fn managed_new_and_follow_up_argv_preserve_and_resume_one_exact_session() {
    let fixture = Fixture::new(None, None);
    let home = fixture.provider_home();
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &busybox_provider(&home, &[]),
    );
    let provider = fixture.provider();
    let offered = features();
    let new_run = compose_managed(
        "first turn",
        &CompositionInputs {
            state_dir: &fixture.state_dir(),
            run_id: "managed-new-1",
            provider: &provider,
            offered_features: &offered,
            egress_configured: true,
        },
        ManagedSessionMode::New,
    )
    .expect("managed new request");
    let new_spec = RunSpec::from_canonical_bytes(new_run.document()).expect("new spec");
    assert!(new_spec.arguments().iter().any(|value| value == "--json"));
    assert!(
        !new_spec
            .environment()
            .iter()
            .any(|(name, _)| name == "JCODE_RUNTIME_DIR" || name == "JCODE_NO_TELEMETRY"),
        "JCode-only variables never reach a Codex workload"
    );
    assert!(
        !new_spec
            .arguments()
            .iter()
            .any(|value| value == "--ephemeral")
    );

    let follow_up = compose_managed(
        "second turn",
        &CompositionInputs {
            state_dir: &fixture.state_dir(),
            run_id: "managed-follow-up-1",
            provider: &provider,
            offered_features: &offered,
            egress_configured: true,
        },
        ManagedSessionMode::Resume("018f0000-0000-7000-8000-000000000001"),
    )
    .expect("managed follow-up");
    let follow_spec = RunSpec::from_canonical_bytes(follow_up.document()).expect("follow-up spec");
    let arguments = follow_spec
        .arguments()
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        arguments,
        [
            "-s",
            "read-only",
            "-C",
            follow_up
                .answer_path()
                .parent()
                .expect("workspace")
                .to_str()
                .expect("workspace text"),
            "exec",
            "resume",
            "--skip-git-repo-check",
            "-o",
            follow_up.answer_path().to_str().expect("answer text"),
            "--json",
            "018f0000-0000-7000-8000-000000000001",
            "-",
        ]
    );
}

#[test]
fn jcode_composition_selects_the_supervised_protocol_and_exact_resume_binding() {
    let fixture = Fixture::new(None, None);
    let home = fixture.provider_home();
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &format!(
            "engine=jcode\nbinary={BUSYBOX}\nhome={}\nversion=jcode-fixture\narg=--quiet\narg=api-stdio\n",
            home.display()
        ),
    );
    let provider = fixture.provider();
    assert_eq!(provider.engine(), ProviderEngine::Jcode);
    let offered = features();
    let new = compose_managed(
        "first JCode turn",
        &CompositionInputs {
            state_dir: &fixture.state_dir(),
            run_id: "jcode-new-1",
            provider: &provider,
            offered_features: &offered,
            egress_configured: true,
        },
        ManagedSessionMode::New,
    )
    .expect("new JCode session composes");
    let new_spec = RunSpec::from_canonical_bytes(new.document()).expect("new JCode spec");
    assert_eq!(
        new_spec.admission().integration_mode().as_str(),
        JCODE_INTEGRATION_MODE
    );
    assert!(new_spec.arguments().iter().any(|arg| arg == "api-stdio"));
    assert!(
        new_spec
            .environment()
            .iter()
            .any(|(name, value)| name == "JCODE_HOME" && value == home.as_os_str())
    );
    assert!(
        new_spec
            .environment()
            .iter()
            .any(|(name, value)| name == "JCODE_NO_TELEMETRY" && value == "1"),
        "the sandbox has no telemetry egress; the opt-out keeps the notice out of the journal"
    );
    assert!(
        !new_spec
            .environment()
            .iter()
            .any(|(name, _)| name == JCODE_RESUME_ENV)
    );

    let session = "018f0000-0000-7000-8000-000000000001";
    let follow = compose_managed(
        "second JCode turn",
        &CompositionInputs {
            state_dir: &fixture.state_dir(),
            run_id: "jcode-follow-1",
            provider: &provider,
            offered_features: &offered,
            egress_configured: true,
        },
        ManagedSessionMode::Resume(session),
    )
    .expect("JCode follow-up composes");
    let follow_spec = RunSpec::from_canonical_bytes(follow.document()).expect("follow-up spec");
    assert_eq!(follow_spec.arguments(), new_spec.arguments());
    assert!(
        follow_spec.environment().iter().any(|(name, value)| {
            name == JCODE_RESUME_ENV && value.to_string_lossy() == session
        })
    );
}

/// The operator's task is the prompt, and it is nowhere else in the document.
#[test]
fn the_task_reaches_the_prompt_and_nothing_else() {
    let fixture = Fixture::new(None, None);
    let home = fixture.provider_home();
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &busybox_provider(&home, &[]),
    );
    let task = "UNIQUE-TASK-TEXT-9f2a";
    let composition = compose_for(&fixture, "prompt1", task);

    assert_eq!(
        composition.prompt(),
        task.as_bytes(),
        "the prompt must be the operator's task, byte for byte"
    );
    let spec = RunSpec::from_canonical_bytes(composition.document()).expect("the document decodes");
    for argument in spec.arguments() {
        assert!(
            !argument.to_string_lossy().contains(task),
            "the task must not become an argument"
        );
    }
    for (name, value) in spec.environment() {
        assert!(
            !value.to_string_lossy().contains(task),
            "the task must not become an environment value: {name:?}"
        );
    }
    assert!(
        !String::from_utf8_lossy(composition.document()).contains(task),
        "the task must not appear in the document at all; it lives in the slot"
    );
}

#[test]
fn read_only_question_profile_lowers_reasoning_without_reading_task_text() {
    let fixture = Fixture::new(None, None);
    let home = fixture.provider_home();
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &busybox_provider(&home, &[]),
    );
    let state_dir = fixture.state_dir();
    let provider = fixture.provider();
    let offered = features();
    let inputs = CompositionInputs {
        state_dir: &state_dir,
        run_id: "question-profile1",
        provider: &provider,
        offered_features: &offered,
        egress_configured: true,
    };
    let composition = compose_with_profile(
        "ordinary question text",
        &inputs,
        ProviderRunProfile::FastConversation,
    )
    .expect("question profile composes");
    let spec = RunSpec::from_canonical_bytes(composition.document()).expect("document decodes");
    let arguments: Vec<String> = spec
        .arguments()
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    assert!(
        arguments
            .windows(2)
            .any(|pair| pair == ["-c", QUESTION_REASONING_CONFIG]),
        "Q&A profile must carry the explicit low-reasoning override: {arguments:?}"
    );
    assert!(
        arguments
            .windows(2)
            .any(|pair| pair == ["-c", QUESTION_MODEL_CONFIG]),
        "Q&A profile must carry the explicit fast-model override: {arguments:?}"
    );
    assert_eq!(
        spec.sandbox().budgets().cgroup_memory().quantity(),
        QUESTION_MEMORY_BYTES,
        "conversation has a smaller memory ceiling than complex work"
    );

    let standard = compose(
        "AUTOMONIQUE_READ_ONLY_QA_V1\nuser-shaped marker",
        &CompositionInputs {
            state_dir: &state_dir,
            run_id: "standard-profile1",
            provider: &provider,
            offered_features: &offered,
            egress_configured: true,
        },
    )
    .expect("standard profile composes");
    let standard = RunSpec::from_canonical_bytes(standard.document()).expect("document decodes");
    assert!(
        !standard
            .arguments()
            .iter()
            .any(|argument| argument == QUESTION_REASONING_CONFIG),
        "task text must not select the Q&A profile"
    );
    assert_ne!(
        standard.sandbox().budgets().cgroup_memory().quantity(),
        QUESTION_MEMORY_BYTES,
        "standard work must retain its independent resource profile"
    );
    assert_eq!(
        standard.sandbox().budgets().cgroup_memory().quantity(),
        COMPOSE_MEMORY_BYTES
    );

    let intelligent = compose_with_profile(
        "an operational question",
        &CompositionInputs {
            state_dir: &state_dir,
            run_id: "intelligent-question1",
            provider: &provider,
            offered_features: &offered,
            egress_configured: true,
        },
        ProviderRunProfile::IntelligentQuestion,
    )
    .expect("intelligent question profile composes");
    let intelligent =
        RunSpec::from_canonical_bytes(intelligent.document()).expect("document decodes");
    assert_eq!(
        intelligent.sandbox().budgets().cgroup_memory().quantity(),
        QUESTION_MEMORY_BYTES
    );
    assert!(
        !intelligent
            .arguments()
            .iter()
            .any(|argument| argument == QUESTION_MODEL_CONFIG),
        "operational Q&A must retain the configured intelligent model"
    );

    let research = compose_with_profile(
        "an explicitly authorized public-web question",
        &CompositionInputs {
            state_dir: &state_dir,
            run_id: "web-research1",
            provider: &provider,
            offered_features: &offered,
            egress_configured: true,
        },
        ProviderRunProfile::WebResearch,
    )
    .expect("web research profile composes");
    let research = RunSpec::from_canonical_bytes(research.document()).expect("document decodes");
    let research_arguments: Vec<_> = research.arguments().iter().collect();
    assert_eq!(
        research_arguments
            .first()
            .map(|argument| argument.as_os_str()),
        Some(std::ffi::OsStr::new("--search")),
        "Codex live search is a global flag and must precede its subcommand"
    );
    assert_eq!(
        research_arguments
            .get(1)
            .map(|argument| argument.as_os_str()),
        Some(std::ffi::OsStr::new("exec")),
        "the fixed configured exec subcommand must remain directly after the search flag"
    );
    assert_eq!(
        research_arguments
            .get(2)
            .map(|argument| argument.as_os_str()),
        Some(std::ffi::OsStr::new("-c")),
        "the live web-search mode override follows the exec subcommand"
    );
    assert_eq!(
        research_arguments
            .get(3)
            .map(|argument| argument.as_os_str()),
        Some(std::ffi::OsStr::new(r#"web_search_mode="live""#)),
    );
    assert_eq!(
        research.sandbox().budgets().cgroup_memory().quantity(),
        QUESTION_MEMORY_BYTES
    );
    assert!(
        !intelligent
            .arguments()
            .iter()
            .any(|argument| argument == "--search"),
        "ordinary operational questions must remain no-search"
    );

    let scratchpad = compose_with_profile(
        "create and run a small Python program",
        &CompositionInputs {
            state_dir: &state_dir,
            run_id: "agentic-scratchpad1",
            provider: &provider,
            offered_features: &offered,
            egress_configured: true,
        },
        ProviderRunProfile::AgenticScratchpad,
    )
    .expect("agentic scratchpad profile composes");
    let scratchpad =
        RunSpec::from_canonical_bytes(scratchpad.document()).expect("document decodes");
    let scratchpad_arguments: Vec<String> = scratchpad
        .arguments()
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    assert!(
        scratchpad_arguments
            .windows(2)
            .any(|pair| pair == ["-s", "workspace-write"]),
        "the trusted scratchpad profile must enable Codex workspace writes: {scratchpad_arguments:?}"
    );
    for runtime in ["/usr/bin", "/usr/lib"] {
        assert!(
            scratchpad
                .sandbox()
                .path_grants()
                .as_slice()
                .iter()
                .any(|grant| grant.path().as_str() == runtime
                    && grant.access() == PathAccess::ReadExecute),
            "scratchpad runtime {runtime} must be executable but not writable"
        );
    }
    assert_eq!(
        scratchpad.sandbox().budgets().cgroup_memory().quantity(),
        COMPOSE_MEMORY_BYTES,
        "agentic work retains the bounded complex-work memory ceiling"
    );
    assert!(
        standard
            .sandbox()
            .path_grants()
            .as_slice()
            .iter()
            .all(|grant| grant.access() != PathAccess::ReadExecute),
        "ordinary work must not inherit scratchpad runtime execution"
    );
}

/// A deployment that configured nothing composes nothing, and says so.
#[test]
fn an_unconfigured_deployment_composes_nothing() {
    let fixture = Fixture::new(None, None);
    let home = fixture.provider_home();
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &busybox_provider(&home, &[]),
    );

    // No destination policy: a document declaring brokered egress could not be
    // admitted, so it is refused before anything durable exists.
    let refusal = compose(
        "anything",
        &CompositionInputs {
            state_dir: &fixture.state_dir(),
            run_id: "unconfigured1",
            provider: &fixture.provider(),
            offered_features: &features(),
            egress_configured: false,
        },
    );
    assert!(
        matches!(refusal, Err(ComposeRefusal::NotConfigured)),
        "a deployment with no destinations must refuse: {refusal:?}"
    );
    assert_eq!(
        RunFailure::from_compose(ComposeRefusal::NotConfigured),
        RunFailure::NotConfigured,
        "and the operator must read it as not configured"
    );

    // No provider file at all is the ordinary unconfigured state, and it is not
    // an error.
    let bare = Fixture::new(None, None);
    assert_eq!(
        ProviderConfig::load(&bare.state_dir().join(PROVIDER_CONFIG_NAME))
            .expect("an absent configuration is not an error"),
        None
    );

    // An invocation that can never write an answer is a configuration error
    // rather than a run that happens to say nothing.
    write_private(
        &bare.state_dir().join(PROVIDER_CONFIG_NAME),
        &busybox_provider(&bare.provider_home(), &["sh", "-c", "true"]),
    );
    assert!(
        matches!(
            ProviderConfig::load(&bare.state_dir().join(PROVIDER_CONFIG_NAME)),
            Err(ComposeRefusal::NotConfigured)
        ),
        "an argv that never names the answer file must be refused"
    );
}

/// An empty task and one past the prompt ceiling are both refused, and neither
/// is a panic.
#[test]
fn a_task_that_cannot_be_a_prompt_is_refused() {
    let fixture = Fixture::new(None, None);
    let home = fixture.provider_home();
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &busybox_provider(&home, &[]),
    );
    let provider = fixture.provider();
    let state_dir = fixture.state_dir();
    for task in [String::from("   "), "x".repeat(1024 * 1024)] {
        let refusal = compose(
            &task,
            &CompositionInputs {
                state_dir: &state_dir,
                run_id: "badtask1",
                provider: &provider,
                offered_features: &features(),
                egress_configured: true,
            },
        );
        assert!(
            matches!(refusal, Err(ComposeRefusal::TaskRejected)),
            "a task of {} bytes must be refused: {refusal:?}",
            task.len()
        );
    }
}

// --- the contained proof --------------------------------------------------

fn sandbox_enforceable() -> bool {
    HostCapabilities::probe()
        .select_mode(&automonique_daemon::execute::ENFORCED_PROPERTIES)
        .is_ok()
}

fn first_failing_gate() -> Option<&'static str> {
    if !Path::new(BUSYBOX).exists() {
        return Some("no static busybox at /usr/bin/busybox");
    }
    if !sandbox_enforceable() {
        return Some("this host cannot enforce the composed sandbox");
    }
    if locate_launch_helper().is_none() {
        return Some("no launch entry helper beside this binary");
    }
    if ContainmentDomain::discover().is_err() {
        return Some("no delegated cgroup v2 domain");
    }
    None
}

/// Record that a contained proof did not run here, or refuse to let it be
/// skipped.
///
/// A skip is silent only where nothing could have been proven: no delegated
/// cgroup domain wraps this binary, so no enforced run was ever reachable. Once
/// a domain *is* present — the delegated scope the module recipe wraps the
/// binary in — every other gate is something the caller built the environment
/// to satisfy, and a missing busybox, helper or sandbox mechanism is then a
/// broken proof rather than an absent one. Passing vacuously inside the very
/// scope that exists to make the proof reachable is the one outcome this
/// function must never produce, with or without [`REQUIRE_ENFORCED_ENV`].
fn not_proven(test: &str, reason: &str) {
    assert!(
        std::env::var_os(REQUIRE_ENFORCED_ENV).is_none(),
        "{test}: {REQUIRE_ENFORCED_ENV} is set but this host cannot prove it: {reason}"
    );
    assert!(
        ContainmentDomain::discover().is_err(),
        "{test}: a delegated cgroup domain is present but the proof is unreachable: {reason}"
    );
    eprintln!("[run_compose] NOT PROVEN: {test}: {reason}");
}

/// A loopback listener nothing ever dials, so the destination policy names a
/// real port on this host rather than anywhere off it.
fn unused_loopback_port() -> u16 {
    let listener =
        TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("a loopback port");
    listener.local_addr().expect("bound").port()
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
    let deadline = Instant::now() + Duration::from_secs(15);
    while !config.admin_socket().exists() {
        assert!(Instant::now() < deadline, "daemon did not bind");
        std::thread::sleep(Duration::from_millis(5));
    }
    Serving {
        stop,
        thread: Some(thread),
    }
}

impl Serving {
    fn shutdown(mut self, config: &DaemonConfig) {
        let request = AdminRequest::new(
            RequestId::new("shutdown").expect("request ID"),
            AdminCommand::Shutdown,
        );
        let payload = request
            .to_message()
            .expect("encode request")
            .to_canonical_bytes();
        let response =
            AdminResponse::from_canonical_bytes(&exchange(config, &payload)).expect("response");
        assert!(matches!(response, AdminResponse::ShutdownAccepted { .. }));
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

fn exchange(config: &DaemonConfig, payload: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(config.admin_socket()).expect("connect to daemon");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
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

fn platform(config: &DaemonConfig, label: &str, request: PlatformRequest) -> PlatformResponse {
    let request_id = RequestId::new(label).expect("request ID");
    let payload = PlatformRequestMessage::new(request_id.clone(), request)
        .to_message()
        .expect("platform request")
        .to_canonical_bytes();
    let response = PlatformResponseMessage::from_canonical_bytes(&exchange(config, &payload))
        .expect("platform response");
    assert_eq!(response.request_id(), &request_id);
    response.response().clone()
}

/// A fixture whose provider is busybox running `argv`, with a destination policy
/// pointing at one unused loopback port.
fn contained_fixture(argv: &[String]) -> Fixture {
    let fixture = Fixture::new(
        None,
        Some(&format!("127.0.0.1 {} loopback\n", unused_loopback_port())),
    );
    let home = fixture.provider_home();
    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &busybox_provider(&home, &borrowed),
    );
    fixture
}

fn open_lane(fixture: &Fixture) -> SocketRunLane {
    SocketRunLane::open(
        &fixture.state_dir(),
        &fixture.config.admin_socket(),
        &fixture.config.run_index_path(),
    )
    .expect("the run lane opens")
}

/// The first `ready` run the index reports, or a loud failure at `deadline`.
fn wait_for_ready_run(
    index: &automonique_store::run_index::RunIndex,
    deadline: Instant,
    failure: &str,
) -> String {
    loop {
        let page = index.page(0, 8).expect("run page");
        if let Some(record) = page
            .entries
            .into_iter()
            .find(|record| record.spool_state == automonique_store::run_index::RunSpoolState::Ready)
        {
            break record.run_id;
        }
        assert!(Instant::now() < deadline, "{failure}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Wait until `run_id`'s durable spool holds one authoritative pause frame of
/// `kind` whose label is exactly `text`, or fail loudly with `failure` at
/// `deadline`.
///
/// Exact rather than `contains`: the label is the whole of what a renderer
/// shows, so a frame that carried a prefix, an identifier or a placeholder
/// beside the prompt would be a different frame from the one asserted here.
fn wait_for_pause_frame(
    events: &Path,
    run_id: &str,
    deadline: Instant,
    kind: automonique_protocol::event::EventKind,
    text: Option<&str>,
    failure: &str,
) {
    let spool = events.parent().expect("spool directory");
    while !automonique_runner::read_events(spool, run_id).is_ok_and(|projected| {
        projected.iter().any(|event| {
            ProgressFrame::from_canonical_bytes(event.payload()).is_ok_and(|frame| {
                frame.kind() == kind
                    && frame.authority() == automonique_protocol::event::Authority::Authoritative
                    && frame
                        .body()
                        .text()
                        .map(automonique_protocol::progress_api::ProgressText::as_str)
                        == text
            })
        })
    }) {
        assert!(Instant::now() < deadline, "{failure}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// THE WHOLE FEATURE, MINUS THE PROVIDER.
///
/// Two `/run` tasks go through the production lane against a serving daemon, and
/// each reply is the string that run's own contained workload wrote — derived
/// from that run's own prompt, so the two cannot be confused. Beside them, a
/// workload that writes nothing and one that fails are asserted to reach their
/// own typed refusals rather than an answer.
#[test]
fn a_contained_run_answers_through_the_real_lane() {
    let test = "a_contained_run_answers_through_the_real_lane";
    if let Some(reason) = first_failing_gate() {
        not_proven(test, reason);
        return;
    }

    let fixture = contained_fixture(&echo_prompt_argv());
    let serving = serve(&fixture.config);
    let mut lane = open_lane(&fixture);
    assert!(
        lane.configured(),
        "a fixture with a provider and a destination policy must be configured"
    );

    // TWO RUNS, TWO ANSWERS, AND NEITHER IS THE OTHER'S.
    let first = with_deadline(&mut lane, "the first distinct task");
    let second = with_deadline(&mut lane, "a second and different task");
    assert_eq!(
        first,
        format!("{ANSWER_PREFIX}the first distinct task"),
        "the reply must be what this run's workload wrote"
    );
    assert_eq!(
        second,
        format!("{ANSWER_PREFIX}a second and different task"),
        "the reply must be what *this* run's workload wrote"
    );
    assert_ne!(
        first, second,
        "a lane reading a fixed path would answer both runs the same"
    );
    assert!(
        !first.contains("second") && !second.contains("first"),
        "each answer must come from its own run's workspace: {first:?} / {second:?}"
    );

    // THE PROMPT SLOT DOES NOT OUTLIVE THE RUN.
    let prompts = fixture.state_dir().join("prompts");
    let remaining = std::fs::read_dir(&prompts)
        .map(|entries| entries.count())
        .unwrap_or_default();
    assert_eq!(
        remaining, 0,
        "operator content must not outlive the run that consumed it"
    );

    // THE SCRATCH MOUNT OUTLIVES NO RUN, AND ITS RECORD DOES.
    //
    // Each run got its own temporary-storage mount under its private
    // directory; after the run the lane reconciled it, unmounted it, confirmed
    // that from the mount table, and left the ledger's final checkpoint beside
    // where the mount was. Read back from disk, not from the lane.
    let runs = fixture.state_dir().join("runs");
    let mut checkpoints = 0;
    for entry in std::fs::read_dir(&runs).expect("the runs directory exists") {
        let run_dir = entry.expect("a run directory entry").path();
        let checkpoint = automonique_runner::Checkpoint::read(
            &run_dir.join(automonique_runner::CHECKPOINT_LEAF),
        )
        .expect("every run leaves its final temporary-storage checkpoint");
        assert_eq!(checkpoint.phase, automonique_runner::CheckpointPhase::Final);
        let final_record = checkpoint
            .final_record
            .expect("a final checkpoint carries the readback taken at unmount");
        assert!(final_record.unmount_confirmed, "the mount table is clear");
        assert!(!final_record.aborted, "the server answered the readback");
        assert_eq!(checkpoint.snapshot.refused_bytes, 0, "nothing was refused");
        assert_eq!(checkpoint.snapshot.refused_objects, 0);
        checkpoints += 1;
    }
    assert_eq!(checkpoints, 2, "one checkpoint per run");
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
    let runs_text = runs.to_string_lossy();
    assert!(
        !mountinfo
            .lines()
            .any(|line| line.contains("fuse.automonique-tempfs") && line.contains(&*runs_text)),
        "no temporary-storage mount outlives its run"
    );

    serving.shutdown(&fixture.config);
}

#[test]
fn a_contained_jcode_protocol_turn_answers_through_the_production_lane() {
    let test = "a_contained_jcode_protocol_turn_answers_through_the_production_lane";
    if let Some(reason) = first_failing_gate() {
        not_proven(test, reason);
        return;
    }
    let fixture = Fixture::new(
        None,
        Some(&format!("127.0.0.1 {} loopback\n", unused_loopback_port())),
    );
    let home = fixture.provider_home();
    let script = concat!(
        "IFS= read -r request; printf '%s\\n' '",
        "{\"v\":1,\"reply_to\":1,\"ev\":\"hello_ok\",\"version\":1,\"server\":\"jcode/production-fixture\",",
        "\"capabilities\":[\"sessions\",\"streaming\",\"cancellation\",\"soft_interrupt\",",
        "\"stdin_requests\",\"history\",\"model_catalog\",\"reasoning_effort\",\"usage\",\"runtime_info\"]}'; ",
        "IFS= read -r request; printf '%s\\n' '",
        "{\"v\":1,\"reply_to\":2,\"ev\":\"attached\",\"session\":{\"session_id\":\"jcode-production-session\",\"status\":\"idle\"}}'; ",
        "IFS= read -r request; printf '%s\\n' ",
        "'{\"v\":1,\"ev\":\"message_accepted\",\"session_id\":\"jcode-production-session\"}' ",
        "'{\"v\":1,\"ev\":\"session_status\",\"session_id\":\"jcode-production-session\",\"status\":\"generating\"}' ",
        "'{\"v\":1,\"ev\":\"text_delta\",\"session_id\":\"jcode-production-session\",\"text\":\"JCODE-PRODUCTION-OK\"}' ",
        "'{\"v\":1,\"ev\":\"token_usage\",\"session_id\":\"jcode-production-session\",\"input\":4,\"output\":1}' ",
        "'{\"v\":1,\"ev\":\"turn_done\",\"session_id\":\"jcode-production-session\"}'; ",
        "while IFS= read -r request; do :; done"
    );
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &format!(
            "engine=jcode\nbinary={BUSYBOX}\nhome={}\nversion=jcode/production-fixture\narg=sh\narg=-c\narg={script}\narg=api-stdio\n",
            home.display()
        ),
    );

    let serving = serve(&fixture.config);
    let mut lane = open_lane(&fixture);
    assert_eq!(
        with_deadline(&mut lane, "exercise the JCode protocol"),
        "JCODE-PRODUCTION-OK"
    );
    let sessions = automonique_daemon::managed_sessions::ManagedSessionStore::open(
        fixture
            .state_dir()
            .join(automonique_daemon::MANAGED_SESSIONS_NAME),
    )
    .expect("managed sessions");
    let observed = sessions
        .by_id("jcode-production-session")
        .expect("session lookup")
        .expect("JCode session retained");
    assert_eq!(observed.provider_session_id, "jcode-production-session");
    serving.shutdown(&fixture.config);
}

#[test]
fn a_jcode_provider_permission_waits_for_the_durable_operator_decision() {
    let test = "a_jcode_provider_permission_waits_for_the_durable_operator_decision";
    if let Some(reason) = first_failing_gate() {
        not_proven(test, reason);
        return;
    }
    let fixture = Fixture::new(
        None,
        Some(&format!("127.0.0.1 {} loopback\n", unused_loopback_port())),
    );
    let home = fixture.provider_home();
    let script = concat!(
        "IFS= read -r request; printf '%s\\n' '",
        "{\"v\":1,\"reply_to\":1,\"ev\":\"hello_ok\",\"version\":1,\"server\":\"jcode/approval-fixture\",",
        "\"capabilities\":[\"sessions\",\"streaming\",\"cancellation\",\"soft_interrupt\",",
        "\"permission_requests\",\"history\",\"model_catalog\",\"reasoning_effort\",\"usage\",\"runtime_info\"]}'; ",
        "IFS= read -r request; printf '%s\\n' '",
        "{\"v\":1,\"reply_to\":2,\"ev\":\"attached\",\"session\":{\"session_id\":\"jcode-approval-session\",\"status\":\"idle\"}}'; ",
        "IFS= read -r request; printf '%s\\n' ",
        "'{\"v\":1,\"ev\":\"message_accepted\",\"session_id\":\"jcode-approval-session\"}' ",
        "'{\"v\":1,\"ev\":\"permission_request\",\"session_id\":\"jcode-approval-session\",\"request_id\":\"permission-1\",\"tool_name\":\"write\",\"description\":\"write the approved fixture\"}'; ",
        "IFS= read -r request; printf '%s\\n' ",
        "'{\"v\":1,\"reply_to\":4,\"ev\":\"ok\"}' ",
        "'{\"v\":1,\"ev\":\"text_delta\",\"session_id\":\"jcode-approval-session\",\"text\":\"JCODE-APPROVAL-OK\"}' ",
        "'{\"v\":1,\"ev\":\"turn_done\",\"session_id\":\"jcode-approval-session\"}'; ",
        "while IFS= read -r request; do :; done"
    );
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &format!(
            "engine=jcode\nbinary={BUSYBOX}\nhome={}\nversion=jcode/approval-fixture\narg=sh\narg=-c\narg={script}\narg=api-stdio\n",
            home.display()
        ),
    );

    let serving = serve(&fixture.config);
    let mut lane = open_lane(&fixture);
    let run = std::thread::spawn(move || lane.run("exercise durable provider approval"));
    let approvals_path = fixture
        .state_dir()
        .join(automonique_daemon::APPROVAL_REQUESTS_NAME);
    let deadline = Instant::now() + Duration::from_secs(15);
    let (request_key, run_id) = loop {
        let approvals = ApprovalRequests::open(&approvals_path).expect("approval requests open");
        let pending = approvals.pending(8).expect("pending approvals");
        if let Some(record) = pending
            .into_iter()
            .find(|record| record.state == ApprovalState::Pending)
        {
            break (record.request_key, record.run_id);
        }
        assert!(
            Instant::now() < deadline,
            "provider approval was not projected"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    // The wait reaches the progress stream as one approval frame whose label
    // leads with the durable key a consumer decides by, then names the tool
    // and what it asked. This is the frame the ACP bridge and the AG-UI
    // adapter read the key from.
    wait_for_pause_frame(
        &fixture
            .state_dir()
            .join("runs")
            .join(&run_id)
            .join("spool")
            .join("events.ndjson"),
        &run_id,
        deadline,
        automonique_protocol::event::EventKind::ApprovalRequested,
        Some(&format!(
            "approval {request_key}: write — write the approved fixture"
        )),
        "provider approval did not reach the progress stream with its key",
    );
    let decision = ApprovalRequest::DecideRequest {
        request_id: RequestId::new("provider-approval-decision").expect("request ID"),
        decision: DecideRequest::new(
            ApprovalKey::new(request_key).expect("approval key"),
            ApprovalDecision::Granted,
            Decider::new("test-operator").expect("decider"),
        ),
    };
    let response = ApprovalResponse::from_canonical_bytes(&exchange(
        &fixture.config,
        &decision
            .to_message()
            .expect("approval request")
            .to_canonical_bytes(),
    ))
    .expect("approval response");
    assert!(matches!(response, ApprovalResponse::Recorded { .. }));
    assert_eq!(
        run.join().expect("run thread").expect("approved run"),
        "JCODE-APPROVAL-OK"
    );
    serving.shutdown(&fixture.config);
}

#[test]
fn a_live_jcode_turn_cancels_through_the_production_control_lane() {
    let test = "a_live_jcode_turn_cancels_through_the_production_control_lane";
    if let Some(reason) = first_failing_gate() {
        not_proven(test, reason);
        return;
    }
    let fixture = Fixture::new(
        None,
        Some(&format!("127.0.0.1 {} loopback\n", unused_loopback_port())),
    );
    let home = fixture.provider_home();
    let script = concat!(
        "IFS= read -r request; printf '%s\\n' '",
        "{\"v\":1,\"reply_to\":1,\"ev\":\"hello_ok\",\"version\":1,\"server\":\"jcode/cancel-fixture\",",
        "\"capabilities\":[\"sessions\",\"streaming\",\"cancellation\",\"soft_interrupt\",",
        "\"permission_requests\",\"history\",\"model_catalog\",\"reasoning_effort\",\"usage\",\"runtime_info\"]}'; ",
        "IFS= read -r request; printf '%s\\n' '",
        "{\"v\":1,\"reply_to\":2,\"ev\":\"attached\",\"session\":{\"session_id\":\"jcode-cancel-session\",\"status\":\"idle\"}}'; ",
        "IFS= read -r request; printf '%s\\n' ",
        "'{\"v\":1,\"ev\":\"message_accepted\",\"session_id\":\"jcode-cancel-session\"}' ",
        "'{\"v\":1,\"ev\":\"tool_start\",\"session_id\":\"jcode-cancel-session\",\"call_id\":\"tool-1\",\"name\":\"wait\"}'; ",
        "IFS= read -r request; printf '%s\\n' ",
        "'{\"v\":1,\"reply_to\":4,\"ev\":\"ok\"}' ",
        "'{\"v\":1,\"ev\":\"turn_done\",\"session_id\":\"jcode-cancel-session\"}'; ",
        "while IFS= read -r request; do :; done"
    );
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &format!(
            "engine=jcode\nbinary={BUSYBOX}\nhome={}\nversion=jcode/cancel-fixture\narg=sh\narg=-c\narg={script}\narg=api-stdio\n",
            home.display()
        ),
    );

    let serving = serve(&fixture.config);
    let mut run_lane = open_lane(&fixture);
    let run = std::thread::spawn(move || run_lane.run("wait until cancelled"));
    let index =
        automonique_store::run_index::RunIndex::open(fixture.state_dir().join(RUN_INDEX_NAME))
            .expect("run index");
    let deadline = Instant::now() + Duration::from_secs(15);
    let run_id =
        loop {
            let page = index.page(0, 8).expect("run page");
            if let Some(record) = page.entries.into_iter().find(|record| {
                record.spool_state == automonique_store::run_index::RunSpoolState::Ready
            }) {
                break record.run_id;
            }
            assert!(
                Instant::now() < deadline,
                "JCode turn did not become cancellable"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
    let events = fixture
        .state_dir()
        .join("runs")
        .join(&run_id)
        .join("spool")
        .join("events.ndjson");
    while std::fs::read_to_string(&events)
        .map(|text| text.lines().count())
        .unwrap_or_default()
        < 5
    {
        assert!(
            Instant::now() < deadline,
            "JCode turn did not reach its live tool event"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut control = open_lane(&fixture);
    control
        .cancel_run(&run_id, "jcode-cancel-test-1")
        .expect("cancellation delivered");
    assert_eq!(run.join().expect("run thread"), Err(RunFailure::Cancelled));
    let mut journal = automonique_store::provider_journal::ProviderJournal::open(
        fixture
            .state_dir()
            .join(automonique_daemon::PROVIDER_JOURNAL_NAME),
    )
    .expect("provider journal");
    let recovered = journal
        .recover_attempt(&format!("{run_id}-attempt"))
        .expect("recover JCode attempt");
    let session = recovered.session.expect("provider session was opened");
    let turns = journal
        .session_turns(session.session_id)
        .expect("provider turns");
    let aborted = turns
        .iter()
        .find(|turn| turn.state == automonique_store::provider_journal::TurnState::Aborted)
        .expect("the cancellation must abort an actual JCode turn");
    assert!(
        journal
            .turn_requests(aborted.turn_id)
            .expect("cancelled turn requests")
            .iter()
            .any(|request| {
                request.request_key.starts_with("cancel:")
                    && request.outcome
                        == automonique_store::provider_journal::RequestState::Answered
            }),
        "provider turn_done must durably acknowledge the cancel request"
    );
    serving.shutdown(&fixture.config);
}

#[test]
fn a_control_lease_steers_the_live_jcode_turn_and_nothing_after_it() {
    let test = "a_control_lease_steers_the_live_jcode_turn_and_nothing_after_it";
    if let Some(reason) = first_failing_gate() {
        not_proven(test, reason);
        return;
    }
    let fixture = Fixture::new(
        None,
        Some(&format!("127.0.0.1 {} loopback\n", unused_loopback_port())),
    );
    let home = fixture.provider_home();
    let script = concat!(
        "IFS= read -r request; printf '%s\\n' '",
        "{\"v\":1,\"reply_to\":1,\"ev\":\"hello_ok\",\"version\":1,\"server\":\"jcode/steer-fixture\",",
        "\"capabilities\":[\"sessions\",\"streaming\",\"cancellation\",\"soft_interrupt\",",
        "\"stdin_requests\",\"history\",\"model_catalog\",\"reasoning_effort\",\"usage\",\"runtime_info\"]}'; ",
        "IFS= read -r request; printf '%s\\n' '",
        "{\"v\":1,\"reply_to\":2,\"ev\":\"attached\",\"session\":{\"session_id\":\"jcode-steer-session\",\"status\":\"idle\"}}'; ",
        "IFS= read -r request; printf '%s\\n' ",
        "'{\"v\":1,\"ev\":\"message_accepted\",\"session_id\":\"jcode-steer-session\"}' ",
        "'{\"v\":1,\"ev\":\"stdin_request\",\"session_id\":\"jcode-steer-session\",\"request_id\":\"stdin-1\",\"prompt\":\"fixture input\",\"is_password\":false,\"tool_call_id\":\"tool-input-1\"}'; ",
        "IFS= read -r request; case \"$request\" in ",
        "*'\"req\":\"stdin_response\"'*'\"request_id\":\"stdin-1\"'*'\"input\":\"fixture-input\"'*) : ;; ",
        "*) exit 18 ;; esac; ",
        "printf '%s\\n' ",
        "'{\"v\":1,\"reply_to\":4,\"ev\":\"ok\"}' ",
        "'{\"v\":1,\"ev\":\"tool_start\",\"session_id\":\"jcode-steer-session\",\"call_id\":\"tool-1\",\"name\":\"wait-for-steer\"}'; ",
        "IFS= read -r request; case \"$request\" in ",
        "*'\"req\":\"soft_interrupt\"'*'\"content\":\"replace-the-answer\"'*) : ;; ",
        "*) exit 19 ;; esac; ",
        "printf '%s\\n' ",
        "'{\"v\":1,\"reply_to\":5,\"ev\":\"ok\"}' ",
        "'{\"v\":1,\"ev\":\"tool_done\",\"session_id\":\"jcode-steer-session\",\"call_id\":\"tool-1\",\"name\":\"wait-for-steer\"}' ",
        "'{\"v\":1,\"ev\":\"text_delta\",\"session_id\":\"jcode-steer-session\",\"text\":\"JCODE-STEERED-OK\"}' ",
        "'{\"v\":1,\"ev\":\"turn_done\",\"session_id\":\"jcode-steer-session\"}'; ",
        "while IFS= read -r request; do :; done"
    );
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &format!(
            "engine=jcode\nbinary={BUSYBOX}\nhome={}\nversion=jcode/steer-fixture\narg=sh\narg=-c\narg={script}\narg=api-stdio\n",
            home.display()
        ),
    );

    let serving = serve(&fixture.config);
    let mut run_lane = open_lane(&fixture);
    let run = std::thread::spawn(move || run_lane.run("wait for corrected live input"));
    let index =
        automonique_store::run_index::RunIndex::open(fixture.state_dir().join(RUN_INDEX_NAME))
            .expect("run index");
    let deadline = Instant::now() + Duration::from_secs(15);
    let run_id =
        loop {
            let page = index.page(0, 8).expect("run page");
            if let Some(record) = page.entries.into_iter().find(|record| {
                record.spool_state == automonique_store::run_index::RunSpoolState::Ready
            }) {
                break record.run_id;
            }
            assert!(Instant::now() < deadline, "JCode turn did not become live");
            std::thread::sleep(Duration::from_millis(20));
        };
    let events = fixture
        .state_dir()
        .join("runs")
        .join(&run_id)
        .join("spool")
        .join("events.ndjson");
    // The wait is surfaced as the protocol's own input-request kind, labelled
    // with the provider's prompt and nothing else: no request identifier, no
    // placeholder, and never as an approval — that is a different affordance.
    wait_for_pause_frame(
        &events,
        &run_id,
        deadline,
        automonique_protocol::event::EventKind::InputRequested,
        Some("fixture input"),
        "JCode turn did not expose its bounded stdin request",
    );
    assert!(
        !automonique_runner::read_events(events.parent().expect("spool directory"), &run_id)
            .expect("spool events")
            .iter()
            .any(|event| {
                ProgressFrame::from_canonical_bytes(event.payload()).is_ok_and(|frame| {
                    frame.kind() == automonique_protocol::event::EventKind::ApprovalRequested
                })
            }),
        "a provider input request must not be drawn as an approval"
    );

    let session = ResourceCoordinate::new(
        ResourceAuthority::Automonique,
        ResourceKind::Session,
        ResourceId::new("jcode-steer-session").expect("session ID"),
    );
    let client = ClientId::new("jcode-steer-client").expect("client ID");
    let PlatformResponse::ControlClaimed(lease) = platform(
        &fixture.config,
        "jcode-steer-claim",
        PlatformRequest::ClaimControl(ClaimControlRequest {
            session: session.clone(),
            client: client.clone(),
            idempotency_key: IdempotencyKey::new("jcode-steer-claim-1").expect("claim key"),
        }),
    ) else {
        panic!("live JCode session must grant control")
    };
    let lease_target = ResourceCoordinate::new(
        ResourceAuthority::Automonique,
        ResourceKind::ControlLease,
        ResourceId::new(lease.id.as_str()).expect("lease resource ID"),
    );
    let PlatformResponse::Receipt(receipt) = platform(
        &fixture.config,
        "jcode-input-execute",
        PlatformRequest::Execute(
            PlatformExecuteRequest::new(
                PlatformAction::Steer,
                lease_target.clone(),
                IdempotencyKey::new("jcode-input-execute-1").expect("input key"),
                Some(lease.revision),
                Some(PlatformText::new("fixture-input").expect("input text")),
            )
            .expect("input action"),
        ),
    ) else {
        panic!("accepted stdin response must return its durable receipt")
    };
    assert_eq!(receipt.outcome, ReceiptOutcome::Completed);
    while !automonique_runner::read_events(events.parent().expect("spool directory"), &run_id)
        .is_ok_and(|projected| {
            projected.iter().any(|event| {
                ProgressFrame::from_canonical_bytes(event.payload()).is_ok_and(|frame| {
                    frame.kind() == automonique_protocol::event::EventKind::ToolCallStarted
                })
            })
        })
    {
        assert!(
            Instant::now() < deadline,
            "JCode turn did not continue to its live tool event"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let PlatformResponse::Receipt(receipt) = platform(
        &fixture.config,
        "jcode-steer-execute",
        PlatformRequest::Execute(
            PlatformExecuteRequest::new(
                PlatformAction::Steer,
                lease_target.clone(),
                IdempotencyKey::new("jcode-steer-execute-1").expect("steer key"),
                Some(lease.revision),
                Some(PlatformText::new("replace-the-answer").expect("steer text")),
            )
            .expect("steer action"),
        ),
    ) else {
        panic!("accepted steer must return its durable receipt")
    };
    assert_eq!(receipt.outcome, ReceiptOutcome::Completed);
    assert_eq!(
        run.join().expect("run thread").expect("steered run"),
        "JCODE-STEERED-OK"
    );
    let projected =
        automonique_runner::read_events(events.parent().expect("spool directory"), &run_id)
            .expect("verified spool events");
    assert!(
        projected.iter().any(|event| {
            ProgressFrame::from_canonical_bytes(event.payload()).is_ok_and(|frame| {
                frame.kind() == automonique_protocol::event::EventKind::TurnSteered
                    && frame.authority() == automonique_protocol::event::Authority::Authoritative
            })
        }),
        "provider acknowledgement must become an authoritative turn_steered event"
    );
    let mut journal = automonique_store::provider_journal::ProviderJournal::open(
        fixture
            .state_dir()
            .join(automonique_daemon::PROVIDER_JOURNAL_NAME),
    )
    .expect("provider journal");
    let recovery = journal
        .recover_attempt(&format!("{run_id}-attempt"))
        .expect("JCode recovery");
    let journal_session = recovery.session.expect("provider session");
    let turn = journal
        .session_turns(journal_session.session_id)
        .expect("turns")
        .pop()
        .expect("turn");
    let requests = journal.turn_requests(turn.turn_id).expect("requests");
    assert!(requests.iter().any(|request| {
        request.request_key == "stdin:stdin-1"
            && request.outcome == automonique_store::provider_journal::RequestState::Answered
    }));
    assert!(requests.iter().any(|request| {
        request.request_key.starts_with("steer:")
            && request.outcome == automonique_store::provider_journal::RequestState::Answered
    }));

    let PlatformResponse::Receipt(stale_host_receipt) = platform(
        &fixture.config,
        "jcode-steer-after-turn",
        PlatformRequest::Execute(
            PlatformExecuteRequest::new(
                PlatformAction::Steer,
                lease_target.clone(),
                IdempotencyKey::new("jcode-steer-execute-2").expect("steer key"),
                Some(lease.revision),
                Some(PlatformText::new("must-not-be-delivered").expect("steer text")),
            )
            .expect("post-turn steer action"),
        ),
    ) else {
        panic!("a post-turn steer must be durably rejected")
    };
    assert_eq!(stale_host_receipt.outcome, ReceiptOutcome::Rejected);
    assert_eq!(
        stale_host_receipt
            .explanation
            .as_ref()
            .map(PlatformText::as_str),
        Some("session_not_live")
    );

    let PlatformResponse::ControlReleased { .. } = platform(
        &fixture.config,
        "jcode-steer-release",
        PlatformRequest::ReleaseControl(ReleaseControlRequest {
            session,
            client,
            lease: lease.id.clone(),
            idempotency_key: IdempotencyKey::new("jcode-steer-release-1").expect("release key"),
        }),
    ) else {
        panic!("control release")
    };
    let PlatformResponse::Refused {
        outcome,
        explanation,
    } = platform(
        &fixture.config,
        "jcode-steer-after-release",
        PlatformRequest::Execute(
            PlatformExecuteRequest::new(
                PlatformAction::Steer,
                lease_target,
                IdempotencyKey::new("jcode-steer-execute-3").expect("steer key"),
                Some(lease.revision),
                Some(PlatformText::new("must-not-cross-released-lease").expect("steer text")),
            )
            .expect("released-lease steer action"),
        ),
    )
    else {
        panic!("released control must refuse steering")
    };
    assert_eq!(outcome, ReceiptOutcome::Rejected);
    assert_eq!(explanation.as_str(), "control_lease_not_active");
    serving.shutdown(&fixture.config);
}

/// A JCode fixture that raises one provider wait and then never speaks again:
/// `pause` is the exact event line the turn blocks on after `message_accepted`.
///
/// Every request after that is read and dropped, so the provider is still
/// alive — and still waiting — when the daemon is told to stop.
fn silent_after_pause_fixture(server: &str, session: &str, pause: &str) -> Fixture {
    let fixture = Fixture::new(
        None,
        Some(&format!("127.0.0.1 {} loopback\n", unused_loopback_port())),
    );
    let home = fixture.provider_home();
    let script = format!(
        concat!(
            "IFS= read -r request; printf '%s\\n' '",
            "{{\"v\":1,\"reply_to\":1,\"ev\":\"hello_ok\",\"version\":1,\"server\":\"{server}\",",
            "\"capabilities\":[\"sessions\",\"streaming\",\"cancellation\",\"soft_interrupt\",",
            "\"stdin_requests\",\"permission_requests\",\"history\",\"model_catalog\",",
            "\"reasoning_effort\",\"usage\",\"runtime_info\"]}}'; ",
            "IFS= read -r request; printf '%s\\n' '",
            "{{\"v\":1,\"reply_to\":2,\"ev\":\"attached\",\"session\":{{\"session_id\":\"{session}\",\"status\":\"idle\"}}}}'; ",
            "IFS= read -r request; printf '%s\\n' ",
            "'{{\"v\":1,\"ev\":\"message_accepted\",\"session_id\":\"{session}\"}}' ",
            "'{pause}'; ",
            "while IFS= read -r request; do :; done"
        ),
        server = server,
        session = session,
        pause = pause,
    );
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &format!(
            "engine=jcode\nbinary={BUSYBOX}\nhome={}\nversion={server}\narg=sh\narg=-c\narg={script}\narg=api-stdio\n",
            home.display()
        ),
    );
    fixture
}

/// Stop a serving daemon whose one live JCode turn is paused on `pause`, and
/// prove the stop was bounded and the wait was left durably unanswered.
///
/// `pause_label` is asked for only once the turn is live, because the approval
/// label names a key the daemon has not proposed until then.
///
/// Returns the run identity and the aborted turn's request rows, so each
/// caller asserts the durable fate of the request it raised.
fn drain_paused_turn(
    fixture: &Fixture,
    task: &str,
    pause_kind: automonique_protocol::event::EventKind,
    pause_label: impl FnOnce() -> String,
    pause_failure: &str,
) -> (String, Vec<automonique_store::provider_journal::RequestRow>) {
    let serving = serve(&fixture.config);
    let mut run_lane = open_lane(fixture);
    let task = task.to_owned();
    let run = std::thread::spawn(move || run_lane.run(&task));
    let index =
        automonique_store::run_index::RunIndex::open(fixture.state_dir().join(RUN_INDEX_NAME))
            .expect("run index");
    let deadline = Instant::now() + Duration::from_secs(15);
    let run_id = wait_for_ready_run(&index, deadline, "JCode turn did not become live");
    let events = fixture
        .state_dir()
        .join("runs")
        .join(&run_id)
        .join("spool")
        .join("events.ndjson");
    let pause_label = pause_label();
    wait_for_pause_frame(
        &events,
        &run_id,
        deadline,
        pause_kind,
        Some(&pause_label),
        pause_failure,
    );

    // THE STOP. The document allows this turn five minutes, and before the
    // drain flag the worker would have used all of them waiting for a person.
    let stopping = Instant::now();
    serving.shutdown(&fixture.config);
    let drained = stopping.elapsed();
    assert!(
        drained < Duration::from_secs(30),
        "a draining daemon waited {drained:?} on a pending provider request"
    );
    assert_eq!(
        run.join().expect("run thread"),
        Err(RunFailure::Cancelled),
        "the abandoned wait must end the run as cancelled, not as an answer"
    );
    let record = index
        .by_run_id(&run_id)
        .expect("run record")
        .into_iter()
        .last()
        .expect("the run is indexed");
    assert_eq!(
        record.spool_state,
        automonique_store::run_index::RunSpoolState::Cancelled
    );

    let mut journal = automonique_store::provider_journal::ProviderJournal::open(
        fixture
            .state_dir()
            .join(automonique_daemon::PROVIDER_JOURNAL_NAME),
    )
    .expect("provider journal");
    let recovery = journal
        .recover_attempt(&format!("{run_id}-attempt"))
        .expect("JCode recovery");
    assert!(
        recovery.process.is_some_and(|process| {
            process.state != automonique_store::provider_journal::ProcessState::Live
        }),
        "the provider process must not be recorded live after the host closed"
    );
    let session = recovery.session.expect("provider session");
    let turn = journal
        .session_turns(session.session_id)
        .expect("turns")
        .pop()
        .expect("turn");
    assert_eq!(
        turn.state,
        automonique_store::provider_journal::TurnState::Aborted,
        "the paused turn is aborted, not completed"
    );
    let requests = journal.turn_requests(turn.turn_id).expect("requests");
    (run_id, requests)
}

/// A DRAINING DAEMON DOES NOT WAIT FOR A PERSON.
///
/// The provider asks for input and nobody answers. The daemon is told to stop.
/// The wait is abandoned within a bounded time, the request is neither
/// answered on the operator's behalf nor stranded pending: it is settled as
/// failed with [`DAEMON_DRAINING_REASON`], so a successor reading the journal
/// can tell a wait this daemon walked away from apart from one the provider
/// ended.
#[test]
fn a_draining_daemon_abandons_a_pending_provider_input_wait_durably() {
    let test = "a_draining_daemon_abandons_a_pending_provider_input_wait_durably";
    if let Some(reason) = first_failing_gate() {
        not_proven(test, reason);
        return;
    }
    let fixture = silent_after_pause_fixture(
        "jcode/drain-input-fixture",
        "jcode-drain-input-session",
        "{\"v\":1,\"ev\":\"stdin_request\",\"session_id\":\"jcode-drain-input-session\",\"request_id\":\"stdin-drain\",\"prompt\":\"answer before the daemon stops\",\"is_password\":false,\"tool_call_id\":\"tool-input-1\"}",
    );
    let (_, requests) = drain_paused_turn(
        &fixture,
        "wait for input nobody gives",
        automonique_protocol::event::EventKind::InputRequested,
        || "answer before the daemon stops".to_owned(),
        "JCode turn did not expose its stdin request",
    );
    let stdin = requests
        .iter()
        .find(|request| request.request_key == "stdin:stdin-drain")
        .expect("the stdin request is journalled");
    assert_eq!(
        stdin.outcome,
        automonique_store::provider_journal::RequestState::Failed
    );
    assert_eq!(
        stdin.failure_reason.as_deref(),
        Some(DAEMON_DRAINING_REASON)
    );
    assert!(
        stdin.response_digest.is_none(),
        "no answer may be fabricated for the operator"
    );
}

/// The same rule for a permission wait: the daemon decides nothing. The
/// durable approval it proposed is still pending in the approval store for
/// the operator to find, and the journal names the drain as the reason the
/// host stopped waiting on it.
#[test]
fn a_draining_daemon_abandons_a_pending_provider_approval_wait_durably() {
    let test = "a_draining_daemon_abandons_a_pending_provider_approval_wait_durably";
    if let Some(reason) = first_failing_gate() {
        not_proven(test, reason);
        return;
    }
    let fixture = silent_after_pause_fixture(
        "jcode/drain-approval-fixture",
        "jcode-drain-approval-session",
        "{\"v\":1,\"ev\":\"permission_request\",\"session_id\":\"jcode-drain-approval-session\",\"request_id\":\"permission-drain\",\"tool_name\":\"write\",\"description\":\"write before the daemon stops\"}",
    );
    let approvals_path = fixture
        .state_dir()
        .join(automonique_daemon::APPROVAL_REQUESTS_NAME);
    let (run_id, requests) = drain_paused_turn(
        &fixture,
        "wait for an approval nobody gives",
        automonique_protocol::event::EventKind::ApprovalRequested,
        || {
            // The label is asserted through the key the store actually holds:
            // the frame must name the durable approval, not a guess at one.
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                let approvals =
                    ApprovalRequests::open(&approvals_path).expect("approval requests open");
                if let Some(record) = approvals
                    .pending(8)
                    .expect("pending approvals")
                    .into_iter()
                    .find(|record| record.state == ApprovalState::Pending)
                {
                    break format!(
                        "approval {}: write — write before the daemon stops",
                        record.request_key
                    );
                }
                assert!(
                    Instant::now() < deadline,
                    "provider approval was not proposed"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        },
        "JCode turn did not expose its permission request",
    );
    let permission = requests
        .iter()
        .find(|request| request.request_key == "approval:permission-drain")
        .expect("the permission request is journalled");
    assert_eq!(
        permission.outcome,
        automonique_store::provider_journal::RequestState::Failed
    );
    assert_eq!(
        permission.failure_reason.as_deref(),
        Some(DAEMON_DRAINING_REASON)
    );
    let approvals = ApprovalRequests::open(&approvals_path).expect("approval requests open");
    let still_pending = approvals
        .pending(8)
        .expect("pending approvals")
        .into_iter()
        .find(|record| record.run_id == run_id)
        .expect("the proposed approval survives the drain");
    assert_eq!(
        still_pending.state,
        ApprovalState::Pending,
        "a draining daemon must not decide the operator's approval"
    );
}

#[test]
fn managed_jcode_follow_up_attaches_the_exact_provider_session() {
    let test = "managed_jcode_follow_up_attaches_the_exact_provider_session";
    if let Some(reason) = first_failing_gate() {
        not_proven(test, reason);
        return;
    }
    let fixture = Fixture::new(
        None,
        Some(&format!("127.0.0.1 {} loopback\n", unused_loopback_port())),
    );
    let home = fixture.provider_home();
    let script = concat!(
        "IFS= read -r request; printf '%s\\n' '",
        "{\"v\":1,\"reply_to\":1,\"ev\":\"hello_ok\",\"version\":1,\"server\":\"jcode/resume-fixture\",",
        "\"capabilities\":[\"sessions\",\"streaming\",\"cancellation\",\"soft_interrupt\",",
        "\"stdin_requests\",\"history\",\"model_catalog\",\"reasoning_effort\",\"usage\",\"runtime_info\"]}'; ",
        "IFS= read -r request; case \"$request\" in ",
        "*'\"req\":\"create_session\"'*) answer=JCODE-NEW-OK ;; ",
        "*'\"req\":\"attach_session\"'*'jcode-resume-session'*) answer=JCODE-RESUME-OK ;; ",
        "*) exit 9 ;; esac; ",
        "printf '%s\\n' '",
        "{\"v\":1,\"reply_to\":2,\"ev\":\"attached\",\"session\":{\"session_id\":\"jcode-resume-session\",\"status\":\"idle\"}}'; ",
        "IFS= read -r request; printf '%s\\n' ",
        "'{\"v\":1,\"ev\":\"message_accepted\",\"session_id\":\"jcode-resume-session\"}'; ",
        "printf '{\"v\":1,\"ev\":\"text_delta\",\"session_id\":\"jcode-resume-session\",\"text\":\"%s\"}\\n' \"$answer\"; ",
        "printf '%s\\n' '{\"v\":1,\"ev\":\"turn_done\",\"session_id\":\"jcode-resume-session\"}'; ",
        "while IFS= read -r request; do :; done"
    );
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &format!(
            "engine=jcode\nbinary={BUSYBOX}\nhome={}\nversion=jcode/resume-fixture\narg=sh\narg=-c\narg={script}\narg=api-stdio\n",
            home.display()
        ),
    );

    let serving = serve(&fixture.config);
    let mut lane = open_lane(&fixture);
    assert_eq!(
        lane.run_managed(
            "managed-jcode-new-1",
            "create the retained session",
            ManagedSessionMode::New,
        )
        .expect("new managed JCode turn"),
        "JCODE-NEW-OK"
    );
    assert_eq!(
        lane.run_managed(
            "managed-jcode-follow-1",
            "continue the retained session",
            ManagedSessionMode::Resume("jcode-resume-session"),
        )
        .expect("resumed managed JCode turn"),
        "JCODE-RESUME-OK"
    );
    serving.shutdown(&fixture.config);
}

/// The approved profile's defining capability: a provider process may create
/// a script in its empty workspace and execute a system interpreter, while the
/// ordinary run profile carries no such runtime grant.
#[test]
fn an_agentic_scratchpad_creates_and_executes_a_workspace_script() {
    let test = "an_agentic_scratchpad_creates_and_executes_a_workspace_script";
    if let Some(reason) = first_failing_gate() {
        not_proven(test, reason);
        return;
    }
    if !Path::new("/usr/bin/python3").exists() {
        not_proven(test, "no Python interpreter at /usr/bin/python3");
        return;
    }

    let argv = vec![
        String::from("sh"),
        String::from("-c"),
        format!(
            "{BUSYBOX} printf 'print(\"scratchpad-script-ok\")\\n' > {ATTEMPT_WORKSPACE_PLACEHOLDER}/task.py; /usr/bin/python3 {ATTEMPT_WORKSPACE_PLACEHOLDER}/task.py > {ANSWER_PLACEHOLDER}"
        ),
    ];
    let fixture = contained_fixture(&argv);
    let serving = serve(&fixture.config);
    let mut lane = open_lane(&fixture);
    assert_eq!(
        lane.run_agentic_scratchpad("create, run, and verify the script"),
        Ok(String::from("scratchpad-script-ok")),
        "the trusted agentic profile must support iterative workspace scripts"
    );
    serving.shutdown(&fixture.config);
}

/// The falsification. A workload that writes no answer, and one that fails, are
/// each reported as themselves.
///
/// Without this the test above would pass just as well against a lane that
/// answered every run with a fixed string.
#[test]
fn a_run_that_writes_nothing_or_fails_is_not_reported_as_an_answer() {
    let test = "a_run_that_writes_nothing_or_fails_is_not_reported_as_an_answer";
    if let Some(reason) = first_failing_gate() {
        not_proven(test, reason);
        return;
    }

    // A workload that touches its answer file and writes nothing into it. The
    // argv still names the answer file, so the configuration is admissible; the
    // run simply leaves nothing there.
    let silent = vec![
        String::from("sh"),
        String::from("-c"),
        format!("{BUSYBOX} true > {ANSWER_PLACEHOLDER}"),
    ];
    let fixture = contained_fixture(&silent);
    let serving = serve(&fixture.config);
    let mut lane = open_lane(&fixture);
    assert_eq!(
        lane.run("a task whose run says nothing"),
        Err(RunFailure::NoAnswer),
        "an empty answer file must not be reported as an answer"
    );
    serving.shutdown(&fixture.config);

    // A workload that exits nonzero. The answer file is never created, and the
    // terminal state is `failed` rather than a completion with no answer.
    let failing = vec![
        String::from("sh"),
        String::from("-c"),
        format!("{BUSYBOX} false; {BUSYBOX} true > {ANSWER_PLACEHOLDER}.unused; exit 3"),
    ];
    let fixture = contained_fixture(&failing);
    let serving = serve(&fixture.config);
    let mut lane = open_lane(&fixture);
    assert_eq!(
        lane.run("a task whose run fails"),
        Err(RunFailure::Failed),
        "a failed run must be reported as a failure"
    );
    serving.shutdown(&fixture.config);
}

/// A serving daemon with no provider configuration refuses every `/run` and
/// never panics.
#[test]
fn an_unconfigured_daemon_answers_not_configured() {
    let fixture = Fixture::new(None, None);
    let mut lane = open_lane(&fixture);
    assert!(!lane.configured());
    assert_eq!(
        lane.run("anything at all"),
        Err(RunFailure::NotConfigured),
        "an unconfigured daemon must refuse in a word an operator can read"
    );
}

#[test]
fn a_dedicated_conversation_provider_is_selected_for_bounded_fast_profiles() {
    let fixture = Fixture::new(None, Some("127.0.0.1 1 loopback\n"));
    let primary_home = fixture.provider_home();
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &busybox_provider(&primary_home, &["sh", "-c", "true > {answer}"]),
    );
    let conversation_home = fixture.state_dir().join("conversation-home");
    std::fs::create_dir(&conversation_home).expect("conversation home");
    std::fs::set_permissions(&conversation_home, std::fs::Permissions::from_mode(0o700))
        .expect("private conversation home");
    write_private(
        &fixture.state_dir().join(CONVERSATION_PROVIDER_CONFIG_NAME),
        &busybox_provider(&conversation_home, &["sh", "-c", "true > {answer}"]),
    );

    let lane = open_lane(&fixture);
    assert_eq!(
        lane.question_runtime(QuestionProfile::Conversation),
        QuestionRuntime::deepseek_flash(QuestionProfile::Conversation)
    );
    assert_eq!(
        lane.question_runtime(QuestionProfile::OperationalLookup),
        QuestionRuntime::deepseek_flash(QuestionProfile::OperationalLookup)
    );
    assert_eq!(
        lane.question_runtime(QuestionProfile::Operational),
        QuestionRuntime::codex(QuestionProfile::Operational),
        "operational questions must retain the primary intelligent provider"
    );
}

#[test]
fn a_primary_provider_cutover_rolls_the_stable_deployment_slot_forward() {
    let fixture = Fixture::new(None, Some("127.0.0.1 1 loopback\n"));
    let primary_home = fixture.provider_home();
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &format!(
            "engine=jcode\nbinary={BUSYBOX}\nhome={}\nversion=jcode-cutover-fixture\n\
             arg=--quiet\narg=api-stdio\n",
            primary_home.display()
        ),
    );
    let conversation_home = fixture.state_dir().join("conversation-home");
    std::fs::create_dir(&conversation_home).expect("conversation home");
    std::fs::set_permissions(&conversation_home, std::fs::Permissions::from_mode(0o700))
        .expect("private conversation home");
    write_private(
        &fixture.state_dir().join(CONVERSATION_PROVIDER_CONFIG_NAME),
        &busybox_provider(&conversation_home, &["sh", "-c", "true > {answer}"]),
    );

    let deployments_path = fixture.state_dir().join(PROVIDER_DEPLOYMENTS_NAME);
    let mut deployments = ProviderDeployments::open(&deployments_path).expect("deployment store");
    deployments
        .register(DeploymentRegistration {
            deployment_id: "primary",
            provider_kind: "codex",
            primary_rank: Some(1),
            context_window_rank: Some(0),
        })
        .expect("old primary deployment");
    deployments
        .register(DeploymentRegistration {
            deployment_id: "conversation",
            provider_kind: "conversation",
            primary_rank: Some(0),
            context_window_rank: Some(1),
        })
        .expect("conversation deployment");
    drop(deployments);

    let lane = open_lane(&fixture);
    assert_eq!(
        lane.question_runtime(QuestionProfile::Conversation),
        QuestionRuntime::deepseek_flash(QuestionProfile::Conversation),
        "a primary-engine cutover must not disable the conversation router"
    );
    let deployments = ProviderDeployments::open(deployments_path).expect("reopen deployment store");
    assert_eq!(deployments.get("primary").unwrap().provider_kind, "jcode");
}

#[test]
fn a_malformed_conversation_provider_fails_closed_without_codex_fallback() {
    let fixture = Fixture::new(None, Some("127.0.0.1 1 loopback\n"));
    let primary_home = fixture.provider_home();
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &busybox_provider(&primary_home, &["sh", "-c", "true > {answer}"]),
    );
    write_private(
        &fixture.state_dir().join(CONVERSATION_PROVIDER_CONFIG_NAME),
        "schema=unknown\n",
    );

    let mut lane = open_lane(&fixture);
    assert_eq!(
        lane.question_runtime(QuestionProfile::Conversation),
        QuestionRuntime::conversation_provider_refused()
    );
    assert_eq!(
        lane.run_question(
            "do not spend the primary provider",
            QuestionProfile::Conversation
        ),
        Err(RunFailure::NotConfigured)
    );
}

/// Paid, owner-triggered proof that the small adapter works through the real
/// prompt slot, cgroup, Landlock boundary and CONNECT broker. Ignored by every
/// ordinary test run; it reads only explicit path coordinates from the
/// environment and never accepts a credential value there.
#[test]
#[ignore = "requires an explicitly configured paid DeepSeek provider"]
fn live_deepseek_conversation_answers_through_the_contained_lane() {
    let test = "live_deepseek_conversation_answers_through_the_contained_lane";
    if let Some(reason) = first_failing_gate() {
        panic!("{test} containment gate failed: {reason}");
    }
    let binary = std::env::var("AUTOMONIQUE_LIVE_DEEPSEEK_BINARY")
        .expect("set the absolute contained adapter path");
    let home = std::env::var("AUTOMONIQUE_LIVE_DEEPSEEK_HOME")
        .expect("set the absolute private provider-home path");
    assert!(Path::new(&binary).is_absolute());
    assert!(Path::new(&home).is_absolute());

    let fixture = Fixture::new(None, Some("api.deepseek.com 443 public\n"));
    write_private(
        &fixture.state_dir().join(CONVERSATION_PROVIDER_CONFIG_NAME),
        &format!(
            "binary={binary}\nhome={home}\nversion=deepseek-v4-flash-live-proof\n\
             arg=--output\narg={{answer}}\n"
        ),
    );
    let serving = serve(&fixture.config);
    let mut lane = open_lane(&fixture);
    assert_eq!(
        lane.question_runtime(QuestionProfile::Conversation),
        QuestionRuntime::deepseek_flash(QuestionProfile::Conversation)
    );
    let started = Instant::now();
    let answer = lane
        .run_question(
            "Reply with exactly: AUTOMONIQUE-DEEPSEEK-CONTAINED-OK",
            QuestionProfile::Conversation,
        )
        .expect("live contained provider answer");
    assert_eq!(answer, "AUTOMONIQUE-DEEPSEEK-CONTAINED-OK");
    assert!(
        started.elapsed() < Duration::from_secs(25),
        "the provider exceeded its complete request budget"
    );
    serving.shutdown(&fixture.config);
}

/// Owner-triggered proof against the already-running daemon rather than a
/// test fixture. This is the closest bounded reproduction of Telegram's
/// question worker: it opens the production socket lane over live state,
/// submits one ordinary conversation, starts it through the live admin socket,
/// and waits for the answer from that daemon's run index.
#[test]
#[ignore = "requires an explicitly configured live daemon and paid DeepSeek provider"]
fn live_daemon_answers_a_deepseek_conversation_through_its_admin_socket() {
    let state = PathBuf::from(
        std::env::var("AUTOMONIQUE_LIVE_STATE_DIR").expect("set the private live state path"),
    );
    let runtime = PathBuf::from(
        std::env::var("AUTOMONIQUE_LIVE_RUNTIME_DIR").expect("set the live runtime path"),
    );
    assert!(state.is_absolute());
    assert!(runtime.is_absolute());

    let mut lane = SocketRunLane::open(
        &state,
        &runtime.join("automonique/admin.sock"),
        &state.join(RUN_INDEX_NAME),
    )
    .expect("open live socket lane");
    let answer = lane
        .run_question(
            "Reply with exactly: AUTOMONIQUE-LIVE-TELEGRAM-LANE-OK",
            QuestionProfile::Conversation,
        )
        .expect("live daemon conversation answer");
    assert_eq!(answer, "AUTOMONIQUE-LIVE-TELEGRAM-LANE-OK");
}

/// Run one task, failing the test rather than hanging if the lane does not
/// answer.
///
/// The lane has its own deadline; this is a second, shorter one so a hermetic
/// gate reports a stuck run as a failure instead of waiting out the lane's.
fn with_deadline(lane: &mut SocketRunLane, task: &str) -> String {
    let started = Instant::now();
    let answer = lane.run(task).expect("the run answers");
    assert!(
        started.elapsed() < LANE_DEADLINE,
        "a hermetic run must not take {LANE_DEADLINE:?}"
    );
    answer
}
