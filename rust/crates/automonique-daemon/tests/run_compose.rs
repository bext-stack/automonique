// SPDX-License-Identifier: Elastic-2.0

//! `/run` end to end, with no provider and no network: what a composed document
//! is admitted to, and that the answer a contained run writes comes back.
//!
//! # The claim, and the proofs under it
//!
//! The claim is that an operator's `/run <task>` becomes one contained run whose
//! answer is the reply — composed by this daemon, admitted by the Wave-4
//! brokered execute lane, run under the real containment, and read back out of
//! the run's own workspace.
//!
//! 1. [`a_composed_document_is_admitted_and_carries_unix_plus_the_broker_grants`]
//!    pins the composition to the byte. The composed document is decoded,
//!    admitted against the context this daemon builds, attached to a *running*
//!    broker, and the encoded launch frame is asserted to carry `socket=tcp`,
//!    `socket=unix`, one `connect_port` equal to that broker's own, and the two
//!    proxy variables — and to carry no UDP grant, no port 443, no bind port and
//!    no resolver file.
//! 2. [`the_answer_path_is_the_workspace_the_lane_will_resolve`] is the seam the
//!    whole answer-capture design rests on: the path in the argv is the path
//!    [`automonique_daemon::execute::run_workspace`] resolves, absolute, inside
//!    the workspace, and named in the document rather than patched in later.
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
//! fixed path, cached an answer, or reported the wrong run's workspace fails.
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
    ANSWER_LEAF, ANSWER_PLACEHOLDER, COMPOSE_MEMORY_BYTES, ComposeRefusal, Composition,
    CompositionInputs, DEFAULT_ARGV, PROVIDER_CONFIG_NAME, ProviderConfig, ProviderRunProfile,
    QUESTION_MEMORY_BYTES, QUESTION_MODEL_CONFIG, QUESTION_REASONING_CONFIG, WORKSPACE_PLACEHOLDER,
    compose, compose_with_profile,
};
use automonique_daemon::execute::{
    DAEMON_BACKEND_ID, DAEMON_WORKSPACE_REGISTRY, locate_launch_helper, offered_host_features,
    run_workspace,
};
use automonique_daemon::run_lane::{CONVERSATION_PROVIDER_CONFIG_NAME, SocketRunLane};
use automonique_daemon::telegram_bridge::{QuestionProfile, QuestionRuntime, RunFailure, RunLane};
use automonique_daemon::{Daemon, DaemonConfig};
use automonique_egress_broker::{BrokerConfig, EgressBroker};
use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_protocol::digest::Sha256;
use automonique_protocol::sandbox::{
    Digest, ExecutionBackendId, HostFeature, ImplementationDigest,
};
use automonique_runner::admission::{
    AdmissionContext, AdmissionContextParts, AdmittedLaunch, BrokeredDestination, BrokeredScope,
    PromptSource, ResolvedPrompt, UnenforcedBudget, admit,
};
use automonique_runner::capability::{BoundaryProperty, HostCapabilities};
use automonique_runner::{
    ContainmentDomain, LaunchPlan, PromptDeliveryPlan, ProtectedPromptReference, RunSpec,
    WorkspaceRegistryId,
};

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
    let workspace = run_workspace(&fixture.state_dir(), composition.run_id());
    let prompt = composition.prompt().to_vec();
    let declared = Digest::parse(&format!("sha256:{}", Sha256::digest(&prompt).to_hex()))
        .expect("prompt digest");
    let PromptDeliveryPlan::ProtectedReference(slot) = spec.prompt_delivery().clone() else {
        panic!("a composed document must route its prompt through a protected slot")
    };
    let context = AdmissionContext::new(AdmissionContextParts {
        backend: ExecutionBackendId::new(DAEMON_BACKEND_ID).expect("backend"),
        workspace_registry_id: WorkspaceRegistryId::new(DAEMON_WORKSPACE_REGISTRY)
            .expect("registry"),
        workspace_root: workspace.clone(),
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
fn the_answer_path_is_the_workspace_the_lane_will_resolve() {
    let fixture = Fixture::new(None, None);
    let home = fixture.provider_home();
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &busybox_provider(&home, &[]),
    );
    let composition = compose_for(&fixture, "answerpath1", "say something");

    let workspace = run_workspace(&fixture.state_dir(), "answerpath1");
    assert_eq!(
        composition.answer_path(),
        workspace.join(ANSWER_LEAF),
        "the answer must live in the workspace the execution lane resolves"
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
        arguments.contains(&workspace.display().to_string()),
        "the argv must point the provider at the resolved workspace: {arguments:?}"
    );
    assert!(
        !arguments
            .iter()
            .any(|argument| argument.contains(WORKSPACE_PLACEHOLDER)
                || argument.contains(ANSWER_PLACEHOLDER)),
        "no placeholder may survive into the document: {arguments:?}"
    );
    // The reviewed default is what a deployment that configured no argv gets.
    assert!(
        DEFAULT_ARGV.contains(&"--ephemeral") && DEFAULT_ARGV.contains(&ANSWER_PLACEHOLDER),
        "the reviewed invocation must be a pure completion that names its answer file"
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
        .select_mode(&[
            BoundaryProperty::DescendantContainment,
            BoundaryProperty::FilesystemRestriction,
            BoundaryProperty::TcpDenial,
            BoundaryProperty::SyscallRestriction,
        ])
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

fn not_proven(test: &str, reason: &str) {
    assert!(
        std::env::var_os(REQUIRE_ENFORCED_ENV).is_none(),
        "{test}: {REQUIRE_ENFORCED_ENV} is set but this host cannot prove it: {reason}"
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
