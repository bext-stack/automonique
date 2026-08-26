// SPDX-License-Identifier: Elastic-2.0

//! Brokered egress through the execution lane: what a `brokered_named` document
//! is admitted to, and what a run really reaches.
//!
//! # The claim, and the four proofs under it
//!
//! The claim is that a document declaring `brokered_named` egress runs under the
//! *same* containment as one that denies it, plus exactly one loopback port —
//! and that the port leads only to a broker holding that run's own allowlist.
//!
//! 1. [`a_brokered_document_composes_exactly_the_broker_grants`] pins the
//!    composition to the byte: the encoded launch frame carries `socket=tcp`,
//!    one `connect_port` equal to a *running* broker's own port, and the two
//!    proxy variables bound to that broker's own `proxy_url()` — and carries no
//!    UDP grant, no port 443, and no `bind` port.
//! 2. [`a_document_that_denies_egress_gets_no_broker_and_no_network_at_all`] is
//!    the anti-vacuity mirror: the same builder, one field changed, and the
//!    frame has no socket grant and no port of any kind. A lane that granted
//!    the network unconditionally would fail it.
//! 3. [`egress_this_launch_cannot_enforce_is_refused_rather_than_approximated`]
//!    covers every egress shape that is *not* admitted: `brokered_any` on either
//!    axis, two axes that disagree, and `brokered_named` with no destinations
//!    resolved.
//! 4. [`the_broker_permits_the_admitted_destinations_and_nothing_else`] drives a
//!    broker built from an admitted launch's own requirement and shows an
//!    allowlisted destination tunnelling and a neighbouring one refused, then
//!    shows the port closed once the broker is dropped.
//!
//! # What is proved here, and what is left to the owner-run proof
//!
//! Proofs 1 to 3 are pure: they run everywhere, need no host capability, and
//! start no workload. Proof 4 starts a real broker and a real loopback
//! destination, and **its client is this test process, not a contained
//! workload** — it proves the broker a launch is admitted for, not the launch's
//! own reach.
//!
//! [`a_contained_workload_reaches_only_its_allowlisted_destination`] is the one
//! that closes that gap, and it needs the enforced host every other execution
//! proof needs: a delegated cgroup v2 domain, the Landlock and seccomp
//! mechanisms, busybox, and the built entry helper. It runs a *contained*
//! workload through the daemon's own lane, with no direct egress of any kind,
//! and asserts it reached an allowlisted destination through the broker and was
//! refused a neighbouring one.
//!
//! ```sh
//! cd rust
//! cargo build -p automonique-runner --bin automonique-launch-enter
//! cargo test -p automonique-daemon --test execute_brokered --no-run
//! systemd-run --user --scope -p Delegate=yes \
//!   --setenv=AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1 \
//!   "$(ls -t target/debug/deps/execute_brokered-* | grep -v '\.d$' | head -1)" \
//!   --test-threads=1 --nocapture
//! ```
//!
//! The scope must wrap the **test binary** rather than `cargo test`: cgroup v2
//! forbids enabling `subtree_control` on a cgroup that holds member processes,
//! so wrapping cargo makes every request answer `containment_unavailable`.
//!
//! What none of this establishes, and what Gate B1 is for: **no real provider
//! runs here**. The workload is busybox speaking one `CONNECT` by hand at a
//! destination on this host. That a real provider's own HTTP stack honours
//! `HTTPS_PROXY`, tunnels its model traffic through this broker, and completes a
//! live round trip under this containment is an owner-run, paid, networked
//! proof, and nothing in this file stands in for it.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use automonique_daemon::egress::allowlist_for;
use automonique_daemon::execute::{
    DAEMON_WORKSPACE_REGISTRY, locate_launch_helper, offered_host_features,
};
use automonique_daemon::{Daemon, DaemonConfig};
use automonique_egress_broker::{BrokerConfig, EgressBroker};
use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse, SubmittedRunSpec};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_protocol::context::{ContextManifest, TokenBudget};
use automonique_protocol::digest::Sha256;
use automonique_protocol::execute_api::{ExecuteRefusal, ExecuteRequest, ExecuteResponse};
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
    FilesystemAccess, HostFeature, ImplementationDigest, IsolationRequirement, NestedIsolation,
    NetworkAccess, PathGrants, PolicyDigest, ProhibitedCapabilities, ProviderControlEgress,
    RequiredFeature, RequiredFeatures, SandboxProfile, SandboxSpec, SandboxSpecParts,
    ToolWorkloadEgress, WorkspaceContextHash,
};
use automonique_protocol::tools::RunId;
use automonique_protocol::workspace::{IsolationKind, WorkspaceRegistration, WorkspaceToken};
use automonique_runner::admission::{
    AdmissionContext, AdmissionContextParts, AdmissionRefusal, AdmittedLaunch, BrokeredDestination,
    BrokeredScope, PromptSource, ResolvedPrompt, TemporaryStorageEnforcement, UnenforcedBudget,
    admit,
};
use automonique_runner::capability::HostCapabilities;
use automonique_runner::{
    AdmissionFields, AdmissionFieldsParts, ArtifactGrantBindings, ContainmentDomain, CwdToken,
    ExecutionPlanDigest, ExtensionSetDigest, FallbackEligibility, IntegrationMode, IoReservation,
    LaunchPlan, ModelRoutingDigest, PersonaDigest, PortabilityPolicy, ProfileDigest,
    PromptDeliveryPlan, ProtectedPromptReference, RemoteAttestationPolicy, RequiredCapabilities,
    RunCoordinates, RunOrigin, RunSpec, RunSpecParts, RunnerEventDialect, SchedulerDecisionDigest,
    SchedulerReservationBinding, SchedulerReservationId, SkillsetDigest, ToolsetDigest,
    WorkspaceRegistryId, WorkspaceReservation,
};

const BUSYBOX: &str = "/usr/bin/busybox";
const REQUIRE_ENFORCED_ENV: &str = "AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT";
const MEMORY_BYTES: u64 = 128 * 1024 * 1024;
const PROCESSES: u64 = 64;
const TIMEOUT_MILLIS: u64 = 30_000;
const SPOOL_BYTES: u64 = 1024 * 1024;
const TERMINAL_DEADLINE: Duration = Duration::from_secs(90);
/// What the fake destination answers with once a tunnel reaches it.
const DESTINATION_TOKEN: &[u8] = b"DESTINATION-OK\n";

// --- the document ---------------------------------------------------------

fn digest_text(digit: char) -> String {
    format!("sha256:{}", digit.to_string().repeat(64))
}

/// The egress a document declares, on both of its axes at once.
///
/// One value for two fields is not a shortcut: this launch builds one boundary
/// around one process tree, so a document whose axes disagree is refused, and
/// [`egress_this_launch_cannot_enforce_is_refused_rather_than_approximated`] is
/// where that is proved. Every admissible document therefore has one answer.
#[derive(Clone, Copy)]
struct Egress {
    control: NetworkAccess,
    workload: NetworkAccess,
}

impl Egress {
    const fn both(access: NetworkAccess) -> Self {
        Self {
            control: access,
            workload: access,
        }
    }
}

/// A synthetic feature both the document and the context name.
///
/// The hermetic proofs negotiate against this rather than against the host, so
/// they assert the same composition on every machine. The enforced proof pins
/// what this daemon really offers instead; see [`required_features`].
fn synthetic_feature() -> HostFeature {
    HostFeature::new(
        "descendant_containment",
        ImplementationDigest::parse(&digest_text('3')).expect("digest"),
    )
    .expect("feature")
}

fn features_requiring(offered: &[HostFeature]) -> RequiredFeatures {
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

/// What this daemon really offers, for the enforced proof.
///
/// On a host that offers nothing the document must still declare a feature —
/// an empty required set is refused, because a spec requiring no enforcement
/// would admit on a host that enforces nothing — and on such a host a host-wide
/// gate refuses long before the negotiation is reached.
fn required_features() -> RequiredFeatures {
    let offered = offered_host_features();
    if offered.is_empty() {
        return features_requiring(&[synthetic_feature()]);
    }
    features_requiring(&offered)
}

fn sandbox(egress: Egress, features: RequiredFeatures) -> SandboxSpec {
    SandboxSpec::compile(SandboxSpecParts {
        profile: SandboxProfile::new(
            "brokered-profile",
            1,
            FilesystemAccess::IsolatedWritable,
            // The profile is a minimum contract the spec may not widen, so the
            // tool axis moves with it.
            ToolWorkloadEgress::brokered(egress.workload),
        )
        .expect("profile"),
        policy_digest: PolicyDigest::parse(&digest_text('4')).expect("policy digest"),
        actor: Actor::new("acme", "actor-1").expect("actor"),
        provider_account: ProviderAccountId::new("provider-account-1").expect("account"),
        workspace_context: WorkspaceContextHash::parse(&digest_text('5')).expect("context"),
        base_revision: Revision::new(7).expect("revision"),
        path_grants: PathGrants::declare(&[]).expect("grants"),
        allowlists: ExecutionAllowlists::declare(&[]).expect("allowlists"),
        provider_control_egress: ProviderControlEgress::brokered(egress.control),
        tool_workload_egress: ToolWorkloadEgress::brokered(egress.workload),
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
        required_features: features,
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

/// Every part of one document a test varies.
struct Document {
    run: String,
    slot: String,
    script: String,
    egress: Egress,
    features: RequiredFeatures,
    provider_binary: BinaryProvenance,
    environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
}

impl Document {
    /// The hermetic default: a brokered document, a synthetic pin, no script
    /// that has to run.
    fn hermetic(run: &str) -> Self {
        Self {
            run: run.to_owned(),
            slot: format!("{run}-slot"),
            script: "true".to_owned(),
            egress: Egress::both(NetworkAccess::BrokeredNamed),
            features: features_requiring(&[synthetic_feature()]),
            provider_binary: BinaryProvenance::new("busybox", &digest_text('1'), None)
                .expect("provenance"),
            environment: Vec::new(),
        }
    }

    fn spec(&self) -> RunSpec {
        RunSpec::new(RunSpecParts {
            protocol_version: 1,
            coordinates: RunCoordinates::new(
                WorkId::new("work-1").expect("work"),
                RunId::new(&self.run).expect("run"),
                AttemptId::new(format!("{}-attempt-1", self.run)).expect("attempt"),
                HostId::new("host-1").expect("host"),
                HostLifetime::Attempt,
                ExecutionBackendId::new("local-direct").expect("backend"),
            ),
            executable: PathBuf::from(BUSYBOX),
            arguments: vec!["sh".into(), "-c".into(), self.script.clone().into()],
            cwd_token: CwdToken::new("cwd-1").expect("cwd"),
            environment: self.environment.clone(),
            prompt: PromptDeliveryPlan::ProtectedReference(
                ProtectedPromptReference::new(&self.slot).expect("slot"),
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
            provider_binary: self.provider_binary.clone(),
            sandbox: sandbox(self.egress, self.features.clone()),
            admission: admission(),
        })
        .expect("valid run specification")
    }
}

// --- hermetic admission, without a daemon ---------------------------------

/// The context this daemon would build, with `destinations` as its policy.
fn context(
    root: &Path,
    document: &Document,
    destinations: &[BrokeredDestination],
) -> AdmissionContext {
    let prompt = b"a prompt".to_vec();
    let declared = automonique_protocol::sandbox::Digest::parse(&format!(
        "sha256:{}",
        Sha256::digest(&prompt).to_hex()
    ))
    .expect("digest");
    AdmissionContext::new(AdmissionContextParts {
        backend: ExecutionBackendId::new("local-direct").expect("backend"),
        workspace_registry_id: WorkspaceRegistryId::new(DAEMON_WORKSPACE_REGISTRY)
            .expect("registry"),
        workspace_root: root.to_path_buf(),
        working_directory: root.to_path_buf(),
        observed_provider_binary: document.provider_binary.clone(),
        host_features: vec![synthetic_feature()],
        prompt: Some(
            ResolvedPrompt::new(
                PromptSource::ProtectedReference(
                    ProtectedPromptReference::new(&document.slot).expect("slot"),
                ),
                prompt,
                declared,
            )
            .expect("resolved prompt"),
        ),
        unenforced_budgets: UnenforcedBudget::ALL.to_vec(),
        brokered_destinations: destinations.to_vec(),
        temporary_storage: TemporaryStorageEnforcement::Available,
    })
    .expect("a valid context")
}

/// One allowlisted public destination, the shape a provider document would use.
fn public_destination() -> BrokeredDestination {
    BrokeredDestination::new("chatgpt.com", 443, BrokeredScope::Public).expect("destination")
}

fn admit_hermetically(
    root: &Path,
    document: &Document,
    destinations: &[BrokeredDestination],
) -> Result<AdmittedLaunch, AdmissionRefusal> {
    admit(&document.spec(), &context(root, document, destinations))
}

// --- reading a launch frame ----------------------------------------------

/// The lines of an encoded launch frame.
///
/// The frame is asserted against rather than the plan's own accessors on
/// purpose: it is the exact bytes the entry helper consumes, so a grant that is
/// in the frame is a grant the workload gets, and one that is not is not.
fn frame_lines(plan: &LaunchPlan) -> Vec<String> {
    let frame = plan.encode().expect("the plan encodes");
    String::from_utf8(frame)
        .expect("the frame is text")
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The value of one environment entry in an encoded frame, by name.
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

// --- the hermetic proofs --------------------------------------------------

/// A brokered document is admitted to exactly one loopback port, and to nothing
/// the pre-broker live-provider path needed.
#[test]
fn a_brokered_document_composes_exactly_the_broker_grants() {
    let root = tempfile::tempdir().expect("temporary root");
    let document = Document::hermetic("brokered1");
    let destinations = [public_destination()];
    let admitted = admit_hermetically(root.path(), &document, &destinations).expect("admitted");

    // ADMISSION NAMES THE DESTINATIONS AND SIGNALS THE BROKER.
    let requirement = admitted
        .broker_requirement()
        .expect("a brokered document requires a broker");
    assert_eq!(requirement.destinations(), &destinations);
    assert!(
        !admitted.has_broker(),
        "admission starts no broker, so none is attached yet"
    );

    // Before a broker is attached the plan carries no network at all: the port
    // does not exist until a broker binds it.
    let bare = frame_lines(admitted.plan());
    assert!(
        !bare.iter().any(|line| line.starts_with("socket=")),
        "an admitted-but-unattached plan must carry no socket grant: {bare:?}"
    );

    // A REAL BROKER, OVER THIS RUN'S OWN ADMITTED ALLOWLIST.
    let allowlist = allowlist_for(requirement.destinations()).expect("the allowlist builds");
    let broker = EgressBroker::start(BrokerConfig::new(allowlist)).expect("the broker binds");
    assert!(
        broker.local_addr().ip().is_loopback(),
        "the broker must bind loopback and nothing else"
    );
    let port = broker.local_addr().port();
    let admitted = admitted.with_broker(broker.local_addr()).expect("attached");
    assert!(admitted.has_broker());

    let lines = frame_lines(admitted.plan());
    // WHAT THE WORKLOAD GETS.
    assert!(
        lines.iter().any(|line| line == "socket=tcp"),
        "the workload must be able to create a TCP socket: {lines:?}"
    );
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

    // WHAT IT DOES NOT GET — the whole of the pre-broker relaxation.
    //
    // `live_codex` granted `SocketGrant::InetDatagram` so a provider could do
    // its own DNS, and `allow_connect_port(443)` so it could reach an HTTPS
    // endpoint on any address. Neither is here, and there is no bind port, so
    // the workload cannot listen on the broker's port and impersonate it.
    assert!(
        !lines.iter().any(|line| line == "socket=inet-datagram"),
        "no UDP socket: a brokered workload does no DNS at all: {lines:?}"
    );
    assert!(
        !lines.iter().any(|line| line == "connect_port=443"),
        "no direct HTTPS egress: {lines:?}"
    );
    assert!(
        !lines.iter().any(|line| line.starts_with("bind_port=")),
        "no bind port: {lines:?}"
    );
    // And no resolver files, which the pre-broker path needed read grants for.
    for resolver_file in ["/etc/resolv.conf", "/etc/hosts"] {
        assert!(
            !lines
                .iter()
                .any(|line| line.starts_with("grant=")
                    && line.contains(&hex(resolver_file.as_bytes()))),
            "a brokered workload needs no resolver file: {resolver_file}"
        );
    }

    // A SECOND BROKER CANNOT BE ATTACHED.
    let second = EgressBroker::start(BrokerConfig::default()).expect("a second broker binds");
    assert!(
        matches!(
            admitted.with_broker(second.local_addr()),
            Err(AdmissionRefusal::BrokerAlreadyAttached)
        ),
        "two attachments would grant two ports"
    );
}

/// The mirror: one field changed, and there is no network of any kind.
#[test]
fn a_document_that_denies_egress_gets_no_broker_and_no_network_at_all() {
    let root = tempfile::tempdir().expect("temporary root");
    let mut document = Document::hermetic("denied1");
    document.egress = Egress::both(NetworkAccess::Denied);

    // The deployment's policy is a standing answer offered to every document,
    // so it is passed here too: a document that denies egress must be admitted
    // without it, not refused because of it and not widened by it.
    let admitted =
        admit_hermetically(root.path(), &document, &[public_destination()]).expect("admitted");
    assert!(
        admitted.broker_requirement().is_none(),
        "a denied document must require no broker whatever the host policy holds"
    );

    let lines = frame_lines(admitted.plan());
    assert!(
        !lines.iter().any(|line| line.starts_with("socket=")),
        "no socket grant of any kind: {lines:?}"
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.starts_with("connect_port=") || line.starts_with("bind_port=")),
        "no port of any kind: {lines:?}"
    );
    for name in ["HTTPS_PROXY", "HTTP_PROXY"] {
        assert_eq!(
            frame_environment(&lines, name),
            None,
            "{name} must not be bound"
        );
    }

    // And a broker may not be attached to it after the fact.
    let broker = EgressBroker::start(BrokerConfig::default()).expect("the broker binds");
    assert!(
        matches!(
            admitted.with_broker(broker.local_addr()),
            Err(AdmissionRefusal::BrokerNotRequired)
        ),
        "a launch that requires no broker must refuse one"
    );
}

/// Every egress shape this launch cannot enforce exactly, refused by name.
#[test]
fn egress_this_launch_cannot_enforce_is_refused_rather_than_approximated() {
    let root = tempfile::tempdir().expect("temporary root");
    let destinations = [public_destination()];

    // `brokered_any` is a policy with no allowlist in it, on either axis.
    let mut any = Document::hermetic("any1");
    any.egress = Egress::both(NetworkAccess::BrokeredAny);
    assert!(
        matches!(
            admit_hermetically(root.path(), &any, &destinations),
            Err(AdmissionRefusal::UnmappableField(
                "sandbox.provider_control_egress"
            ))
        ),
        "brokered_any must be refused"
    );

    // Two axes that disagree describe an enforcement one boundary cannot make.
    let mut mixed = Document::hermetic("mixed1");
    mixed.egress = Egress {
        control: NetworkAccess::BrokeredNamed,
        workload: NetworkAccess::Denied,
    };
    assert!(
        matches!(
            admit_hermetically(root.path(), &mixed, &destinations),
            Err(AdmissionRefusal::UnmappableField(
                "sandbox.provider_control_egress"
            ))
        ),
        "one boundary cannot enforce two different egress policies"
    );

    // A document that asks for brokered egress on a deployment that resolves no
    // destinations does not run. There is no default and no empty allowlist.
    let brokered = Document::hermetic("unresolved1");
    assert!(
        matches!(
            admit_hermetically(root.path(), &brokered, &[]),
            Err(AdmissionRefusal::ContextMissing(
                "sandbox.tool_workload_egress"
            ))
        ),
        "an unresolved destination set must refuse"
    );
}

/// A document that binds a proxy variable itself cannot be pointed at a broker.
///
/// The plan refuses one name bound twice, so there is no resolution in which a
/// document's own `HTTPS_PROXY` and the broker's could both be delivered — and
/// picking either would be a silent policy decision about where a workload's
/// traffic goes.
#[test]
fn a_document_that_binds_a_proxy_variable_itself_is_refused_a_broker() {
    let root = tempfile::tempdir().expect("temporary root");
    let mut document = Document::hermetic("selfproxy1");
    document.environment = vec![("HTTPS_PROXY".into(), "http://127.0.0.1:1".into())];
    let admitted =
        admit_hermetically(root.path(), &document, &[public_destination()]).expect("admitted");
    let broker = EgressBroker::start(BrokerConfig::default()).expect("the broker binds");
    assert!(
        matches!(
            admitted.with_broker(broker.local_addr()),
            Err(AdmissionRefusal::Plan { .. })
        ),
        "a document cannot pre-bind the variable that points it at its broker"
    );
}

/// An endpoint that is not a loopback port is refused rather than granted.
#[test]
fn only_a_loopback_endpoint_may_be_attached() {
    let root = tempfile::tempdir().expect("temporary root");
    let document = Document::hermetic("endpoint1");
    for rejected in [
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        SocketAddr::from(([203, 0, 113, 7], 8080)),
    ] {
        let admitted =
            admit_hermetically(root.path(), &document, &[public_destination()]).expect("admitted");
        assert!(
            matches!(
                admitted.with_broker(rejected),
                Err(AdmissionRefusal::BrokerEndpointRejected(_))
            ),
            "{rejected} must be refused"
        );
    }
}

/// The broker a launch is admitted for permits its destinations and nothing
/// else, and stops existing when it is dropped.
///
/// The client here is **this test process**, not a contained workload: what is
/// proved is the allowlist a launch's own requirement produces, and the
/// lifetime of the broker built from it. The contained half is
/// [`a_contained_workload_reaches_only_its_allowlisted_destination`].
#[test]
fn the_broker_permits_the_admitted_destinations_and_nothing_else() {
    let root = tempfile::tempdir().expect("temporary root");
    let permitted = Destination::listen();
    let refused = Destination::listen();

    let mut document = Document::hermetic("allowlist1");
    document.egress = Egress::both(NetworkAccess::BrokeredNamed);
    let destinations =
        [
            BrokeredDestination::new("127.0.0.1", permitted.port, BrokeredScope::Loopback)
                .expect("destination"),
        ];
    let admitted = admit_hermetically(root.path(), &document, &destinations).expect("admitted");
    let allowlist = allowlist_for(
        admitted
            .broker_requirement()
            .expect("brokered")
            .destinations(),
    )
    .expect("the allowlist builds");
    let broker = EgressBroker::start(BrokerConfig::new(allowlist)).expect("the broker binds");
    let endpoint = broker.local_addr();

    let answer = connect_through(endpoint, permitted.port);
    assert!(
        answer.starts_with("HTTP/1.1 200 Connection Established"),
        "an allowlisted destination must tunnel: {answer:?}"
    );
    assert!(
        answer.contains(std::str::from_utf8(DESTINATION_TOKEN).expect("token is text")),
        "the destination's own bytes must reach the client: {answer:?}"
    );

    let answer = connect_through(endpoint, refused.port);
    assert!(
        answer.starts_with("HTTP/1.1 403 Forbidden"),
        "a destination one port away must be refused: {answer:?}"
    );
    assert_eq!(
        refused.accepted(),
        0,
        "a refused destination must never be dialled at all"
    );

    // TEARDOWN IS REAL.
    drop(broker);
    assert!(
        TcpStream::connect_timeout(&endpoint, Duration::from_millis(500)).is_err(),
        "a dropped broker must leave no listener behind"
    );
}

// --- a fake destination, on this host ------------------------------------

/// A loopback listener that answers [`DESTINATION_TOKEN`] and closes.
struct Destination {
    port: u16,
    accepted: Arc<std::sync::atomic::AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Destination {
    fn listen() -> Self {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("a loopback destination binds");
        let port = listener.local_addr().expect("bound").port();
        listener.set_nonblocking(true).expect("non-blocking accept");
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_accepted = Arc::clone(&accepted);
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(std::sync::atomic::Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        thread_accepted.fetch_add(1, std::sync::atomic::Ordering::Release);
                        let _ = stream.write_all(DESTINATION_TOKEN);
                        let _ = stream.flush();
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            port,
            accepted,
            stop,
            thread: Some(thread),
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(std::sync::atomic::Ordering::Acquire)
    }
}

impl Drop for Destination {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Speak one `CONNECT` at `endpoint` for `127.0.0.1:port` and read the answer.
fn connect_through(endpoint: SocketAddr, port: u16) -> String {
    let mut stream =
        TcpStream::connect_timeout(&endpoint, Duration::from_secs(5)).expect("the broker answers");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read deadline");
    stream
        .write_all(connect_head(port).as_bytes())
        .expect("the request is written");
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer);
    String::from_utf8_lossy(&answer).into_owned()
}

/// The exact `CONNECT` head a client sends for a loopback destination.
fn connect_head(port: u16) -> String {
    format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
}

// --- the enforced proof ---------------------------------------------------

fn sandbox_enforceable() -> bool {
    HostCapabilities::probe()
        .select_mode(&automonique_daemon::execute::ENFORCED_PROPERTIES)
        .is_ok()
}

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

fn not_proven(test: &str, reason: &str) {
    assert!(
        std::env::var_os(REQUIRE_ENFORCED_ENV).is_none(),
        "{test}: {REQUIRE_ENFORCED_ENV} is set but this host cannot prove it: {reason}"
    );
    eprintln!("[execute_brokered] NOT PROVEN: {test}: {reason}");
}

/// A private root with the daemon's state directory, its prompt slots, and its
/// destination policy already in place.
///
/// The policy is written before the daemon opens because the lane reads it once,
/// at open: what a run is admitted against is the policy the daemon started
/// with.
fn fixture(policy: &str, slots: &[(&str, Vec<u8>)]) -> (tempfile::TempDir, DaemonConfig) {
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
    for (slot, bytes) in slots {
        std::fs::write(prompts.join(slot), bytes).expect("prompt slot");
        std::fs::set_permissions(prompts.join(slot), std::fs::Permissions::from_mode(0o600))
            .expect("private slot");
    }
    std::fs::write(state_dir.join("egress-destinations"), policy).expect("destination policy");
    std::fs::set_permissions(
        state_dir.join("egress-destinations"),
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("private policy");
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

fn admin(config: &DaemonConfig, request: AdminRequest) -> AdminResponse {
    let payload = request
        .to_message()
        .expect("encode request")
        .to_canonical_bytes();
    AdminResponse::from_canonical_bytes(&exchange(config, &payload)).expect("admitted response")
}

fn execute(config: &DaemonConfig, label: &str, run: &str) -> ExecuteResponse {
    let request = ExecuteRequest::ExecuteRun {
        request_id: RequestId::new(label).expect("request ID"),
        run_id: RunId::new(run).expect("run identity"),
    };
    let payload = request
        .to_message()
        .expect("encode execute request")
        .to_canonical_bytes();
    ExecuteResponse::from_canonical_bytes(&exchange(config, &payload)).expect("execute response")
}

fn listed_state(config: &DaemonConfig, run: &str) -> RunState {
    let request = RunsRequest::ListRuns {
        request_id: RequestId::new("list").expect("request ID"),
        query: ListRuns::new(RunStateFilter::any(), None, PageSize::MAX),
    };
    let payload = request
        .to_message()
        .expect("encode runs request")
        .to_canonical_bytes();
    let response =
        RunsResponse::from_canonical_bytes(&exchange(config, &payload)).expect("runs response");
    let RunsResponse::RunList { page, .. } = response else {
        panic!("expected a page, got {response:?}")
    };
    page.runs()
        .iter()
        .find(|summary| summary.run_id().as_str() == run)
        .unwrap_or_else(|| panic!("{run} is not listed"))
        .state()
}

fn await_terminal(config: &DaemonConfig, run: &str) -> RunState {
    let deadline = Instant::now() + TERMINAL_DEADLINE;
    loop {
        let state = listed_state(config, run);
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

/// The script one contained workload runs.
///
/// It learns where its broker is **only** from `HTTPS_PROXY` — the variable the
/// launch bound — because there is nothing else it could learn it from: the
/// port is this run's own ephemeral one and was not known when the document was
/// written. Everything it executes is the granted busybox by absolute path.
///
/// `cat` copies the run's prompt (the `CONNECT` head) into the tunnel and the
/// `sleep` holds the pipe's write end open afterwards, so the workload does not
/// close its side before the answer arrives.
fn workload_script(witness: &Path) -> String {
    format!(
        "proxy=${{HTTPS_PROXY#http://}}; \
         {{ {BUSYBOX} cat; {BUSYBOX} sleep 2; }} | \
         {BUSYBOX} nc -w 5 ${{proxy%:*}} ${{proxy##*:}} > {}",
        witness.display()
    )
}

/// A contained workload with no direct egress reaches an allowlisted
/// destination through its broker, and is refused a neighbouring one.
///
/// This is the whole Wave 4 integration, minus the provider: a real document,
/// through the real socket, admitted by the real bridge, under the real
/// containment, with a real broker started and torn down by the lane.
#[test]
fn a_contained_workload_reaches_only_its_allowlisted_destination() {
    let test = "a_contained_workload_reaches_only_its_allowlisted_destination";
    if !Path::new(BUSYBOX).exists() {
        not_proven(test, "no static busybox at /usr/bin/busybox");
        return;
    }
    if let Some(gate) = first_failing_gate() {
        not_proven(test, &format!("this host refuses at {gate}"));
        return;
    }

    // One destination this deployment permits, and one it does not. Both are
    // real listeners, so "refused" means the broker never dialled rather than
    // that there was nothing there.
    let permitted = Destination::listen();
    let refused = Destination::listen();
    let policy = format!("127.0.0.1 {} loopback\n", permitted.port);

    let reach = "brokerreach1";
    let deny = "brokerdeny1";
    // Each run's prompt is its own `CONNECT` head — the one thing that differs
    // between the two documents, and the only place a destination is named.
    let slots = [
        (
            format!("{reach}-slot"),
            connect_head(permitted.port).into_bytes(),
        ),
        (
            format!("{deny}-slot"),
            connect_head(refused.port).into_bytes(),
        ),
    ];
    let slot_refs: Vec<(&str, Vec<u8>)> = slots
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.clone()))
        .collect();
    let (_root, config) = fixture(&policy, &slot_refs);

    let witness = |run: &str| {
        config
            .state_dir()
            .join("runs")
            .join(run)
            .join("workspace")
            .join("witness.txt")
    };
    let provider_binary = {
        let bytes = std::fs::read(BUSYBOX).expect("busybox is readable");
        BinaryProvenance::new(
            "busybox",
            &format!("sha256:{}", Sha256::digest(&bytes).to_hex()),
            None,
        )
        .expect("observed provenance")
    };

    let serving = serve(&config);
    for run in [reach, deny] {
        let mut document = Document::hermetic(run);
        document.script = workload_script(&witness(run));
        document.features = required_features();
        document.provider_binary = provider_binary.clone();
        let payload = document
            .spec()
            .to_canonical_bytes()
            .expect("canonical encoding");
        let submission = SubmittedRunSpec::sealed(payload, run).expect("bounded submission");
        let response = admin(
            &config,
            AdminRequest::submit_run(RequestId::new(run).expect("request ID"), submission),
        );
        assert!(
            matches!(response, AdminResponse::RunAccepted { .. }),
            "expected acceptance, got {response:?}"
        );

        let started = execute(&config, run, run);
        assert!(
            matches!(started, ExecuteResponse::Accepted { .. }),
            "expected the brokered run to start, got {started:?}"
        );
        assert_eq!(await_terminal(&config, run), RunState::Completed);
    }

    // THE ALLOWLISTED DESTINATION WAS REACHED, THROUGH THE BROKER.
    let reached = std::fs::read_to_string(witness(reach)).expect("the workload wrote its witness");
    assert!(
        reached.starts_with("HTTP/1.1 200 Connection Established"),
        "the contained workload must have tunnelled: {reached:?}"
    );
    assert!(
        reached.contains(std::str::from_utf8(DESTINATION_TOKEN).expect("token is text")),
        "the destination's own bytes must have reached the contained workload: {reached:?}"
    );
    assert_eq!(
        permitted.accepted(),
        1,
        "the broker must have dialled the allowlisted destination exactly once"
    );

    // THE NEIGHBOURING ONE WAS NOT.
    let denied = std::fs::read_to_string(witness(deny)).expect("the workload wrote its witness");
    assert!(
        denied.starts_with("HTTP/1.1 403 Forbidden"),
        "a destination this run was not admitted for must be refused: {denied:?}"
    );
    assert_eq!(
        refused.accepted(),
        0,
        "a refused destination must never be dialled at all"
    );

    serving.shutdown(&config);

    // THE BROKERS ARE GONE.
    //
    // Both runs ended, so both brokers were dropped by their workers. Nothing
    // is listening on either port: proved by the destination counters above
    // staying still, and by the daemon having joined every worker before it
    // returned.
    assert_eq!(permitted.accepted(), 1);
}

/// A brokered document on a deployment with no destination policy is refused,
/// and runs nothing.
///
/// The negative control for the policy file: without it, the enforced proof
/// would pass just as well against a lane that granted egress unconditionally.
#[test]
fn a_brokered_document_without_a_destination_policy_is_refused() {
    let test = "a_brokered_document_without_a_destination_policy_is_refused";
    if !Path::new(BUSYBOX).exists() {
        not_proven(test, "no static busybox at /usr/bin/busybox");
        return;
    }
    if let Some(gate) = first_failing_gate() {
        not_proven(test, &format!("this host refuses at {gate}"));
        return;
    }

    let run = "brokerunset1";
    let (_root, config) = fixture(
        "# no destinations\n",
        &[(&format!("{run}-slot"), b"x".to_vec())],
    );
    let witness = config
        .state_dir()
        .join("runs")
        .join(run)
        .join("workspace")
        .join("witness.txt");

    let mut document = Document::hermetic(run);
    document.script = workload_script(&witness);
    document.features = required_features();
    document.provider_binary = {
        let bytes = std::fs::read(BUSYBOX).expect("busybox is readable");
        BinaryProvenance::new(
            "busybox",
            &format!("sha256:{}", Sha256::digest(&bytes).to_hex()),
            None,
        )
        .expect("observed provenance")
    };

    let serving = serve(&config);
    let payload = document
        .spec()
        .to_canonical_bytes()
        .expect("canonical encoding");
    let submission = SubmittedRunSpec::sealed(payload, run).expect("bounded submission");
    admin(
        &config,
        AdminRequest::submit_run(RequestId::new(run).expect("request ID"), submission),
    );

    let response = execute(&config, run, run);
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
    assert!(!witness.exists(), "a refused document must run no workload");
    assert_eq!(listed_state(&config, run), RunState::Ready);

    serving.shutdown(&config);
}
