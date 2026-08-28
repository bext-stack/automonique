// SPDX-License-Identifier: Elastic-2.0

//! Exercised proof of the RunSpec → sandboxed-launch admission bridge.
//!
//! The unit proofs are pure: they assert the exact plan bytes, the exact
//! ceilings, and the exact typed refusal for every field the bridge cannot
//! map. The final proof is not pure — it admits a real spec and runs the
//! resulting plan under the full composed sandbox, so "admitted" means
//! "launchable" rather than "well typed".
//!
//! Like every enforced proof in this crate, the launch needs a delegated
//! cgroup v2 domain. Outside one it degrades loudly, and
//! `AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1` turns the degradation into a
//! failure:
//!
//! ```sh
//! systemd-run --user --scope -p Delegate=yes \
//!   --setenv=AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1 \
//!   cargo test --manifest-path rust/Cargo.toml -p automonique-runner --test admission
//! ```

use automonique_protocol::context::{ContextManifest, TokenBudget};
use automonique_protocol::host::{AttemptId, HostId, HostLifetime, WorkId};
use automonique_protocol::identity::Actor;
use automonique_protocol::models::{
    ArtifactTransfer, ExecutorClass, ProviderAccountId, RemoteCoordinate, WorkspaceTransfer,
};
use automonique_protocol::primitives::Revision;
use automonique_protocol::provider::{
    BinaryProvenance, Capability, CapabilityGroup, ProviderSessionId, SessionBinding,
};
use automonique_protocol::sandbox::{
    AllowlistClass, AllowlistEntry, BudgetQuantities, Budgets, CredentialDescriptor,
    CredentialDescriptors, Digest, ExecutionAllowlists, ExecutionBackendId, FilesystemAccess,
    HostFeature, ImplementationDigest, IsolationRequirement, NestedIsolation, NetworkAccess,
    PathAccess, PathGrant, PathGrants, PolicyDigest, ProcessClass, ProhibitedCapabilities,
    ProviderControlEgress, RequiredFeature, RequiredFeatures, SandboxError, SandboxProfile,
    SandboxSpec, SandboxSpecParts, ToolWorkloadEgress, WorkspaceContextHash,
};
use automonique_protocol::tools::{CredentialAudiences, RunId};
use automonique_protocol::workspace::{
    AttemptWorkspaceRegistration, AttemptWorkspaceToken, IsolationKind,
};
use automonique_runner::admission::{
    AdmissionContext, AdmissionContextParts, AdmissionRefusal, AdmittedLaunch, BrokeredDestination,
    BrokeredScope, INFORMATIONAL_FIELDS, PromptSource, ProviderIdentityBinding,
    ProviderIdentityPolicy, ResolvedPrompt, SESSION_SENTINEL_DIGITS, SESSION_SENTINEL_PREFIX,
    TemporaryStorageEnforcement, UnenforcedBudget, admit,
    refuse_identity_temporary_storage_conflict,
};
use automonique_runner::filesystem::PathIntent;
use automonique_runner::{
    AdmissionFields, AdmissionFieldsParts, ArtifactGrantBinding, ArtifactGrantBindings,
    ArtifactGrantDigest, ArtifactGrantId, AttemptWorkspaceRegistryId, BackendPromptSession,
    ContainmentDomain, ContainmentError, ContainmentLimits, Controller, CredentialBinding,
    CwdToken, ExecutionPlanDigest, ExtensionSetDigest, FallbackEligibility, IntegrationMode,
    IoReservation, LaunchPlan, LaunchPlanError, ModelRoutingDigest, PersonaDigest,
    PortabilityPolicy, ProfileDigest, PromptDeliveryPlan, ProtectedPromptReference,
    RemoteAttestationPolicy, RequiredCapabilities, RunContainment, RunCoordinates, RunOrigin,
    RunSpec, RunSpecParts, RunnerEventDialect, SchedulerDecisionDigest,
    SchedulerReservationBinding, SchedulerReservationId, SkillsetDigest, ToolsetDigest,
    WorkspaceReservation,
};
use sha2::{Digest as _, Sha256};
use std::ffi::OsString;
use std::fs;
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU64;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const HELPER: &str = env!("CARGO_BIN_EXE_automonique-launch-enter");
const BUSYBOX: &str = "/usr/bin/busybox";
const REQUIRE_ENFORCED_ENV: &str = "AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT";
const DRAIN_DEADLINE: Duration = Duration::from_secs(10);
const PROMPT: &[u8] = b"admitted prompt bytes\n";
const PROMPT_SLOT: &str = "prompt-slot-1";
const ENV_NAME: &str = "AUTOMONIQUE_TEST_TOKEN";
const ENV_VALUE: &str = "admitted-value";
const MEMORY_BYTES: u64 = 128 * 1024 * 1024;
const CPU_MILLICORES: u64 = 1_000;
const PROCESSES: u64 = 64;
const DESCRIPTORS: u64 = 256;
const TIMEOUT_MILLIS: u64 = 5_000;
const SPOOL_BYTES: u64 = 1024 * 1024;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "automonique-admission-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn digest_text(digit: char) -> String {
    format!("sha256:{}", digit.to_string().repeat(64))
}

fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::parse(&format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}

fn implementation() -> ImplementationDigest {
    ImplementationDigest::parse(&digest_text('3')).unwrap()
}

fn provider_binary() -> BinaryProvenance {
    let schema = digest_text('2');
    BinaryProvenance::new("1.2.3", &digest_text('1'), Some(schema.as_str())).unwrap()
}

/// A sandbox spec every mapping rule accepts, exposed as mutable parts so one
/// test can widen exactly one axis and prove the refusal that axis produces.
fn sandbox_parts() -> SandboxSpecParts {
    SandboxSpecParts {
        profile: SandboxProfile::new(
            "admission-profile",
            1,
            FilesystemAccess::IsolatedWritable,
            ToolWorkloadEgress::denied(),
        )
        .unwrap(),
        policy_digest: PolicyDigest::parse(&digest_text('4')).unwrap(),
        actor: Actor::new("acme", "actor-1").unwrap(),
        provider_account: ProviderAccountId::new("provider-account-1").unwrap(),
        workspace_context: WorkspaceContextHash::parse(&digest_text('5')).unwrap(),
        base_revision: Revision::new(7).unwrap(),
        path_grants: PathGrants::declare(&[]).unwrap(),
        allowlists: ExecutionAllowlists::declare(&[]).unwrap(),
        provider_control_egress: ProviderControlEgress::denied(),
        tool_workload_egress: ToolWorkloadEgress::denied(),
        credentials: CredentialDescriptors::declare(&[]).unwrap(),
        budgets: Budgets::declare(BudgetQuantities {
            cgroup_memory_bytes: MEMORY_BYTES,
            cgroup_cpu_millicores: CPU_MILLICORES,
            rlimit_processes: PROCESSES,
            rlimit_descriptors: DESCRIPTORS,
            timeout_millis: TIMEOUT_MILLIS,
            temporary_storage_bytes: 1024 * 1024,
            spool_bytes: SPOOL_BYTES,
            artifact_bytes: 1024 * 1024,
        })
        .unwrap(),
        required_features: RequiredFeatures::declare(&[RequiredFeature::new(
            "process_boundary",
            &[implementation()],
        )
        .unwrap()])
        .unwrap(),
        nested_isolation: NestedIsolation::new(
            IsolationRequirement::HostBoundary,
            IsolationRequirement::HostBoundary,
        ),
        approval_revision: Revision::FIRST,
        prohibited_capabilities: ProhibitedCapabilities::declare(&[]).unwrap(),
    }
}

/// Runner-owned admission fields every mapping rule accepts.
fn admission_parts() -> AdmissionFieldsParts {
    let mode = IntegrationMode::new("native").unwrap();
    AdmissionFieldsParts {
        io_reservation: IoReservation::new(1024, 1024).unwrap(),
        workspace_reservation: WorkspaceReservation::new(8_192).unwrap(),
        session_binding: None,
        fallback_eligibility: FallbackEligibility::declare(&mode, Vec::new()).unwrap(),
        integration_mode: mode,
        required_capabilities: RequiredCapabilities::declare(Vec::new()).unwrap(),
        context_manifest: ContextManifest::new(
            Revision::FIRST,
            TokenBudget::new(0),
            Vec::new(),
            Vec::new(),
        ),
        profile_digest: ProfileDigest::parse(&digest_text('6')).unwrap(),
        model_routing_digest: ModelRoutingDigest::parse(&digest_text('7')).unwrap(),
        toolset_digest: ToolsetDigest::parse(&digest_text('8')).unwrap(),
        skillset_digest: SkillsetDigest::parse(&digest_text('9')).unwrap(),
        extension_set_digest: ExtensionSetDigest::parse(&digest_text('a')).unwrap(),
        origin: RunOrigin::Interactive,
        executor_class: ExecutorClass::Local,
        portability_policy: PortabilityPolicy::Pinned,
        remote_attestation_policy: RemoteAttestationPolicy::NotRequired,
        persona_digest: PersonaDigest::parse(&digest_text('b')).unwrap(),
        execution_plan_digest: ExecutionPlanDigest::parse(&digest_text('c')).unwrap(),
        scheduler_reservation: SchedulerReservationBinding::new(
            SchedulerReservationId::new("reservation-1").unwrap(),
            Revision::FIRST,
            SchedulerDecisionDigest::parse(&digest_text('d')).unwrap(),
        ),
        artifact_grants: ArtifactGrantBindings::declare(Vec::new()).unwrap(),
        credential_bindings: Vec::new(),
        event_dialect: RunnerEventDialect::AutomoniqueRunnerV1,
    }
}

/// A spec every mapping rule accepts, exposed as mutable parts.
fn spec_parts() -> RunSpecParts {
    RunSpecParts {
        protocol_version: 1,
        coordinates: RunCoordinates::new(
            WorkId::new("work-1").unwrap(),
            RunId::new("run-1").unwrap(),
            AttemptId::new("attempt-1").unwrap(),
            HostId::new("host-1").unwrap(),
            HostLifetime::Attempt,
            ExecutionBackendId::new("local-direct").unwrap(),
        ),
        executable: PathBuf::from(BUSYBOX),
        arguments: vec![
            OsString::from("sh"),
            OsString::from("-c"),
            OsString::from("true"),
        ],
        cwd_token: CwdToken::new("cwd-1").unwrap(),
        environment: vec![(OsString::from(ENV_NAME), OsString::from(ENV_VALUE))],
        prompt: PromptDeliveryPlan::ProtectedReference(
            ProtectedPromptReference::new(PROMPT_SLOT).unwrap(),
        ),
        attempt_workspace_registry_id: AttemptWorkspaceRegistryId::new("workspace-registry-1")
            .unwrap(),
        attempt_workspace: AttemptWorkspaceRegistration::new(
            "acme",
            "source-1",
            Revision::new(7).unwrap(),
            "snapshot-1",
            IsolationKind::AttemptCopy,
            AttemptWorkspaceToken::new("workspace-token-1").unwrap(),
        )
        .unwrap(),
        provider_binary: provider_binary(),
        sandbox: SandboxSpec::compile(sandbox_parts()).unwrap(),
        admission: AdmissionFields::new(admission_parts()),
    }
}

fn mappable_spec() -> RunSpec {
    RunSpec::new(spec_parts()).unwrap()
}

/// A context every mapping rule accepts, exposed as mutable parts.
fn context_parts(root: &Path) -> AdmissionContextParts {
    AdmissionContextParts {
        backend: ExecutionBackendId::new("local-direct").unwrap(),
        attempt_workspace_registry_id: AttemptWorkspaceRegistryId::new("workspace-registry-1")
            .unwrap(),
        attempt_workspace_root: root.to_path_buf(),
        working_directory: root.to_path_buf(),
        observed_provider_binary: provider_binary(),
        host_features: vec![HostFeature::new("process_boundary", implementation()).unwrap()],
        prompt: Some(
            ResolvedPrompt::new(
                PromptSource::ProtectedReference(
                    ProtectedPromptReference::new(PROMPT_SLOT).unwrap(),
                ),
                PROMPT.to_vec(),
                sha256_digest(PROMPT),
            )
            .unwrap(),
        ),
        unenforced_budgets: UnenforcedBudget::ALL.to_vec(),
        // The mappable spec denies egress on both axes, and a context that
        // resolved a destination for it would be refused as a contradiction.
        brokered_destinations: Vec::new(),
        // Off, which is the default and what production runs. Tests that prove
        // the attachment override this field.
        provider_identity: ProviderIdentityPolicy::Disabled,
        // The mappable context is one whose host can enforce the temporary
        // storage budget; tests that need the fail-closed direction override
        // this field.
        temporary_storage: TemporaryStorageEnforcement::Available,
    }
}

fn mappable_context(root: &Path) -> AdmissionContext {
    AdmissionContext::new(context_parts(root)).unwrap()
}

/// Admit a spec whose admission fields differ from the mappable ones.
fn admit_with_admission_fields(
    root: &Path,
    mutate: impl FnOnce(&mut AdmissionFieldsParts),
) -> Result<AdmittedLaunch, AdmissionRefusal> {
    let mut fields = admission_parts();
    mutate(&mut fields);
    let mut parts = spec_parts();
    parts.admission = AdmissionFields::new(fields);
    let spec = RunSpec::new(parts).unwrap();
    admit(&spec, &mappable_context(root))
}

/// Admit a spec whose sandbox spec differs from the mappable one.
fn admit_with_sandbox(
    root: &Path,
    mutate: impl FnOnce(&mut SandboxSpecParts),
) -> Result<AdmittedLaunch, AdmissionRefusal> {
    let mut sandbox = sandbox_parts();
    mutate(&mut sandbox);
    let mut parts = spec_parts();
    parts.sandbox = SandboxSpec::compile(sandbox).unwrap();
    let spec = RunSpec::new(parts).unwrap();
    admit(&spec, &mappable_context(root))
}

/// Admit the mappable spec against a context that differs from the mappable
/// one.
fn admit_with_context(
    root: &Path,
    mutate: impl FnOnce(&mut AdmissionContextParts),
) -> Result<AdmittedLaunch, AdmissionRefusal> {
    let mut parts = context_parts(root);
    mutate(&mut parts);
    let context = AdmissionContext::new(parts)?;
    admit(&mappable_spec(), &context)
}

#[test]
fn a_fully_mappable_spec_admits_the_exact_plan_limits_and_outputs() {
    let workspace = TempDir::new("mappable");
    let spec = mappable_spec();
    let admitted = admit(&spec, &mappable_context(workspace.path())).unwrap();

    // The plan, to the byte, in the exact order the bridge documents:
    // program, argv, the executable's own execute grant, the workspace at the
    // intent its filesystem access permits, the spec's path grants, the
    // environment, and the prompt.
    let expected = LaunchPlan::new(BUSYBOX, "1".repeat(64))
        .unwrap()
        .rlimit_descriptors(DESCRIPTORS)
        .unwrap()
        .argument("sh")
        .unwrap()
        .argument("-c")
        .unwrap()
        .argument("true")
        .unwrap()
        .filesystem_grant(PathIntent::ReadExecute, BUSYBOX)
        .unwrap()
        .filesystem_grant(PathIntent::ReadWrite, workspace.path())
        .unwrap()
        .environment(ENV_NAME, ENV_VALUE)
        .unwrap()
        .prompt(PROMPT)
        .unwrap();
    assert_eq!(
        admitted.plan().encode().unwrap(),
        expected.encode().unwrap(),
        "the admitted frame must equal the hand-built plan byte for byte"
    );

    // No implicit widening: exactly two grants, one variable, one prompt, no
    // ports and no socket grants.
    let frame = String::from_utf8(admitted.plan().encode().unwrap()).unwrap();
    assert_eq!(frame.matches("grant=").count(), 2, "{frame}");
    assert_eq!(frame.matches("env=").count(), 1, "{frame}");
    assert_eq!(frame.matches("prompt_hex=").count(), 1, "{frame}");
    assert_eq!(frame.matches("rlimit_nofile=").count(), 1, "{frame}");
    assert!(!frame.contains("connect_port="), "{frame}");
    assert!(!frame.contains("bind_port="), "{frame}");
    assert!(!frame.contains("socket="), "{frame}");

    // Ceilings come from the spec's budgets, not from a default.
    assert_eq!(
        admitted.limits(),
        ContainmentLimits::none()
            .with_memory_max_bytes(MEMORY_BYTES)
            .with_pids_max(PROCESSES)
            .with_cpu_max_millicores(CPU_MILLICORES)
    );
    assert_eq!(
        admitted.limits().required_controllers(),
        vec![Controller::Pids, Controller::Memory, Controller::Cpu]
    );

    // The document the launch was derived from is named by its own digest.
    assert_eq!(
        admitted.spec_digest().as_str(),
        spec.canonical_digest().unwrap().as_str()
    );
    assert!(admitted.spec_digest().as_str().starts_with("sha256:"));

    // The remaining supervised-attempt inputs.
    assert_eq!(admitted.run_id(), "run-1");
    assert_eq!(admitted.timeout(), Duration::from_millis(TIMEOUT_MILLIS));
    assert_eq!(admitted.spool_budget_bytes(), SPOOL_BYTES);
    assert_eq!(admitted.working_directory(), workspace.path());
    assert_eq!(
        admitted.unenforced_budgets(),
        UnenforcedBudget::ALL.as_slice()
    );
}

#[test]
fn admitting_the_same_spec_and_context_twice_is_byte_identical() {
    let workspace = TempDir::new("deterministic");
    // Two independently built specs and contexts, not one value admitted
    // twice, so a plan that depended on construction order would differ here.
    let first = admit(&mappable_spec(), &mappable_context(workspace.path())).unwrap();
    let second = admit(&mappable_spec(), &mappable_context(workspace.path())).unwrap();
    assert_eq!(
        first.plan().encode().unwrap(),
        second.plan().encode().unwrap()
    );
    assert_eq!(first.limits(), second.limits());
    assert_eq!(first.spec_digest().as_str(), second.spec_digest().as_str());
    assert_eq!(first.unenforced_budgets(), second.unenforced_budgets());
}

#[test]
fn declared_path_grants_map_by_access_in_declared_order() {
    let workspace = TempDir::new("grants");
    let mut sandbox = sandbox_parts();
    // Five grants, declared in an order no sort and no hash reproduces, so a
    // mapping that collected them through an unordered container or tidied
    // them into sorted order cannot match the frame below.
    sandbox.path_grants = PathGrants::declare(&[
        PathGrant::new("/outputs", PathAccess::ReadWrite).unwrap(),
        PathGrant::new("/inputs", PathAccess::ReadOnly).unwrap(),
        PathGrant::new("/tools", PathAccess::ReadExecute).unwrap(),
        PathGrant::new("/scratch", PathAccess::ReadWrite).unwrap(),
        PathGrant::new("/cache", PathAccess::ReadOnly).unwrap(),
    ])
    .unwrap();
    let mut parts = spec_parts();
    parts.sandbox = SandboxSpec::compile(sandbox).unwrap();
    let spec = RunSpec::new(parts).unwrap();
    let admitted = admit(&spec, &mappable_context(workspace.path())).unwrap();

    let expected = LaunchPlan::new(BUSYBOX, "1".repeat(64))
        .unwrap()
        .rlimit_descriptors(DESCRIPTORS)
        .unwrap()
        .argument("sh")
        .unwrap()
        .argument("-c")
        .unwrap()
        .argument("true")
        .unwrap()
        .filesystem_grant(PathIntent::ReadExecute, BUSYBOX)
        .unwrap()
        .filesystem_grant(PathIntent::ReadWrite, workspace.path())
        .unwrap()
        .filesystem_grant(PathIntent::ReadWrite, "/outputs")
        .unwrap()
        .filesystem_grant(PathIntent::Read, "/inputs")
        .unwrap()
        .filesystem_grant(PathIntent::ReadExecute, "/tools")
        .unwrap()
        .filesystem_grant(PathIntent::ReadWrite, "/scratch")
        .unwrap()
        .filesystem_grant(PathIntent::Read, "/cache")
        .unwrap()
        .environment(ENV_NAME, ENV_VALUE)
        .unwrap()
        .prompt(PROMPT)
        .unwrap();
    assert_eq!(
        admitted.plan().encode().unwrap(),
        expected.encode().unwrap(),
        "read, read-execute, and read-write grants must map in the spec's own order"
    );
}

#[test]
fn a_read_only_snapshot_workspace_is_granted_read_only() {
    let workspace = TempDir::new("readonly");
    let mut sandbox = sandbox_parts();
    sandbox.profile = SandboxProfile::new(
        "admission-profile",
        1,
        FilesystemAccess::ReadOnlySnapshot,
        ToolWorkloadEgress::denied(),
    )
    .unwrap();
    let mut parts = spec_parts();
    parts.attempt_workspace = AttemptWorkspaceRegistration::new(
        "acme",
        "source-1",
        Revision::new(7).unwrap(),
        "snapshot-1",
        IsolationKind::ReadOnlySnapshot,
        AttemptWorkspaceToken::new("workspace-token-1").unwrap(),
    )
    .unwrap();
    parts.sandbox = SandboxSpec::compile(sandbox).unwrap();
    let spec = RunSpec::new(parts).unwrap();
    let admitted = admit(&spec, &mappable_context(workspace.path())).unwrap();

    let frame = String::from_utf8(admitted.plan().encode().unwrap()).unwrap();
    let workspace_hex = hex(workspace.path().as_os_str().as_encoded_bytes());
    assert!(
        frame.contains(&format!("grant=read:{workspace_hex}")),
        "a read-only snapshot must not be granted write; frame={frame}"
    );
    assert!(
        !frame.contains(&format!("grant=read-write:{workspace_hex}")),
        "frame={frame}"
    );
}

#[test]
fn the_informational_field_list_is_closed_and_names_nothing_consulted() {
    assert_eq!(
        AdmittedLaunch::informational_fields(),
        INFORMATIONAL_FIELDS.as_slice()
    );
    for (index, field) in INFORMATIONAL_FIELDS.iter().enumerate() {
        assert!(
            !INFORMATIONAL_FIELDS[..index].contains(field),
            "{field} is listed twice"
        );
    }
    // Every field the bridge actually reads must be absent from the list; a
    // field cannot be both consulted and informational.
    for consulted in [
        "run_id",
        "backend_id",
        "executable",
        "argv",
        "cwd_token",
        "environment",
        "prompt_delivery",
        "workspace_registry_id",
        "workspace.isolation",
        "provider_binary",
        "admission.executor_class",
        "admission.session_binding",
        "admission.fallback_eligibility",
        "admission.required_capabilities",
        "admission.portability_policy",
        "admission.remote_attestation_policy",
        "admission.artifact_grants",
        "admission.credential_bindings",
        "sandbox.allowlists",
        "sandbox.credentials",
        "sandbox.path_grants",
        "sandbox.prohibited_capabilities",
        "sandbox.provider_control_egress",
        "sandbox.tool_workload_egress",
        "sandbox.required_features",
        "sandbox.profile.filesystem",
        "sandbox.nested_isolation.nested_tools",
        "sandbox.nested_isolation.extensions",
        "sandbox.budgets.cgroup_memory",
        "sandbox.budgets.rlimit_processes",
        "sandbox.budgets.timeout",
        "sandbox.budgets.spool",
        "sandbox.budgets.cgroup_cpu",
        "sandbox.budgets.rlimit_descriptors",
        "sandbox.budgets.temporary_storage",
        "sandbox.budgets.artifact",
    ] {
        assert!(
            !INFORMATIONAL_FIELDS.contains(&consulted),
            "{consulted} is consulted, so it must not be published as informational"
        );
    }
}

#[test]
fn unmappable_admission_fields_are_refused_by_name() {
    let workspace = TempDir::new("admissionfields");
    let root = workspace.path();

    let error = admit_with_admission_fields(root, |fields| {
        fields.session_binding = Some(
            SessionBinding::new(
                "acme",
                "local-direct",
                "provider-account-1",
                "namespace-1",
                ProviderSessionId::new("session-1").unwrap(),
            )
            .unwrap(),
        );
    })
    .unwrap_err();
    assert_unmappable(&error, "admission.session_binding");

    let error = admit_with_admission_fields(root, |fields| {
        let mode = IntegrationMode::new("native").unwrap();
        fields.fallback_eligibility =
            FallbackEligibility::declare(&mode, vec![IntegrationMode::new("alternate").unwrap()])
                .unwrap();
    })
    .unwrap_err();
    assert_unmappable(&error, "admission.fallback_eligibility");

    let error = admit_with_admission_fields(root, |fields| {
        fields.required_capabilities = RequiredCapabilities::declare(vec![
            Capability::new(CapabilityGroup::Tools, "structured_output").unwrap(),
        ])
        .unwrap();
    })
    .unwrap_err();
    assert_unmappable(&error, "admission.required_capabilities");

    let error = admit_with_admission_fields(root, |fields| {
        fields.portability_policy = PortabilityPolicy::Portable {
            workspace_transfer: WorkspaceTransfer::ContentAddressedBundle,
            artifact_transfer: ArtifactTransfer::DigestVerifiedPush,
        };
    })
    .unwrap_err();
    assert_unmappable(&error, "admission.portability_policy");

    let error = admit_with_admission_fields(root, |fields| {
        fields.remote_attestation_policy = RemoteAttestationPolicy::Signed;
    })
    .unwrap_err();
    assert_unmappable(&error, "admission.remote_attestation_policy");

    let error = admit_with_admission_fields(root, |fields| {
        fields.artifact_grants = ArtifactGrantBindings::declare(vec![ArtifactGrantBinding::new(
            ArtifactGrantId::new("grant-1").unwrap(),
            Revision::FIRST,
            ArtifactGrantDigest::parse(&digest_text('e')).unwrap(),
        )])
        .unwrap();
    })
    .unwrap_err();
    assert_unmappable(&error, "admission.artifact_grants");
}

#[test]
fn a_credential_binding_is_refused_rather_than_delivered() {
    let workspace = TempDir::new("credential");
    // A binding exists only alongside its descriptor: the spec's own
    // validation requires the two sets to agree, so this exercises both.
    let mut sandbox = sandbox_parts();
    sandbox.credentials = CredentialDescriptors::declare(&[CredentialDescriptor::new(
        "fixture_credential",
        ProcessClass::ProviderAdapter,
    )
    .unwrap()])
    .unwrap();
    let mut fields = admission_parts();
    fields.credential_bindings = vec![
        CredentialBinding::new(
            "fixture_credential",
            NonZeroU64::new(4).unwrap(),
            CredentialAudiences::exactly(&["audience-a"]).unwrap(),
        )
        .unwrap(),
    ];
    let mut parts = spec_parts();
    parts.sandbox = SandboxSpec::compile(sandbox).unwrap();
    parts.admission = AdmissionFields::new(fields);
    let spec = RunSpec::new(parts).unwrap();

    let error = admit(&spec, &mappable_context(workspace.path())).unwrap_err();
    assert_unmappable(&error, "admission.credential_bindings");
}

#[test]
fn unmappable_sandbox_fields_are_refused_by_name() {
    let workspace = TempDir::new("sandboxfields");
    let root = workspace.path();

    let error = admit_with_sandbox(root, |sandbox| {
        sandbox.allowlists = ExecutionAllowlists::declare(&[AllowlistEntry::new(
            AllowlistClass::Interpreter,
            "python3",
        )
        .unwrap()])
        .unwrap();
    })
    .unwrap_err();
    assert_unmappable(&error, "sandbox.allowlists");

    let error = admit_with_sandbox(root, |sandbox| {
        sandbox.prohibited_capabilities = ProhibitedCapabilities::declare(&["ptrace"]).unwrap();
    })
    .unwrap_err();
    assert_unmappable(&error, "sandbox.prohibited_capabilities");

    let error = admit_with_sandbox(root, |sandbox| {
        sandbox.provider_control_egress =
            ProviderControlEgress::brokered(NetworkAccess::BrokeredNamed);
    })
    .unwrap_err();
    assert_unmappable(&error, "sandbox.provider_control_egress");

    let error = admit_with_sandbox(root, |sandbox| {
        // The profile must permit what the spec grants, so both move together.
        sandbox.profile = SandboxProfile::new(
            "admission-profile",
            1,
            FilesystemAccess::IsolatedWritable,
            ToolWorkloadEgress::brokered(NetworkAccess::BrokeredAny),
        )
        .unwrap();
        sandbox.tool_workload_egress = ToolWorkloadEgress::brokered(NetworkAccess::BrokeredAny);
    })
    .unwrap_err();
    assert_unmappable(&error, "sandbox.tool_workload_egress");

    let error = admit_with_sandbox(root, |sandbox| {
        sandbox.nested_isolation = NestedIsolation::new(
            IsolationRequirement::SeparateChildBoundary,
            IsolationRequirement::HostBoundary,
        );
    })
    .unwrap_err();
    assert_unmappable(&error, "sandbox.nested_isolation.nested_tools");

    let error = admit_with_sandbox(root, |sandbox| {
        sandbox.nested_isolation = NestedIsolation::new(
            IsolationRequirement::HostBoundary,
            IsolationRequirement::StrongerIsolation,
        );
    })
    .unwrap_err();
    assert_unmappable(&error, "sandbox.nested_isolation.extensions");
}

#[test]
fn a_non_local_executor_class_is_refused() {
    let workspace = TempDir::new("executor");
    // A remote executor also demands attestation, so both fields move; the
    // executor class is checked first and is the refusal that must appear.
    let error = admit_with_admission_fields(workspace.path(), |fields| {
        fields.executor_class =
            ExecutorClass::Remote(RemoteCoordinate::new("vendor-1", "resource-1").unwrap());
        fields.remote_attestation_policy = RemoteAttestationPolicy::MutuallyAuthenticated;
    })
    .unwrap_err();
    assert_unmappable(&error, "admission.executor_class");

    let error = admit_with_admission_fields(workspace.path(), |fields| {
        fields.executor_class = ExecutorClass::Container;
    })
    .unwrap_err();
    assert_unmappable(&error, "admission.executor_class");
}

#[test]
fn the_context_must_bind_to_the_spec_it_resolves() {
    let workspace = TempDir::new("bindings");
    let root = workspace.path();

    let error = admit_with_context(root, |context| {
        context.backend = ExecutionBackendId::new("other-backend").unwrap();
    })
    .unwrap_err();
    assert!(
        matches!(error, AdmissionRefusal::ContextMismatch("backend_id")),
        "got {error:?}"
    );

    let error = admit_with_context(root, |context| {
        context.attempt_workspace_registry_id =
            AttemptWorkspaceRegistryId::new("workspace-registry-2").unwrap();
    })
    .unwrap_err();
    assert!(
        matches!(
            error,
            AdmissionRefusal::ContextMismatch("workspace_registry_id")
        ),
        "got {error:?}"
    );

    // A different binary digest under the same version: the pin is the digest.
    let error = admit_with_context(root, |context| {
        context.observed_provider_binary =
            BinaryProvenance::new("1.2.3", &digest_text('f'), Some(&digest_text('2'))).unwrap();
    })
    .unwrap_err();
    assert!(
        matches!(error, AdmissionRefusal::ContextMismatch("provider_binary")),
        "got {error:?}"
    );

    // A different schema digest is equally a different binary.
    let error = admit_with_context(root, |context| {
        context.observed_provider_binary =
            BinaryProvenance::new("1.2.3", &digest_text('1'), None).unwrap();
    })
    .unwrap_err();
    assert!(
        matches!(error, AdmissionRefusal::ContextMismatch("provider_binary")),
        "got {error:?}"
    );

    // The version alone is informational: the same digests admit.
    admit_with_context(root, |context| {
        context.observed_provider_binary =
            BinaryProvenance::new("9.9.9", &digest_text('1'), Some(&digest_text('2'))).unwrap();
    })
    .expect("provenance identity is the digest pair, not the version string");
}

#[test]
fn a_host_that_does_not_offer_a_required_feature_is_refused() {
    let workspace = TempDir::new("features");
    let root = workspace.path();

    let error = admit_with_context(root, |context| {
        context.host_features = Vec::new();
    })
    .unwrap_err();
    match error {
        AdmissionRefusal::HostFeatureRejected(SandboxError::RequiredEnforcementMissing {
            feature,
        }) => assert_eq!(feature, "process_boundary"),
        other => panic!("got {other:?}"),
    }

    // Offered, but through an implementation the spec does not accept.
    let error = admit_with_context(root, |context| {
        context.host_features = vec![
            HostFeature::new(
                "process_boundary",
                ImplementationDigest::parse(&digest_text('0')).unwrap(),
            )
            .unwrap(),
        ];
    })
    .unwrap_err();
    assert!(
        matches!(
            error,
            AdmissionRefusal::HostFeatureRejected(
                SandboxError::EnforcementImplementationRejected { .. }
            )
        ),
        "got {error:?}"
    );
}

#[test]
fn a_backend_session_prompt_is_refused() {
    let workspace = TempDir::new("backendprompt");
    // A backend-session delivery needs the matching session binding, so the
    // spec is only constructible with both; the prompt refusal is the one that
    // must be reported... after the session binding, which is checked first.
    let mut fields = admission_parts();
    fields.session_binding = Some(
        SessionBinding::new(
            "acme",
            "local-direct",
            "provider-account-1",
            "namespace-1",
            ProviderSessionId::new("session-1").unwrap(),
        )
        .unwrap(),
    );
    let mut parts = spec_parts();
    parts.prompt =
        PromptDeliveryPlan::BackendSession(BackendPromptSession::new("session-1").unwrap());
    parts.admission = AdmissionFields::new(fields);
    let spec = RunSpec::new(parts).unwrap();
    let error = admit(&spec, &mappable_context(workspace.path())).unwrap_err();
    // Both are unmappable; the session binding is the earlier refusal and the
    // one a caller must fix first.
    assert_unmappable(&error, "admission.session_binding");
}

#[test]
fn a_prompt_resolved_for_another_coordinate_is_refused() {
    let workspace = TempDir::new("promptbinding");
    let root = workspace.path();

    // Right bytes, right digest, wrong slot.
    let error = admit_with_context(root, |context| {
        context.prompt = Some(
            ResolvedPrompt::new(
                PromptSource::ProtectedReference(
                    ProtectedPromptReference::new("prompt-slot-2").unwrap(),
                ),
                PROMPT.to_vec(),
                sha256_digest(PROMPT),
            )
            .unwrap(),
        );
    })
    .unwrap_err();
    assert!(
        matches!(error, AdmissionRefusal::ContextMismatch("prompt_delivery")),
        "got {error:?}"
    );

    // Resolved as a stdin prompt while the spec names a protected slot.
    let error = admit_with_context(root, |context| {
        context.prompt = Some(
            ResolvedPrompt::new(PromptSource::Stdin, PROMPT.to_vec(), sha256_digest(PROMPT))
                .unwrap(),
        );
    })
    .unwrap_err();
    assert!(
        matches!(error, AdmissionRefusal::ContextMismatch("prompt_delivery")),
        "got {error:?}"
    );

    // No resolution at all.
    let error = admit_with_context(root, |context| {
        context.prompt = None;
    })
    .unwrap_err();
    assert!(
        matches!(error, AdmissionRefusal::ContextMissing("prompt_delivery")),
        "got {error:?}"
    );
}

#[test]
fn prompt_bytes_that_do_not_match_their_declared_digest_are_refused() {
    let workspace = TempDir::new("promptdigest");
    let root = workspace.path();

    // The store declared the digest of the prompt the spec expects, but handed
    // back different bytes. Admission recomputes and refuses.
    let error = admit_with_context(root, |context| {
        context.prompt = Some(
            ResolvedPrompt::new(
                PromptSource::ProtectedReference(
                    ProtectedPromptReference::new(PROMPT_SLOT).unwrap(),
                ),
                b"substituted prompt\n".to_vec(),
                sha256_digest(PROMPT),
            )
            .unwrap(),
        );
    })
    .unwrap_err();
    assert!(
        matches!(error, AdmissionRefusal::PromptDigestMismatch),
        "got {error:?}"
    );

    // A single flipped byte is enough.
    let mut altered = PROMPT.to_vec();
    altered[0] ^= 0x01;
    let error = admit_with_context(root, |context| {
        context.prompt = Some(
            ResolvedPrompt::new(
                PromptSource::ProtectedReference(
                    ProtectedPromptReference::new(PROMPT_SLOT).unwrap(),
                ),
                altered,
                sha256_digest(PROMPT),
            )
            .unwrap(),
        );
    })
    .unwrap_err();
    assert!(
        matches!(error, AdmissionRefusal::PromptDigestMismatch),
        "got {error:?}"
    );

    // A digest in an algorithm this bridge does not compute is refused at the
    // resolution itself, so an unverifiable prompt cannot reach admission.
    let error = ResolvedPrompt::new(
        PromptSource::Stdin,
        PROMPT.to_vec(),
        Digest::parse(&format!("sha512:{}", "4".repeat(128))).unwrap(),
    )
    .unwrap_err();
    assert!(
        matches!(error, AdmissionRefusal::UnsupportedPromptDigest),
        "got {error:?}"
    );
}

#[test]
fn a_stdin_delivery_carries_the_resolved_bytes() {
    let workspace = TempDir::new("stdinprompt");
    let mut parts = spec_parts();
    parts.prompt = PromptDeliveryPlan::Stdin;
    let spec = RunSpec::new(parts).unwrap();
    let mut context = context_parts(workspace.path());
    context.prompt = Some(
        ResolvedPrompt::new(PromptSource::Stdin, PROMPT.to_vec(), sha256_digest(PROMPT)).unwrap(),
    );
    let admitted = admit(&spec, &AdmissionContext::new(context).unwrap()).unwrap();
    assert_eq!(admitted.plan().prompt_len(), Some(PROMPT.len()));
}

#[test]
fn quotas_map_exactly_and_a_zero_ceiling_is_refused() {
    let workspace = TempDir::new("quotas");
    let root = workspace.path();

    // Exact, not rounded, not defaulted.
    let admitted = admit_with_sandbox(root, |sandbox| {
        sandbox.budgets = Budgets::declare(BudgetQuantities {
            cgroup_memory_bytes: 7 * 1024 * 1024 + 1,
            cgroup_cpu_millicores: 1_500,
            rlimit_processes: 13,
            rlimit_descriptors: 256,
            timeout_millis: TIMEOUT_MILLIS,
            temporary_storage_bytes: 1024 * 1024,
            spool_bytes: SPOOL_BYTES,
            artifact_bytes: 1024 * 1024,
        })
        .unwrap();
    })
    .unwrap();
    assert_eq!(
        admitted.limits(),
        ContainmentLimits::none()
            .with_memory_max_bytes(7 * 1024 * 1024 + 1)
            .with_pids_max(13)
            .with_cpu_max_millicores(1_500)
    );
    assert_eq!(admitted.plan().descriptor_limit(), Some(256));

    let error = admit_with_sandbox(root, |sandbox| {
        sandbox.budgets = Budgets::declare(BudgetQuantities {
            cgroup_memory_bytes: 0,
            cgroup_cpu_millicores: 1_000,
            rlimit_processes: PROCESSES,
            rlimit_descriptors: 256,
            timeout_millis: TIMEOUT_MILLIS,
            temporary_storage_bytes: 1024 * 1024,
            spool_bytes: SPOOL_BYTES,
            artifact_bytes: 1024 * 1024,
        })
        .unwrap();
    })
    .unwrap_err();
    assert!(
        matches!(
            error,
            AdmissionRefusal::QuotaRejected("sandbox.budgets.cgroup_memory")
        ),
        "got {error:?}"
    );

    let error = admit_with_sandbox(root, |sandbox| {
        sandbox.budgets = Budgets::declare(BudgetQuantities {
            cgroup_memory_bytes: MEMORY_BYTES,
            cgroup_cpu_millicores: 0,
            rlimit_processes: PROCESSES,
            rlimit_descriptors: DESCRIPTORS,
            timeout_millis: TIMEOUT_MILLIS,
            temporary_storage_bytes: 1024 * 1024,
            spool_bytes: SPOOL_BYTES,
            artifact_bytes: 1024 * 1024,
        })
        .unwrap();
    })
    .unwrap_err();
    assert!(
        matches!(
            error,
            AdmissionRefusal::QuotaRejected("sandbox.budgets.cgroup_cpu")
        ),
        "got {error:?}"
    );

    let error = admit_with_sandbox(root, |sandbox| {
        sandbox.budgets = Budgets::declare(BudgetQuantities {
            cgroup_memory_bytes: MEMORY_BYTES,
            cgroup_cpu_millicores: CPU_MILLICORES,
            rlimit_processes: PROCESSES,
            rlimit_descriptors: 2,
            timeout_millis: TIMEOUT_MILLIS,
            temporary_storage_bytes: 1024 * 1024,
            spool_bytes: SPOOL_BYTES,
            artifact_bytes: 1024 * 1024,
        })
        .unwrap();
    })
    .unwrap_err();
    assert!(
        matches!(
            error,
            AdmissionRefusal::QuotaRejected("sandbox.budgets.rlimit_descriptors")
        ),
        "got {error:?}"
    );

    let error = admit_with_sandbox(root, |sandbox| {
        sandbox.budgets = Budgets::declare(BudgetQuantities {
            cgroup_memory_bytes: MEMORY_BYTES,
            cgroup_cpu_millicores: 1_000,
            rlimit_processes: 0,
            rlimit_descriptors: 256,
            timeout_millis: TIMEOUT_MILLIS,
            temporary_storage_bytes: 1024 * 1024,
            spool_bytes: SPOOL_BYTES,
            artifact_bytes: 1024 * 1024,
        })
        .unwrap();
    })
    .unwrap_err();
    assert!(
        matches!(
            error,
            AdmissionRefusal::QuotaRejected("sandbox.budgets.rlimit_processes")
        ),
        "got {error:?}"
    );
}

#[test]
fn every_budget_without_an_enforcement_surface_must_be_acknowledged() {
    let workspace = TempDir::new("unenforced");
    let root = workspace.path();

    // Only artifact accounting has no enforcement surface now: temporary
    // storage is enforced through a per-run FUSE mount, and CPU and descriptor
    // limits were enforced before that.
    for missing in UnenforcedBudget::ALL {
        let error = admit_with_context(root, |context| {
            context.unenforced_budgets = UnenforcedBudget::ALL
                .into_iter()
                .filter(|budget| *budget != missing)
                .collect();
        })
        .unwrap_err();
        match error {
            AdmissionRefusal::UnenforcedBudgetUnacknowledged(budget) => {
                assert_eq!(budget, missing, "the refusal must name the missing budget");
            }
            other => panic!("got {other:?}"),
        }
    }

    // The acknowledgement is republished, so a supervisor can record exactly
    // which declarations this launch does not apply.
    let admitted = admit(&mappable_spec(), &mappable_context(root)).unwrap();
    assert_eq!(
        admitted.unenforced_budgets(),
        UnenforcedBudget::ALL.as_slice()
    );
    assert_eq!(UnenforcedBudget::ALL.len(), 1);
}

#[test]
fn the_temporary_storage_budget_maps_to_a_derived_object_ceiling() {
    let workspace = TempDir::new("tempfs-budget");
    let admitted = admit_with_sandbox(workspace.path(), |sandbox| {
        sandbox.budgets = Budgets::declare(BudgetQuantities {
            cgroup_memory_bytes: MEMORY_BYTES,
            cgroup_cpu_millicores: CPU_MILLICORES,
            rlimit_processes: PROCESSES,
            rlimit_descriptors: DESCRIPTORS,
            timeout_millis: TIMEOUT_MILLIS,
            // Exactly 256 blocks of 4096 bytes: one object per block.
            temporary_storage_bytes: 1024 * 1024,
            spool_bytes: SPOOL_BYTES,
            artifact_bytes: 1024 * 1024,
        })
        .unwrap();
    })
    .unwrap();
    let budget = admitted.temporary_storage_budget();
    assert_eq!(budget.bytes(), 1024 * 1024);
    assert_eq!(budget.objects(), 256);
    // The plan carries no scratch grant and no TMPDIR until a mount is attached.
    assert!(!admitted.has_temporary_storage());
    assert!(
        admitted
            .plan()
            .environment_names()
            .all(|name| name != "TMPDIR"),
        "TMPDIR must not be in the plan before a mount is attached"
    );
}

#[test]
fn a_host_that_cannot_mount_refuses_the_temporary_storage_budget() {
    let workspace = TempDir::new("tempfs-unenforceable");
    let error = admit_with_context(workspace.path(), |context| {
        context.temporary_storage =
            TemporaryStorageEnforcement::Unavailable("/dev/fuse is missing".to_owned());
    })
    .unwrap_err();
    match error {
        AdmissionRefusal::TemporaryStorageUnenforceable(reason) => {
            assert!(reason.contains("/dev/fuse"), "the refusal must carry why");
        }
        other => panic!("got {other:?}"),
    }
}

#[test]
fn identity_separation_and_the_temporary_storage_mount_cannot_combine() {
    // The rule is a pure function of the plan, pinned here exactly as
    // `AdmittedLaunch::with_temporary_storage` consults it: no document field
    // can request identity separation yet, so this seam is where the
    // combination is kept apart.
    let digest = "a".repeat(64);
    let plain = automonique_runner::LaunchPlan::new("/usr/bin/true", &digest).unwrap();
    assert!(refuse_identity_temporary_storage_conflict(&plain).is_ok());

    let separated = plain.separate_workload_identity().unwrap();
    let error = refuse_identity_temporary_storage_conflict(&separated).unwrap_err();
    assert!(matches!(
        error,
        AdmissionRefusal::WorkloadIdentityTemporaryStorageConflict
    ));
    let rendered = error.to_string();
    assert!(
        rendered.contains("child user namespace") && rendered.contains("FUSE"),
        "the refusal must name the kernel limitation: {rendered}"
    );
}

#[test]
fn required_uid_separation_attaches_only_the_private_namespaced_tempfs_path() {
    let workspace = TempDir::new("namespaced-attachment");
    let mountpoint = workspace.path().join("tmp");
    fs::create_dir(&mountpoint).unwrap();
    let uid_implementation = ImplementationDigest::parse(&digest_text('e')).unwrap();
    let mut sandbox = sandbox_parts();
    sandbox.required_features = RequiredFeatures::declare(&[RequiredFeature::new(
        "uid_separation",
        std::slice::from_ref(&uid_implementation),
    )
    .unwrap()])
    .unwrap();
    let mut parts = spec_parts();
    parts.sandbox = SandboxSpec::compile(sandbox).unwrap();
    let spec = RunSpec::new(parts).unwrap();
    let mut context = context_parts(workspace.path());
    context.host_features = vec![HostFeature::new("uid_separation", uid_implementation).unwrap()];
    let admitted = admit(&spec, &AdmissionContext::new(context).unwrap()).unwrap();
    assert!(admitted.plan().separates_workload_identity());
    let attached = admitted
        .with_namespaced_temporary_storage(&mountpoint)
        .unwrap();
    let frame = String::from_utf8(attached.plan().encode().unwrap()).unwrap();
    assert!(frame.contains("\nidentity=subordinate\n"), "{frame}");
    assert!(frame.contains("\ntempfs="), "{frame}");
    assert!(frame.contains("\nenv=544d50444952:"), "{frame}");

    // The legacy supervisor-visible mount seam remains fail-closed for this
    // same plan; only the explicit private-mount attachment may compose it.
    assert!(matches!(
        refuse_identity_temporary_storage_conflict(attached.plan()),
        Err(AdmissionRefusal::WorkloadIdentityTemporaryStorageConflict)
    ));
}

#[test]
fn a_byte_ceiling_that_statfs_cannot_report_exactly_is_refused() {
    let workspace = TempDir::new("tempfs-misaligned");
    // Not a multiple of the 4096-byte readback block.
    let error = admit_with_sandbox(workspace.path(), |sandbox| {
        sandbox.budgets = Budgets::declare(BudgetQuantities {
            cgroup_memory_bytes: MEMORY_BYTES,
            cgroup_cpu_millicores: CPU_MILLICORES,
            rlimit_processes: PROCESSES,
            rlimit_descriptors: DESCRIPTORS,
            timeout_millis: TIMEOUT_MILLIS,
            temporary_storage_bytes: 4097,
            spool_bytes: SPOOL_BYTES,
            artifact_bytes: 1024 * 1024,
        })
        .unwrap();
    })
    .unwrap_err();
    assert!(
        matches!(
            error,
            AdmissionRefusal::QuotaRejected("sandbox.budgets.temporary_storage")
        ),
        "got {error:?}"
    );

    // A ceiling above the charging cap is refused the same way.
    let error = admit_with_sandbox(workspace.path(), |sandbox| {
        sandbox.budgets = Budgets::declare(BudgetQuantities {
            cgroup_memory_bytes: MEMORY_BYTES,
            cgroup_cpu_millicores: CPU_MILLICORES,
            rlimit_processes: PROCESSES,
            rlimit_descriptors: DESCRIPTORS,
            timeout_millis: TIMEOUT_MILLIS,
            temporary_storage_bytes: 256 * 1024 * 1024,
            spool_bytes: SPOOL_BYTES,
            artifact_bytes: 1024 * 1024,
        })
        .unwrap();
    })
    .unwrap_err();
    assert!(
        matches!(
            error,
            AdmissionRefusal::QuotaRejected("sandbox.budgets.temporary_storage")
        ),
        "got {error:?}"
    );
}

#[test]
fn a_document_that_binds_tmpdir_is_refused_because_the_budget_owns_it() {
    let workspace = TempDir::new("tempfs-tmpdir");
    let mut parts = spec_parts();
    parts.environment = vec![(OsString::from("TMPDIR"), OsString::from("/somewhere"))];
    let spec = RunSpec::new(parts).unwrap();
    let error = admit(&spec, &mappable_context(workspace.path())).unwrap_err();
    assert!(
        matches!(error, AdmissionRefusal::TemporaryStorageTmpdirConflict),
        "got {error:?}"
    );
}

#[test]
fn a_run_identifier_that_cannot_name_a_cgroup_is_refused() {
    let workspace = TempDir::new("runid");
    // A valid protocol run identifier that a cgroup directory entry cannot be.
    let mut parts = spec_parts();
    parts.coordinates = RunCoordinates::new(
        WorkId::new("work-1").unwrap(),
        RunId::new("run.1").unwrap(),
        AttemptId::new("attempt-1").unwrap(),
        HostId::new("host-1").unwrap(),
        HostLifetime::Attempt,
        ExecutionBackendId::new("local-direct").unwrap(),
    );
    let spec = RunSpec::new(parts).unwrap();
    let error = admit(&spec, &mappable_context(workspace.path())).unwrap_err();
    assert!(
        matches!(error, AdmissionRefusal::RunIdUnusable),
        "got {error:?}"
    );
}

#[test]
fn two_grants_for_one_path_are_refused_rather_than_merged() {
    let workspace = TempDir::new("collision");
    let root = workspace.path();

    // The spec grants the very path the workspace resolution grants.
    let mut sandbox = sandbox_parts();
    sandbox.path_grants =
        PathGrants::declare(&[
            PathGrant::new(root.to_str().unwrap(), PathAccess::ReadOnly).unwrap()
        ])
        .unwrap();
    let mut parts = spec_parts();
    parts.sandbox = SandboxSpec::compile(sandbox).unwrap();
    let spec = RunSpec::new(parts).unwrap();
    let error = admit(&spec, &mappable_context(root)).unwrap_err();
    match error {
        AdmissionRefusal::Plan {
            field: "sandbox.path_grants",
            error: LaunchPlanError::PolicyRejected(reason),
        } => assert!(
            reason.contains("same path") && reason.contains(root.to_str().unwrap()),
            "the refusal must name the colliding path, got {reason}"
        ),
        other => panic!("got {other:?}"),
    }

    // The same collision against the program's own execute grant.
    let mut sandbox = sandbox_parts();
    sandbox.path_grants =
        PathGrants::declare(&[PathGrant::new(BUSYBOX, PathAccess::ReadOnly).unwrap()]).unwrap();
    let mut parts = spec_parts();
    parts.sandbox = SandboxSpec::compile(sandbox).unwrap();
    let spec = RunSpec::new(parts).unwrap();
    let error = admit(&spec, &mappable_context(root)).unwrap_err();
    assert!(
        matches!(
            error,
            AdmissionRefusal::Plan {
                field: "sandbox.path_grants",
                ..
            }
        ),
        "got {error:?}"
    );
}

#[test]
fn environment_entries_the_launch_frame_cannot_carry_are_refused() {
    let workspace = TempDir::new("environment");
    let root = workspace.path();

    // The spec's environment grammar admits lowercase; the launch frame's does
    // not. Uppercasing it here would be inventing a variable the spec never
    // wrote, so the mapping refuses.
    let mut parts = spec_parts();
    parts.environment = vec![(OsString::from("lower_case"), OsString::from("value"))];
    let spec = RunSpec::new(parts).unwrap();
    let error = admit(&spec, &mappable_context(root)).unwrap_err();
    assert!(
        matches!(
            error,
            AdmissionRefusal::Plan {
                field: "environment",
                error: LaunchPlanError::EnvironmentRejected(_)
            }
        ),
        "got {error:?}"
    );

    // The spec permits 64 variables; one frame carries at most 32.
    let mut parts = spec_parts();
    parts.environment = (0..40)
        .map(|index| {
            (
                OsString::from(format!("VAR_{index}")),
                OsString::from("value"),
            )
        })
        .collect();
    let spec = RunSpec::new(parts).unwrap();
    let error = admit(&spec, &mappable_context(root)).unwrap_err();
    assert!(
        matches!(
            error,
            AdmissionRefusal::Plan {
                field: "environment",
                error: LaunchPlanError::EnvironmentRejected(_)
            }
        ),
        "got {error:?}"
    );
}

#[test]
fn a_context_resolution_must_be_absolute_canonical_and_inside_the_workspace() {
    let workspace = TempDir::new("contextpaths");
    let root = workspace.path();

    // A relative workspace root is not a resolution.
    let mut parts = context_parts(root);
    parts.attempt_workspace_root = PathBuf::from("relative/workspace");
    parts.working_directory = PathBuf::from("relative/workspace");
    let error = AdmissionContext::new(parts).unwrap_err();
    assert!(
        matches!(error, AdmissionRefusal::ContextRejected("workspace_root")),
        "got {error:?}"
    );

    // A traversal component is refused rather than normalized away.
    let mut parts = context_parts(root);
    parts.working_directory = root.join("..").join("elsewhere");
    let error = AdmissionContext::new(parts).unwrap_err();
    assert!(
        matches!(
            error,
            AdmissionRefusal::ContextRejected("working_directory")
        ),
        "got {error:?}"
    );

    // Absolute and canonical, but not inside the workspace.
    let mut parts = context_parts(root);
    parts.working_directory = PathBuf::from("/elsewhere");
    let error = AdmissionContext::new(parts).unwrap_err();
    assert!(
        matches!(error, AdmissionRefusal::WorkingDirectoryOutsideWorkspace),
        "got {error:?}"
    );

    // A subdirectory of the workspace is a resolution, not an escape.
    let mut parts = context_parts(root);
    parts.working_directory = root.join("nested");
    let context = AdmissionContext::new(parts).unwrap();
    let admitted = admit(&mappable_spec(), &context).unwrap();
    assert_eq!(admitted.working_directory(), root.join("nested"));

    // One budget acknowledged twice is a malformed context, not a stronger one.
    let mut parts = context_parts(root);
    parts.unenforced_budgets = vec![UnenforcedBudget::Artifact, UnenforcedBudget::Artifact];
    let error = AdmissionContext::new(parts).unwrap_err();
    assert!(
        matches!(
            error,
            AdmissionRefusal::ContextRejected("unenforced_budgets")
        ),
        "got {error:?}"
    );
}

#[test]
fn a_refusal_names_the_field_in_its_message() {
    let workspace = TempDir::new("display");
    let error = admit_with_admission_fields(workspace.path(), |fields| {
        fields.artifact_grants = ArtifactGrantBindings::declare(vec![ArtifactGrantBinding::new(
            ArtifactGrantId::new("grant-1").unwrap(),
            Revision::FIRST,
            ArtifactGrantDigest::parse(&digest_text('e')).unwrap(),
        )])
        .unwrap();
    })
    .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("admission.artifact_grants"), "{message}");

    // A prompt refusal quotes nothing about the prompt.
    let error = admit_with_context(workspace.path(), |context| {
        context.prompt = Some(
            ResolvedPrompt::new(
                PromptSource::ProtectedReference(
                    ProtectedPromptReference::new(PROMPT_SLOT).unwrap(),
                ),
                b"substituted".to_vec(),
                sha256_digest(PROMPT),
            )
            .unwrap(),
        );
    })
    .unwrap_err();
    let message = error.to_string();
    assert!(!message.contains("substituted"), "{message}");
    assert!(message.contains("digest"), "{message}");
}

// ---------------------------------------------------------------------------
// Enforced proof: an admitted plan is a launchable plan.
// ---------------------------------------------------------------------------

fn enforcement_domain(proof: &str) -> Option<ContainmentDomain> {
    match ContainmentDomain::discover() {
        Ok(found) => {
            eprintln!(
                "[admission] ENFORCED  {proof}: domain {}",
                found.root().display()
            );
            Some(found)
        }
        Err(error) => {
            eprintln!("[admission] NOT PROVEN {proof}: {error}");
            assert!(
                matches!(
                    error,
                    ContainmentError::DomainNotDelegated
                        | ContainmentError::NotUnifiedCgroupV2
                        | ContainmentError::MissingAtomicKill
                ),
                "undelegated environments must refuse with a typed reason, got {error:?}"
            );
            assert!(
                std::env::var_os(REQUIRE_ENFORCED_ENV).is_none(),
                "{REQUIRE_ENFORCED_ENV} is set, so {proof} must run against a \
                 delegated cgroup v2 domain, but none was available: {error}"
            );
            None
        }
    }
}

fn run_id(label: &str) -> String {
    let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    format!("a{}-{label}-{serial}", std::process::id())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

/// A well-formed sentinel, of the shape the broker mints.
fn sentinel() -> String {
    format!(
        "{SESSION_SENTINEL_PREFIX}{}",
        "a1".repeat(SESSION_SENTINEL_DIGITS / 2)
    )
}

fn provider_destination() -> BrokeredDestination {
    BrokeredDestination::new("api.example.com", 443, BrokeredScope::Public).unwrap()
}

fn identity_binding() -> ProviderIdentityBinding {
    ProviderIdentityBinding::new(
        "PROVIDER_BASE_URL",
        "PROVIDER_API_KEY",
        provider_destination(),
    )
    .unwrap()
}

/// Admit a brokered spec against a context that resolves one destination and
/// carries `policy`.
fn admit_brokered(
    root: &Path,
    policy: ProviderIdentityPolicy,
) -> Result<AdmittedLaunch, AdmissionRefusal> {
    let mut sandbox = sandbox_parts();
    sandbox.profile = SandboxProfile::new(
        "admission-profile",
        1,
        FilesystemAccess::IsolatedWritable,
        ToolWorkloadEgress::brokered(NetworkAccess::BrokeredNamed),
    )
    .unwrap();
    sandbox.provider_control_egress = ProviderControlEgress::brokered(NetworkAccess::BrokeredNamed);
    sandbox.tool_workload_egress = ToolWorkloadEgress::brokered(NetworkAccess::BrokeredNamed);
    let mut parts = spec_parts();
    parts.sandbox = SandboxSpec::compile(sandbox).unwrap();
    let spec = RunSpec::new(parts).unwrap();

    let mut context = context_parts(root);
    context.brokered_destinations =
        vec![BrokeredDestination::new("chatgpt.com", 443, BrokeredScope::Public).unwrap()];
    context.provider_identity = policy;
    admit(&spec, &AdmissionContext::new(context)?)
}

#[test]
fn a_launch_binds_no_provider_identity_unless_a_deployment_asks_for_one() {
    let workspace = TempDir::new("identity-default");
    let root = workspace.path();

    // The default on the parts struct is the disabled one, so a caller that
    // never heard of this feature cannot switch it on by omission.
    assert_eq!(
        ProviderIdentityPolicy::default(),
        ProviderIdentityPolicy::Disabled
    );

    let admitted = admit_brokered(root, ProviderIdentityPolicy::Disabled).unwrap();
    assert!(admitted.provider_identity_requirement().is_none());
    assert!(!admitted.has_provider_identity());
    assert_eq!(
        admitted
            .plan()
            .environment_names()
            .filter(|name| *name == "PROVIDER_BASE_URL" || *name == "PROVIDER_API_KEY")
            .count(),
        0
    );

    // And a launch with a policy but no broker gets nothing either: a workload
    // whose spec denies egress has nothing to be identity-bound to.
    let admitted = admit_with_context(root, |context| {
        context.provider_identity = ProviderIdentityPolicy::Enabled(identity_binding());
    })
    .unwrap();
    assert!(admitted.broker_requirement().is_none());
    assert!(admitted.provider_identity_requirement().is_none());
    assert!(matches!(
        admitted.with_provider_identity(loopback(4242), &sentinel()),
        Err(AdmissionRefusal::ProviderIdentityNotRequired)
    ));
}

#[test]
fn an_attached_provider_identity_adds_one_port_and_two_variables_and_nothing_else() {
    let workspace = TempDir::new("identity-attach");
    let admitted = admit_brokered(
        workspace.path(),
        ProviderIdentityPolicy::Enabled(identity_binding()),
    )
    .unwrap();

    let requirement = admitted
        .provider_identity_requirement()
        .expect("a bound identity survives admission");
    assert_eq!(requirement.base_url_variable(), "PROVIDER_BASE_URL");
    assert_eq!(requirement.credential_variable(), "PROVIDER_API_KEY");
    assert_eq!(requirement.destination(), &provider_destination());

    let before = admitted.plan().clone();
    let token = sentinel();
    let attached = admitted
        .with_provider_identity(loopback(4242), &token)
        .unwrap();
    assert!(attached.has_provider_identity());

    let expected = before
        .clone()
        .allow_connect_port(4242)
        .unwrap()
        .environment("PROVIDER_BASE_URL", b"http://127.0.0.1:4242")
        .unwrap()
        .environment("PROVIDER_API_KEY", token.as_bytes())
        .unwrap();
    assert_eq!(attached.plan(), &expected);

    // A second attachment is refused rather than layered.
    assert!(matches!(
        attached.with_provider_identity(loopback(4243), &token),
        Err(AdmissionRefusal::ProviderIdentityAlreadyAttached)
    ));
}

#[test]
fn an_endpoint_or_sentinel_that_is_not_one_is_refused_before_it_enters_a_plan() {
    let workspace = TempDir::new("identity-refusals");
    let root = workspace.path();
    let policy = ProviderIdentityPolicy::Enabled(identity_binding());

    for endpoint in [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4242),
    ] {
        let admitted = admit_brokered(root, policy.clone()).unwrap();
        assert!(
            matches!(
                admitted.with_provider_identity(endpoint, &sentinel()),
                Err(AdmissionRefusal::ProviderEndpointRejected(_))
            ),
            "{endpoint} must not be a provider endpoint"
        );
    }

    // The mistake that matters: a caller handing the workload something that is
    // not a sentinel — an empty string, a placeholder, or the real credential.
    for token in [
        String::new(),
        "sk-ant-the-real-credential".to_owned(),
        SESSION_SENTINEL_PREFIX.to_owned(),
        format!(
            "{SESSION_SENTINEL_PREFIX}{}",
            "z".repeat(SESSION_SENTINEL_DIGITS)
        ),
        format!(
            "{SESSION_SENTINEL_PREFIX}{}",
            "a".repeat(SESSION_SENTINEL_DIGITS - 1)
        ),
    ] {
        let admitted = admit_brokered(root, policy.clone()).unwrap();
        assert!(
            matches!(
                admitted.with_provider_identity(loopback(4242), &token),
                Err(AdmissionRefusal::SentinelRejected)
            ),
            "{token:?} must not be accepted as a sentinel"
        );
    }
}

#[test]
fn a_binding_that_would_fight_another_attachment_is_refused_when_it_is_built() {
    for (base_url, credential) in [
        ("HTTPS_PROXY", "PROVIDER_API_KEY"),
        ("PROVIDER_BASE_URL", "HTTP_PROXY"),
        ("PROVIDER_BASE_URL", "TMPDIR"),
        ("PROVIDER_BASE_URL", "PROVIDER_BASE_URL"),
        ("provider_base_url", "PROVIDER_API_KEY"),
        ("9PROVIDER", "PROVIDER_API_KEY"),
        ("PROVIDER-BASE-URL", "PROVIDER_API_KEY"),
        ("", "PROVIDER_API_KEY"),
    ] {
        let error = ProviderIdentityBinding::new(base_url, credential, provider_destination())
            .expect_err("{base_url}/{credential} must not bind");
        assert!(
            matches!(
                error,
                AdmissionRefusal::ContextRejected("provider_identity")
            ),
            "{base_url}/{credential} produced {error:?}"
        );
    }
}

#[test]
fn a_context_cannot_both_tunnel_to_the_provider_host_and_bind_its_identity() {
    let workspace = TempDir::new("identity-contradiction");
    let mut parts = context_parts(workspace.path());
    parts.brokered_destinations = vec![provider_destination()];
    parts.provider_identity = ProviderIdentityPolicy::Enabled(identity_binding());

    let error = AdmissionContext::new(parts).unwrap_err();
    assert!(
        matches!(
            error,
            AdmissionRefusal::ContextRejected("provider_identity")
        ),
        "{error:?}"
    );
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn assert_unmappable(error: &AdmissionRefusal, expected: &str) {
    match error {
        AdmissionRefusal::UnmappableField(field) => assert_eq!(*field, expected),
        other => panic!("expected {expected} to be unmappable, got {other:?}"),
    }
}

#[test]
fn an_admitted_plan_runs_under_the_full_composed_sandbox() {
    let Some(domain) = enforcement_domain("an_admitted_plan_runs_under_the_full_composed_sandbox")
    else {
        return;
    };
    // The admitted ceilings are real ceilings, so the domain must be able to
    // distribute all three controllers; where it cannot, the ceiling genuinely
    // cannot be applied and the proof cannot run.
    if domain
        .prepare(&[Controller::Pids, Controller::Memory, Controller::Cpu])
        .is_err()
    {
        eprintln!("[admission] NOT PROVEN: the domain cannot distribute pids, memory and cpu");
        return;
    }

    let workspace = TempDir::new("enforced");
    let prompt_witness = workspace.path().join("prompt.txt");
    let environment_witness = workspace.path().join("environment.txt");
    // The workload copies its own stdin, which is the admitted prompt, and
    // then reports the one variable the spec delivered. Every command is the
    // granted busybox by absolute path: the plan grants execute on exactly the
    // program the spec named and on nothing else.
    let script = format!(
        "{BUSYBOX} cat > {prompt}; {BUSYBOX} printf '%s' \"${ENV_NAME}\" > {environment}",
        prompt = prompt_witness.display(),
        environment = environment_witness.display(),
    );
    let mut parts = spec_parts();
    parts.arguments = vec![
        OsString::from("sh"),
        OsString::from("-c"),
        OsString::from(script),
    ];
    parts.coordinates = RunCoordinates::new(
        WorkId::new("work-1").unwrap(),
        RunId::new(run_id("enforced")).unwrap(),
        AttemptId::new("attempt-1").unwrap(),
        HostId::new("host-1").unwrap(),
        HostLifetime::Attempt,
        ExecutionBackendId::new("local-direct").unwrap(),
    );
    let spec = RunSpec::new(parts).unwrap();
    let admitted = admit(&spec, &mappable_context(workspace.path())).unwrap();

    // Nothing but the admitted values reaches the kernel: the run cgroup is
    // named by the admitted run identifier and bounded by the admitted limits.
    let containment =
        RunContainment::create(&domain, admitted.run_id(), admitted.limits()).unwrap();
    assert_eq!(
        fs::read_to_string(containment.path().join("memory.max"))
            .unwrap()
            .trim(),
        MEMORY_BYTES.to_string(),
        "the admitted memory ceiling must reach the kernel"
    );
    assert_eq!(
        fs::read_to_string(containment.path().join("pids.max"))
            .unwrap()
            .trim(),
        PROCESSES.to_string(),
        "the admitted process ceiling must reach the kernel"
    );

    let frame = admitted.plan().encode().unwrap();
    let mut child = Command::new(HELPER)
        .env_clear()
        .env(automonique_runner::CGROUP_DIR_ENV, containment.path())
        .current_dir(admitted.working_directory())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("helper spawns");
    use std::io::Write as _;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&frame)
        .expect("frame written");

    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        match child.try_wait().expect("wait") {
            Some(status) => break status,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("admitted workload did not exit within the deadline");
            }
        }
    };
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    let stderr = String::from_utf8_lossy(&stderr).into_owned();
    assert_eq!(status.code(), Some(0), "workload failed; stderr={stderr:?}");

    // The prompt arrived as the workload's own stdin, byte for byte.
    assert_eq!(
        fs::read(&prompt_witness).unwrap(),
        PROMPT,
        "the admitted prompt must reach the workload unaltered; stderr={stderr:?}"
    );
    // The one variable the spec declared arrived, and the write landed inside
    // the workspace the admitted plan granted.
    assert_eq!(fs::read_to_string(&environment_witness).unwrap(), ENV_VALUE);

    containment.dispose(DRAIN_DEADLINE).unwrap();
}
