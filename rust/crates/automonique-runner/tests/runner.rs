// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::automation::DurableId;
use automonique_protocol::context::{
    ComponentCaps, ContextManifest, PolicyComponent, RedactionOutcome, SuppliedClass,
    SuppliedComponent, TokenBudget, TrustClass,
};
use automonique_protocol::host::{AttemptId, HostId, HostLifetime, WorkId};
use automonique_protocol::identity::Actor;
use automonique_protocol::models::{ExecutorClass, ProviderAccountId, RemoteCoordinate};
use automonique_protocol::primitives::Revision;
use automonique_protocol::provider::{BinaryProvenance, ProviderSessionId, SessionBinding};
use automonique_protocol::sandbox::{
    BudgetQuantities, Budgets, CredentialDescriptors, ExecutionAllowlists, ExecutionBackendId,
    FilesystemAccess, ImplementationDigest, IsolationRequirement, NestedIsolation, NetworkAccess,
    PathGrants, PolicyDigest, ProhibitedCapabilities, ProviderControlEgress, RequiredFeature,
    RequiredFeatures, SandboxProfile, SandboxSpec, SandboxSpecParts, ToolWorkloadEgress,
    WorkspaceContextHash,
};
use automonique_protocol::tools::{CausationId, NestedCause, RunId};
use automonique_protocol::wire::MAX_JSON_ENTRIES;
use automonique_protocol::workspace::{IsolationKind, WorkspaceRegistration, WorkspaceToken};
use automonique_runner::{
    AdmissionFields, AdmissionFieldsParts, ArtifactGrantBinding, ArtifactGrantBindings,
    ArtifactGrantDigest, ArtifactGrantId, Authority, BackendPromptSession, CancellationToken,
    ContainmentEvidence, CwdToken, EventKind, ExecutionPlanDigest, ExtensionSetDigest,
    FallbackEligibility, IntegrationMode, IoReservation, ModelRoutingDigest, OriginCoordinate,
    PersonaDigest, PortabilityPolicy, ProfileDigest, PromptDeliveryPlan, ProtectedPromptReference,
    RemoteAttestationPolicy, RequiredCapabilities, RunCoordinates, RunOrigin, RunOriginSource,
    RunSpec, RunSpecError, RunSpecParts, Runner, RunnerError, RunnerEventDialect,
    SchedulerDecisionDigest, SchedulerReservationBinding, SchedulerReservationId, SkillsetDigest,
    Spool, SpoolError, ToolsetDigest, WorkspaceRegistryId, WorkspaceReservation,
};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "automonique-runner-{label}-{}-{serial}",
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

fn parts(_root: &Path, prompt: PromptDeliveryPlan) -> RunSpecParts {
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
        executable: PathBuf::from("/bin/true"),
        arguments: Vec::new(),
        cwd_token: CwdToken::new("cwd-1").unwrap(),
        environment: Vec::new(),
        prompt,
        workspace_registry_id: WorkspaceRegistryId::new("workspace-registry-1").unwrap(),
        workspace: workspace("acme", 7, IsolationKind::ReadOnlySnapshot),
        provider_binary: provider_binary(),
        sandbox: sandbox(
            "acme",
            7,
            FilesystemAccess::ReadOnlySnapshot,
            5_000,
            1024 * 1024,
        ),
        admission: admission(0),
    }
}

fn admission(workspace_bytes: u64) -> AdmissionFields {
    AdmissionFields::new(admission_parts(workspace_bytes))
}

fn admission_parts(workspace_bytes: u64) -> AdmissionFieldsParts {
    let mode = IntegrationMode::new("native").unwrap();
    AdmissionFieldsParts {
        io_reservation: IoReservation::new(1024, 1024).unwrap(),
        workspace_reservation: WorkspaceReservation::new(workspace_bytes).unwrap(),
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

fn digest_text(digit: char) -> String {
    format!("sha256:{}", digit.to_string().repeat(64))
}

fn parts_with_context(root: &Path, context_manifest: ContextManifest) -> RunSpecParts {
    let mut spec = parts(root, PromptDeliveryPlan::Stdin);
    let mut admission = admission_parts(0);
    admission.context_manifest = context_manifest;
    spec.admission = AdmissionFields::new(admission);
    spec
}

fn policy_component(source: &str) -> PolicyComponent {
    policy_component_with_token_cap(source, 1)
}

fn policy_component_with_token_cap(source: &str, token_cap: u64) -> PolicyComponent {
    PolicyComponent::new(
        source,
        Revision::FIRST,
        "policy-component-digest",
        ComponentCaps::new(1, token_cap).unwrap(),
        RedactionOutcome::Clean,
    )
    .unwrap()
}

fn supplied_component(source: &str) -> SuppliedComponent {
    supplied_component_with_token_cap(source, 1)
}

fn supplied_component_with_token_cap(source: &str, token_cap: u64) -> SuppliedComponent {
    SuppliedComponent::new(
        source,
        SuppliedClass::Skills,
        TrustClass::ActorSupplied,
        "supplied-component-digest",
        ComponentCaps::new(1, token_cap).unwrap(),
        RedactionOutcome::Clean,
    )
    .unwrap()
}

fn session_binding(
    tenant: &str,
    backend: &str,
    provider_account: &str,
    session: &str,
) -> SessionBinding {
    SessionBinding::new(
        tenant,
        backend,
        provider_account,
        "namespace-1",
        ProviderSessionId::new(session).unwrap(),
    )
    .unwrap()
}

fn provider_binary() -> BinaryProvenance {
    BinaryProvenance::new(
        "1.2.3",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        Some("sha256:2222222222222222222222222222222222222222222222222222222222222222"),
    )
    .unwrap()
}

fn workspace(tenant: &str, base: u64, isolation: IsolationKind) -> WorkspaceRegistration {
    WorkspaceRegistration::new(
        tenant,
        "source-1",
        Revision::new(base).unwrap(),
        "snapshot-1",
        isolation,
        WorkspaceToken::new("workspace-token-1").unwrap(),
    )
    .unwrap()
}

fn sandbox(
    tenant: &str,
    base: u64,
    filesystem: FilesystemAccess,
    timeout_millis: u64,
    spool_bytes: u64,
) -> SandboxSpec {
    let implementation = ImplementationDigest::parse(
        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    )
    .unwrap();
    SandboxSpec::compile(SandboxSpecParts {
        profile: SandboxProfile::new("test-profile", 1, filesystem, ToolWorkloadEgress::denied())
            .unwrap(),
        policy_digest: PolicyDigest::parse(
            "sha256:4444444444444444444444444444444444444444444444444444444444444444",
        )
        .unwrap(),
        actor: Actor::new(tenant, "actor-1").unwrap(),
        provider_account: ProviderAccountId::new("provider-account-1").unwrap(),
        workspace_context: WorkspaceContextHash::parse(
            "sha256:5555555555555555555555555555555555555555555555555555555555555555",
        )
        .unwrap(),
        base_revision: Revision::new(base).unwrap(),
        path_grants: PathGrants::declare(&[]).unwrap(),
        allowlists: ExecutionAllowlists::declare(&[]).unwrap(),
        provider_control_egress: ProviderControlEgress::brokered(NetworkAccess::BrokeredNamed),
        tool_workload_egress: ToolWorkloadEgress::denied(),
        credentials: CredentialDescriptors::declare(&[]).unwrap(),
        budgets: Budgets::declare(BudgetQuantities {
            cgroup_memory_bytes: 128 * 1024 * 1024,
            cgroup_cpu_millicores: 1_000,
            rlimit_processes: 64,
            rlimit_descriptors: 256,
            timeout_millis,
            temporary_storage_bytes: 1024 * 1024,
            spool_bytes,
            artifact_bytes: 1024 * 1024,
        })
        .unwrap(),
        required_features: RequiredFeatures::declare(&[RequiredFeature::new(
            "process_boundary",
            &[implementation],
        )
        .unwrap()])
        .unwrap(),
        nested_isolation: NestedIsolation::new(
            IsolationRequirement::SeparateChildBoundary,
            IsolationRequirement::SeparateChildBoundary,
        ),
        approval_revision: Revision::FIRST,
        prohibited_capabilities: ProhibitedCapabilities::declare(&[]).unwrap(),
    })
    .unwrap()
}

#[test]
fn strict_run_spec_validation_rejects_unbounded_and_ambiguous_values() {
    let root = TempDir::new("validation");
    let prompt = PromptDeliveryPlan::Stdin;
    let mut candidate = parts(root.path(), prompt.clone());
    candidate.protocol_version = 2;
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::UnsupportedProtocol(2)
    );

    let mut candidate = parts(root.path(), prompt.clone());
    candidate.executable = PathBuf::from("/usr/bin/../bin/true");
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::PathNotCanonical("executable")
    );

    assert_eq!(
        CwdToken::new("../relative").unwrap_err(),
        RunSpecError::FieldInvalid("cwd_token")
    );

    let mut candidate = parts(root.path(), prompt.clone());
    candidate.arguments = vec![OsString::from("x".repeat(4097))];
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::ArgumentTooLarge
    );

    let mut candidate = parts(root.path(), prompt.clone());
    candidate.environment = vec![("BAD=KEY".into(), "value".into())];
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::EnvironmentKeyInvalid
    );

    let mut candidate = parts(root.path(), prompt);
    candidate.environment = vec![
        ("PATH".into(), "/bin".into()),
        ("PATH".into(), "/usr/bin".into()),
    ];
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::DuplicateEnvironmentKey
    );
}

#[test]
fn run_spec_partial_has_typed_coordinates_and_payload_free_prompt_modes() {
    let root = TempDir::new("typed-coordinates");
    let prompt = PromptDeliveryPlan::ProtectedReference(
        ProtectedPromptReference::new("prompt-slot-1").unwrap(),
    );
    let spec = RunSpec::new(parts(root.path(), prompt)).unwrap();
    assert_eq!(spec.work_id().as_str(), "work-1");
    assert_eq!(spec.run_id().as_str(), "run-1");
    assert_eq!(spec.attempt_id().as_str(), "attempt-1");
    assert_eq!(spec.host_id().as_str(), "host-1");
    assert_eq!(spec.host_lifetime(), HostLifetime::Attempt);
    assert_eq!(spec.backend_id().as_str(), "local-direct");
    assert_eq!(spec.cwd_token().as_str(), "cwd-1");
    assert!(matches!(
        spec.prompt_delivery(),
        PromptDeliveryPlan::ProtectedReference(_)
    ));

    assert_eq!(
        ProtectedPromptReference::new("../prompt").unwrap_err(),
        RunSpecError::FieldInvalid("protected_prompt_reference")
    );
    assert_eq!(
        BackendPromptSession::new("/tmp/session").unwrap_err(),
        RunSpecError::FieldInvalid("backend_prompt_session")
    );
}

#[test]
fn cwd_token_enforces_exact_bounds_and_rejects_path_shapes() {
    let boundary = "x".repeat(256);
    assert_eq!(CwdToken::new(&boundary).unwrap().as_str(), boundary);
    assert_eq!(
        CwdToken::new("x".repeat(257)).unwrap_err(),
        RunSpecError::FieldInvalid("cwd_token")
    );
    for invalid in ["", "/root", "a/b", r"a\b", "..", "name:slot", "~home"] {
        assert_eq!(
            CwdToken::new(invalid).unwrap_err(),
            RunSpecError::FieldInvalid("cwd_token")
        );
    }
}

#[test]
fn debug_redacts_argv_environment_and_prompt_coordinates() {
    let root = TempDir::new("debug-redaction");
    let mut candidate = parts(
        root.path(),
        PromptDeliveryPlan::ProtectedReference(
            ProtectedPromptReference::new("SESSION_SENTINEL").unwrap(),
        ),
    );
    candidate.arguments = vec!["ARG_SENTINEL".into()];
    candidate.environment = vec![("SAFE_KEY".into(), "ENV_SENTINEL".into())];
    candidate.cwd_token = CwdToken::new("CWD_SENTINEL").unwrap();
    let rendered_parts = format!("{candidate:?}");
    let rendered_spec = format!("{:?}", RunSpec::new(candidate).unwrap());
    for rendered in [&rendered_parts, &rendered_spec] {
        assert!(!rendered.contains("ARG_SENTINEL"));
        assert!(!rendered.contains("ENV_SENTINEL"));
        assert!(!rendered.contains("SESSION_SENTINEL"));
        assert!(!rendered.contains("CWD_SENTINEL"));
    }
}

#[test]
fn path_and_environment_aggregate_bounds_fail_closed() {
    let root = TempDir::new("aggregate-bounds");
    let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
    candidate.executable = PathBuf::from(format!("/{}", "x".repeat(4_096)));
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::FieldInvalid("executable")
    );

    let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
    candidate.executable = PathBuf::from(format!("/{}", "x".repeat(4_095)));
    assert_eq!(candidate.executable.as_os_str().as_bytes().len(), 4_096);
    assert!(RunSpec::new(candidate).is_ok());

    let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
    candidate.executable = PathBuf::from(OsString::from_vec(b"/bin/\xff".to_vec()));
    assert!(RunSpec::new(candidate).is_ok());

    let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
    candidate.environment = (0..17)
        .map(|index| (format!("KEY_{index}").into(), "x".repeat(4_096).into()))
        .collect();
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::EnvironmentTooLarge
    );
}

#[test]
fn canonical_workspace_sandbox_and_provider_values_are_embedded_exactly() {
    let root = TempDir::new("canonical-embeddings");
    let spec = RunSpec::new(parts(root.path(), PromptDeliveryPlan::Stdin)).unwrap();
    assert_eq!(
        spec.workspace_registry_id().as_str(),
        "workspace-registry-1"
    );
    assert_eq!(spec.workspace().tenant(), "acme");
    assert_eq!(spec.workspace().base_revision(), Revision::new(7).unwrap());
    assert_eq!(spec.sandbox().tenant(), "acme");
    assert_eq!(spec.sandbox().base_revision(), Revision::new(7).unwrap());
    assert_eq!(spec.provider_binary().version(), "1.2.3");
    assert_eq!(
        spec.provider_binary().digest(),
        "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    );
    assert_eq!(
        WorkspaceRegistryId::new("../workspace").unwrap_err(),
        RunSpecError::FieldInvalid("workspace_registry_id")
    );
}

#[test]
fn workspace_and_sandbox_cross_field_mismatches_refuse() {
    let root = TempDir::new("cross-field-refusal");

    let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
    candidate.workspace = workspace("other-tenant", 7, IsolationKind::ReadOnlySnapshot);
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::WorkspaceTenantMismatch
    );

    let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
    candidate.workspace = workspace("acme", 8, IsolationKind::ReadOnlySnapshot);
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::WorkspaceBaseMismatch
    );

    let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
    candidate.workspace = workspace("acme", 7, IsolationKind::AttemptCopy);
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::WorkspaceIsolationMismatch
    );

    let writable_cases = [
        (
            IsolationKind::AttemptCopy,
            FilesystemAccess::IsolatedWritable,
        ),
        (IsolationKind::Overlay, FilesystemAccess::WritableWithGrants),
    ];
    for (isolation, access) in writable_cases {
        let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
        candidate.workspace = workspace("acme", 7, isolation);
        candidate.sandbox = sandbox("acme", 7, access, 5_000, 1024 * 1024);
        candidate.admission = admission(1024);
        assert!(RunSpec::new(candidate).is_ok());
    }

    for spool_bytes in [4_096, 1024 * 1024 * 1024] {
        let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
        candidate.sandbox = sandbox(
            "acme",
            7,
            FilesystemAccess::ReadOnlySnapshot,
            5_000,
            spool_bytes,
        );
        assert_eq!(
            RunSpec::new(candidate).unwrap().spool_budget_bytes(),
            spool_bytes
        );
    }
    for spool_bytes in [4_095, 1024 * 1024 * 1024 + 1] {
        let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
        candidate.sandbox = sandbox(
            "acme",
            7,
            FilesystemAccess::ReadOnlySnapshot,
            5_000,
            spool_bytes,
        );
        assert_eq!(
            RunSpec::new(candidate).unwrap_err(),
            RunSpecError::SpoolLimitInvalid
        );
    }
}

#[test]
fn admission_field_constructors_refuse_unbounded_or_ambiguous_values() {
    assert_eq!(
        IoReservation::new(u64::MAX, 0).unwrap_err(),
        RunSpecError::FieldInvalid("io_reservation")
    );
    assert_eq!(
        WorkspaceReservation::new(u64::MAX).unwrap_err(),
        RunSpecError::FieldInvalid("workspace_reservation")
    );
    assert_eq!(
        IntegrationMode::new("../native").unwrap_err(),
        RunSpecError::FieldInvalid("integration_mode")
    );
    let selected = IntegrationMode::new("native").unwrap();
    assert_eq!(
        FallbackEligibility::declare(&selected, vec![selected.clone()]).unwrap_err(),
        RunSpecError::FieldInvalid("fallback_eligibility")
    );
    let duplicate = IntegrationMode::new("remote").unwrap();
    assert_eq!(
        FallbackEligibility::declare(&selected, vec![duplicate.clone(), duplicate]).unwrap_err(),
        RunSpecError::FieldInvalid("fallback_eligibility")
    );
    assert_eq!(
        ProfileDigest::parse("sha256:00").unwrap_err(),
        RunSpecError::FieldInvalid("profile_digest")
    );
}

#[test]
fn nonauthorizing_bindings_are_bounded_distinct_and_duplicate_free() {
    for invalid in ["", ".", "..", "with/slash", "with:colon", "é", "-leading"] {
        assert_eq!(
            SchedulerReservationId::new(invalid).unwrap_err(),
            RunSpecError::FieldInvalid("scheduler_reservation_id")
        );
    }
    let boundary = format!("a{}", "z".repeat(255));
    assert_eq!(
        SchedulerReservationId::new(&boundary).unwrap().as_str(),
        boundary
    );
    assert_eq!(
        SchedulerReservationId::new(&format!("a{}", "z".repeat(256))).unwrap_err(),
        RunSpecError::FieldInvalid("scheduler_reservation_id")
    );

    let grant = ArtifactGrantBinding::new(
        ArtifactGrantId::new("grant-1").unwrap(),
        Revision::FIRST,
        ArtifactGrantDigest::parse(&digest_text('e')).unwrap(),
    );
    assert_eq!(grant.id().as_str(), "grant-1");
    assert_eq!(grant.revision(), Revision::FIRST);
    assert_eq!(grant.grant_digest().digest().to_string(), digest_text('e'));
    assert_eq!(
        ArtifactGrantBindings::declare(vec![grant.clone(), grant]).unwrap_err(),
        RunSpecError::FieldInvalid("artifact_grants")
    );
    let duplicate_id_changed_coordinates = vec![
        ArtifactGrantBinding::new(
            ArtifactGrantId::new("same-grant").unwrap(),
            Revision::FIRST,
            ArtifactGrantDigest::parse(&digest_text('e')).unwrap(),
        ),
        ArtifactGrantBinding::new(
            ArtifactGrantId::new("same-grant").unwrap(),
            Revision::new(2).unwrap(),
            ArtifactGrantDigest::parse(&digest_text('f')).unwrap(),
        ),
    ];
    assert_eq!(
        ArtifactGrantBindings::declare(duplicate_id_changed_coordinates).unwrap_err(),
        RunSpecError::FieldInvalid("artifact_grants")
    );
    let exact_limit = (0..128)
        .map(|index| {
            ArtifactGrantBinding::new(
                ArtifactGrantId::new(&format!("grant-{index}")).unwrap(),
                Revision::FIRST,
                ArtifactGrantDigest::parse(&digest_text('e')).unwrap(),
            )
        })
        .collect();
    assert_eq!(
        ArtifactGrantBindings::declare(exact_limit)
            .unwrap()
            .as_slice()
            .len(),
        128
    );
    let ordered = ArtifactGrantBindings::declare(vec![
        ArtifactGrantBinding::new(
            ArtifactGrantId::new("grant-first").unwrap(),
            Revision::FIRST,
            ArtifactGrantDigest::parse(&digest_text('e')).unwrap(),
        ),
        ArtifactGrantBinding::new(
            ArtifactGrantId::new("grant-second").unwrap(),
            Revision::FIRST,
            ArtifactGrantDigest::parse(&digest_text('f')).unwrap(),
        ),
    ])
    .unwrap();
    assert_eq!(ordered.as_slice()[0].id().as_str(), "grant-first");
    assert_eq!(ordered.as_slice()[1].id().as_str(), "grant-second");
    let too_many = (0..129)
        .map(|index| {
            ArtifactGrantBinding::new(
                ArtifactGrantId::new(&format!("grant-{index}")).unwrap(),
                Revision::FIRST,
                ArtifactGrantDigest::parse(&digest_text('e')).unwrap(),
            )
        })
        .collect();
    assert_eq!(
        ArtifactGrantBindings::declare(too_many).unwrap_err(),
        RunSpecError::FieldInvalid("artifact_grants")
    );

    let root = TempDir::new("bindings");
    let spec = RunSpec::new(parts(root.path(), PromptDeliveryPlan::Stdin)).unwrap();
    assert_eq!(
        spec.admission().scheduler_reservation().id().as_str(),
        "reservation-1"
    );
    assert!(spec.admission().artifact_grants().is_empty());
    let debug = format!("{:?}", spec.admission());
    assert!(!debug.contains("reservation-1"));

    for invalid in [
        "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:AAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:aa",
    ] {
        assert_eq!(
            SchedulerDecisionDigest::parse(invalid).unwrap_err(),
            RunSpecError::FieldInvalid("scheduler_decision_digest")
        );
    }
}

#[test]
fn remote_executor_classes_require_an_attestation_policy() {
    let root = TempDir::new("remote-attestation");
    for executor_class in [
        ExecutorClass::Ssh,
        ExecutorClass::Batch,
        ExecutorClass::Cluster,
        ExecutorClass::MicroVm,
        ExecutorClass::Remote(RemoteCoordinate::new("vendor", "resource").unwrap()),
    ] {
        let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
        let mut fields = admission_parts(0);
        fields.executor_class = executor_class;
        candidate.admission = AdmissionFields::new(fields);
        assert_eq!(
            RunSpec::new(candidate).unwrap_err(),
            RunSpecError::FieldInvalid("remote_attestation_policy")
        );
    }

    let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
    let mut fields = admission_parts(0);
    fields.executor_class = ExecutorClass::Ssh;
    fields.remote_attestation_policy = RemoteAttestationPolicy::Signed;
    candidate.admission = AdmissionFields::new(fields);
    assert!(RunSpec::new(candidate).is_ok());
}

#[test]
fn admission_cross_field_mismatches_fail_closed() {
    let root = TempDir::new("admission-cross-fields");

    let selected = IntegrationMode::new("selected").unwrap();
    let alternate = IntegrationMode::new("alternate").unwrap();
    let mut fields = admission_parts(0);
    fields.integration_mode = alternate.clone();
    fields.fallback_eligibility = FallbackEligibility::declare(&selected, vec![alternate]).unwrap();
    let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
    candidate.admission = AdmissionFields::new(fields);
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::FieldInvalid("fallback_eligibility")
    );

    let mut candidate = parts(
        root.path(),
        PromptDeliveryPlan::BackendSession(BackendPromptSession::new("session-1").unwrap()),
    );
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::FieldInvalid("backend_prompt_session")
    );

    candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
    candidate.coordinates = RunCoordinates::new(
        WorkId::new("work-1").unwrap(),
        RunId::new("run-1").unwrap(),
        AttemptId::new("attempt-1").unwrap(),
        HostId::new("host-1").unwrap(),
        HostLifetime::Session,
        ExecutionBackendId::new("local-direct").unwrap(),
    );
    assert!(RunSpec::new(candidate).is_ok());

    let mut candidate = parts(
        root.path(),
        PromptDeliveryPlan::BackendSession(BackendPromptSession::new("session-1").unwrap()),
    );
    let mut fields = admission_parts(0);
    fields.session_binding = Some(session_binding(
        "acme",
        "local-direct",
        "provider-account-1",
        "session-1",
    ));
    candidate.admission = AdmissionFields::new(fields);
    assert!(RunSpec::new(candidate).is_ok());

    for binding in [
        session_binding(
            "other-tenant",
            "local-direct",
            "provider-account-1",
            "session-1",
        ),
        session_binding("acme", "other-backend", "provider-account-1", "session-1"),
        session_binding("acme", "local-direct", "other-account", "session-1"),
    ] {
        let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
        let mut fields = admission_parts(0);
        fields.session_binding = Some(binding);
        candidate.admission = AdmissionFields::new(fields);
        assert_eq!(
            RunSpec::new(candidate).unwrap_err(),
            RunSpecError::FieldInvalid("session_binding")
        );
    }

    let mut candidate = parts(
        root.path(),
        PromptDeliveryPlan::BackendSession(BackendPromptSession::new("wrong-session").unwrap()),
    );
    let mut fields = admission_parts(0);
    fields.session_binding = Some(session_binding(
        "acme",
        "local-direct",
        "provider-account-1",
        "session-1",
    ));
    candidate.admission = AdmissionFields::new(fields);
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::FieldInvalid("backend_prompt_session")
    );
}

#[test]
fn noninteractive_origin_preserves_exact_read_only_coordinates() {
    let automation = DurableId::new("automation-1").unwrap();
    let goal = DurableId::new("goal-1").unwrap();
    let trigger = DurableId::new("trigger-1").unwrap();
    let event = DurableId::new("event-1").unwrap();
    let cause = NestedCause::root(
        Actor::new("acme", "actor-1").unwrap(),
        RunId::new("run-1").unwrap(),
        CausationId::new("cause-1").unwrap(),
    );
    let origin = RunOrigin::non_interactive(
        RunOriginSource::Automation,
        event.clone(),
        OriginCoordinate::Automation(automation.clone()),
        vec![event.clone()],
        cause.clone(),
    )
    .unwrap();
    let RunOrigin::NonInteractive(origin_data) = &origin else {
        panic!("expected noninteractive origin");
    };
    assert_eq!(origin_data.source(), RunOriginSource::Automation);
    assert_eq!(origin_data.event_id(), &event);
    assert_eq!(origin_data.automation(), Some(&automation));
    assert_eq!(origin_data.goal(), None);
    assert_eq!(origin_data.trigger(), None);
    assert_eq!(origin_data.causal_events(), std::slice::from_ref(&event));
    assert_eq!(origin_data.cause(), &cause);

    let root = TempDir::new("noninteractive-origin");
    let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
    let mut fields = admission_parts(0);
    fields.origin = origin;
    candidate.admission = AdmissionFields::new(fields);
    assert!(RunSpec::new(candidate).is_ok());

    for (source, coordinate) in [
        (
            RunOriginSource::Goal,
            OriginCoordinate::Automation(goal.clone()),
        ),
        (
            RunOriginSource::Trigger,
            OriginCoordinate::Goal(trigger.clone()),
        ),
        (
            RunOriginSource::Recovery,
            OriginCoordinate::Trigger(trigger.clone()),
        ),
        (RunOriginSource::Interactive, OriginCoordinate::None),
    ] {
        assert_eq!(
            RunOrigin::non_interactive(
                source,
                event.clone(),
                coordinate,
                vec![event.clone()],
                cause.clone(),
            )
            .unwrap_err(),
            RunSpecError::FieldInvalid("origin")
        );
    }

    assert_eq!(
        RunOrigin::Interactive.source(),
        RunOriginSource::Interactive
    );
    assert!(RunOrigin::Interactive.non_interactive_details().is_none());

    for source in [
        RunOriginSource::Schedule,
        RunOriginSource::Recovery,
        RunOriginSource::GraphChild,
        RunOriginSource::BackgroundCuration,
        RunOriginSource::Media,
        RunOriginSource::RemoteWakeup,
        RunOriginSource::Batch,
        RunOriginSource::Evaluation,
    ] {
        let generic = RunOrigin::non_interactive(
            source,
            event.clone(),
            OriginCoordinate::None,
            vec![event.clone()],
            cause.clone(),
        )
        .unwrap();
        assert_eq!(generic.source(), source);
    }

    for (source, coordinate) in [
        (
            RunOriginSource::Automation,
            OriginCoordinate::Automation(automation),
        ),
        (RunOriginSource::Goal, OriginCoordinate::Goal(goal)),
        (RunOriginSource::Trigger, OriginCoordinate::Trigger(trigger)),
    ] {
        let typed = RunOrigin::non_interactive(
            source,
            event.clone(),
            coordinate,
            vec![event.clone()],
            cause.clone(),
        )
        .unwrap();
        assert_eq!(typed.source(), source);
        let details = typed.non_interactive_details().unwrap();
        match source {
            RunOriginSource::Automation => assert!(details.automation().is_some()),
            RunOriginSource::Goal => assert!(details.goal().is_some()),
            RunOriginSource::Trigger => assert!(details.trigger().is_some()),
            _ => unreachable!(),
        }
    }

    assert_eq!(
        RunOrigin::non_interactive(
            RunOriginSource::Recovery,
            event.clone(),
            OriginCoordinate::None,
            Vec::new(),
            cause.clone(),
        )
        .unwrap_err(),
        RunSpecError::FieldInvalid("causal_events")
    );
    assert_eq!(
        RunOrigin::non_interactive(
            RunOriginSource::Recovery,
            event.clone(),
            OriginCoordinate::None,
            vec![event.clone(), event.clone()],
            cause.clone(),
        )
        .unwrap_err(),
        RunSpecError::FieldInvalid("causal_events")
    );
    let too_many_events = (0..65)
        .map(|index| DurableId::new(&format!("event-{index}")).unwrap())
        .collect();
    assert_eq!(
        RunOrigin::non_interactive(
            RunOriginSource::Recovery,
            event.clone(),
            OriginCoordinate::None,
            too_many_events,
            cause.clone(),
        )
        .unwrap_err(),
        RunSpecError::FieldInvalid("causal_events")
    );

    let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
    let mut fields = admission_parts(0);
    fields.origin = RunOrigin::non_interactive(
        RunOriginSource::Recovery,
        event.clone(),
        OriginCoordinate::None,
        vec![event],
        NestedCause::root(
            Actor::new("other", "actor-1").unwrap(),
            RunId::new("run-1").unwrap(),
            CausationId::new("cause-2").unwrap(),
        ),
    )
    .unwrap();
    candidate.admission = AdmissionFields::new(fields);
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::FieldInvalid("origin")
    );

    let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
    let mut fields = admission_parts(0);
    fields.origin = RunOrigin::non_interactive(
        RunOriginSource::Recovery,
        DurableId::new("event-run-mismatch").unwrap(),
        OriginCoordinate::None,
        vec![DurableId::new("event-run-mismatch").unwrap()],
        NestedCause::root(
            Actor::new("acme", "actor-1").unwrap(),
            RunId::new("other-run").unwrap(),
            CausationId::new("cause-3").unwrap(),
        ),
    )
    .unwrap();
    candidate.admission = AdmissionFields::new(fields);
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::FieldInvalid("origin")
    );
}

#[test]
fn arbitrary_execution_is_refused_without_descendant_complete_containment() {
    let root = TempDir::new("containment-refusal");
    let spec = RunSpec::new(parts(root.path(), PromptDeliveryPlan::Stdin)).unwrap();
    assert!(matches!(
        Runner.run(spec, &CancellationToken::new()),
        Err(RunnerError::ContainmentUnenforced(
            ContainmentEvidence::ProcessGroupOnly
        ))
    ));
    assert!(!root.path().join("spool").exists());
}

#[test]
fn event_sequences_are_monotonic_and_terminal_is_exactly_once() {
    let root = TempDir::new("terminal");
    let mut spool = Spool::open(root.path().join("spool"), "run-terminal", 1024 * 1024).unwrap();
    spool
        .append(EventKind::Started, Authority::Synthetic, b"start")
        .unwrap();
    spool
        .append(EventKind::Terminal, Authority::Authoritative, b"completed")
        .unwrap();
    let events = spool.events_after(0).unwrap();
    assert_eq!(
        events
            .iter()
            .map(|event| event.sequence())
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind() == EventKind::Terminal)
            .count(),
        1
    );
    assert_eq!(spool.status().last_sequence(), 2);
    assert!(matches!(
        spool.append(EventKind::AdapterEvent, Authority::Authoritative, b"late"),
        Err(SpoolError::AlreadyTerminal)
    ));
}

#[test]
fn restart_reconstructs_cursor() {
    let root = TempDir::new("cursor");
    {
        let mut spool = Spool::open(root.path().join("spool"), "run-cursor", 1024 * 1024).unwrap();
        spool
            .append(EventKind::Started, Authority::Synthetic, b"start")
            .unwrap();
        spool
            .append(EventKind::AdapterEvent, Authority::Authoritative, b"one")
            .unwrap();
    }
    let resumed = Spool::open(root.path().join("spool"), "run-cursor", 1024 * 1024).unwrap();
    assert_eq!(
        resumed
            .events_after(1)
            .unwrap()
            .iter()
            .map(|event| event.sequence())
            .collect::<Vec<_>>(),
        vec![2]
    );
    assert!(matches!(
        resumed.events_after(3),
        Err(SpoolError::CursorAhead { .. })
    ));
}

#[test]
fn restart_discards_only_an_incomplete_crash_tail() {
    let root = TempDir::new("partial-tail");
    let spool_root = root.path().join("spool");
    {
        let mut spool = Spool::open(&spool_root, "run-tail", 1024 * 1024).unwrap();
        spool
            .append(EventKind::Started, Authority::Synthetic, b"start")
            .unwrap();
    }
    OpenOptions::new()
        .append(true)
        .open(spool_root.join("events.ndjson"))
        .unwrap()
        .write_all(b"{\"protocol\":\"automonique.runner.event\"")
        .unwrap();

    let mut resumed = Spool::open(&spool_root, "run-tail", 1024 * 1024).unwrap();
    assert_eq!(resumed.events_after(0).unwrap().len(), 1);
    assert_eq!(
        resumed
            .append(EventKind::Terminal, Authority::Authoritative, b"completed")
            .unwrap()
            .sequence(),
        2
    );
}

#[test]
fn complete_frame_payload_mutation_is_refused_by_hash_chain() {
    let root = TempDir::new("mutated-frame");
    let spool_root = root.path().join("spool");
    {
        let mut spool = Spool::open(&spool_root, "run-mutated", 1024 * 1024).unwrap();
        spool
            .append(EventKind::Started, Authority::Synthetic, b"start")
            .unwrap();
        spool
            .append(EventKind::AdapterEvent, Authority::Authoritative, b"safe")
            .unwrap();
    }
    let path = spool_root.join("events.ndjson");
    let original = fs::read_to_string(&path).unwrap();
    let lines = original.lines().collect::<Vec<_>>();
    let first_digest = field(lines[0], "sha256");
    assert_eq!(field(lines[1], "previous_sha256"), first_digest);
    let mutated = original.replacen("73616665", "73616664", 1);
    assert_ne!(mutated, original);
    fs::write(&path, mutated).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        Spool::open(&spool_root, "run-mutated", 1024 * 1024),
        Err(SpoolError::Corrupt)
    ));
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    let marker = format!("\"{name}\":\"");
    line.split_once(&marker)
        .and_then(|(_, rest)| rest.split_once('\"'))
        .map(|(value, _)| value)
        .unwrap()
}

#[test]
fn stale_status_temporary_does_not_block_restart() {
    let root = TempDir::new("stale-status");
    let spool_root = root.path().join("spool");
    {
        let mut spool = Spool::open(&spool_root, "run-status", 1024 * 1024).unwrap();
        spool
            .append(EventKind::Started, Authority::Synthetic, b"start")
            .unwrap();
    }
    fs::write(
        spool_root.join(format!(".status.{}.tmp", std::process::id())),
        b"partial",
    )
    .unwrap();
    let reopened = Spool::open(&spool_root, "run-status", 1024 * 1024).unwrap();
    assert_eq!(reopened.status().last_sequence(), 1);
}

#[test]
fn context_policy_array_accepts_exact_wire_limit_with_duplicates_and_order() {
    let root = TempDir::new("context-policy-limit");
    let repeated = policy_component("policy-repeated");
    let mut policy = vec![repeated; MAX_JSON_ENTRIES];
    policy[0] = policy_component("policy-first");
    policy[MAX_JSON_ENTRIES - 1] = policy_component("policy-last");
    let manifest = ContextManifest::new(
        Revision::FIRST,
        TokenBudget::new(MAX_JSON_ENTRIES as u64),
        policy,
        Vec::new(),
    );

    let spec = RunSpec::new(parts_with_context(root.path(), manifest)).expect("exact limit");
    let preserved = spec.admission().context_manifest().policy();
    assert_eq!(preserved.len(), MAX_JSON_ENTRIES);
    assert_eq!(preserved[0].source(), "policy-first");
    assert_eq!(preserved[1].source(), "policy-repeated");
    assert_eq!(preserved[2].source(), "policy-repeated");
    assert_eq!(preserved[MAX_JSON_ENTRIES - 1].source(), "policy-last");
}

#[test]
fn context_policy_array_refuses_one_over_wire_limit() {
    let root = TempDir::new("context-policy-over-limit");
    let policy = vec![policy_component("policy-repeated"); MAX_JSON_ENTRIES + 1];
    let manifest = ContextManifest::new(
        Revision::FIRST,
        TokenBudget::new((MAX_JSON_ENTRIES + 1) as u64),
        policy,
        Vec::new(),
    );

    assert_eq!(
        RunSpec::new(parts_with_context(root.path(), manifest)).unwrap_err(),
        RunSpecError::FieldInvalid("context_manifest")
    );
}

#[test]
fn context_supplied_array_accepts_exact_wire_limit_with_duplicates_and_order() {
    let root = TempDir::new("context-supplied-limit");
    let repeated = supplied_component("supplied-repeated");
    let mut supplied = vec![repeated; MAX_JSON_ENTRIES];
    supplied[0] = supplied_component("supplied-first");
    supplied[MAX_JSON_ENTRIES - 1] = supplied_component("supplied-last");
    let manifest = ContextManifest::new(
        Revision::FIRST,
        TokenBudget::new(MAX_JSON_ENTRIES as u64),
        Vec::new(),
        supplied,
    );

    let spec = RunSpec::new(parts_with_context(root.path(), manifest)).expect("exact limit");
    let preserved = spec.admission().context_manifest().supplied();
    assert_eq!(preserved.len(), MAX_JSON_ENTRIES);
    assert_eq!(preserved[0].source(), "supplied-first");
    assert_eq!(preserved[1].source(), "supplied-repeated");
    assert_eq!(preserved[2].source(), "supplied-repeated");
    assert_eq!(preserved[MAX_JSON_ENTRIES - 1].source(), "supplied-last");
}

#[test]
fn context_supplied_array_refuses_one_over_wire_limit() {
    let root = TempDir::new("context-supplied-over-limit");
    let supplied = vec![supplied_component("supplied-repeated"); MAX_JSON_ENTRIES + 1];
    let manifest = ContextManifest::new(
        Revision::FIRST,
        TokenBudget::new((MAX_JSON_ENTRIES + 1) as u64),
        Vec::new(),
        supplied,
    );

    assert_eq!(
        RunSpec::new(parts_with_context(root.path(), manifest)).unwrap_err(),
        RunSpecError::FieldInvalid("context_manifest")
    );
}

#[test]
fn context_combined_array_limits_use_the_exact_checked_budget() {
    let root = TempDir::new("context-combined-limit");
    let policy = vec![policy_component("policy-repeated"); MAX_JSON_ENTRIES];
    let supplied = vec![supplied_component("supplied-repeated"); MAX_JSON_ENTRIES];
    let exact_budget = (MAX_JSON_ENTRIES * 2) as u64;

    let accepted = ContextManifest::new(
        Revision::FIRST,
        TokenBudget::new(exact_budget),
        policy.clone(),
        supplied.clone(),
    );
    let spec = RunSpec::new(parts_with_context(root.path(), accepted)).expect("exact budget");
    assert_eq!(
        spec.admission().context_manifest().policy().len(),
        MAX_JSON_ENTRIES
    );
    assert_eq!(
        spec.admission().context_manifest().supplied().len(),
        MAX_JSON_ENTRIES
    );

    let under_budgeted = ContextManifest::new(
        Revision::FIRST,
        TokenBudget::new(exact_budget - 1),
        policy,
        supplied,
    );
    assert_eq!(
        RunSpec::new(parts_with_context(root.path(), under_budgeted)).unwrap_err(),
        RunSpecError::FieldInvalid("context_manifest")
    );
}

#[test]
fn context_token_cap_arithmetic_overflow_refuses() {
    let root = TempDir::new("context-token-overflow");
    let manifest = ContextManifest::new(
        Revision::FIRST,
        TokenBudget::new(u64::MAX),
        vec![policy_component_with_token_cap("policy-max", u64::MAX)],
        vec![supplied_component_with_token_cap("supplied-one", 1)],
    );

    assert_eq!(
        RunSpec::new(parts_with_context(root.path(), manifest)).unwrap_err(),
        RunSpecError::FieldInvalid("context_manifest")
    );
}
