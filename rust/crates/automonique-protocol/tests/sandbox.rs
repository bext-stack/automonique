// SPDX-License-Identifier: Elastic-2.0

//! R1-18 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-18.md`.

use automonique_protocol::identity::Actor;
use automonique_protocol::models::ProviderAccountId;
use automonique_protocol::primitives::Revision;
use automonique_protocol::sandbox::{
    AllowlistClass, AllowlistEntry, ApprovalRequest, Budget, BudgetQuantities, BudgetUnit, Budgets,
    CgroupId, CredentialDelivery, CredentialDescriptor, CredentialDescriptors, Digest,
    DigestDomain, Disposition, EgressPolicyDigest, EnforcementAttestation,
    EnforcementAttestationParts, ExecutionAllowlists, ExecutionBackendId, ExternalDaemonContext,
    FilesystemAccess, HostFeature, IsolationRequirement, KernelBootId, LandlockAbi,
    LandlockAttestation, LandlockRulesetDigest, NamespaceIdentity, NamespaceKind, NestedIsolation,
    NetworkAccess, PathAccess, PathGrant, PathGrants, PolicyDigest, ProcessClass, ProcessGroupId,
    ProfileOrdering, ProhibitedCapabilities, ProviderControlEgress, QuarantineReason,
    QuarantinedHost, QuarantinedOperation, RequiredFeature, RequiredFeatures, ReuseOutcome,
    SandboxError, SandboxPath, SandboxProfile, SandboxSpec, SandboxSpecParts, SeccompDigest,
    SupervisorProperty, TaggedDigest, ToolWorkloadEgress, ViolationClass, adopt_host,
    evaluate_reuse,
};

/// One row of a coverage table: a requirement clause and the probe that reads
/// it back off a compiled spec.
type SpecProbe = (&'static str, fn(&SandboxSpec) -> bool);

/// One row of a variation table: the field varied and how to vary it.
type AttestationVariation = (&'static str, fn(&mut AttestationFixture));

/// One row of a variation table: the axis varied and how to vary it.
type PartsVariation = (&'static str, fn(&mut SandboxSpecParts));

/// A synthetic but well-formed digest body.
fn digest_text(seed: u8) -> String {
    format!("sha256:{seed:064x}")
}

/// A synthetic digest in whichever domain the call site needs.
fn tagged<D: DigestDomain>(seed: u8) -> TaggedDigest<D> {
    TaggedDigest::parse(&digest_text(seed)).expect("valid digest")
}

fn path(value: &str) -> SandboxPath {
    SandboxPath::new(value).expect("valid path")
}

fn actor(tenant: &str, id: &str) -> Actor {
    Actor::new(tenant, id).expect("valid actor")
}

fn account(id: &str) -> ProviderAccountId {
    ProviderAccountId::new(id).expect("valid provider account")
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("non-zero revision")
}

fn profile(id: &str, filesystem: FilesystemAccess, network: NetworkAccess) -> SandboxProfile {
    SandboxProfile::new(id, 1, filesystem, ToolWorkloadEgress::brokered(network))
        .expect("valid profile")
}

fn workspace_offline() -> SandboxProfile {
    profile(
        "workspace-offline",
        FilesystemAccess::IsolatedWritable,
        NetworkAccess::Denied,
    )
}

fn workspace_egress() -> SandboxProfile {
    profile(
        "workspace-egress",
        FilesystemAccess::IsolatedWritable,
        NetworkAccess::BrokeredNamed,
    )
}

fn grants() -> PathGrants {
    PathGrants::declare(&[
        PathGrant::new("/workspace/attempt-1", PathAccess::ReadWrite).expect("valid grant"),
        PathGrant::new("/opt/toolchain", PathAccess::ReadOnly).expect("valid grant"),
    ])
    .expect("valid grants")
}

fn allowlists() -> ExecutionAllowlists {
    ExecutionAllowlists::declare(&[
        AllowlistEntry::new(AllowlistClass::Executable, "cargo").expect("valid entry"),
        AllowlistEntry::new(AllowlistClass::Interpreter, "python3").expect("valid entry"),
        AllowlistEntry::new(AllowlistClass::Tool, "fs.read").expect("valid entry"),
        AllowlistEntry::new(AllowlistClass::McpServer, "docs").expect("valid entry"),
        AllowlistEntry::new(AllowlistClass::Companion, "watcher").expect("valid entry"),
    ])
    .expect("valid allowlists")
}

fn credentials() -> CredentialDescriptors {
    CredentialDescriptors::declare(&[CredentialDescriptor::new(
        "provider-token",
        ProcessClass::ProviderAdapter,
    )
    .expect("valid descriptor")])
    .expect("valid descriptors")
}

fn quantities() -> BudgetQuantities {
    BudgetQuantities {
        cgroup_memory_bytes: 2 * 1024 * 1024 * 1024,
        cgroup_cpu_millicores: 2_000,
        rlimit_processes: 512,
        rlimit_descriptors: 1_024,
        timeout_millis: 60_000,
        temporary_storage_bytes: 1024 * 1024 * 1024,
        spool_bytes: 512 * 1024 * 1024,
        artifact_bytes: 4 * 1024 * 1024 * 1024,
    }
}

fn budgets() -> Budgets {
    Budgets::declare(quantities()).expect("valid budgets")
}

fn required_features() -> RequiredFeatures {
    RequiredFeatures::declare(&[
        RequiredFeature::new("cgroup_v2", &[tagged::<_>(11)]).expect("valid feature"),
        RequiredFeature::new("landlock_abi_3", &[tagged::<_>(12)]).expect("valid feature"),
    ])
    .expect("valid features")
}

fn prohibited() -> ProhibitedCapabilities {
    ProhibitedCapabilities::declare(&["CAP_SYS_ADMIN", "CAP_NET_ADMIN"]).expect("valid set")
}

/// The spec every case in this suite varies from.
fn base_parts(profile: SandboxProfile) -> SandboxSpecParts {
    SandboxSpecParts {
        profile,
        policy_digest: tagged(1),
        actor: actor("acme", "ada"),
        provider_account: account("acct-eu-1"),
        workspace_context: tagged(2),
        base_revision: revision(7),
        path_grants: grants(),
        allowlists: allowlists(),
        provider_control_egress: ProviderControlEgress::brokered(NetworkAccess::BrokeredNamed),
        tool_workload_egress: ToolWorkloadEgress::denied(),
        credentials: credentials(),
        budgets: budgets(),
        required_features: required_features(),
        nested_isolation: NestedIsolation::new(
            IsolationRequirement::SeparateChildBoundary,
            IsolationRequirement::SeparateChildBoundary,
        ),
        approval_revision: revision(3),
        prohibited_capabilities: prohibited(),
    }
}

fn spec_for(profile: SandboxProfile) -> SandboxSpec {
    SandboxSpec::compile(base_parts(profile)).expect("valid spec")
}

fn compiled(parts: SandboxSpecParts) -> SandboxSpec {
    SandboxSpec::compile(parts).expect("valid spec")
}

fn host_feature(name: &str, implementation: u8) -> HostFeature {
    HostFeature::new(name, tagged(implementation)).expect("valid host feature")
}

/// Every value an [`EnforcementAttestation`] is built from, so one case can
/// vary exactly one field.
#[derive(Clone, Debug)]
struct AttestationFixture {
    resolved_paths: Vec<SandboxPath>,
    namespaces: Vec<NamespaceIdentity>,
    process_group: u32,
    cgroup: String,
    backend: String,
    kernel_boot: String,
    supervisor_properties: Vec<SupervisorProperty>,
    landlock_abi: u8,
    landlock_ruleset: u8,
    seccomp: u8,
    egress: u8,
    credential_delivery: CredentialDelivery,
    external_daemon: Option<(String, u8)>,
}

impl AttestationFixture {
    fn base() -> Self {
        Self {
            resolved_paths: vec![path("/workspace/attempt-1"), path("/opt/toolchain")],
            namespaces: vec![
                NamespaceIdentity::new(NamespaceKind::Mount, 4_026_531_840)
                    .expect("valid namespace"),
                NamespaceIdentity::new(NamespaceKind::Network, 4_026_531_841)
                    .expect("valid namespace"),
            ],
            process_group: 4242,
            cgroup: "/automonique.slice/run-1.scope".to_owned(),
            backend: "scope-1".to_owned(),
            kernel_boot: "6.8.0/boot-1".to_owned(),
            supervisor_properties: vec![
                SupervisorProperty::NoNewPrivileges,
                SupervisorProperty::PrivateTmp,
            ],
            landlock_abi: 3,
            landlock_ruleset: 21,
            seccomp: 22,
            egress: 23,
            credential_delivery: CredentialDelivery::SealedDescriptor,
            external_daemon: Some(("jcode".to_owned(), 24)),
        }
    }

    fn record(&self) -> EnforcementAttestation {
        EnforcementAttestation::record(EnforcementAttestationParts {
            resolved_paths: &self.resolved_paths,
            namespaces: &self.namespaces,
            process_group: ProcessGroupId::new(self.process_group).expect("valid process group"),
            cgroup: CgroupId::new(self.cgroup.as_str()).expect("valid cgroup"),
            backend: ExecutionBackendId::new(self.backend.as_str()).expect("valid backend"),
            kernel_boot: KernelBootId::new(self.kernel_boot.as_str()).expect("valid kernel boot"),
            supervisor_properties: &self.supervisor_properties,
            landlock: LandlockAttestation::new(
                LandlockAbi::new(self.landlock_abi).expect("valid abi"),
                tagged::<_>(self.landlock_ruleset),
            ),
            seccomp_digest: tagged::<_>(self.seccomp),
            egress_digest: tagged::<_>(self.egress),
            credential_delivery: self.credential_delivery,
            external_daemon: self.external_daemon.as_ref().map(|(daemon, seed)| {
                ExternalDaemonContext::new(daemon, tagged::<_>(*seed)).expect("valid daemon")
            }),
        })
        .expect("valid attestation")
    }
}

mod profile_ordering {
    use super::*;

    #[test]
    fn the_comparison_is_a_partial_order_not_a_boolean() {
        let observe = profile(
            "observe",
            FilesystemAccess::ReadOnlySnapshot,
            NetworkAccess::Denied,
        );
        let offline = workspace_offline();
        let egress = workspace_egress();

        assert_eq!(observe.compare(&observe), ProfileOrdering::Identical);
        assert_eq!(observe.compare(&offline), ProfileOrdering::Narrower);
        assert_eq!(offline.compare(&observe), ProfileOrdering::Wider);
        assert_eq!(offline.compare(&egress), ProfileOrdering::Narrower);
    }

    #[test]
    fn incomparable_is_reachable_and_preserved() {
        // More filesystem, less network. Neither profile dominates, and
        // answering "not narrower" would license a reuse that widens one axis.
        let more_files = profile(
            "a",
            FilesystemAccess::WritableWithGrants,
            NetworkAccess::Denied,
        );
        let more_network = profile(
            "b",
            FilesystemAccess::ReadOnlySnapshot,
            NetworkAccess::BrokeredAny,
        );
        assert_eq!(
            more_files.compare(&more_network),
            ProfileOrdering::Incomparable
        );
        assert_eq!(
            more_network.compare(&more_files),
            ProfileOrdering::Incomparable
        );
    }

    #[test]
    fn combining_disagreeing_axes_never_resolves_to_the_permissive_one() {
        assert_eq!(
            ProfileOrdering::Narrower.combine(ProfileOrdering::Wider),
            ProfileOrdering::Incomparable
        );
        assert_eq!(
            ProfileOrdering::Wider.combine(ProfileOrdering::Narrower),
            ProfileOrdering::Incomparable
        );
        assert_eq!(
            ProfileOrdering::Identical.combine(ProfileOrdering::Narrower),
            ProfileOrdering::Narrower
        );
        assert_eq!(
            ProfileOrdering::Incomparable.combine(ProfileOrdering::Identical),
            ProfileOrdering::Incomparable
        );
    }
}

mod spec_completeness {
    use super::*;

    /// The field list of `plan/contracts/R1-18.md` § Sandbox contract, which
    /// restates `docs/product-plan/requirements/sandbox-management.md`
    /// § Policy compilation, with the accessor that observes each clause on a
    /// compiled spec.
    ///
    /// The row is "every listed field is required, proven by a coverage table
    /// against the requirement". This is that table: each entry names the
    /// requirement clause and reads the value back off the compiled spec.
    const SPEC_FIELD_COVERAGE: [SpecProbe; 20] = [
        ("profile ID", |spec| {
            spec.profile().id() == "workspace-egress"
        }),
        ("profile version", |spec| spec.profile().version() == 1),
        ("complete policy digest", |spec| {
            spec.policy_digest().digest().hex().ends_with('1')
                && spec.policy_digest().digest().hex().len() == 64
        }),
        ("tenant", |spec| spec.tenant() == "acme"),
        ("actor", |spec| spec.actor().id() == "ada"),
        ("provider account", |spec| {
            spec.provider_account().as_str() == "acct-eu-1"
        }),
        ("workspace security-context hash", |spec| {
            spec.workspace_context().digest().hex().ends_with('2')
        }),
        ("immutable base revision", |spec| {
            spec.base_revision().get() == 7
        }),
        ("readable path grants", |spec| {
            spec.path_grants().readable().count() == 2
        }),
        ("writable path grants", |spec| {
            spec.path_grants().writable().count() == 1
        }),
        (
            "executable, interpreter, tool, MCP and companion allowlists",
            |spec| {
                AllowlistClass::ALL
                    .into_iter()
                    .all(|class| spec.allowlists().class(class).len() == 1)
                    && spec.tool_allowlist().len() == 1
            },
        ),
        ("provider-control network policy", |spec| {
            spec.provider_control_egress().access() == NetworkAccess::BrokeredNamed
        }),
        ("tool-workload network policy", |spec| {
            spec.tool_workload_egress().access() == NetworkAccess::Denied
        }),
        (
            "credential descriptors with their exact process class",
            |spec| {
                spec.credential_descriptors().len() == 1
                    && spec.credential_descriptors()[0].recipient() == ProcessClass::ProviderAdapter
            },
        ),
        (
            "cgroup, rlimit, timeout, temporary-storage, spool and artifact budgets",
            |spec| {
                let budgets = spec.budgets();
                budgets.all().len() == 8
                    && budgets.cgroup_memory().unit() == BudgetUnit::MemoryBytes
                    && budgets.cgroup_cpu().unit() == BudgetUnit::CpuMillicores
                    && budgets.rlimit_processes().unit() == BudgetUnit::Processes
                    && budgets.rlimit_descriptors().unit() == BudgetUnit::FileDescriptors
                    && budgets.timeout().quantity() == 60_000
                    && budgets.temporary_storage().unit() == BudgetUnit::TempBytes
                    && budgets.spool().unit() == BudgetUnit::SpoolBytes
                    && budgets.artifact().unit() == BudgetUnit::ArtifactBytes
            },
        ),
        ("required kernel and backend features", |spec| {
            spec.required_features().len() == 2 && spec.required_features()[0].name() == "cgroup_v2"
        }),
        ("accepted enforcement implementation digests", |spec| {
            spec.enforcement_implementation_digests().count() == 2
        }),
        ("nested isolation requirements", |spec| {
            spec.nested_isolation().nested_tools() == IsolationRequirement::SeparateChildBoundary
                && spec.nested_isolation().extensions()
                    == IsolationRequirement::SeparateChildBoundary
        }),
        ("approval and policy revision", |spec| {
            spec.approval_revision().get() == 3
        }),
        ("prohibited-capability set", |spec| {
            spec.prohibited_capabilities()
                .iter()
                .map(|capability| capability.as_str())
                .collect::<Vec<_>>()
                == ["CAP_SYS_ADMIN", "CAP_NET_ADMIN"]
        }),
    ];

    #[test]
    fn every_field_the_requirement_lists_is_observable_on_a_compiled_spec() {
        let spec = spec_for(workspace_egress());
        for (clause, observe) in SPEC_FIELD_COVERAGE {
            assert!(observe(&spec), "{clause} is not carried by the spec");
        }
    }

    #[test]
    fn the_coverage_table_names_every_clause_once() {
        let mut clauses: Vec<&str> = SPEC_FIELD_COVERAGE
            .iter()
            .map(|(clause, _)| *clause)
            .collect();
        let total = clauses.len();
        clauses.sort_unstable();
        clauses.dedup();
        assert_eq!(clauses.len(), total, "a clause is listed twice");
        assert_eq!(total, 20);
    }

    #[test]
    fn the_spec_tenant_cannot_disagree_with_its_actor() {
        // The tenant is read off the actor, which has no constructor without
        // one, so the two are one value rather than two that must be kept in
        // step.
        let spec = spec_for(workspace_egress());
        assert_eq!(spec.tenant(), spec.actor().tenant());
    }

    #[test]
    fn a_component_cannot_be_built_from_an_invalid_value() {
        assert_eq!(
            PolicyDigest::parse("sha256:policy")
                .expect_err("not a digest")
                .category(),
            "digest_length"
        );
        assert_eq!(
            Digest::parse("landlock-1")
                .expect_err("no algorithm")
                .category(),
            "missing_algorithm"
        );
        assert_eq!(
            Digest::parse(&format!("md5:{}", "0".repeat(32)))
                .expect_err("unknown algorithm")
                .category(),
            "unknown_algorithm"
        );
        assert_eq!(
            Digest::parse(&format!("sha256:{}", "A".repeat(64)))
                .expect_err("uppercase")
                .category(),
            "not_lowercase_hex"
        );
        assert_eq!(
            SandboxPath::new("workspace/attempt-1")
                .expect_err("relative")
                .category(),
            "not_absolute"
        );
        assert_eq!(
            SandboxPath::new("/workspace/../etc")
                .expect_err("traversal")
                .category(),
            "traversal_component"
        );
        assert_eq!(
            SandboxPath::new("/workspace//attempt")
                .expect_err("empty component")
                .category(),
            "empty_component"
        );
        assert_eq!(
            AllowlistEntry::new(AllowlistClass::Tool, "")
                .expect_err("empty name")
                .category(),
            "field_invalid"
        );
        assert_eq!(
            RequiredFeatures::declare(&[])
                .expect_err("a spec requiring no enforcement admits anywhere")
                .category(),
            "field_invalid"
        );
        assert_eq!(
            RequiredFeature::new("cgroup_v2", &[])
                .expect_err("no implementation could satisfy it")
                .category(),
            "field_invalid"
        );
        assert_eq!(
            ProcessGroupId::new(0).expect_err("zero").category(),
            "not_positive"
        );
        assert_eq!(
            LandlockAbi::new(0)
                .expect_err("zero means unavailable")
                .category(),
            "not_positive"
        );
        assert_eq!(
            NamespaceIdentity::new(NamespaceKind::Mount, 0)
                .expect_err("zero inode")
                .category(),
            "not_positive"
        );
    }

    #[test]
    fn a_duplicate_entry_is_refused_rather_than_silently_merged() {
        let duplicate_path = PathGrants::declare(&[
            PathGrant::new("/workspace/attempt-1", PathAccess::ReadOnly).expect("valid"),
            PathGrant::new("/workspace/attempt-1", PathAccess::ReadWrite).expect("valid"),
        ])
        .expect_err("one path, two meanings");
        assert_eq!(duplicate_path.category(), "duplicate_entry");

        let duplicate_credential = CredentialDescriptors::declare(&[
            CredentialDescriptor::new("token", ProcessClass::ProviderAdapter).expect("valid"),
            CredentialDescriptor::new("token", ProcessClass::ToolProcess).expect("valid"),
        ])
        .expect_err("one credential, two recipients");
        assert_eq!(duplicate_credential.category(), "duplicate_entry");
    }

    #[test]
    fn a_spec_cannot_grant_more_than_the_profile_it_compiles_from() {
        // The profile is a minimum contract, so a wider spec is a capability
        // added without a new plan revision.
        let mut parts = base_parts(workspace_offline());
        parts.tool_workload_egress = ToolWorkloadEgress::brokered(NetworkAccess::BrokeredNamed);
        let refused = SandboxSpec::compile(parts).expect_err("wider than its profile");
        assert_eq!(refused.category(), "widens_profile");
        assert!(refused.to_string().contains("tool_workload_egress"));

        let mut read_only = base_parts(profile(
            "observe",
            FilesystemAccess::ReadOnlySnapshot,
            NetworkAccess::Denied,
        ));
        read_only.path_grants =
            PathGrants::declare(&[
                PathGrant::new("/workspace/attempt-1", PathAccess::ReadWrite).expect("valid"),
            ])
            .expect("valid grants");
        let refused =
            SandboxSpec::compile(read_only).expect_err("a write under a read-only profile");
        assert_eq!(refused.category(), "widens_profile");

        // The same literal at or below the profile compiles.
        let mut narrower = base_parts(workspace_offline());
        narrower.tool_workload_egress = ToolWorkloadEgress::denied();
        SandboxSpec::compile(narrower).expect("a narrower spec compiles");
    }
}

mod no_silent_downgrade {
    use super::*;

    #[test]
    fn a_missing_required_feature_refuses_naming_it() {
        let spec = spec_for(workspace_offline());
        assert_eq!(
            spec.admit_on(&[host_feature("cgroup_v2", 11)])
                .expect_err("landlock absent"),
            SandboxError::RequiredEnforcementMissing {
                feature: "landlock_abi_3".to_owned(),
            }
        );
        spec.admit_on(&[
            host_feature("cgroup_v2", 11),
            host_feature("landlock_abi_3", 12),
        ])
        .expect("every feature present");
    }

    #[test]
    fn there_is_no_weaker_outcome_to_fall_back_to() {
        // `admit_on` returns unit or an error. It has no success variant
        // carrying a reduced profile, so a downgrade is not expressible as a
        // return value. The two-feature power set is exhausted here.
        let spec = spec_for(workspace_offline());
        let cgroup = host_feature("cgroup_v2", 11);
        let landlock = host_feature("landlock_abi_3", 12);
        for host in [Vec::new(), vec![cgroup.clone()], vec![landlock.clone()]] {
            let outcome = spec.admit_on(&host);
            assert!(outcome.is_err(), "an incomplete host must not admit");
            assert_eq!(
                outcome.expect_err("refused").category(),
                "required_enforcement_missing"
            );
        }
        spec.admit_on(&[cgroup, landlock])
            .expect("the complete host admits");
    }

    #[test]
    fn an_unaccepted_implementation_of_a_present_feature_refuses() {
        // The feature is there; the implementation behind it is not one the
        // spec reviewed. Accepting it would be a downgrade the spec never
        // declared.
        let spec = spec_for(workspace_offline());
        let refusal = spec
            .admit_on(&[
                host_feature("cgroup_v2", 11),
                host_feature("landlock_abi_3", 99),
            ])
            .expect_err("unaccepted implementation");
        assert_eq!(refusal.category(), "enforcement_implementation_rejected");
        assert!(refusal.to_string().contains("landlock_abi_3"));
        assert!(refusal.to_string().contains(&digest_text(99)));
    }
}

mod egress_split {
    use super::*;

    #[test]
    fn the_two_policies_are_independent_values() {
        let spec = spec_for(workspace_egress());
        // The control plane may reach the broker while tool traffic may not.
        assert_ne!(
            spec.provider_control_egress().access(),
            spec.tool_workload_egress().access()
        );
        // The compile-fail proof that one cannot be assigned to the other lives
        // in the library doc tests, where it executes.
        assert_eq!(
            ProviderControlEgress::denied().access(),
            NetworkAccess::Denied
        );
        assert_eq!(ToolWorkloadEgress::denied().access(), NetworkAccess::Denied);
    }

    #[test]
    fn widening_the_control_plane_does_not_widen_the_tool_workload() {
        let mut parts = base_parts(workspace_egress());
        parts.provider_control_egress = ProviderControlEgress::brokered(NetworkAccess::BrokeredAny);
        let spec = compiled(parts);
        assert_eq!(
            spec.provider_control_egress().access(),
            NetworkAccess::BrokeredAny
        );
        assert_eq!(spec.tool_workload_egress().access(), NetworkAccess::Denied);
    }
}

mod attestation_comparison {
    use super::*;

    #[test]
    fn a_matching_attestation_is_adopted() {
        let recorded = AttestationFixture::base().record();
        let observed = AttestationFixture::base().record();
        let outcome = adopt_host(Some(&recorded), Some(&observed));
        let adopted = outcome.adopted().expect("matching digests adopt");
        assert_eq!(adopted.attestation(), &recorded);
        assert!(outcome.quarantined().is_none());
    }

    #[test]
    fn a_missing_or_differing_attestation_quarantines() {
        let recorded = AttestationFixture::base().record();
        let mut varied = AttestationFixture::base();
        varied.seccomp = 91;
        let observed = varied.record();

        for (case, outcome, expected) in [
            (
                "changed seccomp digest",
                adopt_host(Some(&recorded), Some(&observed)),
                QuarantineReason::Mismatch {
                    field: "seccomp_digest",
                },
            ),
            (
                "recorded but not observed",
                adopt_host(Some(&recorded), None),
                QuarantineReason::NoObservedAttestation,
            ),
            (
                "observed but never recorded",
                adopt_host(None, Some(&recorded)),
                QuarantineReason::NoRecordedAttestation,
            ),
            (
                "nothing at all",
                adopt_host(None, None),
                QuarantineReason::NothingAttested,
            ),
        ] {
            let quarantined = outcome
                .quarantined()
                .unwrap_or_else(|| panic!("{case} must not adopt"));
            assert_eq!(quarantined.reason(), expected, "{case}");
            assert!(outcome.adopted().is_none(), "{case}");
        }
    }

    #[test]
    fn every_recorded_field_is_compared() {
        // A field adoption does not compare is a field an attacker can vary
        // freely, so each one is varied alone and must name itself.
        let variations: [AttestationVariation; 12] = [
            ("resolved_paths", |fixture| {
                fixture.resolved_paths.push(path("/workspace/extra"));
            }),
            ("namespaces", |fixture| {
                fixture.namespaces[1] =
                    NamespaceIdentity::new(NamespaceKind::Network, 4_026_531_999)
                        .expect("valid namespace");
            }),
            ("process_group", |fixture| fixture.process_group = 5150),
            ("cgroup", |fixture| {
                fixture.cgroup = "/other.slice/run-2.scope".to_owned();
            }),
            ("backend", |fixture| fixture.backend = "scope-2".to_owned()),
            ("kernel_boot", |fixture| {
                fixture.kernel_boot = "6.8.0/boot-2".to_owned();
            }),
            ("supervisor_properties", |fixture| {
                fixture.supervisor_properties.clear();
            }),
            ("landlock", |fixture| fixture.landlock_abi = 4),
            ("seccomp_digest", |fixture| fixture.seccomp = 91),
            ("egress_digest", |fixture| fixture.egress = 92),
            ("credential_delivery", |fixture| {
                fixture.credential_delivery = CredentialDelivery::EnvironmentVariable;
            }),
            ("external_daemon", |fixture| fixture.external_daemon = None),
        ];

        let recorded = AttestationFixture::base().record();
        let mut named: Vec<&str> = Vec::new();
        for (field, vary) in variations {
            let mut fixture = AttestationFixture::base();
            vary(&mut fixture);
            let observed = fixture.record();
            assert_ne!(recorded, observed, "{field} was not actually varied");
            let quarantined = adopt_host(Some(&recorded), Some(&observed))
                .quarantined()
                .unwrap_or_else(|| panic!("{field} varied and still adopted"));
            assert_eq!(
                quarantined.reason(),
                QuarantineReason::Mismatch { field },
                "the difference in {field} was reported as something else"
            );
            named.push(field);
        }
        assert_eq!(named, EnforcementAttestation::COMPARED_FIELDS.to_vec());

        // The Landlock ruleset digest lives inside the same field as the ABI;
        // varying it alone is still caught.
        let mut ruleset = AttestationFixture::base();
        ruleset.landlock_ruleset = 93;
        assert_eq!(
            adopt_host(Some(&recorded), Some(&ruleset.record()))
                .quarantined()
                .expect("a changed ruleset does not adopt")
                .reason(),
            QuarantineReason::Mismatch { field: "landlock" }
        );
    }

    #[test]
    fn a_quarantined_host_carries_the_only_operations_it_permits() {
        let recorded = AttestationFixture::base().record();
        let quarantined = adopt_host(Some(&recorded), None)
            .quarantined()
            .expect("no observed object");
        assert_eq!(
            quarantined.permitted_operations(),
            [
                QuarantinedOperation::Observe,
                QuarantinedOperation::Reconcile,
                QuarantinedOperation::Cancel,
            ]
        );
        assert_eq!(
            QuarantinedHost::PERMITTED_OPERATIONS.len(),
            QuarantinedOperation::ALL.len()
        );
        // The set is the whole of the type: there is no fourth operation to
        // permit or forbid. The compile-fail proof that no other variant can be
        // named lives in the library doc tests, where it executes.
        assert_eq!(QuarantinedOperation::ALL.len(), 3);
        let mut spellings: Vec<&str> = QuarantinedOperation::ALL
            .iter()
            .map(|operation| operation.as_str())
            .collect();
        spellings.sort_unstable();
        assert_eq!(spellings, ["cancel", "observe", "reconcile"]);
    }

    #[test]
    fn attestation_is_compared_and_not_reconstructed() {
        // The adopted host borrows the *recorded* attestation. Nothing in the
        // adopted value comes from the observation, so a host cannot be adopted
        // onto what it reports about itself.
        let recorded = AttestationFixture::base().record();
        let observed = AttestationFixture::base().record();
        let adopted = adopt_host(Some(&recorded), Some(&observed))
            .adopted()
            .expect("identical attestations adopt");
        assert!(std::ptr::eq(adopted.attestation(), &recorded));
    }

    #[test]
    fn an_attestation_cannot_record_two_namespaces_of_one_kind() {
        let mut fixture = AttestationFixture::base();
        fixture.namespaces = vec![
            NamespaceIdentity::new(NamespaceKind::Mount, 1).expect("valid"),
            NamespaceIdentity::new(NamespaceKind::Mount, 2).expect("valid"),
        ];
        let refused = EnforcementAttestation::record(EnforcementAttestationParts {
            resolved_paths: &fixture.resolved_paths,
            namespaces: &fixture.namespaces,
            process_group: ProcessGroupId::new(fixture.process_group).expect("valid"),
            cgroup: CgroupId::new(fixture.cgroup.as_str()).expect("valid"),
            backend: ExecutionBackendId::new(fixture.backend.as_str()).expect("valid"),
            kernel_boot: KernelBootId::new(fixture.kernel_boot.as_str()).expect("valid"),
            supervisor_properties: &fixture.supervisor_properties,
            landlock: LandlockAttestation::new(
                LandlockAbi::new(fixture.landlock_abi).expect("valid"),
                tagged::<_>(fixture.landlock_ruleset),
            ),
            seccomp_digest: tagged::<_>(fixture.seccomp),
            egress_digest: tagged::<_>(fixture.egress),
            credential_delivery: fixture.credential_delivery,
            external_daemon: None,
        })
        .expect_err("a process is in one namespace of each kind");
        assert_eq!(refused.category(), "duplicate_entry");
    }

    #[test]
    fn every_attested_field_is_readable() {
        let attestation = AttestationFixture::base().record();
        assert_eq!(attestation.resolved_paths().len(), 2);
        assert_eq!(attestation.namespaces().len(), 2);
        assert_eq!(attestation.process_group().get(), 4242);
        assert_eq!(
            attestation.cgroup().as_str(),
            "/automonique.slice/run-1.scope"
        );
        assert_eq!(attestation.backend().as_str(), "scope-1");
        assert_eq!(attestation.kernel_boot().as_str(), "6.8.0/boot-1");
        assert_eq!(attestation.supervisor_properties().len(), 2);
        assert_eq!(attestation.landlock_abi().version(), 3);
        assert_eq!(
            attestation.landlock_ruleset_digest(),
            &tagged::<_>(21) as &LandlockRulesetDigest
        );
        assert_eq!(
            attestation.seccomp_digest(),
            &tagged::<_>(22) as &SeccompDigest
        );
        assert_eq!(
            attestation.egress_digest(),
            &tagged::<_>(23) as &EgressPolicyDigest
        );
        assert_eq!(
            attestation.credential_delivery_mode(),
            CredentialDelivery::SealedDescriptor
        );
        assert_eq!(
            attestation.external_daemon().expect("recorded").daemon(),
            "jcode"
        );
        assert_eq!(EnforcementAttestation::COMPARED_FIELDS.len(), 12);
    }
}

mod narrowing_only_reuse {
    use super::*;

    #[test]
    fn identical_and_narrower_requests_reuse() {
        let existing = spec_for(workspace_egress());
        assert_eq!(
            evaluate_reuse(&existing, &existing),
            ReuseOutcome::Reuse,
            "an identical request reuses"
        );

        let narrower = spec_for(workspace_offline());
        assert_eq!(evaluate_reuse(&existing, &narrower), ReuseOutcome::Reuse);
    }

    #[test]
    fn a_wider_request_requires_a_new_host() {
        let existing = spec_for(workspace_offline());
        let mut wider = base_parts(profile(
            "workspace-egress",
            FilesystemAccess::WritableWithGrants,
            NetworkAccess::BrokeredAny,
        ));
        wider.tool_workload_egress = ToolWorkloadEgress::brokered(NetworkAccess::BrokeredAny);
        assert_eq!(
            evaluate_reuse(&existing, &compiled(wider)),
            ReuseOutcome::RequiresNewHost
        );
    }

    #[test]
    fn an_incomparable_request_requires_a_new_host() {
        // It narrows one axis and widens another, so it is not a narrowing.
        let existing = spec_for(profile(
            "a",
            FilesystemAccess::WritableWithGrants,
            NetworkAccess::Denied,
        ));
        let mut sideways = base_parts(profile(
            "b",
            FilesystemAccess::ReadOnlySnapshot,
            NetworkAccess::BrokeredAny,
        ));
        sideways.path_grants =
            PathGrants::declare(&[
                PathGrant::new("/opt/toolchain", PathAccess::ReadOnly).expect("valid")
            ])
            .expect("valid grants");
        assert_eq!(
            evaluate_reuse(&existing, &compiled(sideways)),
            ReuseOutcome::RequiresNewHost
        );
    }

    #[test]
    fn a_different_subject_always_requires_a_new_host() {
        let existing = spec_for(workspace_egress());
        let subjects: [PartsVariation; 4] = [
            ("tenant", |parts| parts.actor = actor("globex", "ada")),
            ("actor", |parts| parts.actor = actor("acme", "mallory")),
            ("provider account", |parts| {
                parts.provider_account = account("acct-us-2");
            }),
            ("workspace context", |parts| {
                parts.workspace_context = tagged(42);
            }),
        ];
        for (subject, vary) in subjects {
            let mut parts = base_parts(workspace_egress());
            vary(&mut parts);
            assert_eq!(
                evaluate_reuse(&existing, &compiled(parts)),
                ReuseOutcome::RequiresNewHost,
                "a different {subject} is not a narrowing"
            );
        }
    }

    #[test]
    fn widening_any_authority_axis_requires_a_new_host() {
        let existing = spec_for(workspace_egress());
        let widenings: [PartsVariation; 9] = [
            ("profile", |parts| {
                parts.profile = profile(
                    "workspace-egress",
                    FilesystemAccess::WritableWithGrants,
                    NetworkAccess::BrokeredNamed,
                );
            }),
            ("provider control egress", |parts| {
                parts.provider_control_egress =
                    ProviderControlEgress::brokered(NetworkAccess::BrokeredAny);
            }),
            ("tool workload egress", |parts| {
                parts.tool_workload_egress =
                    ToolWorkloadEgress::brokered(NetworkAccess::BrokeredNamed);
            }),
            ("path grants", |parts| {
                parts.path_grants = PathGrants::declare(&[
                    PathGrant::new("/workspace/attempt-1", PathAccess::ReadWrite).expect("valid"),
                    PathGrant::new("/opt/toolchain", PathAccess::ReadWrite).expect("valid"),
                ])
                .expect("valid grants");
            }),
            ("allowlists", |parts| {
                parts.allowlists = ExecutionAllowlists::declare(&[
                    AllowlistEntry::new(AllowlistClass::Executable, "cargo").expect("valid"),
                    AllowlistEntry::new(AllowlistClass::Interpreter, "python3").expect("valid"),
                    AllowlistEntry::new(AllowlistClass::Tool, "fs.read").expect("valid"),
                    AllowlistEntry::new(AllowlistClass::Tool, "fs.write").expect("valid"),
                    AllowlistEntry::new(AllowlistClass::McpServer, "docs").expect("valid"),
                    AllowlistEntry::new(AllowlistClass::Companion, "watcher").expect("valid"),
                ])
                .expect("valid allowlists");
            }),
            ("credential descriptors", |parts| {
                parts.credentials = CredentialDescriptors::declare(&[
                    CredentialDescriptor::new("provider-token", ProcessClass::ProviderAdapter)
                        .expect("valid"),
                    CredentialDescriptor::new("github-token", ProcessClass::ToolProcess)
                        .expect("valid"),
                ])
                .expect("valid descriptors");
            }),
            ("budgets", |parts| {
                let mut raised = quantities();
                raised.timeout_millis = 120_000;
                parts.budgets = Budgets::declare(raised).expect("valid budgets");
            }),
            ("required features", |parts| {
                parts.required_features = RequiredFeatures::declare(&[RequiredFeature::new(
                    "cgroup_v2",
                    &[tagged::<_>(11)],
                )
                .expect("valid")])
                .expect("valid features");
            }),
            ("prohibited capabilities", |parts| {
                parts.prohibited_capabilities =
                    ProhibitedCapabilities::declare(&["CAP_SYS_ADMIN"]).expect("valid set");
            }),
        ];
        for (axis, widen) in widenings {
            let mut parts = base_parts(workspace_egress());
            widen(&mut parts);
            let requested = compiled(parts);
            assert_ne!(
                requested.compare_authority(&existing),
                ProfileOrdering::Narrower,
                "{axis} was not actually widened"
            );
            assert_eq!(
                evaluate_reuse(&existing, &requested),
                ReuseOutcome::RequiresNewHost,
                "widening {axis} must not reuse the host"
            );
        }
    }

    #[test]
    fn narrowing_any_authority_axis_still_reuses() {
        let existing = spec_for(workspace_egress());
        let narrowings: [PartsVariation; 8] = [
            ("profile", |parts| parts.profile = workspace_offline()),
            ("provider control egress", |parts| {
                parts.provider_control_egress = ProviderControlEgress::denied();
            }),
            ("path grants", |parts| {
                parts.path_grants = PathGrants::declare(&[PathGrant::new(
                    "/workspace/attempt-1",
                    PathAccess::ReadWrite,
                )
                .expect("valid")])
                .expect("valid grants");
            }),
            ("allowlists", |parts| {
                parts.allowlists = ExecutionAllowlists::declare(&[
                    AllowlistEntry::new(AllowlistClass::Executable, "cargo").expect("valid"),
                    AllowlistEntry::new(AllowlistClass::Interpreter, "python3").expect("valid"),
                    AllowlistEntry::new(AllowlistClass::Tool, "fs.read").expect("valid"),
                    AllowlistEntry::new(AllowlistClass::McpServer, "docs").expect("valid"),
                ])
                .expect("valid allowlists");
            }),
            ("credential descriptors", |parts| {
                parts.credentials = CredentialDescriptors::declare(&[]).expect("valid descriptors");
            }),
            ("budgets", |parts| {
                let mut lowered = quantities();
                lowered.timeout_millis = 30_000;
                parts.budgets = Budgets::declare(lowered).expect("valid budgets");
            }),
            ("required features", |parts| {
                parts.required_features = RequiredFeatures::declare(&[
                    RequiredFeature::new("cgroup_v2", &[tagged::<_>(11)]).expect("valid"),
                    RequiredFeature::new("landlock_abi_3", &[tagged::<_>(12)]).expect("valid"),
                    RequiredFeature::new("seccomp_v2", &[tagged::<_>(13)]).expect("valid"),
                ])
                .expect("valid features");
            }),
            ("prohibited capabilities", |parts| {
                parts.prohibited_capabilities = ProhibitedCapabilities::declare(&[
                    "CAP_SYS_ADMIN",
                    "CAP_NET_ADMIN",
                    "CAP_MKNOD",
                ])
                .expect("valid set");
            }),
        ];
        for (axis, narrow) in narrowings {
            let mut parts = base_parts(workspace_egress());
            narrow(&mut parts);
            let requested = compiled(parts);
            assert_eq!(
                requested.compare_authority(&existing),
                ProfileOrdering::Narrower,
                "{axis} was not actually narrowed"
            );
            assert_eq!(
                evaluate_reuse(&existing, &requested),
                ReuseOutcome::Reuse,
                "narrowing {axis} may reuse the host"
            );
        }
    }

    #[test]
    fn nested_isolation_narrows_upwards_and_widens_downwards() {
        let existing = spec_for(workspace_egress());
        let mut stricter = base_parts(workspace_egress());
        stricter.nested_isolation = NestedIsolation::new(
            IsolationRequirement::StrongerIsolation,
            IsolationRequirement::SeparateChildBoundary,
        );
        assert_eq!(
            evaluate_reuse(&existing, &compiled(stricter)),
            ReuseOutcome::Reuse
        );

        let mut weaker = base_parts(workspace_egress());
        weaker.nested_isolation = NestedIsolation::new(
            IsolationRequirement::HostBoundary,
            IsolationRequirement::SeparateChildBoundary,
        );
        assert_eq!(
            evaluate_reuse(&existing, &compiled(weaker)),
            ReuseOutcome::RequiresNewHost
        );
    }

    #[test]
    fn grants_can_only_ever_narrow() {
        let reviewed = grants();
        let greedy = PathGrants::declare(&[
            PathGrant::new("/workspace/attempt-1", PathAccess::ReadWrite).expect("valid"),
            PathGrant::new("/opt/toolchain", PathAccess::ReadWrite).expect("valid"),
            PathGrant::new("/etc/shadow", PathAccess::ReadOnly).expect("valid"),
        ])
        .expect("valid grants");

        let narrowed = reviewed.narrowed_to(&greedy);
        // The path the reviewed set never granted is absent, and the mode it
        // granted read-only stays read-only.
        assert_eq!(narrowed.len(), 2);
        assert!(narrowed.is_within(&reviewed));
        assert!(
            narrowed
                .as_slice()
                .iter()
                .all(|grant| grant.path().as_str() != "/etc/shadow")
        );
        assert_eq!(
            narrowed
                .as_slice()
                .iter()
                .find(|grant| grant.path().as_str() == "/opt/toolchain")
                .expect("still granted")
                .access(),
            PathAccess::ReadOnly
        );

        // Intersection in either order is still within the reviewed set.
        assert!(greedy.narrowed_to(&reviewed).is_within(&reviewed));
    }
}

mod approval_cannot_widen {
    use super::*;

    #[test]
    fn an_approval_carries_a_request_and_no_specification() {
        let request = ApprovalRequest::new("command", "run the test suite").expect("valid");
        assert_eq!(request.class(), "command");
        assert_eq!(request.description(), "run the test suite");
        // The compile-fail proof that no accessor returns a spec lives in the
        // library doc tests, where it executes.
    }
}

mod budget_typing {
    use super::*;

    #[test]
    fn a_budget_carries_its_unit() {
        let budget = Budget::new(BudgetUnit::Processes, 64).expect("valid");
        assert_eq!(budget.unit(), BudgetUnit::Processes);
        assert_eq!(budget.quantity(), 64);
        assert_eq!(budget.unit().as_str(), "processes");
    }

    #[test]
    fn every_unit_enforces_its_own_ceiling() {
        assert_eq!(BudgetUnit::ALL.len(), 8);
        for unit in BudgetUnit::ALL {
            Budget::new(unit, unit.ceiling()).expect("exactly at the ceiling");
            let error = Budget::new(unit, unit.ceiling() + 1).expect_err("over the ceiling");
            assert_eq!(error.category(), "budget_out_of_range");
            assert!(error.to_string().contains(unit.as_str()));
        }
    }

    #[test]
    fn every_budget_category_is_declared_with_its_own_unit() {
        let budgets = budgets();
        let units: Vec<&str> = budgets
            .all()
            .into_iter()
            .map(|budget| budget.unit().as_str())
            .collect();
        assert_eq!(
            units,
            [
                "memory_bytes",
                "cpu_millicores",
                "processes",
                "file_descriptors",
                "milliseconds",
                "temp_bytes",
                "spool_bytes",
                "artifact_bytes",
            ]
        );
    }

    #[test]
    fn an_over_ceiling_category_refuses_naming_its_unit() {
        let mut over = quantities();
        over.spool_bytes = BudgetUnit::SpoolBytes.ceiling() + 1;
        let error = Budgets::declare(over).expect_err("over the spool ceiling");
        assert_eq!(error.category(), "budget_out_of_range");
        assert!(error.to_string().contains("spool_bytes"));
    }
}

mod violation_dispositions {
    use super::*;

    #[test]
    fn every_violation_class_has_a_disposition_and_none_continues() {
        assert_eq!(ViolationClass::ALL.len(), 4);
        for class in ViolationClass::ALL {
            let disposition = class.disposition();
            assert!(
                matches!(
                    disposition,
                    Disposition::TerminateRun
                        | Disposition::TerminateRunAndRecord
                        | Disposition::Quarantine
                ),
                "{} resolved to something permissive",
                class.as_str()
            );
            assert!(!disposition.as_str().is_empty());
        }
    }

    #[test]
    fn enforcement_loss_and_attestation_mismatch_quarantine() {
        assert_eq!(
            ViolationClass::EnforcementLoss.disposition(),
            Disposition::Quarantine
        );
        assert_eq!(
            ViolationClass::AttestationMismatch.disposition(),
            Disposition::Quarantine
        );
    }

    #[test]
    fn exhaustion_and_violation_are_distinct_classes() {
        assert_ne!(
            ViolationClass::BudgetExhaustion,
            ViolationClass::PolicyViolation
        );
        assert_ne!(
            ViolationClass::BudgetExhaustion.disposition(),
            ViolationClass::PolicyViolation.disposition(),
            "an exhausted budget is recorded; a policy violation is not the same event"
        );
    }

    #[test]
    fn class_spellings_are_distinct() {
        let mut spellings: Vec<&str> = ViolationClass::ALL
            .iter()
            .map(|class| class.as_str())
            .collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);
    }
}
