// SPDX-License-Identifier: Elastic-2.0

//! R1-18 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-18.md`.

use automonique_protocol::sandbox::{
    AdoptionOutcome, ApprovalRequest, Budget, BudgetUnit, Disposition, EnforcementAttestation,
    FilesystemAccess, NetworkAccess, ProfileOrdering, ProviderControlEgress, ReuseOutcome,
    SandboxError, SandboxProfile, SandboxSpec, SandboxSpecParts, ToolWorkloadEgress,
    ViolationClass, adopt_host, evaluate_reuse,
};

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

fn spec_for(profile: SandboxProfile) -> SandboxSpec {
    SandboxSpec::compile(SandboxSpecParts {
        profile,
        policy_digest: "sha256:policy",
        tenant: "acme",
        workspace_context: "ws-1",
        provider_control_egress: ProviderControlEgress::brokered(NetworkAccess::BrokeredNamed),
        tool_workload_egress: ToolWorkloadEgress::denied(),
        required_features: &["cgroup_v2", "landlock_abi_3"],
        budgets: vec![Budget::new(BudgetUnit::Milliseconds, 60_000).expect("valid budget")],
        prohibited_capabilities: &["CAP_SYS_ADMIN"],
    })
    .expect("valid spec")
}

fn attestation(seccomp: &str) -> EnforcementAttestation {
    EnforcementAttestation::new(
        "ns-1",
        "cgroup-1",
        "boot-1",
        "landlock-1",
        seccomp,
        "egress-1",
    )
    .expect("valid attestation")
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
        let egress = profile(
            "workspace-egress",
            FilesystemAccess::IsolatedWritable,
            NetworkAccess::BrokeredNamed,
        );

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
}

mod spec_completeness {
    use super::*;

    #[test]
    fn every_declared_field_is_present_on_a_compiled_spec() {
        let spec = spec_for(workspace_offline());
        assert_eq!(spec.profile().id(), "workspace-offline");
        assert_eq!(spec.policy_digest(), "sha256:policy");
        assert_eq!(spec.tenant(), "acme");
        assert_eq!(spec.required_features().len(), 2);
        assert_eq!(spec.budgets().len(), 1);
        assert_eq!(spec.prohibited_capabilities(), ["CAP_SYS_ADMIN"]);
        assert_eq!(
            spec.provider_control_egress().access(),
            NetworkAccess::BrokeredNamed
        );
        assert_eq!(spec.tool_workload_egress().access(), NetworkAccess::Denied);
    }

    #[test]
    fn a_spec_cannot_be_compiled_with_an_empty_required_field() {
        let attempt = SandboxSpec::compile(SandboxSpecParts {
            profile: workspace_offline(),
            policy_digest: "",
            tenant: "acme",
            workspace_context: "ws-1",
            provider_control_egress: ProviderControlEgress::denied(),
            tool_workload_egress: ToolWorkloadEgress::denied(),
            required_features: &[],
            budgets: Vec::new(),
            prohibited_capabilities: &[],
        });
        assert_eq!(
            attempt.expect_err("empty digest").category(),
            "field_invalid"
        );
    }
}

mod no_silent_downgrade {
    use super::*;

    #[test]
    fn a_missing_required_feature_refuses_naming_it() {
        let spec = spec_for(workspace_offline());
        assert_eq!(
            spec.admit_on(&["cgroup_v2"]).expect_err("landlock absent"),
            SandboxError::RequiredEnforcementMissing {
                feature: "landlock_abi_3".to_owned(),
            }
        );
        spec.admit_on(&["cgroup_v2", "landlock_abi_3"])
            .expect("every feature present");
    }

    #[test]
    fn there_is_no_weaker_outcome_to_fall_back_to() {
        // `admit_on` returns unit or an error. It has no success variant
        // carrying a reduced profile, so a downgrade is not expressible as a
        // return value.
        let spec = spec_for(workspace_offline());
        for host in [vec![], vec!["cgroup_v2"], vec!["landlock_abi_3"]] {
            let outcome = spec.admit_on(&host);
            assert!(outcome.is_err(), "an incomplete host must not admit");
            assert_eq!(
                outcome.expect_err("refused").category(),
                "required_enforcement_missing"
            );
        }
    }
}

mod egress_split {
    use super::*;

    #[test]
    fn the_two_policies_are_independent_values() {
        let spec = spec_for(workspace_offline());
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
}

mod attestation_comparison {
    use super::*;

    #[test]
    fn a_matching_attestation_is_adopted() {
        let recorded = attestation("seccomp-1");
        assert_eq!(
            adopt_host(Some(&recorded), Some(&attestation("seccomp-1"))),
            AdoptionOutcome::Adopted
        );
    }

    #[test]
    fn a_missing_or_differing_attestation_quarantines() {
        let recorded = attestation("seccomp-1");
        assert_eq!(
            adopt_host(Some(&recorded), Some(&attestation("seccomp-2"))),
            AdoptionOutcome::Quarantined,
            "a changed enforcement digest is not adoptable"
        );
        assert_eq!(
            adopt_host(Some(&recorded), None),
            AdoptionOutcome::Quarantined
        );
        assert_eq!(
            adopt_host(None, Some(&recorded)),
            AdoptionOutcome::Quarantined,
            "an unrecorded boundary cannot be adopted by observing one"
        );
        assert_eq!(adopt_host(None, None), AdoptionOutcome::Quarantined);
    }
}

mod narrowing_only_reuse {
    use super::*;

    #[test]
    fn identical_and_narrower_requests_reuse() {
        let existing = spec_for(profile(
            "workspace-egress",
            FilesystemAccess::IsolatedWritable,
            NetworkAccess::BrokeredNamed,
        ));
        assert_eq!(
            evaluate_reuse(&existing, &existing),
            ReuseOutcome::Reuse,
            "an identical request reuses"
        );

        let narrower = spec_for(profile(
            "observe",
            FilesystemAccess::ReadOnlySnapshot,
            NetworkAccess::Denied,
        ));
        assert_eq!(evaluate_reuse(&existing, &narrower), ReuseOutcome::Reuse);
    }

    #[test]
    fn a_wider_request_requires_a_new_host() {
        let existing = spec_for(workspace_offline());
        let wider = spec_for(profile(
            "workspace-egress",
            FilesystemAccess::WritableWithGrants,
            NetworkAccess::BrokeredAny,
        ));
        assert_eq!(
            evaluate_reuse(&existing, &wider),
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
        let sideways = spec_for(profile(
            "b",
            FilesystemAccess::ReadOnlySnapshot,
            NetworkAccess::BrokeredAny,
        ));
        assert_eq!(
            evaluate_reuse(&existing, &sideways),
            ReuseOutcome::RequiresNewHost
        );
    }

    #[test]
    fn a_different_tenant_or_workspace_always_requires_a_new_host() {
        let existing = spec_for(workspace_offline());
        let other_tenant = SandboxSpec::compile(SandboxSpecParts {
            profile: workspace_offline(),
            policy_digest: "sha256:policy",
            tenant: "globex",
            workspace_context: "ws-1",
            provider_control_egress: ProviderControlEgress::brokered(NetworkAccess::BrokeredNamed),
            tool_workload_egress: ToolWorkloadEgress::denied(),
            required_features: &["cgroup_v2", "landlock_abi_3"],
            budgets: Vec::new(),
            prohibited_capabilities: &[],
        })
        .expect("valid spec");
        assert_eq!(
            evaluate_reuse(&existing, &other_tenant),
            ReuseOutcome::RequiresNewHost
        );
    }

    #[test]
    fn widening_the_control_plane_requires_a_new_host() {
        let existing = spec_for(workspace_offline());
        let wider_control = SandboxSpec::compile(SandboxSpecParts {
            profile: workspace_offline(),
            policy_digest: "sha256:policy",
            tenant: "acme",
            workspace_context: "ws-1",
            provider_control_egress: ProviderControlEgress::brokered(NetworkAccess::BrokeredAny),
            tool_workload_egress: ToolWorkloadEgress::denied(),
            required_features: &["cgroup_v2", "landlock_abi_3"],
            budgets: Vec::new(),
            prohibited_capabilities: &[],
        })
        .expect("valid spec");
        assert_eq!(
            evaluate_reuse(&existing, &wider_control),
            ReuseOutcome::RequiresNewHost
        );
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
        for unit in [
            BudgetUnit::Milliseconds,
            BudgetUnit::MemoryBytes,
            BudgetUnit::Processes,
            BudgetUnit::TempBytes,
        ] {
            Budget::new(unit, unit.ceiling()).expect("exactly at the ceiling");
            let error = Budget::new(unit, unit.ceiling() + 1).expect_err("over the ceiling");
            assert_eq!(error.category(), "budget_out_of_range");
            assert!(error.to_string().contains(unit.as_str()));
        }
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
