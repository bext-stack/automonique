// SPDX-License-Identifier: Elastic-2.0

//! R1-21 verification contract.

use automonique_protocol::tools::{
    ApprovalRequirement, ExtensionKind, ExtensionManifest, HookClass, SecretSource,
    SideEffectClass, ToolDescriptor, ToolError, ToolsetGrant, WorkflowCapability, search_tools,
};

fn tool(id: &str, side_effect: SideEffectClass) -> ToolDescriptor {
    ToolDescriptor::new(
        id,
        side_effect,
        ApprovalRequirement::PerInvocation,
        "sha256:d",
    )
    .expect("valid descriptor")
}

fn grant(ids: &[&str]) -> ToolsetGrant {
    ToolsetGrant::new(ids).expect("valid grant")
}

mod descriptor_completeness {
    use super::*;

    #[test]
    fn side_effect_and_approval_are_required_arguments() {
        let descriptor = tool("fs.write", SideEffectClass::WorkspaceWrite);
        assert_eq!(descriptor.side_effect(), SideEffectClass::WorkspaceWrite);
        assert_eq!(descriptor.approval(), ApprovalRequirement::PerInvocation);
        assert_eq!(descriptor.provenance_digest(), "sha256:d");
    }

    #[test]
    fn a_descriptor_requires_an_id_and_a_digest() {
        assert!(
            ToolDescriptor::new(
                "",
                SideEffectClass::ReadOnly,
                ApprovalRequirement::None,
                "d"
            )
            .is_err()
        );
        assert!(
            ToolDescriptor::new(
                "t",
                SideEffectClass::ReadOnly,
                ApprovalRequirement::None,
                ""
            )
            .is_err()
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
}

mod search_authorization {
    use super::*;

    #[test]
    fn search_returns_only_authorized_tools() {
        let registry = vec![
            tool("fs.read", SideEffectClass::ReadOnly),
            tool("fs.write", SideEffectClass::WorkspaceWrite),
            tool("shell.exec", SideEffectClass::PrivilegedRequest),
        ];
        let results = search_tools(&registry, &grant(&["fs.read", "fs.write"]), "");
        assert_eq!(results.matches(), ["fs.read", "fs.write"]);
        assert!(
            !results.matches().iter().any(|id| id == "shell.exec"),
            "search must not reveal an inaccessible tool"
        );
    }

    #[test]
    fn an_unauthorized_tool_is_absent_even_from_an_exact_query() {
        let registry = vec![tool("shell.exec", SideEffectClass::PrivilegedRequest)];
        let results = search_tools(&registry, &grant(&["fs.read"]), "shell.exec");
        assert!(
            results.matches().is_empty(),
            "naming a tool exactly must not confirm it exists"
        );
    }

    #[test]
    fn search_cannot_be_called_without_a_grant() {
        let registry = vec![tool("fs.read", SideEffectClass::ReadOnly)];
        assert!(
            search_tools(&registry, &grant(&[]), "fs")
                .matches()
                .is_empty()
        );
    }
}

mod workflow_bounds {
    use super::*;

    #[test]
    fn a_workflow_stops_at_its_call_ceiling() {
        let mut capability = WorkflowCapability::new(grant(&["fs.read"]), 2);
        capability.invoke("fs.read").expect("first call");
        capability.invoke("fs.read").expect("second call");
        assert_eq!(
            capability
                .invoke("fs.read")
                .expect_err("over the ceiling")
                .category(),
            "workflow_budget_exceeded"
        );
        assert_eq!(capability.calls_made(), 2);
    }

    #[test]
    fn a_workflow_cannot_reach_a_tool_outside_its_eligible_set() {
        let mut capability = WorkflowCapability::new(grant(&["fs.read"]), 10);
        assert!(
            capability.invoke("shell.exec").is_err(),
            "an ineligible tool is not reachable from a workflow"
        );
        assert_eq!(capability.calls_made(), 0);
    }
}

mod extension_manifests {
    use super::*;

    #[test]
    fn a_backend_extension_may_declare_capabilities() {
        let manifest =
            ExtensionManifest::new(ExtensionKind::Tool, "publisher", "sha256:d", &["fs.read"])
                .expect("valid manifest");
        assert_eq!(manifest.kind(), ExtensionKind::Tool);
        assert_eq!(manifest.backend_capabilities(), ["fs.read"]);
    }

    #[test]
    fn a_ui_extension_declaring_a_backend_capability_is_refused() {
        let error = ExtensionManifest::new(
            ExtensionKind::UserInterface,
            "publisher",
            "sha256:d",
            &["fs.read"],
        )
        .expect_err("a UI extension cannot hold backend authority");
        assert_eq!(
            error,
            ToolError::UiExtensionCannotHoldBackendCapability {
                capability: "fs.read".to_owned(),
            }
        );
    }

    #[test]
    fn a_ui_extension_without_backend_capabilities_is_fine() {
        ExtensionManifest::new(ExtensionKind::UserInterface, "publisher", "sha256:d", &[])
            .expect("a UI extension with no backend authority is valid");
    }
}

mod hook_class_powers {
    use super::*;

    #[test]
    fn no_hook_class_may_approve_widen_or_rewrite() {
        assert_eq!(HookClass::ALL.len(), 5);
        for class in HookClass::ALL {
            assert!(!class.may_approve(), "{} could approve", class.as_str());
            assert!(
                !class.may_widen_sandbox(),
                "{} could widen a sandbox",
                class.as_str()
            );
            assert!(
                !class.may_rewrite_history(),
                "{} could rewrite history",
                class.as_str()
            );
        }
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
}

mod secret_sealing {
    use super::*;

    #[test]
    fn a_command_helper_is_a_pinned_executable_with_closed_arguments() {
        let source =
            SecretSource::command("/usr/bin/pass-helper", &["show", "db"]).expect("valid source");
        assert_eq!(source.executable(), "/usr/bin/pass-helper");
        assert_eq!(source.arguments(), ["show", "db"]);
    }

    #[test]
    fn an_arbitrary_shell_string_is_refused() {
        for candidate in [
            "sh -c 'echo secret'",
            "helper; rm -rf /",
            "helper | tee /tmp/x",
            "helper && other",
        ] {
            assert_eq!(
                SecretSource::command(candidate, &[])
                    .expect_err("shell-shaped")
                    .category(),
                "secret_source_open_arguments",
                "{candidate} was accepted"
            );
        }
    }
}
