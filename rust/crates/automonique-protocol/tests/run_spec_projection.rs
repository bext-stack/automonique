// SPDX-License-Identifier: Elastic-2.0

//! Closed spelling controls for protocol-owned values nested by RunSpec.

use automonique_protocol::context::{ComponentClass, RedactionOutcome, SuppliedClass, TrustClass};
use automonique_protocol::host::HostLifetime;
use automonique_protocol::models::{
    ArtifactTransfer, ExecutorClass, RemoteCoordinate, WorkspaceTransfer,
};
use automonique_protocol::provider::CapabilityGroup;
use automonique_protocol::sandbox::{
    AllowlistClass, BudgetUnit, FilesystemAccess, IsolationRequirement, NetworkAccess, PathAccess,
    ProcessClass,
};
use automonique_protocol::workspace::IsolationKind;

#[test]
fn identity_workspace_and_provider_enum_spellings_round_trip_exactly() {
    for value in HostLifetime::ALL {
        assert_eq!(HostLifetime::from_spelling(value.as_str()), Some(value));
    }
    assert_eq!(HostLifetime::from_spelling("Attempt"), None);

    for value in IsolationKind::ALL {
        assert_eq!(IsolationKind::from_spelling(value.as_str()), Some(value));
    }
    assert_eq!(IsolationKind::from_spelling("read-only-snapshot"), None);

    for value in CapabilityGroup::ALL {
        assert_eq!(CapabilityGroup::from_spelling(value.as_str()), Some(value));
    }
    assert_eq!(CapabilityGroup::from_spelling("unknown"), None);
}

#[test]
fn context_and_sandbox_enum_spellings_round_trip_exactly() {
    for value in TrustClass::ALL {
        assert_eq!(TrustClass::from_spelling(value.as_str()), Some(value));
    }
    assert_eq!(TrustClass::from_spelling("Policy"), None);

    for value in RedactionOutcome::ALL {
        assert_eq!(RedactionOutcome::from_spelling(value.as_str()), Some(value));
    }
    assert_eq!(RedactionOutcome::from_spelling("not_scanned"), None);

    for value in SuppliedClass::ALL {
        assert_eq!(SuppliedClass::from_spelling(value.as_str()), Some(value));
    }
    assert_eq!(SuppliedClass::from_spelling("system_policy"), None);

    for value in ComponentClass::ALL {
        assert_eq!(ComponentClass::from_spelling(value.as_str()), Some(value));
    }
    assert_eq!(ComponentClass::from_spelling("unknown"), None);

    for value in PathAccess::ALL {
        assert_eq!(PathAccess::from_spelling(value.as_str()), Some(value));
    }
    assert_eq!(PathAccess::from_spelling("write"), None);

    for value in FilesystemAccess::ALL {
        assert_eq!(FilesystemAccess::from_spelling(value.as_str()), Some(value));
    }
    assert_eq!(FilesystemAccess::from_spelling("all"), None);

    for value in NetworkAccess::ALL {
        assert_eq!(NetworkAccess::from_spelling(value.as_str()), Some(value));
    }
    assert_eq!(NetworkAccess::from_spelling("allowed"), None);

    for value in AllowlistClass::ALL {
        assert_eq!(AllowlistClass::from_spelling(value.as_str()), Some(value));
    }
    assert_eq!(AllowlistClass::from_spelling("server"), None);

    for value in ProcessClass::ALL {
        assert_eq!(ProcessClass::from_spelling(value.as_str()), Some(value));
    }
    assert_eq!(ProcessClass::from_spelling("provider"), None);

    for value in BudgetUnit::ALL {
        assert_eq!(BudgetUnit::from_spelling(value.as_str()), Some(value));
    }
    assert_eq!(BudgetUnit::from_spelling("bytes"), None);

    for value in IsolationRequirement::ALL {
        assert_eq!(
            IsolationRequirement::from_spelling(value.as_str()),
            Some(value)
        );
    }
    assert_eq!(IsolationRequirement::from_spelling("isolated"), None);
}

#[test]
fn executor_and_transfer_parsers_preserve_payload_rules() {
    for value in ExecutorClass::FIELDLESS {
        assert_eq!(
            ExecutorClass::from_spelling(value.as_str(), None),
            Some(value)
        );
    }
    let coordinate = RemoteCoordinate::new("vendor", "resource-1").expect("valid coordinate");
    assert_eq!(
        ExecutorClass::from_spelling("remote", Some(coordinate.clone())),
        Some(ExecutorClass::Remote(coordinate.clone()))
    );
    assert_eq!(ExecutorClass::from_spelling("remote", None), None);
    assert_eq!(
        ExecutorClass::from_spelling("local", Some(coordinate)),
        None
    );
    assert_eq!(ExecutorClass::from_spelling("unknown", None), None);

    for value in WorkspaceTransfer::ALL {
        assert_eq!(
            WorkspaceTransfer::from_spelling(value.as_str()),
            Some(value)
        );
    }
    assert_eq!(WorkspaceTransfer::from_spelling("copy"), None);

    for value in ArtifactTransfer::ALL {
        assert_eq!(ArtifactTransfer::from_spelling(value.as_str()), Some(value));
    }
    assert_eq!(ArtifactTransfer::from_spelling("push"), None);
}
