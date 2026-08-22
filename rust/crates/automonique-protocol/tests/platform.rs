// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::platform::*;
use automonique_protocol::primitives::{EpochMillis, Revision, ValueError};

fn coordinate(authority: ResourceAuthority, kind: ResourceKind) -> ResourceCoordinate {
    ResourceCoordinate::new(authority, kind, ResourceId::new("resource-1").unwrap())
}

#[test]
fn authorities_remain_distinct_in_resource_identity() {
    let local = coordinate(ResourceAuthority::Automonique, ResourceKind::Run);
    let global = coordinate(ResourceAuthority::AiOperations, ResourceKind::Run);
    assert_ne!(local, global);
    assert_eq!(
        ResourceAuthority::ALL.map(ResourceAuthority::as_str),
        [
            "ai_operations",
            "automonique",
            "github",
            "provider",
            "client"
        ]
    );
}

#[test]
fn every_transport_advertises_one_semantic_method_set() {
    let capabilities = Capabilities::platform_v1();
    assert_eq!(capabilities.methods, PlatformMethod::ALL);
    assert_eq!(capabilities.transports, PlatformTransport::ALL);
    assert_eq!(capabilities.protocol, PLATFORM_PROTOCOL);
    assert_eq!(capabilities.schema, PLATFORM_SCHEMA_V1);
}

#[test]
fn action_authority_is_enforced_before_execution() {
    let result = ExecuteRequest::new(
        PlatformAction::SubmitJob,
        coordinate(ResourceAuthority::Automonique, ResourceKind::Job),
        IdempotencyKey::new("retry-1").unwrap(),
        None,
        None,
    );
    assert_eq!(result, Err(PlatformError::AuthorityMismatch));
}

#[test]
fn opaque_values_are_bounded_and_control_free() {
    assert_eq!(
        ResourceId::new("x".repeat(MAX_PLATFORM_FIELD_BYTES + 1)),
        Err(ValueError::TooLong {
            max_bytes: MAX_PLATFORM_FIELD_BYTES,
            actual_bytes: MAX_PLATFORM_FIELD_BYTES + 1,
        })
    );
    assert_eq!(
        ReceiptId::new("bad\nvalue"),
        Err(ValueError::ControlCharacter)
    );
}

#[test]
fn snapshots_refuse_silent_truncation() {
    let resources = (0..=MAX_SNAPSHOT_RESOURCES)
        .map(|index| {
            ResourceCoordinate::new(
                ResourceAuthority::GitHub,
                ResourceKind::Issue,
                ResourceId::new(format!("issue-{index}")).unwrap(),
            )
        })
        .collect();
    assert_eq!(
        SnapshotRequest::new(resources),
        Err(PlatformError::TooManyResources)
    );
}

#[test]
fn receipt_outcomes_keep_unknown_and_rejection_separate() {
    assert_ne!(ReceiptOutcome::Unknown, ReceiptOutcome::Rejected);
    assert_eq!(
        ReceiptOutcome::ALL.map(ReceiptOutcome::as_str),
        [
            "accepted",
            "completed",
            "rejected",
            "conflict",
            "unknown",
            "resync_required",
        ]
    );

    let freshness = Freshness {
        state: FreshnessState::Fresh,
        observed_at: EpochMillis::EPOCH,
        revision: Revision::FIRST,
    };
    assert_eq!(freshness.revision, Revision::FIRST);
}

#[test]
fn security_sensitive_enums_fail_closed() {
    assert_eq!(
        ResourceAuthority::parse("dashboard"),
        Err(PlatformError::UnknownEnum {
            field: "resource_authority"
        })
    );
    assert_eq!(
        PlatformAction::parse("provider_direct_mutation"),
        Err(PlatformError::UnknownEnum {
            field: "platform_action"
        })
    );
}

#[test]
fn every_compatibility_adapter_names_consumers_and_removal_test() {
    for (index, adapter) in COMPATIBILITY_ADAPTERS.iter().enumerate() {
        assert!(!adapter.name.is_empty());
        assert!(!adapter.consumers.is_empty());
        assert!(!adapter.removal_test.is_empty());
        assert!(
            COMPATIBILITY_ADAPTERS[..index]
                .iter()
                .all(|earlier| earlier.name != adapter.name)
        );
    }
}
