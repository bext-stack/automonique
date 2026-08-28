// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::platform::{
    ResourceAuthority, ResourceCoordinate, ResourceId, ResourceKind,
};
use automonique_protocol::platform_v2::{ProjectId, UserWorkspaceId};
use automonique_protocol::platform_v2_attention::*;
use automonique_protocol::platform_v2_attention_api::*;
use automonique_protocol::primitives::Revision;

fn revision(value: u64) -> Revision {
    Revision::new(value).unwrap()
}
fn source(kind: AttentionSourceKind) -> AttentionSource {
    AttentionSource::new(kind, AttentionSourceId::new("provider-feed-1").unwrap())
}
fn session(id: &str) -> automonique_protocol::platform_v2::V1SessionRef {
    platform_session(ResourceCoordinate::new(
        ResourceAuthority::Automonique,
        ResourceKind::Session,
        ResourceId::new(id).unwrap(),
    ))
    .unwrap()
}
fn item(
    id: &str,
    item_revision: u64,
    observed_at_ms: u64,
    state: AttentionItemState,
    reason: AttentionItemReason,
) -> AttentionItem {
    AttentionItem::new(
        AttentionItemId::new(id).unwrap(),
        revision(item_revision),
        observed_at_ms,
        state,
        reason,
        true,
        vec![
            AttentionAgentId::new("agent-root").unwrap(),
            AttentionAgentId::new("agent-child").unwrap(),
        ],
        Some(session("session-1")),
    )
    .unwrap()
}
fn snapshot(snapshot_revision: u64, previous_revision: Option<u64>) -> AttentionSourceSnapshot {
    AttentionSourceSnapshot::new(
        source(AttentionSourceKind::ProviderSession),
        ProjectId::new("project-1").unwrap(),
        UserWorkspaceId::new("workspace-1").unwrap(),
        revision(snapshot_revision),
        previous_revision.map(revision),
        2_000 + snapshot_revision,
        vec![item(
            "attention-1",
            snapshot_revision,
            2_000,
            AttentionItemState::NeedsYou,
            AttentionItemReason::ApprovalRequired,
        )],
    )
    .unwrap()
}

#[test]
fn every_reason_has_one_closed_compatible_state() {
    for reason in AttentionItemReason::ALL {
        assert!(
            AttentionItem::new(
                AttentionItemId::new(format!("item-{}", reason.as_str())).unwrap(),
                Revision::FIRST,
                1,
                reason.state(),
                reason,
                false,
                Vec::new(),
                Some(session("session-1")),
            )
            .is_ok()
        );
        for state in AttentionItemState::ALL {
            if state != reason.state() {
                assert!(
                    AttentionItem::new(
                        AttentionItemId::new("item").unwrap(),
                        Revision::FIRST,
                        1,
                        state,
                        reason,
                        false,
                        Vec::new(),
                        Some(session("session-1")),
                    )
                    .is_err()
                );
            }
        }
    }
}

#[test]
fn provider_items_require_an_exact_platform_session_and_other_sources_forbid_it() {
    let provider_without_session = AttentionItem::new(
        AttentionItemId::new("item").unwrap(),
        Revision::FIRST,
        1,
        AttentionItemState::Working,
        AttentionItemReason::AgentWorking,
        false,
        Vec::new(),
        None,
    )
    .unwrap();
    assert!(
        AttentionSourceSnapshot::new(
            source(AttentionSourceKind::ProviderSession),
            ProjectId::new("project").unwrap(),
            UserWorkspaceId::new("workspace").unwrap(),
            Revision::FIRST,
            None,
            1,
            vec![provider_without_session],
        )
        .is_err()
    );

    let review_with_session = item(
        "item",
        1,
        1,
        AttentionItemState::Blocked,
        AttentionItemReason::Conflict,
    );
    assert!(
        AttentionSourceSnapshot::new(
            source(AttentionSourceKind::Review),
            ProjectId::new("project").unwrap(),
            UserWorkspaceId::new("workspace").unwrap(),
            Revision::FIRST,
            None,
            1,
            vec![review_with_session],
        )
        .is_err()
    );

    assert!(
        platform_session(ResourceCoordinate::new(
            ResourceAuthority::Provider,
            ResourceKind::Run,
            ResourceId::new("not-a-session").unwrap(),
        ))
        .is_err()
    );
    assert!(
        platform_session(ResourceCoordinate::new(
            ResourceAuthority::Client,
            ResourceKind::Session,
            ResourceId::new("client-local-session").unwrap(),
        ))
        .is_err()
    );
}

#[test]
fn nested_paths_are_bounded_ordered_and_acyclic() {
    let duplicate = AttentionAgentId::new("same-agent").unwrap();
    assert!(
        AttentionItem::new(
            AttentionItemId::new("item").unwrap(),
            Revision::FIRST,
            1,
            AttentionItemState::Working,
            AttentionItemReason::AgentWorking,
            false,
            vec![duplicate.clone(), duplicate],
            Some(session("session-1")),
        )
        .is_err()
    );
    assert!(
        AttentionItem::new(
            AttentionItemId::new("item").unwrap(),
            Revision::FIRST,
            1,
            AttentionItemState::Working,
            AttentionItemReason::AgentWorking,
            false,
            (0..=MAX_NESTED_AGENT_DEPTH)
                .map(|index| AttentionAgentId::new(format!("agent-{index}")).unwrap())
                .collect(),
            Some(session("session-1")),
        )
        .is_err()
    );
}

#[test]
fn snapshots_are_complete_sorted_source_scoped_replacements() {
    assert!(
        AttentionSourceSnapshot::new(
            source(AttentionSourceKind::ProviderSession),
            ProjectId::new("project").unwrap(),
            UserWorkspaceId::new("workspace").unwrap(),
            revision(2),
            None,
            10,
            Vec::new(),
        )
        .is_err()
    );
    assert!(
        AttentionSourceSnapshot::new(
            source(AttentionSourceKind::ProviderSession),
            ProjectId::new("project").unwrap(),
            UserWorkspaceId::new("workspace").unwrap(),
            revision(2),
            Some(revision(2)),
            10,
            Vec::new(),
        )
        .is_err()
    );
    assert!(
        AttentionSourceSnapshot::new(
            source(AttentionSourceKind::ProviderSession),
            ProjectId::new("project").unwrap(),
            UserWorkspaceId::new("workspace").unwrap(),
            revision(3),
            Some(revision(2)),
            10,
            vec![
                item(
                    "z",
                    1,
                    1,
                    AttentionItemState::Done,
                    AttentionItemReason::Complete
                ),
                item(
                    "a",
                    1,
                    1,
                    AttentionItemState::Done,
                    AttentionItemReason::Complete
                ),
            ],
        )
        .is_err()
    );
}

#[test]
fn successor_validation_refuses_scope_drift_time_regression_and_same_revision_edits() {
    let current = snapshot(1, None);
    let next = snapshot(3, Some(1));
    current.validate_successor(&next).unwrap();

    let wrong_previous = snapshot(3, Some(2));
    assert!(current.validate_successor(&wrong_previous).is_err());

    let changed_without_item_revision = AttentionSourceSnapshot::new(
        source(AttentionSourceKind::ProviderSession),
        ProjectId::new("project-1").unwrap(),
        UserWorkspaceId::new("workspace-1").unwrap(),
        revision(2),
        Some(revision(1)),
        2_002,
        vec![item(
            "attention-1",
            1,
            2_000,
            AttentionItemState::Blocked,
            AttentionItemReason::Conflict,
        )],
    )
    .unwrap();
    assert!(
        current
            .validate_successor(&changed_without_item_revision)
            .is_err()
    );

    let other_workspace = AttentionSourceSnapshot::new(
        source(AttentionSourceKind::ProviderSession),
        ProjectId::new("project-1").unwrap(),
        UserWorkspaceId::new("workspace-2").unwrap(),
        revision(2),
        Some(revision(1)),
        2_002,
        Vec::new(),
    )
    .unwrap();
    assert!(current.validate_successor(&other_workspace).is_err());

    let regressed_item_observation = AttentionSourceSnapshot::new(
        source(AttentionSourceKind::ProviderSession),
        ProjectId::new("project-1").unwrap(),
        UserWorkspaceId::new("workspace-1").unwrap(),
        revision(2),
        Some(revision(1)),
        2_002,
        vec![item(
            "attention-1",
            2,
            1_999,
            AttentionItemState::NeedsYou,
            AttentionItemReason::ApprovalRequired,
        )],
    )
    .unwrap();
    assert!(
        current
            .validate_successor(&regressed_item_observation)
            .is_err()
    );
}

#[test]
fn request_and_snapshot_use_exact_canonical_closed_documents() {
    let request = AttentionReadRequest::new(
        source(AttentionSourceKind::ProviderSession),
        ProjectId::new("project-1").unwrap(),
        UserWorkspaceId::new("workspace-1").unwrap(),
    );
    let request_bytes = encode_attention_read_request(&request).unwrap();
    assert_eq!(
        decode_attention_read_request(&request_bytes).unwrap(),
        request
    );

    let fixture = decode_attention_source_snapshot(include_bytes!(
        "../fixtures/platform-v2-attention-v1.json"
    ))
    .unwrap();
    let canonical = encode_attention_source_snapshot(&fixture).unwrap();
    assert_eq!(
        decode_attention_source_snapshot(&canonical).unwrap(),
        fixture
    );
    let wire = String::from_utf8(canonical).unwrap();
    assert!(wire.contains("\"semantics\":\"atomic_replace\""));
    for forbidden in ["pane", "tab", "window", "host_path", "terminal"] {
        assert!(!wire.contains(forbidden));
    }
}

#[test]
fn decoding_fails_closed_on_unknown_fields_enums_schema_and_coordinate_kind() {
    let valid =
        String::from_utf8(encode_attention_source_snapshot(&snapshot(1, None)).unwrap()).unwrap();
    let unknown_field = valid.replacen("{", "{\"tab_id\":\"local\",", 1);
    assert!(decode_attention_source_snapshot(unknown_field.as_bytes()).is_err());
    assert!(
        decode_attention_source_snapshot(
            valid
                .replace(
                    PLATFORM_ATTENTION_SCHEMA_V1,
                    "automonique.platform/attention/v2"
                )
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        decode_attention_source_snapshot(
            valid.replace("\"needs_you\"", "\"surprising\"").as_bytes()
        )
        .is_err()
    );
    assert!(
        decode_attention_source_snapshot(
            valid
                .replace("\"kind\":\"session\"", "\"kind\":\"run\"")
                .as_bytes()
        )
        .is_err()
    );
    assert!(matches!(
        decode_attention_source_snapshot(&vec![b'x'; MAX_ATTENTION_SNAPSHOT_CANONICAL_BYTES + 1]),
        Err(AttentionApiError::FrameTooLarge)
    ));
}
