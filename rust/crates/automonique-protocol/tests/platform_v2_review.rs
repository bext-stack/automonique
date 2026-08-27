// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::platform::IdempotencyKey;
use automonique_protocol::platform_v2::{UserWorkspaceId, WorkContextIdentity};
use automonique_protocol::platform_v2_review::*;
use automonique_protocol::platform_v2_review_api::*;
use automonique_protocol::primitives::Revision;

fn id<T, const MAX: usize>(value: &str) -> automonique_protocol::primitives::OpaqueId<T, MAX>
where
    T: automonique_protocol::primitives::IdDomain,
{
    automonique_protocol::primitives::OpaqueId::new(value).unwrap()
}
fn field(value: &str) -> ReviewField {
    ReviewField::new(value).unwrap()
}
fn text(value: &str) -> ReviewText {
    ReviewText::new(value).unwrap()
}
fn hunk_text(value: &str) -> ReviewHunkPreview {
    ReviewHunkPreview::new(value).unwrap()
}
fn rev(value: u64) -> Revision {
    Revision::new(value).unwrap()
}
fn authority(kind: ReviewAuthorityKind) -> ReviewAuthority {
    ReviewAuthority::new(kind, id("authority-1"))
}
fn freshness(revision: u64) -> ReviewFreshness {
    ReviewFreshness::new(
        ReviewFreshnessState::Fresh,
        rev(revision),
        1_800_000_000_000,
    )
    .unwrap()
}
fn workspace() -> WorkContextIdentity {
    WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("wc_user_1").unwrap())
}

fn snapshot() -> ReviewSnapshot {
    let anchor = ReviewAnchor::new(id("file-1"), id("hunk-1"), DiffSide::New, 11).unwrap();
    ReviewSnapshot::new(
        workspace(),
        rev(9),
        vec![
            ReviewFile::new(
                id("file-1"),
                RepositoryRelativePath::new("src/review.rs").unwrap(),
                DiffChangeKind::Modified,
                WorktreeFileState::Unstaged,
                PreviewMetadata::new(
                    PreviewKind::Text,
                    Some(field("text/plain")),
                    Some(120),
                    None,
                    None,
                    true,
                )
                .unwrap(),
                ConflictState::None,
                vec![
                    DiffHunk::new(
                        id("hunk-1"),
                        10,
                        2,
                        10,
                        3,
                        hunk_text("@@ -10,2 +10,3 @@ · sanitized preview"),
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
        ],
        vec![ReviewComment::new(
            id("comment-1"),
            rev(2),
            id("actor-1"),
            text("Please keep this typed."),
            anchor,
            CommentAgentState::Sent,
            true,
        )],
        vec![
            ReviewProposal::new(
                id("proposal-1"),
                ReviewProposalKind::Commit,
                vec![id("file-1")],
                Some(field("protocol: add review contract")),
            )
            .unwrap(),
        ],
        vec![
            CheckProjection::new(
                id("check-1"),
                CheckState::Passed,
                authority(ReviewAuthorityKind::Ci),
                freshness(7),
                true,
            )
            .unwrap(),
        ],
        ReviewStatusProjection::new(
            ReviewDecision::Pending,
            authority(ReviewAuthorityKind::Review),
            freshness(8),
        )
        .unwrap(),
        PullRequestProjection::new(
            Some(id("pr-1")),
            PullRequestState::Open,
            MergeReadiness::Ready,
            authority(ReviewAuthorityKind::PullRequest),
            freshness(8),
        )
        .unwrap(),
        DeliveryProjection::new(
            Some(id("delivery-1")),
            DeliveryState::Pending,
            authority(ReviewAuthorityKind::Delivery),
            freshness(7),
        )
        .unwrap(),
        AttentionProjection::new(
            AttentionState::NeedsYou,
            AttentionReason::ReviewRequested,
            1,
            rev(9),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn snapshot_is_exact_bounded_and_fixture_stable() {
    let snapshot = snapshot();
    let encoded = encode_review_snapshot(&snapshot).unwrap();
    assert_eq!(decode_review_snapshot(&encoded).unwrap(), snapshot);
    if std::env::var_os("AUTOMONIQUE_PROTOCOL_REGENERATE").is_some() {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/fixtures/platform-v2-review-v1.json"
            ),
            &encoded,
        )
        .unwrap();
    }
    assert_eq!(
        encoded.as_slice(),
        include_bytes!("../fixtures/platform-v2-review-v1.json")
    );
    assert!(encoded.len() < MAX_REVIEW_SNAPSHOT_CANONICAL_BYTES);
}

#[test]
fn preview_path_anchor_and_projection_invariants_fail_closed() {
    assert!(RepositoryRelativePath::new("/srv/private").is_err());
    assert!(RepositoryRelativePath::new("src/../secret").is_err());
    assert!(ReviewHunkPreview::new("x".repeat(MAX_REVIEW_HUNK_PREVIEW_BYTES + 1)).is_err());
    assert!(
        PreviewMetadata::new(
            PreviewKind::Html,
            Some(field("text/html")),
            Some(4),
            None,
            None,
            false
        )
        .is_err()
    );
    assert!(
        PreviewMetadata::new(
            PreviewKind::Binary,
            Some(field("application/octet-stream")),
            Some(4),
            None,
            None,
            false,
        )
        .is_ok()
    );
    assert!(
        PreviewMetadata::new(
            PreviewKind::Image,
            Some(field("image/png")),
            Some(4),
            Some(1),
            Some(1),
            true,
        )
        .is_ok()
    );
    assert!(
        PreviewMetadata::new(
            PreviewKind::Html,
            Some(field("text/html")),
            Some(4),
            None,
            None,
            true,
        )
        .is_ok()
    );
    assert_eq!(
        WorktreeFileState::parse("partially_staged").unwrap(),
        WorktreeFileState::PartiallyStaged
    );
    assert!(
        PreviewMetadata::new(
            PreviewKind::Image,
            Some(field("text/plain")),
            Some(4),
            Some(1),
            Some(1),
            true
        )
        .is_err()
    );
    assert!(ReviewAnchor::new(id("file"), id("hunk"), DiffSide::New, 0).is_err());
    assert!(
        AttentionProjection::new(AttentionState::Done, AttentionReason::Conflict, 0, rev(1))
            .is_err()
    );
    assert!(
        CheckProjection::new(
            id("check"),
            CheckState::Passed,
            authority(ReviewAuthorityKind::Review),
            freshness(1),
            true
        )
        .is_err()
    );
}

#[test]
fn comments_remain_anchored_and_sent_state_is_explicit() {
    let mut encoded = encode_review_snapshot(&snapshot()).unwrap();
    let text = String::from_utf8(encoded)
        .unwrap()
        .replace("\"hunk_id\":\"hunk-1\"", "\"hunk_id\":\"missing\"");
    encoded = text.into_bytes();
    assert!(matches!(
        decode_review_snapshot(&encoded),
        Err(ReviewApiError::Contract(ReviewContractError::AnchorInvalid))
    ));
    assert_eq!(
        snapshot().comments()[0].agent_state(),
        CommentAgentState::Sent
    );
}

fn request(
    action: ReviewAction,
    authentication: ReviewAuthentication,
    authority_kind: ReviewAuthorityKind,
) -> Result<ReviewActionRequest, ReviewContractError> {
    ReviewActionRequest::new(
        workspace(),
        rev(9),
        id("actor-1"),
        authentication,
        authority(authority_kind),
        IdempotencyKey::new("idem-1").unwrap(),
        action,
    )
}

#[test]
fn action_union_is_narrow_exact_revisioned_and_idempotent() {
    let actions = vec![
        (
            ReviewAction::AddComment {
                comment_id: id("comment-2"),
                anchor: ReviewAnchor::new(id("file-1"), id("hunk-1"), DiffSide::New, 12).unwrap(),
                body: text("One bounded comment"),
            },
            ReviewAuthorityKind::Review,
        ),
        (
            ReviewAction::SendCommentToAgent {
                comment_id: id("comment-1"),
                expected_comment_revision: rev(2),
            },
            ReviewAuthorityKind::Review,
        ),
        (
            ReviewAction::ApproveReview {
                expected_review_revision: rev(8),
            },
            ReviewAuthorityKind::Review,
        ),
        (
            ReviewAction::RerunCheck {
                check_id: id("check-1"),
                expected_check_revision: rev(7),
            },
            ReviewAuthorityKind::Ci,
        ),
        (
            ReviewAction::OpenPullRequest {
                title: field("Typed review"),
            },
            ReviewAuthorityKind::PullRequest,
        ),
        (
            ReviewAction::UpdatePullRequest {
                pull_request_id: id("pr-1"),
                expected_pull_request_revision: rev(8),
                title: field("Typed review v2"),
            },
            ReviewAuthorityKind::PullRequest,
        ),
        (
            ReviewAction::MergePullRequest {
                pull_request_id: id("pr-1"),
                expected_pull_request_revision: rev(8),
                expected_head_revision: field("0123456789abcdef"),
            },
            ReviewAuthorityKind::PullRequest,
        ),
    ];
    for (action, authority_kind) in actions {
        let request = request(action, ReviewAuthentication::UserSession, authority_kind).unwrap();
        assert_eq!(
            request,
            decode_review_action_request(&encode_review_action_request(&request).unwrap()).unwrap()
        );
        assert_eq!(request.expected_revision(), rev(9));
        assert_eq!(request.idempotency_key().as_str(), "idem-1");
    }
}

#[test]
fn action_and_ambiguous_receipt_fixtures_are_stable() {
    let action = ReviewAction::RerunCheck {
        check_id: id("check-1"),
        expected_check_revision: rev(7),
    };
    let request = request(
        action,
        ReviewAuthentication::UserSession,
        ReviewAuthorityKind::Ci,
    )
    .unwrap();
    let request_bytes = encode_review_action_request(&request).unwrap();
    let receipt = ReviewActionReceipt::new(
        id("receipt-1"),
        IdempotencyKey::new("idem-1").unwrap(),
        id("action-1"),
        id("actor-1"),
        ReviewReceiptOutcome::Unknown,
        None,
        None,
        ReviewReconciliation::PollReceipt,
    )
    .unwrap();
    let receipt_bytes = encode_review_action_receipt(&receipt).unwrap();
    if std::env::var_os("AUTOMONIQUE_PROTOCOL_REGENERATE").is_some() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/");
        std::fs::write(
            format!("{root}platform-v2-review-action-v1.json"),
            &request_bytes,
        )
        .unwrap();
        std::fs::write(
            format!("{root}platform-v2-review-receipt-v1.json"),
            &receipt_bytes,
        )
        .unwrap();
    }
    assert_eq!(
        request_bytes.as_slice(),
        include_bytes!("../fixtures/platform-v2-review-action-v1.json")
    );
    assert_eq!(
        receipt_bytes.as_slice(),
        include_bytes!("../fixtures/platform-v2-review-receipt-v1.json")
    );
}

#[test]
fn provider_session_never_authorizes_mutation_and_authority_is_action_specific() {
    let action = ReviewAction::RerunCheck {
        check_id: id("check-1"),
        expected_check_revision: rev(7),
    };
    assert_eq!(
        request(
            action.clone(),
            ReviewAuthentication::ProviderSession,
            ReviewAuthorityKind::Ci
        ),
        Err(ReviewContractError::AuthorityInvalid)
    );
    assert_eq!(
        request(
            action,
            ReviewAuthentication::UserSession,
            ReviewAuthorityKind::PullRequest
        ),
        Err(ReviewContractError::AuthorityInvalid)
    );
    let action = ReviewAction::MergePullRequest {
        pull_request_id: id("pr-1"),
        expected_pull_request_revision: rev(8),
        expected_head_revision: field("head"),
    };
    assert_eq!(
        request(
            action,
            ReviewAuthentication::ProviderSession,
            ReviewAuthorityKind::PullRequest
        ),
        Err(ReviewContractError::AuthorityInvalid)
    );
}

#[test]
fn ambiguous_writes_reconcile_by_receipt_without_replay() {
    let unknown = ReviewActionReceipt::new(
        id("receipt-1"),
        IdempotencyKey::new("idem-1").unwrap(),
        id("action-1"),
        id("actor-1"),
        ReviewReceiptOutcome::Unknown,
        None,
        None,
        ReviewReconciliation::PollReceipt,
    )
    .unwrap();
    let encoded = encode_review_action_receipt(&unknown).unwrap();
    assert_eq!(decode_review_action_receipt(&encoded).unwrap(), unknown);
    assert!(
        ReviewActionReceipt::new(
            id("receipt-1"),
            IdempotencyKey::new("idem-1").unwrap(),
            id("action-1"),
            id("actor-1"),
            ReviewReceiptOutcome::Unknown,
            None,
            None,
            ReviewReconciliation::Final
        )
        .is_err()
    );
    let conflict = ReviewActionReceipt::new(
        id("receipt-2"),
        IdempotencyKey::new("idem-2").unwrap(),
        id("action-2"),
        id("actor-1"),
        ReviewReceiptOutcome::Conflict,
        None,
        Some(rev(10)),
        ReviewReconciliation::Final,
    )
    .unwrap();
    assert_eq!(
        decode_review_action_receipt(&encode_review_action_receipt(&conflict).unwrap()).unwrap(),
        conflict
    );
}

#[test]
fn mixed_version_and_noncanonical_documents_are_refused() {
    let encoded = encode_review_snapshot(&snapshot()).unwrap();
    let v1 = String::from_utf8(encoded.clone())
        .unwrap()
        .replace("\"platform_version\":2", "\"platform_version\":1")
        .into_bytes();
    assert!(matches!(
        decode_review_snapshot(&v1),
        Err(ReviewApiError::InvalidBody)
    ));
    let spaced = String::from_utf8(encoded)
        .unwrap()
        .replace("{\"attention\"", "{ \"attention\"")
        .into_bytes();
    assert!(matches!(
        decode_review_snapshot(&spaced),
        Err(ReviewApiError::Codec(_))
    ));
}
