// SPDX-License-Identifier: Elastic-2.0

//! Closed production capability map for Platform v2 review effects.
//!
//! Store-owned comment and approval transitions need no ambient credential and
//! are committed atomically by `ReviewStore`. Every operation that would cross
//! into a repository, agent, CI service, or pull-request provider remains
//! unavailable until a future typed registry binds that exact authority to a
//! credential and target. This module deliberately contains no command or
//! provider escape hatch.

use automonique_protocol::platform_v2_review::ReviewAction;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReviewEffectPlan {
    LocalStore,
}

#[derive(Debug, Default)]
pub(crate) struct ProductionReviewEffectAdapter;

impl ProductionReviewEffectAdapter {
    pub(crate) fn plan(&self, action: &ReviewAction) -> Result<ReviewEffectPlan, &'static str> {
        match action {
            ReviewAction::AddComment { .. } | ReviewAction::ApproveReview { .. } => {
                Ok(ReviewEffectPlan::LocalStore)
            }
            ReviewAction::SendCommentToAgent { .. }
            | ReviewAction::BatchSendCommentsToAgent { .. } => {
                Err("platform_v2_review_agent_adapter_unavailable")
            }
            ReviewAction::Stage { .. }
            | ReviewAction::Unstage { .. }
            | ReviewAction::Commit { .. }
            | ReviewAction::ResolveConflict { .. } => {
                Err("platform_v2_review_git_adapter_unavailable")
            }
            ReviewAction::RerunCheck { .. } => Err("platform_v2_review_ci_adapter_unavailable"),
            ReviewAction::OpenPullRequest { .. }
            | ReviewAction::UpdatePullRequest { .. }
            | ReviewAction::MergePullRequest { .. } => {
                Err("platform_v2_review_pull_request_adapter_unavailable")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use automonique_protocol::platform_v2_review::{
        PullRequestId, ReviewAction, ReviewCheckId, ReviewCommentId, ReviewField, ReviewProposalId,
    };
    use automonique_protocol::primitives::Revision;

    #[test]
    fn external_effects_have_narrow_unavailable_categories() {
        let adapter = ProductionReviewEffectAdapter;
        let revision = Revision::FIRST;
        assert_eq!(
            adapter.plan(&ReviewAction::ApproveReview {
                expected_review_revision: revision,
            }),
            Ok(ReviewEffectPlan::LocalStore)
        );
        assert_eq!(
            adapter.plan(&ReviewAction::SendCommentToAgent {
                comment_id: ReviewCommentId::new("comment-1").unwrap(),
                expected_comment_revision: revision,
            }),
            Err("platform_v2_review_agent_adapter_unavailable")
        );
        assert_eq!(
            adapter.plan(&ReviewAction::Stage {
                proposal_id: ReviewProposalId::new("proposal-1").unwrap(),
            }),
            Err("platform_v2_review_git_adapter_unavailable")
        );
        assert_eq!(
            adapter.plan(&ReviewAction::RerunCheck {
                check_id: ReviewCheckId::new("check-1").unwrap(),
                expected_check_revision: revision,
            }),
            Err("platform_v2_review_ci_adapter_unavailable")
        );
        assert_eq!(
            adapter.plan(&ReviewAction::UpdatePullRequest {
                pull_request_id: PullRequestId::new("pr-1").unwrap(),
                expected_pull_request_revision: revision,
                title: ReviewField::new("bounded title").unwrap(),
            }),
            Err("platform_v2_review_pull_request_adapter_unavailable")
        );
    }
}
