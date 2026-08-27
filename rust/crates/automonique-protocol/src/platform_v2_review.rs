// SPDX-License-Identifier: Elastic-2.0

//! Shared Platform v2 review, attention, check, and pull-request contract.
//!
//! Values in this module are projections and narrowly scoped proposals. They
//! contain no host paths, credentials, provider payloads, generic executable
//! input, or ambient authority. A provider session is an observed relation,
//! never authorization for git, filesystem, CI, review, or pull-request
//! mutation.

use core::fmt;

use crate::platform::{IdempotencyKey, ReceiptId};
use crate::platform_v2::{WorkContextIdentity, WorkContextTargetKind};
use crate::primitives::{BoundedString, IdDomain, OpaqueId, Revision, ValueError};

pub const PLATFORM_REVIEW_SCHEMA_V1: &str = "automonique.platform/review/v1";
pub const PLATFORM_REVIEW_SCHEMA_V2: &str = "automonique.platform/review/v2";
pub const PLATFORM_REVIEW_REQUIRES_PLATFORM_MAJOR: u16 = 2;
pub const MAX_REVIEW_FIELD_BYTES: usize = 256;
pub const MAX_REVIEW_PATH_BYTES: usize = 1024;
pub const MAX_REVIEW_TEXT_BYTES: usize = 4096;
pub const MAX_REVIEW_HUNK_PREVIEW_BYTES: usize = 512;
pub const MAX_REVIEW_FILES: usize = 128;
pub const MAX_REVIEW_HUNKS_PER_FILE: usize = 128;
pub const MAX_REVIEW_HUNKS: usize = 512;
pub const MAX_REVIEW_COMMENTS: usize = 256;
pub const MAX_REVIEW_CHECKS: usize = 128;
pub const MAX_REVIEW_PROPOSALS: usize = 32;
pub const MAX_REVIEW_PROPOSAL_FILES: usize = 128;
pub const MAX_REVIEW_ATTENTION_EVENTS: usize = 256;
pub const MAX_REVIEW_UNREAD: u32 = 1_000_000;

macro_rules! id_domain {
    ($domain:ident, $name:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $domain;
        impl IdDomain for $domain {}
        pub type $name = OpaqueId<$domain, MAX_REVIEW_FIELD_BYTES>;
    };
}

id_domain!(ReviewFileIdDomain, ReviewFileId);
id_domain!(ReviewHunkIdDomain, ReviewHunkId);
id_domain!(ReviewCommentIdDomain, ReviewCommentId);
id_domain!(ReviewCheckIdDomain, ReviewCheckId);
id_domain!(ReviewProposalIdDomain, ReviewProposalId);
id_domain!(ReviewActorIdDomain, ReviewActorId);
id_domain!(ReviewAuthorityIdDomain, ReviewAuthorityId);
id_domain!(ReviewActionIdDomain, ReviewActionId);
id_domain!(ReviewAttentionEventIdDomain, ReviewAttentionEventId);
id_domain!(PullRequestIdDomain, PullRequestId);
id_domain!(DeliveryIdDomain, DeliveryId);

pub type ReviewText = BoundedString<MAX_REVIEW_TEXT_BYTES>;
pub type ReviewHunkPreview = BoundedString<MAX_REVIEW_HUNK_PREVIEW_BYTES>;
pub type ReviewField = BoundedString<MAX_REVIEW_FIELD_BYTES>;

/// Repository-relative display path. It cannot name an absolute or parent path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepositoryRelativePath(String);

impl RepositoryRelativePath {
    pub fn new(value: impl Into<String>) -> Result<Self, ReviewContractError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_REVIEW_PATH_BYTES {
            return Err(ReviewContractError::PathInvalid);
        }
        if value.starts_with('/')
            || value.starts_with('\\')
            || value.contains('\\')
            || value.contains('\0')
            || value
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(ReviewContractError::PathInvalid);
        }
        if value.chars().any(char::is_control) {
            return Err(ReviewContractError::PathInvalid);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! wire_enum {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub enum $name { $($variant),+ }
        impl $name {
            pub const ALL: [Self; wire_enum!(@count $($variant),+)] = [$(Self::$variant),+];
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $wire),+ }
            }
            pub fn parse(value: &str) -> Result<Self, ReviewContractError> {
                Self::ALL.into_iter().find(|candidate| candidate.as_str() == value)
                    .ok_or(ReviewContractError::UnknownEnum)
            }
        }
    };
    (@count $($item:ident),+) => { <[()]>::len(&[$(wire_enum!(@unit $item)),+]) };
    (@unit $item:ident) => { () };
}

wire_enum!(DiffChangeKind { Added => "added", Modified => "modified", Deleted => "deleted", Renamed => "renamed" });
wire_enum!(PreviewKind { None => "none", Text => "text", Binary => "binary", Image => "image", Html => "html" });
wire_enum!(ConflictState { None => "none", Unresolved => "unresolved", Resolved => "resolved" });
wire_enum!(DiffSide { Old => "old", New => "new" });
wire_enum!(CommentAgentState { NotSent => "not_sent", Pending => "pending", Sent => "sent", Refused => "refused" });
wire_enum!(WorktreeFileState { Staged => "staged", Unstaged => "unstaged", PartiallyStaged => "partially_staged", Untracked => "untracked" });
wire_enum!(ReviewProposalKind { Stage => "stage", Unstage => "unstage", Commit => "commit", ResolveConflict => "resolve_conflict" });
wire_enum!(ConflictResolution { KeepCurrent => "keep_current", KeepIncoming => "keep_incoming" });
wire_enum!(CheckState { Queued => "queued", Running => "running", Passed => "passed", Failed => "failed", Cancelled => "cancelled", Unavailable => "unavailable" });
wire_enum!(ReviewDecision { Pending => "pending", Approved => "approved", ChangesRequested => "changes_requested", Dismissed => "dismissed" });
wire_enum!(PullRequestState { Absent => "absent", Draft => "draft", Open => "open", Closed => "closed", Merged => "merged" });
wire_enum!(MergeReadiness { Unknown => "unknown", Blocked => "blocked", Ready => "ready", Stale => "stale" });
wire_enum!(DeliveryState { NotDelivered => "not_delivered", Pending => "pending", Delivered => "delivered", Failed => "failed" });
wire_enum!(AttentionState { Idle => "idle", NeedsYou => "needs_you", Working => "working", Done => "done", Blocked => "blocked" });
wire_enum!(AttentionReason { ReviewRequested => "review_requested", CommentReply => "comment_reply", ApprovalRequired => "approval_required", CheckRunning => "check_running", CheckFailed => "check_failed", Conflict => "conflict", DeliveryPending => "delivery_pending", Complete => "complete", ExternalBlocker => "external_blocker" });
wire_enum!(AttentionOriginKind { File => "file", Comment => "comment", Check => "check", Review => "review", PullRequest => "pull_request", Delivery => "delivery", Snapshot => "snapshot" });
wire_enum!(ReviewAuthorityKind { Filesystem => "filesystem", Git => "git", Ci => "ci", PullRequest => "pull_request", Review => "review", Delivery => "delivery" });
wire_enum!(ReviewFreshnessState { Fresh => "fresh", Stale => "stale", Unknown => "unknown" });
wire_enum!(ReviewAuthentication { UserSession => "user_session", ServiceIdentity => "service_identity", ProviderSession => "provider_session" });
wire_enum!(ReviewActionKind { AddComment => "add_comment", SendCommentToAgent => "send_comment_to_agent", BatchSendCommentsToAgent => "batch_send_comments_to_agent", Stage => "stage", Unstage => "unstage", Commit => "commit", ResolveConflict => "resolve_conflict", ApproveReview => "approve_review", RerunCheck => "rerun_check", OpenPullRequest => "open_pull_request", UpdatePullRequest => "update_pull_request", MergePullRequest => "merge_pull_request" });
wire_enum!(ReviewReceiptOutcome { Accepted => "accepted", Completed => "completed", Refused => "refused", Conflict => "conflict", Unknown => "unknown" });
wire_enum!(ReviewReconciliation { Final => "final", PollReceipt => "poll_receipt" });
wire_enum!(ReviewSchemaVersion { V1 => "automonique.platform/review/v1", V2 => "automonique.platform/review/v2" });

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewAuthority {
    kind: ReviewAuthorityKind,
    id: ReviewAuthorityId,
}
impl ReviewAuthority {
    pub fn new(kind: ReviewAuthorityKind, id: ReviewAuthorityId) -> Self {
        Self { kind, id }
    }
    #[must_use]
    pub const fn kind(&self) -> ReviewAuthorityKind {
        self.kind
    }
    #[must_use]
    pub fn id(&self) -> &ReviewAuthorityId {
        &self.id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewFreshness {
    state: ReviewFreshnessState,
    observed_revision: Revision,
    observed_at_ms: u64,
}
impl ReviewFreshness {
    pub fn new(
        state: ReviewFreshnessState,
        observed_revision: Revision,
        observed_at_ms: u64,
    ) -> Result<Self, ReviewContractError> {
        if observed_at_ms > i64::MAX as u64 {
            return Err(ReviewContractError::CounterOutOfRange);
        }
        Ok(Self {
            state,
            observed_revision,
            observed_at_ms,
        })
    }
    #[must_use]
    pub const fn state(&self) -> ReviewFreshnessState {
        self.state
    }
    #[must_use]
    pub const fn observed_revision(&self) -> Revision {
        self.observed_revision
    }
    #[must_use]
    pub const fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewMetadata {
    kind: PreviewKind,
    media_type: Option<ReviewField>,
    byte_size: Option<u64>,
    width: Option<u32>,
    height: Option<u32>,
    sanitized: bool,
}
impl PreviewMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: PreviewKind,
        media_type: Option<ReviewField>,
        byte_size: Option<u64>,
        width: Option<u32>,
        height: Option<u32>,
        sanitized: bool,
    ) -> Result<Self, ReviewContractError> {
        let coherent = match kind {
            PreviewKind::None => {
                media_type.is_none()
                    && byte_size.is_none()
                    && width.is_none()
                    && height.is_none()
                    && !sanitized
            }
            PreviewKind::Text => width.is_none() && height.is_none() && sanitized,
            PreviewKind::Binary => {
                media_type.is_some()
                    && byte_size.is_some()
                    && width.is_none()
                    && height.is_none()
                    && !sanitized
            }
            PreviewKind::Image => {
                media_type
                    .as_ref()
                    .is_some_and(|value| value.as_str().starts_with("image/"))
                    && byte_size.is_some()
                    && width.is_some_and(|v| v > 0)
                    && height.is_some_and(|v| v > 0)
                    && sanitized
            }
            PreviewKind::Html => {
                media_type
                    .as_ref()
                    .is_some_and(|value| value.as_str() == "text/html")
                    && byte_size.is_some()
                    && width.is_none()
                    && height.is_none()
                    && sanitized
            }
        };
        if !coherent || byte_size.is_some_and(|value| value > i64::MAX as u64) {
            return Err(ReviewContractError::PreviewInvalid);
        }
        Ok(Self {
            kind,
            media_type,
            byte_size,
            width,
            height,
            sanitized,
        })
    }
    #[must_use]
    pub const fn kind(&self) -> PreviewKind {
        self.kind
    }
    #[must_use]
    pub fn media_type(&self) -> Option<&ReviewField> {
        self.media_type.as_ref()
    }
    #[must_use]
    pub const fn byte_size(&self) -> Option<u64> {
        self.byte_size
    }
    #[must_use]
    pub const fn width(&self) -> Option<u32> {
        self.width
    }
    #[must_use]
    pub const fn height(&self) -> Option<u32> {
        self.height
    }
    #[must_use]
    pub const fn sanitized(&self) -> bool {
        self.sanitized
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffHunk {
    id: ReviewHunkId,
    old_start: u32,
    old_lines: u32,
    new_start: u32,
    new_lines: u32,
    preview: ReviewHunkPreview,
}
impl DiffHunk {
    pub fn new(
        id: ReviewHunkId,
        old_start: u32,
        old_lines: u32,
        new_start: u32,
        new_lines: u32,
        preview: ReviewHunkPreview,
    ) -> Result<Self, ReviewContractError> {
        if (old_start == 0 && old_lines != 0)
            || (new_start == 0 && new_lines != 0)
            || old_lines.saturating_add(new_lines) == 0
        {
            return Err(ReviewContractError::HunkInvalid);
        }
        Ok(Self {
            id,
            old_start,
            old_lines,
            new_start,
            new_lines,
            preview,
        })
    }
    #[must_use]
    pub fn id(&self) -> &ReviewHunkId {
        &self.id
    }
    #[must_use]
    pub const fn old_start(&self) -> u32 {
        self.old_start
    }
    #[must_use]
    pub const fn old_lines(&self) -> u32 {
        self.old_lines
    }
    #[must_use]
    pub const fn new_start(&self) -> u32 {
        self.new_start
    }
    #[must_use]
    pub const fn new_lines(&self) -> u32 {
        self.new_lines
    }
    #[must_use]
    pub fn preview(&self) -> &ReviewHunkPreview {
        &self.preview
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewFile {
    id: ReviewFileId,
    path: RepositoryRelativePath,
    change: DiffChangeKind,
    worktree: WorktreeFileState,
    preview: PreviewMetadata,
    conflict: ConflictState,
    hunks: Vec<DiffHunk>,
}
impl ReviewFile {
    pub fn new(
        id: ReviewFileId,
        path: RepositoryRelativePath,
        change: DiffChangeKind,
        worktree: WorktreeFileState,
        preview: PreviewMetadata,
        conflict: ConflictState,
        hunks: Vec<DiffHunk>,
    ) -> Result<Self, ReviewContractError> {
        if hunks.len() > MAX_REVIEW_HUNKS_PER_FILE || !strict_by(&hunks, |hunk| hunk.id().as_str())
        {
            return Err(ReviewContractError::CollectionInvalid);
        }
        if preview.kind() != PreviewKind::Text && !hunks.is_empty() {
            return Err(ReviewContractError::PreviewInvalid);
        }
        Ok(Self {
            id,
            path,
            change,
            worktree,
            preview,
            conflict,
            hunks,
        })
    }
    #[must_use]
    pub fn id(&self) -> &ReviewFileId {
        &self.id
    }
    #[must_use]
    pub fn path(&self) -> &RepositoryRelativePath {
        &self.path
    }
    #[must_use]
    pub const fn change(&self) -> DiffChangeKind {
        self.change
    }
    #[must_use]
    pub const fn worktree(&self) -> WorktreeFileState {
        self.worktree
    }
    #[must_use]
    pub fn preview(&self) -> &PreviewMetadata {
        &self.preview
    }
    #[must_use]
    pub const fn conflict(&self) -> ConflictState {
        self.conflict
    }
    #[must_use]
    pub fn hunks(&self) -> &[DiffHunk] {
        &self.hunks
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewAnchor {
    file_id: ReviewFileId,
    hunk_id: ReviewHunkId,
    side: DiffSide,
    line: u32,
}
impl ReviewAnchor {
    pub fn new(
        file_id: ReviewFileId,
        hunk_id: ReviewHunkId,
        side: DiffSide,
        line: u32,
    ) -> Result<Self, ReviewContractError> {
        if line == 0 {
            return Err(ReviewContractError::AnchorInvalid);
        }
        Ok(Self {
            file_id,
            hunk_id,
            side,
            line,
        })
    }
    #[must_use]
    pub fn file_id(&self) -> &ReviewFileId {
        &self.file_id
    }
    #[must_use]
    pub fn hunk_id(&self) -> &ReviewHunkId {
        &self.hunk_id
    }
    #[must_use]
    pub const fn side(&self) -> DiffSide {
        self.side
    }
    #[must_use]
    pub const fn line(&self) -> u32 {
        self.line
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewComment {
    id: ReviewCommentId,
    revision: Revision,
    actor: ReviewActorId,
    body: ReviewText,
    anchor: ReviewAnchor,
    agent_state: CommentAgentState,
    unread: bool,
}
impl ReviewComment {
    pub fn new(
        id: ReviewCommentId,
        revision: Revision,
        actor: ReviewActorId,
        body: ReviewText,
        anchor: ReviewAnchor,
        agent_state: CommentAgentState,
        unread: bool,
    ) -> Self {
        Self {
            id,
            revision,
            actor,
            body,
            anchor,
            agent_state,
            unread,
        }
    }
    #[must_use]
    pub fn id(&self) -> &ReviewCommentId {
        &self.id
    }
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
    #[must_use]
    pub fn actor(&self) -> &ReviewActorId {
        &self.actor
    }
    #[must_use]
    pub fn body(&self) -> &ReviewText {
        &self.body
    }
    #[must_use]
    pub fn anchor(&self) -> &ReviewAnchor {
        &self.anchor
    }
    #[must_use]
    pub const fn agent_state(&self) -> CommentAgentState {
        self.agent_state
    }
    #[must_use]
    pub const fn unread(&self) -> bool {
        self.unread
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewProposal {
    id: ReviewProposalId,
    kind: ReviewProposalKind,
    authority: Option<ReviewAuthority>,
    files: Vec<ReviewFileId>,
    subject: Option<ReviewField>,
}
impl ReviewProposal {
    pub fn new(
        id: ReviewProposalId,
        kind: ReviewProposalKind,
        authority: ReviewAuthority,
        files: Vec<ReviewFileId>,
        subject: Option<ReviewField>,
    ) -> Result<Self, ReviewContractError> {
        if authority.kind() != ReviewAuthorityKind::Git
            || files.is_empty()
            || files.len() > MAX_REVIEW_PROPOSAL_FILES
            || !strict_by(&files, OpaqueId::as_str)
        {
            return Err(ReviewContractError::CollectionInvalid);
        }
        if (kind == ReviewProposalKind::Commit) != subject.is_some() {
            return Err(ReviewContractError::ProposalInvalid);
        }
        Ok(Self {
            id,
            kind,
            authority: Some(authority),
            files,
            subject,
        })
    }
    #[must_use]
    pub fn id(&self) -> &ReviewProposalId {
        &self.id
    }
    #[must_use]
    pub const fn kind(&self) -> ReviewProposalKind {
        self.kind
    }
    #[must_use]
    pub fn authority(&self) -> Option<&ReviewAuthority> {
        self.authority.as_ref()
    }
    #[must_use]
    pub fn files(&self) -> &[ReviewFileId] {
        &self.files
    }
    #[must_use]
    pub fn subject(&self) -> Option<&ReviewField> {
        self.subject.as_ref()
    }

    pub(crate) fn legacy(
        id: ReviewProposalId,
        kind: ReviewProposalKind,
        files: Vec<ReviewFileId>,
        subject: Option<ReviewField>,
    ) -> Result<Self, ReviewContractError> {
        if kind == ReviewProposalKind::ResolveConflict
            || files.is_empty()
            || files.len() > MAX_REVIEW_PROPOSAL_FILES
            || !strict_by(&files, OpaqueId::as_str)
            || (kind == ReviewProposalKind::Commit) != subject.is_some()
        {
            return Err(ReviewContractError::ProposalInvalid);
        }
        Ok(Self {
            id,
            kind,
            authority: None,
            files,
            subject,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckProjection {
    id: ReviewCheckId,
    state: CheckState,
    authority: ReviewAuthority,
    freshness: ReviewFreshness,
    required: bool,
}
impl CheckProjection {
    pub fn new(
        id: ReviewCheckId,
        state: CheckState,
        authority: ReviewAuthority,
        freshness: ReviewFreshness,
        required: bool,
    ) -> Result<Self, ReviewContractError> {
        if authority.kind() != ReviewAuthorityKind::Ci {
            return Err(ReviewContractError::AuthorityInvalid);
        }
        Ok(Self {
            id,
            state,
            authority,
            freshness,
            required,
        })
    }
    #[must_use]
    pub fn id(&self) -> &ReviewCheckId {
        &self.id
    }
    #[must_use]
    pub const fn state(&self) -> CheckState {
        self.state
    }
    #[must_use]
    pub fn authority(&self) -> &ReviewAuthority {
        &self.authority
    }
    #[must_use]
    pub const fn freshness(&self) -> ReviewFreshness {
        self.freshness
    }
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewStatusProjection {
    decision: ReviewDecision,
    authority: ReviewAuthority,
    freshness: ReviewFreshness,
}
impl ReviewStatusProjection {
    pub fn new(
        decision: ReviewDecision,
        authority: ReviewAuthority,
        freshness: ReviewFreshness,
    ) -> Result<Self, ReviewContractError> {
        if authority.kind() != ReviewAuthorityKind::Review {
            return Err(ReviewContractError::AuthorityInvalid);
        }
        Ok(Self {
            decision,
            authority,
            freshness,
        })
    }
    #[must_use]
    pub const fn decision(&self) -> ReviewDecision {
        self.decision
    }
    #[must_use]
    pub fn authority(&self) -> &ReviewAuthority {
        &self.authority
    }
    #[must_use]
    pub const fn freshness(&self) -> ReviewFreshness {
        self.freshness
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestProjection {
    id: Option<PullRequestId>,
    state: PullRequestState,
    readiness: MergeReadiness,
    head_revision: Option<ReviewField>,
    authority: ReviewAuthority,
    freshness: ReviewFreshness,
}
impl PullRequestProjection {
    pub fn new(
        id: Option<PullRequestId>,
        state: PullRequestState,
        readiness: MergeReadiness,
        head_revision: Option<ReviewField>,
        authority: ReviewAuthority,
        freshness: ReviewFreshness,
    ) -> Result<Self, ReviewContractError> {
        if authority.kind() != ReviewAuthorityKind::PullRequest
            || (state == PullRequestState::Absent) != id.is_none()
            || (state == PullRequestState::Absent) != head_revision.is_none()
        {
            return Err(ReviewContractError::AuthorityInvalid);
        }
        Ok(Self {
            id,
            state,
            readiness,
            head_revision,
            authority,
            freshness,
        })
    }
    #[must_use]
    pub fn id(&self) -> Option<&PullRequestId> {
        self.id.as_ref()
    }
    #[must_use]
    pub const fn state(&self) -> PullRequestState {
        self.state
    }
    #[must_use]
    pub const fn readiness(&self) -> MergeReadiness {
        self.readiness
    }
    #[must_use]
    pub fn head_revision(&self) -> Option<&ReviewField> {
        self.head_revision.as_ref()
    }
    #[must_use]
    pub fn authority(&self) -> &ReviewAuthority {
        &self.authority
    }
    #[must_use]
    pub const fn freshness(&self) -> ReviewFreshness {
        self.freshness
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryProjection {
    id: Option<DeliveryId>,
    state: DeliveryState,
    authority: ReviewAuthority,
    freshness: ReviewFreshness,
}
impl DeliveryProjection {
    pub fn new(
        id: Option<DeliveryId>,
        state: DeliveryState,
        authority: ReviewAuthority,
        freshness: ReviewFreshness,
    ) -> Result<Self, ReviewContractError> {
        if authority.kind() != ReviewAuthorityKind::Delivery
            || ((state == DeliveryState::NotDelivered) != id.is_none())
        {
            return Err(ReviewContractError::AuthorityInvalid);
        }
        Ok(Self {
            id,
            state,
            authority,
            freshness,
        })
    }
    #[must_use]
    pub fn id(&self) -> Option<&DeliveryId> {
        self.id.as_ref()
    }
    #[must_use]
    pub const fn state(&self) -> DeliveryState {
        self.state
    }
    #[must_use]
    pub fn authority(&self) -> &ReviewAuthority {
        &self.authority
    }
    #[must_use]
    pub const fn freshness(&self) -> ReviewFreshness {
        self.freshness
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttentionOrigin {
    kind: AttentionOriginKind,
    id: Option<ReviewField>,
    authority: ReviewAuthority,
    revision: Revision,
}
impl AttentionOrigin {
    pub fn new(
        kind: AttentionOriginKind,
        id: Option<ReviewField>,
        authority: ReviewAuthority,
        revision: Revision,
    ) -> Result<Self, ReviewContractError> {
        let requires_id = matches!(
            kind,
            AttentionOriginKind::File
                | AttentionOriginKind::Comment
                | AttentionOriginKind::Check
                | AttentionOriginKind::PullRequest
                | AttentionOriginKind::Delivery
        );
        if requires_id != id.is_some() {
            return Err(ReviewContractError::AttentionInvalid);
        }
        Ok(Self {
            kind,
            id,
            authority,
            revision,
        })
    }
    #[must_use]
    pub const fn kind(&self) -> AttentionOriginKind {
        self.kind
    }
    #[must_use]
    pub fn id(&self) -> Option<&ReviewField> {
        self.id.as_ref()
    }
    #[must_use]
    pub fn authority(&self) -> &ReviewAuthority {
        &self.authority
    }
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttentionEvent {
    id: ReviewAttentionEventId,
    origin: AttentionOrigin,
    reason: AttentionReason,
    unread: u32,
}
impl AttentionEvent {
    pub fn new(
        id: ReviewAttentionEventId,
        origin: AttentionOrigin,
        reason: AttentionReason,
        unread: u32,
    ) -> Result<Self, ReviewContractError> {
        if unread > MAX_REVIEW_UNREAD {
            return Err(ReviewContractError::CounterOutOfRange);
        }
        Ok(Self {
            id,
            origin,
            reason,
            unread,
        })
    }
    #[must_use]
    pub fn id(&self) -> &ReviewAttentionEventId {
        &self.id
    }
    #[must_use]
    pub fn origin(&self) -> &AttentionOrigin {
        &self.origin
    }
    #[must_use]
    pub const fn reason(&self) -> AttentionReason {
        self.reason
    }
    #[must_use]
    pub const fn unread(&self) -> u32 {
        self.unread
    }
    #[must_use]
    pub const fn source_revision(&self) -> Revision {
        self.origin.revision()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttentionProjection {
    state: AttentionState,
    reason: Option<AttentionReason>,
    unread: u32,
    source_revision: Option<Revision>,
}
impl AttentionProjection {
    pub fn derive(
        events: &[AttentionEvent],
        snapshot_revision: Revision,
    ) -> Result<Self, ReviewContractError> {
        if events.len() > MAX_REVIEW_ATTENTION_EVENTS
            || events
                .iter()
                .any(|event| event.source_revision() > snapshot_revision)
        {
            return Err(ReviewContractError::AttentionInvalid);
        }
        if events.is_empty() {
            return Ok(Self {
                state: AttentionState::Idle,
                reason: None,
                unread: 0,
                source_revision: None,
            });
        }
        let mut selected = &events[0];
        let mut unread = 0_u32;
        for event in events {
            unread = unread
                .checked_add(event.unread())
                .filter(|value| *value <= MAX_REVIEW_UNREAD)
                .ok_or(ReviewContractError::CounterOutOfRange)?;
            if attention_precedence(event.reason()) > attention_precedence(selected.reason())
                || (attention_precedence(event.reason()) == attention_precedence(selected.reason())
                    && (event.source_revision() > selected.source_revision()
                        || (event.source_revision() == selected.source_revision()
                            && event.reason() < selected.reason())))
            {
                selected = event;
            }
        }
        let state = attention_state(selected.reason());
        Ok(Self {
            state,
            reason: Some(selected.reason()),
            unread,
            source_revision: Some(
                events
                    .iter()
                    .map(AttentionEvent::source_revision)
                    .max()
                    .ok_or(ReviewContractError::AttentionInvalid)?,
            ),
        })
    }
    #[must_use]
    pub const fn state(&self) -> AttentionState {
        self.state
    }
    #[must_use]
    pub const fn reason(&self) -> Option<AttentionReason> {
        self.reason
    }
    #[must_use]
    pub const fn unread(&self) -> u32 {
        self.unread
    }
    #[must_use]
    pub const fn source_revision(&self) -> Option<Revision> {
        self.source_revision
    }
}

const fn attention_state(reason: AttentionReason) -> AttentionState {
    match reason {
        AttentionReason::Conflict
        | AttentionReason::CheckFailed
        | AttentionReason::ExternalBlocker => AttentionState::Blocked,
        AttentionReason::ApprovalRequired
        | AttentionReason::ReviewRequested
        | AttentionReason::CommentReply => AttentionState::NeedsYou,
        AttentionReason::CheckRunning | AttentionReason::DeliveryPending => AttentionState::Working,
        AttentionReason::Complete => AttentionState::Done,
    }
}

const fn attention_precedence(reason: AttentionReason) -> u8 {
    match attention_state(reason) {
        AttentionState::Blocked => 4,
        AttentionState::NeedsYou => 3,
        AttentionState::Working => 2,
        AttentionState::Done => 1,
        AttentionState::Idle => 0,
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_attention_event(
    event: &AttentionEvent,
    snapshot_revision: Revision,
    files: &[ReviewFile],
    comments: &[ReviewComment],
    checks: &[CheckProjection],
    review: &ReviewStatusProjection,
    pull_request: &PullRequestProjection,
    delivery: &DeliveryProjection,
) -> Result<(), ReviewContractError> {
    let origin = event.origin();
    if origin.revision() > snapshot_revision {
        return Err(ReviewContractError::AttentionInvalid);
    }
    let matches_authority_revision = |authority: &ReviewAuthority, revision: Revision| {
        origin.authority() == authority && origin.revision() == revision
    };
    let valid = match event.reason() {
        AttentionReason::ReviewRequested | AttentionReason::ApprovalRequired => {
            origin.kind() == AttentionOriginKind::Review
                && origin.id().is_none()
                && matches_authority_revision(
                    review.authority(),
                    review.freshness().observed_revision(),
                )
                && matches!(
                    review.decision(),
                    ReviewDecision::Pending | ReviewDecision::ChangesRequested
                )
        }
        AttentionReason::CommentReply => {
            origin.kind() == AttentionOriginKind::Comment
                && origin.authority() == review.authority()
                && comments.iter().any(|comment| {
                    origin_id_is(origin, comment.id().as_str())
                        && origin.revision() == comment.revision()
                        && comment.unread()
                })
        }
        AttentionReason::CheckRunning => {
            origin.kind() == AttentionOriginKind::Check
                && checks.iter().any(|check| {
                    origin_id_is(origin, check.id().as_str())
                        && matches_authority_revision(
                            check.authority(),
                            check.freshness().observed_revision(),
                        )
                        && check.state() == CheckState::Running
                })
        }
        AttentionReason::CheckFailed => {
            origin.kind() == AttentionOriginKind::Check
                && checks.iter().any(|check| {
                    origin_id_is(origin, check.id().as_str())
                        && matches_authority_revision(
                            check.authority(),
                            check.freshness().observed_revision(),
                        )
                        && check.state() == CheckState::Failed
                })
        }
        AttentionReason::Conflict => {
            origin.kind() == AttentionOriginKind::File
                && origin.authority() == review.authority()
                && origin.revision() == snapshot_revision
                && files.iter().any(|file| {
                    origin_id_is(origin, file.id().as_str())
                        && file.conflict() == ConflictState::Unresolved
                })
        }
        AttentionReason::DeliveryPending => {
            origin.kind() == AttentionOriginKind::Delivery
                && delivery
                    .id()
                    .is_some_and(|id| origin_id_is(origin, id.as_str()))
                && matches_authority_revision(
                    delivery.authority(),
                    delivery.freshness().observed_revision(),
                )
                && delivery.state() == DeliveryState::Pending
        }
        AttentionReason::Complete => {
            origin.kind() == AttentionOriginKind::Snapshot
                && origin.id().is_none()
                && origin.authority() == review.authority()
                && origin.revision() == snapshot_revision
                && review.decision() == ReviewDecision::Approved
                && files
                    .iter()
                    .all(|file| file.conflict() != ConflictState::Unresolved)
                && checks
                    .iter()
                    .filter(|check| check.required())
                    .all(|check| check.state() == CheckState::Passed)
                && matches!(
                    pull_request.state(),
                    PullRequestState::Absent | PullRequestState::Merged
                )
                && matches!(
                    delivery.state(),
                    DeliveryState::NotDelivered | DeliveryState::Delivered
                )
        }
        AttentionReason::ExternalBlocker => {
            origin.kind() == AttentionOriginKind::Delivery
                && delivery
                    .id()
                    .is_some_and(|id| origin_id_is(origin, id.as_str()))
                && matches_authority_revision(
                    delivery.authority(),
                    delivery.freshness().observed_revision(),
                )
                && delivery.state() == DeliveryState::Failed
        }
    };
    if valid {
        Ok(())
    } else {
        Err(ReviewContractError::AttentionInvalid)
    }
}

fn origin_id_is(origin: &AttentionOrigin, expected: &str) -> bool {
    origin.id().is_some_and(|id| id.as_str() == expected)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewSnapshot {
    schema: ReviewSchemaVersion,
    workspace: WorkContextIdentity,
    revision: Revision,
    files: Vec<ReviewFile>,
    comments: Vec<ReviewComment>,
    proposals: Vec<ReviewProposal>,
    checks: Vec<CheckProjection>,
    review: ReviewStatusProjection,
    pull_request: PullRequestProjection,
    delivery: DeliveryProjection,
    attention_events: Vec<AttentionEvent>,
    attention: AttentionProjection,
}
impl ReviewSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace: WorkContextIdentity,
        revision: Revision,
        files: Vec<ReviewFile>,
        comments: Vec<ReviewComment>,
        proposals: Vec<ReviewProposal>,
        checks: Vec<CheckProjection>,
        review: ReviewStatusProjection,
        pull_request: PullRequestProjection,
        delivery: DeliveryProjection,
        attention_events: Vec<AttentionEvent>,
    ) -> Result<Self, ReviewContractError> {
        Self::new_versioned(
            ReviewSchemaVersion::V2,
            workspace,
            revision,
            files,
            comments,
            proposals,
            checks,
            review,
            pull_request,
            delivery,
            attention_events,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_versioned(
        schema: ReviewSchemaVersion,
        workspace: WorkContextIdentity,
        revision: Revision,
        files: Vec<ReviewFile>,
        comments: Vec<ReviewComment>,
        proposals: Vec<ReviewProposal>,
        checks: Vec<CheckProjection>,
        review: ReviewStatusProjection,
        pull_request: PullRequestProjection,
        delivery: DeliveryProjection,
        attention_events: Vec<AttentionEvent>,
    ) -> Result<Self, ReviewContractError> {
        validate_workspace(&workspace)?;
        if files.len() > MAX_REVIEW_FILES
            || files.iter().map(|file| file.hunks().len()).sum::<usize>() > MAX_REVIEW_HUNKS
            || comments.len() > MAX_REVIEW_COMMENTS
            || proposals.len() > MAX_REVIEW_PROPOSALS
            || checks.len() > MAX_REVIEW_CHECKS
            || attention_events.len() > MAX_REVIEW_ATTENTION_EVENTS
            || !strict_by(&files, |v| v.id().as_str())
            || !strict_by(&comments, |v| v.id().as_str())
            || !strict_by(&proposals, |v| v.id().as_str())
            || !strict_by(&checks, |v| v.id().as_str())
            || !strict_by(&attention_events, |v| v.id().as_str())
        {
            return Err(ReviewContractError::CollectionInvalid);
        }
        if (schema == ReviewSchemaVersion::V1
            && (attention_events.is_empty()
                || proposals.iter().any(|proposal| {
                    proposal.authority().is_some()
                        || proposal.kind() == ReviewProposalKind::ResolveConflict
                })))
            || (schema == ReviewSchemaVersion::V2
                && proposals
                    .iter()
                    .any(|proposal| proposal.authority().is_none()))
        {
            return Err(ReviewContractError::ProposalInvalid);
        }
        for comment in &comments {
            validate_anchor_in_files(&files, comment.anchor())?;
        }
        for proposal in &proposals {
            for file_id in proposal.files() {
                let file = files
                    .iter()
                    .find(|file| file.id() == file_id)
                    .ok_or(ReviewContractError::ProposalInvalid)?;
                let valid = match proposal.kind() {
                    ReviewProposalKind::Stage => matches!(
                        file.worktree(),
                        WorktreeFileState::Unstaged
                            | WorktreeFileState::PartiallyStaged
                            | WorktreeFileState::Untracked
                    ),
                    ReviewProposalKind::Unstage => matches!(
                        file.worktree(),
                        WorktreeFileState::Staged | WorktreeFileState::PartiallyStaged
                    ),
                    ReviewProposalKind::Commit => matches!(
                        file.worktree(),
                        WorktreeFileState::Staged | WorktreeFileState::PartiallyStaged
                    ),
                    ReviewProposalKind::ResolveConflict => {
                        file.conflict() == ConflictState::Unresolved
                    }
                };
                if !valid {
                    return Err(ReviewContractError::ProposalInvalid);
                }
            }
        }
        for event in &attention_events {
            validate_attention_event(
                event,
                revision,
                &files,
                &comments,
                &checks,
                &review,
                &pull_request,
                &delivery,
            )?;
        }
        for (index, event) in attention_events.iter().enumerate() {
            if attention_events[index + 1..]
                .iter()
                .any(|other| other.origin() == event.origin() && other.reason() == event.reason())
            {
                return Err(ReviewContractError::AttentionInvalid);
            }
        }
        let attention = AttentionProjection::derive(&attention_events, revision)?;
        Ok(Self {
            schema,
            workspace,
            revision,
            files,
            comments,
            proposals,
            checks,
            review,
            pull_request,
            delivery,
            attention_events,
            attention,
        })
    }
    #[must_use]
    pub const fn schema(&self) -> ReviewSchemaVersion {
        self.schema
    }
    #[must_use]
    pub fn workspace(&self) -> &WorkContextIdentity {
        &self.workspace
    }
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
    #[must_use]
    pub fn files(&self) -> &[ReviewFile] {
        &self.files
    }
    #[must_use]
    pub fn comments(&self) -> &[ReviewComment] {
        &self.comments
    }
    #[must_use]
    pub fn proposals(&self) -> &[ReviewProposal] {
        &self.proposals
    }
    #[must_use]
    pub fn checks(&self) -> &[CheckProjection] {
        &self.checks
    }
    #[must_use]
    pub fn review(&self) -> &ReviewStatusProjection {
        &self.review
    }
    #[must_use]
    pub fn pull_request(&self) -> &PullRequestProjection {
        &self.pull_request
    }
    #[must_use]
    pub fn delivery(&self) -> &DeliveryProjection {
        &self.delivery
    }
    #[must_use]
    pub fn attention_events(&self) -> &[AttentionEvent] {
        &self.attention_events
    }
    #[must_use]
    pub const fn attention(&self) -> AttentionProjection {
        self.attention
    }

    /// Resolve a proposed mutation against the exact authoritative snapshot.
    /// Kind-only authority is insufficient: the authority identity, target
    /// identity, target revision, lifecycle and freshness must all agree.
    pub fn resolve_action(&self, request: &ReviewActionRequest) -> Result<(), ReviewContractError> {
        if request.workspace() != self.workspace() || request.expected_revision() != self.revision()
        {
            return Err(ReviewContractError::ActionInvalid);
        }
        let require_authority = |expected: &ReviewAuthority| {
            if request.authority() == expected {
                Ok(())
            } else {
                Err(ReviewContractError::AuthorityInvalid)
            }
        };
        let proposal = |id: &ReviewProposalId, kind: ReviewProposalKind| {
            self.proposals()
                .iter()
                .find(|proposal| proposal.id() == id && proposal.kind() == kind)
                .ok_or(ReviewContractError::ActionInvalid)
        };
        match request.action() {
            ReviewAction::AddComment {
                comment_id, anchor, ..
            } => {
                require_authority(self.review().authority())?;
                require_fresh(self.review().freshness())?;
                if self
                    .comments()
                    .iter()
                    .any(|comment| comment.id() == comment_id)
                {
                    return Err(ReviewContractError::ActionInvalid);
                }
                validate_anchor_in_files(self.files(), anchor)
            }
            ReviewAction::SendCommentToAgent {
                comment_id,
                expected_comment_revision,
            } => {
                require_authority(self.review().authority())?;
                require_fresh(self.review().freshness())?;
                let comment = self
                    .comments()
                    .iter()
                    .find(|comment| comment.id() == comment_id)
                    .ok_or(ReviewContractError::ActionInvalid)?;
                if comment.revision() != *expected_comment_revision
                    || !matches!(
                        comment.agent_state(),
                        CommentAgentState::NotSent | CommentAgentState::Refused
                    )
                {
                    return Err(ReviewContractError::ActionInvalid);
                }
                Ok(())
            }
            ReviewAction::BatchSendCommentsToAgent { comments } => {
                require_authority(self.review().authority())?;
                require_fresh(self.review().freshness())?;
                for target in comments {
                    let comment = self
                        .comments()
                        .iter()
                        .find(|comment| comment.id() == target.comment_id())
                        .ok_or(ReviewContractError::ActionInvalid)?;
                    if comment.revision() != target.expected_revision()
                        || !matches!(
                            comment.agent_state(),
                            CommentAgentState::NotSent | CommentAgentState::Refused
                        )
                    {
                        return Err(ReviewContractError::ActionInvalid);
                    }
                }
                Ok(())
            }
            ReviewAction::Stage { proposal_id } => {
                let proposal = proposal(proposal_id, ReviewProposalKind::Stage)?;
                require_authority(
                    proposal
                        .authority()
                        .ok_or(ReviewContractError::ActionInvalid)?,
                )?;
                if proposal.files().iter().any(|id| {
                    self.files()
                        .iter()
                        .any(|file| file.id() == id && file.conflict() == ConflictState::Unresolved)
                }) {
                    return Err(ReviewContractError::ActionInvalid);
                }
                Ok(())
            }
            ReviewAction::Unstage { proposal_id } => {
                let proposal = proposal(proposal_id, ReviewProposalKind::Unstage)?;
                require_authority(
                    proposal
                        .authority()
                        .ok_or(ReviewContractError::ActionInvalid)?,
                )
            }
            ReviewAction::Commit { proposal_id } => {
                let proposal = proposal(proposal_id, ReviewProposalKind::Commit)?;
                require_authority(
                    proposal
                        .authority()
                        .ok_or(ReviewContractError::ActionInvalid)?,
                )?;
                if proposal.files().iter().any(|id| {
                    self.files()
                        .iter()
                        .any(|file| file.id() == id && file.conflict() == ConflictState::Unresolved)
                }) {
                    return Err(ReviewContractError::ActionInvalid);
                }
                Ok(())
            }
            ReviewAction::ResolveConflict {
                proposal_id,
                file_id,
                ..
            } => {
                let proposal = proposal(proposal_id, ReviewProposalKind::ResolveConflict)?;
                require_authority(
                    proposal
                        .authority()
                        .ok_or(ReviewContractError::ActionInvalid)?,
                )?;
                if !proposal.files().contains(file_id)
                    || !self.files().iter().any(|file| {
                        file.id() == file_id && file.conflict() == ConflictState::Unresolved
                    })
                {
                    return Err(ReviewContractError::ActionInvalid);
                }
                Ok(())
            }
            ReviewAction::ApproveReview {
                expected_review_revision,
            } => {
                require_authority(self.review().authority())?;
                require_fresh(self.review().freshness())?;
                if self.review().freshness().observed_revision() != *expected_review_revision
                    || !matches!(
                        self.review().decision(),
                        ReviewDecision::Pending | ReviewDecision::ChangesRequested
                    )
                {
                    return Err(ReviewContractError::ActionInvalid);
                }
                Ok(())
            }
            ReviewAction::RerunCheck {
                check_id,
                expected_check_revision,
            } => {
                let check = self
                    .checks()
                    .iter()
                    .find(|check| check.id() == check_id)
                    .ok_or(ReviewContractError::ActionInvalid)?;
                require_authority(check.authority())?;
                require_fresh(check.freshness())?;
                if check.freshness().observed_revision() != *expected_check_revision
                    || !matches!(
                        check.state(),
                        CheckState::Passed | CheckState::Failed | CheckState::Cancelled
                    )
                {
                    return Err(ReviewContractError::ActionInvalid);
                }
                Ok(())
            }
            ReviewAction::OpenPullRequest {
                expected_pull_request_revision,
                ..
            } => {
                require_authority(self.pull_request().authority())?;
                require_fresh(self.pull_request().freshness())?;
                if self.pull_request().state() != PullRequestState::Absent
                    || self.pull_request().freshness().observed_revision()
                        != *expected_pull_request_revision
                {
                    return Err(ReviewContractError::ActionInvalid);
                }
                Ok(())
            }
            ReviewAction::UpdatePullRequest {
                pull_request_id,
                expected_pull_request_revision,
                ..
            } => {
                require_authority(self.pull_request().authority())?;
                require_fresh(self.pull_request().freshness())?;
                if self.pull_request().id() != Some(pull_request_id)
                    || self.pull_request().freshness().observed_revision()
                        != *expected_pull_request_revision
                    || !matches!(
                        self.pull_request().state(),
                        PullRequestState::Draft | PullRequestState::Open
                    )
                {
                    return Err(ReviewContractError::ActionInvalid);
                }
                Ok(())
            }
            ReviewAction::MergePullRequest {
                pull_request_id,
                expected_pull_request_revision,
                expected_head_revision,
            } => {
                require_authority(self.pull_request().authority())?;
                require_fresh(self.pull_request().freshness())?;
                if self.pull_request().id() != Some(pull_request_id)
                    || self.pull_request().freshness().observed_revision()
                        != *expected_pull_request_revision
                    || self.pull_request().head_revision() != Some(expected_head_revision)
                    || self.pull_request().state() != PullRequestState::Open
                    || self.pull_request().readiness() != MergeReadiness::Ready
                {
                    return Err(ReviewContractError::ActionInvalid);
                }
                Ok(())
            }
        }
    }
}

fn require_fresh(freshness: ReviewFreshness) -> Result<(), ReviewContractError> {
    if freshness.state() == ReviewFreshnessState::Fresh {
        Ok(())
    } else {
        Err(ReviewContractError::ActionInvalid)
    }
}

fn validate_anchor_in_files(
    files: &[ReviewFile],
    anchor: &ReviewAnchor,
) -> Result<(), ReviewContractError> {
    let file = files
        .iter()
        .find(|file| file.id() == anchor.file_id())
        .ok_or(ReviewContractError::AnchorInvalid)?;
    let hunk = file
        .hunks()
        .iter()
        .find(|hunk| hunk.id() == anchor.hunk_id())
        .ok_or(ReviewContractError::AnchorInvalid)?;
    let (start, lines) = match anchor.side() {
        DiffSide::Old => (hunk.old_start(), hunk.old_lines()),
        DiffSide::New => (hunk.new_start(), hunk.new_lines()),
    };
    let end = start
        .checked_add(lines)
        .ok_or(ReviewContractError::AnchorInvalid)?;
    if lines == 0 || anchor.line() < start || anchor.line() >= end {
        Err(ReviewContractError::AnchorInvalid)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewCommentTarget {
    comment_id: ReviewCommentId,
    expected_revision: Revision,
}
impl ReviewCommentTarget {
    #[must_use]
    pub const fn new(comment_id: ReviewCommentId, expected_revision: Revision) -> Self {
        Self {
            comment_id,
            expected_revision,
        }
    }
    #[must_use]
    pub const fn comment_id(&self) -> &ReviewCommentId {
        &self.comment_id
    }
    #[must_use]
    pub const fn expected_revision(&self) -> Revision {
        self.expected_revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewAction {
    AddComment {
        comment_id: ReviewCommentId,
        anchor: ReviewAnchor,
        body: ReviewText,
    },
    SendCommentToAgent {
        comment_id: ReviewCommentId,
        expected_comment_revision: Revision,
    },
    BatchSendCommentsToAgent {
        comments: Vec<ReviewCommentTarget>,
    },
    Stage {
        proposal_id: ReviewProposalId,
    },
    Unstage {
        proposal_id: ReviewProposalId,
    },
    Commit {
        proposal_id: ReviewProposalId,
    },
    ResolveConflict {
        proposal_id: ReviewProposalId,
        file_id: ReviewFileId,
        resolution: ConflictResolution,
    },
    ApproveReview {
        expected_review_revision: Revision,
    },
    RerunCheck {
        check_id: ReviewCheckId,
        expected_check_revision: Revision,
    },
    OpenPullRequest {
        expected_pull_request_revision: Revision,
        title: ReviewField,
    },
    UpdatePullRequest {
        pull_request_id: PullRequestId,
        expected_pull_request_revision: Revision,
        title: ReviewField,
    },
    MergePullRequest {
        pull_request_id: PullRequestId,
        expected_pull_request_revision: Revision,
        expected_head_revision: ReviewField,
    },
}
impl ReviewAction {
    #[must_use]
    pub const fn kind(&self) -> ReviewActionKind {
        match self {
            Self::AddComment { .. } => ReviewActionKind::AddComment,
            Self::SendCommentToAgent { .. } => ReviewActionKind::SendCommentToAgent,
            Self::BatchSendCommentsToAgent { .. } => ReviewActionKind::BatchSendCommentsToAgent,
            Self::Stage { .. } => ReviewActionKind::Stage,
            Self::Unstage { .. } => ReviewActionKind::Unstage,
            Self::Commit { .. } => ReviewActionKind::Commit,
            Self::ResolveConflict { .. } => ReviewActionKind::ResolveConflict,
            Self::ApproveReview { .. } => ReviewActionKind::ApproveReview,
            Self::RerunCheck { .. } => ReviewActionKind::RerunCheck,
            Self::OpenPullRequest { .. } => ReviewActionKind::OpenPullRequest,
            Self::UpdatePullRequest { .. } => ReviewActionKind::UpdatePullRequest,
            Self::MergePullRequest { .. } => ReviewActionKind::MergePullRequest,
        }
    }
    #[must_use]
    pub const fn required_authority(&self) -> ReviewAuthorityKind {
        match self {
            Self::AddComment { .. }
            | Self::SendCommentToAgent { .. }
            | Self::BatchSendCommentsToAgent { .. }
            | Self::ApproveReview { .. } => ReviewAuthorityKind::Review,
            Self::Stage { .. }
            | Self::Unstage { .. }
            | Self::Commit { .. }
            | Self::ResolveConflict { .. } => ReviewAuthorityKind::Git,
            Self::RerunCheck { .. } => ReviewAuthorityKind::Ci,
            Self::OpenPullRequest { .. }
            | Self::UpdatePullRequest { .. }
            | Self::MergePullRequest { .. } => ReviewAuthorityKind::PullRequest,
        }
    }

    fn validate_shape(&self) -> Result<(), ReviewContractError> {
        if let Self::BatchSendCommentsToAgent { comments } = self
            && (comments.is_empty()
                || comments.len() > MAX_REVIEW_COMMENTS
                || !strict_by(comments, |target| target.comment_id().as_str()))
        {
            return Err(ReviewContractError::CollectionInvalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewActionRequest {
    workspace: WorkContextIdentity,
    expected_revision: Revision,
    actor: ReviewActorId,
    authentication: ReviewAuthentication,
    authority: ReviewAuthority,
    idempotency_key: IdempotencyKey,
    action: ReviewAction,
}
impl ReviewActionRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace: WorkContextIdentity,
        expected_revision: Revision,
        actor: ReviewActorId,
        authentication: ReviewAuthentication,
        authority: ReviewAuthority,
        idempotency_key: IdempotencyKey,
        action: ReviewAction,
    ) -> Result<Self, ReviewContractError> {
        validate_workspace(&workspace)?;
        action.validate_shape()?;
        if authentication == ReviewAuthentication::ProviderSession
            || authority.kind() != action.required_authority()
        {
            return Err(ReviewContractError::AuthorityInvalid);
        }
        Ok(Self {
            workspace,
            expected_revision,
            actor,
            authentication,
            authority,
            idempotency_key,
            action,
        })
    }
    #[must_use]
    pub fn workspace(&self) -> &WorkContextIdentity {
        &self.workspace
    }
    #[must_use]
    pub const fn expected_revision(&self) -> Revision {
        self.expected_revision
    }
    #[must_use]
    pub fn actor(&self) -> &ReviewActorId {
        &self.actor
    }
    #[must_use]
    pub const fn authentication(&self) -> ReviewAuthentication {
        self.authentication
    }
    #[must_use]
    pub fn authority(&self) -> &ReviewAuthority {
        &self.authority
    }
    #[must_use]
    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
    #[must_use]
    pub fn action(&self) -> &ReviewAction {
        &self.action
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewActionReceipt {
    receipt_id: ReceiptId,
    idempotency_key: IdempotencyKey,
    action_id: ReviewActionId,
    actor: ReviewActorId,
    outcome: ReviewReceiptOutcome,
    revision: Option<Revision>,
    current_revision: Option<Revision>,
    reconciliation: ReviewReconciliation,
}
impl ReviewActionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receipt_id: ReceiptId,
        idempotency_key: IdempotencyKey,
        action_id: ReviewActionId,
        actor: ReviewActorId,
        outcome: ReviewReceiptOutcome,
        revision: Option<Revision>,
        current_revision: Option<Revision>,
        reconciliation: ReviewReconciliation,
    ) -> Result<Self, ReviewContractError> {
        let valid = match outcome {
            ReviewReceiptOutcome::Accepted => {
                revision.is_none()
                    && current_revision.is_none()
                    && reconciliation == ReviewReconciliation::PollReceipt
            }
            ReviewReceiptOutcome::Completed => {
                revision.is_some()
                    && current_revision.is_none()
                    && reconciliation == ReviewReconciliation::Final
            }
            ReviewReceiptOutcome::Refused => {
                revision.is_none()
                    && current_revision.is_none()
                    && reconciliation == ReviewReconciliation::Final
            }
            ReviewReceiptOutcome::Conflict => {
                revision.is_none()
                    && current_revision.is_some()
                    && reconciliation == ReviewReconciliation::Final
            }
            ReviewReceiptOutcome::Unknown => {
                revision.is_none()
                    && current_revision.is_none()
                    && reconciliation == ReviewReconciliation::PollReceipt
            }
        };
        if !valid {
            return Err(ReviewContractError::ReceiptInvalid);
        }
        Ok(Self {
            receipt_id,
            idempotency_key,
            action_id,
            actor,
            outcome,
            revision,
            current_revision,
            reconciliation,
        })
    }
    #[must_use]
    pub fn receipt_id(&self) -> &ReceiptId {
        &self.receipt_id
    }
    #[must_use]
    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
    #[must_use]
    pub fn action_id(&self) -> &ReviewActionId {
        &self.action_id
    }
    #[must_use]
    pub fn actor(&self) -> &ReviewActorId {
        &self.actor
    }
    #[must_use]
    pub const fn outcome(&self) -> ReviewReceiptOutcome {
        self.outcome
    }
    #[must_use]
    pub const fn revision(&self) -> Option<Revision> {
        self.revision
    }
    #[must_use]
    pub const fn current_revision(&self) -> Option<Revision> {
        self.current_revision
    }
    #[must_use]
    pub const fn reconciliation(&self) -> ReviewReconciliation {
        self.reconciliation
    }
}

fn validate_workspace(value: &WorkContextIdentity) -> Result<(), ReviewContractError> {
    if matches!(
        value.kind(),
        WorkContextTargetKind::UserWorkspace
            | WorkContextTargetKind::AttemptWorkspace
            | WorkContextTargetKind::Session
    ) {
        Ok(())
    } else {
        Err(ReviewContractError::WorkspaceInvalid)
    }
}

fn strict_by<T>(values: &[T], key: impl Fn(&T) -> &str) -> bool {
    values
        .windows(2)
        .all(|pair| key(&pair[0]).as_bytes() < key(&pair[1]).as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewContractError {
    Field(ValueError),
    UnknownEnum,
    PathInvalid,
    CounterOutOfRange,
    PreviewInvalid,
    HunkInvalid,
    AnchorInvalid,
    ProposalInvalid,
    AttentionInvalid,
    AuthorityInvalid,
    WorkspaceInvalid,
    CollectionInvalid,
    ReceiptInvalid,
    ActionInvalid,
}
impl From<ValueError> for ReviewContractError {
    fn from(value: ValueError) -> Self {
        Self::Field(value)
    }
}
impl fmt::Display for ReviewContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "review contract refused value: {self:?}")
    }
}
impl std::error::Error for ReviewContractError {}
