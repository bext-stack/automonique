// SPDX-License-Identifier: Elastic-2.0

//! Strict canonical JSON codecs for the Platform v2 review sub-contract.

use core::fmt;

use crate::codec::CodecError;
use crate::platform::{IdempotencyKey, ReceiptId};
use crate::platform_v2::{WorkContextIdentity, WorkContextTargetKind};
use crate::platform_v2_review::*;
use crate::primitives::{OpaqueId, Revision, ValueError};
use crate::wire::{JsonValue, parse_canonical};

pub const MAX_REVIEW_SNAPSHOT_CANONICAL_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_REVIEW_ACTION_CANONICAL_BYTES: usize = 32 * 1024;
pub const MAX_REVIEW_RECEIPT_CANONICAL_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewApiError {
    Codec(CodecError),
    Contract(ReviewContractError),
    InvalidBody,
    FrameTooLarge,
}
impl From<CodecError> for ReviewApiError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}
impl From<ReviewContractError> for ReviewApiError {
    fn from(value: ReviewContractError) -> Self {
        Self::Contract(value)
    }
}
impl From<ValueError> for ReviewApiError {
    fn from(value: ValueError) -> Self {
        Self::Contract(ReviewContractError::Field(value))
    }
}
impl ReviewApiError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Codec(error) => error.category(),
            Self::Contract(_) => "review_value_invalid",
            Self::InvalidBody => "review_invalid_body",
            Self::FrameTooLarge => "frame_too_large",
        }
    }
}
impl fmt::Display for ReviewApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "review codec refused document: {self:?}")
    }
}
impl std::error::Error for ReviewApiError {}

fn object(entries: Vec<(&str, JsonValue)>) -> JsonValue {
    JsonValue::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
fn text(value: impl Into<String>) -> JsonValue {
    JsonValue::String(value.into())
}
fn integer(value: u64) -> Result<JsonValue, ReviewApiError> {
    i64::try_from(value)
        .map(JsonValue::Integer)
        .map_err(|_| ReviewApiError::InvalidBody)
}
fn nullable_text(value: Option<&str>) -> JsonValue {
    value.map_or(JsonValue::Null, text)
}
fn nullable_integer(value: Option<u64>) -> Result<JsonValue, ReviewApiError> {
    value.map_or(Ok(JsonValue::Null), integer)
}
fn array(values: impl IntoIterator<Item = JsonValue>) -> JsonValue {
    JsonValue::Array(values.into_iter().collect())
}

fn fields<'a>(
    value: &'a JsonValue,
    expected: &[&str],
) -> Result<&'a [(String, JsonValue)], ReviewApiError> {
    let JsonValue::Object(entries) = value else {
        return Err(ReviewApiError::InvalidBody);
    };
    if entries.len() != expected.len()
        || entries
            .iter()
            .any(|(name, _)| !expected.contains(&name.as_str()))
    {
        return Err(ReviewApiError::InvalidBody);
    }
    Ok(entries)
}
fn get<'a>(value: &'a JsonValue, name: &str) -> Result<&'a JsonValue, ReviewApiError> {
    value.get(name).ok_or(ReviewApiError::InvalidBody)
}
fn string<'a>(value: &'a JsonValue, name: &str) -> Result<&'a str, ReviewApiError> {
    get(value, name)?
        .as_str()
        .ok_or(ReviewApiError::InvalidBody)
}
fn unsigned(value: &JsonValue, name: &str) -> Result<u64, ReviewApiError> {
    let raw = get(value, name)?
        .as_integer()
        .ok_or(ReviewApiError::InvalidBody)?;
    u64::try_from(raw).map_err(|_| ReviewApiError::InvalidBody)
}
fn boolean(value: &JsonValue, name: &str) -> Result<bool, ReviewApiError> {
    match get(value, name)? {
        JsonValue::Bool(value) => Ok(*value),
        _ => Err(ReviewApiError::InvalidBody),
    }
}
fn items<'a>(
    value: &'a JsonValue,
    name: &str,
    max: usize,
) -> Result<&'a [JsonValue], ReviewApiError> {
    let values = get(value, name)?
        .as_array()
        .ok_or(ReviewApiError::InvalidBody)?;
    if values.len() > max {
        return Err(ReviewApiError::InvalidBody);
    }
    Ok(values)
}
fn maybe_string<'a>(value: &'a JsonValue, name: &str) -> Result<Option<&'a str>, ReviewApiError> {
    match get(value, name)? {
        JsonValue::Null => Ok(None),
        JsonValue::String(value) => Ok(Some(value)),
        _ => Err(ReviewApiError::InvalidBody),
    }
}
fn maybe_unsigned(value: &JsonValue, name: &str) -> Result<Option<u64>, ReviewApiError> {
    match get(value, name)? {
        JsonValue::Null => Ok(None),
        JsonValue::Integer(value) => u64::try_from(*value)
            .map(Some)
            .map_err(|_| ReviewApiError::InvalidBody),
        _ => Err(ReviewApiError::InvalidBody),
    }
}
fn revision(value: u64) -> Result<Revision, ReviewApiError> {
    Revision::new(value).map_err(|_| ReviewApiError::InvalidBody)
}
fn parse(payload: &[u8], maximum: usize) -> Result<JsonValue, ReviewApiError> {
    if payload.len() > maximum {
        return Err(ReviewApiError::FrameTooLarge);
    }
    Ok(parse_canonical(payload)?)
}
fn encode(value: JsonValue, maximum: usize) -> Result<Vec<u8>, ReviewApiError> {
    let bytes = value.to_canonical_bytes();
    if bytes.len() > maximum {
        return Err(ReviewApiError::FrameTooLarge);
    }
    Ok(bytes)
}

fn workspace_json(value: &WorkContextIdentity) -> JsonValue {
    object(vec![
        ("id", text(value.id())),
        ("kind", text(value.kind().as_str())),
    ])
}
fn workspace(value: &JsonValue) -> Result<WorkContextIdentity, ReviewApiError> {
    fields(value, &["id", "kind"])?;
    let kind = WorkContextTargetKind::parse(string(value, "kind")?)
        .map_err(|_| ReviewApiError::InvalidBody)?;
    WorkContextIdentity::parse_local(kind, string(value, "id")?)
        .map_err(|_| ReviewApiError::InvalidBody)
}
fn authority_json(value: &ReviewAuthority) -> JsonValue {
    object(vec![
        ("id", text(value.id().as_str())),
        ("kind", text(value.kind().as_str())),
    ])
}
fn authority(value: &JsonValue) -> Result<ReviewAuthority, ReviewApiError> {
    fields(value, &["id", "kind"])?;
    Ok(ReviewAuthority::new(
        ReviewAuthorityKind::parse(string(value, "kind")?)?,
        ReviewAuthorityId::new(string(value, "id")?)?,
    ))
}
fn freshness_json(value: ReviewFreshness) -> Result<JsonValue, ReviewApiError> {
    Ok(object(vec![
        ("observed_at_ms", integer(value.observed_at_ms())?),
        (
            "observed_revision",
            integer(value.observed_revision().get())?,
        ),
        ("state", text(value.state().as_str())),
    ]))
}
fn freshness(value: &JsonValue) -> Result<ReviewFreshness, ReviewApiError> {
    fields(value, &["observed_at_ms", "observed_revision", "state"])?;
    Ok(ReviewFreshness::new(
        ReviewFreshnessState::parse(string(value, "state")?)?,
        revision(unsigned(value, "observed_revision")?)?,
        unsigned(value, "observed_at_ms")?,
    )?)
}
fn preview_json(value: &PreviewMetadata) -> Result<JsonValue, ReviewApiError> {
    Ok(object(vec![
        ("byte_size", nullable_integer(value.byte_size())?),
        ("height", nullable_integer(value.height().map(u64::from))?),
        ("kind", text(value.kind().as_str())),
        (
            "media_type",
            nullable_text(value.media_type().map(ReviewField::as_str)),
        ),
        ("sanitized", JsonValue::Bool(value.sanitized())),
        ("width", nullable_integer(value.width().map(u64::from))?),
    ]))
}
fn preview(value: &JsonValue) -> Result<PreviewMetadata, ReviewApiError> {
    fields(
        value,
        &[
            "byte_size",
            "height",
            "kind",
            "media_type",
            "sanitized",
            "width",
        ],
    )?;
    Ok(PreviewMetadata::new(
        PreviewKind::parse(string(value, "kind")?)?,
        maybe_string(value, "media_type")?
            .map(ReviewField::new)
            .transpose()?,
        maybe_unsigned(value, "byte_size")?,
        maybe_unsigned(value, "width")?
            .map(u32::try_from)
            .transpose()
            .map_err(|_| ReviewApiError::InvalidBody)?,
        maybe_unsigned(value, "height")?
            .map(u32::try_from)
            .transpose()
            .map_err(|_| ReviewApiError::InvalidBody)?,
        boolean(value, "sanitized")?,
    )?)
}
fn hunk_json(value: &DiffHunk) -> Result<JsonValue, ReviewApiError> {
    Ok(object(vec![
        ("id", text(value.id().as_str())),
        ("new_lines", integer(u64::from(value.new_lines()))?),
        ("new_start", integer(u64::from(value.new_start()))?),
        ("old_lines", integer(u64::from(value.old_lines()))?),
        ("old_start", integer(u64::from(value.old_start()))?),
        ("preview", text(value.preview().as_str())),
    ]))
}
fn hunk(value: &JsonValue) -> Result<DiffHunk, ReviewApiError> {
    fields(
        value,
        &[
            "id",
            "new_lines",
            "new_start",
            "old_lines",
            "old_start",
            "preview",
        ],
    )?;
    Ok(DiffHunk::new(
        ReviewHunkId::new(string(value, "id")?)?,
        u32::try_from(unsigned(value, "old_start")?).map_err(|_| ReviewApiError::InvalidBody)?,
        u32::try_from(unsigned(value, "old_lines")?).map_err(|_| ReviewApiError::InvalidBody)?,
        u32::try_from(unsigned(value, "new_start")?).map_err(|_| ReviewApiError::InvalidBody)?,
        u32::try_from(unsigned(value, "new_lines")?).map_err(|_| ReviewApiError::InvalidBody)?,
        ReviewHunkPreview::new(string(value, "preview")?)?,
    )?)
}
fn file_json(value: &ReviewFile) -> Result<JsonValue, ReviewApiError> {
    Ok(object(vec![
        ("change", text(value.change().as_str())),
        ("conflict", text(value.conflict().as_str())),
        (
            "hunks",
            array(
                value
                    .hunks()
                    .iter()
                    .map(hunk_json)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        ),
        ("id", text(value.id().as_str())),
        ("path", text(value.path().as_str())),
        ("preview", preview_json(value.preview())?),
        ("worktree", text(value.worktree().as_str())),
    ]))
}
fn file(value: &JsonValue) -> Result<ReviewFile, ReviewApiError> {
    fields(
        value,
        &[
            "change", "conflict", "hunks", "id", "path", "preview", "worktree",
        ],
    )?;
    Ok(ReviewFile::new(
        ReviewFileId::new(string(value, "id")?)?,
        RepositoryRelativePath::new(string(value, "path")?)?,
        DiffChangeKind::parse(string(value, "change")?)?,
        WorktreeFileState::parse(string(value, "worktree")?)?,
        preview(get(value, "preview")?)?,
        ConflictState::parse(string(value, "conflict")?)?,
        items(value, "hunks", MAX_REVIEW_HUNKS_PER_FILE)?
            .iter()
            .map(hunk)
            .collect::<Result<Vec<_>, _>>()?,
    )?)
}
fn anchor_json(value: &ReviewAnchor) -> Result<JsonValue, ReviewApiError> {
    Ok(object(vec![
        ("file_id", text(value.file_id().as_str())),
        ("hunk_id", text(value.hunk_id().as_str())),
        ("line", integer(u64::from(value.line()))?),
        ("side", text(value.side().as_str())),
    ]))
}
fn anchor(value: &JsonValue) -> Result<ReviewAnchor, ReviewApiError> {
    fields(value, &["file_id", "hunk_id", "line", "side"])?;
    Ok(ReviewAnchor::new(
        ReviewFileId::new(string(value, "file_id")?)?,
        ReviewHunkId::new(string(value, "hunk_id")?)?,
        DiffSide::parse(string(value, "side")?)?,
        u32::try_from(unsigned(value, "line")?).map_err(|_| ReviewApiError::InvalidBody)?,
    )?)
}
fn comment_json(value: &ReviewComment) -> Result<JsonValue, ReviewApiError> {
    Ok(object(vec![
        ("agent_state", text(value.agent_state().as_str())),
        ("anchor", anchor_json(value.anchor())?),
        ("actor", text(value.actor().as_str())),
        ("body", text(value.body().as_str())),
        ("id", text(value.id().as_str())),
        ("revision", integer(value.revision().get())?),
        ("unread", JsonValue::Bool(value.unread())),
    ]))
}
fn comment(value: &JsonValue) -> Result<ReviewComment, ReviewApiError> {
    fields(
        value,
        &[
            "agent_state",
            "anchor",
            "actor",
            "body",
            "id",
            "revision",
            "unread",
        ],
    )?;
    Ok(ReviewComment::new(
        ReviewCommentId::new(string(value, "id")?)?,
        revision(unsigned(value, "revision")?)?,
        ReviewActorId::new(string(value, "actor")?)?,
        ReviewText::new(string(value, "body")?)?,
        anchor(get(value, "anchor")?)?,
        CommentAgentState::parse(string(value, "agent_state")?)?,
        boolean(value, "unread")?,
    ))
}
fn proposal_json(value: &ReviewProposal) -> JsonValue {
    object(vec![
        (
            "files",
            array(value.files().iter().map(|id| text(id.as_str()))),
        ),
        ("id", text(value.id().as_str())),
        ("kind", text(value.kind().as_str())),
        (
            "subject",
            nullable_text(value.subject().map(ReviewField::as_str)),
        ),
    ])
}
fn proposal(value: &JsonValue) -> Result<ReviewProposal, ReviewApiError> {
    fields(value, &["files", "id", "kind", "subject"])?;
    Ok(ReviewProposal::new(
        ReviewProposalId::new(string(value, "id")?)?,
        ReviewProposalKind::parse(string(value, "kind")?)?,
        items(value, "files", MAX_REVIEW_PROPOSAL_FILES)?
            .iter()
            .map(|item| {
                item.as_str()
                    .ok_or(ReviewApiError::InvalidBody)
                    .and_then(|v| {
                        ReviewFileId::new(v)
                            .map_err(ReviewContractError::from)
                            .map_err(ReviewApiError::from)
                    })
            })
            .collect::<Result<Vec<_>, _>>()?,
        maybe_string(value, "subject")?
            .map(ReviewField::new)
            .transpose()?,
    )?)
}
fn check_json(value: &CheckProjection) -> Result<JsonValue, ReviewApiError> {
    Ok(object(vec![
        ("authority", authority_json(value.authority())),
        ("freshness", freshness_json(value.freshness())?),
        ("id", text(value.id().as_str())),
        ("required", JsonValue::Bool(value.required())),
        ("state", text(value.state().as_str())),
    ]))
}
fn check(value: &JsonValue) -> Result<CheckProjection, ReviewApiError> {
    fields(
        value,
        &["authority", "freshness", "id", "required", "state"],
    )?;
    Ok(CheckProjection::new(
        ReviewCheckId::new(string(value, "id")?)?,
        CheckState::parse(string(value, "state")?)?,
        authority(get(value, "authority")?)?,
        freshness(get(value, "freshness")?)?,
        boolean(value, "required")?,
    )?)
}
fn review_json(value: &ReviewStatusProjection) -> Result<JsonValue, ReviewApiError> {
    Ok(object(vec![
        ("authority", authority_json(value.authority())),
        ("decision", text(value.decision().as_str())),
        ("freshness", freshness_json(value.freshness())?),
    ]))
}
fn review(value: &JsonValue) -> Result<ReviewStatusProjection, ReviewApiError> {
    fields(value, &["authority", "decision", "freshness"])?;
    Ok(ReviewStatusProjection::new(
        ReviewDecision::parse(string(value, "decision")?)?,
        authority(get(value, "authority")?)?,
        freshness(get(value, "freshness")?)?,
    )?)
}
fn pull_request_json(value: &PullRequestProjection) -> Result<JsonValue, ReviewApiError> {
    Ok(object(vec![
        ("authority", authority_json(value.authority())),
        ("freshness", freshness_json(value.freshness())?),
        (
            "head_revision",
            nullable_text(value.head_revision().map(ReviewField::as_str)),
        ),
        ("id", nullable_text(value.id().map(OpaqueId::as_str))),
        ("readiness", text(value.readiness().as_str())),
        ("state", text(value.state().as_str())),
    ]))
}
fn pull_request(value: &JsonValue) -> Result<PullRequestProjection, ReviewApiError> {
    fields(
        value,
        &[
            "authority",
            "freshness",
            "head_revision",
            "id",
            "readiness",
            "state",
        ],
    )?;
    Ok(PullRequestProjection::new(
        maybe_string(value, "id")?
            .map(PullRequestId::new)
            .transpose()?,
        PullRequestState::parse(string(value, "state")?)?,
        MergeReadiness::parse(string(value, "readiness")?)?,
        maybe_string(value, "head_revision")?
            .map(ReviewField::new)
            .transpose()?,
        authority(get(value, "authority")?)?,
        freshness(get(value, "freshness")?)?,
    )?)
}
fn delivery_json(value: &DeliveryProjection) -> Result<JsonValue, ReviewApiError> {
    Ok(object(vec![
        ("authority", authority_json(value.authority())),
        ("freshness", freshness_json(value.freshness())?),
        ("id", nullable_text(value.id().map(OpaqueId::as_str))),
        ("state", text(value.state().as_str())),
    ]))
}
fn delivery(value: &JsonValue) -> Result<DeliveryProjection, ReviewApiError> {
    fields(value, &["authority", "freshness", "id", "state"])?;
    Ok(DeliveryProjection::new(
        maybe_string(value, "id")?
            .map(DeliveryId::new)
            .transpose()?,
        DeliveryState::parse(string(value, "state")?)?,
        authority(get(value, "authority")?)?,
        freshness(get(value, "freshness")?)?,
    )?)
}
fn attention_json(value: AttentionProjection) -> Result<JsonValue, ReviewApiError> {
    Ok(object(vec![
        ("reason", text(value.reason().as_str())),
        ("source_revision", integer(value.source_revision().get())?),
        ("state", text(value.state().as_str())),
        ("unread", integer(u64::from(value.unread()))?),
    ]))
}
fn attention(value: &JsonValue) -> Result<AttentionProjection, ReviewApiError> {
    fields(value, &["reason", "source_revision", "state", "unread"])?;
    let reason = AttentionReason::parse(string(value, "reason")?)?;
    let event = AttentionEvent::new(
        reason,
        u32::try_from(unsigned(value, "unread")?).map_err(|_| ReviewApiError::InvalidBody)?,
        revision(unsigned(value, "source_revision")?)?,
    )?;
    let projection = AttentionProjection::derive(&[event], event.source_revision())?;
    if projection.state() != AttentionState::parse(string(value, "state")?)? {
        return Err(ReviewApiError::InvalidBody);
    }
    Ok(projection)
}
fn attention_event_json(value: AttentionEvent) -> Result<JsonValue, ReviewApiError> {
    Ok(object(vec![
        ("reason", text(value.reason().as_str())),
        ("source_revision", integer(value.source_revision().get())?),
        ("unread", integer(u64::from(value.unread()))?),
    ]))
}
fn attention_event(value: &JsonValue) -> Result<AttentionEvent, ReviewApiError> {
    fields(value, &["reason", "source_revision", "unread"])?;
    Ok(AttentionEvent::new(
        AttentionReason::parse(string(value, "reason")?)?,
        u32::try_from(unsigned(value, "unread")?).map_err(|_| ReviewApiError::InvalidBody)?,
        revision(unsigned(value, "source_revision")?)?,
    )?)
}

pub fn encode_review_snapshot(value: &ReviewSnapshot) -> Result<Vec<u8>, ReviewApiError> {
    encode(
        object(vec![
            ("attention", attention_json(value.attention())?),
            (
                "attention_events",
                array(
                    value
                        .attention_events()
                        .iter()
                        .copied()
                        .map(attention_event_json)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            ),
            (
                "checks",
                array(
                    value
                        .checks()
                        .iter()
                        .map(check_json)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            ),
            (
                "comments",
                array(
                    value
                        .comments()
                        .iter()
                        .map(comment_json)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            ),
            ("delivery", delivery_json(value.delivery())?),
            (
                "files",
                array(
                    value
                        .files()
                        .iter()
                        .map(file_json)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            ),
            (
                "platform_version",
                integer(u64::from(PLATFORM_REVIEW_REQUIRES_PLATFORM_MAJOR))?,
            ),
            (
                "proposals",
                array(value.proposals().iter().map(proposal_json)),
            ),
            ("pull_request", pull_request_json(value.pull_request())?),
            ("review", review_json(value.review())?),
            ("revision", integer(value.revision().get())?),
            ("schema", text(PLATFORM_REVIEW_SCHEMA_V1)),
            ("workspace", workspace_json(value.workspace())),
        ]),
        MAX_REVIEW_SNAPSHOT_CANONICAL_BYTES,
    )
}
pub fn decode_review_snapshot(payload: &[u8]) -> Result<ReviewSnapshot, ReviewApiError> {
    let value = parse(payload, MAX_REVIEW_SNAPSHOT_CANONICAL_BYTES)?;
    fields(
        &value,
        &[
            "attention",
            "attention_events",
            "checks",
            "comments",
            "delivery",
            "files",
            "platform_version",
            "proposals",
            "pull_request",
            "review",
            "revision",
            "schema",
            "workspace",
        ],
    )?;
    if string(&value, "schema")? != PLATFORM_REVIEW_SCHEMA_V1
        || unsigned(&value, "platform_version")?
            != u64::from(PLATFORM_REVIEW_REQUIRES_PLATFORM_MAJOR)
    {
        return Err(ReviewApiError::InvalidBody);
    }
    let carried_attention = attention(get(&value, "attention")?)?;
    let snapshot = ReviewSnapshot::new(
        workspace(get(&value, "workspace")?)?,
        revision(unsigned(&value, "revision")?)?,
        items(&value, "files", MAX_REVIEW_FILES)?
            .iter()
            .map(file)
            .collect::<Result<Vec<_>, _>>()?,
        items(&value, "comments", MAX_REVIEW_COMMENTS)?
            .iter()
            .map(comment)
            .collect::<Result<Vec<_>, _>>()?,
        items(&value, "proposals", MAX_REVIEW_PROPOSALS)?
            .iter()
            .map(proposal)
            .collect::<Result<Vec<_>, _>>()?,
        items(&value, "checks", MAX_REVIEW_CHECKS)?
            .iter()
            .map(check)
            .collect::<Result<Vec<_>, _>>()?,
        review(get(&value, "review")?)?,
        pull_request(get(&value, "pull_request")?)?,
        delivery(get(&value, "delivery")?)?,
        items(&value, "attention_events", MAX_REVIEW_ATTENTION_EVENTS)?
            .iter()
            .map(attention_event)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    if snapshot.attention() != carried_attention {
        return Err(ReviewApiError::InvalidBody);
    }
    Ok(snapshot)
}

fn action_json(value: &ReviewAction) -> Result<JsonValue, ReviewApiError> {
    let (kind, payload) = match value {
        ReviewAction::AddComment {
            comment_id,
            anchor,
            body,
        } => (
            ReviewActionKind::AddComment,
            object(vec![
                ("anchor", anchor_json(anchor)?),
                ("body", text(body.as_str())),
                ("comment_id", text(comment_id.as_str())),
            ]),
        ),
        ReviewAction::SendCommentToAgent {
            comment_id,
            expected_comment_revision,
        } => (
            ReviewActionKind::SendCommentToAgent,
            object(vec![
                ("comment_id", text(comment_id.as_str())),
                (
                    "expected_comment_revision",
                    integer(expected_comment_revision.get())?,
                ),
            ]),
        ),
        ReviewAction::ApproveReview {
            expected_review_revision,
        } => (
            ReviewActionKind::ApproveReview,
            object(vec![(
                "expected_review_revision",
                integer(expected_review_revision.get())?,
            )]),
        ),
        ReviewAction::RerunCheck {
            check_id,
            expected_check_revision,
        } => (
            ReviewActionKind::RerunCheck,
            object(vec![
                ("check_id", text(check_id.as_str())),
                (
                    "expected_check_revision",
                    integer(expected_check_revision.get())?,
                ),
            ]),
        ),
        ReviewAction::OpenPullRequest {
            expected_pull_request_revision,
            title,
        } => (
            ReviewActionKind::OpenPullRequest,
            object(vec![
                (
                    "expected_pull_request_revision",
                    integer(expected_pull_request_revision.get())?,
                ),
                ("title", text(title.as_str())),
            ]),
        ),
        ReviewAction::UpdatePullRequest {
            pull_request_id,
            expected_pull_request_revision,
            title,
        } => (
            ReviewActionKind::UpdatePullRequest,
            object(vec![
                (
                    "expected_pull_request_revision",
                    integer(expected_pull_request_revision.get())?,
                ),
                ("pull_request_id", text(pull_request_id.as_str())),
                ("title", text(title.as_str())),
            ]),
        ),
        ReviewAction::MergePullRequest {
            pull_request_id,
            expected_pull_request_revision,
            expected_head_revision,
        } => (
            ReviewActionKind::MergePullRequest,
            object(vec![
                (
                    "expected_head_revision",
                    text(expected_head_revision.as_str()),
                ),
                (
                    "expected_pull_request_revision",
                    integer(expected_pull_request_revision.get())?,
                ),
                ("pull_request_id", text(pull_request_id.as_str())),
            ]),
        ),
    };
    Ok(object(vec![
        ("kind", text(kind.as_str())),
        ("payload", payload),
    ]))
}
fn action(value: &JsonValue) -> Result<ReviewAction, ReviewApiError> {
    fields(value, &["kind", "payload"])?;
    let payload = get(value, "payload")?;
    Ok(match ReviewActionKind::parse(string(value, "kind")?)? {
        ReviewActionKind::AddComment => {
            fields(payload, &["anchor", "body", "comment_id"])?;
            ReviewAction::AddComment {
                comment_id: ReviewCommentId::new(string(payload, "comment_id")?)?,
                anchor: anchor(get(payload, "anchor")?)?,
                body: ReviewText::new(string(payload, "body")?)?,
            }
        }
        ReviewActionKind::SendCommentToAgent => {
            fields(payload, &["comment_id", "expected_comment_revision"])?;
            ReviewAction::SendCommentToAgent {
                comment_id: ReviewCommentId::new(string(payload, "comment_id")?)?,
                expected_comment_revision: revision(unsigned(
                    payload,
                    "expected_comment_revision",
                )?)?,
            }
        }
        ReviewActionKind::ApproveReview => {
            fields(payload, &["expected_review_revision"])?;
            ReviewAction::ApproveReview {
                expected_review_revision: revision(unsigned(payload, "expected_review_revision")?)?,
            }
        }
        ReviewActionKind::RerunCheck => {
            fields(payload, &["check_id", "expected_check_revision"])?;
            ReviewAction::RerunCheck {
                check_id: ReviewCheckId::new(string(payload, "check_id")?)?,
                expected_check_revision: revision(unsigned(payload, "expected_check_revision")?)?,
            }
        }
        ReviewActionKind::OpenPullRequest => {
            fields(payload, &["expected_pull_request_revision", "title"])?;
            ReviewAction::OpenPullRequest {
                expected_pull_request_revision: revision(unsigned(
                    payload,
                    "expected_pull_request_revision",
                )?)?,
                title: ReviewField::new(string(payload, "title")?)?,
            }
        }
        ReviewActionKind::UpdatePullRequest => {
            fields(
                payload,
                &["expected_pull_request_revision", "pull_request_id", "title"],
            )?;
            ReviewAction::UpdatePullRequest {
                pull_request_id: PullRequestId::new(string(payload, "pull_request_id")?)?,
                expected_pull_request_revision: revision(unsigned(
                    payload,
                    "expected_pull_request_revision",
                )?)?,
                title: ReviewField::new(string(payload, "title")?)?,
            }
        }
        ReviewActionKind::MergePullRequest => {
            fields(
                payload,
                &[
                    "expected_head_revision",
                    "expected_pull_request_revision",
                    "pull_request_id",
                ],
            )?;
            ReviewAction::MergePullRequest {
                pull_request_id: PullRequestId::new(string(payload, "pull_request_id")?)?,
                expected_pull_request_revision: revision(unsigned(
                    payload,
                    "expected_pull_request_revision",
                )?)?,
                expected_head_revision: ReviewField::new(string(
                    payload,
                    "expected_head_revision",
                )?)?,
            }
        }
    })
}
pub fn encode_review_action_request(
    value: &ReviewActionRequest,
) -> Result<Vec<u8>, ReviewApiError> {
    encode(
        object(vec![
            ("action", action_json(value.action())?),
            ("actor", text(value.actor().as_str())),
            ("authentication", text(value.authentication().as_str())),
            ("authority", authority_json(value.authority())),
            (
                "expected_revision",
                integer(value.expected_revision().get())?,
            ),
            ("idempotency_key", text(value.idempotency_key().as_str())),
            (
                "platform_version",
                integer(u64::from(PLATFORM_REVIEW_REQUIRES_PLATFORM_MAJOR))?,
            ),
            ("schema", text(PLATFORM_REVIEW_SCHEMA_V1)),
            ("workspace", workspace_json(value.workspace())),
        ]),
        MAX_REVIEW_ACTION_CANONICAL_BYTES,
    )
}
pub fn decode_review_action_request(payload: &[u8]) -> Result<ReviewActionRequest, ReviewApiError> {
    let value = parse(payload, MAX_REVIEW_ACTION_CANONICAL_BYTES)?;
    fields(
        &value,
        &[
            "action",
            "actor",
            "authentication",
            "authority",
            "expected_revision",
            "idempotency_key",
            "platform_version",
            "schema",
            "workspace",
        ],
    )?;
    if string(&value, "schema")? != PLATFORM_REVIEW_SCHEMA_V1
        || unsigned(&value, "platform_version")? != 2
    {
        return Err(ReviewApiError::InvalidBody);
    }
    Ok(ReviewActionRequest::new(
        workspace(get(&value, "workspace")?)?,
        revision(unsigned(&value, "expected_revision")?)?,
        ReviewActorId::new(string(&value, "actor")?)?,
        ReviewAuthentication::parse(string(&value, "authentication")?)?,
        authority(get(&value, "authority")?)?,
        IdempotencyKey::new(string(&value, "idempotency_key")?)?,
        action(get(&value, "action")?)?,
    )?)
}

pub fn encode_review_action_receipt(
    value: &ReviewActionReceipt,
) -> Result<Vec<u8>, ReviewApiError> {
    encode(
        object(vec![
            ("action_id", text(value.action_id().as_str())),
            ("actor", text(value.actor().as_str())),
            (
                "current_revision",
                nullable_integer(value.current_revision().map(Revision::get))?,
            ),
            ("idempotency_key", text(value.idempotency_key().as_str())),
            ("outcome", text(value.outcome().as_str())),
            ("platform_version", integer(2)?),
            ("receipt_id", text(value.receipt_id().as_str())),
            ("reconciliation", text(value.reconciliation().as_str())),
            (
                "revision",
                nullable_integer(value.revision().map(Revision::get))?,
            ),
            ("schema", text(PLATFORM_REVIEW_SCHEMA_V1)),
        ]),
        MAX_REVIEW_RECEIPT_CANONICAL_BYTES,
    )
}
pub fn decode_review_action_receipt(payload: &[u8]) -> Result<ReviewActionReceipt, ReviewApiError> {
    let value = parse(payload, MAX_REVIEW_RECEIPT_CANONICAL_BYTES)?;
    fields(
        &value,
        &[
            "action_id",
            "actor",
            "current_revision",
            "idempotency_key",
            "outcome",
            "platform_version",
            "receipt_id",
            "reconciliation",
            "revision",
            "schema",
        ],
    )?;
    if string(&value, "schema")? != PLATFORM_REVIEW_SCHEMA_V1
        || unsigned(&value, "platform_version")? != 2
    {
        return Err(ReviewApiError::InvalidBody);
    }
    Ok(ReviewActionReceipt::new(
        ReceiptId::new(string(&value, "receipt_id")?)?,
        IdempotencyKey::new(string(&value, "idempotency_key")?)?,
        ReviewActionId::new(string(&value, "action_id")?)?,
        ReviewActorId::new(string(&value, "actor")?)?,
        ReviewReceiptOutcome::parse(string(&value, "outcome")?)?,
        maybe_unsigned(&value, "revision")?
            .map(revision)
            .transpose()?,
        maybe_unsigned(&value, "current_revision")?
            .map(revision)
            .transpose()?,
        ReviewReconciliation::parse(string(&value, "reconciliation")?)?,
    )?)
}
