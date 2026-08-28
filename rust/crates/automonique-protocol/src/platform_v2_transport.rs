// SPDX-License-Identifier: Elastic-2.0

//! Correlated envelopes for Platform negotiation and the additive Platform v2 lane.
//!
//! Platform v1 remains owned by [`crate::platform_api`]. Negotiation has its
//! own protocol name and major, while structured work-context traffic uses
//! major two of the existing Platform protocol. A decoder never tries one
//! major's body as another major after a refusal.

use core::fmt;
use core::str::FromStr;
use std::collections::{BTreeMap, BTreeSet};

use crate::codec::{
    CodecError, Envelope, FrameDecode, MajorVersion, MessageKind, ProtocolName, RequestId,
    SupportedProtocol, VersionRange, decode_frame_with_limit, encode_frame_with_limit,
};
use crate::platform::{IdempotencyKey, PLATFORM_PROTOCOL, ReceiptId};
use crate::platform_v2::{
    NegotiatedPlatform, PLATFORM_SCHEMA_V2, PlatformVersion, PlatformVersionOffer, ProjectId,
    UserWorkspaceId, WorkContextIdentity, WorkContextPage, WorkContextQuery, WorkContextRecord,
    WorkContextResync, WorkContextTargetKind,
};
use crate::platform_v2_api::{
    MAX_PLATFORM_NEGOTIATION_CANONICAL_BYTES, WorkContextApiError, decode_negotiated_platform,
    decode_platform_version_offer, decode_work_context_page, decode_work_context_query,
    decode_work_context_resync, encode_negotiated_platform, encode_platform_version_offer,
    encode_work_context_page, encode_work_context_query, encode_work_context_resync, exact_fields,
    identity, identity_json, object, record, record_json, string,
};
use crate::platform_v2_lifecycle::{
    MAX_MUTATION_CANONICAL_BYTES, MutationApproval, MutationApprovalDecision, MutationApprovalId,
    MutationPreview, MutationPreviewDigest, MutationPreviewRef, MutationReceipt, MutationRefusal,
    WorkContextMutationIntent,
};
use crate::platform_v2_lifecycle_api::{
    LifecycleApiError, decode_work_context_mutation_approval, decode_work_context_mutation_preview,
    decode_work_context_mutation_receipt, decode_work_context_mutation_refusal,
    encode_work_context_mutation_approval, encode_work_context_mutation_preview,
    encode_work_context_mutation_receipt, encode_work_context_mutation_refusal, intent,
    intent_json,
};
use crate::platform_v2_lineage::{
    LineageProjection, WorkspaceIntent, WorkspaceIntentId, WorkspaceIntentOutcome,
};
use crate::platform_v2_lineage_api::{
    LineageApiError, decode_lineage_projection, decode_workspace_intent,
    decode_workspace_intent_outcome, encode_lineage_projection, encode_workspace_intent,
    encode_workspace_intent_outcome,
};
use crate::platform_v2_review::{
    PLATFORM_REVIEW_REQUIRES_PLATFORM_MAJOR, PLATFORM_REVIEW_SCHEMA_V1, ReviewAction,
    ReviewActionReceipt, ReviewSnapshot,
};
use crate::platform_v2_review_api::{
    MAX_REVIEW_SNAPSHOT_CANONICAL_BYTES, ReviewApiError, action, action_json,
    decode_review_action_receipt, decode_review_snapshot, encode_review_action_receipt,
    encode_review_snapshot,
};
use crate::primitives::{BoundedString, Revision, ValueError};
use crate::wire::{JsonValue, Message, parse_canonical};

/// Protocol used only to select a Platform major.
pub const PLATFORM_NEGOTIATION_PROTOCOL: &str = "automonique.platform.negotiation";
/// Negotiation is a stable protocol of its own, currently at major one.
pub const PLATFORM_NEGOTIATION_MAJOR: u32 = 1;
/// Structured work-context traffic is major two of `automonique.platform`.
pub const PLATFORM_V2_MAJOR: u32 = 2;

/// Audited worst-case bytes added by the canonical message envelope.
pub const PLATFORM_V2_ENVELOPE_OVERHEAD_BYTES: usize = 512;
pub const MAX_PLATFORM_NEGOTIATION_REQUEST_CANONICAL_BYTES: usize =
    MAX_PLATFORM_NEGOTIATION_CANONICAL_BYTES + PLATFORM_V2_ENVELOPE_OVERHEAD_BYTES;
pub const MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES: usize =
    MAX_PLATFORM_NEGOTIATION_CANONICAL_BYTES + PLATFORM_V2_ENVELOPE_OVERHEAD_BYTES;
pub const MAX_PLATFORM_V2_REQUEST_CANONICAL_BYTES: usize =
    512 * 1024 + PLATFORM_V2_ENVELOPE_OVERHEAD_BYTES;
pub const MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES: usize =
    8 * 1024 * 1024 + PLATFORM_V2_ENVELOPE_OVERHEAD_BYTES;

const _: () = assert!(
    MAX_REVIEW_SNAPSHOT_CANONICAL_BYTES + PLATFORM_V2_ENVELOPE_OVERHEAD_BYTES
        <= MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES
);
const _: () = assert!(MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES <= u32::MAX as usize);

pub type PlatformV2RefusalCategory = BoundedString<128>;
pub type PlatformV2RefusalExplanation = BoundedString<512>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformV2Refusal {
    category: PlatformV2RefusalCategory,
    explanation: PlatformV2RefusalExplanation,
}
impl PlatformV2Refusal {
    pub fn new(
        category: impl Into<String>,
        explanation: impl Into<String>,
    ) -> Result<Self, ValueError> {
        Ok(Self {
            category: PlatformV2RefusalCategory::new(category.into())?,
            explanation: PlatformV2RefusalExplanation::new(explanation.into())?,
        })
    }
    #[must_use]
    pub const fn category(&self) -> &PlatformV2RefusalCategory {
        &self.category
    }
    #[must_use]
    pub const fn explanation(&self) -> &PlatformV2RefusalExplanation {
        &self.explanation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformV2TransportError {
    Codec(CodecError),
    WorkContext(WorkContextApiError),
    Lifecycle(LifecycleApiError),
    Lineage(LineageApiError),
    Review(ReviewApiError),
    InvalidBody,
    CorrelationMismatch,
    NegotiationMismatch,
    ResponseMismatch,
    UnknownKind,
    FrameTooLarge {
        max_bytes: usize,
        actual_bytes: usize,
    },
}
impl PlatformV2TransportError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Codec(value) => value.category(),
            Self::WorkContext(value) => value.category(),
            Self::Lifecycle(value) => value.category(),
            Self::Lineage(value) => value.category(),
            Self::Review(value) => value.category(),
            Self::InvalidBody => "platform_v2_invalid_body",
            Self::CorrelationMismatch => "platform_v2_correlation_mismatch",
            Self::NegotiationMismatch => "platform_negotiation_mismatch",
            Self::ResponseMismatch => "platform_v2_response_mismatch",
            Self::UnknownKind => "platform_v2_unknown_kind",
            Self::FrameTooLarge { .. } => "frame_too_large",
        }
    }
}
impl fmt::Display for PlatformV2TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.category())
    }
}
impl std::error::Error for PlatformV2TransportError {}
impl From<CodecError> for PlatformV2TransportError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}
impl From<WorkContextApiError> for PlatformV2TransportError {
    fn from(value: WorkContextApiError) -> Self {
        Self::WorkContext(value)
    }
}
impl From<LifecycleApiError> for PlatformV2TransportError {
    fn from(value: LifecycleApiError) -> Self {
        Self::Lifecycle(value)
    }
}
impl From<LineageApiError> for PlatformV2TransportError {
    fn from(value: LineageApiError) -> Self {
        Self::Lineage(value)
    }
}
impl From<ReviewApiError> for PlatformV2TransportError {
    fn from(value: ReviewApiError) -> Self {
        Self::Review(value)
    }
}

fn major(value: u32) -> MajorVersion {
    MajorVersion::new(value).expect("non-zero protocol major")
}
fn supported(protocol: &str, version: u32) -> Result<SupportedProtocol, CodecError> {
    Ok(SupportedProtocol::new(
        ProtocolName::new(protocol)?,
        VersionRange::exact(major(version)),
    ))
}
fn envelope(
    protocol: &str,
    version: u32,
    request_id: RequestId,
    kind: &str,
) -> Result<Envelope, CodecError> {
    Ok(Envelope::new(
        ProtocolName::new(protocol)?,
        major(version),
        request_id,
        MessageKind::new(kind)?,
    ))
}
fn admitted(
    payload: &[u8],
    maximum: usize,
    protocol: &str,
    version: u32,
) -> Result<Message, PlatformV2TransportError> {
    if payload.len() > maximum {
        return Err(PlatformV2TransportError::FrameTooLarge {
            max_bytes: maximum,
            actual_bytes: payload.len(),
        });
    }
    Ok(Message::from_canonical_bytes_admitted(
        payload,
        &[supported(protocol, version)?],
    )?)
}
fn encoded(message: Message, maximum: usize) -> Result<Vec<u8>, PlatformV2TransportError> {
    let bytes = message.to_canonical_bytes();
    if bytes.len() > maximum {
        Err(PlatformV2TransportError::FrameTooLarge {
            max_bytes: maximum,
            actual_bytes: bytes.len(),
        })
    } else {
        Ok(bytes)
    }
}
fn document(bytes: Vec<u8>) -> Result<JsonValue, PlatformV2TransportError> {
    Ok(parse_canonical(&bytes)?)
}
fn body_document(message: &Message) -> Vec<u8> {
    message.body().to_canonical_bytes()
}
fn framed_payload(input: &[u8], maximum: usize) -> Result<&[u8], PlatformV2TransportError> {
    match decode_frame_with_limit(input, maximum)? {
        FrameDecode::Frame { payload, consumed } if consumed == input.len() => Ok(payload),
        FrameDecode::Frame { .. } | FrameDecode::NeedMore { .. } => {
            Err(PlatformV2TransportError::InvalidBody)
        }
    }
}
fn framed(bytes: &[u8], maximum: usize) -> Result<Vec<u8>, PlatformV2TransportError> {
    let mut frame = Vec::with_capacity(crate::codec::LENGTH_PREFIX_BYTES + bytes.len());
    encode_frame_with_limit(bytes, &mut frame, maximum)?;
    Ok(frame)
}
fn v2() -> NegotiatedPlatform {
    NegotiatedPlatform::new(
        PlatformVersion::V2,
        PLATFORM_SCHEMA_V2,
        crate::platform_v2::WorkContextAvailability::V2Structured,
    )
    .expect("coherent Platform v2 negotiation")
}

/// Client-owned inputs for preparing a mutation.
///
/// The authenticated actor, tenant, serving authority, authority ceiling,
/// request digest, preview identity, and trusted times are deliberately absent.
/// A host must inject those values when it constructs the authoritative
/// [`crate::platform_v2_lifecycle::WorkContextMutationProposal`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationPrepareRequest {
    idempotency_key: IdempotencyKey,
    intent: WorkContextMutationIntent,
}
impl MutationPrepareRequest {
    #[must_use]
    pub const fn new(idempotency_key: IdempotencyKey, intent: WorkContextMutationIntent) -> Self {
        Self {
            idempotency_key,
            intent,
        }
    }
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
    #[must_use]
    pub const fn intent(&self) -> &WorkContextMutationIntent {
        &self.intent
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationDecisionRequest {
    preview: MutationPreviewRef,
    preview_digest: MutationPreviewDigest,
    decision: MutationApprovalDecision,
}
impl MutationDecisionRequest {
    #[must_use]
    pub const fn new(
        preview: MutationPreviewRef,
        preview_digest: MutationPreviewDigest,
        decision: MutationApprovalDecision,
    ) -> Self {
        Self {
            preview,
            preview_digest,
            decision,
        }
    }
    #[must_use]
    pub const fn preview(&self) -> &MutationPreviewRef {
        &self.preview
    }
    #[must_use]
    pub const fn preview_digest(&self) -> MutationPreviewDigest {
        self.preview_digest
    }
    #[must_use]
    pub const fn decision(&self) -> MutationApprovalDecision {
        self.decision
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationSubmitRequest {
    preview: MutationPreviewRef,
    preview_digest: MutationPreviewDigest,
    approval: Option<MutationApprovalId>,
}
impl MutationSubmitRequest {
    #[must_use]
    pub const fn new(
        preview: MutationPreviewRef,
        preview_digest: MutationPreviewDigest,
        approval: Option<MutationApprovalId>,
    ) -> Self {
        Self {
            preview,
            preview_digest,
            approval,
        }
    }
    #[must_use]
    pub const fn preview(&self) -> &MutationPreviewRef {
        &self.preview
    }
    #[must_use]
    pub const fn preview_digest(&self) -> MutationPreviewDigest {
        self.preview_digest
    }
    #[must_use]
    pub const fn approval(&self) -> Option<&MutationApprovalId> {
        self.approval.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiptLookupKey {
    ReceiptId(ReceiptId),
    IdempotencyKey(IdempotencyKey),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationReceiptLookup {
    project: ProjectId,
    key: ReceiptLookupKey,
}
impl MutationReceiptLookup {
    #[must_use]
    pub const fn new(project: ProjectId, key: ReceiptLookupKey) -> Self {
        Self { project, key }
    }
    #[must_use]
    pub const fn project(&self) -> &ProjectId {
        &self.project
    }
    #[must_use]
    pub const fn key(&self) -> &ReceiptLookupKey {
        &self.key
    }
}

/// Closed lifecycle operations a capability response must describe for every
/// server-issued project root. Keeping unavailable operations in the response
/// prevents clients from confusing an omitted future action with permission.
pub const LIFECYCLE_CAPABILITY_EFFECT_KINDS: [&str; 5] = [
    "create_attempt_workspace",
    "create_checkout",
    "create_host_setup",
    "resume_attempt_workspace",
    "resume_session",
];

pub type LifecycleCapabilityCategory = BoundedString<128>;

/// One action-specific capability under one authenticated project root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleOperationCapability {
    project: ProjectId,
    effect_kind: String,
    category: Option<LifecycleCapabilityCategory>,
}

impl LifecycleOperationCapability {
    pub fn available(
        project: ProjectId,
        effect_kind: impl Into<String>,
    ) -> Result<Self, PlatformV2TransportError> {
        Self::new(project, effect_kind.into(), None)
    }

    pub fn unavailable(
        project: ProjectId,
        effect_kind: impl Into<String>,
        category: impl Into<String>,
    ) -> Result<Self, PlatformV2TransportError> {
        Self::new(
            project,
            effect_kind.into(),
            Some(
                LifecycleCapabilityCategory::new(category.into())
                    .map_err(|_| PlatformV2TransportError::InvalidBody)?,
            ),
        )
    }

    fn new(
        project: ProjectId,
        effect_kind: String,
        category: Option<LifecycleCapabilityCategory>,
    ) -> Result<Self, PlatformV2TransportError> {
        if !LIFECYCLE_CAPABILITY_EFFECT_KINDS.contains(&effect_kind.as_str()) {
            return Err(PlatformV2TransportError::InvalidBody);
        }
        Ok(Self {
            project,
            effect_kind,
            category,
        })
    }

    #[must_use]
    pub const fn project(&self) -> &ProjectId {
        &self.project
    }

    #[must_use]
    pub fn effect_kind(&self) -> &str {
        &self.effect_kind
    }

    #[must_use]
    pub const fn available_now(&self) -> bool {
        self.category.is_none()
    }

    #[must_use]
    pub const fn category(&self) -> Option<&LifecycleCapabilityCategory> {
        self.category.as_ref()
    }
}

/// Fenced project roots and complete action-specific lifecycle capability
/// truth observed by the daemon for one authenticated principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleCapabilities {
    projects: BTreeSet<ProjectId>,
    operations: Vec<LifecycleOperationCapability>,
}

impl LifecycleCapabilities {
    pub fn new(
        projects: BTreeSet<ProjectId>,
        mut operations: Vec<LifecycleOperationCapability>,
    ) -> Result<Self, PlatformV2TransportError> {
        if projects.is_empty() || projects.len() > 128 {
            return Err(PlatformV2TransportError::InvalidBody);
        }
        operations.sort_by(|left, right| {
            (left.project().as_str(), left.effect_kind())
                .cmp(&(right.project().as_str(), right.effect_kind()))
        });
        let expected = projects
            .len()
            .checked_mul(LIFECYCLE_CAPABILITY_EFFECT_KINDS.len())
            .ok_or(PlatformV2TransportError::InvalidBody)?;
        if operations.len() != expected {
            return Err(PlatformV2TransportError::InvalidBody);
        }
        let mut observed = BTreeMap::<&str, BTreeSet<&str>>::new();
        for operation in &operations {
            if !projects.contains(operation.project())
                || !observed
                    .entry(operation.project().as_str())
                    .or_default()
                    .insert(operation.effect_kind())
            {
                return Err(PlatformV2TransportError::InvalidBody);
            }
        }
        if observed.values().any(|effects| {
            effects.len() != LIFECYCLE_CAPABILITY_EFFECT_KINDS.len()
                || LIFECYCLE_CAPABILITY_EFFECT_KINDS
                    .iter()
                    .any(|kind| !effects.contains(kind))
        }) {
            return Err(PlatformV2TransportError::InvalidBody);
        }
        Ok(Self {
            projects,
            operations,
        })
    }

    #[must_use]
    pub const fn projects(&self) -> &BTreeSet<ProjectId> {
        &self.projects
    }

    #[must_use]
    pub fn operations(&self) -> &[LifecycleOperationCapability] {
        &self.operations
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineageReadRequest {
    project: ProjectId,
    workspace: UserWorkspaceId,
}
impl LineageReadRequest {
    #[must_use]
    pub const fn new(project: ProjectId, workspace: UserWorkspaceId) -> Self {
        Self { project, workspace }
    }
    #[must_use]
    pub const fn project(&self) -> &ProjectId {
        &self.project
    }
    #[must_use]
    pub const fn workspace(&self) -> &UserWorkspaceId {
        &self.workspace
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceIntentRequest {
    project: ProjectId,
    intent: WorkspaceIntent,
}
impl WorkspaceIntentRequest {
    #[must_use]
    pub const fn new(project: ProjectId, intent: WorkspaceIntent) -> Self {
        Self { project, intent }
    }
    #[must_use]
    pub const fn project(&self) -> &ProjectId {
        &self.project
    }
    #[must_use]
    pub const fn intent(&self) -> &WorkspaceIntent {
        &self.intent
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceIntentLookup {
    project: ProjectId,
    intent_id: WorkspaceIntentId,
}
impl WorkspaceIntentLookup {
    #[must_use]
    pub const fn new(project: ProjectId, intent_id: WorkspaceIntentId) -> Self {
        Self { project, intent_id }
    }
    #[must_use]
    pub const fn project(&self) -> &ProjectId {
        &self.project
    }
    #[must_use]
    pub const fn intent_id(&self) -> &WorkspaceIntentId {
        &self.intent_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewReadRequest {
    project: ProjectId,
    workspace: WorkContextIdentity,
}
impl ReviewReadRequest {
    pub fn new(
        project: ProjectId,
        workspace: WorkContextIdentity,
    ) -> Result<Self, PlatformV2TransportError> {
        if !is_review_workspace(&workspace) {
            return Err(PlatformV2TransportError::InvalidBody);
        }
        Ok(Self { project, workspace })
    }
    #[must_use]
    pub const fn project(&self) -> &ProjectId {
        &self.project
    }
    #[must_use]
    pub const fn workspace(&self) -> &WorkContextIdentity {
        &self.workspace
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewReceiptLookup {
    project: ProjectId,
    workspace: WorkContextIdentity,
    idempotency_key: IdempotencyKey,
}

/// Client-owned inputs for one review action.
///
/// Authentication, actor identity, and action authority are resolved by the
/// host after peer authentication and cannot be asserted on this wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewActionTransportRequest {
    workspace: WorkContextIdentity,
    expected_revision: Revision,
    action: ReviewAction,
    idempotency_key: IdempotencyKey,
}
impl ReviewActionTransportRequest {
    pub fn new(
        workspace: WorkContextIdentity,
        expected_revision: Revision,
        action: ReviewAction,
        idempotency_key: IdempotencyKey,
    ) -> Result<Self, PlatformV2TransportError> {
        if !is_review_workspace(&workspace) || action.validate_client_shape().is_err() {
            return Err(PlatformV2TransportError::InvalidBody);
        }
        Ok(Self {
            workspace,
            expected_revision,
            action,
            idempotency_key,
        })
    }
    #[must_use]
    pub const fn workspace(&self) -> &WorkContextIdentity {
        &self.workspace
    }
    #[must_use]
    pub const fn expected_revision(&self) -> Revision {
        self.expected_revision
    }
    #[must_use]
    pub const fn action(&self) -> &ReviewAction {
        &self.action
    }
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
}
impl ReviewReceiptLookup {
    pub fn new(
        project: ProjectId,
        workspace: WorkContextIdentity,
        idempotency_key: IdempotencyKey,
    ) -> Result<Self, PlatformV2TransportError> {
        if !is_review_workspace(&workspace) {
            return Err(PlatformV2TransportError::InvalidBody);
        }
        Ok(Self {
            project,
            workspace,
            idempotency_key,
        })
    }
    #[must_use]
    pub const fn project(&self) -> &ProjectId {
        &self.project
    }
    #[must_use]
    pub const fn workspace(&self) -> &WorkContextIdentity {
        &self.workspace
    }
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
}

fn is_review_workspace(workspace: &WorkContextIdentity) -> bool {
    matches!(
        workspace.kind(),
        WorkContextTargetKind::UserWorkspace
            | WorkContextTargetKind::AttemptWorkspace
            | WorkContextTargetKind::Session
    )
}

/// Raw, response-only canonical approval document.
///
/// This is intentionally not a typed [`MutationApproval`]: that domain value
/// cannot be validated without the exact preview. Call [`Self::decode`] with
/// that context before treating these bytes as an approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawMutationApprovalDocument(Vec<u8>);
impl RawMutationApprovalDocument {
    pub fn from_approval(value: &MutationApproval) -> Result<Self, PlatformV2TransportError> {
        Ok(Self(encode_work_context_mutation_approval(value)?))
    }
    fn from_body(value: &JsonValue) -> Result<Self, PlatformV2TransportError> {
        let bytes = value.to_canonical_bytes();
        validate_server_document(&bytes, &["approval", "schema"])?;
        Ok(Self(bytes))
    }
    pub fn decode(&self, preview: &MutationPreview) -> Result<MutationApproval, LifecycleApiError> {
        decode_work_context_mutation_approval(&self.0, preview)
    }
    /// Read only the approval decision needed to correlate a decision response.
    ///
    /// The remaining approval stays raw until the caller supplies the exact
    /// preview required for full lifecycle validation.
    pub fn decision(&self) -> Result<MutationApprovalDecision, PlatformV2TransportError> {
        let document = parse_canonical(&self.0)?;
        exact_fields(&document, &["approval", "schema"])?;
        let approval = document
            .get("approval")
            .ok_or(PlatformV2TransportError::InvalidBody)?;
        exact_fields(
            approval,
            &[
                "decided_at_ms",
                "decided_by",
                "decision",
                "expires_at_ms",
                "id",
                "idempotency_key",
                "preview",
                "preview_digest",
                "request_digest",
            ],
        )?;
        MutationApprovalDecision::parse(string(approval, "decision")?)
            .map_err(|_| PlatformV2TransportError::InvalidBody)
    }
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Raw, response-only canonical receipt document.
///
/// This is intentionally not a typed [`MutationReceipt`]. Its contextual
/// decode requires the exact preview and server-stamped submission retained by
/// the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawMutationReceiptDocument(Vec<u8>);
impl RawMutationReceiptDocument {
    pub fn from_receipt(value: &MutationReceipt) -> Result<Self, PlatformV2TransportError> {
        Ok(Self(encode_work_context_mutation_receipt(value)?))
    }
    fn from_body(value: &JsonValue) -> Result<Self, PlatformV2TransportError> {
        let bytes = value.to_canonical_bytes();
        validate_server_document(
            &bytes,
            &[
                "approval_id",
                "id",
                "idempotency_key",
                "outcome",
                "preview",
                "preview_digest",
                "recorded_at_ms",
                "request_digest",
                "resulting_revision",
                "schema",
            ],
        )?;
        Ok(Self(bytes))
    }
    pub fn decode(
        &self,
        submission: &crate::platform_v2_lifecycle::MutationSubmission,
        preview: &MutationPreview,
    ) -> Result<MutationReceipt, LifecycleApiError> {
        decode_work_context_mutation_receipt(&self.0, submission, preview)
    }
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn validate_server_document(bytes: &[u8], fields: &[&str]) -> Result<(), PlatformV2TransportError> {
    if bytes.len() > MAX_MUTATION_CANONICAL_BYTES {
        return Err(PlatformV2TransportError::FrameTooLarge {
            max_bytes: MAX_MUTATION_CANONICAL_BYTES,
            actual_bytes: bytes.len(),
        });
    }
    let value = parse_canonical(bytes)?;
    exact_fields(&value, fields)?;
    if string(&value, "schema")? != PLATFORM_SCHEMA_V2 {
        return Err(PlatformV2TransportError::InvalidBody);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformNegotiationRequest {
    Negotiate(PlatformVersionOffer),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformNegotiationResponse {
    Negotiated(NegotiatedPlatform),
    Refused(PlatformV2Refusal),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformNegotiationRequestMessage {
    request_id: RequestId,
    request: PlatformNegotiationRequest,
}
impl PlatformNegotiationRequestMessage {
    #[must_use]
    pub const fn new(request_id: RequestId, request: PlatformNegotiationRequest) -> Self {
        Self {
            request_id,
            request,
        }
    }
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }
    #[must_use]
    pub const fn request(&self) -> &PlatformNegotiationRequest {
        &self.request
    }
    #[must_use]
    pub const fn offer(&self) -> &PlatformVersionOffer {
        match &self.request {
            PlatformNegotiationRequest::Negotiate(offer) => offer,
        }
    }
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, PlatformV2TransportError> {
        let PlatformNegotiationRequest::Negotiate(value) = &self.request;
        encoded(
            Message::new(
                envelope(
                    PLATFORM_NEGOTIATION_PROTOCOL,
                    PLATFORM_NEGOTIATION_MAJOR,
                    self.request_id.clone(),
                    "negotiate",
                )?,
                document(encode_platform_version_offer(value)?)?,
            ),
            MAX_PLATFORM_NEGOTIATION_REQUEST_CANONICAL_BYTES,
        )
    }
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, PlatformV2TransportError> {
        let message = admitted(
            payload,
            MAX_PLATFORM_NEGOTIATION_REQUEST_CANONICAL_BYTES,
            PLATFORM_NEGOTIATION_PROTOCOL,
            PLATFORM_NEGOTIATION_MAJOR,
        )?;
        if message.envelope().kind().as_str() != "negotiate" {
            return Err(PlatformV2TransportError::UnknownKind);
        }
        Ok(Self::new(
            message.envelope().request_id().clone(),
            PlatformNegotiationRequest::Negotiate(decode_platform_version_offer(&body_document(
                &message,
            ))?),
        ))
    }
    pub fn to_frame(&self) -> Result<Vec<u8>, PlatformV2TransportError> {
        framed(
            &self.to_canonical_bytes()?,
            MAX_PLATFORM_NEGOTIATION_REQUEST_CANONICAL_BYTES,
        )
    }
    pub fn from_frame(frame: &[u8]) -> Result<Self, PlatformV2TransportError> {
        Self::from_canonical_bytes(framed_payload(
            frame,
            MAX_PLATFORM_NEGOTIATION_REQUEST_CANONICAL_BYTES,
        )?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformNegotiationResponseMessage {
    request_id: RequestId,
    response: PlatformNegotiationResponse,
}
impl PlatformNegotiationResponseMessage {
    fn new(request_id: RequestId, response: PlatformNegotiationResponse) -> Self {
        Self {
            request_id,
            response,
        }
    }
    pub fn for_request(
        request: &PlatformNegotiationRequestMessage,
        response: PlatformNegotiationResponse,
    ) -> Result<Self, PlatformV2TransportError> {
        validate_negotiation_response(request.offer(), &response)?;
        Ok(Self::new(request.request_id.clone(), response))
    }
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }
    #[must_use]
    pub const fn response(&self) -> &PlatformNegotiationResponse {
        &self.response
    }
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, PlatformV2TransportError> {
        let (kind, body) = match &self.response {
            PlatformNegotiationResponse::Negotiated(value) => {
                ("negotiated", document(encode_negotiated_platform(value)?)?)
            }
            PlatformNegotiationResponse::Refused(value) => {
                ("platform_v2_refused", refusal_json(value))
            }
        };
        encoded(
            Message::new(
                envelope(
                    PLATFORM_NEGOTIATION_PROTOCOL,
                    PLATFORM_NEGOTIATION_MAJOR,
                    self.request_id.clone(),
                    kind,
                )?,
                body,
            ),
            MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES,
        )
    }
    pub fn from_canonical_bytes(
        payload: &[u8],
        request: &PlatformNegotiationRequestMessage,
    ) -> Result<Self, PlatformV2TransportError> {
        let message = admitted(
            payload,
            MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES,
            PLATFORM_NEGOTIATION_PROTOCOL,
            PLATFORM_NEGOTIATION_MAJOR,
        )?;
        let response = match message.envelope().kind().as_str() {
            "negotiated" => PlatformNegotiationResponse::Negotiated(decode_negotiated_platform(
                &body_document(&message),
            )?),
            "platform_v2_refused" => PlatformNegotiationResponse::Refused(refusal(message.body())?),
            _ => return Err(PlatformV2TransportError::UnknownKind),
        };
        if message.envelope().request_id() != request.request_id() {
            return Err(PlatformV2TransportError::CorrelationMismatch);
        }
        validate_negotiation_response(request.offer(), &response)?;
        Ok(Self::new(message.envelope().request_id().clone(), response))
    }
    pub fn to_frame(&self) -> Result<Vec<u8>, PlatformV2TransportError> {
        framed(
            &self.to_canonical_bytes()?,
            MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES,
        )
    }
    pub fn from_frame(
        frame: &[u8],
        request: &PlatformNegotiationRequestMessage,
    ) -> Result<Self, PlatformV2TransportError> {
        Self::from_canonical_bytes(
            framed_payload(frame, MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES)?,
            request,
        )
    }
}

fn validate_negotiation_response(
    offer: &PlatformVersionOffer,
    response: &PlatformNegotiationResponse,
) -> Result<(), PlatformV2TransportError> {
    if let PlatformNegotiationResponse::Negotiated(selected) = response
        && !offer.versions().contains(&selected.version().number())
    {
        return Err(PlatformV2TransportError::NegotiationMismatch);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)] // The public variants intentionally mirror the audited domain types.
pub enum PlatformV2Request {
    GetLifecycleCapabilities,
    QueryWorkContexts(WorkContextQuery),
    GetWorkContext(WorkContextIdentity),
    PrepareMutation(MutationPrepareRequest),
    DecideMutation(MutationDecisionRequest),
    SubmitMutation(MutationSubmitRequest),
    GetMutationReceipt(MutationReceiptLookup),
    GetLineage(LineageReadRequest),
    SubmitWorkspaceIntent(WorkspaceIntentRequest),
    GetWorkspaceIntent(WorkspaceIntentLookup),
    GetReview(ReviewReadRequest),
    ExecuteReviewAction(ReviewActionTransportRequest),
    GetReviewReceipt(ReviewReceiptLookup),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)] // Keep canonical domain documents direct in the transport API.
pub enum PlatformV2Response {
    LifecycleCapabilities(LifecycleCapabilities),
    WorkContextPage(WorkContextPage),
    WorkContextResync(WorkContextResync),
    WorkContextRecord(WorkContextRecord),
    MutationPreview(MutationPreview),
    MutationApproval(RawMutationApprovalDocument),
    MutationReceipt(RawMutationReceiptDocument),
    MutationRefused(MutationRefusal),
    LineageResult(LineageProjection),
    WorkspaceIntentResult(WorkspaceIntentOutcome),
    ReviewResult(ReviewSnapshot),
    ReviewReceipt(ReviewActionReceipt),
    Refused(PlatformV2Refusal),
}

fn preview_ref_json(value: &MutationPreviewRef) -> Result<JsonValue, PlatformV2TransportError> {
    Ok(object(vec![
        ("id", JsonValue::String(value.id().as_str().to_owned())),
        (
            "revision",
            JsonValue::Integer(
                i64::try_from(value.revision().get())
                    .map_err(|_| PlatformV2TransportError::InvalidBody)?,
            ),
        ),
    ]))
}
fn preview_ref(value: &JsonValue) -> Result<MutationPreviewRef, PlatformV2TransportError> {
    exact_fields(value, &["id", "revision"])?;
    let revision = value
        .get("revision")
        .and_then(JsonValue::as_integer)
        .and_then(|v| u64::try_from(v).ok())
        .ok_or(PlatformV2TransportError::InvalidBody)?;
    Ok(MutationPreviewRef::new(
        crate::platform_v2_lifecycle::MutationPreviewId::new(string(value, "id")?.to_owned())
            .map_err(|_| PlatformV2TransportError::InvalidBody)?,
        Revision::new(revision).map_err(|_| PlatformV2TransportError::InvalidBody)?,
    ))
}
fn refusal_json(value: &PlatformV2Refusal) -> JsonValue {
    object(vec![
        (
            "category",
            JsonValue::String(value.category.as_str().to_owned()),
        ),
        (
            "explanation",
            JsonValue::String(value.explanation.as_str().to_owned()),
        ),
        ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
    ])
}
fn refusal(value: &JsonValue) -> Result<PlatformV2Refusal, PlatformV2TransportError> {
    exact_fields(value, &["category", "explanation", "schema"])?;
    if string(value, "schema")? != PLATFORM_SCHEMA_V2 {
        return Err(PlatformV2TransportError::InvalidBody);
    }
    PlatformV2Refusal::new(string(value, "category")?, string(value, "explanation")?)
        .map_err(|_| PlatformV2TransportError::InvalidBody)
}
fn scope_json(project: &ProjectId, workspace: Option<&WorkContextIdentity>) -> JsonValue {
    object(vec![
        ("project", JsonValue::String(project.as_str().to_owned())),
        ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
        (
            "workspace",
            workspace.map_or(JsonValue::Null, identity_json),
        ),
    ])
}
fn scope(
    value: &JsonValue,
) -> Result<(ProjectId, Option<WorkContextIdentity>), PlatformV2TransportError> {
    exact_fields(value, &["project", "schema", "workspace"])?;
    if string(value, "schema")? != PLATFORM_SCHEMA_V2 {
        return Err(PlatformV2TransportError::InvalidBody);
    }
    let project = ProjectId::new(string(value, "project")?.to_owned())
        .map_err(|_| PlatformV2TransportError::InvalidBody)?;
    let workspace = match value.get("workspace") {
        Some(JsonValue::Null) => None,
        Some(value) => Some(identity(value)?),
        None => return Err(PlatformV2TransportError::InvalidBody),
    };
    Ok((project, workspace))
}
fn lookup_json(
    project: &ProjectId,
    workspace: Option<&WorkContextIdentity>,
    key: &ReceiptLookupKey,
) -> JsonValue {
    let (receipt_id, idempotency_key) = match key {
        ReceiptLookupKey::ReceiptId(value) => (
            JsonValue::String(value.as_str().to_owned()),
            JsonValue::Null,
        ),
        ReceiptLookupKey::IdempotencyKey(value) => (
            JsonValue::Null,
            JsonValue::String(value.as_str().to_owned()),
        ),
    };
    object(vec![
        ("idempotency_key", idempotency_key),
        ("project", JsonValue::String(project.as_str().to_owned())),
        ("receipt_id", receipt_id),
        ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
        (
            "workspace",
            workspace.map_or(JsonValue::Null, identity_json),
        ),
    ])
}
fn lookup(
    value: &JsonValue,
) -> Result<(ProjectId, Option<WorkContextIdentity>, ReceiptLookupKey), PlatformV2TransportError> {
    exact_fields(
        value,
        &[
            "idempotency_key",
            "project",
            "receipt_id",
            "schema",
            "workspace",
        ],
    )?;
    if string(value, "schema")? != PLATFORM_SCHEMA_V2 {
        return Err(PlatformV2TransportError::InvalidBody);
    }
    let key = match (value.get("receipt_id"), value.get("idempotency_key")) {
        (Some(JsonValue::String(id)), Some(JsonValue::Null)) => ReceiptLookupKey::ReceiptId(
            ReceiptId::new(id).map_err(|_| PlatformV2TransportError::InvalidBody)?,
        ),
        (Some(JsonValue::Null), Some(JsonValue::String(key))) => ReceiptLookupKey::IdempotencyKey(
            IdempotencyKey::new(key).map_err(|_| PlatformV2TransportError::InvalidBody)?,
        ),
        _ => return Err(PlatformV2TransportError::InvalidBody),
    };
    let project = ProjectId::new(string(value, "project")?.to_owned())
        .map_err(|_| PlatformV2TransportError::InvalidBody)?;
    let workspace = match value.get("workspace") {
        Some(JsonValue::Null) => None,
        Some(value) => Some(identity(value)?),
        None => return Err(PlatformV2TransportError::InvalidBody),
    };
    Ok((project, workspace, key))
}

fn review_lookup_json(value: &ReviewReceiptLookup) -> JsonValue {
    object(vec![
        (
            "idempotency_key",
            JsonValue::String(value.idempotency_key.as_str().to_owned()),
        ),
        (
            "project",
            JsonValue::String(value.project.as_str().to_owned()),
        ),
        ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
        ("workspace", identity_json(&value.workspace)),
    ])
}

fn request_kind(value: &PlatformV2Request) -> &'static str {
    match value {
        PlatformV2Request::GetLifecycleCapabilities => "get_lifecycle_capabilities",
        PlatformV2Request::QueryWorkContexts(_) => "query_work_contexts",
        PlatformV2Request::GetWorkContext(_) => "get_work_context",
        PlatformV2Request::PrepareMutation(_) => "prepare_mutation",
        PlatformV2Request::DecideMutation(_) => "decide_mutation",
        PlatformV2Request::SubmitMutation(_) => "submit_mutation",
        PlatformV2Request::GetMutationReceipt(_) => "get_mutation_receipt",
        PlatformV2Request::GetLineage(_) => "get_lineage",
        PlatformV2Request::SubmitWorkspaceIntent(_) => "submit_workspace_intent",
        PlatformV2Request::GetWorkspaceIntent(_) => "get_workspace_intent",
        PlatformV2Request::GetReview(_) => "get_review",
        PlatformV2Request::ExecuteReviewAction(_) => "execute_review_action",
        PlatformV2Request::GetReviewReceipt(_) => "get_review_receipt",
    }
}
fn request_body(value: &PlatformV2Request) -> Result<JsonValue, PlatformV2TransportError> {
    Ok(match value {
        PlatformV2Request::GetLifecycleCapabilities => object(vec![(
            "schema",
            JsonValue::String(PLATFORM_SCHEMA_V2.to_owned()),
        )]),
        PlatformV2Request::QueryWorkContexts(value) => {
            if value.project().is_none() {
                return Err(PlatformV2TransportError::InvalidBody);
            }
            document(encode_work_context_query(value)?)?
        }
        PlatformV2Request::GetWorkContext(value) => identity_json(value),
        PlatformV2Request::PrepareMutation(value) => object(vec![
            (
                "idempotency_key",
                JsonValue::String(value.idempotency_key.as_str().to_owned()),
            ),
            ("intent", intent_json(&value.intent)?),
            ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
        ]),
        PlatformV2Request::DecideMutation(value) => object(vec![
            (
                "decision",
                JsonValue::String(value.decision.as_str().to_owned()),
            ),
            ("preview", preview_ref_json(&value.preview)?),
            (
                "preview_digest",
                JsonValue::String(value.preview_digest.to_string()),
            ),
            ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
        ]),
        PlatformV2Request::SubmitMutation(value) => object(vec![
            (
                "approval_id",
                value.approval.as_ref().map_or(JsonValue::Null, |v| {
                    JsonValue::String(v.as_str().to_owned())
                }),
            ),
            ("preview", preview_ref_json(&value.preview)?),
            (
                "preview_digest",
                JsonValue::String(value.preview_digest.to_string()),
            ),
            ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
        ]),
        PlatformV2Request::GetMutationReceipt(value) => {
            lookup_json(&value.project, None, &value.key)
        }
        PlatformV2Request::GetLineage(value) => object(vec![
            (
                "project",
                JsonValue::String(value.project.as_str().to_owned()),
            ),
            ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
            (
                "workspace",
                JsonValue::String(value.workspace.as_str().to_owned()),
            ),
        ]),
        PlatformV2Request::SubmitWorkspaceIntent(value) => object(vec![
            (
                "intent",
                document(encode_workspace_intent(&v2(), &value.intent)?)?,
            ),
            (
                "project",
                JsonValue::String(value.project.as_str().to_owned()),
            ),
            ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
        ]),
        PlatformV2Request::GetWorkspaceIntent(value) => object(vec![
            (
                "intent_id",
                JsonValue::String(value.intent_id.as_str().to_owned()),
            ),
            (
                "project",
                JsonValue::String(value.project.as_str().to_owned()),
            ),
            ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
        ]),
        PlatformV2Request::GetReview(value) => scope_json(&value.project, Some(&value.workspace)),
        PlatformV2Request::ExecuteReviewAction(value) => object(vec![
            ("action", action_json(&value.action)?),
            (
                "expected_revision",
                JsonValue::Integer(
                    i64::try_from(value.expected_revision.get())
                        .map_err(|_| PlatformV2TransportError::InvalidBody)?,
                ),
            ),
            (
                "idempotency_key",
                JsonValue::String(value.idempotency_key.as_str().to_owned()),
            ),
            (
                "platform_version",
                JsonValue::Integer(i64::from(PLATFORM_REVIEW_REQUIRES_PLATFORM_MAJOR)),
            ),
            (
                "schema",
                JsonValue::String(PLATFORM_REVIEW_SCHEMA_V1.to_owned()),
            ),
            ("workspace", identity_json(&value.workspace)),
        ]),
        PlatformV2Request::GetReviewReceipt(value) => review_lookup_json(value),
    })
}
fn request_from_message(message: &Message) -> Result<PlatformV2Request, PlatformV2TransportError> {
    let bytes = body_document(message);
    Ok(match message.envelope().kind().as_str() {
        "get_lifecycle_capabilities" => {
            exact_fields(message.body(), &["schema"])?;
            if string(message.body(), "schema")? != PLATFORM_SCHEMA_V2 {
                return Err(PlatformV2TransportError::InvalidBody);
            }
            PlatformV2Request::GetLifecycleCapabilities
        }
        "query_work_contexts" => {
            let value = decode_work_context_query(&bytes)?;
            if value.project().is_none() {
                return Err(PlatformV2TransportError::InvalidBody);
            }
            PlatformV2Request::QueryWorkContexts(value)
        }
        "get_work_context" => PlatformV2Request::GetWorkContext(identity(message.body())?),
        "prepare_mutation" => {
            exact_fields(message.body(), &["idempotency_key", "intent", "schema"])?;
            if string(message.body(), "schema")? != PLATFORM_SCHEMA_V2 {
                return Err(PlatformV2TransportError::InvalidBody);
            }
            PlatformV2Request::PrepareMutation(MutationPrepareRequest::new(
                IdempotencyKey::new(string(message.body(), "idempotency_key")?)
                    .map_err(|_| PlatformV2TransportError::InvalidBody)?,
                intent(
                    message
                        .body()
                        .get("intent")
                        .ok_or(PlatformV2TransportError::InvalidBody)?,
                )?,
            ))
        }
        "decide_mutation" => {
            exact_fields(
                message.body(),
                &["decision", "preview", "preview_digest", "schema"],
            )?;
            if string(message.body(), "schema")? != PLATFORM_SCHEMA_V2 {
                return Err(PlatformV2TransportError::InvalidBody);
            }
            PlatformV2Request::DecideMutation(MutationDecisionRequest::new(
                preview_ref(
                    message
                        .body()
                        .get("preview")
                        .ok_or(PlatformV2TransportError::InvalidBody)?,
                )?,
                MutationPreviewDigest::from_str(string(message.body(), "preview_digest")?)
                    .map_err(|_| PlatformV2TransportError::InvalidBody)?,
                MutationApprovalDecision::parse(string(message.body(), "decision")?)
                    .map_err(|_| PlatformV2TransportError::InvalidBody)?,
            ))
        }
        "submit_mutation" => {
            exact_fields(
                message.body(),
                &["approval_id", "preview", "preview_digest", "schema"],
            )?;
            if string(message.body(), "schema")? != PLATFORM_SCHEMA_V2 {
                return Err(PlatformV2TransportError::InvalidBody);
            }
            let approval = match message.body().get("approval_id") {
                Some(JsonValue::Null) => None,
                Some(JsonValue::String(value)) => Some(
                    MutationApprovalId::new(value.clone())
                        .map_err(|_| PlatformV2TransportError::InvalidBody)?,
                ),
                _ => return Err(PlatformV2TransportError::InvalidBody),
            };
            PlatformV2Request::SubmitMutation(MutationSubmitRequest::new(
                preview_ref(
                    message
                        .body()
                        .get("preview")
                        .ok_or(PlatformV2TransportError::InvalidBody)?,
                )?,
                MutationPreviewDigest::from_str(string(message.body(), "preview_digest")?)
                    .map_err(|_| PlatformV2TransportError::InvalidBody)?,
                approval,
            ))
        }
        "get_mutation_receipt" => {
            let (project, workspace, key) = lookup(message.body())?;
            if workspace.is_some() {
                return Err(PlatformV2TransportError::InvalidBody);
            }
            PlatformV2Request::GetMutationReceipt(MutationReceiptLookup::new(project, key))
        }
        "get_lineage" => {
            exact_fields(message.body(), &["project", "schema", "workspace"])?;
            if string(message.body(), "schema")? != PLATFORM_SCHEMA_V2 {
                return Err(PlatformV2TransportError::InvalidBody);
            }
            PlatformV2Request::GetLineage(LineageReadRequest::new(
                ProjectId::new(string(message.body(), "project")?.to_owned())
                    .map_err(|_| PlatformV2TransportError::InvalidBody)?,
                UserWorkspaceId::new(string(message.body(), "workspace")?.to_owned())
                    .map_err(|_| PlatformV2TransportError::InvalidBody)?,
            ))
        }
        "submit_workspace_intent" => {
            exact_fields(message.body(), &["intent", "project", "schema"])?;
            if string(message.body(), "schema")? != PLATFORM_SCHEMA_V2 {
                return Err(PlatformV2TransportError::InvalidBody);
            }
            PlatformV2Request::SubmitWorkspaceIntent(WorkspaceIntentRequest::new(
                ProjectId::new(string(message.body(), "project")?.to_owned())
                    .map_err(|_| PlatformV2TransportError::InvalidBody)?,
                decode_workspace_intent(
                    &v2(),
                    &message
                        .body()
                        .get("intent")
                        .ok_or(PlatformV2TransportError::InvalidBody)?
                        .to_canonical_bytes(),
                )?,
            ))
        }
        "get_workspace_intent" => {
            exact_fields(message.body(), &["intent_id", "project", "schema"])?;
            if string(message.body(), "schema")? != PLATFORM_SCHEMA_V2 {
                return Err(PlatformV2TransportError::InvalidBody);
            }
            PlatformV2Request::GetWorkspaceIntent(WorkspaceIntentLookup::new(
                ProjectId::new(string(message.body(), "project")?.to_owned())
                    .map_err(|_| PlatformV2TransportError::InvalidBody)?,
                WorkspaceIntentId::new(string(message.body(), "intent_id")?.to_owned())
                    .map_err(|_| PlatformV2TransportError::InvalidBody)?,
            ))
        }
        "get_review" => {
            let (project, workspace) = scope(message.body())?;
            PlatformV2Request::GetReview(ReviewReadRequest::new(
                project,
                workspace.ok_or(PlatformV2TransportError::InvalidBody)?,
            )?)
        }
        "execute_review_action" => {
            exact_fields(
                message.body(),
                &[
                    "action",
                    "expected_revision",
                    "idempotency_key",
                    "platform_version",
                    "schema",
                    "workspace",
                ],
            )?;
            if string(message.body(), "schema")? != PLATFORM_REVIEW_SCHEMA_V1
                || message
                    .body()
                    .get("platform_version")
                    .and_then(JsonValue::as_integer)
                    != Some(i64::from(PLATFORM_REVIEW_REQUIRES_PLATFORM_MAJOR))
            {
                return Err(PlatformV2TransportError::InvalidBody);
            }
            let expected_revision = message
                .body()
                .get("expected_revision")
                .and_then(JsonValue::as_integer)
                .and_then(|value| u64::try_from(value).ok())
                .and_then(|value| Revision::new(value).ok())
                .ok_or(PlatformV2TransportError::InvalidBody)?;
            PlatformV2Request::ExecuteReviewAction(ReviewActionTransportRequest::new(
                identity(
                    message
                        .body()
                        .get("workspace")
                        .ok_or(PlatformV2TransportError::InvalidBody)?,
                )?,
                expected_revision,
                action(
                    message
                        .body()
                        .get("action")
                        .ok_or(PlatformV2TransportError::InvalidBody)?,
                )?,
                IdempotencyKey::new(string(message.body(), "idempotency_key")?)
                    .map_err(|_| PlatformV2TransportError::InvalidBody)?,
            )?)
        }
        "get_review_receipt" => {
            exact_fields(
                message.body(),
                &["idempotency_key", "project", "schema", "workspace"],
            )?;
            if string(message.body(), "schema")? != PLATFORM_SCHEMA_V2 {
                return Err(PlatformV2TransportError::InvalidBody);
            }
            PlatformV2Request::GetReviewReceipt(ReviewReceiptLookup::new(
                ProjectId::new(string(message.body(), "project")?)
                    .map_err(|_| PlatformV2TransportError::InvalidBody)?,
                identity(
                    message
                        .body()
                        .get("workspace")
                        .ok_or(PlatformV2TransportError::InvalidBody)?,
                )?,
                IdempotencyKey::new(string(message.body(), "idempotency_key")?)
                    .map_err(|_| PlatformV2TransportError::InvalidBody)?,
            )?)
        }
        _ => return Err(PlatformV2TransportError::UnknownKind),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformV2RequestMessage {
    request_id: RequestId,
    request: PlatformV2Request,
}
impl PlatformV2RequestMessage {
    #[must_use]
    pub const fn new(request_id: RequestId, request: PlatformV2Request) -> Self {
        Self {
            request_id,
            request,
        }
    }
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }
    #[must_use]
    pub const fn request(&self) -> &PlatformV2Request {
        &self.request
    }
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, PlatformV2TransportError> {
        encoded(
            Message::new(
                envelope(
                    PLATFORM_PROTOCOL,
                    PLATFORM_V2_MAJOR,
                    self.request_id.clone(),
                    request_kind(&self.request),
                )?,
                request_body(&self.request)?,
            ),
            MAX_PLATFORM_V2_REQUEST_CANONICAL_BYTES,
        )
    }
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, PlatformV2TransportError> {
        let message = admitted(
            payload,
            MAX_PLATFORM_V2_REQUEST_CANONICAL_BYTES,
            PLATFORM_PROTOCOL,
            PLATFORM_V2_MAJOR,
        )?;
        let request = request_from_message(&message)?;
        Ok(Self::new(message.envelope().request_id().clone(), request))
    }
    pub fn to_frame(&self) -> Result<Vec<u8>, PlatformV2TransportError> {
        framed(
            &self.to_canonical_bytes()?,
            MAX_PLATFORM_V2_REQUEST_CANONICAL_BYTES,
        )
    }
    pub fn from_frame(frame: &[u8]) -> Result<Self, PlatformV2TransportError> {
        Self::from_canonical_bytes(framed_payload(
            frame,
            MAX_PLATFORM_V2_REQUEST_CANONICAL_BYTES,
        )?)
    }
}

fn response_kind(value: &PlatformV2Response) -> &'static str {
    match value {
        PlatformV2Response::LifecycleCapabilities(_) => "lifecycle_capabilities",
        PlatformV2Response::WorkContextPage(_) => "work_context_page",
        PlatformV2Response::WorkContextResync(_) => "work_context_resync",
        PlatformV2Response::WorkContextRecord(_) => "work_context_record",
        PlatformV2Response::MutationPreview(_) => "mutation_preview",
        PlatformV2Response::MutationApproval(_) => "mutation_approval",
        PlatformV2Response::MutationReceipt(_) => "mutation_receipt",
        PlatformV2Response::MutationRefused(_) => "mutation_refused",
        PlatformV2Response::LineageResult(_) => "lineage_result",
        PlatformV2Response::WorkspaceIntentResult(_) => "workspace_intent_result",
        PlatformV2Response::ReviewResult(_) => "review_result",
        PlatformV2Response::ReviewReceipt(_) => "review_receipt",
        PlatformV2Response::Refused(_) => "platform_v2_refused",
    }
}
fn response_answers_request(request: &PlatformV2Request, response: &PlatformV2Response) -> bool {
    if matches!(response, PlatformV2Response::Refused(_)) {
        return true;
    }
    matches!(
        (request, response),
        (
            PlatformV2Request::GetLifecycleCapabilities,
            PlatformV2Response::LifecycleCapabilities(_)
        ) | (
            PlatformV2Request::QueryWorkContexts(_),
            PlatformV2Response::WorkContextPage(_) | PlatformV2Response::WorkContextResync(_)
        ) | (
            PlatformV2Request::GetWorkContext(_),
            PlatformV2Response::WorkContextRecord(_)
        ) | (
            PlatformV2Request::PrepareMutation(_),
            PlatformV2Response::MutationPreview(_) | PlatformV2Response::MutationRefused(_)
        ) | (
            PlatformV2Request::DecideMutation(_),
            PlatformV2Response::MutationApproval(_) | PlatformV2Response::MutationRefused(_)
        ) | (
            PlatformV2Request::SubmitMutation(_) | PlatformV2Request::GetMutationReceipt(_),
            PlatformV2Response::MutationReceipt(_) | PlatformV2Response::MutationRefused(_)
        ) | (
            PlatformV2Request::GetLineage(_),
            PlatformV2Response::LineageResult(_)
        ) | (
            PlatformV2Request::SubmitWorkspaceIntent(_) | PlatformV2Request::GetWorkspaceIntent(_),
            PlatformV2Response::WorkspaceIntentResult(_)
        ) | (
            PlatformV2Request::GetReview(_),
            PlatformV2Response::ReviewResult(_)
        ) | (
            PlatformV2Request::ExecuteReviewAction(_) | PlatformV2Request::GetReviewReceipt(_),
            PlatformV2Response::ReviewReceipt(_)
        )
    )
}
fn response_body(value: &PlatformV2Response) -> Result<JsonValue, PlatformV2TransportError> {
    Ok(match value {
        PlatformV2Response::LifecycleCapabilities(value) => object(vec![
            (
                "operations",
                JsonValue::Array(
                    value
                        .operations()
                        .iter()
                        .map(|operation| {
                            object(vec![
                                ("available", JsonValue::Bool(operation.available_now())),
                                (
                                    "category",
                                    operation.category().map_or(JsonValue::Null, |category| {
                                        JsonValue::String(category.as_str().to_owned())
                                    }),
                                ),
                                (
                                    "effect_kind",
                                    JsonValue::String(operation.effect_kind().to_owned()),
                                ),
                                (
                                    "project",
                                    JsonValue::String(operation.project().as_str().to_owned()),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "projects",
                JsonValue::Array(
                    value
                        .projects()
                        .iter()
                        .map(|project| JsonValue::String(project.as_str().to_owned()))
                        .collect(),
                ),
            ),
            ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
        ]),
        PlatformV2Response::WorkContextPage(value) => document(encode_work_context_page(value)?)?,
        PlatformV2Response::WorkContextResync(value) => {
            document(encode_work_context_resync(value)?)?
        }
        PlatformV2Response::WorkContextRecord(value) => record_json(value)?,
        PlatformV2Response::MutationPreview(value) => {
            document(encode_work_context_mutation_preview(value)?)?
        }
        PlatformV2Response::MutationApproval(value) => document(value.0.clone())?,
        PlatformV2Response::MutationReceipt(value) => document(value.0.clone())?,
        PlatformV2Response::MutationRefused(value) => {
            document(encode_work_context_mutation_refusal(value)?)?
        }
        PlatformV2Response::LineageResult(value) => {
            document(encode_lineage_projection(&v2(), value)?)?
        }
        PlatformV2Response::WorkspaceIntentResult(value) => {
            document(encode_workspace_intent_outcome(&v2(), value)?)?
        }
        PlatformV2Response::ReviewResult(value) => document(encode_review_snapshot(value)?)?,
        PlatformV2Response::ReviewReceipt(value) => document(encode_review_action_receipt(value)?)?,
        PlatformV2Response::Refused(value) => refusal_json(value),
    })
}
fn response_from_message(
    message: &Message,
) -> Result<PlatformV2Response, PlatformV2TransportError> {
    let bytes = body_document(message);
    Ok(match message.envelope().kind().as_str() {
        "lifecycle_capabilities" => {
            exact_fields(message.body(), &["operations", "projects", "schema"])?;
            if string(message.body(), "schema")? != PLATFORM_SCHEMA_V2 {
                return Err(PlatformV2TransportError::InvalidBody);
            }
            let JsonValue::Array(projects) = message
                .body()
                .get("projects")
                .ok_or(PlatformV2TransportError::InvalidBody)?
            else {
                return Err(PlatformV2TransportError::InvalidBody);
            };
            let mut decoded_projects = BTreeSet::new();
            for value in projects {
                let JsonValue::String(value) = value else {
                    return Err(PlatformV2TransportError::InvalidBody);
                };
                let project = ProjectId::new(value.clone())
                    .map_err(|_| PlatformV2TransportError::InvalidBody)?;
                if !decoded_projects.insert(project) {
                    return Err(PlatformV2TransportError::InvalidBody);
                }
            }
            let JsonValue::Array(operations) = message
                .body()
                .get("operations")
                .ok_or(PlatformV2TransportError::InvalidBody)?
            else {
                return Err(PlatformV2TransportError::InvalidBody);
            };
            let operations = operations
                .iter()
                .map(|value| {
                    exact_fields(value, &["available", "category", "effect_kind", "project"])?;
                    let project = ProjectId::new(string(value, "project")?.to_owned())
                        .map_err(|_| PlatformV2TransportError::InvalidBody)?;
                    let effect_kind = string(value, "effect_kind")?.to_owned();
                    let available = match value.get("available") {
                        Some(JsonValue::Bool(value)) => *value,
                        _ => return Err(PlatformV2TransportError::InvalidBody),
                    };
                    match (available, value.get("category")) {
                        (true, Some(JsonValue::Null)) => {
                            LifecycleOperationCapability::available(project, effect_kind)
                        }
                        (false, Some(JsonValue::String(category))) => {
                            LifecycleOperationCapability::unavailable(
                                project,
                                effect_kind,
                                category.clone(),
                            )
                        }
                        _ => Err(PlatformV2TransportError::InvalidBody),
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            PlatformV2Response::LifecycleCapabilities(LifecycleCapabilities::new(
                decoded_projects,
                operations,
            )?)
        }
        "work_context_page" => {
            PlatformV2Response::WorkContextPage(decode_work_context_page(&bytes)?)
        }
        "work_context_resync" => {
            PlatformV2Response::WorkContextResync(decode_work_context_resync(&bytes)?)
        }
        "work_context_record" => PlatformV2Response::WorkContextRecord(record(message.body())?),
        "mutation_preview" => {
            PlatformV2Response::MutationPreview(decode_work_context_mutation_preview(&bytes)?)
        }
        "mutation_approval" => PlatformV2Response::MutationApproval(
            RawMutationApprovalDocument::from_body(message.body())?,
        ),
        "mutation_receipt" => PlatformV2Response::MutationReceipt(
            RawMutationReceiptDocument::from_body(message.body())?,
        ),
        "mutation_refused" => {
            PlatformV2Response::MutationRefused(decode_work_context_mutation_refusal(&bytes)?)
        }
        "lineage_result" => {
            PlatformV2Response::LineageResult(decode_lineage_projection(&v2(), &bytes)?)
        }
        "workspace_intent_result" => PlatformV2Response::WorkspaceIntentResult(
            decode_workspace_intent_outcome(&v2(), &bytes)?,
        ),
        "review_result" => PlatformV2Response::ReviewResult(decode_review_snapshot(&bytes)?),
        "review_receipt" => {
            PlatformV2Response::ReviewReceipt(decode_review_action_receipt(&bytes)?)
        }
        "platform_v2_refused" => PlatformV2Response::Refused(refusal(message.body())?),
        _ => return Err(PlatformV2TransportError::UnknownKind),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformV2ResponseMessage {
    request_id: RequestId,
    response: PlatformV2Response,
}
impl PlatformV2ResponseMessage {
    const fn new(request_id: RequestId, response: PlatformV2Response) -> Self {
        Self {
            request_id,
            response,
        }
    }
    pub fn for_request(
        request: &PlatformV2RequestMessage,
        response: PlatformV2Response,
    ) -> Result<Self, PlatformV2TransportError> {
        if !response_answers_request(request.request(), &response) {
            return Err(PlatformV2TransportError::ResponseMismatch);
        }
        Ok(Self::new(request.request_id.clone(), response))
    }
    #[must_use]
    pub const fn refusal(request_id: RequestId, refusal: PlatformV2Refusal) -> Self {
        Self::new(request_id, PlatformV2Response::Refused(refusal))
    }
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }
    #[must_use]
    pub const fn response(&self) -> &PlatformV2Response {
        &self.response
    }
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, PlatformV2TransportError> {
        encoded(
            Message::new(
                envelope(
                    PLATFORM_PROTOCOL,
                    PLATFORM_V2_MAJOR,
                    self.request_id.clone(),
                    response_kind(&self.response),
                )?,
                response_body(&self.response)?,
            ),
            MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES,
        )
    }
    fn decode_uncorrelated(payload: &[u8]) -> Result<Self, PlatformV2TransportError> {
        let message = admitted(
            payload,
            MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES,
            PLATFORM_PROTOCOL,
            PLATFORM_V2_MAJOR,
        )?;
        let response = response_from_message(&message)?;
        Ok(Self::new(message.envelope().request_id().clone(), response))
    }
    pub fn from_canonical_bytes(
        payload: &[u8],
        request: &PlatformV2RequestMessage,
    ) -> Result<Self, PlatformV2TransportError> {
        let response = Self::decode_uncorrelated(payload)?;
        if response.request_id() != request.request_id() {
            return Err(PlatformV2TransportError::CorrelationMismatch);
        }
        if !response_answers_request(request.request(), response.response()) {
            return Err(PlatformV2TransportError::ResponseMismatch);
        }
        Ok(response)
    }
    pub fn to_frame(&self) -> Result<Vec<u8>, PlatformV2TransportError> {
        framed(
            &self.to_canonical_bytes()?,
            MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES,
        )
    }
    pub fn from_frame(
        frame: &[u8],
        request: &PlatformV2RequestMessage,
    ) -> Result<Self, PlatformV2TransportError> {
        Self::from_canonical_bytes(
            framed_payload(frame, MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES)?,
            request,
        )
    }
}
