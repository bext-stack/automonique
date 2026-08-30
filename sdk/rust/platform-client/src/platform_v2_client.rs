// SPDX-License-Identifier: Apache-2.0

//! Negotiated, typed Platform v2 client surface.
//!
//! The wire codec remains owned by `automonique-protocol`. This module adds
//! transport policy, negotiation state, and operation-specific result types;
//! it never accepts actor, tenant, or authority assertions from a caller.
//!
//! The authenticated canonical-byte exchange is deliberately not public:
//!
//! ```compile_fail
//! use automonique_platform_client::platform_v2_client::{PlatformV2Lane, PlatformV2Transport};
//! ```
//!
//! ```compile_fail
//! use automonique_platform_client::{BearerToken, HttpsTransport};
//! let token = BearerToken::new("secret").unwrap();
//! let mut transport = HttpsTransport::new("https://manage.example/v2", token).unwrap();
//! let _ = transport.exchange((), b"arbitrary authenticated bytes");
//! ```

use std::io::Read;
#[cfg(unix)]
use std::io::Write;
use std::{error::Error, fmt};

use automonique_protocol::codec::{
    FrameDecode, LENGTH_PREFIX_BYTES, RequestId, decode_frame_with_limit, encode_frame_with_limit,
};
use automonique_protocol::platform::IdempotencyKey;
use automonique_protocol::platform_v2::{
    NegotiatedPlatform, PlatformVersion, PlatformVersionOffer, ProjectId, UserWorkspaceId,
    WorkContextIdentity, WorkContextPage, WorkContextQuery, WorkContextRecord, WorkContextResync,
};
use automonique_protocol::platform_v2_attention::{
    AttentionReadRequest, AttentionSource, AttentionSourceSnapshot,
};
use automonique_protocol::platform_v2_inventory::{
    ResourceListingPage, ResourceListingQuery, ResourceListingResync,
};
use automonique_protocol::platform_v2_lifecycle::{
    MutationApprovalDecision, MutationApprovalId, MutationPreview, MutationPreviewDigest,
    MutationPreviewRef, MutationRefusal, WorkContextMutationIntent,
};
use automonique_protocol::platform_v2_lineage::{
    LineageProjection, WorkspaceIntent, WorkspaceIntentId, WorkspaceIntentOutcome,
};
use automonique_protocol::platform_v2_review::{ReviewAction, ReviewActionReceipt, ReviewSnapshot};
use automonique_protocol::platform_v2_transport::{
    LineageReadRequest, MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES,
    MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES, MutationDecisionRequest, MutationPrepareRequest,
    MutationReceiptLookup, MutationSubmitRequest, PlatformNegotiationRequest,
    PlatformNegotiationRequestMessage, PlatformNegotiationResponse,
    PlatformNegotiationResponseMessage, PlatformV2Refusal, PlatformV2Request,
    PlatformV2RequestMessage, PlatformV2Response, PlatformV2ResponseMessage,
    PlatformV2TransportError, RawMutationApprovalDocument, RawMutationReceiptDocument,
    ReceiptLookupKey, ReviewActionTransportRequest, ReviewCapabilities, ReviewConfirmationDigest,
    ReviewReadRequest, ReviewReceiptCorrelationDigest, ReviewReceiptLookup, WorkspaceIntentLookup,
    WorkspaceIntentRequest,
};
use automonique_protocol::primitives::Revision;

use crate::HttpsTransport;
#[cfg(unix)]
use crate::UnixTransport;

/// Platform v2-specific client and transport refusal categories.
///
/// This is intentionally separate from the stable Platform v1 [`crate::ClientError`]
/// so adding negotiated v2 does not change exhaustive v1 matches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformV2ClientError {
    Io,
    Protocol,
    Correlation,
    NotNegotiated,
    ResponseTooLarge,
    Endpoint,
    Unauthorized,
    UnexpectedStatus,
    UnexpectedContentType,
}

impl PlatformV2ClientError {
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::Protocol => "protocol",
            Self::Correlation => "correlation",
            Self::NotNegotiated => "not_negotiated",
            Self::ResponseTooLarge => "response_too_large",
            Self::Endpoint => "endpoint",
            Self::Unauthorized => "unauthorized",
            Self::UnexpectedStatus => "unexpected_status",
            Self::UnexpectedContentType => "unexpected_content_type",
        }
    }
}

impl fmt::Display for PlatformV2ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "platform v2 client refused: {}", self.category())
    }
}

impl Error for PlatformV2ClientError {}

type ClientError = PlatformV2ClientError;

pub const PLATFORM_NEGOTIATION_CONTENT_TYPE: &str =
    "application/vnd.automonique.platform.negotiation.v1+json";
pub const PLATFORM_V2_CONTENT_TYPE: &str = "application/vnd.automonique.platform.v2+json";

/// A canonical request/response lane with its independent response bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlatformV2Lane {
    Negotiation,
    V2,
}

impl PlatformV2Lane {
    #[must_use]
    const fn content_type(self) -> &'static str {
        match self {
            Self::Negotiation => PLATFORM_NEGOTIATION_CONTENT_TYPE,
            Self::V2 => PLATFORM_V2_CONTENT_TYPE,
        }
    }

    #[must_use]
    const fn maximum_response_bytes(self) -> usize {
        match self {
            Self::Negotiation => MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES,
            Self::V2 => MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES,
        }
    }
}

/// Canonical-byte transport used by production and deterministic test fakes.
/// Correlation and response-kind checks remain in [`PlatformV2Client`].
trait PlatformV2Transport {
    fn exchange(
        &mut self,
        lane: PlatformV2Lane,
        canonical_request: &[u8],
    ) -> Result<Vec<u8>, ClientError>;
}

#[cfg(unix)]
impl PlatformV2Transport for UnixTransport {
    fn exchange(
        &mut self,
        lane: PlatformV2Lane,
        canonical_request: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let maximum = lane.maximum_response_bytes();
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + canonical_request.len());
        encode_frame_with_limit(canonical_request, &mut frame, canonical_request.len())
            .map_err(|_| ClientError::Protocol)?;
        let mut stream =
            std::os::unix::net::UnixStream::connect(self.socket()).map_err(|_| ClientError::Io)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|_| ClientError::Io)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|_| ClientError::Io)?;
        stream.write_all(&frame).map_err(|_| ClientError::Io)?;
        stream.flush().map_err(|_| ClientError::Io)?;

        let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
        stream
            .read_exact(&mut prefix)
            .map_err(|_| ClientError::Io)?;
        let length =
            usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| ClientError::Protocol)?;
        if length == 0 || length > maximum {
            return Err(ClientError::ResponseTooLarge);
        }
        let mut framed = Vec::with_capacity(LENGTH_PREFIX_BYTES + length);
        framed.extend_from_slice(&prefix);
        framed.resize(LENGTH_PREFIX_BYTES + length, 0);
        stream
            .read_exact(&mut framed[LENGTH_PREFIX_BYTES..])
            .map_err(|_| ClientError::Io)?;
        match decode_frame_with_limit(&framed, maximum).map_err(|_| ClientError::Protocol)? {
            FrameDecode::Frame { payload, consumed } if consumed == framed.len() => {
                Ok(payload.to_vec())
            }
            FrameDecode::Frame { .. } | FrameDecode::NeedMore { .. } => Err(ClientError::Protocol),
        }
    }
}

impl PlatformV2Transport for HttpsTransport {
    fn exchange(
        &mut self,
        lane: PlatformV2Lane,
        canonical_request: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let authorization = self.credential.authorization();
        let mut response = self
            .v2_agent
            .post(&self.endpoint)
            .header("authorization", authorization.as_str())
            .header("content-type", lane.content_type())
            .header("accept", lane.content_type())
            .config()
            .timeout_global(Some(self.timeout))
            .build()
            .send(canonical_request)
            .map_err(|error| match error {
                ureq::Error::BodyExceedsLimit(_) => ClientError::ResponseTooLarge,
                ureq::Error::StatusCode(401 | 403) => ClientError::Unauthorized,
                ureq::Error::StatusCode(_) => ClientError::UnexpectedStatus,
                _ => ClientError::Io,
            })?;
        let status = response.status().as_u16();
        if matches!(status, 401 | 403) {
            return Err(ClientError::Unauthorized);
        }
        if !(200..=299).contains(&status) {
            return Err(ClientError::UnexpectedStatus);
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if content_type != Some(lane.content_type()) {
            return Err(ClientError::UnexpectedContentType);
        }
        let maximum = lane.maximum_response_bytes();
        let mut body = Vec::new();
        response
            .body_mut()
            .with_config()
            .limit((maximum + 1) as u64)
            .reader()
            .read_to_end(&mut body)
            .map_err(|_| ClientError::Io)?;
        if body.len() > maximum {
            return Err(ClientError::ResponseTooLarge);
        }
        Ok(body)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegotiationResult {
    V2(NegotiatedPlatform),
    Downgraded(NegotiatedPlatform),
    Refused(PlatformV2Refusal),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkContextQueryResult {
    Page(WorkContextPage),
    Resync(WorkContextResync),
    Refused(PlatformV2Refusal),
}

/// The two answers a bounded resource listing can have, plus the transport
/// refusal every request shares.
///
/// A resync is its own variant rather than an empty page, because the one way
/// a listing can skip or duplicate a record is by resuming a cursor the server
/// no longer recognises.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceListingResult {
    Page(Box<ResourceListingPage>),
    Resync(ResourceListingResync),
    Refused(PlatformV2Refusal),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkContextGetResult {
    Record(WorkContextRecord),
    Refused(PlatformV2Refusal),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationPrepareResult {
    Preview(Box<MutationPreview>),
    MutationRefused(MutationRefusal),
    Refused(PlatformV2Refusal),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationDecisionResult {
    Approval(RawMutationApprovalDocument),
    MutationRefused(MutationRefusal),
    Refused(PlatformV2Refusal),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationReceiptResult {
    Receipt(RawMutationReceiptDocument),
    MutationRefused(MutationRefusal),
    Refused(PlatformV2Refusal),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LineageResult {
    Projection(LineageProjection),
    Refused(PlatformV2Refusal),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkspaceIntentResult {
    Outcome(WorkspaceIntentOutcome),
    Refused(PlatformV2Refusal),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewReadResult {
    Snapshot(Box<ReviewSnapshot>),
    Refused(PlatformV2Refusal),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttentionReadResult {
    Snapshot(Box<AttentionSourceSnapshot>),
    Refused(PlatformV2Refusal),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewCapabilitiesResult {
    // Boxed like the attention snapshot above: the capability document grew a
    // pull-request slot per grant, so carrying it inline would make every
    // refusal pay for the largest success.
    Capabilities(Box<ReviewCapabilities>),
    Refused(PlatformV2Refusal),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewReceiptResult {
    Receipt(ReviewActionReceipt),
    Refused(PlatformV2Refusal),
}

/// Exact server-advertised coordinates required to confirm one review action.
///
/// The digest types are already length- and grammar-bounded by the protocol,
/// while the workspace revision prevents a capability from being replayed
/// against a different authoritative workspace state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewActionConfirmation {
    confirmation_digest: ReviewConfirmationDigest,
    expected_workspace_revision: Revision,
    receipt_correlation_digest: ReviewReceiptCorrelationDigest,
}

impl ReviewActionConfirmation {
    #[must_use]
    pub const fn new(
        confirmation_digest: ReviewConfirmationDigest,
        expected_workspace_revision: Revision,
        receipt_correlation_digest: ReviewReceiptCorrelationDigest,
    ) -> Self {
        Self {
            confirmation_digest,
            expected_workspace_revision,
            receipt_correlation_digest,
        }
    }

    #[must_use]
    pub const fn confirmation_digest(&self) -> &ReviewConfirmationDigest {
        &self.confirmation_digest
    }

    #[must_use]
    pub const fn expected_workspace_revision(&self) -> Revision {
        self.expected_workspace_revision
    }

    #[must_use]
    pub const fn receipt_correlation_digest(&self) -> &ReviewReceiptCorrelationDigest {
        &self.receipt_correlation_digest
    }
}

/// Client whose v2 methods remain unavailable until this exact connection has
/// negotiated structured Platform major two.
type RawExchange<T> = fn(&mut T, PlatformV2Lane, &[u8]) -> Result<Vec<u8>, ClientError>;

pub struct PlatformV2Client<T> {
    transport: T,
    exchange: RawExchange<T>,
    next_request: u64,
    negotiated: Option<NegotiatedPlatform>,
}

impl PlatformV2Client<HttpsTransport> {
    #[must_use]
    pub const fn new_https(transport: HttpsTransport) -> Self {
        Self::with_exchange(transport, HttpsTransport::exchange)
    }
}

#[cfg(unix)]
impl PlatformV2Client<UnixTransport> {
    #[must_use]
    pub const fn new_unix(transport: UnixTransport) -> Self {
        Self::with_exchange(transport, UnixTransport::exchange)
    }
}

impl<T> PlatformV2Client<T> {
    const fn with_exchange(transport: T, exchange: RawExchange<T>) -> Self {
        Self {
            transport,
            exchange,
            next_request: 1,
            negotiated: None,
        }
    }

    fn next_request_id(&mut self) -> Result<RequestId, ClientError> {
        let id = RequestId::new(format!("platform-v2-client-{}", self.next_request))
            .map_err(|_| ClientError::Protocol)?;
        self.next_request = self
            .next_request
            .checked_add(1)
            .ok_or(ClientError::Protocol)?;
        Ok(id)
    }

    pub fn negotiate(
        &mut self,
        offer: PlatformVersionOffer,
    ) -> Result<NegotiationResult, ClientError> {
        self.negotiated = None;
        let request = PlatformNegotiationRequestMessage::new(
            self.next_request_id()?,
            PlatformNegotiationRequest::Negotiate(offer),
        );
        let payload = request
            .to_canonical_bytes()
            .map_err(|_| ClientError::Protocol)?;
        let response = (self.exchange)(&mut self.transport, PlatformV2Lane::Negotiation, &payload)?;
        let response = PlatformNegotiationResponseMessage::from_canonical_bytes(
            &response, &request,
        )
        .map_err(|error| match error {
            PlatformV2TransportError::CorrelationMismatch => ClientError::Correlation,
            PlatformV2TransportError::FrameTooLarge { .. } => ClientError::ResponseTooLarge,
            _ => ClientError::Protocol,
        })?;
        Ok(match response.response() {
            PlatformNegotiationResponse::Negotiated(value)
                if value.version() == PlatformVersion::V2 =>
            {
                self.negotiated = Some(*value);
                NegotiationResult::V2(*value)
            }
            PlatformNegotiationResponse::Negotiated(value) => NegotiationResult::Downgraded(*value),
            PlatformNegotiationResponse::Refused(value) => {
                NegotiationResult::Refused(value.clone())
            }
        })
    }

    fn request(&mut self, request: PlatformV2Request) -> Result<PlatformV2Response, ClientError> {
        if self.negotiated.is_none() {
            return Err(ClientError::NotNegotiated);
        }
        let message = PlatformV2RequestMessage::new(self.next_request_id()?, request);
        let payload = message
            .to_canonical_bytes()
            .map_err(|_| ClientError::Protocol)?;
        let response = (self.exchange)(&mut self.transport, PlatformV2Lane::V2, &payload)?;
        PlatformV2ResponseMessage::from_canonical_bytes(&response, &message)
            .map(|message| message.response().clone())
            .map_err(|error| match error {
                PlatformV2TransportError::CorrelationMismatch => ClientError::Correlation,
                PlatformV2TransportError::FrameTooLarge { .. } => ClientError::ResponseTooLarge,
                _ => ClientError::Protocol,
            })
    }

    pub fn query_work_contexts(
        &mut self,
        query: WorkContextQuery,
    ) -> Result<WorkContextQueryResult, ClientError> {
        let expected_after = query.after().cloned();
        let expected_limit = query.limit();
        match self.request(PlatformV2Request::QueryWorkContexts(query))? {
            PlatformV2Response::WorkContextPage(value)
                if value.requested_limit() == expected_limit
                    && value.after() == expected_after.as_ref() =>
            {
                Ok(WorkContextQueryResult::Page(value))
            }
            PlatformV2Response::WorkContextResync(value)
                if expected_after.as_ref() == Some(value.expired_after()) =>
            {
                Ok(WorkContextQueryResult::Resync(value))
            }
            PlatformV2Response::Refused(value) => Ok(WorkContextQueryResult::Refused(value)),
            _ => Err(ClientError::Protocol),
        }
    }

    /// List the bounded resource inventory, one page at a time.
    ///
    /// The answer is checked against the request before it is returned: the
    /// page must echo the limit this caller asked for, must carry the server's
    /// own clamp of it, and must continue from the cursor that was presented.
    /// A caller may ask for a page larger than the server's ceiling and will
    /// receive the server's — that is the contract, not a truncation, and
    /// `granted_limit` is what a caller reads to know which it got.
    pub fn list_resources(
        &mut self,
        query: ResourceListingQuery,
    ) -> Result<ResourceListingResult, ClientError> {
        // The correlation predicate is the contract's, not this client's:
        // `answers` re-derives the server's clamp instead of believing the
        // page, and `expires` refuses a resync for a walk that presented no
        // cursor. Restating either here would be a second copy of a rule that
        // grows in the protocol crate.
        let expected = query.clone();
        match self.request(PlatformV2Request::ListResources(query))? {
            PlatformV2Response::ResourceListingPage(value) if value.answers(&expected) => {
                Ok(ResourceListingResult::Page(Box::new(value)))
            }
            PlatformV2Response::ResourceListingResync(value) if value.expires(&expected) => {
                Ok(ResourceListingResult::Resync(value))
            }
            PlatformV2Response::Refused(value) => Ok(ResourceListingResult::Refused(value)),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn get_work_context(
        &mut self,
        identity: WorkContextIdentity,
    ) -> Result<WorkContextGetResult, ClientError> {
        match self.request(PlatformV2Request::GetWorkContext(identity.clone()))? {
            PlatformV2Response::WorkContextRecord(value) if value.identity() == &identity => {
                Ok(WorkContextGetResult::Record(value))
            }
            PlatformV2Response::Refused(value) => Ok(WorkContextGetResult::Refused(value)),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn prepare_mutation(
        &mut self,
        idempotency_key: IdempotencyKey,
        intent: WorkContextMutationIntent,
    ) -> Result<MutationPrepareResult, ClientError> {
        let expected_key = idempotency_key.clone();
        let expected_intent = intent.clone();
        match self.request(PlatformV2Request::PrepareMutation(
            MutationPrepareRequest::new(idempotency_key, intent),
        ))? {
            PlatformV2Response::MutationPreview(value)
                if value.proposal().idempotency_key() == &expected_key
                    && value.proposal().intent() == &expected_intent =>
            {
                Ok(MutationPrepareResult::Preview(Box::new(value)))
            }
            PlatformV2Response::MutationRefused(value) => {
                Ok(MutationPrepareResult::MutationRefused(value))
            }
            PlatformV2Response::Refused(value) => Ok(MutationPrepareResult::Refused(value)),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn decide_mutation(
        &mut self,
        preview: MutationPreviewRef,
        preview_digest: MutationPreviewDigest,
        decision: MutationApprovalDecision,
    ) -> Result<MutationDecisionResult, ClientError> {
        let expected_decision = decision;
        match self.request(PlatformV2Request::DecideMutation(
            MutationDecisionRequest::new(preview, preview_digest, decision),
        ))? {
            PlatformV2Response::MutationApproval(value) if matches!(value.decision(), Ok(decision) if decision == expected_decision) => {
                Ok(MutationDecisionResult::Approval(value))
            }
            PlatformV2Response::MutationRefused(value) => {
                Ok(MutationDecisionResult::MutationRefused(value))
            }
            PlatformV2Response::Refused(value) => Ok(MutationDecisionResult::Refused(value)),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn submit_mutation(
        &mut self,
        preview: MutationPreviewRef,
        preview_digest: MutationPreviewDigest,
        approval: Option<MutationApprovalId>,
    ) -> Result<MutationReceiptResult, ClientError> {
        match self.request(PlatformV2Request::SubmitMutation(
            MutationSubmitRequest::new(preview, preview_digest, approval),
        ))? {
            PlatformV2Response::MutationReceipt(value) => Ok(MutationReceiptResult::Receipt(value)),
            PlatformV2Response::MutationRefused(value) => {
                Ok(MutationReceiptResult::MutationRefused(value))
            }
            PlatformV2Response::Refused(value) => Ok(MutationReceiptResult::Refused(value)),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn get_mutation_receipt(
        &mut self,
        lookup: MutationReceiptLookup,
    ) -> Result<MutationReceiptResult, ClientError> {
        match self.request(PlatformV2Request::GetMutationReceipt(lookup))? {
            PlatformV2Response::MutationReceipt(value) => Ok(MutationReceiptResult::Receipt(value)),
            PlatformV2Response::MutationRefused(value) => {
                Ok(MutationReceiptResult::MutationRefused(value))
            }
            PlatformV2Response::Refused(value) => Ok(MutationReceiptResult::Refused(value)),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn get_mutation_receipt_by_idempotency_key(
        &mut self,
        project: ProjectId,
        idempotency_key: IdempotencyKey,
    ) -> Result<MutationReceiptResult, ClientError> {
        self.get_mutation_receipt(MutationReceiptLookup::new(
            project,
            ReceiptLookupKey::IdempotencyKey(idempotency_key),
        ))
    }

    pub fn get_lineage(
        &mut self,
        project: ProjectId,
        workspace: UserWorkspaceId,
    ) -> Result<LineageResult, ClientError> {
        let expected = workspace.clone();
        match self.request(PlatformV2Request::GetLineage(LineageReadRequest::new(
            project, workspace,
        )))? {
            PlatformV2Response::LineageResult(value) if value.workspace() == &expected => {
                Ok(LineageResult::Projection(value))
            }
            PlatformV2Response::Refused(value) => Ok(LineageResult::Refused(value)),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn submit_workspace_intent(
        &mut self,
        project: ProjectId,
        intent: WorkspaceIntent,
    ) -> Result<WorkspaceIntentResult, ClientError> {
        match self.request(PlatformV2Request::SubmitWorkspaceIntent(
            WorkspaceIntentRequest::new(project, intent),
        ))? {
            PlatformV2Response::WorkspaceIntentResult(value) => {
                Ok(WorkspaceIntentResult::Outcome(value))
            }
            PlatformV2Response::Refused(value) => Ok(WorkspaceIntentResult::Refused(value)),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn get_workspace_intent(
        &mut self,
        project: ProjectId,
        intent_id: WorkspaceIntentId,
    ) -> Result<WorkspaceIntentResult, ClientError> {
        match self.request(PlatformV2Request::GetWorkspaceIntent(
            WorkspaceIntentLookup::new(project, intent_id),
        ))? {
            PlatformV2Response::WorkspaceIntentResult(value) => {
                Ok(WorkspaceIntentResult::Outcome(value))
            }
            PlatformV2Response::Refused(value) => Ok(WorkspaceIntentResult::Refused(value)),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn get_review(
        &mut self,
        project: ProjectId,
        workspace: WorkContextIdentity,
    ) -> Result<ReviewReadResult, ClientError> {
        let expected = workspace.clone();
        let request =
            ReviewReadRequest::new(project, workspace).map_err(|_| ClientError::Protocol)?;
        match self.request(PlatformV2Request::GetReview(request))? {
            PlatformV2Response::ReviewResult(value) if value.workspace() == &expected => {
                Ok(ReviewReadResult::Snapshot(Box::new(value)))
            }
            PlatformV2Response::Refused(value) => Ok(ReviewReadResult::Refused(value)),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn get_attention_source_snapshot(
        &mut self,
        source: AttentionSource,
        project: ProjectId,
        user_workspace: UserWorkspaceId,
    ) -> Result<AttentionReadResult, ClientError> {
        let expected_source = source.clone();
        let expected_project = project.clone();
        let expected_workspace = user_workspace.clone();
        let request = AttentionReadRequest::new(source, project, user_workspace);
        match self.request(PlatformV2Request::GetAttentionSourceSnapshot(request))? {
            PlatformV2Response::AttentionSourceSnapshot(value)
                if value.source() == &expected_source
                    && value.project() == &expected_project
                    && value.user_workspace() == &expected_workspace =>
            {
                Ok(AttentionReadResult::Snapshot(Box::new(value)))
            }
            PlatformV2Response::Refused(value) => Ok(AttentionReadResult::Refused(value)),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn get_review_capabilities(
        &mut self,
        project: ProjectId,
        workspace: WorkContextIdentity,
    ) -> Result<ReviewCapabilitiesResult, ClientError> {
        let expected_project = project.clone();
        let expected_workspace = workspace.clone();
        let request =
            ReviewReadRequest::new(project, workspace).map_err(|_| ClientError::Protocol)?;
        match self.request(PlatformV2Request::GetReviewCapabilities(request))? {
            PlatformV2Response::ReviewCapabilities(value)
                if value.project() == &expected_project
                    && value.workspace() == &expected_workspace =>
            {
                Ok(ReviewCapabilitiesResult::Capabilities(Box::new(value)))
            }
            PlatformV2Response::Refused(value) => Ok(ReviewCapabilitiesResult::Refused(value)),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn execute_review_action(
        &mut self,
        workspace: WorkContextIdentity,
        expected_revision: Revision,
        action: ReviewAction,
        idempotency_key: IdempotencyKey,
    ) -> Result<ReviewReceiptResult, ClientError> {
        let expected_key = idempotency_key.clone();
        let request = ReviewActionTransportRequest::new(
            workspace,
            expected_revision,
            action,
            idempotency_key,
        )
        .map_err(|_| ClientError::Protocol)?;
        match self.request(PlatformV2Request::ExecuteReviewAction(request))? {
            PlatformV2Response::ReviewReceipt(value)
                if value.idempotency_key() == &expected_key =>
            {
                Ok(ReviewReceiptResult::Receipt(value))
            }
            PlatformV2Response::Refused(value) => Ok(ReviewReceiptResult::Refused(value)),
            _ => Err(ClientError::Protocol),
        }
    }

    /// Confirm one exact server-advertised review action preview.
    ///
    /// The confirmation coordinates must come from the matching current
    /// [`ReviewCapabilities`]. Rerun actions are deliberately refused by
    /// `execute_review_action` so callers cannot skip this explicit phase.
    pub fn execute_confirmed_review_action(
        &mut self,
        workspace: WorkContextIdentity,
        expected_revision: Revision,
        action: ReviewAction,
        idempotency_key: IdempotencyKey,
        confirmation: ReviewActionConfirmation,
    ) -> Result<ReviewReceiptResult, ClientError> {
        let expected_key = idempotency_key.clone();
        let ReviewActionConfirmation {
            confirmation_digest,
            expected_workspace_revision,
            receipt_correlation_digest,
        } = confirmation;
        let request = ReviewActionTransportRequest::new_confirmed_correlated(
            workspace,
            expected_revision,
            action,
            idempotency_key,
            confirmation_digest,
            expected_workspace_revision,
            receipt_correlation_digest,
        )
        .map_err(|_| ClientError::Protocol)?;
        match self.request(PlatformV2Request::ExecuteReviewAction(request))? {
            PlatformV2Response::ReviewReceipt(value)
                if value.idempotency_key() == &expected_key =>
            {
                Ok(ReviewReceiptResult::Receipt(value))
            }
            PlatformV2Response::Refused(value) => Ok(ReviewReceiptResult::Refused(value)),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn get_review_receipt(
        &mut self,
        project: ProjectId,
        workspace: WorkContextIdentity,
        idempotency_key: IdempotencyKey,
    ) -> Result<ReviewReceiptResult, ClientError> {
        let expected_key = idempotency_key.clone();
        let lookup = ReviewReceiptLookup::new(project, workspace, idempotency_key)
            .map_err(|_| ClientError::Protocol)?;
        match self.request(PlatformV2Request::GetReviewReceipt(lookup))? {
            PlatformV2Response::ReviewReceipt(value)
                if value.idempotency_key() == &expected_key =>
            {
                Ok(ReviewReceiptResult::Receipt(value))
            }
            PlatformV2Response::Refused(value) => Ok(ReviewReceiptResult::Refused(value)),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn get_correlated_review_receipt(
        &mut self,
        project: ProjectId,
        workspace: WorkContextIdentity,
        idempotency_key: IdempotencyKey,
        receipt_correlation_digest: ReviewReceiptCorrelationDigest,
    ) -> Result<ReviewReceiptResult, ClientError> {
        let expected_key = idempotency_key.clone();
        let lookup = ReviewReceiptLookup::new_correlated(
            project,
            workspace,
            idempotency_key,
            receipt_correlation_digest,
        )
        .map_err(|_| ClientError::Protocol)?;
        match self.request(PlatformV2Request::GetReviewReceipt(lookup))? {
            PlatformV2Response::ReviewReceipt(value)
                if value.idempotency_key() == &expected_key =>
            {
                Ok(ReviewReceiptResult::Receipt(value))
            }
            PlatformV2Response::Refused(value) => Ok(ReviewReceiptResult::Refused(value)),
            _ => Err(ClientError::Protocol),
        }
    }

    #[must_use]
    pub const fn negotiated(&self) -> Option<NegotiatedPlatform> {
        self.negotiated
    }

    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }
}

/// Deterministic, runtime-neutral fixtures for SDK and application tests.
pub mod testing {
    use std::collections::VecDeque;

    use super::*;

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum DeterministicPlatformV2Step {
        Negotiation(PlatformNegotiationResponse),
        V2(Box<PlatformV2Response>),
        MalformedResponse,
        OversizedResponse,
        UncorrelatedNegotiation(PlatformNegotiationResponse),
        Error(ClientError),
    }

    /// Exact-order typed transport. Responses are correlated from the
    /// canonical request presented by the client, so the real decoder remains
    /// in the exercised path.
    #[derive(Clone, Debug)]
    pub struct DeterministicPlatformV2Transport {
        steps: VecDeque<DeterministicPlatformV2Step>,
        negotiations: Vec<PlatformNegotiationRequestMessage>,
        requests: Vec<PlatformV2RequestMessage>,
    }

    impl DeterministicPlatformV2Transport {
        #[must_use]
        pub fn new(steps: impl IntoIterator<Item = DeterministicPlatformV2Step>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                negotiations: Vec::new(),
                requests: Vec::new(),
            }
        }

        #[must_use]
        pub fn pending_steps(&self) -> usize {
            self.steps.len()
        }

        #[must_use]
        pub fn negotiations(&self) -> &[PlatformNegotiationRequestMessage] {
            &self.negotiations
        }

        #[must_use]
        pub fn requests(&self) -> &[PlatformV2RequestMessage] {
            &self.requests
        }
    }

    impl PlatformV2Client<DeterministicPlatformV2Transport> {
        #[must_use]
        pub const fn new_testing(transport: DeterministicPlatformV2Transport) -> Self {
            Self::with_exchange(transport, DeterministicPlatformV2Transport::exchange)
        }
    }

    impl PlatformV2Transport for DeterministicPlatformV2Transport {
        fn exchange(
            &mut self,
            lane: PlatformV2Lane,
            canonical_request: &[u8],
        ) -> Result<Vec<u8>, ClientError> {
            let step = self.steps.pop_front().ok_or(ClientError::Protocol)?;
            let step = match step {
                DeterministicPlatformV2Step::Error(error) => return Err(error),
                DeterministicPlatformV2Step::MalformedResponse => return Ok(b"not-json".to_vec()),
                DeterministicPlatformV2Step::OversizedResponse => {
                    return Ok(vec![b'x'; lane.maximum_response_bytes() + 1]);
                }
                DeterministicPlatformV2Step::UncorrelatedNegotiation(response) => {
                    if lane != PlatformV2Lane::Negotiation {
                        return Err(ClientError::Protocol);
                    }
                    let request =
                        PlatformNegotiationRequestMessage::from_canonical_bytes(canonical_request)
                            .map_err(|_| ClientError::Protocol)?;
                    let other = PlatformNegotiationRequestMessage::new(
                        RequestId::new("fixture-other-request")
                            .map_err(|_| ClientError::Protocol)?,
                        request.request().clone(),
                    );
                    return PlatformNegotiationResponseMessage::for_request(&other, response)
                        .and_then(|message| message.to_canonical_bytes())
                        .map_err(|_| ClientError::Protocol);
                }
                step => step,
            };
            match (lane, step) {
                (
                    PlatformV2Lane::Negotiation,
                    DeterministicPlatformV2Step::Negotiation(response),
                ) => {
                    let request =
                        PlatformNegotiationRequestMessage::from_canonical_bytes(canonical_request)
                            .map_err(|_| ClientError::Protocol)?;
                    let response =
                        PlatformNegotiationResponseMessage::for_request(&request, response)
                            .and_then(|message| message.to_canonical_bytes())
                            .map_err(|_| ClientError::Protocol)?;
                    self.negotiations.push(request);
                    Ok(response)
                }
                (PlatformV2Lane::V2, DeterministicPlatformV2Step::V2(response)) => {
                    let request = PlatformV2RequestMessage::from_canonical_bytes(canonical_request)
                        .map_err(|_| ClientError::Protocol)?;
                    let response = PlatformV2ResponseMessage::for_request(&request, *response)
                        .and_then(|message| message.to_canonical_bytes())
                        .map_err(|_| ClientError::Protocol)?;
                    self.requests.push(request);
                    Ok(response)
                }
                _ => Err(ClientError::Protocol),
            }
        }
    }
}
