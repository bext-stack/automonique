// SPDX-License-Identifier: Apache-2.0

//! Transport-neutral Rust client and presentation reducer for platform v1.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use automonique_protocol::codec::{
    FrameDecode, LENGTH_PREFIX_BYTES, RequestId, decode_frame, encode_frame,
};
use automonique_protocol::platform::{
    ActionReceipt, AttachRequest, Attachment, Capabilities, ClaimControlRequest, ClientId,
    ControlLease, DetachRequest, ExecuteRequest, GetReceiptRequest, IdempotencyKey,
    ListSessionsRequest, PlatformCursor, PlatformRequest, PlatformResponse, PlatformText,
    ReceiptId, ReceiptOutcome, ReleaseControlRequest, ResourceAuthority, ResourceCoordinate,
    ResourceRecord, SessionList, Snapshot, SnapshotRequest, SubscribeRequest, Subscription,
};
use automonique_protocol::platform_api::{
    MAX_PLATFORM_CANONICAL_BYTES, PlatformRequestMessage, PlatformResponseMessage,
};
use zeroize::Zeroizing;

pub const PLATFORM_CONTENT_TYPE: &str = "application/vnd.automonique.platform.v1+json";
const MAX_BEARER_BYTES: usize = 4096;

/// Stable client refusal categories. Payload bytes are never retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientError {
    Io,
    Protocol,
    Correlation,
    ResponseTooLarge,
    Endpoint,
    Unauthorized,
    UnexpectedStatus,
    UnexpectedContentType,
}

impl ClientError {
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::Protocol => "protocol",
            Self::Correlation => "correlation",
            Self::ResponseTooLarge => "response_too_large",
            Self::Endpoint => "endpoint",
            Self::Unauthorized => "unauthorized",
            Self::UnexpectedStatus => "unexpected_status",
            Self::UnexpectedContentType => "unexpected_content_type",
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "platform client refused: {}", self.category())
    }
}

impl Error for ClientError {}

/// Bounded bearer credential retained only by the HTTPS transport and always
/// redacted from diagnostics.
pub struct BearerToken(Zeroizing<String>);

impl BearerToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ClientError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_BEARER_BYTES
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
        {
            return Err(ClientError::Unauthorized);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    fn authorization(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("Bearer {}", self.0.as_str()))
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BearerToken(<redacted>)")
    }
}

/// Semantic request transport. Unix, HTTPS, WebSocket, and fakes implement the
/// same operation and return the same response vocabulary.
pub trait PlatformTransport {
    fn request(
        &mut self,
        request_id: RequestId,
        request: PlatformRequest,
    ) -> Result<PlatformResponse, ClientError>;
}

/// Authenticated local Unix-socket transport.
#[derive(Clone, Debug)]
pub struct UnixTransport {
    socket: PathBuf,
    timeout: Duration,
}

impl UnixTransport {
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            timeout: Duration::from_secs(5),
        }
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }
}

impl PlatformTransport for UnixTransport {
    fn request(
        &mut self,
        request_id: RequestId,
        request: PlatformRequest,
    ) -> Result<PlatformResponse, ClientError> {
        let payload = PlatformRequestMessage::new(request_id.clone(), request)
            .to_message()
            .map_err(|_| ClientError::Protocol)?
            .to_canonical_bytes();
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
        encode_frame(&payload, &mut frame).map_err(|_| ClientError::Protocol)?;

        let mut stream = UnixStream::connect(&self.socket).map_err(|_| ClientError::Io)?;
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
        if length == 0 || length > MAX_PLATFORM_CANONICAL_BYTES {
            return Err(ClientError::ResponseTooLarge);
        }
        let mut framed = Vec::with_capacity(LENGTH_PREFIX_BYTES + length);
        framed.extend_from_slice(&prefix);
        framed.resize(LENGTH_PREFIX_BYTES + length, 0);
        stream
            .read_exact(&mut framed[LENGTH_PREFIX_BYTES..])
            .map_err(|_| ClientError::Io)?;
        let FrameDecode::Frame { payload, consumed } =
            decode_frame(&framed).map_err(|_| ClientError::Protocol)?
        else {
            return Err(ClientError::Protocol);
        };
        if consumed != framed.len() {
            return Err(ClientError::Protocol);
        }
        let response = PlatformResponseMessage::from_canonical_bytes(payload)
            .map_err(|_| ClientError::Protocol)?;
        if response.request_id() != &request_id {
            return Err(ClientError::Correlation);
        }
        Ok(response.response().clone())
    }
}

/// Remote HTTPS transport carrying the exact canonical platform frame used on
/// the Unix socket. Authentication is outside the frame and no remote wire
/// types or retry policy are introduced here.
pub struct HttpsTransport {
    endpoint: String,
    token: BearerToken,
    timeout: Duration,
    agent: ureq::Agent,
}

impl HttpsTransport {
    pub fn new(endpoint: impl Into<String>, token: BearerToken) -> Result<Self, ClientError> {
        let endpoint = endpoint.into();
        validate_endpoint(&endpoint)?;
        Ok(Self {
            endpoint,
            token,
            timeout: Duration::from_secs(10),
            agent: ureq::Agent::config_builder().build().new_agent(),
        })
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl fmt::Debug for HttpsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpsTransport")
            .field("endpoint", &self.endpoint)
            .field("token", &"<redacted>")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

fn validate_endpoint(endpoint: &str) -> Result<(), ClientError> {
    let uri: ureq::http::Uri = endpoint.parse().map_err(|_| ClientError::Endpoint)?;
    let scheme = uri.scheme_str().ok_or(ClientError::Endpoint)?;
    let host = uri.host().ok_or(ClientError::Endpoint)?;
    if uri
        .authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
        || uri.query().is_some()
        || (scheme != "https"
            && !(scheme == "http" && matches!(host, "localhost" | "127.0.0.1" | "[::1]")))
    {
        return Err(ClientError::Endpoint);
    }
    Ok(())
}

impl PlatformTransport for HttpsTransport {
    fn request(
        &mut self,
        request_id: RequestId,
        request: PlatformRequest,
    ) -> Result<PlatformResponse, ClientError> {
        let payload = PlatformRequestMessage::new(request_id.clone(), request)
            .to_message()
            .map_err(|_| ClientError::Protocol)?
            .to_canonical_bytes();
        let authorization = self.token.authorization();
        let mut response = self
            .agent
            .post(&self.endpoint)
            .header("authorization", authorization.as_str())
            .header("content-type", PLATFORM_CONTENT_TYPE)
            .header("accept", PLATFORM_CONTENT_TYPE)
            .config()
            .timeout_global(Some(self.timeout))
            .build()
            .send(&payload)
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
        if content_type != Some(PLATFORM_CONTENT_TYPE) {
            return Err(ClientError::UnexpectedContentType);
        }
        let mut body = Vec::new();
        response
            .body_mut()
            .with_config()
            .limit((MAX_PLATFORM_CANONICAL_BYTES + 1) as u64)
            .reader()
            .read_to_end(&mut body)
            .map_err(|_| ClientError::Io)?;
        if body.len() > MAX_PLATFORM_CANONICAL_BYTES {
            return Err(ClientError::ResponseTooLarge);
        }
        let response = PlatformResponseMessage::from_canonical_bytes(&body)
            .map_err(|_| ClientError::Protocol)?;
        if response.request_id() != &request_id {
            return Err(ClientError::Correlation);
        }
        Ok(response.response().clone())
    }
}

/// Small typed facade shared by interactive and headless clients.
pub struct PlatformClient<T> {
    transport: T,
    next_request: u64,
}

/// Recoverable result of a cursor subscription.
///
/// A retained cursor yields a page. An expired cursor is not a transport or
/// protocol failure: the server explicitly asks the client to replace that
/// stream with a fresh snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubscriptionResult {
    Page(Subscription),
    ResyncRequired { explanation: PlatformText },
}

/// Recoverable result of refreshing the attachable-session directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionListResult {
    Sessions(SessionList),
    ResyncRequired { explanation: PlatformText },
}

/// Typed result of an explicit platform mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionResult {
    Receipt(ActionReceipt),
    Refused {
        outcome: ReceiptOutcome,
        explanation: PlatformText,
    },
}

impl<T: PlatformTransport> PlatformClient<T> {
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            next_request: 1,
        }
    }

    pub fn request(&mut self, request: PlatformRequest) -> Result<PlatformResponse, ClientError> {
        let request_id = RequestId::new(format!("platform-client-{}", self.next_request))
            .map_err(|_| ClientError::Protocol)?;
        self.next_request = self
            .next_request
            .checked_add(1)
            .ok_or(ClientError::Protocol)?;
        self.transport.request(request_id, request)
    }

    /// Send a request with a caller-supplied correlation identifier. Gateways
    /// use this to preserve the exact request identity across transports.
    pub fn request_correlated(
        &mut self,
        request_id: RequestId,
        request: PlatformRequest,
    ) -> Result<PlatformResponse, ClientError> {
        self.transport.request(request_id, request)
    }

    pub fn capabilities(&mut self) -> Result<Capabilities, ClientError> {
        match self.request(PlatformRequest::Capabilities)? {
            PlatformResponse::Capabilities(value) => Ok(value),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn snapshot(
        &mut self,
        resources: Vec<ResourceCoordinate>,
    ) -> Result<Snapshot, ClientError> {
        match self.request(PlatformRequest::Snapshot(
            SnapshotRequest::new(resources).map_err(|_| ClientError::Protocol)?,
        ))? {
            PlatformResponse::Snapshot(value) => Ok(value),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn subscribe(
        &mut self,
        cursor: Option<PlatformCursor>,
    ) -> Result<Subscription, ClientError> {
        match self.subscribe_recoverable(cursor)? {
            SubscriptionResult::Page(value) => Ok(value),
            SubscriptionResult::ResyncRequired { .. } => Err(ClientError::Protocol),
        }
    }

    /// Subscribe while preserving the protocol's explicit cursor-expiry
    /// outcome so interactive clients can resnapshot instead of treating it
    /// as an opaque failure.
    pub fn subscribe_recoverable(
        &mut self,
        cursor: Option<PlatformCursor>,
    ) -> Result<SubscriptionResult, ClientError> {
        match self.request(PlatformRequest::Subscribe(SubscribeRequest { cursor }))? {
            PlatformResponse::Subscription(value) => Ok(SubscriptionResult::Page(value)),
            PlatformResponse::Refused {
                outcome: ReceiptOutcome::ResyncRequired,
                explanation,
            } => Ok(SubscriptionResult::ResyncRequired { explanation }),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn execute(&mut self, request: ExecuteRequest) -> Result<ActionReceipt, ClientError> {
        match self.execute_outcome(request)? {
            ActionResult::Receipt(value) => Ok(value),
            ActionResult::Refused { .. } => Err(ClientError::Protocol),
        }
    }

    /// Execute without collapsing a typed authorization, conflict, or stale
    /// revision refusal into a generic protocol error.
    pub fn execute_outcome(
        &mut self,
        request: ExecuteRequest,
    ) -> Result<ActionResult, ClientError> {
        match self.request(PlatformRequest::Execute(request))? {
            PlatformResponse::Receipt(value) => Ok(ActionResult::Receipt(value)),
            PlatformResponse::Refused {
                outcome,
                explanation,
            } => Ok(ActionResult::Refused {
                outcome,
                explanation,
            }),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn get_receipt(
        &mut self,
        request: GetReceiptRequest,
    ) -> Result<ActionReceipt, ClientError> {
        match self.request(PlatformRequest::GetReceipt(request))? {
            PlatformResponse::Receipt(value) => Ok(value),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn list_sessions(
        &mut self,
        authority: ResourceAuthority,
        cursor: Option<PlatformCursor>,
    ) -> Result<SessionList, ClientError> {
        match self.list_sessions_recoverable(authority, cursor)? {
            SessionListResult::Sessions(value) => Ok(value),
            SessionListResult::ResyncRequired { .. } => Err(ClientError::Protocol),
        }
    }

    /// Refresh session discovery while preserving an expired-directory cursor
    /// as a recoverable resnapshot signal.
    pub fn list_sessions_recoverable(
        &mut self,
        authority: ResourceAuthority,
        cursor: Option<PlatformCursor>,
    ) -> Result<SessionListResult, ClientError> {
        match self.request(PlatformRequest::ListSessions(ListSessionsRequest {
            authority,
            cursor,
        }))? {
            PlatformResponse::Sessions(value) => Ok(SessionListResult::Sessions(value)),
            PlatformResponse::Refused {
                outcome: ReceiptOutcome::ResyncRequired,
                explanation,
            } => Ok(SessionListResult::ResyncRequired { explanation }),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn attach(
        &mut self,
        session: ResourceCoordinate,
        client: ClientId,
    ) -> Result<Attachment, ClientError> {
        match self.request(PlatformRequest::Attach(AttachRequest { session, client }))? {
            PlatformResponse::Attached(value) => Ok(value),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn detach(
        &mut self,
        session: ResourceCoordinate,
        client: ClientId,
    ) -> Result<(), ClientError> {
        match self.request(PlatformRequest::Detach(DetachRequest {
            session: session.clone(),
            client: client.clone(),
        }))? {
            PlatformResponse::Detached {
                session: response_session,
                client: response_client,
            } if response_session == session && response_client == client => Ok(()),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn claim_control(
        &mut self,
        session: ResourceCoordinate,
        client: ClientId,
        idempotency_key: IdempotencyKey,
    ) -> Result<ControlLease, ClientError> {
        match self.request(PlatformRequest::ClaimControl(ClaimControlRequest {
            session,
            client,
            idempotency_key,
        }))? {
            PlatformResponse::ControlClaimed(value) => Ok(value),
            _ => Err(ClientError::Protocol),
        }
    }

    pub fn release_control(&mut self, request: ReleaseControlRequest) -> Result<(), ClientError> {
        let session = request.session.clone();
        let client = request.client.clone();
        let lease = request.lease.clone();
        match self.request(PlatformRequest::ReleaseControl(request))? {
            PlatformResponse::ControlReleased {
                session: response_session,
                client: response_client,
                lease: response_lease,
            } if response_session == session
                && response_client == client
                && response_lease == lease =>
            {
                Ok(())
            }
            _ => Err(ClientError::Protocol),
        }
    }

    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct CursorKey {
    authority: &'static str,
    topic: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct AttachmentKey {
    session: String,
    client: String,
}

impl AttachmentKey {
    fn of(attachment: &Attachment) -> Self {
        Self {
            session: resource_key(&attachment.session),
            client: attachment.client.as_str().to_owned(),
        }
    }
}

impl CursorKey {
    fn of(cursor: &PlatformCursor) -> Self {
        Self {
            authority: cursor.authority.as_str(),
            topic: cursor.topic.as_str().to_owned(),
        }
    }
}

fn resource_key(value: &ResourceCoordinate) -> String {
    format!(
        "{}\0{}\0{}",
        value.authority.as_str(),
        value.kind.as_str(),
        value.id.as_str()
    )
}

/// Presentation-neutral state with one independent cursor per attachment.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PlatformView {
    resources: BTreeMap<String, ResourceRecord>,
    cursors: BTreeMap<CursorKey, PlatformCursor>,
    attachment_cursors: BTreeMap<AttachmentKey, PlatformCursor>,
    receipts: BTreeMap<String, ActionReceipt>,
    resync_required: BTreeSet<CursorKey>,
    attachment_resync_required: BTreeSet<AttachmentKey>,
}

/// Result of applying one subscription page to a [`PlatformView`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionApply {
    Applied { events: usize },
    ResyncRequired,
}

impl PlatformView {
    pub fn apply_snapshot(&mut self, snapshot: Snapshot) {
        let key = CursorKey::of(&snapshot.cursor);
        for resource in snapshot.resources {
            self.resources
                .insert(resource_key(&resource.resource), resource);
        }
        self.cursors.insert(key.clone(), snapshot.cursor);
        self.resync_required.remove(&key);
    }

    #[must_use]
    pub fn apply_subscription(&mut self, page: Subscription) -> SubscriptionApply {
        let key = CursorKey::of(&page.cursor);
        let Some(prior) = self.cursors.get(&key).cloned() else {
            self.resync_required.insert(key);
            return SubscriptionApply::ResyncRequired;
        };
        match stage_subscription(&self.resources, &prior, page) {
            Ok((resources, cursor, applied)) => {
                self.resources = resources;
                self.cursors.insert(key.clone(), cursor);
                self.resync_required.remove(&key);
                SubscriptionApply::Applied { events: applied }
            }
            Err(()) => {
                self.resync_required.insert(key);
                SubscriptionApply::ResyncRequired
            }
        }
    }

    /// Apply a page to one attachment without advancing any other attachment
    /// that happens to observe the same authority/topic.
    #[must_use]
    pub fn apply_attachment_subscription(
        &mut self,
        attachment: &Attachment,
        page: Subscription,
    ) -> SubscriptionApply {
        let key = AttachmentKey::of(attachment);
        let Some(prior) = self.attachment_cursors.get(&key).cloned() else {
            self.attachment_resync_required.insert(key);
            return SubscriptionApply::ResyncRequired;
        };
        match stage_subscription(&self.resources, &prior, page) {
            Ok((resources, cursor, applied)) => {
                self.resources = resources;
                self.attachment_cursors.insert(key.clone(), cursor);
                self.attachment_resync_required.remove(&key);
                SubscriptionApply::Applied { events: applied }
            }
            Err(()) => {
                self.attachment_resync_required.insert(key);
                SubscriptionApply::ResyncRequired
            }
        }
    }

    pub fn apply_receipt(&mut self, receipt: ActionReceipt) {
        let key = receipt.id.as_str().to_owned();
        if self
            .receipts
            .get(&key)
            .is_some_and(|prior| receipt.revision < prior.revision)
        {
            return;
        }
        self.receipts.insert(key, receipt);
    }

    /// Start or resume the independent stream represented by an attachment.
    pub fn track_attachment(&mut self, attachment: &Attachment) {
        let key = AttachmentKey::of(attachment);
        self.attachment_cursors
            .insert(key.clone(), attachment.cursor.clone());
        self.attachment_resync_required.remove(&key);
    }

    /// Forget the independent stream represented by a detached attachment.
    pub fn forget_attachment(&mut self, attachment: &Attachment) {
        let key = AttachmentKey::of(attachment);
        self.attachment_cursors.remove(&key);
        self.attachment_resync_required.remove(&key);
    }

    #[must_use]
    pub fn resource(&self, coordinate: &ResourceCoordinate) -> Option<&ResourceRecord> {
        self.resources.get(&resource_key(coordinate))
    }

    /// Iterate the current projection in stable resource-coordinate order.
    pub fn resources(&self) -> impl ExactSizeIterator<Item = &ResourceRecord> {
        self.resources.values()
    }

    #[must_use]
    pub fn receipt(&self, id: &ReceiptId) -> Option<&ActionReceipt> {
        self.receipts.get(id.as_str())
    }

    /// Iterate reconciled receipts in stable receipt-id order.
    pub fn receipts(&self) -> impl ExactSizeIterator<Item = &ActionReceipt> {
        self.receipts.values()
    }

    /// Return the latest cursor for the same authority/topic as `cursor`.
    #[must_use]
    pub fn cursor(&self, cursor: &PlatformCursor) -> Option<&PlatformCursor> {
        self.cursors.get(&CursorKey::of(cursor))
    }

    /// Return the latest cursor for one exact session/client attachment.
    #[must_use]
    pub fn attachment_cursor(&self, attachment: &Attachment) -> Option<&PlatformCursor> {
        self.attachment_cursors.get(&AttachmentKey::of(attachment))
    }

    #[must_use]
    pub fn needs_resync(&self, cursor: &PlatformCursor) -> bool {
        self.resync_required.contains(&CursorKey::of(cursor))
    }

    /// Whether one exact attachment must be detached and reattached before it
    /// can resume safely.
    #[must_use]
    pub fn attachment_needs_resync(&self, attachment: &Attachment) -> bool {
        self.attachment_resync_required
            .contains(&AttachmentKey::of(attachment))
    }
}

fn stage_subscription(
    resources: &BTreeMap<String, ResourceRecord>,
    prior: &PlatformCursor,
    page: Subscription,
) -> Result<(BTreeMap<String, ResourceRecord>, PlatformCursor, usize), ()> {
    let key = CursorKey::of(&page.cursor);
    if CursorKey::of(prior) != key {
        return Err(());
    }
    let mut sequence = prior.sequence.get();
    let mut staged = resources.clone();
    let mut applied = 0;
    for event in page.events {
        if CursorKey::of(&event.cursor) != key {
            return Err(());
        }
        let event_sequence = event.cursor.sequence.get();
        if event_sequence <= sequence {
            if staged
                .get(&resource_key(&event.resource.resource))
                .is_some_and(|existing| existing == &event.resource)
            {
                continue;
            }
            return Err(());
        }
        if event_sequence != sequence.saturating_add(1) {
            return Err(());
        }
        if staged
            .get(&resource_key(&event.resource.resource))
            .is_some_and(|existing| event.resource.freshness.revision < existing.freshness.revision)
        {
            return Err(());
        }
        staged.insert(resource_key(&event.resource.resource), event.resource);
        sequence = event_sequence;
        applied += 1;
    }
    if page.cursor.sequence.get() != sequence {
        return Err(());
    }
    Ok((staged, page.cursor, applied))
}
