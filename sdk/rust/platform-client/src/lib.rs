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
    ActionReceipt, Capabilities, PlatformCursor, PlatformRequest, PlatformResponse, ReceiptId,
    ResourceCoordinate, ResourceRecord, Snapshot, Subscription,
};
use automonique_protocol::platform_api::{
    MAX_PLATFORM_CANONICAL_BYTES, PlatformRequestMessage, PlatformResponseMessage,
};

/// Stable client refusal categories. Payload bytes are never retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientError {
    Io,
    Protocol,
    Correlation,
    ResponseTooLarge,
}

impl ClientError {
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::Protocol => "protocol",
            Self::Correlation => "correlation",
            Self::ResponseTooLarge => "response_too_large",
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "platform client refused: {}", self.category())
    }
}

impl Error for ClientError {}

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

/// Small typed facade shared by interactive and headless clients.
pub struct PlatformClient<T> {
    transport: T,
    next_request: u64,
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

    pub fn capabilities(&mut self) -> Result<Capabilities, ClientError> {
        match self.request(PlatformRequest::Capabilities)? {
            PlatformResponse::Capabilities(value) => Ok(value),
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
    receipts: BTreeMap<String, ActionReceipt>,
    resync_required: BTreeSet<CursorKey>,
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

    pub fn apply_subscription(&mut self, page: Subscription) {
        let key = CursorKey::of(&page.cursor);
        let Some(prior) = self.cursors.get(&key) else {
            self.resync_required.insert(key);
            return;
        };
        let mut sequence = prior.sequence.get();
        let mut staged = self.resources.clone();
        for event in page.events {
            if CursorKey::of(&event.cursor) != key {
                self.resync_required.insert(key);
                return;
            }
            let event_sequence = event.cursor.sequence.get();
            if event_sequence <= sequence {
                if staged
                    .get(&resource_key(&event.resource.resource))
                    .is_some_and(|existing| existing == &event.resource)
                {
                    continue;
                }
                self.resync_required.insert(key);
                return;
            }
            if event_sequence != sequence.saturating_add(1) {
                self.resync_required.insert(key);
                return;
            }
            if staged
                .get(&resource_key(&event.resource.resource))
                .is_some_and(|existing| {
                    event.resource.freshness.revision < existing.freshness.revision
                })
            {
                self.resync_required.insert(key);
                return;
            }
            staged.insert(resource_key(&event.resource.resource), event.resource);
            sequence = event_sequence;
        }
        if page.cursor.sequence.get() != sequence {
            self.resync_required.insert(key);
            return;
        }
        self.resources = staged;
        self.cursors.insert(key.clone(), page.cursor);
        self.resync_required.remove(&key);
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

    #[must_use]
    pub fn resource(&self, coordinate: &ResourceCoordinate) -> Option<&ResourceRecord> {
        self.resources.get(&resource_key(coordinate))
    }

    #[must_use]
    pub fn receipt(&self, id: &ReceiptId) -> Option<&ActionReceipt> {
        self.receipts.get(id.as_str())
    }

    #[must_use]
    pub fn needs_resync(&self, cursor: &PlatformCursor) -> bool {
        self.resync_required.contains(&CursorKey::of(cursor))
    }
}
