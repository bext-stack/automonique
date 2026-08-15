// SPDX-License-Identifier: Elastic-2.0

//! Bounded synchronous Socket Mode connection primitives.
//!
//! The injected [`SynchronousWebSocket`] seam keeps protocol tests hermetic,
//! while [`SlackSocketModeConnector`] provides the production adapter over
//! Tungstenite and Rustls. The temporary URL is locked to Slack's production
//! `wss` hosts and redacted like a credential, connection and I/O deadlines are
//! clamped, only text envelopes are admitted, websocket control payloads are
//! checked, and an acknowledgement has one canonical JSON spelling.

use std::fmt;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use tungstenite::handshake::{HandshakeError, client::ClientHandshake};
use tungstenite::protocol::frame::{CloseFrame, coding::CloseCode};
use tungstenite::protocol::{Message, WebSocket, WebSocketConfig};
use tungstenite::stream::MaybeTlsStream;

/// Longest temporary Socket Mode URL accepted from `apps.connections.open`.
pub const MAX_SOCKET_MODE_URL_BYTES: usize = 2_048;

/// Longest text envelope accepted from a Socket Mode websocket.
///
/// Slack documents a 256 KiB event-payload ceiling. The outer Socket Mode
/// metadata fits inside the same bounded frame in the current protocol, and a
/// frame beyond this limit is refused rather than partially retained.
pub const MAX_SOCKET_MODE_ENVELOPE_BYTES: usize = 256 * 1024;

/// Whole-operation deadline ceiling for one synchronous websocket read/write.
pub const SOCKET_MODE_IO_TIMEOUT_SECONDS: u64 = 10;

/// Most control frames skipped while waiting for one application envelope.
const MAX_CONTROL_FRAMES_PER_RECEIVE: usize = 16;

/// RFC 6455's maximum control-frame payload.
const MAX_CONTROL_PAYLOAD_BYTES: usize = 125;

/// Longest opaque Socket Mode acknowledgement key accepted.
const MAX_ENVELOPE_ID_BYTES: usize = 128;

/// A temporary Socket Mode websocket URL returned by Slack.
///
/// The query contains a short-lived ticket and is therefore credential-like:
/// the type has no `Display` or raw getter, its `Debug` is redacted, and the
/// exact URL is lent only through [`Self::with_url`]. Construction accepts only
/// `wss://wss.slack.com` or a `wss-*` host beneath `slack.com`, with Slack's
/// `/link/` path and a non-empty `ticket` query field. No loopback exception is
/// provided because HTTP tests inject a transport and never need a fake Socket
/// Mode origin.
pub struct SlackSocketUrl {
    value: String,
    host: String,
}

impl SlackSocketUrl {
    /// Validate a temporary production Socket Mode URL.
    ///
    /// # Errors
    ///
    /// Returns [`SocketModeFailure::UrlRejected`] for a non-`wss` URL, a host
    /// outside Slack's production domain, a port/userinfo/fragment, a path other
    /// than `/link/`, a missing ticket, or a value outside the byte bound.
    pub fn new(value: &str) -> Result<Self, SocketModeFailure> {
        if value.is_empty()
            || value.len() > MAX_SOCKET_MODE_URL_BYTES
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
            || value.contains(['#', '@', '\\'])
        {
            return Err(SocketModeFailure::UrlRejected);
        }
        let remainder = value
            .strip_prefix("wss://")
            .ok_or(SocketModeFailure::UrlRejected)?;
        let (authority, tail) = remainder
            .split_once('/')
            .ok_or(SocketModeFailure::UrlRejected)?;
        if authority.is_empty() || authority.contains(':') || !valid_socket_host(authority) {
            return Err(SocketModeFailure::UrlRejected);
        }
        let path_and_query = format!("/{tail}");
        let (path, query) = path_and_query
            .split_once('?')
            .ok_or(SocketModeFailure::UrlRejected)?;
        if path != "/link/" || !has_nonempty_ticket(query) {
            return Err(SocketModeFailure::UrlRejected);
        }
        Ok(Self {
            value: value.to_owned(),
            host: authority.to_owned(),
        })
    }

    /// Production host named by this URL, without its credential-bearing query.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Lend the exact URL to a trusted websocket connector for one operation.
    pub fn with_url<R>(&self, consume: impl FnOnce(&str) -> R) -> R {
        consume(&self.value)
    }
}

impl fmt::Debug for SlackSocketUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SlackSocketUrl")
            .field("host", &self.host)
            .field("ticket", &"<redacted>")
            .finish()
    }
}

impl Drop for SlackSocketUrl {
    fn drop(&mut self) {
        let width = self.value.len();
        self.value.clear();
        for _ in 0..width {
            self.value.push('\0');
        }
    }
}

fn valid_socket_host(host: &str) -> bool {
    if host != "wss.slack.com" && !(host.starts_with("wss-") && host.ends_with(".slack.com")) {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn has_nonempty_ticket(query: &str) -> bool {
    query.split('&').any(|field| {
        field
            .split_once('=')
            .is_some_and(|(name, value)| name == "ticket" && !value.is_empty())
    })
}

/// One complete websocket message surfaced by an injected synchronous adapter.
///
/// A concrete websocket library is responsible for masking, fragmentation and
/// TLS. It maps a protocol-level control-frame violation to
/// [`SocketIoFailure::Protocol`]; payload checks repeated here keep fake and
/// production adapters under the same bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocketFrame {
    Text(Vec<u8>),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    /// Raw RFC 6455 close payload: optional two-byte code then UTF-8 reason.
    Close(Vec<u8>),
}

/// Closed failures an injected websocket adapter may report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketIoFailure {
    TimedOut,
    /// Websocket protocol violation, including malformed/fragmented controls.
    Protocol,
    Unavailable,
}

/// Minimal synchronous websocket seam used by [`SocketModeConnection`].
pub trait SynchronousWebSocket {
    fn receive(&mut self, timeout: Duration) -> Result<SocketFrame, SocketIoFailure>;
    fn send(&mut self, frame: SocketFrame, timeout: Duration) -> Result<(), SocketIoFailure>;
}

/// One received, bounded UTF-8 Socket Mode envelope.
pub struct SocketModeEnvelope(String);

impl SocketModeEnvelope {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for SocketModeEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SocketModeEnvelope")
            .field("content", &"<redacted>")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// Canonical Socket Mode acknowledgement body.
pub struct SocketModeAcknowledgement(Vec<u8>);

impl SocketModeAcknowledgement {
    /// Construct exactly `{"envelope_id":<JSON string>}`.
    ///
    /// # Errors
    ///
    /// Refuses an empty, overlong, non-ASCII-graphic, or colon-bearing key. The
    /// grammar matches the transport parser's unambiguous Slack identifier
    /// grammar; JSON escaping is still applied rather than assumed unnecessary.
    pub fn new(envelope_id: &str) -> Result<Self, SocketModeFailure> {
        if envelope_id.is_empty()
            || envelope_id.len() > MAX_ENVELOPE_ID_BYTES
            || !envelope_id
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b':')
        {
            return Err(SocketModeFailure::InvalidAcknowledgement);
        }
        let encoded = serde_json::to_string(envelope_id)
            .map_err(|_| SocketModeFailure::InvalidAcknowledgement)?;
        Ok(Self(format!("{{\"envelope_id\":{encoded}}}").into_bytes()))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SocketModeAcknowledgement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SocketModeAcknowledgement")
            .field("envelope_id", &"<redacted>")
            .finish()
    }
}

/// Closed Socket Mode connection failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketModeFailure {
    UrlRejected,
    Redirected,
    TimedOut,
    Unavailable,
    BinaryFrame,
    EnvelopeTooLarge,
    InvalidText,
    MalformedControl,
    Closed,
    InvalidAcknowledgement,
}

impl SocketModeFailure {
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::UrlRejected => "socket_url_rejected",
            Self::Redirected => "socket_redirected",
            Self::TimedOut => "socket_timed_out",
            Self::Unavailable => "socket_unavailable",
            Self::BinaryFrame => "socket_binary_frame",
            Self::EnvelopeTooLarge => "socket_envelope_too_large",
            Self::InvalidText => "socket_invalid_text",
            Self::MalformedControl => "socket_malformed_control",
            Self::Closed => "socket_closed",
            Self::InvalidAcknowledgement => "socket_invalid_acknowledgement",
        }
    }
}

impl fmt::Display for SocketModeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.category())
    }
}

impl std::error::Error for SocketModeFailure {}

/// Bounded synchronous protocol over one injected websocket connection.
pub struct SocketModeConnection<S> {
    socket: S,
    timeout: Duration,
}

impl<S> SocketModeConnection<S>
where
    S: SynchronousWebSocket,
{
    #[must_use]
    pub fn new(socket: S) -> Self {
        Self::with_timeout(socket, Duration::from_secs(SOCKET_MODE_IO_TIMEOUT_SECONDS))
    }

    /// Bind one socket with a timeout no wider than the connector ceiling.
    #[must_use]
    pub fn with_timeout(socket: S, timeout: Duration) -> Self {
        let ceiling = Duration::from_secs(SOCKET_MODE_IO_TIMEOUT_SECONDS);
        let timeout = if timeout.is_zero() {
            ceiling
        } else {
            timeout.min(ceiling)
        };
        Self { socket, timeout }
    }

    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn into_inner(self) -> S {
        self.socket
    }

    /// Receive one application text envelope, handling bounded ping/pong noise.
    ///
    /// # Errors
    ///
    /// Binary data, oversized/invalid text, malformed controls, close, timeout,
    /// protocol violations and adapter failures are all distinct fail-closed
    /// outcomes. A run of more than sixteen valid controls without an envelope
    /// is refused as unavailable instead of spinning forever.
    pub fn receive_envelope(&mut self) -> Result<SocketModeEnvelope, SocketModeFailure> {
        for _ in 0..=MAX_CONTROL_FRAMES_PER_RECEIVE {
            let frame = self.socket.receive(self.timeout).map_err(map_io_failure)?;
            match frame {
                SocketFrame::Text(bytes) => return envelope(bytes),
                SocketFrame::Binary(_) => return Err(SocketModeFailure::BinaryFrame),
                SocketFrame::Ping(payload) => {
                    validate_control_payload(&payload)?;
                    self.socket
                        .send(SocketFrame::Pong(payload), self.timeout)
                        .map_err(map_io_failure)?;
                }
                SocketFrame::Pong(payload) => validate_control_payload(&payload)?,
                SocketFrame::Close(payload) => {
                    validate_close_payload(&payload)?;
                    return Err(SocketModeFailure::Closed);
                }
            }
        }
        Err(SocketModeFailure::Unavailable)
    }

    /// Send one canonical text acknowledgement.
    pub fn send_acknowledgement(
        &mut self,
        acknowledgement: &SocketModeAcknowledgement,
    ) -> Result<(), SocketModeFailure> {
        self.socket
            .send(
                SocketFrame::Text(acknowledgement.as_bytes().to_vec()),
                self.timeout,
            )
            .map_err(map_io_failure)
    }

    /// Validate an envelope key and send its canonical acknowledgement.
    pub fn acknowledge(&mut self, envelope_id: &str) -> Result<(), SocketModeFailure> {
        let acknowledgement = SocketModeAcknowledgement::new(envelope_id)?;
        self.send_acknowledgement(&acknowledgement)
    }
}

/// Concrete synchronous Rustls websocket opened only from a [`SlackSocketUrl`].
///
/// The inner tungstenite value is private so no caller can swap in a plaintext
/// stream or a second URL. `Debug` reports no peer address, request path, ticket,
/// frame, or TLS internals.
pub struct ProductionSocketModeSocket {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
}

impl fmt::Debug for ProductionSocketModeSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductionSocketModeSocket(<redacted>)")
    }
}

impl SynchronousWebSocket for ProductionSocketModeSocket {
    fn receive(&mut self, timeout: Duration) -> Result<SocketFrame, SocketIoFailure> {
        set_stream_timeout(self.socket.get_mut(), timeout)?;
        message_to_frame(self.socket.read().map_err(map_tungstenite_io)?)
    }

    fn send(&mut self, frame: SocketFrame, timeout: Duration) -> Result<(), SocketIoFailure> {
        set_stream_timeout(self.socket.get_mut(), timeout)?;
        self.socket
            .send(frame_to_message(frame)?)
            .map_err(map_tungstenite_io)
    }
}

/// Production connector for one temporary Slack Socket Mode URL.
///
/// DNS resolution, TCP connect, TLS and websocket handshake are synchronous.
/// DNS is isolated behind a bounded channel wait, TCP uses one shared deadline
/// across all resolved addresses, and the TCP stream carries read/write
/// timeouts before Rustls or the websocket handshake sees it. The websocket
/// configuration independently caps both frames and reassembled messages.
#[derive(Clone, Copy, Debug)]
pub struct SlackSocketModeConnector {
    timeout: Duration,
}

impl Default for SlackSocketModeConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl SlackSocketModeConnector {
    /// Construct with the connector-wide I/O deadline ceiling.
    #[must_use]
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(SOCKET_MODE_IO_TIMEOUT_SECONDS),
        }
    }

    /// Construct with a tighter connect, handshake, read and write timeout.
    #[must_use]
    pub fn with_timeout(timeout: Duration) -> Self {
        let ceiling = Duration::from_secs(SOCKET_MODE_IO_TIMEOUT_SECONDS);
        Self {
            timeout: if timeout.is_zero() {
                ceiling
            } else {
                timeout.min(ceiling)
            },
        }
    }

    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Open a verified Rustls websocket to this exact temporary Slack URL.
    ///
    /// # Errors
    ///
    /// DNS/TCP/TLS/handshake failures are content-free typed outcomes. A
    /// websocket redirect is named and never followed. No live call occurs
    /// until this method is explicitly invoked.
    pub fn connect(
        &self,
        url: &SlackSocketUrl,
    ) -> Result<SocketModeConnection<ProductionSocketModeSocket>, SocketModeFailure> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(SocketModeFailure::TimedOut)?;
        let addresses = resolve_addresses(url.host(), remaining(deadline)?)?;
        let stream = connect_addresses(&addresses, deadline)?;
        let handshake_timeout = remaining(deadline)?;
        stream
            .set_read_timeout(Some(handshake_timeout))
            .map_err(|_| SocketModeFailure::Unavailable)?;
        stream
            .set_write_timeout(Some(handshake_timeout))
            .map_err(|_| SocketModeFailure::Unavailable)?;
        stream
            .set_nodelay(true)
            .map_err(|_| SocketModeFailure::Unavailable)?;

        let result = url.with_url(|exact| {
            tungstenite::client_tls_with_config(exact, stream, Some(websocket_config()), None)
        });
        let (socket, _) = result.map_err(map_handshake_error)?;
        Ok(SocketModeConnection::with_timeout(
            ProductionSocketModeSocket { socket },
            self.timeout,
        ))
    }
}

fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(4 * 1024)
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_SOCKET_MODE_ENVELOPE_BYTES + 1)
        .max_message_size(Some(MAX_SOCKET_MODE_ENVELOPE_BYTES))
        .max_frame_size(Some(MAX_SOCKET_MODE_ENVELOPE_BYTES))
        .accept_unmasked_frames(false)
}

fn resolve_addresses(host: &str, timeout: Duration) -> Result<Vec<SocketAddr>, SocketModeFailure> {
    let host = host.to_owned();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name(String::from("automonique-slack-dns"))
        .spawn(move || {
            let resolved = (host.as_str(), 443)
                .to_socket_addrs()
                .map(|addresses| addresses.collect::<Vec<_>>());
            let _ = sender.send(resolved);
        })
        .map_err(|_| SocketModeFailure::Unavailable)?;
    match receiver.recv_timeout(timeout) {
        Ok(Ok(addresses)) if !addresses.is_empty() => Ok(addresses),
        Ok(Ok(_) | Err(_)) => Err(SocketModeFailure::Unavailable),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(SocketModeFailure::TimedOut),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(SocketModeFailure::Unavailable),
    }
}

fn connect_addresses(
    addresses: &[SocketAddr],
    deadline: Instant,
) -> Result<TcpStream, SocketModeFailure> {
    let mut last_was_timeout = false;
    for address in addresses {
        let timeout = remaining(deadline)?;
        match TcpStream::connect_timeout(address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                last_was_timeout = matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                );
            }
        }
    }
    if last_was_timeout {
        Err(SocketModeFailure::TimedOut)
    } else {
        Err(SocketModeFailure::Unavailable)
    }
}

fn remaining(deadline: Instant) -> Result<Duration, SocketModeFailure> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(SocketModeFailure::TimedOut)
}

fn set_stream_timeout(
    stream: &mut MaybeTlsStream<TcpStream>,
    timeout: Duration,
) -> Result<(), SocketIoFailure> {
    let tcp = match stream {
        MaybeTlsStream::Plain(tcp) => tcp,
        MaybeTlsStream::Rustls(tls) => &mut tls.sock,
        _ => return Err(SocketIoFailure::Unavailable),
    };
    tcp.set_read_timeout(Some(timeout))
        .and_then(|()| tcp.set_write_timeout(Some(timeout)))
        .map_err(|_| SocketIoFailure::Unavailable)
}

fn message_to_frame(message: Message) -> Result<SocketFrame, SocketIoFailure> {
    match message {
        Message::Text(text) => Ok(SocketFrame::Text(text.as_str().as_bytes().to_vec())),
        Message::Binary(bytes) => Ok(SocketFrame::Binary(bytes.to_vec())),
        Message::Ping(bytes) => Ok(SocketFrame::Ping(bytes.to_vec())),
        Message::Pong(bytes) => Ok(SocketFrame::Pong(bytes.to_vec())),
        Message::Close(None) => Ok(SocketFrame::Close(Vec::new())),
        Message::Close(Some(close)) => {
            let mut payload = Vec::with_capacity(close.reason.len() + 2);
            payload.extend_from_slice(&u16::from(close.code).to_be_bytes());
            payload.extend_from_slice(close.reason.as_str().as_bytes());
            Ok(SocketFrame::Close(payload))
        }
        Message::Frame(_) => Err(SocketIoFailure::Protocol),
    }
}

fn frame_to_message(frame: SocketFrame) -> Result<Message, SocketIoFailure> {
    match frame {
        SocketFrame::Text(bytes) => String::from_utf8(bytes)
            .map(Message::text)
            .map_err(|_| SocketIoFailure::Protocol),
        SocketFrame::Binary(bytes) => Ok(Message::binary(bytes)),
        SocketFrame::Ping(bytes) => Ok(Message::Ping(bytes.into())),
        SocketFrame::Pong(bytes) => Ok(Message::Pong(bytes.into())),
        SocketFrame::Close(bytes) => close_message(&bytes),
    }
}

fn close_message(payload: &[u8]) -> Result<Message, SocketIoFailure> {
    validate_close_payload(payload).map_err(|_| SocketIoFailure::Protocol)?;
    if payload.is_empty() {
        return Ok(Message::Close(None));
    }
    let code = CloseCode::from(u16::from_be_bytes([payload[0], payload[1]]));
    let reason = std::str::from_utf8(&payload[2..]).map_err(|_| SocketIoFailure::Protocol)?;
    Ok(Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    })))
}

fn map_handshake_error(
    error: HandshakeError<ClientHandshake<MaybeTlsStream<TcpStream>>>,
) -> SocketModeFailure {
    match error {
        HandshakeError::Failure(error) => map_tungstenite_failure(error),
        HandshakeError::Interrupted(_) => SocketModeFailure::Unavailable,
    }
}

fn map_tungstenite_failure(error: tungstenite::Error) -> SocketModeFailure {
    match error {
        tungstenite::Error::Io(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            SocketModeFailure::TimedOut
        }
        tungstenite::Error::Http(response) if response.status().is_redirection() => {
            SocketModeFailure::Redirected
        }
        tungstenite::Error::Url(_) => SocketModeFailure::UrlRejected,
        tungstenite::Error::Capacity(_) => SocketModeFailure::EnvelopeTooLarge,
        tungstenite::Error::Utf8(_) => SocketModeFailure::InvalidText,
        tungstenite::Error::Protocol(_) => SocketModeFailure::MalformedControl,
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => {
            SocketModeFailure::Closed
        }
        _ => SocketModeFailure::Unavailable,
    }
}

fn map_tungstenite_io(error: tungstenite::Error) -> SocketIoFailure {
    match map_tungstenite_failure(error) {
        SocketModeFailure::TimedOut => SocketIoFailure::TimedOut,
        SocketModeFailure::MalformedControl
        | SocketModeFailure::EnvelopeTooLarge
        | SocketModeFailure::InvalidText => SocketIoFailure::Protocol,
        _ => SocketIoFailure::Unavailable,
    }
}

fn envelope(bytes: Vec<u8>) -> Result<SocketModeEnvelope, SocketModeFailure> {
    if bytes.is_empty() {
        return Err(SocketModeFailure::InvalidText);
    }
    if bytes.len() > MAX_SOCKET_MODE_ENVELOPE_BYTES {
        return Err(SocketModeFailure::EnvelopeTooLarge);
    }
    String::from_utf8(bytes)
        .map(SocketModeEnvelope)
        .map_err(|_| SocketModeFailure::InvalidText)
}

fn validate_control_payload(payload: &[u8]) -> Result<(), SocketModeFailure> {
    if payload.len() > MAX_CONTROL_PAYLOAD_BYTES {
        return Err(SocketModeFailure::MalformedControl);
    }
    Ok(())
}

fn validate_close_payload(payload: &[u8]) -> Result<(), SocketModeFailure> {
    validate_control_payload(payload)?;
    if payload.len() == 1 {
        return Err(SocketModeFailure::MalformedControl);
    }
    if payload.len() >= 2 {
        let code = u16::from_be_bytes([payload[0], payload[1]]);
        if !valid_close_code(code) || std::str::from_utf8(&payload[2..]).is_err() {
            return Err(SocketModeFailure::MalformedControl);
        }
    }
    Ok(())
}

fn valid_close_code(code: u16) -> bool {
    matches!(code, 1000 | 1001 | 1002 | 1003 | 1007..=1014) || (3000..=4999).contains(&code)
}

const fn map_io_failure(failure: SocketIoFailure) -> SocketModeFailure {
    match failure {
        SocketIoFailure::TimedOut => SocketModeFailure::TimedOut,
        SocketIoFailure::Protocol => SocketModeFailure::MalformedControl,
        SocketIoFailure::Unavailable => SocketModeFailure::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    #[derive(Default)]
    struct FakeSocket {
        received: VecDeque<Result<SocketFrame, SocketIoFailure>>,
        sent: Vec<(SocketFrame, Duration)>,
    }

    impl SynchronousWebSocket for FakeSocket {
        fn receive(&mut self, _timeout: Duration) -> Result<SocketFrame, SocketIoFailure> {
            self.received
                .pop_front()
                .unwrap_or(Err(SocketIoFailure::Unavailable))
        }

        fn send(&mut self, frame: SocketFrame, timeout: Duration) -> Result<(), SocketIoFailure> {
            self.sent.push((frame, timeout));
            Ok(())
        }
    }

    fn socket(frames: impl IntoIterator<Item = SocketFrame>) -> SocketModeConnection<FakeSocket> {
        SocketModeConnection::with_timeout(
            FakeSocket {
                received: frames.into_iter().map(Ok).collect(),
                sent: Vec::new(),
            },
            Duration::from_millis(250),
        )
    }

    fn concrete_pair() -> (
        SocketModeConnection<ProductionSocketModeSocket>,
        WebSocket<TcpStream>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("server read timeout");
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .expect("server write timeout");
            tungstenite::accept_with_config(stream, Some(websocket_config()))
                .expect("server handshake")
        });
        let stream = TcpStream::connect(address).expect("connect loopback");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("client read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("client write timeout");
        let request = format!("ws://{address}/fixture");
        let (client, _) = tungstenite::client::client_with_config(
            request,
            MaybeTlsStream::Plain(stream),
            Some(websocket_config()),
        )
        .expect("client handshake");
        let server = server.join().expect("server thread");
        (
            SocketModeConnection::with_timeout(
                ProductionSocketModeSocket { socket: client },
                Duration::from_millis(500),
            ),
            server,
        )
    }

    #[test]
    fn only_a_slack_production_wss_ticket_is_admitted_and_it_is_redacted() {
        let exact = "wss://wss-primary.slack.com/link/?ticket=fixture-secret&app_id=A1";
        let url = SlackSocketUrl::new(exact).expect("socket URL");
        assert_eq!(url.host(), "wss-primary.slack.com");
        url.with_url(|value| assert_eq!(value, exact));
        let rendered = format!("{url:?}");
        assert!(!rendered.contains("fixture-secret"), "{rendered}");
        assert!(rendered.contains("<redacted>"));

        for refused in [
            "http://wss.slack.com/link/?ticket=x",
            "ws://wss.slack.com/link/?ticket=x",
            "wss://evil.invalid/link/?ticket=x",
            "wss://wss.slack.com.evil.invalid/link/?ticket=x",
            "wss://slack.com/link/?ticket=x",
            "wss://user@wss.slack.com/link/?ticket=x",
            "wss://wss.slack.com:443/link/?ticket=x",
            "wss://wss.slack.com/other/?ticket=x",
            "wss://wss.slack.com/link/",
            "wss://wss.slack.com/link/?ticket=",
            "wss://wss.slack.com/link/?app_id=A1",
            "wss://wss.slack.com/link/?ticket=x#fragment",
        ] {
            assert_eq!(
                SlackSocketUrl::new(refused).err(),
                Some(SocketModeFailure::UrlRejected),
                "{refused}"
            );
        }
    }

    #[test]
    fn text_is_received_byte_exactly_after_a_ping_is_answered() {
        let mut connection = socket([
            SocketFrame::Ping(b"probe".to_vec()),
            SocketFrame::Text(br#"{"type":"hello"}"#.to_vec()),
        ]);
        let envelope = connection.receive_envelope().expect("envelope");
        assert_eq!(envelope.as_bytes(), br#"{"type":"hello"}"#);
        assert!(!format!("{envelope:?}").contains("hello"));
        let inner = connection.into_inner();
        assert_eq!(
            inner.sent,
            vec![(
                SocketFrame::Pong(b"probe".to_vec()),
                Duration::from_millis(250)
            )]
        );
    }

    #[test]
    fn acknowledgement_has_one_exact_json_spelling() {
        let acknowledgement =
            SocketModeAcknowledgement::new("E1\"quoted").expect("bounded acknowledgement");
        assert_eq!(
            acknowledgement.as_bytes(),
            br#"{"envelope_id":"E1\"quoted"}"#
        );
        assert!(!format!("{acknowledgement:?}").contains("quoted"));

        let mut connection = socket([]);
        connection.acknowledge("E1").expect("ack sent");
        let inner = connection.into_inner();
        assert_eq!(
            inner.sent,
            vec![(
                SocketFrame::Text(br#"{"envelope_id":"E1"}"#.to_vec()),
                Duration::from_millis(250)
            )]
        );
    }

    #[test]
    fn binary_oversized_invalid_text_and_bad_ack_are_refused() {
        assert_eq!(
            socket([SocketFrame::Binary(vec![1])])
                .receive_envelope()
                .err(),
            Some(SocketModeFailure::BinaryFrame)
        );
        assert_eq!(
            socket([SocketFrame::Text(vec![
                b'x';
                MAX_SOCKET_MODE_ENVELOPE_BYTES + 1
            ])])
            .receive_envelope()
            .err(),
            Some(SocketModeFailure::EnvelopeTooLarge)
        );
        assert_eq!(
            socket([SocketFrame::Text(vec![0xff])])
                .receive_envelope()
                .err(),
            Some(SocketModeFailure::InvalidText)
        );
        for invalid in ["", "E:1", "with space", "line\nbreak"] {
            assert_eq!(
                SocketModeAcknowledgement::new(invalid).err(),
                Some(SocketModeFailure::InvalidAcknowledgement)
            );
        }
    }

    #[test]
    fn malformed_controls_and_adapter_timeouts_fail_closed() {
        assert_eq!(
            socket([SocketFrame::Ping(vec![0; 126])])
                .receive_envelope()
                .err(),
            Some(SocketModeFailure::MalformedControl)
        );
        assert_eq!(
            socket([SocketFrame::Close(vec![0])])
                .receive_envelope()
                .err(),
            Some(SocketModeFailure::MalformedControl)
        );
        assert_eq!(
            socket([SocketFrame::Close(vec![0x03, 0xed])])
                .receive_envelope()
                .err(),
            Some(SocketModeFailure::MalformedControl)
        );
        let mut connection = SocketModeConnection::new(FakeSocket {
            received: [Err(SocketIoFailure::TimedOut)].into_iter().collect(),
            sent: Vec::new(),
        });
        assert_eq!(
            connection.receive_envelope().err(),
            Some(SocketModeFailure::TimedOut)
        );
    }

    #[test]
    fn timeout_is_clamped_and_zero_means_the_ceiling() {
        let ceiling = Duration::from_secs(SOCKET_MODE_IO_TIMEOUT_SECONDS);
        assert_eq!(
            SocketModeConnection::with_timeout(FakeSocket::default(), Duration::ZERO).timeout(),
            ceiling
        );
        assert_eq!(
            SocketModeConnection::with_timeout(FakeSocket::default(), Duration::from_secs(60))
                .timeout(),
            ceiling
        );
        assert_eq!(
            SlackSocketModeConnector::with_timeout(Duration::ZERO).timeout(),
            ceiling
        );
        assert_eq!(
            SlackSocketModeConnector::with_timeout(Duration::from_secs(60)).timeout(),
            ceiling
        );
    }

    #[test]
    fn concrete_adapter_round_trips_text_ping_and_exact_ack_on_loopback() {
        let (mut connection, mut server) = concrete_pair();
        server
            .send(Message::Ping(b"probe".to_vec().into()))
            .expect("send ping");
        server
            .send(Message::text(r#"{"type":"events_api"}"#))
            .expect("send envelope");

        let envelope = connection.receive_envelope().expect("receive envelope");
        assert_eq!(envelope.as_str(), r#"{"type":"events_api"}"#);
        let pong = server.read().expect("read pong");
        assert_eq!(pong, Message::Pong(b"probe".to_vec().into()));

        connection.acknowledge("E1").expect("send acknowledgement");
        let acknowledgement = server.read().expect("read acknowledgement");
        assert_eq!(acknowledgement, Message::text(r#"{"envelope_id":"E1"}"#));
        assert!(!format!("{:?}", connection.into_inner()).contains("ticket="));
    }

    #[test]
    fn concrete_adapter_preserves_binary_rejection_and_timeout_mapping() {
        let (mut connection, mut server) = concrete_pair();
        server
            .send(Message::binary(vec![0_u8, 1, 2]))
            .expect("send binary");
        assert_eq!(
            connection.receive_envelope().err(),
            Some(SocketModeFailure::BinaryFrame)
        );

        let timeout = std::io::Error::new(std::io::ErrorKind::TimedOut, "fixture");
        assert_eq!(
            map_tungstenite_io(tungstenite::Error::Io(timeout)),
            SocketIoFailure::TimedOut
        );
    }

    #[test]
    fn websocket_redirects_are_named_and_never_followed() {
        let response = tungstenite::http::Response::builder()
            .status(302)
            .body(None)
            .expect("response");
        assert_eq!(
            map_tungstenite_failure(tungstenite::Error::Http(Box::new(response))),
            SocketModeFailure::Redirected
        );
    }
}
