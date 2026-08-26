// SPDX-License-Identifier: Elastic-2.0

//! The one route through this crate that reads a request instead of tunnelling
//! it: the identity-bound provider endpoint.
//!
//! # Why this parser exists when [`crate::request`] refuses to have one
//!
//! The `CONNECT` proxy is deliberately blind, and its module says so: a proxy
//! that also forwarded origin-form requests would own a second HTTP parser
//! whose disagreement with the destination's parser is what request smuggling
//! is made of. That argument is still correct, and this module does not
//! contradict it — it accepts the cost knowingly, for one endpoint, because the
//! alternative is worse.
//!
//! The alternative is a workload holding the real provider credential. A
//! credential inside the sandbox is a credential an injected instruction can
//! spend, and it can be spent against the *allowlisted* provider host, which no
//! destination policy can distinguish from legitimate traffic. Taking the
//! credential out of the sandbox means something outside it must put the
//! credential back in, and that means something outside it must read the
//! request head. There is no version of identity-bound egress that stays blind.
//!
//! What keeps the cost bounded is that this parser forwards **nothing it did
//! not itself construct**. The head that goes upstream is rebuilt field by
//! field from parsed values: a method that is a bare uppercase token, a target
//! this module re-serialises, a `Host` the broker derives from its own
//! destination, and a credential the broker holds. Everything ambiguous is
//! refused rather than repaired — the same rule the `CONNECT` parser follows —
//! so there is no shape this forwarder passes on that it could not name.
//!
//! # The response is not parsed at all
//!
//! Once the request is upstream, every byte coming back is copied to the client
//! verbatim through a fixed buffer, with no framing interpretation and no
//! accumulation. A server-sent-event stream, a chunked body and a plain
//! `Content-Length` body are all the same thing here: bytes, in order, as they
//! arrive. That is what keeps a streaming model response streaming, and it also
//! means the response direction adds no parser to disagree with anyone.
//!
//! # TLS terminates here, and only here
//!
//! Requests forwarded to a public destination leave over rustls, verified
//! against the webpki root set. This is not a man in the middle: the workload
//! never established a TLS session to intercept — it spoke plain HTTP to a
//! loopback port that belongs to the supervisor, exactly as configured, and the
//! supervisor made its own session to the provider. No certificate authority is
//! minted, no certificate is forged, and nothing the workload trusts is
//! altered. A loopback destination is forwarded in the clear, because it never
//! leaves the host.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::allowlist::{Destination, DestinationHost};
use crate::identity::{IdentityRefusal, ProviderIdentity, SessionSentinel};
use crate::request::{HEAD_TERMINATOR, find, strip_cr};

/// Upper bound on the request head, terminator excluded.
pub const MAX_PROVIDER_HEAD_BYTES: usize = 16 * 1024;

/// Upper bound on header lines after the request line.
pub const MAX_PROVIDER_HEADER_LINES: usize = 64;

/// Upper bound on one forwarded request body.
///
/// A provider request carries a conversation, so this is generous; it is a
/// ceiling on supervisor memory rather than a policy on what a workload may
/// say. The *response* has no such ceiling, because it is streamed and never
/// held.
pub const MAX_PROVIDER_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Size of the response passthrough buffer. One allocation per request.
pub const RESPONSE_BUFFER_BYTES: usize = 16 * 1024;

/// Size of one read while the head is being collected.
const READ_CHUNK_BYTES: usize = 1024;

/// Header names this forwarder never carries through from the client.
///
/// Two groups. The hop-by-hop names describe the client's connection to the
/// broker and would be lies about the broker's connection to the provider. The
/// credential names are dropped **unconditionally**, including the one the
/// sentinel arrived in and the one it did not: the request that leaves this
/// host carries exactly one credential, the substituted one, and no header the
/// workload chose can sit beside it.
const DROPPED_REQUEST_HEADERS: [&str; 12] = [
    "authorization",
    "connection",
    "expect",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
    "x-api-key",
];

/// One parsed origin-form request head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

impl ProviderRequest {
    /// Parse a complete request head (the bytes before the terminating
    /// `CRLFCRLF`).
    ///
    /// # Errors
    ///
    /// Returns the [`IdentityRefusal`] naming what was wrong. Nothing is
    /// repaired: a head this rejects is a head two parsers could read
    /// differently.
    pub fn parse(head: &[u8]) -> Result<Self, IdentityRefusal> {
        if head.len() > MAX_PROVIDER_HEAD_BYTES {
            return Err(IdentityRefusal::HeadTooLarge);
        }
        reject_stray_newlines(head)?;
        let mut lines = head.split(|&byte| byte == b'\n');
        let request_line = strip_cr(lines.next().ok_or(IdentityRefusal::HeadMalformed)?);
        let (method, target) = parse_request_line(request_line)?;

        let mut headers = Vec::new();
        for line in lines {
            let line = strip_cr(line);
            if line.is_empty() {
                return Err(IdentityRefusal::HeadMalformed);
            }
            if headers.len() == MAX_PROVIDER_HEADER_LINES {
                return Err(IdentityRefusal::HeadTooLarge);
            }
            headers.push(parse_header(line)?);
        }
        Ok(Self {
            method,
            target,
            headers,
        })
    }

    /// The request method, an uppercase token.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The origin-form target, beginning with `/`.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Every value sent under `name`, which must already be lowercase.
    fn values(&self, name: &str) -> impl Iterator<Item = &str> {
        self.headers
            .iter()
            .filter(move |(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    }

    /// Check that this request carries `sentinel` and nothing else that could
    /// be a credential.
    ///
    /// Both accepted spellings are searched, because which one a provider
    /// client uses is the client's business. Finding two is refused rather than
    /// resolved: if a request carries both an `x-api-key` and an
    /// `Authorization`, one of them was not issued by this broker, and picking
    /// a winner would be picking which foreign credential to ignore.
    ///
    /// # Errors
    ///
    /// [`IdentityRefusal::MissingCredential`],
    /// [`IdentityRefusal::AmbiguousCredential`] or
    /// [`IdentityRefusal::ForeignCredential`]. Every one of them is returned
    /// before the caller resolves or dials anything.
    pub fn authenticate(&self, sentinel: &SessionSentinel) -> Result<(), IdentityRefusal> {
        let mut presented: Option<&str> = None;
        let mut count = 0usize;
        for value in self.values("x-api-key") {
            count += 1;
            presented = Some(value);
        }
        for value in self.values("authorization") {
            count += 1;
            // A non-bearer `Authorization` is still a credential, and still not
            // ours. Keeping it as a candidate makes it a foreign credential
            // rather than an unparsed header that quietly disappears.
            presented = Some(value.strip_prefix("Bearer ").unwrap_or(value));
        }
        match (count, presented) {
            (0, _) => Err(IdentityRefusal::MissingCredential),
            (1, Some(value)) if sentinel.matches(value.as_bytes()) => Ok(()),
            (1, _) => Err(IdentityRefusal::ForeignCredential),
            _ => Err(IdentityRefusal::AmbiguousCredential),
        }
    }

    /// How many body bytes follow this head.
    ///
    /// # Errors
    ///
    /// [`IdentityRefusal::RequestFramingRejected`] for a repeated, malformed or
    /// over-large `Content-Length`, and for any `Transfer-Encoding`. Chunked
    /// request bodies are refused rather than re-framed: the broker would have
    /// to become a chunked-encoding parser to forward one safely, and no
    /// provider request needs to be sent that way.
    pub fn body_length(&self) -> Result<usize, IdentityRefusal> {
        if self.values("transfer-encoding").next().is_some() {
            return Err(IdentityRefusal::RequestFramingRejected);
        }
        let mut lengths = self.values("content-length");
        let Some(value) = lengths.next() else {
            return Ok(0);
        };
        if lengths.next().is_some() {
            return Err(IdentityRefusal::RequestFramingRejected);
        }
        let length: usize = value
            .parse()
            .map_err(|_| IdentityRefusal::RequestFramingRejected)?;
        if length > MAX_PROVIDER_BODY_BYTES {
            return Err(IdentityRefusal::RequestFramingRejected);
        }
        Ok(length)
    }

    /// Rebuild the head that goes upstream, substituting the credential.
    ///
    /// Every byte here is either a parsed token, a constant, or a value the
    /// broker owns. Nothing is spliced through untouched but the surviving
    /// header lines, and those were each validated as `name: value` with no
    /// control bytes.
    #[must_use]
    pub(crate) fn upstream_head(&self, identity: &ProviderIdentity) -> Vec<u8> {
        let destination = identity.upstream();
        let mut head = format!("{} {} HTTP/1.1\r\n", self.method, self.target);
        head.push_str(&format!("host: {}\r\n", host_header(destination)));
        head.push_str(&identity.credential().header_line());
        head.push_str("\r\n");
        // One request per connection. It removes reuse across identities, makes
        // the response's end unambiguous without parsing its framing, and
        // leaves nothing pipelined behind a request that was refused.
        head.push_str("connection: close\r\n");
        for (name, value) in &self.headers {
            if DROPPED_REQUEST_HEADERS.contains(&name.as_str()) {
                continue;
            }
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        head.into_bytes()
    }
}

/// A request head, plus any body bytes that arrived with it.
#[derive(Clone, Debug)]
pub struct HeadRead {
    /// The parsed request.
    pub request: ProviderRequest,
    /// Body bytes the client sent in the same read as the head.
    pub early_body: Vec<u8>,
}

/// Read one request head from `client`, bounded in both bytes and time.
///
/// # Errors
///
/// The [`IdentityRefusal`] naming why no head was obtained.
pub fn read_head(client: &TcpStream, deadline: Duration) -> Result<HeadRead, IdentityRefusal> {
    client
        .set_read_timeout(Some(deadline))
        .map_err(|_| IdentityRefusal::ClientUnreadable)?;
    let mut buffer = Vec::with_capacity(READ_CHUNK_BYTES);
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    loop {
        if let Some(index) = find(&buffer, HEAD_TERMINATOR) {
            let request = ProviderRequest::parse(&buffer[..index])?;
            return Ok(HeadRead {
                request,
                early_body: buffer[index + HEAD_TERMINATOR.len()..].to_vec(),
            });
        }
        if buffer.len() > MAX_PROVIDER_HEAD_BYTES {
            return Err(IdentityRefusal::HeadTooLarge);
        }
        let mut source = client;
        let read = source
            .read(&mut chunk)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                    IdentityRefusal::HeadTimedOut
                }
                _ => IdentityRefusal::ClientUnreadable,
            })?;
        if read == 0 {
            return Err(IdentityRefusal::HeadMalformed);
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

/// Read exactly `length` body bytes, counting those that arrived with the head.
///
/// # Errors
///
/// [`IdentityRefusal::RequestFramingRejected`] if the client framed more bytes
/// than it sent, or sent more than it framed; [`IdentityRefusal::HeadTimedOut`]
/// or [`IdentityRefusal::ClientUnreadable`] if the read did not complete.
pub fn read_body(
    client: &TcpStream,
    early: Vec<u8>,
    length: usize,
    deadline: Duration,
) -> Result<Vec<u8>, IdentityRefusal> {
    if early.len() > length {
        // More body than the request framed. Refused rather than truncated:
        // the surplus is exactly the shape a smuggled second request takes.
        return Err(IdentityRefusal::RequestFramingRejected);
    }
    let mut body = early;
    if body.len() == length {
        return Ok(body);
    }
    client
        .set_read_timeout(Some(deadline))
        .map_err(|_| IdentityRefusal::ClientUnreadable)?;
    let mut source = client;
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    while body.len() < length {
        let want = (length - body.len()).min(READ_CHUNK_BYTES);
        let read = source
            .read(&mut chunk[..want])
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                    IdentityRefusal::HeadTimedOut
                }
                _ => IdentityRefusal::ClientUnreadable,
            })?;
        if read == 0 {
            return Err(IdentityRefusal::RequestFramingRejected);
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(body)
}

/// An established connection to the provider.
///
/// Public destinations are wrapped in TLS; loopback destinations are not,
/// because a loopback session never leaves the host and demanding a
/// certificate for one would only mean minting certificates.
pub enum Upstream {
    /// A cleartext session to a loopback destination.
    Plain(TcpStream),
    /// A TLS session, terminated in this process.
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Upstream {
    /// Wrap a connected socket according to the destination's scope.
    ///
    /// # Errors
    ///
    /// [`IdentityRefusal::UpstreamTlsRefused`] if the destination's name is not
    /// a valid TLS server name or the handshake could not be started.
    pub fn establish(
        socket: TcpStream,
        destination: &Destination,
        idle: Duration,
    ) -> Result<Self, IdentityRefusal> {
        socket
            .set_read_timeout(Some(idle))
            .map_err(|_| IdentityRefusal::UpstreamUnreachable)?;
        socket
            .set_write_timeout(Some(idle))
            .map_err(|_| IdentityRefusal::UpstreamUnreachable)?;
        if !destination.scope().requires_transport_security() {
            return Ok(Self::Plain(socket));
        }
        let name = match destination.host() {
            DestinationHost::Name(name) => name.clone(),
            DestinationHost::Address(address) => address.to_string(),
        };
        let server_name = rustls::pki_types::ServerName::try_from(name)
            .map_err(|_| IdentityRefusal::UpstreamTlsRefused)?;
        let connection = rustls::ClientConnection::new(client_config(), server_name)
            .map_err(|_| IdentityRefusal::UpstreamTlsRefused)?;
        Ok(Self::Tls(Box::new(rustls::StreamOwned::new(
            connection, socket,
        ))))
    }

    /// The socket underneath, for a shutdown that has to reach it.
    #[must_use]
    pub fn socket(&self) -> &TcpStream {
        match self {
            Self::Plain(socket) => socket,
            Self::Tls(stream) => stream.get_ref(),
        }
    }
}

impl Read for Upstream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(socket) => socket.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for Upstream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(socket) => socket.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(socket) => socket.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

/// Copy the response to the client as it arrives, and report how much moved.
///
/// No framing is interpreted and nothing is accumulated: one fixed buffer,
/// written on and flushed after every read, so a server-sent-event stream
/// reaches the workload event by event rather than at the end. The upstream's
/// idle deadline bounds a stall; the client's write deadline bounds a workload
/// that stops reading.
pub fn stream_response(upstream: &mut Upstream, client: &TcpStream) -> std::io::Result<u64> {
    let mut buffer = [0u8; RESPONSE_BUFFER_BYTES];
    let mut moved = 0u64;
    let mut sink = client;
    loop {
        let read = match upstream.read(&mut buffer) {
            Ok(0) => return Ok(moved),
            Ok(read) => read,
            // A provider that closes a TLS session without a `close_notify` is
            // common enough that treating it as a failure would truncate real
            // responses; the bytes already delivered are still delivered.
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(moved),
            Err(error) => return Err(error),
        };
        sink.write_all(&buffer[..read])?;
        sink.flush()?;
        moved += read as u64;
    }
}

/// The `Host` value for a destination, omitting the port when it is the
/// scheme's default.
fn host_header(destination: &Destination) -> String {
    let host = match destination.host() {
        DestinationHost::Name(name) => name.clone(),
        DestinationHost::Address(address) if address.is_ipv6() => format!("[{address}]"),
        DestinationHost::Address(address) => address.to_string(),
    };
    let default_port = if destination.scope().requires_transport_security() {
        443
    } else {
        80
    };
    if destination.port() == default_port {
        host
    } else {
        format!("{host}:{}", destination.port())
    }
}

/// Parse `METHOD /target HTTP/1.1`, exactly.
fn parse_request_line(line: &[u8]) -> Result<(String, String), IdentityRefusal> {
    let mut tokens = line.split(|&byte| byte == b' ');
    let method = tokens.next().ok_or(IdentityRefusal::HeadMalformed)?;
    let target = tokens.next().ok_or(IdentityRefusal::HeadMalformed)?;
    let version = tokens.next().ok_or(IdentityRefusal::HeadMalformed)?;
    if tokens.next().is_some() {
        return Err(IdentityRefusal::HeadMalformed);
    }
    if method.is_empty() || target.is_empty() || version.is_empty() {
        return Err(IdentityRefusal::HeadMalformed);
    }
    if version != b"HTTP/1.1" {
        return Err(IdentityRefusal::VersionUnsupported);
    }
    // A bare uppercase token, and never `CONNECT`: this listener is an origin,
    // and an origin that honoured `CONNECT` would be the tunnel the identity
    // binding exists to remove.
    if method == b"CONNECT" || !method.iter().all(u8::is_ascii_uppercase) {
        return Err(IdentityRefusal::MethodRejected);
    }
    // Origin-form only. An absolute-form target would make this a proxy, and a
    // proxy is reachable at hosts the broker never chose.
    if target.first() != Some(&b'/') || !target.iter().all(|byte| byte.is_ascii_graphic()) {
        return Err(IdentityRefusal::TargetRejected);
    }
    Ok((
        String::from_utf8(method.to_vec()).map_err(|_| IdentityRefusal::MethodRejected)?,
        String::from_utf8(target.to_vec()).map_err(|_| IdentityRefusal::TargetRejected)?,
    ))
}

/// Parse one header line into a lowercase name and a trimmed value.
fn parse_header(line: &[u8]) -> Result<(String, String), IdentityRefusal> {
    if line
        .first()
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        // An obs-fold continuation. Refused rather than joined, because joining
        // is a guess about what the destination's parser would have done.
        return Err(IdentityRefusal::HeadMalformed);
    }
    let colon = line
        .iter()
        .position(|&byte| byte == b':')
        .ok_or(IdentityRefusal::HeadMalformed)?;
    let (name, value) = line.split_at(colon);
    let value = &value[1..];
    if name.is_empty() || !name.iter().all(|byte| is_token_byte(*byte)) {
        return Err(IdentityRefusal::HeadMalformed);
    }
    let value = trim_optional_whitespace(value);
    if !value
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b' ' || *byte == b'\t')
    {
        return Err(IdentityRefusal::HeadMalformed);
    }
    Ok((
        String::from_utf8(name.to_ascii_lowercase()).map_err(|_| IdentityRefusal::HeadMalformed)?,
        String::from_utf8(value.to_vec()).map_err(|_| IdentityRefusal::HeadMalformed)?,
    ))
}

/// RFC 9110 `tchar`.
const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn trim_optional_whitespace(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| *byte != b' ' && *byte != b'\t')
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| *byte != b' ' && *byte != b'\t')
        .map_or(start, |index| index + 1);
    &value[start..end]
}

/// Refuse a head whose line endings are not uniformly `CRLF`.
fn reject_stray_newlines(head: &[u8]) -> Result<(), IdentityRefusal> {
    for (index, &byte) in head.iter().enumerate() {
        if byte == b'\r' && head.get(index + 1) != Some(&b'\n') {
            return Err(IdentityRefusal::HeadMalformed);
        }
        if byte == b'\n' && (index == 0 || head[index - 1] != b'\r') {
            return Err(IdentityRefusal::HeadMalformed);
        }
    }
    Ok(())
}

/// The shared client configuration, built once.
///
/// Roots come from the compiled-in webpki set rather than the host trust store:
/// the broker runs beside a sandbox whose whole point is that its filesystem
/// view is not the host's, and a root set that cannot be edited at runtime is
/// one fewer thing a compromised host process can widen.
fn client_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }))
}

/// Connect to the first in-scope resolved address that answers.
///
/// Resolution happens once and the dial goes to a *materialized address* from
/// that one resolution, so a name that answers differently on a second lookup
/// cannot move the connection after the scope check has passed.
pub fn dial_in_scope(
    addresses: &[SocketAddr],
    timeout: Duration,
) -> Result<TcpStream, IdentityRefusal> {
    addresses
        .iter()
        .find_map(|address| TcpStream::connect_timeout(address, timeout).ok())
        .ok_or(IdentityRefusal::UpstreamUnreachable)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_PROVIDER_BODY_BYTES, MAX_PROVIDER_HEAD_BYTES, MAX_PROVIDER_HEADER_LINES,
        ProviderRequest, host_header,
    };
    use crate::allowlist::{AddressScope, Destination};
    use crate::identity::{
        CredentialScheme, IdentityRefusal, ProviderCredential, ProviderIdentity, SessionSentinel,
    };

    fn parse(head: &str) -> Result<ProviderRequest, IdentityRefusal> {
        ProviderRequest::parse(head.as_bytes())
    }

    fn identity(sentinel: SessionSentinel) -> ProviderIdentity {
        ProviderIdentity::new(
            Destination::new("api.example.com", 443, AddressScope::Public).unwrap(),
            sentinel,
            ProviderCredential::new(CredentialScheme::ApiKeyHeader, "sk-real-supervisor-key")
                .unwrap(),
        )
    }

    #[test]
    fn an_origin_form_request_parses_into_its_parts() {
        let request = parse("POST /v1/messages HTTP/1.1\r\nX-Api-Key: abc\r\nContent-Length: 3")
            .expect("a well-formed head parses");
        assert_eq!(request.method(), "POST");
        assert_eq!(request.target(), "/v1/messages");
        assert_eq!(request.body_length().unwrap(), 3);
        assert_eq!(request.values("x-api-key").collect::<Vec<_>>(), ["abc"]);
    }

    #[test]
    fn the_listener_is_an_origin_and_not_a_proxy() {
        assert_eq!(
            parse("CONNECT api.example.com:443 HTTP/1.1\r\nHost: x").unwrap_err(),
            IdentityRefusal::MethodRejected
        );
        assert_eq!(
            parse("post /v1/messages HTTP/1.1\r\nHost: x").unwrap_err(),
            IdentityRefusal::MethodRejected
        );
        assert_eq!(
            parse("GET https://elsewhere.example/v1 HTTP/1.1\r\nHost: x").unwrap_err(),
            IdentityRefusal::TargetRejected
        );
        assert_eq!(
            parse("GET /v1/messages HTTP/1.0\r\nHost: x").unwrap_err(),
            IdentityRefusal::VersionUnsupported
        );
    }

    #[test]
    fn an_ambiguous_head_is_refused_rather_than_repaired() {
        for head in [
            "GET  /v1 HTTP/1.1\r\nHost: x",
            "GET /v1 HTTP/1.1 extra\r\nHost: x",
            "GET /v1 HTTP/1.1\r\nHost x",
            "GET /v1 HTTP/1.1\r\n Host: x",
            "GET /v1 HTTP/1.1\r\n\tcontinued: x",
            "GET /v1 HTTP/1.1\r\n: x",
            "GET /v1 HTTP/1.1\nHost: x",
            "GET /v1 HTTP/1.1\r\rHost: x",
            "GET /v1 HTTP/1.1\r\nHo st: x",
        ] {
            let error = parse(head).unwrap_err();
            assert!(
                matches!(
                    error,
                    IdentityRefusal::HeadMalformed | IdentityRefusal::VersionUnsupported
                ),
                "{head:?} produced {error}"
            );
        }
    }

    #[test]
    fn a_head_beyond_its_ceilings_is_refused() {
        let long = format!(
            "GET /v1 HTTP/1.1\r\nX-Pad: {}",
            "p".repeat(MAX_PROVIDER_HEAD_BYTES)
        );
        assert_eq!(parse(&long).unwrap_err(), IdentityRefusal::HeadTooLarge);
        let mut many = String::from("GET /v1 HTTP/1.1");
        for index in 0..=MAX_PROVIDER_HEADER_LINES {
            many.push_str(&format!("\r\nX-Pad-{index}: p"));
        }
        assert_eq!(parse(&many).unwrap_err(), IdentityRefusal::HeadTooLarge);
    }

    #[test]
    fn the_sentinel_is_the_only_credential_that_authenticates() {
        let sentinel = SessionSentinel::generate().unwrap();
        let token = sentinel.token().to_owned();

        let accepted = parse(&format!("POST /v1 HTTP/1.1\r\nX-Api-Key: {token}")).unwrap();
        assert_eq!(accepted.authenticate(&sentinel), Ok(()));
        let bearer = parse(&format!(
            "POST /v1 HTTP/1.1\r\nAuthorization: Bearer {token}"
        ))
        .unwrap();
        assert_eq!(bearer.authenticate(&sentinel), Ok(()));

        for head in [
            "POST /v1 HTTP/1.1\r\nX-Api-Key: sk-ant-attacker",
            "POST /v1 HTTP/1.1\r\nAuthorization: Bearer sk-ant-attacker",
            "POST /v1 HTTP/1.1\r\nAuthorization: Basic c2s6YXR0YWNrZXI=",
        ] {
            assert_eq!(
                parse(head).unwrap().authenticate(&sentinel),
                Err(IdentityRefusal::ForeignCredential),
                "{head:?}"
            );
        }

        assert_eq!(
            parse("POST /v1 HTTP/1.1\r\nContent-Length: 0")
                .unwrap()
                .authenticate(&sentinel),
            Err(IdentityRefusal::MissingCredential)
        );

        // The sentinel present *and* a foreign key beside it is still refused:
        // otherwise the foreign key would be the one that reached upstream.
        for head in [
            format!("POST /v1 HTTP/1.1\r\nX-Api-Key: {token}\r\nAuthorization: Bearer sk-attacker"),
            format!("POST /v1 HTTP/1.1\r\nX-Api-Key: {token}\r\nX-Api-Key: sk-attacker"),
        ] {
            assert_eq!(
                parse(&head).unwrap().authenticate(&sentinel),
                Err(IdentityRefusal::AmbiguousCredential),
                "{head:?}"
            );
        }
    }

    #[test]
    fn a_body_this_forwarder_cannot_frame_is_refused() {
        for head in [
            "POST /v1 HTTP/1.1\r\nTransfer-Encoding: chunked",
            "POST /v1 HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2",
            "POST /v1 HTTP/1.1\r\nContent-Length: nine",
            "POST /v1 HTTP/1.1\r\nContent-Length: -1",
            &format!(
                "POST /v1 HTTP/1.1\r\nContent-Length: {}",
                MAX_PROVIDER_BODY_BYTES + 1
            ),
        ] {
            assert_eq!(
                parse(head).unwrap().body_length(),
                Err(IdentityRefusal::RequestFramingRejected),
                "{head:?}"
            );
        }
        assert_eq!(
            parse("GET /v1 HTTP/1.1\r\nAccept: */*")
                .unwrap()
                .body_length(),
            Ok(0)
        );
    }

    #[test]
    fn the_forwarded_head_carries_the_real_credential_and_nothing_the_client_chose() {
        let sentinel = SessionSentinel::generate().unwrap();
        let token = sentinel.token().to_owned();
        let bound = identity(sentinel);
        let request = parse(&format!(
            "POST /v1/messages HTTP/1.1\r\n\
             Host: 127.0.0.1:9\r\n\
             X-Api-Key: {token}\r\n\
             Connection: keep-alive\r\n\
             Proxy-Authorization: Basic c2s6\r\n\
             Expect: 100-continue\r\n\
             Anthropic-Version: 2023-06-01\r\n\
             Content-Length: 4"
        ))
        .unwrap();
        let head = String::from_utf8(request.upstream_head(&bound)).unwrap();

        assert!(head.starts_with("POST /v1/messages HTTP/1.1\r\n"), "{head}");
        assert!(
            head.contains("\r\nx-api-key: sk-real-supervisor-key\r\n"),
            "{head}"
        );
        assert!(head.contains("host: api.example.com\r\n"), "{head}");
        assert!(head.contains("connection: close\r\n"), "{head}");
        assert!(head.contains("anthropic-version: 2023-06-01\r\n"), "{head}");
        assert!(head.contains("content-length: 4\r\n"), "{head}");
        assert!(head.ends_with("\r\n\r\n"), "{head}");
        // Nothing the workload sent that could authenticate, redirect, or
        // describe the wrong connection survives.
        assert!(
            !head.contains(&token),
            "the sentinel must not leave the host"
        );
        assert!(!head.contains("keep-alive"), "{head}");
        assert!(!head.contains("Proxy-Authorization"), "{head}");
        assert!(!head.contains("proxy-authorization"), "{head}");
        assert!(!head.contains("100-continue"), "{head}");
        assert!(!head.contains("127.0.0.1:9"), "{head}");
        assert_eq!(head.matches("x-api-key").count(), 1, "{head}");
    }

    #[test]
    fn the_host_header_names_the_destination_the_broker_chose() {
        let public = Destination::new("api.example.com", 443, AddressScope::Public).unwrap();
        assert_eq!(host_header(&public), "api.example.com");
        let odd = Destination::new("api.example.com", 8443, AddressScope::Public).unwrap();
        assert_eq!(host_header(&odd), "api.example.com:8443");
        let loopback = Destination::new("127.0.0.1", 80, AddressScope::Loopback).unwrap();
        assert_eq!(host_header(&loopback), "127.0.0.1");
        let loopback = Destination::new("127.0.0.1", 9443, AddressScope::Loopback).unwrap();
        assert_eq!(host_header(&loopback), "127.0.0.1:9443");
    }
}
