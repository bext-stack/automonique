// SPDX-License-Identifier: Elastic-2.0

//! Reading and parsing exactly one HTTP `CONNECT` request head.
//!
//! # `CONNECT` and nothing else
//!
//! This parser accepts one request shape: `CONNECT host:port HTTP/1.1`, with
//! header lines whose values are read past and never interpreted. Every other
//! method is refused, which is a security property rather than a limitation:
//! a proxy that also served origin-form or absolute-form requests would be
//! parsing, rewriting, and forwarding a plaintext HTTP request on the
//! workload's behalf — it would see request bodies, hold credentials in
//! headers, and own a second parser whose disagreement with the destination's
//! parser is what request smuggling is made of. A `CONNECT`-only proxy reads
//! one line, makes one decision, and afterwards moves opaque bytes.
//!
//! # Refusing rather than repairing
//!
//! Everything ambiguous is refused: bare `CR` or bare `LF` inside the head,
//! obs-fold continuation lines, repeated spaces in the request line, a
//! lowercase method, a zero-padded port. Each is a place where two parsers
//! could disagree about what was sent, and this one has no reason to guess: its
//! only client is a workload the operator configured.
//!
//! # Early data is preserved, not dropped
//!
//! A client is entitled to send its first payload bytes immediately after the
//! request head without waiting for the `200`. Those bytes arrive in the same
//! read as the head, so [`read_request`] returns them alongside it and the
//! caller forwards them to the destination first, before relaying. Dropping
//! them would corrupt exactly the clients careful enough to pipeline.

use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

use crate::allowlist::{DestinationError, DestinationHost, parse_host, parse_port};

/// Upper bound on the request head, terminator excluded.
pub const MAX_REQUEST_HEAD_BYTES: usize = 8192;

/// Upper bound on header lines after the request line.
pub const MAX_HEADER_LINES: usize = 64;

/// Size of one read from the client while the head is being collected. Also
/// bounds how much early data can be captured with the head; anything beyond it
/// stays in the socket and is relayed normally, in order.
const READ_CHUNK_BYTES: usize = 1024;

/// The head's terminator: one empty line.
const HEAD_TERMINATOR: &[u8] = b"\r\n\r\n";

/// One parsed `CONNECT` target. Carries no headers, because none are used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectRequest {
    host: DestinationHost,
    port: u16,
}

impl ConnectRequest {
    /// The requested host, parsed and normalized by the same code that parses
    /// allowlist entries — so a match is a match between two identical
    /// normalizations, not between two hopefully-similar strings.
    #[must_use]
    pub fn host(&self) -> &DestinationHost {
        &self.host
    }

    /// The requested port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Parse a complete request head (the bytes before the terminating
    /// `CRLFCRLF`, which the caller has already located).
    pub fn parse(head: &[u8]) -> Result<Self, RequestError> {
        if head.len() > MAX_REQUEST_HEAD_BYTES {
            return Err(RequestError::HeadTooLarge);
        }
        reject_stray_newlines(head)?;
        let mut lines = head.split(|&byte| byte == b'\n');
        let request_line = lines.next().ok_or(RequestError::RequestLineMalformed)?;
        let request_line = strip_cr(request_line);
        let target = parse_request_line(request_line)?;

        let mut header_lines = 0usize;
        for line in lines {
            let line = strip_cr(line);
            if line.is_empty() {
                // Only possible as the head's own final empty line; the
                // terminator was stripped by the caller, so an empty line here
                // means a blank line inside the head.
                return Err(RequestError::HeaderMalformed);
            }
            header_lines += 1;
            if header_lines > MAX_HEADER_LINES {
                return Err(RequestError::TooManyHeaderLines);
            }
            reject_malformed_header(line)?;
        }
        Ok(target)
    }
}

/// Why a request was refused. Every variant closes the connection; none of them
/// leads to a dial.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    /// The head exceeded [`MAX_REQUEST_HEAD_BYTES`] with no terminator.
    HeadTooLarge,
    /// The client closed, or stopped sending, before the head was complete.
    HeadIncomplete,
    /// The client sent nothing within the head deadline.
    HeadTimedOut,
    /// Reading from the client failed.
    ClientUnreadable,
    /// The method was not exactly `CONNECT`. Includes every origin-form and
    /// absolute-form request: this proxy tunnels, it does not forward.
    MethodNotConnect,
    /// The version was not exactly `HTTP/1.1`.
    VersionUnsupported,
    /// The request line was not three space-separated tokens.
    RequestLineMalformed,
    /// The authority was not a well-formed `host:port`.
    AuthorityRejected(DestinationError),
    /// A header line was empty, obs-folded, or had no name-terminating colon.
    HeaderMalformed,
    /// More than [`MAX_HEADER_LINES`] header lines were sent.
    TooManyHeaderLines,
    /// The head contained a bare `CR` or bare `LF`.
    StrayNewline,
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeadTooLarge => write!(
                formatter,
                "the request head exceeds {MAX_REQUEST_HEAD_BYTES} bytes"
            ),
            Self::HeadIncomplete => {
                formatter.write_str("the client closed before the request head was complete")
            }
            Self::HeadTimedOut => {
                formatter.write_str("the client did not send a request head within the deadline")
            }
            Self::ClientUnreadable => formatter.write_str("reading from the client failed"),
            Self::MethodNotConnect => {
                formatter.write_str("the method is not CONNECT; this proxy only tunnels")
            }
            Self::VersionUnsupported => formatter.write_str("the version is not HTTP/1.1"),
            Self::RequestLineMalformed => {
                formatter.write_str("the request line is not three space-separated tokens")
            }
            Self::AuthorityRejected(error) => write!(formatter, "authority rejected: {error}"),
            Self::HeaderMalformed => {
                formatter.write_str("a header line is empty, obs-folded, or has no colon")
            }
            Self::TooManyHeaderLines => {
                write!(formatter, "more than {MAX_HEADER_LINES} header lines")
            }
            Self::StrayNewline => {
                formatter.write_str("the request head contains a bare CR or bare LF")
            }
        }
    }
}

impl std::error::Error for RequestError {}

/// A request head, plus any payload bytes that arrived with it.
#[derive(Clone, Debug)]
pub struct ReadRequest {
    /// The parsed target.
    pub request: ConnectRequest,
    /// Bytes the client sent after the head without waiting for the response.
    /// The caller must write these to the destination before relaying.
    pub early_data: Vec<u8>,
}

/// Read one request head from `client`, bounded in both bytes and time.
///
/// `deadline` is installed as the socket's read timeout, so a client that
/// connects and says nothing costs one thread for that long and no longer. It
/// is a per-read timeout rather than a whole-head timeout, which a client that
/// dribbles one byte per interval could stretch; [`MAX_REQUEST_HEAD_BYTES`] is
/// what bounds that case, and the caller's connection cap is what bounds how
/// many such clients can exist at once.
pub fn read_request(client: &TcpStream, deadline: Duration) -> Result<ReadRequest, RequestError> {
    client
        .set_read_timeout(Some(deadline))
        .map_err(|_| RequestError::ClientUnreadable)?;
    let mut buffer = Vec::with_capacity(READ_CHUNK_BYTES);
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    loop {
        if let Some(index) = find(&buffer, HEAD_TERMINATOR) {
            if index > MAX_REQUEST_HEAD_BYTES {
                return Err(RequestError::HeadTooLarge);
            }
            let request = ConnectRequest::parse(&buffer[..index])?;
            let early_data = buffer[index + HEAD_TERMINATOR.len()..].to_vec();
            return Ok(ReadRequest {
                request,
                early_data,
            });
        }
        if buffer.len() > MAX_REQUEST_HEAD_BYTES {
            return Err(RequestError::HeadTooLarge);
        }
        let mut source = client;
        let read = source
            .read(&mut chunk)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                    RequestError::HeadTimedOut
                }
                _ => RequestError::ClientUnreadable,
            })?;
        if read == 0 {
            return Err(RequestError::HeadIncomplete);
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

/// Parse `CONNECT host:port HTTP/1.1`, exactly.
fn parse_request_line(line: &[u8]) -> Result<ConnectRequest, RequestError> {
    let mut tokens = line.split(|&byte| byte == b' ');
    let method = tokens.next().ok_or(RequestError::RequestLineMalformed)?;
    let authority = tokens.next().ok_or(RequestError::RequestLineMalformed)?;
    let version = tokens.next().ok_or(RequestError::RequestLineMalformed)?;
    if tokens.next().is_some() {
        return Err(RequestError::RequestLineMalformed);
    }
    // An empty token means repeated or leading spaces: two parsers could read
    // that differently, so it is refused rather than collapsed.
    if method.is_empty() || authority.is_empty() || version.is_empty() {
        return Err(RequestError::RequestLineMalformed);
    }
    if method != b"CONNECT" {
        return Err(RequestError::MethodNotConnect);
    }
    if version != b"HTTP/1.1" {
        return Err(RequestError::VersionUnsupported);
    }
    parse_authority(authority)
}

/// Split `host:port` on the port's colon, keeping bracketed IPv6 intact.
fn parse_authority(authority: &[u8]) -> Result<ConnectRequest, RequestError> {
    let authority = std::str::from_utf8(authority)
        .map_err(|_| RequestError::AuthorityRejected(DestinationError::HostNotLdh))?;
    let separator = if authority.starts_with('[') {
        // The port's colon is the one after the closing bracket, never one of
        // the literal's own.
        let close = authority.find(']').ok_or(RequestError::AuthorityRejected(
            DestinationError::BracketedHostNotIpv6,
        ))?;
        authority[close..]
            .find(':')
            .map(|offset| close + offset)
            .ok_or(RequestError::AuthorityRejected(
                DestinationError::PortRejected,
            ))?
    } else {
        // A bare host must carry exactly one colon; a second one means an
        // unbracketed IPv6 literal or a malformed authority, and either way it
        // is not something to guess about.
        let first = authority.find(':').ok_or(RequestError::AuthorityRejected(
            DestinationError::PortRejected,
        ))?;
        if authority[first + 1..].contains(':') {
            return Err(RequestError::AuthorityRejected(
                DestinationError::HostNotLdh,
            ));
        }
        first
    };
    let host = parse_host(&authority[..separator]).map_err(RequestError::AuthorityRejected)?;
    let port = parse_port(&authority[separator + 1..]).map_err(RequestError::AuthorityRejected)?;
    Ok(ConnectRequest { host, port })
}

/// Refuse a head whose line endings are not uniformly `CRLF`.
fn reject_stray_newlines(head: &[u8]) -> Result<(), RequestError> {
    for (index, &byte) in head.iter().enumerate() {
        if byte == b'\r' && head.get(index + 1) != Some(&b'\n') {
            return Err(RequestError::StrayNewline);
        }
        if byte == b'\n' && (index == 0 || head[index - 1] != b'\r') {
            return Err(RequestError::StrayNewline);
        }
    }
    Ok(())
}

/// A header line must have a non-empty name, no whitespace before the colon,
/// and no leading whitespace of its own (which would be an obs-fold).
fn reject_malformed_header(line: &[u8]) -> Result<(), RequestError> {
    if line
        .first()
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        return Err(RequestError::HeaderMalformed);
    }
    let colon = line
        .iter()
        .position(|&byte| byte == b':')
        .ok_or(RequestError::HeaderMalformed)?;
    let name = &line[..colon];
    if name.is_empty() || name.iter().any(|byte| byte.is_ascii_whitespace()) {
        return Err(RequestError::HeaderMalformed);
    }
    Ok(())
}

fn strip_cr(line: &[u8]) -> &[u8] {
    match line.split_last() {
        Some((b'\r', rest)) => rest,
        _ => line,
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::{ConnectRequest, MAX_HEADER_LINES, MAX_REQUEST_HEAD_BYTES, RequestError};
    use crate::allowlist::{DestinationError, DestinationHost};
    use std::net::{IpAddr, Ipv6Addr};

    fn parse(head: &str) -> Result<ConnectRequest, RequestError> {
        ConnectRequest::parse(head.as_bytes())
    }

    #[test]
    fn the_two_request_shapes_codex_actually_sends_are_accepted() {
        // Observed on the wire from the provider under HTTPS_PROXY: the
        // websocket transport sends Host + Proxy-Connection, the HTTPS
        // transport sends Host + user-agent. Both must parse identically.
        let websocket = parse(
            "CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\nProxy-Connection: keep-alive",
        )
        .unwrap();
        let https = parse(
            "CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\nuser-agent: codex_cli_rs",
        )
        .unwrap();
        assert_eq!(websocket, https);
        assert_eq!(
            websocket.host(),
            &DestinationHost::Name("chatgpt.com".to_owned())
        );
        assert_eq!(websocket.port(), 443);
    }

    #[test]
    fn a_request_with_no_headers_at_all_is_accepted() {
        let request = parse("CONNECT chatgpt.com:443 HTTP/1.1").unwrap();
        assert_eq!(request.port(), 443);
    }

    #[test]
    fn a_bracketed_ipv6_authority_splits_on_the_port_colon() {
        let request = parse("CONNECT [::1]:8443 HTTP/1.1").unwrap();
        assert_eq!(
            request.host(),
            &DestinationHost::Address(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(request.port(), 8443);
    }

    #[test]
    fn every_malformed_request_is_refused_with_the_reason_it_was_refused_for() {
        let cases: [(&str, RequestError); 16] = [
            ("", RequestError::RequestLineMalformed),
            ("CONNECT", RequestError::RequestLineMalformed),
            (
                "CONNECT chatgpt.com:443",
                RequestError::RequestLineMalformed,
            ),
            (
                "CONNECT  chatgpt.com:443 HTTP/1.1",
                RequestError::RequestLineMalformed,
            ),
            (
                " CONNECT chatgpt.com:443 HTTP/1.1",
                RequestError::RequestLineMalformed,
            ),
            (
                "CONNECT chatgpt.com:443 HTTP/1.1 extra",
                RequestError::RequestLineMalformed,
            ),
            (
                "connect chatgpt.com:443 HTTP/1.1",
                RequestError::MethodNotConnect,
            ),
            (
                "GET http://chatgpt.com/ HTTP/1.1",
                RequestError::MethodNotConnect,
            ),
            (
                "POST http://chatgpt.com/ HTTP/1.1",
                RequestError::MethodNotConnect,
            ),
            (
                "CONNECT chatgpt.com:443 HTTP/1.0",
                RequestError::VersionUnsupported,
            ),
            (
                "CONNECT chatgpt.com:443 HTTP/2",
                RequestError::VersionUnsupported,
            ),
            (
                "CONNECT chatgpt.com HTTP/1.1",
                RequestError::AuthorityRejected(DestinationError::PortRejected),
            ),
            (
                "CONNECT chatgpt.com:0 HTTP/1.1",
                RequestError::AuthorityRejected(DestinationError::PortRejected),
            ),
            (
                "CONNECT chatgpt.com:99999 HTTP/1.1",
                RequestError::AuthorityRejected(DestinationError::PortRejected),
            ),
            (
                "CONNECT chatgpt.com:0443 HTTP/1.1",
                RequestError::AuthorityRejected(DestinationError::PortRejected),
            ),
            (
                "CONNECT ::1:443 HTTP/1.1",
                RequestError::AuthorityRejected(DestinationError::HostNotLdh),
            ),
        ];
        for (head, expected) in cases {
            assert_eq!(parse(head), Err(expected), "head {head:?}");
        }
    }

    #[test]
    fn header_lines_that_could_be_read_two_ways_are_refused() {
        let base = "CONNECT chatgpt.com:443 HTTP/1.1\r\n";
        for suffix in [
            "Host chatgpt.com",       // no colon
            ": chatgpt.com",          // empty name
            "Ho st: chatgpt.com",     // whitespace in the name
            " Host: chatgpt.com",     // obs-fold continuation
            "\tHost: chatgpt.com",    // obs-fold continuation
            "Host: a\r\n\r\nHost: b", // blank line inside the head
        ] {
            assert_eq!(
                parse(&format!("{base}{suffix}")),
                Err(RequestError::HeaderMalformed),
                "header {suffix:?}"
            );
        }
    }

    #[test]
    fn bare_newlines_are_refused_because_two_parsers_could_disagree_about_them() {
        for head in [
            "CONNECT chatgpt.com:443 HTTP/1.1\nHost: chatgpt.com",
            "CONNECT chatgpt.com:443 HTTP/1.1\rHost: chatgpt.com",
            "CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: a\nHost: b",
        ] {
            assert_eq!(
                parse(head),
                Err(RequestError::StrayNewline),
                "head {head:?}"
            );
        }
    }

    #[test]
    fn the_head_is_bounded_in_both_size_and_line_count() {
        let mut head = String::from("CONNECT chatgpt.com:443 HTTP/1.1");
        for index in 0..=MAX_HEADER_LINES {
            head.push_str("\r\n");
            head.push_str(&format!("X-Pad-{index}: v"));
        }
        assert_eq!(parse(&head), Err(RequestError::TooManyHeaderLines));

        let oversized = format!(
            "CONNECT chatgpt.com:443 HTTP/1.1\r\nX-Pad: {}",
            "v".repeat(MAX_REQUEST_HEAD_BYTES)
        );
        assert_eq!(parse(&oversized), Err(RequestError::HeadTooLarge));
    }
}
