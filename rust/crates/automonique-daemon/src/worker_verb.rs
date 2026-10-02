// SPDX-License-Identifier: Elastic-2.0

//! What the worker's small command-line verbs share.
//!
//! `automonique share` and `automonique purge` are called by a coding agent
//! in the middle of a ticket. Both read one private configuration frame from
//! the state directory, issue exactly one bounded JSON `POST`, and answer
//! with a marker line the agent greps for. This module holds the three
//! pieces they have in common so each verb only spells its own contract:
//!
//! - [`read_private`] and [`frame`]: the strict configuration frame the
//!   other files in the state directory use (private owner-only regular
//!   file, bounded size, exact schema line, exact `end=` line).
//! - [`JsonPost`]: the one seam that opens a socket. [`LivePost`] is the
//!   production implementation; the tests supply a fake, which is what keeps
//!   every test here free of the network.
//! - [`VerbOutcome`]: the lines to print and the exit code, so the whole
//!   verb is a function a test can call.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Environment variable naming the state directory for the worker.
pub const STATE_DIR_ENV: &str = "AUTOMONIQUE_STATE_DIR";

/// Upper bound on a verb configuration file.
pub(crate) const MAX_CONFIG_BYTES: u64 = 4_096;

/// The state directory a worker verb reads its configuration from.
///
/// [`STATE_DIR_ENV`] is what the fleet worker's service sets and what an
/// agent it launches inherits; `XDG_STATE_HOME/automonique` is the daemon's
/// own convention and the fallback for an operator's shell.
#[must_use]
pub fn state_dir_from_environment() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os(STATE_DIR_ENV)
        && !explicit.is_empty()
    {
        return Some(PathBuf::from(explicit));
    }
    std::env::var_os("XDG_STATE_HOME")
        .filter(|root| !root.is_empty())
        .map(|root| PathBuf::from(root).join("automonique"))
}

/// What a verb printed and how it exited.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerbOutcome {
    /// Lines for standard output, marker line first.
    pub lines: Vec<String>,
    /// Usage line for standard error, when the arguments were refused.
    pub usage: Option<&'static str>,
    /// Process exit code: 0 success, 1 failure, 2 refused arguments.
    pub code: u8,
}

impl VerbOutcome {
    pub(crate) fn ok(lines: Vec<String>) -> Self {
        Self {
            lines,
            usage: None,
            code: 0,
        }
    }

    pub(crate) fn failed(marker: &str, reason: &str) -> Self {
        Self {
            lines: vec![format!("{marker} {reason}")],
            usage: None,
            code: 1,
        }
    }

    pub(crate) fn usage(marker: &str, reason: &str, usage: &'static str) -> Self {
        Self {
            lines: vec![format!("{marker} {reason}")],
            usage: Some(usage),
            code: 2,
        }
    }
}

/// Why a present configuration file was refused before its keys were read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameRefusal {
    /// Not a private regular file owned by this user, or over the size bound.
    Insecure,
    /// The file could not be read.
    Unreadable,
    /// Bad header, missing terminator, a line without `=`, or trailing
    /// content after the terminator.
    Malformed,
}

/// Read one private configuration file, distinguishing "absent" (`Ok(None)`)
/// from "present but not acceptable".
///
/// The file is refused unless it is a regular file (a symbolic link is not),
/// owned by the effective user, unreadable by group and others, and within
/// [`MAX_CONFIG_BYTES`].
pub(crate) fn read_private(path: &Path) -> Result<Option<String>, FrameRefusal> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(FrameRefusal::Unreadable),
    };
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.len() > MAX_CONFIG_BYTES
    {
        return Err(FrameRefusal::Insecure);
    }
    let raw = fs::read(path).map_err(|_| FrameRefusal::Unreadable)?;
    String::from_utf8(raw)
        .map(Some)
        .map_err(|_| FrameRefusal::Malformed)
}

/// Split one configuration frame into its `key=value` lines, in order.
///
/// The first line must be exactly `header`, the last exactly `terminator`,
/// and every line between them must carry a `=`. Unknown and duplicate keys
/// are the caller's to refuse, because only the caller knows its keys.
pub(crate) fn frame<'text>(
    text: &'text str,
    header: &str,
    terminator: &str,
) -> Result<Vec<(&'text str, &'text str)>, FrameRefusal> {
    let mut lines = text.lines();
    if lines.next() != Some(header) {
        return Err(FrameRefusal::Malformed);
    }
    let mut pairs = Vec::new();
    let mut terminated = false;
    for line in lines {
        if terminated {
            return Err(FrameRefusal::Malformed);
        }
        if line == terminator {
            terminated = true;
            continue;
        }
        pairs.push(line.split_once('=').ok_or(FrameRefusal::Malformed)?);
    }
    if !terminated {
        return Err(FrameRefusal::Malformed);
    }
    Ok(pairs)
}

/// Whether `value` is a credential that can travel as one header value:
/// non-empty, bounded, visible ASCII only.
pub(crate) fn header_safe_secret(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// One answered request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpReply {
    /// HTTP status code.
    pub status: u16,
    /// Response body, already within the transport's ceiling.
    pub body: Vec<u8>,
}

/// Why a request produced no reply. Deliberately carries nothing from the
/// transport's own error text, which can name the address it was dialling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostFailure {
    /// The whole-call budget elapsed.
    TimedOut,
    /// The response body exceeded its ceiling.
    ResponseTooLarge,
    /// Anything else: refused connection, TLS failure, name resolution.
    Unavailable,
}

impl PostFailure {
    /// One short sentence for a failure marker.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::TimedOut => "the service did not answer in time",
            Self::ResponseTooLarge => "the service answered with an oversized response",
            Self::Unavailable => "the service is unreachable",
        }
    }
}

/// The one operation both verbs perform on the network.
pub trait JsonPost {
    /// `POST` one JSON body with extra request headers.
    ///
    /// # Errors
    ///
    /// Returns [`PostFailure`] when no complete, bounded reply was read. A
    /// non-2xx status is a reply, not an error.
    fn post_json(
        &self,
        url: &str,
        headers: &[(&'static str, &str)],
        body: &str,
    ) -> Result<HttpReply, PostFailure>;
}

/// The production [`JsonPost`]: one bounded `ureq` call, no proxy, no
/// redirect, a whole-call timeout and a response size ceiling.
#[derive(Clone, Copy, Debug)]
pub struct LivePost {
    https_only: bool,
    timeout: Duration,
    max_response_bytes: usize,
}

impl LivePost {
    /// A transport that refuses anything but `https://`.
    #[must_use]
    pub const fn https(timeout: Duration, max_response_bytes: usize) -> Self {
        Self {
            https_only: true,
            timeout,
            max_response_bytes,
        }
    }

    /// A transport for a plaintext endpoint the caller has already proven to
    /// be loopback.
    #[must_use]
    pub const fn loopback(timeout: Duration, max_response_bytes: usize) -> Self {
        Self {
            https_only: false,
            timeout,
            max_response_bytes,
        }
    }
}

impl JsonPost for LivePost {
    fn post_json(
        &self,
        url: &str,
        headers: &[(&'static str, &str)],
        body: &str,
    ) -> Result<HttpReply, PostFailure> {
        let agent = ureq::Agent::config_builder()
            .https_only(self.https_only)
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .new_agent();
        let mut request = agent
            .post(url)
            .header("content-type", "application/json")
            .header("accept", "application/json");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let mut response = request
            .config()
            .timeout_global(Some(self.timeout))
            .build()
            .send(body)
            .map_err(|error| match error {
                ureq::Error::Timeout(_) => PostFailure::TimedOut,
                _ => PostFailure::Unavailable,
            })?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .body_mut()
            .with_config()
            .limit((self.max_response_bytes + 1) as u64)
            .reader()
            .read_to_end(&mut bytes)
            .map_err(|_| PostFailure::Unavailable)?;
        if bytes.len() > self.max_response_bytes {
            return Err(PostFailure::ResponseTooLarge);
        }
        Ok(HttpReply {
            status,
            body: bytes,
        })
    }
}

/// A short machine token a service put in its `error` field, when it is safe
/// to repeat on a marker line; `None` for anything else.
pub(crate) fn error_token(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let token = value.get("error")?.as_str()?;
    (!token.is_empty()
        && token.len() <= 40
        && token
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'))
    .then(|| token.to_owned())
}

#[cfg(test)]
pub(crate) mod testing {
    use std::cell::RefCell;

    use super::{HttpReply, JsonPost, PostFailure};

    /// One request a fake transport was asked to send.
    #[derive(Clone, Debug)]
    pub(crate) struct Sent {
        pub(crate) url: String,
        pub(crate) headers: Vec<(String, String)>,
        pub(crate) body: String,
    }

    /// A transport that answers from a canned reply and records every call.
    pub(crate) struct FakePost {
        reply: Result<HttpReply, PostFailure>,
        pub(crate) sent: RefCell<Vec<Sent>>,
    }

    impl FakePost {
        pub(crate) fn answering(status: u16, body: &str) -> Self {
            Self {
                reply: Ok(HttpReply {
                    status,
                    body: body.as_bytes().to_vec(),
                }),
                sent: RefCell::new(Vec::new()),
            }
        }

        pub(crate) fn failing(failure: PostFailure) -> Self {
            Self {
                reply: Err(failure),
                sent: RefCell::new(Vec::new()),
            }
        }

        pub(crate) fn calls(&self) -> usize {
            self.sent.borrow().len()
        }
    }

    impl JsonPost for FakePost {
        fn post_json(
            &self,
            url: &str,
            headers: &[(&'static str, &str)],
            body: &str,
        ) -> Result<HttpReply, PostFailure> {
            self.sent.borrow_mut().push(Sent {
                url: url.to_owned(),
                headers: headers
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                    .collect(),
                body: body.to_owned(),
            });
            self.reply.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    const HEADER: &str = "schema=automonique.fixture/v1";
    const END: &str = "end=automonique.fixture/v1";

    #[test]
    fn a_frame_needs_its_exact_header_and_terminator() {
        let text = format!("{HEADER}\na=1\nb=two=2\n{END}\n");
        assert_eq!(
            frame(&text, HEADER, END).expect("frame"),
            vec![("a", "1"), ("b", "two=2")]
        );
        for bad in [
            format!("a=1\n{END}\n"),
            format!("{HEADER}\na=1\n"),
            format!("{HEADER}\nno-separator\n{END}\n"),
            format!("{HEADER}\na=1\n{END}\ntrailing=1\n"),
            String::new(),
        ] {
            assert_eq!(frame(&bad, HEADER, END), Err(FrameRefusal::Malformed));
        }
    }

    #[test]
    fn a_configuration_file_must_be_private_regular_and_bounded() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("verb.conf");
        assert_eq!(read_private(&path), Ok(None), "absent is not an error");

        fs::write(&path, "x=1\n").expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        assert_eq!(read_private(&path), Err(FrameRefusal::Insecure));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(read_private(&path), Ok(Some(String::from("x=1\n"))));

        fs::write(&path, "x".repeat(MAX_CONFIG_BYTES as usize + 1)).expect("write");
        assert_eq!(read_private(&path), Err(FrameRefusal::Insecure));

        let link = root.path().join("link.conf");
        fs::write(&path, "x=1\n").expect("write");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        assert_eq!(read_private(&link), Err(FrameRefusal::Insecure));

        fs::write(&path, [0xff, 0xfe]).expect("write");
        assert_eq!(read_private(&path), Err(FrameRefusal::Malformed));
    }

    #[test]
    fn only_short_machine_tokens_are_repeated_from_an_error_body() {
        assert_eq!(
            error_token(br#"{"ok":false,"error":"unsupported_type"}"#).as_deref(),
            Some("unsupported_type")
        );
        assert_eq!(error_token(br#"{"error":"Bad Thing: /srv/x"}"#), None);
        assert_eq!(error_token(br#"{"error":7}"#), None);
        assert_eq!(error_token(b"<html>"), None);
    }

    #[test]
    fn a_header_secret_is_visible_ascii_and_bounded() {
        assert!(header_safe_secret("fixture-secret_123"));
        assert!(!header_safe_secret(""));
        assert!(!header_safe_secret("two words"));
        assert!(!header_safe_secret("line\nbreak"));
        assert!(!header_safe_secret("é"));
        assert!(!header_safe_secret(&"x".repeat(513)));
    }
}
