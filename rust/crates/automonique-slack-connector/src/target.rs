// SPDX-License-Identifier: Elastic-2.0

//! The origin lock and every identifier that may become part of a request.
//!
//! [`SlackBase`] is the whole of what a caller may say about *where* this
//! connector points, and it admits one production origin. Everything that
//! follows the origin is a constant: the `/api` prefix and the closed
//! [`crate::SlackMethod`] set. No caller value reaches the URL at all — Slack
//! takes its arguments in the request body — so the identifiers here are
//! validated for a different reason than a path segment would be: an id that
//! is not the shape Slack issues is a configuration mistake, and finding it
//! before a socket opens is cheaper than reading `channel_not_found` off a live
//! call.

use std::fmt;

use crate::{MAX_URL_BYTES, SlackRefusal};

/// The one production origin this connector may address.
pub const SLACK_API_ORIGIN: &str = "https://slack.com";

/// Longest conversation id accepted.
pub const MAX_CHANNEL_ID_BYTES: usize = 32;

/// Longest user id accepted.
pub const MAX_USER_ID_BYTES: usize = 32;

/// Longest workspace id accepted.
pub const MAX_TEAM_ID_BYTES: usize = 32;

/// Longest message timestamp accepted.
pub const MAX_TIMESTAMP_BYTES: usize = 32;

/// Longest pagination cursor accepted.
pub const MAX_CURSOR_BYTES: usize = 512;

/// A validated Slack API origin.
///
/// # What is admitted
///
/// * `https://slack.com`, which is the production shape and the only host this
///   connector will ever send a credential to, and
/// * `http://127.0.0.1[:<port>]` or `http://[::1][:<port>]`, which is the only
///   plaintext shape and cannot address anything off this host.
///
/// The loopback exception exists so the connector's wire behaviour — its
/// headers, its method paths, its decoders — is provable against an in-process
/// fake without a certificate. It is safe by construction rather than by
/// policy: the two literals it admits are not routable off-box, and no name
/// that could resolve elsewhere is accepted with `http`. A plaintext base marks
/// itself as such so the HTTP agent built from it is the only one that ever
/// relaxes `https_only`.
///
/// Note what is *not* admitted: `www.slack.com`, a workspace host such as
/// `example.slack.com`, or `slack.com:8443`. The Web API lives on exactly one
/// name and port, and a credential-bearing call to anything else is a call to
/// something that is not the Slack Web API.
#[derive(Clone, Eq, PartialEq)]
pub struct SlackBase {
    origin: String,
    plaintext_loopback: bool,
}

impl SlackBase {
    /// The production origin.
    #[must_use]
    pub fn production() -> Self {
        Self {
            origin: SLACK_API_ORIGIN.to_owned(),
            plaintext_loopback: false,
        }
    }

    /// Validate one origin.
    ///
    /// A single trailing `/` is accepted and dropped. Anything further — a path
    /// segment, a `?`, a `#`, or `user@host` — is refused rather than trimmed,
    /// because silently discarding part of a configured URL is how a connector
    /// ends up addressing a host nobody configured. In particular
    /// `https://slack.com/api` is refused: the `/api` prefix belongs to this
    /// crate, and accepting it in the base too would double it.
    ///
    /// # Errors
    ///
    /// Returns [`SlackRefusal::Base`] for any origin outside the two admitted
    /// shapes.
    pub fn new(base: &str) -> Result<Self, SlackRefusal> {
        if base.is_empty() || base.len() > 128 || !base.is_ascii() {
            return Err(SlackRefusal::Base);
        }
        let (scheme, remainder) = split_scheme(base).ok_or(SlackRefusal::Base)?;
        let authority = remainder.strip_suffix('/').unwrap_or(remainder);
        if authority.is_empty()
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
            || authority.contains('@')
            || authority.contains('\\')
        {
            return Err(SlackRefusal::Base);
        }
        let (host, port) = split_port(authority).ok_or(SlackRefusal::Base)?;

        match scheme {
            // One host, and no port.
            Scheme::Https => {
                if !host.eq_ignore_ascii_case("slack.com") || port.is_some() {
                    return Err(SlackRefusal::Base);
                }
                Ok(Self::production())
            }
            // Only the two loopback literals, never a name that a resolver
            // could point somewhere else.
            Scheme::Http => {
                if !matches!(host, "127.0.0.1" | "[::1]") {
                    return Err(SlackRefusal::Base);
                }
                let mut origin = String::with_capacity(authority.len() + 8);
                origin.push_str("http://");
                origin.push_str(host);
                if let Some(port) = port {
                    origin.push(':');
                    origin.push_str(&port.to_string());
                }
                Ok(Self {
                    origin,
                    plaintext_loopback: true,
                })
            }
        }
    }

    /// The normalized origin, with no trailing slash.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Whether this base is the plaintext loopback shape.
    ///
    /// The HTTP agent consults this and nothing else when deciding whether to
    /// relax `https_only`.
    #[must_use]
    pub const fn is_plaintext_loopback(&self) -> bool {
        self.plaintext_loopback
    }
}

/// The origin carries no credential, so `Debug` shows it: an operator
/// diagnosing a misconfigured deployment needs to see which host was addressed.
impl fmt::Debug for SlackBase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SlackBase")
            .field("origin", &self.origin)
            .field("plaintext_loopback", &self.plaintext_loopback)
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Scheme {
    Https,
    Http,
}

/// Split a scheme prefix, case-insensitively as RFC 3986 requires.
fn split_scheme(base: &str) -> Option<(Scheme, &str)> {
    let separator = base.find("://")?;
    let (scheme, remainder) = base.split_at(separator);
    let remainder = &remainder["://".len()..];
    if scheme.eq_ignore_ascii_case("https") {
        Some((Scheme::Https, remainder))
    } else if scheme.eq_ignore_ascii_case("http") {
        Some((Scheme::Http, remainder))
    } else {
        None
    }
}

/// Split an optional `:<port>` off an authority.
///
/// The IPv6 literal is handled first so the colons inside it are not mistaken
/// for a port separator. A port is decimal, in range, and without a leading
/// zero, so one authority has exactly one spelling.
fn split_port(authority: &str) -> Option<(&str, Option<u16>)> {
    let search_from = if authority.starts_with('[') {
        authority.find(']')? + 1
    } else {
        0
    };
    let Some(colon) = authority[search_from..].find(':') else {
        return Some((authority, None));
    };
    let (host, port) = authority.split_at(search_from + colon);
    let port = &port[1..];
    if port.is_empty()
        || port.len() > 5
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || (port.len() > 1 && port.starts_with('0'))
    {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some((host, Some(port)))
}

/// Whether a value is one of Slack's opaque object ids: one of `initials`,
/// then uppercase ASCII alphanumerics, within `max_bytes`.
///
/// Slack renders every object id this way — `C…`/`G…`/`D…` for conversations,
/// `U…`/`W…` for users, `T…` for workspaces. Lowercase is refused rather than
/// upcased: an id is compared for equality all over a caller, and two spellings
/// of one id is how a member check silently fails.
fn is_object_id(value: &str, initials: &[u8], max_bytes: usize) -> bool {
    let bytes = value.as_bytes();
    match bytes.split_first() {
        Some((first, rest)) => {
            initials.contains(first)
                && !rest.is_empty()
                && value.len() <= max_bytes
                && rest
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase())
        }
        None => false,
    }
}

/// A validated conversation id.
///
/// `C…` is a public channel, `G…` a private one, `D…` a direct message. All
/// three are addressable: the type filter on a *listing* is a separate
/// decision from what a caller may read or post to.
///
/// A channel *name* is deliberately not accepted. The Web API has taken ids
/// only since `conversations.*` replaced `channels.*`, and admitting a name
/// here would mean a connector that looks configured and answers
/// `channel_not_found` on every call.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ChannelId(String);

impl ChannelId {
    /// Validate one conversation id.
    ///
    /// # Errors
    ///
    /// Returns [`SlackRefusal::ChannelId`] for anything outside the grammar.
    pub fn new(value: &str) -> Result<Self, SlackRefusal> {
        if is_object_id(value, b"CGD", MAX_CHANNEL_ID_BYTES) {
            Ok(Self(value.to_owned()))
        } else {
            Err(SlackRefusal::ChannelId)
        }
    }

    /// The exact wire value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A validated user id.
///
/// `U…` is an ordinary member and `W…` an Enterprise Grid one; both are read
/// off messages and both resolve through `users.info`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UserId(String);

impl UserId {
    /// Validate one user id.
    ///
    /// # Errors
    ///
    /// Returns [`SlackRefusal::UserId`] for anything outside the grammar.
    pub fn new(value: &str) -> Result<Self, SlackRefusal> {
        if is_object_id(value, b"UW", MAX_USER_ID_BYTES) {
            Ok(Self(value.to_owned()))
        } else {
            Err(SlackRefusal::UserId)
        }
    }

    /// The exact wire value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A validated workspace id.
///
/// Decode-only: no method in this connector takes one as an argument, so
/// parsing is total and answers `None` rather than a refusal — the caller is
/// asking "is this a workspace id?", not asserting that it is.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TeamId(String);

impl TeamId {
    /// Read one workspace id, or `None` when the value is not one.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        is_object_id(value, b"TE", MAX_TEAM_ID_BYTES).then(|| Self(value.to_owned()))
    }

    /// The exact wire value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TeamId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A validated Slack message timestamp.
///
/// Slack's message identity is a string of the form `1723542000.000100`: whole
/// seconds, a dot, and a per-message suffix. It is *not* a number — the suffix
/// is significant and `1723542000.000100` and `1723542000.0001` are different
/// messages — so it is carried as text and never parsed into a float.
///
/// The fractional part is optional because the same grammar is Slack's
/// `oldest`/`latest` *window* argument, which callers legitimately spell as
/// bare seconds.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MessageTs(String);

impl MessageTs {
    /// Validate one timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`SlackRefusal::Timestamp`] for an empty value, one over
    /// [`MAX_TIMESTAMP_BYTES`], one carrying a sign or an exponent, or one with
    /// more than a single dot.
    pub fn new(value: &str) -> Result<Self, SlackRefusal> {
        if value.is_empty() || value.len() > MAX_TIMESTAMP_BYTES {
            return Err(SlackRefusal::Timestamp);
        }
        let (seconds, fraction) = match value.split_once('.') {
            Some((seconds, fraction)) => (seconds, Some(fraction)),
            None => (value, None),
        };
        let digits =
            |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
        if !digits(seconds) || fraction.is_some_and(|fraction| !digits(fraction)) {
            return Err(SlackRefusal::Timestamp);
        }
        Ok(Self(value.to_owned()))
    }

    /// The exact wire value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MessageTs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A validated pagination cursor.
///
/// Slack hands back an opaque base64 cursor and expects it returned verbatim.
/// It is bounded and checked against the base64 alphabet rather than decoded:
/// its contents are Slack's business, and inventing a structure for it here
/// would risk refusing a cursor Slack legitimately issued.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Cursor(String);

impl Cursor {
    /// Validate one cursor.
    ///
    /// # Errors
    ///
    /// Returns [`SlackRefusal::Cursor`] for an empty cursor, one over
    /// [`MAX_CURSOR_BYTES`], or one outside the base64 alphabet (both the
    /// standard and URL-safe spellings, with or without padding).
    pub fn new(value: &str) -> Result<Self, SlackRefusal> {
        if value.is_empty()
            || value.len() > MAX_CURSOR_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
            })
        {
            return Err(SlackRefusal::Cursor);
        }
        Ok(Self(value.to_owned()))
    }

    /// The exact wire value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether a value is a bounded workspace URL, as `auth.test` reports one.
pub(crate) fn is_workspace_url(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_URL_BYTES
        && value.is_ascii()
        && !value.chars().any(char::is_control)
        && (value.starts_with("https://") || value.starts_with("http://"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_one_tls_origin_is_addressable() {
        let base = SlackBase::new("https://slack.com/").expect("base");
        assert_eq!(base.origin(), SLACK_API_ORIGIN);
        assert!(!base.is_plaintext_loopback());
        assert_eq!(SlackBase::production().origin(), SLACK_API_ORIGIN);
        // The scheme and host are case-insensitive; the rendering is not.
        assert_eq!(
            SlackBase::new("HTTPS://Slack.Com").expect("base").origin(),
            SLACK_API_ORIGIN
        );

        for refused in [
            "https://slack.com:8443",
            "https://www.slack.com",
            "https://example.slack.com",
            "https://slack.com.evil.invalid",
            "https://slack.com/api",
            "https://slack.com?a=1",
            "https://slack.com#frag",
            "https://user:pass@slack.com",
            "https://slack.com\\@evil.invalid",
            "http://slack.com",
            "//slack.com",
            "slack.com",
            "ftp://slack.com",
            "",
        ] {
            assert_eq!(
                SlackBase::new(refused).err(),
                Some(SlackRefusal::Base),
                "must refuse {refused:?}"
            );
        }
    }

    #[test]
    fn only_the_two_loopback_literals_may_be_plaintext() {
        for admitted in [
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
            "http://127.0.0.1",
        ] {
            let base = SlackBase::new(admitted).expect(admitted);
            assert!(base.is_plaintext_loopback(), "{admitted}");
        }
        for refused in [
            "http://localhost:8080",
            "http://10.0.0.7:8080",
            "http://127.0.0.2:8080",
            "http://0.0.0.0:8080",
            "http://127.0.0.1:0",
            "http://127.0.0.1:080",
        ] {
            assert_eq!(
                SlackBase::new(refused).err(),
                Some(SlackRefusal::Base),
                "must refuse {refused}"
            );
        }
    }

    #[test]
    fn a_conversation_id_is_one_of_slacks_own_and_never_a_name() {
        for admitted in ["C0RESERVED", "G0RESERVED", "D0RESERVED", "C1"] {
            assert_eq!(ChannelId::new(admitted).expect(admitted).as_str(), admitted);
        }
        assert_eq!(
            ChannelId::new("C0RESERVED").expect("id").to_string(),
            "C0RESERVED"
        );
        for refused in [
            "",
            "C",
            "#general",
            "general",
            "c0reserved",
            "C0reserved",
            "U0RESERVED",
            "C0 RESERVED",
            "C0-RESERVED",
            "C0RESERVED\u{7}",
            "C0RESERVE\u{301}",
            &"C".repeat(MAX_CHANNEL_ID_BYTES + 1),
        ] {
            assert_eq!(
                ChannelId::new(refused).err(),
                Some(SlackRefusal::ChannelId),
                "must refuse {refused:?}"
            );
        }
        let longest = format!("C{}", "0".repeat(MAX_CHANNEL_ID_BYTES - 1));
        assert!(ChannelId::new(&longest).is_ok());
    }

    #[test]
    fn a_user_id_admits_both_member_spellings_and_a_team_id_only_parses() {
        for admitted in ["U0RESERVED", "W0RESERVED", "USLACKBOT"] {
            assert_eq!(UserId::new(admitted).expect(admitted).as_str(), admitted);
        }
        for refused in ["", "U", "u0reserved", "C0RESERVED", "B0RESERVED"] {
            assert_eq!(
                UserId::new(refused).err(),
                Some(SlackRefusal::UserId),
                "must refuse {refused:?}"
            );
        }
        assert_eq!(
            UserId::new("U0RESERVED").expect("id").to_string(),
            "U0RESERVED"
        );

        assert_eq!(
            TeamId::parse("T0RESERVED").map(|id| id.to_string()),
            Some("T0RESERVED".to_owned())
        );
        assert_eq!(
            TeamId::parse("E0RESERVED").map(|id| id.as_str().to_owned()),
            Some("E0RESERVED".to_owned()),
            "an Enterprise Grid workspace reports an E-prefixed id"
        );
        for refused in ["", "T", "t0reserved", "C0RESERVED"] {
            assert_eq!(TeamId::parse(refused), None, "must refuse {refused:?}");
        }
    }

    #[test]
    fn a_timestamp_is_slacks_message_identity_and_never_a_number() {
        for admitted in ["1723542000.000100", "1723542000", "0.1"] {
            assert_eq!(MessageTs::new(admitted).expect(admitted).as_str(), admitted);
        }
        // The suffix is significant: two spellings are two messages.
        assert_ne!(
            MessageTs::new("1723542000.000100").expect("ts"),
            MessageTs::new("1723542000.0001").expect("ts")
        );
        assert_eq!(
            MessageTs::new("1723542000.000100").expect("ts").to_string(),
            "1723542000.000100"
        );
        for refused in [
            "",
            ".",
            "1723542000.",
            ".000100",
            "1723542000.000100.1",
            "-1723542000",
            "+1723542000",
            "1.7e9",
            "now",
            "1723542000 000100",
            &"1".repeat(MAX_TIMESTAMP_BYTES + 1),
        ] {
            assert_eq!(
                MessageTs::new(refused).err(),
                Some(SlackRefusal::Timestamp),
                "must refuse {refused:?}"
            );
        }
    }

    #[test]
    fn a_cursor_is_bounded_base64_carried_verbatim() {
        let cursor = Cursor::new("dGVhbTpDMFJFU0VSVkVE").expect("cursor");
        assert_eq!(cursor.as_str(), "dGVhbTpDMFJFU0VSVkVE");
        assert!(Cursor::new("bmV4dF90czox=").is_ok());
        assert!(Cursor::new("a-b_c").is_ok());
        for refused in ["", "with space", "quote\"", "back\\slash", "curseur\u{301}"] {
            assert_eq!(
                Cursor::new(refused).err(),
                Some(SlackRefusal::Cursor),
                "must refuse {refused:?}"
            );
        }
        assert!(Cursor::new(&"c".repeat(MAX_CURSOR_BYTES)).is_ok());
        assert_eq!(
            Cursor::new(&"c".repeat(MAX_CURSOR_BYTES + 1)).err(),
            Some(SlackRefusal::Cursor)
        );
    }

    #[test]
    fn a_workspace_url_is_bounded_and_absolute() {
        assert!(is_workspace_url("https://example.slack.com/"));
        assert!(!is_workspace_url(""));
        assert!(!is_workspace_url("example.slack.com"));
        assert!(!is_workspace_url("https://exemple\u{301}.invalid/"));
        assert!(!is_workspace_url("https://example.slack.com/\u{7}"));
        assert!(!is_workspace_url(&format!(
            "https://{}.invalid",
            "a".repeat(MAX_URL_BYTES)
        )));
    }
}
