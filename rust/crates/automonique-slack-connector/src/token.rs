// SPDX-License-Identifier: Elastic-2.0

//! Slack credentials and the narrow view an HTTP boundary gets of them.
//!
//! This mirrors `GitHubToken` in `automonique-github-connector`, `FleetToken`
//! in `automonique-support-connector` and `OpaqueBotToken` in
//! `automonique-transport-runtime`: a bounded byte container with no `Display`,
//! a `Debug` that renders only `<redacted>`, best-effort zeroing on drop, and a
//! callback view so the bytes cannot be copied out by accident. It is a separate
//! type rather than a reuse because a connector should not be able to send
//! another service's credential to Slack by passing the wrong value of a shared
//! type — and because this one carries a prefix rule the others do not.

use std::fmt;

use crate::SlackRefusal;
use automonique_connector_substrate::secret::scrub_rendered;

/// The only credential prefix this connector accepts.
///
/// Slack issues several token families and they are not interchangeable:
/// `xoxp-` is a user token that acts *as a person*, `xoxa-`/`xoxe-` are app and
/// refresh tokens, and `xoxb-` is the bot token this connector is written for.
/// Requiring the prefix means a misconfiguration that would have posted under a
/// human's name is refused before a socket is opened, and a credential for an
/// entirely different service cannot be handed to Slack at all.
pub const SLACK_BOT_TOKEN_PREFIX: &str = "xoxb-";

/// The only Socket Mode credential prefix this connector accepts.
///
/// An app-level token represents the application rather than one installation
/// and is the credential Slack accepts on `apps.connections.open`. Keeping it
/// distinct from [`SlackToken`] makes it impossible to spend the bot token on
/// the Socket Mode bootstrap call, or the app token on a Web API operation.
pub const SLACK_APP_TOKEN_PREFIX: &str = "xapp-";

/// Longest bearer credential accepted.
///
/// A current `xoxb-` token is under 100 bytes; the ceiling leaves room for a
/// longer future spelling without leaving room for a file.
pub const MAX_SLACK_TOKEN_BYTES: usize = 512;

/// A Slack bot credential.
///
/// The accepted character set is RFC 6750 `token68` — ASCII letters, digits,
/// and `-._~+/=`. That covers every Slack token spelling and excludes space, CR
/// and LF, so a token can never terminate the `Authorization` header early or
/// inject one of its own. Both the character set and the
/// [`SLACK_BOT_TOKEN_PREFIX`] are checked once, at construction, so rendering
/// the header afterwards cannot fail.
pub struct SlackToken(Vec<u8>);

/// A Slack app-level credential used only to open Socket Mode connections.
///
/// Like [`SlackToken`], this type has no `Display`, redacts `Debug`, lends its
/// bytes only through a callback view, and best-effort overwrites its storage on
/// drop. The separate type is the important part: a caller cannot accidentally
/// substitute one Slack credential audience for the other.
pub struct SlackAppToken(Vec<u8>);

impl SlackToken {
    /// Construct a bounded, header-safe bot credential.
    ///
    /// # Errors
    ///
    /// Returns [`SlackRefusal::Token`] when the secret is empty, longer than
    /// [`MAX_SLACK_TOKEN_BYTES`], contains a byte outside `token68`, or is not
    /// prefixed [`SLACK_BOT_TOKEN_PREFIX`] followed by at least one byte.
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, SlackRefusal> {
        let secret = secret.into();
        if secret.len() <= SLACK_BOT_TOKEN_PREFIX.len()
            || secret.len() > MAX_SLACK_TOKEN_BYTES
            || !secret.starts_with(SLACK_BOT_TOKEN_PREFIX.as_bytes())
            || !secret.iter().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
            })
        {
            return Err(SlackRefusal::Token);
        }
        Ok(Self(secret))
    }

    /// Whether a credential is held at all.
    ///
    /// The only fact about the credential this type will state.
    #[must_use]
    pub fn is_present(&self) -> bool {
        !self.0.is_empty()
    }

    /// Lend the credential to the HTTP boundary for one call.
    #[must_use]
    pub fn authorization(&self) -> SlackAuthorization<'_> {
        SlackAuthorization(&self.0)
    }
}

impl SlackAppToken {
    /// Construct a bounded, header-safe app-level credential.
    ///
    /// # Errors
    ///
    /// Returns [`SlackRefusal::AppToken`] when the secret is empty, longer than
    /// [`MAX_SLACK_TOKEN_BYTES`], contains a byte outside RFC 6750 `token68`, or
    /// is not prefixed [`SLACK_APP_TOKEN_PREFIX`] followed by at least one byte.
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, SlackRefusal> {
        let secret = secret.into();
        if !valid_token(&secret, SLACK_APP_TOKEN_PREFIX) {
            return Err(SlackRefusal::AppToken);
        }
        Ok(Self(secret))
    }

    /// Whether a credential is held at all.
    #[must_use]
    pub fn is_present(&self) -> bool {
        !self.0.is_empty()
    }

    /// Lend the credential to the Socket Mode HTTP boundary for one call.
    #[must_use]
    pub fn authorization(&self) -> SlackAuthorization<'_> {
        SlackAuthorization(&self.0)
    }
}

fn valid_token(secret: &[u8], prefix: &str) -> bool {
    secret.len() > prefix.len()
        && secret.len() <= MAX_SLACK_TOKEN_BYTES
        && secret.starts_with(prefix.as_bytes())
        && secret.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        })
}

/// A deliberate, short-lived credential view for the HTTP boundary.
///
/// The callback shape stops the bytes escaping into a `Debug`, a clone, or a
/// log line by accident. An implementation can still copy them, so the HTTP
/// client is a trusted credential consumer and is reviewed as one.
pub struct SlackAuthorization<'a>(&'a [u8]);

impl SlackAuthorization<'_> {
    /// Render the exact `Authorization` header value and hand it to `consume`.
    ///
    /// The rendered value lives only for the callback. Construction already
    /// proved every byte is ASCII `token68`, so building the header here cannot
    /// fail.
    pub fn with_header_value<R>(&self, consume: impl FnOnce(&str) -> R) -> R {
        let mut header = String::with_capacity(self.0.len() + 7);
        header.push_str("Bearer ");
        for byte in self.0 {
            header.push(char::from(*byte));
        }
        let result = consume(&header);
        scrub_rendered(header);
        result
    }
}

impl fmt::Debug for SlackAuthorization<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SlackAuthorization(<redacted>)")
    }
}

impl fmt::Debug for SlackToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SlackToken(<redacted>)")
    }
}

impl fmt::Debug for SlackAppToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SlackAppToken(<redacted>)")
    }
}

impl Drop for SlackToken {
    fn drop(&mut self) {
        // Best-effort hygiene only. Rust does not guarantee an optimizer
        // preserves these dead stores; production secret custody must supply a
        // reviewed non-elidable secret container at this boundary. Recorded the
        // same way `GitHubToken` and `FleetToken` record it, so all three are
        // reviewed alike.
        self.0.fill(0);
    }
}

impl Drop for SlackAppToken {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic bot token. It is not a real credential and addresses
    /// nothing: no server outside this crate's own tests ever sees it.
    const SECRET: &str = "xoxb-0000000000-0000000000-fixture-never-print";
    const APP_SECRET: &str = "xapp-1-A0FIXTURE-fixture-never-print";

    #[test]
    fn a_token_renders_the_exact_bearer_header_and_nothing_else() {
        let token = SlackToken::new(SECRET.as_bytes().to_vec()).expect("token");
        assert!(token.is_present());
        token.authorization().with_header_value(|header| {
            assert_eq!(header, format!("Bearer {SECRET}"));
        });
    }

    #[test]
    fn the_secret_never_reaches_debug_or_a_refusal() {
        let token = SlackToken::new(SECRET.as_bytes().to_vec()).expect("token");
        let rendered = format!(
            "{token:?} {:?} {} {:?}",
            token.authorization(),
            SlackRefusal::Token,
            SlackRefusal::Token
        );
        assert!(!rendered.contains(SECRET), "rendered: {rendered}");
        assert!(!rendered.contains("xoxb-"), "rendered: {rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn only_a_bot_token_is_accepted() {
        for refused in [
            // A user token acts as a person, not as the app.
            "xoxp-0000000000-0000000000-fixture",
            "xoxa-2-fixture",
            "xoxe-1-fixture",
            // Another service's credential must not be sendable to Slack.
            "ghp_fixture-token-never-print",
            // The prefix alone is not a token.
            "xoxb-",
            "xoxb",
            "",
        ] {
            assert_eq!(
                SlackToken::new(refused.as_bytes().to_vec()).err(),
                Some(SlackRefusal::Token),
                "must refuse {refused:?}"
            );
        }
        assert!(SlackToken::new(b"xoxb-a".to_vec()).is_ok());
    }

    #[test]
    fn an_app_token_has_its_own_audience_and_is_always_redacted() {
        let token = SlackAppToken::new(APP_SECRET.as_bytes().to_vec()).expect("app token");
        assert!(token.is_present());
        token.authorization().with_header_value(|header| {
            assert_eq!(header, format!("Bearer {APP_SECRET}"));
        });
        let rendered = format!("{token:?} {:?}", token.authorization());
        assert!(!rendered.contains(APP_SECRET), "rendered: {rendered}");
        assert!(!rendered.contains("xapp-"), "rendered: {rendered}");
        assert!(rendered.contains("<redacted>"));

        for refused in [
            SECRET,
            "xoxp-fixture",
            "xapp-",
            "xapp",
            "xapp-fixture with space",
            "xapp-fixture\r\ninjected",
            "",
        ] {
            assert_eq!(
                SlackAppToken::new(refused.as_bytes().to_vec()).err(),
                Some(SlackRefusal::AppToken),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn the_header_character_set_forbids_header_injection() {
        for hostile in [
            "xoxb-token with space",
            "xoxb-token\r\nX-Injected: 1",
            "xoxb-token\nX-Injected: 1",
            "xoxb-token\u{0}",
            "xoxb-jeton-accentue\u{301}",
            "xoxb-token\"quoted\"",
        ] {
            assert_eq!(
                SlackToken::new(hostile.as_bytes().to_vec()).err(),
                Some(SlackRefusal::Token),
                "must refuse {hostile:?}"
            );
        }
        // Every token68 byte class is admitted after the prefix.
        assert!(SlackToken::new(b"xoxb-aZ09-._~+/=".to_vec()).is_ok());
    }

    #[test]
    fn the_token_length_bound_is_exact() {
        let pad = |width: usize| {
            let mut secret = SLACK_BOT_TOKEN_PREFIX.as_bytes().to_vec();
            secret.resize(width, b'a');
            secret
        };
        assert!(SlackToken::new(pad(MAX_SLACK_TOKEN_BYTES)).is_ok());
        assert_eq!(
            SlackToken::new(pad(MAX_SLACK_TOKEN_BYTES + 1)).err(),
            Some(SlackRefusal::Token)
        );
        // One byte past the prefix is the shortest accepted credential.
        assert!(SlackToken::new(pad(SLACK_BOT_TOKEN_PREFIX.len() + 1)).is_ok());
        assert_eq!(
            SlackToken::new(pad(SLACK_BOT_TOKEN_PREFIX.len())).err(),
            Some(SlackRefusal::Token)
        );
    }
}
