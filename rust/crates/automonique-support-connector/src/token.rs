// SPDX-License-Identifier: Elastic-2.0

//! The fleet bearer credential and the narrow view an HTTP boundary gets of it.
//!
//! This mirrors `OpaqueBotToken` in `automonique-transport-runtime`: a bounded
//! byte container with no `Display`, a `Debug` that renders only `<redacted>`,
//! best-effort zeroing on drop, and a callback view so the bytes cannot be
//! copied out by accident. It is a separate type rather than a reuse because
//! the Telegram token is a path credential with a `<bot-id>:<secret>` grammar,
//! while this one is a header credential and must satisfy the header's
//! character set instead.

use std::fmt;

use crate::FleetRefusal;

/// Longest bearer credential accepted.
pub const MAX_FLEET_TOKEN_BYTES: usize = 512;

/// A fleet bearer credential.
///
/// The accepted character set is RFC 6750 `token68` — ASCII letters, digits,
/// and `-._~+/=`. That is exactly what may follow `Bearer ` in an
/// `Authorization` header, and it excludes space, CR and LF, so a token can
/// never terminate the header early or inject one of its own. Validation
/// happens once, at construction, so rendering the header afterwards cannot
/// fail.
pub struct FleetToken(Vec<u8>);

impl FleetToken {
    /// Construct a bounded, header-safe bearer credential.
    ///
    /// # Errors
    ///
    /// Returns [`FleetRefusal::Token`] when the secret is empty, longer than
    /// [`MAX_FLEET_TOKEN_BYTES`], or contains a byte outside `token68`.
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, FleetRefusal> {
        let secret = secret.into();
        if secret.is_empty()
            || secret.len() > MAX_FLEET_TOKEN_BYTES
            || !secret.iter().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
            })
        {
            return Err(FleetRefusal::Token);
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
    pub fn authorization(&self) -> FleetAuthorization<'_> {
        FleetAuthorization(&self.0)
    }
}

/// A deliberate, short-lived credential view for the HTTP boundary.
///
/// The callback shape stops the bytes escaping into a `Debug`, a clone, or a
/// log line by accident. An implementation can still copy them, so the HTTP
/// client is a trusted credential consumer and is reviewed as one.
pub struct FleetAuthorization<'a>(&'a [u8]);

impl FleetAuthorization<'_> {
    /// Render the exact `Authorization` header value and hand it to `consume`.
    ///
    /// The rendered value lives only for the callback. Construction already
    /// proved every byte is ASCII `token68`, so building the header here
    /// cannot fail.
    pub fn with_header_value<R>(&self, consume: impl FnOnce(&str) -> R) -> R {
        let mut header = String::with_capacity(self.0.len() + 7);
        header.push_str("Bearer ");
        for byte in self.0 {
            header.push(char::from(*byte));
        }
        let result = consume(&header);
        scrub(header);
        result
    }
}

/// Overwrite a temporary header rendering before its buffer is released.
///
/// `String::clear` keeps the allocation and the bytes in it, so the zeros are
/// pushed back over the same capacity afterwards. This is the same best-effort
/// hygiene [`FleetToken`] applies on drop, and it needs no `unsafe` because
/// `NUL` is valid UTF-8.
fn scrub(mut header: String) {
    let width = header.len();
    header.clear();
    for _ in 0..width {
        header.push('\0');
    }
}

impl fmt::Debug for FleetAuthorization<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FleetAuthorization(<redacted>)")
    }
}

impl fmt::Debug for FleetToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FleetToken(<redacted>)")
    }
}

impl Drop for FleetToken {
    fn drop(&mut self) {
        // Best-effort hygiene only. Rust does not guarantee an optimizer
        // preserves these dead stores; production secret custody must supply a
        // reviewed non-elidable secret container at this boundary. Recorded the
        // same way `OpaqueBotToken` records it, so the two are reviewed alike.
        self.0.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sd_fixture-token-never-print";

    #[test]
    fn a_token_renders_the_exact_bearer_header_and_nothing_else() {
        let token = FleetToken::new(SECRET.as_bytes().to_vec()).expect("token");
        assert!(token.is_present());
        token.authorization().with_header_value(|header| {
            assert_eq!(header, format!("Bearer {SECRET}"));
        });
    }

    #[test]
    fn the_secret_never_reaches_debug_or_a_refusal() {
        let token = FleetToken::new(SECRET.as_bytes().to_vec()).expect("token");
        let rendered = format!(
            "{token:?} {:?} {} {:?}",
            token.authorization(),
            FleetRefusal::Token,
            FleetRefusal::Token
        );
        assert!(!rendered.contains(SECRET), "rendered: {rendered}");
        assert!(!rendered.contains("sd_"), "rendered: {rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn the_header_character_set_forbids_header_injection() {
        for hostile in [
            "token with space",
            "token\r\nX-Injected: 1",
            "token\nX-Injected: 1",
            "token\u{0}",
            "jeton-accentue\u{301}",
            "token\"quoted\"",
            "",
        ] {
            assert_eq!(
                FleetToken::new(hostile.as_bytes().to_vec()).err(),
                Some(FleetRefusal::Token),
                "must refuse {hostile:?}"
            );
        }
        // Every token68 byte class is admitted.
        assert!(FleetToken::new(b"sd_aZ09-._~+/=".to_vec()).is_ok());
    }

    #[test]
    fn the_token_length_bound_is_exact() {
        assert!(FleetToken::new(vec![b'a'; MAX_FLEET_TOKEN_BYTES]).is_ok());
        assert_eq!(
            FleetToken::new(vec![b'a'; MAX_FLEET_TOKEN_BYTES + 1]).err(),
            Some(FleetRefusal::Token)
        );
    }
}
