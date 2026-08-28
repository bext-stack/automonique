// SPDX-License-Identifier: Elastic-2.0

//! The GitHub bearer credential and the narrow view an HTTP boundary gets of
//! it.
//!
//! This mirrors `FleetToken` in `automonique-support-connector` and
//! `OpaqueBotToken` in `automonique-transport-runtime`: a bounded byte
//! container with no `Display`, a `Debug` that renders only `<redacted>`,
//! best-effort zeroing on drop, and a callback view so the bytes cannot be
//! copied out by accident. It is a separate type rather than a reuse because a
//! connector should not be able to send another service's credential to
//! GitHub by passing the wrong value of a shared type.

use std::fmt;

use crate::GitHubRefusal;
use automonique_connector_substrate::secret::scrub_rendered;
use zeroize::Zeroize;

/// Longest bearer credential accepted.
///
/// A `ghp_` classic token is 40 bytes and a `github_pat_` fine-grained one is
/// under 100; the ceiling leaves room for a longer future spelling without
/// leaving room for a file.
pub const MAX_GITHUB_TOKEN_BYTES: usize = 512;

/// A GitHub bearer credential.
///
/// The accepted character set is RFC 6750 `token68` — ASCII letters, digits,
/// and `-._~+/=`. That covers every token GitHub issues (`ghp_`, `gho_`,
/// `ghs_`, `github_pat_…`) and excludes space, CR and LF, so a token can never
/// terminate the `Authorization` header early or inject one of its own.
/// Validation happens once, at construction, so rendering the header afterwards
/// cannot fail.
pub struct GitHubToken(Vec<u8>);

impl GitHubToken {
    /// Validate a borrowed credential without taking or copying its custody.
    ///
    /// This is intended for secret-bearing configuration parsers that already
    /// keep the source bytes in a zeroizing container.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Token`] for the same invalid values as
    /// [`Self::new`].
    pub fn validate(secret: &[u8]) -> Result<(), GitHubRefusal> {
        if secret.is_empty()
            || secret.len() > MAX_GITHUB_TOKEN_BYTES
            || !secret.iter().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
            })
        {
            return Err(GitHubRefusal::Token);
        }
        Ok(())
    }

    /// Construct a bounded, header-safe bearer credential.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Token`] when the secret is empty, longer than
    /// [`MAX_GITHUB_TOKEN_BYTES`], or contains a byte outside `token68`.
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, GitHubRefusal> {
        let mut secret = secret.into();
        if let Err(error) = Self::validate(&secret) {
            // `Self` is never constructed on this path, so scrub the owned
            // allocation explicitly rather than relying on `Drop`.
            secret.zeroize();
            return Err(error);
        }
        Ok(Self(secret))
    }

    /// Whether a credential is held at all.
    ///
    /// The only fact about the credential this type will state. The legacy
    /// client's `githubConfigured()` asks exactly this question and nothing
    /// more.
    #[must_use]
    pub fn is_present(&self) -> bool {
        !self.0.is_empty()
    }

    /// Lend the credential to the HTTP boundary for one call.
    #[must_use]
    pub fn authorization(&self) -> GitHubAuthorization<'_> {
        GitHubAuthorization(&self.0)
    }
}

/// A deliberate, short-lived credential view for the HTTP boundary.
///
/// The callback shape stops the bytes escaping into a `Debug`, a clone, or a
/// log line by accident. An implementation can still copy them, so the HTTP
/// client is a trusted credential consumer and is reviewed as one.
pub struct GitHubAuthorization<'a>(&'a [u8]);

impl GitHubAuthorization<'_> {
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

impl fmt::Debug for GitHubAuthorization<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitHubAuthorization(<redacted>)")
    }
}

impl fmt::Debug for GitHubToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitHubToken(<redacted>)")
    }
}

impl Drop for GitHubToken {
    fn drop(&mut self) {
        // Best-effort hygiene only. Rust does not guarantee an optimizer
        // preserves these dead stores; production secret custody must supply a
        // reviewed non-elidable secret container at this boundary. Recorded the
        // same way `FleetToken` records it, so the two are reviewed alike.
        self.0.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "ghp_fixture-token-never-print";

    #[test]
    fn a_token_renders_the_exact_bearer_header_and_nothing_else() {
        let token = GitHubToken::new(SECRET.as_bytes().to_vec()).expect("token");
        assert!(token.is_present());
        token.authorization().with_header_value(|header| {
            assert_eq!(header, format!("Bearer {SECRET}"));
        });
    }

    #[test]
    fn the_secret_never_reaches_debug_or_a_refusal() {
        let token = GitHubToken::new(SECRET.as_bytes().to_vec()).expect("token");
        let rendered = format!(
            "{token:?} {:?} {} {:?}",
            token.authorization(),
            GitHubRefusal::Token,
            GitHubRefusal::Token
        );
        assert!(!rendered.contains(SECRET), "rendered: {rendered}");
        assert!(!rendered.contains("ghp_"), "rendered: {rendered}");
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
                GitHubToken::new(hostile.as_bytes().to_vec()).err(),
                Some(GitHubRefusal::Token),
                "must refuse {hostile:?}"
            );
        }
        // Every token68 byte class is admitted, including the underscore every
        // GitHub token prefix uses.
        assert!(GitHubToken::new(b"github_pat_aZ09-._~+/=".to_vec()).is_ok());
    }

    #[test]
    fn the_token_length_bound_is_exact() {
        assert!(GitHubToken::new(vec![b'a'; MAX_GITHUB_TOKEN_BYTES]).is_ok());
        assert_eq!(
            GitHubToken::new(vec![b'a'; MAX_GITHUB_TOKEN_BYTES + 1]).err(),
            Some(GitHubRefusal::Token)
        );
    }
}
