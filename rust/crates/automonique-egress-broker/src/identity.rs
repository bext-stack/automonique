// SPDX-License-Identifier: Elastic-2.0

//! The per-session identity that makes the provider endpoint unusable to a
//! credential the supervisor did not issue.
//!
//! # The attack this exists for
//!
//! A destination allowlist answers "may this workload talk to
//! `api.example.com`?". It cannot answer "*as whom*?". An injected instruction
//! that persuades a workload to `POST` its workspace to the model endpoint with
//! an attacker-supplied API key is, to an allowlist, a permitted request to a
//! permitted host. The bytes leave through the front door.
//!
//! Identity-bound egress closes that door by taking the credential away from
//! the workload entirely. The sandboxee is given a [`SessionSentinel`] — an
//! opaque, per-session, single-purpose string that is worth nothing to anyone
//! but this broker — and a base URL pointing at the broker's own loopback
//! listener. The real [`ProviderCredential`] never enters the sandbox: it stays
//! in supervisor memory and is substituted at the moment of forwarding. A
//! request carrying any other credential is refused with a typed
//! [`IdentityRefusal`], recorded, and — the part that matters — refused
//! *before* anything is resolved or dialled, so a foreign key does not even
//! produce a packet.
//!
//! # Why the sentinel is compared in constant time
//!
//! The sentinel is the only thing standing between a workload and the real
//! credential, and the workload can present as many guesses as it likes. A
//! byte-by-byte comparison that returns early would let it recover the sentinel
//! one byte at a time from the timing of the refusal. [`subtle`] gives the
//! comparison a running time that depends on the length and nothing else.
//!
//! # What the sentinel is not
//!
//! It is not a capability the workload can spend elsewhere, because it is
//! accepted at exactly one loopback listener owned by one broker for the life
//! of one run. It is not a secret worth exfiltrating, because it authorizes
//! nothing off this host. And it is not a substitute for the destination
//! checks: a substituted request goes through the same parse-then-match,
//! resolve-once, connect-to-the-resolved-address and address-scope path as
//! everything else this crate forwards.

use std::fmt;
use std::io::Read;
use std::sync::Mutex;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::allowlist::Destination;

/// Bytes of entropy behind one sentinel.
pub const SENTINEL_ENTROPY_BYTES: usize = 32;

/// Prefix every sentinel carries.
///
/// It exists so an operator reading a workload's environment can tell at a
/// glance that the value is a broker sentinel rather than a leaked provider
/// key, and so a sentinel that escapes into a log is recognisable as harmless.
pub const SENTINEL_PREFIX: &str = "amq-egress-session-";

/// Longest secret a [`ProviderCredential`] may hold.
pub const MAX_CREDENTIAL_BYTES: usize = 4096;

/// Most refusals one broker keeps for inspection.
///
/// The ledger is a bounded ring: a workload that hammers the listener with
/// foreign credentials cannot grow the supervisor's memory, and the *counters*
/// — which are unbounded — remain the complete tally.
pub const MAX_LEDGER_ENTRIES: usize = 64;

/// The source of entropy for a sentinel. Read directly rather than through a
/// random-number crate, because one read of 32 bytes at session setup does not
/// justify a dependency and the kernel's pool is the authority either way.
const ENTROPY_SOURCE: &str = "/dev/urandom";

/// A per-session credential the workload may present and nobody else can use.
///
/// Cloning is deliberately unavailable: one session, one sentinel, one owner.
pub struct SessionSentinel {
    token: String,
}

impl SessionSentinel {
    /// Mint a sentinel from kernel entropy.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::EntropyUnavailable`] if the entropy source
    /// cannot be read. There is no fallback to a weaker source: a predictable
    /// sentinel is a forgeable one, and a broker that could not mint a real one
    /// must not start a session that pretends otherwise.
    pub fn generate() -> Result<Self, IdentityError> {
        let mut bytes = [0u8; SENTINEL_ENTROPY_BYTES];
        let mut source =
            std::fs::File::open(ENTROPY_SOURCE).map_err(IdentityError::EntropyUnavailable)?;
        source
            .read_exact(&mut bytes)
            .map_err(IdentityError::EntropyUnavailable)?;
        let token = format!("{SENTINEL_PREFIX}{}", hex::encode(bytes));
        bytes.zeroize();
        Ok(Self { token })
    }

    /// Rebuild a sentinel from a token that was minted earlier.
    ///
    /// Used where the token has already crossed a boundary — a test that pins
    /// an exact value, or a supervisor that minted the sentinel before the
    /// broker existed. The shape is checked, not the entropy: this cannot tell
    /// a well-formed guess from a well-formed mint, which is why
    /// [`Self::generate`] is what production uses.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::TokenRejected`] unless `token` is the prefix
    /// followed by exactly `2 * SENTINEL_ENTROPY_BYTES` lowercase hex digits.
    pub fn from_token(token: &str) -> Result<Self, IdentityError> {
        let Some(digits) = token.strip_prefix(SENTINEL_PREFIX) else {
            return Err(IdentityError::TokenRejected);
        };
        if digits.len() != SENTINEL_ENTROPY_BYTES * 2
            || !digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(IdentityError::TokenRejected);
        }
        Ok(Self {
            token: token.to_owned(),
        })
    }

    /// The token the workload is given.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Whether `presented` is this session's sentinel, compared in constant
    /// time.
    ///
    /// A length mismatch returns early, which leaks the length of the
    /// sentinel — a compile-time constant that is already public here.
    #[must_use]
    pub fn matches(&self, presented: &[u8]) -> bool {
        let expected = self.token.as_bytes();
        if presented.len() != expected.len() {
            return false;
        }
        expected.ct_eq(presented).into()
    }
}

impl fmt::Debug for SessionSentinel {
    /// Redacted. A sentinel in a log is not a disaster, but a sentinel that
    /// appears in a log *by default* trains everyone to expect secrets there.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionSentinel")
            .field("token", &"<sentinel>")
            .finish()
    }
}

impl Drop for SessionSentinel {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

/// How a credential is carried on the wire towards the provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialScheme {
    /// `x-api-key: <secret>`, the Anthropic-compatible Messages spelling.
    ApiKeyHeader,
    /// `authorization: Bearer <secret>`.
    BearerToken,
}

impl CredentialScheme {
    /// The header name, lowercase.
    #[must_use]
    pub const fn header_name(self) -> &'static str {
        match self {
            Self::ApiKeyHeader => "x-api-key",
            Self::BearerToken => "authorization",
        }
    }

    /// The header value for `secret`.
    #[must_use]
    fn header_value(self, secret: &str) -> String {
        match self {
            Self::ApiKeyHeader => secret.to_owned(),
            Self::BearerToken => format!("Bearer {secret}"),
        }
    }
}

/// The real provider credential, held by the supervisor and never by the
/// sandbox.
pub struct ProviderCredential {
    scheme: CredentialScheme,
    secret: String,
}

impl ProviderCredential {
    /// Bind a secret to the scheme the provider expects.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::CredentialRejected`] for an empty secret, one
    /// longer than [`MAX_CREDENTIAL_BYTES`], or one containing a byte that
    /// cannot appear in a header value. The last of those is the important
    /// one: a secret carrying `CR` or `LF` would let whoever supplied it inject
    /// header lines into every request the broker forwards.
    pub fn new(scheme: CredentialScheme, secret: &str) -> Result<Self, IdentityError> {
        if secret.is_empty() || secret.len() > MAX_CREDENTIAL_BYTES {
            return Err(IdentityError::CredentialRejected);
        }
        if !secret
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        {
            return Err(IdentityError::CredentialRejected);
        }
        Ok(Self {
            scheme,
            secret: secret.to_owned(),
        })
    }

    /// The scheme this credential is carried under.
    #[must_use]
    pub const fn scheme(&self) -> CredentialScheme {
        self.scheme
    }

    /// The header line this credential contributes, without its terminator.
    #[must_use]
    pub(crate) fn header_line(&self) -> String {
        format!(
            "{}: {}",
            self.scheme.header_name(),
            self.scheme.header_value(&self.secret)
        )
    }
}

impl fmt::Debug for ProviderCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCredential")
            .field("scheme", &self.scheme)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl Drop for ProviderCredential {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// One provider endpoint, the sentinel that reaches it, and the credential
/// substituted into every request that does.
#[derive(Debug)]
pub struct ProviderIdentity {
    upstream: Destination,
    sentinel: SessionSentinel,
    credential: ProviderCredential,
}

impl ProviderIdentity {
    /// Bind a sentinel and a credential to one upstream destination.
    #[must_use]
    pub const fn new(
        upstream: Destination,
        sentinel: SessionSentinel,
        credential: ProviderCredential,
    ) -> Self {
        Self {
            upstream,
            sentinel,
            credential,
        }
    }

    /// The destination substituted requests are forwarded to.
    ///
    /// This destination lives here and **not** in the [`CONNECT`
    /// allowlist](crate::DestinationAllowlist). The two are mutually exclusive
    /// by design: while an identity is bound, a `CONNECT` naming this host is
    /// refused, because a tunnel is opaque and a foreign key would ride inside
    /// it untouched. The only route to the provider is the substituting one.
    #[must_use]
    pub const fn upstream(&self) -> &Destination {
        &self.upstream
    }

    /// The token the workload is given in place of a credential.
    #[must_use]
    pub fn sentinel_token(&self) -> &str {
        self.sentinel.token()
    }

    /// The credential's scheme, which is what the *upstream* expects. The
    /// sandbox may present its sentinel under either accepted spelling; what
    /// leaves this host is always this one.
    #[must_use]
    pub const fn credential_scheme(&self) -> CredentialScheme {
        self.credential.scheme()
    }

    pub(crate) const fn sentinel(&self) -> &SessionSentinel {
        &self.sentinel
    }

    pub(crate) const fn credential(&self) -> &ProviderCredential {
        &self.credential
    }
}

/// Why an identity could not be constructed.
#[derive(Debug)]
pub enum IdentityError {
    /// Kernel entropy could not be read, so no sentinel was minted.
    EntropyUnavailable(std::io::Error),
    /// A token was not this crate's sentinel shape.
    TokenRejected,
    /// A secret was empty, over-long, or contained a byte that cannot appear
    /// in a header value.
    CredentialRejected,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntropyUnavailable(error) => {
                write!(formatter, "{ENTROPY_SOURCE} could not be read: {error}")
            }
            Self::TokenRejected => write!(
                formatter,
                "a sentinel is {SENTINEL_PREFIX} followed by {} lowercase hex digits",
                SENTINEL_ENTROPY_BYTES * 2
            ),
            Self::CredentialRejected => write!(
                formatter,
                "a credential is 1..={MAX_CREDENTIAL_BYTES} bytes of printable ASCII"
            ),
        }
    }
}

impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::EntropyUnavailable(error) => Some(error),
            _ => None,
        }
    }
}

/// Why one request to the identity-bound listener was refused.
///
/// Every variant is a decision the broker made on its own; none of them is a
/// message from the provider. The three at the top are the ones this feature
/// exists to produce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityRefusal {
    /// The request carried a credential that is not this session's sentinel.
    /// The exfiltration case: refused before resolution and before any dial.
    ForeignCredential,
    /// The request carried no credential at all.
    MissingCredential,
    /// A `CONNECT` named the provider host while an identity was bound. An
    /// opaque tunnel would carry a foreign credential straight past the
    /// substitution, so the tunnel is refused and the substituting route is
    /// the only one left.
    TunnelToProviderRefused,
    /// More than one credential header was present. One of them is not ours,
    /// and guessing which would be the wrong instinct.
    AmbiguousCredential,
    /// The method was `CONNECT`, or was not a bare token.
    MethodRejected,
    /// The target was not origin-form (`/path`). This listener is a provider
    /// endpoint, not a proxy.
    TargetRejected,
    /// The version was not `HTTP/1.1`.
    VersionUnsupported,
    /// A header line was empty, obs-folded, or had no name-terminating colon,
    /// or the head contained a bare `CR` or `LF`.
    HeadMalformed,
    /// The head exceeded its byte or line ceiling.
    HeadTooLarge,
    /// No head arrived within the deadline.
    HeadTimedOut,
    /// Reading from the client failed.
    ClientUnreadable,
    /// `Content-Length` was absent where a body was framed, malformed,
    /// repeated, or larger than the request-body ceiling; or a request framed
    /// itself with `Transfer-Encoding`, which this forwarder does not accept.
    RequestFramingRejected,
    /// The upstream could not be resolved, or every resolved address refused.
    UpstreamUnreachable,
    /// Every resolved address fell outside the destination's address scope.
    UpstreamOutOfScope,
    /// The TLS session towards the upstream could not be established.
    UpstreamTlsRefused,
}

impl IdentityRefusal {
    /// A stable spelling for a ledger line or a log.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ForeignCredential => "foreign_credential",
            Self::MissingCredential => "missing_credential",
            Self::TunnelToProviderRefused => "tunnel_to_provider_refused",
            Self::AmbiguousCredential => "ambiguous_credential",
            Self::MethodRejected => "method_rejected",
            Self::TargetRejected => "target_rejected",
            Self::VersionUnsupported => "version_unsupported",
            Self::HeadMalformed => "head_malformed",
            Self::HeadTooLarge => "head_too_large",
            Self::HeadTimedOut => "head_timed_out",
            Self::ClientUnreadable => "client_unreadable",
            Self::RequestFramingRejected => "request_framing_rejected",
            Self::UpstreamUnreachable => "upstream_unreachable",
            Self::UpstreamOutOfScope => "upstream_out_of_scope",
            Self::UpstreamTlsRefused => "upstream_tls_refused",
        }
    }

    /// Whether this refusal was reached with the provider socket still
    /// untouched.
    ///
    /// This is the property the acceptance test asserts: a workload holding a
    /// foreign credential must not cause so much as a `connect(2)` towards the
    /// provider. Only the three upstream variants are reached after a dial has
    /// been attempted.
    #[must_use]
    pub const fn precedes_any_dial(self) -> bool {
        !matches!(
            self,
            Self::UpstreamUnreachable | Self::UpstreamOutOfScope | Self::UpstreamTlsRefused
        )
    }
}

impl fmt::Display for IdentityRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for IdentityRefusal {}

/// One recorded refusal.
///
/// Deliberately three plain fields and no payload: nothing the client sent is
/// retained, so the ledger cannot become the leak it exists to prevent. In
/// particular a presented credential — which is exactly the kind of value an
/// operator would later wish they had *not* written down — is never recorded,
/// not even truncated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RefusalRecord {
    /// Which refusal it was.
    pub refusal: IdentityRefusal,
    /// Whether the provider socket was still untouched at the point of refusal.
    pub before_any_dial: bool,
    /// How many refusals the broker had recorded before this one, so a
    /// truncated ledger still shows what it dropped.
    pub sequence: u64,
}

/// A bounded, in-memory record of refusals, oldest dropped first.
#[derive(Debug, Default)]
pub(crate) struct RefusalLedger {
    entries: Mutex<(u64, Vec<RefusalRecord>)>,
}

impl RefusalLedger {
    pub(crate) fn record(&self, refusal: IdentityRefusal) {
        let Ok(mut held) = self.entries.lock() else {
            return;
        };
        let (ref mut sequence, ref mut entries) = *held;
        let record = RefusalRecord {
            refusal,
            before_any_dial: refusal.precedes_any_dial(),
            sequence: *sequence,
        };
        *sequence += 1;
        if entries.len() == MAX_LEDGER_ENTRIES {
            entries.remove(0);
        }
        entries.push(record);
    }

    pub(crate) fn entries(&self) -> Vec<RefusalRecord> {
        self.entries
            .lock()
            .map(|held| held.1.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CredentialScheme, IdentityError, IdentityRefusal, MAX_CREDENTIAL_BYTES, MAX_LEDGER_ENTRIES,
        ProviderCredential, RefusalLedger, SENTINEL_ENTROPY_BYTES, SENTINEL_PREFIX,
        SessionSentinel,
    };

    #[test]
    fn a_minted_sentinel_is_prefixed_hex_of_the_declared_width() {
        let sentinel = SessionSentinel::generate().unwrap();
        let digits = sentinel.token().strip_prefix(SENTINEL_PREFIX).unwrap();
        assert_eq!(digits.len(), SENTINEL_ENTROPY_BYTES * 2);
        assert!(digits.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(SessionSentinel::from_token(sentinel.token()).is_ok());
    }

    #[test]
    fn two_sentinels_minted_in_a_row_differ() {
        let first = SessionSentinel::generate().unwrap();
        let second = SessionSentinel::generate().unwrap();
        assert_ne!(first.token(), second.token());
    }

    #[test]
    fn a_sentinel_matches_only_itself() {
        let sentinel = SessionSentinel::generate().unwrap();
        assert!(sentinel.matches(sentinel.token().as_bytes()));
        assert!(!sentinel.matches(b""));
        assert!(!sentinel.matches(b"sk-foreign-key"));
        let mut near = sentinel.token().to_owned();
        near.pop();
        near.push(if sentinel.token().ends_with('0') {
            '1'
        } else {
            '0'
        });
        assert_eq!(near.len(), sentinel.token().len());
        assert!(!sentinel.matches(near.as_bytes()));
        assert!(!sentinel.matches(&sentinel.token().as_bytes()[..10]));
    }

    #[test]
    fn a_token_of_the_wrong_shape_is_not_a_sentinel() {
        for token in [
            "",
            "amq-egress-session-",
            "sk-ant-something",
            &format!(
                "{SENTINEL_PREFIX}{}",
                "z".repeat(SENTINEL_ENTROPY_BYTES * 2)
            ),
            &format!(
                "{SENTINEL_PREFIX}{}",
                "A".repeat(SENTINEL_ENTROPY_BYTES * 2)
            ),
            &format!("{SENTINEL_PREFIX}{}", "0".repeat(SENTINEL_ENTROPY_BYTES)),
        ] {
            assert!(
                matches!(
                    SessionSentinel::from_token(token),
                    Err(IdentityError::TokenRejected)
                ),
                "{token:?} must not parse as a sentinel"
            );
        }
    }

    #[test]
    fn a_credential_renders_the_header_its_scheme_names() {
        let key = ProviderCredential::new(CredentialScheme::ApiKeyHeader, "sk-real").unwrap();
        assert_eq!(key.header_line(), "x-api-key: sk-real");
        let bearer = ProviderCredential::new(CredentialScheme::BearerToken, "sk-real").unwrap();
        assert_eq!(bearer.header_line(), "authorization: Bearer sk-real");
    }

    #[test]
    fn a_credential_that_could_inject_a_header_line_is_refused() {
        for secret in [
            "",
            "sk\rreal",
            "sk\nreal",
            "sk\r\nx-forwarded-for: 10.0.0.1",
            "sk\treal",
            &"k".repeat(MAX_CREDENTIAL_BYTES + 1),
        ] {
            assert!(
                matches!(
                    ProviderCredential::new(CredentialScheme::ApiKeyHeader, secret),
                    Err(IdentityError::CredentialRejected)
                ),
                "{secret:?} must not become a credential"
            );
        }
    }

    #[test]
    fn a_credential_never_prints_its_secret() {
        let credential =
            ProviderCredential::new(CredentialScheme::BearerToken, "sk-super-secret").unwrap();
        let rendered = format!("{credential:?}");
        assert!(!rendered.contains("sk-super-secret"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        let sentinel = SessionSentinel::generate().unwrap();
        let rendered = format!("{sentinel:?}");
        assert!(!rendered.contains(sentinel.token()), "{rendered}");
    }

    #[test]
    fn the_ledger_keeps_the_most_recent_refusals_and_counts_all_of_them() {
        let ledger = RefusalLedger::default();
        for _ in 0..MAX_LEDGER_ENTRIES + 5 {
            ledger.record(IdentityRefusal::ForeignCredential);
        }
        let entries = ledger.entries();
        assert_eq!(entries.len(), MAX_LEDGER_ENTRIES);
        assert_eq!(entries[0].sequence, 5);
        assert_eq!(
            entries[MAX_LEDGER_ENTRIES - 1].sequence,
            MAX_LEDGER_ENTRIES as u64 + 4
        );
        assert!(entries.iter().all(|entry| entry.before_any_dial));
    }

    #[test]
    fn every_refusal_this_feature_exists_for_precedes_a_dial() {
        for refusal in [
            IdentityRefusal::ForeignCredential,
            IdentityRefusal::MissingCredential,
            IdentityRefusal::TunnelToProviderRefused,
            IdentityRefusal::AmbiguousCredential,
        ] {
            assert!(refusal.precedes_any_dial(), "{refusal}");
        }
        for refusal in [
            IdentityRefusal::UpstreamUnreachable,
            IdentityRefusal::UpstreamOutOfScope,
            IdentityRefusal::UpstreamTlsRefused,
        ] {
            assert!(!refusal.precedes_any_dial(), "{refusal}");
        }
    }
}
