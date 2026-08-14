// SPDX-License-Identifier: Elastic-2.0

//! The origin lock and the fleet instance identity.
//!
//! [`FleetBase`] is the whole of what a caller may say about *where* this
//! connector points. It admits an origin — scheme, host, optional port — and
//! refuses everything that could follow one: a path, a query, a fragment, or
//! userinfo. The request path itself is a private constant in `client`, so the
//! full URL is the base and one string this crate owns.

use std::fmt;

use crate::FleetRefusal;

/// Longest origin accepted, before parsing.
const MAX_BASE_BYTES: usize = 253 + 16;
/// Longest host label, per DNS.
const MAX_LABEL_BYTES: usize = 63;
/// Longest host name, per DNS.
const MAX_HOST_BYTES: usize = 253;
/// Longest opaque identifier accepted as an instance or action id.
pub const MAX_FLEET_IDENTIFIER_BYTES: usize = 120;

/// A validated fleet origin.
///
/// # What is admitted
///
/// * `https://<dns-host>` with an optional `:<port>`, which is the production
///   shape, and
/// * `http://127.0.0.1[:<port>]` or `http://[::1][:<port>]`, which is the only
///   plaintext shape and cannot address anything off this host.
///
/// The loopback exception exists so the connector's wire behaviour — its
/// header, its envelope, its decoders — is provable against an in-process fake
/// without a certificate. It is safe by construction rather than by policy: the
/// two literals it admits are not routable off-box, and no name that could
/// resolve elsewhere is accepted with `http`. A plaintext base marks itself as
/// such so the HTTP agent built from it is the only one that ever relaxes
/// `https_only`.
#[derive(Clone, Eq, PartialEq)]
pub struct FleetBase {
    origin: String,
    plaintext_loopback: bool,
}

impl FleetBase {
    /// Validate one origin.
    ///
    /// A single trailing `/` is accepted and dropped, matching how the legacy
    /// client normalizes its configured URL. Anything further — a path segment,
    /// a `?`, a `#`, or `user@host` — is refused rather than trimmed, because
    /// silently discarding part of a configured URL is how a connector ends up
    /// addressing a host nobody configured.
    ///
    /// # Errors
    ///
    /// Returns [`FleetRefusal::Base`] for any origin outside the two admitted
    /// shapes.
    pub fn new(base: &str) -> Result<Self, FleetRefusal> {
        if base.is_empty() || base.len() > MAX_BASE_BYTES || !base.is_ascii() {
            return Err(FleetRefusal::Base);
        }
        let (scheme, remainder) = split_scheme(base).ok_or(FleetRefusal::Base)?;
        let authority = remainder.strip_suffix('/').unwrap_or(remainder);
        if authority.is_empty()
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
            || authority.contains('@')
            || authority.contains('\\')
        {
            return Err(FleetRefusal::Base);
        }
        let (host, port) = split_port(authority).ok_or(FleetRefusal::Base)?;

        let plaintext_loopback = match scheme {
            Scheme::Https => {
                if !is_dns_host(host) {
                    return Err(FleetRefusal::Base);
                }
                false
            }
            // Only the two loopback literals, never a name that a resolver
            // could point somewhere else.
            Scheme::Http => {
                if !matches!(host, "127.0.0.1" | "[::1]") {
                    return Err(FleetRefusal::Base);
                }
                true
            }
        };

        let mut origin = String::with_capacity(authority.len() + 8);
        origin.push_str(scheme.as_str());
        origin.push_str("://");
        origin.push_str(host);
        if let Some(port) = port {
            origin.push(':');
            origin.push_str(&port.to_string());
        }
        Ok(Self {
            origin,
            plaintext_loopback,
        })
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
impl fmt::Debug for FleetBase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FleetBase")
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

impl Scheme {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Http => "http",
        }
    }
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

/// Whether a host is a DNS name this connector may address over TLS.
///
/// Labels are alphanumeric with interior hyphens. A bare label is refused: the
/// fleet is a public service reached by a dotted name, and accepting a
/// single-label host would let a search-domain suffix decide the destination.
/// An IP literal is refused too — a certificate for one is not how this service
/// is deployed, and pinning the connector to names keeps the target lock
/// readable in configuration.
fn is_dns_host(host: &str) -> bool {
    if host.is_empty() || host.len() > MAX_HOST_BYTES || !host.contains('.') {
        return false;
    }
    let mut labels = 0_usize;
    for label in host.split('.') {
        labels += 1;
        if label.is_empty()
            || label.len() > MAX_LABEL_BYTES
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return false;
        }
    }
    // The last label of a public name is never all-digits; refusing that here
    // is what keeps a dotted IPv4 literal out.
    labels >= 2
        && !host
            .rsplit('.')
            .next()
            .is_some_and(|last| last.bytes().all(|byte| byte.is_ascii_digit()))
}

/// The fleet's identity for this Automonique instance.
///
/// Every support action carries it as the envelope's `id`. It is an opaque
/// bounded identifier, not a credential: the legacy client prints its first
/// eight characters at startup, so it is rendered by `Debug` here too. The
/// grammar excludes the quote and backslash bytes that would otherwise have to
/// survive JSON escaping to stay unambiguous in a captured request.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FleetInstanceId(String);

impl FleetInstanceId {
    /// Construct a bounded opaque instance identity.
    ///
    /// # Errors
    ///
    /// Returns [`FleetRefusal::InstanceId`] when the value is empty, longer
    /// than [`MAX_FLEET_IDENTIFIER_BYTES`], or outside the identifier grammar.
    pub fn new(value: &str) -> Result<Self, FleetRefusal> {
        if is_opaque_identifier(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(FleetRefusal::InstanceId)
        }
    }

    /// The exact wire value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether a value is a bounded opaque identifier.
///
/// ASCII graphic bytes only, excluding the JSON string metacharacters that make
/// a captured envelope ambiguous to read.
pub(crate) fn is_opaque_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_FLEET_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_production_origin_is_normalized_and_stays_tls_locked() {
        let base = FleetBase::new("https://manage.example.com/").expect("base");
        assert_eq!(base.origin(), "https://manage.example.com");
        assert!(!base.is_plaintext_loopback());

        // The scheme is case-insensitive; the normalized rendering is not.
        let upper = FleetBase::new("HTTPS://manage.example.com").expect("base");
        assert_eq!(upper.origin(), "https://manage.example.com");

        let ported = FleetBase::new("https://support.example.com:8443").expect("base");
        assert_eq!(ported.origin(), "https://support.example.com:8443");
    }

    #[test]
    fn only_the_two_loopback_literals_may_be_plaintext() {
        for admitted in [
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
            "http://127.0.0.1",
        ] {
            let base = FleetBase::new(admitted).expect(admitted);
            assert!(base.is_plaintext_loopback(), "{admitted}");
        }
        for refused in [
            "http://manage.example.com",
            "http://localhost:8080",
            "http://10.0.0.7:8080",
            "http://127.0.0.2:8080",
            "http://0.0.0.0:8080",
        ] {
            assert_eq!(
                FleetBase::new(refused).err(),
                Some(FleetRefusal::Base),
                "must refuse {refused}"
            );
        }
    }

    #[test]
    fn nothing_after_the_origin_is_accepted() {
        for refused in [
            "https://manage.example.com/api",
            "https://manage.example.com/api/manage/shelldeck/fleet",
            "https://manage.example.com/?a=1",
            "https://manage.example.com/#frag",
            "https://manage.example.com?a=1",
            "https://manage.example.com#frag",
            "https://user:pass@manage.example.com",
            "https://manage.example.com\\@evil.example",
            "https://manage.example.com//",
            "//manage.example.com",
            "manage.example.com",
            "ftp://manage.example.com",
            "file://etc/passwd",
            "",
        ] {
            assert_eq!(
                FleetBase::new(refused).err(),
                Some(FleetRefusal::Base),
                "must refuse {refused:?}"
            );
        }
    }

    #[test]
    fn a_tls_host_must_be_a_dotted_dns_name() {
        assert!(FleetBase::new("https://a.b").is_ok());
        assert!(FleetBase::new("https://sub-domain.example.com").is_ok());
        for refused in [
            "https://intranet",
            "https://.example.com",
            "https://example..com",
            "https://-lead.example.com",
            "https://trail-.example.com",
            "https://93.184.216.34",
            "https://[::1]",
            "https://he\u{301}berge.example",
        ] {
            assert_eq!(
                FleetBase::new(refused).err(),
                Some(FleetRefusal::Base),
                "must refuse {refused}"
            );
        }
    }

    #[test]
    fn a_port_has_exactly_one_spelling() {
        assert!(FleetBase::new("https://a.b:1").is_ok());
        assert!(FleetBase::new("https://a.b:65535").is_ok());
        for refused in [
            "https://a.b:0",
            "https://a.b:00",
            "https://a.b:080",
            "https://a.b:65536",
            "https://a.b:",
            "https://a.b:port",
            "https://a.b:-1",
        ] {
            assert_eq!(
                FleetBase::new(refused).err(),
                Some(FleetRefusal::Base),
                "must refuse {refused}"
            );
        }
    }

    #[test]
    fn an_instance_id_is_bounded_and_unambiguous_in_an_envelope() {
        let id = FleetInstanceId::new("sd-instance-01").expect("instance");
        assert_eq!(id.as_str(), "sd-instance-01");
        for refused in [
            "",
            "with space",
            "quote\"inside",
            "back\\slash",
            "newline\nafter",
            "accentue\u{301}",
        ] {
            assert_eq!(
                FleetInstanceId::new(refused).err(),
                Some(FleetRefusal::InstanceId),
                "must refuse {refused:?}"
            );
        }
        assert!(FleetInstanceId::new(&"i".repeat(MAX_FLEET_IDENTIFIER_BYTES)).is_ok());
        assert_eq!(
            FleetInstanceId::new(&"i".repeat(MAX_FLEET_IDENTIFIER_BYTES + 1)).err(),
            Some(FleetRefusal::InstanceId)
        );
    }
}
