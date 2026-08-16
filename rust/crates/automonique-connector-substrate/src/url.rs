// SPDX-License-Identifier: Elastic-2.0

//! Splitting a base URL into the parts a connector target is built from.
//!
//! Not a URL parser. It reads the two pieces every connector needs from a
//! configured base — the scheme and an optional port — and refuses anything it
//! is not certain about, which is what a target ceiling wants: a base that
//! cannot be read exactly is a misconfiguration, not something to guess at.

/// The two transport schemes a connector base may name.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Scheme {
    /// `https`.
    Https,
    /// `http`.
    Http,
}

impl Scheme {
    /// The canonical lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Http => "http",
        }
    }
}

/// Split a scheme prefix, case-insensitively as RFC 3986 requires.
#[must_use]
pub fn split_scheme(base: &str) -> Option<(Scheme, &str)> {
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
#[must_use]
pub fn split_port(authority: &str) -> Option<(&str, Option<u16>)> {
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

#[cfg(test)]
mod tests {
    use super::*;

    mod schemes {
        use super::*;

        #[test]
        fn both_schemes_split_off_their_remainder() {
            assert_eq!(
                split_scheme("https://example.invalid/path"),
                Some((Scheme::Https, "example.invalid/path"))
            );
            assert_eq!(
                split_scheme("http://example.invalid"),
                Some((Scheme::Http, "example.invalid"))
            );
        }

        /// RFC 3986 makes the scheme case-insensitive, and a configured base is
        /// typed by a person.
        #[test]
        fn the_scheme_is_matched_without_regard_to_case() {
            for base in ["HTTPS://host", "HttpS://host", "hTTps://host"] {
                assert_eq!(split_scheme(base), Some((Scheme::Https, "host")), "{base}");
            }
            assert_eq!(split_scheme("HTTP://host"), Some((Scheme::Http, "host")));
        }

        #[test]
        fn any_other_scheme_is_refused() {
            for base in [
                "ftp://host",
                "ws://host",
                "wss://host",
                "file:///tmp",
                "javascript://host",
                "httpss://host",
                "shttp://host",
            ] {
                assert_eq!(split_scheme(base), None, "{base}");
            }
        }

        #[test]
        fn a_base_without_a_scheme_is_refused() {
            for base in ["example.invalid", "", "//example.invalid", "https:/host"] {
                assert_eq!(split_scheme(base), None, "{base}");
            }
        }

        #[test]
        fn an_empty_remainder_is_still_a_split() {
            assert_eq!(split_scheme("https://"), Some((Scheme::Https, "")));
        }

        #[test]
        fn the_canonical_spelling_is_lowercase() {
            assert_eq!(Scheme::Https.as_str(), "https");
            assert_eq!(Scheme::Http.as_str(), "http");
        }
    }

    mod ports {
        use super::*;

        #[test]
        fn an_authority_without_a_port_keeps_its_whole_host() {
            assert_eq!(
                split_port("example.invalid"),
                Some(("example.invalid", None))
            );
        }

        #[test]
        fn a_port_is_split_off() {
            assert_eq!(
                split_port("example.invalid:8443"),
                Some(("example.invalid", Some(8443)))
            );
            assert_eq!(split_port("host:1"), Some(("host", Some(1))));
            assert_eq!(split_port("host:65535"), Some(("host", Some(65535))));
        }

        /// The colons inside an IPv6 literal are part of the address, and a
        /// splitter that took the first one would silently rewrite the host.
        #[test]
        fn an_ipv6_literal_keeps_its_own_colons() {
            assert_eq!(split_port("[::1]"), Some(("[::1]", None)));
            assert_eq!(split_port("[::1]:8443"), Some(("[::1]", Some(8443))));
            assert_eq!(
                split_port("[2001:db8::dead:beef]:443"),
                Some(("[2001:db8::dead:beef]", Some(443)))
            );
        }

        #[test]
        fn an_unterminated_ipv6_literal_is_refused() {
            assert_eq!(split_port("[::1"), None);
        }

        /// A port with a leading zero has a second spelling, and `:0` names no
        /// port at all.
        #[test]
        fn a_port_with_no_single_spelling_is_refused() {
            for authority in ["host:0", "host:00", "host:080", "host:0443"] {
                assert_eq!(split_port(authority), None, "{authority}");
            }
        }

        #[test]
        fn a_port_outside_the_sixteen_bit_range_is_refused() {
            for authority in ["host:65536", "host:99999", "host:123456"] {
                assert_eq!(split_port(authority), None, "{authority}");
            }
        }

        #[test]
        fn a_port_that_is_not_decimal_digits_is_refused() {
            for authority in ["host:", "host:http", "host:8a43", "host:-1", "host:84 43"] {
                assert_eq!(split_port(authority), None, "{authority}");
            }
        }
    }
}
