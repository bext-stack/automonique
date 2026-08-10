// SPDX-License-Identifier: Elastic-2.0

//! Contract checks for R1-02 bounded domain primitives.
//!
//! Every secret used here is a synthetic literal invented for the test. The
//! suite reads no clock, resolves no name and opens no socket.

use automonique_protocol::primitives::{
    BoundedString, EpochMillis, IdDomain, OpaqueId, PublicHttpUrl, Revision, RevisionError,
    SecretText, TimeError, UrlError, ValueError,
};

#[derive(Clone, Copy, Debug)]
pub struct Tenant;
impl IdDomain for Tenant {}

#[derive(Clone, Copy, Debug)]
pub struct Actor;
impl IdDomain for Actor {}

type TenantId = OpaqueId<Tenant, 8>;
type ActorId = OpaqueId<Actor, 8>;

// ---------------------------------------------------------------- Identifier domains

#[test]
fn zero_bound_identifier_is_rejected() {
    let error = OpaqueId::<Tenant, 0>::new("t").unwrap_err();
    assert_eq!(ValueError::ZeroBound, error);
    assert_eq!("zero_bound", error.category());
}

#[test]
fn identifier_accepts_exact_byte_boundary() {
    let id = TenantId::new("12345678").expect("eight bytes is the exact ceiling");
    assert_eq!("12345678", id.as_str());
    assert_eq!("12345678", id.to_string());
}

#[test]
fn identifier_rejects_one_byte_over_the_boundary() {
    let error = TenantId::new("123456789").unwrap_err();
    assert_eq!(
        ValueError::TooLong {
            max_bytes: 8,
            actual_bytes: 9,
        },
        error
    );
}

#[test]
fn identifier_bound_counts_utf8_bytes_not_characters() {
    // Two characters, eight UTF-8 bytes: accepted and preserved exactly.
    let id = TenantId::new("𝄞𝄞").expect("eight UTF-8 bytes is the exact ceiling");
    assert_eq!("𝄞𝄞", id.as_str());
    assert_eq!(2, id.as_str().chars().count());
    assert_eq!(8, id.as_str().len());

    // Three characters, twelve bytes: rejected rather than truncated.
    assert_eq!(
        ValueError::TooLong {
            max_bytes: 8,
            actual_bytes: 12,
        },
        TenantId::new("𝄞𝄞𝄞").unwrap_err()
    );
}

#[test]
fn identifier_rejects_empty_and_control_characters() {
    assert_eq!(ValueError::Empty, TenantId::new("").unwrap_err());
    assert_eq!(
        ValueError::ControlCharacter,
        TenantId::new("a\nb").unwrap_err()
    );
    assert_eq!(
        ValueError::ControlCharacter,
        TenantId::new("a\0b").unwrap_err()
    );
    assert_eq!(
        ValueError::ControlCharacter,
        TenantId::new("a\u{7f}b").unwrap_err()
    );
}

#[test]
fn identifier_does_not_interpret_its_contents() {
    // The layer assigns no meaning: unusual but control-free spellings survive.
    for spelling in ["../../etc", "a b", "%00", "Ω"] {
        let id = OpaqueId::<Tenant, 32>::new(spelling).expect("control-free value is opaque");
        assert_eq!(spelling, id.as_str());
    }
}

#[test]
fn unlike_domains_are_distinct_values() {
    // The compile-fail doctest on OpaqueId proves the types cannot be assigned
    // to one another; this proves they are separate values at runtime too.
    let tenant = TenantId::new("shared").expect("valid");
    let actor = ActorId::new("shared").expect("valid");
    assert_eq!(tenant.as_str(), actor.as_str());
    assert_eq!(TenantId::MAX_BYTES, ActorId::MAX_BYTES);
}

#[test]
fn identifier_round_trips_through_extraction() {
    let id = TenantId::new("abc").expect("valid");
    assert_eq!("abc", id.clone().into_inner());
    assert_eq!(id, TenantId::new("abc").expect("valid"));
}

// ---------------------------------------------------------------------- Text bounds

#[test]
fn text_covers_its_byte_boundaries() {
    assert_eq!(
        ValueError::ZeroBound,
        BoundedString::<0>::new("x").unwrap_err()
    );
    assert_eq!(ValueError::Empty, BoundedString::<4>::new("").unwrap_err());
    assert_eq!(
        "abcd",
        BoundedString::<4>::new("abcd").expect("exact").as_str()
    );
    assert_eq!(
        ValueError::TooLong {
            max_bytes: 4,
            actual_bytes: 5,
        },
        BoundedString::<4>::new("abcde").unwrap_err()
    );
}

#[test]
fn text_preserves_multibyte_utf8_without_truncation_or_normalization() {
    // Decomposed "é" (e + U+0301) must not be normalized into the composed form.
    let decomposed = "e\u{301}";
    let text = BoundedString::<8>::new(decomposed).expect("three bytes fits");
    assert_eq!(decomposed, text.as_str());
    assert_ne!("\u{e9}", text.as_str());
    assert_eq!(3, text.as_str().len());

    // A value one byte over is rejected, never trimmed to fit.
    let error = BoundedString::<2>::new(decomposed).unwrap_err();
    assert_eq!(
        ValueError::TooLong {
            max_bytes: 2,
            actual_bytes: 3,
        },
        error
    );
}

#[test]
fn text_rejects_control_characters() {
    for value in ["a\tb", "a\rb", "line\nbreak", "\u{9f}"] {
        assert_eq!(
            ValueError::ControlCharacter,
            BoundedString::<16>::new(value).unwrap_err(),
            "{value:?} must be rejected"
        );
    }
}

// ----------------------------------------------------------------- Time and revision

#[test]
fn timestamps_cover_negative_zero_and_positive_instants() {
    assert_eq!(0, EpochMillis::EPOCH.as_millis());
    assert_eq!((0, 0), EpochMillis::from_millis(0).to_parts());
    assert_eq!((1, 500), EpochMillis::from_millis(1_500).to_parts());
    // A negative instant keeps a non-negative remainder.
    assert_eq!((-1, 999), EpochMillis::from_millis(-1).to_parts());
    assert_eq!((-1, 0), EpochMillis::from_millis(-1_000).to_parts());
    assert_eq!((-2, 999), EpochMillis::from_millis(-1_001).to_parts());
}

#[test]
fn timestamp_parts_round_trip() {
    for millis in [-1_001_i64, -1_000, -1, 0, 1, 999, 1_000, 1_234_567_890_123] {
        let (seconds, remainder) = EpochMillis::from_millis(millis).to_parts();
        assert!(remainder <= 999);
        assert_eq!(
            EpochMillis::from_millis(millis),
            EpochMillis::from_parts(seconds, remainder).expect("round trip"),
            "{millis} must survive decomposition"
        );
    }
}

#[test]
fn timestamp_rejects_out_of_range_remainder_and_overflow() {
    assert_eq!(
        TimeError::MillisecondOutOfRange,
        EpochMillis::from_parts(0, 1_000).unwrap_err()
    );
    assert_eq!(
        TimeError::Overflow,
        EpochMillis::from_parts(i64::MAX, 0).unwrap_err()
    );
    assert_eq!(
        TimeError::Overflow,
        EpochMillis::from_millis(i64::MAX)
            .checked_add_millis(1)
            .unwrap_err()
    );
    assert_eq!(
        TimeError::Overflow,
        EpochMillis::from_millis(i64::MIN)
            .checked_add_millis(-1)
            .unwrap_err()
    );
    assert_eq!(
        TimeError::Overflow,
        EpochMillis::from_millis(i64::MAX)
            .checked_difference_millis(EpochMillis::from_millis(-1))
            .unwrap_err()
    );
}

#[test]
fn timestamp_arithmetic_is_checked_and_exact() {
    let base = EpochMillis::from_millis(1_000);
    assert_eq!(
        1_250,
        base.checked_add_millis(250).expect("in range").as_millis()
    );
    assert_eq!(
        250,
        EpochMillis::from_millis(1_250)
            .checked_difference_millis(base)
            .expect("in range")
    );
}

#[test]
fn revisions_are_non_zero_and_overflow_is_typed() {
    assert_eq!(RevisionError::Zero, Revision::new(0).unwrap_err());
    assert_eq!(1, Revision::FIRST.get());
    assert_eq!(2, Revision::FIRST.checked_next().expect("in range").get());
    assert_eq!("1", Revision::FIRST.to_string());

    let last = Revision::new(u64::MAX).expect("non-zero");
    assert_eq!(RevisionError::Overflow, last.checked_next().unwrap_err());
    // Overflow is an error rather than a wrap back to a lower revision.
    assert_eq!(u64::MAX, last.get());
}

#[test]
fn revisions_order_monotonically() {
    let first = Revision::FIRST;
    let second = first.checked_next().expect("in range");
    assert!(second > first);
}

// -------------------------------------------------------------------------- URL safety

type Url = PublicHttpUrl<64>;

#[test]
fn zero_bound_url_is_rejected() {
    assert_eq!(
        UrlError::Value(ValueError::ZeroBound),
        PublicHttpUrl::<0>::new("http://example.com").unwrap_err()
    );
}

#[test]
fn url_covers_its_exact_and_over_limit_boundaries() {
    // "http://a.com/" plus filler reaching exactly 32 bytes.
    let exact = format!("http://a.com/{}", "p".repeat(19));
    assert_eq!(32, exact.len());
    assert_eq!(
        exact,
        PublicHttpUrl::<32>::new(exact.clone())
            .expect("exact ceiling")
            .as_str()
    );

    let over = format!("{exact}p");
    assert_eq!(
        UrlError::Value(ValueError::TooLong {
            max_bytes: 32,
            actual_bytes: 33,
        }),
        PublicHttpUrl::<32>::new(over).unwrap_err()
    );
}

#[test]
fn url_accepts_dns_ipv4_and_bracketed_ipv6_hosts() {
    for value in [
        "http://example.com",
        "https://example.com",
        "https://sub.domain.example.com/path?query=1",
        "https://name-with-dash.example",
        "https://example.com:8443/path",
        "http://192.0.2.1",
        "http://192.0.2.1:80/health",
        "http://[2001:db8::1]",
        "http://[2001:db8::1]:8080/path",
        "http://[::1]",
    ] {
        let url = Url::new(value).unwrap_or_else(|error| panic!("{value:?} rejected: {error}"));
        // The accepted spelling is preserved exactly, never normalized.
        assert_eq!(value, url.as_str());
    }
}

#[test]
fn url_rejects_unsafe_and_malformed_values_offline() {
    let cases: [(&str, UrlError); 21] = [
        ("ftp://example.com", UrlError::Scheme),
        ("example.com", UrlError::Scheme),
        ("//example.com", UrlError::Scheme),
        ("HTTP://example.com", UrlError::Scheme),
        ("file:///etc/passwd", UrlError::Scheme),
        ("javascript:alert(1)", UrlError::Scheme),
        ("http://", UrlError::EmptyHost),
        ("http://:443", UrlError::EmptyHost),
        ("http://:443/path", UrlError::EmptyHost),
        ("http://user@example.com", UrlError::UserInfo),
        ("http://user:pass@example.com", UrlError::UserInfo),
        ("http://example.com#fragment", UrlError::Fragment),
        ("http://example.com\\path", UrlError::Backslash),
        ("http:\\\\example.com", UrlError::Backslash),
        ("http://exa mple.com", UrlError::Whitespace),
        ("http://example.com/a b", UrlError::Whitespace),
        ("http://exämple.com", UrlError::NonAscii),
        ("http://-example.com", UrlError::Host),
        ("http://example..com", UrlError::Host),
        ("http://example.com:0", UrlError::Port),
        ("http://example.com:65536", UrlError::Port),
    ];
    for (value, expected) in cases {
        assert_eq!(
            expected,
            Url::new(value).unwrap_err(),
            "{value:?} must be rejected"
        );
    }
}

#[test]
fn url_rejects_further_invalid_ports_and_hosts() {
    for value in [
        "http://example.com:",
        "http://example.com:80a",
        "http://example.com:+80",
        "http://example.com:080",
    ] {
        assert_eq!(
            UrlError::Port,
            Url::new(value).unwrap_err(),
            "{value:?} must be rejected"
        );
    }
    for value in [
        "http://[2001:db8::zz]",
        "http://[]",
        "http://[2001:db8::1",
        "http://2001:db8::1",
        "http://example.com]",
    ] {
        let error = Url::new(value).unwrap_err();
        assert!(
            matches!(error, UrlError::Host | UrlError::EmptyHost | UrlError::Port),
            "{value:?} must be rejected, got {error:?}"
        );
    }
}

#[test]
fn url_rejects_control_characters() {
    assert_eq!(
        UrlError::Value(ValueError::ControlCharacter),
        Url::new("http://example.com/\u{7f}").unwrap_err()
    );
}

// ----------------------------------------------------------------------- Secret safety

/// Synthetic, invented for this test. Not a credential.
const SYNTHETIC_SECRET: &str = "synthetic-not-a-real-credential";

#[test]
fn secret_rejects_zero_bound_empty_and_over_limit() {
    assert_eq!(
        ValueError::ZeroBound,
        SecretText::<0>::new("x").unwrap_err()
    );
    assert_eq!(ValueError::Empty, SecretText::<16>::new("").unwrap_err());
    assert_eq!(
        ValueError::TooLong {
            max_bytes: 4,
            actual_bytes: 5,
        },
        SecretText::<4>::new("abcde").unwrap_err()
    );
}

#[test]
fn secret_accepts_the_exact_utf8_boundary() {
    let secret = SecretText::<8>::new("𝄞𝄞").expect("eight UTF-8 bytes is the exact ceiling");
    assert_eq!("𝄞𝄞", secret.expose_secret());
    assert_eq!("𝄞𝄞", secret.into_exposed());
}

#[test]
fn secret_debug_is_a_constant_redaction() {
    let secret = SecretText::<64>::new(SYNTHETIC_SECRET).expect("valid");
    let rendered = format!("{secret:?}");
    assert!(
        !rendered.contains(SYNTHETIC_SECRET),
        "debug output leaked the secret: {rendered}"
    );
    assert!(
        rendered.contains("<redacted>"),
        "unexpected debug: {rendered}"
    );

    // Two different secrets render identically, so length is not inferable.
    let other = SecretText::<64>::new("a").expect("valid");
    assert_eq!(format!("{secret:?}"), format!("{other:?}"));
}

#[test]
fn no_secret_error_mentions_the_submitted_value() {
    let errors = [
        SecretText::<4>::new(SYNTHETIC_SECRET).unwrap_err(),
        SecretText::<0>::new(SYNTHETIC_SECRET).unwrap_err(),
        SecretText::<64>::new("").unwrap_err(),
        SecretText::<64>::new("a\nb").unwrap_err(),
    ];
    for error in errors {
        for rendered in [format!("{error}"), format!("{error:?}")] {
            assert!(
                !rendered.contains(SYNTHETIC_SECRET),
                "error leaked the secret: {rendered}"
            );
            assert!(
                !rendered.contains("a\nb"),
                "error leaked the value: {rendered}"
            );
        }
        assert!(!error.category().is_empty());
    }
}

#[test]
fn secret_reads_are_explicit() {
    let secret = SecretText::<64>::new(SYNTHETIC_SECRET).expect("valid");
    // Borrowing is explicit and extraction consumes the wrapper; the
    // compile-fail doctests prove no implicit formatting path exists.
    assert_eq!(SYNTHETIC_SECRET, secret.expose_secret());
    assert_eq!(SYNTHETIC_SECRET, secret.into_exposed());
}

#[test]
fn every_rejection_has_a_stable_category() {
    assert_eq!("zero_bound", ValueError::ZeroBound.category());
    assert_eq!("empty", ValueError::Empty.category());
    assert_eq!(
        "too_long",
        ValueError::TooLong {
            max_bytes: 1,
            actual_bytes: 2,
        }
        .category()
    );
    assert_eq!("control_character", ValueError::ControlCharacter.category());
    assert_eq!("scheme", UrlError::Scheme.category());
    assert_eq!("empty_host", UrlError::EmptyHost.category());
    assert_eq!("host", UrlError::Host.category());
    assert_eq!("port", UrlError::Port.category());
    assert_eq!("user_info", UrlError::UserInfo.category());
    assert_eq!("fragment", UrlError::Fragment.category());
    assert_eq!("backslash", UrlError::Backslash.category());
    assert_eq!("whitespace", UrlError::Whitespace.category());
    assert_eq!("non_ascii", UrlError::NonAscii.category());
    assert_eq!(
        "too_long",
        UrlError::Value(ValueError::TooLong {
            max_bytes: 1,
            actual_bytes: 2,
        })
        .category()
    );
    assert_eq!("overflow", TimeError::Overflow.category());
    assert_eq!(
        "millisecond_out_of_range",
        TimeError::MillisecondOutOfRange.category()
    );
    assert_eq!("zero_revision", RevisionError::Zero.category());
    assert_eq!("overflow", RevisionError::Overflow.category());
}
