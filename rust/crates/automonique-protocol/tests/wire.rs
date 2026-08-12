// SPDX-License-Identifier: Elastic-2.0

//! Canonical JSON and envelope decoding, closing the R1-03 wire gap.
//!
//! These cover the part of the R1-03 objective the first slice deferred:
//! decoding an envelope from frame bytes. The framing, negotiation and enum
//! rules are covered in `codec.rs`.

use automonique_protocol::codec::{
    CodecError, Envelope, FrameDecode, MAX_NESTING_DEPTH, MajorVersion, MessageKind, ProtocolName,
    RequestId, SupportedProtocol, VersionRange, decode_frame, encode_frame,
};
use automonique_protocol::wire::{JsonValue, MAX_JSON_ENTRIES, Message, parse_canonical};

fn envelope() -> Envelope {
    Envelope::new(
        ProtocolName::new("automonique.runner").expect("valid"),
        MajorVersion::new(1).expect("valid"),
        RequestId::new("req-1").expect("valid"),
        MessageKind::new("subscribe").expect("valid"),
    )
}

mod canonical_encoding {
    use super::*;

    #[test]
    fn object_keys_are_sorted_regardless_of_construction_order() {
        let forward = JsonValue::Object(vec![
            ("alpha".to_owned(), JsonValue::Integer(1)),
            ("beta".to_owned(), JsonValue::Integer(2)),
        ]);
        let reversed = JsonValue::Object(vec![
            ("beta".to_owned(), JsonValue::Integer(2)),
            ("alpha".to_owned(), JsonValue::Integer(1)),
        ]);
        assert_eq!(forward.to_canonical_bytes(), reversed.to_canonical_bytes());
        assert_eq!(forward.to_canonical_bytes(), br#"{"alpha":1,"beta":2}"#);
    }

    #[test]
    fn there_is_no_insignificant_whitespace() {
        let value = JsonValue::Array(vec![
            JsonValue::Null,
            JsonValue::Bool(true),
            JsonValue::Integer(-42),
        ]);
        assert_eq!(value.to_canonical_bytes(), b"[null,true,-42]");
    }

    #[test]
    fn escaping_is_minimal_and_fixed() {
        let value = JsonValue::String("quote\" back\\ tab\ttext\u{1}".to_owned());
        // Short forms for the named escapes; \u00xx for any other control.
        assert_eq!(
            String::from_utf8(value.to_canonical_bytes()).expect("utf-8"),
            r#""quote\" back\\ tab\ttext\u0001""#
        );
        // A forward slash is not escaped, and non-ASCII stays raw UTF-8.
        let unescaped = JsonValue::String("a/b \u{1f600}".to_owned());
        assert_eq!(
            String::from_utf8(unescaped.to_canonical_bytes()).expect("utf-8"),
            "\"a/b \u{1f600}\""
        );
    }

    #[test]
    fn every_value_round_trips_through_its_canonical_bytes() {
        let value = JsonValue::Object(vec![
            (
                "nested".to_owned(),
                JsonValue::Array(vec![
                    JsonValue::Object(vec![("k".to_owned(), JsonValue::String("v".to_owned()))]),
                    JsonValue::Integer(i64::MIN),
                    JsonValue::Integer(i64::MAX),
                ]),
            ),
            ("flag".to_owned(), JsonValue::Bool(false)),
            ("nothing".to_owned(), JsonValue::Null),
        ]);
        let bytes = value.to_canonical_bytes();
        let parsed = parse_canonical(&bytes).expect("canonical round trip");
        assert_eq!(parsed.to_canonical_bytes(), bytes);
    }

    #[test]
    fn long_ascii_and_multibyte_strings_take_the_same_lossless_path() {
        let value = JsonValue::String(format!("{}é雪😀{}", "a".repeat(512), "z".repeat(512)));
        let bytes = value.to_canonical_bytes();
        let parsed = parse_canonical(&bytes).expect("mixed UTF-8 canonical round trip");
        assert_eq!(parsed, value);
        assert_eq!(parsed.to_canonical_bytes(), bytes);
    }
}

mod strict_decoding {
    use super::*;

    #[test]
    fn non_canonical_input_is_refused_rather_than_normalized() {
        // Each of these parses as JSON but has a second, canonical spelling.
        for payload in [
            br#"{"beta":2,"alpha":1}"#.as_slice(),
            br#"{"a": 1}"#.as_slice(),
            br#"[1, 2]"#.as_slice(),
            br#"{"a":01}"#.as_slice(),
            br#"-0"#.as_slice(),
            br#""a\/b""#.as_slice(),
        ] {
            assert_eq!(
                parse_canonical(payload)
                    .expect_err("non-canonical spelling")
                    .category(),
                "non_canonical_json",
                "{}",
                String::from_utf8_lossy(payload)
            );
        }
    }

    #[test]
    fn malformed_input_is_refused() {
        for payload in [
            b"".as_slice(),
            b"{".as_slice(),
            br#"{"a"}"#.as_slice(),
            br#"{"a":}"#.as_slice(),
            b"[1,]".as_slice(),
            b"tru".as_slice(),
            b"\xff\xfe".as_slice(),
            br#""unterminated"#.as_slice(),
        ] {
            let error = parse_canonical(payload).expect_err("malformed");
            assert!(
                matches!(error, CodecError::MalformedJson | CodecError::TrailingData),
                "{} gave {error:?}",
                String::from_utf8_lossy(payload)
            );
        }
    }

    #[test]
    fn a_raw_control_character_in_a_string_is_refused() {
        assert_eq!(
            parse_canonical(b"\"a\nb\"").expect_err("raw control"),
            CodecError::MalformedJson
        );
    }

    #[test]
    fn duplicate_keys_are_refused_rather_than_letting_one_win() {
        assert_eq!(
            parse_canonical(br#"{"a":1,"a":2}"#).expect_err("duplicate key"),
            CodecError::DuplicateKey
        );
    }

    #[test]
    fn trailing_data_after_a_complete_value_is_refused() {
        assert_eq!(
            parse_canonical(b"{}{}").expect_err("trailing"),
            CodecError::TrailingData
        );
        assert_eq!(
            parse_canonical(b"1 ").expect_err("trailing whitespace"),
            CodecError::NonCanonicalJson
        );
    }

    #[test]
    fn non_integer_numbers_are_refused() {
        for payload in [b"1.5".as_slice(), b"1e3".as_slice(), b"-2.0".as_slice()] {
            assert_eq!(
                parse_canonical(payload).expect_err("float").category(),
                "invalid_json_value",
                "{}",
                String::from_utf8_lossy(payload)
            );
        }
    }

    #[test]
    fn an_integer_beyond_signed_64_bits_is_refused() {
        assert_eq!(
            parse_canonical(b"9223372036854775808").expect_err("overflow"),
            CodecError::IntegerOutOfRange
        );
        assert_eq!(
            parse_canonical(b"9223372036854775807").expect("i64::MAX"),
            JsonValue::Integer(i64::MAX)
        );
    }

    #[test]
    fn nesting_beyond_the_ceiling_is_refused_at_a_known_depth() {
        let deep = format!(
            "{}{}",
            "[".repeat(MAX_NESTING_DEPTH + 1),
            "]".repeat(MAX_NESTING_DEPTH + 1)
        );
        assert_eq!(
            parse_canonical(deep.as_bytes()).expect_err("too deep"),
            CodecError::NestingTooDeep {
                max_depth: MAX_NESTING_DEPTH,
            }
        );

        // Exactly at the ceiling still parses.
        let at_limit = format!(
            "{}{}",
            "[".repeat(MAX_NESTING_DEPTH),
            "]".repeat(MAX_NESTING_DEPTH)
        );
        parse_canonical(at_limit.as_bytes()).expect("at the ceiling");
    }

    #[test]
    fn an_oversized_container_is_refused() {
        let entries: Vec<String> = (0..=MAX_JSON_ENTRIES).map(|n| n.to_string()).collect();
        let payload = format!("[{}]", entries.join(","));
        assert_eq!(
            parse_canonical(payload.as_bytes()).expect_err("too many entries"),
            CodecError::TooManyEntries {
                max: MAX_JSON_ENTRIES,
            }
        );
    }
}

mod envelope_decoding {
    use super::*;

    #[test]
    fn an_envelope_round_trips_through_a_frame() {
        let message = Message::new(
            envelope(),
            JsonValue::Object(vec![("after".to_owned(), JsonValue::Integer(42))]),
        );
        let payload = message.to_canonical_bytes();

        let mut framed = Vec::new();
        encode_frame(&payload, &mut framed).expect("within bounds");
        let decoded_payload = match decode_frame(&framed).expect("frame decodes") {
            FrameDecode::Frame { payload, .. } => payload,
            FrameDecode::NeedMore { .. } => panic!("complete frame reported incomplete"),
        };

        let decoded = Message::from_canonical_bytes(decoded_payload).expect("message decodes");
        assert_eq!(decoded.envelope().protocol().as_str(), "automonique.runner");
        assert_eq!(decoded.envelope().version().get(), 1);
        assert_eq!(decoded.envelope().request_id().as_str(), "req-1");
        assert_eq!(decoded.envelope().kind().as_str(), "subscribe");
        assert_eq!(
            decoded.body().get("after").and_then(JsonValue::as_integer),
            Some(42)
        );
        assert_eq!(decoded, message);
    }

    #[test]
    fn a_missing_envelope_field_is_named() {
        for (payload, field) in [
            (
                br#"{"body":{},"kind":"subscribe","request_id":"r","version":1}"#.as_slice(),
                "protocol",
            ),
            (
                br#"{"body":{},"kind":"subscribe","protocol":"automonique.runner","version":1}"#
                    .as_slice(),
                "request_id",
            ),
            (
                br#"{"body":{},"protocol":"automonique.runner","request_id":"r","version":1}"#
                    .as_slice(),
                "kind",
            ),
            (
                br#"{"body":{},"kind":"subscribe","protocol":"automonique.runner","request_id":"r"}"#
                    .as_slice(),
                "version",
            ),
            (
                br#"{"kind":"subscribe","protocol":"automonique.runner","request_id":"r","version":1}"#
                    .as_slice(),
                "body",
            ),
        ] {
            assert_eq!(
                Message::from_canonical_bytes(payload).expect_err("missing field"),
                CodecError::MissingField { field },
            );
        }
    }

    #[test]
    fn a_wrongly_typed_envelope_field_is_named() {
        let payload =
            br#"{"body":{},"kind":"subscribe","protocol":1,"request_id":"r","version":1}"#;
        assert_eq!(
            Message::from_canonical_bytes(payload).expect_err("wrong type"),
            CodecError::InvalidJsonValue { field: "protocol" }
        );
    }

    #[test]
    fn envelope_field_grammar_still_applies_after_decoding() {
        let payload =
            br#"{"body":{},"kind":"Subscribe","protocol":"automonique.runner","request_id":"r","version":1}"#;
        assert_eq!(
            Message::from_canonical_bytes(payload)
                .expect_err("uppercase kind")
                .category(),
            "field_grammar"
        );
    }

    #[test]
    fn version_zero_is_refused_after_decoding() {
        let payload =
            br#"{"body":{},"kind":"subscribe","protocol":"automonique.runner","request_id":"r","version":0}"#;
        assert_eq!(
            Message::from_canonical_bytes(payload)
                .expect_err("zero version")
                .category(),
            "field_invalid"
        );
    }

    #[test]
    fn an_envelope_body_survives_a_field_this_build_does_not_define() {
        let payload = br#"{"body":{"after":1,"future_field":"tolerated"},"kind":"subscribe","protocol":"automonique.runner","request_id":"r","version":1}"#;
        let decoded = Message::from_canonical_bytes(payload).expect("additive fields decode");
        assert_eq!(
            decoded
                .body()
                .get("future_field")
                .and_then(JsonValue::as_str),
            Some("tolerated")
        );
        assert_eq!(decoded.to_canonical_bytes(), payload);
    }

    #[test]
    fn no_refusal_echoes_the_payload() {
        let secret = "s3cr3t-token";
        let payload = format!(
            r#"{{"body":{{"token":"{secret}"}},"kind":"Subscribe","protocol":"automonique.runner","request_id":"r","version":1}}"#
        );
        let error = Message::from_canonical_bytes(payload.as_bytes()).expect_err("bad kind");
        assert!(!error.to_string().contains(secret));
    }
}

/// Admission: what a peer implements, decided after the message is understood
/// and never guessed.
mod envelope_admission {
    use super::*;

    fn supported(name: &str, min: u32, max: u32) -> SupportedProtocol {
        SupportedProtocol::new(
            ProtocolName::new(name).expect("valid name"),
            VersionRange::new(
                MajorVersion::new(min).expect("valid"),
                MajorVersion::new(max).expect("valid"),
            )
            .expect("range is not inverted"),
        )
    }

    fn envelope_payload(protocol: &str, version: u32) -> String {
        format!(
            r#"{{"body":{{}},"kind":"subscribe","protocol":"{protocol}","request_id":"r","version":{version}}}"#
        )
    }

    #[test]
    fn an_implemented_protocol_at_a_supported_version_is_admitted() {
        let payload = envelope_payload("automonique.runner", 2);
        let decoded = Message::from_canonical_bytes_admitted(
            payload.as_bytes(),
            &[supported("automonique.runner", 1, 3)],
        )
        .expect("admitted");
        assert_eq!(decoded.envelope().protocol().as_str(), "automonique.runner");
        assert_eq!(decoded.envelope().version().get(), 2);
    }

    #[test]
    fn a_protocol_this_peer_does_not_implement_is_refused() {
        let payload = envelope_payload("automonique.unimplemented", 1);
        assert_eq!(
            Message::from_canonical_bytes_admitted(
                payload.as_bytes(),
                &[supported("automonique.runner", 1, 1)],
            )
            .expect_err("unimplemented protocol"),
            CodecError::UnknownProtocol
        );
    }

    #[test]
    fn a_major_version_outside_the_range_is_refused_naming_the_range() {
        let payload = envelope_payload("automonique.runner", 4);
        assert_eq!(
            Message::from_canonical_bytes_admitted(
                payload.as_bytes(),
                &[supported("automonique.runner", 1, 3)],
            )
            .expect_err("unsupported major"),
            CodecError::UnsupportedVersion {
                supported_min: 1,
                supported_max: 3,
                offered: 4,
            }
        );
    }

    #[test]
    fn the_two_negotiation_axes_stay_distinct() {
        // A version refusal must not be reported as an unknown protocol, and an
        // unknown protocol must not be reported as a version mismatch: a peer
        // upgrades in response to one and not the other.
        let unknown = envelope_payload("automonique.other", 1);
        let outdated = envelope_payload("automonique.runner", 9);
        let peer = [supported("automonique.runner", 1, 3)];
        assert_eq!(
            Message::from_canonical_bytes_admitted(unknown.as_bytes(), &peer)
                .expect_err("unknown")
                .category(),
            "unknown_protocol"
        );
        assert_eq!(
            Message::from_canonical_bytes_admitted(outdated.as_bytes(), &peer)
                .expect_err("outdated")
                .category(),
            "unsupported_version"
        );
    }

    #[test]
    fn an_empty_supported_set_implements_nothing() {
        let payload = envelope_payload("automonique.runner", 1);
        assert_eq!(
            Message::from_canonical_bytes_admitted(payload.as_bytes(), &[])
                .expect_err("nothing is implemented"),
            CodecError::UnknownProtocol
        );
    }

    #[test]
    fn another_entry_does_not_mask_a_version_refusal() {
        // The entry that carries the name owns the verdict, wherever it sits in
        // the list; entries that do not carry it must not turn a version
        // refusal back into an unknown protocol.
        let payload = envelope_payload("automonique.runner", 9);
        for peer in [
            [
                supported("automonique.other", 1, 1),
                supported("automonique.runner", 1, 3),
            ],
            [
                supported("automonique.runner", 1, 3),
                supported("automonique.other", 1, 1),
            ],
        ] {
            assert_eq!(
                Message::from_canonical_bytes_admitted(payload.as_bytes(), &peer)
                    .expect_err("unsupported major"),
                CodecError::UnsupportedVersion {
                    supported_min: 1,
                    supported_max: 3,
                    offered: 9,
                }
            );
        }
    }

    #[test]
    fn shape_is_settled_before_negotiation() {
        // Every one of these names an unimplemented protocol as well as being
        // malformed. A peer told its protocol is unknown when its message is
        // what is broken would change the wrong thing.
        for (payload, expected) in [
            (
                r#"{"body":{},"kind":"subscribe","protocol":"automonique.unimplemented","request_id":"r"}"#,
                "missing_field",
            ),
            (
                r#"{"body":{},"kind":"Subscribe","protocol":"automonique.unimplemented","request_id":"r","version":1}"#,
                "field_grammar",
            ),
            (
                r#"{"body":{},"kind":"subscribe","protocol":"automonique.unimplemented","request_id":"r","version":0}"#,
                "field_invalid",
            ),
            (
                r#"{"body":{}, "kind":"subscribe","protocol":"automonique.unimplemented","request_id":"r","version":1}"#,
                "non_canonical_json",
            ),
        ] {
            assert_eq!(
                Message::from_canonical_bytes_admitted(
                    payload.as_bytes(),
                    &[supported("automonique.runner", 1, 1)],
                )
                .expect_err("shape refusal")
                .category(),
                expected,
                "{payload}"
            );
        }
    }
}
