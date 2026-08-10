// SPDX-License-Identifier: Elastic-2.0

//! R1-03 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-03.md`.

use automonique_protocol::codec::{
    CodecError, DepthGuard, Envelope, FrameDecode, LENGTH_PREFIX_BYTES, MAX_ENUM_VALUE_BYTES,
    MAX_FRAME_BYTES, MAX_MESSAGE_KIND_BYTES, MAX_NESTING_DEPTH, MAX_PROTOCOL_NAME_BYTES,
    MajorVersion, MessageKind, ProtocolName, ReadOnly, ReadOnlyEnum, RequestId,
    SecuritySensitiveEnum, SpoolReference, SupportedProtocol, VersionRange, decode_frame,
    decode_read_only_enum, decode_security_enum, encode_frame,
};
use automonique_protocol::primitives::ValueError;

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_frame(payload, &mut out).expect("payload is within bounds");
    out
}

/// Collect every frame available in `input`, returning the payloads and the
/// bytes left unconsumed.
fn drain(input: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let mut payloads = Vec::new();
    let mut cursor = 0;
    loop {
        match decode_frame(&input[cursor..]).expect("frames are well formed") {
            FrameDecode::Frame { payload, consumed } => {
                payloads.push(payload.to_vec());
                cursor += consumed;
            }
            FrameDecode::NeedMore { .. } => return (payloads, input.len() - cursor),
        }
    }
}

mod frame_boundaries {
    use super::*;

    #[test]
    fn exact_limit_round_trips() {
        let payload = vec![0x5a_u8; MAX_FRAME_BYTES];
        let encoded = frame(&payload);
        assert_eq!(encoded.len(), LENGTH_PREFIX_BYTES + MAX_FRAME_BYTES);
        match decode_frame(&encoded).expect("exact-limit frame decodes") {
            FrameDecode::Frame { payload: got, .. } => assert_eq!(got, payload.as_slice()),
            FrameDecode::NeedMore { .. } => panic!("complete frame reported as incomplete"),
        }
    }

    #[test]
    fn one_byte_over_the_limit_is_refused_on_encode() {
        let payload = vec![0_u8; MAX_FRAME_BYTES + 1];
        let error = encode_frame(&payload, &mut Vec::new()).expect_err("over-limit is refused");
        assert_eq!(error.category(), "frame_too_large");
    }

    #[test]
    fn zero_length_is_refused_in_both_directions() {
        assert_eq!(
            encode_frame(&[], &mut Vec::new()).expect_err("empty payload is refused"),
            CodecError::EmptyFrame
        );
        let mut zero = 0_u32.to_be_bytes().to_vec();
        zero.push(0xff);
        assert_eq!(
            decode_frame(&zero).expect_err("zero-length declaration is refused"),
            CodecError::EmptyFrame
        );
    }

    #[test]
    fn concatenated_frames_decode_identically_under_every_chunking() {
        let expected: Vec<Vec<u8>> = vec![
            b"first".to_vec(),
            vec![0x00, 0xff, 0x0a, 0x0d],
            "\u{1f600} multibyte".as_bytes().to_vec(),
        ];
        let mut stream = Vec::new();
        for payload in &expected {
            stream.extend_from_slice(&frame(payload));
        }

        let (whole, remainder) = drain(&stream);
        assert_eq!(whole, expected);
        assert_eq!(remainder, 0);

        // Feeding one byte at a time must produce the same sequence.
        let mut buffered: Vec<u8> = Vec::new();
        let mut incremental: Vec<Vec<u8>> = Vec::new();
        for byte in &stream {
            buffered.push(*byte);
            let (ready, _) = drain(&buffered);
            if ready.len() > incremental.len() {
                incremental = ready;
            }
        }
        assert_eq!(incremental, expected);

        // And so must every fixed chunk width.
        for width in 1..=stream.len() {
            let mut buffered = Vec::new();
            let mut collected: Vec<Vec<u8>> = Vec::new();
            for chunk in stream.chunks(width) {
                buffered.extend_from_slice(chunk);
                let (ready, _) = drain(&buffered);
                if ready.len() > collected.len() {
                    collected = ready;
                }
            }
            assert_eq!(
                collected, expected,
                "chunk width {width} changed the result"
            );
        }
    }
}

mod partial_input {
    use super::*;

    #[test]
    fn truncated_prefix_reports_the_exact_remaining_count() {
        let encoded = frame(b"payload");
        for available in 0..LENGTH_PREFIX_BYTES {
            match decode_frame(&encoded[..available]).expect("partial prefix is not an error") {
                FrameDecode::NeedMore { additional } => {
                    assert_eq!(additional.get(), LENGTH_PREFIX_BYTES - available);
                }
                FrameDecode::Frame { .. } => panic!("partial prefix yielded a frame"),
            }
        }
    }

    #[test]
    fn truncated_body_reports_the_exact_remaining_count_and_consumes_nothing() {
        let encoded = frame(b"payload");
        for available in LENGTH_PREFIX_BYTES..encoded.len() {
            match decode_frame(&encoded[..available]).expect("partial body is not an error") {
                FrameDecode::NeedMore { additional } => {
                    assert_eq!(additional.get(), encoded.len() - available);
                }
                FrameDecode::Frame { .. } => panic!("partial body yielded a frame"),
            }
        }
    }

    #[test]
    fn a_trailing_partial_frame_leaves_the_complete_one_intact() {
        let mut stream = frame(b"complete");
        stream.extend_from_slice(&frame(b"incomplete")[..3]);
        let (payloads, remainder) = drain(&stream);
        assert_eq!(payloads, vec![b"complete".to_vec()]);
        assert_eq!(remainder, 3);
    }
}

mod allocation_safety {
    use super::*;

    #[test]
    fn an_oversized_prefix_is_refused_before_the_body_is_considered() {
        // Four bytes of prefix claiming ~4 GiB, with no body at all. A decoder
        // that sized a buffer from the prefix would fail here rather than
        // returning a typed refusal.
        let hostile = u32::MAX.to_be_bytes();
        let error = decode_frame(&hostile).expect_err("oversized declaration is refused");
        match error {
            CodecError::FrameTooLarge {
                max_bytes,
                declared_bytes,
            } => {
                assert_eq!(max_bytes, MAX_FRAME_BYTES);
                assert_eq!(declared_bytes, u32::MAX as usize);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn the_refusal_does_not_depend_on_available_input() {
        let mut hostile = (MAX_FRAME_BYTES as u32 + 1).to_be_bytes().to_vec();
        hostile.extend_from_slice(b"only a few real bytes");
        assert_eq!(
            decode_frame(&hostile)
                .expect_err("over-limit declaration is refused")
                .category(),
            "frame_too_large"
        );
    }
}

mod envelope_negotiation {
    use super::*;

    fn version(value: u32) -> MajorVersion {
        MajorVersion::new(value).expect("non-zero version")
    }

    fn envelope(protocol: &str, major: u32) -> Envelope {
        Envelope::new(
            ProtocolName::new(protocol).expect("valid protocol name"),
            version(major),
            RequestId::new("req-1").expect("valid request id"),
            MessageKind::new("subscribe").expect("valid kind"),
        )
    }

    fn runner() -> SupportedProtocol {
        SupportedProtocol::new(
            ProtocolName::new("automonique.runner").expect("valid protocol name"),
            VersionRange::new(version(1), version(3)).expect("ordered range"),
        )
    }

    #[test]
    fn unknown_protocol_and_unsupported_version_are_distinct_failures() {
        let unknown = runner()
            .admit(&envelope("automonique.other", 1))
            .expect_err("unknown protocol fails closed");
        assert_eq!(unknown, CodecError::UnknownProtocol);

        let unsupported = runner()
            .admit(&envelope("automonique.runner", 9))
            .expect_err("unsupported version fails closed");
        assert_eq!(
            unsupported,
            CodecError::UnsupportedVersion {
                supported_min: 1,
                supported_max: 3,
                offered: 9,
            }
        );
        assert_ne!(unknown.wire_code(), unsupported.wire_code());
    }

    #[test]
    fn a_supported_envelope_is_admitted() {
        for major in 1..=3 {
            runner()
                .admit(&envelope("automonique.runner", major))
                .expect("in-range version is admitted");
        }
    }

    #[test]
    fn overlapping_ranges_resolve_to_the_highest_common_version() {
        let local = VersionRange::new(version(1), version(4)).expect("ordered");
        let peer = VersionRange::new(version(3), version(7)).expect("ordered");
        assert_eq!(local.negotiate(peer).expect("ranges overlap").get(), 4);
        assert_eq!(peer.negotiate(local).expect("ranges overlap").get(), 4);

        let identical = VersionRange::exact(version(2));
        assert_eq!(
            identical
                .negotiate(identical)
                .expect("identical ranges")
                .get(),
            2
        );
    }

    #[test]
    fn disjoint_ranges_fail_naming_both_operands() {
        let local = VersionRange::new(version(1), version(2)).expect("ordered");
        let peer = VersionRange::new(version(5), version(6)).expect("ordered");
        assert_eq!(
            local.negotiate(peer).expect_err("disjoint ranges"),
            CodecError::NoVersionOverlap {
                local_min: 1,
                local_max: 2,
                peer_min: 5,
                peer_max: 6,
            }
        );
    }

    #[test]
    fn an_inverted_range_fails_at_construction() {
        assert_eq!(
            VersionRange::new(version(5), version(2)).expect_err("inverted range"),
            CodecError::InvertedVersionRange { min: 5, max: 2 }
        );
    }

    #[test]
    fn version_zero_is_not_a_version() {
        assert_eq!(
            MajorVersion::new(0)
                .expect_err("zero is refused")
                .category(),
            "field_invalid"
        );
    }

    #[test]
    fn field_grammar_is_enforced() {
        for bad in [
            "Automonique",
            "automonique..runner",
            "automonique.",
            "1runner",
        ] {
            assert_eq!(
                ProtocolName::new(bad)
                    .expect_err("invalid protocol grammar")
                    .category(),
                "field_grammar",
                "{bad} was accepted"
            );
        }
        assert_eq!(
            ProtocolName::new("a".repeat(MAX_PROTOCOL_NAME_BYTES + 1))
                .expect_err("over-length protocol")
                .category(),
            "field_invalid"
        );
        assert!(ProtocolName::new("a".repeat(MAX_PROTOCOL_NAME_BYTES)).is_ok());
        assert_eq!(
            MessageKind::new("Subscribe")
                .expect_err("uppercase kind")
                .category(),
            "field_grammar"
        );
        assert!(MessageKind::new("a".repeat(MAX_MESSAGE_KIND_BYTES)).is_ok());
        assert_eq!(
            RequestId::new("").expect_err("empty request id").category(),
            "field_invalid"
        );
    }
}

mod enum_discipline {
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    enum ApprovalDecision {
        Allow,
        Deny,
    }

    impl SecuritySensitiveEnum for ApprovalDecision {
        const FIELD: &'static str = "decision";

        fn from_wire(value: &str) -> Option<Self> {
            match value {
                "allow" => Some(Self::Allow),
                "deny" => Some(Self::Deny),
                _ => None,
            }
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    enum RunState {
        Running,
        Done,
    }

    impl ReadOnlyEnum for RunState {
        const FIELD: &'static str = "state";

        fn from_wire(value: &str) -> Option<Self> {
            match value {
                "running" => Some(Self::Running),
                "done" => Some(Self::Done),
                _ => None,
            }
        }
    }

    #[test]
    fn a_security_sensitive_enum_refuses_an_unknown_value() {
        assert_eq!(
            decode_security_enum::<ApprovalDecision>("allow").expect("defined value"),
            ApprovalDecision::Allow
        );
        assert_eq!(
            decode_security_enum::<ApprovalDecision>("allow_always")
                .expect_err("undefined value fails closed"),
            CodecError::UnknownEnumValue { field: "decision" }
        );
    }

    #[test]
    fn a_read_only_enum_retains_an_unknown_spelling() {
        assert_eq!(
            decode_read_only_enum::<RunState>("running").expect("defined value"),
            ReadOnly::Known(RunState::Running)
        );
        let unknown = decode_read_only_enum::<RunState>("hibernated").expect("unknown is retained");
        assert_eq!(unknown.unknown_spelling(), Some("hibernated"));
        assert!(unknown.known().is_none());
    }

    #[test]
    fn a_retained_unknown_spelling_is_still_bounded() {
        let oversized = "x".repeat(MAX_ENUM_VALUE_BYTES + 1);
        assert_eq!(
            decode_read_only_enum::<RunState>(&oversized)
                .expect_err("unbounded spellings are not retained")
                .category(),
            "field_invalid"
        );
        assert!(decode_read_only_enum::<RunState>(&"x".repeat(MAX_ENUM_VALUE_BYTES)).is_ok());
    }
}

mod nesting_and_limits {
    use super::*;

    #[test]
    fn depth_fails_at_exactly_one_level_beyond_the_ceiling() {
        let mut guard = DepthGuard::new();
        for level in 1..=MAX_NESTING_DEPTH {
            guard.enter().expect("within the ceiling");
            assert_eq!(guard.depth(), level);
        }
        assert_eq!(
            guard.enter().expect_err("one level too deep"),
            CodecError::NestingTooDeep {
                max_depth: MAX_NESTING_DEPTH,
            }
        );
        assert_eq!(
            guard.depth(),
            MAX_NESTING_DEPTH,
            "a refusal does not descend"
        );
    }

    #[test]
    fn exiting_restores_capacity_and_never_underflows() {
        let mut guard = DepthGuard::with_max_depth(2);
        guard.enter().expect("first level");
        guard.enter().expect("second level");
        assert!(guard.enter().is_err());
        guard.exit();
        guard.enter().expect("capacity is restored after exit");
        guard.exit();
        guard.exit();
        guard.exit();
        assert_eq!(guard.depth(), 0);
    }

    #[test]
    fn depth_length_and_field_ceilings_fail_independently() {
        let depth = DepthGuard::with_max_depth(0)
            .enter()
            .expect_err("zero ceiling accepts nothing");
        let length = decode_frame(&(MAX_FRAME_BYTES as u32 + 1).to_be_bytes())
            .expect_err("over-length frame");
        let field = ProtocolName::new("a".repeat(MAX_PROTOCOL_NAME_BYTES + 1))
            .expect_err("over-length field");

        let categories = [depth.category(), length.category(), field.category()];
        assert_eq!(
            categories,
            ["nesting_too_deep", "frame_too_large", "field_invalid"]
        );
    }
}

mod error_mapping {
    use super::*;

    /// One value of every `CodecError` variant. Adding a variant without
    /// extending this list fails the exhaustiveness assertion below.
    fn every_variant() -> Vec<CodecError> {
        vec![
            CodecError::EmptyFrame,
            CodecError::FrameTooLarge {
                max_bytes: MAX_FRAME_BYTES,
                declared_bytes: MAX_FRAME_BYTES + 1,
            },
            CodecError::NestingTooDeep {
                max_depth: MAX_NESTING_DEPTH,
            },
            CodecError::Field {
                field: "protocol",
                error: ValueError::Empty,
            },
            CodecError::Grammar { field: "kind" },
            CodecError::UnknownProtocol,
            CodecError::UnsupportedVersion {
                supported_min: 1,
                supported_max: 2,
                offered: 3,
            },
            CodecError::NoVersionOverlap {
                local_min: 1,
                local_max: 2,
                peer_min: 3,
                peer_max: 4,
            },
            CodecError::InvertedVersionRange { min: 4, max: 1 },
            CodecError::UnknownEnumValue { field: "decision" },
        ]
    }

    #[test]
    fn every_variant_has_one_stable_distinct_wire_code() {
        let variants = every_variant();
        let mut codes: Vec<u16> = variants.iter().map(CodecError::wire_code).collect();
        let total = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), total, "two categories share a wire code");

        let mut categories: Vec<&str> = variants.iter().map(CodecError::category).collect();
        categories.sort_unstable();
        categories.dedup();
        assert_eq!(categories.len(), total, "two variants share a category");
    }

    #[test]
    fn the_mapping_is_exhaustive_over_the_error_enum() {
        // A new variant must be added to `every_variant`; this match makes the
        // omission a compile error rather than a silently untested code.
        for error in every_variant() {
            match error {
                CodecError::EmptyFrame
                | CodecError::FrameTooLarge { .. }
                | CodecError::NestingTooDeep { .. }
                | CodecError::Field { .. }
                | CodecError::Grammar { .. }
                | CodecError::UnknownProtocol
                | CodecError::UnsupportedVersion { .. }
                | CodecError::NoVersionOverlap { .. }
                | CodecError::InvertedVersionRange { .. }
                | CodecError::UnknownEnumValue { .. } => {}
            }
            assert!(error.wire_code() >= 1000);
            assert!(!error.category().is_empty());
        }
    }

    #[test]
    fn no_message_contains_payload_bytes() {
        // A hostile frame whose body would be embarrassing to log.
        let secret = "s3cr3t-token-do-not-log";
        let mut hostile = (MAX_FRAME_BYTES as u32 + 1).to_be_bytes().to_vec();
        hostile.extend_from_slice(secret.as_bytes());
        let error = decode_frame(&hostile).expect_err("over-limit declaration is refused");
        let rendered = error.to_string();
        assert!(!rendered.contains(secret));

        // Nor does a rejected field echo the value it rejected.
        let rejected = ProtocolName::new("NOT-A-VALID-NAME").expect_err("invalid grammar");
        assert!(!rejected.to_string().contains("NOT-A-VALID-NAME"));

        for error in every_variant() {
            let rendered = error.to_string();
            assert!(!rendered.is_empty());
            assert!(!rendered.contains(secret));
        }
    }
}

mod spool_reference {
    use super::*;

    #[test]
    fn a_spool_reference_is_carried_without_being_resolved() {
        let reference = SpoolReference::new(42, 4096);
        assert_eq!(reference.sequence(), 42);
        assert_eq!(reference.offset(), 4096);
        assert_eq!(reference, SpoolReference::new(42, 4096));
        assert_ne!(reference, SpoolReference::new(42, 4097));
    }
}
