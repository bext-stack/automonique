// SPDX-License-Identifier: Elastic-2.0

//! Property tests for the three hand-rolled codecs.
//!
//! The rest of this crate's suite is example-based: a fixture names a byte
//! string and asserts what it decodes to. That proves the cases someone thought
//! of. These tests state the laws instead — decode after encode is the
//! identity, one value has one encoding, a non-canonical spelling is never
//! silently accepted, no byte string makes a decoder panic — and let proptest
//! look for the counterexample.
//!
//! The laws are also the safety net under refactoring. A change to
//! `wire.rs`, `codec.rs` or `digest.rs` that preserves every checked-in fixture
//! but breaks an invariant fails here rather than in a peer's decoder.
//!
//! Case counts default to proptest's 256 and honour `PROPTEST_CASES`; the few
//! properties that allocate whole frames run fewer cases so the suite stays
//! inside the ordinary `cargo test` budget. The ceiling cases that do need
//! megabyte buffers are plain `#[test]`s, run once each.

use proptest::prelude::*;
use sha2::{Digest as _, Sha256 as ReferenceSha256};

use automonique_protocol::codec::{
    CodecError, Envelope, FrameDecode, LENGTH_PREFIX_BYTES, MAX_FRAME_BYTES, MajorVersion,
    MessageKind, ProtocolName, RequestId, decode_frame, encode_frame,
};
use automonique_protocol::digest::Sha256;
use automonique_protocol::wire::{JsonValue, Message, parse_canonical};

/// Case count for one property, honouring a `PROPTEST_CASES` override.
///
/// `ProptestConfig::default()` already reads the variable, so an operator who
/// sets it wants that number everywhere and the per-property default is what
/// gets dropped. Without it the caller's number applies: the cheap properties
/// keep proptest's 256, the frame properties ask for fewer.
fn cases(default: u32) -> ProptestConfig {
    let configured = ProptestConfig::default();
    if std::env::var_os("PROPTEST_CASES").is_some() {
        configured
    } else {
        ProptestConfig {
            cases: default,
            ..configured
        }
    }
}

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// Characters biased towards the ones the encoder has to make a decision about.
///
/// Uniform `char` alone would spend nearly every draw in the astral planes and
/// almost never produce a quote, a backslash or a C0 control — exactly the
/// bytes where an escaping bug lives.
fn arb_char() -> impl Strategy<Value = char> {
    prop_oneof![
        4 => prop::char::range('a', 'z'),
        3 => prop::sample::select(vec![
            '"', '\\', '/', '\n', '\r', '\t', '\u{8}', '\u{c}',
            '\u{0}', '\u{1}', '\u{1f}', '\u{7f}', ' ',
        ]),
        2 => prop::char::range('\u{80}', '\u{7ff}'),
        1 => any::<char>(),
    ]
}

fn arb_string() -> impl Strategy<Value = String> {
    prop::collection::vec(arb_char(), 0..10).prop_map(|chars| chars.into_iter().collect())
}

/// Bounded `JsonValue` trees whose objects are already canonical.
///
/// Keys come from a `BTreeMap`, so they are unique and in the byte order the
/// encoder sorts into. That is what makes decode-after-encode an equality
/// rather than an equality-up-to-reordering: a value with duplicate keys has no
/// canonical encoding to round-trip through, and one with unsorted keys encodes
/// to a byte string that decodes back to a *different* `Vec` of entries.
fn arb_json_value() -> impl Strategy<Value = JsonValue> {
    let leaf = prop_oneof![
        1 => Just(JsonValue::Null),
        1 => any::<bool>().prop_map(JsonValue::Bool),
        2 => any::<i64>().prop_map(JsonValue::Integer),
        3 => arb_string().prop_map(JsonValue::String),
    ];
    // Depth 4 stays well inside `MAX_NESTING_DEPTH`; the depth ceiling itself is
    // an example-based test in `tests/wire.rs` and not a law about arbitrary
    // trees.
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(JsonValue::Array),
            prop::collection::btree_map(arb_string(), inner, 0..6)
                .prop_map(|entries| JsonValue::Object(entries.into_iter().collect())),
        ]
    })
}

/// Bytes a hostile peer might send, from four directions at once.
///
/// Uniform noise alone is a weak fuzzer for a text format: it fails at the
/// first byte and never reaches the parser's interesting states. Valid
/// encodings reach them but never leave the accepting path. The corrupted and
/// alphabet-soup arms are what get a decoder deep into a structure and then
/// hand it something it did not expect.
fn arb_payload() -> impl Strategy<Value = Vec<u8>> {
    const JSON_ALPHABET: &[u8] = b"{}[],:\"\\/0123456789.-+eEabcdfilnrstu \t\r\n";

    prop_oneof![
        2 => prop::collection::vec(any::<u8>(), 0..256),
        3 => prop::collection::vec(prop::sample::select(JSON_ALPHABET), 0..192),
        3 => arb_json_value().prop_map(|value| value.to_canonical_bytes()),
        3 => (arb_json_value(), any::<prop::sample::Index>(), any::<u8>()).prop_map(
            |(value, index, byte)| {
                let mut bytes = value.to_canonical_bytes();
                if !bytes.is_empty() {
                    let position = index.index(bytes.len());
                    bytes[position] = byte;
                }
                bytes
            }
        ),
        2 => arb_message_bytes(),
    ]
}

fn arb_protocol_name() -> impl Strategy<Value = ProtocolName> {
    prop::string::string_regex(r"[a-z][a-z0-9]{0,7}(\.[a-z0-9]{1,7}){0,2}")
        .expect("protocol name pattern")
        .prop_map(|name| ProtocolName::new(name).expect("generated protocol name is valid"))
}

fn arb_request_id() -> impl Strategy<Value = RequestId> {
    prop::string::string_regex(r"[A-Za-z0-9._:-]{1,24}")
        .expect("request id pattern")
        .prop_map(|id| RequestId::new(id).expect("generated request id is valid"))
}

fn arb_message_kind() -> impl Strategy<Value = MessageKind> {
    prop::string::string_regex(r"[a-z][a-z0-9_]{0,15}")
        .expect("message kind pattern")
        .prop_map(|kind| MessageKind::new(kind).expect("generated message kind is valid"))
}

fn arb_envelope() -> impl Strategy<Value = Envelope> {
    (
        arb_protocol_name(),
        1_u32..64,
        arb_request_id(),
        arb_message_kind(),
    )
        .prop_map(|(protocol, version, request_id, kind)| {
            Envelope::new(
                protocol,
                MajorVersion::new(version).expect("generated major version is valid"),
                request_id,
                kind,
            )
        })
}

fn arb_message() -> impl Strategy<Value = Message> {
    (arb_envelope(), arb_json_value()).prop_map(|(envelope, body)| Message::new(envelope, body))
}

fn arb_message_bytes() -> impl Strategy<Value = Vec<u8>> {
    arb_message().prop_map(|message| message.to_canonical_bytes())
}

/// Encode without sorting object keys.
///
/// A deliberate mirror of `JsonValue::write_canonical` with the one line that
/// makes it canonical removed, so a test can hand the parser the *other*
/// spelling of a value it would otherwise never see. Reaching for the real
/// encoder here is impossible by construction: it sorts.
fn write_unsorted(value: &JsonValue, out: &mut Vec<u8>) {
    match value {
        JsonValue::Object(entries) => {
            out.push(b'{');
            for (index, (key, entry)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(&JsonValue::String(key.clone()).to_canonical_bytes());
                out.push(b':');
                write_unsorted(entry, out);
            }
            out.push(b'}');
        }
        JsonValue::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_unsorted(item, out);
            }
            out.push(b']');
        }
        scalar => out.extend_from_slice(&scalar.to_canonical_bytes()),
    }
}

// ---------------------------------------------------------------------------
// 1. Canonical JSON round-trips
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(cases(256))]

    /// Decoding after encoding is the identity on canonical values.
    #[test]
    fn a_canonical_value_survives_a_round_trip(value in arb_json_value()) {
        let bytes = value.to_canonical_bytes();
        prop_assert_eq!(parse_canonical(&bytes), Ok(value));
    }

    /// Encoding is injective: two values that encode alike are the same value.
    ///
    /// Stated as the contrapositive because that is the direction a wire format
    /// is attacked from — two distinct messages sharing one byte string is what
    /// lets a signature over the bytes cover the wrong message.
    #[test]
    fn distinct_values_never_share_an_encoding(
        left in arb_json_value(),
        right in arb_json_value(),
    ) {
        if left.to_canonical_bytes() == right.to_canonical_bytes() {
            prop_assert_eq!(left, right);
        }
    }

    /// A message round-trips through its envelope framing as well as its body.
    #[test]
    fn a_message_survives_a_round_trip(message in arb_message()) {
        let bytes = message.to_canonical_bytes();
        prop_assert_eq!(Message::from_canonical_bytes(&bytes), Ok(message));
    }

    /// Decoding a message is idempotent, from whichever direction it is reached.
    ///
    /// The stronger-looking statement — that a decoded message re-encodes to
    /// the bytes it came from — is false on purpose, and the fuzz target found
    /// it before this comment existed. Unknown top-level fields decode and are
    /// dropped (`fixtures/wire-v1.json`'s `envelope-unknown-additive-field`),
    /// because a peer on a later minor version must be able to add a field
    /// without this one refusing the message. Idempotence is the strongest law
    /// that survives that tolerance, and it still catches the failure that
    /// matters: an envelope field that decodes to a different spelling than it
    /// encodes to.
    #[test]
    fn decoding_a_message_is_idempotent(payload in arb_payload()) {
        let Ok(message) = Message::from_canonical_bytes(&payload) else {
            return Ok(());
        };
        let reencoded = message.to_canonical_bytes();
        prop_assert_eq!(Message::from_canonical_bytes(&reencoded), Ok(message));
    }
}

// ---------------------------------------------------------------------------
// 2. Permutation invariance
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(cases(256))]

    /// Insertion order is not observable in the encoding.
    ///
    /// This is the total-ordering property that makes a cross-language
    /// comparison meaningful: a peer that builds the same object with a hash
    /// map, in whatever order iteration hands it, must produce these bytes.
    #[test]
    fn insertion_order_does_not_reach_the_encoding(
        (sorted, shuffled) in prop::collection::btree_map(arb_string(), arb_json_value(), 0..8)
            .prop_map(|entries| entries.into_iter().collect::<Vec<_>>())
            .prop_flat_map(|sorted| (Just(sorted.clone()), Just(sorted).prop_shuffle())),
    ) {
        let from_sorted = JsonValue::Object(sorted).to_canonical_bytes();
        let from_shuffled = JsonValue::Object(shuffled).to_canonical_bytes();
        prop_assert_eq!(from_sorted, from_shuffled);
    }

    /// Nesting does not defeat it: reordering at any depth encodes identically.
    #[test]
    fn reordering_a_nested_object_does_not_reach_the_encoding(
        value in arb_json_value(),
    ) {
        let reversed = reverse_object_entries(&value);
        prop_assert_eq!(value.to_canonical_bytes(), reversed.to_canonical_bytes());
    }
}

/// Reverse every object's entry order, recursively, leaving values alone.
fn reverse_object_entries(value: &JsonValue) -> JsonValue {
    match value {
        JsonValue::Object(entries) => JsonValue::Object(
            entries
                .iter()
                .rev()
                .map(|(key, entry)| (key.clone(), reverse_object_entries(entry)))
                .collect(),
        ),
        JsonValue::Array(items) => {
            JsonValue::Array(items.iter().map(reverse_object_entries).collect())
        }
        scalar => scalar.clone(),
    }
}

// ---------------------------------------------------------------------------
// 3. Strictness: a non-canonical spelling is refused, never normalized
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(cases(256))]

    /// Whatever the parser accepts re-encodes to exactly the bytes it was given.
    ///
    /// This is the whole strictness contract in one line, and it holds over
    /// arbitrary bytes rather than over mutations someone thought to write
    /// down. Every targeted mutation below is a special case of it; they exist
    /// to pin the *error* each spelling earns, which this cannot say.
    #[test]
    fn acceptance_implies_the_input_was_already_canonical(payload in arb_payload()) {
        if let Ok(value) = parse_canonical(&payload) {
            prop_assert_eq!(value.to_canonical_bytes(), payload);
        }
    }

    /// Insignificant whitespace is refused as non-canonical, not as a syntax
    /// error — the peer's JSON is fine, its spelling is not.
    #[test]
    fn surrounding_whitespace_is_refused_as_non_canonical(
        value in arb_json_value(),
        space in prop::sample::select(vec![b' ', b'\t', b'\n', b'\r']),
        leading in any::<bool>(),
    ) {
        let canonical = value.to_canonical_bytes();
        let mut padded = Vec::with_capacity(canonical.len() + 1);
        if leading {
            padded.push(space);
            padded.extend_from_slice(&canonical);
        } else {
            padded.extend_from_slice(&canonical);
            padded.push(space);
        }
        prop_assert_eq!(parse_canonical(&padded), Err(CodecError::NonCanonicalJson));
    }

    /// Unsorted object keys are refused rather than sorted on the way in.
    #[test]
    fn unsorted_object_keys_are_refused(value in arb_json_value()) {
        let reversed = reverse_object_entries(&value);
        let mut unsorted = Vec::new();
        write_unsorted(&reversed, &mut unsorted);
        let canonical = value.to_canonical_bytes();
        // Reversing a one-entry object, or one whose keys happen to be a
        // palindrome of themselves, leaves the canonical spelling untouched.
        if unsorted == canonical {
            prop_assert_eq!(parse_canonical(&unsorted), Ok(value));
        } else {
            prop_assert_eq!(parse_canonical(&unsorted), Err(CodecError::NonCanonicalJson));
        }
    }

    /// A duplicate key is refused before either value is chosen.
    ///
    /// The refusal has its own class: silently keeping first-wins or last-wins
    /// is how a decoder and a reviewer reading the same bytes end up disagreeing
    /// about what the message said.
    #[test]
    fn a_duplicate_key_is_refused(
        key in arb_string(),
        first in arb_json_value(),
        second in arb_json_value(),
    ) {
        let entries = vec![(key.clone(), first), (key, second)];
        let mut payload = Vec::new();
        write_unsorted(&JsonValue::Object(entries), &mut payload);
        prop_assert_eq!(parse_canonical(&payload), Err(CodecError::DuplicateKey));
    }

    /// A character with a shorter spelling may not arrive in `\u` form.
    #[test]
    fn a_redundant_unicode_escape_is_refused(character in prop::char::range(' ', '~')) {
        let payload = format!("\"\\u{:04x}\"", character as u32).into_bytes();
        prop_assert_eq!(parse_canonical(&payload), Err(CodecError::NonCanonicalJson));
    }

    /// `\/` parses to `/`, whose canonical spelling is the bare byte.
    #[test]
    fn the_optional_solidus_escape_is_refused(
        prefix in prop::string::string_regex("[a-z]{0,4}").expect("prefix pattern"),
    ) {
        let payload = format!("\"{prefix}\\/\"").into_bytes();
        prop_assert_eq!(parse_canonical(&payload), Err(CodecError::NonCanonicalJson));
    }

    /// An uppercase hex escape is a second spelling of a control character.
    ///
    /// The codes are enumerated rather than drawn from a range and filtered:
    /// these are the only controls above the named escapes whose hex spelling
    /// contains a letter at all, and `0x10`-`0x19` spell the same in either
    /// case, so there would be nothing to refuse.
    #[test]
    fn an_uppercase_unicode_escape_is_refused(
        code in prop::sample::select(vec![0x0e_u32, 0x0f, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]),
    ) {
        let payload = format!("\"\\u{code:04X}\"").into_bytes();
        prop_assert_eq!(parse_canonical(&payload), Err(CodecError::NonCanonicalJson));
    }

    /// A leading zero is a second spelling of an integer.
    #[test]
    fn a_leading_zero_is_refused(value in 0_i64..1_000_000) {
        let payload = format!("0{value}").into_bytes();
        prop_assert_eq!(parse_canonical(&payload), Err(CodecError::NonCanonicalJson));
    }

    /// `-0` is a second spelling of zero, and so is every `-00…0` after it.
    #[test]
    fn negative_zero_is_refused(zeros in 1_usize..6) {
        let payload = format!("-{}", "0".repeat(zeros)).into_bytes();
        prop_assert_eq!(parse_canonical(&payload), Err(CodecError::NonCanonicalJson));
    }

    /// Floats and exponents are outside the wire's number domain.
    #[test]
    fn a_non_integer_number_is_refused(
        value in 1_i64..1_000_000,
        suffix in prop::sample::select(vec![".0", ".5", "e1", "E1", "e+1", ".25e3"]),
    ) {
        let payload = format!("{value}{suffix}").into_bytes();
        prop_assert_eq!(
            parse_canonical(&payload),
            Err(CodecError::InvalidJsonValue { field: "json_number" })
        );
    }

    /// An integer outside the signed 64-bit range is refused, not saturated.
    #[test]
    fn an_out_of_range_integer_is_refused(excess in 1_u64..1_000_000) {
        let payload = format!("{}", u128::from(u64::MAX) + u128::from(excess)).into_bytes();
        prop_assert_eq!(parse_canonical(&payload), Err(CodecError::IntegerOutOfRange));
    }

    /// Bytes after a complete value are refused rather than ignored.
    #[test]
    fn trailing_bytes_are_refused(value in arb_json_value()) {
        let mut payload = value.to_canonical_bytes();
        // `]` can never continue a complete value, so this is always trailing
        // data rather than a longer value.
        payload.push(b']');
        prop_assert_eq!(parse_canonical(&payload), Err(CodecError::TrailingData));
    }

    /// Invalid UTF-8 is a malformed payload, not a lossy decode.
    #[test]
    fn invalid_utf8_is_refused(
        text in prop::string::string_regex("[a-z]{1,8}").expect("text pattern"),
    ) {
        let payload = [b"\"", text.as_bytes(), b"\xff\"".as_slice()].concat();
        prop_assert_eq!(parse_canonical(&payload), Err(CodecError::MalformedJson));
    }
}

// ---------------------------------------------------------------------------
// 4. No byte string makes a decoder panic
// ---------------------------------------------------------------------------

/// One never-panic property per decoder.
///
/// Written as a macro because the crate exposes twenty-one of these entry
/// points, each with its own error type, and a hand-written copy each would be
/// twenty-one places to forget to update. One test per decoder rather than one
/// loop over all of them so a failure names the decoder in its own test name.
macro_rules! never_panics_on_arbitrary_bytes {
    ($($name:ident => $decoder:path),* $(,)?) => {
        $(
            proptest! {
                #![proptest_config(cases(128))]

                #[test]
                fn $name(payload in arb_payload()) {
                    // A refusal is the expected outcome for nearly every draw.
                    // The assertion is the absence of a panic, an abort or a
                    // hang, which the harness makes for us by returning.
                    let _ = <$decoder>::from_canonical_bytes(&payload);
                }
            }
        )*
    };
}

never_panics_on_arbitrary_bytes! {
    admin_request_never_panics => automonique_protocol::admin::AdminRequest,
    admin_response_never_panics => automonique_protocol::admin::AdminResponse,
    local_request_never_panics => automonique_protocol::admin::LocalRequest,
    approval_request_never_panics => automonique_protocol::approval_api::ApprovalRequest,
    approval_response_never_panics => automonique_protocol::approval_api::ApprovalResponse,
    automation_request_never_panics => automonique_protocol::automation_api::AutomationRequest,
    automation_response_never_panics => automonique_protocol::automation_api::AutomationResponse,
    batch_request_never_panics => automonique_protocol::batch_api::BatchRequest,
    batch_response_never_panics => automonique_protocol::batch_api::BatchResponse,
    batch_plan_never_panics => automonique_protocol::batch_runner::BatchPlan,
    batch_progress_never_panics => automonique_protocol::batch_runner::BatchProgress,
    execute_request_never_panics => automonique_protocol::execute_api::ExecuteRequest,
    execute_response_never_panics => automonique_protocol::execute_api::ExecuteResponse,
    memory_request_never_panics => automonique_protocol::memory_api::MemoryRequest,
    memory_response_never_panics => automonique_protocol::memory_api::MemoryResponse,
    intended_action_envelope_never_panics => automonique_protocol::parity::IntendedActionEnvelope,
    deviation_registry_never_panics => automonique_protocol::parity::DeviationRegistry,
    release_manifest_never_panics => automonique_protocol::release::ReleaseManifest,
    release_attestation_never_panics
        => automonique_protocol::release_trust_root::ReleaseAttestation,
    runs_request_never_panics => automonique_protocol::runs_api::RunsRequest,
    runs_response_never_panics => automonique_protocol::runs_api::RunsResponse,
    message_never_panics => automonique_protocol::wire::Message,
}

proptest! {
    #![proptest_config(cases(256))]

    /// The canonical-JSON parser itself never panics.
    #[test]
    fn parse_canonical_never_panics(payload in arb_payload()) {
        let _ = parse_canonical(&payload);
    }

    /// Neither does the framing decoder, whatever the length prefix claims.
    #[test]
    fn decode_frame_never_panics(input in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode_frame(&input);
    }

    /// Nor does admission, on any payload and any set of supported protocols.
    #[test]
    fn admitted_decode_never_panics(
        payload in arb_payload(),
        supported in prop::collection::vec(arb_supported_protocol(), 0..4),
    ) {
        let _ = Message::from_canonical_bytes_admitted(&payload, &supported);
    }

    /// A length prefix is never trusted enough to size an allocation.
    ///
    /// The property is stated as a bound on the decoder's own behaviour: a
    /// four-byte prefix claiming more than the ceiling is refused before the
    /// payload is looked at, so the eight-byte input below can never cost more
    /// than eight bytes to reject.
    #[test]
    fn an_oversized_length_prefix_is_refused_before_any_allocation(
        declared in (MAX_FRAME_BYTES as u32 + 1)..=u32::MAX,
    ) {
        let mut input = declared.to_be_bytes().to_vec();
        input.extend_from_slice(b"payload!");
        prop_assert_eq!(
            decode_frame(&input),
            Err(CodecError::FrameTooLarge {
                max_bytes: MAX_FRAME_BYTES,
                declared_bytes: declared as usize,
            })
        );
    }
}

fn arb_supported_protocol() -> impl Strategy<Value = automonique_protocol::codec::SupportedProtocol>
{
    use automonique_protocol::codec::{SupportedProtocol, VersionRange};

    (arb_protocol_name(), 1_u32..8, 0_u32..8).prop_map(|(name, min, span)| {
        let low = MajorVersion::new(min).expect("generated minimum is valid");
        let high = MajorVersion::new(min + span).expect("generated maximum is valid");
        SupportedProtocol::new(
            name,
            VersionRange::new(low, high).expect("generated range is ordered"),
        )
    })
}

// ---------------------------------------------------------------------------
// 5. Framing
// ---------------------------------------------------------------------------

proptest! {
    // Fewer cases: each one allocates and copies its payload twice.
    #![proptest_config(cases(64))]

    /// Decoding after encoding returns the payload and the exact byte count.
    #[test]
    fn a_frame_survives_a_round_trip(
        payload in prop::collection::vec(any::<u8>(), 1..4096),
    ) {
        let mut encoded = Vec::new();
        encode_frame(&payload, &mut encoded).expect("payload is within the ceiling");
        prop_assert_eq!(
            decode_frame(&encoded),
            Ok(FrameDecode::Frame {
                payload: &payload,
                consumed: LENGTH_PREFIX_BYTES + payload.len(),
            })
        );
    }

    /// A frame decodes out of a stream without consuming what follows it.
    #[test]
    fn a_frame_is_decoded_without_touching_the_next_one(
        first in prop::collection::vec(any::<u8>(), 1..512),
        rest in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let mut stream = Vec::new();
        encode_frame(&first, &mut stream).expect("payload is within the ceiling");
        stream.extend_from_slice(&rest);
        prop_assert_eq!(
            decode_frame(&stream),
            Ok(FrameDecode::Frame {
                payload: &first,
                consumed: LENGTH_PREFIX_BYTES + first.len(),
            })
        );
    }

    /// Every truncation asks for the bytes that would let it make progress,
    /// and never for more than the frame actually needs.
    ///
    /// The request comes in two stages because the decoder learns the payload
    /// length only after it has the prefix: below four bytes it can ask for the
    /// prefix and nothing else, and above four it knows the whole remainder.
    /// Over-asking is the failure that matters — a reader told to wait for
    /// bytes the sender will never send stalls forever — so the bound holds in
    /// both stages, and under-asking is excluded by the request never being
    /// zero.
    #[test]
    fn a_truncated_frame_asks_for_the_bytes_that_let_it_progress(
        payload in prop::collection::vec(any::<u8>(), 1..512),
        cut in any::<prop::sample::Index>(),
    ) {
        let mut encoded = Vec::new();
        encode_frame(&payload, &mut encoded).expect("payload is within the ceiling");
        let total = encoded.len();
        let kept = cut.index(total);
        let outcome = decode_frame(&encoded[..kept]).expect("a truncation is not an error");
        match outcome {
            FrameDecode::NeedMore { additional } => {
                let expected = if kept < LENGTH_PREFIX_BYTES {
                    LENGTH_PREFIX_BYTES - kept
                } else {
                    total - kept
                };
                prop_assert_eq!(additional.get(), expected);
                prop_assert!(additional.get() <= total - kept, "the decoder over-asked");
            }
            FrameDecode::Frame { .. } => {
                prop_assert!(false, "a truncated frame decoded as complete");
            }
        }
    }

    /// Feeding a stream one byte at a time terminates on the frame, taking the
    /// decoder's advice at every step.
    ///
    /// This is the two-stage rule above turned into the loop a real reader
    /// writes. It also proves the advice is never zero: a zero would make this
    /// spin rather than fail.
    #[test]
    fn following_the_decoder_s_advice_always_reaches_the_frame(
        payload in prop::collection::vec(any::<u8>(), 1..512),
    ) {
        let mut encoded = Vec::new();
        encode_frame(&payload, &mut encoded).expect("payload is within the ceiling");

        let mut available = 0_usize;
        loop {
            match decode_frame(&encoded[..available]).expect("a truncation is not an error") {
                FrameDecode::Frame { payload: decoded, consumed } => {
                    prop_assert_eq!(decoded, payload.as_slice());
                    prop_assert_eq!(consumed, encoded.len());
                    break;
                }
                FrameDecode::NeedMore { additional } => {
                    available += additional.get();
                    prop_assert!(available <= encoded.len(), "the decoder asked past the frame");
                }
            }
        }
    }

    /// An empty payload has no envelope and is refused at both ends.
    #[test]
    fn a_zero_length_frame_is_refused(trailing in prop::collection::vec(any::<u8>(), 0..16)) {
        let mut input = 0_u32.to_be_bytes().to_vec();
        input.extend_from_slice(&trailing);
        prop_assert_eq!(decode_frame(&input), Err(CodecError::EmptyFrame));
        let mut out = Vec::new();
        prop_assert_eq!(encode_frame(&[], &mut out), Err(CodecError::EmptyFrame));
    }

    /// A framed message survives the whole stack: encode, frame, unframe, decode.
    #[test]
    fn a_framed_message_survives_the_whole_stack(message in arb_message()) {
        let payload = message.to_canonical_bytes();
        let mut stream = Vec::new();
        encode_frame(&payload, &mut stream).expect("payload is within the ceiling");
        let FrameDecode::Frame { payload: framed, .. } =
            decode_frame(&stream).expect("frame decodes")
        else {
            prop_assert!(false, "a complete frame decoded as incomplete");
            return Ok(());
        };
        prop_assert_eq!(Message::from_canonical_bytes(framed), Ok(message));
    }
}

/// The ceiling itself, at full size, once rather than per generated case.
#[test]
fn a_frame_at_the_ceiling_round_trips() {
    let payload = vec![0x5a_u8; MAX_FRAME_BYTES];
    let mut encoded = Vec::new();
    encode_frame(&payload, &mut encoded).expect("the ceiling is inclusive");
    assert_eq!(encoded.len(), LENGTH_PREFIX_BYTES + MAX_FRAME_BYTES);
    assert_eq!(
        decode_frame(&encoded),
        Ok(FrameDecode::Frame {
            payload: &payload,
            consumed: LENGTH_PREFIX_BYTES + MAX_FRAME_BYTES,
        })
    );
}

/// One byte past the ceiling is refused by the encoder.
#[test]
fn a_frame_past_the_ceiling_is_refused() {
    let payload = vec![0x5a_u8; MAX_FRAME_BYTES + 1];
    let mut encoded = Vec::new();
    assert_eq!(
        encode_frame(&payload, &mut encoded),
        Err(CodecError::FrameTooLarge {
            max_bytes: MAX_FRAME_BYTES,
            declared_bytes: MAX_FRAME_BYTES + 1,
        })
    );
    assert!(encoded.is_empty(), "a refused frame wrote bytes");
}

// ---------------------------------------------------------------------------
// 6. Differential SHA-256
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(cases(256))]

    /// The hand-rolled digest agrees with RustCrypto on arbitrary input.
    ///
    /// `digest.rs` exists so the protocol crate can stay dependency-free, which
    /// means nothing else in the shipped graph can check it. Comparing against a
    /// second, independently written implementation is the only check that is
    /// not the implementation grading its own homework.
    #[test]
    fn the_digest_agrees_with_rustcrypto(input in prop::collection::vec(any::<u8>(), 0..4096)) {
        let ours = Sha256::digest(&input);
        let reference = ReferenceSha256::digest(&input);
        prop_assert_eq!(ours.as_bytes().as_slice(), reference.as_slice());
    }

    /// Incremental hashing agrees with the one-shot call at any chunk boundary.
    ///
    /// Arbitrary splits are the point: a buffering bug in `update` shows up only
    /// when a chunk boundary lands off the 64-byte block, and a fixed chunk size
    /// is exactly the case that never lands there.
    #[test]
    fn incremental_hashing_agrees_at_arbitrary_chunk_boundaries(
        input in prop::collection::vec(any::<u8>(), 0..4096),
        cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..12),
    ) {
        let mut boundaries: Vec<usize> =
            cuts.iter().map(|cut| cut.index(input.len() + 1)).collect();
        boundaries.push(0);
        boundaries.push(input.len());
        boundaries.sort_unstable();
        boundaries.dedup();

        let mut ours = Sha256::new();
        let mut reference = ReferenceSha256::new();
        for window in boundaries.windows(2) {
            let chunk = &input[window[0]..window[1]];
            ours.update(chunk);
            reference.update(chunk);
        }

        let incremental = ours.finish();
        let expected = reference.finalize();
        prop_assert_eq!(incremental.as_bytes().as_slice(), expected.as_slice());

        let one_shot = Sha256::digest(&input);
        let one_shot_expected = ReferenceSha256::digest(&input);
        prop_assert_eq!(one_shot.as_bytes().as_slice(), one_shot_expected.as_slice());
    }

    /// The hex spelling is the digest bytes and nothing else.
    #[test]
    fn the_hex_spelling_matches_the_reference(
        input in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let ours = Sha256::digest(&input).to_hex();
        let reference = ReferenceSha256::digest(&input)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        prop_assert_eq!(ours, reference);
    }
}

/// The padding boundaries, which arbitrary lengths reach only by luck.
///
/// 55/56 and 119/120 are where SHA-256's length suffix stops fitting in the
/// current block and forces another one; 64 and 128 are exact block multiples.
#[test]
fn the_digest_agrees_with_rustcrypto_at_every_padding_boundary() {
    for length in [
        0_usize, 1, 54, 55, 56, 57, 63, 64, 65, 118, 119, 120, 121, 127, 128, 129,
    ] {
        let input: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
        assert_eq!(
            Sha256::digest(&input).as_bytes().as_slice(),
            ReferenceSha256::digest(&input).as_slice(),
            "length {length}"
        );
    }
}

/// A message longer than one buffered `update` still agrees.
#[test]
fn the_digest_agrees_with_rustcrypto_on_a_multi_megabyte_message() {
    let input: Vec<u8> = (0..4_194_304_u32)
        .map(|index| (index % 251) as u8)
        .collect();
    assert_eq!(
        Sha256::digest(&input).as_bytes().as_slice(),
        ReferenceSha256::digest(&input).as_slice()
    );
}
