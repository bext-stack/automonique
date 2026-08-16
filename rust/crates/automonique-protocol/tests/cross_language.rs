// SPDX-License-Identifier: Elastic-2.0

//! R1-06 verification contract: cross-language wire conformance.
//!
//! The corpus is checked in at `fixtures/wire-v1.json`. Rust is the wire source
//! of truth, so a disagreement is fixed in whichever implementation is wrong,
//! never in the corpus.
//!
//! Two directions are recorded separately. A run that cannot execute one of
//! them reports a gap rather than a pass, because a corpus where one direction
//! silently skipped proves only that an encoder and its own decoder share a
//! bug.
//!
//! Four sections make up the corpus:
//!
//! - `fixtures` are hex literals whose bytes travel through JSON artifacts;
//! - `generated_fixtures` are too large to review as a literal, so they are a
//!   generator rule both sides follow and exchange as files. That the two
//!   implementations read the rule identically is measured first, before any
//!   verdict about them is believed;
//! - `enum_fixtures` drive the read-only and security-sensitive enum decoders
//!   rather than the generic value parser;
//! - `frame_fixtures` drive the length-delimited codec at its exact ceiling,
//!   one byte past it, at zero length and at both incomplete-frame edges.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use automonique_protocol::codec::{
    CodecError, FrameDecode, MajorVersion, ProtocolName, ReadOnly, ReadOnlyEnum,
    SecuritySensitiveEnum, SupportedProtocol, VersionRange, decode_frame, decode_read_only_enum,
    decode_security_enum, encode_frame,
};
use automonique_protocol::wire::{JsonValue, Message, parse_canonical};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn corpus_path() -> PathBuf {
    crate_root().join("fixtures/wire-v1.json")
}

fn runner_path() -> PathBuf {
    crate_root()
        .join("../../../sdk/typescript/packages/protocol/conformance/run.ts")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("missing-runner"))
}

/// One value fixture, parsed with the crate's own codec rather than a JSON
/// library.
struct Fixture {
    id: String,
    bytes: Vec<u8>,
    accept: bool,
    category: Option<String>,
}

/// One enum declaration, mirrored by a Rust type below.
struct EnumDeclaration {
    id: String,
    field: String,
    kind: String,
    known: Vec<String>,
}

/// One enum fixture. `expected` is the decoded spelling for an accepted value
/// and the refusal category for a rejected one, in the same encoding both
/// implementations report.
struct EnumFixture {
    id: String,
    enum_id: String,
    bytes: Vec<u8>,
    expected: String,
}

/// What decoding a frame fixture's input must produce.
enum FrameExpect {
    Frame {
        consumed: usize,
        payload_bytes: usize,
    },
    NeedMore {
        additional: usize,
    },
    Reject {
        category: String,
    },
}

/// What encoding a frame fixture's payload must produce.
struct FrameEncode {
    payload: Vec<u8>,
    accept: bool,
    category: Option<String>,
}

struct FrameFixture {
    id: String,
    input: Vec<u8>,
    decode: FrameExpect,
    encode: Option<FrameEncode>,
}

struct Corpus {
    fixtures: Vec<Fixture>,
    generated: Vec<Fixture>,
    envelope_ids: Vec<String>,
    enums: Vec<EnumDeclaration>,
    enum_fixtures: Vec<EnumFixture>,
    frames: Vec<FrameFixture>,
    supported: Vec<SupportedProtocol>,
    supported_names: Vec<String>,
}

impl Corpus {
    fn value_fixture_count(&self) -> usize {
        self.fixtures.len() + self.generated.len()
    }

    fn is_envelope(&self, id: &str) -> bool {
        self.envelope_ids.iter().any(|declared| declared == id)
    }

    /// Decode as the fixture's own kind: an envelope fixture is admitted
    /// against the declared protocol set, everything else is a bare value.
    fn decode(&self, id: &str, bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
        if self.is_envelope(id) {
            Message::from_canonical_bytes_admitted(bytes, &self.supported)
                .map(|message| message.to_canonical_bytes())
        } else {
            parse_canonical(bytes).map(|value| value.to_canonical_bytes())
        }
    }
}

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex byte"))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn string_field(value: &JsonValue, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
}

fn required_string(value: &JsonValue, field: &str) -> String {
    string_field(value, field).unwrap_or_else(|| panic!("corpus entry has no {field}"))
}

fn required_usize(value: &JsonValue, field: &str) -> usize {
    let raw = value
        .get(field)
        .and_then(JsonValue::as_integer)
        .unwrap_or_else(|| panic!("corpus entry has no integer {field}"));
    usize::try_from(raw).unwrap_or_else(|_| panic!("{field} does not fit a usize"))
}

fn array_field<'a>(value: &'a JsonValue, field: &str) -> &'a [JsonValue] {
    match value.get(field) {
        Some(JsonValue::Array(items)) => items.as_slice(),
        _ => panic!("corpus field {field} is not an array"),
    }
}

fn string_list(value: &JsonValue, field: &str) -> Vec<String> {
    array_field(value, field)
        .iter()
        .filter_map(|item| item.as_str().map(str::to_owned))
        .collect()
}

/// Build fixture bytes from a generator rule.
///
/// A multi-megabyte hex literal would make the corpus unreviewable, so a large
/// payload is a rule instead. Both implementations build the bytes from the
/// same rule and the runner compares them byte-for-byte before decoding, so the
/// rule is a shared input rather than a shared assumption.
fn build_segments(segments: &[JsonValue]) -> Vec<u8> {
    let mut out = Vec::new();
    for segment in segments {
        if let Some(literal) = string_field(segment, "literal_hex") {
            out.extend_from_slice(&decode_hex(&literal));
            continue;
        }
        let unit = decode_hex(&required_string(segment, "repeat_hex"));
        let count = required_usize(segment, "count");
        match unit.as_slice() {
            [byte] => out.resize(out.len() + count, *byte),
            _ => {
                out.reserve(unit.len() * count);
                for _ in 0..count {
                    out.extend_from_slice(&unit);
                }
            }
        }
    }
    out
}

fn value_fixture(item: &JsonValue, bytes: Vec<u8>) -> Fixture {
    Fixture {
        id: required_string(item, "id"),
        bytes,
        accept: string_field(item, "outcome").as_deref() == Some("accept"),
        category: string_field(item, "category"),
    }
}

fn load_corpus() -> Corpus {
    let raw = std::fs::read(corpus_path()).expect("corpus is checked in");
    // The corpus is pretty-printed for review and the crate's parser accepts
    // only canonical bytes, so it is normalized here. `serde` is unavailable by
    // design, so the corpus is parsed with the crate's own parser.
    let document = parse_canonical(&normalize(&raw)).expect("corpus parses");

    let fixtures = array_field(&document, "fixtures")
        .iter()
        .map(|item| {
            let bytes = decode_hex(&required_string(item, "bytes_hex"));
            value_fixture(item, bytes)
        })
        .collect();
    let generated = array_field(&document, "generated_fixtures")
        .iter()
        .map(|item| {
            let bytes = build_segments(array_field(item, "segments"));
            value_fixture(item, bytes)
        })
        .collect();
    let enums = array_field(&document, "enums")
        .iter()
        .map(|item| EnumDeclaration {
            id: required_string(item, "id"),
            field: required_string(item, "field"),
            kind: required_string(item, "kind"),
            known: string_list(item, "known"),
        })
        .collect();
    let enum_fixtures = array_field(&document, "enum_fixtures")
        .iter()
        .map(|item| {
            let accept = string_field(item, "outcome").as_deref() == Some("accept");
            EnumFixture {
                id: required_string(item, "id"),
                enum_id: required_string(item, "enum"),
                bytes: decode_hex(&required_string(item, "bytes_hex")),
                expected: required_string(item, if accept { "decoded" } else { "category" }),
            }
        })
        .collect();
    let frames = array_field(&document, "frame_fixtures")
        .iter()
        .map(|item| {
            let expectation = item.get("decode").expect("frame fixture declares a decode");
            let decode = match required_string(expectation, "outcome").as_str() {
                "frame" => FrameExpect::Frame {
                    consumed: required_usize(expectation, "consumed"),
                    payload_bytes: required_usize(expectation, "payload_bytes"),
                },
                "need_more" => FrameExpect::NeedMore {
                    additional: required_usize(expectation, "additional"),
                },
                "reject" => FrameExpect::Reject {
                    category: required_string(expectation, "category"),
                },
                other => panic!("unknown frame decode outcome {other}"),
            };
            let encode = item.get("encode").map(|clause| FrameEncode {
                payload: build_segments(array_field(clause, "payload")),
                accept: string_field(clause, "outcome").as_deref() == Some("accept"),
                category: string_field(clause, "category"),
            });
            FrameFixture {
                id: required_string(item, "id"),
                input: build_segments(array_field(item, "input")),
                decode,
                encode,
            }
        })
        .collect();

    let declared = array_field(&document, "supported_protocols");
    let supported_names: Vec<String> = declared
        .iter()
        .map(|item| required_string(item, "protocol"))
        .collect();
    let supported = declared
        .iter()
        .map(|item| {
            let name = ProtocolName::new(required_string(item, "protocol"))
                .expect("declared protocol name is valid");
            let low = MajorVersion::new(
                u32::try_from(required_usize(item, "min_version")).expect("major version fits"),
            )
            .expect("declared minimum is a version");
            let high = MajorVersion::new(
                u32::try_from(required_usize(item, "max_version")).expect("major version fits"),
            )
            .expect("declared maximum is a version");
            SupportedProtocol::new(
                name,
                VersionRange::new(low, high).expect("declared range is not inverted"),
            )
        })
        .collect();

    Corpus {
        fixtures,
        generated,
        envelope_ids: string_list(&document, "envelope_ids"),
        enums,
        enum_fixtures,
        frames,
        supported,
        supported_names,
    }
}

/// Re-serialize the checked-in corpus into canonical form.
///
/// The file is pretty-printed for review; the crate's parser accepts only
/// canonical bytes. Normalizing here keeps the corpus human-readable without
/// weakening the parser, which is the thing under test.
fn normalize(raw: &[u8]) -> Vec<u8> {
    let text = core::str::from_utf8(raw).expect("corpus is UTF-8");
    let mut out = Vec::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    for byte in text.bytes() {
        if in_string {
            out.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => {
                in_string = true;
                out.push(byte);
            }
            b' ' | b'\n' | b'\r' | b'\t' => {}
            _ => out.push(byte),
        }
    }
    // Key order in the file is already ascending, so stripping whitespace is
    // sufficient to reach canonical form.
    out
}

/// A JavaScript runtime that can execute the `.ts` conformance runner.
///
/// The capability rather than the name: `run.ts` is TypeScript, so a `node`
/// too old to strip types answers `--version` happily and then fails with
/// `ERR_UNKNOWN_FILE_EXTENSION`, which names the wrong problem. bun is probed
/// first because it is the runtime the conformance verdict was measured under.
fn javascript_runtime() -> Option<&'static str> {
    ["bun", "node"]
        .into_iter()
        .find(|candidate| runs_typescript(candidate))
}

/// Whether `candidate` can execute a TypeScript file.
fn runs_typescript(candidate: &str) -> bool {
    static PROBE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    // Unique per call: these tests run as threads of one process, so a fixed
    // name would let one probe delete the file another is about to run.
    let probe = std::env::temp_dir().join(format!(
        "automonique-xlang-runtime-probe-{}-{}.ts",
        std::process::id(),
        PROBE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    if std::fs::write(&probe, "const ok: string = \"ok\";\nconsole.log(ok);\n").is_err() {
        return false;
    }
    let ran = Command::new(candidate)
        .arg(&probe)
        .output()
        .is_ok_and(|output| output.status.success());
    let _ = std::fs::remove_file(&probe);
    ran
}

/// Set to demand the JavaScript toolchain rather than tolerate its absence.
///
/// CI sets it, because on a runner a missing toolchain is a broken job
/// definition, not a fact about the environment. Locally it is unset, so a
/// contributor without bun installed still gets a green run.
///
/// A second copy of the same three lines lives in `codegen.rs`, because each
/// file in `tests/` is its own binary; `javascript_runtime` above is duplicated
/// for the same reason. Both must move together.
const REQUIRE_JS_TOOLCHAIN_ENV: &str = "AUTOMONIQUE_REQUIRE_JS_TOOLCHAIN";

fn js_toolchain_required() -> bool {
    std::env::var(REQUIRE_JS_TOOLCHAIN_ENV).is_ok_and(|value| !value.is_empty() && value != "0")
}

/// Record a claim that needed the JavaScript toolchain to measure.
///
/// Under [`REQUIRE_JS_TOOLCHAIN_ENV`] a missing runtime is a failure rather
/// than a note: on a runner that never installed bun, this suite would
/// otherwise write a `"measured":false` evidence file and pass, which is a
/// green cross-language conformance result for a comparison that never
/// happened.
///
/// Unset, it prints the gap as a `::warning::` annotation. Cargo captures test
/// output without `--nocapture`, so the annotation is belt and braces; the env
/// var is what makes CI honest.
#[track_caller]
fn record_js_gap(note: &str) {
    assert!(
        !js_toolchain_required(),
        "GAP: {note}\n{REQUIRE_JS_TOOLCHAIN_ENV} is set, so an unmeasured claim is a \
         failure: install the JavaScript toolchain or stop asking CI to prove this."
    );
    eprintln!("::warning::GAP: {note}");
}

/// A security-sensitive enum: an undefined value is refused, never defaulted.
///
/// Declared here rather than in the crate because the corpus needs a concrete
/// enum to drive `decode_security_enum` with, and R1-06 adds no protocol
/// semantics. The corpus mirrors this definition and
/// `the_corpus_mirrors_the_rust_enum_definitions` fails if the two drift.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApprovalDecision {
    Allow,
    Ask,
    Deny,
}

impl ApprovalDecision {
    const KNOWN: [&'static str; 3] = ["allow", "ask", "deny"];

    const fn as_wire(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }
}

impl SecuritySensitiveEnum for ApprovalDecision {
    const FIELD: &'static str = "decision";

    fn from_wire(value: &str) -> Option<Self> {
        match value {
            "allow" => Some(Self::Allow),
            "ask" => Some(Self::Ask),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

/// A read-only enum: an undefined value is retained with its spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunState {
    Failed,
    Queued,
    Running,
    Succeeded,
}

impl RunState {
    const KNOWN: [&'static str; 4] = ["failed", "queued", "running", "succeeded"];

    const fn as_wire(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
        }
    }
}

impl ReadOnlyEnum for RunState {
    const FIELD: &'static str = "state";

    fn from_wire(value: &str) -> Option<Self> {
        match value {
            "failed" => Some(Self::Failed),
            "queued" => Some(Self::Queued),
            "running" => Some(Self::Running),
            "succeeded" => Some(Self::Succeeded),
            _ => None,
        }
    }
}

/// Decode one enum fixture and report what was observed, in the encoding both
/// implementations use: `known:<spelling>`, `unknown:<spelling>`, or the
/// refusal category.
fn observe_enum(declaration: &EnumDeclaration, bytes: &[u8]) -> String {
    let observed = (|| -> Result<String, CodecError> {
        let value = parse_canonical(bytes)?;
        let spelling = value
            .get(&declaration.field)
            .ok_or(CodecError::MissingField { field: "enum" })?
            .as_str()
            .ok_or(CodecError::InvalidJsonValue { field: "enum" })?;
        match declaration.id.as_str() {
            "approval_decision" => decode_security_enum::<ApprovalDecision>(spelling)
                .map(|decision| format!("known:{}", decision.as_wire())),
            "run_state" => decode_read_only_enum::<RunState>(spelling).map(|state| match state {
                ReadOnly::Known(known) => format!("known:{}", known.as_wire()),
                ReadOnly::Unknown(retained) => format!("unknown:{retained}"),
            }),
            other => panic!("the corpus declares an enum {other} with no Rust counterpart"),
        }
    })();
    observed.unwrap_or_else(|error| error.category().to_owned())
}

fn frame_bytes(payload: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    encode_frame(payload, &mut out)?;
    Ok(out)
}

#[test]
fn the_corpus_covers_the_declared_edges() {
    let corpus = load_corpus();
    assert!(
        corpus.fixtures.len() >= 60,
        "corpus shrank to {} value fixtures",
        corpus.fixtures.len()
    );
    assert!(!corpus.envelope_ids.is_empty(), "no envelope fixtures");

    let ids: Vec<&str> = corpus
        .fixtures
        .iter()
        .chain(corpus.generated.iter())
        .map(|fixture| fixture.id.as_str())
        .chain(
            corpus
                .enum_fixtures
                .iter()
                .map(|fixture| fixture.id.as_str()),
        )
        .chain(corpus.frames.iter().map(|fixture| fixture.id.as_str()))
        .collect();
    // Required coverage from the R1-06 contract.
    for required in [
        // Integer, string and nesting edges.
        "integer-i64-max",
        "integer-i64-min",
        "string-multibyte",
        "string-escapes",
        "nesting-at-ceiling",
        "nesting-one-past-ceiling",
        "duplicate-key",
        "malformed-invalid-utf8",
        // Empty and maximal payloads.
        "string-empty",
        "array-empty",
        "object-empty",
        "string-at-json-string-ceiling",
        "string-one-past-json-string-ceiling",
        "array-at-entry-ceiling",
        "array-one-past-entry-ceiling",
        // Frame edges.
        "frame-zero-length",
        "frame-at-max-bytes",
        "frame-one-past-max-bytes",
        "frame-need-more-prefix",
        "frame-need-more-payload",
        // Compatibility tolerance.
        "envelope-unknown-additive-field",
        "read-only-enum-unknown",
        "enum-read-only-known",
        "enum-read-only-unknown-value",
        "enum-read-only-unknown-one-past-max-bytes",
        "enum-security-known",
        "enum-security-unknown",
        // Negotiation.
        "envelope-unknown-protocol",
        "envelope-unsupported-major",
        // Bounded wire fields at their exact and over-limit bound.
        "envelope-protocol-at-max-bytes",
        "envelope-protocol-one-past-max-bytes",
        "envelope-request-id-at-max-bytes",
        "envelope-request-id-one-past-max-bytes",
        "envelope-kind-at-max-bytes",
        "envelope-kind-one-past-max-bytes",
    ] {
        assert!(
            ids.contains(&required),
            "corpus lost coverage of {required}"
        );
    }

    let mut seen = ids.clone();
    seen.sort_unstable();
    let total = seen.len();
    seen.dedup();
    assert_eq!(seen.len(), total, "corpus contains a duplicate fixture id");

    let mut names = corpus.supported_names.clone();
    names.sort_unstable();
    let declared = names.len();
    names.dedup();
    assert_eq!(
        names.len(),
        declared,
        "two supported protocols share a name, which makes admission order-dependent"
    );
}

#[test]
fn the_corpus_mirrors_the_rust_enum_definitions() {
    let corpus = load_corpus();
    assert_eq!(corpus.enums.len(), 2, "the corpus lost an enum declaration");
    for declaration in &corpus.enums {
        let (kind, field, known): (&str, &str, &[&str]) = match declaration.id.as_str() {
            "approval_decision" => (
                "security_sensitive",
                ApprovalDecision::FIELD,
                &ApprovalDecision::KNOWN,
            ),
            "run_state" => ("read_only", RunState::FIELD, &RunState::KNOWN),
            other => panic!("the corpus declares an enum {other} with no Rust counterpart"),
        };
        assert_eq!(declaration.kind, kind, "{} changed kind", declaration.id);
        assert_eq!(declaration.field, field, "{} changed field", declaration.id);
        assert_eq!(
            declaration.known, known,
            "{} drifted from the Rust definition",
            declaration.id
        );
    }
    // The declared spellings are exactly the ones the Rust enums admit.
    for spelling in ApprovalDecision::KNOWN {
        assert!(ApprovalDecision::from_wire(spelling).is_some());
    }
    for spelling in RunState::KNOWN {
        assert!(RunState::from_wire(spelling).is_some());
    }
}

#[test]
fn rust_agrees_with_the_corpus_in_both_outcome_and_bytes() {
    let corpus = load_corpus();
    for fixture in corpus.fixtures.iter().chain(corpus.generated.iter()) {
        match (fixture.accept, corpus.decode(&fixture.id, &fixture.bytes)) {
            (true, Ok(reencoded)) => assert_eq!(
                encode_hex(&reencoded),
                encode_hex(&fixture.bytes),
                "{} did not re-encode to its own bytes",
                fixture.id
            ),
            (true, Err(error)) => {
                panic!("{} should be accepted but was refused: {error}", fixture.id)
            }
            (false, Ok(_)) => panic!("{} should be refused but was accepted", fixture.id),
            (false, Err(error)) => assert_eq!(
                error.category(),
                fixture
                    .category
                    .as_deref()
                    .expect("reject fixtures name a category"),
                "{} was refused with the wrong category",
                fixture.id
            ),
        }
    }
}

#[test]
fn rust_agrees_with_the_enum_corpus() {
    let corpus = load_corpus();
    assert!(
        corpus.enum_fixtures.len() >= 7,
        "the enum corpus shrank to {}",
        corpus.enum_fixtures.len()
    );
    for fixture in &corpus.enum_fixtures {
        let declaration = corpus
            .enums
            .iter()
            .find(|declaration| declaration.id == fixture.enum_id)
            .unwrap_or_else(|| panic!("{} names an undeclared enum", fixture.id));
        assert_eq!(
            observe_enum(declaration, &fixture.bytes),
            fixture.expected,
            "{} did not decode as the corpus declares",
            fixture.id
        );
    }
}

#[test]
fn rust_agrees_with_the_frame_corpus() {
    let corpus = load_corpus();
    assert!(
        corpus.frames.len() >= 8,
        "the frame corpus shrank to {}",
        corpus.frames.len()
    );
    for fixture in &corpus.frames {
        match &fixture.decode {
            FrameExpect::Frame {
                consumed,
                payload_bytes,
            } => match decode_frame(&fixture.input).expect("frame decodes") {
                FrameDecode::Frame {
                    payload,
                    consumed: observed,
                } => {
                    assert_eq!(
                        observed, *consumed,
                        "{} consumed the wrong count",
                        fixture.id
                    );
                    assert_eq!(
                        payload.len(),
                        *payload_bytes,
                        "{} yielded the wrong payload length",
                        fixture.id
                    );
                }
                FrameDecode::NeedMore { additional } => {
                    panic!("{} asked for {additional} more bytes", fixture.id)
                }
            },
            FrameExpect::NeedMore { additional } => {
                match decode_frame(&fixture.input).expect("incomplete frames are not refusals") {
                    FrameDecode::NeedMore {
                        additional: observed,
                    } => assert_eq!(
                        observed.get(),
                        *additional,
                        "{} asked for the wrong number of bytes",
                        fixture.id
                    ),
                    FrameDecode::Frame { consumed, .. } => {
                        panic!(
                            "{} decoded {consumed} bytes from an incomplete frame",
                            fixture.id
                        )
                    }
                }
            }
            FrameExpect::Reject { category } => assert_eq!(
                decode_frame(&fixture.input)
                    .expect_err("the corpus declares a refusal")
                    .category(),
                category,
                "{} was refused with the wrong category",
                fixture.id
            ),
        }

        let Some(encode) = &fixture.encode else {
            continue;
        };
        match (encode.accept, frame_bytes(&encode.payload)) {
            (true, Ok(encoded)) => {
                assert_eq!(
                    encoded.len(),
                    encode.payload.len() + 4,
                    "{} did not carry a four-byte prefix",
                    fixture.id
                );
                match decode_frame(&encoded).expect("an encoded frame decodes") {
                    FrameDecode::Frame { payload, consumed } => {
                        assert_eq!(payload, encode.payload.as_slice());
                        assert_eq!(consumed, encoded.len());
                    }
                    FrameDecode::NeedMore { .. } => {
                        panic!("{} produced a frame it cannot decode", fixture.id)
                    }
                }
            }
            (true, Err(error)) => panic!("{} should encode but was refused: {error}", fixture.id),
            (false, Ok(_)) => panic!("{} should not encode but did", fixture.id),
            (false, Err(error)) => assert_eq!(
                error.category(),
                encode
                    .category
                    .as_deref()
                    .expect("a refusing encode clause names a category"),
                "{} was refused with the wrong category",
                fixture.id
            ),
        }
    }
}

/// Read a tally the runner recorded, so the Rust side judges the run by the
/// numbers rather than by its exit status alone.
fn tally(document: &JsonValue, section: &str, key: &str) -> i64 {
    document
        .get(section)
        .and_then(|value| value.get(key))
        .and_then(JsonValue::as_integer)
        .unwrap_or_else(|| panic!("the results artifact has no {section}.{key}"))
}

#[test]
fn both_directions_agree_across_languages() {
    let corpus = load_corpus();
    let directory = std::env::temp_dir().join(format!(
        "automonique-wire-conformance-{}",
        std::process::id()
    ));
    let exchange = directory.join("exchange");
    std::fs::create_dir_all(&exchange).expect("scratch directory");
    let rust_encoded_path = directory.join("rust-encoded.json");
    let results_path = directory.join("results.json");
    let exchanged = |id: &str, suffix: &str| exchange.join(format!("{id}.{suffix}.bin"));

    // Rust encodes every accepted literal fixture for the other runtime to
    // decode. Hex is fine for these: the largest is a few hundred bytes.
    let mut rust_encoded: BTreeMap<String, String> = BTreeMap::new();
    for fixture in corpus.fixtures.iter().filter(|fixture| fixture.accept) {
        let bytes = corpus
            .decode(&fixture.id, &fixture.bytes)
            .expect("accepted fixture decodes");
        rust_encoded.insert(fixture.id.clone(), encode_hex(&bytes));
    }
    let encoded_document = format!(
        "{{{}}}",
        rust_encoded
            .iter()
            .map(|(id, hex)| format!("\"{id}\":\"{hex}\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    std::fs::write(&rust_encoded_path, &encoded_document).expect("write rust artifact");

    // Generated and frame fixtures are exchanged as files, because a fixture
    // that is megabytes wide cannot travel through a JSON string this crate's
    // own parser would refuse as over-long.
    for fixture in &corpus.generated {
        std::fs::write(exchanged(&fixture.id, "input"), &fixture.bytes).expect("write input");
        if fixture.accept {
            let bytes = corpus
                .decode(&fixture.id, &fixture.bytes)
                .expect("accepted generated fixture decodes");
            std::fs::write(exchanged(&fixture.id, "rust"), &bytes).expect("write rust bytes");
        }
    }
    let mut frame_encode_clauses = 0_usize;
    for fixture in &corpus.frames {
        std::fs::write(exchanged(&fixture.id, "input"), &fixture.input).expect("write input");
        if let Some(encode) = &fixture.encode {
            frame_encode_clauses += 1;
            if encode.accept {
                let bytes = frame_bytes(&encode.payload).expect("accepted payload frames");
                std::fs::write(exchanged(&fixture.id, "rust"), &bytes).expect("write rust frame");
            }
        }
    }

    let Some(runtime) = javascript_runtime() else {
        // The claim is unmeasured, not passing. Record it as such and say why.
        let unmeasured = concat!(
            "{\"schema\":\"automonique.wire-conformance/v1\",\"measured\":false,",
            "\"reason\":\"no JavaScript runtime is installed; the cross-language ",
            "claim is unmeasured rather than passing\"}"
        );
        std::fs::write(&results_path, unmeasured).expect("write gap record");
        record_js_gap(&format!(
            "no JavaScript runtime; cross-language conformance is unmeasured. \
             Evidence written to {}",
            results_path.display()
        ));
        return;
    };

    let output = Command::new(runtime)
        .arg(runner_path())
        .arg(corpus_path())
        .arg(&rust_encoded_path)
        .arg(&results_path)
        .arg(&exchange)
        .output()
        .expect("conformance runner starts");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "conformance runner failed under {runtime}\nstdout: {stdout}\nstderr: {stderr}"
    );

    let results = std::fs::read(&results_path).expect("runner wrote results");
    let document = parse_canonical(&normalize(&results)).expect("results parse");
    assert_eq!(
        document.get("measured").and_then(|value| match value {
            JsonValue::Bool(flag) => Some(*flag),
            _ => None,
        }),
        Some(true),
        "a measured run must say so"
    );
    assert_eq!(
        document.get("categories_unknown_to_this_implementation"),
        Some(&JsonValue::Array(Vec::new())),
        "the corpus names a refusal category the other implementation cannot produce"
    );

    // Judge the run by its recorded tallies, not by its exit status: a runner
    // that skipped a section would still exit zero.
    let value_fixtures = i64::try_from(corpus.value_fixture_count()).expect("count fits");
    assert_eq!(
        document.get("fixtures").and_then(JsonValue::as_integer),
        Some(value_fixtures),
        "the runner saw a different number of value fixtures"
    );
    for section in ["rust_encode_bun_decode", "bun_encode_rust_decode"] {
        assert_eq!(
            tally(&document, section, "pass"),
            value_fixtures,
            "{section}"
        );
        assert_eq!(tally(&document, section, "fail"), 0, "{section}");
        assert_eq!(tally(&document, section, "gap"), 0, "{section}");
        assert_eq!(tally(&document, section, "absent"), 0, "{section}");
    }
    let enum_fixtures = i64::try_from(corpus.enum_fixtures.len()).expect("count fits");
    assert_eq!(tally(&document, "enum_tally", "pass"), enum_fixtures);
    assert_eq!(tally(&document, "enum_tally", "fail"), 0);
    let frames = i64::try_from(corpus.frames.len()).expect("count fits");
    let clauses = i64::try_from(frame_encode_clauses).expect("count fits");
    for section in ["frame_input_agreement", "frame_decode"] {
        assert_eq!(tally(&document, section, "pass"), frames, "{section}");
        assert_eq!(tally(&document, section, "fail"), 0, "{section}");
        assert_eq!(tally(&document, section, "gap"), 0, "{section}");
    }
    for section in ["frame_encode_rust_to_bun", "frame_encode_bun_to_rust"] {
        assert_eq!(tally(&document, section, "pass"), clauses, "{section}");
        assert_eq!(tally(&document, section, "fail"), 0, "{section}");
        assert_eq!(tally(&document, section, "gap"), 0, "{section}");
        assert_eq!(
            tally(&document, section, "absent"),
            frames - clauses,
            "{section}"
        );
    }

    // Direction two, literal fixtures: decode what the other runtime encoded.
    let JsonValue::Array(entries) = document.get("results").expect("results list") else {
        panic!("results is not an array");
    };
    let mut checked = 0_usize;
    for entry in entries {
        let id = string_field(entry, "id").expect("result id");
        let Some(hex) = string_field(entry, "bun_encoded_hex") else {
            continue;
        };
        let bytes = decode_hex(&hex);
        let fixture = corpus
            .fixtures
            .iter()
            .find(|fixture| fixture.id == id)
            .expect("result names a corpus fixture");
        let reencoded = corpus
            .decode(&id, &bytes)
            .unwrap_or_else(|error| panic!("{id}: Rust refused runtime-encoded bytes: {error}"));
        assert_eq!(
            encode_hex(&reencoded),
            encode_hex(&fixture.bytes),
            "{id}: runtime-encoded bytes do not match the fixture"
        );
        checked += 1;
    }
    assert_eq!(
        checked,
        corpus
            .fixtures
            .iter()
            .filter(|fixture| fixture.accept)
            .count(),
        "the runtime-to-Rust direction skipped a literal fixture"
    );

    // Direction two, generated fixtures: the same comparison over files.
    for fixture in corpus.generated.iter().filter(|fixture| fixture.accept) {
        let bytes = std::fs::read(exchanged(&fixture.id, "bun"))
            .unwrap_or_else(|_| panic!("{}: the runtime wrote no artifact", fixture.id));
        let reencoded = corpus.decode(&fixture.id, &bytes).unwrap_or_else(|error| {
            panic!(
                "{}: Rust refused runtime-encoded bytes: {error}",
                fixture.id
            )
        });
        assert_eq!(
            reencoded.len(),
            fixture.bytes.len(),
            "{}: runtime-encoded bytes differ in length",
            fixture.id
        );
        assert!(
            reencoded == fixture.bytes,
            "{}: runtime-encoded bytes do not match the fixture",
            fixture.id
        );
    }

    // Direction two, frames: byte-for-byte on the frame the other runtime
    // built, including the four-byte big-endian prefix.
    for fixture in &corpus.frames {
        let Some(encode) = &fixture.encode else {
            continue;
        };
        if !encode.accept {
            continue;
        }
        let ours = frame_bytes(&encode.payload).expect("accepted payload frames");
        let theirs = std::fs::read(exchanged(&fixture.id, "bun"))
            .unwrap_or_else(|_| panic!("{}: the runtime wrote no frame", fixture.id));
        assert_eq!(
            theirs.len(),
            ours.len(),
            "{}: the two frames differ in length",
            fixture.id
        );
        assert!(
            theirs == ours,
            "{}: the two frames differ byte-for-byte",
            fixture.id
        );
        match decode_frame(&theirs).expect("the runtime's frame decodes") {
            FrameDecode::Frame { payload, consumed } => {
                assert_eq!(payload, encode.payload.as_slice(), "{}", fixture.id);
                assert_eq!(consumed, theirs.len(), "{}", fixture.id);
            }
            FrameDecode::NeedMore { .. } => {
                panic!("{}: the runtime's frame is incomplete", fixture.id)
            }
        }
    }

    println!("cross-language conformance under {runtime}: {stdout}");
    // Only on success: a failing run leaves its artifacts for inspection.
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn the_runner_and_corpus_are_present() {
    assert!(
        corpus_path().is_file(),
        "the fixture corpus is not checked in"
    );
    assert!(
        Path::new(&runner_path()).is_file(),
        "the conformance runner is not checked in"
    );
}
