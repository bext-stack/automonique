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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use automonique_protocol::codec::CodecError;
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

/// One fixture, parsed with the crate's own codec rather than a JSON library.
struct Fixture {
    id: String,
    bytes: Vec<u8>,
    accept: bool,
    category: Option<String>,
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

fn load_corpus() -> (Vec<Fixture>, Vec<String>) {
    let raw = std::fs::read(corpus_path()).expect("corpus is checked in");
    // The corpus is itself canonical-JSON-compatible input for our own parser
    // only after normalization, so parse it with a tolerant read: it is data,
    // not wire input. `serde` is unavailable here by design, so the corpus is
    // written canonically and parsed with the crate's parser.
    let document = parse_canonical(&normalize(&raw)).expect("corpus parses");
    let envelope_ids = match document.get("envelope_ids") {
        Some(JsonValue::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    };
    let fixtures = match document.get("fixtures") {
        Some(JsonValue::Array(items)) => items
            .iter()
            .map(|item| Fixture {
                id: string_field(item, "id").expect("fixture id"),
                bytes: decode_hex(&string_field(item, "bytes_hex").expect("fixture bytes")),
                accept: string_field(item, "outcome").as_deref() == Some("accept"),
                category: string_field(item, "category"),
            })
            .collect(),
        _ => panic!("corpus has no fixture list"),
    };
    (fixtures, envelope_ids)
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

fn javascript_runtime() -> Option<&'static str> {
    ["bun", "node"].into_iter().find(|candidate| {
        Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    })
}

#[test]
fn the_corpus_covers_the_declared_edges() {
    let (fixtures, envelope_ids) = load_corpus();
    assert!(
        fixtures.len() >= 40,
        "corpus shrank to {} fixtures",
        fixtures.len()
    );
    assert!(!envelope_ids.is_empty(), "no envelope fixtures declared");

    let ids: Vec<&str> = fixtures.iter().map(|fixture| fixture.id.as_str()).collect();
    // Required coverage from the R1-06 contract.
    for required in [
        "integer-i64-max",
        "integer-i64-min",
        "string-multibyte",
        "string-escapes",
        "nesting-at-ceiling",
        "nesting-one-past-ceiling",
        "envelope-unknown-additive-field",
        "read-only-enum-unknown",
        "duplicate-key",
        "malformed-invalid-utf8",
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
}

#[test]
fn rust_agrees_with_the_corpus_in_both_outcome_and_bytes() {
    let (fixtures, envelope_ids) = load_corpus();
    for fixture in &fixtures {
        let is_envelope = envelope_ids.contains(&fixture.id);
        let outcome: Result<Vec<u8>, CodecError> = if is_envelope {
            Message::from_canonical_bytes(&fixture.bytes)
                .map(|message| message.to_canonical_bytes())
        } else {
            parse_canonical(&fixture.bytes).map(|value| value.to_canonical_bytes())
        };
        match (fixture.accept, outcome) {
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
fn both_directions_agree_across_languages() {
    let (fixtures, envelope_ids) = load_corpus();
    let directory = std::env::temp_dir().join(format!(
        "automonique-wire-conformance-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("scratch directory");
    let rust_encoded_path = directory.join("rust-encoded.json");
    let results_path = directory.join("results.json");

    // Rust encodes every accepted fixture for the other runtime to decode.
    let mut rust_encoded: BTreeMap<String, String> = BTreeMap::new();
    for fixture in fixtures.iter().filter(|fixture| fixture.accept) {
        let bytes = if envelope_ids.contains(&fixture.id) {
            Message::from_canonical_bytes(&fixture.bytes)
                .expect("accepted envelope fixture decodes")
                .to_canonical_bytes()
        } else {
            parse_canonical(&fixture.bytes)
                .expect("accepted fixture decodes")
                .to_canonical_bytes()
        };
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

    let Some(runtime) = javascript_runtime() else {
        // The claim is unmeasured, not passing. Record it as such and say why.
        let unmeasured = concat!(
            "{\"schema\":\"automonique.wire-conformance/v1\",\"measured\":false,",
            "\"reason\":\"no JavaScript runtime is installed; the cross-language ",
            "claim is unmeasured rather than passing\"}"
        );
        std::fs::write(&results_path, unmeasured).expect("write gap record");
        eprintln!(
            "GAP: no JavaScript runtime; cross-language conformance is unmeasured. \
             Evidence written to {}",
            results_path.display()
        );
        return;
    };

    let output = Command::new(runtime)
        .arg(runner_path())
        .arg(corpus_path())
        .arg(&rust_encoded_path)
        .arg(&results_path)
        .output()
        .expect("conformance runner starts");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "conformance runner failed under {runtime}\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Direction two: decode what the other runtime encoded.
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
        let fixture = fixtures
            .iter()
            .find(|fixture| fixture.id == id)
            .expect("result names a corpus fixture");
        if envelope_ids.contains(&id) {
            Message::from_canonical_bytes(&bytes).unwrap_or_else(|error| {
                panic!("{id}: Rust refused runtime-encoded bytes: {error}")
            });
        }
        let value = parse_canonical(&bytes)
            .unwrap_or_else(|error| panic!("{id}: Rust refused runtime-encoded bytes: {error}"));
        assert_eq!(
            encode_hex(&value.to_canonical_bytes()),
            encode_hex(&fixture.bytes),
            "{id}: runtime-encoded bytes do not match the fixture"
        );
        checked += 1;
    }
    assert!(
        checked >= fixtures.iter().filter(|fixture| fixture.accept).count(),
        "only {checked} fixtures were checked in the runtime-to-Rust direction"
    );

    println!("cross-language conformance under {runtime}: {stdout}");
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
