// SPDX-License-Identifier: Elastic-2.0

//! The shared attention succession corpus.
//!
//! Every client that retains `automonique.platform/attention/v1` across reads
//! must reach the same outcome for the same sequence. This test proves the
//! corpus itself is wire-valid and that the recorded continuous-mode outcomes
//! agree with the contract's own successor rule, so ShellDeck and Mobile can
//! replay the same file against their reducers and be compared to it and to
//! each other rather than to prose.
//!
//! Revisions are carried as decimal strings. A client that routes one through a
//! float loses the corpus values, which sit above 2^53 on purpose.

use automonique_protocol::platform_v2_attention::AttentionSourceSnapshot;
use automonique_protocol::platform_v2_attention_api::decode_attention_source_snapshot;
use automonique_protocol::wire::JsonValue;
use automonique_protocol::wire::parse_canonical;

const CORPUS: &[u8] = include_bytes!("../fixtures/platform-v2-attention-conformance-v1.json");

/// Fields the corpus carries as decimal strings and the wire carries as
/// integers. Everything else crosses unchanged.
const NUMERIC_FIELDS: &[&str] = &["observed_at_ms", "previous_revision", "revision"];

fn field<'a>(value: &'a JsonValue, name: &str) -> &'a JsonValue {
    value
        .get(name)
        .unwrap_or_else(|| panic!("attention corpus value has no {name}"))
}

fn text<'a>(value: &'a JsonValue, name: &str) -> &'a str {
    field(value, name)
        .as_str()
        .unwrap_or_else(|| panic!("attention corpus {name} is not text"))
}

fn items<'a>(value: &'a JsonValue, name: &str) -> &'a [JsonValue] {
    field(value, name)
        .as_array()
        .unwrap_or_else(|| panic!("attention corpus {name} is not an array"))
}

fn canonical_decimal(value: &str) -> i64 {
    assert!(
        value == "0"
            || (!value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit())),
        "attention corpus revision is not a canonical decimal: {value}"
    );
    value
        .parse()
        .expect("attention corpus revision fits the protocol fence")
}

/// Rewrite the corpus's decimal strings into the integers the wire expects,
/// leaving every other value exactly as written.
fn wire_value(value: &JsonValue, key: Option<&str>) -> JsonValue {
    if let (Some(name), JsonValue::String(text)) = (key, value)
        && NUMERIC_FIELDS.contains(&name)
    {
        return JsonValue::Integer(canonical_decimal(text));
    }
    match value {
        JsonValue::Array(entries) => JsonValue::Array(
            entries
                .iter()
                .map(|entry| wire_value(entry, None))
                .collect(),
        ),
        JsonValue::Object(entries) => JsonValue::Object(
            entries
                .iter()
                .map(|(name, entry)| (name.clone(), wire_value(entry, Some(name))))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn write_canonical(value: &JsonValue, output: &mut Vec<u8>) {
    match value {
        JsonValue::Null => output.extend_from_slice(b"null"),
        JsonValue::Bool(value) => {
            output.extend_from_slice(if *value { b"true" } else { b"false" });
        }
        JsonValue::Integer(value) => output.extend_from_slice(value.to_string().as_bytes()),
        JsonValue::String(value) => {
            output.push(b'"');
            for byte in value.bytes() {
                match byte {
                    b'"' => output.extend_from_slice(b"\\\""),
                    b'\\' => output.extend_from_slice(b"\\\\"),
                    other => output.push(other),
                }
            }
            output.push(b'"');
        }
        JsonValue::Array(entries) => {
            output.push(b'[');
            for (index, entry) in entries.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical(entry, output);
            }
            output.push(b']');
        }
        JsonValue::Object(entries) => {
            output.push(b'{');
            for (index, (name, entry)) in entries.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical(&JsonValue::String(name.clone()), output);
                output.push(b':');
                write_canonical(entry, output);
            }
            output.push(b'}');
        }
    }
}

fn snapshot_of(value: &JsonValue) -> AttentionSourceSnapshot {
    let mut payload = Vec::new();
    write_canonical(&wire_value(value, None), &mut payload);
    decode_attention_source_snapshot(&payload)
        .expect("every attention corpus snapshot is wire-valid")
}

fn corpus() -> JsonValue {
    parse_canonical(CORPUS).expect("attention corpus is canonical JSON")
}

#[test]
fn corpus_declares_its_schema_target_and_case_identities() {
    let corpus = corpus();
    assert_eq!(
        text(&corpus, "schema"),
        "automonique.attention-conformance/v1"
    );
    assert_eq!(text(&corpus, "version"), "1");
    let target = field(&corpus, "target");
    assert_eq!(text(target, "project"), "project-conformance");
    assert_eq!(text(target, "user_workspace"), "workspace-conformance");

    let cases = items(&corpus, "cases");
    assert!(!cases.is_empty(), "corpus has no cases");
    let ids = cases
        .iter()
        .map(|case| text(case, "id").to_owned())
        .collect::<Vec<_>>();
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(ids.len(), unique.len(), "case identities are not unique");
}

#[test]
fn every_corpus_snapshot_is_wire_valid_and_targets_the_declared_workspace() {
    let corpus = corpus();
    let target = field(&corpus, "target");
    for case in items(&corpus, "cases") {
        let source = field(case, "source");
        for read in items(case, "reads") {
            if text(read, "kind") != "snapshot" {
                continue;
            }
            let snapshot = snapshot_of(field(read, "snapshot"));
            assert_eq!(
                snapshot.project().as_str(),
                text(target, "project"),
                "case {} reads another project",
                text(case, "id")
            );
            assert_eq!(
                snapshot.user_workspace().as_str(),
                text(target, "user_workspace"),
                "case {} reads another workspace",
                text(case, "id")
            );
            assert_eq!(
                snapshot.source().id().as_str(),
                text(source, "id"),
                "case {} reads another source",
                text(case, "id")
            );
        }
    }
}

/// The corpus records what a retaining client must conclude. Once a snapshot is
/// retained the contract itself decides acceptance on both lanes, so the two
/// must agree: a recorded `invalid_successor` is exactly a `validate_successor`
/// refusal, and a recorded `baseline_invalid` is exactly a `validate_baseline`
/// refusal.
#[test]
fn recorded_outcomes_agree_with_the_contract_replacement_rules() {
    let corpus = corpus();
    let mut checked = 0_usize;
    for case in items(&corpus, "cases") {
        let mut retained: Option<AttentionSourceSnapshot> = None;
        for read in items(case, "reads") {
            let kind = text(read, "kind");
            if kind != "snapshot" {
                // A refusal or transport loss hides the projection without
                // touching the retained revision chain.
                continue;
            }
            let candidate = snapshot_of(field(read, "snapshot"));
            let outcome = text(read, "outcome");
            let mode = text(read, "mode");
            let accepted = matches!(
                outcome,
                "inserted" | "replaced" | "exact_replay" | "availability_restored"
            );

            if let Some(current) = &retained
                && current.revision() != candidate.revision()
            {
                let valid = if mode == "continuous" {
                    current.validate_successor(&candidate).is_ok()
                } else {
                    current.validate_baseline(&candidate).is_ok()
                };
                assert_eq!(
                    valid,
                    accepted,
                    "case {} read outcome {outcome} disagrees with the contract",
                    text(case, "id")
                );
                checked += 1;
            }

            if outcome == "exact_replay" || outcome == "availability_restored" {
                assert_eq!(
                    retained.as_ref().map(AttentionSourceSnapshot::revision),
                    Some(candidate.revision()),
                    "case {} replays a revision it does not retain",
                    text(case, "id")
                );
            }
            if accepted {
                retained = Some(candidate);
            }
        }
    }
    assert!(
        checked > 1,
        "the corpus exercises neither replacement lane against a retained snapshot"
    );
}

/// The two lanes are not the same rule. A baseline exists precisely so a client
/// that lost the chain can resynchronize, so it must accept a read the
/// continuous lane has to refuse.
#[test]
fn the_baseline_lane_admits_a_bridged_gap_a_successor_lane_refuses() {
    let corpus = corpus();
    let mut bridged = 0_usize;
    for case in items(&corpus, "cases") {
        let mut retained: Option<AttentionSourceSnapshot> = None;
        for read in items(case, "reads") {
            if text(read, "kind") != "snapshot" {
                continue;
            }
            let candidate = snapshot_of(field(read, "snapshot"));
            let outcome = text(read, "outcome");
            if let Some(current) = &retained
                && text(read, "mode") == "baseline"
                && outcome == "replaced"
                && current.validate_successor(&candidate).is_err()
            {
                assert!(
                    current.validate_baseline(&candidate).is_ok(),
                    "case {} bridges a gap the baseline lane also refuses",
                    text(case, "id")
                );
                bridged += 1;
            }
            if matches!(
                outcome,
                "inserted" | "replaced" | "exact_replay" | "availability_restored"
            ) {
                retained = Some(candidate);
            }
        }
    }
    assert!(bridged > 0, "the corpus never bridges a retention gap");
}

/// A case's expected visible set must be exactly the items of whatever snapshot
/// it retains at the end, and nothing at all once the source is hidden.
#[test]
fn expected_visibility_matches_the_retained_snapshot() {
    let corpus = corpus();
    for case in items(&corpus, "cases") {
        let mut retained: Option<AttentionSourceSnapshot> = None;
        let mut available = false;
        for read in items(case, "reads") {
            match text(read, "kind") {
                "snapshot" => {
                    let outcome = text(read, "outcome");
                    if matches!(
                        outcome,
                        "inserted" | "replaced" | "exact_replay" | "availability_restored"
                    ) {
                        retained = Some(snapshot_of(field(read, "snapshot")));
                        available = true;
                    }
                }
                "refusal" | "unavailable" => available = false,
                other => panic!("unknown corpus read kind {other}"),
            }
        }
        let expected = field(case, "expected");
        let expected_available = matches!(field(expected, "available"), JsonValue::Bool(true));
        assert_eq!(
            expected_available,
            available,
            "case {} records the wrong availability",
            text(case, "id")
        );
        let expected_visible = items(expected, "visible_items")
            .iter()
            .map(|value| value.as_str().expect("visible item id is text"))
            .collect::<Vec<_>>();
        let actual_visible = if available {
            retained
                .as_ref()
                .map(|snapshot| {
                    snapshot
                        .items()
                        .iter()
                        .map(|item| item.id().as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        assert_eq!(
            expected_visible,
            actual_visible,
            "case {} records the wrong visible items",
            text(case, "id")
        );
    }
}
