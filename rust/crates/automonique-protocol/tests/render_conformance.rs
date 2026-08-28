// SPDX-License-Identifier: Elastic-2.0

use std::collections::BTreeSet;

use automonique_protocol::platform_v2_review::{
    AttentionReason, AttentionState, CheckState, DeliveryState, MergeReadiness, PreviewKind,
    PullRequestState, ReviewDecision, ReviewFreshnessState,
};
use automonique_protocol::wire::{JsonValue, parse_canonical};

const MAX_SAFE_JAVASCRIPT_INTEGER: u64 = 9_007_199_254_740_991;
const CORPUS: &[u8] = include_bytes!("../fixtures/platform-v2-render-conformance-v1.json");

fn field<'a>(value: &'a JsonValue, name: &str) -> &'a JsonValue {
    value
        .get(name)
        .unwrap_or_else(|| panic!("render corpus value has no {name}"))
}

fn text<'a>(value: &'a JsonValue, name: &str) -> &'a str {
    field(value, name)
        .as_str()
        .unwrap_or_else(|| panic!("render corpus {name} is not text"))
}

fn items<'a>(value: &'a JsonValue, name: &str) -> &'a [JsonValue] {
    field(value, name)
        .as_array()
        .unwrap_or_else(|| panic!("render corpus {name} is not an array"))
}

fn decimal(value: &str) -> u64 {
    assert!(
        value == "0"
            || (!value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit())),
        "revision is not a canonical decimal: {value}"
    );
    value.parse().expect("revision fits the protocol u64 fence")
}

fn nullable_text<'a>(value: &'a JsonValue, name: &str) -> Option<&'a str> {
    match field(value, name) {
        JsonValue::Null => None,
        JsonValue::String(value) => Some(value),
        _ => panic!("render corpus {name} is neither text nor null"),
    }
}

fn assert_fresh_semantic(
    expected: &JsonValue,
    input: &JsonValue,
    prefix: &str,
    state: &str,
    root_revision: u64,
) {
    assert_eq!(text(expected, "semantic_key"), format!("{prefix}.{state}"));
    let freshness = field(input, "freshness");
    let freshness_state = text(freshness, "state");
    assert_eq!(
        text(expected, "freshness_key"),
        format!("freshness.{freshness_state}")
    );
    let source_revision = text(expected, "source_revision");
    assert_eq!(source_revision, text(freshness, "observed_revision"));
    assert!(decimal(source_revision) <= root_revision);
}

#[test]
fn canonical_render_corpus_covers_every_declared_semantic_without_numeric_loss() {
    let corpus = parse_canonical(CORPUS).expect("render corpus is canonical JSON");
    assert_eq!(corpus.to_canonical_bytes(), CORPUS);
    assert_eq!(text(&corpus, "schema"), "automonique.render-conformance/v1");
    assert_eq!(text(&corpus, "version"), "1");

    let mut attention_states = BTreeSet::new();
    let mut review_states = BTreeSet::new();
    let mut check_states = BTreeSet::new();
    let mut pull_request_states = BTreeSet::new();
    let mut readiness_states = BTreeSet::new();
    let mut delivery_states = BTreeSet::new();
    let mut preview_kinds = BTreeSet::new();
    let mut freshness_states = BTreeSet::new();
    let mut case_ids = BTreeSet::new();

    for case in items(&corpus, "cases") {
        assert!(case_ids.insert(text(case, "id")));
        let input = field(case, "input");
        let expected = field(case, "expected");
        let root_revision_text = text(input, "revision");
        let root_revision = decimal(root_revision_text);
        assert!(root_revision > MAX_SAFE_JAVASCRIPT_INTEGER);
        assert_eq!(text(expected, "source_revision"), root_revision_text);

        let attention = field(input, "attention");
        let expected_attention = field(expected, "attention");
        let attention_state = text(attention, "state");
        AttentionState::parse(attention_state).expect("declared attention state");
        attention_states.insert(attention_state);
        assert_eq!(
            text(expected_attention, "semantic_key"),
            format!("attention.{attention_state}")
        );
        let reason = nullable_text(attention, "reason");
        let source_revision = nullable_text(attention, "source_revision");
        if attention_state == "idle" {
            assert_eq!(
                (reason, source_revision, text(attention, "unread")),
                (None, None, "0")
            );
            assert_eq!(nullable_text(expected_attention, "reason_key"), None);
            assert_eq!(nullable_text(expected_attention, "source_revision"), None);
        } else {
            let reason = reason.expect("non-idle attention has a reason");
            AttentionReason::parse(reason).expect("declared attention reason");
            let expected_reason = format!("attention_reason.{reason}");
            assert_eq!(
                nullable_text(expected_attention, "reason_key"),
                Some(expected_reason.as_str())
            );
            let source_revision = source_revision.expect("non-idle attention has a source");
            assert_eq!(
                nullable_text(expected_attention, "source_revision"),
                Some(source_revision)
            );
            assert!(decimal(source_revision) <= root_revision);
        }

        let review = field(input, "review");
        let review_state = text(review, "decision");
        ReviewDecision::parse(review_state).expect("declared review decision");
        review_states.insert(review_state);
        let review_freshness = text(field(review, "freshness"), "state");
        ReviewFreshnessState::parse(review_freshness).expect("declared freshness");
        freshness_states.insert(review_freshness);
        assert_fresh_semantic(
            field(expected, "review"),
            review,
            "review",
            review_state,
            root_revision,
        );

        let expected_checks = items(expected, "checks");
        let checks = items(input, "checks");
        assert_eq!(checks.len(), expected_checks.len());
        for (check, expected_check) in checks.iter().zip(expected_checks) {
            assert_eq!(text(check, "id"), text(expected_check, "id"));
            let state = text(check, "state");
            CheckState::parse(state).expect("declared check state");
            check_states.insert(state);
            let requirement = match field(check, "required") {
                JsonValue::Bool(true) => "required",
                JsonValue::Bool(false) => "optional",
                _ => panic!("check required is not boolean"),
            };
            assert_fresh_semantic(
                expected_check,
                check,
                "check",
                &format!("{state}.{requirement}"),
                root_revision,
            );
            let state = text(field(check, "freshness"), "state");
            ReviewFreshnessState::parse(state).expect("declared freshness");
            freshness_states.insert(state);
        }

        let pull_request = field(input, "pull_request");
        let pull_request_state = text(pull_request, "state");
        let readiness = text(pull_request, "readiness");
        PullRequestState::parse(pull_request_state).expect("declared pull request state");
        MergeReadiness::parse(readiness).expect("declared merge readiness");
        pull_request_states.insert(pull_request_state);
        readiness_states.insert(readiness);
        assert_fresh_semantic(
            field(expected, "pull_request"),
            pull_request,
            "pull_request",
            &format!("{pull_request_state}.{readiness}"),
            root_revision,
        );

        let delivery = field(input, "delivery");
        let delivery_state = text(delivery, "state");
        DeliveryState::parse(delivery_state).expect("declared delivery state");
        delivery_states.insert(delivery_state);
        assert_fresh_semantic(
            field(expected, "delivery"),
            delivery,
            "delivery",
            delivery_state,
            root_revision,
        );

        let files = items(input, "files");
        let previews = items(expected, "previews");
        assert_eq!(files.len(), previews.len());
        for (file, expected_preview) in files.iter().zip(previews) {
            assert_eq!(text(file, "id"), text(expected_preview, "id"));
            let preview = field(file, "preview");
            let kind = text(preview, "kind");
            PreviewKind::parse(kind).expect("declared preview kind");
            preview_kinds.insert(kind);
            let posture = match field(preview, "sanitized") {
                JsonValue::Bool(true) => "sanitized",
                JsonValue::Bool(false) => "raw",
                _ => panic!("preview sanitized is not boolean"),
            };
            assert_eq!(
                text(expected_preview, "semantic_key"),
                format!("preview.{kind}.{posture}")
            );
            assert_eq!(
                text(expected_preview, "source_revision"),
                root_revision_text
            );
        }
    }

    assert_eq!(
        attention_states,
        AttentionState::ALL.map(AttentionState::as_str).into()
    );
    assert_eq!(
        review_states,
        ReviewDecision::ALL.map(ReviewDecision::as_str).into()
    );
    assert_eq!(check_states, CheckState::ALL.map(CheckState::as_str).into());
    assert_eq!(
        pull_request_states,
        PullRequestState::ALL.map(PullRequestState::as_str).into()
    );
    assert_eq!(
        readiness_states,
        MergeReadiness::ALL.map(MergeReadiness::as_str).into()
    );
    assert_eq!(
        delivery_states,
        DeliveryState::ALL.map(DeliveryState::as_str).into()
    );
    assert_eq!(
        preview_kinds,
        PreviewKind::ALL.map(PreviewKind::as_str).into()
    );
    assert_eq!(
        freshness_states,
        ReviewFreshnessState::ALL
            .map(ReviewFreshnessState::as_str)
            .into()
    );
}
