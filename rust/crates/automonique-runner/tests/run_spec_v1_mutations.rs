// SPDX-License-Identifier: Elastic-2.0

use automonique_runner::{PromptDeliveryPlan, RunOriginSource, RunSpec, RunSpecDecodeError};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const GOLDEN: &[u8] = include_bytes!("fixtures/run_spec_v1_full.cjson");

fn mutate(input: &[u8], from: &str, to: &str) -> Vec<u8> {
    let source = std::str::from_utf8(input).unwrap();
    assert_eq!(
        source.matches(from).count(),
        1,
        "mutation must be unique: {from}"
    );
    source.replacen(from, to, 1).into_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Expected {
    Accepted,
    Refused(RunSpecDecodeError),
}

fn assert_expected(bytes: &[u8], baseline_digest: &str, expected: Expected) {
    match (RunSpec::from_canonical_bytes(bytes), expected) {
        (Ok(spec), Expected::Accepted) => {
            let reencoded = spec.to_canonical_bytes().unwrap();
            assert_eq!(reencoded, bytes);
            assert_ne!(reencoded, GOLDEN);
            let digest = spec.canonical_digest().unwrap();
            let mut independent = Sha256::new();
            independent.update(b"automonique.run-spec/v1\0");
            independent.update(bytes);
            let expected = format!("sha256:{:x}", independent.finalize());
            assert_eq!(digest.as_str(), expected);
            assert_ne!(digest.as_str(), baseline_digest);
        }
        (Err(error), Expected::Refused(expected_error)) => {
            assert_eq!(error, expected_error);
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.is_empty());
            assert!(!rendered.contains("fixture_credential"));
        }
        (actual, expected) => {
            panic!("unexpected ledger outcome: {actual:?}, expected {expected:?}")
        }
    }
}

#[test]
fn every_normative_requirement_row_changes_digest_or_refuses_typed() {
    let baseline = RunSpec::from_canonical_bytes(GOLDEN).unwrap();
    let baseline_digest = baseline.canonical_digest().unwrap();
    let ledger = [
        (
            1,
            "coordinates",
            "\"work_id\":\"work-1\"",
            "\"work_id\":\"work-2\"",
            Expected::Accepted,
        ),
        (
            2,
            "executable",
            "\"version\":\"2.0.0\"",
            "\"version\":\"2.0.1\"",
            Expected::Accepted,
        ),
        (
            3,
            "prompt",
            "\"backend_session\":\"session-1\"",
            "\"backend_session\":\"session-2\"",
            Expected::Refused(RunSpecDecodeError::Domain("run_spec")),
        ),
        (
            4,
            "workspace",
            "\"cwd_token\":\"cwd-1\"",
            "\"cwd_token\":\"cwd-2\"",
            Expected::Accepted,
        ),
        (
            5,
            "environment",
            "\"value_hex\":\"76616c7565\"",
            "\"value_hex\":\"76616c7566\"",
            Expected::Accepted,
        ),
        (
            6,
            "budgets",
            "\"cgroup_memory_bytes\":\"268435456\"",
            "\"cgroup_memory_bytes\":\"268435455\"",
            Expected::Accepted,
        ),
        (
            7,
            "sandbox",
            "\"id\":\"full-profile\"",
            "\"id\":\"full-profile-2\"",
            Expected::Accepted,
        ),
        (
            8,
            "egress",
            "\"provider_control_egress\":\"brokered_named\"",
            "\"provider_control_egress\":\"brokered_any\"",
            Expected::Accepted,
        ),
        (
            9,
            "reservations",
            "\"read_bytes\":\"2048\"",
            "\"read_bytes\":\"2049\"",
            Expected::Accepted,
        ),
        (
            10,
            "nested",
            "\"extensions\":\"stronger_isolation\"",
            "\"extensions\":\"separate_child_boundary\"",
            Expected::Accepted,
        ),
        (
            11,
            "session",
            "\"provider_namespace\":\"fixture-namespace\"",
            "\"provider_namespace\":\"fixture-namespace-2\"",
            Expected::Accepted,
        ),
        (
            12,
            "integration",
            "\"integration_mode\":\"native\"",
            "\"integration_mode\":\"native-2\"",
            Expected::Accepted,
        ),
        (
            13,
            "capabilities",
            "\"name\":\"resume\"",
            "\"name\":\"resume-2\"",
            Expected::Accepted,
        ),
        (
            14,
            "context",
            "\"digest\":\"policy-digest-a\"",
            "\"digest\":\"policy-digest-c\"",
            Expected::Accepted,
        ),
        (
            15,
            "origin",
            "\"event_id\":\"event-1\"",
            "\"event_id\":\"event-2\"",
            Expected::Accepted,
        ),
        (
            16,
            "executor",
            "\"remote_attestation_policy\":\"mutually_authenticated\"",
            "\"remote_attestation_policy\":\"signed\"",
            Expected::Accepted,
        ),
        (
            17,
            "provider_digest",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "sha256:1011111111111111111111111111111111111111111111111111111111111111",
            Expected::Accepted,
        ),
        (
            18,
            "scheduler",
            "\"id\":\"reservation-1\",\"revision\":\"2\"",
            "\"id\":\"reservation-1\",\"revision\":\"3\"",
            Expected::Accepted,
        ),
        (
            19,
            "artifact_credential",
            "\"id\":\"grant-1\",\"revision\":\"2\"",
            "\"id\":\"grant-1\",\"revision\":\"4\"",
            Expected::Accepted,
        ),
        (
            20,
            "event_policy",
            "\"event_dialect\":\"automonique_runner_v1\"",
            "\"event_dialect\":\"automonique_runner_v2\"",
            Expected::Refused(RunSpecDecodeError::Field("event_dialect")),
        ),
    ];
    assert_eq!(ledger.len(), 20);
    assert_eq!(
        ledger
            .iter()
            .map(|(row, ..)| row)
            .copied()
            .collect::<BTreeSet<_>>()
            .len(),
        20
    );
    assert_eq!(
        ledger
            .iter()
            .map(|(_, family, ..)| family)
            .copied()
            .collect::<BTreeSet<_>>()
            .len(),
        20
    );
    for (expected_row, (row, _, from, to, expected)) in (1..=20).zip(ledger) {
        assert_eq!(row, expected_row);
        let bytes = mutate(GOLDEN, from, to);
        assert_expected(&bytes, baseline_digest.as_str(), expected);
    }
}

fn decode_round_trip(bytes: &[u8]) -> RunSpec {
    let spec = RunSpec::from_canonical_bytes(bytes).unwrap();
    assert_eq!(spec.to_canonical_bytes().unwrap(), bytes);
    spec
}

#[test]
fn alternate_prompt_optional_origin_executor_and_portability_branches_round_trip() {
    let stdin = mutate(
        GOLDEN,
        "\"prompt_delivery\":{\"backend_session\":\"session-1\",\"mode\":\"backend_session\",\"protected_reference\":null}",
        "\"prompt_delivery\":{\"backend_session\":null,\"mode\":\"stdin\",\"protected_reference\":null}",
    );
    assert!(matches!(
        decode_round_trip(&stdin).prompt_delivery(),
        PromptDeliveryPlan::Stdin
    ));

    let protected = mutate(
        GOLDEN,
        "\"prompt_delivery\":{\"backend_session\":\"session-1\",\"mode\":\"backend_session\",\"protected_reference\":null}",
        "\"prompt_delivery\":{\"backend_session\":null,\"mode\":\"protected_reference\",\"protected_reference\":\"prompt-slot-1\"}",
    );
    assert!(matches!(
        decode_round_trip(&protected).prompt_delivery(),
        PromptDeliveryPlan::ProtectedReference(_)
    ));

    let null_schema = mutate(
        GOLDEN,
        "\"schema_digest\":\"sha256:2222222222222222222222222222222222222222222222222222222222222222\"",
        "\"schema_digest\":null",
    );
    assert_eq!(
        decode_round_trip(&null_schema)
            .provider_binary()
            .schema_digest(),
        None
    );

    let no_session = mutate(
        &stdin,
        "\"session_binding\":{\"backend\":\"local-direct\",\"provider_account\":\"provider-account-1\",\"provider_namespace\":\"fixture-namespace\",\"session\":\"session-1\",\"tenant\":\"acme\"}",
        "\"session_binding\":null",
    );
    assert!(
        decode_round_trip(&no_session)
            .admission()
            .session_binding()
            .is_none()
    );

    let interactive = mutate(
        GOLDEN,
        "\"origin\":{\"automation_id\":\"automation-1\",\"causal_events\":[\"event-parent-1\",\"event-parent-2\"],\"cause\":{\"actor\":{\"id\":\"actor-1\",\"tenant\":\"acme\"},\"causation_id\":\"cause-2\",\"parent_id\":\"cause-1\",\"run_id\":\"run-1\"},\"event_id\":\"event-1\",\"goal_id\":null,\"source\":\"automation\",\"trigger_id\":null}",
        "\"origin\":{\"automation_id\":null,\"causal_events\":[],\"cause\":null,\"event_id\":null,\"goal_id\":null,\"source\":\"interactive\",\"trigger_id\":null}",
    );
    assert_eq!(
        decode_round_trip(&interactive)
            .admission()
            .origin()
            .source(),
        RunOriginSource::Interactive
    );

    let local = mutate(
        GOLDEN,
        "\"executor_class\":{\"kind\":\"remote\",\"remote_coordinate\":{\"resource_id\":\"resource-1\",\"vendor\":\"vendor-1\"}}",
        "\"executor_class\":{\"kind\":\"local\",\"remote_coordinate\":null}",
    );
    decode_round_trip(&local);
    let pinned = mutate(
        GOLDEN,
        "\"portability_policy\":{\"artifact_transfer\":\"digest_verified_push\",\"kind\":\"portable\",\"workspace_transfer\":\"content_addressed_bundle\"}",
        "\"portability_policy\":{\"artifact_transfer\":null,\"kind\":\"pinned\",\"workspace_transfer\":null}",
    );
    decode_round_trip(&pinned);
}

#[test]
fn protocol_digest_algorithms_and_constructor_permitted_order_duplicates_round_trip() {
    let policy_sha256 = mutate(
        GOLDEN,
        "blake3:5555555555555555555555555555555555555555555555555555555555555555",
        "sha256:5555555555555555555555555555555555555555555555555555555555555555",
    );
    decode_round_trip(&policy_sha256);

    let duplicate_implementation = mutate(
        GOLDEN,
        &format!("sha512:{}", "4".repeat(128)),
        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    );
    decode_round_trip(&duplicate_implementation);

    let reordered_implementations = mutate(
        GOLDEN,
        &format!(
            "[\"sha256:{}\",\"sha512:{}\"]",
            "3".repeat(64),
            "4".repeat(128)
        ),
        &format!(
            "[\"sha512:{}\",\"sha256:{}\"]",
            "4".repeat(128),
            "3".repeat(64)
        ),
    );
    decode_round_trip(&reordered_implementations);

    let duplicate_context = mutate(
        GOLDEN,
        "{\"caps\":{\"byte_cap\":\"200\",\"token_cap\":\"20\"},\"digest\":\"policy-digest-b\",\"redaction\":\"redacted\",\"revision\":\"3\",\"source\":\"policy-source-b\"}",
        "{\"caps\":{\"byte_cap\":\"100\",\"token_cap\":\"10\"},\"digest\":\"policy-digest-a\",\"redaction\":\"clean\",\"revision\":\"2\",\"source\":\"policy-source-a\"}",
    );
    decode_round_trip(&duplicate_context);
}
