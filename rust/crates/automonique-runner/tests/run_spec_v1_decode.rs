// SPDX-License-Identifier: Elastic-2.0

use automonique_runner::{
    CancellationToken, ContainmentEvidence, MAX_RUN_SPEC_BYTES, PromptDeliveryPlan,
    RunOriginSource, RunSpec, RunSpecDecodeError, Runner, RunnerError,
};

const GOLDEN: &[u8] = include_bytes!("fixtures/run_spec_v1_full.cjson");
const DIGEST: &str = "sha256:12a7a94d02665732ee3a205d443056359ca992bfa2ae923e6b6123e82e0ccc04";

fn replace_once(from: &str, to: &str) -> Vec<u8> {
    let source = std::str::from_utf8(GOLDEN).unwrap();
    assert_eq!(source.matches(from).count(), 1, "mutation must be unique");
    source.replacen(from, to, 1).into_bytes()
}

#[test]
fn full_independent_golden_decodes_reencodes_and_remains_nonauthorizing() {
    let spec = RunSpec::from_canonical_bytes(GOLDEN).unwrap();
    assert_eq!(spec.to_canonical_bytes().unwrap(), GOLDEN);
    assert_eq!(spec.canonical_digest().unwrap().as_str(), DIGEST);
    assert_eq!(spec.work_id().as_str(), "work-1");
    assert_eq!(
        spec.admission().origin().source(),
        RunOriginSource::Automation
    );
    assert_eq!(spec.admission().artifact_grants().len(), 2);
    assert!(matches!(
        spec.prompt_delivery(),
        PromptDeliveryPlan::BackendSession(_)
    ));
    assert!(matches!(
        Runner.run(spec, &CancellationToken::new()),
        Err(RunnerError::ContainmentUnenforced(
            ContainmentEvidence::ProcessGroupOnly
        ))
    ));
}

#[test]
fn decoder_refuses_closed_shape_type_and_canonicality_mutations() {
    let cases = [
        (
            replace_once("\"argv_hex\":[\"61ff\",\"7365636f6e64\"],", ""),
            RunSpecDecodeError::ObjectShape("run_spec"),
        ),
        (
            replace_once("\"argv_hex\"", "\"aardv_hex\""),
            RunSpecDecodeError::ObjectShape("run_spec"),
        ),
        (
            replace_once(
                "\"workspace_reservation\":\"8192\"",
                "\"workspace_reservation\":8192",
            ),
            RunSpecDecodeError::Field("workspace_reservation"),
        ),
        (
            replace_once("\"read_bytes\":\"2048\"", "\"read_bytes\":\"02048\""),
            RunSpecDecodeError::Field("read_bytes"),
        ),
        (
            replace_once(
                "\"executable_path_hex\":\"2f",
                "\"executable_path_hex\":\"2F",
            ),
            RunSpecDecodeError::Field("executable_path_hex"),
        ),
        (
            replace_once(
                "\"profile_digest\":\"sha256:",
                "\"profile_digest\":\"blake3:",
            ),
            RunSpecDecodeError::Field("profile_digest"),
        ),
        (
            replace_once(
                "\"protected_reference\":null",
                "\"protected_reference\":\"prompt-slot\"",
            ),
            RunSpecDecodeError::Field("prompt_delivery"),
        ),
        (
            replace_once(
                "\"caps\":{\"byte_cap\":\"100\",\"token_cap\":\"10\"}",
                "\"caps\":{\"byte_cap\":\"100\",\"extra\":\"1\",\"token_cap\":\"10\"}",
            ),
            RunSpecDecodeError::ObjectShape("component_caps"),
        ),
        (
            replace_once("\"recipient\":\"provider_adapter\"", "\"recipient\":false"),
            RunSpecDecodeError::Field("credential_recipient"),
        ),
    ];
    for (bytes, expected) in cases {
        assert_eq!(RunSpec::from_canonical_bytes(&bytes).unwrap_err(), expected);
    }

    let mut trailing = GOLDEN.to_vec();
    trailing.push(b'\n');
    assert_eq!(
        RunSpec::from_canonical_bytes(&trailing).unwrap_err(),
        RunSpecDecodeError::InvalidCanonicalJson
    );
    let reordered = replace_once(
        "\"argv_hex\":[\"61ff\",\"7365636f6e64\"],\"artifact_grants\"",
        "\"artifact_grants\":[],\"argv_hex\":[\"61ff\",\"7365636f6e64\"],\"discarded_artifact_grants\"",
    );
    assert!(matches!(
        RunSpec::from_canonical_bytes(&reordered),
        Err(RunSpecDecodeError::InvalidCanonicalJson | RunSpecDecodeError::ObjectShape(_))
    ));
}

#[test]
fn decoder_refuses_normalization_domain_duplicates_and_oversize_before_parse() {
    let audience_order = replace_once(
        "\"audiences\":[\"audience-a\",\"audience-b\"]",
        "\"audiences\":[\"audience-b\",\"audience-a\"]",
    );
    assert_eq!(
        RunSpec::from_canonical_bytes(&audience_order).unwrap_err(),
        RunSpecDecodeError::Field("credential_audiences")
    );
    let duplicate_grant = replace_once("\"id\":\"grant-2\"", "\"id\":\"grant-1\"");
    assert_eq!(
        RunSpec::from_canonical_bytes(&duplicate_grant).unwrap_err(),
        RunSpecDecodeError::Domain("artifact_grants")
    );
    let duplicate_cause = replace_once("\"event-parent-2\"", "\"event-parent-1\"");
    assert_eq!(
        RunSpec::from_canonical_bytes(&duplicate_cause).unwrap_err(),
        RunSpecDecodeError::Domain("origin")
    );
    let zero_revision = replace_once(
        "\"id\":\"reservation-1\",\"revision\":\"2\"",
        "\"id\":\"reservation-1\",\"revision\":\"0\"",
    );
    assert_eq!(
        RunSpec::from_canonical_bytes(&zero_revision).unwrap_err(),
        RunSpecDecodeError::Field("scheduler_revision")
    );
    let oversized = vec![b' '; MAX_RUN_SPEC_BYTES + 1];
    assert_eq!(
        RunSpec::from_canonical_bytes(&oversized).unwrap_err(),
        RunSpecDecodeError::DocumentTooLarge
    );
}

#[test]
fn decoder_errors_never_echo_hostile_input() {
    let hostile = replace_once(
        "\"profile_digest\":\"sha256:",
        "\"profile_digest\":\"SECRET_VALUE:",
    );
    let error = RunSpec::from_canonical_bytes(&hostile).unwrap_err();
    assert!(!format!("{error:?} {error}").contains("SECRET_VALUE"));
}

#[test]
fn decoder_refuses_platform_hex_leaf_and_aggregate_one_over_before_decode() {
    fn encoded(byte_count: usize) -> String {
        "61".repeat(byte_count)
    }

    let executable = replace_once(
        "\"executable_path_hex\":\"2f62696e2f74727565\"",
        &format!(
            "\"executable_path_hex\":\"{}\"",
            encoded(automonique_runner::MAX_PATH_BYTES + 1)
        ),
    );
    assert_eq!(
        RunSpec::from_canonical_bytes(&executable).unwrap_err(),
        RunSpecDecodeError::Field("executable_path_hex")
    );

    let argument = replace_once(
        "\"61ff\"",
        &format!("\"{}\"", encoded(automonique_runner::MAX_ARG_BYTES + 1)),
    );
    assert_eq!(
        RunSpec::from_canonical_bytes(&argument).unwrap_err(),
        RunSpecDecodeError::Field("argv_hex")
    );

    let environment_key = replace_once(
        "\"key_hex\":\"414c504841\"",
        &format!(
            "\"key_hex\":\"{}\"",
            encoded(automonique_runner::MAX_FIELD_BYTES + 1)
        ),
    );
    assert_eq!(
        RunSpec::from_canonical_bytes(&environment_key).unwrap_err(),
        RunSpecDecodeError::Field("key_hex")
    );
    let environment_value = replace_once(
        "\"value_hex\":\"ff78\"",
        &format!(
            "\"value_hex\":\"{}\"",
            encoded(automonique_runner::MAX_ARG_BYTES + 1)
        ),
    );
    assert_eq!(
        RunSpec::from_canonical_bytes(&environment_value).unwrap_err(),
        RunSpecDecodeError::Field("value_hex")
    );

    let argv = (0..9)
        .map(|_| format!("\"{}\"", encoded(automonique_runner::MAX_ARG_BYTES)))
        .collect::<Vec<_>>()
        .join(",");
    let aggregate_arguments = replace_once(
        "\"argv_hex\":[\"61ff\",\"7365636f6e64\"]",
        &format!("\"argv_hex\":[{argv}]"),
    );
    assert_eq!(
        RunSpec::from_canonical_bytes(&aggregate_arguments).unwrap_err(),
        RunSpecDecodeError::Field("argv_hex")
    );

    let environment = (0..16)
        .map(|index| {
            format!(
                "{{\"key_hex\":\"{:02x}\",\"value_hex\":\"{}\"}}",
                index,
                encoded(automonique_runner::MAX_ARG_BYTES)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let aggregate_environment = replace_once(
        "\"environment_hex\":[{\"key_hex\":\"414c504841\",\"value_hex\":\"ff78\"},{\"key_hex\":\"42455441\",\"value_hex\":\"76616c7565\"}]",
        &format!("\"environment_hex\":[{environment}]"),
    );
    assert_eq!(
        RunSpec::from_canonical_bytes(&aggregate_environment).unwrap_err(),
        RunSpecDecodeError::Field("environment_hex")
    );
}
