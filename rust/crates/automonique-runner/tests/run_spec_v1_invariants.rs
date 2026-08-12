// SPDX-License-Identifier: Elastic-2.0

use automonique_runner::{RunSpec, RunSpecDecodeError};

const GOLDEN: &[u8] = include_bytes!("fixtures/run_spec_v1_full.cjson");

fn replace_once(from: &str, to: &str) -> Vec<u8> {
    let source = std::str::from_utf8(GOLDEN).unwrap();
    assert_eq!(source.matches(from).count(), 1, "mutation must be unique");
    source.replacen(from, to, 1).into_bytes()
}

#[test]
fn provider_capabilities_and_os_prohibitions_remain_independent_namespaces() {
    let bytes = replace_once(
        "\"prohibited_capabilities\":[\"ptrace\",\"raw_socket\"]",
        "\"prohibited_capabilities\":[\"resume\",\"raw_socket\"]",
    );
    let spec = RunSpec::from_canonical_bytes(&bytes).unwrap();
    assert!(
        spec.admission()
            .required_capabilities()
            .iter()
            .any(|capability| capability.name() == "resume")
    );
    assert!(
        spec.sandbox()
            .prohibited_capabilities()
            .iter()
            .any(|capability| capability.as_str() == "resume")
    );
    assert_eq!(spec.to_canonical_bytes().unwrap(), bytes);
}

#[test]
fn sandbox_approval_revision_does_not_invent_tool_approval_cadence() {
    let bytes = replace_once("\"approval_revision\":\"2\"", "\"approval_revision\":\"3\"");
    let spec = RunSpec::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(spec.sandbox().approval_revision().get(), 3);
    assert!(
        !std::str::from_utf8(&bytes)
            .unwrap()
            .contains("approval_requirement")
    );
    assert_eq!(spec.to_canonical_bytes().unwrap(), bytes);

    let invented = replace_once(
        "\"approval_revision\":\"2\",\"base_revision\"",
        "\"approval_cadence\":\"per_invocation\",\"approval_revision\":\"2\",\"base_revision\"",
    );
    assert_eq!(
        RunSpec::from_canonical_bytes(&invented).unwrap_err(),
        RunSpecDecodeError::ObjectShape("sandbox_spec")
    );
}

#[test]
fn wire_schema_and_root_key_set_are_closed() {
    let version = replace_once(
        "\"schema\":\"automonique.run-spec/v1\"",
        "\"schema\":\"automonique.run-spec/v2\"",
    );
    assert_eq!(
        RunSpec::from_canonical_bytes(&version).unwrap_err(),
        RunSpecDecodeError::Field("schema")
    );

    let duplicate = replace_once(
        "\"argv_hex\":[\"61ff\",\"7365636f6e64\"]",
        "\"argv_hex\":[\"61ff\",\"7365636f6e64\"],\"argv_hex\":[]",
    );
    assert_eq!(
        RunSpec::from_canonical_bytes(&duplicate).unwrap_err(),
        RunSpecDecodeError::InvalidCanonicalJson
    );
}

#[test]
fn both_provider_digest_fields_refuse_algorithm_length_character_and_case_errors() {
    let digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let schema = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let cases = [
        (
            digest,
            &format!("blake3:{}", "1".repeat(64)),
            "binary_digest",
        ),
        (
            digest,
            &format!("sha256:{}", "1".repeat(63)),
            "binary_digest",
        ),
        (
            digest,
            &format!("sha256:{}G", "1".repeat(63)),
            "binary_digest",
        ),
        (
            digest,
            &format!("SHA256:{}", "1".repeat(64)),
            "binary_digest",
        ),
        (
            schema,
            &format!("blake3:{}", "2".repeat(64)),
            "schema_digest",
        ),
        (
            schema,
            &format!("sha256:{}", "2".repeat(63)),
            "schema_digest",
        ),
        (
            schema,
            &format!("sha256:{}G", "2".repeat(63)),
            "schema_digest",
        ),
        (
            schema,
            &format!("SHA256:{}", "2".repeat(64)),
            "schema_digest",
        ),
    ];
    for (from, to, field) in cases {
        let bytes = replace_once(from, to);
        assert_eq!(
            RunSpec::from_canonical_bytes(&bytes).unwrap_err(),
            RunSpecDecodeError::Field(field)
        );
    }
}
