// SPDX-License-Identifier: Elastic-2.0

use automonique_runner::{RunSpec, RunSpecDecodeError};

const GOLDEN: &[u8] = include_bytes!("fixtures/run_spec_v1_full.cjson");

fn replace_once(from: &str, to: &str) -> Vec<u8> {
    let source = std::str::from_utf8(GOLDEN).unwrap();
    assert_eq!(
        source.matches(from).count(),
        1,
        "mutation must be unique: {from}"
    );
    source.replacen(from, to, 1).into_bytes()
}

fn refuses(bytes: &[u8], expected: RunSpecDecodeError) {
    assert_eq!(RunSpec::from_canonical_bytes(bytes).unwrap_err(), expected);
}

#[test]
fn recursive_objects_refuse_missing_unknown_wrong_type_and_duplicate_keys() {
    let cases = [
        (
            replace_once("\"extensions\":\"stronger_isolation\",", ""),
            RunSpecDecodeError::ObjectShape("nested_isolation"),
        ),
        (
            replace_once(
                "\"extensions\":\"stronger_isolation\"",
                "\"extensiona\":\"x\",\"extensions\":\"stronger_isolation\"",
            ),
            RunSpecDecodeError::ObjectShape("nested_isolation"),
        ),
        (
            replace_once(
                "\"remote_coordinate\":{\"resource_id\":\"resource-1\",\"vendor\":\"vendor-1\"}",
                "\"remote_coordinate\":[]",
            ),
            RunSpecDecodeError::ObjectShape("remote_coordinate"),
        ),
        (
            replace_once(
                "\"caps\":{\"byte_cap\":\"100\",\"token_cap\":\"10\"}",
                "\"caps\":{\"byte_cap\":\"100\",\"byte_cap\":\"101\",\"token_cap\":\"10\"}",
            ),
            RunSpecDecodeError::InvalidCanonicalJson,
        ),
        (
            replace_once(
                "\"artifact_transfer\":\"digest_verified_push\"",
                "\"artifact_transfer\":true",
            ),
            RunSpecDecodeError::Field("artifact_transfer"),
        ),
        (
            replace_once(
                "\"accepted_implementations\":[\"sha256:3333333333333333333333333333333333333333333333333333333333333333\",\"sha512:44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444\"]",
                "\"accepted_implementations\":{}",
            ),
            RunSpecDecodeError::Field("accepted_implementations"),
        ),
    ];
    for (bytes, expected) in cases {
        refuses(&bytes, expected);
    }
}

#[test]
fn canonical_decimal_revision_and_nonzero_boundaries_refuse_overflow_and_zero() {
    let cases = [
        (
            replace_once(
                "\"workspace_reservation\":\"8192\"",
                "\"workspace_reservation\":\"18446744073709551616\"",
            ),
            RunSpecDecodeError::Field("workspace_reservation"),
        ),
        (
            replace_once(
                "\"workspace_reservation\":\"8192\"",
                "\"workspace_reservation\":\"18446744073709551615\"",
            ),
            RunSpecDecodeError::Domain("workspace_reservation"),
        ),
        (
            replace_once("\"approval_revision\":\"2\"", "\"approval_revision\":\"0\""),
            RunSpecDecodeError::Field("approval_revision"),
        ),
        (
            replace_once(
                "\"approval_revision\":\"2\"",
                "\"approval_revision\":\"18446744073709551616\"",
            ),
            RunSpecDecodeError::Field("approval_revision"),
        ),
        (
            replace_once("\"version\":\"4\"", "\"version\":\"0\""),
            RunSpecDecodeError::Field("credential_version"),
        ),
        (
            replace_once("\"version\":\"4\"", "\"version\":\"18446744073709551616\""),
            RunSpecDecodeError::Field("credential_version"),
        ),
    ];
    for (bytes, expected) in cases {
        refuses(&bytes, expected);
    }

    let accepted_maxima = [
        replace_once(
            "\"token_budget\":\"100\"",
            "\"token_budget\":\"18446744073709551615\"",
        ),
        replace_once(
            "\"approval_revision\":\"2\"",
            "\"approval_revision\":\"18446744073709551615\"",
        ),
        replace_once("\"version\":\"4\"", "\"version\":\"18446744073709551615\""),
    ];
    for bytes in accepted_maxima {
        let spec = RunSpec::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(spec.to_canonical_bytes().unwrap(), bytes);
    }
}

#[test]
fn platform_hex_refuses_odd_nonhex_nul_and_decoded_path_or_environment_hazards() {
    let cases = [
        (
            replace_once(
                "\"executable_path_hex\":\"2f62696e2f74727565\"",
                "\"executable_path_hex\":\"2f6\"",
            ),
            RunSpecDecodeError::Field("executable_path_hex"),
        ),
        (
            replace_once(
                "\"executable_path_hex\":\"2f62696e2f74727565\"",
                "\"executable_path_hex\":\"2g\"",
            ),
            RunSpecDecodeError::Field("executable_path_hex"),
        ),
        (
            replace_once("\"key_hex\":\"414c504841\"", "\"key_hex\":\"410042\""),
            RunSpecDecodeError::Domain("run_spec"),
        ),
        (
            replace_once(
                "\"executable_path_hex\":\"2f62696e2f74727565\"",
                "\"executable_path_hex\":\"2f62696e2f2e2e2f74727565\"",
            ),
            RunSpecDecodeError::Domain("run_spec"),
        ),
        (
            replace_once("\"cwd_token\":\"cwd-1\"", "\"cwd_token\":\"../cwd\""),
            RunSpecDecodeError::Domain("cwd_token"),
        ),
        (
            replace_once(
                "\"protected_reference\":null",
                "\"protected_reference\":\"../prompt\"",
            ),
            RunSpecDecodeError::Domain("protected_reference"),
        ),
    ];
    for (bytes, expected) in cases {
        refuses(&bytes, expected);
    }
}

#[test]
fn runner_and_protocol_digest_grammars_are_distinct_and_exact() {
    let cases = [
        (
            replace_once(
                "\"profile_digest\":\"sha256:6666666666666666666666666666666666666666666666666666666666666666\"",
                "\"profile_digest\":\"sha512:6666666666666666666666666666666666666666666666666666666666666666\"",
            ),
            RunSpecDecodeError::Field("profile_digest"),
        ),
        (
            replace_once(
                "\"profile_digest\":\"sha256:6666666666666666666666666666666666666666666666666666666666666666\"",
                "\"profile_digest\":\"sha256:6666\"",
            ),
            RunSpecDecodeError::Field("profile_digest"),
        ),
        (
            replace_once(
                "\"profile_digest\":\"sha256:6666666666666666666666666666666666666666666666666666666666666666\"",
                "\"profile_digest\":\"sha256:666666666666666666666666666666666666666666666666666666666666666G\"",
            ),
            RunSpecDecodeError::Field("profile_digest"),
        ),
        (
            replace_once(
                "\"policy_digest\":\"blake3:5555555555555555555555555555555555555555555555555555555555555555\"",
                "\"policy_digest\":\"md5:5555555555555555555555555555555555555555555555555555555555555555\"",
            ),
            RunSpecDecodeError::Field("policy_digest"),
        ),
        (
            replace_once(
                "\"workspace_context\":\"sha512:66666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666\"",
                "\"workspace_context\":\"sha512:6666\"",
            ),
            RunSpecDecodeError::Field("workspace_context"),
        ),
    ];
    for (bytes, expected) in cases {
        refuses(&bytes, expected);
    }
}

#[test]
fn collection_identity_order_and_cross_field_mismatches_refuse_exactly() {
    let cases = [
        (
            replace_once("\"key_hex\":\"42455441\"", "\"key_hex\":\"414c504841\""),
            RunSpecDecodeError::Domain("run_spec"),
        ),
        (
            replace_once(
                "{\"group\":\"tools\",\"name\":\"structured_output\"}",
                "{\"group\":\"sessions\",\"name\":\"resume\"}",
            ),
            RunSpecDecodeError::Domain("required_capabilities"),
        ),
        (
            replace_once("\"path\":\"/inputs\"", "\"path\":\"/workspace\""),
            RunSpecDecodeError::Domain("path_grants"),
        ),
        (
            replace_once(
                "\"name\":\"fixture_credential\",\"recipient\":\"provider_adapter\"",
                "\"name\":\"other_credential\",\"recipient\":\"provider_adapter\"",
            ),
            RunSpecDecodeError::Domain("run_spec"),
        ),
        (
            replace_once(
                "\"session\":\"session-1\",\"tenant\":\"acme\"",
                "\"session\":\"session-1\",\"tenant\":\"other\"",
            ),
            RunSpecDecodeError::Domain("run_spec"),
        ),
        (
            replace_once("\"session\":\"session-1\"", "\"session\":\"session-2\""),
            RunSpecDecodeError::Domain("run_spec"),
        ),
        (
            replace_once(
                "\"base_revision\":\"7\",\"canonical_source\":\"fixture-source\"",
                "\"base_revision\":\"8\",\"canonical_source\":\"fixture-source\"",
            ),
            RunSpecDecodeError::Domain("run_spec"),
        ),
    ];
    for (bytes, expected) in cases {
        refuses(&bytes, expected);
    }
}
