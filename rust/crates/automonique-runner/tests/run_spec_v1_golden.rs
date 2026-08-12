// SPDX-License-Identifier: Elastic-2.0

//! Independent structural evidence for the complete RunSpec v1 golden bytes.
//!
//! This test intentionally does not call the runner's RunSpec constructor,
//! encoder, decoder, or digest API. The checked-in bytes and digest pins were
//! produced outside the product implementation; see the provenance sidecar.

use automonique_protocol::codec::MAX_FRAME_BYTES;
use automonique_protocol::wire::{self, JsonValue};
use sha2::{Digest, Sha256};

const GOLDEN: &[u8] = include_bytes!("fixtures/run_spec_v1_full.cjson");
const PROVENANCE: &str = include_str!("fixtures/run_spec_v1_full.provenance.txt");
const EXPECTED_BYTES: usize = 5_472;
const EXPECTED_RAW_SHA256: &str =
    "6ff8aca4c2713cb1a8fa13e7d35aa52173000c758801b8e770213bc8a947954c";
const DOMAIN_PREFIX: &[u8] = b"automonique.run-spec/v1\0";
const EXPECTED_DOMAIN_SHA256: &str =
    "12a7a94d02665732ee3a205d443056359ca992bfa2ae923e6b6123e82e0ccc04";

const TOP_LEVEL_KEYS: [&str; 38] = [
    "argv_hex",
    "artifact_grants",
    "attempt_id",
    "backend_id",
    "context_manifest",
    "credential_bindings",
    "cwd_token",
    "environment_hex",
    "event_dialect",
    "executable_path_hex",
    "execution_plan_digest",
    "executor_class",
    "extension_set_digest",
    "fallback_eligibility",
    "host_id",
    "host_lifetime",
    "integration_mode",
    "io_reservation",
    "model_routing_digest",
    "origin",
    "persona_digest",
    "portability_policy",
    "profile_digest",
    "prompt_delivery",
    "provider_binary",
    "remote_attestation_policy",
    "required_capabilities",
    "run_id",
    "sandbox_spec",
    "scheduler_reservation",
    "schema",
    "session_binding",
    "skillset_digest",
    "toolset_digest",
    "work_id",
    "workspace",
    "workspace_registry_id",
    "workspace_reservation",
];

const REQUIREMENT_ROW_KEYS: [&[&str]; 20] = [
    &[
        "schema",
        "work_id",
        "run_id",
        "attempt_id",
        "host_id",
        "host_lifetime",
        "backend_id",
    ],
    &["provider_binary", "executable_path_hex", "argv_hex"],
    &["prompt_delivery"],
    &["workspace_registry_id", "workspace", "cwd_token"],
    &["environment_hex"],
    &["sandbox_spec"],
    &["sandbox_spec"],
    &["sandbox_spec"],
    &["sandbox_spec", "io_reservation", "workspace_reservation"],
    &["sandbox_spec"],
    &["session_binding"],
    &["integration_mode", "fallback_eligibility"],
    &["required_capabilities", "sandbox_spec"],
    &[
        "context_manifest",
        "profile_digest",
        "model_routing_digest",
        "toolset_digest",
        "skillset_digest",
        "extension_set_digest",
    ],
    &["origin"],
    &[
        "executor_class",
        "portability_policy",
        "remote_attestation_policy",
    ],
    &["provider_binary"],
    &[
        "sandbox_spec",
        "persona_digest",
        "execution_plan_digest",
        "scheduler_reservation",
    ],
    &["sandbox_spec", "artifact_grants", "credential_bindings"],
    &["event_dialect", "sandbox_spec"],
];

fn object(value: &JsonValue) -> &[(String, JsonValue)] {
    match value {
        JsonValue::Object(entries) => entries,
        _ => panic!("fixture branch is not an object"),
    }
}

fn array(value: &JsonValue) -> &[JsonValue] {
    match value {
        JsonValue::Array(entries) => entries,
        _ => panic!("fixture branch is not an array"),
    }
}

fn required<'a>(value: &'a JsonValue, key: &str) -> &'a JsonValue {
    value.get(key).unwrap_or_else(|| panic!("missing {key}"))
}

fn nonempty_array<'a>(value: &'a JsonValue, key: &str) -> &'a [JsonValue] {
    let entries = array(required(value, key));
    assert!(!entries.is_empty(), "{key} must be populated");
    entries
}

fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part);
    }
    format!("{:x}", digest.finalize())
}

fn assert_forbidden_keys_absent(value: &JsonValue) {
    match value {
        JsonValue::Array(entries) => {
            for entry in entries {
                assert_forbidden_keys_absent(entry);
            }
        }
        JsonValue::Object(entries) => {
            for (key, entry) in entries {
                assert!(
                    !matches!(
                        key.as_str(),
                        "credential_value" | "credential_secret" | "prompt_bytes" | "prompt_value"
                    ),
                    "protected value key is structurally forbidden"
                );
                assert_forbidden_keys_absent(entry);
            }
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Integer(_) | JsonValue::String(_) => {}
    }
}

#[test]
fn independent_full_golden_is_pinned_canonical_and_structurally_complete() {
    assert_eq!(GOLDEN.len(), EXPECTED_BYTES);
    assert!(GOLDEN.len() <= MAX_FRAME_BYTES);
    assert!(!GOLDEN.ends_with(b"\n"));
    assert_eq!(sha256_hex(&[GOLDEN]), EXPECTED_RAW_SHA256);
    assert_eq!(sha256_hex(&[DOMAIN_PREFIX, GOLDEN]), EXPECTED_DOMAIN_SHA256);

    assert!(PROVENANCE.contains(&format!("Canonical JSON byte count: {EXPECTED_BYTES}")));
    assert!(PROVENANCE.contains(EXPECTED_RAW_SHA256));
    assert!(PROVENANCE.contains(EXPECTED_DOMAIN_SHA256));
    assert!(PROVENANCE.contains("Python 3 standard library"));
    assert!(PROVENANCE.contains("OpenSSL 3"));

    let document = wire::parse_canonical(GOLDEN).expect("independent fixture must be canonical");
    let actual_keys = object(&document)
        .iter()
        .map(|(key, _)| key.as_str())
        .collect::<Vec<_>>();
    assert_eq!(actual_keys, TOP_LEVEL_KEYS);

    assert_eq!(REQUIREMENT_ROW_KEYS.len(), 20);
    for (index, keys) in REQUIREMENT_ROW_KEYS.iter().enumerate() {
        assert!(
            !keys.is_empty(),
            "requirement row {} has no keys",
            index + 1
        );
        for key in *keys {
            assert!(
                document.get(key).is_some(),
                "requirement row {} is missing {key}",
                index + 1
            );
        }
    }

    nonempty_array(&document, "argv_hex");
    nonempty_array(&document, "artifact_grants");
    nonempty_array(&document, "credential_bindings");
    nonempty_array(&document, "environment_hex");
    nonempty_array(&document, "fallback_eligibility");
    nonempty_array(&document, "required_capabilities");

    let context = required(&document, "context_manifest");
    nonempty_array(context, "policy");
    nonempty_array(context, "supplied");

    let origin = required(&document, "origin");
    assert_eq!(required(origin, "source").as_str(), Some("automation"));
    nonempty_array(origin, "causal_events");
    let cause = required(origin, "cause");
    assert!(matches!(cause, JsonValue::Object(_)));
    assert_eq!(required(cause, "parent_id").as_str(), Some("cause-1"));

    let prompt = required(&document, "prompt_delivery");
    assert_eq!(required(prompt, "mode").as_str(), Some("backend_session"));
    assert_eq!(
        required(prompt, "backend_session").as_str(),
        Some("session-1")
    );
    assert!(matches!(
        required(prompt, "protected_reference"),
        JsonValue::Null
    ));
    assert!(matches!(
        required(&document, "session_binding"),
        JsonValue::Object(_)
    ));

    let executor = required(&document, "executor_class");
    assert_eq!(required(executor, "kind").as_str(), Some("remote"));
    assert!(matches!(
        required(executor, "remote_coordinate"),
        JsonValue::Object(_)
    ));
    let portability = required(&document, "portability_policy");
    assert_eq!(required(portability, "kind").as_str(), Some("portable"));
    assert!(
        required(portability, "workspace_transfer")
            .as_str()
            .is_some()
    );
    assert!(
        required(portability, "artifact_transfer")
            .as_str()
            .is_some()
    );

    let provider = required(&document, "provider_binary");
    assert!(required(provider, "schema_digest").as_str().is_some());

    let sandbox = required(&document, "sandbox_spec");
    nonempty_array(sandbox, "allowlists");
    nonempty_array(sandbox, "credentials");
    nonempty_array(sandbox, "path_grants");
    nonempty_array(sandbox, "prohibited_capabilities");
    let features = nonempty_array(sandbox, "required_features");
    assert_eq!(features.len(), 2);
    for feature in features {
        nonempty_array(feature, "accepted_implementations");
    }
    assert!(
        required(sandbox, "policy_digest")
            .as_str()
            .is_some_and(|value| value.starts_with("blake3:"))
    );
    assert!(
        required(sandbox, "workspace_context")
            .as_str()
            .is_some_and(|value| value.starts_with("sha512:"))
    );

    assert_forbidden_keys_absent(&document);
}
