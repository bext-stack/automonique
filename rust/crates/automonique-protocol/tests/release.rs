// SPDX-License-Identifier: Elastic-2.0

//! R1-05 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-05.md`.

use automonique_protocol::codec::{CodecError, MajorVersion, VersionRange};
use automonique_protocol::primitives::ValueError;
use automonique_protocol::release::{
    ArtifactDigest, ArtifactKind, CapabilityOutcome, CapabilityRequirement, CredentialDescriptor,
    DigestAlgorithm, KNOWN_MANIFEST_FIELDS, MAX_SUPPORTED_MANIFEST_SCHEMA, MAX_UNKNOWN_FIELDS,
    ManifestError, ManifestText, ReleaseManifest, ReleaseManifestBuilder, RollbackTarget,
    SdkCompatibility,
};
use automonique_protocol::wire::JsonValue;

const SCHEMA_HEX: &str = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";
const OTHER_HEX: &str = "0011223344556677889900112233445566778899aabbccddeeff001122334455";
const SOURCE_REVISION: &str = "8457c0e7d1311b99566cda0235ba58e7ca1c45c8";

/// A host path a manifest must never be able to hold.
const ABSOLUTE: &str = "/etc/automonique/secret.pem";

fn version(value: u32) -> MajorVersion {
    MajorVersion::new(value).expect("non-zero version")
}

fn range(min: u32, max: u32) -> VersionRange {
    VersionRange::new(version(min), version(max)).expect("ordered range")
}

fn digest(hex: &str) -> ArtifactDigest {
    ArtifactDigest::new("sha-256", hex).expect("valid digest")
}

fn sdk() -> SdkCompatibility {
    SdkCompatibility::new(range(1, 2), digest(SCHEMA_HEX))
}

/// A builder with every required field supplied.
fn complete() -> ReleaseManifestBuilder {
    ReleaseManifestBuilder::new()
        .schema_revision(MAX_SUPPORTED_MANIFEST_SCHEMA)
        .version("0.1.0")
        .source_revision(SOURCE_REVISION)
        .build_target("x86_64-unknown-linux-gnu")
        .protocol(range(1, 3))
        .events(range(1, 2))
        .database_schema(range(4, 6))
        .sdk(sdk())
        .digest(ArtifactKind::Binary, digest(OTHER_HEX))
}

/// The same manifest with every optional section supplied too.
fn complete_with_optional_sections() -> ReleaseManifestBuilder {
    complete()
        .capability(CapabilityRequirement::required("cgroup_v2").expect("valid"))
        .capability(CapabilityRequirement::optional("systemd_adapter").expect("valid"))
        .credential(CredentialDescriptor::new("database", 3).expect("valid"))
        .rollback(RollbackTarget::new("0.0.9", range(3, 5)).expect("valid"))
}

fn field(name: &str, value: JsonValue) -> (String, JsonValue) {
    (name.to_owned(), value)
}

fn json_text(value: &str) -> JsonValue {
    JsonValue::String(value.to_owned())
}

fn json_range(min: i64, max: i64) -> JsonValue {
    JsonValue::Object(vec![
        field("min", JsonValue::Integer(min)),
        field("max", JsonValue::Integer(max)),
    ])
}

fn json_digest(algorithm: &str, hex: &str) -> JsonValue {
    JsonValue::Object(vec![
        field("algorithm", json_text(algorithm)),
        field("hex", json_text(hex)),
    ])
}

fn json_capability(id: &str, required: bool) -> JsonValue {
    JsonValue::Object(vec![
        field("id", json_text(id)),
        field("required", JsonValue::Bool(required)),
    ])
}

fn json_credential(name: &str, credential_version: i64) -> JsonValue {
    JsonValue::Object(vec![
        field("name", json_text(name)),
        field("version", JsonValue::Integer(credential_version)),
    ])
}

fn json_rollback(target: &str, min: i64, max: i64) -> JsonValue {
    JsonValue::Object(vec![
        field("database_schema", json_range(min, max)),
        field("version", json_text(target)),
    ])
}

/// The document form of [`complete_with_optional_sections`].
fn document_fields() -> Vec<(String, JsonValue)> {
    vec![
        field("build_target", json_text("x86_64-unknown-linux-gnu")),
        field(
            "capabilities",
            JsonValue::Array(vec![
                json_capability("cgroup_v2", true),
                json_capability("systemd_adapter", false),
            ]),
        ),
        field(
            "credentials",
            JsonValue::Array(vec![json_credential("database", 3)]),
        ),
        field("database_schema", json_range(4, 6)),
        field(
            "digests",
            JsonValue::Object(vec![field("binary", json_digest("sha-256", OTHER_HEX))]),
        ),
        field("events", json_range(1, 2)),
        field("protocol", json_range(1, 3)),
        field("rollback", json_rollback("0.0.9", 3, 5)),
        field(
            "schema_revision",
            JsonValue::Integer(i64::from(MAX_SUPPORTED_MANIFEST_SCHEMA)),
        ),
        field(
            "sdk",
            JsonValue::Object(vec![
                field("protocol", json_range(1, 2)),
                field("schema_digest", json_digest("sha-256", SCHEMA_HEX)),
            ]),
        ),
        field("source_revision", json_text(SOURCE_REVISION)),
        field("version", json_text("0.1.0")),
    ]
}

/// Encode a document. `to_canonical_bytes` sorts keys, so the fixtures are
/// canonical by construction and a refusal can never be an accident of spelling.
fn encode(fields: Vec<(String, JsonValue)>) -> Vec<u8> {
    JsonValue::Object(fields).to_canonical_bytes()
}

fn complete_document() -> Vec<u8> {
    encode(document_fields())
}

fn document_without(key: &str) -> Vec<u8> {
    encode(
        document_fields()
            .into_iter()
            .filter(|(name, _)| name != key)
            .collect(),
    )
}

fn document_with(key: &str, value: JsonValue) -> Vec<u8> {
    let mut fields: Vec<(String, JsonValue)> = document_fields()
        .into_iter()
        .filter(|(name, _)| name != key)
        .collect();
    fields.push(field(key, value));
    encode(fields)
}

fn parse_failure(payload: &[u8]) -> ManifestError {
    ReleaseManifest::from_canonical_bytes(payload).expect_err("the document is refused")
}

mod field_completeness {
    use super::*;

    #[test]
    fn a_complete_manifest_builds() {
        let manifest = complete().build().expect("every required field supplied");
        assert_eq!(manifest.version(), "0.1.0");
        assert_eq!(manifest.build_target(), "x86_64-unknown-linux-gnu");
        assert_eq!(manifest.database_schema().min().get(), 4);
    }

    #[test]
    fn a_complete_document_parses_into_the_same_value_the_builder_produces() {
        let parsed = ReleaseManifest::from_canonical_bytes(&complete_document())
            .expect("every required field is present in the document");
        assert_eq!(parsed.version(), "0.1.0");
        assert_eq!(parsed.source_revision(), SOURCE_REVISION);
        assert_eq!(parsed.build_target(), "x86_64-unknown-linux-gnu");
        assert_eq!(parsed.schema_revision(), MAX_SUPPORTED_MANIFEST_SCHEMA);
        assert_eq!(parsed.protocol(), range(1, 3));
        assert_eq!(parsed.events(), range(1, 2));
        assert_eq!(parsed.database_schema(), range(4, 6));
        assert_eq!(
            parsed.digest(ArtifactKind::Binary),
            Some(&digest(OTHER_HEX))
        );
        assert_eq!(parsed.credentials().len(), 1);
        assert_eq!(parsed.rollback().expect("declared").version(), "0.0.9");

        // The parse path and the builder are the same validation, so the two
        // routes cannot disagree about what a valid manifest is.
        let assembled = complete_with_optional_sections()
            .build()
            .expect("the equivalent assembly");
        assert_eq!(parsed, assembled);
    }

    /// Coverage table: removing any one required field must fail naming it.
    #[test]
    fn every_required_field_is_enforced_and_named() {
        let omissions: Vec<(&str, ReleaseManifestBuilder)> = vec![
            ("schema_revision", {
                ReleaseManifestBuilder::new()
                    .version("0.1.0")
                    .source_revision("rev")
                    .build_target("target")
                    .protocol(range(1, 3))
                    .events(range(1, 2))
                    .database_schema(range(4, 6))
                    .sdk(sdk())
                    .digest(ArtifactKind::Binary, digest(OTHER_HEX))
            }),
            ("version", {
                ReleaseManifestBuilder::new()
                    .schema_revision(1)
                    .source_revision("rev")
                    .build_target("target")
                    .protocol(range(1, 3))
                    .events(range(1, 2))
                    .database_schema(range(4, 6))
                    .sdk(sdk())
                    .digest(ArtifactKind::Binary, digest(OTHER_HEX))
            }),
            ("source_revision", {
                ReleaseManifestBuilder::new()
                    .schema_revision(1)
                    .version("0.1.0")
                    .build_target("target")
                    .protocol(range(1, 3))
                    .events(range(1, 2))
                    .database_schema(range(4, 6))
                    .sdk(sdk())
                    .digest(ArtifactKind::Binary, digest(OTHER_HEX))
            }),
            ("build_target", {
                ReleaseManifestBuilder::new()
                    .schema_revision(1)
                    .version("0.1.0")
                    .source_revision("rev")
                    .protocol(range(1, 3))
                    .events(range(1, 2))
                    .database_schema(range(4, 6))
                    .sdk(sdk())
                    .digest(ArtifactKind::Binary, digest(OTHER_HEX))
            }),
            ("protocol", {
                ReleaseManifestBuilder::new()
                    .schema_revision(1)
                    .version("0.1.0")
                    .source_revision("rev")
                    .build_target("target")
                    .events(range(1, 2))
                    .database_schema(range(4, 6))
                    .sdk(sdk())
                    .digest(ArtifactKind::Binary, digest(OTHER_HEX))
            }),
            ("events", {
                ReleaseManifestBuilder::new()
                    .schema_revision(1)
                    .version("0.1.0")
                    .source_revision("rev")
                    .build_target("target")
                    .protocol(range(1, 3))
                    .database_schema(range(4, 6))
                    .sdk(sdk())
                    .digest(ArtifactKind::Binary, digest(OTHER_HEX))
            }),
            ("database_schema", {
                ReleaseManifestBuilder::new()
                    .schema_revision(1)
                    .version("0.1.0")
                    .source_revision("rev")
                    .build_target("target")
                    .protocol(range(1, 3))
                    .events(range(1, 2))
                    .sdk(sdk())
                    .digest(ArtifactKind::Binary, digest(OTHER_HEX))
            }),
            ("sdk", {
                ReleaseManifestBuilder::new()
                    .schema_revision(1)
                    .version("0.1.0")
                    .source_revision("rev")
                    .build_target("target")
                    .protocol(range(1, 3))
                    .events(range(1, 2))
                    .database_schema(range(4, 6))
                    .digest(ArtifactKind::Binary, digest(OTHER_HEX))
            }),
            ("binary_digest", {
                ReleaseManifestBuilder::new()
                    .schema_revision(1)
                    .version("0.1.0")
                    .source_revision("rev")
                    .build_target("target")
                    .protocol(range(1, 3))
                    .events(range(1, 2))
                    .database_schema(range(4, 6))
                    .sdk(sdk())
            }),
        ];
        assert_eq!(omissions.len(), 9, "the required-field table changed");
        for (field, builder) in omissions {
            assert_eq!(
                builder.build().expect_err("omission is refused"),
                ManifestError::MissingField { field },
                "omitting {field} did not fail naming it"
            );
        }
    }

    /// The same table, exercised through the parse path rather than the
    /// builder, so `enforced at parse` is measured on a manifest *document*.
    #[test]
    fn every_required_field_is_enforced_at_parse_and_named() {
        let omissions: Vec<(&str, &'static str)> = vec![
            ("schema_revision", "schema_revision"),
            ("version", "version"),
            ("source_revision", "source_revision"),
            ("build_target", "build_target"),
            ("protocol", "protocol"),
            ("events", "events"),
            ("database_schema", "database_schema"),
            ("sdk", "sdk"),
            ("digests", "binary_digest"),
        ];
        assert_eq!(omissions.len(), 9, "the required-field table changed");
        for (key, field) in omissions {
            assert_eq!(
                parse_failure(&document_without(key)),
                ManifestError::MissingField { field },
                "omitting {key} from the document did not fail naming {field}"
            );
        }

        // A `digests` map that is present but carries no binary entry is the
        // same refusal: the required artifact, not merely the section, is
        // enforced.
        let without_binary = document_with(
            "digests",
            JsonValue::Object(vec![field("policy", json_digest("sha-256", SCHEMA_HEX))]),
        );
        assert_eq!(
            parse_failure(&without_binary),
            ManifestError::MissingField {
                field: "binary_digest"
            }
        );
    }

    /// Coverage of the declared field set: every key the parser interprets is
    /// classified, and the classification is checked against the parser's own
    /// list rather than restated by hand.
    #[test]
    fn the_table_covers_every_document_field_this_build_interprets() {
        let required = [
            "schema_revision",
            "version",
            "source_revision",
            "build_target",
            "protocol",
            "events",
            "database_schema",
            "sdk",
            "digests",
        ];
        let optional = ["capabilities", "credentials", "rollback"];

        let mut classified: Vec<&str> = required.iter().chain(optional.iter()).copied().collect();
        classified.sort_unstable();
        let mut declared = KNOWN_MANIFEST_FIELDS.to_vec();
        declared.sort_unstable();
        assert_eq!(
            classified, declared,
            "the coverage table drifted from the parsed field set"
        );
        assert_eq!(required.len() + optional.len(), KNOWN_MANIFEST_FIELDS.len());

        // Each required key refuses when absent; that is the table above.
        for key in required {
            assert!(
                ReleaseManifest::from_canonical_bytes(&document_without(key)).is_err(),
                "{key} is classified required but its omission was accepted"
            );
        }
        // Each optional key is absent-tolerant and retained when present.
        for key in optional {
            assert!(
                ReleaseManifest::from_canonical_bytes(&document_without(key)).is_ok(),
                "{key} is classified optional but its omission was refused"
            );
        }
        let manifest =
            ReleaseManifest::from_canonical_bytes(&complete_document()).expect("valid document");
        assert_eq!(
            manifest.evaluate_capabilities(&["systemd_adapter"]),
            CapabilityOutcome::Refused {
                missing_required: vec!["cgroup_v2".to_owned()],
                missing_optional: Vec::new(),
            },
            "capabilities were not retained through the parse path"
        );
        assert_eq!(manifest.credentials()[0].name(), "database");
        assert_eq!(manifest.rollback().expect("declared").version(), "0.0.9");
    }

    #[test]
    fn no_required_field_defaults_silently() {
        // An empty builder fails on the first required field rather than
        // producing a manifest full of defaults.
        assert_eq!(
            ReleaseManifestBuilder::new()
                .build()
                .expect_err("empty builder"),
            ManifestError::MissingField {
                field: "schema_revision"
            }
        );
        // An empty document is the same: no field is invented for it.
        assert_eq!(
            parse_failure(&encode(Vec::new())),
            ManifestError::MissingField {
                field: "schema_revision"
            }
        );
    }

    #[test]
    fn bounded_fields_reject_empty_over_length_and_control_characters() {
        for (field, value) in [
            ("version", String::new()),
            ("version", "1.0\u{7}".to_owned()),
            ("source_revision", "r".repeat(200)),
        ] {
            let builder = match field {
                "version" => complete().version(&value),
                _ => complete().source_revision(&value),
            };
            let error = builder.build().expect_err("bounded rule violated");
            assert_eq!(error.category(), "field_invalid", "{field} {value:?}");
        }
    }

    #[test]
    fn the_same_bounds_apply_on_the_parse_path() {
        for (key, value) in [
            ("version", String::new()),
            ("version", "1.0\u{7}".to_owned()),
            ("source_revision", "r".repeat(200)),
        ] {
            let error = parse_failure(&document_with(key, json_text(&value)));
            assert_eq!(error.category(), "field_invalid", "{key} {value:?}");
        }
        assert_eq!(
            parse_failure(&document_with(
                "source_revision",
                json_text(&"r".repeat(200))
            )),
            ManifestError::Field {
                field: "source_revision",
                error: ValueError::TooLong {
                    max_bytes: 128,
                    actual_bytes: 200,
                },
            }
        );
    }

    #[test]
    fn a_field_of_the_wrong_json_type_is_refused_naming_it() {
        let cases: Vec<(&str, JsonValue, &'static str)> = vec![
            ("schema_revision", json_text("1"), "schema_revision"),
            ("schema_revision", JsonValue::Integer(-1), "schema_revision"),
            ("version", JsonValue::Integer(1), "version"),
            ("build_target", JsonValue::Null, "build_target"),
            ("protocol", JsonValue::Integer(1), "protocol"),
            ("sdk", json_text("x"), "sdk"),
            ("digests", JsonValue::Array(Vec::new()), "digests"),
            (
                "capabilities",
                JsonValue::Object(Vec::new()),
                "capabilities",
            ),
            ("credentials", JsonValue::Object(Vec::new()), "credentials"),
            ("rollback", JsonValue::Integer(1), "rollback"),
        ];
        for (key, value, field) in cases {
            assert_eq!(
                parse_failure(&document_with(key, value)),
                ManifestError::FieldType { field },
                "{key} of the wrong type was not refused naming {field}"
            );
        }
    }

    #[test]
    fn a_document_that_is_not_canonical_is_refused_as_a_document() {
        // Parses, but carries insignificant whitespace: refused rather than
        // silently normalized.
        assert_eq!(
            parse_failure(b"{\"schema_revision\": 1}"),
            ManifestError::Document {
                error: CodecError::NonCanonicalJson
            }
        );
        assert_eq!(
            parse_failure(b"{"),
            ManifestError::Document {
                error: CodecError::MalformedJson
            }
        );
        assert_eq!(
            parse_failure(b"{}5"),
            ManifestError::Document {
                error: CodecError::TrailingData
            }
        );
        // A syntactically fine document that is not an object at all.
        assert_eq!(
            parse_failure(b"5"),
            ManifestError::FieldType { field: "manifest" }
        );
    }
}

mod schema_revision {
    use super::*;

    #[test]
    fn a_future_revision_is_refused_before_other_fields_are_interpreted() {
        // The rest of this builder is deliberately invalid: every other field
        // is absent. If the revision were not checked first, the error would
        // name a missing field instead.
        let error = ReleaseManifestBuilder::new()
            .schema_revision(MAX_SUPPORTED_MANIFEST_SCHEMA + 1)
            .build()
            .expect_err("future revision is refused");
        assert_eq!(
            error,
            ManifestError::UnsupportedSchemaRevision {
                supported_max: MAX_SUPPORTED_MANIFEST_SCHEMA,
                declared: MAX_SUPPORTED_MANIFEST_SCHEMA + 1,
            }
        );
    }

    #[test]
    fn a_future_document_revision_is_refused_before_other_fields_are_interpreted() {
        // A document carrying nothing but a future revision. Every other
        // required field is absent, so a reader that interpreted anything else
        // first would answer `MissingField`.
        let document = encode(vec![field(
            "schema_revision",
            JsonValue::Integer(i64::from(MAX_SUPPORTED_MANIFEST_SCHEMA) + 1),
        )]);
        assert_eq!(
            parse_failure(&document),
            ManifestError::UnsupportedSchemaRevision {
                supported_max: MAX_SUPPORTED_MANIFEST_SCHEMA,
                declared: MAX_SUPPORTED_MANIFEST_SCHEMA + 1,
            }
        );

        // The sharper case: an otherwise complete document whose `version` is
        // the wrong JSON type. A reader that decoded any field before comparing
        // the revision would answer `FieldType { field: "version" }` here, so
        // this pins the ordering rather than merely the refusal.
        let mut fields: Vec<(String, JsonValue)> = document_fields()
            .into_iter()
            .filter(|(name, _)| name != "schema_revision" && name != "version")
            .collect();
        fields.push(field(
            "schema_revision",
            JsonValue::Integer(i64::from(MAX_SUPPORTED_MANIFEST_SCHEMA) + 1),
        ));
        fields.push(field("version", JsonValue::Integer(1)));
        assert_eq!(
            parse_failure(&encode(fields)),
            ManifestError::UnsupportedSchemaRevision {
                supported_max: MAX_SUPPORTED_MANIFEST_SCHEMA,
                declared: MAX_SUPPORTED_MANIFEST_SCHEMA + 1,
            }
        );
    }

    #[test]
    fn unknown_fields_are_retained_within_a_supported_revision() {
        let manifest = complete()
            .unknown_field("future_knob", "enabled")
            .unknown_field("another", "value")
            .build()
            .expect("unknown fields do not prevent construction");
        let retained = manifest.unknown_fields();
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0].0.as_str(), "future_knob");
        assert_eq!(retained[0].1, json_text("enabled"));
        assert_eq!(retained[1].0.as_str(), "another");
        assert_eq!(retained[1].1, json_text("value"));
    }

    #[test]
    fn retention_is_bounded_rather_than_unlimited() {
        let mut builder = complete();
        for index in 0..=MAX_UNKNOWN_FIELDS {
            builder = builder.unknown_field(&format!("knob_{index}"), "enabled");
        }
        assert_eq!(
            builder.build().expect_err("over the retention ceiling"),
            ManifestError::TooManyUnknownFields {
                max: MAX_UNKNOWN_FIELDS
            }
        );

        let mut fields = document_fields();
        for index in 0..=MAX_UNKNOWN_FIELDS {
            fields.push(field(&format!("knob_{index}"), json_text("enabled")));
        }
        assert_eq!(
            parse_failure(&encode(fields)),
            ManifestError::TooManyUnknownFields {
                max: MAX_UNKNOWN_FIELDS
            }
        );

        // Exactly at the ceiling is accepted, so the bound is the stated one.
        let mut fields = document_fields();
        for index in 0..MAX_UNKNOWN_FIELDS {
            fields.push(field(&format!("knob_{index}"), json_text("enabled")));
        }
        let manifest =
            ReleaseManifest::from_canonical_bytes(&encode(fields)).expect("at the ceiling");
        assert_eq!(manifest.unknown_fields().len(), MAX_UNKNOWN_FIELDS);
    }

    #[test]
    fn unknown_document_fields_are_retained_verbatim_and_never_reinterpreted() {
        let nested = JsonValue::Object(vec![
            field("depth", JsonValue::Integer(2)),
            field(
                "names",
                JsonValue::Array(vec![json_text("a"), json_text("b")]),
            ),
        ]);
        let manifest =
            ReleaseManifest::from_canonical_bytes(&document_with("future_knob", nested.clone()))
                .expect("an unknown field does not prevent parsing");
        let retained = manifest.unknown_fields();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].0.as_str(), "future_knob");
        // Preserved exactly, including its shape: nothing was flattened,
        // reordered into a known field, or turned into text.
        assert_eq!(retained[0].1, nested);
        assert_eq!(manifest.version(), "0.1.0");
    }
}

mod range_algebra {
    use super::*;

    #[test]
    fn an_inverted_range_fails_at_construction() {
        assert!(VersionRange::new(version(6), version(4)).is_err());
    }

    #[test]
    fn an_inverted_or_zero_range_in_a_document_is_refused_naming_the_range() {
        assert_eq!(
            parse_failure(&document_with("protocol", json_range(6, 4))),
            ManifestError::Range {
                field: "protocol",
                error: CodecError::InvertedVersionRange { min: 6, max: 4 },
            }
        );
        // Zero is not a major version, and the refusal names the bound.
        let error = parse_failure(&document_with("events", json_range(0, 4)));
        assert_eq!(error.category(), "range_invalid");
        assert!(
            matches!(
                error,
                ManifestError::Range {
                    field: "events_min",
                    ..
                }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn overlapping_adjacent_disjoint_and_identical_ranges_resolve_as_declared() {
        let release = complete().protocol(range(1, 4)).build().expect("valid");

        let overlapping = complete().protocol(range(3, 7)).build().expect("valid");
        assert_eq!(
            release
                .negotiate_protocol(&overlapping)
                .expect("overlap")
                .get(),
            4
        );

        let identical = complete().protocol(range(1, 4)).build().expect("valid");
        assert_eq!(
            release
                .negotiate_protocol(&identical)
                .expect("identical")
                .get(),
            4
        );

        // Adjacent but touching at one version still overlaps.
        let touching = complete().protocol(range(4, 9)).build().expect("valid");
        assert_eq!(
            release
                .negotiate_protocol(&touching)
                .expect("touching")
                .get(),
            4
        );

        let disjoint = complete().protocol(range(6, 9)).build().expect("valid");
        let error = release
            .negotiate_protocol(&disjoint)
            .expect_err("disjoint ranges");
        assert_eq!(error.category(), "range_invalid");
        // The refusal names both operands.
        let rendered = error.to_string();
        assert!(rendered.contains("1..=4"), "{rendered}");
        assert!(rendered.contains("6..=9"), "{rendered}");
    }
}

mod digest_discipline {
    use super::*;

    #[test]
    fn unknown_and_weakened_algorithms_are_rejected_at_parse() {
        for algorithm in ["md5", "sha-1", "sha1", "crc32", "", "SHA-256"] {
            assert_eq!(
                ArtifactDigest::new(algorithm, SCHEMA_HEX).expect_err("refused"),
                ManifestError::UnacceptableDigestAlgorithm,
                "{algorithm} was accepted"
            );
        }
    }

    /// The same closed set, reached through the document decoder rather than
    /// the constructor, so `DigestAlgorithm::from_wire` is exercised on the
    /// path a real manifest takes.
    #[test]
    fn the_document_decoder_rejects_unknown_and_weakened_algorithms() {
        for algorithm in ["md5", "sha-1", "sha1", "crc32", "", "SHA-256"] {
            let artifact_digest = document_with(
                "digests",
                JsonValue::Object(vec![field("binary", json_digest(algorithm, SCHEMA_HEX))]),
            );
            assert_eq!(
                parse_failure(&artifact_digest),
                ManifestError::UnacceptableDigestAlgorithm,
                "{algorithm} was accepted for the binary digest"
            );

            let sdk_digest = document_with(
                "sdk",
                JsonValue::Object(vec![
                    field("protocol", json_range(1, 2)),
                    field("schema_digest", json_digest(algorithm, SCHEMA_HEX)),
                ]),
            );
            assert_eq!(
                parse_failure(&sdk_digest),
                ManifestError::UnacceptableDigestAlgorithm,
                "{algorithm} was accepted for the SDK schema digest"
            );
        }

        // The accepted algorithms still carry their shape rule through the
        // decoder: a sha-512 declaration holding 64 hex characters is refused
        // naming both lengths.
        let wrong_length = document_with(
            "digests",
            JsonValue::Object(vec![field("binary", json_digest("sha-512", SCHEMA_HEX))]),
        );
        assert_eq!(
            parse_failure(&wrong_length),
            ManifestError::MalformedDigest {
                expected_len: 128,
                actual_len: 64,
            }
        );

        let accepted = document_with(
            "digests",
            JsonValue::Object(vec![field(
                "binary",
                json_digest("sha-512", &"a".repeat(128)),
            )]),
        );
        let manifest =
            ReleaseManifest::from_canonical_bytes(&accepted).expect("sha-512 is accepted");
        assert_eq!(
            manifest
                .digest(ArtifactKind::Binary)
                .expect("declared")
                .algorithm(),
            DigestAlgorithm::Sha512
        );
    }

    #[test]
    fn an_artifact_name_this_build_does_not_define_is_refused() {
        for kind in [
            ArtifactKind::Binary,
            ArtifactKind::SchemaBundle,
            ArtifactKind::Policy,
            ArtifactKind::Persona,
            ArtifactKind::Companion,
            ArtifactKind::Asset,
        ] {
            assert_eq!(ArtifactKind::from_wire(kind.as_str()), Some(kind));
        }
        assert_eq!(ArtifactKind::from_wire("kernel"), None);
        assert_eq!(ArtifactKind::from_wire("Binary"), None);

        let unknown = document_with(
            "digests",
            JsonValue::Object(vec![
                field("binary", json_digest("sha-256", OTHER_HEX)),
                field("kernel", json_digest("sha-256", SCHEMA_HEX)),
            ]),
        );
        assert_eq!(
            parse_failure(&unknown),
            ManifestError::UnknownEnumValue { field: "digests" }
        );
    }

    #[test]
    fn a_digest_must_match_its_algorithm_shape() {
        assert_eq!(
            ArtifactDigest::new("sha-256", "abcd").expect_err("short"),
            ManifestError::MalformedDigest {
                expected_len: 64,
                actual_len: 4,
            }
        );
        // Uppercase and non-hex characters are refused at the declared length.
        let uppercase = SCHEMA_HEX.to_uppercase();
        assert_eq!(
            ArtifactDigest::new("sha-256", &uppercase)
                .expect_err("uppercase")
                .category(),
            "malformed_digest"
        );
        assert!(ArtifactDigest::new("sha-512", &"a".repeat(128)).is_ok());
    }

    #[test]
    fn comparison_is_constant_time_and_a_mismatch_names_only_the_artifact() {
        let declared = digest(SCHEMA_HEX);
        assert!(declared.matches(&digest(SCHEMA_HEX)));
        assert!(!declared.matches(&digest(OTHER_HEX)));

        // Differing algorithms never compare equal.
        let other_algorithm = ArtifactDigest::new("sha-512", &"a".repeat(128)).expect("valid");
        assert!(!declared.matches(&other_algorithm));

        let error = declared
            .verify(ArtifactKind::SchemaBundle, &digest(OTHER_HEX))
            .expect_err("mismatch");
        assert_eq!(
            error,
            ManifestError::DigestMismatch {
                artifact: ArtifactKind::SchemaBundle
            }
        );
        let rendered = error.to_string();
        assert!(rendered.contains("schema_bundle"));
        assert!(!rendered.contains(SCHEMA_HEX));
        assert!(!rendered.contains(OTHER_HEX));
    }

    #[test]
    fn a_declared_digest_is_retrievable_by_artifact_kind() {
        let manifest = complete()
            .digest(ArtifactKind::Policy, digest(SCHEMA_HEX))
            .build()
            .expect("valid");
        assert_eq!(
            manifest.digest(ArtifactKind::Policy),
            Some(&digest(SCHEMA_HEX))
        );
        assert_eq!(manifest.digest(ArtifactKind::Persona), None);
    }
}

mod rollback_coexistence {
    use super::*;

    #[test]
    fn an_incompatible_rollback_target_is_refused_by_the_manifest_layer() {
        let target = RollbackTarget::new("0.0.9", range(1, 2)).expect("valid target");
        let error = complete()
            .database_schema(range(4, 6))
            .rollback(target)
            .build()
            .expect_err("schema ranges cannot coexist");
        assert_eq!(
            error,
            ManifestError::RollbackIncompatible {
                release_min: 4,
                release_max: 6,
                rollback_min: 1,
                rollback_max: 2,
            }
        );
    }

    #[test]
    fn an_incompatible_rollback_target_is_refused_at_parse_too() {
        assert_eq!(
            parse_failure(&document_with("rollback", json_rollback("0.0.9", 1, 2))),
            ManifestError::RollbackIncompatible {
                release_min: 4,
                release_max: 6,
                rollback_min: 1,
                rollback_max: 2,
            }
        );
    }

    #[test]
    fn an_overlapping_rollback_target_is_accepted() {
        let target = RollbackTarget::new("0.0.9", range(3, 5)).expect("valid target");
        let manifest = complete()
            .database_schema(range(4, 6))
            .rollback(target)
            .build()
            .expect("ranges overlap");
        assert_eq!(manifest.rollback().expect("declared").version(), "0.0.9");
    }

    #[test]
    fn a_manifest_without_a_rollback_target_builds() {
        assert!(complete().build().expect("valid").rollback().is_none());
        assert!(
            ReleaseManifest::from_canonical_bytes(&document_without("rollback"))
                .expect("valid")
                .rollback()
                .is_none()
        );
    }
}

mod capability_requirements {
    use super::*;

    fn with_capabilities() -> ReleaseManifestBuilder {
        complete()
            .capability(CapabilityRequirement::required("cgroup_v2").expect("valid"))
            .capability(CapabilityRequirement::required("landlock_abi_3").expect("valid"))
            .capability(CapabilityRequirement::optional("systemd_adapter").expect("valid"))
    }

    #[test]
    fn every_capability_present_is_satisfied() {
        let manifest = with_capabilities().build().expect("valid");
        assert_eq!(
            manifest.evaluate_capabilities(&["cgroup_v2", "landlock_abi_3", "systemd_adapter"]),
            CapabilityOutcome::Satisfied
        );
    }

    #[test]
    fn an_unmet_optional_capability_degrades() {
        let manifest = with_capabilities().build().expect("valid");
        assert_eq!(
            manifest.evaluate_capabilities(&["cgroup_v2", "landlock_abi_3"]),
            CapabilityOutcome::Degraded {
                missing_optional: vec!["systemd_adapter".to_owned()],
            }
        );
    }

    #[test]
    fn an_unmet_required_capability_refuses() {
        let manifest = with_capabilities().build().expect("valid");
        assert_eq!(
            manifest.evaluate_capabilities(&["cgroup_v2", "systemd_adapter"]),
            CapabilityOutcome::Refused {
                missing_required: vec!["landlock_abi_3".to_owned()],
                missing_optional: Vec::new(),
            }
        );
    }

    #[test]
    fn refusal_and_degradation_are_never_collapsed() {
        let manifest = with_capabilities().build().expect("valid");
        // A host missing one of each reports both, as distinct lists, under the
        // refusing outcome. A caller cannot read this as mere degradation.
        let outcome = manifest.evaluate_capabilities(&["cgroup_v2"]);
        assert_eq!(
            outcome,
            CapabilityOutcome::Refused {
                missing_required: vec!["landlock_abi_3".to_owned()],
                missing_optional: vec!["systemd_adapter".to_owned()],
            }
        );
        assert!(!matches!(outcome, CapabilityOutcome::Degraded { .. }));
    }

    #[test]
    fn the_required_flag_survives_the_parse_path_and_must_be_declared() {
        let manifest =
            ReleaseManifest::from_canonical_bytes(&complete_document()).expect("valid document");
        assert_eq!(
            manifest.evaluate_capabilities(&["cgroup_v2"]),
            CapabilityOutcome::Degraded {
                missing_optional: vec!["systemd_adapter".to_owned()],
            }
        );

        // The flag has no default: a capability entry that omits it is refused
        // rather than assumed optional.
        let missing_flag = document_with(
            "capabilities",
            JsonValue::Array(vec![JsonValue::Object(vec![field(
                "id",
                json_text("cgroup_v2"),
            )])]),
        );
        assert_eq!(
            parse_failure(&missing_flag),
            ManifestError::MissingField {
                field: "capability_required"
            }
        );
        let wrong_type = document_with(
            "capabilities",
            JsonValue::Array(vec![JsonValue::Object(vec![
                field("id", json_text("cgroup_v2")),
                field("required", json_text("yes")),
            ])]),
        );
        assert_eq!(
            parse_failure(&wrong_type),
            ManifestError::FieldType {
                field: "capability_required"
            }
        );
    }
}

mod sdk_compatibility {
    use super::*;

    #[test]
    fn a_mismatch_is_detectable_from_the_manifest_alone() {
        let manifest = complete().build().expect("valid");
        let sdk = manifest.sdk();

        assert!(sdk.admits(version(1), &digest(SCHEMA_HEX)));
        assert!(sdk.admits(version(2), &digest(SCHEMA_HEX)));

        // Protocol out of range.
        assert!(!sdk.admits(version(3), &digest(SCHEMA_HEX)));
        // Schema digest differs.
        assert!(!sdk.admits(version(1), &digest(OTHER_HEX)));
    }

    #[test]
    fn the_sdk_coordinates_survive_the_parse_path() {
        let manifest =
            ReleaseManifest::from_canonical_bytes(&complete_document()).expect("valid document");
        let sdk = manifest.sdk();
        assert_eq!(sdk.protocol(), range(1, 2));
        assert_eq!(sdk.schema_digest(), &digest(SCHEMA_HEX));
        assert!(sdk.admits(version(2), &digest(SCHEMA_HEX)));
        assert!(!sdk.admits(version(3), &digest(SCHEMA_HEX)));
        assert!(!sdk.admits(version(1), &digest(OTHER_HEX)));
    }
}

mod secret_hygiene {
    use super::*;

    #[test]
    fn a_credential_appears_only_as_a_descriptor_and_version() {
        let descriptor = CredentialDescriptor::new("database", 3).expect("valid");
        assert_eq!(descriptor.name(), "database");
        assert_eq!(descriptor.version(), 3);

        let manifest = complete().credential(descriptor).build().expect("valid");
        assert_eq!(manifest.credentials().len(), 1);
        // The descriptor exposes a name and a version; there is no accessor
        // that could return a value, which the compile-fail doc test on
        // `CredentialDescriptor` pins.
        assert_eq!(manifest.credentials()[0].version(), 3);
    }

    #[test]
    fn an_absolute_host_path_is_refused() {
        assert_eq!(
            complete()
                .build_target("/opt/automonique/bin")
                .build()
                .expect_err("absolute path"),
            ManifestError::AbsolutePath {
                field: "build_target"
            }
        );
    }

    /// Every bounded manifest string, not one of them.
    ///
    /// This table exists because the rule used to be applied at a single call
    /// site: `build_target` refused an absolute path and the other seven fields
    /// accepted one.
    #[test]
    fn every_bounded_manifest_field_refuses_an_absolute_host_path() {
        let probes: Vec<(&'static str, ManifestError)> = vec![
            (
                "version",
                complete()
                    .version(ABSOLUTE)
                    .build()
                    .expect_err("version accepted an absolute path"),
            ),
            (
                "source_revision",
                complete()
                    .source_revision(ABSOLUTE)
                    .build()
                    .expect_err("source_revision accepted an absolute path"),
            ),
            (
                "build_target",
                complete()
                    .build_target(ABSOLUTE)
                    .build()
                    .expect_err("build_target accepted an absolute path"),
            ),
            (
                "unknown_field_key",
                complete()
                    .unknown_field(ABSOLUTE, "value")
                    .build()
                    .expect_err("unknown_field_key accepted an absolute path"),
            ),
            (
                "unknown_field_value",
                complete()
                    .unknown_field("future_knob", ABSOLUTE)
                    .build()
                    .expect_err("unknown_field_value accepted an absolute path"),
            ),
            (
                "credential_name",
                CredentialDescriptor::new(ABSOLUTE, 1)
                    .expect_err("credential_name accepted an absolute path"),
            ),
            (
                "capability_id",
                CapabilityRequirement::required(ABSOLUTE)
                    .expect_err("capability_id accepted an absolute path"),
            ),
            (
                "rollback_version",
                RollbackTarget::new(ABSOLUTE, range(3, 5))
                    .expect_err("rollback_version accepted an absolute path"),
            ),
        ];
        assert_eq!(probes.len(), 8, "the bounded-field table changed");
        for (field, error) in probes {
            assert_eq!(
                error,
                ManifestError::AbsolutePath { field },
                "{field} did not refuse an absolute host path"
            );
        }
        // The optional constructor is the same type, so it refuses too.
        assert_eq!(
            CapabilityRequirement::optional(ABSOLUTE).expect_err("refused"),
            ManifestError::AbsolutePath {
                field: "capability_id"
            }
        );
    }

    /// The same eight fields reached through a manifest *document*.
    #[test]
    fn the_parse_path_refuses_an_absolute_host_path_in_every_string_field() {
        let probes: Vec<(&'static str, Vec<u8>)> = vec![
            ("version", document_with("version", json_text(ABSOLUTE))),
            (
                "source_revision",
                document_with("source_revision", json_text(ABSOLUTE)),
            ),
            (
                "build_target",
                document_with("build_target", json_text(ABSOLUTE)),
            ),
            (
                "unknown_field_key",
                document_with(ABSOLUTE, json_text("value")),
            ),
            (
                "unknown_field_value",
                document_with("future_knob", json_text(ABSOLUTE)),
            ),
            (
                "credential_name",
                document_with(
                    "credentials",
                    JsonValue::Array(vec![json_credential(ABSOLUTE, 1)]),
                ),
            ),
            (
                "capability_id",
                document_with(
                    "capabilities",
                    JsonValue::Array(vec![json_capability(ABSOLUTE, true)]),
                ),
            ),
            (
                "rollback_version",
                document_with("rollback", json_rollback(ABSOLUTE, 3, 5)),
            ),
        ];
        assert_eq!(probes.len(), 8, "the bounded-field table changed");
        for (field, document) in probes {
            assert_eq!(
                parse_failure(&document),
                ManifestError::AbsolutePath { field },
                "{field} did not refuse an absolute host path at parse"
            );
        }
    }

    #[test]
    fn a_retained_unknown_field_is_not_a_hole_in_the_rule() {
        // A host path nested three levels inside a field this build does not
        // interpret is still refused: preservation is not permission.
        let nested = JsonValue::Array(vec![JsonValue::Object(vec![field(
            "path",
            json_text(ABSOLUTE),
        )])]);
        assert_eq!(
            parse_failure(&document_with("future_knob", nested)),
            ManifestError::AbsolutePath {
                field: "unknown_field_value"
            }
        );
        let nested_key = JsonValue::Object(vec![field(ABSOLUTE, json_text("value"))]);
        assert_eq!(
            parse_failure(&document_with("future_knob", nested_key)),
            ManifestError::AbsolutePath {
                field: "unknown_field_key"
            }
        );
    }

    #[test]
    fn absolute_spellings_are_refused_and_relative_ones_are_not() {
        for spelling in [
            ABSOLUTE,
            "/",
            "/opt/automonique/bin",
            "\\\\server\\share",
            "\\etc\\automonique",
            "C:\\Windows\\System32",
            "c:/windows",
        ] {
            assert_eq!(
                ManifestText::new(spelling, "probe").expect_err("absolute"),
                ManifestError::AbsolutePath { field: "probe" },
                "{spelling} was accepted"
            );
        }
        for spelling in [
            "x86_64-unknown-linux-gnu",
            "0.1.0",
            "etc/automonique/secret.pem",
            "C:relative",
            "~/.config/automonique",
            SOURCE_REVISION,
        ] {
            assert!(
                ManifestText::new(spelling, "probe").is_ok(),
                "{spelling} was refused"
            );
        }
    }

    #[test]
    fn a_field_added_later_cannot_opt_out_of_the_rule() {
        // The rule lives in the type, not at a call site, so it applies to a
        // field name that does not exist yet. The compile-fail doc test on
        // `ManifestText` pins the other half: the inner value is private, so
        // there is no second way to obtain one.
        assert_eq!(
            ManifestText::new(ABSOLUTE, "a_field_added_next_year").expect_err("refused"),
            ManifestError::AbsolutePath {
                field: "a_field_added_next_year"
            }
        );
        assert_eq!(
            ManifestText::new("", "a_field_added_next_year")
                .expect_err("refused")
                .category(),
            "field_invalid"
        );
    }

    #[test]
    fn no_error_rendering_contains_a_secret_or_a_digest_body() {
        let secret = "s3cr3t-value-never-logged";
        let errors = vec![
            ArtifactDigest::new("md5", SCHEMA_HEX).expect_err("weak"),
            ArtifactDigest::new("sha-256", "abcd").expect_err("malformed"),
            digest(SCHEMA_HEX)
                .verify(ArtifactKind::Binary, &digest(OTHER_HEX))
                .expect_err("mismatch"),
            complete()
                .build_target("/absolute")
                .build()
                .expect_err("absolute"),
            ReleaseManifestBuilder::new().build().expect_err("missing"),
            parse_failure(&document_with("version", json_text(ABSOLUTE))),
            parse_failure(b"{\"schema_revision\": 1}"),
        ];
        for error in errors {
            let rendered = error.to_string();
            assert!(!rendered.is_empty());
            assert!(!rendered.contains(secret));
            assert!(!rendered.contains(SCHEMA_HEX));
            assert!(!rendered.contains(OTHER_HEX));
            // A refusal names the field, never the rejected value.
            assert!(!rendered.contains(ABSOLUTE), "{rendered}");
        }
    }
}
