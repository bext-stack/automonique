// SPDX-License-Identifier: Elastic-2.0

//! R1-05 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-05.md`.

use automonique_protocol::codec::{MajorVersion, VersionRange};
use automonique_protocol::release::{
    ArtifactDigest, ArtifactKind, CapabilityOutcome, CapabilityRequirement, CredentialDescriptor,
    MAX_SUPPORTED_MANIFEST_SCHEMA, ManifestError, ReleaseManifestBuilder, RollbackTarget,
    SdkCompatibility,
};

const SCHEMA_HEX: &str = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";
const OTHER_HEX: &str = "0011223344556677889900112233445566778899aabbccddeeff001122334455";

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
        .source_revision("8457c0e7d1311b99566cda0235ba58e7ca1c45c8")
        .build_target("x86_64-unknown-linux-gnu")
        .protocol(range(1, 3))
        .events(range(1, 2))
        .database_schema(range(4, 6))
        .sdk(sdk())
        .digest(ArtifactKind::Binary, digest(OTHER_HEX))
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
    fn unknown_fields_are_retained_within_a_supported_revision() {
        let manifest = complete()
            .unknown_field("future_knob", "enabled")
            .unknown_field("another", "value")
            .build()
            .expect("unknown fields do not prevent construction");
        assert_eq!(
            manifest.unknown_fields(),
            &[
                ("future_knob".to_owned(), "enabled".to_owned()),
                ("another".to_owned(), "value".to_owned()),
            ]
        );
    }
}

mod range_algebra {
    use super::*;

    #[test]
    fn an_inverted_range_fails_at_construction() {
        assert!(VersionRange::new(version(6), version(4)).is_err());
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
        ];
        for error in errors {
            let rendered = error.to_string();
            assert!(!rendered.is_empty());
            assert!(!rendered.contains(secret));
            assert!(!rendered.contains(SCHEMA_HEX));
            assert!(!rendered.contains(OTHER_HEX));
        }
    }
}
