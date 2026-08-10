// SPDX-License-Identifier: Elastic-2.0

//! R1-10 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-10.md`.

use automonique_protocol::codec::{MajorVersion, VersionRange};
use automonique_protocol::schema::{
    BundleRegistry, EnumDescriptor, EnumSensitivity, FieldDescriptor, PinnedBundle, Resolution,
    SchemaDocument, SchemaError, VerdictKind, classify,
};

fn version(value: u32) -> MajorVersion {
    MajorVersion::new(value).expect("non-zero version")
}

fn range(min: u32, max: u32) -> VersionRange {
    VersionRange::new(version(min), version(max)).expect("ordered range")
}

fn field(path: &str, required: bool, type_name: &str) -> FieldDescriptor {
    FieldDescriptor::new(path, required, type_name).expect("valid field")
}

fn enumeration(path: &str, sensitivity: EnumSensitivity, values: &[&str]) -> EnumDescriptor {
    EnumDescriptor::new(path, sensitivity, values).expect("valid enum")
}

/// The baseline document every classification test diffs against.
fn baseline() -> SchemaDocument {
    SchemaDocument::new(
        vec![
            field("turn.id", true, "string"),
            field("turn.note", false, "string"),
        ],
        vec![
            enumeration(
                "approval.decision",
                EnumSensitivity::SecuritySensitive,
                &["allow", "deny"],
            ),
            enumeration("run.state", EnumSensitivity::ReadOnly, &["running", "done"]),
        ],
        &["turn_started", "turn_completed"],
        &["/v1/turns"],
        &[("x-vendor-block", "opaque")],
    )
    .expect("valid document")
}

fn document_with(
    fields: Vec<FieldDescriptor>,
    enums: Vec<EnumDescriptor>,
    kinds: &[&str],
    endpoints: &[&str],
    unmodelled: &[(&str, &str)],
) -> SchemaDocument {
    SchemaDocument::new(fields, enums, kinds, endpoints, unmodelled).expect("valid document")
}

mod bundle_integrity {
    use super::*;

    #[test]
    fn a_bundle_loads_only_when_declared_and_computed_digests_agree() {
        PinnedBundle::load(
            "codex",
            range(1, 3),
            "sha256:aaaa",
            "sha256:aaaa",
            baseline(),
        )
        .expect("digests agree");

        assert_eq!(
            PinnedBundle::load(
                "codex",
                range(1, 3),
                "sha256:aaaa",
                "sha256:bbbb",
                baseline()
            )
            .expect_err("digests differ"),
            SchemaError::DigestMismatch
        );
    }

    #[test]
    fn a_bundle_requires_a_provider_and_a_digest() {
        assert!(
            PinnedBundle::load("", range(1, 3), "sha256:aaaa", "sha256:aaaa", baseline()).is_err()
        );
        assert!(PinnedBundle::load("codex", range(1, 3), "", "", baseline()).is_err());
    }
}

mod range_mapping {
    use super::*;

    fn bundle(provider: &str, min: u32, max: u32, digest: &str) -> PinnedBundle {
        PinnedBundle::load(provider, range(min, max), digest, digest, baseline())
            .expect("valid bundle")
    }

    #[test]
    fn overlapping_ranges_for_one_provider_are_a_conflict_at_load() {
        let mut registry = BundleRegistry::new();
        registry
            .insert(bundle("codex", 1, 3, "sha256:a"))
            .expect("first bundle");
        assert_eq!(
            registry
                .insert(bundle("codex", 3, 7, "sha256:b"))
                .expect_err("ranges touch at 3"),
            SchemaError::OverlappingRanges {
                provider: "codex".to_owned(),
            }
        );
        // A disjoint range for the same provider is fine.
        registry
            .insert(bundle("codex", 4, 7, "sha256:c"))
            .expect("disjoint range");
        // And another provider may use any range.
        registry
            .insert(bundle("opencode", 1, 3, "sha256:d"))
            .expect("different provider");
    }

    #[test]
    fn a_version_outside_every_range_is_unpinned_not_a_nearest_neighbour() {
        let mut registry = BundleRegistry::new();
        registry
            .insert(bundle("codex", 1, 3, "sha256:a"))
            .expect("first");
        registry
            .insert(bundle("codex", 10, 12, "sha256:b"))
            .expect("second");

        // 5 sits between the two ranges; guessing either would be wrong.
        assert_eq!(registry.resolve("codex", version(5)), Resolution::Unpinned);
        assert_eq!(registry.resolve("codex", version(99)), Resolution::Unpinned);
        assert_eq!(
            registry.resolve("unknown-provider", version(1)),
            Resolution::Unpinned
        );

        match registry.resolve("codex", version(2)) {
            Resolution::Pinned(bundle) => assert_eq!(bundle.digest(), "sha256:a"),
            Resolution::Unpinned => panic!("version 2 is pinned"),
        }
        match registry.resolve("codex", version(12)) {
            Resolution::Pinned(bundle) => assert_eq!(bundle.digest(), "sha256:b"),
            Resolution::Unpinned => panic!("version 12 is pinned"),
        }
    }
}

mod verdict_exhaustiveness {
    use super::*;

    #[test]
    fn identical_documents_are_compatible_with_nothing_to_report() {
        let verdict = classify(&baseline(), &baseline());
        assert_eq!(verdict.kind(), VerdictKind::Compatible);
        assert!(
            verdict.evidence().is_empty(),
            "nothing changed, so nothing is named"
        );
    }

    #[test]
    fn every_verdict_is_exactly_one_of_the_three() {
        let cases = [
            (baseline(), VerdictKind::Compatible),
            (
                document_with(
                    vec![field("turn.id", true, "string")],
                    baseline_enums(),
                    &["turn_started", "turn_completed"],
                    &["/v1/turns"],
                    &[("x-vendor-block", "opaque")],
                ),
                VerdictKind::Breaking,
            ),
            (
                document_with(
                    baseline_fields(),
                    baseline_enums(),
                    &["turn_started", "turn_completed"],
                    &["/v1/turns"],
                    &[("x-vendor-block", "changed")],
                ),
                VerdictKind::Unclassifiable,
            ),
        ];
        for (next, expected) in cases {
            let verdict = classify(&baseline(), &next);
            assert_eq!(verdict.kind(), expected);
            assert!(!verdict.kind().as_str().is_empty());
        }
    }

    fn baseline_fields() -> Vec<FieldDescriptor> {
        vec![
            field("turn.id", true, "string"),
            field("turn.note", false, "string"),
        ]
    }

    fn baseline_enums() -> Vec<EnumDescriptor> {
        vec![
            enumeration(
                "approval.decision",
                EnumSensitivity::SecuritySensitive,
                &["allow", "deny"],
            ),
            enumeration("run.state", EnumSensitivity::ReadOnly, &["running", "done"]),
        ]
    }
}

mod unclassifiable_is_preserved {
    use super::*;

    #[test]
    fn an_unmodelled_change_never_reports_compatible() {
        let next = SchemaDocument::new(
            vec![
                field("turn.id", true, "string"),
                field("turn.note", false, "string"),
                // A purely additive change alongside the unmodelled one.
                field("turn.label", false, "string"),
            ],
            vec![
                enumeration(
                    "approval.decision",
                    EnumSensitivity::SecuritySensitive,
                    &["allow", "deny"],
                ),
                enumeration("run.state", EnumSensitivity::ReadOnly, &["running", "done"]),
            ],
            &["turn_started", "turn_completed"],
            &["/v1/turns"],
            &[("x-vendor-block", "reshaped")],
        )
        .expect("valid document");

        let verdict = classify(&baseline(), &next);
        assert_eq!(
            verdict.kind(),
            VerdictKind::Unclassifiable,
            "an additive change alongside an unmodelled one must not read as compatible"
        );
        assert!(!verdict.evidence().is_empty());
    }

    #[test]
    fn a_definite_breakage_outranks_an_unmodelled_change() {
        let next = SchemaDocument::new(
            vec![field("turn.note", false, "string")],
            vec![
                enumeration(
                    "approval.decision",
                    EnumSensitivity::SecuritySensitive,
                    &["allow", "deny"],
                ),
                enumeration("run.state", EnumSensitivity::ReadOnly, &["running", "done"]),
            ],
            &["turn_started", "turn_completed"],
            &["/v1/turns"],
            &[("x-vendor-block", "reshaped")],
        )
        .expect("valid document");

        // Breaking is the more actionable answer when both are present.
        assert_eq!(classify(&baseline(), &next).kind(), VerdictKind::Breaking);
    }
}

mod evidence_completeness {
    use super::*;

    #[test]
    fn a_breaking_verdict_names_what_broke() {
        let next = SchemaDocument::new(
            vec![field("turn.note", false, "string")],
            vec![
                enumeration(
                    "approval.decision",
                    EnumSensitivity::SecuritySensitive,
                    &["allow", "deny"],
                ),
                enumeration("run.state", EnumSensitivity::ReadOnly, &["running", "done"]),
            ],
            &["turn_started", "turn_completed"],
            &["/v1/turns"],
            &[("x-vendor-block", "opaque")],
        )
        .expect("valid document");

        let verdict = classify(&baseline(), &next);
        assert_eq!(verdict.kind(), VerdictKind::Breaking);
        let paths: Vec<&str> = verdict.evidence().iter().map(|c| c.path()).collect();
        assert!(paths.contains(&"turn.id"), "{paths:?}");
        assert!(
            verdict
                .evidence()
                .iter()
                .any(|change| change.reason() == "field removed")
        );
    }

    #[test]
    fn a_compatible_verdict_names_what_was_added() {
        let next = SchemaDocument::new(
            vec![
                field("turn.id", true, "string"),
                field("turn.note", false, "string"),
                field("turn.label", false, "string"),
            ],
            vec![
                enumeration(
                    "approval.decision",
                    EnumSensitivity::SecuritySensitive,
                    &["allow", "deny"],
                ),
                enumeration("run.state", EnumSensitivity::ReadOnly, &["running", "done"]),
            ],
            &["turn_started", "turn_completed"],
            &["/v1/turns"],
            &[("x-vendor-block", "opaque")],
        )
        .expect("valid document");

        let verdict = classify(&baseline(), &next);
        assert_eq!(verdict.kind(), VerdictKind::Compatible);
        assert_eq!(verdict.evidence().len(), 1);
        assert_eq!(verdict.evidence()[0].path(), "turn.label");
        assert_eq!(verdict.evidence()[0].reason(), "optional field added");
    }

    #[test]
    fn breaking_and_unclassifiable_verdicts_are_never_evidence_free() {
        let breaking = classify(
            &baseline(),
            &SchemaDocument::new(
                vec![],
                vec![],
                &["turn_started", "turn_completed"],
                &["/v1/turns"],
                &[("x-vendor-block", "opaque")],
            )
            .expect("valid"),
        );
        assert_eq!(breaking.kind(), VerdictKind::Breaking);
        assert!(!breaking.evidence().is_empty());

        let unclassifiable = classify(
            &baseline(),
            &SchemaDocument::new(
                vec![
                    field("turn.id", true, "string"),
                    field("turn.note", false, "string"),
                ],
                vec![
                    enumeration(
                        "approval.decision",
                        EnumSensitivity::SecuritySensitive,
                        &["allow", "deny"],
                    ),
                    enumeration("run.state", EnumSensitivity::ReadOnly, &["running", "done"]),
                ],
                &["turn_started", "turn_completed"],
                &["/v1/turns"],
                &[("x-vendor-block", "different")],
            )
            .expect("valid"),
        );
        assert_eq!(unclassifiable.kind(), VerdictKind::Unclassifiable);
        assert!(!unclassifiable.evidence().is_empty());
    }
}

mod additive_rules {
    use super::*;

    fn next_with(
        fields: Vec<FieldDescriptor>,
        kinds: &[&str],
        endpoints: &[&str],
    ) -> SchemaDocument {
        SchemaDocument::new(
            fields,
            vec![
                enumeration(
                    "approval.decision",
                    EnumSensitivity::SecuritySensitive,
                    &["allow", "deny"],
                ),
                enumeration("run.state", EnumSensitivity::ReadOnly, &["running", "done"]),
            ],
            kinds,
            endpoints,
            &[("x-vendor-block", "opaque")],
        )
        .expect("valid document")
    }

    fn base_fields() -> Vec<FieldDescriptor> {
        vec![
            field("turn.id", true, "string"),
            field("turn.note", false, "string"),
        ]
    }

    #[test]
    fn additive_changes_classify_compatible() {
        let mut fields = base_fields();
        fields.push(field("turn.label", false, "string"));
        assert_eq!(
            classify(
                &baseline(),
                &next_with(
                    fields,
                    &["turn_started", "turn_completed", "turn_steered"],
                    &["/v1/turns", "/v1/runs"]
                )
            )
            .kind(),
            VerdictKind::Compatible
        );
    }

    #[test]
    fn a_new_required_field_is_breaking() {
        let mut fields = base_fields();
        fields.push(field("turn.tenant", true, "string"));
        assert_eq!(
            classify(
                &baseline(),
                &next_with(fields, &["turn_started", "turn_completed"], &["/v1/turns"])
            )
            .kind(),
            VerdictKind::Breaking
        );
    }

    #[test]
    fn narrowing_a_type_or_tightening_a_field_is_breaking() {
        let narrowed = vec![
            field("turn.id", true, "string"),
            field("turn.note", false, "integer"),
        ];
        assert_eq!(
            classify(
                &baseline(),
                &next_with(
                    narrowed,
                    &["turn_started", "turn_completed"],
                    &["/v1/turns"]
                )
            )
            .kind(),
            VerdictKind::Breaking
        );

        let tightened = vec![
            field("turn.id", true, "string"),
            field("turn.note", true, "string"),
        ];
        assert_eq!(
            classify(
                &baseline(),
                &next_with(
                    tightened,
                    &["turn_started", "turn_completed"],
                    &["/v1/turns"]
                )
            )
            .kind(),
            VerdictKind::Breaking
        );
    }

    #[test]
    fn removing_a_message_kind_or_endpoint_is_breaking() {
        assert_eq!(
            classify(
                &baseline(),
                &next_with(base_fields(), &["turn_started"], &["/v1/turns"])
            )
            .kind(),
            VerdictKind::Breaking
        );
        assert_eq!(
            classify(
                &baseline(),
                &next_with(base_fields(), &["turn_started", "turn_completed"], &[])
            )
            .kind(),
            VerdictKind::Breaking
        );
    }

    #[test]
    fn relaxing_a_requirement_is_compatible() {
        let relaxed = vec![
            field("turn.id", false, "string"),
            field("turn.note", false, "string"),
        ];
        let verdict = classify(
            &baseline(),
            &next_with(relaxed, &["turn_started", "turn_completed"], &["/v1/turns"]),
        );
        assert_eq!(verdict.kind(), VerdictKind::Compatible);
        assert_eq!(verdict.evidence()[0].reason(), "field became optional");
    }
}

mod security_enum_rule {
    use super::*;

    fn with_enums(enums: Vec<EnumDescriptor>) -> SchemaDocument {
        SchemaDocument::new(
            vec![
                field("turn.id", true, "string"),
                field("turn.note", false, "string"),
            ],
            enums,
            &["turn_started", "turn_completed"],
            &["/v1/turns"],
            &[("x-vendor-block", "opaque")],
        )
        .expect("valid document")
    }

    #[test]
    fn a_value_added_to_a_security_sensitive_enum_is_breaking() {
        let next = with_enums(vec![
            enumeration(
                "approval.decision",
                EnumSensitivity::SecuritySensitive,
                &["allow", "deny", "allow_always"],
            ),
            enumeration("run.state", EnumSensitivity::ReadOnly, &["running", "done"]),
        ]);
        let verdict = classify(&baseline(), &next);
        assert_eq!(
            verdict.kind(),
            VerdictKind::Breaking,
            "an existing reader fails closed on the new value"
        );
        assert!(
            verdict
                .evidence()
                .iter()
                .any(|change| change.reason() == "value added to a security-sensitive enum")
        );
    }

    #[test]
    fn a_value_added_to_a_read_only_enum_is_compatible() {
        let next = with_enums(vec![
            enumeration(
                "approval.decision",
                EnumSensitivity::SecuritySensitive,
                &["allow", "deny"],
            ),
            enumeration(
                "run.state",
                EnumSensitivity::ReadOnly,
                &["running", "done", "hibernated"],
            ),
        ]);
        assert_eq!(classify(&baseline(), &next).kind(), VerdictKind::Compatible);
    }

    #[test]
    fn removing_an_enum_value_or_changing_sensitivity_is_breaking() {
        let removed = with_enums(vec![
            enumeration(
                "approval.decision",
                EnumSensitivity::SecuritySensitive,
                &["allow"],
            ),
            enumeration("run.state", EnumSensitivity::ReadOnly, &["running", "done"]),
        ]);
        assert_eq!(
            classify(&baseline(), &removed).kind(),
            VerdictKind::Breaking
        );

        let resensitised = with_enums(vec![
            enumeration(
                "approval.decision",
                EnumSensitivity::SecuritySensitive,
                &["allow", "deny"],
            ),
            enumeration(
                "run.state",
                EnumSensitivity::SecuritySensitive,
                &["running", "done"],
            ),
        ]);
        assert_eq!(
            classify(&baseline(), &resensitised).kind(),
            VerdictKind::Breaking
        );
    }
}

mod determinism {
    use super::*;

    #[test]
    fn repeated_classification_yields_identical_verdicts_and_evidence() {
        let next = SchemaDocument::new(
            vec![
                field("turn.note", false, "string"),
                field("turn.label", false, "string"),
            ],
            vec![enumeration(
                "run.state",
                EnumSensitivity::ReadOnly,
                &["running", "done"],
            )],
            &["turn_completed"],
            &["/v1/turns"],
            &[("x-vendor-block", "opaque")],
        )
        .expect("valid document");

        let first = classify(&baseline(), &next);
        for _ in 0..8 {
            assert_eq!(classify(&baseline(), &next), first);
        }
    }

    #[test]
    fn evidence_order_does_not_depend_on_input_order() {
        // The same document described in a different order must produce the
        // same verdict and the same canonically ordered evidence.
        let forward = SchemaDocument::new(
            vec![
                field("a.one", false, "string"),
                field("b.two", false, "string"),
                field("c.three", false, "string"),
            ],
            vec![],
            &["alpha", "beta"],
            &["/one", "/two"],
            &[],
        )
        .expect("valid");
        let reversed = SchemaDocument::new(
            vec![
                field("c.three", false, "string"),
                field("b.two", false, "string"),
                field("a.one", false, "string"),
            ],
            vec![],
            &["beta", "alpha"],
            &["/two", "/one"],
            &[],
        )
        .expect("valid");
        assert_eq!(forward, reversed, "construction order is normalized away");

        let empty = SchemaDocument::default();
        let from_forward = classify(&empty, &forward);
        let from_reversed = classify(&empty, &reversed);
        assert_eq!(from_forward, from_reversed);

        let paths: Vec<&str> = from_forward.evidence().iter().map(|c| c.path()).collect();
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        assert_eq!(paths, sorted, "evidence is canonically ordered");
    }
}
