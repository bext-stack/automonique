// SPDX-License-Identifier: Elastic-2.0

//! R1-10 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `docs/product-plan/requirements/state-and-protocols.md`.

use automonique_protocol::codec::{MajorVersion, VersionRange};
use automonique_protocol::digest::DigestError;
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

/// A document distinguishable from [`baseline`] and from every other variant,
/// used wherever a test needs genuinely different bundles.
fn variant(marker: &str) -> SchemaDocument {
    let mut fields = vec![
        field("turn.id", true, "string"),
        field("turn.note", false, "string"),
    ];
    fields.push(field(&format!("turn.{marker}"), false, "string"));
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
        &["turn_started", "turn_completed"],
        &["/v1/turns"],
        &[("x-vendor-block", "opaque")],
    )
    .expect("valid document")
}

/// Load a bundle under the digest its own document actually has.
fn pinned(provider: &str, min: u32, max: u32, document: SchemaDocument) -> PinnedBundle {
    let declared = document.digest().to_string();
    PinnedBundle::load(provider, range(min, max), &declared, document).expect("valid bundle")
}

mod bundle_integrity {
    use super::*;

    /// SHA-256 itself, measured against published vectors before anything is
    /// built on it. A hash that is wrong only on long inputs would make every
    /// digest check below meaningless.
    mod digest_algorithm {
        use automonique_protocol::digest::{DigestError, Sha256, Sha256Digest};

        /// FIPS 180-4 / RFC 6234 published vectors: the empty message, the
        /// one-block "abc" case, the 448-bit case and the 896-bit multi-block
        /// case.
        const PUBLISHED: [(&str, &str); 4] = [
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                concat!(
                    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn",
                    "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
                ),
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            ),
        ];

        /// `"a"` repeated, at and around every padding boundary: 55 is the last
        /// length that pads inside one block, 56 forces a second block, and 64
        /// is an exact block. Expected values were produced by an independent
        /// implementation (CPython `hashlib.sha256`) and are recorded here as
        /// fixtures; the four entries of [`PUBLISHED`] are the published ones.
        const BOUNDARIES: [(usize, &str); 16] = [
            (
                1,
                "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            ),
            (
                54,
                "a3f01b6939256127582ac8ae9fb47a382a244680806a3f613a118851c1ca1d47",
            ),
            (
                55,
                "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
            ),
            (
                56,
                "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
            ),
            (
                57,
                "f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6",
            ),
            (
                63,
                "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
            ),
            (
                64,
                "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
            ),
            (
                65,
                "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
            ),
            (
                111,
                "6374f73208854473827f6f6a3f43b1f53eaa3b82c21c1a6d69a2110b2a79baad",
            ),
            (
                112,
                "f54353008a2553262ecdc4a34749563ba0950e8b0fc8652780b0a614b99683c1",
            ),
            (
                119,
                "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb",
            ),
            (
                120,
                "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c",
            ),
            (
                127,
                "c57e9278af78fa3cab38667bef4ce29d783787a2f731d4e12200270f0c32320a",
            ),
            (
                128,
                "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e",
            ),
            (
                129,
                "c12cb024a2e5551cca0e08fce8f1c5e314555cc3fef6329ee994a3db752166ae",
            ),
            (
                1000,
                "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3",
            ),
        ];

        /// A thousand bytes that are not all identical, so a bug that depends
        /// on byte value rather than length is visible.
        fn pattern() -> Vec<u8> {
            (0..1000u32)
                .map(|index| u8::try_from(index % 251).expect("below 251"))
                .collect()
        }

        #[test]
        fn published_vectors_hash_to_their_published_digests() {
            for (message, expected) in PUBLISHED {
                assert_eq!(
                    Sha256::digest(message.as_bytes()).to_hex(),
                    expected,
                    "message of {} bytes",
                    message.len()
                );
            }
        }

        #[test]
        fn the_one_million_character_vector_hashes_correctly() {
            let message = "a".repeat(1_000_000);
            assert_eq!(
                Sha256::digest(message.as_bytes()).to_hex(),
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
            );
        }

        #[test]
        fn lengths_around_every_padding_boundary_hash_correctly() {
            for (length, expected) in BOUNDARIES {
                let message = "a".repeat(length);
                assert_eq!(
                    Sha256::digest(message.as_bytes()).to_hex(),
                    expected,
                    "{length} bytes"
                );
            }
        }

        #[test]
        fn every_byte_value_hashes_correctly() {
            let message: Vec<u8> = (0..=u8::MAX).collect();
            assert_eq!(
                Sha256::digest(&message).to_hex(),
                "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"
            );
        }

        #[test]
        fn the_chunking_of_an_update_stream_does_not_change_the_digest() {
            let message = pattern();
            let whole = Sha256::digest(&message);
            assert_eq!(
                whole.to_hex(),
                "4e4c294b331f7a2099a379bec34b9f9fc03dc46ab465d998f4d683da53487e6d"
            );
            for size in 1..=70 {
                let mut hasher = Sha256::new();
                for chunk in message.chunks(size) {
                    hasher.update(chunk);
                }
                assert_eq!(hasher.finish(), whole, "chunked into {size}-byte writes");
            }
        }

        #[test]
        fn a_digest_has_exactly_one_accepted_spelling() {
            let digest = Sha256::digest(b"abc");
            assert_eq!(
                digest.to_string(),
                "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
            assert_eq!(digest.to_string().parse(), Ok(digest));
            assert_eq!(digest.as_bytes().len(), 32);

            for unnamed in [
                String::new(),
                digest.to_hex(),
                format!("sha1:{}", digest.to_hex()),
                format!("sha256{}", digest.to_hex()),
            ] {
                assert_eq!(
                    unnamed.parse::<Sha256Digest>(),
                    Err(DigestError::AlgorithmUnnamed),
                    "{unnamed}"
                );
            }
            for malformed in [
                "sha256:aaaa".to_owned(),
                format!("sha256:{}", digest.to_hex().to_uppercase()),
                format!("sha256:{}0", digest.to_hex()),
                format!("sha256:{}", "z".repeat(64)),
            ] {
                assert_eq!(
                    malformed.parse::<Sha256Digest>(),
                    Err(DigestError::HexInvalid),
                    "{malformed}"
                );
            }
        }
    }

    /// The document encoding the digest is taken over. If two different
    /// documents could share an encoding, computing the digest would prove
    /// nothing.
    mod document_encoding {
        use super::*;

        #[test]
        fn changing_any_part_of_a_document_changes_its_digest() {
            let mutations = [
                baseline(),
                // A renamed field.
                document_with(
                    vec![
                        field("turn.identifier", true, "string"),
                        field("turn.note", false, "string"),
                    ],
                    baseline_enums(),
                    &["turn_started", "turn_completed"],
                    &["/v1/turns"],
                    &[("x-vendor-block", "opaque")],
                ),
                // A retyped field.
                document_with(
                    vec![
                        field("turn.id", true, "integer"),
                        field("turn.note", false, "string"),
                    ],
                    baseline_enums(),
                    &["turn_started", "turn_completed"],
                    &["/v1/turns"],
                    &[("x-vendor-block", "opaque")],
                ),
                // A field whose only change is its requiredness.
                document_with(
                    vec![
                        field("turn.id", true, "string"),
                        field("turn.note", true, "string"),
                    ],
                    baseline_enums(),
                    &["turn_started", "turn_completed"],
                    &["/v1/turns"],
                    &[("x-vendor-block", "opaque")],
                ),
                // An enum whose only change is its sensitivity.
                document_with(
                    baseline_fields(),
                    vec![
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
                    ],
                    &["turn_started", "turn_completed"],
                    &["/v1/turns"],
                    &[("x-vendor-block", "opaque")],
                ),
                // An extra enum value.
                document_with(
                    baseline_fields(),
                    vec![
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
                    ],
                    &["turn_started", "turn_completed"],
                    &["/v1/turns"],
                    &[("x-vendor-block", "opaque")],
                ),
                // An extra message kind.
                document_with(
                    baseline_fields(),
                    baseline_enums(),
                    &["turn_started", "turn_completed", "turn_steered"],
                    &["/v1/turns"],
                    &[("x-vendor-block", "opaque")],
                ),
                // An extra endpoint.
                document_with(
                    baseline_fields(),
                    baseline_enums(),
                    &["turn_started", "turn_completed"],
                    &["/v1/turns", "/v1/runs"],
                    &[("x-vendor-block", "opaque")],
                ),
                // A reshaped unmodelled value.
                document_with(
                    baseline_fields(),
                    baseline_enums(),
                    &["turn_started", "turn_completed"],
                    &["/v1/turns"],
                    &[("x-vendor-block", "reshaped")],
                ),
                // A renamed unmodelled key.
                document_with(
                    baseline_fields(),
                    baseline_enums(),
                    &["turn_started", "turn_completed"],
                    &["/v1/turns"],
                    &[("x-vendor-blob", "opaque")],
                ),
            ];

            let mut digests: Vec<String> = mutations
                .iter()
                .map(|document| document.digest().to_string())
                .collect();
            let count = digests.len();
            digests.sort();
            digests.dedup();
            assert_eq!(
                digests.len(),
                count,
                "each single-part mutation must move the digest"
            );
        }

        #[test]
        fn adjacent_parts_cannot_be_resplit_without_changing_the_digest() {
            // Without a length prefix both of these encode the text "abc", and
            // a bundle could be swapped for the other without detection.
            let split_left = document_with(vec![], vec![], &["ab", "c"], &[], &[]);
            let split_right = document_with(vec![], vec![], &["a", "bc"], &[], &[]);
            assert_ne!(split_left.digest(), split_right.digest());

            let key_heavy = document_with(vec![], vec![], &[], &[], &[("ab", "c")]);
            let value_heavy = document_with(vec![], vec![], &[], &[], &[("a", "bc")]);
            assert_ne!(key_heavy.digest(), value_heavy.digest());

            // A message kind and an endpoint spelled the same are different
            // sections, so they cannot be swapped either.
            let as_kind = document_with(vec![], vec![], &["shared"], &[], &[]);
            let as_endpoint = document_with(vec![], vec![], &[], &["shared"], &[]);
            assert_ne!(as_kind.digest(), as_endpoint.digest());
        }

        #[test]
        fn the_digest_does_not_depend_on_the_order_parts_were_supplied_in() {
            let forward = document_with(
                vec![
                    field("a.one", false, "string"),
                    field("b.two", false, "string"),
                ],
                vec![],
                &["alpha", "beta"],
                &["/one", "/two"],
                &[("k1", "v1"), ("k2", "v2")],
            );
            let reversed = document_with(
                vec![
                    field("b.two", false, "string"),
                    field("a.one", false, "string"),
                ],
                vec![],
                &["beta", "alpha"],
                &["/two", "/one"],
                &[("k2", "v2"), ("k1", "v1")],
            );
            assert_eq!(forward.canonical_bytes(), reversed.canonical_bytes());
            assert_eq!(forward.digest(), reversed.digest());
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

    #[test]
    fn a_bundle_loads_only_when_its_declared_digest_describes_its_document() {
        let document = baseline();
        let declared = document.digest().to_string();
        let bundle =
            PinnedBundle::load("codex", range(1, 3), &declared, document).expect("digest matches");
        assert_eq!(bundle.digest().to_string(), declared);
        assert_eq!(bundle.digest(), bundle.document().digest());
    }

    #[test]
    fn a_bundle_carrying_another_documents_digest_does_not_load() {
        let other = variant("other");
        let declared = other.digest();
        let document = baseline();
        let computed = document.digest();
        assert_ne!(declared, computed);

        assert_eq!(
            PinnedBundle::load("codex", range(1, 3), &declared.to_string(), document)
                .expect_err("the declared digest belongs to a different document"),
            SchemaError::DigestMismatch { declared, computed }
        );
    }

    #[test]
    fn a_pin_that_was_not_updated_when_the_document_drifted_does_not_load() {
        // The realistic failure: the upstream schema gained a field and nobody
        // recomputed the pin.
        let pinned_at = baseline().digest();
        let drifted = document_with(
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
        );
        let computed = drifted.digest();

        assert_eq!(
            PinnedBundle::load("codex", range(1, 3), &pinned_at.to_string(), drifted)
                .expect_err("the document moved under the pin"),
            SchemaError::DigestMismatch {
                declared: pinned_at,
                computed,
            }
        );
    }

    #[test]
    fn a_declared_digest_must_be_a_canonical_sha256_spelling() {
        let real = baseline().digest().to_hex();
        for (declared, expected) in [
            ("", DigestError::AlgorithmUnnamed),
            // The placeholder digests this suite used before the digest was
            // computed are no longer even well-formed.
            ("sha256:aaaa", DigestError::HexInvalid),
            ("sha256:", DigestError::HexInvalid),
        ] {
            assert_eq!(
                PinnedBundle::load("codex", range(1, 3), declared, baseline())
                    .expect_err("malformed digest"),
                SchemaError::DigestMalformed { error: expected },
                "{declared}"
            );
        }
        for (declared, expected) in [
            (real.clone(), DigestError::AlgorithmUnnamed),
            (format!("sha1:{real}"), DigestError::AlgorithmUnnamed),
            (
                format!("sha256:{}", real.to_uppercase()),
                DigestError::HexInvalid,
            ),
        ] {
            assert_eq!(
                PinnedBundle::load("codex", range(1, 3), &declared, baseline())
                    .expect_err("malformed digest"),
                SchemaError::DigestMalformed { error: expected },
                "{declared}"
            );
        }
    }

    #[test]
    fn a_bundle_requires_a_provider() {
        let document = baseline();
        let declared = document.digest().to_string();
        assert_eq!(
            PinnedBundle::load("", range(1, 3), &declared, document).expect_err("empty provider"),
            SchemaError::FieldInvalid { field: "provider" }
        );
    }

    #[test]
    fn every_refusal_has_a_distinct_stable_category() {
        assert_eq!(
            SchemaError::DigestMismatch {
                declared: baseline().digest(),
                computed: variant("other").digest(),
            }
            .category(),
            "digest_mismatch"
        );
        assert_eq!(
            SchemaError::DigestMalformed {
                error: DigestError::HexInvalid,
            }
            .category(),
            "digest_malformed"
        );
    }
}

mod range_mapping {
    use super::*;

    #[test]
    fn overlapping_ranges_for_one_provider_are_a_conflict_at_load() {
        // Each bundle carries a genuinely different document. Four bundles
        // holding the same document under four different digests is no longer
        // writable: a declared digest that does not describe its document is
        // refused at load.
        let mut registry = BundleRegistry::new();
        registry
            .insert(pinned("codex", 1, 3, variant("first")))
            .expect("first bundle");
        assert_eq!(
            registry
                .insert(pinned("codex", 3, 7, variant("second")))
                .expect_err("ranges touch at 3"),
            SchemaError::OverlappingRanges {
                provider: "codex".to_owned(),
            }
        );
        // A disjoint range for the same provider is fine.
        registry
            .insert(pinned("codex", 4, 7, variant("third")))
            .expect("disjoint range");
        // And another provider may use any range.
        registry
            .insert(pinned("opencode", 1, 3, variant("fourth")))
            .expect("different provider");
    }

    #[test]
    fn distinct_bundles_carry_distinct_documents_and_distinct_digests() {
        let markers = ["first", "second", "third", "fourth"];
        let mut digests: Vec<String> = markers
            .iter()
            .map(|marker| variant(marker).digest().to_string())
            .collect();
        assert_eq!(digests.len(), markers.len());
        digests.sort();
        digests.dedup();
        assert_eq!(digests.len(), markers.len(), "{digests:?}");
    }

    #[test]
    fn a_version_outside_every_range_is_unpinned_not_a_nearest_neighbour() {
        let low = variant("low");
        let high = variant("high");
        let mut registry = BundleRegistry::new();
        registry
            .insert(pinned("codex", 1, 3, low.clone()))
            .expect("first");
        registry
            .insert(pinned("codex", 10, 12, high.clone()))
            .expect("second");

        // 5 sits between the two ranges; guessing either would be wrong.
        assert_eq!(registry.resolve("codex", version(5)), Resolution::Unpinned);
        assert_eq!(registry.resolve("codex", version(99)), Resolution::Unpinned);
        assert_eq!(
            registry.resolve("unknown-provider", version(1)),
            Resolution::Unpinned
        );

        match registry.resolve("codex", version(2)) {
            Resolution::Pinned(bundle) => assert_eq!(bundle.digest(), low.digest()),
            Resolution::Unpinned => panic!("version 2 is pinned"),
        }
        match registry.resolve("codex", version(12)) {
            Resolution::Pinned(bundle) => assert_eq!(bundle.digest(), high.digest()),
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
