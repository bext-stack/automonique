// SPDX-License-Identifier: Elastic-2.0

//! The release trust-root verification contract.
//!
//! The load-bearing test in this file is
//! `no_input_reaches_verified::a_perfect_attestation_is_still_unverifiable`.
//! Everything else checks that a refusal is the *right* refusal; that one
//! checks that success is not reachable at all, which is the property the whole
//! module exists to hold.

use automonique_protocol::codec::{CodecError, MajorVersion, VersionRange};
use automonique_protocol::primitives::ValueError;
use automonique_protocol::release::{
    ArtifactDigest, ArtifactKind, ReleaseManifest, ReleaseManifestBuilder, SdkCompatibility,
};
use automonique_protocol::release_trust_root::{
    AttestationSignature, AttestationVerdict, KeyId, MAX_ATTESTATION_DOCUMENT_BYTES,
    MAX_KEY_ID_BYTES, MAX_TRUSTED_KEYS, RELEASE_ATTESTATION_SCHEMA_V1, ReleaseAttestation,
    ReleaseTrustDecision, SignatureAlgorithm, TrustRefusal, TrustRootError, TrustedKey,
    TrustedKeySet, UnverifiableReason, verify_attestation, verify_attestation_document,
};
use automonique_protocol::wire::JsonValue;

const BINARY_HEX: &str = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";
const SCHEMA_HEX: &str = "0011223344556677889900112233445566778899aabbccddeeff001122334455";
const TRUSTED_ED25519: &str = "release-2026-a";
const TRUSTED_ECDSA: &str = "release-2026-b";

fn version(value: u32) -> MajorVersion {
    MajorVersion::new(value).expect("non-zero version")
}

fn range(min: u32, max: u32) -> VersionRange {
    VersionRange::new(version(min), version(max)).expect("ordered range")
}

fn digest(hex: &str) -> ArtifactDigest {
    ArtifactDigest::new("sha-256", hex).expect("valid digest")
}

fn manifest_named(release_version: &str) -> ReleaseManifest {
    ReleaseManifestBuilder::new()
        .schema_revision(1)
        .version(release_version)
        .source_revision("8457c0e7d1311b99566cda0235ba58e7ca1c45c8")
        .build_target("x86_64-unknown-linux-gnu")
        .protocol(range(1, 3))
        .events(range(1, 2))
        .database_schema(range(4, 6))
        .sdk(SdkCompatibility::new(range(1, 2), digest(SCHEMA_HEX)))
        .digest(ArtifactKind::Binary, digest(BINARY_HEX))
        .build()
        .expect("valid manifest")
}

fn manifest() -> ReleaseManifest {
    manifest_named("0.1.0")
}

/// A signature of the fixed width both accepted algorithms use.
fn signature_hex(seed: &str) -> String {
    seed.repeat(128 / seed.len())
}

/// A trust root pinning one Ed25519 key and one ECDSA key.
fn keys() -> TrustedKeySet {
    TrustedKeySet::new([
        TrustedKey::new(TRUSTED_ED25519, "ed25519").expect("valid key"),
        TrustedKey::new(TRUSTED_ECDSA, "ecdsa-p256-sha256").expect("valid key"),
    ])
    .expect("valid set")
}

/// A trust root pinning only Ed25519.
fn ed25519_only() -> TrustedKeySet {
    TrustedKeySet::new([TrustedKey::new(TRUSTED_ED25519, "ed25519").expect("valid key")])
        .expect("valid set")
}

/// An attestation with every field valid and correct for `manifest`.
fn perfect_attestation(subject: &ReleaseManifest) -> ReleaseAttestation {
    ReleaseAttestation::new(
        subject.canonical_digest(),
        TRUSTED_ED25519,
        "ed25519",
        &signature_hex("7c"),
    )
    .expect("valid attestation")
}

fn field(name: &str, value: JsonValue) -> (String, JsonValue) {
    (name.to_owned(), value)
}

fn json_text(value: &str) -> JsonValue {
    JsonValue::String(value.to_owned())
}

fn json_digest(algorithm: &str, hex: &str) -> JsonValue {
    JsonValue::Object(vec![
        field("algorithm", json_text(algorithm)),
        field("hex", json_text(hex)),
    ])
}

/// The document form of [`perfect_attestation`].
fn document_fields(subject: &ReleaseManifest) -> Vec<(String, JsonValue)> {
    vec![
        field("algorithm", json_text("ed25519")),
        field("key_id", json_text(TRUSTED_ED25519)),
        field(
            "manifest_digest",
            json_digest("sha-256", subject.canonical_digest().hex()),
        ),
        field("schema", json_text(RELEASE_ATTESTATION_SCHEMA_V1)),
        field("signature", json_text(&signature_hex("7c"))),
    ]
}

fn encode(fields: Vec<(String, JsonValue)>) -> Vec<u8> {
    JsonValue::Object(fields).to_canonical_bytes()
}

fn document_without(key: &str, subject: &ReleaseManifest) -> Vec<u8> {
    encode(
        document_fields(subject)
            .into_iter()
            .filter(|(name, _)| name != key)
            .collect(),
    )
}

fn document_with(key: &str, value: JsonValue, subject: &ReleaseManifest) -> Vec<u8> {
    let mut fields: Vec<(String, JsonValue)> = document_fields(subject)
        .into_iter()
        .filter(|(name, _)| name != key)
        .collect();
    fields.push(field(key, value));
    encode(fields)
}

fn parse_failure(payload: &[u8]) -> TrustRootError {
    ReleaseAttestation::from_canonical_bytes(payload).expect_err("the document is refused")
}

/// The whole point of the module.
mod no_input_reaches_verified {
    use super::*;

    /// Every field valid, the key pinned, the algorithm allowed, the digest the
    /// manifest's own — and the answer is still that nothing was verified.
    ///
    /// If this test ever fails, either a real backend landed (and this file is
    /// the first thing that must change) or something started claiming a check
    /// it did not perform.
    #[test]
    fn a_perfect_attestation_is_still_unverifiable() {
        let subject = manifest();
        let attestation = perfect_attestation(&subject);
        let trust_root = keys();

        // Nothing is wrong with any input: state that positively, so a later
        // reader cannot mistake this for a malformed-input test.
        assert!(trust_root.allows_algorithm(attestation.algorithm()));
        assert_eq!(
            trust_root
                .key(attestation.key_id())
                .expect("the key is pinned")
                .algorithm(),
            attestation.algorithm()
        );
        assert!(
            subject
                .canonical_digest()
                .matches(attestation.manifest_digest())
        );

        let verdict = verify_attestation(&subject, &attestation, &trust_root);
        assert_eq!(
            verdict,
            AttestationVerdict::Unverifiable {
                reason: UnverifiableReason::NoCryptoBackend
            }
        );
        assert_eq!(verdict.category(), "unverifiable");
        assert_eq!(
            ReleaseTrustDecision::from_verdict(verdict),
            ReleaseTrustDecision::Refuse {
                reason: TrustRefusal::NoTrustRoot
            }
        );
    }

    /// The same claim across every input this crate can build.
    ///
    /// Two algorithms, four key identifiers (both pinned, one unpinned, one
    /// short but well-formed), three signatures, two bound digests (the
    /// manifest's own and an unrelated one), two manifests and three trust
    /// roots: 288 combinations, each verified through both the typed and the
    /// document route. None is `Verified`; none admits.
    #[test]
    fn no_constructible_input_produces_verified_or_admit() {
        let subjects = [manifest(), manifest_named("0.2.0")];
        let roots = [keys(), ed25519_only(), other_root()];
        let mut checked = 0_usize;
        for subject in &subjects {
            for algorithm in ["ed25519", "ecdsa-p256-sha256"] {
                for key_id in [TRUSTED_ED25519, TRUSTED_ECDSA, "release-2027-z", "a"] {
                    for seed in ["00", "7c", "ff"] {
                        for bound in [subject.canonical_digest(), digest(BINARY_HEX)] {
                            let attestation = ReleaseAttestation::new(
                                bound,
                                key_id,
                                algorithm,
                                &signature_hex(seed),
                            )
                            .expect("valid attestation");
                            for root in &roots {
                                let verdict = verify_attestation(subject, &attestation, root);
                                assert!(
                                    !matches!(verdict, AttestationVerdict::Verified(_)),
                                    "{key_id}/{algorithm} reached Verified"
                                );
                                assert_ne!(verdict.category(), "verified");
                                assert!(
                                    !ReleaseTrustDecision::from_verdict(verdict).admits(),
                                    "{key_id}/{algorithm} admitted"
                                );

                                let bytes = attestation.to_canonical_bytes();
                                let via_document =
                                    verify_attestation_document(subject, &bytes, root);
                                assert!(
                                    !matches!(via_document, AttestationVerdict::Verified(_)),
                                    "{key_id}/{algorithm} reached Verified through the document"
                                );
                                assert!(
                                    !ReleaseTrustDecision::from_verdict(via_document).admits(),
                                    "{key_id}/{algorithm} admitted through the document"
                                );
                                checked += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(checked, 288);
    }

    /// A trust root that pins neither fixture key.
    fn other_root() -> TrustedKeySet {
        TrustedKeySet::new([TrustedKey::new("release-2024-legacy", "ed25519").expect("valid")])
            .expect("valid set")
    }

    /// The reason the sweep above can be exhaustive over *shapes* rather than
    /// over values: the success arm carries an uninhabited proof, so no body
    /// could return it whatever the input.
    ///
    /// The compile-fail doc test on the module pins that a caller cannot mint
    /// one either. This test records the runtime half — every route out of the
    /// module is a refusal.
    #[test]
    fn every_decision_this_module_can_produce_is_a_refusal() {
        let subject = manifest();
        let trust_root = keys();
        let verdicts = [
            verify_attestation(&subject, &perfect_attestation(&subject), &trust_root),
            verify_attestation(
                &subject,
                &ReleaseAttestation::new(
                    subject.canonical_digest(),
                    "release-2027-z",
                    "ed25519",
                    &signature_hex("7c"),
                )
                .expect("valid"),
                &ed25519_only(),
            ),
            verify_attestation(
                &subject,
                &ReleaseAttestation::new(
                    subject.canonical_digest(),
                    TRUSTED_ED25519,
                    "ecdsa-p256-sha256",
                    &signature_hex("7c"),
                )
                .expect("valid"),
                &ed25519_only(),
            ),
            verify_attestation(
                &subject,
                &ReleaseAttestation::new(
                    subject.canonical_digest(),
                    TRUSTED_ECDSA,
                    "ed25519",
                    &signature_hex("7c"),
                )
                .expect("valid"),
                &keys(),
            ),
            verify_attestation(
                &manifest_named("0.2.0"),
                &perfect_attestation(&subject),
                &trust_root,
            ),
            verify_attestation_document(&subject, b"{}", &trust_root),
        ];
        let mut reasons = Vec::new();
        for verdict in verdicts {
            let decision = ReleaseTrustDecision::from_verdict(verdict);
            assert!(!decision.admits());
            let ReleaseTrustDecision::Refuse { reason } = decision else {
                panic!("a decision that is not a refusal")
            };
            reasons.push(reason);
        }
        assert_eq!(
            reasons,
            vec![
                TrustRefusal::NoTrustRoot,
                TrustRefusal::UnknownKey,
                TrustRefusal::DisallowedAlgorithm,
                TrustRefusal::KeyAlgorithmMismatch,
                TrustRefusal::ManifestDigestMismatch,
                TrustRefusal::MalformedAttestation,
            ]
        );
    }
}

mod state_machine_order {
    use super::*;

    #[test]
    fn an_unpinned_key_is_named() {
        let subject = manifest();
        let attestation = ReleaseAttestation::new(
            subject.canonical_digest(),
            "release-2027-z",
            "ed25519",
            &signature_hex("7c"),
        )
        .expect("valid");
        assert_eq!(
            verify_attestation(&subject, &attestation, &keys()),
            AttestationVerdict::UnknownKey {
                key_id: KeyId::new("release-2027-z").expect("valid")
            }
        );
    }

    #[test]
    fn an_algorithm_no_pinned_key_signs_with_is_refused() {
        let subject = manifest();
        let attestation = ReleaseAttestation::new(
            subject.canonical_digest(),
            TRUSTED_ED25519,
            "ecdsa-p256-sha256",
            &signature_hex("7c"),
        )
        .expect("valid");
        assert_eq!(
            verify_attestation(&subject, &attestation, &ed25519_only()),
            AttestationVerdict::DisallowedAlgorithm {
                algorithm: SignatureAlgorithm::EcdsaP256Sha256
            }
        );
    }

    /// Algorithm confusion on a key that *is* pinned: the set admits ECDSA
    /// because another key uses it, and this key does not.
    #[test]
    fn a_pinned_key_signing_with_another_keys_algorithm_is_refused() {
        let subject = manifest();
        let attestation = ReleaseAttestation::new(
            subject.canonical_digest(),
            TRUSTED_ECDSA,
            "ed25519",
            &signature_hex("7c"),
        )
        .expect("valid");
        assert_eq!(
            verify_attestation(&subject, &attestation, &keys()),
            AttestationVerdict::KeyAlgorithmMismatch {
                key_id: KeyId::new(TRUSTED_ECDSA).expect("valid"),
                trusted: SignatureAlgorithm::EcdsaP256Sha256,
                presented: SignatureAlgorithm::Ed25519,
            }
        );
    }

    #[test]
    fn an_attestation_bound_to_another_manifest_is_refused() {
        let subject = manifest();
        let attestation = perfect_attestation(&subject);
        assert_eq!(
            verify_attestation(&manifest_named("0.2.0"), &attestation, &keys()),
            AttestationVerdict::ManifestDigestMismatch
        );
    }

    /// A digest that is well formed but covers nothing in particular is refused
    /// exactly like one covering the wrong release: the check is agreement, not
    /// plausibility.
    #[test]
    fn an_unrelated_digest_is_refused() {
        let subject = manifest();
        let attestation = ReleaseAttestation::new(
            digest(BINARY_HEX),
            TRUSTED_ED25519,
            "ed25519",
            &signature_hex("7c"),
        )
        .expect("valid");
        assert_eq!(
            verify_attestation(&subject, &attestation, &keys()),
            AttestationVerdict::ManifestDigestMismatch
        );
    }

    /// The documented order, proved by inputs that fail two checks at once.
    #[test]
    fn the_earliest_failing_check_is_the_one_reported() {
        let subject = manifest();
        let other = manifest_named("0.2.0");

        // Unpinned key *and* wrong digest: the key is reported.
        let unknown_and_stale = ReleaseAttestation::new(
            other.canonical_digest(),
            "release-2027-z",
            "ed25519",
            &signature_hex("7c"),
        )
        .expect("valid");
        assert_eq!(
            verify_attestation(&subject, &unknown_and_stale, &keys()).category(),
            "unknown_key"
        );

        // Disallowed algorithm *and* unpinned key: the algorithm is reported,
        // so key membership cannot be probed by varying the algorithm.
        let disallowed_and_unknown = ReleaseAttestation::new(
            subject.canonical_digest(),
            "release-2027-z",
            "ecdsa-p256-sha256",
            &signature_hex("7c"),
        )
        .expect("valid");
        assert_eq!(
            verify_attestation(&subject, &disallowed_and_unknown, &ed25519_only()).category(),
            "disallowed_algorithm"
        );

        // Wrong algorithm for a pinned key *and* wrong digest: the algorithm is
        // reported.
        let mismatched_and_stale = ReleaseAttestation::new(
            other.canonical_digest(),
            TRUSTED_ECDSA,
            "ed25519",
            &signature_hex("7c"),
        )
        .expect("valid");
        assert_eq!(
            verify_attestation(&subject, &mismatched_and_stale, &keys()).category(),
            "key_algorithm_mismatch"
        );
    }

    #[test]
    fn a_verdict_is_the_same_every_time() {
        let subject = manifest();
        let attestation = perfect_attestation(&subject);
        let trust_root = keys();
        let first = verify_attestation(&subject, &attestation, &trust_root);
        for _ in 0..8 {
            assert_eq!(
                verify_attestation(&subject, &attestation, &trust_root),
                first
            );
        }
    }
}

mod trusted_key_set {
    use super::*;

    #[test]
    fn a_trust_root_with_no_keys_is_refused() {
        assert_eq!(
            TrustedKeySet::new([]).expect_err("empty"),
            TrustRootError::NoTrustedKeys
        );
    }

    #[test]
    fn one_identifier_cannot_be_pinned_twice() {
        assert_eq!(
            TrustedKeySet::new([
                TrustedKey::new(TRUSTED_ED25519, "ed25519").expect("valid"),
                TrustedKey::new(TRUSTED_ED25519, "ecdsa-p256-sha256").expect("valid"),
            ])
            .expect_err("duplicate"),
            TrustRootError::DuplicateTrustedKeyId {
                key_id: KeyId::new(TRUSTED_ED25519).expect("valid")
            }
        );
    }

    #[test]
    fn the_key_bound_holds_and_is_not_off_by_one() {
        let at_bound: Vec<TrustedKey> = (0..MAX_TRUSTED_KEYS)
            .map(|index| TrustedKey::new(&format!("release-{index}"), "ed25519").expect("valid"))
            .collect();
        assert_eq!(
            TrustedKeySet::new(at_bound.clone())
                .expect("the bound itself is accepted")
                .keys()
                .len(),
            MAX_TRUSTED_KEYS
        );

        let mut over = at_bound;
        over.push(TrustedKey::new("release-overflow", "ed25519").expect("valid"));
        assert_eq!(
            TrustedKeySet::new(over).expect_err("over bound"),
            TrustRootError::TooManyTrustedKeys {
                max: MAX_TRUSTED_KEYS
            }
        );
    }

    #[test]
    fn an_algorithm_outside_the_closed_set_is_refused() {
        for algorithm in [
            "none",
            "rsa-pkcs1-sha256",
            "rsa-pss-sha256",
            "ed25519ph",
            "ecdsa-p256",
            "Ed25519",
            "ED25519",
            "",
            " ed25519",
        ] {
            assert_eq!(
                TrustedKey::new(TRUSTED_ED25519, algorithm).expect_err("refused"),
                TrustRootError::UnknownAlgorithm,
                "{algorithm} was accepted"
            );
            assert_eq!(SignatureAlgorithm::from_wire(algorithm), None);
        }
    }

    #[test]
    fn a_key_identifier_outside_its_grammar_is_refused() {
        assert_eq!(
            KeyId::new("").expect_err("empty"),
            TrustRootError::KeyIdBounds {
                error: ValueError::Empty
            }
        );
        let long = "a".repeat(MAX_KEY_ID_BYTES + 1);
        assert_eq!(
            KeyId::new(&long).expect_err("too long"),
            TrustRootError::KeyIdBounds {
                error: ValueError::TooLong {
                    max_bytes: MAX_KEY_ID_BYTES,
                    actual_bytes: MAX_KEY_ID_BYTES + 1,
                }
            }
        );
        assert!(KeyId::new(&"a".repeat(MAX_KEY_ID_BYTES)).is_ok());

        for value in [
            "Release-2026",
            "release 2026",
            "release/2026",
            "../release",
            "/etc/keys",
            "release\n2026",
            "2026-release",
            "-release",
            ".release",
            "release\u{7f}",
            "reléase",
        ] {
            assert_eq!(
                KeyId::new(value).expect_err("refused"),
                TrustRootError::KeyIdCharacter,
                "{value:?} was accepted"
            );
        }

        for value in ["release-2026-a", "a", "a.b_c-d0"] {
            assert_eq!(
                KeyId::new(value).expect("accepted").as_str(),
                value,
                "{value:?} was refused"
            );
        }
    }

    /// The order a reviewer lists keys in does not reach the value or its
    /// rendering.
    #[test]
    fn a_key_set_is_order_independent_and_renders_deterministically() {
        let forwards = keys();
        let backwards = TrustedKeySet::new([
            TrustedKey::new(TRUSTED_ECDSA, "ecdsa-p256-sha256").expect("valid"),
            TrustedKey::new(TRUSTED_ED25519, "ed25519").expect("valid"),
        ])
        .expect("valid set");
        assert_eq!(forwards, backwards);
        assert_eq!(
            forwards.to_canonical_document().to_canonical_bytes(),
            backwards.to_canonical_document().to_canonical_bytes()
        );
        assert_eq!(
            String::from_utf8(forwards.to_canonical_document().to_canonical_bytes())
                .expect("utf-8"),
            "[{\"algorithm\":\"ed25519\",\"key_id\":\"release-2026-a\"},\
             {\"algorithm\":\"ecdsa-p256-sha256\",\"key_id\":\"release-2026-b\"}]"
        );
        assert_eq!(
            forwards
                .key_ids()
                .into_iter()
                .map(KeyId::as_str)
                .collect::<Vec<&str>>(),
            vec![TRUSTED_ED25519, TRUSTED_ECDSA]
        );
    }

    #[test]
    fn the_allowlist_is_derived_from_the_pinned_keys() {
        assert_eq!(
            keys().algorithms(),
            vec![
                SignatureAlgorithm::Ed25519,
                SignatureAlgorithm::EcdsaP256Sha256
            ]
        );
        assert_eq!(
            ed25519_only().algorithms(),
            vec![SignatureAlgorithm::Ed25519]
        );
        assert!(!ed25519_only().allows_algorithm(SignatureAlgorithm::EcdsaP256Sha256));
        assert!(keys().allows_algorithm(SignatureAlgorithm::EcdsaP256Sha256));
    }
}

mod attestation_construction {
    use super::*;

    /// SHA-512 is a stronger digest and is still refused: this build cannot
    /// recompute one over a manifest, so it would have nothing to compare.
    #[test]
    fn a_digest_this_build_cannot_recompute_is_refused_at_construction() {
        let sha512 = ArtifactDigest::new("sha-512", &"ab".repeat(64)).expect("valid digest");
        assert_eq!(
            ReleaseAttestation::new(sha512, TRUSTED_ED25519, "ed25519", &signature_hex("7c"))
                .expect_err("refused"),
            TrustRootError::UnsupportedManifestDigestAlgorithm
        );
    }

    #[test]
    fn a_signature_of_the_wrong_width_is_refused() {
        let subject = manifest();
        for hex in ["", &"7c".repeat(63), &"7c".repeat(65), "7c"] {
            assert_eq!(
                ReleaseAttestation::new(
                    subject.canonical_digest(),
                    TRUSTED_ED25519,
                    "ed25519",
                    hex
                )
                .expect_err("refused"),
                TrustRootError::SignatureLength {
                    expected_len: 128,
                    actual_len: hex.len(),
                },
                "{} was accepted",
                hex.len()
            );
        }
    }

    #[test]
    fn a_signature_that_is_not_lowercase_hexadecimal_is_refused() {
        let subject = manifest();
        // Every probe is the right width, so the refusal is about the grammar
        // and not about the length.
        for hex in [
            "7C".repeat(64),
            format!("{}zz", "7c".repeat(63)),
            format!("{}7 ", "7c".repeat(63)),
            format!("{}g0", "7c".repeat(63)),
        ] {
            assert_eq!(hex.len(), 128);
            let refusal = ReleaseAttestation::new(
                subject.canonical_digest(),
                TRUSTED_ED25519,
                "ed25519",
                &hex,
            )
            .expect_err("refused");
            assert_eq!(
                refusal,
                TrustRootError::SignatureCharacter,
                "{hex:?} was accepted"
            );
        }
        assert_eq!(
            AttestationSignature::new(SignatureAlgorithm::Ed25519, &signature_hex("7c"))
                .expect("valid")
                .hex(),
            signature_hex("7c")
        );
    }

    #[test]
    fn an_attestation_round_trips_through_its_document() {
        let subject = manifest();
        let attestation = perfect_attestation(&subject);
        let bytes = attestation.to_canonical_bytes();
        assert_eq!(bytes, encode(document_fields(&subject)));
        assert_eq!(
            ReleaseAttestation::from_canonical_bytes(&bytes).expect("valid"),
            attestation
        );
    }

    #[test]
    fn the_known_field_table_is_exactly_what_a_document_carries() {
        let subject = manifest();
        let JsonValue::Object(entries) = perfect_attestation(&subject).to_canonical_document()
        else {
            panic!("an attestation document is an object")
        };
        let mut written: Vec<&str> = entries.iter().map(|(key, _)| key.as_str()).collect();
        written.sort_unstable();
        assert_eq!(written, KNOWN_ATTESTATION_FIELDS_SORTED);
    }

    const KNOWN_ATTESTATION_FIELDS_SORTED: [&str; 5] = [
        "algorithm",
        "key_id",
        "manifest_digest",
        "schema",
        "signature",
    ];

    #[test]
    fn a_document_naming_another_contract_is_refused_before_its_fields() {
        let subject = manifest();
        for schema in [
            "automonique.release-attestation/v2",
            "automonique.release-manifest/v1",
            "",
        ] {
            assert_eq!(
                parse_failure(&document_with("schema", json_text(schema), &subject)),
                TrustRootError::UnsupportedSchema,
                "{schema} was accepted"
            );
        }
        // The schema is read first: a document with a wrong schema *and* an
        // unknown field is refused on the schema.
        let mut fields = document_fields(&subject);
        fields.push(field("schema", json_text("other/v1")));
        fields.retain(|(name, value)| name != "schema" || value.as_str() == Some("other/v1"));
        fields.push(field("future_knob", json_text("x")));
        assert_eq!(
            parse_failure(&encode(fields)),
            TrustRootError::UnsupportedSchema
        );
    }

    #[test]
    fn a_field_this_build_does_not_interpret_is_refused_not_retained() {
        let subject = manifest();
        assert_eq!(
            parse_failure(&document_with("future_knob", json_text("x"), &subject)),
            TrustRootError::UnknownField
        );
    }

    #[test]
    fn every_required_field_is_required() {
        let subject = manifest();
        for (key, field_name) in [
            ("algorithm", "algorithm"),
            ("key_id", "key_id"),
            ("manifest_digest", "manifest_digest"),
            ("signature", "signature"),
        ] {
            assert_eq!(
                parse_failure(&document_without(key, &subject)),
                TrustRootError::MissingField { field: field_name },
                "{key} was optional"
            );
        }
        assert_eq!(
            parse_failure(&document_without("schema", &subject)),
            TrustRootError::MissingField { field: "schema" }
        );
        for key in ["algorithm", "hex"] {
            let mut digest_fields = vec![
                field("algorithm", json_text("sha-256")),
                field("hex", json_text(subject.canonical_digest().hex())),
            ];
            digest_fields.retain(|(name, _)| name != key);
            assert_eq!(
                parse_failure(&document_with(
                    "manifest_digest",
                    JsonValue::Object(digest_fields),
                    &subject
                ))
                .category(),
                "missing_field",
                "manifest_digest.{key} was optional"
            );
        }
    }

    #[test]
    fn a_field_of_the_wrong_json_type_is_refused() {
        let subject = manifest();
        for key in ["algorithm", "key_id", "schema", "signature"] {
            assert_eq!(
                parse_failure(&document_with(key, JsonValue::Integer(7), &subject)),
                TrustRootError::FieldType { field: key },
                "{key} accepted an integer"
            );
        }
        assert_eq!(
            parse_failure(&document_with(
                "manifest_digest",
                json_text("sha-256:cafe"),
                &subject
            )),
            TrustRootError::FieldType {
                field: "manifest_digest"
            }
        );
        assert_eq!(
            parse_failure(&JsonValue::Array(Vec::new()).to_canonical_bytes()),
            TrustRootError::FieldType {
                field: "attestation"
            }
        );
    }

    #[test]
    fn a_non_canonical_or_unreadable_document_is_refused() {
        assert_eq!(
            parse_failure(b"{ \"schema\": \"automonique.release-attestation/v1\" }"),
            TrustRootError::Document {
                error: CodecError::NonCanonicalJson
            }
        );
        assert_eq!(parse_failure(b"not json").category(), "malformed_document");
    }

    #[test]
    fn a_document_over_the_size_bound_is_refused_before_it_is_parsed() {
        let oversized = vec![b'{'; MAX_ATTESTATION_DOCUMENT_BYTES + 1];
        assert_eq!(
            parse_failure(&oversized),
            TrustRootError::DocumentTooLarge {
                max: MAX_ATTESTATION_DOCUMENT_BYTES
            }
        );
    }

    #[test]
    fn a_malformed_document_is_a_verdict_on_the_document_route() {
        let subject = manifest();
        let verdict = verify_attestation_document(
            &subject,
            &document_with("future_knob", json_text("x"), &subject),
            &keys(),
        );
        assert_eq!(
            verdict,
            AttestationVerdict::Malformed {
                error: TrustRootError::UnknownField
            }
        );
        assert_eq!(
            ReleaseTrustDecision::from_verdict(verdict),
            ReleaseTrustDecision::Refuse {
                reason: TrustRefusal::MalformedAttestation
            }
        );
    }
}

mod signing_payload {
    use super::*;

    /// The payload is what a backend would verify, so it must not contain the
    /// signature and must be stable.
    #[test]
    fn the_payload_excludes_the_signature_and_is_deterministic() {
        let subject = manifest();
        let first = perfect_attestation(&subject);
        let second = ReleaseAttestation::new(
            subject.canonical_digest(),
            TRUSTED_ED25519,
            "ed25519",
            &signature_hex("00"),
        )
        .expect("valid");
        assert_ne!(first.signature().hex(), second.signature().hex());
        assert_eq!(first.signing_payload(), second.signing_payload());
        assert_eq!(first.signing_payload(), first.signing_payload());

        let rendered = String::from_utf8(first.signing_payload()).expect("utf-8");
        assert!(!rendered.contains(first.signature().hex()));
        assert!(!rendered.contains("signature"));
    }

    /// Domain separation: the contract name is inside the signed bytes, so a
    /// signature made for another document shape does not transfer here.
    #[test]
    fn the_payload_names_the_contract_it_belongs_to() {
        let subject = manifest();
        let rendered =
            String::from_utf8(perfect_attestation(&subject).signing_payload()).expect("utf-8");
        assert!(rendered.contains(RELEASE_ATTESTATION_SCHEMA_V1));
        assert_eq!(
            rendered,
            format!(
                "{{\"algorithm\":\"ed25519\",\"key_id\":\"release-2026-a\",\
                 \"manifest_digest\":{{\"algorithm\":\"sha-256\",\"hex\":\"{}\"}},\
                 \"schema\":\"automonique.release-attestation/v1\"}}",
                subject.canonical_digest().hex()
            )
        );
    }

    /// Everything the signature is supposed to bind actually changes it.
    #[test]
    fn every_bound_field_changes_the_payload() {
        let subject = manifest();
        let base = perfect_attestation(&subject);
        let other_key = ReleaseAttestation::new(
            subject.canonical_digest(),
            TRUSTED_ECDSA,
            "ed25519",
            &signature_hex("7c"),
        )
        .expect("valid");
        let other_algorithm = ReleaseAttestation::new(
            subject.canonical_digest(),
            TRUSTED_ED25519,
            "ecdsa-p256-sha256",
            &signature_hex("7c"),
        )
        .expect("valid");
        let other_manifest = ReleaseAttestation::new(
            manifest_named("0.2.0").canonical_digest(),
            TRUSTED_ED25519,
            "ed25519",
            &signature_hex("7c"),
        )
        .expect("valid");
        let payloads = [
            base.signing_payload(),
            other_key.signing_payload(),
            other_algorithm.signing_payload(),
            other_manifest.signing_payload(),
        ];
        for (index, left) in payloads.iter().enumerate() {
            for right in &payloads[index + 1..] {
                assert_ne!(left, right);
            }
        }
    }
}

mod refusal_reporting {
    use super::*;

    #[test]
    fn every_refusal_has_a_stable_category_and_a_message() {
        let subject = manifest();
        let errors = [
            TrustRootError::Document {
                error: CodecError::NonCanonicalJson,
            },
            TrustRootError::DocumentTooLarge { max: 1 },
            TrustRootError::MissingField { field: "key_id" },
            TrustRootError::FieldType { field: "key_id" },
            TrustRootError::UnknownField,
            TrustRootError::UnsupportedSchema,
            TrustRootError::KeyIdBounds {
                error: ValueError::Empty,
            },
            TrustRootError::KeyIdCharacter,
            TrustRootError::UnknownAlgorithm,
            TrustRootError::SignatureLength {
                expected_len: 128,
                actual_len: 2,
            },
            TrustRootError::SignatureCharacter,
            TrustRootError::ManifestDigest {
                error: ArtifactDigest::new("md5", "00").expect_err("refused"),
            },
            TrustRootError::UnsupportedManifestDigestAlgorithm,
            TrustRootError::NoTrustedKeys,
            TrustRootError::DuplicateTrustedKeyId {
                key_id: KeyId::new(TRUSTED_ED25519).expect("valid"),
            },
            TrustRootError::TooManyTrustedKeys { max: 1 },
        ];
        let mut categories: Vec<&str> = errors.iter().map(TrustRootError::category).collect();
        for error in &errors {
            assert!(!error.to_string().is_empty());
        }
        categories.sort_unstable();
        let count = categories.len();
        categories.dedup();
        assert_eq!(categories.len(), count, "two refusals share a category");

        // A refusal never carries signature bytes.
        let attestation = perfect_attestation(&subject);
        for error in &errors {
            assert!(!error.to_string().contains(attestation.signature().hex()));
        }
    }

    #[test]
    fn every_verdict_and_refusal_has_a_stable_spelling() {
        assert_eq!(
            UnverifiableReason::NoCryptoBackend.as_str(),
            "no_crypto_backend"
        );
        for (refusal, spelling) in [
            (TrustRefusal::NoTrustRoot, "no_trust_root"),
            (TrustRefusal::UnknownKey, "unknown_key"),
            (TrustRefusal::DisallowedAlgorithm, "disallowed_algorithm"),
            (TrustRefusal::KeyAlgorithmMismatch, "key_algorithm_mismatch"),
            (
                TrustRefusal::ManifestDigestMismatch,
                "manifest_digest_mismatch",
            ),
            (TrustRefusal::MalformedAttestation, "malformed_attestation"),
        ] {
            assert_eq!(refusal.as_str(), spelling);
        }
        for (algorithm, spelling) in [
            (SignatureAlgorithm::Ed25519, "ed25519"),
            (SignatureAlgorithm::EcdsaP256Sha256, "ecdsa-p256-sha256"),
        ] {
            assert_eq!(algorithm.as_str(), spelling);
            assert_eq!(SignatureAlgorithm::from_wire(spelling), Some(algorithm));
            assert_eq!(algorithm.signature_hex_len(), 128);
        }
    }
}
