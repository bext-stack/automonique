// SPDX-License-Identifier: Elastic-2.0

//! R1-08 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `docs/product-plan/requirements/agent-integrations.md`.

use automonique_protocol::provider::{
    BinaryProvenance, Capability, CapabilityGroup, CapabilityState, MAX_CAPABILITIES,
    ModeDeclaration, ProviderError, ProviderSessionId, SessionBinding, UnknownCapability,
};
use automonique_protocol::sandbox::DigestError;

const SHA_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SHA_C: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const SHA_D: &str = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn capability(group: CapabilityGroup, name: &str) -> Capability {
    Capability::new(group, name).expect("valid capability")
}

fn provenance() -> BinaryProvenance {
    BinaryProvenance::new("1.2.3", SHA_A, Some(SHA_B)).expect("valid provenance")
}

fn session(value: &str) -> ProviderSessionId {
    ProviderSessionId::new(value).expect("valid session id")
}

fn binding() -> SessionBinding {
    SessionBinding::new("tenant-a", "codex", "account-1", "default", session("s-1"))
        .expect("valid binding")
}

/// An approval-aware, resumable mode with one absent optional capability.
fn declaration() -> ModeDeclaration {
    ModeDeclaration::new(
        "app-server",
        vec![
            capability(CapabilityGroup::Approvals, "approval_response"),
            capability(CapabilityGroup::Sessions, "resume"),
        ],
        vec![
            capability(CapabilityGroup::Approvals, "approval_response"),
            capability(CapabilityGroup::Sessions, "resume"),
            capability(CapabilityGroup::Turns, "steer"),
        ],
        vec![capability(CapabilityGroup::Telemetry, "cost")],
        vec![UnknownCapability::new("future_capability").expect("valid")],
        provenance(),
    )
    .expect("consistent declaration")
}

mod capability_structure {
    use super::*;

    #[test]
    fn an_unknown_capability_round_trips_and_is_never_present() {
        let declaration = declaration();
        assert_eq!(declaration.unknown().len(), 1);
        assert_eq!(declaration.unknown()[0].name(), "future_capability");

        // It is not reachable as a defined capability, so it cannot be counted
        // as present by any lookup.
        let guessed = capability(CapabilityGroup::Sessions, "future_capability");
        assert_eq!(declaration.state(&guessed), CapabilityState::Unprobed);
    }

    #[test]
    fn unprobed_and_absent_are_distinguishable() {
        let declaration = declaration();
        assert_eq!(
            declaration.state(&capability(CapabilityGroup::Telemetry, "cost")),
            CapabilityState::Absent
        );
        assert_eq!(
            declaration.state(&capability(CapabilityGroup::Telemetry, "never_asked")),
            CapabilityState::Unprobed
        );
        assert_eq!(
            declaration.state(&capability(CapabilityGroup::Turns, "steer")),
            CapabilityState::Present
        );
    }

    #[test]
    fn capability_names_are_bounded() {
        assert!(Capability::new(CapabilityGroup::Tools, "").is_err());
        assert!(Capability::new(CapabilityGroup::Tools, "a\u{7}b").is_err());
        assert!(Capability::new(CapabilityGroup::Tools, &"x".repeat(200)).is_err());
    }
}

mod set_discipline {
    use super::*;

    #[test]
    fn a_mode_that_requires_what_it_lacks_fails_at_construction() {
        let contradictory = ModeDeclaration::new(
            "broken",
            vec![capability(CapabilityGroup::Approvals, "approval_response")],
            vec![],
            vec![capability(CapabilityGroup::Approvals, "approval_response")],
            vec![],
            provenance(),
        );
        assert_eq!(
            contradictory.expect_err("required and degraded overlap"),
            ProviderError::RequiredCapabilityIsDegraded {
                capability: "approval_response".to_owned(),
            }
        );
    }

    #[test]
    fn the_capability_ceiling_is_enforced() {
        let many: Vec<Capability> = (0..=MAX_CAPABILITIES)
            .map(|index| capability(CapabilityGroup::Tools, &format!("tool_{index}")))
            .collect();
        assert_eq!(
            ModeDeclaration::new("wide", vec![], many, vec![], vec![], provenance())
                .expect_err("above the ceiling")
                .category(),
            "too_many_capabilities"
        );
    }
}

mod fail_closed_selection {
    use super::*;

    #[test]
    fn a_satisfied_mode_is_selected_and_reports_its_degradation() {
        let selection = declaration().select().expect("requirements are met");
        assert_eq!(selection.mode(), "app-server");
        assert_eq!(selection.degraded(), ["cost"]);
    }

    #[test]
    fn a_missing_requirement_refuses_naming_every_gap() {
        let fallback = ModeDeclaration::new(
            "run-oneshot",
            vec![
                capability(CapabilityGroup::Approvals, "approval_response"),
                capability(CapabilityGroup::Sessions, "resume"),
                capability(CapabilityGroup::Turns, "steer"),
            ],
            vec![capability(CapabilityGroup::Sessions, "resume")],
            vec![],
            vec![],
            provenance(),
        )
        .expect("valid declaration");

        assert_eq!(
            fallback.select().expect_err("requirements are unmet"),
            ProviderError::RequiredCapabilitiesMissing {
                missing: vec!["approval_response".to_owned(), "steer".to_owned()],
            }
        );
    }

    /// The two substitutions the requirement names explicitly. Each is
    /// expressible only as a refusal: there is no API that returns a selection
    /// with an approval or resume capability swapped for something weaker.
    #[test]
    fn the_forbidden_substitutions_are_only_expressible_as_refusals() {
        for absent in ["approval_response", "resume"] {
            let native: Vec<Capability> = ["approval_response", "resume"]
                .into_iter()
                .filter(|name| *name != absent)
                .map(|name| capability(CapabilityGroup::Sessions, name))
                .collect();
            let declaration = ModeDeclaration::new(
                "degraded-mode",
                vec![
                    capability(CapabilityGroup::Sessions, "approval_response"),
                    capability(CapabilityGroup::Sessions, "resume"),
                ],
                native,
                vec![],
                vec![],
                provenance(),
            )
            .expect("valid declaration");

            let error = declaration.select().expect_err("must refuse");
            assert_eq!(
                error,
                ProviderError::RequiredCapabilitiesMissing {
                    missing: vec![absent.to_owned()],
                }
            );
        }
    }

    #[test]
    fn an_unprobed_requirement_refuses_rather_than_assuming_presence() {
        let declaration = ModeDeclaration::new(
            "unprobed",
            vec![capability(CapabilityGroup::Events, "replay")],
            vec![],
            vec![],
            vec![],
            provenance(),
        )
        .expect("valid declaration");
        assert_eq!(
            declaration.select().expect_err("unprobed is not present"),
            ProviderError::RequiredCapabilitiesMissing {
                missing: vec!["replay".to_owned()],
            }
        );
    }
}

mod identity_distinctness {
    use super::*;
    use automonique_protocol::provider::{
        ProviderInstanceId, ProviderItemId, ProviderRequestId, ProviderTurnId,
    };

    #[test]
    fn the_five_identities_are_separate_values() {
        let instance = ProviderInstanceId::new("i-1").expect("valid");
        let session = ProviderSessionId::new("s-1").expect("valid");
        let turn = ProviderTurnId::new("t-1").expect("valid");
        let item = ProviderItemId::new("m-1").expect("valid");
        let request = ProviderRequestId::new("r-1").expect("valid");

        // Same spelling in different domains stays distinguishable by type.
        assert_eq!(instance.as_str(), "i-1");
        assert_eq!(session.as_str(), "s-1");
        assert_eq!(turn.as_str(), "t-1");
        assert_eq!(item.as_str(), "m-1");
        assert_eq!(request.as_str(), "r-1");
    }

    // Non-interconvertibility is proved by the `compile_fail` doc tests on the
    // `provider` module, which run against the library target. A doc comment
    // here would never execute, so the proof lives where it is checked.
    #[test]
    fn the_same_spelling_in_two_domains_stays_separate() {
        assert!(ProviderTurnId::new("t-1").is_ok());
        assert!(ProviderSessionId::new("t-1").is_ok());
    }
}

mod binding_safety {
    use super::*;

    #[test]
    fn an_identical_binding_is_confirmed() {
        let binding = binding();
        assert_eq!(binding.tenant(), "tenant-a");
        assert_eq!(binding.backend(), "codex");
        assert_eq!(binding.provider_account(), "account-1");
        assert_eq!(binding.provider_namespace(), "default");
        assert_eq!(binding.session().as_str(), "s-1");
        binding.confirm_same(&binding).expect("same binding");
    }

    #[test]
    fn a_binding_differing_in_any_component_names_it() {
        let cases = [
            (
                "tenant",
                SessionBinding::new("tenant-b", "codex", "account-1", "default", session("s-1")),
            ),
            (
                "backend",
                SessionBinding::new("tenant-a", "claude", "account-1", "default", session("s-1")),
            ),
            (
                "provider_account",
                SessionBinding::new("tenant-a", "codex", "account-2", "default", session("s-1")),
            ),
            (
                "provider_namespace",
                SessionBinding::new("tenant-a", "codex", "account-1", "other", session("s-1")),
            ),
            (
                "session",
                SessionBinding::new("tenant-a", "codex", "account-1", "default", session("s-2")),
            ),
        ];
        for (component, other) in cases {
            let other = other.expect("valid binding");
            assert_eq!(
                binding().confirm_same(&other).expect_err("differs"),
                ProviderError::BindingMismatch { component },
                "expected a mismatch in {component}"
            );
        }
    }

    #[test]
    fn a_binding_cannot_be_built_from_an_empty_component() {
        assert!(
            SessionBinding::new("", "codex", "account-1", "default", session("s-1")).is_err(),
            "an empty tenant is not a tenant"
        );
    }
}

mod provenance_completeness {
    use super::*;

    #[test]
    fn a_capability_record_carries_the_binary_it_was_observed_against() {
        let declaration = declaration();
        assert_eq!(declaration.provenance().version(), "1.2.3");
        assert_eq!(declaration.provenance().digest(), SHA_A);
        assert_eq!(declaration.provenance().schema_digest(), Some(SHA_B));
    }

    #[test]
    fn a_stale_record_is_detectable_by_digest_alone() {
        let recorded = provenance();
        assert!(recorded.matches(&provenance()));

        let upgraded = BinaryProvenance::new("1.2.4", SHA_C, Some(SHA_B)).expect("valid");
        assert!(!recorded.matches(&upgraded));

        // A schema change alone is also a difference.
        let reschemad = BinaryProvenance::new("1.2.3", SHA_A, Some(SHA_D)).expect("valid");
        assert!(!recorded.matches(&reschemad));
    }

    #[test]
    fn provenance_requires_a_version_and_a_digest() {
        assert!(BinaryProvenance::new("", SHA_A, None).is_err());
        assert!(BinaryProvenance::new("1.0.0", "", None).is_err());
        assert!(BinaryProvenance::new("1.0.0", SHA_A, None).is_ok());
    }

    #[test]
    fn binary_and_schema_digests_are_canonical_lowercase_sha256() {
        let malformed = [
            (
                "sha256:aaaa",
                ProviderError::Digest {
                    field: "binary_digest",
                    error: DigestError::Length {
                        expected: 64,
                        actual: 4,
                    },
                },
            ),
            (
                "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ProviderError::Digest {
                    field: "binary_digest",
                    error: DigestError::NotLowercaseHex,
                },
            ),
            (
                "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
                ProviderError::Digest {
                    field: "binary_digest",
                    error: DigestError::NotLowercaseHex,
                },
            ),
            (
                "md5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ProviderError::Digest {
                    field: "binary_digest",
                    error: DigestError::UnknownAlgorithm,
                },
            ),
            (
                "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ProviderError::DigestAlgorithm {
                    field: "binary_digest",
                },
            ),
        ];
        for (candidate, expected) in malformed {
            assert_eq!(
                BinaryProvenance::new("1.0.0", candidate, None)
                    .expect_err("noncanonical binary digest"),
                expected,
                "candidate {candidate}"
            );
        }

        assert_eq!(
            BinaryProvenance::new("1.0.0", SHA_A, Some("sha256:bbbb"))
                .expect_err("noncanonical schema digest"),
            ProviderError::Digest {
                field: "schema_digest",
                error: DigestError::Length {
                    expected: 64,
                    actual: 4,
                },
            }
        );
    }
}
