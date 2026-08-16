// SPDX-License-Identifier: Elastic-2.0

//! R1-17 verification contract, and the version-compatibility matrix.
//!
//! Each module up to `identifier_classes` corresponds to one row of the check
//! table in `plan/contracts/R1-17.md`. The modules after it cover the
//! compatibility ranges: the range invariants, the verdict bands, the
//! cross-checks against the constants this crate can see, and the manifest a
//! crate this one cannot depend on would pin.

use std::path::PathBuf;

use automonique_protocol::compat::{
    CanonicalName, CompatError, IdentifierClass, LegacyAlias, LegacyName, MigrationContract,
    NameEntry, NameRegistry, SpellingResolution, automonique_registry, emit_registry_module,
};

/// The checked-in module the registry generates.
fn generated_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/compat/generated.rs")
}

fn contract() -> MigrationContract {
    MigrationContract::new("plan/contracts/R1-17.md").expect("valid contract")
}

fn alias(spelling: &str) -> LegacyAlias {
    LegacyAlias::new(spelling, contract(), "0.9.0").expect("valid alias")
}

/// One entry with one authorized alias, owned by the settings service.
fn entry() -> NameEntry {
    NameEntry::new(
        "AUTOMONIQUE_DB",
        IdentifierClass::EnvironmentVariable,
        "settings-service",
        "durable:db-path",
    )
    .expect("valid entry")
    .with_alias(alias("LEGACY_DB"))
}

fn registry() -> NameRegistry {
    let mut registry = NameRegistry::new();
    registry.insert(entry()).expect("valid entry");
    registry
}

mod single_source {
    use super::*;

    #[test]
    fn both_spellings_come_from_one_entry() {
        let registry = registry();
        let spellings: Vec<String> = registry
            .owner_table()
            .into_iter()
            .map(|row| row.spelling)
            .collect();
        assert_eq!(spellings, vec!["AUTOMONIQUE_DB", "LEGACY_DB"]);
    }

    #[test]
    fn an_alias_not_in_the_registry_has_no_authorizing_entry() {
        let registry = registry();
        let generated = registry.generated_aliases();
        assert_eq!(generated, vec!["LEGACY_DB".to_owned()]);

        // A build declaring an alias the registry never generated is drift; the
        // comparison is what a CI step performs.
        let declared_by_hand = ["LEGACY_DB".to_owned(), "LEGACY_DB_OLD".to_owned()];
        let undeclared: Vec<&String> = declared_by_hand
            .iter()
            .filter(|spelling| !generated.contains(spelling))
            .collect();
        assert_eq!(
            undeclared,
            vec![&"LEGACY_DB_OLD".to_owned()],
            "a hand-written alias must be detectable as absent from the registry"
        );
    }

    #[test]
    fn a_spelling_cannot_be_claimed_twice() {
        let mut registry = registry();
        let colliding = NameEntry::new(
            "OTHER_NAME",
            IdentifierClass::EnvironmentVariable,
            "other-service",
            "durable:other",
        )
        .expect("valid")
        .with_alias(alias("LEGACY_DB"));
        assert_eq!(
            registry.insert(colliding).expect_err("collides"),
            CompatError::DuplicateSpelling {
                spelling: "LEGACY_DB".to_owned(),
            }
        );
    }
}

mod generated_from_the_registry {
    use super::*;

    /// The registry the crate ships, as opposed to the one-entry fixture above.
    #[test]
    fn the_declared_registry_is_accepted_by_its_own_rules() {
        let registry = automonique_registry();
        assert!(
            registry.entries().len() >= 4,
            "the registry is the seed for every canonical name; it cannot be empty"
        );
        for entry in registry.entries() {
            assert!(
                !entry.aliases().is_empty(),
                "{} declares no alias, so it has nothing to generate a compatibility \
                 surface from",
                entry.canonical()
            );
            for alias in entry.aliases() {
                assert!(!alias.authorized_by().as_str().is_empty());
                assert!(!alias.retire_after().is_empty());
            }
        }
        // One owner and one durable identity per canonical name, over the real
        // registry rather than the fixture. Every spelling is a row: the table
        // is the proof, so a spelling missing from it would be a spot check.
        let spellings: usize = registry
            .entries()
            .iter()
            .map(|entry| 1 + entry.aliases().len())
            .sum();
        let table = registry.owner_table();
        assert_eq!(table.len(), spellings);
        println!(
            "one-owner table: {} entries, {spellings} spellings, {} aliases",
            registry.entries().len(),
            registry.generated_aliases().len()
        );
        for row in table {
            let resolved = match registry.resolve(&row.spelling) {
                SpellingResolution::Canonical { entry } => entry,
                SpellingResolution::Alias { entry, .. } => entry,
                SpellingResolution::Unknown => panic!("{} resolves to nothing", row.spelling),
            };
            assert_eq!(row.owner, resolved.owner());
            assert_eq!(row.durable_identity, resolved.durable_identity());
        }
    }

    /// The drift check. `emit_registry_module` is the only writer of
    /// `src/compat/generated.rs`, and this fails while the checked-in copy and
    /// the registry disagree in either direction: a registry entry that was
    /// never generated, and a spelling written into the generated file by hand.
    #[test]
    fn the_checked_in_module_is_what_the_registry_generates() {
        let expected = emit_registry_module(&automonique_registry());
        let path = generated_path();
        if std::env::var_os("AUTOMONIQUE_REGENERATE_COMPAT").is_some() {
            // Write atomically: a plain write leaves the file momentarily
            // zero-length, and `tests/codegen.rs` records that racing a reader
            // in the same parallel run turns the workspace red for reasons
            // unrelated to the code under test.
            let staging = path.with_extension("rs.staging");
            std::fs::write(&staging, &expected).expect("stage the generated module");
            std::fs::rename(&staging, &path).expect("publish the generated module");
        }
        let actual = std::fs::read_to_string(&path).expect("the generated module is checked in");
        // Name the first difference rather than printing two whole modules: the
        // failure a reader needs is which line drifted.
        let difference = actual
            .lines()
            .zip(expected.lines())
            .enumerate()
            .find(|(_, (checked_in, generated))| checked_in != generated)
            .map(|(index, (checked_in, generated))| {
                format!(
                    "line {}: checked in {checked_in:?}, registry generates {generated:?}",
                    index + 1
                )
            });
        assert_eq!(
            difference, None,
            "src/compat/generated.rs no longer matches the registry — regenerate with \
             AUTOMONIQUE_REGENERATE_COMPAT=1 cargo test -p automonique-protocol --test compat"
        );
        assert_eq!(
            actual.lines().count(),
            expected.lines().count(),
            "src/compat/generated.rs has a different number of lines from what the \
             registry generates"
        );
        assert_eq!(actual, expected);
    }

    #[test]
    fn generation_is_deterministic() {
        let first = emit_registry_module(&automonique_registry());
        for _ in 0..8 {
            assert_eq!(emit_registry_module(&automonique_registry()), first);
        }
    }

    /// Every generated constant is a registry spelling, and every registry
    /// spelling has a constant. A set difference in either direction is drift.
    #[test]
    fn the_generated_constants_and_the_registry_name_the_same_spellings() {
        let registry = automonique_registry();

        let generated_canonical: Vec<&str> = CanonicalName::ALL
            .iter()
            .map(|name| name.spelling())
            .collect();
        let declared_canonical: Vec<&str> = registry
            .entries()
            .iter()
            .map(NameEntry::canonical)
            .collect();
        assert_eq!(generated_canonical, declared_canonical);

        let generated_aliases: Vec<String> = LegacyName::ALL
            .iter()
            .map(|name| name.spelling().to_owned())
            .collect();
        let mut sorted = generated_aliases.clone();
        sorted.sort();
        assert_eq!(sorted, registry.generated_aliases());

        // An alias constant forwards to the same entry the registry resolves it
        // to, so the generated table cannot claim a different owner.
        for alias in LegacyName::ALL {
            let SpellingResolution::Alias { entry, observation } =
                registry.resolve(alias.spelling())
            else {
                panic!("{} is not an alias in the registry", alias.spelling());
            };
            assert_eq!(alias.canonical().spelling(), entry.canonical());
            assert_eq!(alias.canonical().owner(), entry.owner());
            assert_eq!(
                alias.canonical().durable_identity(),
                entry.durable_identity()
            );
            assert_eq!(alias.retire_after(), observation.retire_after());
        }
    }

    /// The generated names are distinct, so no two spellings collapse onto one
    /// constant and quietly lose an entry.
    #[test]
    fn the_generated_constants_are_distinct() {
        let generated = emit_registry_module(&automonique_registry());
        let mut names: Vec<&str> = generated
            .lines()
            .filter_map(|line| line.trim().strip_prefix("pub const "))
            .filter_map(|line| line.split_once(": Self = "))
            .map(|(name, _)| name)
            .collect();
        let total = names.len();
        assert_eq!(
            total,
            CanonicalName::ALL.len() + LegacyName::ALL.len(),
            "every constant is one registry spelling"
        );
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "two spellings produced one constant");
    }

    /// A hand-written alias is not merely undeclared, it is unnameable: the
    /// paired doctests on `automonique_registry` compile the declared constant
    /// and fail to compile an undeclared one. This is the runtime half — the
    /// registry is the only thing that answers what a spelling means.
    #[test]
    fn an_undeclared_spelling_resolves_to_nothing() {
        let registry = automonique_registry();
        assert_eq!(
            registry.resolve("LEGACY_RUNNER_OLD"),
            SpellingResolution::Unknown
        );
        assert!(
            !registry
                .generated_aliases()
                .contains(&"LEGACY_RUNNER_OLD".to_owned())
        );
    }
}

mod forwarding_only {
    use super::*;

    #[test]
    fn an_alias_resolves_to_the_canonical_entry_and_nothing_else() {
        let registry = registry();
        let canonical = match registry.resolve("AUTOMONIQUE_DB") {
            SpellingResolution::Canonical { entry } => entry,
            _ => panic!("the canonical spelling did not resolve as canonical"),
        };
        let (forwarded, observation) = match registry.resolve("LEGACY_DB") {
            SpellingResolution::Alias { entry, observation } => (entry, observation),
            _ => panic!("the alias did not resolve as an alias"),
        };

        // Same entry, so the alias carries no behaviour of its own.
        assert_eq!(canonical.canonical(), forwarded.canonical());
        assert_eq!(canonical.owner(), forwarded.owner());
        assert_eq!(canonical.durable_identity(), forwarded.durable_identity());
        assert_eq!(observation.canonical(), "AUTOMONIQUE_DB");
    }

    #[test]
    fn an_unknown_spelling_resolves_to_nothing() {
        assert_eq!(
            registry().resolve("NOT_A_NAME"),
            SpellingResolution::Unknown
        );
    }
}

mod conflict_rejection {
    use super::*;

    #[test]
    fn setting_both_spellings_fails_naming_both_values() {
        let error = registry()
            .resolve_configuration(&[("AUTOMONIQUE_DB", "/new"), ("LEGACY_DB", "/old")])
            .expect_err("both spellings set");
        assert_eq!(
            error,
            CompatError::CanonicalAndAliasBothSet {
                canonical: "AUTOMONIQUE_DB".to_owned(),
                canonical_value: "/new".to_owned(),
                alias: "LEGACY_DB".to_owned(),
                alias_value: "/old".to_owned(),
            }
        );
        // The message names both, so an operator can see what to unset.
        let rendered = error.to_string();
        assert!(rendered.contains("/new"));
        assert!(rendered.contains("/old"));
        assert!(rendered.contains("precedence"));
    }

    #[test]
    fn the_conflict_is_symmetric_in_declaration_order() {
        let reversed = registry()
            .resolve_configuration(&[("LEGACY_DB", "/old"), ("AUTOMONIQUE_DB", "/new")])
            .expect_err("both spellings set");
        assert_eq!(reversed.category(), "canonical_and_alias_both_set");
        let rendered = reversed.to_string();
        assert!(rendered.contains("/new"));
        assert!(rendered.contains("/old"));
    }

    #[test]
    fn identical_values_under_both_spellings_are_still_a_conflict() {
        // Agreeing by accident is not the same as being configured once, and a
        // rule that tolerates it teaches operators to set both.
        assert!(
            registry()
                .resolve_configuration(&[("AUTOMONIQUE_DB", "/same"), ("LEGACY_DB", "/same")])
                .is_err()
        );
    }
}

mod deprecation_observation {
    use super::*;

    #[test]
    fn an_alias_alone_succeeds_and_yields_an_enumerable_observation() {
        let resolved = registry()
            .resolve_configuration(&[("LEGACY_DB", "/old")])
            .expect("an alias alone is valid configuration");
        assert_eq!(resolved.len(), 1);
        let (canonical, value, observation) = &resolved[0];
        assert_eq!(canonical, "AUTOMONIQUE_DB");
        assert_eq!(value, "/old");

        let observed = observation.as_ref().expect("an observation was recorded");
        assert_eq!(observed.alias(), "LEGACY_DB");
        assert_eq!(observed.canonical(), "AUTOMONIQUE_DB");
        assert_eq!(observed.retire_after(), "0.9.0");
    }

    #[test]
    fn the_canonical_spelling_records_no_deprecation() {
        let resolved = registry()
            .resolve_configuration(&[("AUTOMONIQUE_DB", "/new")])
            .expect("canonical configuration");
        assert!(resolved[0].2.is_none());
    }
}

mod one_owner {
    use super::*;

    #[test]
    fn the_generated_table_shows_one_owner_for_every_spelling() {
        let table = registry().owner_table();
        assert_eq!(table.len(), 2);

        let owners: Vec<&str> = table.iter().map(|row| row.owner.as_str()).collect();
        assert!(
            owners.windows(2).all(|pair| pair[0] == pair[1]),
            "spellings of one entry disagreed on their owner: {owners:?}"
        );
        let identities: Vec<&str> = table
            .iter()
            .map(|row| row.durable_identity.as_str())
            .collect();
        assert!(identities.windows(2).all(|pair| pair[0] == pair[1]));

        // Exactly one row is the canonical spelling.
        assert_eq!(table.iter().filter(|row| row.canonical).count(), 1);
    }

    #[test]
    fn a_two_owner_entry_is_refused() {
        let mut registry = registry();
        let second_owner = NameEntry::new(
            "AUTOMONIQUE_DB",
            IdentifierClass::EnvironmentVariable,
            "another-service",
            "durable:db-path",
        )
        .expect("valid");
        assert_eq!(
            registry.insert(second_owner).expect_err("two owners"),
            CompatError::TwoOwners {
                canonical: "AUTOMONIQUE_DB".to_owned(),
                first: "settings-service".to_owned(),
                second: "another-service".to_owned(),
            }
        );
    }
}

mod authorized_aliases {
    use super::*;

    #[test]
    fn every_alias_declares_a_contract_and_a_window() {
        let declared = entry();
        let alias = &declared.aliases()[0];
        assert_eq!(alias.authorized_by().as_str(), "plan/contracts/R1-17.md");
        assert_eq!(alias.retire_after(), "0.9.0");
    }

    #[test]
    fn an_alias_cannot_be_built_without_a_contract_identifier() {
        assert!(
            MigrationContract::new("").is_err(),
            "an unauthorized alias has no contract to name"
        );
        assert!(LegacyAlias::new("", contract(), "0.9.0").is_err());
        assert!(LegacyAlias::new("LEGACY_DB", contract(), "").is_err());
    }
}

mod durable_identifiers_unchanged {
    use super::*;

    #[test]
    fn a_canonical_rename_does_not_touch_the_durable_identity() {
        let original = entry();
        let renamed = original
            .renamed_to("AUTOMONIQUE_DATABASE")
            .expect("valid rename");

        assert_eq!(renamed.canonical(), "AUTOMONIQUE_DATABASE");
        assert_eq!(
            renamed.durable_identity(),
            original.durable_identity(),
            "a durable identity is never rewritten for branding"
        );
        assert_eq!(renamed.owner(), original.owner());
        // Aliases survive the rename and still forward.
        assert_eq!(renamed.aliases().len(), 1);
        assert_eq!(renamed.aliases()[0].spelling(), "LEGACY_DB");
    }

    #[test]
    fn renaming_takes_no_durable_identity_argument() {
        // `renamed_to` accepts only the new spelling, so there is no parameter
        // through which a durable identity could be changed at the same time.
        let renamed = entry().renamed_to("X").expect("valid");
        assert_eq!(renamed.durable_identity(), "durable:db-path");
    }
}

mod identifier_classes {
    use super::*;

    #[test]
    fn every_class_is_representable_with_a_distinct_spelling() {
        assert_eq!(IdentifierClass::ALL.len(), 8);
        let mut spellings: Vec<&str> = IdentifierClass::ALL
            .iter()
            .map(|class| class.as_str())
            .collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);

        for class in IdentifierClass::ALL {
            let declared = NameEntry::new("NAME", class, "owner", "durable:x").expect("valid");
            assert_eq!(declared.class(), class);
        }
    }
}

/// The version half of the module: ranges, verdicts and the shipped matrix.
mod versions {
    use automonique_protocol::codec::MajorVersion;
    use automonique_protocol::compat::{
        COMPATIBILITY_MATRIX_SCHEMA_V1, CompatError, CompatVerdict, CompatibilityMatrix,
        CompatibilityRange, Component, ComponentVersion, RefusalReason, VersionAuthority,
        matrix_manifest, shipped_matrix,
    };

    fn version(value: u32) -> MajorVersion {
        MajorVersion::new(value).expect("a nonzero version")
    }

    /// The components whose live constant lives in a crate this one cannot
    /// depend on. Restated here rather than derived, so adding a foreign
    /// component without acknowledging the gap fails this file.
    const KNOWN_FOREIGN: [Component; 7] = [
        Component::StoreSchema,
        Component::CancelLedgerSchema,
        Component::GenerationAuditSchema,
        Component::ProviderJournalSchema,
        Component::RunSubmissionsSchema,
        Component::SlackIngressSchema,
        Component::RunSpecDocument,
    ];

    mod range_invariants {
        use super::*;

        #[test]
        fn a_minimum_above_the_current_version_is_refused() {
            assert_eq!(
                CompatibilityRange::new(Component::StoreSchema, 7, 6).expect_err("inverted"),
                CompatError::InvertedRange {
                    component: Component::StoreSchema,
                    min_supported: 7,
                    current: 6,
                }
            );
            // The message names both bounds, because an operator has to see
            // which of the two is wrong.
            let rendered = CompatibilityRange::new(Component::StoreSchema, 7, 6)
                .expect_err("inverted")
                .to_string();
            assert!(rendered.contains('7'), "{rendered}");
            assert!(rendered.contains('6'), "{rendered}");
        }

        #[test]
        fn a_zero_bound_is_refused_naming_which_bound() {
            assert_eq!(
                CompatibilityRange::new(Component::AdminProtocol, 0, 1).expect_err("zero min"),
                CompatError::ZeroVersion {
                    component: Component::AdminProtocol,
                    bound: "min_supported",
                }
            );
            assert_eq!(
                CompatibilityRange::new(Component::AdminProtocol, 1, 0).expect_err("zero current"),
                CompatError::ZeroVersion {
                    component: Component::AdminProtocol,
                    bound: "current",
                }
            );
            assert_eq!(
                ComponentVersion::offered(Component::AdminProtocol, 0)
                    .expect_err("zero offered")
                    .category(),
                "zero_version"
            );
        }

        #[test]
        fn every_component_in_the_vocabulary_starts_at_one() {
            // Zero is refused because no component has ever had a version zero.
            // If one ever did, this assertion is what would have to change
            // first.
            let matrix = shipped_matrix();
            for component in Component::ALL {
                assert_eq!(
                    matrix.range(component).min_supported().get(),
                    1,
                    "{component} claims a minimum other than 1"
                );
            }
        }

        #[test]
        fn a_single_version_range_is_representable_and_an_empty_one_is_not() {
            let exact = CompatibilityRange::new(Component::AdminProtocol, 1, 1).expect("valid");
            assert_eq!(exact.min_supported(), exact.current());
            // Both bounds are inclusive and at least one, so there is no
            // construction producing a range that admits nothing.
            assert!(exact.assess(version(1)).may_mutate());
        }
    }

    mod verdict_bands {
        use super::*;

        #[test]
        fn a_version_inside_the_range_is_compatible_and_may_mutate() {
            let range = CompatibilityRange::new(Component::StoreSchema, 1, 6).expect("valid");
            for offered in 1..=6 {
                let verdict = range.assess(version(offered));
                assert_eq!(
                    verdict.category(),
                    "compatible",
                    "version {offered} inside 1..=6 was not compatible"
                );
                assert!(verdict.may_read());
                assert!(verdict.may_mutate());
                assert_eq!(verdict.offered().version().get(), offered);
                assert_eq!(verdict.offered().component(), Component::StoreSchema);
            }
        }

        /// The adjacent band is exactly one release above `current`: a peer
        /// produced by an N -> N+1 rolling upgrade. The requirement tolerates
        /// "adjacent releases" and nothing wider.
        #[test]
        fn one_release_above_the_current_version_is_read_only_with_an_upgrade_note() {
            let range = CompatibilityRange::new(Component::StoreSchema, 1, 6).expect("valid");
            let CompatVerdict::ReadOnlyCompatible { upgrade_required } = range.assess(version(7))
            else {
                panic!("version 7 against current 6 is the adjacent band");
            };
            assert_eq!(upgrade_required.upgrade_to().get(), 7);
            assert_eq!(upgrade_required.supported().min().get(), 1);
            assert_eq!(upgrade_required.supported().max().get(), 6);

            // The note names both versions, so a peer is told what it offered
            // and what this build has.
            let note = upgrade_required.note();
            assert!(note.contains("store_schema"), "{note}");
            assert!(note.contains('7'), "{note}");
            assert!(note.contains("1..=6"), "{note}");

            let verdict = range.assess(version(7));
            assert!(verdict.may_read(), "an adjacent peer is still readable");
            assert!(
                !verdict.may_mutate(),
                "an adjacent peer must not mutate under a dialect this build does not define"
            );
        }

        #[test]
        fn a_version_below_the_minimum_is_incompatible_naming_both_versions() {
            let range = CompatibilityRange::new(Component::StoreSchema, 3, 6).expect("valid");
            let CompatVerdict::Incompatible { refusal } = range.assess(version(2)) else {
                panic!("version 2 is below the minimum of 3");
            };
            assert_eq!(refusal.reason(), RefusalReason::BelowMinimumSupported);
            assert_eq!(refusal.category(), "below_minimum_supported");

            let note = refusal.note();
            assert!(note.contains("store_schema"), "{note}");
            assert!(note.contains('2'), "{note}");
            assert!(note.contains("3..=6"), "{note}");
            // The peer is the side that has to move here, not this build.
            assert!(note.contains("Upgrade the peer"), "{note}");

            assert!(
                !range.assess(version(2)).may_read(),
                "the decoders for a retired dialect are gone; offering reads would be a \
                 claim this build cannot honour"
            );
            assert!(!range.assess(version(2)).may_mutate());
        }

        /// Two releases ahead is not adjacent, and nothing in the requirement
        /// claims decode tolerance across it.
        #[test]
        fn two_releases_above_the_current_version_is_incompatible() {
            let range = CompatibilityRange::new(Component::StoreSchema, 1, 6).expect("valid");
            let CompatVerdict::Incompatible { refusal } = range.assess(version(8)) else {
                panic!("version 8 against current 6 is two releases away");
            };
            assert_eq!(refusal.reason(), RefusalReason::BeyondAdjacentRelease);
            let note = refusal.note();
            assert!(note.contains('8'), "{note}");
            assert!(note.contains("1..=6"), "{note}");
            // Here it is this build that has to move.
            assert!(note.contains("upgrade this build"), "{note}");
            assert!(!range.assess(version(8)).may_read());
        }

        /// The whole band structure in one sweep, so a swapped or widened band
        /// cannot hide in the gap between the cases above.
        #[test]
        fn the_bands_partition_every_version_around_the_range() {
            let range = CompatibilityRange::new(Component::StoreSchema, 3, 6).expect("valid");
            let observed: Vec<(u32, &str)> = (1..=10)
                .map(|offered| (offered, range.assess(version(offered)).category()))
                .collect();
            assert_eq!(
                observed,
                vec![
                    (1, "incompatible"),
                    (2, "incompatible"),
                    (3, "compatible"),
                    (4, "compatible"),
                    (5, "compatible"),
                    (6, "compatible"),
                    (7, "read_only_compatible"),
                    (8, "incompatible"),
                    (9, "incompatible"),
                    (10, "incompatible"),
                ]
            );
        }

        /// No verdict admits a write outside the supported range, for any
        /// component and any offered version near it.
        #[test]
        fn mutation_is_reachable_only_from_inside_the_range() {
            let matrix = shipped_matrix();
            for component in Component::ALL {
                let range = matrix.range(component);
                let ceiling = range.current().get() + 4;
                for offered in 1..=ceiling {
                    let verdict = matrix.assess(component, version(offered));
                    let inside =
                        offered >= range.min_supported().get() && offered <= range.current().get();
                    assert_eq!(
                        verdict.may_mutate(),
                        inside,
                        "{component} at version {offered} disagreed about mutation"
                    );
                    assert!(
                        !verdict.may_mutate() || verdict.may_read(),
                        "{component} at version {offered} may mutate but not read"
                    );
                }
            }
        }

        #[test]
        fn every_refusal_reason_has_a_distinct_spelling() {
            let mut spellings: Vec<&str> = RefusalReason::ALL
                .iter()
                .map(|reason| reason.as_str())
                .collect();
            let total = spellings.len();
            spellings.sort_unstable();
            spellings.dedup();
            assert_eq!(spellings.len(), total);
        }
    }

    mod matrix_shape {
        use super::*;

        #[test]
        fn every_component_has_exactly_one_row_at_its_own_index() {
            let matrix = shipped_matrix();
            assert_eq!(matrix.rows().len(), Component::COUNT);
            for component in Component::ALL {
                assert_eq!(
                    Component::ALL[component.index()],
                    component,
                    "{component} does not sit at its own index"
                );
                assert_eq!(matrix.rows()[component.index()].component(), component);
                assert_eq!(matrix.range(component).component(), component);
            }
        }

        #[test]
        fn every_component_spelling_is_distinct() {
            let mut spellings: Vec<&str> = Component::ALL
                .iter()
                .map(|component| component.as_str())
                .collect();
            let total = spellings.len();
            assert_eq!(total, Component::COUNT);
            spellings.sort_unstable();
            spellings.dedup();
            assert_eq!(spellings.len(), total, "two components share a spelling");
        }

        #[test]
        fn every_component_names_the_symbol_its_version_comes_from() {
            for component in Component::ALL {
                let authority = component.authority();
                assert!(
                    !authority.symbol().is_empty(),
                    "{component} names no authoritative symbol"
                );
                assert!(
                    authority.symbol().contains("::"),
                    "{component} names {} , which is not a symbol path",
                    authority.symbol()
                );
            }
        }
    }

    /// The claims this crate can check against the live constant.
    mod local_cross_checks {
        use automonique_protocol::admin::{AdminError, AdminRequest};
        use automonique_protocol::codec::{
            CodecError, Envelope, MessageKind, ProtocolName, RequestId,
        };
        use automonique_protocol::codegen::maintained_modules;
        use automonique_protocol::release::{
            MANIFEST_SCHEMA_REVISION, MAX_SUPPORTED_MANIFEST_SCHEMA,
        };
        use automonique_protocol::wire::{JsonValue, Message};

        use super::*;

        /// A canonical admin status payload at an arbitrary major version.
        fn admin_payload(major: u32) -> Vec<u8> {
            Message::new(
                Envelope::new(
                    ProtocolName::new(automonique_protocol::admin::ADMIN_PROTOCOL)
                        .expect("the shipped protocol name"),
                    version(major),
                    RequestId::new("compat-matrix").expect("a valid request id"),
                    MessageKind::new("status").expect("a defined kind"),
                ),
                JsonValue::Object(Vec::new()),
            )
            .to_canonical_bytes()
        }

        /// The admin range is not a public constant, so it is checked through
        /// the behaviour it produces: the refusal carries the live minimum and
        /// maximum, and those are what the matrix has to agree with.
        #[test]
        fn the_admin_protocol_row_matches_the_range_the_socket_actually_admits() {
            let declared = shipped_matrix().range(Component::AdminProtocol);
            let beyond = declared.current().get() + 1;
            let error = AdminRequest::from_canonical_bytes(&admin_payload(beyond))
                .expect_err("a version above the admitted range");
            assert_eq!(
                error,
                AdminError::Codec(CodecError::UnsupportedVersion {
                    supported_min: declared.min_supported().get(),
                    supported_max: declared.current().get(),
                    offered: beyond,
                }),
                "the matrix row for admin_protocol drifted from admin::supported_protocol"
            );

            // And the version the matrix calls current is not refused on the
            // version axis, so the row cannot be right by naming a range the
            // socket does not admit at all.
            let accepted =
                AdminRequest::from_canonical_bytes(&admin_payload(declared.current().get()));
            assert!(
                !matches!(
                    accepted,
                    Err(AdminError::Codec(CodecError::UnsupportedVersion { .. }))
                ),
                "the socket refused the version the matrix calls current"
            );
        }

        #[test]
        fn the_release_manifest_row_matches_the_shipped_constants() {
            let declared = shipped_matrix().range(Component::ReleaseManifestSchema);
            assert_eq!(
                declared.current().get(),
                MANIFEST_SCHEMA_REVISION,
                "the matrix row for release_manifest_schema drifted from \
                 MANIFEST_SCHEMA_REVISION"
            );
            assert_eq!(
                declared.current().get(),
                MAX_SUPPORTED_MANIFEST_SCHEMA,
                "the matrix names a current revision the build cannot interpret"
            );
        }

        #[test]
        fn the_typescript_sdk_row_matches_the_generated_command_surface() {
            let declared = shipped_matrix().range(Component::TypeScriptSdkSurface);
            let surfaces: Vec<u32> = maintained_modules()
                .into_iter()
                .filter_map(|module| module.command_surface)
                .map(|surface| surface.version)
                .collect();
            assert!(
                !surfaces.is_empty(),
                "no generated command surface to check the row against"
            );
            for offered in surfaces {
                assert_eq!(
                    offered,
                    declared.current().get(),
                    "the matrix row for typescript_sdk_surface drifted from the version a \
                     generated command surface speaks"
                );
            }
        }

        /// Every row the matrix calls locally checkable is checked by one of
        /// the tests above, and every row it calls foreign is not. The lists
        /// are restated rather than derived, so a new component has to declare
        /// which side it falls on.
        #[test]
        fn the_checkable_and_foreign_rows_are_exactly_what_is_declared() {
            let checked_above = [
                Component::AdminProtocol,
                Component::ReleaseManifestSchema,
                Component::TypeScriptSdkSurface,
            ];
            let (local, foreign): (Vec<Component>, Vec<Component>) = Component::ALL
                .into_iter()
                .partition(|component| component.authority().is_checkable_here());
            assert_eq!(local, checked_above.to_vec());
            assert_eq!(foreign, KNOWN_FOREIGN.to_vec());
            assert_eq!(local.len() + foreign.len(), Component::COUNT);

            for component in foreign {
                assert!(
                    matches!(component.authority(), VersionAuthority::Foreign { .. }),
                    "{component} is not marked foreign"
                );
                assert_eq!(component.authority().as_str(), "foreign");
            }
        }
    }

    mod manifest {
        use super::*;

        #[test]
        fn the_manifest_is_byte_identical_across_runs() {
            let first = matrix_manifest();
            for _ in 0..8 {
                assert_eq!(matrix_manifest(), first);
            }
            // And a separately built matrix renders the same bytes, so the
            // rendering does not depend on which instance produced it.
            assert_eq!(shipped_matrix().manifest(), first);
        }

        #[test]
        fn the_manifest_names_its_schema_and_every_component_once() {
            let rendered = matrix_manifest();
            let mut lines = rendered.lines();
            assert_eq!(lines.next(), Some(COMPATIBILITY_MATRIX_SCHEMA_V1));
            let rows: Vec<&str> = lines.collect();
            assert_eq!(rows.len(), Component::COUNT);

            let matrix = shipped_matrix();
            for component in Component::ALL {
                let range = matrix.range(component);
                let authority = component.authority();
                let expected = format!(
                    "{} {}..={} {} {}",
                    component,
                    range.min_supported(),
                    range.current(),
                    authority.as_str(),
                    authority.symbol()
                );
                assert_eq!(
                    rows.iter().filter(|row| **row == expected).count(),
                    1,
                    "{component} has no line reading {expected:?} in:\n{rendered}"
                );
            }
        }

        /// Sorted by component spelling rather than declaration order, so
        /// reordering the enum cannot move a pinned line.
        #[test]
        fn the_manifest_rows_are_sorted() {
            let rendered = matrix_manifest();
            let rows: Vec<&str> = rendered.lines().skip(1).collect();
            let mut sorted = rows.clone();
            sorted.sort_unstable();
            assert_eq!(rows, sorted);
        }

        /// The whole point of the manifest: a crate that owns a foreign
        /// constant can read its expected value out of this text without
        /// depending on the protocol crate's types. This is the shape of the
        /// check that does not exist yet.
        #[test]
        fn a_foreign_row_can_be_read_back_out_of_the_manifest_text() {
            let rendered = matrix_manifest();
            for component in KNOWN_FOREIGN {
                let prefix = format!("{component} ");
                let row = rendered
                    .lines()
                    .find(|line| line.starts_with(&prefix))
                    .unwrap_or_else(|| panic!("{component} has no manifest row"));
                let mut fields = row.split(' ');
                assert_eq!(fields.next(), Some(component.as_str()));
                let bounds = fields.next().expect("a bounds field");
                let (min, current) = bounds.split_once("..=").expect("an inclusive range");
                let declared = shipped_matrix().range(component);
                assert_eq!(
                    min.parse::<u32>().expect("a numeric minimum"),
                    declared.min_supported().get()
                );
                assert_eq!(
                    current.parse::<u32>().expect("a numeric current"),
                    declared.current().get()
                );
                assert_eq!(fields.next(), Some("foreign"));
                assert_eq!(fields.next(), Some(component.authority().symbol()));
                assert_eq!(fields.next(), None, "the row carries an unexplained field");
            }
        }

        /// The values the manifest asserts for the foreign crates, restated so
        /// that changing one in `declared_bounds` without changing the constant
        /// it names is a visible edit rather than a silent one.
        #[test]
        fn the_asserted_foreign_versions_are_the_ones_this_wave_recorded() {
            let matrix = shipped_matrix();
            let recorded = [
                (Component::StoreSchema, 1, 7),
                (Component::CancelLedgerSchema, 1, 1),
                (Component::GenerationAuditSchema, 1, 1),
                (Component::ProviderJournalSchema, 1, 1),
                (Component::RunSubmissionsSchema, 1, 1),
                (Component::SlackIngressSchema, 1, 1),
                (Component::RunSpecDocument, 1, 1),
            ];
            assert_eq!(recorded.len(), KNOWN_FOREIGN.len());
            for (component, min, current) in recorded {
                let declared = matrix.range(component);
                assert_eq!(
                    (declared.min_supported().get(), declared.current().get()),
                    (min, current),
                    "{component} drifted from the value recorded against {}",
                    component.authority().symbol()
                );
            }
        }
    }

    /// The matrix is a description; nothing enforces it yet.
    mod honesty {
        use super::*;

        #[test]
        fn the_matrix_is_a_value_and_carries_no_enforcement_hook() {
            // `assess` answers a question. It returns a verdict and takes
            // nothing it could act on: no connection, no store, no boundary.
            // The only way this becomes enforcement is a later slice calling
            // it, which is what makes the claim checkable rather than a
            // promise.
            let matrix: CompatibilityMatrix = shipped_matrix();
            let verdict = matrix.assess(Component::AdminProtocol, version(1));
            assert!(verdict.may_mutate());
            assert_eq!(verdict.offered().component(), Component::AdminProtocol);
        }
    }
}
