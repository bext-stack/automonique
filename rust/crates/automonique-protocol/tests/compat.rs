// SPDX-License-Identifier: Elastic-2.0

//! R1-17 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-17.md`.

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
