// SPDX-License-Identifier: Elastic-2.0

//! R1-17 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-17.md`.

use automonique_protocol::compat::{
    CompatError, IdentifierClass, LegacyAlias, MigrationContract, NameEntry, NameRegistry,
    SpellingResolution,
};

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
