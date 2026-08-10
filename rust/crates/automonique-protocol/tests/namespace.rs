// SPDX-License-Identifier: Elastic-2.0

//! R1-19 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-19.md`.

use std::path::PathBuf;

use automonique_protocol::compat::MigrationContract;
use automonique_protocol::namespace::{
    InventoryEntry, NamespaceGate, ScannedIdentifier, SurfaceClass,
};

fn contract() -> MigrationContract {
    MigrationContract::new("plan/contracts/R1-19.md").expect("valid contract")
}

fn scanned(surface: SurfaceClass, name: &str) -> ScannedIdentifier {
    ScannedIdentifier::new(surface, name, "rust/Cargo.toml").expect("valid identifier")
}

/// One identifier on every surface class, all canonical.
fn full_canonical_sweep() -> Vec<ScannedIdentifier> {
    SurfaceClass::ALL
        .into_iter()
        .map(|surface| scanned(surface, &format!("automonique-{}", surface.as_str())))
        .collect()
}

mod surface_coverage {
    use super::*;

    #[test]
    fn every_declared_surface_class_is_covered() {
        assert_eq!(SurfaceClass::ALL.len(), 10);
        let report = NamespaceGate::new().run(&full_canonical_sweep());
        assert!(report.passed());
        assert!(
            report.unscanned_surfaces().is_empty(),
            "unscanned: {:?}",
            report.unscanned_surfaces()
        );
    }

    #[test]
    fn an_unscanned_class_is_reported_as_a_gap_not_a_pass() {
        // Scanning only packages leaves nine classes unlooked-at. The gate
        // still "passes" its findings, so the gap has to be visible separately.
        let report = NamespaceGate::new().run(&[scanned(SurfaceClass::Package, "automonique")]);
        assert!(report.findings.is_empty());
        assert_eq!(
            report.unscanned_surfaces().len(),
            9,
            "the gate must not look like it covered everything"
        );
        assert!(!report.unscanned_surfaces().contains(&SurfaceClass::Package));
    }

    #[test]
    fn surface_spellings_are_distinct() {
        let mut spellings: Vec<&str> = SurfaceClass::ALL
            .iter()
            .map(|class| class.as_str())
            .collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);
    }
}

mod namespace_enforcement {
    use super::*;

    #[test]
    fn the_canonical_prefixes_and_the_bare_name_are_accepted() {
        for name in ["automonique", "automonique-lab", "automonique_protocol"] {
            let report = NamespaceGate::new().run(&[scanned(SurfaceClass::Crate, name)]);
            assert!(report.findings.is_empty(), "{name} was refused");
        }
    }

    #[test]
    fn an_identifier_outside_the_namespace_fails_naming_everything() {
        let report =
            NamespaceGate::new().run(&[scanned(SurfaceClass::Metric, "legacy_runs_total")]);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.identifier, "legacy_runs_total");
        assert_eq!(finding.location, "rust/Cargo.toml");
        assert_eq!(finding.surface, SurfaceClass::Metric);
        assert!(!report.passed());
    }

    #[test]
    fn a_near_miss_prefix_is_still_outside_the_namespace() {
        for name in [
            "automoniqu-lab",
            "auto_monique",
            "Automonique-lab",
            "xautomonique-lab",
        ] {
            let report = NamespaceGate::new().run(&[scanned(SurfaceClass::Crate, name)]);
            assert_eq!(report.findings.len(), 1, "{name} was wrongly accepted");
        }
    }
}

mod bidirectional_inventory {
    use super::*;

    #[test]
    fn an_inventoried_identifier_passes() {
        let mut gate = NamespaceGate::new();
        gate.inventory(
            InventoryEntry::new(SurfaceClass::Binary, "legacyctl", contract()).expect("valid"),
        );
        let report = gate.run(&[scanned(SurfaceClass::Binary, "legacyctl")]);
        assert!(report.passed(), "{:?}", report.findings);
    }

    #[test]
    fn an_inventory_entry_for_a_vanished_identifier_also_fails() {
        let mut gate = NamespaceGate::new();
        gate.inventory(
            InventoryEntry::new(SurfaceClass::Binary, "legacyctl", contract()).expect("valid"),
        );
        // The binary was removed; the exception outlived it.
        let report = gate.run(&[scanned(SurfaceClass::Binary, "automonique")]);
        assert!(report.findings.is_empty(), "nothing is un-namespaced");
        assert_eq!(report.orphaned_inventory, vec!["legacyctl".to_owned()]);
        assert!(
            !report.passed(),
            "an accumulating exception list must not pass"
        );
    }

    #[test]
    fn the_two_directions_are_reported_separately() {
        let mut gate = NamespaceGate::new();
        gate.inventory(
            InventoryEntry::new(SurfaceClass::Binary, "gone", contract()).expect("valid"),
        );
        let report = gate.run(&[scanned(SurfaceClass::Metric, "legacy_total")]);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.orphaned_inventory.len(), 1);
    }

    #[test]
    fn an_inventory_entry_is_scoped_to_its_surface() {
        let mut gate = NamespaceGate::new();
        gate.inventory(
            InventoryEntry::new(SurfaceClass::Binary, "legacyctl", contract()).expect("valid"),
        );
        // The same spelling on a different surface is not covered.
        let report = gate.run(&[
            scanned(SurfaceClass::Binary, "legacyctl"),
            scanned(SurfaceClass::Metric, "legacyctl"),
        ]);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].surface, SurfaceClass::Metric);
    }
}

mod authorized_exceptions {
    use super::*;

    #[test]
    fn every_inventory_entry_names_its_contract() {
        let entry =
            InventoryEntry::new(SurfaceClass::Binary, "legacyctl", contract()).expect("valid");
        assert_eq!(entry.authorized_by().as_str(), "plan/contracts/R1-19.md");
        assert_eq!(entry.name(), "legacyctl");
    }

    #[test]
    fn an_entry_cannot_be_built_without_a_contract_identifier() {
        assert!(
            MigrationContract::new("").is_err(),
            "an unauthorized exception has no contract to name"
        );
    }
}

mod determinism {
    use super::*;

    #[test]
    fn findings_are_ordered_independently_of_input_order() {
        let forward = vec![
            scanned(SurfaceClass::Metric, "zeta_total"),
            scanned(SurfaceClass::Metric, "alpha_total"),
            scanned(SurfaceClass::Crate, "mid_crate"),
        ];
        let mut reversed = forward.clone();
        reversed.reverse();

        let gate = NamespaceGate::new();
        let first = gate.run(&forward);
        let second = gate.run(&reversed);
        assert_eq!(first, second, "report depends on input order");

        let identifiers: Vec<&str> = first
            .findings
            .iter()
            .map(|finding| finding.identifier.as_str())
            .collect();
        let mut sorted = identifiers.clone();
        sorted.sort_unstable();
        assert_eq!(identifiers, sorted, "findings are not canonically ordered");
    }

    #[test]
    fn repeated_runs_are_identical() {
        let gate = NamespaceGate::new();
        let input = full_canonical_sweep();
        let first = gate.run(&input);
        for _ in 0..8 {
            assert_eq!(gate.run(&input), first);
        }
    }
}

mod actionable_output {
    use super::*;

    #[test]
    fn every_finding_names_both_resolution_paths() {
        let report = NamespaceGate::new().run(&[scanned(SurfaceClass::Metric, "legacy_total")]);
        let finding = &report.findings[0];
        let [rename, inventory] = finding.resolutions();
        assert!(rename.contains("rename"));
        assert!(rename.contains("automonique-"));
        assert!(inventory.contains("inventory"));
        assert!(inventory.contains("migration contract"));

        let rendered = finding.to_string();
        assert!(rendered.contains("legacy_total"));
        assert!(rendered.contains("metric"));
        assert!(rendered.contains("rust/Cargo.toml"));
    }
}

mod the_gate_can_fail {
    use super::*;

    /// Collect the real workspace's package and module identifiers.
    fn workspace_identifiers() -> Vec<ScannedIdentifier> {
        let crates_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("crates");
        let mut found = Vec::new();
        for entry in std::fs::read_dir(&crates_dir).expect("the workspace has crates") {
            let path = entry.expect("directory entry").path();
            if !path.is_dir() {
                continue;
            }
            let package = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("utf-8 crate directory");
            found.push(
                ScannedIdentifier::new(SurfaceClass::Package, package, &path.display().to_string())
                    .expect("valid identifier"),
            );

            let src = path.join("src");
            let Ok(modules) = std::fs::read_dir(&src) else {
                continue;
            };
            for module in modules {
                let module_path = module.expect("entry").path();
                if module_path.extension().and_then(|value| value.to_str()) != Some("rs") {
                    continue;
                }
                let stem = module_path
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .expect("utf-8 module");
                if stem == "lib" || stem == "main" {
                    continue;
                }
                // Module names are namespaced by their crate, so the gate
                // checks the crate-qualified path.
                found.push(
                    ScannedIdentifier::new(
                        SurfaceClass::Module,
                        &format!("{}::{stem}", package.replace('-', "_")),
                        &module_path.display().to_string(),
                    )
                    .expect("valid identifier"),
                );
            }
        }
        found
    }

    #[test]
    fn the_real_workspace_passes_the_gate() {
        let identifiers = workspace_identifiers();
        assert!(
            identifiers.len() >= 10,
            "only {} identifiers were collected",
            identifiers.len()
        );
        let report = NamespaceGate::new().run(&identifiers);
        assert!(
            report.findings.is_empty(),
            "the workspace has un-namespaced identifiers: {:?}",
            report.findings
        );
    }

    #[test]
    fn a_deliberately_introduced_identifier_is_rejected() {
        // The gate is worthless if it has never failed. This injects exactly
        // what CI is meant to catch.
        let mut identifiers = workspace_identifiers();
        identifiers.push(
            ScannedIdentifier::new(
                SurfaceClass::Crate,
                "legacy-runner",
                "rust/crates/legacy-runner",
            )
            .expect("valid identifier"),
        );
        let report = NamespaceGate::new().run(&identifiers);
        assert!(!report.passed(), "the gate accepted a legacy crate name");
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.identifier == "legacy-runner"),
            "the injected identifier was not named"
        );
    }
}
