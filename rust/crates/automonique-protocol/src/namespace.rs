// SPDX-License-Identifier: Elastic-2.0

//! The canonical namespace gate.
//!
//! Every namespaced surface must carry `automonique-*` or `automonique_*`. The
//! only exceptions are legacy compatibility identifiers listed in an inventory,
//! and each of those must name the migration contract that authorized it.
//!
//! There is deliberately no suppression comment, no separate allowlist file and
//! no environment variable. Adding an exception means adding an inventory entry
//! with its contract, which is reviewable; an escape hatch is exactly the
//! mechanism `plan/doctrine.md` forbids for making a queue green. This module
//! reads neither the environment nor the filesystem, so there is nothing for a
//! variable or a dropped-in file to point at; the scan that feeds it is the
//! caller's, and it is exercised against the real tree by `tests/namespace.rs`.
//!
//! An exception cannot exist without the migration contract that authorized it.
//! The contract is a constructor argument, not a field left unset later:
//!
//! ```compile_fail
//! use automonique_protocol::namespace::{InventoryEntry, SurfaceClass};
//! // There is no constructor taking an identifier on its own.
//! let entry = InventoryEntry::new(SurfaceClass::Binary, "legacyctl").unwrap();
//! ```
//!
//! ```
//! use automonique_protocol::compat::MigrationContract;
//! use automonique_protocol::namespace::{InventoryEntry, SurfaceClass};
//!
//! let contract = MigrationContract::new("docs/product-plan/reference/migration-plan.md").unwrap();
//! let entry = InventoryEntry::new(SurfaceClass::Binary, "legacyctl", contract).unwrap();
//! assert_eq!(
//!     entry.authorized_by().as_str(),
//!     "docs/product-plan/reference/migration-plan.md"
//! );
//! ```
//!
//! A finding always carries both ways out, because [`Finding::resolutions`]
//! returns a two-element array rather than a list that could arrive short:
//!
//! ```compile_fail
//! use automonique_protocol::namespace::{NamespaceGate, ScannedIdentifier, SurfaceClass};
//!
//! let seen = ScannedIdentifier::new(SurfaceClass::Metric, "legacy_total", "Cargo.toml").unwrap();
//! let report = NamespaceGate::new().run(&[seen]);
//! // A finding cannot offer only one way out.
//! let [rename] = report.findings[0].resolutions();
//! ```
//!
//! ```
//! use automonique_protocol::namespace::{NamespaceGate, ScannedIdentifier, SurfaceClass};
//!
//! let seen = ScannedIdentifier::new(SurfaceClass::Metric, "legacy_total", "Cargo.toml").unwrap();
//! let report = NamespaceGate::new().run(&[seen]);
//! let [rename, inventory] = report.findings[0].resolutions();
//! assert!(rename.contains("rename"));
//! assert!(inventory.contains("migration contract"));
//! ```

use core::fmt;
use std::error::Error;

use crate::compat::MigrationContract;
use crate::primitives::ValueError;

/// The canonical hyphenated prefix.
pub const CANONICAL_HYPHEN_PREFIX: &str = "automonique-";

/// The canonical underscored prefix.
pub const CANONICAL_UNDERSCORE_PREFIX: &str = "automonique_";

/// The bare canonical name, which is itself in the namespace.
pub const CANONICAL_BARE: &str = "automonique";

/// The canonical dotted prefix, used by schema and protocol names.
///
/// This is not a third general prefix. It is accepted only on surfaces whose
/// canonical spelling is dotted — see [`SurfaceClass::permits_dotted_namespace`]
/// — so a package or binary called `automonique.thing` is still a finding.
pub const CANONICAL_DOT_PREFIX: &str = "automonique.";

/// Maximum UTF-8 byte length of a scanned identifier or location.
pub const MAX_NAMESPACE_FIELD_BYTES: usize = 512;

/// A class of namespaced surface.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SurfaceClass {
    /// A Cargo package.
    Package,
    /// A crate.
    Crate,
    /// A module path.
    Module,
    /// A Cargo feature flag.
    Feature,
    /// A binary target.
    Binary,
    /// A schema or protocol name.
    Schema,
    /// A metric name.
    Metric,
    /// A tracing target.
    TracingTarget,
    /// A fixture identifier.
    Fixture,
    /// A release artifact name.
    ReleaseArtifact,
}

impl SurfaceClass {
    /// Every class the gate is required to cover.
    pub const ALL: [Self; 10] = [
        Self::Package,
        Self::Crate,
        Self::Module,
        Self::Feature,
        Self::Binary,
        Self::Schema,
        Self::Metric,
        Self::TracingTarget,
        Self::Fixture,
        Self::ReleaseArtifact,
    ];

    /// How many classes there are.
    pub const COUNT: usize = Self::ALL.len();

    /// Position in [`SurfaceClass::ALL`].
    ///
    /// Used to index a coverage record, so every class has exactly one slot and
    /// none can be missing from a report.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Package => 0,
            Self::Crate => 1,
            Self::Module => 2,
            Self::Feature => 3,
            Self::Binary => 4,
            Self::Schema => 5,
            Self::Metric => 6,
            Self::TracingTarget => 7,
            Self::Fixture => 8,
            Self::ReleaseArtifact => 9,
        }
    }

    /// Whether [`CANONICAL_DOT_PREFIX`] is a canonical spelling here.
    ///
    /// Schema and protocol names in this product are dotted — `automonique.doctor/v1`
    /// — so the dotted spelling carries the namespace on that surface and only
    /// there. Widening it to every class would let `automonique.anything` pass
    /// as a package or a binary, which is not a spelling this tree uses.
    #[must_use]
    pub const fn permits_dotted_namespace(self) -> bool {
        matches!(self, Self::Schema)
    }

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Package => "package",
            Self::Crate => "crate",
            Self::Module => "module",
            Self::Feature => "feature",
            Self::Binary => "binary",
            Self::Schema => "schema",
            Self::Metric => "metric",
            Self::TracingTarget => "tracing_target",
            Self::Fixture => "fixture",
            Self::ReleaseArtifact => "release_artifact",
        }
    }
}

/// Why a gate input was rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamespaceError {
    /// A bounded field was rejected.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
}

impl NamespaceError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Field { .. } => "field_invalid",
        }
    }
}

impl fmt::Display for NamespaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
        }
    }
}

impl Error for NamespaceError {}

/// One identifier observed on a namespaced surface.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ScannedIdentifier {
    surface: SurfaceClass,
    name: String,
    location: String,
}

impl ScannedIdentifier {
    /// Record an observed identifier.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceError::Field`] for an invalid name or location.
    pub fn new(surface: SurfaceClass, name: &str, location: &str) -> Result<Self, NamespaceError> {
        bounded(name, "identifier")?;
        bounded(location, "location")?;
        Ok(Self {
            surface,
            name: name.to_owned(),
            location: location.to_owned(),
        })
    }

    /// Whether the identifier is inside the canonical namespace.
    #[must_use]
    pub fn is_canonical(&self) -> bool {
        self.name == CANONICAL_BARE
            || self.name.starts_with(CANONICAL_HYPHEN_PREFIX)
            || self.name.starts_with(CANONICAL_UNDERSCORE_PREFIX)
            || (self.surface.permits_dotted_namespace()
                && self.name.starts_with(CANONICAL_DOT_PREFIX))
    }

    /// The identifier.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Where it was observed.
    #[must_use]
    pub fn location(&self) -> &str {
        &self.location
    }

    /// The surface class.
    #[must_use]
    pub const fn surface(&self) -> SurfaceClass {
        self.surface
    }
}

/// Whether a surface class was looked at, and what looking produced.
///
/// `Scanned { count: 0 }` is "a scanner covered this class and found nothing".
/// [`Self::NotScanned`] is "nothing looked". They are different answers, and a
/// gate that merges them reports a gap as a pass.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SurfaceCoverage {
    /// A scanner covered this class.
    Scanned {
        /// How many identifiers it produced. Zero is a legitimate result.
        count: usize,
    },
    /// No scanner covered this class. An explicit gap, never a pass.
    NotScanned,
}

impl SurfaceCoverage {
    /// Whether anything looked at this class.
    #[must_use]
    pub const fn was_scanned(self) -> bool {
        matches!(self, Self::Scanned { .. })
    }

    /// How many identifiers were produced; zero when nothing looked.
    #[must_use]
    pub const fn count(self) -> usize {
        match self {
            Self::Scanned { count } => count,
            Self::NotScanned => 0,
        }
    }
}

impl fmt::Display for SurfaceCoverage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scanned { count: 0 } => formatter.write_str("scanned, none found"),
            Self::Scanned { count } => write!(formatter, "scanned, {count} found"),
            Self::NotScanned => formatter.write_str("not scanned"),
        }
    }
}

/// What a scan looked at, one entry per surface class.
///
/// Total by construction: the entries are an array indexed by
/// [`SurfaceClass::index`], so every class always carries an answer and a class
/// cannot be silently absent from a report. The only two answers are
/// [`SurfaceCoverage::Scanned`] and [`SurfaceCoverage::NotScanned`]; silence is
/// not one of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceCoverageReport {
    entries: [SurfaceCoverage; SurfaceClass::COUNT],
}

impl Default for SurfaceCoverageReport {
    fn default() -> Self {
        Self::nothing_scanned()
    }
}

impl SurfaceCoverageReport {
    /// A report in which no class has been looked at yet.
    #[must_use]
    pub const fn nothing_scanned() -> Self {
        Self {
            entries: [SurfaceCoverage::NotScanned; SurfaceClass::COUNT],
        }
    }

    /// Coverage of one class.
    #[must_use]
    pub const fn of(&self, surface: SurfaceClass) -> SurfaceCoverage {
        self.entries[surface.index()]
    }

    /// Every class with its coverage, in [`SurfaceClass::ALL`] order.
    #[must_use]
    pub fn rows(&self) -> [(SurfaceClass, SurfaceCoverage); SurfaceClass::COUNT] {
        SurfaceClass::ALL.map(|class| (class, self.of(class)))
    }

    /// Classes no scanner covered.
    #[must_use]
    pub fn not_scanned(&self) -> Vec<SurfaceClass> {
        SurfaceClass::ALL
            .into_iter()
            .filter(|class| !self.of(*class).was_scanned())
            .collect()
    }

    /// Classes a scanner covered that genuinely have no members here.
    #[must_use]
    pub fn scanned_none_found(&self) -> Vec<SurfaceClass> {
        SurfaceClass::ALL
            .into_iter()
            .filter(|class| self.of(*class) == SurfaceCoverage::Scanned { count: 0 })
            .collect()
    }

    /// Whether every class was looked at.
    #[must_use]
    pub fn is_total(&self) -> bool {
        SurfaceClass::ALL
            .into_iter()
            .all(|class| self.of(class).was_scanned())
    }
}

/// A scan being assembled: what was found, and which classes were looked at.
///
/// A class leaves [`SurfaceCoverage::NotScanned`] only through [`Self::record`],
/// so "scanned, none found" costs an actual call with an empty list. There is no
/// way to look like a class was covered without handing over its results, and
/// [`Self::record`] builds the identifiers itself from the class it was given,
/// so an identifier filed under the wrong surface is unrepresentable.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SurfaceInventory {
    coverage: SurfaceCoverageReport,
    identifiers: Vec<ScannedIdentifier>,
}

impl SurfaceInventory {
    /// An inventory in which nothing has been scanned.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            coverage: SurfaceCoverageReport::nothing_scanned(),
            identifiers: Vec::new(),
        }
    }

    /// Record that `surface` was scanned, yielding `found` name/location pairs.
    ///
    /// An empty `found` records "scanned, none found". Recording the same class
    /// twice accumulates, because one class can be scanned from several roots.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceError::Field`] for an invalid name or location.
    pub fn record(
        &mut self,
        surface: SurfaceClass,
        found: &[(String, String)],
    ) -> Result<(), NamespaceError> {
        let mut recorded = Vec::with_capacity(found.len());
        for (name, location) in found {
            recorded.push(ScannedIdentifier::new(surface, name, location)?);
        }
        let slot = &mut self.coverage.entries[surface.index()];
        *slot = SurfaceCoverage::Scanned {
            count: slot.count() + recorded.len(),
        };
        self.identifiers.append(&mut recorded);
        Ok(())
    }

    /// What was looked at.
    #[must_use]
    pub const fn coverage(&self) -> &SurfaceCoverageReport {
        &self.coverage
    }

    /// Everything found, in the order it was recorded.
    #[must_use]
    pub fn identifiers(&self) -> &[ScannedIdentifier] {
        &self.identifiers
    }
}

/// An inventoried legacy identifier and the contract that authorized it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryEntry {
    name: String,
    surface: SurfaceClass,
    authorized_by: MigrationContract,
}

impl InventoryEntry {
    /// Inventory a legacy identifier.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceError::Field`] for an invalid name.
    pub fn new(
        surface: SurfaceClass,
        name: &str,
        authorized_by: MigrationContract,
    ) -> Result<Self, NamespaceError> {
        bounded(name, "inventory_identifier")?;
        Ok(Self {
            name: name.to_owned(),
            surface,
            authorized_by,
        })
    }

    /// The inventoried identifier.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The contract that authorized it.
    #[must_use]
    pub const fn authorized_by(&self) -> &MigrationContract {
        &self.authorized_by
    }
}

/// One identifier that failed the gate.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Finding {
    /// The offending identifier.
    pub identifier: String,
    /// Where it was found.
    pub location: String,
    /// Which surface it sits on.
    pub surface: SurfaceClass,
}

impl Finding {
    /// The two ways to resolve this finding.
    ///
    /// A finding that does not say how to resolve it produces a suppression
    /// instead of a fix.
    #[must_use]
    pub fn resolutions(&self) -> [String; 2] {
        [
            format!(
                "rename {} to {CANONICAL_HYPHEN_PREFIX}… or {CANONICAL_UNDERSCORE_PREFIX}…",
                self.identifier
            ),
            format!(
                "inventory {} as a {} with its authorizing migration contract",
                self.identifier,
                self.surface.as_str()
            ),
        ]
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} ({} at {}): {} | {}",
            self.identifier,
            self.surface.as_str(),
            self.location,
            self.resolutions()[0],
            self.resolutions()[1]
        )
    }
}

/// The result of one gate run.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GateReport {
    /// Identifiers outside the namespace and outside the inventory.
    pub findings: Vec<Finding>,
    /// Inventory entries whose identifier no longer exists.
    ///
    /// Reported separately from `findings`, because an accumulating exception
    /// list is a different failure from an un-namespaced identifier.
    pub orphaned_inventory: Vec<String>,
    /// How many identifiers were scanned per surface class.
    pub scanned_per_surface: Vec<(SurfaceClass, usize)>,
    /// Which classes were looked at, whether or not they yielded anything.
    coverage: SurfaceCoverageReport,
}

impl GateReport {
    /// Whether the gate passed.
    ///
    /// Findings and orphans only. Coverage is reported separately by
    /// [`Self::complete_coverage`], because "no violations among what was
    /// scanned" and "everything was scanned" are two different claims and
    /// collapsing them is how a gap becomes a pass.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.findings.is_empty() && self.orphaned_inventory.is_empty()
    }

    /// What the scan looked at, per class.
    #[must_use]
    pub const fn coverage(&self) -> &SurfaceCoverageReport {
        &self.coverage
    }

    /// Surface classes for which nothing was scanned.
    ///
    /// Reported as an explicit gap: "the gate passes" must never mean "the gate
    /// did not look".
    #[must_use]
    pub fn unscanned_surfaces(&self) -> Vec<SurfaceClass> {
        self.coverage.not_scanned()
    }

    /// Surface classes that were scanned and genuinely have no members.
    ///
    /// Distinct from [`Self::unscanned_surfaces`]: these were looked at.
    #[must_use]
    pub fn scanned_none_found(&self) -> Vec<SurfaceClass> {
        self.coverage.scanned_none_found()
    }

    /// Confirm that every declared surface class was looked at.
    ///
    /// # Errors
    ///
    /// Returns the classes that were not scanned, so a caller cannot treat a
    /// partial scan as a clean one without naming the gap.
    pub fn complete_coverage(&self) -> Result<(), Vec<SurfaceClass>> {
        let gaps = self.coverage.not_scanned();
        if gaps.is_empty() { Ok(()) } else { Err(gaps) }
    }
}

/// The gate, holding its inventory of authorized exceptions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NamespaceGate {
    inventory: Vec<InventoryEntry>,
}

impl NamespaceGate {
    /// Start a gate with no exceptions.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inventory: Vec::new(),
        }
    }

    /// Inventory one authorized legacy identifier.
    pub fn inventory(&mut self, entry: InventoryEntry) {
        self.inventory.push(entry);
    }

    /// Run the gate over a completed scan.
    ///
    /// Preferred over [`Self::run`]: the scan carries which classes were looked
    /// at, so a class that was scanned and found empty is reported as such
    /// rather than as a gap.
    #[must_use]
    pub fn run_scan(&self, scan: &SurfaceInventory) -> GateReport {
        let mut report = self.run(scan.identifiers());
        report.coverage = *scan.coverage();
        report
    }

    /// Run the gate over a set of observed identifiers.
    ///
    /// Deterministic: findings and orphans are sorted, so the same tree yields
    /// the same ordered report regardless of the order identifiers arrived in.
    ///
    /// A bare list carries no record of what was looked at, so coverage is
    /// inferred conservatively: a class with no identifiers is reported as
    /// [`SurfaceCoverage::NotScanned`]. Use [`Self::run_scan`] to distinguish an
    /// empty class from an unscanned one.
    #[must_use]
    pub fn run(&self, scanned: &[ScannedIdentifier]) -> GateReport {
        let mut findings: Vec<Finding> = scanned
            .iter()
            .filter(|identifier| !identifier.is_canonical())
            .filter(|identifier| {
                !self.inventory.iter().any(|entry| {
                    entry.name == identifier.name && entry.surface == identifier.surface
                })
            })
            .map(|identifier| Finding {
                identifier: identifier.name.clone(),
                location: identifier.location.clone(),
                surface: identifier.surface,
            })
            .collect();
        findings.sort();
        findings.dedup();

        let mut orphaned_inventory: Vec<String> = self
            .inventory
            .iter()
            .filter(|entry| {
                !scanned.iter().any(|identifier| {
                    identifier.name == entry.name && identifier.surface == entry.surface
                })
            })
            .map(|entry| entry.name.clone())
            .collect();
        orphaned_inventory.sort();
        orphaned_inventory.dedup();

        let mut scanned_per_surface: Vec<(SurfaceClass, usize)> = SurfaceClass::ALL
            .into_iter()
            .map(|class| {
                (
                    class,
                    scanned
                        .iter()
                        .filter(|identifier| identifier.surface == class)
                        .count(),
                )
            })
            .collect();
        scanned_per_surface.sort();

        let mut coverage = SurfaceCoverageReport::nothing_scanned();
        for (class, count) in &scanned_per_surface {
            if *count > 0 {
                coverage.entries[class.index()] = SurfaceCoverage::Scanned { count: *count };
            }
        }

        GateReport {
            findings,
            orphaned_inventory,
            scanned_per_surface,
            coverage,
        }
    }
}

fn bounded(value: &str, field: &'static str) -> Result<(), NamespaceError> {
    let error = if value.is_empty() {
        Some(ValueError::Empty)
    } else if value.len() > MAX_NAMESPACE_FIELD_BYTES {
        Some(ValueError::TooLong {
            max_bytes: MAX_NAMESPACE_FIELD_BYTES,
            actual_bytes: value.len(),
        })
    } else if value.chars().any(char::is_control) {
        Some(ValueError::ControlCharacter)
    } else {
        None
    };
    match error {
        Some(error) => Err(NamespaceError::Field { field, error }),
        None => Ok(()),
    }
}
