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
//! mechanism `plan/doctrine.md` forbids for making a queue green.

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
    }

    /// The identifier.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The surface class.
    #[must_use]
    pub const fn surface(&self) -> SurfaceClass {
        self.surface
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
}

impl GateReport {
    /// Whether the gate passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.findings.is_empty() && self.orphaned_inventory.is_empty()
    }

    /// Surface classes for which nothing was scanned.
    ///
    /// Reported as an explicit gap: "the gate passes" must never mean "the gate
    /// did not look".
    #[must_use]
    pub fn unscanned_surfaces(&self) -> Vec<SurfaceClass> {
        SurfaceClass::ALL
            .into_iter()
            .filter(|class| {
                !self
                    .scanned_per_surface
                    .iter()
                    .any(|(scanned, count)| scanned == class && *count > 0)
            })
            .collect()
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

    /// Run the gate over a set of observed identifiers.
    ///
    /// Deterministic: findings and orphans are sorted, so the same tree yields
    /// the same ordered report regardless of the order identifiers arrived in.
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

        GateReport {
            findings,
            orphaned_inventory,
            scanned_per_surface,
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
