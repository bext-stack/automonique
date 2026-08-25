// SPDX-License-Identifier: Elastic-2.0

//! One registry for canonical names and their legacy aliases.
//!
//! Both spellings are generated from one entry, so two spellings of a setting
//! can never become two sources of truth. When a configuration names both, the
//! result is a conflict rather than a precedence rule: a precedence rule is how
//! one of two configured values silently wins for a year.
//!
//! Durable identities are never rewritten for branding. An entry's durable
//! identity is fixed at construction and survives a canonical rename, which is
//! what makes a compatibility alias a forwarding boundary rather than a
//! migration.
//!
//! The module answers a second compatibility question, about versions rather
//! than spellings: which version of each versioned surface this tree admits.
//! [`shipped_matrix`] declares one [`CompatibilityRange`] per [`Component`],
//! and [`CompatibilityMatrix::assess`] turns an offered version into a typed
//! [`CompatVerdict`]. See that type for what the three verdicts mean and
//! [`shipped_matrix`] for what the matrix does and does not prove.

use core::fmt;
use std::error::Error;

use crate::codec::{MajorVersion, VersionRange};
use crate::primitives::ValueError;

mod generated;

pub use generated::{CanonicalName, LegacyName};

/// Maximum UTF-8 byte length of a registry field.
pub const MAX_COMPAT_FIELD_BYTES: usize = 256;

/// What kind of identifier an entry names.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IdentifierClass {
    /// An environment variable.
    EnvironmentVariable,
    /// A command or subcommand.
    Command,
    /// A configuration key.
    ConfigurationKey,
    /// A wire protocol name.
    ProtocolName,
    /// A schema name.
    SchemaName,
    /// A metric name.
    Metric,
    /// A tracing target.
    TracingTarget,
    /// An HTTP route.
    Route,
}

impl IdentifierClass {
    /// Every class, for coverage checks.
    pub const ALL: [Self; 8] = [
        Self::EnvironmentVariable,
        Self::Command,
        Self::ConfigurationKey,
        Self::ProtocolName,
        Self::SchemaName,
        Self::Metric,
        Self::TracingTarget,
        Self::Route,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EnvironmentVariable => "environment_variable",
            Self::Command => "command",
            Self::ConfigurationKey => "configuration_key",
            Self::ProtocolName => "protocol_name",
            Self::SchemaName => "schema_name",
            Self::Metric => "metric",
            Self::TracingTarget => "tracing_target",
            Self::Route => "route",
        }
    }
}

/// Why a registry or resolution operation was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompatError {
    /// An alias was added without an authorizing migration contract.
    AliasNotAuthorized {
        /// The alias spelling.
        alias: String,
    },
    /// One entry resolves to more than one runtime owner.
    TwoOwners {
        /// The canonical name.
        canonical: String,
        /// The first owner.
        first: String,
        /// The conflicting owner.
        second: String,
    },
    /// A spelling is claimed by two entries.
    DuplicateSpelling {
        /// The spelling claimed twice.
        spelling: String,
    },
    /// A configuration set both a canonical name and one of its aliases.
    ///
    /// Carries both spellings and both values, because a caller has to see
    /// exactly what it configured twice.
    CanonicalAndAliasBothSet {
        /// The canonical spelling.
        canonical: String,
        /// The value set under the canonical spelling.
        canonical_value: String,
        /// The alias spelling.
        alias: String,
        /// The value set under the alias.
        alias_value: String,
    },
    /// A bounded field was rejected.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
    /// A component's declared range ended before it began.
    InvertedRange {
        /// The component whose declaration is wrong.
        component: Component,
        /// The declared lowest admitted version.
        min_supported: u32,
        /// The declared live version.
        current: u32,
    },
    /// A version was zero.
    ///
    /// Every component in the vocabulary starts at one, so zero is not a lower
    /// bound this build could ever have supported. On the store's sibling
    /// databases a `user_version` of zero means the file has no schema yet,
    /// which is a different thing from a version and is not representable here.
    ZeroVersion {
        /// The component whose version was zero.
        component: Component,
        /// Which bound was zero.
        bound: &'static str,
    },
}

impl CompatError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::AliasNotAuthorized { .. } => "alias_not_authorized",
            Self::TwoOwners { .. } => "two_owners",
            Self::DuplicateSpelling { .. } => "duplicate_spelling",
            Self::CanonicalAndAliasBothSet { .. } => "canonical_and_alias_both_set",
            Self::Field { .. } => "field_invalid",
            Self::InvertedRange { .. } => "inverted_range",
            Self::ZeroVersion { .. } => "zero_version",
        }
    }
}

impl fmt::Display for CompatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AliasNotAuthorized { alias } => write!(
                formatter,
                "alias {alias} has no authorizing migration contract"
            ),
            Self::TwoOwners {
                canonical,
                first,
                second,
            } => write!(
                formatter,
                "{canonical} resolves to two owners: {first} and {second}"
            ),
            Self::DuplicateSpelling { spelling } => {
                write!(formatter, "spelling {spelling} is claimed twice")
            }
            Self::CanonicalAndAliasBothSet {
                canonical,
                canonical_value,
                alias,
                alias_value,
            } => write!(
                formatter,
                "{canonical} is set to {canonical_value} and its alias {alias} to \
                 {alias_value}; unset one rather than relying on precedence"
            ),
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
            Self::InvertedRange {
                component,
                min_supported,
                current,
            } => write!(
                formatter,
                "{component} declares min_supported {min_supported} above its current \
                 version {current}"
            ),
            Self::ZeroVersion { component, bound } => write!(
                formatter,
                "{component} declares a zero {bound}; the component starts at version 1"
            ),
        }
    }
}

impl Error for CompatError {}

/// The migration contract that authorizes one alias.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MigrationContract(String);

impl MigrationContract {
    /// Name the contract that authorizes a compatibility surface.
    ///
    /// # Errors
    ///
    /// Returns [`CompatError::Field`] for an invalid identifier.
    pub fn new(id: &str) -> Result<Self, CompatError> {
        bounded(id, "migration_contract")?;
        Ok(Self(id.to_owned()))
    }

    /// The contract identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A legacy spelling that forwards to a canonical name.
///
/// An alias cannot exist without an authorizing migration contract, so a
/// compatibility surface is always traceable to the decision that permitted it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyAlias {
    spelling: String,
    authorized_by: MigrationContract,
    retire_after: String,
}

impl LegacyAlias {
    /// Declare an authorized alias.
    ///
    /// # Errors
    ///
    /// Returns [`CompatError::Field`] for an invalid spelling or window.
    pub fn new(
        spelling: &str,
        authorized_by: MigrationContract,
        retire_after: &str,
    ) -> Result<Self, CompatError> {
        bounded(spelling, "alias_spelling")?;
        bounded(retire_after, "retire_after")?;
        Ok(Self {
            spelling: spelling.to_owned(),
            authorized_by,
            retire_after: retire_after.to_owned(),
        })
    }

    /// The legacy spelling.
    #[must_use]
    pub fn spelling(&self) -> &str {
        &self.spelling
    }

    /// The contract that authorized it.
    #[must_use]
    pub const fn authorized_by(&self) -> &MigrationContract {
        &self.authorized_by
    }

    /// The declared compatibility window.
    #[must_use]
    pub fn retire_after(&self) -> &str {
        &self.retire_after
    }
}

/// One name and every spelling that reaches it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameEntry {
    canonical: String,
    class: IdentifierClass,
    owner: String,
    durable_identity: String,
    aliases: Vec<LegacyAlias>,
}

impl NameEntry {
    /// Declare a canonical name with its runtime owner and durable identity.
    ///
    /// # Errors
    ///
    /// Returns [`CompatError::Field`] for an invalid component.
    pub fn new(
        canonical: &str,
        class: IdentifierClass,
        owner: &str,
        durable_identity: &str,
    ) -> Result<Self, CompatError> {
        bounded(canonical, "canonical")?;
        bounded(owner, "owner")?;
        bounded(durable_identity, "durable_identity")?;
        Ok(Self {
            canonical: canonical.to_owned(),
            class,
            owner: owner.to_owned(),
            durable_identity: durable_identity.to_owned(),
            aliases: Vec::new(),
        })
    }

    /// Add an authorized alias.
    #[must_use]
    pub fn with_alias(mut self, alias: LegacyAlias) -> Self {
        self.aliases.push(alias);
        self
    }

    /// The canonical spelling.
    #[must_use]
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// The identifier class.
    #[must_use]
    pub const fn class(&self) -> IdentifierClass {
        self.class
    }

    /// The single runtime owner.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The durable identity, which never changes for branding.
    #[must_use]
    pub fn durable_identity(&self) -> &str {
        &self.durable_identity
    }

    /// Every alias.
    #[must_use]
    pub fn aliases(&self) -> &[LegacyAlias] {
        &self.aliases
    }

    /// Rename the canonical spelling.
    ///
    /// The durable identity is deliberately not a parameter: a rename changes
    /// what the name is called and nothing about what it is.
    ///
    /// # Errors
    ///
    /// Returns [`CompatError::Field`] for an invalid spelling.
    pub fn renamed_to(&self, canonical: &str) -> Result<Self, CompatError> {
        bounded(canonical, "canonical")?;
        let mut renamed = self.clone();
        renamed.canonical = canonical.to_owned();
        Ok(renamed)
    }

    /// Every spelling that reaches this entry, canonical first.
    #[must_use]
    pub fn spellings(&self) -> Vec<&str> {
        let mut all = vec![self.canonical.as_str()];
        all.extend(self.aliases.iter().map(LegacyAlias::spelling));
        all
    }
}

/// What a spelling lookup found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpellingResolution<'a> {
    /// The canonical spelling.
    Canonical {
        /// The entry it names.
        entry: &'a NameEntry,
    },
    /// A legacy alias, with the observation an operator should see.
    Alias {
        /// The entry it forwards to.
        entry: &'a NameEntry,
        /// The deprecation observation.
        observation: DeprecationObservation,
    },
    /// Not a spelling this build knows.
    Unknown,
}

/// A record that a legacy spelling was used.
///
/// A value rather than a log line, so a client can surface it and an operator
/// can enumerate every alias still in use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeprecationObservation {
    alias: String,
    canonical: String,
    retire_after: String,
}

impl DeprecationObservation {
    /// The legacy spelling that was used.
    #[must_use]
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// The canonical spelling to migrate to.
    #[must_use]
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// The declared compatibility window.
    #[must_use]
    pub fn retire_after(&self) -> &str {
        &self.retire_after
    }
}

/// One row of the generated one-owner proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerRow {
    /// The spelling.
    pub spelling: String,
    /// Whether it is the canonical spelling.
    pub canonical: bool,
    /// The runtime owner it resolves to.
    pub owner: String,
    /// The durable identity it resolves to.
    pub durable_identity: String,
}

/// Every name, with its aliases.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NameRegistry {
    entries: Vec<NameEntry>,
}

impl NameRegistry {
    /// Start an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add an entry.
    ///
    /// # Errors
    ///
    /// Returns [`CompatError::AliasNotAuthorized`] if an alias lacks a
    /// contract, [`CompatError::DuplicateSpelling`] if any spelling is already
    /// claimed, and [`CompatError::TwoOwners`] if the entry would give one name
    /// two owners.
    pub fn insert(&mut self, entry: NameEntry) -> Result<(), CompatError> {
        for alias in &entry.aliases {
            if alias.authorized_by.as_str().is_empty() {
                return Err(CompatError::AliasNotAuthorized {
                    alias: alias.spelling.clone(),
                });
            }
        }
        if let Some(existing) = self
            .entries
            .iter()
            .find(|existing| existing.canonical == entry.canonical)
            && existing.owner != entry.owner
        {
            return Err(CompatError::TwoOwners {
                canonical: entry.canonical.clone(),
                first: existing.owner.clone(),
                second: entry.owner.clone(),
            });
        }
        for spelling in entry.spellings() {
            if self
                .entries
                .iter()
                .any(|existing| existing.spellings().contains(&spelling))
            {
                return Err(CompatError::DuplicateSpelling {
                    spelling: spelling.to_owned(),
                });
            }
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Every entry, in declaration order.
    ///
    /// Declaration order is what the generator emits in, so a reader can line
    /// the generated module up against the registry entry by entry.
    #[must_use]
    pub fn entries(&self) -> &[NameEntry] {
        &self.entries
    }

    /// Resolve one spelling.
    #[must_use]
    pub fn resolve(&self, spelling: &str) -> SpellingResolution<'_> {
        for entry in &self.entries {
            if entry.canonical == spelling {
                return SpellingResolution::Canonical { entry };
            }
            if let Some(alias) = entry
                .aliases
                .iter()
                .find(|alias| alias.spelling == spelling)
            {
                return SpellingResolution::Alias {
                    entry,
                    observation: DeprecationObservation {
                        alias: alias.spelling.clone(),
                        canonical: entry.canonical.clone(),
                        retire_after: alias.retire_after.clone(),
                    },
                };
            }
        }
        SpellingResolution::Unknown
    }

    /// Generate the one-owner proof table.
    ///
    /// Every spelling in the registry appears, with the owner and durable
    /// identity it resolves to. A reviewer checks the table rather than
    /// spot-checking entries.
    #[must_use]
    pub fn owner_table(&self) -> Vec<OwnerRow> {
        let mut rows: Vec<OwnerRow> = self
            .entries
            .iter()
            .flat_map(|entry| {
                entry.spellings().into_iter().map(move |spelling| OwnerRow {
                    spelling: spelling.to_owned(),
                    canonical: spelling == entry.canonical,
                    owner: entry.owner.clone(),
                    durable_identity: entry.durable_identity.clone(),
                })
            })
            .collect();
        rows.sort_by(|left, right| left.spelling.cmp(&right.spelling));
        rows
    }

    /// Every alias spelling the registry generates.
    ///
    /// A build compares its declared aliases against this set; anything
    /// hand-written that is not here has no authorizing entry.
    #[must_use]
    pub fn generated_aliases(&self) -> Vec<String> {
        let mut aliases: Vec<String> = self
            .entries
            .iter()
            .flat_map(|entry| entry.aliases.iter().map(|alias| alias.spelling.clone()))
            .collect();
        aliases.sort();
        aliases
    }

    /// Resolve configuration that may use either spelling.
    ///
    /// # Errors
    ///
    /// Returns [`CompatError::CanonicalAndAliasBothSet`] naming both spellings
    /// and both values. There is no precedence rule to fall back on.
    pub fn resolve_configuration(
        &self,
        settings: &[(&str, &str)],
    ) -> Result<Vec<(String, String, Option<DeprecationObservation>)>, CompatError> {
        let mut resolved: Vec<(String, String, Option<DeprecationObservation>)> = Vec::new();
        for (spelling, value) in settings {
            let (canonical, observation) = match self.resolve(spelling) {
                SpellingResolution::Canonical { entry } => (entry.canonical.clone(), None),
                SpellingResolution::Alias { entry, observation } => {
                    (entry.canonical.clone(), Some(observation))
                }
                SpellingResolution::Unknown => continue,
            };
            if let Some((_, existing_value, existing_observation)) = resolved
                .iter()
                .find(|(existing, _, _)| existing == &canonical)
            {
                let (canonical_spelling, canonical_value, alias, alias_value) =
                    if existing_observation.is_none() {
                        (
                            canonical.clone(),
                            existing_value.clone(),
                            (*spelling).to_owned(),
                            (*value).to_owned(),
                        )
                    } else {
                        (
                            canonical.clone(),
                            (*value).to_owned(),
                            existing_observation
                                .as_ref()
                                .map(|observed| observed.alias.clone())
                                .unwrap_or_default(),
                            existing_value.clone(),
                        )
                    };
                return Err(CompatError::CanonicalAndAliasBothSet {
                    canonical: canonical_spelling,
                    canonical_value,
                    alias,
                    alias_value,
                });
            }
            resolved.push((canonical, (*value).to_owned(), observation));
        }
        Ok(resolved)
    }
}

/// The migration contract that authorizes every alias declared below.
const MIGRATION_PLAN: &str = "docs/product-plan/reference/migration-plan.md";

/// The compatibility window every seeded alias declares.
const COMPATIBILITY_WINDOW: &str = "0.9.0";

/// The one registry this crate's canonical names and legacy aliases come from.
///
/// The entries are the compatibility surfaces
/// `docs/product-plan/reference/migration-plan.md` names, and that document is
/// the migration contract each alias cites. The registry is deliberately not
/// exhaustive: `R0-13` produces the classified identifier inventory this is
/// meant to be generated from, and until it exists an entry may only be added
/// with a named authorizing document, never because a spelling was convenient.
///
/// [`emit_registry_module`] turns this into `src/compat/generated.rs`, and
/// every canonical name and alias constant in the crate comes from there. A
/// spelling that is not declared here therefore has no constant to name.
///
/// # Panics
///
/// Panics if the declaration below is inconsistent — a spelling claimed twice,
/// or one canonical name given two owners. That is a mistake in this file
/// rather than a caller error, and it fails every test that touches the
/// registry;
/// `generated_from_the_registry::the_declared_registry_is_accepted_by_its_own_rules`
/// is the one that names it.
///
/// # Examples
///
/// Every alias the registry declares has a generated constant, and the constant
/// carries the same spelling the registry generates:
///
/// ```
/// use automonique_protocol::compat::{LegacyName, automonique_registry};
///
/// assert_eq!(LegacyName::LEGACY_RUNNER.spelling(), "LEGACY_RUNNER");
/// assert!(
///     automonique_registry()
///         .generated_aliases()
///         .contains(&"LEGACY_RUNNER".to_owned())
/// );
/// ```
///
/// A spelling the registry does not declare has no constant, so a hand-written
/// alias does not compile rather than becoming permanent by accident:
///
/// ```compile_fail
/// use automonique_protocol::compat::LegacyName;
///
/// let _ = LegacyName::LEGACY_RUNNER_OLD;
/// ```
#[must_use]
pub fn automonique_registry() -> NameRegistry {
    let mut registry = NameRegistry::new();
    for (canonical, class, owner, durable_identity, alias) in [
        (
            "AUTOMONIQUE_RUNNER",
            IdentifierClass::EnvironmentVariable,
            "automonique-runner",
            "durable:runner-selection",
            "LEGACY_RUNNER",
        ),
        (
            "automonique doctor",
            IdentifierClass::Command,
            "automonique-cli",
            "durable:doctor-report",
            "legacyctl",
        ),
        (
            "automonique audit",
            IdentifierClass::Command,
            "automonique-core",
            "durable:reconciliation-audit",
            "legacy:audit",
        ),
        (
            "automonique-shell",
            IdentifierClass::Command,
            "automonique-shell",
            "durable:shell-subsystem",
            "legacy-shell",
        ),
    ] {
        let contract = MigrationContract::new(MIGRATION_PLAN).expect("a declared contract path");
        let alias = LegacyAlias::new(alias, contract, COMPATIBILITY_WINDOW)
            .expect("a declared alias spelling and window");
        let entry = NameEntry::new(canonical, class, owner, durable_identity)
            .expect("a declared canonical name")
            .with_alias(alias);
        registry
            .insert(entry)
            .expect("the declared registry is consistent");
    }
    registry
}

/// Generate the Rust module that names every spelling in `registry`.
///
/// The output is `src/compat/generated.rs`. It is checked in so that the
/// spellings are readable and greppable without running anything, and
/// `generated_from_the_registry::the_checked_in_module_is_what_the_registry_generates`
/// compares it against a fresh generation and fails on any difference, so the
/// checked-in copy cannot drift away from the registry.
///
/// Generation is a pure string transformation: this crate performs no
/// filesystem operation, and the test that owns the file writes it.
///
/// The shape is written the way `rustfmt` leaves it — one match arm per line,
/// one constant per line — so that `cargo fmt --all -- --check` and this
/// generator agree. The single array, `ALL`, is emitted on one line only while
/// it fits inside rustfmt's array width, which is the one place the two could
/// otherwise disagree.
#[must_use]
pub fn emit_registry_module(registry: &NameRegistry) -> String {
    let entries = registry.entries();
    let aliases: Vec<(usize, &LegacyAlias)> = entries
        .iter()
        .enumerate()
        .flat_map(|(index, entry)| entry.aliases().iter().map(move |alias| (index, alias)))
        .collect();

    let mut out = String::new();
    out.push_str(GENERATED_HEADER);

    let canonical_spellings: Vec<&str> = entries.iter().map(NameEntry::canonical).collect();
    emit_names(
        &mut out,
        "CanonicalName",
        "canonical name",
        &canonical_spellings,
    );
    emit_accessor(
        &mut out,
        "spelling",
        "&'static str",
        "The canonical spelling.",
        &literals(&canonical_spellings),
    );
    emit_accessor(
        &mut out,
        "class",
        "IdentifierClass",
        "The identifier class this name belongs to.",
        &entries
            .iter()
            .map(|entry| class_path(entry.class()).to_owned())
            .collect::<Vec<String>>(),
    );
    emit_accessor(
        &mut out,
        "owner",
        "&'static str",
        "The single runtime owner every spelling of this name resolves to.",
        &literals(&entries.iter().map(NameEntry::owner).collect::<Vec<&str>>()),
    );
    emit_accessor(
        &mut out,
        "durable_identity",
        "&'static str",
        "The durable identity, which no rename of the canonical spelling moves.",
        &literals(
            &entries
                .iter()
                .map(NameEntry::durable_identity)
                .collect::<Vec<&str>>(),
        ),
    );
    out.push_str("}\n\n");

    let alias_spellings: Vec<&str> = aliases
        .iter()
        .map(|(_, alias)| alias.spelling())
        .collect::<Vec<&str>>();
    emit_names(&mut out, "LegacyName", "legacy alias", &alias_spellings);
    emit_accessor(
        &mut out,
        "spelling",
        "&'static str",
        "The legacy spelling.",
        &literals(&alias_spellings),
    );
    emit_accessor(
        &mut out,
        "canonical",
        "CanonicalName",
        "The canonical name this alias forwards to.",
        &aliases
            .iter()
            .map(|(entry_index, _)| {
                format!(
                    "CanonicalName::{}",
                    constant_name(entries[*entry_index].canonical())
                )
            })
            .collect::<Vec<String>>(),
    );
    emit_accessor(
        &mut out,
        "authorized_by",
        "&'static str",
        "The migration contract that authorized this alias.",
        &literals(
            &aliases
                .iter()
                .map(|(_, alias)| alias.authorized_by().as_str())
                .collect::<Vec<&str>>(),
        ),
    );
    emit_accessor(
        &mut out,
        "retire_after",
        "&'static str",
        "The declared compatibility window.",
        &literals(
            &aliases
                .iter()
                .map(|(_, alias)| alias.retire_after())
                .collect::<Vec<&str>>(),
        ),
    );
    out.push_str("}\n");
    out
}

const GENERATED_HEADER: &str = concat!(
    "// SPDX-License-Identifier: Elastic-2.0\n",
    "\n",
    "//! Canonical names and legacy aliases, generated from the one registry.\n",
    "//!\n",
    "//! GENERATED by `automonique_protocol::compat::emit_registry_module` from\n",
    "//! `automonique_protocol::compat::automonique_registry`. Do not edit by hand:\n",
    "//! regenerate with `AUTOMONIQUE_REGENERATE_COMPAT=1 cargo test -p\n",
    "//! automonique-protocol --test compat` and commit the result.\n",
    "//!\n",
    "//! Every spelling here is generated from one registry entry, and a spelling\n",
    "//! the registry does not declare has no constant — naming one does not\n",
    "//! compile, which is what stops a hand-written alias from becoming permanent\n",
    "//! by accident.\n",
    "\n",
    "use super::IdentifierClass;\n",
    "\n",
);

/// Emit the newtype, its constants and its `ALL` array.
fn emit_names(out: &mut String, type_name: &str, noun: &str, spellings: &[&str]) {
    out.push_str(&format!(
        "/// One {noun} declared by the registry.\n\
         ///\n\
         /// The index is private, so the only values that exist are the\n\
         /// constants below, one per registry entry.\n\
         #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]\n\
         pub struct {type_name}(usize);\n\
         \n\
         impl {type_name} {{\n"
    ));
    for (index, spelling) in spellings.iter().enumerate() {
        let constant = constant_name(spelling);
        out.push_str(&format!(
            "    /// The {noun} spelled `{spelling}`.\n    pub const {constant}: Self = \
             Self({index});\n"
        ));
    }
    let elements: Vec<String> = spellings
        .iter()
        .map(|spelling| format!("Self::{}", constant_name(spelling)))
        .collect();
    let count = elements.len();
    let one_line = format!(
        "    pub const ALL: [Self; {count}] = [{}];\n",
        elements.join(", ")
    );
    out.push_str(&format!("\n    /// Every {noun}, in registry order.\n"));
    // rustfmt keeps an array on one line only while it fits its array width.
    if one_line.trim_end().len() <= RUSTFMT_ARRAY_WIDTH {
        out.push_str(&one_line);
    } else {
        out.push_str(&format!("    pub const ALL: [Self; {count}] = [\n"));
        for element in &elements {
            out.push_str(&format!("        {element},\n"));
        }
        out.push_str("    ];\n");
    }
}

/// rustfmt's default `array_width`, the width under which it keeps an array on
/// one line.
const RUSTFMT_ARRAY_WIDTH: usize = 60;

/// Emit one `const fn` answering `expressions[index]`.
///
/// A registry of one entry is emitted without a match: `match self.0 { _ => x }`
/// is a match on a single binding, which strict Clippy refuses, and the plain
/// expression is what it asks for instead.
fn emit_accessor(
    out: &mut String,
    name: &str,
    return_type: &str,
    doc: &str,
    expressions: &[String],
) {
    out.push_str(&format!(
        "\n    /// {doc}\n    #[must_use]\n    pub const fn {name}(self) -> {return_type} {{\n"
    ));
    if let [only] = expressions {
        out.push_str(&format!("        {only}\n"));
    } else {
        out.push_str("        match self.0 {\n");
        for (index, expression) in expressions.iter().enumerate() {
            let arm = arm_pattern(index, expressions.len());
            out.push_str(&format!("            {arm} => {expression},\n"));
        }
        out.push_str("        }\n");
    }
    out.push_str("    }\n");
}

/// Quote each value as a Rust string literal.
fn literals(values: &[&str]) -> Vec<String> {
    values
        .iter()
        .map(|value| format!("\"{}\"", escaped(value)))
        .collect()
}

/// The match arm for `index`, with the last one catching the rest.
///
/// The index is private and every constructed value indexes a declared entry,
/// so the final arm is the only unreachable-free way to make the match total.
fn arm_pattern(index: usize, total: usize) -> String {
    if index + 1 == total {
        "_".to_owned()
    } else {
        index.to_string()
    }
}

/// The Rust path of an identifier class.
const fn class_path(class: IdentifierClass) -> &'static str {
    match class {
        IdentifierClass::EnvironmentVariable => "IdentifierClass::EnvironmentVariable",
        IdentifierClass::Command => "IdentifierClass::Command",
        IdentifierClass::ConfigurationKey => "IdentifierClass::ConfigurationKey",
        IdentifierClass::ProtocolName => "IdentifierClass::ProtocolName",
        IdentifierClass::SchemaName => "IdentifierClass::SchemaName",
        IdentifierClass::Metric => "IdentifierClass::Metric",
        IdentifierClass::TracingTarget => "IdentifierClass::TracingTarget",
        IdentifierClass::Route => "IdentifierClass::Route",
    }
}

/// The screaming-snake constant name for a spelling.
///
/// Every ASCII alphanumeric run becomes one segment, so `LEGACY_RUNNER`,
/// `legacy-shell`, `legacy:audit` and `automonique doctor` all have one obvious
/// constant. A spelling that produced an empty or digit-leading name is
/// prefixed, because neither is a Rust identifier.
fn constant_name(spelling: &str) -> String {
    let mut out = String::new();
    let mut pending_separator = false;
    for character in spelling.chars() {
        if character.is_ascii_alphanumeric() {
            if pending_separator && !out.is_empty() {
                out.push('_');
            }
            out.push(character.to_ascii_uppercase());
            pending_separator = false;
        } else {
            pending_separator = true;
        }
    }
    if out.is_empty() || out.starts_with(|character: char| character.is_ascii_digit()) {
        out.insert_str(0, "N_");
    }
    out
}

/// Escape a spelling for a Rust string literal.
///
/// A registry field cannot contain a control character — [`bounded`] refuses
/// one — so a backslash and a double quote are the whole escape set.
fn escaped(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn bounded(value: &str, field: &'static str) -> Result<(), CompatError> {
    crate::primitives::bounded_value(value, MAX_COMPAT_FIELD_BYTES)
        .map_err(|error| CompatError::Field { field, error })
}

/// Stable schema identifier for the rendered compatibility matrix.
pub const COMPATIBILITY_MATRIX_SCHEMA_V1: &str = "automonique.compat/v1";

/// One versioned surface this product admits a version of.
///
/// The vocabulary is closed and names only surfaces that carry a real version
/// number today. It is deliberately not a list of everything that might one day
/// be versioned: a component with no live constant behind it would make the
/// matrix a wish rather than a description.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Component {
    /// The `automonique.admin` control socket wire protocol.
    AdminProtocol,
    /// The release manifest document schema.
    ReleaseManifestSchema,
    /// The generated TypeScript SDK command surface.
    TypeScriptSdkSurface,
    /// The primary store's SQLite schema.
    StoreSchema,
    /// The cancel ledger sibling database schema.
    CancelLedgerSchema,
    /// The generation audit sibling database schema.
    GenerationAuditSchema,
    /// The provider journal sibling database schema.
    ProviderJournalSchema,
    /// The run submissions sibling database schema.
    RunSubmissionsSchema,
    /// The Slack ingress sibling database schema.
    SlackIngressSchema,
    /// The runner's `RunSpec` document.
    RunSpecDocument,
}

impl Component {
    /// Every component, for coverage checks.
    pub const ALL: [Self; 10] = [
        Self::AdminProtocol,
        Self::ReleaseManifestSchema,
        Self::TypeScriptSdkSurface,
        Self::StoreSchema,
        Self::CancelLedgerSchema,
        Self::GenerationAuditSchema,
        Self::ProviderJournalSchema,
        Self::RunSubmissionsSchema,
        Self::SlackIngressSchema,
        Self::RunSpecDocument,
    ];

    /// How many components the vocabulary names.
    pub const COUNT: usize = Self::ALL.len();

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdminProtocol => "admin_protocol",
            Self::ReleaseManifestSchema => "release_manifest_schema",
            Self::TypeScriptSdkSurface => "typescript_sdk_surface",
            Self::StoreSchema => "store_schema",
            Self::CancelLedgerSchema => "cancel_ledger_schema",
            Self::GenerationAuditSchema => "generation_audit_schema",
            Self::ProviderJournalSchema => "provider_journal_schema",
            Self::RunSubmissionsSchema => "run_submissions_schema",
            Self::SlackIngressSchema => "slack_ingress_schema",
            Self::RunSpecDocument => "run_spec_document",
        }
    }

    /// Position in [`Component::ALL`], which is how a matrix indexes its rows.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::AdminProtocol => 0,
            Self::ReleaseManifestSchema => 1,
            Self::TypeScriptSdkSurface => 2,
            Self::StoreSchema => 3,
            Self::CancelLedgerSchema => 4,
            Self::GenerationAuditSchema => 5,
            Self::ProviderJournalSchema => 6,
            Self::RunSubmissionsSchema => 7,
            Self::SlackIngressSchema => 8,
            Self::RunSpecDocument => 9,
        }
    }

    /// Where the version this component's range claims actually lives.
    #[must_use]
    pub const fn authority(self) -> VersionAuthority {
        match self {
            // Private, but its range is observable: an admin payload offering
            // an unsupported version is refused with `CodecError::
            // UnsupportedVersion`, which carries the live minimum and maximum.
            Self::AdminProtocol => VersionAuthority::Local {
                symbol: "automonique_protocol::admin::supported_protocol",
            },
            Self::ReleaseManifestSchema => VersionAuthority::Local {
                symbol: "automonique_protocol::release::MANIFEST_SCHEMA_REVISION",
            },
            Self::TypeScriptSdkSurface => VersionAuthority::Local {
                symbol: "automonique_protocol::codegen::maintained_modules",
            },
            Self::StoreSchema => VersionAuthority::Foreign {
                symbol: "automonique_store::SCHEMA_VERSION",
            },
            Self::CancelLedgerSchema => VersionAuthority::Foreign {
                symbol: "automonique_store::cancel_ledger::CANCEL_LEDGER_SCHEMA_VERSION",
            },
            Self::GenerationAuditSchema => VersionAuthority::Foreign {
                symbol: "automonique_store::generation_audit::GENERATION_AUDIT_SCHEMA_VERSION",
            },
            Self::ProviderJournalSchema => VersionAuthority::Foreign {
                symbol: "automonique_store::provider_journal::PROVIDER_JOURNAL_SCHEMA_VERSION",
            },
            Self::RunSubmissionsSchema => VersionAuthority::Foreign {
                symbol: "automonique_store::run_submissions::RUN_SUBMISSIONS_SCHEMA_VERSION",
            },
            Self::SlackIngressSchema => VersionAuthority::Foreign {
                symbol: "automonique_store::slack_ingress::SLACK_INGRESS_SCHEMA_VERSION",
            },
            Self::RunSpecDocument => VersionAuthority::Foreign {
                symbol: "automonique_runner::spec::RunSpec::protocol_version",
            },
        }
    }

    /// The range this tree declares for the component.
    ///
    /// An exhaustive match, so adding a component is a compile error until its
    /// bounds are declared rather than a row that quietly defaults to `1..=1`.
    const fn declared_bounds(self) -> (u32, u32) {
        match self {
            // Exactly the first version: `supported_protocol` declares
            // `VersionRange::new(MajorVersion::FIRST, MajorVersion::FIRST)`.
            Self::AdminProtocol => (1, 1),
            // `MAX_SUPPORTED_MANIFEST_SCHEMA == MANIFEST_SCHEMA_REVISION == 1`.
            Self::ReleaseManifestSchema => (1, 1),
            // The generated admin command surface speaks `MajorVersion::FIRST`
            // and admits no other.
            Self::TypeScriptSdkSurface => (1, 1),
            // `SCHEMA_VERSION` is 10, and the numbered migrations run an
            // unbroken v1 -> v2 -> ... -> v10 chain, so a v1 file still opens.
            Self::StoreSchema => (1, 10),
            // These sibling databases remain on their first schema.
            Self::CancelLedgerSchema | Self::GenerationAuditSchema | Self::RunSubmissionsSchema => {
                (1, 1)
            }
            // Slack ingress v2 adds provenance and migrates v1 files in place.
            Self::SlackIngressSchema => (1, 2),
            // Provider journal v4 adds deterministic replay after v3 provenance.
            Self::ProviderJournalSchema => (1, 4),
            // `RunSpec` admission refuses any `protocol_version` but 1.
            Self::RunSpecDocument => (1, 1),
        }
    }
}

impl fmt::Display for Component {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Where a component's live version constant lives, relative to this crate.
///
/// The distinction is the honest part of the matrix. A local claim is checkable
/// here; a foreign one is an assertion this crate cannot verify, because
/// `automonique-protocol` is dependency-free by design and cannot import the
/// store or the runner to look.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum VersionAuthority {
    /// The authority is visible from this crate, so a test here compares
    /// against it directly.
    Local {
        /// Path of the authoritative symbol.
        symbol: &'static str,
    },
    /// The authority lives in a crate this one cannot depend on.
    ///
    /// The matrix carries the expected value and names the symbol; a test in
    /// the owning crate pinning [`matrix_manifest`] is what would close the
    /// loop, and none exists yet.
    Foreign {
        /// Path of the authoritative symbol.
        symbol: &'static str,
    },
}

impl VersionAuthority {
    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local { .. } => "local",
            Self::Foreign { .. } => "foreign",
        }
    }

    /// The authoritative symbol's path.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Local { symbol } | Self::Foreign { symbol } => symbol,
        }
    }

    /// Whether a test in this crate can compare the claim against the source.
    #[must_use]
    pub const fn is_checkable_here(self) -> bool {
        matches!(self, Self::Local { .. })
    }
}

/// One component at one version.
///
/// A version bound to the component it is a version of, so an admin protocol
/// version cannot be passed where a store schema version belongs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ComponentVersion {
    component: Component,
    version: MajorVersion,
}

impl ComponentVersion {
    /// Name a component at a version.
    #[must_use]
    pub const fn new(component: Component, version: MajorVersion) -> Self {
        Self { component, version }
    }

    /// Name a component at a version read off a wire.
    ///
    /// # Errors
    ///
    /// Returns [`CompatError::ZeroVersion`] for zero, which is the only value
    /// [`MajorVersion::new`] refuses.
    pub fn offered(component: Component, version: u32) -> Result<Self, CompatError> {
        Ok(Self::new(
            component,
            checked_version(component, version, "offered")?,
        ))
    }

    /// The component.
    #[must_use]
    pub const fn component(self) -> Component {
        self.component
    }

    /// The version.
    #[must_use]
    pub const fn version(self) -> MajorVersion {
        self.version
    }
}

impl fmt::Display for ComponentVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}@{}", self.component, self.version)
    }
}

/// The versions of one component this tree admits.
///
/// The range is `[min_supported, current]`, where `current` is the live version
/// this tree runs and is also the highest version it admits without reservation.
/// The bounds are inclusive and both are at least one, so an empty range is
/// unrepresentable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CompatibilityRange {
    component: Component,
    supported: VersionRange,
}

impl CompatibilityRange {
    /// Declare the range for one component.
    ///
    /// # Errors
    ///
    /// Returns [`CompatError::ZeroVersion`] when either bound is zero and
    /// [`CompatError::InvertedRange`] when `min_supported` is above `current`.
    /// A build cannot claim to support versions below a floor it has already
    /// passed, and there is no bound-swapping repair: an inverted declaration
    /// is a mistake about what shipped, not a typo to fix silently.
    pub fn new(
        component: Component,
        min_supported: u32,
        current: u32,
    ) -> Result<Self, CompatError> {
        let min = checked_version(component, min_supported, "min_supported")?;
        let max = checked_version(component, current, "current")?;
        let supported = VersionRange::new(min, max).map_err(|_| CompatError::InvertedRange {
            component,
            min_supported,
            current,
        })?;
        Ok(Self {
            component,
            supported,
        })
    }

    /// The component this range describes.
    #[must_use]
    pub const fn component(self) -> Component {
        self.component
    }

    /// The lowest version this tree still admits.
    #[must_use]
    pub const fn min_supported(self) -> MajorVersion {
        self.supported.min()
    }

    /// The live version this tree runs.
    #[must_use]
    pub const fn current(self) -> MajorVersion {
        self.supported.max()
    }

    /// The range as the crate's shared version-range value.
    #[must_use]
    pub const fn supported(self) -> VersionRange {
        self.supported
    }

    /// Decide what an offered version is entitled to.
    ///
    /// The bands are documented on [`CompatVerdict`].
    #[must_use]
    pub const fn assess(self, offered: MajorVersion) -> CompatVerdict {
        let at = ComponentVersion::new(self.component, offered);
        if self.supported.accepts(offered) {
            return CompatVerdict::Compatible { offered: at };
        }
        if offered.get() < self.supported.min().get() {
            return CompatVerdict::Incompatible {
                refusal: CompatRefusal {
                    offered: at,
                    supported: self.supported,
                    reason: RefusalReason::BelowMinimumSupported,
                },
            };
        }
        // Above the range, so the subtraction cannot wrap. One release of
        // distance is the whole tolerated band; see `CompatVerdict`.
        if offered.get() - self.supported.max().get() == 1 {
            return CompatVerdict::ReadOnlyCompatible {
                upgrade_required: UpgradeRequirement {
                    offered: at,
                    supported: self.supported,
                },
            };
        }
        CompatVerdict::Incompatible {
            refusal: CompatRefusal {
                offered: at,
                supported: self.supported,
                reason: RefusalReason::BeyondAdjacentRelease,
            },
        }
    }
}

impl fmt::Display for CompatibilityRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {}..={}",
            self.component,
            self.supported.min(),
            self.supported.max()
        )
    }
}

/// What an offered version is entitled to.
///
/// The three bands come from one sentence in
/// `docs/product-plan/requirements/state-and-protocols.md`: "Additive fields
/// and unknown read-only events are tolerated across adjacent releases;
/// incompatible clients are read-only and receive an explicit upgrade
/// requirement."
///
/// - Inside `[min_supported, current]`: [`CompatVerdict::Compatible`]. Nothing
///   to reconcile.
/// - Exactly `current + 1`: [`CompatVerdict::ReadOnlyCompatible`]. This is a
///   peer one release ahead of this build, which is what an N -> N+1 rolling
///   upgrade produces and the only distance the requirement calls adjacent.
///   Reads are served, mutation is not, and the verdict carries the explicit
///   upgrade requirement the sentence demands.
/// - Below `min_supported`, or above `current + 1`:
///   [`CompatVerdict::Incompatible`], carrying a refusal that names both
///   versions and which side has to move.
///
/// Read-only is offered only where this build can genuinely still decode. Below
/// `min_supported` the decoders for that dialect are gone, so offering reads
/// would be a claim the build cannot honour; above `current + 1` nothing in the
/// requirement claims tolerance across two generations, and inventing it is the
/// silent downgrade the house forbids.
///
/// Tolerance of *additive fields* is not modelled here, because it is not a
/// property of a range. It is a property of the decoders: `codec::ReadOnly`
/// preserves an unknown read-only enum spelling without giving it meaning,
/// while `codec::SecuritySensitiveEnum` refuses one. A flag on this matrix
/// claiming "additive fields tolerated" would assert something the matrix has
/// no way to know.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatVerdict {
    /// Inside the supported range.
    Compatible {
        /// The version that was assessed.
        offered: ComponentVersion,
    },
    /// One release ahead: readable, not mutable, and told to upgrade.
    ReadOnlyCompatible {
        /// What has to change, naming both versions.
        upgrade_required: UpgradeRequirement,
    },
    /// Outside every tolerated band.
    Incompatible {
        /// Why, naming both versions.
        refusal: CompatRefusal,
    },
}

impl CompatVerdict {
    /// The version that was assessed.
    #[must_use]
    pub const fn offered(&self) -> ComponentVersion {
        match self {
            Self::Compatible { offered } => *offered,
            Self::ReadOnlyCompatible { upgrade_required } => upgrade_required.offered,
            Self::Incompatible { refusal } => refusal.offered,
        }
    }

    /// Stable machine-readable outcome.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Compatible { .. } => "compatible",
            Self::ReadOnlyCompatible { .. } => "read_only_compatible",
            Self::Incompatible { .. } => "incompatible",
        }
    }

    /// Whether reads may be served.
    #[must_use]
    pub const fn may_read(&self) -> bool {
        matches!(
            self,
            Self::Compatible { .. } | Self::ReadOnlyCompatible { .. }
        )
    }

    /// Whether mutations may be accepted.
    ///
    /// Only full compatibility grants this, so no verdict admits a write under
    /// a dialect this build does not entirely define.
    #[must_use]
    pub const fn may_mutate(&self) -> bool {
        matches!(self, Self::Compatible { .. })
    }
}

/// The explicit upgrade requirement a read-only peer receives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpgradeRequirement {
    offered: ComponentVersion,
    supported: VersionRange,
}

impl UpgradeRequirement {
    /// The version that was assessed.
    #[must_use]
    pub const fn offered(self) -> ComponentVersion {
        self.offered
    }

    /// The range this build supports.
    #[must_use]
    pub const fn supported(self) -> VersionRange {
        self.supported
    }

    /// The version this build has to reach to serve the peer fully.
    #[must_use]
    pub const fn upgrade_to(self) -> MajorVersion {
        self.offered.version()
    }

    /// The requirement in words, naming both versions.
    #[must_use]
    pub fn note(&self) -> String {
        format!(
            "{} offered version {}; this build supports {}..={}. Reads are served and \
             mutations are refused until this build reaches version {}.",
            self.offered.component(),
            self.offered.version(),
            self.supported.min(),
            self.supported.max(),
            self.upgrade_to()
        )
    }
}

impl fmt::Display for UpgradeRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.note())
    }
}

/// Why an offered version was refused outright.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompatRefusal {
    offered: ComponentVersion,
    supported: VersionRange,
    reason: RefusalReason,
}

impl CompatRefusal {
    /// The version that was assessed.
    #[must_use]
    pub const fn offered(self) -> ComponentVersion {
        self.offered
    }

    /// The range this build supports.
    #[must_use]
    pub const fn supported(self) -> VersionRange {
        self.supported
    }

    /// Which band the version fell outside.
    #[must_use]
    pub const fn reason(self) -> RefusalReason {
        self.reason
    }

    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        self.reason.as_str()
    }

    /// The refusal in words, naming both versions and which side has to move.
    #[must_use]
    pub fn note(&self) -> String {
        let component = self.offered.component();
        let offered = self.offered.version();
        let min = self.supported.min();
        let max = self.supported.max();
        match self.reason {
            RefusalReason::BelowMinimumSupported => format!(
                "{component} offered version {offered}; this build supports {min}..={max} \
                 and no longer decodes {offered}. Upgrade the peer to at least version \
                 {min}."
            ),
            RefusalReason::BeyondAdjacentRelease => format!(
                "{component} offered version {offered}; this build supports {min}..={max}. \
                 Only version {} is tolerated read-only, so upgrade this build to version \
                 {offered}.",
                max.get().saturating_add(1)
            ),
        }
    }
}

impl fmt::Display for CompatRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.note())
    }
}

/// Which side of the supported range a refused version fell on.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RefusalReason {
    /// Older than the oldest version this build still decodes.
    BelowMinimumSupported,
    /// Newer than the one adjacent release this build tolerates.
    BeyondAdjacentRelease,
}

impl RefusalReason {
    /// Every reason, for coverage checks.
    pub const ALL: [Self; 2] = [Self::BelowMinimumSupported, Self::BeyondAdjacentRelease];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BelowMinimumSupported => "below_minimum_supported",
            Self::BeyondAdjacentRelease => "beyond_adjacent_release",
        }
    }
}

/// Every component's supported range, one row each.
///
/// Indexed by [`Component::index`], so every component has a row and a lookup
/// cannot miss.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompatibilityMatrix {
    rows: [CompatibilityRange; Component::COUNT],
}

impl CompatibilityMatrix {
    /// The range declared for one component.
    #[must_use]
    pub const fn range(&self, component: Component) -> CompatibilityRange {
        self.rows[component.index()]
    }

    /// Every range, in [`Component::ALL`] order.
    #[must_use]
    pub const fn rows(&self) -> &[CompatibilityRange] {
        &self.rows
    }

    /// Decide what an offered version of a component is entitled to.
    #[must_use]
    pub const fn assess(&self, component: Component, offered: MajorVersion) -> CompatVerdict {
        self.range(component).assess(offered)
    }

    /// Render the matrix as stable text.
    ///
    /// One header line naming [`COMPATIBILITY_MATRIX_SCHEMA_V1`], then one line
    /// per component sorted by wire spelling:
    /// `<component> <min>..=<current> <local|foreign> <symbol>`.
    ///
    /// Sorted by spelling rather than emitted in [`Component::ALL`] order, so
    /// reordering the enum — which changes nothing about what is supported —
    /// cannot change the rendering a downstream test has pinned.
    #[must_use]
    pub fn manifest(&self) -> String {
        let mut lines: Vec<String> = self
            .rows
            .iter()
            .map(|row| {
                let authority = row.component().authority();
                format!(
                    "{} {}..={} {} {}",
                    row.component(),
                    row.min_supported(),
                    row.current(),
                    authority.as_str(),
                    authority.symbol()
                )
            })
            .collect();
        lines.sort();
        let mut out = String::from(COMPATIBILITY_MATRIX_SCHEMA_V1);
        for line in lines {
            out.push('\n');
            out.push_str(&line);
        }
        out.push('\n');
        out
    }
}

/// The matrix this tree ships.
///
/// # What this proves, and what it does not
///
/// The matrix *describes* the ranges this tree supports. Nothing enforces it at
/// any daemon boundary today: the admin socket still admits versions through
/// `admin::supported_protocol`, the store through its own numbered migrations,
/// and the runner through `RunSpec` admission. A later slice adopts
/// [`CompatVerdict`] at those boundaries; until then a disagreement between the
/// matrix and a boundary shows up as a failing cross-check here, not as a
/// changed refusal in production.
///
/// Rows whose authority is [`VersionAuthority::Local`] are checked against the
/// live constant by `tests/compat.rs`. Rows whose authority is
/// [`VersionAuthority::Foreign`] are assertions: `automonique-protocol` is
/// dependency-free by design and cannot import `automonique-store` or
/// `automonique-runner` to look. They are kept true by discipline and by
/// [`matrix_manifest`], which a test in the owning crate can pin against its
/// own constants. No such test exists yet, and that is the open gap.
///
/// # Panics
///
/// Panics if a declared range in [`Component::declared_bounds`] is inconsistent
/// — a zero bound, or a minimum above the current version. That is a mistake in
/// this file rather than a caller error, and it fails every test that touches
/// the matrix.
///
/// # Examples
///
/// A version inside the range mutates; the one release above it reads only:
///
/// ```
/// use automonique_protocol::codec::MajorVersion;
/// use automonique_protocol::compat::{Component, shipped_matrix};
///
/// let matrix = shipped_matrix();
/// let current = matrix.range(Component::StoreSchema).current();
/// assert!(matrix.assess(Component::StoreSchema, current).may_mutate());
///
/// let next = MajorVersion::new(current.get() + 1).expect("nonzero");
/// let verdict = matrix.assess(Component::StoreSchema, next);
/// assert!(verdict.may_read());
/// assert!(!verdict.may_mutate());
/// ```
#[must_use]
pub fn shipped_matrix() -> CompatibilityMatrix {
    CompatibilityMatrix {
        rows: Component::ALL.map(|component| {
            let (min_supported, current) = component.declared_bounds();
            CompatibilityRange::new(component, min_supported, current)
                .expect("the declared matrix is consistent")
        }),
    }
}

/// The shipped matrix rendered as stable text.
///
/// See [`CompatibilityMatrix::manifest`] for the format and
/// [`shipped_matrix`] for what pinning it does and does not prove.
#[must_use]
pub fn matrix_manifest() -> String {
    shipped_matrix().manifest()
}

/// Build a version, refusing zero.
///
/// `MajorVersion::new` refuses zero and nothing else, so the discarded error
/// carries no information this one does not.
fn checked_version(
    component: Component,
    value: u32,
    bound: &'static str,
) -> Result<MajorVersion, CompatError> {
    MajorVersion::new(value).map_err(|_| CompatError::ZeroVersion { component, bound })
}
