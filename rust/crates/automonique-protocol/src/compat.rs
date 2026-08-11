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

use core::fmt;
use std::error::Error;

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
    let error = if value.is_empty() {
        Some(ValueError::Empty)
    } else if value.len() > MAX_COMPAT_FIELD_BYTES {
        Some(ValueError::TooLong {
            max_bytes: MAX_COMPAT_FIELD_BYTES,
            actual_bytes: value.len(),
        })
    } else if value.chars().any(char::is_control) {
        Some(ValueError::ControlCharacter)
    } else {
        None
    };
    match error {
        Some(error) => Err(CompatError::Field { field, error }),
        None => Ok(()),
    }
}
