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
