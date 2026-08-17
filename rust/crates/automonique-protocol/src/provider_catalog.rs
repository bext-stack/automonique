// SPDX-License-Identifier: Elastic-2.0

//! The provider/model plugin catalog: which providers and models this control
//! plane knows, as data.
//!
//! `docs/product-plan/requirements/models-media-and-execution.md` § Model and
//! provider catalog asks for "a normalized catalog for built-in Jcode, Claude,
//! Codex and opencode plus direct/custom model providers", where "provider
//! plugins declare models, modalities, context/output limits, reasoning
//! controls, tool/structured-output support, regions/data policy, pricing and
//! auth methods" and conformance information.
//!
//! Two of those layers already exist and are reused rather than restated:
//!
//! - [`crate::models`] owns everything *per model* — [`ModelCatalogEntry`]
//!   carries modalities, limits, reasoning, tools, structured output, region,
//!   sovereignty zone, data policy, pricing and auth method, and refuses an
//!   entry that omits any of them.
//! - [`crate::provider`] owns everything *per binding* —
//!   [`ModeDeclaration`] carries the capability sets observed for one
//!   integration mode against one [`BinaryProvenance`], and [`Selection`] is
//!   the only proof that a mode was admitted.
//!
//! What was missing is the registry that binds them: which provider *kinds*
//! this build knows, which binary each was observed as, which integration
//! modes it declares, which models it offers, which event dialect its runner
//! events are spelled in, and whether a conformance record exists for the exact
//! coordinates the plan keys conformance by. That is this module.
//!
//! # What a registration is not
//!
//! `docs/product-plan/requirements/agent-integrations.md` closes with the rule
//! this module is built around: "Conformance results are keyed by provider
//! binary digest, version, integration mode, schema hash and Automonique
//! adapter version. A binary digest without a passing record cannot become the
//! production native adapter automatically."
//!
//! So registration and conformance are separate. A [`ProviderCatalogEntry`]
//! says a provider is *known*; only [`ProviderCatalogEntry::admit_native`]
//! says a mode may be used as the native adapter, and it refuses unless a
//! [`ConformanceRecord`] exists for that exact binary, version, schema hash,
//! mode and adapter version — and passed.
//!
//! A [`NativeAdmission`] cannot be fabricated, only returned:
//!
//! ```compile_fail
//! use automonique_protocol::provider_catalog::NativeAdmission;
//! let admitted = NativeAdmission { mode: String::new(), adapter_version: String::new() };
//! ```
//!
//! # Honest present
//!
//! This module describes what is registered. It verifies nothing:
//!
//! - it opens no file, hashes no bytes and runs no conformance suite. A
//!   [`ConformanceRecord`] is a caller's claim, recorded with the coordinates
//!   that make it checkable elsewhere, not a measurement taken here;
//! - it carries no executable path and no process handle, so nothing obtained
//!   from it can be launched. The pinned digest travels; the path is the
//!   spawn layer's business (see the counterpart note on
//!   [`ProviderCatalogEntry::executable_sha256_hex`]);
//! - it installs, downloads, signs and revokes nothing. The plan's catalog
//!   browsing rule — "Catalog browsing never installs code"
//!   (`docs/product-plan/requirements/tools-extensions-and-hooks.md`) and
//!   "Catalog/marketplace metadata is not trust"
//!   (`docs/product-plan/requirements/operations-and-governance.md`) — holds
//!   here trivially, because there is no code path that could.
//!
//! # Divergences from the plan's catalog
//!
//! Named rather than silently approximated:
//!
//! - **Four built-in providers, one registerable kind.** The plan names Jcode,
//!   Claude, Codex and opencode. [`ProviderKind`] has one variant, matching
//!   `automonique_agents::spawn_plan::ProviderKind`: a provider kind is an argv
//!   contract plus an event vocabulary, and this tree has established exactly
//!   one of each. The other three are not accepted as free text — they are
//!   listed in [`PLANNED_PROVIDER_KINDS`] and [`ProviderKind::resolve`] refuses
//!   them with [`CatalogError::PlannedProviderKind`], which names the gap
//!   instead of pretending it is closed.
//! - **Direct/custom model providers and custom endpoints** (R14-01) are
//!   therefore unrepresentable. A caller cannot register an endpoint URL; there
//!   is no field for one.
//! - **Marketplaces, dynamic plugins and remote registries** — the SPI of
//!   `docs/product-plan/requirements/external-capability-ledger.md` R1-24
//!   ("Provider catalog/SPI alongside primary Jcode/Claude/Codex/opencode
//!   adapters") — have no representation. Entries are values a caller
//!   constructs in-process.
//! - **Aliases** are not re-modelled: [`crate::models::AliasProfile`] already
//!   binds them at a recorded revision. [`ProviderCatalog::admits_model`] is
//!   the seam — hand it an alias target and it says whether a registered
//!   provider offers that model.
//! - **The rendered inventory omits pricing, auth, reasoning and tool
//!   support.** [`crate::models`] defines no stable wire spelling for
//!   [`crate::models::PricingUnit`], [`crate::models::AuthMethod`],
//!   [`crate::models::ReasoningControl`], [`crate::models::ToolSupport`] or
//!   [`crate::models::StructuredOutputSupport`], and inventing a second
//!   spelling authority here is exactly the drift the house forbids. The data
//!   is carried — [`ProviderCatalogEntry::model`] returns the whole
//!   [`ModelCatalogEntry`] — it is only the text rendering that stops at fields
//!   whose spelling already has an owner.
//! - This vocabulary sits beside `models.rs` in `automonique-protocol`, where
//!   the model and provider catalog values it extends live.
//!
//! # Cross-crate spellings this crate cannot import
//!
//! `automonique-protocol` is dependency-free by design, so two vocabularies
//! defined elsewhere are mirrored here as assertions rather than imports:
//! [`ProviderKind`] against `automonique_agents::spawn_plan::ProviderKind`,
//! and [`RunnerEventDialect`] against
//! `automonique_runner::spec_fields::RunnerEventDialect`. Both are pinned by
//! literal in `tests/provider_catalog.rs`; a rename on either side shows up as
//! a failing assertion in the owning crate's suite or in that test, not as a
//! silently divergent spelling. This is the same honest gap
//! [`crate::compat`] records for its foreign matrix rows.

use core::fmt;
use core::marker::PhantomData;
use std::error::Error;

use crate::models::{Modality, ModelCatalogEntry, ModelRef};
use crate::primitives::ValueError;
use crate::provider::{BinaryProvenance, ModeDeclaration, ProviderError, Selection};
use crate::sandbox::Digest;

/// Stable schema identifier for the rendered inventory.
pub const PROVIDER_CATALOG_SCHEMA_V1: &str = "automonique.provider-catalog/v1";

/// Maximum UTF-8 byte length of a catalog field this module owns.
pub const MAX_CATALOG_FIELD_BYTES: usize = 128;

/// Maximum integration modes one provider entry may declare.
pub const MAX_MODES_PER_ENTRY: usize = 8;

/// Maximum models one provider entry may offer.
pub const MAX_MODELS_PER_ENTRY: usize = 256;

/// Maximum conformance records one provider entry may carry.
pub const MAX_CONFORMANCE_RECORDS_PER_ENTRY: usize = 32;

/// Provider kinds the plan names that this build cannot register.
///
/// Listed so a caller naming one gets [`CatalogError::PlannedProviderKind`] —
/// "the plan asks for this and no adapter exists yet" — rather than
/// [`CatalogError::UnknownProviderKind`], which would be a lie about a
/// documented requirement. Sourced from
/// `docs/product-plan/requirements/models-media-and-execution.md` § Model and
/// provider catalog.
pub const PLANNED_PROVIDER_KINDS: [&str; 3] = ["claude", "jcode", "opencode"];

/// A provider kind this control plane can register.
///
/// Deliberately one variant, mirroring
/// `automonique_agents::spawn_plan::ProviderKind`. A kind is not a label: it is
/// an argv contract plus an event vocabulary, and adding one means adding both
/// with the fixtures that pin them. There is no constructor from arbitrary
/// text; [`ProviderKind::resolve`] is the only way in from a string, and it
/// refuses everything outside this enum.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProviderKind {
    /// The Codex CLI.
    Codex,
}

impl ProviderKind {
    /// Every registerable kind, in canonical order.
    pub const ALL: [Self; 1] = [Self::Codex];

    /// Stable lowercase spelling.
    ///
    /// Identical to the counterpart in `automonique-agents`, which this crate
    /// cannot import; see the module's cross-crate note.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    ///
    /// The typed-`None` lookup. Use [`ProviderKind::resolve`] when the caller
    /// deserves to know *why* a spelling was rejected.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }

    /// Resolve a spelling to a registerable kind, or say why not.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::Value`] for a spelling outside the bounded
    /// grammar, [`CatalogError::PlannedProviderKind`] for one of
    /// [`PLANNED_PROVIDER_KINDS`], and [`CatalogError::UnknownProviderKind`]
    /// otherwise.
    pub fn resolve(value: &str) -> Result<Self, CatalogError> {
        bounded(value, "provider_kind")?;
        if let Some(kind) = Self::from_spelling(value) {
            return Ok(kind);
        }
        if PLANNED_PROVIDER_KINDS.contains(&value) {
            return Err(CatalogError::PlannedProviderKind {
                name: value.to_owned(),
            });
        }
        Err(CatalogError::UnknownProviderKind {
            name: value.to_owned(),
        })
    }
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The event dialect a registered provider's normalized events are spelled in.
///
/// Mirrors `automonique_runner::spec_fields::RunnerEventDialect`, which this
/// dependency-free crate cannot import. One variant, one spelling, pinned by
/// literal in the test suite.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RunnerEventDialect {
    /// The Automonique runner's version-one normalized event vocabulary.
    AutomoniqueRunnerV1,
}

impl RunnerEventDialect {
    /// Every dialect, in canonical order.
    pub const ALL: [Self; 1] = [Self::AutomoniqueRunnerV1];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutomoniqueRunnerV1 => "automonique_runner_v1",
        }
    }

    /// Parse the exact stable spelling.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|dialect| dialect.as_str() == value)
    }
}

/// What a conformance run concluded.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConformanceOutcome {
    /// The suite ran against these coordinates and passed.
    Passed,
    /// The suite ran against these coordinates and failed.
    Failed,
}

impl ConformanceOutcome {
    /// Every outcome, for coverage checks.
    pub const ALL: [Self; 2] = [Self::Passed, Self::Failed];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
        }
    }
}

/// Why a catalog operation was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogError {
    /// A spelling this build has never defined.
    UnknownProviderKind {
        /// The rejected spelling.
        name: String,
    },
    /// A spelling the product plan names and no adapter implements yet.
    PlannedProviderKind {
        /// The planned spelling.
        name: String,
    },
    /// The kind is registerable but this catalog has no entry for it.
    ProviderAbsent {
        /// The absent kind.
        kind: ProviderKind,
    },
    /// The registered provider does not offer that model.
    ModelNotOffered {
        /// The requested model coordinate.
        model: String,
    },
    /// The entry declares no such integration mode.
    ModeNotRegistered {
        /// The requested mode.
        mode: String,
    },
    /// Two entries claimed the same provider kind.
    DuplicateProviderKind {
        /// The repeated kind.
        kind: ProviderKind,
    },
    /// One entry declared the same integration mode twice.
    DuplicateMode {
        /// The repeated mode.
        mode: String,
    },
    /// One entry offered the same model twice.
    DuplicateModel {
        /// The repeated model coordinate.
        model: String,
    },
    /// Two conformance records claimed the same mode and adapter version.
    DuplicateConformance {
        /// The repeated mode.
        mode: String,
        /// The repeated adapter version.
        adapter_version: String,
    },
    /// A field without which the entry would describe nothing was absent.
    Required {
        /// The absent field.
        field: &'static str,
    },
    /// A bounded collection exceeded its ceiling.
    TooMany {
        /// The collection.
        field: &'static str,
        /// Maximum accepted.
        max: usize,
    },
    /// A bounded value was rejected.
    Value {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
    /// A mode's capabilities were observed against a different binary.
    ModeProvenanceMismatch {
        /// The offending mode.
        mode: String,
        /// The component that differs.
        field: &'static str,
    },
    /// A conformance record names a different binary than the entry's.
    ConformanceProvenanceMismatch {
        /// The record's mode.
        mode: String,
        /// The component that differs.
        field: &'static str,
    },
    /// A model's own provider spelling is not the kind it was registered under.
    ModelProviderMismatch {
        /// The offending model coordinate.
        model: String,
        /// The provider the model names.
        declared: String,
        /// The kind the entry registers.
        expected: &'static str,
    },
    /// A capability declaration or selection was refused by [`crate::provider`].
    Mode {
        /// The underlying refusal.
        error: ProviderError,
    },
    /// No conformance record exists for these coordinates.
    NotConformant {
        /// The mode asked for.
        mode: String,
        /// The adapter version asked for.
        adapter_version: String,
    },
    /// A conformance record exists for these coordinates and it failed.
    ConformanceFailed {
        /// The mode asked for.
        mode: String,
        /// The adapter version asked for.
        adapter_version: String,
    },
    /// A digest that [`BinaryProvenance`] had already accepted did not parse.
    ///
    /// Structurally unreachable while [`BinaryProvenance::new`] validates its
    /// own digest against [`Digest`]. Kept as a refusal rather than a panic so
    /// that a later relaxation there surfaces here as a rejected registration.
    DigestUnparsable {
        /// The field that would not parse.
        field: &'static str,
    },
}

impl CatalogError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::UnknownProviderKind { .. } => "unknown_provider_kind",
            Self::PlannedProviderKind { .. } => "planned_provider_kind",
            Self::ProviderAbsent { .. } => "provider_absent",
            Self::ModelNotOffered { .. } => "model_not_offered",
            Self::ModeNotRegistered { .. } => "mode_not_registered",
            Self::DuplicateProviderKind { .. } => "duplicate_provider_kind",
            Self::DuplicateMode { .. } => "duplicate_mode",
            Self::DuplicateModel { .. } => "duplicate_model",
            Self::DuplicateConformance { .. } => "duplicate_conformance",
            Self::Required { .. } => "required",
            Self::TooMany { .. } => "too_many",
            Self::Value { .. } => "value_invalid",
            Self::ModeProvenanceMismatch { .. } => "mode_provenance_mismatch",
            Self::ConformanceProvenanceMismatch { .. } => "conformance_provenance_mismatch",
            Self::ModelProviderMismatch { .. } => "model_provider_mismatch",
            Self::Mode { .. } => "mode_refused",
            Self::NotConformant { .. } => "not_conformant",
            Self::ConformanceFailed { .. } => "conformance_failed",
            Self::DigestUnparsable { .. } => "digest_unparsable",
        }
    }
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProviderKind { name } => {
                write!(
                    formatter,
                    "provider kind {name} is not defined by this build"
                )
            }
            Self::PlannedProviderKind { name } => write!(
                formatter,
                "provider kind {name} is named by the product plan and has no adapter yet"
            ),
            Self::ProviderAbsent { kind } => {
                write!(formatter, "the catalog has no entry for provider {kind}")
            }
            Self::ModelNotOffered { model } => {
                write!(formatter, "no registered provider offers model {model}")
            }
            Self::ModeNotRegistered { mode } => {
                write!(formatter, "integration mode {mode} is not registered")
            }
            Self::DuplicateProviderKind { kind } => {
                write!(formatter, "provider {kind} was registered twice")
            }
            Self::DuplicateMode { mode } => {
                write!(formatter, "integration mode {mode} was declared twice")
            }
            Self::DuplicateModel { model } => write!(formatter, "model {model} was offered twice"),
            Self::DuplicateConformance {
                mode,
                adapter_version,
            } => write!(
                formatter,
                "two conformance records name mode {mode} at adapter version {adapter_version}"
            ),
            Self::Required { field } => write!(formatter, "field {field} is required"),
            Self::TooMany { field, max } => {
                write!(formatter, "more than {max} entries were given for {field}")
            }
            Self::Value { field, error } => write!(formatter, "field {field}: {error}"),
            Self::ModeProvenanceMismatch { mode, field } => write!(
                formatter,
                "mode {mode} was observed against a different {field}"
            ),
            Self::ConformanceProvenanceMismatch { mode, field } => write!(
                formatter,
                "the conformance record for mode {mode} names a different {field}"
            ),
            Self::ModelProviderMismatch {
                model,
                declared,
                expected,
            } => write!(
                formatter,
                "model {model} names provider {declared}, registered under {expected}"
            ),
            Self::Mode { error } => write!(formatter, "{error}"),
            Self::NotConformant {
                mode,
                adapter_version,
            } => write!(
                formatter,
                "no conformance record for mode {mode} at adapter version {adapter_version}"
            ),
            Self::ConformanceFailed {
                mode,
                adapter_version,
            } => write!(
                formatter,
                "conformance for mode {mode} at adapter version {adapter_version} failed"
            ),
            Self::DigestUnparsable { field } => {
                write!(formatter, "field {field} is not a parseable digest")
            }
        }
    }
}

impl Error for CatalogError {}

impl From<ProviderError> for CatalogError {
    fn from(error: ProviderError) -> Self {
        Self::Mode { error }
    }
}

/// One recorded conformance result.
///
/// Carries every coordinate
/// `docs/product-plan/requirements/agent-integrations.md` keys conformance by:
/// provider binary digest, version and schema hash (all three inside
/// [`BinaryProvenance`]), integration mode, and Automonique adapter version.
/// A record missing any of them is unrepresentable, so a result cannot be
/// filed against "the Codex adapter" in the abstract and later be read as
/// covering a different build.
///
/// Nothing here runs a suite. This is a claim, recorded with the coordinates
/// that let some other layer check it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceRecord {
    provenance: BinaryProvenance,
    mode: String,
    adapter_version: String,
    outcome: ConformanceOutcome,
}

impl ConformanceRecord {
    /// Record a conformance result.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::Value`] for an invalid mode or adapter version.
    pub fn record(
        provenance: BinaryProvenance,
        mode: &str,
        adapter_version: &str,
        outcome: ConformanceOutcome,
    ) -> Result<Self, CatalogError> {
        bounded(mode, "conformance_mode")?;
        bounded(adapter_version, "adapter_version")?;
        Ok(Self {
            provenance,
            mode: mode.to_owned(),
            adapter_version: adapter_version.to_owned(),
            outcome,
        })
    }

    /// The binary these coordinates name.
    #[must_use]
    pub const fn provenance(&self) -> &BinaryProvenance {
        &self.provenance
    }

    /// The integration mode tested.
    #[must_use]
    pub fn mode(&self) -> &str {
        &self.mode
    }

    /// The Automonique adapter version tested.
    #[must_use]
    pub fn adapter_version(&self) -> &str {
        &self.adapter_version
    }

    /// What the run concluded.
    #[must_use]
    pub const fn outcome(&self) -> ConformanceOutcome {
        self.outcome
    }
}

/// Every field a [`ProviderCatalogEntry`] needs, named at the call site.
///
/// A struct rather than a positional list, following
/// [`crate::models::CatalogEntryParts`]: the two `Vec`s of declarations and the
/// two identity values are easy to transpose, and a transposed pair would
/// compile while describing the wrong provider.
#[derive(Clone, Debug)]
pub struct ProviderEntryParts {
    /// The provider kind being registered.
    pub kind: ProviderKind,
    /// The binary this registration describes. Its schema digest is required.
    pub executable: BinaryProvenance,
    /// The dialect this provider's normalized events are spelled in.
    pub dialect: RunnerEventDialect,
    /// Integration modes declared for this binary. At least one is required.
    pub modes: Vec<ModeDeclaration>,
    /// Models this provider offers. At least one is required.
    pub models: Vec<ModelCatalogEntry>,
    /// Conformance results recorded against this binary. May be empty.
    pub conformance: Vec<ConformanceRecord>,
}

/// One registered provider.
///
/// Registration is a description. It grants nothing: no path, no handle, no
/// authority. The only thing an entry can be asked to *decide* is
/// [`ProviderCatalogEntry::admit_native`], and that decision is itself only a
/// value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCatalogEntry {
    kind: ProviderKind,
    executable: BinaryProvenance,
    executable_sha256_hex: String,
    dialect: RunnerEventDialect,
    modes: Vec<ModeDeclaration>,
    models: Vec<ModelCatalogEntry>,
    conformance: Vec<ConformanceRecord>,
}

impl ProviderCatalogEntry {
    /// Register a provider.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::Required`] when the schema digest, the mode list
    /// or the model list is absent; [`CatalogError::TooMany`] above any
    /// ceiling; [`CatalogError::DuplicateMode`],
    /// [`CatalogError::DuplicateModel`] or
    /// [`CatalogError::DuplicateConformance`] for a repeated key;
    /// [`CatalogError::ModeProvenanceMismatch`] or
    /// [`CatalogError::ConformanceProvenanceMismatch`] when a declaration or
    /// record was observed against a different binary;
    /// [`CatalogError::ModelProviderMismatch`] when an offered model names a
    /// provider other than the registered kind; and
    /// [`CatalogError::ModeNotRegistered`] when a conformance record names a
    /// mode this entry does not declare.
    pub fn register(parts: ProviderEntryParts) -> Result<Self, CatalogError> {
        // Conformance is keyed by schema hash, so a binary whose protocol
        // schema is unknown cannot be registered at all: every conformance
        // record filed against it would be unkeyable.
        if parts.executable.schema_digest().is_none() {
            return Err(CatalogError::Required {
                field: "schema_digest",
            });
        }
        let executable_sha256_hex = Digest::parse(parts.executable.digest())
            .map_err(|_| CatalogError::DigestUnparsable {
                field: "binary_digest",
            })?
            .hex()
            .to_owned();

        let modes = check_modes(&parts.modes, &parts.executable)?;
        check_models(&parts.models, parts.kind)?;
        check_conformance(&parts.conformance, &modes, &parts.executable)?;

        Ok(Self {
            kind: parts.kind,
            executable: parts.executable,
            executable_sha256_hex,
            dialect: parts.dialect,
            modes: parts.modes,
            models: parts.models,
            conformance: parts.conformance,
        })
    }

    /// The registered kind.
    #[must_use]
    pub const fn kind(&self) -> ProviderKind {
        self.kind
    }

    /// The binary this registration describes.
    #[must_use]
    pub const fn executable(&self) -> &BinaryProvenance {
        &self.executable
    }

    /// The pinned binary digest as bare lowercase hex.
    ///
    /// [`BinaryProvenance`] spells a digest `sha256:<hex>`;
    /// `automonique_agents::spawn_plan::ProviderExecutable::pinned` takes the
    /// bare hex and refuses anything else. This accessor is the bridge, so a
    /// later adapter pairing a catalog entry with a path does not reformat a
    /// digest by hand. It is a spelling conversion and nothing more: no file is
    /// opened and no digest is computed here or there — `ProviderExecutable`
    /// hashes at plan time, not at pin time.
    #[must_use]
    pub fn executable_sha256_hex(&self) -> &str {
        &self.executable_sha256_hex
    }

    /// The dialect this provider's normalized events are spelled in.
    #[must_use]
    pub const fn dialect(&self) -> RunnerEventDialect {
        self.dialect
    }

    /// Every declared integration mode, in declaration order.
    #[must_use]
    pub fn modes(&self) -> &[ModeDeclaration] {
        &self.modes
    }

    /// Every offered model, in declaration order.
    #[must_use]
    pub fn models(&self) -> &[ModelCatalogEntry] {
        &self.models
    }

    /// Every recorded conformance result, in declaration order.
    #[must_use]
    pub fn conformance(&self) -> &[ConformanceRecord] {
        &self.conformance
    }

    /// One declared mode by exact name.
    #[must_use]
    pub fn mode(&self, name: &str) -> Option<&ModeDeclaration> {
        self.modes
            .iter()
            .find(|declaration| declaration.mode() == name)
    }

    /// One offered model by exact identifier within this provider.
    #[must_use]
    pub fn model(&self, model: &str) -> Option<&ModelCatalogEntry> {
        self.models
            .iter()
            .find(|entry| entry.model().model() == model)
    }

    /// Admit one mode as the production native adapter, or refuse.
    ///
    /// Three things must hold, and each is a separate refusal:
    ///
    /// 1. the mode is declared by this entry;
    /// 2. [`ModeDeclaration::select`] admits it — every mandatory capability is
    ///    present, so a missing approval or resume capability is a refusal
    ///    rather than a downgrade;
    /// 3. a [`ConformanceRecord`] exists for this exact binary, mode and
    ///    adapter version, and it passed.
    ///
    /// Step three is the plan's rule that "a binary digest without a passing
    /// record cannot become the production native adapter automatically". There
    /// is no argument that skips it.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::Value`] for an invalid adapter version,
    /// [`CatalogError::ModeNotRegistered`], [`CatalogError::Mode`] wrapping the
    /// capability refusal, [`CatalogError::NotConformant`] when no record
    /// exists, and [`CatalogError::ConformanceFailed`] when one exists and
    /// failed.
    pub fn admit_native(
        &self,
        mode: &str,
        adapter_version: &str,
    ) -> Result<NativeAdmission, CatalogError> {
        bounded(adapter_version, "adapter_version")?;
        let declaration = self
            .mode(mode)
            .ok_or_else(|| CatalogError::ModeNotRegistered {
                mode: mode.to_owned(),
            })?;
        let selection = declaration.select()?;
        let record = self
            .conformance
            .iter()
            .find(|record| record.mode() == mode && record.adapter_version() == adapter_version)
            .ok_or_else(|| CatalogError::NotConformant {
                mode: mode.to_owned(),
                adapter_version: adapter_version.to_owned(),
            })?;
        match record.outcome() {
            ConformanceOutcome::Passed => Ok(NativeAdmission {
                kind: self.kind,
                mode: mode.to_owned(),
                adapter_version: adapter_version.to_owned(),
                selection,
                _private: PhantomData,
            }),
            ConformanceOutcome::Failed => Err(CatalogError::ConformanceFailed {
                mode: mode.to_owned(),
                adapter_version: adapter_version.to_owned(),
            }),
        }
    }
}

/// Proof that one mode of one registered provider is admissible as the native
/// adapter.
///
/// Obtainable only from [`ProviderCatalogEntry::admit_native`]. It carries the
/// coordinates of the decision and the [`Selection`] that backs it, and
/// deliberately nothing else — no path, no binary handle, no capability token.
/// Holding one lets a caller *say* the adapter is admitted; it does not let a
/// caller run anything.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeAdmission {
    kind: ProviderKind,
    mode: String,
    adapter_version: String,
    selection: Selection,
    _private: PhantomData<()>,
}

impl NativeAdmission {
    /// The admitted provider kind.
    #[must_use]
    pub const fn kind(&self) -> ProviderKind {
        self.kind
    }

    /// The admitted integration mode.
    #[must_use]
    pub fn mode(&self) -> &str {
        &self.mode
    }

    /// The adapter version the conformance record was filed against.
    #[must_use]
    pub fn adapter_version(&self) -> &str {
        &self.adapter_version
    }

    /// The capability selection backing the admission.
    ///
    /// Exposed so a caller can display what is degraded and a policy can refuse
    /// a job that needs one of them. This layer never decides that a
    /// degradation is acceptable — that is [`Selection`]'s standing rule.
    #[must_use]
    pub const fn selection(&self) -> &Selection {
        &self.selection
    }
}

/// The set of providers this control plane knows.
///
/// Keyed by [`ProviderKind`], one entry each. Because the key is a closed
/// one-variant enum and duplicates refuse, the catalog's size is bounded by
/// `ProviderKind::ALL.len()` by construction: a separate count ceiling would be
/// decorative, so there is not one.
///
/// An empty catalog is permitted and is not a refusal. A control plane with
/// nothing registered is a real state, and forcing a caller to fabricate an
/// entry to represent it would be the dishonest option.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProviderCatalog {
    entries: Vec<ProviderCatalogEntry>,
}

impl ProviderCatalog {
    /// Assemble a catalog, sorted by provider spelling.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::DuplicateProviderKind`] when a kind is
    /// registered twice.
    pub fn register(
        entries: impl IntoIterator<Item = ProviderCatalogEntry>,
    ) -> Result<Self, CatalogError> {
        let mut entries: Vec<ProviderCatalogEntry> = entries.into_iter().collect();
        entries.sort_by_key(|entry| entry.kind.as_str());
        if let Some(pair) = entries.windows(2).find(|pair| pair[0].kind == pair[1].kind) {
            return Err(CatalogError::DuplicateProviderKind { kind: pair[0].kind });
        }
        Ok(Self { entries })
    }

    /// Every entry, sorted by provider spelling.
    #[must_use]
    pub fn entries(&self) -> &[ProviderCatalogEntry] {
        &self.entries
    }

    /// The entry for one kind, or nothing.
    #[must_use]
    pub fn entry(&self, kind: ProviderKind) -> Option<&ProviderCatalogEntry> {
        self.entries.iter().find(|entry| entry.kind == kind)
    }

    /// Look one model up by provider kind and exact model identifier.
    #[must_use]
    pub fn lookup(&self, kind: ProviderKind, model: &str) -> Option<&ModelCatalogEntry> {
        self.entry(kind).and_then(|entry| entry.model(model))
    }

    /// Resolve a [`ModelRef`] — an alias target, a routing candidate — against
    /// the registry, saying which step failed.
    ///
    /// [`ModelRef`] carries its provider as free text, because
    /// [`crate::models`] has no closed provider vocabulary to check it against.
    /// This is where that text meets [`ProviderKind`]: a reference naming a
    /// planned-but-unimplemented provider is refused by name rather than
    /// silently missing.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::UnknownProviderKind`] or
    /// [`CatalogError::PlannedProviderKind`] when the reference's provider is
    /// not registerable, [`CatalogError::ProviderAbsent`] when it is
    /// registerable but not in this catalog, and
    /// [`CatalogError::ModelNotOffered`] when the provider is present and does
    /// not offer the model.
    pub fn admits_model(&self, model: &ModelRef) -> Result<&ModelCatalogEntry, CatalogError> {
        let kind = ProviderKind::resolve(model.provider())?;
        let entry = self
            .entry(kind)
            .ok_or(CatalogError::ProviderAbsent { kind })?;
        entry
            .model(model.model())
            .ok_or_else(|| CatalogError::ModelNotOffered {
                model: model.to_string(),
            })
    }

    /// Render the catalog as stable text, for a later doctor or status surface.
    ///
    /// One header line naming [`PROVIDER_CATALOG_SCHEMA_V1`], then per entry in
    /// provider-spelling order: one `provider` line, one `mode` line per
    /// declared mode sorted by mode name, one `conformance` line per record
    /// sorted by mode then adapter version, and one `model` line per offered
    /// model sorted by coordinate. Modalities render in
    /// [`Modality::ALL`] order rather than declaration order, so reordering a
    /// declaration — which changes nothing about what a model accepts — cannot
    /// change the rendering.
    ///
    /// The result is stable text for display and for pinning in tests. It is
    /// not a parsing grammar: a bounded field may itself contain a space, and
    /// nothing quotes or escapes it. See the module note on why pricing, auth,
    /// reasoning and tool support are absent.
    #[must_use]
    pub fn manifest(&self) -> String {
        let mut out = String::from(PROVIDER_CATALOG_SCHEMA_V1);
        out.push('\n');
        for entry in &self.entries {
            let kind = entry.kind.as_str();
            let schema = entry.executable.schema_digest().unwrap_or("none");
            out.push_str(&format!(
                "provider {kind} version={} binary={} schema={schema} dialect={}\n",
                entry.executable.version(),
                entry.executable.digest(),
                entry.dialect.as_str(),
            ));

            let mut modes: Vec<String> = entry
                .modes
                .iter()
                .map(|declaration| {
                    format!(
                        "mode {kind} {} required={} degraded={} unknown={}\n",
                        declaration.mode(),
                        declaration.required().len(),
                        declaration.degraded().len(),
                        declaration.unknown().len(),
                    )
                })
                .collect();
            modes.sort();
            out.extend(modes);

            let mut records: Vec<String> = entry
                .conformance
                .iter()
                .map(|record| {
                    format!(
                        "conformance {kind} {} adapter={} outcome={}\n",
                        record.mode(),
                        record.adapter_version(),
                        record.outcome().as_str(),
                    )
                })
                .collect();
            records.sort();
            out.extend(records);

            let mut models: Vec<String> = entry
                .models
                .iter()
                .map(|model| {
                    let modalities: Vec<&str> = Modality::ALL
                        .into_iter()
                        .filter(|modality| model.modalities().contains(modality))
                        .map(Modality::as_str)
                        .collect();
                    format!(
                        "model {} modalities={} context={} output={} region={} zone={}\n",
                        model.model(),
                        modalities.join(","),
                        model.context_limit_tokens(),
                        model.max_output_tokens(),
                        model.region(),
                        model.sovereignty_zone(),
                    )
                })
                .collect();
            models.sort();
            out.extend(models);
        }
        out
    }
}

/// Validate the mode list and return the declared mode names.
fn check_modes<'a>(
    modes: &'a [ModeDeclaration],
    executable: &BinaryProvenance,
) -> Result<Vec<&'a str>, CatalogError> {
    if modes.len() > MAX_MODES_PER_ENTRY {
        return Err(CatalogError::TooMany {
            field: "modes",
            max: MAX_MODES_PER_ENTRY,
        });
    }
    if modes.is_empty() {
        return Err(CatalogError::Required { field: "modes" });
    }
    for declaration in modes {
        // `BinaryProvenance::matches` compares digest and schema digest. The
        // entry additionally pins the version, because conformance is keyed by
        // it: two provenances at one digest disagreeing about the version is a
        // caller mistake, not a rebuild.
        if !executable.matches(declaration.provenance()) {
            return Err(CatalogError::ModeProvenanceMismatch {
                mode: declaration.mode().to_owned(),
                field: "binary_digest",
            });
        }
        if executable.version() != declaration.provenance().version() {
            return Err(CatalogError::ModeProvenanceMismatch {
                mode: declaration.mode().to_owned(),
                field: "binary_version",
            });
        }
    }
    let mut names: Vec<&str> = modes.iter().map(ModeDeclaration::mode).collect();
    names.sort_unstable();
    if let Some(pair) = names.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(CatalogError::DuplicateMode {
            mode: pair[0].to_owned(),
        });
    }
    Ok(names)
}

/// Validate the model list against the registered kind.
fn check_models(models: &[ModelCatalogEntry], kind: ProviderKind) -> Result<(), CatalogError> {
    if models.len() > MAX_MODELS_PER_ENTRY {
        return Err(CatalogError::TooMany {
            field: "models",
            max: MAX_MODELS_PER_ENTRY,
        });
    }
    if models.is_empty() {
        return Err(CatalogError::Required { field: "models" });
    }
    for model in models {
        if model.model().provider() != kind.as_str() {
            return Err(CatalogError::ModelProviderMismatch {
                model: model.model().to_string(),
                declared: model.model().provider().to_owned(),
                expected: kind.as_str(),
            });
        }
    }
    let mut coordinates: Vec<&ModelRef> = models.iter().map(ModelCatalogEntry::model).collect();
    coordinates.sort_unstable();
    if let Some(pair) = coordinates.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(CatalogError::DuplicateModel {
            model: pair[0].to_string(),
        });
    }
    Ok(())
}

/// Validate conformance records against the entry's binary and declared modes.
fn check_conformance(
    records: &[ConformanceRecord],
    modes: &[&str],
    executable: &BinaryProvenance,
) -> Result<(), CatalogError> {
    if records.len() > MAX_CONFORMANCE_RECORDS_PER_ENTRY {
        return Err(CatalogError::TooMany {
            field: "conformance",
            max: MAX_CONFORMANCE_RECORDS_PER_ENTRY,
        });
    }
    for record in records {
        if !modes.contains(&record.mode()) {
            return Err(CatalogError::ModeNotRegistered {
                mode: record.mode().to_owned(),
            });
        }
        if !executable.matches(record.provenance()) {
            return Err(CatalogError::ConformanceProvenanceMismatch {
                mode: record.mode().to_owned(),
                field: "binary_digest",
            });
        }
        if executable.version() != record.provenance().version() {
            return Err(CatalogError::ConformanceProvenanceMismatch {
                mode: record.mode().to_owned(),
                field: "binary_version",
            });
        }
    }
    let mut keys: Vec<(&str, &str)> = records
        .iter()
        .map(|record| (record.mode(), record.adapter_version()))
        .collect();
    keys.sort_unstable();
    if let Some(pair) = keys.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(CatalogError::DuplicateConformance {
            mode: pair[0].0.to_owned(),
            adapter_version: pair[0].1.to_owned(),
        });
    }
    Ok(())
}

fn bounded(value: &str, field: &'static str) -> Result<(), CatalogError> {
    crate::primitives::bounded_value(value, MAX_CATALOG_FIELD_BYTES)
        .map_err(|error| CatalogError::Value { field, error })
}
