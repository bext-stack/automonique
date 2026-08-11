// SPDX-License-Identifier: Elastic-2.0

//! Model catalog, routing decisions, credential pools, media adapters and
//! executor registration.
//!
//! Two questions must always be answerable from these values: *why did this run
//! on that model*, and *what boundary would have been crossed to run it
//! elsewhere*. The type budget is therefore spent on making a boundary crossing
//! unrepresentable rather than merely refused at dispatch.
//!
//! The boundaries held here are:
//!
//! - a rejected routing candidate cannot exist without the constraint that
//!   eliminated it ([`ConsideredCandidate::eliminated`]);
//! - a credential rotation cannot name two pools ([`Rotation`]);
//! - a spoken confirmation cannot satisfy an approval ([`PendingApproval`]);
//! - a browser grant cannot become native OS access ([`NativeOsGrant`]);
//! - a vendor's sandbox label cannot become lifecycle evidence
//!   ([`LifecycleEvidence`]);
//! - reference advice cannot become an authoritative record
//!   ([`AggregateResult`]).
//!
//! Nothing here calls a model, transcodes a byte, allocates a worker, contacts
//! a vendor or takes a screenshot. Callers supply instants and observations,
//! and evidence about this module must say that rather than implying a provider
//! was reached.

use core::fmt;
use core::marker::PhantomData;
use std::error::Error;

use crate::primitives::{EpochMillis, Revision, ValueError};
use crate::sandbox::{EnforcementAttestation, NetworkAccess};

/// Maximum UTF-8 byte length of a model, media or executor field.
pub const MAX_MODEL_FIELD_BYTES: usize = 256;

/// Why a model, media or executor operation was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelError {
    /// A bounded field was rejected.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
    /// A declared limit was absent or zero.
    LimitRequired {
        /// Which limit.
        field: &'static str,
    },
    /// An alias was bound twice in one profile.
    DuplicateAlias {
        /// The repeated alias.
        alias: String,
    },
    /// An alias is not bound in this profile revision.
    UnknownAlias {
        /// The unbound alias.
        alias: String,
    },
    /// A decision was recorded with no candidates at all.
    NoCandidates,
    /// Every candidate was eliminated, so nothing ran.
    NoSelection,
    /// More than one candidate claimed to be the selected one.
    AmbiguousSelection {
        /// How many claimed selection.
        count: usize,
    },
    /// A pool member was requested for an account the pool does not contain.
    UnknownAccount {
        /// The absent account.
        account: String,
    },
    /// An account's declared policy differs from the pool it was placed in.
    PoolPolicyMismatch {
        /// The offending account.
        account: String,
        /// Which axis differs.
        axis: &'static str,
    },
    /// A rotation named one account as both source and target.
    RotationToSelf {
        /// The account named twice.
        account: String,
    },
    /// A rotation target cannot serve traffic.
    RotationTargetUnavailable {
        /// The target account.
        account: String,
        /// Its observed state.
        state: &'static str,
    },
    /// A fallback chain was declared with no hops.
    EmptyChain,
    /// A fallback hop weakens a semantic the head hop requested.
    ///
    /// Raised at declaration, so the chain never reaches dispatch.
    FallbackWeakens {
        /// Which semantic: tools, sandbox, residency or approval.
        axis: &'static str,
        /// Index of the offending hop.
        hop: usize,
    },
    /// A class already has a declared chain.
    DuplicateChainClass {
        /// The repeated class.
        class: &'static str,
    },
    /// A derivative reused the protected original's digest.
    DerivativeNotDistinct,
    /// Provenance does not name the artifact it claims to derive from.
    ProvenanceMismatch,
    /// A browser action named an origin outside the reviewed allowlist.
    OriginNotAllowlisted {
        /// The refused origin.
        origin: String,
    },
    /// Approval evidence names a different action than the one pending.
    ApprovalMismatch,
    /// A wake was attempted on an environment that is not suspended.
    NotSuspended {
        /// The observed state.
        state: &'static str,
    },
    /// A hibernated environment has no snapshot to wake from.
    SnapshotRequired,
}

impl ModelError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Field { .. } => "field_invalid",
            Self::LimitRequired { .. } => "limit_required",
            Self::DuplicateAlias { .. } => "duplicate_alias",
            Self::UnknownAlias { .. } => "unknown_alias",
            Self::NoCandidates => "no_candidates",
            Self::NoSelection => "no_selection",
            Self::AmbiguousSelection { .. } => "ambiguous_selection",
            Self::UnknownAccount { .. } => "unknown_account",
            Self::PoolPolicyMismatch { .. } => "pool_policy_mismatch",
            Self::RotationToSelf { .. } => "rotation_to_self",
            Self::RotationTargetUnavailable { .. } => "rotation_target_unavailable",
            Self::EmptyChain => "empty_chain",
            Self::FallbackWeakens { .. } => "fallback_weakens",
            Self::DuplicateChainClass { .. } => "duplicate_chain_class",
            Self::DerivativeNotDistinct => "derivative_not_distinct",
            Self::ProvenanceMismatch => "provenance_mismatch",
            Self::OriginNotAllowlisted { .. } => "origin_not_allowlisted",
            Self::ApprovalMismatch => "approval_mismatch",
            Self::NotSuspended { .. } => "not_suspended",
            Self::SnapshotRequired => "snapshot_required",
        }
    }
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
            Self::LimitRequired { field } => {
                write!(formatter, "limit {field} is required and must be non-zero")
            }
            Self::DuplicateAlias { alias } => write!(formatter, "alias {alias} is bound twice"),
            Self::UnknownAlias { alias } => {
                write!(formatter, "alias {alias} is not bound at this revision")
            }
            Self::NoCandidates => formatter.write_str("a routing decision considered no candidate"),
            Self::NoSelection => {
                formatter.write_str("every candidate was eliminated, so nothing was selected")
            }
            Self::AmbiguousSelection { count } => {
                write!(
                    formatter,
                    "{count} candidates claimed selection; exactly one may"
                )
            }
            Self::UnknownAccount { account } => {
                write!(formatter, "account {account} is not in this pool")
            }
            Self::PoolPolicyMismatch { account, axis } => write!(
                formatter,
                "account {account} declares a different {axis} than its pool"
            ),
            Self::RotationToSelf { account } => {
                write!(formatter, "rotation named {account} as source and target")
            }
            Self::RotationTargetUnavailable { account, state } => {
                write!(formatter, "rotation target {account} is {state}")
            }
            Self::EmptyChain => formatter.write_str("a fallback chain needs at least one hop"),
            Self::FallbackWeakens { axis, hop } => write!(
                formatter,
                "fallback hop {hop} weakens {axis}; a chain that weakens is refused at declaration"
            ),
            Self::DuplicateChainClass { class } => {
                write!(formatter, "class {class} already has a declared chain")
            }
            Self::DerivativeNotDistinct => {
                formatter.write_str("a derivative must be a distinct artifact from the original")
            }
            Self::ProvenanceMismatch => {
                formatter.write_str("provenance names a different source artifact")
            }
            Self::OriginNotAllowlisted { origin } => {
                write!(
                    formatter,
                    "origin {origin} is outside the reviewed allowlist"
                )
            }
            Self::ApprovalMismatch => {
                formatter.write_str("approval evidence names a different action")
            }
            Self::NotSuspended { state } => {
                write!(formatter, "environment is {state}, not suspended")
            }
            Self::SnapshotRequired => {
                formatter.write_str("a hibernated environment needs a snapshot to wake from")
            }
        }
    }
}

impl Error for ModelError {}

/// Why a mid-session model switch was refused.
///
/// A refusal is a distinct outcome from a switch: there is no variant that
/// performs the crossing and annotates it, so a caller cannot treat a crossed
/// boundary as a completed switch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SwitchRefusal {
    /// The requested model sits in a different sovereignty zone.
    SovereigntyBoundary {
        /// The session's zone.
        from: String,
        /// The requested zone.
        to: String,
    },
    /// The requested model bills to a different provider account.
    ProviderAccountBoundary {
        /// The session's account.
        from: String,
        /// The requested account.
        to: String,
    },
    /// A session-bound provider cannot hand its session to another provider.
    SessionBoundMigration {
        /// The provider holding the session.
        provider: String,
    },
    /// Another model being healthy is not a reason to leave a bound session.
    HealthAloneInsufficient {
        /// The provider holding the session.
        provider: String,
    },
    /// The turn revision space is exhausted, so no new revision can record it.
    RevisionExhausted,
}

impl SwitchRefusal {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::SovereigntyBoundary { .. } => "sovereignty_boundary",
            Self::ProviderAccountBoundary { .. } => "provider_account_boundary",
            Self::SessionBoundMigration { .. } => "session_bound_migration",
            Self::HealthAloneInsufficient { .. } => "health_alone_insufficient",
            Self::RevisionExhausted => "revision_exhausted",
        }
    }
}

impl fmt::Display for SwitchRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SovereigntyBoundary { from, to } => write!(
                formatter,
                "a switch from sovereignty zone {from} to {to} is a refusal, not a switch"
            ),
            Self::ProviderAccountBoundary { from, to } => write!(
                formatter,
                "a switch from provider account {from} to {to} is a refusal, not a switch"
            ),
            Self::SessionBoundMigration { provider } => write!(
                formatter,
                "provider {provider} is session-bound and cannot migrate mid-session"
            ),
            Self::HealthAloneInsufficient { provider } => write!(
                formatter,
                "provider {provider} is session-bound; another model being healthy is not a reason"
            ),
            Self::RevisionExhausted => formatter.write_str("turn revisions are exhausted"),
        }
    }
}

impl Error for SwitchRefusal {}

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

/// A provider-qualified model coordinate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelRef {
    provider: String,
    model: String,
}

impl ModelRef {
    /// Name a model within a provider.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid component.
    pub fn new(provider: &str, model: &str) -> Result<Self, ModelError> {
        bounded(provider, "provider")?;
        bounded(model, "model")?;
        Ok(Self {
            provider: provider.to_owned(),
            model: model.to_owned(),
        })
    }

    /// The provider that serves the model.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// The model identifier within that provider.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }
}

impl fmt::Display for ModelRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.provider, self.model)
    }
}

/// A separately identified provider account or key slot.
///
/// The identifier is a coordinate. It never carries credential material.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderAccountId(String);

impl ProviderAccountId {
    /// Name an account.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid identifier.
    pub fn new(value: &str) -> Result<Self, ModelError> {
        bounded(value, "provider_account")?;
        Ok(Self(value.to_owned()))
    }

    /// The account identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProviderAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// An input or output modality a model accepts.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Modality {
    /// Text tokens.
    Text,
    /// Raster images.
    Image,
    /// Audio samples.
    Audio,
    /// Video frames.
    Video,
    /// Structured documents.
    Document,
}

impl Modality {
    /// Every modality, for coverage checks.
    pub const ALL: [Self; 5] = [
        Self::Text,
        Self::Image,
        Self::Audio,
        Self::Video,
        Self::Document,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Image => "image",
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Document => "document",
        }
    }
}

/// How a model exposes reasoning effort.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReasoningControl {
    /// No reasoning control is offered.
    Unsupported,
    /// The provider fixes the budget.
    ProviderFixedBudget,
    /// The caller selects an effort level.
    CallerSelectedEffort,
}

/// How a model exposes tools.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ToolSupport {
    /// No tool calling.
    None,
    /// One tool call at a time.
    Sequential,
    /// Several tool calls per turn.
    Parallel,
}

/// How a model constrains its output shape.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StructuredOutputSupport {
    /// Free text only.
    None,
    /// A JSON object without a declared schema.
    JsonObject,
    /// A caller-declared schema the provider constrains against.
    SchemaConstrained,
}

/// Whether a provider may train on submitted content.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TrainingUse {
    /// Training is contractually prohibited.
    Prohibited,
    /// Training is permitted by the tenant contract.
    PermittedByContract,
}

/// How long a provider retains submitted prompts.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PromptRetention {
    /// Nothing is retained after the response.
    NoneRetained,
    /// Retained for a declared number of days.
    Days(u32),
}

/// The data policy a catalog entry or media adapter declares.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataPolicy {
    training: TrainingUse,
    retention: PromptRetention,
    boundary: String,
}

impl DataPolicy {
    /// Declare a data policy.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid boundary name.
    pub fn new(
        training: TrainingUse,
        retention: PromptRetention,
        boundary: &str,
    ) -> Result<Self, ModelError> {
        bounded(boundary, "data_boundary")?;
        Ok(Self {
            training,
            retention,
            boundary: boundary.to_owned(),
        })
    }

    /// Whether the provider may train on submitted content.
    #[must_use]
    pub const fn training(&self) -> TrainingUse {
        self.training
    }

    /// How long prompts are retained.
    #[must_use]
    pub const fn retention(&self) -> PromptRetention {
        self.retention
    }

    /// The declared data boundary.
    #[must_use]
    pub fn boundary(&self) -> &str {
        &self.boundary
    }
}

/// What a price is charged per.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PricingUnit {
    /// One million tokens.
    MillionTokens,
    /// One second of media.
    Second,
    /// One generated image.
    Image,
    /// One thousand characters.
    ThousandCharacters,
}

/// A declared price, in currency micros per unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pricing {
    currency: String,
    unit: PricingUnit,
    input_micros: u64,
    output_micros: u64,
}

impl Pricing {
    /// Declare a price.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid currency.
    pub fn new(
        currency: &str,
        unit: PricingUnit,
        input_micros: u64,
        output_micros: u64,
    ) -> Result<Self, ModelError> {
        bounded(currency, "currency")?;
        Ok(Self {
            currency: currency.to_owned(),
            unit,
            input_micros,
            output_micros,
        })
    }

    /// The currency the micros are denominated in.
    #[must_use]
    pub fn currency(&self) -> &str {
        &self.currency
    }

    /// What the price is charged per.
    #[must_use]
    pub const fn unit(&self) -> PricingUnit {
        self.unit
    }

    /// Input micros per unit.
    #[must_use]
    pub const fn input_micros(&self) -> u64 {
        self.input_micros
    }

    /// Output micros per unit.
    #[must_use]
    pub const fn output_micros(&self) -> u64 {
        self.output_micros
    }
}

/// How a provider account authenticates.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthMethod {
    /// A long-lived API key held in a secret store.
    ApiKey,
    /// An OAuth device grant.
    OAuthDeviceGrant,
    /// A paid subscription session.
    SubscriptionSession,
    /// A platform workload identity.
    WorkloadIdentity,
}

/// Every field a [`ModelCatalogEntry`] needs, named at the call site.
///
/// A struct rather than a positional list: six of these are strings or numbers
/// of the same type, and a transposed pair would compile while describing the
/// wrong model. Naming them removes the hazard without making a field optional.
#[derive(Clone, Debug)]
pub struct CatalogEntryParts<'a> {
    /// The model this entry describes.
    pub model: ModelRef,
    /// Human-readable name.
    pub display_name: &'a str,
    /// Accepted modalities. At least one is required.
    pub modalities: &'a [Modality],
    /// Context window, in tokens.
    pub context_limit_tokens: u64,
    /// Maximum output, in tokens.
    pub max_output_tokens: u64,
    /// Reasoning controls offered.
    pub reasoning: ReasoningControl,
    /// Tool support offered.
    pub tools: ToolSupport,
    /// Structured-output support offered.
    pub structured_output: StructuredOutputSupport,
    /// Serving region.
    pub region: &'a str,
    /// Sovereignty zone the region belongs to.
    pub sovereignty_zone: &'a str,
    /// Data policy.
    pub data_policy: DataPolicy,
    /// Declared price.
    pub pricing: Pricing,
    /// How the account authenticates.
    pub auth: AuthMethod,
}

/// One normalized catalog entry.
///
/// Every field is a constructor argument, so an entry that omits its region,
/// data policy, pricing or auth method is unrepresentable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelCatalogEntry {
    model: ModelRef,
    display_name: String,
    modalities: Vec<Modality>,
    context_limit_tokens: u64,
    max_output_tokens: u64,
    reasoning: ReasoningControl,
    tools: ToolSupport,
    structured_output: StructuredOutputSupport,
    region: String,
    sovereignty_zone: String,
    data_policy: DataPolicy,
    pricing: Pricing,
    auth: AuthMethod,
}

impl ModelCatalogEntry {
    /// Declare a catalog entry.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid component and
    /// [`ModelError::LimitRequired`] when a declared limit is zero or the
    /// modality list is empty.
    pub fn declare(parts: CatalogEntryParts<'_>) -> Result<Self, ModelError> {
        bounded(parts.display_name, "display_name")?;
        bounded(parts.region, "region")?;
        bounded(parts.sovereignty_zone, "sovereignty_zone")?;
        if parts.modalities.is_empty() {
            return Err(ModelError::LimitRequired {
                field: "modalities",
            });
        }
        if parts.context_limit_tokens == 0 {
            return Err(ModelError::LimitRequired {
                field: "context_limit_tokens",
            });
        }
        if parts.max_output_tokens == 0 {
            return Err(ModelError::LimitRequired {
                field: "max_output_tokens",
            });
        }
        Ok(Self {
            model: parts.model,
            display_name: parts.display_name.to_owned(),
            modalities: parts.modalities.to_vec(),
            context_limit_tokens: parts.context_limit_tokens,
            max_output_tokens: parts.max_output_tokens,
            reasoning: parts.reasoning,
            tools: parts.tools,
            structured_output: parts.structured_output,
            region: parts.region.to_owned(),
            sovereignty_zone: parts.sovereignty_zone.to_owned(),
            data_policy: parts.data_policy,
            pricing: parts.pricing,
            auth: parts.auth,
        })
    }

    /// The model described.
    #[must_use]
    pub const fn model(&self) -> &ModelRef {
        &self.model
    }

    /// Human-readable name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Accepted modalities.
    #[must_use]
    pub fn modalities(&self) -> &[Modality] {
        &self.modalities
    }

    /// Context window, in tokens.
    #[must_use]
    pub const fn context_limit_tokens(&self) -> u64 {
        self.context_limit_tokens
    }

    /// Maximum output, in tokens.
    #[must_use]
    pub const fn max_output_tokens(&self) -> u64 {
        self.max_output_tokens
    }

    /// Reasoning controls offered.
    #[must_use]
    pub const fn reasoning(&self) -> ReasoningControl {
        self.reasoning
    }

    /// Tool support offered.
    #[must_use]
    pub const fn tools(&self) -> ToolSupport {
        self.tools
    }

    /// Structured-output support offered.
    #[must_use]
    pub const fn structured_output(&self) -> StructuredOutputSupport {
        self.structured_output
    }

    /// Serving region.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Sovereignty zone the region belongs to.
    #[must_use]
    pub fn sovereignty_zone(&self) -> &str {
        &self.sovereignty_zone
    }

    /// Data policy.
    #[must_use]
    pub const fn data_policy(&self) -> &DataPolicy {
        &self.data_policy
    }

    /// Declared price.
    #[must_use]
    pub const fn pricing(&self) -> &Pricing {
        &self.pricing
    }

    /// How the account authenticates.
    #[must_use]
    pub const fn auth(&self) -> AuthMethod {
        self.auth
    }
}

/// One alias binding inside a profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliasBinding {
    alias: String,
    target: ModelRef,
}

impl AliasBinding {
    /// Bind an alias to a model.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid alias.
    pub fn new(alias: &str, target: ModelRef) -> Result<Self, ModelError> {
        bounded(alias, "alias")?;
        Ok(Self {
            alias: alias.to_owned(),
            target,
        })
    }

    /// The alias.
    #[must_use]
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// The model it names.
    #[must_use]
    pub const fn target(&self) -> &ModelRef {
        &self.target
    }
}

/// A resolved alias, carrying the revision it was resolved at.
///
/// The revision travels with the answer, so a recorded resolution can be
/// replayed against the same profile revision and produce the same model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliasResolution {
    alias: String,
    target: ModelRef,
    revision: Revision,
}

impl AliasResolution {
    /// The alias resolved.
    #[must_use]
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// The model it resolved to.
    #[must_use]
    pub const fn target(&self) -> &ModelRef {
        &self.target
    }

    /// The profile revision that produced this answer.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

/// Versioned alias profile data.
///
/// A profile is a value, not global mutable state: two revisions coexist, and
/// resolving against one is unaffected by the other.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliasProfile {
    revision: Revision,
    bindings: Vec<AliasBinding>,
}

impl AliasProfile {
    /// Declare a profile revision.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::DuplicateAlias`] when one alias is bound twice,
    /// because a repeated binding makes resolution order-dependent.
    pub fn new(revision: Revision, bindings: Vec<AliasBinding>) -> Result<Self, ModelError> {
        for (index, binding) in bindings.iter().enumerate() {
            if bindings[..index]
                .iter()
                .any(|earlier| earlier.alias == binding.alias)
            {
                return Err(ModelError::DuplicateAlias {
                    alias: binding.alias.clone(),
                });
            }
        }
        Ok(Self { revision, bindings })
    }

    /// The revision this profile records.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// The bindings it declares.
    #[must_use]
    pub fn bindings(&self) -> &[AliasBinding] {
        &self.bindings
    }

    /// Resolve an alias at this revision.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::UnknownAlias`] when the alias is not bound here.
    /// There is no fallback to another revision, so a resolution never silently
    /// reads a newer profile.
    pub fn resolve(&self, alias: &str) -> Result<AliasResolution, ModelError> {
        self.bindings
            .iter()
            .find(|binding| binding.alias == alias)
            .map(|binding| AliasResolution {
                alias: binding.alias.clone(),
                target: binding.target.clone(),
                revision: self.revision,
            })
            .ok_or_else(|| ModelError::UnknownAlias {
                alias: alias.to_owned(),
            })
    }
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// A constraint routing policy can eliminate a candidate with.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RoutingConstraint {
    /// The candidate is not on the tenant's explicit provider list.
    ExplicitList,
    /// The candidate serves from the wrong region.
    Region,
    /// The candidate's data-collection policy is unacceptable.
    DataCollection,
    /// The candidate lacks a required parameter or capability.
    RequiredParameter,
    /// The candidate is over the cost ceiling.
    Cost,
    /// The candidate is over the latency ceiling.
    Latency,
    /// The candidate is under the throughput floor.
    Throughput,
    /// The candidate is unhealthy.
    Health,
    /// The tenant contract does not cover the candidate.
    TenantContract,
}

impl RoutingConstraint {
    /// Every constraint, for coverage checks.
    pub const ALL: [Self; 9] = [
        Self::ExplicitList,
        Self::Region,
        Self::DataCollection,
        Self::RequiredParameter,
        Self::Cost,
        Self::Latency,
        Self::Throughput,
        Self::Health,
        Self::TenantContract,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitList => "explicit_list",
            Self::Region => "region",
            Self::DataCollection => "data_collection",
            Self::RequiredParameter => "required_parameter",
            Self::Cost => "cost",
            Self::Latency => "latency",
            Self::Throughput => "throughput",
            Self::Health => "health",
            Self::TenantContract => "tenant_contract",
        }
    }
}

/// Why one candidate was eliminated.
///
/// The constraint is a constructor argument, so an elimination without a reason
/// cannot be built, and therefore cannot be stored in a decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Elimination {
    constraint: RoutingConstraint,
    detail: String,
}

impl Elimination {
    /// Record why a candidate was eliminated.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid detail.
    pub fn new(constraint: RoutingConstraint, detail: &str) -> Result<Self, ModelError> {
        bounded(detail, "elimination_detail")?;
        Ok(Self {
            constraint,
            detail: detail.to_owned(),
        })
    }

    /// The constraint that eliminated the candidate.
    #[must_use]
    pub const fn constraint(&self) -> RoutingConstraint {
        self.constraint
    }

    /// The observation the constraint was applied to.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// What happened to one candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateOutcome {
    /// This candidate ran.
    Selected,
    /// This candidate was eliminated, and by what.
    Eliminated(Elimination),
}

/// One candidate in the order it was considered.
///
/// A rejected candidate carries its [`Elimination`], and the only way to build
/// one is to supply that elimination:
///
/// ```
/// use automonique_protocol::models::{
///     ConsideredCandidate, Elimination, ModelRef, ProviderAccountId, RoutingConstraint,
/// };
/// let account = ProviderAccountId::new("acct-eu-1").unwrap();
/// let model = ModelRef::new("anthropic", "sonnet").unwrap();
/// let reason = Elimination::new(RoutingConstraint::Region, "serves us-east-1").unwrap();
/// let rejected = ConsideredCandidate::eliminated(account, model, reason);
/// assert_eq!(
///     rejected.elimination().unwrap().constraint(),
///     RoutingConstraint::Region
/// );
/// ```
///
/// Dropping the reason does not compile, so a decision cannot record a
/// rejection it cannot explain:
///
/// ```compile_fail
/// use automonique_protocol::models::{ConsideredCandidate, ModelRef, ProviderAccountId};
/// let account = ProviderAccountId::new("acct-eu-1").unwrap();
/// let model = ModelRef::new("anthropic", "sonnet").unwrap();
/// let rejected = ConsideredCandidate::eliminated(account, model);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsideredCandidate {
    account: ProviderAccountId,
    model: ModelRef,
    outcome: CandidateOutcome,
}

impl ConsideredCandidate {
    /// Record the candidate that ran.
    #[must_use]
    pub const fn selected(account: ProviderAccountId, model: ModelRef) -> Self {
        Self {
            account,
            model,
            outcome: CandidateOutcome::Selected,
        }
    }

    /// Record a candidate that did not run, and why.
    #[must_use]
    pub const fn eliminated(
        account: ProviderAccountId,
        model: ModelRef,
        elimination: Elimination,
    ) -> Self {
        Self {
            account,
            model,
            outcome: CandidateOutcome::Eliminated(elimination),
        }
    }

    /// The provider account considered.
    #[must_use]
    pub const fn account(&self) -> &ProviderAccountId {
        &self.account
    }

    /// The model considered.
    #[must_use]
    pub const fn model(&self) -> &ModelRef {
        &self.model
    }

    /// What happened to it.
    #[must_use]
    pub const fn outcome(&self) -> &CandidateOutcome {
        &self.outcome
    }

    /// The elimination, when this candidate did not run.
    #[must_use]
    pub const fn elimination(&self) -> Option<&Elimination> {
        match &self.outcome {
            CandidateOutcome::Selected => None,
            CandidateOutcome::Eliminated(elimination) => Some(elimination),
        }
    }
}

/// A durable, explainable routing decision.
///
/// The decision stores the candidates in the order policy considered them.
/// Because every non-selected candidate is a [`ConsideredCandidate`] built from
/// an [`Elimination`], a decision without rejection reasons is unrepresentable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingDecision {
    policy_revision: Revision,
    decided_at: EpochMillis,
    ordered: Vec<ConsideredCandidate>,
    selected: usize,
}

impl RoutingDecision {
    /// Record a decision.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::NoCandidates`] for an empty consideration order,
    /// [`ModelError::NoSelection`] when every candidate was eliminated, and
    /// [`ModelError::AmbiguousSelection`] when more than one claims selection.
    pub fn record(
        policy_revision: Revision,
        decided_at: EpochMillis,
        ordered: Vec<ConsideredCandidate>,
    ) -> Result<Self, ModelError> {
        if ordered.is_empty() {
            return Err(ModelError::NoCandidates);
        }
        let selections: Vec<usize> = ordered
            .iter()
            .enumerate()
            .filter(|(_, candidate)| candidate.elimination().is_none())
            .map(|(index, _)| index)
            .collect();
        match selections.as_slice() {
            [] => Err(ModelError::NoSelection),
            [single] => Ok(Self {
                policy_revision,
                decided_at,
                ordered,
                selected: *single,
            }),
            many => Err(ModelError::AmbiguousSelection { count: many.len() }),
        }
    }

    /// The routing policy revision that produced the decision.
    #[must_use]
    pub const fn policy_revision(&self) -> Revision {
        self.policy_revision
    }

    /// When the decision was taken, as supplied by the caller.
    #[must_use]
    pub const fn decided_at(&self) -> EpochMillis {
        self.decided_at
    }

    /// The candidates in the order they were considered.
    #[must_use]
    pub fn ordered_candidates(&self) -> &[ConsideredCandidate] {
        &self.ordered
    }

    /// The candidate that ran.
    #[must_use]
    pub fn selected(&self) -> &ConsideredCandidate {
        &self.ordered[self.selected]
    }

    /// The provider account that ran the turn.
    #[must_use]
    pub fn selected_account(&self) -> &ProviderAccountId {
        self.selected().account()
    }

    /// Every rejection, paired with the constraint that caused it.
    pub fn rejections(&self) -> impl Iterator<Item = (&ConsideredCandidate, &Elimination)> {
        self.ordered
            .iter()
            .filter_map(|candidate| candidate.elimination().map(|reason| (candidate, reason)))
    }

    /// Why a particular account did not run.
    #[must_use]
    pub fn why_not(&self, account: &str) -> Option<&Elimination> {
        self.ordered
            .iter()
            .find(|candidate| candidate.account().as_str() == account)
            .and_then(ConsideredCandidate::elimination)
    }
}

// ---------------------------------------------------------------------------
// Mid-session switching
// ---------------------------------------------------------------------------

/// Whether a provider holds session state that cannot move.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SessionBinding {
    /// The session is reconstructible anywhere.
    Portable,
    /// The provider holds the session; leaving it ends the session.
    SessionBound,
}

/// Why a switch was requested.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SwitchReason {
    /// The actor asked for a different model.
    ActorDirected,
    /// Tenant policy requires a different model.
    PolicyDirected,
    /// Another model is healthy and this one is not.
    HealthOnly,
}

/// What a switch does to the provider's prefix cache.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CacheConsequence {
    /// The prefix cache survives.
    Preserved,
    /// The prefix cache is discarded and must be rebuilt.
    Discarded,
}

/// What a switch does to the live context.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ContextConsequence {
    /// The live context fits the new model.
    Retained,
    /// The live context exceeds the new model and must be compacted first.
    RequiresCompaction {
        /// By how many tokens the context overruns.
        over_by_tokens: u64,
    },
}

/// A model switch that was permitted, as a new turn revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelSwitch {
    turn_revision: Revision,
    model: ModelRef,
    cache: CacheConsequence,
    context: ContextConsequence,
}

impl ModelSwitch {
    /// The new turn revision the switch created.
    #[must_use]
    pub const fn turn_revision(&self) -> Revision {
        self.turn_revision
    }

    /// The model now in use.
    #[must_use]
    pub const fn model(&self) -> &ModelRef {
        &self.model
    }

    /// What happened to the prefix cache.
    #[must_use]
    pub const fn cache(&self) -> CacheConsequence {
        self.cache
    }

    /// What happened to the live context.
    #[must_use]
    pub const fn context(&self) -> ContextConsequence {
        self.context
    }
}

/// A request to change the model a session is running on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwitchRequest {
    account: ProviderAccountId,
    model: ModelRef,
    sovereignty_zone: String,
    context_limit_tokens: u64,
    reason: SwitchReason,
}

impl SwitchRequest {
    /// Ask for a different model.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid zone and
    /// [`ModelError::LimitRequired`] for a zero context limit.
    pub fn new(
        account: ProviderAccountId,
        model: ModelRef,
        sovereignty_zone: &str,
        context_limit_tokens: u64,
        reason: SwitchReason,
    ) -> Result<Self, ModelError> {
        bounded(sovereignty_zone, "sovereignty_zone")?;
        if context_limit_tokens == 0 {
            return Err(ModelError::LimitRequired {
                field: "context_limit_tokens",
            });
        }
        Ok(Self {
            account,
            model,
            sovereignty_zone: sovereignty_zone.to_owned(),
            context_limit_tokens,
            reason,
        })
    }

    /// The account the requested model bills to.
    #[must_use]
    pub const fn account(&self) -> &ProviderAccountId {
        &self.account
    }

    /// The requested model.
    #[must_use]
    pub const fn model(&self) -> &ModelRef {
        &self.model
    }

    /// The requested model's sovereignty zone.
    #[must_use]
    pub fn sovereignty_zone(&self) -> &str {
        &self.sovereignty_zone
    }

    /// Why the switch was asked for.
    #[must_use]
    pub const fn reason(&self) -> SwitchReason {
        self.reason
    }
}

/// The model a session is currently running on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionModel {
    account: ProviderAccountId,
    model: ModelRef,
    sovereignty_zone: String,
    binding: SessionBinding,
    turn_revision: Revision,
}

impl SessionModel {
    /// Record the model a session is bound to.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid zone.
    pub fn new(
        account: ProviderAccountId,
        model: ModelRef,
        sovereignty_zone: &str,
        binding: SessionBinding,
        turn_revision: Revision,
    ) -> Result<Self, ModelError> {
        bounded(sovereignty_zone, "sovereignty_zone")?;
        Ok(Self {
            account,
            model,
            sovereignty_zone: sovereignty_zone.to_owned(),
            binding,
            turn_revision,
        })
    }

    /// The account currently serving the session.
    #[must_use]
    pub const fn account(&self) -> &ProviderAccountId {
        &self.account
    }

    /// The model currently serving the session.
    #[must_use]
    pub const fn model(&self) -> &ModelRef {
        &self.model
    }

    /// The session's sovereignty zone.
    #[must_use]
    pub fn sovereignty_zone(&self) -> &str {
        &self.sovereignty_zone
    }

    /// Whether the provider holds unmovable session state.
    #[must_use]
    pub const fn binding(&self) -> SessionBinding {
        self.binding
    }

    /// The current turn revision.
    #[must_use]
    pub const fn turn_revision(&self) -> Revision {
        self.turn_revision
    }

    /// Attempt a mid-session switch.
    ///
    /// `live_context_tokens` is the caller's own measurement; this module reads
    /// no session state.
    ///
    /// # Errors
    ///
    /// Returns [`SwitchRefusal::SovereigntyBoundary`] or
    /// [`SwitchRefusal::ProviderAccountBoundary`] when the request would cross
    /// a boundary, [`SwitchRefusal::SessionBoundMigration`] when a session-bound
    /// provider would have to hand its session away,
    /// [`SwitchRefusal::HealthAloneInsufficient`] when health is the only reason
    /// offered for leaving a bound session, and
    /// [`SwitchRefusal::RevisionExhausted`] when no new turn revision exists.
    /// No variant performs the crossing.
    pub fn switch(
        &self,
        request: &SwitchRequest,
        live_context_tokens: u64,
    ) -> Result<ModelSwitch, SwitchRefusal> {
        if self.sovereignty_zone != request.sovereignty_zone {
            return Err(SwitchRefusal::SovereigntyBoundary {
                from: self.sovereignty_zone.clone(),
                to: request.sovereignty_zone.clone(),
            });
        }
        if self.account != request.account {
            return Err(SwitchRefusal::ProviderAccountBoundary {
                from: self.account.as_str().to_owned(),
                to: request.account.as_str().to_owned(),
            });
        }
        if self.binding == SessionBinding::SessionBound {
            if self.model.provider() != request.model.provider() {
                return Err(SwitchRefusal::SessionBoundMigration {
                    provider: self.model.provider().to_owned(),
                });
            }
            if request.reason == SwitchReason::HealthOnly {
                return Err(SwitchRefusal::HealthAloneInsufficient {
                    provider: self.model.provider().to_owned(),
                });
            }
        }
        let turn_revision = self
            .turn_revision
            .checked_next()
            .map_err(|_| SwitchRefusal::RevisionExhausted)?;
        let cache = if self.model == request.model {
            CacheConsequence::Preserved
        } else {
            CacheConsequence::Discarded
        };
        let context = if live_context_tokens > request.context_limit_tokens {
            ContextConsequence::RequiresCompaction {
                over_by_tokens: live_context_tokens - request.context_limit_tokens,
            }
        } else {
            ContextConsequence::Retained
        };
        Ok(ModelSwitch {
            turn_revision,
            model: request.model.clone(),
            cache,
            context,
        })
    }
}

// ---------------------------------------------------------------------------
// Credential pools
// ---------------------------------------------------------------------------

/// A coordinate for looking a credential up in a secret store.
///
/// The reference is not the credential. Constructing one from a secret does not
/// compile, because the constructor accepts only a plain coordinate:
///
/// ```
/// use automonique_protocol::models::CredentialReference;
/// let reference = CredentialReference::new("vault://acme/eu/key-1").unwrap();
/// assert_eq!(reference.as_str(), "vault://acme/eu/key-1");
/// ```
///
/// ```compile_fail
/// use automonique_protocol::models::CredentialReference;
/// use automonique_protocol::primitives::SecretText;
/// let secret: SecretText<32> = SecretText::new("synthetic-value").unwrap();
/// let reference = CredentialReference::new(secret).unwrap();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialReference(String);

impl CredentialReference {
    /// Record where a credential lives.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid coordinate.
    pub fn new(value: &str) -> Result<Self, ModelError> {
        bounded(value, "credential_reference")?;
        Ok(Self(value.to_owned()))
    }

    /// The coordinate.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A quota observation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Quota {
    /// No quota is enforced for this account.
    Unmetered,
    /// This many units remain. Zero means exhausted.
    Remaining(u64),
}

/// What an account has consumed.
///
/// Every field is a count. No field can hold credential material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountUsage {
    requests: u64,
    input_tokens: u64,
    output_tokens: u64,
    quota: Quota,
}

impl AccountUsage {
    /// Record an observation of usage.
    #[must_use]
    pub const fn new(requests: u64, input_tokens: u64, output_tokens: u64, quota: Quota) -> Self {
        Self {
            requests,
            input_tokens,
            output_tokens,
            quota,
        }
    }

    /// Requests issued.
    #[must_use]
    pub const fn requests(self) -> u64 {
        self.requests
    }

    /// Input tokens consumed.
    #[must_use]
    pub const fn input_tokens(self) -> u64 {
        self.input_tokens
    }

    /// Output tokens produced.
    #[must_use]
    pub const fn output_tokens(self) -> u64 {
        self.output_tokens
    }

    /// Remaining quota.
    #[must_use]
    pub const fn quota(self) -> Quota {
        self.quota
    }
}

/// What an account can currently do.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AccountState {
    /// Serving normally.
    Available,
    /// Temporarily rate limited.
    RateLimited,
    /// Out of quota until the window resets.
    Exhausted,
}

impl AccountState {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::RateLimited => "rate_limited",
            Self::Exhausted => "exhausted",
        }
    }
}

/// Every field a [`PoolAccount`] needs, named at the call site.
#[derive(Clone, Debug)]
pub struct PoolAccountParts<'a> {
    /// The account identifier.
    pub id: ProviderAccountId,
    /// The organization that owns the account.
    pub owner_organization: &'a str,
    /// The tenant billed for its usage.
    pub billing_tenant: &'a str,
    /// The data boundary its traffic stays inside.
    pub data_boundary: &'a str,
    /// Where the credential lives. Never the credential itself.
    pub credential: CredentialReference,
    /// Observed usage.
    pub usage: AccountUsage,
    /// Observed state.
    pub state: AccountState,
}

/// One provider account inside a credential pool.
///
/// Usage and exhaustion are readable:
///
/// ```
/// # use automonique_protocol::models::{
/// #     AccountState, AccountUsage, CredentialReference, PoolAccount, PoolAccountParts,
/// #     ProviderAccountId, Quota,
/// # };
/// let account = PoolAccount::declare(PoolAccountParts {
///     id: ProviderAccountId::new("acct-eu-1").unwrap(),
///     owner_organization: "acme",
///     billing_tenant: "acme-eu",
///     data_boundary: "eu",
///     credential: CredentialReference::new("vault://acme/eu/key-1").unwrap(),
///     usage: AccountUsage::new(12, 900, 300, Quota::Remaining(0)),
///     state: AccountState::Exhausted,
/// })
/// .unwrap();
/// assert!(account.is_exhausted());
/// let coordinate = account.credential_reference();
/// ```
///
/// The credential value is not, because no accessor returns one:
///
/// ```compile_fail
/// # use automonique_protocol::models::{
/// #     AccountState, AccountUsage, CredentialReference, PoolAccount, PoolAccountParts,
/// #     ProviderAccountId, Quota,
/// # };
/// # let account = PoolAccount::declare(PoolAccountParts {
/// #     id: ProviderAccountId::new("acct-eu-1").unwrap(),
/// #     owner_organization: "acme",
/// #     billing_tenant: "acme-eu",
/// #     data_boundary: "eu",
/// #     credential: CredentialReference::new("vault://acme/eu/key-1").unwrap(),
/// #     usage: AccountUsage::new(12, 900, 300, Quota::Remaining(0)),
/// #     state: AccountState::Exhausted,
/// # })
/// # .unwrap();
/// let secret = account.credential_value();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolAccount {
    id: ProviderAccountId,
    owner_organization: String,
    billing_tenant: String,
    data_boundary: String,
    credential: CredentialReference,
    usage: AccountUsage,
    state: AccountState,
}

impl PoolAccount {
    /// Declare an account.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid component.
    pub fn declare(parts: PoolAccountParts<'_>) -> Result<Self, ModelError> {
        bounded(parts.owner_organization, "owner_organization")?;
        bounded(parts.billing_tenant, "billing_tenant")?;
        bounded(parts.data_boundary, "data_boundary")?;
        Ok(Self {
            id: parts.id,
            owner_organization: parts.owner_organization.to_owned(),
            billing_tenant: parts.billing_tenant.to_owned(),
            data_boundary: parts.data_boundary.to_owned(),
            credential: parts.credential,
            usage: parts.usage,
            state: parts.state,
        })
    }

    /// The account identifier.
    #[must_use]
    pub const fn id(&self) -> &ProviderAccountId {
        &self.id
    }

    /// The owning organization.
    #[must_use]
    pub fn owner_organization(&self) -> &str {
        &self.owner_organization
    }

    /// The billed tenant.
    #[must_use]
    pub fn billing_tenant(&self) -> &str {
        &self.billing_tenant
    }

    /// The data boundary.
    #[must_use]
    pub fn data_boundary(&self) -> &str {
        &self.data_boundary
    }

    /// Where the credential lives.
    #[must_use]
    pub const fn credential_reference(&self) -> &CredentialReference {
        &self.credential
    }

    /// Observed usage.
    #[must_use]
    pub const fn usage(&self) -> AccountUsage {
        self.usage
    }

    /// Observed state.
    #[must_use]
    pub const fn state(&self) -> AccountState {
        self.state
    }

    /// Whether the account is out of quota.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        matches!(self.state, AccountState::Exhausted)
            || matches!(self.usage.quota, Quota::Remaining(0))
    }
}

/// Every field a [`CredentialPool`] needs, named at the call site.
#[derive(Clone, Debug)]
pub struct CredentialPoolParts<'a> {
    /// The pool identifier.
    pub id: &'a str,
    /// The organization every account belongs to.
    pub owner_organization: &'a str,
    /// The tenant every account bills to.
    pub billing_tenant: &'a str,
    /// The data boundary every account stays inside.
    pub data_boundary: &'a str,
    /// The accounts grouped by this pool.
    pub accounts: Vec<PoolAccount>,
}

/// A reviewed group of provider accounts sharing organization, billing tenant
/// and data boundary.
///
/// The `'pool` parameter is a brand, not a borrow: [`with_credential_pool`]
/// introduces it under a higher-ranked bound, so two pools never share one, and
/// a member of one pool cannot be named in the same expression as a member of
/// another.
#[derive(Debug)]
pub struct CredentialPool<'pool> {
    brand: PhantomData<fn(&'pool ()) -> &'pool ()>,
    id: String,
    owner_organization: String,
    billing_tenant: String,
    data_boundary: String,
    accounts: Vec<PoolAccount>,
}

impl<'pool> CredentialPool<'pool> {
    /// The pool identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The organization every account belongs to.
    #[must_use]
    pub fn owner_organization(&self) -> &str {
        &self.owner_organization
    }

    /// The tenant every account bills to.
    #[must_use]
    pub fn billing_tenant(&self) -> &str {
        &self.billing_tenant
    }

    /// The data boundary every account stays inside.
    #[must_use]
    pub fn data_boundary(&self) -> &str {
        &self.data_boundary
    }

    /// The accounts in the pool.
    #[must_use]
    pub fn accounts(&self) -> &[PoolAccount] {
        &self.accounts
    }

    /// The accounts observed out of quota.
    #[must_use]
    pub fn exhausted(&self) -> Vec<&PoolAccount> {
        self.accounts
            .iter()
            .filter(|account| account.is_exhausted())
            .collect()
    }

    /// Take a pool-scoped handle on one account.
    ///
    /// The handle carries the pool's brand, which is what confines a rotation
    /// to one pool.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::UnknownAccount`] when the pool does not contain it.
    pub fn member(&self, account: &str) -> Result<PoolMember<'pool>, ModelError> {
        self.accounts
            .iter()
            .find(|candidate| candidate.id.as_str() == account)
            .map(|found| PoolMember {
                brand: PhantomData,
                account: found.id.clone(),
                state: found.state,
                exhausted: found.is_exhausted(),
            })
            .ok_or_else(|| ModelError::UnknownAccount {
                account: account.to_owned(),
            })
    }
}

/// A pool-scoped handle on one account.
///
/// The handle is branded with the pool that issued it and cannot leave the
/// pool's scope, so no expression can hold handles from two pools at once.
#[derive(Clone, Debug)]
pub struct PoolMember<'pool> {
    brand: PhantomData<fn(&'pool ()) -> &'pool ()>,
    account: ProviderAccountId,
    state: AccountState,
    exhausted: bool,
}

impl PoolMember<'_> {
    /// The account this handle names.
    #[must_use]
    pub const fn account(&self) -> &ProviderAccountId {
        &self.account
    }

    /// The account's observed state.
    #[must_use]
    pub const fn state(&self) -> AccountState {
        self.state
    }

    /// Whether the account is out of quota.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.exhausted
    }
}

/// Why a rotation was planned.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RotationTrigger {
    /// The source account is rate limited.
    RateLimited,
    /// The source account failed to authenticate.
    AuthFailure,
    /// The source account is out of quota.
    Exhausted,
    /// A reviewed schedule rotates keys.
    ScheduledReview,
}

/// A rotation from one account to another inside one pool.
///
/// Both handles carry the same brand, so rotating within a pool compiles:
///
/// ```
/// use automonique_protocol::models::{
///     AccountState, AccountUsage, CredentialPoolParts, CredentialReference, PoolAccount,
///     PoolAccountParts, ProviderAccountId, Quota, Rotation, RotationTrigger,
///     with_credential_pool,
/// };
/// # fn account(id: &str) -> PoolAccount {
/// #     PoolAccount::declare(PoolAccountParts {
/// #         id: ProviderAccountId::new(id).unwrap(),
/// #         owner_organization: "acme",
/// #         billing_tenant: "acme-eu",
/// #         data_boundary: "eu",
/// #         credential: CredentialReference::new("vault://acme/eu/key").unwrap(),
/// #         usage: AccountUsage::new(0, 0, 0, Quota::Unmetered),
/// #         state: AccountState::Available,
/// #     })
/// #     .unwrap()
/// # }
/// # fn parts<'a>(id: &'a str, accounts: Vec<PoolAccount>) -> CredentialPoolParts<'a> {
/// #     CredentialPoolParts {
/// #         id,
/// #         owner_organization: "acme",
/// #         billing_tenant: "acme-eu",
/// #         data_boundary: "eu",
/// #         accounts,
/// #     }
/// # }
/// let planned = with_credential_pool(parts("pool-a", vec![account("a-1")]), |_outer| {
///     with_credential_pool(
///         parts("pool-b", vec![account("b-1"), account("b-2")]),
///         |inner| {
///             let from = inner.member("b-1").unwrap();
///             let to = inner.member("b-2").unwrap();
///             Rotation::plan(from, to, RotationTrigger::RateLimited)
///                 .unwrap()
///                 .target()
///                 .account()
///                 .as_str()
///                 .to_owned()
///         },
///     )
///     .unwrap()
/// })
/// .unwrap();
/// assert_eq!(planned, "b-2");
/// ```
///
/// Taking the source from one pool and the target from another does not:
///
/// ```compile_fail
/// use automonique_protocol::models::{
///     AccountState, AccountUsage, CredentialPoolParts, CredentialReference, PoolAccount,
///     PoolAccountParts, ProviderAccountId, Quota, Rotation, RotationTrigger,
///     with_credential_pool,
/// };
/// # fn account(id: &str) -> PoolAccount {
/// #     PoolAccount::declare(PoolAccountParts {
/// #         id: ProviderAccountId::new(id).unwrap(),
/// #         owner_organization: "acme",
/// #         billing_tenant: "acme-eu",
/// #         data_boundary: "eu",
/// #         credential: CredentialReference::new("vault://acme/eu/key").unwrap(),
/// #         usage: AccountUsage::new(0, 0, 0, Quota::Unmetered),
/// #         state: AccountState::Available,
/// #     })
/// #     .unwrap()
/// # }
/// # fn parts<'a>(id: &'a str, accounts: Vec<PoolAccount>) -> CredentialPoolParts<'a> {
/// #     CredentialPoolParts {
/// #         id,
/// #         owner_organization: "acme",
/// #         billing_tenant: "acme-eu",
/// #         data_boundary: "eu",
/// #         accounts,
/// #     }
/// # }
/// let planned = with_credential_pool(parts("pool-a", vec![account("a-1")]), |outer| {
///     let from = outer.member("a-1").unwrap();
///     with_credential_pool(parts("pool-b", vec![account("b-2")]), |inner| {
///         let to = inner.member("b-2").unwrap();
///         Rotation::plan(from, to, RotationTrigger::RateLimited)
///             .unwrap()
///             .target()
///             .account()
///             .as_str()
///             .to_owned()
///     })
///     .unwrap()
/// })
/// .unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct Rotation<'pool> {
    source: PoolMember<'pool>,
    target: PoolMember<'pool>,
    trigger: RotationTrigger,
}

impl<'pool> Rotation<'pool> {
    /// Plan a rotation inside one pool.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::RotationToSelf`] when both handles name the same
    /// account, and [`ModelError::RotationTargetUnavailable`] when the target
    /// cannot serve traffic. Crossing pools is not an error variant because it
    /// does not compile.
    pub fn plan(
        source: PoolMember<'pool>,
        target: PoolMember<'pool>,
        trigger: RotationTrigger,
    ) -> Result<Self, ModelError> {
        if source.account == target.account {
            return Err(ModelError::RotationToSelf {
                account: source.account.as_str().to_owned(),
            });
        }
        if target.state != AccountState::Available || target.exhausted {
            return Err(ModelError::RotationTargetUnavailable {
                account: target.account.as_str().to_owned(),
                state: target.state.as_str(),
            });
        }
        Ok(Self {
            source,
            target,
            trigger,
        })
    }

    /// The account being rotated away from.
    #[must_use]
    pub const fn source(&self) -> &PoolMember<'pool> {
        &self.source
    }

    /// The account being rotated to.
    #[must_use]
    pub const fn target(&self) -> &PoolMember<'pool> {
        &self.target
    }

    /// Why the rotation was planned.
    #[must_use]
    pub const fn trigger(&self) -> RotationTrigger {
        self.trigger
    }
}

/// Open a branded credential pool and run `scope` inside it.
///
/// The higher-ranked bound gives each call a fresh, invariant `'pool` brand.
/// Because `R` cannot name that brand, no [`PoolMember`] escapes the scope, and
/// because two calls never share a brand, a rotation cannot name two pools.
///
/// # Errors
///
/// Returns [`ModelError::Field`] for an invalid component and
/// [`ModelError::PoolPolicyMismatch`] when an account declares a different
/// organization, billing tenant or data boundary than the pool it was placed
/// in — the property that makes rotation inside a pool safe.
pub fn with_credential_pool<R>(
    parts: CredentialPoolParts<'_>,
    scope: impl for<'pool> FnOnce(CredentialPool<'pool>) -> R,
) -> Result<R, ModelError> {
    bounded(parts.id, "pool_id")?;
    bounded(parts.owner_organization, "owner_organization")?;
    bounded(parts.billing_tenant, "billing_tenant")?;
    bounded(parts.data_boundary, "data_boundary")?;
    for account in &parts.accounts {
        for (actual, expected, axis) in [
            (
                account.owner_organization.as_str(),
                parts.owner_organization,
                "owner_organization",
            ),
            (
                account.billing_tenant.as_str(),
                parts.billing_tenant,
                "billing_tenant",
            ),
            (
                account.data_boundary.as_str(),
                parts.data_boundary,
                "data_boundary",
            ),
        ] {
            if actual != expected {
                return Err(ModelError::PoolPolicyMismatch {
                    account: account.id.as_str().to_owned(),
                    axis,
                });
            }
        }
    }
    Ok(scope(CredentialPool {
        brand: PhantomData,
        id: parts.id.to_owned(),
        owner_organization: parts.owner_organization.to_owned(),
        billing_tenant: parts.billing_tenant.to_owned(),
        data_boundary: parts.data_boundary.to_owned(),
        accounts: parts.accounts,
    }))
}

// ---------------------------------------------------------------------------
// Fallback chains
// ---------------------------------------------------------------------------

/// A class of traffic that declares its own fallback chain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FallbackClass {
    /// The actor's primary turn.
    PrimaryTurn,
    /// Session titling.
    Titling,
    /// Context compression.
    Compression,
    /// Memory review.
    MemoryReview,
    /// Image and vision analysis.
    Vision,
    /// Speech to text.
    Transcription,
    /// Text to speech.
    Speech,
    /// Evaluation and grading.
    Evaluation,
}

impl FallbackClass {
    /// Every class, for coverage checks.
    pub const ALL: [Self; 8] = [
        Self::PrimaryTurn,
        Self::Titling,
        Self::Compression,
        Self::MemoryReview,
        Self::Vision,
        Self::Transcription,
        Self::Speech,
        Self::Evaluation,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrimaryTurn => "primary_turn",
            Self::Titling => "titling",
            Self::Compression => "compression",
            Self::MemoryReview => "memory_review",
            Self::Vision => "vision",
            Self::Transcription => "transcription",
            Self::Speech => "speech",
            Self::Evaluation => "evaluation",
        }
    }
}

/// How much a hop is contained, ordered weakest containment first.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SandboxContainment {
    /// Runs directly on the host.
    HostDirect,
    /// Contained, with brokered egress.
    BrokeredEgress,
    /// Contained in an isolated workspace with no egress.
    IsolatedWorkspace,
    /// Contained with no filesystem or network reach at all.
    SealedOffline,
}

impl SandboxContainment {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostDirect => "host_direct",
            Self::BrokeredEgress => "brokered_egress",
            Self::IsolatedWorkspace => "isolated_workspace",
            Self::SealedOffline => "sealed_offline",
        }
    }
}

/// How much review an action needs, ordered weakest first.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ApprovalSemantics {
    /// Runs without asking.
    Automatic,
    /// Runs and notifies.
    NotifyOnly,
    /// Waits for one reviewer.
    ReviewRequired,
    /// Waits for two independent reviewers.
    DualControl,
}

impl ApprovalSemantics {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::NotifyOnly => "notify_only",
            Self::ReviewRequired => "review_required",
            Self::DualControl => "dual_control",
        }
    }
}

/// The semantics a hop runs under.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HopSemantics {
    tools: Vec<String>,
    containment: SandboxContainment,
    residency_zone: String,
    approval: ApprovalSemantics,
}

impl HopSemantics {
    /// Declare the semantics a hop offers.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid tool name or zone.
    pub fn new(
        tools: &[&str],
        containment: SandboxContainment,
        residency_zone: &str,
        approval: ApprovalSemantics,
    ) -> Result<Self, ModelError> {
        for tool in tools {
            bounded(tool, "tool")?;
        }
        bounded(residency_zone, "residency_zone")?;
        Ok(Self {
            tools: tools.iter().map(|tool| (*tool).to_owned()).collect(),
            containment,
            residency_zone: residency_zone.to_owned(),
            approval,
        })
    }

    /// The tools the hop offers.
    #[must_use]
    pub fn tools(&self) -> &[String] {
        &self.tools
    }

    /// How contained the hop is.
    #[must_use]
    pub const fn containment(&self) -> SandboxContainment {
        self.containment
    }

    /// Where the hop's data stays.
    #[must_use]
    pub fn residency_zone(&self) -> &str {
        &self.residency_zone
    }

    /// How much review the hop applies.
    #[must_use]
    pub const fn approval(&self) -> ApprovalSemantics {
        self.approval
    }
}

/// One hop of a fallback chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackHop {
    account: ProviderAccountId,
    model: ModelRef,
    semantics: HopSemantics,
}

impl FallbackHop {
    /// Declare a hop.
    #[must_use]
    pub const fn new(account: ProviderAccountId, model: ModelRef, semantics: HopSemantics) -> Self {
        Self {
            account,
            model,
            semantics,
        }
    }

    /// The account the hop bills to.
    #[must_use]
    pub const fn account(&self) -> &ProviderAccountId {
        &self.account
    }

    /// The model the hop uses.
    #[must_use]
    pub const fn model(&self) -> &ModelRef {
        &self.model
    }

    /// The semantics the hop runs under.
    #[must_use]
    pub const fn semantics(&self) -> &HopSemantics {
        &self.semantics
    }
}

/// A declared fallback chain for one class of traffic.
///
/// Weakening is refused at declaration, so a chain that reaches dispatch cannot
/// downgrade tools, sandbox, residency or approval on a later hop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackChain {
    class: FallbackClass,
    hops: Vec<FallbackHop>,
}

impl FallbackChain {
    /// Declare a chain.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::EmptyChain`] for a chain with no hops, and
    /// [`ModelError::FallbackWeakens`] naming the axis and hop index when a
    /// later hop offers fewer tools, less containment, a different residency
    /// zone or weaker approval than the requested head hop.
    pub fn declare(class: FallbackClass, hops: Vec<FallbackHop>) -> Result<Self, ModelError> {
        let Some(head) = hops.first() else {
            return Err(ModelError::EmptyChain);
        };
        let requested = head.semantics.clone();
        for (index, hop) in hops.iter().enumerate().skip(1) {
            if requested
                .tools
                .iter()
                .any(|tool| !hop.semantics.tools.contains(tool))
            {
                return Err(ModelError::FallbackWeakens {
                    axis: "tools",
                    hop: index,
                });
            }
            if hop.semantics.containment < requested.containment {
                return Err(ModelError::FallbackWeakens {
                    axis: "sandbox",
                    hop: index,
                });
            }
            if hop.semantics.residency_zone != requested.residency_zone {
                return Err(ModelError::FallbackWeakens {
                    axis: "residency",
                    hop: index,
                });
            }
            if hop.semantics.approval < requested.approval {
                return Err(ModelError::FallbackWeakens {
                    axis: "approval",
                    hop: index,
                });
            }
        }
        Ok(Self { class, hops })
    }

    /// The class this chain serves.
    #[must_use]
    pub const fn class(&self) -> FallbackClass {
        self.class
    }

    /// The hops, in order.
    #[must_use]
    pub fn hops(&self) -> &[FallbackHop] {
        &self.hops
    }
}

/// Chains declared independently per class.
///
/// There is no chain that serves every class, so a class without a declared
/// chain is visible rather than silently inheriting another class's policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FallbackRegistry {
    chains: Vec<FallbackChain>,
}

impl FallbackRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare the chain for one class.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::DuplicateChainClass`] when the class already has
    /// one, because a second declaration would make the effective chain depend
    /// on registration order.
    pub fn declare(&mut self, chain: FallbackChain) -> Result<(), ModelError> {
        if self.chains.iter().any(|held| held.class == chain.class) {
            return Err(ModelError::DuplicateChainClass {
                class: chain.class.as_str(),
            });
        }
        self.chains.push(chain);
        Ok(())
    }

    /// The chain declared for a class, if any.
    #[must_use]
    pub fn chain_for(&self, class: FallbackClass) -> Option<&FallbackChain> {
        self.chains.iter().find(|chain| chain.class == class)
    }

    /// The classes with no declared chain.
    #[must_use]
    pub fn undeclared(&self) -> Vec<FallbackClass> {
        FallbackClass::ALL
            .into_iter()
            .filter(|class| self.chain_for(*class).is_none())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Usage, context and mixture of agents
// ---------------------------------------------------------------------------

/// How far a context item may travel.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ContextSensitivity {
    /// May be sent to a reference model.
    Shareable,
    /// Stays with the acting model.
    TenantConfidential,
    /// Never leaves the control plane.
    Restricted,
}

/// One item of turn context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextItem {
    label: String,
    sensitivity: ContextSensitivity,
    bytes: u64,
}

impl ContextItem {
    /// Record an item.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid label.
    pub fn new(
        label: &str,
        sensitivity: ContextSensitivity,
        bytes: u64,
    ) -> Result<Self, ModelError> {
        bounded(label, "context_label")?;
        Ok(Self {
            label: label.to_owned(),
            sensitivity,
            bytes,
        })
    }

    /// The item's label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// How far it may travel.
    #[must_use]
    pub const fn sensitivity(&self) -> ContextSensitivity {
        self.sensitivity
    }

    /// Its size.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// The context the acting model holds.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TurnContext {
    items: Vec<ContextItem>,
}

impl TurnContext {
    /// Assemble a turn context.
    #[must_use]
    pub const fn new(items: Vec<ContextItem>) -> Self {
        Self { items }
    }

    /// The items it holds.
    #[must_use]
    pub fn items(&self) -> &[ContextItem] {
        &self.items
    }
}

/// The context a reference model receives.
///
/// It is produced only by minimizing a [`TurnContext`]: everything above
/// [`ContextSensitivity::Shareable`] is dropped and counted, so a reference call
/// cannot be given the acting model's context by mistake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MinimizedContext {
    items: Vec<ContextItem>,
    withheld: usize,
}

impl MinimizedContext {
    /// Minimize an acting context for a reference call.
    #[must_use]
    pub fn minimize(context: &TurnContext) -> Self {
        let items: Vec<ContextItem> = context
            .items
            .iter()
            .filter(|item| item.sensitivity == ContextSensitivity::Shareable)
            .cloned()
            .collect();
        let withheld = context.items.len() - items.len();
        Self { items, withheld }
    }

    /// The items that were shareable.
    #[must_use]
    pub fn items(&self) -> &[ContextItem] {
        &self.items
    }

    /// How many items were withheld.
    #[must_use]
    pub const fn withheld(&self) -> usize {
        self.withheld
    }

    /// The total size of what was shared.
    #[must_use]
    pub fn shared_bytes(&self) -> u64 {
        self.items.iter().map(ContextItem::bytes).sum()
    }
}

/// What a usage record is counted against.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UsageClass {
    /// The actor's primary turn.
    PrimaryTurn,
    /// An auxiliary task such as titling or compression.
    Auxiliary,
    /// A mixture-of-agents reference call.
    Reference,
    /// The acting aggregator's own call.
    Aggregation,
}

impl UsageClass {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrimaryTurn => "primary_turn",
            Self::Auxiliary => "auxiliary",
            Self::Reference => "reference",
            Self::Aggregation => "aggregation",
        }
    }
}

/// One first-class usage record counted against a tenant budget.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageRecord {
    tenant: String,
    account: ProviderAccountId,
    model: ModelRef,
    class: UsageClass,
    input_tokens: u64,
    output_tokens: u64,
}

impl UsageRecord {
    /// Record usage.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid tenant.
    pub fn new(
        tenant: &str,
        account: ProviderAccountId,
        model: ModelRef,
        class: UsageClass,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Result<Self, ModelError> {
        bounded(tenant, "tenant")?;
        Ok(Self {
            tenant: tenant.to_owned(),
            account,
            model,
            class,
            input_tokens,
            output_tokens,
        })
    }

    /// The tenant billed.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The account billed.
    #[must_use]
    pub const fn account(&self) -> &ProviderAccountId {
        &self.account
    }

    /// The model called.
    #[must_use]
    pub const fn model(&self) -> &ModelRef {
        &self.model
    }

    /// What the call was.
    #[must_use]
    pub const fn class(&self) -> UsageClass {
        self.class
    }

    /// Input tokens.
    #[must_use]
    pub const fn input_tokens(&self) -> u64 {
        self.input_tokens
    }

    /// Output tokens.
    #[must_use]
    pub const fn output_tokens(&self) -> u64 {
        self.output_tokens
    }
}

/// A reference model's output.
///
/// The wrapper exists so that reading advice is greppable and so that advice
/// has no `Display` and no conversion into any authoritative text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedAdvice(String);

impl UntrustedAdvice {
    /// Read the advice, acknowledging that it is untrusted.
    #[must_use]
    pub fn expose_untrusted(&self) -> &str {
        &self.0
    }
}

/// A bounded call to a reference model.
///
/// The call takes a [`MinimizedContext`] and nothing else that could grant
/// reach: there is no toolset argument, so a reference model holding tools is
/// unrepresentable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceCall {
    tenant: String,
    account: ProviderAccountId,
    model: ModelRef,
    context: MinimizedContext,
}

impl ReferenceCall {
    /// Prepare a reference call.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid tenant.
    pub fn new(
        tenant: &str,
        account: ProviderAccountId,
        model: ModelRef,
        context: MinimizedContext,
    ) -> Result<Self, ModelError> {
        bounded(tenant, "tenant")?;
        Ok(Self {
            tenant: tenant.to_owned(),
            account,
            model,
            context,
        })
    }

    /// The minimized context the reference model receives.
    #[must_use]
    pub const fn context(&self) -> &MinimizedContext {
        &self.context
    }

    /// The model called.
    #[must_use]
    pub const fn model(&self) -> &ModelRef {
        &self.model
    }

    /// Record the reference model's answer as untrusted advice.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for invalid advice text.
    pub fn respond(
        self,
        advice: &str,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Result<ReferenceOutput, ModelError> {
        bounded(advice, "advice")?;
        let usage = UsageRecord::new(
            &self.tenant,
            self.account.clone(),
            self.model.clone(),
            UsageClass::Reference,
            input_tokens,
            output_tokens,
        )?;
        Ok(ReferenceOutput {
            model: self.model,
            advice: UntrustedAdvice(advice.to_owned()),
            usage,
        })
    }
}

/// One reference model's untrusted advice, with its usage record.
///
/// It has no approval accessor and no conversion into an authoritative record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceOutput {
    model: ModelRef,
    advice: UntrustedAdvice,
    usage: UsageRecord,
}

impl ReferenceOutput {
    /// The model that produced the advice.
    #[must_use]
    pub const fn model(&self) -> &ModelRef {
        &self.model
    }

    /// The advice.
    #[must_use]
    pub const fn advice(&self) -> &UntrustedAdvice {
        &self.advice
    }

    /// The usage this reference call cost.
    #[must_use]
    pub const fn usage(&self) -> &UsageRecord {
        &self.usage
    }
}

/// The one model that acts.
///
/// Only an aggregator holds tools, and only an aggregator produces an
/// [`AggregateResult`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Aggregator {
    tenant: String,
    account: ProviderAccountId,
    model: ModelRef,
    tools: Vec<String>,
}

impl Aggregator {
    /// Declare the acting aggregator.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid tenant or tool name.
    pub fn new(
        tenant: &str,
        account: ProviderAccountId,
        model: ModelRef,
        tools: &[&str],
    ) -> Result<Self, ModelError> {
        bounded(tenant, "tenant")?;
        for tool in tools {
            bounded(tool, "tool")?;
        }
        Ok(Self {
            tenant: tenant.to_owned(),
            account,
            model,
            tools: tools.iter().map(|tool| (*tool).to_owned()).collect(),
        })
    }

    /// The tools the aggregator holds.
    #[must_use]
    pub fn tools(&self) -> &[String] {
        &self.tools
    }

    /// The aggregator's model.
    #[must_use]
    pub const fn model(&self) -> &ModelRef {
        &self.model
    }

    /// Produce the authoritative result, retaining the advice considered.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for invalid result text.
    pub fn conclude(
        &self,
        text: &str,
        references: Vec<ReferenceOutput>,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Result<AggregateResult, ModelError> {
        bounded(text, "result_text")?;
        let usage = UsageRecord::new(
            &self.tenant,
            self.account.clone(),
            self.model.clone(),
            UsageClass::Aggregation,
            input_tokens,
            output_tokens,
        )?;
        Ok(AggregateResult {
            author: self.model.clone(),
            text: text.to_owned(),
            references,
            usage,
        })
    }
}

/// The authoritative record of a mixture-of-agents turn.
///
/// Only [`Aggregator::conclude`] builds one:
///
/// ```
/// # use automonique_protocol::models::{
/// #     Aggregator, MinimizedContext, ModelRef, ProviderAccountId, ReferenceCall, TurnContext,
/// # };
/// # let aggregator = Aggregator::new(
/// #     "acme",
/// #     ProviderAccountId::new("acct-1").unwrap(),
/// #     ModelRef::new("anthropic", "opus").unwrap(),
/// #     &["read_file"],
/// # )
/// # .unwrap();
/// # let context = MinimizedContext::minimize(&TurnContext::new(Vec::new()));
/// # let reference = ReferenceCall::new(
/// #     "acme",
/// #     ProviderAccountId::new("acct-2").unwrap(),
/// #     ModelRef::new("openai", "reference").unwrap(),
/// #     context,
/// # )
/// # .unwrap()
/// # .respond("consider the cache", 10, 5)
/// # .unwrap();
/// let result = aggregator.conclude("the plan", vec![reference], 40, 20).unwrap();
/// assert_eq!(result.text(), "the plan");
/// ```
///
/// A reference output cannot be promoted into one:
///
/// ```compile_fail
/// # use automonique_protocol::models::{
/// #     AggregateResult, MinimizedContext, ModelRef, ProviderAccountId, ReferenceCall,
/// #     TurnContext,
/// # };
/// # let context = MinimizedContext::minimize(&TurnContext::new(Vec::new()));
/// # let reference = ReferenceCall::new(
/// #     "acme",
/// #     ProviderAccountId::new("acct-2").unwrap(),
/// #     ModelRef::new("openai", "reference").unwrap(),
/// #     context,
/// # )
/// # .unwrap()
/// # .respond("consider the cache", 10, 5)
/// # .unwrap();
/// let result: AggregateResult = reference;
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateResult {
    author: ModelRef,
    text: String,
    references: Vec<ReferenceOutput>,
    usage: UsageRecord,
}

impl AggregateResult {
    /// The acting model that authored the result.
    #[must_use]
    pub const fn author(&self) -> &ModelRef {
        &self.author
    }

    /// The authoritative text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The advice considered, still labelled untrusted.
    #[must_use]
    pub fn references(&self) -> &[ReferenceOutput] {
        &self.references
    }

    /// Every usage record this turn produced: one per reference call plus the
    /// aggregator's own.
    #[must_use]
    pub fn usage_records(&self) -> Vec<&UsageRecord> {
        let mut records: Vec<&UsageRecord> =
            self.references.iter().map(ReferenceOutput::usage).collect();
        records.push(&self.usage);
        records
    }
}

// ---------------------------------------------------------------------------
// Approval, voice and wake word
// ---------------------------------------------------------------------------

/// A channel an approval may arrive on.
///
/// There is deliberately no spoken variant. Adding one would be the whole
/// vulnerability, so the enum is the boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ApprovalChannel {
    /// A reviewed console session bound to the actor's identity.
    ReviewedConsole,
    /// A platform identity challenge answered out of band.
    PlatformIdentityChallenge,
}

impl ApprovalChannel {
    /// Every channel, for coverage checks.
    pub const ALL: [Self; 2] = [Self::ReviewedConsole, Self::PlatformIdentityChallenge];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReviewedConsole => "reviewed_console",
            Self::PlatformIdentityChallenge => "platform_identity_challenge",
        }
    }
}

/// Evidence that an identified actor approved one specific action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalEvidence {
    actor: String,
    channel: ApprovalChannel,
    action_digest: String,
}

impl ApprovalEvidence {
    /// Record an approval.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid actor or digest.
    pub fn new(
        actor: &str,
        channel: ApprovalChannel,
        action_digest: &str,
    ) -> Result<Self, ModelError> {
        bounded(actor, "actor")?;
        bounded(action_digest, "action_digest")?;
        Ok(Self {
            actor: actor.to_owned(),
            channel,
            action_digest: action_digest.to_owned(),
        })
    }

    /// Who approved.
    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }

    /// How the approval arrived.
    #[must_use]
    pub const fn channel(&self) -> ApprovalChannel {
        self.channel
    }

    /// The exact action approved.
    #[must_use]
    pub fn action_digest(&self) -> &str {
        &self.action_digest
    }
}

/// An action waiting on approval.
///
/// Approval is satisfied only by [`ApprovalEvidence`] naming the same action:
///
/// ```
/// use automonique_protocol::models::{ApprovalChannel, ApprovalEvidence, PendingApproval};
/// let pending = PendingApproval::new("deploy", "sha256:action").unwrap();
/// let evidence =
///     ApprovalEvidence::new("ada", ApprovalChannel::ReviewedConsole, "sha256:action").unwrap();
/// assert!(pending.is_satisfied_by(&evidence));
/// ```
///
/// A spoken confirmation is not evidence, and cannot be offered as any:
///
/// ```compile_fail
/// use automonique_protocol::models::{PendingApproval, SpokenConfirmation};
/// let pending = PendingApproval::new("deploy", "sha256:action").unwrap();
/// let spoken = SpokenConfirmation::new("yes, deploy it").unwrap();
/// assert!(pending.is_satisfied_by(&spoken));
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingApproval {
    class: String,
    action_digest: String,
}

impl PendingApproval {
    /// Record that an action is waiting.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid class or digest.
    pub fn new(class: &str, action_digest: &str) -> Result<Self, ModelError> {
        bounded(class, "approval_class")?;
        bounded(action_digest, "action_digest")?;
        Ok(Self {
            class: class.to_owned(),
            action_digest: action_digest.to_owned(),
        })
    }

    /// The class of authority sought.
    #[must_use]
    pub fn class(&self) -> &str {
        &self.class
    }

    /// The action waiting.
    #[must_use]
    pub fn action_digest(&self) -> &str {
        &self.action_digest
    }

    /// Whether this evidence approves this action.
    #[must_use]
    pub fn is_satisfied_by(&self, evidence: &ApprovalEvidence) -> bool {
        evidence.action_digest == self.action_digest
    }

    /// Resolve the pending action.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::ApprovalMismatch`] when the evidence names another
    /// action, so approval for one action never authorizes a second.
    pub fn resolve(self, evidence: &ApprovalEvidence) -> Result<ApprovedAction, ModelError> {
        if !self.is_satisfied_by(evidence) {
            return Err(ModelError::ApprovalMismatch);
        }
        Ok(ApprovedAction {
            action_digest: self.action_digest,
            actor: evidence.actor.clone(),
            channel: evidence.channel,
        })
    }
}

/// An action that was approved by an identified actor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedAction {
    action_digest: String,
    actor: String,
    channel: ApprovalChannel,
}

impl ApprovedAction {
    /// The action approved.
    #[must_use]
    pub fn action_digest(&self) -> &str {
        &self.action_digest
    }

    /// Who approved it.
    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }

    /// How the approval arrived.
    #[must_use]
    pub const fn channel(&self) -> ApprovalChannel {
        self.channel
    }
}

/// Something a person said.
///
/// Its only outward path is a context item, which is content, not authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpokenConfirmation {
    transcript: String,
}

impl SpokenConfirmation {
    /// Record what was said.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid transcript.
    pub fn new(transcript: &str) -> Result<Self, ModelError> {
        bounded(transcript, "transcript")?;
        Ok(Self {
            transcript: transcript.to_owned(),
        })
    }

    /// What was said.
    #[must_use]
    pub fn transcript(&self) -> &str {
        &self.transcript
    }

    /// Turn the utterance into ordinary turn content.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid transcript.
    pub fn into_context_item(self) -> Result<ContextItem, ModelError> {
        let bytes = self.transcript.len() as u64;
        ContextItem::new(
            "voice_transcript",
            ContextSensitivity::TenantConfidential,
            bytes,
        )
    }
}

/// A locally detected wake word.
///
/// Detection starts capture. It grants nothing, which is why the only thing it
/// produces is a [`CaptureStart`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WakeWordDetection {
    phrase: String,
    detected_at: EpochMillis,
    detected_locally: bool,
}

impl WakeWordDetection {
    /// Record a detection.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid phrase.
    pub fn new(
        phrase: &str,
        detected_at: EpochMillis,
        detected_locally: bool,
    ) -> Result<Self, ModelError> {
        bounded(phrase, "wake_phrase")?;
        Ok(Self {
            phrase: phrase.to_owned(),
            detected_at,
            detected_locally,
        })
    }

    /// The phrase detected.
    #[must_use]
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// Whether detection happened on the device.
    #[must_use]
    pub const fn detected_locally(&self) -> bool {
        self.detected_locally
    }

    /// Begin capturing input. This is the whole of the wake word's effect.
    #[must_use]
    pub const fn begin_capture(&self) -> CaptureStart {
        CaptureStart {
            started_at: self.detected_at,
        }
    }
}

/// The start of an input capture.
///
/// It carries an instant and nothing else: no actor, no scope, no approval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureStart {
    started_at: EpochMillis,
}

impl CaptureStart {
    /// When capture began, as supplied by the caller.
    #[must_use]
    pub const fn started_at(self) -> EpochMillis {
        self.started_at
    }
}

// ---------------------------------------------------------------------------
// Media
// ---------------------------------------------------------------------------

/// A family of media adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MediaFamily {
    /// Vision and image understanding.
    Vision,
    /// Speech to text.
    SpeechToText,
    /// Text to speech.
    TextToSpeech,
    /// Wake-word detection.
    WakeWord,
    /// Image generation and editing.
    ImageGeneration,
    /// Video generation.
    VideoGeneration,
    /// OCR and document extraction.
    DocumentExtraction,
    /// Format conversion.
    MediaConversion,
}

impl MediaFamily {
    /// Every family, for coverage checks.
    pub const ALL: [Self; 8] = [
        Self::Vision,
        Self::SpeechToText,
        Self::TextToSpeech,
        Self::WakeWord,
        Self::ImageGeneration,
        Self::VideoGeneration,
        Self::DocumentExtraction,
        Self::MediaConversion,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vision => "vision",
            Self::SpeechToText => "speech_to_text",
            Self::TextToSpeech => "text_to_speech",
            Self::WakeWord => "wake_word",
            Self::ImageGeneration => "image_generation",
            Self::VideoGeneration => "video_generation",
            Self::DocumentExtraction => "document_extraction",
            Self::MediaConversion => "media_conversion",
        }
    }
}

/// Where a media backend runs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MediaDeployment {
    /// On the actor's own device.
    Local,
    /// On organization-controlled hardware.
    OrganizationHosted,
    /// On a third-party cloud.
    Cloud,
}

/// How long a media backend keeps submitted content.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MediaRetention {
    /// Discarded after the response.
    Discarded,
    /// Kept for a declared number of days.
    Days(u32),
}

/// Every field a [`MediaAdapterDeclaration`] needs, named at the call site.
#[derive(Clone, Debug)]
pub struct MediaAdapterParts<'a> {
    /// The adapter identifier.
    pub id: &'a str,
    /// Which family it belongs to.
    pub family: MediaFamily,
    /// Where it runs.
    pub deployment: MediaDeployment,
    /// Formats it accepts.
    pub formats: &'a [&'a str],
    /// Largest accepted input.
    pub max_input_bytes: u64,
    /// Longest accepted input, in milliseconds. Zero for still media.
    pub max_duration_ms: u64,
    /// The model it runs.
    pub model: ModelRef,
    /// The model's version.
    pub model_version: &'a str,
    /// Declared price.
    pub pricing: Pricing,
    /// How long it keeps content.
    pub retention: MediaRetention,
    /// Its data policy.
    pub data_policy: DataPolicy,
    /// Where its credential lives.
    pub credential: CredentialReference,
    /// How much network it is allowed.
    pub egress: NetworkAccess,
}

/// A declared media adapter.
///
/// Every field is a constructor argument, so an adapter that omits its
/// retention, data policy, credential or egress is unrepresentable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaAdapterDeclaration {
    id: String,
    family: MediaFamily,
    deployment: MediaDeployment,
    formats: Vec<String>,
    max_input_bytes: u64,
    max_duration_ms: u64,
    model: ModelRef,
    model_version: String,
    pricing: Pricing,
    retention: MediaRetention,
    data_policy: DataPolicy,
    credential: CredentialReference,
    egress: NetworkAccess,
}

impl MediaAdapterDeclaration {
    /// Declare an adapter.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid component and
    /// [`ModelError::LimitRequired`] for an empty format list or a zero input
    /// ceiling.
    pub fn declare(parts: MediaAdapterParts<'_>) -> Result<Self, ModelError> {
        bounded(parts.id, "media_adapter_id")?;
        bounded(parts.model_version, "model_version")?;
        for format in parts.formats {
            bounded(format, "format")?;
        }
        if parts.formats.is_empty() {
            return Err(ModelError::LimitRequired { field: "formats" });
        }
        if parts.max_input_bytes == 0 {
            return Err(ModelError::LimitRequired {
                field: "max_input_bytes",
            });
        }
        Ok(Self {
            id: parts.id.to_owned(),
            family: parts.family,
            deployment: parts.deployment,
            formats: parts
                .formats
                .iter()
                .map(|format| (*format).to_owned())
                .collect(),
            max_input_bytes: parts.max_input_bytes,
            max_duration_ms: parts.max_duration_ms,
            model: parts.model,
            model_version: parts.model_version.to_owned(),
            pricing: parts.pricing,
            retention: parts.retention,
            data_policy: parts.data_policy,
            credential: parts.credential,
            egress: parts.egress,
        })
    }

    /// The adapter identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Its family.
    #[must_use]
    pub const fn family(&self) -> MediaFamily {
        self.family
    }

    /// Where it runs.
    #[must_use]
    pub const fn deployment(&self) -> MediaDeployment {
        self.deployment
    }

    /// Formats it accepts.
    #[must_use]
    pub fn formats(&self) -> &[String] {
        &self.formats
    }

    /// Largest accepted input.
    #[must_use]
    pub const fn max_input_bytes(&self) -> u64 {
        self.max_input_bytes
    }

    /// Longest accepted input.
    #[must_use]
    pub const fn max_duration_ms(&self) -> u64 {
        self.max_duration_ms
    }

    /// The model it runs.
    #[must_use]
    pub const fn model(&self) -> &ModelRef {
        &self.model
    }

    /// The model's version.
    #[must_use]
    pub fn model_version(&self) -> &str {
        &self.model_version
    }

    /// Declared price.
    #[must_use]
    pub const fn pricing(&self) -> &Pricing {
        &self.pricing
    }

    /// How long it keeps content.
    #[must_use]
    pub const fn retention(&self) -> MediaRetention {
        self.retention
    }

    /// Its data policy.
    #[must_use]
    pub const fn data_policy(&self) -> &DataPolicy {
        &self.data_policy
    }

    /// Where its credential lives.
    #[must_use]
    pub const fn credential_reference(&self) -> &CredentialReference {
        &self.credential
    }

    /// How much network it is allowed.
    #[must_use]
    pub const fn egress(&self) -> NetworkAccess {
        self.egress
    }
}

/// A content-addressed artifact digest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArtifactDigest(String);

impl ArtifactDigest {
    /// Name an artifact by digest.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid digest.
    pub fn new(value: &str) -> Result<Self, ModelError> {
        bounded(value, "artifact_digest")?;
        Ok(Self(value.to_owned()))
    }

    /// The digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How widely a media artifact may be shown.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MediaVisibility {
    /// Visible only inside the tenant.
    TenantPrivate,
    /// Visible to the conversation's participants.
    ParticipantsOnly,
}

/// The protected original of a media artifact.
///
/// A platform derivative is a different type, so handing a messaging platform
/// the original where a derivative was intended does not compile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedOriginal {
    digest: ArtifactDigest,
    tenant: String,
    visibility: MediaVisibility,
}

impl ProtectedOriginal {
    /// Record a protected original.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid tenant.
    pub fn new(
        digest: ArtifactDigest,
        tenant: &str,
        visibility: MediaVisibility,
    ) -> Result<Self, ModelError> {
        bounded(tenant, "tenant")?;
        Ok(Self {
            digest,
            tenant: tenant.to_owned(),
            visibility,
        })
    }

    /// Its digest.
    #[must_use]
    pub const fn digest(&self) -> &ArtifactDigest {
        &self.digest
    }

    /// The owning tenant.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// How widely it may be shown.
    #[must_use]
    pub const fn visibility(&self) -> MediaVisibility {
        self.visibility
    }
}

/// Where a media artifact came from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaProvenance {
    source: ArtifactDigest,
    adapter: String,
    model: ModelRef,
    model_version: String,
    produced_at: EpochMillis,
}

impl MediaProvenance {
    /// Record provenance.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid component.
    pub fn new(
        source: ArtifactDigest,
        adapter: &str,
        model: ModelRef,
        model_version: &str,
        produced_at: EpochMillis,
    ) -> Result<Self, ModelError> {
        bounded(adapter, "media_adapter_id")?;
        bounded(model_version, "model_version")?;
        Ok(Self {
            source,
            adapter: adapter.to_owned(),
            model,
            model_version: model_version.to_owned(),
            produced_at,
        })
    }

    /// The artifact this one came from.
    #[must_use]
    pub const fn source(&self) -> &ArtifactDigest {
        &self.source
    }

    /// The adapter that produced it.
    #[must_use]
    pub fn adapter(&self) -> &str {
        &self.adapter
    }

    /// The model that produced it.
    #[must_use]
    pub const fn model(&self) -> &ModelRef {
        &self.model
    }

    /// The model version.
    #[must_use]
    pub fn model_version(&self) -> &str {
        &self.model_version
    }

    /// When it was produced, as supplied by the caller.
    #[must_use]
    pub const fn produced_at(&self) -> EpochMillis {
        self.produced_at
    }
}

/// A format- and size-specific derivative delivered to a platform.
///
/// It is a distinct artifact with its own digest, and it carries the provenance
/// that names the original it came from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformDerivative {
    digest: ArtifactDigest,
    format: String,
    provenance: MediaProvenance,
}

impl PlatformDerivative {
    /// Derive a platform-safe artifact from a protected original.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::DerivativeNotDistinct`] when the derivative reuses
    /// the original's digest, [`ModelError::ProvenanceMismatch`] when the
    /// provenance names a different source, and [`ModelError::Field`] for an
    /// invalid format.
    pub fn derive(
        original: &ProtectedOriginal,
        digest: ArtifactDigest,
        format: &str,
        provenance: MediaProvenance,
    ) -> Result<Self, ModelError> {
        bounded(format, "format")?;
        if digest == original.digest {
            return Err(ModelError::DerivativeNotDistinct);
        }
        if provenance.source != original.digest {
            return Err(ModelError::ProvenanceMismatch);
        }
        Ok(Self {
            digest,
            format: format.to_owned(),
            provenance,
        })
    }

    /// Its digest.
    #[must_use]
    pub const fn digest(&self) -> &ArtifactDigest {
        &self.digest
    }

    /// The delivered format.
    #[must_use]
    pub fn format(&self) -> &str {
        &self.format
    }

    /// Where it came from.
    #[must_use]
    pub const fn provenance(&self) -> &MediaProvenance {
        &self.provenance
    }
}

/// Newly generated media.
///
/// Provenance is a constructor argument, so generated media without provenance
/// is unrepresentable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedMedia {
    digest: ArtifactDigest,
    provenance: MediaProvenance,
}

impl GeneratedMedia {
    /// Record generated media.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::DerivativeNotDistinct`] when the generated digest
    /// equals its own input digest.
    pub fn record(digest: ArtifactDigest, provenance: MediaProvenance) -> Result<Self, ModelError> {
        if digest == provenance.source {
            return Err(ModelError::DerivativeNotDistinct);
        }
        Ok(Self { digest, provenance })
    }

    /// Its digest.
    #[must_use]
    pub const fn digest(&self) -> &ArtifactDigest {
        &self.digest
    }

    /// Where it came from.
    #[must_use]
    pub const fn provenance(&self) -> &MediaProvenance {
        &self.provenance
    }
}

// ---------------------------------------------------------------------------
// Browser and computer use
// ---------------------------------------------------------------------------

/// What a session may capture.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CapturePolicy {
    /// Nothing is captured.
    NoCapture,
    /// Screenshots are captured with redaction applied.
    RedactedScreenshots,
    /// Screenshots are captured whole.
    FullScreenshots,
}

/// Who a session runs as.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IsolationIdentity {
    tenant: String,
    run: String,
    profile: String,
}

impl IsolationIdentity {
    /// Record an isolation identity.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid component.
    pub fn new(tenant: &str, run: &str, profile: &str) -> Result<Self, ModelError> {
        bounded(tenant, "tenant")?;
        bounded(run, "run")?;
        bounded(profile, "profile")?;
        Ok(Self {
            tenant: tenant.to_owned(),
            run: run.to_owned(),
            profile: profile.to_owned(),
        })
    }

    /// The owning tenant.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The run the session belongs to.
    #[must_use]
    pub fn run(&self) -> &str {
        &self.run
    }

    /// The isolated profile.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

/// Every field a [`BrowserGrant`] needs, named at the call site.
#[derive(Clone, Debug)]
pub struct BrowserGrantParts<'a> {
    /// The reviewed origin allowlist.
    pub origins: &'a [&'a str],
    /// What may be captured.
    pub capture: CapturePolicy,
    /// Who the session runs as.
    pub isolation: IsolationIdentity,
    /// The sandbox attestation the session runs under.
    pub attestation: EnforcementAttestation,
    /// Who reviewed the grant.
    pub reviewer: &'a str,
    /// When it was reviewed.
    pub reviewed_at: EpochMillis,
}

/// Authority to drive a browser against a reviewed origin allowlist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserGrant {
    origins: Vec<String>,
    capture: CapturePolicy,
    isolation: IsolationIdentity,
    attestation: EnforcementAttestation,
    reviewer: String,
    reviewed_at: EpochMillis,
}

impl BrowserGrant {
    /// Declare a reviewed browser grant.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid component and
    /// [`ModelError::LimitRequired`] for an empty allowlist, because a grant
    /// with no reviewed origins would be a grant to everything.
    pub fn declare(parts: BrowserGrantParts<'_>) -> Result<Self, ModelError> {
        for origin in parts.origins {
            bounded(origin, "origin")?;
        }
        if parts.origins.is_empty() {
            return Err(ModelError::LimitRequired { field: "origins" });
        }
        bounded(parts.reviewer, "reviewer")?;
        Ok(Self {
            origins: parts
                .origins
                .iter()
                .map(|origin| (*origin).to_owned())
                .collect(),
            capture: parts.capture,
            isolation: parts.isolation,
            attestation: parts.attestation,
            reviewer: parts.reviewer.to_owned(),
            reviewed_at: parts.reviewed_at,
        })
    }

    /// The reviewed origin allowlist.
    #[must_use]
    pub fn origins(&self) -> &[String] {
        &self.origins
    }

    /// What may be captured.
    #[must_use]
    pub const fn capture(&self) -> CapturePolicy {
        self.capture
    }

    /// Who the session runs as.
    #[must_use]
    pub const fn isolation(&self) -> &IsolationIdentity {
        &self.isolation
    }

    /// The sandbox attestation recorded for the session.
    #[must_use]
    pub const fn attestation(&self) -> &EnforcementAttestation {
        &self.attestation
    }

    /// Who reviewed the grant.
    #[must_use]
    pub fn reviewer(&self) -> &str {
        &self.reviewer
    }

    /// When it was reviewed.
    #[must_use]
    pub const fn reviewed_at(&self) -> EpochMillis {
        self.reviewed_at
    }

    /// Whether an origin is on the reviewed allowlist.
    #[must_use]
    pub fn permits_origin(&self, origin: &str) -> bool {
        self.origins.iter().any(|allowed| allowed == origin)
    }

    /// Take a download.
    ///
    /// The only return type is a [`QuarantinedArtifact`], so a download that
    /// bypasses quarantine is unrepresentable.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::OriginNotAllowlisted`] for an unreviewed origin
    /// and [`ModelError::Field`] for an invalid name.
    pub fn download(
        &self,
        origin: &str,
        name: &str,
        digest: ArtifactDigest,
    ) -> Result<QuarantinedArtifact, ModelError> {
        bounded(name, "download_name")?;
        if !self.permits_origin(origin) {
            return Err(ModelError::OriginNotAllowlisted {
                origin: origin.to_owned(),
            });
        }
        Ok(QuarantinedArtifact {
            name: name.to_owned(),
            digest,
            origin: origin.to_owned(),
        })
    }
}

/// Every field a [`NativeOsGrant`] needs, named at the call site.
#[derive(Clone, Debug)]
pub struct NativeOsGrantParts<'a> {
    /// The explicit display or session driven.
    pub display: &'a str,
    /// Who the driver runs as.
    pub isolation: IsolationIdentity,
    /// What may be captured.
    pub capture: CapturePolicy,
    /// The sandbox attestation the driver runs under.
    pub attestation: EnforcementAttestation,
    /// Who reviewed the grant.
    pub reviewer: &'a str,
    /// When it was reviewed.
    pub reviewed_at: EpochMillis,
}

/// Authority to drive the native operating system.
///
/// It is declared on its own evidence:
///
/// ```
/// # use automonique_protocol::models::{
/// #     CapturePolicy, IsolationIdentity, NativeOsGrant, NativeOsGrantParts,
/// # };
/// # use automonique_protocol::primitives::EpochMillis;
/// # use automonique_protocol::sandbox::EnforcementAttestation;
/// # let attestation =
/// #     EnforcementAttestation::new("ns", "cg", "boot", "ll", "sc", "eg").unwrap();
/// let native = NativeOsGrant::declare(NativeOsGrantParts {
///     display: ":1",
///     isolation: IsolationIdentity::new("acme", "run-1", "desktop").unwrap(),
///     capture: CapturePolicy::RedactedScreenshots,
///     attestation,
///     reviewer: "ada",
///     reviewed_at: EpochMillis::from_millis(1),
/// })
/// .unwrap();
/// assert_eq!(native.display(), ":1");
/// ```
///
/// A browser grant is not native access and does not convert into one:
///
/// ```compile_fail
/// # use automonique_protocol::models::{
/// #     BrowserGrant, BrowserGrantParts, CapturePolicy, IsolationIdentity, NativeOsGrant,
/// # };
/// # use automonique_protocol::primitives::EpochMillis;
/// # use automonique_protocol::sandbox::EnforcementAttestation;
/// # let attestation =
/// #     EnforcementAttestation::new("ns", "cg", "boot", "ll", "sc", "eg").unwrap();
/// # let browser = BrowserGrant::declare(BrowserGrantParts {
/// #     origins: &["https://example.test"],
/// #     capture: CapturePolicy::RedactedScreenshots,
/// #     isolation: IsolationIdentity::new("acme", "run-1", "browser").unwrap(),
/// #     attestation,
/// #     reviewer: "ada",
/// #     reviewed_at: EpochMillis::from_millis(1),
/// # })
/// # .unwrap();
/// let native: NativeOsGrant = browser.into();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeOsGrant {
    display: String,
    isolation: IsolationIdentity,
    capture: CapturePolicy,
    attestation: EnforcementAttestation,
    reviewer: String,
    reviewed_at: EpochMillis,
}

impl NativeOsGrant {
    /// Declare a reviewed native-OS grant.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid component.
    pub fn declare(parts: NativeOsGrantParts<'_>) -> Result<Self, ModelError> {
        bounded(parts.display, "display")?;
        bounded(parts.reviewer, "reviewer")?;
        Ok(Self {
            display: parts.display.to_owned(),
            isolation: parts.isolation,
            capture: parts.capture,
            attestation: parts.attestation,
            reviewer: parts.reviewer.to_owned(),
            reviewed_at: parts.reviewed_at,
        })
    }

    /// The explicit display driven.
    #[must_use]
    pub fn display(&self) -> &str {
        &self.display
    }

    /// Who the driver runs as.
    #[must_use]
    pub const fn isolation(&self) -> &IsolationIdentity {
        &self.isolation
    }

    /// What may be captured.
    #[must_use]
    pub const fn capture(&self) -> CapturePolicy {
        self.capture
    }

    /// The sandbox attestation recorded for the driver.
    #[must_use]
    pub const fn attestation(&self) -> &EnforcementAttestation {
        &self.attestation
    }

    /// Who reviewed the grant.
    #[must_use]
    pub fn reviewer(&self) -> &str {
        &self.reviewer
    }

    /// When it was reviewed.
    #[must_use]
    pub const fn reviewed_at(&self) -> EpochMillis {
        self.reviewed_at
    }
}

/// A downloaded file, held in quarantine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedArtifact {
    name: String,
    digest: ArtifactDigest,
    origin: String,
}

impl QuarantinedArtifact {
    /// The file name as offered by the origin.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Its digest.
    #[must_use]
    pub const fn digest(&self) -> &ArtifactDigest {
        &self.digest
    }

    /// The origin it came from.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Release the artifact from quarantine.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::ApprovalMismatch`] when the evidence approves a
    /// different artifact, so one release never authorizes another.
    pub fn release(self, evidence: &ApprovalEvidence) -> Result<ReleasedArtifact, ModelError> {
        if evidence.action_digest != self.digest.0 {
            return Err(ModelError::ApprovalMismatch);
        }
        Ok(ReleasedArtifact {
            name: self.name,
            digest: self.digest,
            released_by: evidence.actor.clone(),
        })
    }
}

/// A download an identified actor released from quarantine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasedArtifact {
    name: String,
    digest: ArtifactDigest,
    released_by: String,
}

impl ReleasedArtifact {
    /// The file name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Its digest.
    #[must_use]
    pub const fn digest(&self) -> &ArtifactDigest {
        &self.digest
    }

    /// Who released it.
    #[must_use]
    pub fn released_by(&self) -> &str {
        &self.released_by
    }
}

// ---------------------------------------------------------------------------
// Executors
// ---------------------------------------------------------------------------

/// A remote vendor's identifier for a resource.
///
/// A coordinate says where something is. It never says that something is
/// allowed, which is why no accessor on it returns evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteCoordinate {
    vendor: String,
    resource_id: String,
}

impl RemoteCoordinate {
    /// Record where a remote resource lives.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid component.
    pub fn new(vendor: &str, resource_id: &str) -> Result<Self, ModelError> {
        bounded(vendor, "vendor")?;
        bounded(resource_id, "resource_id")?;
        Ok(Self {
            vendor: vendor.to_owned(),
            resource_id: resource_id.to_owned(),
        })
    }

    /// The vendor.
    #[must_use]
    pub fn vendor(&self) -> &str {
        &self.vendor
    }

    /// The vendor's identifier for the resource.
    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }
}

/// A vendor's marketing claim that something is sandboxed.
///
/// It is kept as a distinct type so it can be recorded without ever being
/// mistaken for [`LifecycleEvidence`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VendorSandboxLabel {
    vendor: String,
    label: String,
}

impl VendorSandboxLabel {
    /// Record a vendor's claim.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid component.
    pub fn new(vendor: &str, label: &str) -> Result<Self, ModelError> {
        bounded(vendor, "vendor")?;
        bounded(label, "vendor_label")?;
        Ok(Self {
            vendor: vendor.to_owned(),
            label: label.to_owned(),
        })
    }

    /// The vendor making the claim.
    #[must_use]
    pub fn vendor(&self) -> &str {
        &self.vendor
    }

    /// The claim.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// How lifecycle evidence was authenticated.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EvidenceKind {
    /// Signed by a recorded signer.
    Signed,
    /// Produced over a mutually authenticated channel.
    MutuallyAuthenticated,
}

impl EvidenceKind {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::MutuallyAuthenticated => "mutually_authenticated",
        }
    }
}

/// Evidence about what an executor actually enforced.
///
/// Both constructors require an [`EnforcementAttestation`]:
///
/// ```
/// # use automonique_protocol::models::LifecycleEvidence;
/// # use automonique_protocol::sandbox::EnforcementAttestation;
/// let attestation =
///     EnforcementAttestation::new("ns", "cg", "boot", "ll", "sc", "eg").unwrap();
/// let evidence = LifecycleEvidence::signed("builder-1", "sha256:sig", attestation).unwrap();
/// assert_eq!(evidence.kind().as_str(), "signed");
/// ```
///
/// A vendor's sandbox label is not one, and cannot be supplied as one:
///
/// ```compile_fail
/// # use automonique_protocol::models::{LifecycleEvidence, VendorSandboxLabel};
/// let attestation = VendorSandboxLabel::new("vendor", "runs in a secure sandbox").unwrap();
/// let evidence = LifecycleEvidence::signed("builder-1", "sha256:sig", attestation).unwrap();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleEvidence {
    kind: EvidenceKind,
    local_identity: String,
    remote_identity: String,
    digest: String,
    enforcement: EnforcementAttestation,
}

impl LifecycleEvidence {
    /// Record signed evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid component.
    pub fn signed(
        signer: &str,
        signature_digest: &str,
        enforcement: EnforcementAttestation,
    ) -> Result<Self, ModelError> {
        bounded(signer, "signer")?;
        bounded(signature_digest, "signature_digest")?;
        Ok(Self {
            kind: EvidenceKind::Signed,
            local_identity: signer.to_owned(),
            remote_identity: signer.to_owned(),
            digest: signature_digest.to_owned(),
            enforcement,
        })
    }

    /// Record mutually authenticated evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid component.
    pub fn mutually_authenticated(
        local_identity: &str,
        remote_identity: &str,
        channel_digest: &str,
        enforcement: EnforcementAttestation,
    ) -> Result<Self, ModelError> {
        bounded(local_identity, "local_identity")?;
        bounded(remote_identity, "remote_identity")?;
        bounded(channel_digest, "channel_digest")?;
        Ok(Self {
            kind: EvidenceKind::MutuallyAuthenticated,
            local_identity: local_identity.to_owned(),
            remote_identity: remote_identity.to_owned(),
            digest: channel_digest.to_owned(),
            enforcement,
        })
    }

    /// How the evidence was authenticated.
    #[must_use]
    pub const fn kind(&self) -> EvidenceKind {
        self.kind
    }

    /// The local identity.
    #[must_use]
    pub fn local_identity(&self) -> &str {
        &self.local_identity
    }

    /// The remote identity.
    #[must_use]
    pub fn remote_identity(&self) -> &str {
        &self.remote_identity
    }

    /// The signature or channel digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// What the executor actually enforced.
    #[must_use]
    pub const fn enforcement(&self) -> &EnforcementAttestation {
        &self.enforcement
    }
}

/// The kind of backend an executor is.
///
/// The remote variant carries its coordinate, so a remote registration without
/// one — and a local registration pretending to have one — are both
/// unrepresentable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutorClass {
    /// Direct process execution on the host.
    Local,
    /// A rootless container.
    Container,
    /// An SSH worker with attested host identity.
    Ssh,
    /// A batch submission such as Slurm.
    Batch,
    /// A cluster job.
    Cluster,
    /// A disposable microVM.
    MicroVm,
    /// A remote vendor or organization-defined executor.
    Remote(RemoteCoordinate),
}

impl ExecutorClass {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Container => "container",
            Self::Ssh => "ssh",
            Self::Batch => "batch",
            Self::Cluster => "cluster",
            Self::MicroVm => "micro_vm",
            Self::Remote(_) => "remote",
        }
    }

    /// The remote coordinate, when this is a remote executor.
    #[must_use]
    pub const fn coordinate(&self) -> Option<&RemoteCoordinate> {
        match self {
            Self::Remote(coordinate) => Some(coordinate),
            _ => None,
        }
    }
}

/// How a workspace reaches the executor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WorkspaceTransfer {
    /// A shared mount.
    SharedMount,
    /// Synchronized over an attested channel.
    SynchronizedOverAttestedChannel,
    /// Streamed as a content-addressed bundle.
    ContentAddressedBundle,
}

/// How artifacts leave the executor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ArtifactTransfer {
    /// The control plane pulls, verifying digests.
    DigestVerifiedPull,
    /// The executor pushes, and the control plane verifies digests.
    DigestVerifiedPush,
}

/// The immutable specification an executor accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImmutableSpecAcceptance {
    spec_digest: String,
}

impl ImmutableSpecAcceptance {
    /// Record which specification was accepted.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid digest.
    pub fn new(spec_digest: &str) -> Result<Self, ModelError> {
        bounded(spec_digest, "spec_digest")?;
        Ok(Self {
            spec_digest: spec_digest.to_owned(),
        })
    }

    /// The accepted specification digest.
    #[must_use]
    pub fn spec_digest(&self) -> &str {
        &self.spec_digest
    }
}

/// How credentials reach an executor.
///
/// There is no variant in which the model types a credential.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CredentialHandling {
    /// Injected by the broker as a capability.
    CapabilityInjected,
    /// Issued short-lived by the broker for one allocation.
    BrokerIssuedShortLived,
}

/// Where an executor's event stream is resumed from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventCursor {
    stream: String,
    position: u64,
}

impl EventCursor {
    /// Record a resumable cursor.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid stream name.
    pub fn new(stream: &str, position: u64) -> Result<Self, ModelError> {
        bounded(stream, "event_stream")?;
        Ok(Self {
            stream: stream.to_owned(),
            position,
        })
    }

    /// The stream.
    #[must_use]
    pub fn stream(&self) -> &str {
        &self.stream
    }

    /// The position within it.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }
}

/// How an executor pauses for approval.
///
/// A paused run resumes on [`ApprovalEvidence`] alone; there is no auto-resume
/// field, so an executor that continues without evidence is unrepresentable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ApprovalPause {
    max_pause_ms: u64,
}

impl ApprovalPause {
    /// Declare how long a run may wait.
    #[must_use]
    pub const fn new(max_pause_ms: u64) -> Self {
        Self { max_pause_ms }
    }

    /// How long a run may wait.
    #[must_use]
    pub const fn max_pause_ms(self) -> u64 {
        self.max_pause_ms
    }
}

/// How an executor cancels a run.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Cancellation {
    grace_ms: u64,
}

impl Cancellation {
    /// Declare the cooperative grace period before a forced stop.
    #[must_use]
    pub const fn new(grace_ms: u64) -> Self {
        Self { grace_ms }
    }

    /// The grace period.
    #[must_use]
    pub const fn grace_ms(self) -> u64 {
        self.grace_ms
    }
}

/// What an executor removes when a run ends.
///
/// Every variant removes credentials. There is no best-effort variant, because
/// a backend that might leave a credential behind is not registrable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Cleanup {
    /// Workspace and credentials.
    WorkspaceAndCredentials,
    /// Workspace, credentials and any snapshot taken.
    WorkspaceCredentialsAndSnapshot,
}

/// How an executor accounts for cost.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CostAccounting {
    /// Metered per wall-clock second.
    PerSecond,
    /// Metered per request.
    PerRequest,
    /// Metered per resource unit consumed.
    PerResourceUnit,
}

/// Every field an [`ExecutorRegistration`] needs, named at the call site.
///
/// There is no optional field. A backend that can execute a command but cannot
/// produce, say, an event cursor simply cannot be registered.
#[derive(Clone, Debug)]
pub struct ExecutorRegistrationParts<'a> {
    /// The registration identifier.
    pub id: &'a str,
    /// What kind of backend it is.
    pub class: ExecutorClass,
    /// How the workspace reaches it.
    pub workspace_transfer: WorkspaceTransfer,
    /// How artifacts leave it.
    pub artifact_transfer: ArtifactTransfer,
    /// The immutable specification it accepted.
    pub spec_acceptance: ImmutableSpecAcceptance,
    /// Signed or mutually authenticated lifecycle evidence.
    pub lifecycle_evidence: LifecycleEvidence,
    /// How credentials reach it.
    pub credential_handling: CredentialHandling,
    /// Where its event stream resumes.
    pub event_cursor: EventCursor,
    /// How it pauses for approval.
    pub approval_pause: ApprovalPause,
    /// How it cancels.
    pub cancellation: Cancellation,
    /// What it removes when a run ends.
    pub cleanup: Cleanup,
    /// How it accounts for cost.
    pub cost_accounting: CostAccounting,
}

/// A registered execution backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutorRegistration {
    id: String,
    class: ExecutorClass,
    workspace_transfer: WorkspaceTransfer,
    artifact_transfer: ArtifactTransfer,
    spec_acceptance: ImmutableSpecAcceptance,
    lifecycle_evidence: LifecycleEvidence,
    credential_handling: CredentialHandling,
    event_cursor: EventCursor,
    approval_pause: ApprovalPause,
    cancellation: Cancellation,
    cleanup: Cleanup,
    cost_accounting: CostAccounting,
}

impl ExecutorRegistration {
    /// Register a backend.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid identifier.
    pub fn declare(parts: ExecutorRegistrationParts<'_>) -> Result<Self, ModelError> {
        bounded(parts.id, "executor_id")?;
        Ok(Self {
            id: parts.id.to_owned(),
            class: parts.class,
            workspace_transfer: parts.workspace_transfer,
            artifact_transfer: parts.artifact_transfer,
            spec_acceptance: parts.spec_acceptance,
            lifecycle_evidence: parts.lifecycle_evidence,
            credential_handling: parts.credential_handling,
            event_cursor: parts.event_cursor,
            approval_pause: parts.approval_pause,
            cancellation: parts.cancellation,
            cleanup: parts.cleanup,
            cost_accounting: parts.cost_accounting,
        })
    }

    /// The registration identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// What kind of backend it is.
    #[must_use]
    pub const fn class(&self) -> &ExecutorClass {
        &self.class
    }

    /// How the workspace reaches it.
    #[must_use]
    pub const fn workspace_transfer(&self) -> WorkspaceTransfer {
        self.workspace_transfer
    }

    /// How artifacts leave it.
    #[must_use]
    pub const fn artifact_transfer(&self) -> ArtifactTransfer {
        self.artifact_transfer
    }

    /// The immutable specification it accepted.
    #[must_use]
    pub const fn spec_acceptance(&self) -> &ImmutableSpecAcceptance {
        &self.spec_acceptance
    }

    /// The evidence that admits it. This is the only authority it has.
    #[must_use]
    pub const fn lifecycle_evidence(&self) -> &LifecycleEvidence {
        &self.lifecycle_evidence
    }

    /// How credentials reach it.
    #[must_use]
    pub const fn credential_handling(&self) -> CredentialHandling {
        self.credential_handling
    }

    /// Where its event stream resumes.
    #[must_use]
    pub const fn event_cursor(&self) -> &EventCursor {
        &self.event_cursor
    }

    /// How it pauses for approval.
    #[must_use]
    pub const fn approval_pause(&self) -> ApprovalPause {
        self.approval_pause
    }

    /// How it cancels.
    #[must_use]
    pub const fn cancellation(&self) -> Cancellation {
        self.cancellation
    }

    /// What it removes when a run ends.
    #[must_use]
    pub const fn cleanup(&self) -> Cleanup {
        self.cleanup
    }

    /// How it accounts for cost.
    #[must_use]
    pub const fn cost_accounting(&self) -> CostAccounting {
        self.cost_accounting
    }
}

/// Whether an allocation may run on a registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionOutcome {
    /// The observed evidence matches the registration's.
    Admitted,
    /// The observed evidence differs; the allocation is refused.
    Refused,
}

/// Admit an allocation by comparing lifecycle evidence.
///
/// The registration's coordinate is not consulted, because a vendor identifier
/// is a coordinate rather than authority: two registrations with the same
/// coordinate and different evidence do not admit each other's allocations.
#[must_use]
pub fn admit_allocation(
    registration: &ExecutorRegistration,
    observed: &LifecycleEvidence,
) -> AdmissionOutcome {
    if registration.lifecycle_evidence == *observed {
        AdmissionOutcome::Admitted
    } else {
        AdmissionOutcome::Refused
    }
}

/// What a persistent remote environment is doing.
///
/// Suspension is not a slower kind of running: the states are distinct, and
/// nothing derives one from the other.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EnvironmentState {
    /// A process is running.
    Running,
    /// Scaled to zero: no process, identity retained, wakes on demand.
    ScaledToZero,
    /// Hibernated to a snapshot.
    Hibernated,
    /// Gone.
    Terminated,
}

impl EnvironmentState {
    /// Every state, for coverage checks.
    pub const ALL: [Self; 4] = [
        Self::Running,
        Self::ScaledToZero,
        Self::Hibernated,
        Self::Terminated,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::ScaledToZero => "scaled_to_zero",
            Self::Hibernated => "hibernated",
            Self::Terminated => "terminated",
        }
    }

    /// Whether a process is running.
    #[must_use]
    pub const fn is_running(self) -> bool {
        matches!(self, Self::Running)
    }
}

/// A snapshot a hibernated environment can wake from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotRef {
    id: String,
    digest: String,
    taken_at: EpochMillis,
}

impl SnapshotRef {
    /// Record a snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid component.
    pub fn new(id: &str, digest: &str, taken_at: EpochMillis) -> Result<Self, ModelError> {
        bounded(id, "snapshot_id")?;
        bounded(digest, "snapshot_digest")?;
        Ok(Self {
            id: id.to_owned(),
            digest: digest.to_owned(),
            taken_at,
        })
    }

    /// The snapshot identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Its digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// When it was taken, as supplied by the caller.
    #[must_use]
    pub const fn taken_at(&self) -> EpochMillis {
        self.taken_at
    }
}

/// A persistent remote environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistentEnvironment {
    id: String,
    coordinate: RemoteCoordinate,
    snapshot: Option<SnapshotRef>,
    state: EnvironmentState,
}

impl PersistentEnvironment {
    /// Record an environment.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Field`] for an invalid identifier and
    /// [`ModelError::SnapshotRequired`] for a hibernated environment with no
    /// snapshot, which could never be woken.
    pub fn declare(
        id: &str,
        coordinate: RemoteCoordinate,
        snapshot: Option<SnapshotRef>,
        state: EnvironmentState,
    ) -> Result<Self, ModelError> {
        bounded(id, "environment_id")?;
        if state == EnvironmentState::Hibernated && snapshot.is_none() {
            return Err(ModelError::SnapshotRequired);
        }
        Ok(Self {
            id: id.to_owned(),
            coordinate,
            snapshot,
            state,
        })
    }

    /// The environment identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Where it lives.
    #[must_use]
    pub const fn coordinate(&self) -> &RemoteCoordinate {
        &self.coordinate
    }

    /// Its snapshot, if it has one.
    #[must_use]
    pub const fn snapshot(&self) -> Option<&SnapshotRef> {
        self.snapshot.as_ref()
    }

    /// What it is doing.
    #[must_use]
    pub const fn state(&self) -> EnvironmentState {
        self.state
    }

    /// Wake a suspended environment.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::NotSuspended`] when the environment is running or
    /// terminated, so waking is never a no-op that hides a live process.
    pub fn wake(self) -> Result<Self, ModelError> {
        match self.state {
            EnvironmentState::ScaledToZero | EnvironmentState::Hibernated => Ok(Self {
                state: EnvironmentState::Running,
                ..self
            }),
            EnvironmentState::Running | EnvironmentState::Terminated => {
                Err(ModelError::NotSuspended {
                    state: self.state.as_str(),
                })
            }
        }
    }
}

fn bounded(value: &str, field: &'static str) -> Result<(), ModelError> {
    let error = if value.is_empty() {
        Some(ValueError::Empty)
    } else if value.len() > MAX_MODEL_FIELD_BYTES {
        Some(ValueError::TooLong {
            max_bytes: MAX_MODEL_FIELD_BYTES,
            actual_bytes: value.len(),
        })
    } else if value.chars().any(char::is_control) {
        Some(ValueError::ControlCharacter)
    } else {
        None
    };
    match error {
        Some(error) => Err(ModelError::Field { field, error }),
        None => Ok(()),
    }
}
