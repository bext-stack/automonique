// SPDX-License-Identifier: Elastic-2.0

//! Context manifests, typed references, compression lineage and memory.
//!
//! The boundary this module exists to hold is prompt injection: content that
//! arrived from a repository, a retrieved document or a model's own suggestion
//! must be structurally incapable of becoming policy.
//!
//! Policy components and supplied components are separate types, and a manifest
//! takes policy only through a constructor argument that supplied content
//! cannot reach. A manifest assembled correctly:
//!
//! ```
//! use automonique_protocol::context::{
//!     ComponentCaps, ContextManifest, PolicyComponent, RedactionOutcome, SuppliedClass,
//!     SuppliedComponent, TokenBudget, TrustClass,
//! };
//! use automonique_protocol::primitives::Revision;
//!
//! let caps = ComponentCaps::new(4_096, 512).unwrap();
//! let policy =
//!     PolicyComponent::new("tenant-policy", Revision::FIRST, "sha256:p", caps, RedactionOutcome::Clean)
//!         .unwrap();
//! let retrieved = SuppliedComponent::new(
//!     "retrieved-document",
//!     SuppliedClass::Attachments,
//!     TrustClass::Untrusted,
//!     "sha256:c",
//!     caps,
//!     RedactionOutcome::Redacted,
//! )
//! .unwrap();
//! let manifest =
//!     ContextManifest::new(Revision::FIRST, TokenBudget::new(8_192), vec![policy], vec![retrieved]);
//! assert_eq!(manifest.policy().len(), 1);
//! ```
//!
//! and the same call differing only in what occupies the policy slot:
//!
//! ```compile_fail
//! use automonique_protocol::context::{
//!     ComponentCaps, ContextManifest, RedactionOutcome, SuppliedClass, SuppliedComponent,
//!     TokenBudget, TrustClass,
//! };
//! use automonique_protocol::primitives::Revision;
//!
//! let caps = ComponentCaps::new(4_096, 512).unwrap();
//! let retrieved = SuppliedComponent::new(
//!     "retrieved-document",
//!     SuppliedClass::Attachments,
//!     TrustClass::Untrusted,
//!     "sha256:c",
//!     caps,
//!     RedactionOutcome::Redacted,
//! )
//! .unwrap();
//! // A supplied component cannot be installed as policy.
//! let manifest = ContextManifest::new(
//!     Revision::FIRST,
//!     TokenBudget::new(8_192),
//!     vec![retrieved.clone()],
//!     vec![retrieved],
//! );
//! ```
//!
//! Nothing here assembles a prompt, counts real tokens, fetches a URL, reads a
//! file, runs a compression or activates a skill.

use core::fmt;
use std::error::Error;

use crate::primitives::{EpochMillis, PublicHttpUrl, Revision, UrlError, ValueError};

/// Maximum UTF-8 byte length of a context identifier.
pub const MAX_CONTEXT_FIELD_BYTES: usize = 512;

/// Maximum depth a folder reference may request.
pub const MAX_FOLDER_DEPTH: u32 = 16;

/// Maximum confidence a memory entry may claim.
pub const MAX_CONFIDENCE: u8 = 100;

/// How far a component may be trusted.
///
/// Ordered least to most. A component may never be promoted.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TrustClass {
    /// Model output and retrieved documents.
    Untrusted,
    /// Provider-specific rule files, labelled as compatibility inputs.
    Compatibility,
    /// Content the actor supplied directly, including workspace rules
    /// discovered in the shared `AGENTS.md` format.
    ActorSupplied,
    /// Tenant or system policy. Only a policy component may carry this.
    Policy,
}

impl TrustClass {
    /// Every class, least to most trusted, for coverage checks.
    pub const ALL: [Self; 4] = [
        Self::Untrusted,
        Self::Compatibility,
        Self::ActorSupplied,
        Self::Policy,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Untrusted => "untrusted",
            Self::Compatibility => "compatibility",
            Self::ActorSupplied => "actor_supplied",
            Self::Policy => "policy",
        }
    }

    /// Parse the exact stable spelling.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.as_str() == value)
    }
}

/// Why a context operation was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContextError {
    /// A reference resolved outside the registered workspace.
    OutsideWorkspace {
        /// Which rule refused it.
        rule: &'static str,
    },
    /// A reference was rejected for its own reason.
    ReferenceRefused {
        /// Why.
        reason: &'static str,
    },
    /// A range or bound was not usable.
    InvalidRange {
        /// Why.
        reason: &'static str,
    },
    /// Binary content was offered where text was expected.
    BinaryConfusion,
    /// A secret was detected in resolved content.
    SecretDetected,
    /// The authorization a reference resolved under no longer holds.
    AuthorizationChanged,
    /// A URL reference was not a well-formed public HTTP(S) URL.
    Url {
        /// Why.
        error: UrlError,
    },
    /// A memory entry omitted a required classification.
    ClassificationRequired {
        /// The missing classification.
        field: &'static str,
    },
    /// A confidence was outside `0..=MAX_CONFIDENCE`.
    ConfidenceOutOfRange {
        /// The accepted maximum.
        max: u8,
        /// What was requested.
        requested: u8,
    },
    /// An entry that is already superseded cannot be superseded again.
    AlreadySuperseded,
    /// The entry's retention rule forbids deletion.
    RetentionForbidsDeletion {
        /// The rule that forbids it.
        rule: &'static str,
    },
    /// A bounded field was rejected.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
}

impl ContextError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::OutsideWorkspace { .. } => "outside_workspace",
            Self::ReferenceRefused { .. } => "reference_refused",
            Self::InvalidRange { .. } => "invalid_range",
            Self::BinaryConfusion => "binary_confusion",
            Self::SecretDetected => "secret_detected",
            Self::AuthorizationChanged => "authorization_changed",
            Self::Url { .. } => "url_invalid",
            Self::ClassificationRequired { .. } => "classification_required",
            Self::ConfidenceOutOfRange { .. } => "confidence_out_of_range",
            Self::AlreadySuperseded => "already_superseded",
            Self::RetentionForbidsDeletion { .. } => "retention_forbids_deletion",
            Self::Field { .. } => "field_invalid",
        }
    }
}

impl fmt::Display for ContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutsideWorkspace { rule } => {
                write!(
                    formatter,
                    "reference is outside the registered workspace: {rule}"
                )
            }
            Self::ReferenceRefused { reason } => write!(formatter, "reference refused: {reason}"),
            Self::InvalidRange { reason } => write!(formatter, "invalid range: {reason}"),
            Self::BinaryConfusion => {
                formatter.write_str("binary content was offered as inline text")
            }
            Self::SecretDetected => {
                formatter.write_str("a secret was detected in the resolved content")
            }
            Self::AuthorizationChanged => {
                formatter.write_str("authorization changed after the reference was made")
            }
            Self::Url { error } => write!(formatter, "url reference: {error}"),
            Self::ClassificationRequired { field } => {
                write!(formatter, "a memory entry requires {field}")
            }
            Self::ConfidenceOutOfRange { max, requested } => write!(
                formatter,
                "confidence of {requested} exceeds the maximum of {max}"
            ),
            Self::AlreadySuperseded => formatter
                .write_str("the entry is already superseded and cannot be superseded again"),
            Self::RetentionForbidsDeletion { rule } => {
                write!(formatter, "retention forbids deletion: {rule}")
            }
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
        }
    }
}

impl Error for ContextError {}

/// A validated workspace-relative path.
///
/// The only constructor runs the workspace bound, so an arbitrary host path is
/// not a value of this type and the reference variants that carry one cannot be
/// built with a raw string.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkspacePath(String);

impl WorkspacePath {
    /// Validate a workspace-relative path.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::OutsideWorkspace`] for an absolute path, a
    /// home-relative path or a traversal above the workspace root, and
    /// [`ContextError::ReferenceRefused`] for a non-canonical component, a
    /// backslash or an embedded NUL.
    pub fn new(path: &str) -> Result<Self, ContextError> {
        check_workspace_relative(path)?;
        Ok(Self(path.to_owned()))
    }

    /// The validated path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WorkspacePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A validated opaque identifier: a digest, revision, session or ticket key.
///
/// The value is never interpreted beyond the shared bound: non-empty, within
/// the ceiling and free of control characters.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContextLabel(String);

impl ContextLabel {
    /// Validate an identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] when the value is empty, over the
    /// ceiling or contains a control character.
    pub fn new(value: &str) -> Result<Self, ContextError> {
        label(value, "label")
    }

    /// The validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContextLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Which rule-file format a workspace rule was discovered in.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuleFileFormat {
    /// The shared `AGENTS.md` format the product prefers.
    Shared,
    /// A provider-specific rule file, accepted only as a compatibility input.
    ProviderCompatibility,
}

impl RuleFileFormat {
    /// Every format, for coverage checks.
    pub const ALL: [Self; 2] = [Self::Shared, Self::ProviderCompatibility];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::ProviderCompatibility => "provider_compatibility",
        }
    }

    /// The trust class this format carries.
    ///
    /// A provider-specific file is strictly less trusted than the shared
    /// format, and neither reaches [`TrustClass::Policy`].
    #[must_use]
    pub const fn trust(self) -> TrustClass {
        match self {
            Self::Shared => TrustClass::ActorSupplied,
            Self::ProviderCompatibility => TrustClass::Compatibility,
        }
    }
}

/// A workspace rule file discovered inside the registered workspace.
///
/// The path is a [`WorkspacePath`], so discovery reaching a parent or home
/// directory is not a value of this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceRuleReference {
    path: WorkspacePath,
    format: RuleFileFormat,
}

impl WorkspaceRuleReference {
    /// Record a discovered rule file.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::OutsideWorkspace`] when the path leaves the
    /// registered workspace.
    pub fn discovered(path: &str, format: RuleFileFormat) -> Result<Self, ContextError> {
        Ok(Self {
            path: WorkspacePath::new(path)?,
            format,
        })
    }

    /// Where the rule file is.
    #[must_use]
    pub const fn path(&self) -> &WorkspacePath {
        &self.path
    }

    /// Which format it is in.
    #[must_use]
    pub const fn format(&self) -> RuleFileFormat {
        self.format
    }

    /// The trust class the rule file carries.
    #[must_use]
    pub const fn trust(&self) -> TrustClass {
        self.format.trust()
    }

    /// Turn the rule file into a manifest component at its format's trust.
    ///
    /// The result is a [`SuppliedComponent`], never a [`PolicyComponent`], so
    /// a discovered rule file cannot become policy however it is labelled.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an invalid digest.
    pub fn as_component(
        &self,
        digest: &str,
        caps: ComponentCaps,
        redaction: RedactionOutcome,
    ) -> Result<SuppliedComponent, ContextError> {
        SuppliedComponent::new(
            self.path.as_str(),
            SuppliedClass::WorkspaceRules,
            self.trust(),
            digest,
            caps,
            redaction,
        )
    }
}

/// What redaction concluded about a component.
///
/// There is no "not scanned" variant, so an unscanned component is
/// unrepresentable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RedactionOutcome {
    /// Scanned; nothing needed removing.
    Clean,
    /// Scanned; secret-bearing spans were removed.
    Redacted,
}

impl RedactionOutcome {
    /// Every outcome, for coverage checks.
    pub const ALL: [Self; 2] = [Self::Clean, Self::Redacted];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Redacted => "redacted",
        }
    }

    /// Parse the exact stable spelling.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|outcome| outcome.as_str() == value)
    }
}

/// The byte and token ceilings a component was admitted under.
///
/// Both are required and neither may be zero, so a component without caps has
/// no constructor and a zero cap cannot stand in for "uncapped".
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ComponentCaps {
    byte_cap: u64,
    token_cap: u64,
}

impl ComponentCaps {
    /// Declare both ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] with [`ValueError::ZeroBound`] when
    /// either ceiling is zero.
    pub const fn new(byte_cap: u64, token_cap: u64) -> Result<Self, ContextError> {
        if byte_cap == 0 {
            return Err(ContextError::Field {
                field: "byte_cap",
                error: ValueError::ZeroBound,
            });
        }
        if token_cap == 0 {
            return Err(ContextError::Field {
                field: "token_cap",
                error: ValueError::ZeroBound,
            });
        }
        Ok(Self {
            byte_cap,
            token_cap,
        })
    }

    /// The declared byte ceiling.
    #[must_use]
    pub const fn byte_cap(self) -> u64 {
        self.byte_cap
    }

    /// The declared token ceiling.
    #[must_use]
    pub const fn token_cap(self) -> u64 {
        self.token_cap
    }
}

/// Which accounting class a supplied component belongs to.
///
/// There is deliberately no system-policy member: supplied content cannot be
/// classified as system policy, because the class drives the budget breakdown
/// clients show.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SuppliedClass {
    /// Workspace rule files.
    WorkspaceRules,
    /// Activated skills.
    Skills,
    /// Memory snapshots.
    Memory,
    /// Tool schemas.
    Tools,
    /// MCP server schemas.
    Mcp,
    /// Explicitly referenced attachments.
    Attachments,
    /// Conversation history.
    Conversation,
}

impl SuppliedClass {
    /// Every class, for coverage checks.
    pub const ALL: [Self; 7] = [
        Self::WorkspaceRules,
        Self::Skills,
        Self::Memory,
        Self::Tools,
        Self::Mcp,
        Self::Attachments,
        Self::Conversation,
    ];

    /// The accounting class this maps onto.
    #[must_use]
    pub const fn as_component_class(self) -> ComponentClass {
        match self {
            Self::WorkspaceRules => ComponentClass::WorkspaceRules,
            Self::Skills => ComponentClass::Skills,
            Self::Memory => ComponentClass::Memory,
            Self::Tools => ComponentClass::Tools,
            Self::Mcp => ComponentClass::Mcp,
            Self::Attachments => ComponentClass::Attachments,
            Self::Conversation => ComponentClass::Conversation,
        }
    }

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.as_component_class().as_str()
    }

    /// Parse the exact stable spelling.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.as_str() == value)
    }
}

/// Which accounting class a token count belongs to.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ComponentClass {
    /// System and tenant policy.
    SystemPolicy,
    /// Workspace rule files.
    WorkspaceRules,
    /// Activated skills.
    Skills,
    /// Memory snapshots.
    Memory,
    /// Tool schemas.
    Tools,
    /// MCP server schemas.
    Mcp,
    /// Explicitly referenced attachments.
    Attachments,
    /// Conversation history.
    Conversation,
}

impl ComponentClass {
    /// Every class, for coverage checks.
    pub const ALL: [Self; 8] = [
        Self::SystemPolicy,
        Self::WorkspaceRules,
        Self::Skills,
        Self::Memory,
        Self::Tools,
        Self::Mcp,
        Self::Attachments,
        Self::Conversation,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemPolicy => "system_policy",
            Self::WorkspaceRules => "workspace_rules",
            Self::Skills => "skills",
            Self::Memory => "memory",
            Self::Tools => "tools",
            Self::Mcp => "mcp",
            Self::Attachments => "attachments",
            Self::Conversation => "conversation",
        }
    }

    /// Parse the exact stable spelling.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.as_str() == value)
    }
}

/// A component of a context manifest that policy did not author.
///
/// Its trust class is capped below [`TrustClass::Policy`] at construction, so
/// no supplied content can claim policy trust, and its caps and digest are
/// constructor arguments, so a component without either has no constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuppliedComponent {
    source: String,
    class: SuppliedClass,
    trust: TrustClass,
    digest: String,
    caps: ComponentCaps,
    redaction: RedactionOutcome,
}

impl SuppliedComponent {
    /// Record a supplied component.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an invalid component. A requested
    /// trust of [`TrustClass::Policy`] is lowered to
    /// [`TrustClass::ActorSupplied`] rather than honoured, because supplied
    /// content is never policy however it asks to be labelled.
    pub fn new(
        source: &str,
        class: SuppliedClass,
        requested_trust: TrustClass,
        digest: &str,
        caps: ComponentCaps,
        redaction: RedactionOutcome,
    ) -> Result<Self, ContextError> {
        bounded(source, "source")?;
        bounded(digest, "digest")?;
        let trust = if requested_trust == TrustClass::Policy {
            TrustClass::ActorSupplied
        } else {
            requested_trust
        };
        Ok(Self {
            source: source.to_owned(),
            class,
            trust,
            digest: digest.to_owned(),
            caps,
            redaction,
        })
    }

    /// The trust class actually granted.
    #[must_use]
    pub const fn trust(&self) -> TrustClass {
        self.trust
    }

    /// The accounting class.
    #[must_use]
    pub const fn class(&self) -> SuppliedClass {
        self.class
    }

    /// The content digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Where it came from.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The declared ceilings.
    #[must_use]
    pub const fn caps(&self) -> ComponentCaps {
        self.caps
    }

    /// What redaction concluded.
    #[must_use]
    pub const fn redaction(&self) -> RedactionOutcome {
        self.redaction
    }
}

/// A component authored by system or tenant policy.
///
/// A separate type from [`SuppliedComponent`], so the manifest's policy slot
/// cannot receive supplied content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyComponent {
    source: String,
    revision: Revision,
    digest: String,
    caps: ComponentCaps,
    redaction: RedactionOutcome,
}

impl PolicyComponent {
    /// Record a policy component.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an invalid component.
    pub fn new(
        source: &str,
        revision: Revision,
        digest: &str,
        caps: ComponentCaps,
        redaction: RedactionOutcome,
    ) -> Result<Self, ContextError> {
        bounded(source, "source")?;
        bounded(digest, "digest")?;
        Ok(Self {
            source: source.to_owned(),
            revision,
            digest: digest.to_owned(),
            caps,
            redaction,
        })
    }

    /// Always [`TrustClass::Policy`].
    #[must_use]
    pub const fn trust(&self) -> TrustClass {
        TrustClass::Policy
    }

    /// Always [`ComponentClass::SystemPolicy`].
    #[must_use]
    pub const fn class(&self) -> ComponentClass {
        ComponentClass::SystemPolicy
    }

    /// The policy revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Where it came from.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The content digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The declared ceilings.
    #[must_use]
    pub const fn caps(&self) -> ComponentCaps {
        self.caps
    }

    /// What redaction concluded.
    #[must_use]
    pub const fn redaction(&self) -> RedactionOutcome {
        self.redaction
    }
}

/// The token ceiling a manifest was assembled under.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TokenBudget {
    total_tokens: u64,
}

impl TokenBudget {
    /// Declare a budget.
    #[must_use]
    pub const fn new(total_tokens: u64) -> Self {
        Self { total_tokens }
    }

    /// The declared ceiling.
    #[must_use]
    pub const fn total_tokens(self) -> u64 {
        self.total_tokens
    }

    /// What is left after `used` tokens, or `None` when the budget is overrun.
    #[must_use]
    pub const fn remaining_after(self, used: u64) -> Option<u64> {
        self.total_tokens.checked_sub(used)
    }
}

/// The ordered, content-addressed record of one turn's context.
///
/// The manifest carries its own policy revision and token budget, so a
/// manifest that does not say which policy it was assembled under, or under
/// what ceiling, has no constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextManifest {
    policy_revision: Revision,
    token_budget: TokenBudget,
    policy: Vec<PolicyComponent>,
    supplied: Vec<SuppliedComponent>,
}

impl ContextManifest {
    /// Assemble a manifest from its revision, budget and two component kinds.
    #[must_use]
    pub const fn new(
        policy_revision: Revision,
        token_budget: TokenBudget,
        policy: Vec<PolicyComponent>,
        supplied: Vec<SuppliedComponent>,
    ) -> Self {
        Self {
            policy_revision,
            token_budget,
            policy,
            supplied,
        }
    }

    /// The policy revision this manifest was assembled under.
    #[must_use]
    pub const fn policy_revision(&self) -> Revision {
        self.policy_revision
    }

    /// The token ceiling this manifest was assembled under.
    #[must_use]
    pub const fn token_budget(&self) -> TokenBudget {
        self.token_budget
    }

    /// The policy components.
    #[must_use]
    pub fn policy(&self) -> &[PolicyComponent] {
        &self.policy
    }

    /// The supplied components.
    #[must_use]
    pub fn supplied(&self) -> &[SuppliedComponent] {
        &self.supplied
    }

    /// Every component digest in assembly order: policy first, then supplied.
    ///
    /// Precedence is positional as well as typed — policy content is always
    /// ahead of supplied content.
    #[must_use]
    pub fn ordered_digests(&self) -> Vec<&str> {
        self.policy
            .iter()
            .map(PolicyComponent::digest)
            .chain(self.supplied.iter().map(SuppliedComponent::digest))
            .collect()
    }

    /// The sum of every component's declared token cap.
    #[must_use]
    pub fn declared_token_total(&self) -> u64 {
        self.policy
            .iter()
            .map(|component| component.caps.token_cap)
            .chain(
                self.supplied
                    .iter()
                    .map(|component| component.caps.token_cap),
            )
            .fold(0_u64, u64::saturating_add)
    }

    /// Whether the declared caps fit inside the manifest's budget.
    #[must_use]
    pub fn within_budget(&self) -> bool {
        self.token_budget
            .remaining_after(self.declared_token_total())
            .is_some()
    }

    /// The highest trust any supplied component carries.
    ///
    /// Always below [`TrustClass::Policy`].
    #[must_use]
    pub fn highest_supplied_trust(&self) -> Option<TrustClass> {
        self.supplied.iter().map(SuppliedComponent::trust).max()
    }
}

/// A one-based, non-empty line range inside a file.
///
/// An inverted or zero-based range has no constructor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LineRange {
    first: u32,
    last: u32,
}

impl LineRange {
    /// Declare a range.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidRange`] when the first line is zero or
    /// the last line precedes the first.
    pub const fn new(first: u32, last: u32) -> Result<Self, ContextError> {
        if first == 0 {
            return Err(ContextError::InvalidRange {
                reason: "line numbering starts at 1",
            });
        }
        if last < first {
            return Err(ContextError::InvalidRange {
                reason: "the last line precedes the first",
            });
        }
        Ok(Self { first, last })
    }

    /// The first line.
    #[must_use]
    pub const fn first(self) -> u32 {
        self.first
    }

    /// The last line.
    #[must_use]
    pub const fn last(self) -> u32 {
        self.last
    }
}

/// A bounded folder depth.
///
/// An unbounded traversal has no constructor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FolderDepth(u32);

impl FolderDepth {
    /// Declare a depth in `1..=MAX_FOLDER_DEPTH`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidRange`] for zero or above the maximum.
    pub const fn new(depth: u32) -> Result<Self, ContextError> {
        if depth == 0 {
            return Err(ContextError::InvalidRange {
                reason: "a folder reference must reach at least one level",
            });
        }
        if depth > MAX_FOLDER_DEPTH {
            return Err(ContextError::InvalidRange {
                reason: "folder depth exceeds the maximum",
            });
        }
        Ok(Self(depth))
    }

    /// The declared depth.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Which entries a folder reference materializes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FolderFilter(Option<String>);

impl FolderFilter {
    /// Every entry within the depth.
    #[must_use]
    pub const fn all() -> Self {
        Self(None)
    }

    /// Only entries matching a pattern.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an invalid pattern and
    /// [`ContextError::OutsideWorkspace`] for a pattern that could reach
    /// outside the folder.
    pub fn matching(pattern: &str) -> Result<Self, ContextError> {
        bounded(pattern, "folder_filter")?;
        if pattern.starts_with('/') || pattern.contains("..") {
            return Err(ContextError::OutsideWorkspace {
                rule: "filter escapes the folder",
            });
        }
        Ok(Self(Some(pattern.to_owned())))
    }

    /// The pattern, if the filter is not "everything".
    #[must_use]
    pub fn pattern(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

/// A typed reference into context.
///
/// Every path-bearing variant carries a [`WorkspacePath`] and every URL variant
/// a [`PublicHttpUrl`], so an arbitrary host path is unrepresentable even
/// through a struct literal. Built through the validating constructor:
///
/// ```
/// use automonique_protocol::context::{ContextLabel, ContextReference, WorkspacePath};
///
/// let reference = ContextReference::File {
///     path: WorkspacePath::new("src/main.rs").unwrap(),
///     digest: ContextLabel::new("sha256:f").unwrap(),
///     lines: None,
/// };
/// assert_eq!(reference.kind(), "file");
/// ```
///
/// and the same literal differing only in writing the path directly:
///
/// ```compile_fail
/// use automonique_protocol::context::{ContextLabel, ContextReference};
///
/// let reference = ContextReference::File {
///     path: "/etc/passwd".to_owned(),
///     digest: ContextLabel::new("sha256:f").unwrap(),
///     lines: None,
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContextReference {
    /// A file, optionally a line range, pinned by artifact digest.
    File {
        /// Workspace-relative path.
        path: WorkspacePath,
        /// Content digest.
        digest: ContextLabel,
        /// The referenced lines, or the whole file.
        lines: Option<LineRange>,
    },
    /// A bounded folder view.
    Folder {
        /// Workspace-relative path.
        path: WorkspacePath,
        /// Maximum depth.
        depth: FolderDepth,
        /// Which entries are materialized.
        filter: FolderFilter,
    },
    /// A Git revision range.
    Diff {
        /// The revision being compared.
        revision: ContextLabel,
    },
    /// The staged tree of the registered workspace.
    Staged,
    /// A single commit.
    Commit {
        /// The commit identity.
        commit: ContextLabel,
    },
    /// A named branch.
    Branch {
        /// The branch name.
        branch: ContextLabel,
    },
    /// A reviewed URL.
    Url {
        /// The public HTTP(S) URL.
        url: PublicHttpUrl<MAX_CONTEXT_FIELD_BYTES>,
    },
    /// A prior session.
    Session {
        /// The session identity.
        session: ContextLabel,
    },
    /// A single turn inside a session.
    Turn {
        /// The session identity.
        session: ContextLabel,
        /// The turn identity.
        turn: ContextLabel,
    },
    /// A prior run.
    Run {
        /// The run identity.
        run: ContextLabel,
    },
    /// An external ticket.
    Ticket {
        /// The ticket identity.
        ticket: ContextLabel,
    },
    /// A stored artifact.
    Artifact {
        /// The artifact digest.
        digest: ContextLabel,
    },
    /// A named workspace or multi-folder project.
    Workspace {
        /// The workspace identity.
        workspace: ContextLabel,
    },
}

impl ContextReference {
    /// Every kind's stable spelling, for coverage checks.
    pub const KINDS: [&str; 13] = [
        "artifact",
        "branch",
        "commit",
        "diff",
        "file",
        "folder",
        "run",
        "session",
        "staged",
        "ticket",
        "turn",
        "url",
        "workspace",
    ];

    /// Build a workspace-relative file reference for the whole file.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::OutsideWorkspace`] for an absolute path, a
    /// traversal or a home-relative path,
    /// [`ContextError::ReferenceRefused`] for a non-canonical path, and
    /// [`ContextError::Field`] for an invalid digest.
    pub fn file(path: &str, digest: &str) -> Result<Self, ContextError> {
        Ok(Self::File {
            path: WorkspacePath::new(path)?,
            digest: label(digest, "digest")?,
            lines: None,
        })
    }

    /// Build a file reference bounded to a line range.
    ///
    /// # Errors
    ///
    /// As for [`ContextReference::file`].
    pub fn file_lines(path: &str, digest: &str, lines: LineRange) -> Result<Self, ContextError> {
        Ok(Self::File {
            path: WorkspacePath::new(path)?,
            digest: label(digest, "digest")?,
            lines: Some(lines),
        })
    }

    /// Build a bounded folder reference.
    ///
    /// # Errors
    ///
    /// As for [`ContextReference::file`].
    pub fn folder(
        path: &str,
        depth: FolderDepth,
        filter: FolderFilter,
    ) -> Result<Self, ContextError> {
        Ok(Self::Folder {
            path: WorkspacePath::new(path)?,
            depth,
            filter,
        })
    }

    /// Build a diff reference.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an invalid revision.
    pub fn diff(revision: &str) -> Result<Self, ContextError> {
        Ok(Self::Diff {
            revision: label(revision, "revision")?,
        })
    }

    /// Build a reference to the staged tree.
    #[must_use]
    pub const fn staged() -> Self {
        Self::Staged
    }

    /// Build a commit reference.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an invalid commit identity.
    pub fn commit(commit: &str) -> Result<Self, ContextError> {
        Ok(Self::Commit {
            commit: label(commit, "commit")?,
        })
    }

    /// Build a branch reference.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an invalid branch name.
    pub fn branch(branch: &str) -> Result<Self, ContextError> {
        Ok(Self::Branch {
            branch: label(branch, "branch")?,
        })
    }

    /// Build a URL reference.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Url`] when the value is not a well-formed
    /// public HTTP(S) URL. Nothing is fetched.
    pub fn url(url: &str) -> Result<Self, ContextError> {
        match PublicHttpUrl::new(url) {
            Ok(url) => Ok(Self::Url { url }),
            Err(error) => Err(ContextError::Url { error }),
        }
    }

    /// Build a session reference.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an invalid session identity.
    pub fn session(session: &str) -> Result<Self, ContextError> {
        Ok(Self::Session {
            session: label(session, "session")?,
        })
    }

    /// Build a turn reference.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an invalid session or turn
    /// identity.
    pub fn turn(session: &str, turn: &str) -> Result<Self, ContextError> {
        Ok(Self::Turn {
            session: label(session, "session")?,
            turn: label(turn, "turn")?,
        })
    }

    /// Build a run reference.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an invalid run identity.
    pub fn run(run: &str) -> Result<Self, ContextError> {
        Ok(Self::Run {
            run: label(run, "run")?,
        })
    }

    /// Build a ticket reference.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an invalid ticket identity.
    pub fn ticket(ticket: &str) -> Result<Self, ContextError> {
        Ok(Self::Ticket {
            ticket: label(ticket, "ticket")?,
        })
    }

    /// Build an artifact reference.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an invalid digest.
    pub fn artifact(digest: &str) -> Result<Self, ContextError> {
        Ok(Self::Artifact {
            digest: label(digest, "digest")?,
        })
    }

    /// Build a workspace reference.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an invalid workspace identity.
    pub fn workspace(workspace: &str) -> Result<Self, ContextError> {
        Ok(Self::Workspace {
            workspace: label(workspace, "workspace")?,
        })
    }

    /// Stable lowercase kind.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::File { .. } => "file",
            Self::Folder { .. } => "folder",
            Self::Diff { .. } => "diff",
            Self::Staged => "staged",
            Self::Commit { .. } => "commit",
            Self::Branch { .. } => "branch",
            Self::Url { .. } => "url",
            Self::Session { .. } => "session",
            Self::Turn { .. } => "turn",
            Self::Run { .. } => "run",
            Self::Ticket { .. } => "ticket",
            Self::Artifact { .. } => "artifact",
            Self::Workspace { .. } => "workspace",
        }
    }
}

/// What a resolver observed the referenced bytes to be.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ContentForm {
    /// Valid UTF-8 text.
    Utf8Text,
    /// Bytes that are not text.
    Binary,
}

/// How the caller intends to use the resolved content.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReferenceUse {
    /// Inlined into the prompt as text.
    InlineText,
    /// Carried as an artifact handle, never inlined.
    ArtifactHandle,
}

/// What a secret scan concluded about the resolved content.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecretScan {
    /// Scanned; no secret found.
    Clean,
    /// Scanned; a secret was found.
    SecretDetected,
}

/// Whether the authorization a reference was made under still holds.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthorizationState {
    /// The same grants still apply.
    Unchanged,
    /// The grants changed after the reference was made.
    Changed,
}

/// What a resolver observed about a reference, named at the call site.
#[derive(Clone, Debug)]
pub struct ResolutionFacts<'a> {
    /// Resolved size in bytes.
    pub size_bytes: u64,
    /// Where the content came from.
    pub provenance: &'a str,
    /// What the bytes are.
    pub form: ContentForm,
    /// How the caller intends to use them.
    pub intended_use: ReferenceUse,
    /// What the secret scan concluded.
    pub secrets: SecretScan,
    /// Whether authorization still holds.
    pub authorization: AuthorizationState,
}

/// A reference that resolved, with its size and provenance.
///
/// Resolution is a value operation: nothing is read, fetched or listed. The
/// facts are supplied by the caller that did the reading, and this type refuses
/// the combinations the contract forbids.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedReference {
    reference: ContextReference,
    size_bytes: u64,
    provenance: String,
    form: ContentForm,
    intended_use: ReferenceUse,
}

impl ResolvedReference {
    /// Admit a resolved reference.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::AuthorizationChanged`] when the grants changed,
    /// [`ContextError::SecretDetected`] when the scan found a secret,
    /// [`ContextError::BinaryConfusion`] when binary bytes would be inlined as
    /// text, and [`ContextError::ClassificationRequired`] when provenance is
    /// absent.
    pub fn resolve(
        reference: ContextReference,
        facts: ResolutionFacts<'_>,
    ) -> Result<Self, ContextError> {
        if facts.authorization == AuthorizationState::Changed {
            return Err(ContextError::AuthorizationChanged);
        }
        if facts.secrets == SecretScan::SecretDetected {
            return Err(ContextError::SecretDetected);
        }
        if facts.form == ContentForm::Binary && facts.intended_use == ReferenceUse::InlineText {
            return Err(ContextError::BinaryConfusion);
        }
        if facts.provenance.is_empty() {
            return Err(ContextError::ClassificationRequired {
                field: "provenance",
            });
        }
        bounded(facts.provenance, "provenance")?;
        Ok(Self {
            reference,
            size_bytes: facts.size_bytes,
            provenance: facts.provenance.to_owned(),
            form: facts.form,
            intended_use: facts.intended_use,
        })
    }

    /// The reference that resolved.
    #[must_use]
    pub const fn reference(&self) -> &ContextReference {
        &self.reference
    }

    /// The resolved size.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Where the content came from.
    #[must_use]
    pub fn provenance(&self) -> &str {
        &self.provenance
    }

    /// What the bytes are.
    #[must_use]
    pub const fn form(&self) -> ContentForm {
        self.form
    }

    /// How the content is used.
    #[must_use]
    pub const fn intended_use(&self) -> ReferenceUse {
        self.intended_use
    }
}

/// A locally computed token estimate.
///
/// A distinct type from [`MeasuredTokens`], with no conversion between them.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EstimatedTokens(u64);

impl EstimatedTokens {
    /// Record an estimate.
    #[must_use]
    pub const fn new(tokens: u64) -> Self {
        Self(tokens)
    }

    /// The estimated count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A count the provider reported.
///
/// A distinct type from [`EstimatedTokens`]. There is no `From` implementation
/// and no constructor taking an estimate, so an estimate cannot be recorded as
/// a measurement. A measurement:
///
/// ```
/// use automonique_protocol::context::MeasuredTokens;
///
/// let measured: MeasuredTokens = MeasuredTokens::new(1_200);
/// assert_eq!(measured.get(), 1_200);
/// ```
///
/// and the same binding differing only in where the number came from:
///
/// ```compile_fail
/// use automonique_protocol::context::{EstimatedTokens, MeasuredTokens};
///
/// let measured: MeasuredTokens = EstimatedTokens::new(1_200);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MeasuredTokens(u64);

impl MeasuredTokens {
    /// Record a provider-reported count.
    #[must_use]
    pub const fn new(tokens: u64) -> Self {
        Self(tokens)
    }

    /// The reported count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Why a provider count is unavailable.
///
/// Never empty, so an unavailable count cannot be recorded without saying why.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UnavailableReason(&'static str);

impl UnavailableReason {
    /// Record a reason.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an empty or invalid reason.
    pub fn new(reason: &'static str) -> Result<Self, ContextError> {
        bounded(reason, "unavailable_reason")?;
        Ok(Self(reason))
    }

    /// The reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// What the provider reported about a component class.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProviderTokenCount {
    /// The provider reported a count.
    Reported(MeasuredTokens),
    /// The provider reported nothing, and said so.
    Unavailable(UnavailableReason),
}

/// Estimated and provider-reported tokens for one component class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenAccount {
    class: ComponentClass,
    estimated: EstimatedTokens,
    provider: ProviderTokenCount,
}

impl TokenAccount {
    /// Record one class's accounting.
    #[must_use]
    pub const fn new(
        class: ComponentClass,
        estimated: EstimatedTokens,
        provider: ProviderTokenCount,
    ) -> Self {
        Self {
            class,
            estimated,
            provider,
        }
    }

    /// Which class this accounts for.
    #[must_use]
    pub const fn class(self) -> ComponentClass {
        self.class
    }

    /// The local estimate, which is never a measurement.
    #[must_use]
    pub const fn estimated(self) -> EstimatedTokens {
        self.estimated
    }

    /// The provider-reported count, if there is one.
    #[must_use]
    pub const fn measured(self) -> Option<MeasuredTokens> {
        match self.provider {
            ProviderTokenCount::Reported(tokens) => Some(tokens),
            ProviderTokenCount::Unavailable(_) => None,
        }
    }

    /// Why the provider count is absent, if it is.
    #[must_use]
    pub const fn unavailable_reason(self) -> Option<&'static str> {
        match self.provider {
            ProviderTokenCount::Reported(_) => None,
            ProviderTokenCount::Unavailable(reason) => Some(reason.as_str()),
        }
    }
}

/// Whether a compression's output was checked against its protected facts.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VerificationStatus {
    /// Not checked yet.
    Pending,
    /// Checked; every protected fact survived.
    Verified,
    /// Checked; a protected fact was lost.
    ProtectedFactMissing,
}

impl VerificationStatus {
    /// Every status, for coverage checks.
    pub const ALL: [Self; 3] = [Self::Pending, Self::Verified, Self::ProtectedFactMissing];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::ProtectedFactMissing => "protected_fact_missing",
        }
    }
}

/// Every field a [`CompressionRecord`] needs, named at the call site.
///
/// A struct rather than a positional argument list: four of these are strings
/// and a caller that transposed provider with model, or template digest with
/// output digest, would compile cleanly while recording the wrong lineage.
#[derive(Clone, Debug)]
pub struct CompressionParts<'a> {
    /// First message of the compressed range.
    pub source_from: u64,
    /// Last message of the compressed range.
    pub source_to: u64,
    /// The provider that ran the compression.
    pub compressor_provider: &'a str,
    /// The model that ran the compression.
    pub compressor_model: &'a str,
    /// Digest of the prompt or template used.
    pub template_digest: &'a str,
    /// Digest of the derived view produced.
    pub output_digest: &'a str,
    /// Facts the compression had to preserve.
    pub protected_facts: &'a [&'a str],
    /// Whether the output was checked.
    pub verification: VerificationStatus,
}

/// The durable record of one compression.
///
/// Produces a derived view. The authoritative transcript is not a field and no
/// method returns one, so there is nothing to mutate or delete through a
/// record. A record exposes its range:
///
/// ```
/// use automonique_protocol::context::{CompressionParts, CompressionRecord, VerificationStatus};
///
/// let record = CompressionRecord::record(CompressionParts {
///     source_from: 10,
///     source_to: 42,
///     compressor_provider: "provider-a",
///     compressor_model: "model-b",
///     template_digest: "sha256:t",
///     output_digest: "sha256:o",
///     protected_facts: &["the deploy target is staging"],
///     verification: VerificationStatus::Verified,
/// })
/// .unwrap();
/// let range = record.source_range();
/// ```
///
/// and the same record differing only in reaching for the transcript:
///
/// ```compile_fail
/// use automonique_protocol::context::{CompressionParts, CompressionRecord, VerificationStatus};
///
/// let record = CompressionRecord::record(CompressionParts {
///     source_from: 10,
///     source_to: 42,
///     compressor_provider: "provider-a",
///     compressor_model: "model-b",
///     template_digest: "sha256:t",
///     output_digest: "sha256:o",
///     protected_facts: &["the deploy target is staging"],
///     verification: VerificationStatus::Verified,
/// })
/// .unwrap();
/// let transcript = record.transcript();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompressionRecord {
    source_from: u64,
    source_to: u64,
    compressor_provider: String,
    compressor_model: String,
    template_digest: String,
    output_digest: String,
    protected_facts: Vec<String>,
    verification: VerificationStatus,
}

impl CompressionRecord {
    /// Record a compression.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an invalid component and
    /// [`ContextError::InvalidRange`] when the source range is inverted.
    pub fn record(parts: CompressionParts<'_>) -> Result<Self, ContextError> {
        if parts.source_to < parts.source_from {
            return Err(ContextError::InvalidRange {
                reason: "the compressed range ends before it starts",
            });
        }
        bounded(parts.compressor_provider, "compressor_provider")?;
        bounded(parts.compressor_model, "compressor_model")?;
        bounded(parts.template_digest, "template_digest")?;
        bounded(parts.output_digest, "output_digest")?;
        for fact in parts.protected_facts {
            bounded(fact, "protected_fact")?;
        }
        Ok(Self {
            source_from: parts.source_from,
            source_to: parts.source_to,
            compressor_provider: parts.compressor_provider.to_owned(),
            compressor_model: parts.compressor_model.to_owned(),
            template_digest: parts.template_digest.to_owned(),
            output_digest: parts.output_digest.to_owned(),
            protected_facts: parts
                .protected_facts
                .iter()
                .map(|fact| (*fact).to_owned())
                .collect(),
            verification: parts.verification,
        })
    }

    /// The compressed source range, which still addresses the authoritative
    /// messages.
    #[must_use]
    pub const fn source_range(&self) -> (u64, u64) {
        (self.source_from, self.source_to)
    }

    /// The provider that compressed.
    #[must_use]
    pub fn compressor_provider(&self) -> &str {
        &self.compressor_provider
    }

    /// The model that compressed.
    #[must_use]
    pub fn compressor_model(&self) -> &str {
        &self.compressor_model
    }

    /// Digest of the prompt or template used.
    #[must_use]
    pub fn template_digest(&self) -> &str {
        &self.template_digest
    }

    /// Digest of the derived view produced.
    #[must_use]
    pub fn output_digest(&self) -> &str {
        &self.output_digest
    }

    /// Facts the compression had to preserve.
    #[must_use]
    pub fn protected_facts(&self) -> &[String] {
        &self.protected_facts
    }

    /// The verification status.
    #[must_use]
    pub const fn verification(&self) -> VerificationStatus {
        self.verification
    }

    /// Whether the output was verified against its protected facts.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self.verification, VerificationStatus::Verified)
    }
}

/// A fork taken before a compression, so the uncompressed conversation stays
/// reachable.
///
/// The constructor takes the compression it precedes and refuses a fork point
/// inside the compressed range, so a "fork before compression" that is not
/// actually before one has no constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextFork {
    source_session: ContextLabel,
    fork_session: ContextLabel,
    at_message: u64,
}

impl ContextFork {
    /// Fork a session at a point at or before a compression's first message.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidRange`] when the fork point is inside
    /// the compressed range, [`ContextError::ReferenceRefused`] when the fork
    /// and its source are the same session, and [`ContextError::Field`] for an
    /// invalid identity.
    pub fn before_compression(
        record: &CompressionRecord,
        source_session: &str,
        fork_session: &str,
        at_message: u64,
    ) -> Result<Self, ContextError> {
        let source = label(source_session, "source_session")?;
        let fork = label(fork_session, "fork_session")?;
        if source == fork {
            return Err(ContextError::ReferenceRefused {
                reason: "a fork cannot be its own source",
            });
        }
        if at_message > record.source_from {
            return Err(ContextError::InvalidRange {
                reason: "the fork point is inside the compressed range",
            });
        }
        Ok(Self {
            source_session: source,
            fork_session: fork,
            at_message,
        })
    }

    /// The session forked from, which still holds the authoritative messages.
    #[must_use]
    pub const fn source_session(&self) -> &ContextLabel {
        &self.source_session
    }

    /// The session created by the fork.
    #[must_use]
    pub const fn fork_session(&self) -> &ContextLabel {
        &self.fork_session
    }

    /// The message the fork was taken at.
    #[must_use]
    pub const fn at_message(&self) -> u64 {
        self.at_message
    }

    /// Whether this fork precedes a compression's first compressed message.
    #[must_use]
    pub const fn precedes(&self, record: &CompressionRecord) -> bool {
        self.at_message <= record.source_from
    }
}

/// Which typed store a memory lives in.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MemoryStore {
    /// Stable user facts and preferences.
    UserProfile,
    /// Workspace conventions and durable lessons.
    Workspace,
    /// Reviewed knowledge shared with a team.
    Team,
    /// Bounded state for a goal or automation.
    Task,
    /// Searchable session references.
    EpisodicIndex,
    /// An optional external provider index.
    ExternalProvider,
}

impl MemoryStore {
    /// Every store, for coverage checks.
    pub const ALL: [Self; 6] = [
        Self::UserProfile,
        Self::Workspace,
        Self::Team,
        Self::Task,
        Self::EpisodicIndex,
        Self::ExternalProvider,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserProfile => "user_profile",
            Self::Workspace => "workspace",
            Self::Team => "team",
            Self::Task => "task",
            Self::EpisodicIndex => "episodic_index",
            Self::ExternalProvider => "external_provider",
        }
    }
}

/// How sensitive a memory's content is, ordered least to most.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Sensitivity {
    /// Nothing about it is sensitive.
    Public,
    /// Ordinary internal content.
    Internal,
    /// Content whose disclosure would harm the tenant.
    Confidential,
    /// Content under a specific handling obligation.
    Restricted,
}

impl Sensitivity {
    /// Every level, for coverage checks.
    pub const ALL: [Self; 4] = [
        Self::Public,
        Self::Internal,
        Self::Confidential,
        Self::Restricted,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Confidential => "confidential",
            Self::Restricted => "restricted",
        }
    }
}

/// Who may see a memory, ordered narrowest to widest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Visibility {
    /// Only the actor who owns it.
    Private,
    /// The owning team.
    Team,
    /// Everyone in the tenant.
    Tenant,
}

impl Visibility {
    /// Every visibility, for coverage checks.
    pub const ALL: [Self; 3] = [Self::Private, Self::Team, Self::Tenant];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Team => "team",
            Self::Tenant => "tenant",
        }
    }
}

/// How long a memory is kept.
///
/// Every variant says something. There is deliberately no "unspecified"
/// variant, so a memory without a retention rule is unrepresentable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Retention {
    /// Removed at a fixed instant.
    ExpiresAt(EpochMillis),
    /// Kept until it is revalidated at a fixed instant.
    ReviewBy(EpochMillis),
    /// Kept because a legal hold forbids removal.
    UnderLegalHold,
}

impl Retention {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExpiresAt(_) => "expires_at",
            Self::ReviewBy(_) => "review_by",
            Self::UnderLegalHold => "under_legal_hold",
        }
    }

    /// The instant this rule names, if it names one.
    #[must_use]
    pub const fn instant(self) -> Option<EpochMillis> {
        match self {
            Self::ExpiresAt(at) | Self::ReviewBy(at) => Some(at),
            Self::UnderLegalHold => None,
        }
    }

    /// Whether this rule permits deletion.
    #[must_use]
    pub const fn permits_deletion(self) -> bool {
        !matches!(self, Self::UnderLegalHold)
    }
}

/// A bounded confidence in `0..=MAX_CONFIDENCE`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Confidence(u8);

impl Confidence {
    /// Record a confidence.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ConfidenceOutOfRange`] above
    /// [`MAX_CONFIDENCE`].
    pub const fn new(value: u8) -> Result<Self, ContextError> {
        if value > MAX_CONFIDENCE {
            return Err(ContextError::ConfidenceOutOfRange {
                max: MAX_CONFIDENCE,
                requested: value,
            });
        }
        Ok(Self(value))
    }

    /// The recorded confidence.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Every classification a memory needs, named at the call site.
#[derive(Clone, Debug)]
pub struct MemoryEntryParts<'a> {
    /// The owning store.
    pub store: MemoryStore,
    /// The owning tenant.
    pub tenant: &'a str,
    /// Where the memory came from.
    pub provenance: &'a str,
    /// How confident the writer is.
    pub confidence: Confidence,
    /// How sensitive the content is.
    pub sensitivity: Sensitivity,
    /// Who may see it.
    pub visibility: Visibility,
    /// How long it is kept.
    pub retention: Retention,
}

/// A tenant-scoped memory entry.
///
/// Every classification is a constructor argument, so an entry without
/// provenance, confidence, sensitivity, visibility or retention has no
/// constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryEntry {
    store: MemoryStore,
    tenant: String,
    provenance: String,
    confidence: Confidence,
    sensitivity: Sensitivity,
    visibility: Visibility,
    retention: Retention,
    superseded_by: Option<String>,
}

impl MemoryEntry {
    /// Record a memory.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ClassificationRequired`] when provenance is
    /// absent, and [`ContextError::Field`] for an invalid component.
    pub fn record(parts: MemoryEntryParts<'_>) -> Result<Self, ContextError> {
        bounded(parts.tenant, "tenant")?;
        if parts.provenance.is_empty() {
            return Err(ContextError::ClassificationRequired {
                field: "provenance",
            });
        }
        bounded(parts.provenance, "provenance")?;
        Ok(Self {
            store: parts.store,
            tenant: parts.tenant.to_owned(),
            provenance: parts.provenance.to_owned(),
            confidence: parts.confidence,
            sensitivity: parts.sensitivity,
            visibility: parts.visibility,
            retention: parts.retention,
            superseded_by: None,
        })
    }

    /// The owning store.
    #[must_use]
    pub const fn store(&self) -> MemoryStore {
        self.store
    }

    /// The owning tenant.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// Where the memory came from.
    #[must_use]
    pub fn provenance(&self) -> &str {
        &self.provenance
    }

    /// The recorded confidence.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// How sensitive the content is.
    #[must_use]
    pub const fn sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }

    /// Who may see it.
    #[must_use]
    pub const fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// How long it is kept.
    #[must_use]
    pub const fn retention(&self) -> Retention {
        self.retention
    }

    /// Which entry replaced this one, if any.
    #[must_use]
    pub fn superseded_by(&self) -> Option<&str> {
        self.superseded_by.as_deref()
    }

    /// Correct this memory by superseding it.
    ///
    /// Returns a new value rather than mutating, so the corrected entry stays
    /// addressable and the audit trail survives. An entry that is already
    /// superseded cannot be re-pointed, because that would rewrite the
    /// supersession history rather than extend it.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::AlreadySuperseded`] when this entry already
    /// names a replacement, and [`ContextError::Field`] for an invalid
    /// identifier.
    pub fn supersede_with(&self, replacement_id: &str) -> Result<Self, ContextError> {
        if self.superseded_by.is_some() {
            return Err(ContextError::AlreadySuperseded);
        }
        bounded(replacement_id, "replacement_id")?;
        let mut next = self.clone();
        next.superseded_by = Some(replacement_id.to_owned());
        Ok(next)
    }

    /// Delete this memory, producing its tombstone.
    ///
    /// The only deletion operation returns a [`MemoryTombstone`] carrying the
    /// store, tenant, provenance and sensitivity, so a deletion cannot erase
    /// the audit trail, and there is no operation that removes an entry
    /// without producing one.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::RetentionForbidsDeletion`] when the entry's
    /// retention rule forbids removal, and [`ContextError::Field`] for an
    /// invalid identifier.
    pub fn delete(
        &self,
        entry_id: &str,
        deleted_at: EpochMillis,
        reason: DeletionReason,
    ) -> Result<MemoryTombstone, ContextError> {
        if !self.retention.permits_deletion() {
            return Err(ContextError::RetentionForbidsDeletion {
                rule: self.retention.as_str(),
            });
        }
        bounded(entry_id, "entry_id")?;
        Ok(MemoryTombstone {
            store: self.store,
            tenant: self.tenant.clone(),
            entry_id: entry_id.to_owned(),
            provenance: self.provenance.clone(),
            sensitivity: self.sensitivity,
            deleted_at,
            reason,
        })
    }
}

/// Why a memory was deleted.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DeletionReason {
    /// The owning actor asked for it.
    ActorRequest,
    /// The retention rule's instant passed.
    RetentionExpired,
    /// Policy revoked it.
    PolicyRevocation,
}

impl DeletionReason {
    /// Every reason, for coverage checks.
    pub const ALL: [Self; 3] = [
        Self::ActorRequest,
        Self::RetentionExpired,
        Self::PolicyRevocation,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActorRequest => "actor_request",
            Self::RetentionExpired => "retention_expired",
            Self::PolicyRevocation => "policy_revocation",
        }
    }
}

/// The durable record that a memory was deleted.
///
/// Carries what the audit trail needs and none of the deleted content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryTombstone {
    store: MemoryStore,
    tenant: String,
    entry_id: String,
    provenance: String,
    sensitivity: Sensitivity,
    deleted_at: EpochMillis,
    reason: DeletionReason,
}

impl MemoryTombstone {
    /// The store the entry lived in.
    #[must_use]
    pub const fn store(&self) -> MemoryStore {
        self.store
    }

    /// The owning tenant.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// Which entry was deleted.
    #[must_use]
    pub fn entry_id(&self) -> &str {
        &self.entry_id
    }

    /// Where the deleted memory came from.
    #[must_use]
    pub fn provenance(&self) -> &str {
        &self.provenance
    }

    /// How sensitive the deleted content was.
    #[must_use]
    pub const fn sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }

    /// When it was deleted.
    #[must_use]
    pub const fn deleted_at(&self) -> EpochMillis {
        self.deleted_at
    }

    /// Why it was deleted.
    #[must_use]
    pub const fn reason(&self) -> DeletionReason {
        self.reason
    }
}

/// A memory a model proposed, which is not published state.
///
/// A distinct type from [`MemoryEntry`] with no accessor returning one, so a
/// candidate cannot be handed to anything expecting a published entry. A
/// published entry:
///
/// ```
/// use automonique_protocol::context::{
///     Confidence, MemoryEntry, MemoryEntryParts, MemoryStore, Retention, Sensitivity, Visibility,
/// };
/// use automonique_protocol::primitives::EpochMillis;
///
/// let parts = MemoryEntryParts {
///     store: MemoryStore::Workspace,
///     tenant: "acme",
///     provenance: "session-12",
///     confidence: Confidence::new(80).unwrap(),
///     sensitivity: Sensitivity::Internal,
///     visibility: Visibility::Team,
///     retention: Retention::ReviewBy(EpochMillis::from_millis(9_000)),
/// };
/// let published: MemoryEntry = MemoryEntry::record(parts).unwrap();
/// ```
///
/// and the same binding differing only in which constructor produced it:
///
/// ```compile_fail
/// use automonique_protocol::context::{
///     CandidateMemory, Confidence, MemoryEntry, MemoryEntryParts, MemoryStore, Retention,
///     Sensitivity, Visibility,
/// };
/// use automonique_protocol::primitives::EpochMillis;
///
/// let parts = MemoryEntryParts {
///     store: MemoryStore::Workspace,
///     tenant: "acme",
///     provenance: "session-12",
///     confidence: Confidence::new(80).unwrap(),
///     sensitivity: Sensitivity::Internal,
///     visibility: Visibility::Team,
///     retention: Retention::ReviewBy(EpochMillis::from_millis(9_000)),
/// };
/// let published: MemoryEntry = CandidateMemory::propose(parts).unwrap();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateMemory(MemoryEntry);

impl CandidateMemory {
    /// Propose a memory.
    ///
    /// # Errors
    ///
    /// As for [`MemoryEntry::record`].
    pub fn propose(parts: MemoryEntryParts<'_>) -> Result<Self, ContextError> {
        Ok(Self(MemoryEntry::record(parts)?))
    }

    /// The store the candidate would live in.
    #[must_use]
    pub const fn store(&self) -> MemoryStore {
        self.0.store
    }

    /// The owning tenant.
    #[must_use]
    pub fn tenant(&self) -> &str {
        self.0.tenant()
    }

    /// Where the candidate came from.
    #[must_use]
    pub fn provenance(&self) -> &str {
        self.0.provenance()
    }

    /// How confident the proposer is.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.0.confidence
    }

    /// How sensitive the content is.
    #[must_use]
    pub const fn sensitivity(&self) -> Sensitivity {
        self.0.sensitivity
    }

    /// Who would see it.
    #[must_use]
    pub const fn visibility(&self) -> Visibility {
        self.0.visibility
    }

    /// How long it would be kept.
    #[must_use]
    pub const fn retention(&self) -> Retention {
        self.0.retention
    }
}

/// What a learning proposal suggests.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProposalKind {
    /// A candidate memory.
    Memory,
    /// A patch to an existing skill.
    SkillPatch,
    /// A new, executable skill.
    NewSkill,
}

impl ProposalKind {
    /// Every kind, for coverage checks.
    pub const ALL: [Self; 3] = [Self::Memory, Self::SkillPatch, Self::NewSkill];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::SkillPatch => "skill_patch",
            Self::NewSkill => "new_skill",
        }
    }

    /// Whether the proposal would install executable content.
    #[must_use]
    pub const fn is_executable(self) -> bool {
        matches!(self, Self::SkillPatch | Self::NewSkill)
    }
}

/// What a proposal carries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalPayload {
    /// A candidate memory, not published state.
    Memory(CandidateMemory),
    /// A patch to an existing executable skill.
    SkillPatch {
        /// Which skill.
        skill: ContextLabel,
        /// Digest of the proposed patch.
        patch_digest: ContextLabel,
    },
    /// A new executable skill.
    NewSkill {
        /// Which skill.
        skill: ContextLabel,
        /// Digest of the proposed bundle.
        bundle_digest: ContextLabel,
    },
}

impl ProposalPayload {
    /// What this payload proposes.
    #[must_use]
    pub const fn kind(&self) -> ProposalKind {
        match self {
            Self::Memory(_) => ProposalKind::Memory,
            Self::SkillPatch { .. } => ProposalKind::SkillPatch,
            Self::NewSkill { .. } => ProposalKind::NewSkill,
        }
    }
}

/// A model-originated suggestion, separate from published state.
///
/// Its trust is fixed at [`TrustClass::Untrusted`] and there is no method that
/// raises it. Reading the trust:
///
/// ```
/// use automonique_protocol::context::{ContextLabel, LearningProposal, ProposalPayload, TrustClass};
/// use automonique_protocol::primitives::Revision;
///
/// let proposal = LearningProposal::new(
///     ProposalPayload::NewSkill {
///         skill: ContextLabel::new("deploy").unwrap(),
///         bundle_digest: ContextLabel::new("sha256:b").unwrap(),
///     },
///     "three passing runs",
///     Revision::FIRST,
/// )
/// .unwrap();
/// assert_eq!(proposal.trust(), TrustClass::Untrusted);
/// ```
///
/// and the same proposal differing only in trying to set it:
///
/// ```compile_fail
/// use automonique_protocol::context::{ContextLabel, LearningProposal, ProposalPayload, TrustClass};
/// use automonique_protocol::primitives::Revision;
///
/// let mut proposal = LearningProposal::new(
///     ProposalPayload::NewSkill {
///         skill: ContextLabel::new("deploy").unwrap(),
///         bundle_digest: ContextLabel::new("sha256:b").unwrap(),
///     },
///     "three passing runs",
///     Revision::FIRST,
/// )
/// .unwrap();
/// proposal.set_trust(TrustClass::Policy);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LearningProposal {
    payload: ProposalPayload,
    evidence: String,
    revision: Revision,
}

impl LearningProposal {
    /// Record a proposal.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for missing evidence.
    pub fn new(
        payload: ProposalPayload,
        evidence: &str,
        revision: Revision,
    ) -> Result<Self, ContextError> {
        bounded(evidence, "evidence")?;
        Ok(Self {
            payload,
            evidence: evidence.to_owned(),
            revision,
        })
    }

    /// What is proposed.
    #[must_use]
    pub const fn kind(&self) -> ProposalKind {
        self.payload.kind()
    }

    /// What the proposal carries.
    #[must_use]
    pub const fn payload(&self) -> &ProposalPayload {
        &self.payload
    }

    /// The proposal's revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// The trust a proposal carries, which is always the lowest.
    #[must_use]
    pub const fn trust(&self) -> TrustClass {
        TrustClass::Untrusted
    }

    /// The evidence offered.
    #[must_use]
    pub fn evidence(&self) -> &str {
        &self.evidence
    }

    /// Whether this proposal may be activated without review.
    ///
    /// Always `false` for an executable skill. There is no policy argument
    /// that changes the answer, because an agent-created executable skill is
    /// never silently activated in production.
    #[must_use]
    pub const fn may_auto_activate(&self) -> bool {
        !self.kind().is_executable()
    }
}

fn label(value: &str, field: &'static str) -> Result<ContextLabel, ContextError> {
    bounded(value, field)?;
    Ok(ContextLabel(value.to_owned()))
}

fn check_workspace_relative(path: &str) -> Result<(), ContextError> {
    if path.contains('\0') {
        return Err(ContextError::ReferenceRefused {
            reason: "embedded NUL",
        });
    }
    bounded(path, "path")?;
    if path.starts_with('/') {
        return Err(ContextError::OutsideWorkspace {
            rule: "absolute path",
        });
    }
    if path.starts_with('~') {
        return Err(ContextError::OutsideWorkspace {
            rule: "home-relative path",
        });
    }
    if path.contains('\\') {
        return Err(ContextError::ReferenceRefused {
            reason: "backslash in path",
        });
    }
    let mut depth = 0_i32;
    for component in path.split('/') {
        match component {
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return Err(ContextError::OutsideWorkspace {
                        rule: "traversal above the workspace root",
                    });
                }
            }
            "" | "." => {
                return Err(ContextError::ReferenceRefused {
                    reason: "non-canonical path",
                });
            }
            _ => depth += 1,
        }
    }
    Ok(())
}

fn bounded(value: &str, field: &'static str) -> Result<(), ContextError> {
    let error = if value.is_empty() {
        Some(ValueError::Empty)
    } else if value.len() > MAX_CONTEXT_FIELD_BYTES {
        Some(ValueError::TooLong {
            max_bytes: MAX_CONTEXT_FIELD_BYTES,
            actual_bytes: value.len(),
        })
    } else if value.chars().any(char::is_control) {
        Some(ValueError::ControlCharacter)
    } else {
        None
    };
    match error {
        Some(error) => Err(ContextError::Field { field, error }),
        None => Ok(()),
    }
}
