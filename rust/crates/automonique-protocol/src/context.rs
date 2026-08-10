// SPDX-License-Identifier: Elastic-2.0

//! Context manifests, typed references, compression lineage and memory.
//!
//! The boundary this module exists to hold is prompt injection: content that
//! arrived from a repository, a retrieved document or a model's own suggestion
//! must be structurally incapable of becoming policy.
//!
//! Policy components and supplied components are separate types, and a manifest
//! takes policy only through a constructor argument that supplied content
//! cannot reach:
//!
//! ```compile_fail
//! use automonique_protocol::context::{ContextManifest, SuppliedComponent, TrustClass};
//! # fn supplied() -> SuppliedComponent { unreachable!() }
//! // A supplied component cannot be installed as policy.
//! let manifest = ContextManifest::new(vec![supplied()], vec![supplied()]);
//! ```
//!
//! Nothing here assembles a prompt, counts real tokens, fetches a URL, reads a
//! file, runs a compression or activates a skill.

use core::fmt;
use std::error::Error;

use crate::primitives::{EpochMillis, Revision, ValueError};

/// Maximum UTF-8 byte length of a context identifier.
pub const MAX_CONTEXT_FIELD_BYTES: usize = 512;

/// How far a component may be trusted.
///
/// Ordered least to most. A component may never be promoted.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TrustClass {
    /// Model output, retrieved documents, repository rules.
    Untrusted,
    /// Provider-specific rule files, labelled as compatibility inputs.
    Compatibility,
    /// Content the actor supplied directly.
    ActorSupplied,
    /// Tenant or system policy. Only a policy component may carry this.
    Policy,
}

impl TrustClass {
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
    /// A memory entry omitted a required classification.
    ClassificationRequired {
        /// The missing classification.
        field: &'static str,
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
            Self::ClassificationRequired { .. } => "classification_required",
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
            Self::ClassificationRequired { field } => {
                write!(formatter, "a memory entry requires {field}")
            }
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
        }
    }
}

impl Error for ContextError {}

/// A component of a context manifest that policy did not author.
///
/// Its trust class is capped below [`TrustClass::Policy`] at construction, so
/// no supplied content can claim policy trust.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuppliedComponent {
    source: String,
    trust: TrustClass,
    digest: String,
    byte_cap: usize,
    redacted: bool,
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
        requested_trust: TrustClass,
        digest: &str,
        byte_cap: usize,
        redacted: bool,
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
            trust,
            digest: digest.to_owned(),
            byte_cap,
            redacted,
        })
    }

    /// The trust class actually granted.
    #[must_use]
    pub const fn trust(&self) -> TrustClass {
        self.trust
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

    /// The declared byte ceiling.
    #[must_use]
    pub const fn byte_cap(&self) -> usize {
        self.byte_cap
    }

    /// Whether redaction ran.
    #[must_use]
    pub const fn was_redacted(&self) -> bool {
        self.redacted
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
}

impl PolicyComponent {
    /// Record a policy component.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an invalid component.
    pub fn new(source: &str, revision: Revision, digest: &str) -> Result<Self, ContextError> {
        bounded(source, "source")?;
        bounded(digest, "digest")?;
        Ok(Self {
            source: source.to_owned(),
            revision,
            digest: digest.to_owned(),
        })
    }

    /// Always [`TrustClass::Policy`].
    #[must_use]
    pub const fn trust(&self) -> TrustClass {
        TrustClass::Policy
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
}

/// The ordered, content-addressed record of one turn's context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextManifest {
    policy: Vec<PolicyComponent>,
    supplied: Vec<SuppliedComponent>,
}

impl ContextManifest {
    /// Assemble a manifest from its two component kinds.
    #[must_use]
    pub const fn new(policy: Vec<PolicyComponent>, supplied: Vec<SuppliedComponent>) -> Self {
        Self { policy, supplied }
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

    /// The highest trust any supplied component carries.
    ///
    /// Always below [`TrustClass::Policy`].
    #[must_use]
    pub fn highest_supplied_trust(&self) -> Option<TrustClass> {
        self.supplied.iter().map(SuppliedComponent::trust).max()
    }
}

/// A typed reference into context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContextReference {
    /// A file, optionally a line range, pinned by digest.
    File {
        /// Workspace-relative path.
        path: String,
        /// Content digest.
        digest: String,
    },
    /// A bounded folder view.
    Folder {
        /// Workspace-relative path.
        path: String,
        /// Maximum depth.
        depth: u32,
    },
    /// A Git revision range.
    Diff {
        /// The revision being compared.
        revision: String,
    },
    /// A reviewed URL.
    Url {
        /// The absolute URL.
        url: String,
    },
    /// A prior session.
    Session {
        /// The session identity.
        session: String,
    },
    /// A stored artifact.
    Artifact {
        /// The artifact digest.
        digest: String,
    },
}

impl ContextReference {
    /// Build a workspace-relative file reference.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::OutsideWorkspace`] for an absolute path, a
    /// traversal or a home-relative path, and
    /// [`ContextError::ReferenceRefused`] for an embedded NUL.
    pub fn file(path: &str, digest: &str) -> Result<Self, ContextError> {
        check_workspace_relative(path)?;
        bounded(digest, "digest")?;
        Ok(Self::File {
            path: path.to_owned(),
            digest: digest.to_owned(),
        })
    }

    /// Build a bounded folder reference.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::OutsideWorkspace`] as for
    /// [`ContextReference::file`].
    pub fn folder(path: &str, depth: u32) -> Result<Self, ContextError> {
        check_workspace_relative(path)?;
        Ok(Self::Folder {
            path: path.to_owned(),
            depth,
        })
    }

    /// Stable lowercase kind.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::File { .. } => "file",
            Self::Folder { .. } => "folder",
            Self::Diff { .. } => "diff",
            Self::Url { .. } => "url",
            Self::Session { .. } => "session",
            Self::Artifact { .. } => "artifact",
        }
    }
}

/// A token count and whether it was measured or estimated.
///
/// Distinct variants, so an estimate can never be recorded as a measurement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenCount {
    /// Reported by the provider.
    Measured {
        /// The reported count.
        tokens: u64,
    },
    /// Estimated locally.
    Estimated {
        /// The estimated count.
        tokens: u64,
    },
    /// Not available.
    Unavailable {
        /// Why.
        reason: &'static str,
    },
}

impl TokenCount {
    /// The measured count, if the provider reported one.
    #[must_use]
    pub const fn measured(self) -> Option<u64> {
        match self {
            Self::Measured { tokens } => Some(tokens),
            Self::Estimated { .. } | Self::Unavailable { .. } => None,
        }
    }
}

/// The durable record of one compression.
///
/// Produces a derived view. The authoritative transcript is not a field, so
/// compression cannot mutate or delete it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompressionRecord {
    source_from: u64,
    source_to: u64,
    compressor_model: String,
    template_digest: String,
    output_digest: String,
    protected_facts: Vec<String>,
    verified: bool,
}

impl CompressionRecord {
    /// Record a compression.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an invalid component.
    pub fn new(
        source_from: u64,
        source_to: u64,
        compressor_model: &str,
        template_digest: &str,
        output_digest: &str,
        protected_facts: &[&str],
        verified: bool,
    ) -> Result<Self, ContextError> {
        bounded(compressor_model, "compressor_model")?;
        bounded(template_digest, "template_digest")?;
        bounded(output_digest, "output_digest")?;
        for fact in protected_facts {
            bounded(fact, "protected_fact")?;
        }
        Ok(Self {
            source_from,
            source_to,
            compressor_model: compressor_model.to_owned(),
            template_digest: template_digest.to_owned(),
            output_digest: output_digest.to_owned(),
            protected_facts: protected_facts.iter().map(|f| (*f).to_owned()).collect(),
            verified,
        })
    }

    /// The compressed source range.
    #[must_use]
    pub const fn source_range(&self) -> (u64, u64) {
        (self.source_from, self.source_to)
    }

    /// The model that compressed.
    #[must_use]
    pub fn compressor_model(&self) -> &str {
        &self.compressor_model
    }

    /// Facts the compression had to preserve.
    #[must_use]
    pub fn protected_facts(&self) -> &[String] {
        &self.protected_facts
    }

    /// Whether the output was verified against its protected facts.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        self.verified
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

/// A tenant-scoped memory entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryEntry {
    store: MemoryStore,
    tenant: String,
    provenance: String,
    confidence: u8,
    visibility: TrustClass,
    review_by: Option<EpochMillis>,
    supersedes: Option<String>,
}

impl MemoryEntry {
    /// Record a memory.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ClassificationRequired`] when provenance is
    /// absent, and [`ContextError::Field`] for an invalid component.
    pub fn new(
        store: MemoryStore,
        tenant: &str,
        provenance: &str,
        confidence: u8,
        visibility: TrustClass,
        review_by: Option<EpochMillis>,
    ) -> Result<Self, ContextError> {
        bounded(tenant, "tenant")?;
        if provenance.is_empty() {
            return Err(ContextError::ClassificationRequired {
                field: "provenance",
            });
        }
        bounded(provenance, "provenance")?;
        Ok(Self {
            store,
            tenant: tenant.to_owned(),
            provenance: provenance.to_owned(),
            confidence,
            visibility,
            review_by,
            supersedes: None,
        })
    }

    /// The owning store.
    #[must_use]
    pub const fn store(&self) -> MemoryStore {
        self.store
    }

    /// Where the memory came from.
    #[must_use]
    pub fn provenance(&self) -> &str {
        &self.provenance
    }

    /// The recorded confidence.
    #[must_use]
    pub const fn confidence(&self) -> u8 {
        self.confidence
    }

    /// What this entry supersedes, if anything.
    #[must_use]
    pub fn supersedes(&self) -> Option<&str> {
        self.supersedes.as_deref()
    }

    /// Correct this memory by superseding it.
    ///
    /// Returns a new entry rather than mutating, so the corrected value stays
    /// addressable and the audit trail survives.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for an invalid identifier.
    pub fn superseded_by(&self, replacement_id: &str) -> Result<Self, ContextError> {
        bounded(replacement_id, "replacement_id")?;
        let mut next = self.clone();
        next.supersedes = Some(replacement_id.to_owned());
        Ok(next)
    }

    /// The visibility class.
    #[must_use]
    pub const fn visibility(&self) -> TrustClass {
        self.visibility
    }

    /// When the entry must be reviewed, if ever.
    #[must_use]
    pub const fn review_by(&self) -> Option<EpochMillis> {
        self.review_by
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

/// A model-originated suggestion, separate from published state.
///
/// Its trust is fixed at [`TrustClass::Untrusted`] and there is no method that
/// raises it or activates an executable skill.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LearningProposal {
    kind: ProposalKind,
    evidence: String,
}

impl LearningProposal {
    /// Record a proposal.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Field`] for missing evidence.
    pub fn new(kind: ProposalKind, evidence: &str) -> Result<Self, ContextError> {
        bounded(evidence, "evidence")?;
        Ok(Self {
            kind,
            evidence: evidence.to_owned(),
        })
    }

    /// What is proposed.
    #[must_use]
    pub const fn kind(&self) -> ProposalKind {
        self.kind
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
        matches!(self.kind, ProposalKind::Memory)
    }
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
