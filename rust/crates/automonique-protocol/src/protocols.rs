// SPDX-License-Identifier: Elastic-2.0

//! Protocol client bindings, identifier mappings and honest capability
//! declarations for the public compatibility protocols.
//!
//! An ACP host, an OpenAI-compatible client, the native Runs API, an MCP
//! export, an A2A peer and a relay client all reach one durable domain. The
//! property this module exists to hold is that none of them becomes a second
//! one: a compatibility projection terminates a wire format and can create no
//! effect the canonical domain services do not already offer.
//!
//! Every binding names a tenant actor. The fields are not optional, so an
//! unauthenticated binding is a struct literal that does not compile rather
//! than a value that is refused. First the literal that does compile, so the
//! failure below is attributable to the field it drops:
//!
//! ```
//! # use automonique_protocol::identity::Actor;
//! # use automonique_protocol::primitives::Revision;
//! use automonique_protocol::protocols::{
//!     ClientBinding, ClientBindingParts, ProtocolDialect, ProtocolRange, ProtocolVersion,
//!     Quotas, Scope,
//! };
//! let binding = ClientBinding::bind(ClientBindingParts {
//!     dialect: ProtocolDialect::Acp,
//!     client_id: "zed-1",
//!     actor: Actor::new("acme", "svc-1").unwrap(),
//!     scopes: &[Scope::ReadCanonicalState],
//!     quotas: Quotas { concurrent_runs: 2, requests_per_minute: 60, tokens_per_day: 8_000 },
//!     credential_revision: Revision::FIRST,
//!     supported_range: ProtocolRange::new(ProtocolVersion::new(1), ProtocolVersion::new(2))
//!         .unwrap(),
//! })
//! .unwrap();
//! assert_eq!(binding.actor().tenant(), "acme");
//! ```
//!
//! ```compile_fail
//! # use automonique_protocol::primitives::Revision;
//! use automonique_protocol::protocols::{
//!     ClientBinding, ClientBindingParts, ProtocolDialect, ProtocolRange, ProtocolVersion,
//!     Quotas, Scope,
//! };
//! // There is no tenant-free binding: the actor is not an optional field.
//! let binding = ClientBinding::bind(ClientBindingParts {
//!     dialect: ProtocolDialect::Acp,
//!     client_id: "zed-1",
//!     scopes: &[Scope::ReadCanonicalState],
//!     quotas: Quotas { concurrent_runs: 2, requests_per_minute: 60, tokens_per_day: 8_000 },
//!     credential_revision: Revision::FIRST,
//!     supported_range: ProtocolRange::new(ProtocolVersion::new(1), ProtocolVersion::new(2))
//!         .unwrap(),
//! })
//! .unwrap();
//! ```
//!
//! A [`Projection`] owns nothing. Both of its fields are shared borrows of
//! canonical state, and its dialect is read back out of the binding rather than
//! stored, so there is no field a projection could cache and later disagree
//! with.
//!
//! That claim needs two checks, because the compiler states only half of it.
//! The `compile_fail` below states the lifetime tie: a projection cannot
//! outlive the canonical value it projects, which an alternate store would have
//! to. It says nothing about a cached copy — a projection that stored its
//! dialect beside the binding would still compile and still satisfy the borrow
//! checker. What rules that out is the width of the type, which is exactly its
//! two shared borrows and nothing else, and `tests/protocols.rs` asserts that
//! width rather than leaving it to the prose here.
//!
//! ```
//! # use automonique_protocol::identity::Actor;
//! # use automonique_protocol::primitives::Revision;
//! # use automonique_protocol::protocols::*;
//! # let binding = ClientBinding::bind(ClientBindingParts {
//! #     dialect: ProtocolDialect::OpenAiCompatible,
//! #     client_id: "librechat-1",
//! #     actor: Actor::new("acme", "svc-1").unwrap(),
//! #     scopes: &[Scope::ReadCanonicalState],
//! #     quotas: Quotas { concurrent_runs: 2, requests_per_minute: 60, tokens_per_day: 8_000 },
//! #     credential_revision: Revision::FIRST,
//! #     supported_range: ProtocolRange::new(ProtocolVersion::new(1), ProtocolVersion::new(2))
//! #         .unwrap(),
//! # }).unwrap();
//! # let id = CanonicalId::new(CanonicalKind::Work, "w-1").unwrap();
//! let work = CanonicalWork::new(id, "ship the adapter", Revision::FIRST).unwrap();
//! let projection = Projection::of(&binding, &work).unwrap();
//! assert_eq!(projection.work().title(), "ship the adapter");
//! ```
//!
//! ```compile_fail
//! # use automonique_protocol::identity::Actor;
//! # use automonique_protocol::primitives::Revision;
//! # use automonique_protocol::protocols::*;
//! # let binding = ClientBinding::bind(ClientBindingParts {
//! #     dialect: ProtocolDialect::OpenAiCompatible,
//! #     client_id: "librechat-1",
//! #     actor: Actor::new("acme", "svc-1").unwrap(),
//! #     scopes: &[Scope::ReadCanonicalState],
//! #     quotas: Quotas { concurrent_runs: 2, requests_per_minute: 60, tokens_per_day: 8_000 },
//! #     credential_revision: Revision::FIRST,
//! #     supported_range: ProtocolRange::new(ProtocolVersion::new(1), ProtocolVersion::new(2))
//! #         .unwrap(),
//! # }).unwrap();
//! # let id = CanonicalId::new(CanonicalKind::Work, "w-1").unwrap();
//! let work = CanonicalWork::new(id, "ship the adapter", Revision::FIRST).unwrap();
//! let projection = Projection::of(&binding, &work).unwrap();
//! // A projection that survived the canonical record would be a second store.
//! drop(work);
//! assert_eq!(projection.work().title(), "ship the adapter");
//! ```
//!
//! An approval names exactly one provider or one tool. There is no target
//! meaning "everything" and no host decision meaning "stop asking", so a global
//! bypass mode is not something a host can enable:
//!
//! ```
//! use automonique_protocol::protocols::ApprovalTarget;
//! let target = ApprovalTarget::tool("format").unwrap();
//! assert_eq!(target.name(), "format");
//! ```
//!
//! ```compile_fail
//! use automonique_protocol::protocols::ApprovalTarget;
//! let target = ApprovalTarget::Everything;
//! ```
//!
//! ```compile_fail
//! use automonique_protocol::protocols::HostApprovalDecision;
//! let decision = HostApprovalDecision::BypassAll;
//! ```
//!
//! A remote peer's assertion about who authorized something is text. Only the
//! binding resolves to an [`Actor`]:
//!
//! ```
//! # use automonique_protocol::identity::Actor;
//! # use automonique_protocol::primitives::Revision;
//! # use automonique_protocol::protocols::*;
//! # let binding = ClientBinding::bind(ClientBindingParts {
//! #     dialect: ProtocolDialect::A2a,
//! #     client_id: "peer-1",
//! #     actor: Actor::new("acme", "svc-1").unwrap(),
//! #     scopes: &[Scope::ReadCanonicalState],
//! #     quotas: Quotas { concurrent_runs: 2, requests_per_minute: 60, tokens_per_day: 8_000 },
//! #     credential_revision: Revision::FIRST,
//! #     supported_range: ProtocolRange::new(ProtocolVersion::new(1), ProtocolVersion::new(2))
//! #         .unwrap(),
//! # }).unwrap();
//! let claim = RemoteAgentClaim::new("peer-1", "admin@acme", "write_work").unwrap();
//! let actor: &Actor = binding.actor();
//! assert_eq!(actor.id(), "svc-1");
//! ```
//!
//! ```compile_fail
//! # use automonique_protocol::identity::Actor;
//! # use automonique_protocol::primitives::Revision;
//! # use automonique_protocol::protocols::*;
//! # let binding = ClientBinding::bind(ClientBindingParts {
//! #     dialect: ProtocolDialect::A2a,
//! #     client_id: "peer-1",
//! #     actor: Actor::new("acme", "svc-1").unwrap(),
//! #     scopes: &[Scope::ReadCanonicalState],
//! #     quotas: Quotas { concurrent_runs: 2, requests_per_minute: 60, tokens_per_day: 8_000 },
//! #     credential_revision: Revision::FIRST,
//! #     supported_range: ProtocolRange::new(ProtocolVersion::new(1), ProtocolVersion::new(2))
//! #         .unwrap(),
//! # }).unwrap();
//! let claim = RemoteAgentClaim::new("peer-1", "admin@acme", "write_work").unwrap();
//! // A claim is not a principal.
//! let actor: &Actor = claim.actor();
//! ```
//!
//! A projected semantic is either represented, or degraded to bounded text with
//! a link to the authoritative record, or a typed error. There is no fourth
//! shape, so a field cannot be dropped on the way out:
//!
//! ```
//! # use automonique_protocol::identity::Actor;
//! # use automonique_protocol::primitives::Revision;
//! # use automonique_protocol::protocols::*;
//! # let binding = ClientBinding::bind(ClientBindingParts {
//! #     dialect: ProtocolDialect::McpExport,
//! #     client_id: "mcp-1",
//! #     actor: Actor::new("acme", "svc-1").unwrap(),
//! #     scopes: &[Scope::ReadCanonicalState],
//! #     quotas: Quotas { concurrent_runs: 2, requests_per_minute: 60, tokens_per_day: 8_000 },
//! #     credential_revision: Revision::FIRST,
//! #     supported_range: ProtocolRange::new(ProtocolVersion::new(1), ProtocolVersion::new(2))
//! #         .unwrap(),
//! # }).unwrap();
//! # let id = CanonicalId::new(CanonicalKind::Work, "w-1").unwrap();
//! # let work = CanonicalWork::new(id, "ship the adapter", Revision::FIRST).unwrap();
//! # let projection = Projection::of(&binding, &work).unwrap();
//! let projected = projection.project(ProtocolSemantic::FileDiff, "1 file changed").unwrap();
//! assert!(matches!(projected, ProjectedSemantic::Degraded(_)));
//! ```
//!
//! ```compile_fail
//! # use automonique_protocol::identity::Actor;
//! # use automonique_protocol::primitives::Revision;
//! # use automonique_protocol::protocols::*;
//! # let binding = ClientBinding::bind(ClientBindingParts {
//! #     dialect: ProtocolDialect::McpExport,
//! #     client_id: "mcp-1",
//! #     actor: Actor::new("acme", "svc-1").unwrap(),
//! #     scopes: &[Scope::ReadCanonicalState],
//! #     quotas: Quotas { concurrent_runs: 2, requests_per_minute: 60, tokens_per_day: 8_000 },
//! #     credential_revision: Revision::FIRST,
//! #     supported_range: ProtocolRange::new(ProtocolVersion::new(1), ProtocolVersion::new(2))
//! #         .unwrap(),
//! # }).unwrap();
//! # let id = CanonicalId::new(CanonicalKind::Work, "w-1").unwrap();
//! # let work = CanonicalWork::new(id, "ship the adapter", Revision::FIRST).unwrap();
//! # let projection = Projection::of(&binding, &work).unwrap();
//! let projected = projection.project(ProtocolSemantic::FileDiff, "1 file changed").unwrap();
//! // There is no outcome meaning "the field was dropped".
//! assert!(matches!(projected, ProjectedSemantic::Omitted));
//! ```
//!
//! A client outside a binding's declared protocol range is admitted read-only.
//! Planning a mutation needs a [`MutationAuthority`], which only the in-range
//! branch produces, so the incompatible client is not merely refused at the
//! door — it has nothing to knock with:
//!
//! ```
//! # use automonique_protocol::identity::Actor;
//! # use automonique_protocol::primitives::Revision;
//! # use automonique_protocol::protocols::*;
//! # let binding = ClientBinding::bind(ClientBindingParts {
//! #     dialect: ProtocolDialect::Acp,
//! #     client_id: "zed-1",
//! #     actor: Actor::new("acme", "svc-1").unwrap(),
//! #     scopes: &[Scope::ReadCanonicalState, Scope::WriteTurn],
//! #     quotas: Quotas { concurrent_runs: 2, requests_per_minute: 60, tokens_per_day: 8_000 },
//! #     credential_revision: Revision::FIRST,
//! #     supported_range: ProtocolRange::new(ProtocolVersion::new(1), ProtocolVersion::new(2))
//! #         .unwrap(),
//! # }).unwrap();
//! # let id = CanonicalId::new(CanonicalKind::Work, "w-1").unwrap();
//! # let work = CanonicalWork::new(id.clone(), "ship the adapter", Revision::FIRST).unwrap();
//! # let projection = Projection::of(&binding, &work).unwrap();
//! # let request = ExternalRequest {
//! #     operation: ExternalOperation::SendPrompt,
//! #     target: id,
//! #     idempotency_key: "key-1",
//! #     expected_revision: Revision::FIRST,
//! #     claim: None,
//! # };
//! let Admission::Mutating(authority) = projection.admit(ProtocolVersion::new(2)) else {
//!     panic!("version 2 is inside the declared range");
//! };
//! assert!(authority.plan(&request).is_ok());
//! ```
//!
//! ```compile_fail
//! # use automonique_protocol::identity::Actor;
//! # use automonique_protocol::primitives::Revision;
//! # use automonique_protocol::protocols::*;
//! # let binding = ClientBinding::bind(ClientBindingParts {
//! #     dialect: ProtocolDialect::Acp,
//! #     client_id: "zed-1",
//! #     actor: Actor::new("acme", "svc-1").unwrap(),
//! #     scopes: &[Scope::ReadCanonicalState, Scope::WriteTurn],
//! #     quotas: Quotas { concurrent_runs: 2, requests_per_minute: 60, tokens_per_day: 8_000 },
//! #     credential_revision: Revision::FIRST,
//! #     supported_range: ProtocolRange::new(ProtocolVersion::new(1), ProtocolVersion::new(2))
//! #         .unwrap(),
//! # }).unwrap();
//! # let id = CanonicalId::new(CanonicalKind::Work, "w-1").unwrap();
//! # let work = CanonicalWork::new(id.clone(), "ship the adapter", Revision::FIRST).unwrap();
//! # let projection = Projection::of(&binding, &work).unwrap();
//! # let request = ExternalRequest {
//! #     operation: ExternalOperation::SendPrompt,
//! #     target: id,
//! #     idempotency_key: "key-1",
//! #     expected_revision: Revision::FIRST,
//! #     claim: None,
//! # };
//! let Admission::ReadOnly(client) = projection.admit(ProtocolVersion::new(9)) else {
//!     panic!("version 9 is outside the declared range");
//! };
//! assert!(client.plan(&request).is_ok());
//! ```
//!
//! This module defines the mapping. It serves no endpoint, terminates no wire
//! format, opens no connection, issues no token and reads no clock. Where a
//! type names a canonical location it is a reference, never a request.

use core::fmt;
use std::error::Error;

use crate::identity::Actor;
use crate::journal::{ActionLedger, ActionOutcome, ActionReceipt, JournalError};
use crate::primitives::{Revision, ValueError};

/// Maximum UTF-8 byte length of a protocol field.
pub const MAX_PROTOCOL_FIELD_BYTES: usize = 256;

/// Maximum UTF-8 byte length of a degraded rendering.
pub const MAX_DEGRADED_RENDERING_BYTES: usize = 512;

/// Why a protocol binding, mapping or projection was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// A binding was offered no scopes.
    ///
    /// A caller with no scope is not an ordinary scoped actor, so it is not a
    /// binding at all.
    EmptyScopeSet,
    /// The binding does not carry the scope the canonical action requires.
    ///
    /// Names the action and the scope, because there is no wildcard scope to
    /// look for instead.
    ScopeNotGranted {
        /// The canonical action that was planned.
        action: &'static str,
        /// The scope it requires.
        scope: &'static str,
    },
    /// One external identifier was offered a second canonical identity.
    ExternalIdentityAlreadyMapped {
        /// The external identifier.
        external: String,
        /// The canonical identity it already resolves to.
        mapped_to: String,
        /// The canonical identity offered.
        offered: String,
    },
    /// A second external identifier claimed one canonical identity.
    ///
    /// Returned rather than accepted, because collapsing two identifiers onto
    /// one identity silently is how a mapping stops being injective. An
    /// [`AliasRecord`] is the explicit way to do it.
    CanonicalIdentityAlreadyClaimed {
        /// The canonical identity.
        canonical: String,
        /// The external identifier already mapped to it.
        claimed_by: String,
        /// The external identifier offered.
        offered: String,
    },
    /// An aliasing record named a primary that is not mapped.
    AliasPrimaryUnmapped {
        /// The unmapped primary.
        primary: String,
    },
    /// An external identifier resolves to no canonical identity.
    ExternalIdentifierUnmapped {
        /// The unmapped identifier.
        external: String,
    },
    /// The dialect cannot represent the semantic, even as bounded text.
    ///
    /// Returned rather than dropping the field.
    UnsupportedSemantic {
        /// The dialect.
        dialect: &'static str,
        /// The semantic it cannot represent.
        semantic: &'static str,
    },
    /// A client outside the declared protocol range attempted a mutation.
    MutationOutsideProtocolRange {
        /// The canonical action it attempted.
        action: &'static str,
        /// Lowest supported protocol version.
        declared_min: u32,
        /// Highest supported protocol version.
        declared_max: u32,
        /// The version the client declared.
        client: u32,
    },
    /// A remote agent's assertion was offered as authorization.
    RemoteClaimCarriesNoAuthority {
        /// The asserting peer.
        peer: String,
    },
    /// A protocol range ended before it began.
    InvertedProtocolRange {
        /// Lowest version offered.
        min: u32,
        /// Highest version offered.
        max: u32,
    },
    /// The canonical action ledger refused the effect.
    Action(JournalError),
    /// A bounded field was rejected.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
}

impl ProtocolError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::EmptyScopeSet => "empty_scope_set",
            Self::ScopeNotGranted { .. } => "scope_not_granted",
            Self::ExternalIdentityAlreadyMapped { .. } => "external_identity_already_mapped",
            Self::CanonicalIdentityAlreadyClaimed { .. } => "canonical_identity_already_claimed",
            Self::AliasPrimaryUnmapped { .. } => "alias_primary_unmapped",
            Self::ExternalIdentifierUnmapped { .. } => "external_identifier_unmapped",
            Self::UnsupportedSemantic { .. } => "unsupported_semantic",
            Self::MutationOutsideProtocolRange { .. } => "mutation_outside_protocol_range",
            Self::RemoteClaimCarriesNoAuthority { .. } => "remote_claim_carries_no_authority",
            Self::InvertedProtocolRange { .. } => "inverted_protocol_range",
            Self::Action(error) => error.category(),
            Self::Field { .. } => "field_invalid",
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyScopeSet => {
                formatter.write_str("a protocol client binding must carry at least one scope")
            }
            Self::ScopeNotGranted { action, scope } => write!(
                formatter,
                "action {action} requires scope {scope}, which the binding does not carry"
            ),
            Self::ExternalIdentityAlreadyMapped {
                external,
                mapped_to,
                offered,
            } => write!(
                formatter,
                "external identifier {external} already resolves to {mapped_to} and cannot \
                 also resolve to {offered}"
            ),
            Self::CanonicalIdentityAlreadyClaimed {
                canonical,
                claimed_by,
                offered,
            } => write!(
                formatter,
                "canonical identity {canonical} is already reached by {claimed_by}; {offered} \
                 needs an explicit aliasing record"
            ),
            Self::AliasPrimaryUnmapped { primary } => write!(
                formatter,
                "aliasing record names primary {primary}, which resolves to nothing"
            ),
            Self::ExternalIdentifierUnmapped { external } => write!(
                formatter,
                "external identifier {external} resolves to no canonical identity"
            ),
            Self::UnsupportedSemantic { dialect, semantic } => write!(
                formatter,
                "dialect {dialect} cannot represent {semantic}; it is reported, not dropped"
            ),
            Self::MutationOutsideProtocolRange {
                action,
                declared_min,
                declared_max,
                client,
            } => write!(
                formatter,
                "client protocol {client} is outside the declared range \
                 {declared_min}..={declared_max}; {action} fails closed and the client stays \
                 read-only"
            ),
            Self::RemoteClaimCarriesNoAuthority { peer } => write!(
                formatter,
                "peer {peer} asserted an authorization; only a resolved tenant actor carries one"
            ),
            Self::InvertedProtocolRange { min, max } => {
                write!(formatter, "protocol range {min}..={max} is inverted")
            }
            Self::Action(error) => error.fmt(formatter),
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
        }
    }
}

impl Error for ProtocolError {}

/// A public protocol this deployment speaks.
///
/// The native Runs API is one of them so that "degrade honestly" has a
/// reference point: it is the dialect nothing degrades in.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProtocolDialect {
    /// Agent Client Protocol, spoken to an editor host.
    Acp,
    /// The OpenAI-compatible HTTP API.
    OpenAiCompatible,
    /// The Automonique-native Runs API.
    NativeRuns,
    /// The scoped Model Context Protocol export.
    McpExport,
    /// The Agent-to-Agent adapter.
    A2a,
    /// The relay protocol for independently hosted clients.
    Relay,
}

impl ProtocolDialect {
    /// Every dialect, for coverage checks.
    pub const ALL: [Self; 6] = [
        Self::Acp,
        Self::OpenAiCompatible,
        Self::NativeRuns,
        Self::McpExport,
        Self::A2a,
        Self::Relay,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Acp => "acp",
            Self::OpenAiCompatible => "openai_compatible",
            Self::NativeRuns => "native_runs",
            Self::McpExport => "mcp_export",
            Self::A2a => "a2a",
            Self::Relay => "relay",
        }
    }

    /// Whether this dialect is the canonical surface rather than a projection.
    #[must_use]
    pub const fn is_native(self) -> bool {
        matches!(self, Self::NativeRuns)
    }

    /// What this dialect declares about one semantic.
    ///
    /// Total over both enums: every pair has a declared answer, so a semantic
    /// cannot be undeclared and therefore cannot be quietly skipped.
    #[must_use]
    pub const fn support(self, semantic: ProtocolSemantic) -> SemanticSupport {
        use ProtocolSemantic as Semantic;
        use SemanticSupport::{BoundedText, Native, Unsupported};

        match self {
            Self::NativeRuns => Native,
            Self::Acp => match semantic {
                Semantic::StreamingText
                | Semantic::ThoughtSummary
                | Semantic::ToolActivity
                | Semantic::FileDiff
                | Semantic::TerminalEvent
                | Semantic::ModelSelection
                | Semantic::ApprovalPrompt
                | Semantic::CursorResumption => Native,
                Semantic::WorkGraph => BoundedText,
                Semantic::ExactRevision => Unsupported,
            },
            Self::OpenAiCompatible => match semantic {
                Semantic::StreamingText
                | Semantic::ToolActivity
                | Semantic::ModelSelection
                | Semantic::ApprovalPrompt
                | Semantic::CursorResumption => Native,
                Semantic::ThoughtSummary | Semantic::FileDiff | Semantic::TerminalEvent => {
                    BoundedText
                }
                Semantic::ExactRevision | Semantic::WorkGraph => Unsupported,
            },
            Self::McpExport => match semantic {
                Semantic::ToolActivity | Semantic::ApprovalPrompt => Native,
                Semantic::StreamingText | Semantic::FileDiff | Semantic::TerminalEvent => {
                    BoundedText
                }
                Semantic::ThoughtSummary
                | Semantic::ModelSelection
                | Semantic::CursorResumption
                | Semantic::ExactRevision
                | Semantic::WorkGraph => Unsupported,
            },
            Self::A2a => match semantic {
                Semantic::StreamingText | Semantic::CursorResumption => Native,
                Semantic::ThoughtSummary
                | Semantic::ToolActivity
                | Semantic::FileDiff
                | Semantic::WorkGraph => BoundedText,
                Semantic::TerminalEvent
                | Semantic::ModelSelection
                | Semantic::ApprovalPrompt
                | Semantic::ExactRevision => Unsupported,
            },
            Self::Relay => match semantic {
                Semantic::StreamingText
                | Semantic::ToolActivity
                | Semantic::FileDiff
                | Semantic::TerminalEvent
                | Semantic::ModelSelection
                | Semantic::ApprovalPrompt
                | Semantic::CursorResumption
                | Semantic::ExactRevision => Native,
                Semantic::ThoughtSummary | Semantic::WorkGraph => BoundedText,
            },
        }
    }

    /// The declared capability table for this dialect.
    ///
    /// One row per semantic, in declaration order, so a reviewer reads the
    /// table rather than spot-checking calls.
    #[must_use]
    pub fn capability_table(self) -> Vec<(ProtocolSemantic, SemanticSupport)> {
        ProtocolSemantic::ALL
            .iter()
            .map(|semantic| (*semantic, self.support(*semantic)))
            .collect()
    }
}

/// A semantic the canonical domain can express.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProtocolSemantic {
    /// Incrementally streamed assistant text.
    StreamingText,
    /// A summary of model reasoning, where policy allows one.
    ThoughtSummary,
    /// Structured tool call progress.
    ToolActivity,
    /// A structured file diff.
    FileDiff,
    /// A terminal lifecycle or output event.
    TerminalEvent,
    /// Explicit provider and model selection.
    ModelSelection,
    /// A provider or tool approval prompt.
    ApprovalPrompt,
    /// Resumption from a durable event cursor.
    CursorResumption,
    /// An exact aggregate revision.
    ExactRevision,
    /// The work graph, with its dependencies.
    WorkGraph,
}

impl ProtocolSemantic {
    /// Every semantic, for coverage checks.
    pub const ALL: [Self; 10] = [
        Self::StreamingText,
        Self::ThoughtSummary,
        Self::ToolActivity,
        Self::FileDiff,
        Self::TerminalEvent,
        Self::ModelSelection,
        Self::ApprovalPrompt,
        Self::CursorResumption,
        Self::ExactRevision,
        Self::WorkGraph,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StreamingText => "streaming_text",
            Self::ThoughtSummary => "thought_summary",
            Self::ToolActivity => "tool_activity",
            Self::FileDiff => "file_diff",
            Self::TerminalEvent => "terminal_event",
            Self::ModelSelection => "model_selection",
            Self::ApprovalPrompt => "approval_prompt",
            Self::CursorResumption => "cursor_resumption",
            Self::ExactRevision => "exact_revision",
            Self::WorkGraph => "work_graph",
        }
    }
}

/// What a dialect declares about one semantic.
///
/// There is deliberately no `Dropped` variant: an unsupported field is
/// reported, never omitted.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SemanticSupport {
    /// Represented directly.
    Native,
    /// Not representable directly; rendered as bounded text beside a link to
    /// the authoritative record.
    BoundedText,
    /// Not representable at all; a typed error is returned.
    Unsupported,
}

impl SemanticSupport {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::BoundedText => "bounded_text",
            Self::Unsupported => "unsupported",
        }
    }
}

/// One authority a binding may carry.
///
/// A closed set with no wildcard. Every canonical action names the one scope it
/// needs, so there is no scope that grants the others.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Scope {
    /// Read canonical work, run and turn state.
    ReadCanonicalState,
    /// Create canonical work.
    WriteWork,
    /// Start a run.
    StartRun,
    /// Append a turn.
    WriteTurn,
    /// Cancel a run.
    CancelRun,
    /// Answer a provider or tool approval.
    RespondToApproval,
    /// Invoke a tool.
    InvokeTool,
}

impl Scope {
    /// Every scope, for coverage checks.
    pub const ALL: [Self; 7] = [
        Self::ReadCanonicalState,
        Self::WriteWork,
        Self::StartRun,
        Self::WriteTurn,
        Self::CancelRun,
        Self::RespondToApproval,
        Self::InvokeTool,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadCanonicalState => "read_canonical_state",
            Self::WriteWork => "write_work",
            Self::StartRun => "start_run",
            Self::WriteTurn => "write_turn",
            Self::CancelRun => "cancel_run",
            Self::RespondToApproval => "respond_to_approval",
            Self::InvokeTool => "invoke_tool",
        }
    }
}

/// The ceilings a binding is held to.
///
/// Every field is required, so a binding cannot be quota-free.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Quotas {
    /// Concurrent runs the client may hold.
    pub concurrent_runs: u32,
    /// Requests the client may issue per minute.
    pub requests_per_minute: u32,
    /// Model tokens the client may spend per day.
    pub tokens_per_day: u64,
}

/// A major protocol version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion(u32);

impl ProtocolVersion {
    /// Name a version.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// The version as a primitive.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// The inclusive protocol range one binding supports.
///
/// Adjacent releases coexist by declaring overlapping ranges; a client outside
/// a range is admitted read-only rather than served a mismatched dialect.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProtocolRange {
    min: ProtocolVersion,
    max: ProtocolVersion,
}

impl ProtocolRange {
    /// Declare an inclusive range.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvertedProtocolRange`] when the range ends
    /// before it begins.
    pub const fn new(min: ProtocolVersion, max: ProtocolVersion) -> Result<Self, ProtocolError> {
        if min.get() > max.get() {
            return Err(ProtocolError::InvertedProtocolRange {
                min: min.get(),
                max: max.get(),
            });
        }
        Ok(Self { min, max })
    }

    /// Lowest supported version.
    #[must_use]
    pub const fn min(self) -> ProtocolVersion {
        self.min
    }

    /// Highest supported version.
    #[must_use]
    pub const fn max(self) -> ProtocolVersion {
        self.max
    }

    /// Whether a client version is inside the range.
    #[must_use]
    pub const fn admits(self, client: ProtocolVersion) -> bool {
        client.get() >= self.min.get() && client.get() <= self.max.get()
    }
}

impl fmt::Display for ProtocolRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}..={}", self.min, self.max)
    }
}

/// Every field a [`ClientBinding`] needs, named at the call site.
///
/// A struct rather than a positional argument list, so that a missing tenant
/// actor, scope set, quota or credential revision is a compile error naming the
/// field rather than a value that has to be checked for later.
#[derive(Clone, Debug)]
pub struct ClientBindingParts<'a> {
    /// The dialect the client speaks.
    pub dialect: ProtocolDialect,
    /// The client's stable identifier within the dialect.
    pub client_id: &'a str,
    /// The tenant actor the client resolves to.
    pub actor: Actor,
    /// The scopes the binding grants.
    pub scopes: &'a [Scope],
    /// The ceilings the binding is held to.
    pub quotas: Quotas,
    /// The revision of the credential that authenticated the client.
    pub credential_revision: Revision,
    /// The protocol range this binding supports.
    pub supported_range: ProtocolRange,
}

/// One authenticated external caller, resolved to a tenant actor.
///
/// Every external caller reaches the domain through one of these, so an ACP
/// host, an OpenAI client, an MCP consumer, an A2A peer and a relay client are
/// all ordinary scoped actors rather than privileged transports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientBinding {
    dialect: ProtocolDialect,
    client_id: String,
    actor: Actor,
    scopes: Vec<Scope>,
    quotas: Quotas,
    credential_revision: Revision,
    supported_range: ProtocolRange,
}

impl ClientBinding {
    /// Bind an authenticated client to a tenant actor.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::EmptyScopeSet`] when no scope is granted, and
    /// [`ProtocolError::Field`] for an invalid client identifier. There is no
    /// constructor omitting the actor, so a tenant-free binding is not a
    /// refusal this function can return.
    pub fn bind(parts: ClientBindingParts<'_>) -> Result<Self, ProtocolError> {
        bounded(parts.client_id, "client_id")?;
        if parts.scopes.is_empty() {
            return Err(ProtocolError::EmptyScopeSet);
        }
        let mut scopes = parts.scopes.to_vec();
        scopes.sort_unstable();
        scopes.dedup();
        Ok(Self {
            dialect: parts.dialect,
            client_id: parts.client_id.to_owned(),
            actor: parts.actor,
            scopes,
            quotas: parts.quotas,
            credential_revision: parts.credential_revision,
            supported_range: parts.supported_range,
        })
    }

    /// The dialect the client speaks.
    #[must_use]
    pub const fn dialect(&self) -> ProtocolDialect {
        self.dialect
    }

    /// The client identifier.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The tenant actor the client resolves to.
    ///
    /// This is the only authority in the type. A remote peer's assertion is not
    /// a second source of one.
    #[must_use]
    pub const fn actor(&self) -> &Actor {
        &self.actor
    }

    /// The granted scopes, sorted and deduplicated.
    #[must_use]
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// The ceilings the binding is held to.
    #[must_use]
    pub const fn quotas(&self) -> Quotas {
        self.quotas
    }

    /// The credential revision that authenticated the client.
    #[must_use]
    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    /// The protocol range this binding supports.
    #[must_use]
    pub const fn supported_range(&self) -> ProtocolRange {
        self.supported_range
    }

    /// Whether the binding carries a scope.
    #[must_use]
    pub fn grants(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }
}

/// What kind of canonical identity an identifier names.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CanonicalKind {
    /// A unit of durable work.
    Work,
    /// One run of that work.
    Run,
    /// One turn within a run.
    Turn,
}

impl CanonicalKind {
    /// Every kind, for coverage checks.
    pub const ALL: [Self; 3] = [Self::Work, Self::Run, Self::Turn];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Work => "work",
            Self::Run => "run",
            Self::Turn => "turn",
        }
    }
}

/// A canonical work, run or turn identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CanonicalId {
    kind: CanonicalKind,
    id: String,
}

impl CanonicalId {
    /// Name a canonical identity.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Field`] for an invalid identifier.
    pub fn new(kind: CanonicalKind, id: &str) -> Result<Self, ProtocolError> {
        bounded(id, "canonical_id")?;
        Ok(Self {
            kind,
            id: id.to_owned(),
        })
    }

    /// The kind of identity.
    #[must_use]
    pub const fn kind(&self) -> CanonicalKind {
        self.kind
    }

    /// The identifier within its kind.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The stable key spelling, kind included.
    ///
    /// A work and a run that share a spelling are different identities, and the
    /// key says so.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}/{}", self.kind.as_str(), self.id)
    }
}

/// An identifier minted by an external protocol.
///
/// Scoped by dialect and client, because two hosts may legitimately use the
/// same session identifier for unrelated work. Injectivity is a property of one
/// dialect and one client, not of the string.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ExternalRef {
    dialect: ProtocolDialect,
    client_id: String,
    external_id: String,
}

impl ExternalRef {
    /// Name an external identifier within a dialect and client.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Field`] for an invalid component.
    pub fn new(
        dialect: ProtocolDialect,
        client_id: &str,
        external_id: &str,
    ) -> Result<Self, ProtocolError> {
        bounded(client_id, "client_id")?;
        bounded(external_id, "external_id")?;
        Ok(Self {
            dialect,
            client_id: client_id.to_owned(),
            external_id: external_id.to_owned(),
        })
    }

    /// The dialect that minted it.
    #[must_use]
    pub const fn dialect(&self) -> ProtocolDialect {
        self.dialect
    }

    /// The client that minted it.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The external identifier itself.
    #[must_use]
    pub fn external_id(&self) -> &str {
        &self.external_id
    }

    /// The stable key spelling, dialect and client included.
    #[must_use]
    pub fn key(&self) -> String {
        format!(
            "{}/{}/{}",
            self.dialect.as_str(),
            self.client_id,
            self.external_id
        )
    }
}

/// The explicit record that lets a second external identifier reach one
/// canonical identity.
///
/// Carries who recorded it and why, so an aliasing decision cannot be silent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliasRecord {
    primary: ExternalRef,
    alias: ExternalRef,
    recorded_by: Actor,
    reason: String,
}

impl AliasRecord {
    /// Record an alias.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Field`] for an invalid reason.
    pub fn new(
        primary: ExternalRef,
        alias: ExternalRef,
        recorded_by: Actor,
        reason: &str,
    ) -> Result<Self, ProtocolError> {
        bounded(reason, "alias_reason")?;
        Ok(Self {
            primary,
            alias,
            recorded_by,
            reason: reason.to_owned(),
        })
    }

    /// The identifier already mapped.
    #[must_use]
    pub const fn primary(&self) -> &ExternalRef {
        &self.primary
    }

    /// The identifier being pointed at the same canonical identity.
    #[must_use]
    pub const fn alias(&self) -> &ExternalRef {
        &self.alias
    }

    /// Who recorded the alias.
    #[must_use]
    pub const fn recorded_by(&self) -> &Actor {
        &self.recorded_by
    }

    /// Why.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// External identifiers projected onto canonical identities.
///
/// Injective per dialect and per client in both directions: one external
/// identifier never resolves to two canonical identities, and two external
/// identifiers reach one canonical identity only through [`AliasRecord`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IdentityMap {
    entries: Vec<(ExternalRef, CanonicalId)>,
    aliases: Vec<AliasRecord>,
}

impl IdentityMap {
    /// Start an empty map.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            aliases: Vec::new(),
        }
    }

    /// Map an external identifier onto a canonical identity.
    ///
    /// Rebinding the same pair is idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::ExternalIdentityAlreadyMapped`] when the
    /// identifier already resolves elsewhere, and
    /// [`ProtocolError::CanonicalIdentityAlreadyClaimed`] when another
    /// identifier of the same dialect and client already reaches the canonical
    /// identity. The second refusal is what [`IdentityMap::alias`] exists to
    /// answer explicitly.
    pub fn bind(
        &mut self,
        external: ExternalRef,
        canonical: CanonicalId,
    ) -> Result<(), ProtocolError> {
        if let Some((_, mapped)) = self
            .entries
            .iter()
            .find(|(reference, _)| reference == &external)
        {
            if mapped == &canonical {
                return Ok(());
            }
            return Err(ProtocolError::ExternalIdentityAlreadyMapped {
                external: external.key(),
                mapped_to: mapped.key(),
                offered: canonical.key(),
            });
        }
        if let Some((claimer, _)) = self.entries.iter().find(|(reference, mapped)| {
            mapped == &canonical
                && reference.dialect == external.dialect
                && reference.client_id == external.client_id
        }) {
            return Err(ProtocolError::CanonicalIdentityAlreadyClaimed {
                canonical: canonical.key(),
                claimed_by: claimer.key(),
                offered: external.key(),
            });
        }
        self.entries.push((external, canonical));
        Ok(())
    }

    /// Point a second external identifier at one canonical identity.
    ///
    /// The only way two identifiers of one dialect and client reach one
    /// identity, and it costs an [`AliasRecord`] naming an actor and a reason.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::AliasPrimaryUnmapped`] when the primary
    /// resolves to nothing, and
    /// [`ProtocolError::ExternalIdentityAlreadyMapped`] when the alias already
    /// resolves elsewhere.
    pub fn alias(&mut self, record: AliasRecord) -> Result<(), ProtocolError> {
        let Some(canonical) = self.resolve(record.primary()).cloned() else {
            return Err(ProtocolError::AliasPrimaryUnmapped {
                primary: record.primary().key(),
            });
        };
        let existing = self
            .entries
            .iter()
            .find(|(reference, _)| reference == record.alias())
            .map(|(_, mapped)| mapped.clone());
        match existing {
            Some(mapped) if mapped == canonical => {}
            Some(mapped) => {
                return Err(ProtocolError::ExternalIdentityAlreadyMapped {
                    external: record.alias().key(),
                    mapped_to: mapped.key(),
                    offered: canonical.key(),
                });
            }
            None => self.entries.push((record.alias().clone(), canonical)),
        }
        self.aliases.push(record);
        Ok(())
    }

    /// Resolve an external identifier.
    #[must_use]
    pub fn resolve(&self, external: &ExternalRef) -> Option<&CanonicalId> {
        self.entries
            .iter()
            .find(|(reference, _)| reference == external)
            .map(|(_, canonical)| canonical)
    }

    /// Resolve an external identifier or refuse.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::ExternalIdentifierUnmapped`]. There is no
    /// fallback that invents a canonical identity for an unknown identifier.
    pub fn resolve_or_refuse(&self, external: &ExternalRef) -> Result<&CanonicalId, ProtocolError> {
        self.resolve(external)
            .ok_or_else(|| ProtocolError::ExternalIdentifierUnmapped {
                external: external.key(),
            })
    }

    /// Every external identifier that reaches one canonical identity.
    #[must_use]
    pub fn external_refs_for(&self, canonical: &CanonicalId) -> Vec<&ExternalRef> {
        self.entries
            .iter()
            .filter(|(_, mapped)| mapped == canonical)
            .map(|(reference, _)| reference)
            .collect()
    }

    /// Every recorded alias, for evidence.
    #[must_use]
    pub fn alias_records(&self) -> &[AliasRecord] {
        &self.aliases
    }
}

/// A canonical domain action.
///
/// A closed set. A compatibility projection maps an external operation onto one
/// of these and has no way to name anything else, which is what stops a
/// projection from inventing an effect.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CanonicalActionKind {
    /// Create durable work.
    CreateWork,
    /// Start a run of existing work.
    StartRun,
    /// Append a turn to a run.
    AppendTurn,
    /// Cancel a run.
    CancelRun,
    /// Answer a provider or tool approval.
    RespondToApproval,
    /// Invoke a tool.
    InvokeTool,
}

impl CanonicalActionKind {
    /// Every action, for coverage checks.
    pub const ALL: [Self; 6] = [
        Self::CreateWork,
        Self::StartRun,
        Self::AppendTurn,
        Self::CancelRun,
        Self::RespondToApproval,
        Self::InvokeTool,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateWork => "create_work",
            Self::StartRun => "start_run",
            Self::AppendTurn => "append_turn",
            Self::CancelRun => "cancel_run",
            Self::RespondToApproval => "respond_to_approval",
            Self::InvokeTool => "invoke_tool",
        }
    }

    /// The one scope this action requires.
    #[must_use]
    pub const fn required_scope(self) -> Scope {
        match self {
            Self::CreateWork => Scope::WriteWork,
            Self::StartRun => Scope::StartRun,
            Self::AppendTurn => Scope::WriteTurn,
            Self::CancelRun => Scope::CancelRun,
            Self::RespondToApproval => Scope::RespondToApproval,
            Self::InvokeTool => Scope::InvokeTool,
        }
    }
}

/// An operation a compatibility protocol offers.
///
/// Several operations may name one canonical action — an ACP cancel and an
/// OpenAI stop are the same effect — but no operation names two.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExternalOperation {
    /// Open a session.
    OpenSession,
    /// Send a prompt.
    SendPrompt,
    /// Cancel the current prompt.
    CancelPrompt,
    /// Answer a permission request.
    RespondToPermission,
    /// Call a tool.
    CallTool,
    /// Create a run.
    CreateRun,
    /// Stop a run.
    StopRun,
}

impl ExternalOperation {
    /// Every operation, for coverage checks.
    pub const ALL: [Self; 7] = [
        Self::OpenSession,
        Self::SendPrompt,
        Self::CancelPrompt,
        Self::RespondToPermission,
        Self::CallTool,
        Self::CreateRun,
        Self::StopRun,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenSession => "open_session",
            Self::SendPrompt => "send_prompt",
            Self::CancelPrompt => "cancel_prompt",
            Self::RespondToPermission => "respond_to_permission",
            Self::CallTool => "call_tool",
            Self::CreateRun => "create_run",
            Self::StopRun => "stop_run",
        }
    }

    /// The one canonical action this operation reaches.
    ///
    /// Total and single-valued: there is no operation without a canonical
    /// action, and no operation with two.
    #[must_use]
    pub const fn canonical_action(self) -> CanonicalActionKind {
        match self {
            Self::OpenSession => CanonicalActionKind::CreateWork,
            Self::SendPrompt => CanonicalActionKind::AppendTurn,
            Self::CancelPrompt | Self::StopRun => CanonicalActionKind::CancelRun,
            Self::RespondToPermission => CanonicalActionKind::RespondToApproval,
            Self::CallTool => CanonicalActionKind::InvokeTool,
            Self::CreateRun => CanonicalActionKind::StartRun,
        }
    }
}

/// What a remote agent asserted about authorization.
///
/// Every field is text. There is no accessor returning an [`Actor`], a
/// [`Scope`] or an approval, so an A2A or relay peer cannot hand the binding an
/// authority it did not already have.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteAgentClaim {
    peer: String,
    asserted_actor: String,
    asserted_scope: String,
}

impl RemoteAgentClaim {
    /// Record what a peer asserted.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Field`] for an invalid component.
    pub fn new(
        peer: &str,
        asserted_actor: &str,
        asserted_scope: &str,
    ) -> Result<Self, ProtocolError> {
        bounded(peer, "peer")?;
        bounded(asserted_actor, "asserted_actor")?;
        bounded(asserted_scope, "asserted_scope")?;
        Ok(Self {
            peer: peer.to_owned(),
            asserted_actor: asserted_actor.to_owned(),
            asserted_scope: asserted_scope.to_owned(),
        })
    }

    /// The asserting peer.
    #[must_use]
    pub fn peer(&self) -> &str {
        &self.peer
    }

    /// The principal the peer named, as text.
    #[must_use]
    pub fn asserted_actor(&self) -> &str {
        &self.asserted_actor
    }

    /// The scope the peer named, as text.
    #[must_use]
    pub fn asserted_scope(&self) -> &str {
        &self.asserted_scope
    }

    /// Refuse an attempt to treat the claim as a principal.
    ///
    /// # Errors
    ///
    /// Always returns [`ProtocolError::RemoteClaimCarriesNoAuthority`]. It
    /// exists so a caller reaching for the wrong thing gets a named refusal
    /// rather than a missing method.
    pub fn resolve_actor(&self) -> Result<Actor, ProtocolError> {
        Err(ProtocolError::RemoteClaimCarriesNoAuthority {
            peer: self.peer.clone(),
        })
    }
}

/// One request arriving over a compatibility protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalRequest<'a> {
    /// The operation the client invoked.
    pub operation: ExternalOperation,
    /// The canonical identity it targets, already resolved through an
    /// [`IdentityMap`].
    pub target: CanonicalId,
    /// The client's idempotency key.
    pub idempotency_key: &'a str,
    /// The revision the client expects the target to be at.
    pub expected_revision: Revision,
    /// What a remote peer asserted, if anything. It is carried for the record
    /// and consulted by nothing.
    pub claim: Option<RemoteAgentClaim>,
}

/// One canonical action, ready to be recorded.
///
/// Carries its idempotency key and expected revision as required fields, so a
/// protocol-reachable effect without either is unrepresentable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalActionPlan {
    kind: CanonicalActionKind,
    dialect: ProtocolDialect,
    actor: Actor,
    target: CanonicalId,
    idempotency_key: String,
    expected_revision: Revision,
}

impl CanonicalActionPlan {
    /// The canonical action.
    #[must_use]
    pub const fn kind(&self) -> CanonicalActionKind {
        self.kind
    }

    /// The dialect the request arrived over.
    #[must_use]
    pub const fn dialect(&self) -> ProtocolDialect {
        self.dialect
    }

    /// The tenant actor the effect is attributed to.
    ///
    /// Always the binding's actor.
    #[must_use]
    pub const fn actor(&self) -> &Actor {
        &self.actor
    }

    /// The canonical identity the effect targets.
    #[must_use]
    pub const fn target(&self) -> &CanonicalId {
        &self.target
    }

    /// The idempotency key.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// The expected revision.
    #[must_use]
    pub const fn expected_revision(&self) -> Revision {
        self.expected_revision
    }

    /// The stable action identity.
    #[must_use]
    pub fn action_id(&self) -> String {
        format!("{}/{}", self.dialect.as_str(), self.kind.as_str())
    }

    /// The idempotency key as the canonical ledger sees it.
    ///
    /// The caller's key is namespaced by the acting tenant, the actor and the
    /// canonical action. Without that, one key means different things to
    /// different callers: two tenants that happened to choose the same key
    /// would collide, and the second would receive the first's receipt as
    /// though its own request had already been applied. Scoping also keeps two
    /// different canonical actions on one target from collapsing into one
    /// receipt, which would drop the second effect while reporting success.
    ///
    /// The tenant, the actor and the caller's key are bounded text, and bounded
    /// text may contain the separator. Each is therefore escaped, so the
    /// components can be read back one way only. Joined raw, the tenant `a`
    /// with actor `b/c` and the tenant `a/b` with actor `c` — two actors in two
    /// different tenants — spell one ledger key, which is the collision this
    /// scoping exists to prevent. The dialect and action spellings come from
    /// closed sets that contain no separator, so they are already unambiguous.
    /// A component carrying no separator is emitted unchanged.
    #[must_use]
    pub fn scoped_idempotency_key(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            escaped(self.actor.tenant()),
            escaped(self.actor.id()),
            self.action_id(),
            escaped(&self.idempotency_key)
        )
    }
}

/// Record a planned canonical action.
///
/// The plan is the only thing a compatibility projection produces, and this is
/// the only thing that turns one into an effect: the same canonical ledger the
/// native surface uses. Replaying a key returns the receipt already recorded
/// rather than issuing a second effect.
///
/// # Errors
///
/// Returns [`ProtocolError::Action`] when the ledger refuses — notably when one
/// idempotency key is reused for a different target.
pub fn commit(
    plan: &CanonicalActionPlan,
    ledger: &mut ActionLedger,
) -> Result<ActionReceipt, ProtocolError> {
    ledger
        .record(
            &plan.action_id(),
            &plan.target.key(),
            &plan.scoped_idempotency_key(),
            Some(plan.expected_revision),
            ActionOutcome::Accepted,
        )
        .map_err(ProtocolError::Action)
}

/// A canonical unit of work.
///
/// The authoritative record a projection reads. It is never written through a
/// projection: the projection borrows it immutably.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalWork {
    id: CanonicalId,
    title: String,
    revision: Revision,
}

impl CanonicalWork {
    /// Record canonical work.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Field`] for an invalid title.
    pub fn new(id: CanonicalId, title: &str, revision: Revision) -> Result<Self, ProtocolError> {
        bounded(title, "work_title")?;
        Ok(Self {
            id,
            title: title.to_owned(),
            revision,
        })
    }

    /// The canonical identity.
    #[must_use]
    pub const fn id(&self) -> &CanonicalId {
        &self.id
    }

    /// The work's title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// The work's revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

/// A pointer to the canonical surface for one identity.
///
/// A reference, not a request: nothing here opens a connection. It exists so a
/// client needing semantics its own protocol cannot represent is sent to the
/// authoritative record instead of an approximation of it.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NativeResourceLink {
    kind: CanonicalKind,
    id: String,
}

impl NativeResourceLink {
    /// Point at a canonical identity.
    #[must_use]
    pub fn for_canonical(canonical: &CanonicalId) -> Self {
        Self {
            kind: canonical.kind(),
            id: canonical.id().to_owned(),
        }
    }

    /// The kind of identity it points at.
    #[must_use]
    pub const fn kind(&self) -> CanonicalKind {
        self.kind
    }

    /// The identifier it points at.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The canonical path, relative to the native surface.
    #[must_use]
    pub fn path(&self) -> String {
        format!("/native/v1/{}/{}", self.kind.as_str(), self.id)
    }
}

/// A bounded rendering of a semantic a dialect cannot represent.
///
/// Truncation is recorded rather than hidden, and the original byte length is
/// kept, so a reader can tell that it is looking at a summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedRendering {
    text: String,
    truncated: bool,
    source_bytes: usize,
}

impl BoundedRendering {
    /// Render text within [`MAX_DEGRADED_RENDERING_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Field`] for empty text or a control character.
    /// Over-long text is truncated on a character boundary and marked, never
    /// rejected and never silently shortened.
    pub fn new(value: &str) -> Result<Self, ProtocolError> {
        if value.is_empty() {
            return Err(ProtocolError::Field {
                field: "rendering",
                error: ValueError::Empty,
            });
        }
        if value.chars().any(char::is_control) {
            return Err(ProtocolError::Field {
                field: "rendering",
                error: ValueError::ControlCharacter,
            });
        }
        let source_bytes = value.len();
        let mut end = MAX_DEGRADED_RENDERING_BYTES.min(source_bytes);
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        Ok(Self {
            text: value[..end].to_owned(),
            truncated: end < source_bytes,
            source_bytes,
        })
    }

    /// The rendered text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Whether the rendering is shorter than the source.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// The source's UTF-8 byte length.
    #[must_use]
    pub const fn source_bytes(&self) -> usize {
        self.source_bytes
    }
}

/// A semantic the dialect could not represent, rendered honestly.
///
/// The authoritative link is a required field, so a degraded rendering can
/// never be the only copy of what happened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Degradation {
    semantic: ProtocolSemantic,
    rendering: BoundedRendering,
    authoritative: NativeResourceLink,
}

impl Degradation {
    /// Which semantic degraded.
    #[must_use]
    pub const fn semantic(&self) -> ProtocolSemantic {
        self.semantic
    }

    /// The bounded rendering.
    #[must_use]
    pub const fn rendering(&self) -> &BoundedRendering {
        &self.rendering
    }

    /// Where the authoritative record lives.
    #[must_use]
    pub const fn authoritative(&self) -> &NativeResourceLink {
        &self.authoritative
    }
}

/// How one semantic left a projection.
///
/// Two shapes, both carrying the authoritative link, plus a typed error. There
/// is deliberately no variant meaning "omitted".
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectedSemantic {
    /// The dialect represents it directly.
    Native {
        /// Which semantic.
        semantic: ProtocolSemantic,
        /// Where the authoritative record lives.
        authoritative: NativeResourceLink,
    },
    /// The dialect cannot; it is rendered as bounded text beside the link.
    Degraded(Degradation),
}

impl ProjectedSemantic {
    /// Which semantic was projected.
    #[must_use]
    pub const fn semantic(&self) -> ProtocolSemantic {
        match self {
            Self::Native { semantic, .. } => *semantic,
            Self::Degraded(degradation) => degradation.semantic,
        }
    }

    /// The authoritative link, which every projection carries.
    #[must_use]
    pub const fn authoritative(&self) -> &NativeResourceLink {
        match self {
            Self::Native { authoritative, .. } => authoritative,
            Self::Degraded(degradation) => &degradation.authoritative,
        }
    }
}

/// A compatibility view of canonical state.
///
/// Both fields are shared borrows. There is no owned field, no interior
/// mutability and no `&mut self` method, so a projection cannot hold a session,
/// an approval, a tool registry or an authorization decision of its own; it can
/// only read the canonical record and produce a [`CanonicalActionPlan`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Projection<'canonical> {
    binding: &'canonical ClientBinding,
    work: &'canonical CanonicalWork,
}

impl<'canonical> Projection<'canonical> {
    /// Project canonical work for a bound client.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::ScopeNotGranted`] when the binding cannot read
    /// canonical state. A projection of unreadable state would be an
    /// approximation with nothing behind it.
    pub fn of(
        binding: &'canonical ClientBinding,
        work: &'canonical CanonicalWork,
    ) -> Result<Self, ProtocolError> {
        if !binding.grants(Scope::ReadCanonicalState) {
            return Err(ProtocolError::ScopeNotGranted {
                action: "project",
                scope: Scope::ReadCanonicalState.as_str(),
            });
        }
        Ok(Self { binding, work })
    }

    /// The dialect, read back out of the binding rather than stored.
    #[must_use]
    pub const fn dialect(self) -> ProtocolDialect {
        self.binding.dialect
    }

    /// The binding this projection serves.
    #[must_use]
    pub const fn binding(self) -> &'canonical ClientBinding {
        self.binding
    }

    /// The canonical work being projected.
    #[must_use]
    pub const fn work(self) -> &'canonical CanonicalWork {
        self.work
    }

    /// The native resource link for the projected work.
    ///
    /// Available from every dialect, including the ones that can represent the
    /// least.
    #[must_use]
    pub fn native_link(self) -> NativeResourceLink {
        NativeResourceLink::for_canonical(&self.work.id)
    }

    /// Project one semantic into this dialect.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnsupportedSemantic`] when the dialect declares
    /// it cannot represent the semantic at all, and [`ProtocolError::Field`]
    /// for an unusable rendering. Neither outcome drops the field quietly, and
    /// the canonical record is borrowed immutably throughout, so no projection
    /// can alter what it could not express.
    pub fn project(
        self,
        semantic: ProtocolSemantic,
        rendering: &str,
    ) -> Result<ProjectedSemantic, ProtocolError> {
        match self.dialect().support(semantic) {
            SemanticSupport::Native => Ok(ProjectedSemantic::Native {
                semantic,
                authoritative: self.native_link(),
            }),
            SemanticSupport::BoundedText => Ok(ProjectedSemantic::Degraded(Degradation {
                semantic,
                rendering: BoundedRendering::new(rendering)?,
                authoritative: self.native_link(),
            })),
            SemanticSupport::Unsupported => Err(ProtocolError::UnsupportedSemantic {
                dialect: self.dialect().as_str(),
                semantic: semantic.as_str(),
            }),
        }
    }

    /// Admit a client of a declared protocol version.
    ///
    /// An in-range client receives a [`MutationAuthority`]; an out-of-range one
    /// receives a [`ReadOnlyClient`], which has no method producing a plan.
    /// Reading needs neither, so an incompatible client keeps working — it just
    /// cannot mutate.
    #[must_use]
    pub const fn admit(self, client: ProtocolVersion) -> Admission<'canonical> {
        if self.binding.supported_range.admits(client) {
            Admission::Mutating(MutationAuthority { projection: self })
        } else {
            Admission::ReadOnly(ReadOnlyClient {
                declared: self.binding.supported_range,
                client,
            })
        }
    }
}

/// What a client's declared protocol version entitles it to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission<'canonical> {
    /// Inside the declared range: mutations are reachable.
    Mutating(MutationAuthority<'canonical>),
    /// Outside it: reads still work, and every mutation fails closed.
    ReadOnly(ReadOnlyClient),
}

/// The right to turn an external request into a canonical action.
///
/// Obtainable only from [`Projection::admit`], and only for a client inside the
/// binding's declared range. It borrows the projection, so the binding it
/// authorizes against is the binding that produced it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationAuthority<'canonical> {
    projection: Projection<'canonical>,
}

impl<'canonical> MutationAuthority<'canonical> {
    /// The projection this authority came from.
    #[must_use]
    pub const fn projection(self) -> Projection<'canonical> {
        self.projection
    }

    /// Map an external request onto exactly one canonical action.
    ///
    /// The plan is attributed to the binding's actor. A [`RemoteAgentClaim`] on
    /// the request is carried by the request and read by nothing here, so the
    /// same request with and without one produces the same plan.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::ScopeNotGranted`] when the binding does not
    /// carry the action's scope, and [`ProtocolError::Field`] for an invalid
    /// idempotency key.
    pub fn plan(self, request: &ExternalRequest<'_>) -> Result<CanonicalActionPlan, ProtocolError> {
        let kind = request.operation.canonical_action();
        let scope = kind.required_scope();
        let binding = self.projection.binding;
        if !binding.grants(scope) {
            return Err(ProtocolError::ScopeNotGranted {
                action: kind.as_str(),
                scope: scope.as_str(),
            });
        }
        bounded(request.idempotency_key, "idempotency_key")?;
        Ok(CanonicalActionPlan {
            kind,
            dialect: binding.dialect,
            actor: binding.actor.clone(),
            target: request.target.clone(),
            idempotency_key: request.idempotency_key.to_owned(),
            expected_revision: request.expected_revision,
        })
    }
}

/// A client whose protocol version is outside the binding's declared range.
///
/// It can still read through a [`Projection`]. It cannot plan, because planning
/// lives on [`MutationAuthority`] and this is not one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadOnlyClient {
    declared: ProtocolRange,
    client: ProtocolVersion,
}

impl ReadOnlyClient {
    /// The range the binding declared.
    #[must_use]
    pub const fn declared(self) -> ProtocolRange {
        self.declared
    }

    /// The version the client declared.
    #[must_use]
    pub const fn client(self) -> ProtocolVersion {
        self.client
    }

    /// Refuse a mutation this client cannot be served.
    ///
    /// # Errors
    ///
    /// Always returns [`ProtocolError::MutationOutsideProtocolRange`]. It fails
    /// closed and names both versions rather than serving a mismatched dialect.
    pub const fn refuse_mutation(
        self,
        kind: CanonicalActionKind,
    ) -> Result<CanonicalActionPlan, ProtocolError> {
        Err(ProtocolError::MutationOutsideProtocolRange {
            action: kind.as_str(),
            declared_min: self.declared.min.get(),
            declared_max: self.declared.max.get(),
            client: self.client.get(),
        })
    }
}

/// What a host said about one approval prompt.
///
/// Three answers, all about one named target. There is no answer meaning
/// "everything from now on".
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HostApprovalDecision {
    /// Permit this occurrence.
    AllowOnce,
    /// Permit until the rule is revoked.
    AllowAlways,
    /// Refuse.
    Deny,
}

impl HostApprovalDecision {
    /// Every decision, for coverage checks.
    pub const ALL: [Self; 3] = [Self::AllowOnce, Self::AllowAlways, Self::Deny];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllowOnce => "allow_once",
            Self::AllowAlways => "allow_always",
            Self::Deny => "deny",
        }
    }
}

/// The canonical decision a host answer maps to.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ApprovalDecision {
    /// Permitted for this target revision only.
    AllowOnce,
    /// Permitted until revoked.
    AllowUntilRevoked,
    /// Refused.
    Deny,
}

impl ApprovalDecision {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllowOnce => "allow_once",
            Self::AllowUntilRevoked => "allow_until_revoked",
            Self::Deny => "deny",
        }
    }
}

/// What an approval is about.
///
/// Exactly one provider or exactly one tool, named. There is no variant
/// covering every provider or every tool, so a global bypass has no spelling.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ApprovalTarget {
    /// One provider.
    Provider {
        /// The provider's name.
        name: String,
    },
    /// One tool.
    Tool {
        /// The tool's name.
        name: String,
    },
}

impl ApprovalTarget {
    /// Name one provider.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Field`] for an invalid name.
    pub fn provider(name: &str) -> Result<Self, ProtocolError> {
        bounded(name, "provider_name")?;
        Ok(Self::Provider {
            name: name.to_owned(),
        })
    }

    /// Name one tool.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Field`] for an invalid name.
    pub fn tool(name: &str) -> Result<Self, ProtocolError> {
        bounded(name, "tool_name")?;
        Ok(Self::Tool {
            name: name.to_owned(),
        })
    }

    /// Which kind of target it is.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Provider { .. } => "provider",
            Self::Tool { .. } => "tool",
        }
    }

    /// The named target.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Provider { name } | Self::Tool { name } => name,
        }
    }
}

/// A host approval, mapped onto a typed canonical approval.
///
/// The target revision is a required field and is carried across unchanged, so
/// an approval cannot drift onto a later revision of its target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappedApproval {
    dialect: ProtocolDialect,
    target: ApprovalTarget,
    target_revision: Revision,
    decision: ApprovalDecision,
    decided_by: Actor,
}

impl MappedApproval {
    /// Map a host answer onto a canonical approval.
    ///
    /// The mapping is total and injective on the decision: each host answer has
    /// one canonical decision and no two share one.
    #[must_use]
    pub const fn from_host(
        dialect: ProtocolDialect,
        host: HostApprovalDecision,
        target: ApprovalTarget,
        target_revision: Revision,
        decided_by: Actor,
    ) -> Self {
        let decision = match host {
            HostApprovalDecision::AllowOnce => ApprovalDecision::AllowOnce,
            HostApprovalDecision::AllowAlways => ApprovalDecision::AllowUntilRevoked,
            HostApprovalDecision::Deny => ApprovalDecision::Deny,
        };
        Self {
            dialect,
            target,
            target_revision,
            decision,
            decided_by,
        }
    }

    /// The dialect the answer arrived over.
    #[must_use]
    pub const fn dialect(&self) -> ProtocolDialect {
        self.dialect
    }

    /// The named provider or tool.
    #[must_use]
    pub const fn target(&self) -> &ApprovalTarget {
        &self.target
    }

    /// The exact revision the approval is bound to.
    #[must_use]
    pub const fn target_revision(&self) -> Revision {
        self.target_revision
    }

    /// The canonical decision.
    #[must_use]
    pub const fn decision(&self) -> ApprovalDecision {
        self.decision
    }

    /// The resolved tenant actor who decided.
    #[must_use]
    pub const fn decided_by(&self) -> &Actor {
        &self.decided_by
    }
}

/// Escape the component separator so a joined key parses one way only.
///
/// `\` becomes `\\` and `/` becomes `\/`, which is injective: distinct
/// components produce distinct escapings, and a component containing neither
/// character is returned as it was.
fn escaped(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '/' => escaped.push_str("\\/"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn bounded(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    let error = if value.is_empty() {
        Some(ValueError::Empty)
    } else if value.len() > MAX_PROTOCOL_FIELD_BYTES {
        Some(ValueError::TooLong {
            max_bytes: MAX_PROTOCOL_FIELD_BYTES,
            actual_bytes: value.len(),
        })
    } else if value.chars().any(char::is_control) {
        Some(ValueError::ControlCharacter)
    } else {
        None
    };
    match error {
        Some(error) => Err(ProtocolError::Field { field, error }),
        None => Ok(()),
    }
}
