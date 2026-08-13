// SPDX-License-Identifier: Elastic-2.0

//! What every connector declares, and the shape of the suite that judges it.
//!
//! [`crate::connector`] is the platform-neutral *vocabulary* a bridge speaks —
//! installations, identities, intents, tokens, grants and coordinates — and its
//! whole premise is that it names no platform at all. This module is the layer
//! above it: a [`ConnectorDescriptor`] names one connector kind and declares the
//! ingress shape that kind produces, and a [`ConnectorConformanceSuite`] binds
//! that descriptor to a bounded corpus of named cases, each of which pins one
//! [`ConformanceObligation`] to an expected disposition.
//!
//! The two connectors this tree actually has are the authority. `automonique-
//! transports` parses Telegram `getUpdates` responses against a monotonic
//! `update_id` offset, and Slack Socket Mode frames one envelope at a time; the
//! descriptors [`ConnectorDescriptor::carried_for`] returns are those two shapes
//! written down. Everything a generic generator would enforce is enforced here
//! at construction, so a descriptor that disagrees with them does not exist.
//!
//! A dedup identity that names no field is a constant, and a constant key
//! collides every event onto one row:
//!
//! ```
//! use automonique_protocol::connector_conformance::{DedupIdentity, KeySegment};
//! let refused = DedupIdentity::new([KeySegment::fixed("update").unwrap()]);
//! assert_eq!(refused.unwrap_err().category(), "dedup_identity_constant");
//! ```
//!
//! Only an admitted disposition may retain content, so "denied but we kept the
//! text" is not a declaration that can be made:
//!
//! ```
//! use automonique_protocol::connector_conformance::{DispositionDeclaration, DispositionOutcome};
//! let refused = DispositionDeclaration::declare(DispositionOutcome::Denied, true);
//! assert_eq!(refused.unwrap_err().category(), "content_on_non_admitted_disposition");
//! ```
//!
//! # Honest present
//!
//! This module runs nothing. It parses no frame, opens no socket, holds no
//! token, and executes no case. A [`ConformanceCase`] carries a bounded fixture
//! body and the disposition that fixture must produce; whether a connector
//! actually produces it is measured by that connector's own suite, in the crate
//! that owns the parser. What is checked *here* is that the claim is
//! well-formed: that the corpus is bounded, that every expectation is inside the
//! vocabulary its descriptor declared, and that the obligations the cases leave
//! uncovered are named rather than assumed.
//!
//! # Divergences from the plan
//!
//! Named rather than silently approximated:
//!
//! - **Lease.** `plan/work-graph.toml` gives R13-01 the paths
//!   `connectors/typescript/`, which does not exist in this tree. This is the
//!   Rust-side value vocabulary, and it sits beside [`crate::connector`], where
//!   R1-16 put the neutral connector vocabulary it extends.
//! - **Two kinds, a named catalog of planned ones.** `docs/product-plan/
//!   requirements/connector-catalog.md` § Planned catalog and the R13 rows of
//!   `docs/product-plan/reference/work-breakdown.md` name a long list of
//!   families. This build has exactly two connector cores, so [`ConnectorKind`]
//!   has two variants and the rest are listed in [`PLANNED_CONNECTOR_KINDS`]:
//!   [`ConnectorKind::resolve`] refuses them with
//!   [`ConformanceError::PlannedConnectorKind`] — "the plan asks for this and no
//!   connector exists yet" — rather than with
//!   [`ConformanceError::UnknownConnectorKind`], which would be a lie about a
//!   documented requirement. The same discipline applies on the acknowledgement
//!   axis: the catalog's signed inbound webhook routes are
//!   [`PLANNED_ACK_DISCIPLINES`], not a third [`AckDisciplineKind`] variant.
//!   Families the catalog names without a single stable spelling — "compatible
//!   webhook adapters", "relay-style clients" — are deliberately absent, because
//!   a placeholder nobody can spell refuses nothing.
//! - **The rest of R13-01 is not here.** The epic's row also names a manifest
//!   generator, a fake platform, directory/pairing, media and independent
//!   rollout flags. A descriptor declares an ingress shape, not a graduation
//!   stage: the catalog's rollout ladder (notification-only through broad
//!   subscriptions) has no representation, and neither does the channel
//!   directory or the pairing flow. Those are gaps, not omissions this model
//!   quietly covers.
//!
//! # Cross-crate spellings this crate cannot import
//!
//! `automonique-protocol` is dependency-free by design, so it cannot see
//! `automonique-transports`, where the two real connectors live. Every spelling
//! and bound carried here — the `slack:` and `telegram:` source-key prefixes,
//! the `:` separator and its exclusion from admitted identifiers, the 100-update
//! batch, the 16-attempt redelivery ceiling, the 1024-entry allowlist and the
//! 128-byte identifier bound — is a literal pinned in
//! `tests/connector_conformance.rs` against the constant that owns it. A rename
//! or a re-bound on either side shows up as a failing assertion, not as a
//! silently divergent second authority. This is the same honest gap
//! [`crate::compat`] records for its foreign matrix rows and
//! [`crate::provider_catalog`] for its provider kinds.

use core::fmt;
use std::error::Error;

use crate::connector::ConformanceObligation;
use crate::primitives::{Revision, ValueError};

/// Stable schema identifier for a rendered conformance suite.
pub const CONNECTOR_CONFORMANCE_SCHEMA_V1: &str = "automonique.connector-conformance/v1";

/// The separator that joins the segments of a deduplication key.
///
/// Carried from `automonique_transports::slack`, whose `identifier` admits only
/// ASCII graphic bytes excluding `:` precisely because `:` joins the components
/// of `SlackIngress::source_key`. Admitting it would let two distinct triples
/// collide into one deduplication key.
pub const KEY_SEPARATOR: char = ':';

/// Maximum UTF-8 byte length of a name this module admits.
///
/// Carried from `automonique_transports::MAX_SLACK_IDENTIFIER_BYTES`.
pub const MAX_CONNECTOR_IDENTIFIER_BYTES: usize = 128;

/// Maximum segments one deduplication key may join.
pub const MAX_KEY_SEGMENTS: usize = 8;

/// Maximum coordinates one principal may be composed of.
pub const MAX_PRINCIPAL_COORDINATES: usize = 8;

/// Maximum principals one connector's exact allowlist may hold.
///
/// Carried from the `MAX_POLICY_ENTRIES` both transports bound their allowlists
/// by.
pub const MAX_PRINCIPALS_PER_CONNECTOR: u32 = 1_024;

/// Maximum ingress items an offset-cursor connector may take in one batch.
///
/// This module's own ceiling, above `automonique_transports::
/// MAX_TELEGRAM_UPDATES`. A declaration above it is refused as unbounded.
pub const MAX_INGRESS_BATCH: u32 = 1_024;

/// Maximum redelivery attempts a per-envelope connector may accept.
///
/// This module's own ceiling, above `automonique_transports::
/// MAX_SLACK_RETRY_ATTEMPT`.
pub const MAX_REDELIVERY_ATTEMPTS: u32 = 1_024;

/// Maximum cases one conformance suite may carry.
pub const MAX_CONFORMANCE_CASES: usize = 64;

/// Maximum UTF-8 byte length of one case's fixture body.
pub const MAX_CONFORMANCE_INPUT_BYTES: usize = 8 * 1024;

/// Connector kinds the plan names that this build has no connector for.
///
/// Listed so a caller naming one gets
/// [`ConformanceError::PlannedConnectorKind`] rather than
/// [`ConformanceError::UnknownConnectorKind`]. Sourced from
/// `docs/product-plan/requirements/connector-catalog.md` § Planned catalog and
/// the R13 rows of `docs/product-plan/reference/work-breakdown.md`. Sorted, so
/// a new entry lands in one obvious place.
pub const PLANNED_CONNECTOR_KINDS: [&str; 21] = [
    "dingtalk",
    "discord",
    "email",
    "feishu",
    "google_chat",
    "home_assistant",
    "imessage",
    "irc",
    "line",
    "matrix",
    "mattermost",
    "ntfy",
    "qq",
    "signal",
    "simplex",
    "sms",
    "teams",
    "wecom",
    "weixin",
    "whatsapp",
    "yuanbao",
];

/// Acknowledgement disciplines the plan names that this build cannot declare.
///
/// The catalog's Microsoft Graph webhooks are "signed inbound routes" and
/// Discord is "HTTP Interactions first"
/// (`docs/product-plan/requirements/connector-catalog.md`): a third discipline
/// where the platform posts to a signed endpoint and the response *is* the
/// acknowledgement. No connector here works that way, so it refuses by name
/// instead of being approximated onto [`AckDisciplineKind::PerEnvelope`].
pub const PLANNED_ACK_DISCIPLINES: [&str; 1] = ["signed_webhook"];

/// Why a connector declaration or a conformance suite was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConformanceError {
    /// A bounded field was rejected.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
    /// A name carried a character outside the separator-safe grammar.
    NotSeparatorSafe {
        /// The rejected field.
        field: &'static str,
        /// The first offending character, which may be [`KEY_SEPARATOR`].
        character: char,
    },
    /// A spelling names no connector, planned or otherwise.
    UnknownConnectorKind {
        /// The rejected spelling.
        name: String,
    },
    /// The plan names this connector and this build has no core for it.
    PlannedConnectorKind {
        /// The planned spelling.
        name: String,
    },
    /// A spelling names no acknowledgement discipline.
    UnknownAckDiscipline {
        /// The rejected spelling.
        name: String,
    },
    /// The plan names this discipline and this build cannot declare it.
    PlannedAckDiscipline {
        /// The planned spelling.
        name: String,
    },
    /// A spelling names no disposition.
    UnknownDisposition {
        /// The rejected spelling.
        name: String,
    },
    /// A declared ceiling was above the bound this module owns.
    UnboundedDeclaration {
        /// The rejected field.
        field: &'static str,
        /// The largest accepted value.
        ceiling: u64,
        /// The declared value.
        declared: u64,
    },
    /// A declared ceiling was zero, which admits nothing.
    ZeroCeiling {
        /// The rejected field.
        field: &'static str,
    },
    /// A deduplication key joined only fixed words, so every event collides.
    DedupIdentityConstant,
    /// One field appears twice in a deduplication key.
    DuplicateKeyField {
        /// The repeated field.
        name: String,
    },
    /// The per-delivery acknowledgement key was used as a dedup identity.
    AckKeyInDedupIdentity {
        /// The acknowledgement key field.
        field: String,
    },
    /// A disposition other than admitted claimed to retain content.
    ContentOnNonAdmittedDisposition {
        /// The offending disposition.
        outcome: &'static str,
    },
    /// One disposition was declared twice.
    DuplicateDisposition {
        /// The repeated disposition.
        outcome: &'static str,
    },
    /// A connector that can admit cannot deny, which is default-open.
    AdmissionWithoutDenial,
    /// A case expects a disposition its connector never declared.
    ExpectationOutsideVocabulary {
        /// The connector the suite is for.
        kind: &'static str,
        /// The expectation outside its declared vocabulary.
        outcome: &'static str,
    },
    /// Two cases in one suite share a name.
    DuplicateCaseName {
        /// The repeated name.
        name: String,
    },
    /// A corpus carried more cases than one suite may hold.
    CorpusTooLarge {
        /// Maximum accepted cases.
        max_cases: usize,
        /// Cases supplied.
        actual_cases: usize,
    },
}

impl ConformanceError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Field { .. } => "field_invalid",
            Self::NotSeparatorSafe { .. } => "not_separator_safe",
            Self::UnknownConnectorKind { .. } => "unknown_connector_kind",
            Self::PlannedConnectorKind { .. } => "planned_connector_kind",
            Self::UnknownAckDiscipline { .. } => "unknown_ack_discipline",
            Self::PlannedAckDiscipline { .. } => "planned_ack_discipline",
            Self::UnknownDisposition { .. } => "unknown_disposition",
            Self::UnboundedDeclaration { .. } => "unbounded_declaration",
            Self::ZeroCeiling { .. } => "zero_ceiling",
            Self::DedupIdentityConstant => "dedup_identity_constant",
            Self::DuplicateKeyField { .. } => "duplicate_key_field",
            Self::AckKeyInDedupIdentity { .. } => "ack_key_in_dedup_identity",
            Self::ContentOnNonAdmittedDisposition { .. } => "content_on_non_admitted_disposition",
            Self::DuplicateDisposition { .. } => "duplicate_disposition",
            Self::AdmissionWithoutDenial => "admission_without_denial",
            Self::ExpectationOutsideVocabulary { .. } => "expectation_outside_vocabulary",
            Self::DuplicateCaseName { .. } => "duplicate_case_name",
            Self::CorpusTooLarge { .. } => "corpus_too_large",
        }
    }
}

impl fmt::Display for ConformanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
            Self::NotSeparatorSafe { field, character } => write!(
                formatter,
                "field {field}: {character:?} is outside the separator-safe grammar"
            ),
            Self::UnknownConnectorKind { name } => {
                write!(formatter, "{name} names no connector kind")
            }
            Self::PlannedConnectorKind { name } => write!(
                formatter,
                "the plan names the {name} connector and this build has no core for it"
            ),
            Self::UnknownAckDiscipline { name } => {
                write!(formatter, "{name} names no acknowledgement discipline")
            }
            Self::PlannedAckDiscipline { name } => write!(
                formatter,
                "the plan names the {name} acknowledgement discipline and this build cannot declare it"
            ),
            Self::UnknownDisposition { name } => write!(formatter, "{name} names no disposition"),
            Self::UnboundedDeclaration {
                field,
                ceiling,
                declared,
            } => write!(
                formatter,
                "field {field}: {declared} is above the ceiling of {ceiling}"
            ),
            Self::ZeroCeiling { field } => {
                write!(formatter, "field {field}: a ceiling of zero admits nothing")
            }
            Self::DedupIdentityConstant => {
                formatter.write_str("a deduplication key of fixed words alone collides every event")
            }
            Self::DuplicateKeyField { name } => {
                write!(formatter, "field {name} appears twice in one key")
            }
            Self::AckKeyInDedupIdentity { field } => write!(
                formatter,
                "acknowledgement key {field} is a per-delivery value and cannot identify an event"
            ),
            Self::ContentOnNonAdmittedDisposition { outcome } => write!(
                formatter,
                "disposition {outcome} is not admitted and may not retain content"
            ),
            Self::DuplicateDisposition { outcome } => {
                write!(formatter, "disposition {outcome} was declared twice")
            }
            Self::AdmissionWithoutDenial => formatter
                .write_str("a connector that admits but cannot deny has no closed allowlist"),
            Self::ExpectationOutsideVocabulary { kind, outcome } => write!(
                formatter,
                "the {kind} connector never declared the {outcome} disposition"
            ),
            Self::DuplicateCaseName { name } => {
                write!(formatter, "two cases share the name {name}")
            }
            Self::CorpusTooLarge {
                max_cases,
                actual_cases,
            } => write!(
                formatter,
                "a corpus of {actual_cases} cases exceeds the maximum of {max_cases}"
            ),
        }
    }
}

impl Error for ConformanceError {}

/// A bounded name that cannot contain [`KEY_SEPARATOR`].
///
/// The grammar is `automonique_transports::slack`'s `identifier` rule: non-empty,
/// at most [`MAX_CONNECTOR_IDENTIFIER_BYTES`], every byte ASCII graphic and none
/// of them the separator. There is no public field, no `From<String>` and no
/// `Deref`, so a name that could split a deduplication key in two is not a value
/// this type holds — the rule is a property of the type rather than a check a
/// caller might skip.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SafeName(String);

impl SafeName {
    /// Parse a separator-safe name.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceError::Field`] when the name is empty or longer
    /// than [`MAX_CONNECTOR_IDENTIFIER_BYTES`], and
    /// [`ConformanceError::NotSeparatorSafe`] naming the offending character
    /// otherwise.
    pub fn parse(value: &str, field: &'static str) -> Result<Self, ConformanceError> {
        if value.is_empty() {
            return Err(ConformanceError::Field {
                field,
                error: ValueError::Empty,
            });
        }
        if value.len() > MAX_CONNECTOR_IDENTIFIER_BYTES {
            return Err(ConformanceError::Field {
                field,
                error: ValueError::TooLong {
                    max_bytes: MAX_CONNECTOR_IDENTIFIER_BYTES,
                    actual_bytes: value.len(),
                },
            });
        }
        if let Some(character) = value
            .chars()
            .find(|candidate| !candidate.is_ascii_graphic() || *candidate == KEY_SEPARATOR)
        {
            return Err(ConformanceError::NotSeparatorSafe { field, character });
        }
        Ok(Self(value.to_owned()))
    }

    /// The parsed name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SafeName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A connector this build has a core for.
///
/// Deliberately two variants. A connector kind is an admission parser plus an
/// acknowledgement discipline, and adding one means adding both with the
/// fixtures that pin them. There is no constructor from arbitrary text;
/// [`ConnectorKind::resolve`] is the only way in from a string.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConnectorKind {
    /// Slack Socket Mode, acknowledged one envelope at a time.
    Slack,
    /// Telegram long polling, committed against a monotonic offset.
    Telegram,
}

impl ConnectorKind {
    /// Every kind with a core, in canonical order.
    pub const ALL: [Self; 2] = [Self::Slack, Self::Telegram];

    /// Stable lowercase spelling.
    ///
    /// Identical to the prefix each connector's real source key opens with; see
    /// the module's cross-crate note.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Slack => "slack",
            Self::Telegram => "telegram",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }

    /// Resolve a spelling to a connector kind, or say why not.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceError::NotSeparatorSafe`] or
    /// [`ConformanceError::Field`] for a spelling outside the bounded grammar,
    /// [`ConformanceError::PlannedConnectorKind`] for one of
    /// [`PLANNED_CONNECTOR_KINDS`], and
    /// [`ConformanceError::UnknownConnectorKind`] otherwise.
    pub fn resolve(value: &str) -> Result<Self, ConformanceError> {
        SafeName::parse(value, "connector_kind")?;
        if let Some(kind) = Self::from_spelling(value) {
            return Ok(kind);
        }
        if PLANNED_CONNECTOR_KINDS.contains(&value) {
            return Err(ConformanceError::PlannedConnectorKind {
                name: value.to_owned(),
            });
        }
        Err(ConformanceError::UnknownConnectorKind {
            name: value.to_owned(),
        })
    }
}

impl fmt::Display for ConnectorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One segment of a deduplication key.
///
/// A key is an ordered list of these joined by [`KEY_SEPARATOR`]. A fixed word
/// is a separator between two value segments — `telegram:{bot}:update:{id}` has
/// one — and carries no platform value, which is why a key made of fixed words
/// alone is refused.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum KeySegment {
    /// A value the platform supplies, named by its field.
    Field(SafeName),
    /// A fixed word that separates two value segments.
    Fixed(SafeName),
}

impl KeySegment {
    /// Name a platform-supplied field.
    ///
    /// # Errors
    ///
    /// Returns the [`SafeName::parse`] refusal for an unsafe name.
    pub fn field(name: &str) -> Result<Self, ConformanceError> {
        SafeName::parse(name, "key_field").map(Self::Field)
    }

    /// Name a fixed word.
    ///
    /// # Errors
    ///
    /// Returns the [`SafeName::parse`] refusal for an unsafe name.
    pub fn fixed(word: &str) -> Result<Self, ConformanceError> {
        SafeName::parse(word, "key_word").map(Self::Fixed)
    }

    /// The name this segment carries, whichever kind it is.
    #[must_use]
    pub const fn name(&self) -> &SafeName {
        match self {
            Self::Field(name) | Self::Fixed(name) => name,
        }
    }

    /// Whether this segment is a platform-supplied value.
    #[must_use]
    pub const fn is_field(&self) -> bool {
        matches!(self, Self::Field(_))
    }

    /// How this segment appears in a rendered key template.
    #[must_use]
    pub fn rendered(&self) -> String {
        match self {
            Self::Field(name) => format!("{{{name}}}"),
            Self::Fixed(word) => word.as_str().to_owned(),
        }
    }
}

/// The identity that makes one platform event the same event twice.
///
/// Bounded, non-empty, and never constant: at least one segment must be a
/// platform-supplied [`KeySegment::Field`], because a key of fixed words alone
/// would fold every event of a connector onto a single row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DedupIdentity {
    segments: Vec<KeySegment>,
}

impl DedupIdentity {
    /// Compose a deduplication identity.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceError::Field`] for an empty or over-long list,
    /// [`ConformanceError::DedupIdentityConstant`] when no segment is a field,
    /// and [`ConformanceError::DuplicateKeyField`] when one field repeats.
    pub fn new(segments: impl IntoIterator<Item = KeySegment>) -> Result<Self, ConformanceError> {
        let segments: Vec<_> = segments.into_iter().collect();
        if segments.is_empty() {
            return Err(ConformanceError::Field {
                field: "dedup_identity",
                error: ValueError::Empty,
            });
        }
        if segments.len() > MAX_KEY_SEGMENTS {
            return Err(ConformanceError::Field {
                field: "dedup_identity",
                error: ValueError::TooLong {
                    max_bytes: MAX_KEY_SEGMENTS,
                    actual_bytes: segments.len(),
                },
            });
        }
        if !segments.iter().any(KeySegment::is_field) {
            return Err(ConformanceError::DedupIdentityConstant);
        }
        let mut seen: Vec<&SafeName> = Vec::new();
        for segment in segments.iter().filter(|segment| segment.is_field()) {
            if seen.contains(&segment.name()) {
                return Err(ConformanceError::DuplicateKeyField {
                    name: segment.name().as_str().to_owned(),
                });
            }
            seen.push(segment.name());
        }
        Ok(Self { segments })
    }

    /// Every segment, in key order.
    #[must_use]
    pub fn segments(&self) -> &[KeySegment] {
        &self.segments
    }

    /// Whether a named field takes part in this identity.
    #[must_use]
    pub fn names_field(&self, field: &SafeName) -> bool {
        self.segments
            .iter()
            .any(|segment| segment.is_field() && segment.name() == field)
    }

    /// The key template this identity produces for one connector.
    ///
    /// Deterministic and content-free: field names appear in braces, never
    /// their values.
    #[must_use]
    pub fn render_template(&self, kind: ConnectorKind) -> String {
        let mut rendered = kind.as_str().to_owned();
        for segment in &self.segments {
            rendered.push(KEY_SEPARATOR);
            rendered.push_str(&segment.rendered());
        }
        rendered
    }
}

/// The closed set of acknowledgement disciplines this build can declare.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AckDisciplineKind {
    /// One monotonic cursor commits a whole batch.
    OffsetCursor,
    /// One key acknowledges one delivery attempt.
    PerEnvelope,
}

impl AckDisciplineKind {
    /// Every declarable discipline, in canonical order.
    pub const ALL: [Self; 2] = [Self::OffsetCursor, Self::PerEnvelope];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OffsetCursor => "offset_cursor",
            Self::PerEnvelope => "per_envelope",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }

    /// Resolve a spelling, or say why not.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceError::PlannedAckDiscipline`] for one of
    /// [`PLANNED_ACK_DISCIPLINES`] and
    /// [`ConformanceError::UnknownAckDiscipline`] otherwise.
    pub fn resolve(value: &str) -> Result<Self, ConformanceError> {
        SafeName::parse(value, "ack_discipline")?;
        if let Some(kind) = Self::from_spelling(value) {
            return Ok(kind);
        }
        if PLANNED_ACK_DISCIPLINES.contains(&value) {
            return Err(ConformanceError::PlannedAckDiscipline {
                name: value.to_owned(),
            });
        }
        Err(ConformanceError::UnknownAckDiscipline {
            name: value.to_owned(),
        })
    }
}

/// How a connector tells its platform an event is durable.
///
/// The two shapes diverge in a way that is not cosmetic. An offset cursor
/// commits a whole batch at one point, so a malformed member poisons the batch;
/// a per-envelope key commits one delivery attempt, so a refusal is scoped to a
/// single frame and can never wedge unrelated traffic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AckDiscipline {
    /// A monotonic cursor advanced once per batch.
    OffsetCursor {
        /// The platform field the cursor reads.
        cursor: SafeName,
        /// Maximum items admitted in one batch.
        max_batch: u32,
    },
    /// A per-delivery key acknowledged once the disposition is durable.
    PerEnvelope {
        /// The platform field carrying the acknowledgement key.
        ack_key: SafeName,
        /// Maximum redelivery attempts accepted on one event.
        max_redelivery_attempts: u32,
    },
}

impl AckDiscipline {
    /// Declare an offset-cursor discipline.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceError::ZeroCeiling`] for a batch of zero,
    /// [`ConformanceError::UnboundedDeclaration`] above [`MAX_INGRESS_BATCH`],
    /// and the [`SafeName::parse`] refusal for an unsafe cursor field.
    pub fn offset_cursor(cursor: &str, max_batch: u32) -> Result<Self, ConformanceError> {
        let cursor = SafeName::parse(cursor, "cursor")?;
        if max_batch == 0 {
            return Err(ConformanceError::ZeroCeiling { field: "max_batch" });
        }
        if max_batch > MAX_INGRESS_BATCH {
            return Err(ConformanceError::UnboundedDeclaration {
                field: "max_batch",
                ceiling: u64::from(MAX_INGRESS_BATCH),
                declared: u64::from(max_batch),
            });
        }
        Ok(Self::OffsetCursor { cursor, max_batch })
    }

    /// Declare a per-envelope discipline.
    ///
    /// A ceiling of zero is accepted here and refused for a batch: a platform
    /// that never redelivers is a coherent platform, whereas a batch that
    /// admits nothing is a stall.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceError::UnboundedDeclaration`] above
    /// [`MAX_REDELIVERY_ATTEMPTS`] and the [`SafeName::parse`] refusal for an
    /// unsafe acknowledgement key field.
    pub fn per_envelope(
        ack_key: &str,
        max_redelivery_attempts: u32,
    ) -> Result<Self, ConformanceError> {
        let ack_key = SafeName::parse(ack_key, "ack_key")?;
        if max_redelivery_attempts > MAX_REDELIVERY_ATTEMPTS {
            return Err(ConformanceError::UnboundedDeclaration {
                field: "max_redelivery_attempts",
                ceiling: u64::from(MAX_REDELIVERY_ATTEMPTS),
                declared: u64::from(max_redelivery_attempts),
            });
        }
        Ok(Self::PerEnvelope {
            ack_key,
            max_redelivery_attempts,
        })
    }

    /// Which discipline this is.
    #[must_use]
    pub const fn kind(&self) -> AckDisciplineKind {
        match self {
            Self::OffsetCursor { .. } => AckDisciplineKind::OffsetCursor,
            Self::PerEnvelope { .. } => AckDisciplineKind::PerEnvelope,
        }
    }

    /// The per-delivery acknowledgement key, when this discipline has one.
    #[must_use]
    pub const fn ack_key(&self) -> Option<&SafeName> {
        match self {
            Self::PerEnvelope { ack_key, .. } => Some(ack_key),
            Self::OffsetCursor { .. } => None,
        }
    }
}

/// What a connector concluded about one inbound event.
///
/// The generic counterpart of the closed dispositions both real connectors
/// produce. A connector declares which of these it can reach; nothing here
/// admits a spelling outside the set.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DispositionOutcome {
    /// The exact principal is allowlisted.
    Admitted,
    /// Well-formed and outside the exact allowlist.
    Denied,
    /// Well-formed, durable for progress, and creating no work.
    IgnoredUnsupported,
    /// Malformed. The class, never the per-connector reason.
    Refused,
    /// A connection-lifecycle frame. Not an input.
    ConnectionControl,
}

impl DispositionOutcome {
    /// Every outcome, in canonical order.
    pub const ALL: [Self; 5] = [
        Self::Admitted,
        Self::Denied,
        Self::IgnoredUnsupported,
        Self::Refused,
        Self::ConnectionControl,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Denied => "denied",
            Self::IgnoredUnsupported => "ignored_unsupported",
            Self::Refused => "refused",
            Self::ConnectionControl => "connection_control",
        }
    }

    /// The category one connector reports this outcome under.
    ///
    /// Carried from the real Slack dispositions: `slack_admitted`,
    /// `slack_denied`, `slack_ignored_unsupported` and
    /// `slack_connection_control` are that connector's own spellings.
    /// [`DispositionOutcome::Refused`] is the one deliberate divergence — the
    /// real connector delegates a refusal to its per-reason category, so
    /// `slack_refused` is the class this generic model names and not a string
    /// that connector ever emits.
    #[must_use]
    pub fn qualified_category(self, kind: ConnectorKind) -> String {
        format!("{}_{}", kind.as_str(), self.as_str())
    }

    /// Whether this outcome may carry the user's content.
    ///
    /// True for exactly one outcome. Both real connectors set their content
    /// field only on an admitted disposition, so a denied or ignored record is
    /// evidence that something arrived, not a copy of it.
    #[must_use]
    pub const fn retains_content(self) -> bool {
        matches!(self, Self::Admitted)
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|outcome| outcome.as_str() == value)
    }

    /// Resolve a spelling, or say why not.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceError::UnknownDisposition`] for anything outside
    /// the closed vocabulary.
    pub fn resolve(value: &str) -> Result<Self, ConformanceError> {
        Self::from_spelling(value).ok_or_else(|| ConformanceError::UnknownDisposition {
            name: value.to_owned(),
        })
    }
}

impl fmt::Display for DispositionOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One disposition a connector declares it can reach, and what it retains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispositionDeclaration {
    outcome: DispositionOutcome,
    retains_content: bool,
}

impl DispositionDeclaration {
    /// Declare a disposition.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceError::ContentOnNonAdmittedDisposition`] when a
    /// disposition other than [`DispositionOutcome::Admitted`] claims to retain
    /// content.
    pub fn declare(
        outcome: DispositionOutcome,
        retains_content: bool,
    ) -> Result<Self, ConformanceError> {
        if retains_content && !outcome.retains_content() {
            return Err(ConformanceError::ContentOnNonAdmittedDisposition {
                outcome: outcome.as_str(),
            });
        }
        Ok(Self {
            outcome,
            retains_content,
        })
    }

    /// The declared outcome.
    #[must_use]
    pub const fn outcome(&self) -> DispositionOutcome {
        self.outcome
    }

    /// Whether this connector retains content under this outcome.
    #[must_use]
    pub const fn retains_content(&self) -> bool {
        self.retains_content
    }
}

/// Who may create work through a connector.
///
/// There is one constructor and it takes an exact allowlist. No variant, field
/// or flag expresses "everyone", so a default-open connector is not a
/// declaration this model can make — the same rule both real connectors enforce
/// by refusing an empty allowlist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActorPolicy {
    coordinates: Vec<SafeName>,
    max_principals: u32,
}

impl ActorPolicy {
    /// Declare an exact allowlist over a principal's coordinates.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceError::Field`] for an empty or over-long coordinate
    /// list, [`ConformanceError::DuplicateKeyField`] for a repeated coordinate,
    /// [`ConformanceError::ZeroCeiling`] for an allowlist that admits nothing,
    /// and [`ConformanceError::UnboundedDeclaration`] above
    /// [`MAX_PRINCIPALS_PER_CONNECTOR`].
    pub fn exact_allowlist(
        coordinates: impl IntoIterator<Item = SafeName>,
        max_principals: u32,
    ) -> Result<Self, ConformanceError> {
        let coordinates: Vec<_> = coordinates.into_iter().collect();
        if coordinates.is_empty() {
            return Err(ConformanceError::Field {
                field: "principal_coordinates",
                error: ValueError::Empty,
            });
        }
        if coordinates.len() > MAX_PRINCIPAL_COORDINATES {
            return Err(ConformanceError::Field {
                field: "principal_coordinates",
                error: ValueError::TooLong {
                    max_bytes: MAX_PRINCIPAL_COORDINATES,
                    actual_bytes: coordinates.len(),
                },
            });
        }
        for (index, coordinate) in coordinates.iter().enumerate() {
            if coordinates[..index].contains(coordinate) {
                return Err(ConformanceError::DuplicateKeyField {
                    name: coordinate.as_str().to_owned(),
                });
            }
        }
        if max_principals == 0 {
            return Err(ConformanceError::ZeroCeiling {
                field: "max_principals",
            });
        }
        if max_principals > MAX_PRINCIPALS_PER_CONNECTOR {
            return Err(ConformanceError::UnboundedDeclaration {
                field: "max_principals",
                ceiling: u64::from(MAX_PRINCIPALS_PER_CONNECTOR),
                declared: u64::from(max_principals),
            });
        }
        Ok(Self {
            coordinates,
            max_principals,
        })
    }

    /// The coordinates one principal is composed of.
    #[must_use]
    pub fn coordinates(&self) -> &[SafeName] {
        &self.coordinates
    }

    /// The allowlist ceiling.
    #[must_use]
    pub const fn max_principals(&self) -> u32 {
        self.max_principals
    }
}

/// Every field a [`ConnectorDescriptor`] needs, named at the call site.
///
/// A struct rather than a positional list, following
/// [`crate::provider_catalog::ProviderEntryParts`]: a transposed pair of bounded
/// declarations would compile while describing the wrong connector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescriptorParts {
    /// The connector kind being declared.
    pub kind: ConnectorKind,
    /// How it acknowledges.
    pub ack: AckDiscipline,
    /// What makes one of its events the same event twice.
    pub dedup: DedupIdentity,
    /// The dispositions it can reach.
    pub dispositions: Vec<DispositionDeclaration>,
    /// Who may create work through it.
    pub actors: ActorPolicy,
}

/// What one connector declares about the ingress it produces.
///
/// Every cross-connector invariant a generic generator would enforce is
/// enforced by [`ConnectorDescriptor::declare`], so a descriptor that breaks one
/// is not a value that exists to be checked later.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorDescriptor {
    kind: ConnectorKind,
    ack: AckDiscipline,
    dedup: DedupIdentity,
    dispositions: Vec<DispositionDeclaration>,
    actors: ActorPolicy,
}

impl ConnectorDescriptor {
    /// Declare a connector.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceError::Field`] for an empty disposition vocabulary,
    /// [`ConformanceError::DuplicateDisposition`] for a repeated one,
    /// [`ConformanceError::AdmissionWithoutDenial`] for a vocabulary that can
    /// admit but not deny, and [`ConformanceError::AckKeyInDedupIdentity`] when
    /// a per-delivery acknowledgement key was used as an event identity.
    pub fn declare(parts: DescriptorParts) -> Result<Self, ConformanceError> {
        let DescriptorParts {
            kind,
            ack,
            dedup,
            dispositions,
            actors,
        } = parts;
        if dispositions.is_empty() {
            return Err(ConformanceError::Field {
                field: "dispositions",
                error: ValueError::Empty,
            });
        }
        for (index, declaration) in dispositions.iter().enumerate() {
            if dispositions[..index]
                .iter()
                .any(|earlier| earlier.outcome() == declaration.outcome())
            {
                return Err(ConformanceError::DuplicateDisposition {
                    outcome: declaration.outcome().as_str(),
                });
            }
        }
        let produces = |outcome: DispositionOutcome| {
            dispositions
                .iter()
                .any(|declaration| declaration.outcome() == outcome)
        };
        if produces(DispositionOutcome::Admitted) && !produces(DispositionOutcome::Denied) {
            return Err(ConformanceError::AdmissionWithoutDenial);
        }
        // A per-delivery key is minted afresh for every redelivery of the same
        // event, so a dedup identity naming it would treat one event as many.
        // An offset cursor is the opposite: it is the platform's own per-event
        // identity, and the real Telegram key is built from it.
        if let Some(ack_key) = ack.ack_key()
            && dedup.names_field(ack_key)
        {
            return Err(ConformanceError::AckKeyInDedupIdentity {
                field: ack_key.as_str().to_owned(),
            });
        }
        Ok(Self {
            kind,
            ack,
            dedup,
            dispositions,
            actors,
        })
    }

    /// The descriptor this build's real connector satisfies.
    ///
    /// Every literal here is carried from `automonique-transports`, which this
    /// crate cannot import; `tests/connector_conformance.rs` pins each one.
    ///
    /// # Errors
    ///
    /// Returns a [`ConformanceError`] if a carried literal ever stops
    /// satisfying the invariants — which is the point of returning one.
    pub fn carried_for(kind: ConnectorKind) -> Result<Self, ConformanceError> {
        match kind {
            // `SlackIngress::source_key` is `slack:{app}:{team}:{channel}:{ts}`;
            // `envelope_id` is an acknowledgement key and is deliberately absent
            // from it. Bounds from `MAX_SLACK_RETRY_ATTEMPT` and the transport's
            // `MAX_POLICY_ENTRIES`.
            ConnectorKind::Slack => Self::declare(DescriptorParts {
                kind,
                ack: AckDiscipline::per_envelope("envelope_id", 16)?,
                dedup: DedupIdentity::new([
                    KeySegment::field("app")?,
                    KeySegment::field("team")?,
                    KeySegment::field("channel")?,
                    KeySegment::field("ts")?,
                ])?,
                dispositions: vec![
                    DispositionDeclaration::declare(DispositionOutcome::Admitted, true)?,
                    DispositionDeclaration::declare(DispositionOutcome::Denied, false)?,
                    DispositionDeclaration::declare(DispositionOutcome::IgnoredUnsupported, false)?,
                    DispositionDeclaration::declare(DispositionOutcome::Refused, false)?,
                    DispositionDeclaration::declare(DispositionOutcome::ConnectionControl, false)?,
                ],
                actors: ActorPolicy::exact_allowlist(
                    [
                        SafeName::parse("team", "coordinate")?,
                        SafeName::parse("channel", "coordinate")?,
                        SafeName::parse("user", "coordinate")?,
                    ],
                    MAX_PRINCIPALS_PER_CONNECTOR,
                )?,
            }),
            // `TelegramIngress::source_key` is `telegram:{bot}:update:{id}`, so
            // the key carries one fixed word. There is no connection-lifecycle
            // frame in a poll response and no refusal disposition: a malformed
            // member poisons the whole batch as a `TelegramError`, because the
            // batch shares one commit point. Bound from `MAX_TELEGRAM_UPDATES`.
            ConnectorKind::Telegram => Self::declare(DescriptorParts {
                kind,
                ack: AckDiscipline::offset_cursor("update_id", 100)?,
                dedup: DedupIdentity::new([
                    KeySegment::field("bot")?,
                    KeySegment::fixed("update")?,
                    KeySegment::field("update_id")?,
                ])?,
                dispositions: vec![
                    DispositionDeclaration::declare(DispositionOutcome::Admitted, true)?,
                    DispositionDeclaration::declare(DispositionOutcome::Denied, false)?,
                    DispositionDeclaration::declare(DispositionOutcome::IgnoredUnsupported, false)?,
                ],
                actors: ActorPolicy::exact_allowlist(
                    [
                        SafeName::parse("chat", "coordinate")?,
                        SafeName::parse("actor", "coordinate")?,
                    ],
                    MAX_PRINCIPALS_PER_CONNECTOR,
                )?,
            }),
        }
    }

    /// The connector this describes.
    #[must_use]
    pub const fn kind(&self) -> ConnectorKind {
        self.kind
    }

    /// How it acknowledges.
    #[must_use]
    pub const fn ack(&self) -> &AckDiscipline {
        &self.ack
    }

    /// What makes one of its events the same event twice.
    #[must_use]
    pub const fn dedup(&self) -> &DedupIdentity {
        &self.dedup
    }

    /// The dispositions it declared.
    #[must_use]
    pub fn dispositions(&self) -> &[DispositionDeclaration] {
        &self.dispositions
    }

    /// Who may create work through it.
    #[must_use]
    pub const fn actors(&self) -> &ActorPolicy {
        &self.actors
    }

    /// Whether this connector declared it can reach an outcome.
    #[must_use]
    pub fn produces(&self, outcome: DispositionOutcome) -> bool {
        self.dispositions
            .iter()
            .any(|declaration| declaration.outcome() == outcome)
    }

    /// The deduplication key template, content-free.
    #[must_use]
    pub fn source_key_template(&self) -> String {
        self.dedup.render_template(self.kind)
    }
}

/// One bounded fixture body a conformance case is stated over.
///
/// A fixture, not traffic: this module never parses it and never sends it. Line
/// breaks and tabs are admitted because a checked-in frame may be
/// pretty-printed; every other control character is refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseInput(String);

impl CaseInput {
    /// Parse a bounded fixture body.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceError::Field`] when the body is empty, longer than
    /// [`MAX_CONFORMANCE_INPUT_BYTES`], or carries a control character other
    /// than a line break or a tab.
    pub fn fixture(body: &str) -> Result<Self, ConformanceError> {
        if body.is_empty() {
            return Err(ConformanceError::Field {
                field: "case_input",
                error: ValueError::Empty,
            });
        }
        if body.len() > MAX_CONFORMANCE_INPUT_BYTES {
            return Err(ConformanceError::Field {
                field: "case_input",
                error: ValueError::TooLong {
                    max_bytes: MAX_CONFORMANCE_INPUT_BYTES,
                    actual_bytes: body.len(),
                },
            });
        }
        if body
            .chars()
            .any(|character| character.is_control() && character != '\n' && character != '\t')
        {
            return Err(ConformanceError::Field {
                field: "case_input",
                error: ValueError::ControlCharacter,
            });
        }
        Ok(Self(body.to_owned()))
    }

    /// The fixture body.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One named input a connector must turn into one named disposition.
///
/// Each case names the [`ConformanceObligation`] it exercises, so a suite's
/// coverage is derived from its cases rather than claimed beside them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceCase {
    name: SafeName,
    obligation: ConformanceObligation,
    input: CaseInput,
    expected: DispositionOutcome,
}

impl ConformanceCase {
    /// State a case.
    ///
    /// # Errors
    ///
    /// Returns the [`SafeName::parse`] refusal for an unsafe case name.
    pub fn state(
        name: &str,
        obligation: ConformanceObligation,
        input: CaseInput,
        expected: DispositionOutcome,
    ) -> Result<Self, ConformanceError> {
        Ok(Self {
            name: SafeName::parse(name, "case_name")?,
            obligation,
            input,
            expected,
        })
    }

    /// The case name, unique within its suite.
    #[must_use]
    pub const fn name(&self) -> &SafeName {
        &self.name
    }

    /// The obligation this case exercises.
    #[must_use]
    pub const fn obligation(&self) -> ConformanceObligation {
        self.obligation
    }

    /// The fixture this case is stated over.
    #[must_use]
    pub const fn input(&self) -> &CaseInput {
        &self.input
    }

    /// The disposition the connector must produce.
    #[must_use]
    pub const fn expected(&self) -> DispositionOutcome {
        self.expected
    }
}

/// A bounded corpus of cases bound to one connector at one revision.
///
/// The conformance record R13-01 names, keyed the way
/// [`crate::provider_catalog::ConformanceRecord`] is keyed: a claim recorded
/// with the coordinates that make it checkable elsewhere, not a measurement
/// taken here. Nothing in this type runs a case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorConformanceSuite {
    descriptor: ConnectorDescriptor,
    revision: Revision,
    cases: Vec<ConformanceCase>,
}

impl ConnectorConformanceSuite {
    /// Declare a suite.
    ///
    /// Cases are held in name order, so two suites over the same cases are the
    /// same value however they were assembled.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceError::Field`] for an empty corpus,
    /// [`ConformanceError::CorpusTooLarge`] above [`MAX_CONFORMANCE_CASES`],
    /// [`ConformanceError::DuplicateCaseName`] for a repeated name, and
    /// [`ConformanceError::ExpectationOutsideVocabulary`] for a case expecting a
    /// disposition its connector never declared.
    pub fn declare(
        descriptor: ConnectorDescriptor,
        revision: Revision,
        cases: impl IntoIterator<Item = ConformanceCase>,
    ) -> Result<Self, ConformanceError> {
        let mut cases: Vec<_> = cases.into_iter().collect();
        if cases.is_empty() {
            return Err(ConformanceError::Field {
                field: "cases",
                error: ValueError::Empty,
            });
        }
        if cases.len() > MAX_CONFORMANCE_CASES {
            return Err(ConformanceError::CorpusTooLarge {
                max_cases: MAX_CONFORMANCE_CASES,
                actual_cases: cases.len(),
            });
        }
        cases.sort_by(|left, right| left.name.cmp(&right.name));
        for window in cases.windows(2) {
            if window[0].name == window[1].name {
                return Err(ConformanceError::DuplicateCaseName {
                    name: window[0].name.as_str().to_owned(),
                });
            }
        }
        for case in &cases {
            if !descriptor.produces(case.expected()) {
                return Err(ConformanceError::ExpectationOutsideVocabulary {
                    kind: descriptor.kind().as_str(),
                    outcome: case.expected().as_str(),
                });
            }
        }
        Ok(Self {
            descriptor,
            revision,
            cases,
        })
    }

    /// The stable schema this suite renders under.
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        CONNECTOR_CONFORMANCE_SCHEMA_V1
    }

    /// The connector this suite judges.
    #[must_use]
    pub const fn descriptor(&self) -> &ConnectorDescriptor {
        &self.descriptor
    }

    /// The revision this suite was recorded at.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Every case, in name order.
    #[must_use]
    pub fn cases(&self) -> &[ConformanceCase] {
        &self.cases
    }

    /// The obligations the cases exercise, in canonical order.
    #[must_use]
    pub fn covered_obligations(&self) -> Vec<ConformanceObligation> {
        ConformanceObligation::ALL
            .into_iter()
            .filter(|obligation| {
                self.cases
                    .iter()
                    .any(|case| case.obligation() == *obligation)
            })
            .collect()
    }

    /// The obligations no case exercises, in canonical order.
    ///
    /// A suite that covers eight of nine says which one it skipped, so a
    /// partial run cannot read as a pass.
    #[must_use]
    pub fn missing_obligations(&self) -> Vec<ConformanceObligation> {
        ConformanceObligation::ALL
            .into_iter()
            .filter(|obligation| {
                !self
                    .cases
                    .iter()
                    .any(|case| case.obligation() == *obligation)
            })
            .collect()
    }

    /// Whether every obligation is exercised by at least one case.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.missing_obligations().is_empty()
    }

    /// The deterministic, content-free rendering of this suite.
    ///
    /// Field names, case names, obligations and expected dispositions only. No
    /// fixture body reaches this text, so a rendered suite can travel where the
    /// fixtures it was built from cannot.
    #[must_use]
    pub fn render(&self) -> String {
        let mut rendered = String::new();
        rendered.push_str(self.schema());
        rendered.push('\n');
        rendered.push_str(&format!("connector\t{}\n", self.descriptor.kind()));
        rendered.push_str(&format!("revision\t{}\n", self.revision.get()));
        rendered.push_str(&format!(
            "source_key\t{}\n",
            self.descriptor.source_key_template()
        ));
        rendered.push_str(&format!("ack\t{}\n", self.descriptor.ack().kind().as_str()));
        for coordinate in self.descriptor.actors().coordinates() {
            rendered.push_str(&format!("principal_coordinate\t{coordinate}\n"));
        }
        for outcome in DispositionOutcome::ALL {
            if let Some(declaration) = self
                .descriptor
                .dispositions()
                .iter()
                .find(|declaration| declaration.outcome() == outcome)
            {
                rendered.push_str(&format!(
                    "disposition\t{}\t{}\n",
                    outcome.qualified_category(self.descriptor.kind()),
                    if declaration.retains_content() {
                        "retains_content"
                    } else {
                        "content_free"
                    }
                ));
            }
        }
        for case in &self.cases {
            rendered.push_str(&format!(
                "case\t{}\t{}\t{}\n",
                case.name(),
                case.obligation().as_str(),
                case.expected()
            ));
        }
        for obligation in self.missing_obligations() {
            rendered.push_str(&format!("missing_obligation\t{}\n", obligation.as_str()));
        }
        rendered
    }
}
