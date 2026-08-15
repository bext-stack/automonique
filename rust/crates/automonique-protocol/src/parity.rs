// SPDX-License-Identifier: Elastic-2.0

//! Intended-action envelopes: what an engine *decided to do*, held apart from
//! doing it.
//!
//! `docs/improvement-plan/implementation/M2-parity-harness.md` states the
//! central design question — "where does 'decide to post' become 'actually
//! post'?" — and answers it: every externally visible effect in this product
//! already passes through a narrow injected trait, so suppressing effects needs
//! a recording decorator per trait rather than a new architecture. This module
//! is the value those decorators record.
//!
//! An [`IntendedActionEnvelope`] says *one engine, at one point in one source
//! event's handling, decided to perform this exact action*. It is not a receipt
//! and not a log line: nothing here has happened. Two engines' envelope streams
//! over the same inbound event are what a parity comparison compares, which is
//! why deliberate silence has a spelling of its own — [`IntendedAction::NoAction`]
//! — rather than being the absence of a record. A shadow that stays quiet where
//! the reference engine posts must score as a difference, not as agreement.
//!
//! # Why this shape, and not serde
//!
//! `automonique-protocol` has zero dependencies and its canonical JSON is
//! hand-rolled in [`crate::wire`]: object keys sort in UTF-8 byte order, numbers
//! are integers only, and input that parses but is not already canonical is
//! *refused* rather than normalized. Every document type here therefore follows
//! the crate's own three-method idiom — `to_document` / `to_canonical_bytes` /
//! `from_canonical_bytes` — with a private exact-field gate on decode so an
//! unknown *and* a missing key are both refused, exactly as
//! [`crate::batch_runner::BatchPlan`] does.
//!
//! Each document carries a `schema` member for domain separation, checked on
//! decode into [`ParityError::UnknownSchema`]. The reason is the one written out
//! in [`crate::release_trust_root`]: without it, a digest over some other
//! document that happened to share this shape would also verify here.
//!
//! # The diff vocabulary is not a new one
//!
//! `tools/oracle/vocabulary.py` and `tools/oracle/fields.json` already fix a
//! closed comparison vocabulary for this product — the outcomes, the relations,
//! the comparison fields, and which of those fields are approved-nondeterministic.
//! [`ComparisonField`] and [`Relation`] here are that vocabulary in Rust, member
//! for member, so a live-traffic verdict and a future archive-differential
//! verdict are the same shape. `tests/parity.rs` pins the spellings against the
//! registry rather than trusting this comment.
//!
//! # Integers all the way down
//!
//! The confidence score in this module ([`ParityScore`]) is weighted, and one
//! weight is non-integral (variety counts one and a half). The canonical encoder
//! refuses floats outright, and a score that cannot be canonically encoded
//! cannot be digested into an immutable gate-decision row — so every weight is
//! a fixed-point integer scaled by [`WEIGHT_SCALE`] and the score itself is a
//! whole number of points out of 100.
//!
//! # What this module cannot do
//!
//! It performs no IO, opens no store, reads no clock and reaches no network. An
//! envelope carries a caller-supplied `observed_at_ms` for the same reason the
//! store crate takes `now_ms` from its callers everywhere: a test must not
//! depend on an ambient clock. Comparison ([`compare`]) is a pure function over
//! two optional envelopes, and classification ([`DeviationRegistry::classify`])
//! is a pure function over a difference and a registry the caller loaded.

use core::fmt;
use std::error::Error;

use crate::codec::{CodecError, SecuritySensitiveEnum, decode_security_enum};
use crate::digest::{Sha256, Sha256Digest};
use crate::primitives::ValueError;
use crate::wire::{JsonValue, parse_canonical};

/// Stable schema identifier for a version-one intended-action envelope.
pub const INTENDED_ACTION_SCHEMA_V1: &str = "automonique.intended-action/v1";

/// Stable schema identifier for a version-one known-deviation registry.
pub const DEVIATION_REGISTRY_SCHEMA_V1: &str = "automonique.parity-deviations/v1";

/// Stable schema identifier for a version-one golden-trace header.
pub const PARITY_TRACE_SCHEMA_V1: &str = "automonique.parity-trace/v1";

/// Maximum UTF-8 bytes of a parity scope name.
pub const MAX_SCOPE_BYTES: usize = 128;

/// Maximum UTF-8 bytes of a source key.
///
/// Defined as the durable transport-key bound rather than as a second number
/// that happens to match it: an envelope keyed by a source key the store would
/// refuse could never be recorded, so admitting one here would only move the
/// refusal later. `automonique_store::MAX_TRANSPORT_KEY_BYTES` is that bound;
/// this crate has no dependencies and cannot name it, so `tests/parity.rs`
/// carries the equality as an assertion in the store's own test instead.
pub const MAX_SOURCE_KEY_BYTES: usize = 640;

/// Maximum UTF-8 bytes of one identifier-shaped action field.
pub const MAX_ACTION_ID_BYTES: usize = 512;

/// Maximum UTF-8 bytes of one text-shaped action field.
pub const MAX_ACTION_TEXT_BYTES: usize = 16 * 1024;

/// Maximum canonical bytes of one envelope document.
pub const MAX_ENVELOPE_CANONICAL_BYTES: usize = 64 * 1024;

/// Maximum canonical bytes of one deviation-registry document.
pub const MAX_REGISTRY_CANONICAL_BYTES: usize = 256 * 1024;

/// Maximum entries one deviation registry may hold.
pub const MAX_DEVIATIONS: usize = 512;

/// Maximum UTF-8 bytes of a deviation entry identifier.
pub const MAX_DEVIATION_ID_BYTES: usize = 128;

/// The placeholder a masked field normalizes to.
///
/// A masked field is approved-nondeterministic: `tools/oracle/fields.json`
/// registers `receipt_timestamp` and `provider_event_id` that way. Normalization
/// replaces the value rather than dropping the field, so a field present on one
/// side and absent on the other stays a difference.
pub const MASKED_PLACEHOLDER: &str = "<masked>";

/// Fixed-point scale for [`Category`] weights.
///
/// The plan's weights are happy ×1, error ×2, edge ×2, variety ×1.5 and
/// production-representative ×3. One of those is not an integer and the
/// canonical encoder admits no floats, so every weight is carried as
/// thousandths and every arithmetic step below stays in `i64`.
pub const WEIGHT_SCALE: i64 = 1_000;

/// Highest score [`ParityScore`] can reach.
pub const MAX_SCORE: u32 = 100;

/// A refusal while constructing, encoding, decoding or scoring a parity value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParityError {
    /// The canonical JSON codec refused the document.
    ///
    /// Includes [`CodecError::UnknownEnumValue`] for an engine, action kind,
    /// relation, category, band or classification spelling this build does not
    /// define. Those fail closed rather than decoding to a default.
    Codec(CodecError),
    /// A bounded identifier or text field was empty, over-long or
    /// control-bearing.
    Field {
        /// Field that was refused.
        field: &'static str,
        /// Why it was refused.
        error: ValueError,
    },
    /// The document declared a schema this build does not serve.
    UnknownSchema,
    /// The document was not an object with exactly the expected members.
    InvalidBody,
    /// The document exceeded its canonical ceiling.
    DocumentTooLarge {
        /// Largest canonical document this build decodes.
        max_bytes: usize,
        /// Bytes the caller supplied.
        actual_bytes: usize,
    },
    /// A registry named one deviation identifier twice.
    DuplicateDeviation {
        /// The repeated identifier.
        id: String,
    },
    /// A registry named more deviations than [`MAX_DEVIATIONS`].
    TooManyDeviations {
        /// Most entries one registry holds.
        max: usize,
        /// Entries the caller supplied.
        actual: usize,
    },
    /// A score was computed over an empty corpus, which decides nothing.
    ///
    /// Deliberately not zero: an unmeasured scope and a scope that measured
    /// badly are different facts, and a gate must not read the first as the
    /// second.
    EmptyCorpus,
    /// A count or weight overflowed the fixed-point arithmetic.
    ScoreUnrepresentable,
}

impl ParityError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Codec(_) => "codec",
            Self::Field { .. } => "invalid_field",
            Self::UnknownSchema => "unknown_schema",
            Self::InvalidBody => "invalid_body",
            Self::DocumentTooLarge { .. } => "document_too_large",
            Self::DuplicateDeviation { .. } => "duplicate_deviation",
            Self::TooManyDeviations { .. } => "too_many_deviations",
            Self::EmptyCorpus => "empty_corpus",
            Self::ScoreUnrepresentable => "score_unrepresentable",
        }
    }
}

impl fmt::Display for ParityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "canonical codec refused document: {error}"),
            Self::Field { field, error } => write!(formatter, "invalid field {field}: {error}"),
            Self::UnknownSchema => formatter.write_str("document declares an unserved schema"),
            Self::InvalidBody => formatter.write_str("document body is not exact"),
            Self::DocumentTooLarge {
                max_bytes,
                actual_bytes,
            } => write!(
                formatter,
                "document is {actual_bytes} canonical bytes; maximum is {max_bytes}"
            ),
            Self::DuplicateDeviation { id } => {
                write!(formatter, "deviation {id} is registered twice")
            }
            Self::TooManyDeviations { max, actual } => {
                write!(
                    formatter,
                    "registry holds {actual} entries; maximum is {max}"
                )
            }
            Self::EmptyCorpus => {
                formatter.write_str("no comparison was scored, so no band was reached")
            }
            Self::ScoreUnrepresentable => {
                formatter.write_str("weighted totals exceeded the representable range")
            }
        }
    }
}

impl Error for ParityError {}

impl From<CodecError> for ParityError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

/// Which engine produced an envelope.
///
/// Closed, and decoded through [`SecuritySensitiveEnum`]: an unknown spelling is
/// refused rather than retained, because the value selects which side of a
/// comparison a record lands on.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ParityEngine {
    /// This product, running with its effects suppressed.
    ShadowCandidate,
    /// The reference system, observed acting on shared surfaces.
    LegacyObserved,
}

impl ParityEngine {
    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ShadowCandidate => "shadow-candidate",
            Self::LegacyObserved => "legacy-observed",
        }
    }

    /// Every engine this build defines.
    pub const ALL: [Self; 2] = [Self::ShadowCandidate, Self::LegacyObserved];
}

impl SecuritySensitiveEnum for ParityEngine {
    const FIELD: &'static str = "engine";

    fn from_wire(value: &str) -> Option<Self> {
        match value {
            "shadow-candidate" => Some(Self::ShadowCandidate),
            "legacy-observed" => Some(Self::LegacyObserved),
            _ => None,
        }
    }
}

/// A comparison field, as `tools/oracle/fields.json` registers it.
///
/// The registry is the authority; this enum restates it so Rust can name a
/// field without parsing JSON at runtime. `tests/parity.rs` proves the two
/// agree member for member, so adding a field to the registry without adding it
/// here fails a test rather than silently producing an unnamed difference.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ComparisonField {
    /// Semantic state transition taken for the fixture.
    StateTransition,
    /// External effect the run requested.
    ActionEffect,
    /// Receipt body compared field by field.
    Receipt,
    /// Receipt clock value, approved as nondeterministic.
    ReceiptTimestamp,
    /// Rendered message structure, not its text.
    RenderedMessage,
    /// Normalized provider event kind and ordering.
    ProviderEvent,
    /// Provider-assigned event identifier, approved as nondeterministic.
    ProviderEventId,
    /// Coarse resource class, never a measured quantity.
    ResourceClass,
}

impl ComparisonField {
    /// Stable machine-oriented spelling, matching the registry's `id`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StateTransition => "state_transition",
            Self::ActionEffect => "action_effect",
            Self::Receipt => "receipt",
            Self::ReceiptTimestamp => "receipt_timestamp",
            Self::RenderedMessage => "rendered_message",
            Self::ProviderEvent => "provider_event",
            Self::ProviderEventId => "provider_event_id",
            Self::ResourceClass => "resource_class",
        }
    }

    /// Whether the registry approves this field as nondeterministic.
    ///
    /// A masked field is normalized to [`MASKED_PLACEHOLDER`] before comparison,
    /// so its value can never be the reason a verdict is a mismatch.
    #[must_use]
    pub const fn masked(self) -> bool {
        matches!(self, Self::ReceiptTimestamp | Self::ProviderEventId)
    }

    /// Every comparison field this build defines, in registry order.
    pub const ALL: [Self; 8] = [
        Self::StateTransition,
        Self::ActionEffect,
        Self::Receipt,
        Self::ReceiptTimestamp,
        Self::RenderedMessage,
        Self::ProviderEvent,
        Self::ProviderEventId,
        Self::ResourceClass,
    ];
}

impl SecuritySensitiveEnum for ComparisonField {
    const FIELD: &'static str = "comparison_field";

    fn from_wire(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.as_str() == value)
    }
}

/// How a compared field differed. Never *what* it contained.
///
/// `tools/oracle/vocabulary.py`'s `Relation`, member for member.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Relation {
    /// Both sides carried the field, with different values.
    ValueDiffers,
    /// The reference engine carried the field and the candidate did not.
    AbsentInCandidate,
    /// The candidate carried the field and the reference engine did not.
    AbsentInReference,
    /// The two sides disagreed about the field's shape.
    TypeDiffers,
    /// The same members appeared in a different order.
    OrderDiffers,
    /// The field is registered nondeterministic and was not compared.
    MaskedNondeterministic,
}

impl Relation {
    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValueDiffers => "value_differs",
            Self::AbsentInCandidate => "absent_in_candidate",
            Self::AbsentInReference => "absent_in_reference",
            Self::TypeDiffers => "type_differs",
            Self::OrderDiffers => "order_differs",
            Self::MaskedNondeterministic => "masked_nondeterministic",
        }
    }

    /// Every relation this build defines.
    pub const ALL: [Self; 6] = [
        Self::ValueDiffers,
        Self::AbsentInCandidate,
        Self::AbsentInReference,
        Self::TypeDiffers,
        Self::OrderDiffers,
        Self::MaskedNondeterministic,
    ];
}

impl SecuritySensitiveEnum for Relation {
    const FIELD: &'static str = "relation";

    fn from_wire(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|relation| relation.as_str() == value)
    }
}

/// The kind of action an envelope carries.
///
/// One member per row of the effect-suppression seam table in
/// `docs/improvement-plan/implementation/M2-parity-harness.md`, plus the
/// deliberate silence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ActionKind {
    /// A reply posted into an existing Slack thread.
    SlackThreadReply,
    /// A message posted to a Slack channel outside any thread.
    SlackChannelPost,
    /// An approval card posted for one pending confirmation gate.
    SlackApprovalCard,
    /// An in-place update of a decided approval message.
    SlackDecisionUpdate,
    /// A ticket dispatch that creates a pending gate and releases nothing.
    TicketDispatch,
    /// A confirmation of one already-pending gate.
    TicketConfirm,
    /// A typed approval or rejection applied to one job.
    TicketDecision,
    /// One outbound Telegram message.
    TelegramSend,
    /// One GitHub issue create, reply, checklist or manage action.
    GitHubIssueAction,
    /// One outbound Support email.
    SupportEmailSend,
    /// A deliberate decision to do nothing.
    NoAction,
}

impl ActionKind {
    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SlackThreadReply => "slack-thread-reply",
            Self::SlackChannelPost => "slack-channel-post",
            Self::SlackApprovalCard => "slack-approval-card",
            Self::SlackDecisionUpdate => "slack-decision-update",
            Self::TicketDispatch => "ticket-dispatch",
            Self::TicketConfirm => "ticket-confirm",
            Self::TicketDecision => "ticket-decision",
            Self::TelegramSend => "telegram-send",
            Self::GitHubIssueAction => "github-issue-action",
            Self::SupportEmailSend => "support-email-send",
            Self::NoAction => "no-action",
        }
    }

    /// Every action kind this build defines.
    pub const ALL: [Self; 11] = [
        Self::SlackThreadReply,
        Self::SlackChannelPost,
        Self::SlackApprovalCard,
        Self::SlackDecisionUpdate,
        Self::TicketDispatch,
        Self::TicketConfirm,
        Self::TicketDecision,
        Self::TelegramSend,
        Self::GitHubIssueAction,
        Self::SupportEmailSend,
        Self::NoAction,
    ];

    /// The fields one action of this kind carries, in declaration order.
    #[must_use]
    pub const fn fields(self) -> &'static [ActionField] {
        match self {
            Self::SlackThreadReply => &SLACK_THREAD_REPLY_FIELDS,
            Self::SlackChannelPost => &SLACK_CHANNEL_POST_FIELDS,
            Self::SlackApprovalCard => &SLACK_APPROVAL_CARD_FIELDS,
            Self::SlackDecisionUpdate => &SLACK_DECISION_UPDATE_FIELDS,
            Self::TicketDispatch | Self::TicketConfirm => &TICKET_GATE_FIELDS,
            Self::TicketDecision => &TICKET_DECISION_FIELDS,
            Self::TelegramSend => &TELEGRAM_SEND_FIELDS,
            Self::GitHubIssueAction => &GITHUB_ISSUE_ACTION_FIELDS,
            Self::SupportEmailSend => &SUPPORT_EMAIL_SEND_FIELDS,
            Self::NoAction => &NO_ACTION_FIELDS,
        }
    }
}

const SLACK_THREAD_REPLY_FIELDS: [ActionField; 3] = [
    ActionField::id("channel", ComparisonField::Receipt),
    ActionField::id("parent", ComparisonField::ReceiptTimestamp),
    ActionField::text("text", ComparisonField::RenderedMessage),
];

const SLACK_CHANNEL_POST_FIELDS: [ActionField; 2] = [
    ActionField::id("channel", ComparisonField::Receipt),
    ActionField::text("text", ComparisonField::RenderedMessage),
];

const SLACK_APPROVAL_CARD_FIELDS: [ActionField; 5] = [
    ActionField::id("channel", ComparisonField::Receipt),
    ActionField::id("parent", ComparisonField::ReceiptTimestamp),
    ActionField::id("job_id", ComparisonField::ProviderEventId),
    ActionField::id("issue_url", ComparisonField::Receipt),
    ActionField::text("issue_title", ComparisonField::RenderedMessage),
];

const SLACK_DECISION_UPDATE_FIELDS: [ActionField; 3] = [
    ActionField::id("channel", ComparisonField::Receipt),
    ActionField::id("message_ts", ComparisonField::ReceiptTimestamp),
    ActionField::text("text", ComparisonField::RenderedMessage),
];

/// Shared by dispatch and confirm: the same coordinates name the same gate, and
/// the two are told apart by their [`ActionKind`] rather than by their fields.
const TICKET_GATE_FIELDS: [ActionField; 2] = [
    ActionField::id("issue_url", ComparisonField::Receipt),
    ActionField::id("source_key", ComparisonField::Receipt),
];

const TICKET_DECISION_FIELDS: [ActionField; 4] = [
    ActionField::id("job_id", ComparisonField::ProviderEventId),
    ActionField::id("source_key", ComparisonField::Receipt),
    ActionField::id("decision", ComparisonField::StateTransition),
    ActionField::text("reason", ComparisonField::RenderedMessage),
];

const TELEGRAM_SEND_FIELDS: [ActionField; 2] = [
    ActionField::id("chat", ComparisonField::Receipt),
    ActionField::text("text", ComparisonField::RenderedMessage),
];

const GITHUB_ISSUE_ACTION_FIELDS: [ActionField; 3] = [
    ActionField::id("operation", ComparisonField::StateTransition),
    ActionField::id("issue_url", ComparisonField::Receipt),
    ActionField::text("body", ComparisonField::RenderedMessage),
];

const SUPPORT_EMAIL_SEND_FIELDS: [ActionField; 4] = [
    ActionField::id("action_id", ComparisonField::ProviderEventId),
    ActionField::id("recipient", ComparisonField::Receipt),
    ActionField::text("subject", ComparisonField::RenderedMessage),
    ActionField::text("body", ComparisonField::RenderedMessage),
];

const NO_ACTION_FIELDS: [ActionField; 1] =
    [ActionField::id("reason", ComparisonField::StateTransition)];

impl SecuritySensitiveEnum for ActionKind {
    const FIELD: &'static str = "kind";

    fn from_wire(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }
}

/// How one field of an action is bounded, normalized and compared.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionField {
    name: &'static str,
    compared_as: ComparisonField,
    text: bool,
}

impl ActionField {
    const fn id(name: &'static str, compared_as: ComparisonField) -> Self {
        Self {
            name,
            compared_as,
            text: false,
        }
    }

    const fn text(name: &'static str, compared_as: ComparisonField) -> Self {
        Self {
            name,
            compared_as,
            text: true,
        }
    }

    /// The member name this field takes in the canonical document.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// The registered comparison field a difference here is reported under.
    #[must_use]
    pub const fn compared_as(self) -> ComparisonField {
        self.compared_as
    }

    /// Whether the field carries rendered text rather than an identifier.
    ///
    /// Text fields admit newlines and tabs and are whitespace-collapsed by
    /// [`IntendedAction::normalized`]; identifier fields admit no control
    /// characters at all and are compared verbatim.
    #[must_use]
    pub const fn is_text(self) -> bool {
        self.text
    }

    const fn max_bytes(self) -> usize {
        if self.text {
            MAX_ACTION_TEXT_BYTES
        } else {
            MAX_ACTION_ID_BYTES
        }
    }
}

/// One action an engine decided to perform, and has not performed.
///
/// Held as a kind plus its declared fields rather than as a Rust enum with one
/// variant per kind, because every consumer in this milestone — the canonical
/// encoder, the normalizer, the comparator and the store — walks the fields
/// generically. [`ActionKind::fields`] is the closed schema, and
/// [`IntendedAction::new`] refuses any field list that does not match it exactly,
/// so the type is as closed as a variant-per-kind enum while the comparator stays
/// one loop instead of eleven.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IntendedAction {
    kind: ActionKind,
    values: Vec<String>,
}

impl IntendedAction {
    /// Build one action from its declared field values, in declaration order.
    ///
    /// # Errors
    ///
    /// Returns [`ParityError::InvalidBody`] when the value count differs from
    /// [`ActionKind::fields`], and [`ParityError::Field`] when a value is empty,
    /// over-long or carries a control character its field does not admit.
    pub fn new(kind: ActionKind, values: Vec<String>) -> Result<Self, ParityError> {
        let fields = kind.fields();
        if values.len() != fields.len() {
            return Err(ParityError::InvalidBody);
        }
        for (field, value) in fields.iter().zip(&values) {
            validate_field(*field, value)?;
        }
        Ok(Self { kind, values })
    }

    /// A deliberate decision to do nothing, with the reason that decided it.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn no_action(reason: &str) -> Result<Self, ParityError> {
        Self::new(ActionKind::NoAction, vec![reason.to_owned()])
    }

    /// The kind of action.
    #[must_use]
    pub const fn kind(&self) -> ActionKind {
        self.kind
    }

    /// The field values, in [`ActionKind::fields`] order.
    #[must_use]
    pub fn values(&self) -> &[String] {
        &self.values
    }

    /// Look up one field's value by its declared name.
    #[must_use]
    pub fn value(&self, name: &str) -> Option<&str> {
        self.kind
            .fields()
            .iter()
            .position(|field| field.name() == name)
            .and_then(|index| self.values.get(index))
            .map(String::as_str)
    }

    /// The comparable form of this action.
    ///
    /// Two typed rules, and no others:
    ///
    /// - a field registered masked in `tools/oracle/fields.json` is replaced by
    ///   [`MASKED_PLACEHOLDER`], because its value is approved-nondeterministic
    ///   and comparing it would report clock skew as a parity regression;
    /// - a text field is whitespace-collapsed — every run of whitespace becomes
    ///   one space and the ends are trimmed — because the comparison is of
    ///   rendered message *structure*, which is what the registry's own
    ///   description of `rendered_message` says.
    ///
    /// Identifier fields that are not masked pass through byte for byte. Nothing
    /// here lowercases, truncates or reorders: a normalization that could make
    /// two genuinely different actions equal would convert a missing gate into a
    /// false one.
    #[must_use]
    pub fn normalized(&self) -> Self {
        let values = self
            .kind
            .fields()
            .iter()
            .zip(&self.values)
            .map(|(field, value)| {
                if field.compared_as().masked() {
                    MASKED_PLACEHOLDER.to_owned()
                } else if field.is_text() {
                    collapse_whitespace(value)
                } else {
                    value.clone()
                }
            })
            .collect();
        Self {
            kind: self.kind,
            values,
        }
    }

    fn to_body(&self) -> JsonValue {
        let mut entries = Vec::with_capacity(self.values.len() + 1);
        entries.push((
            "kind".to_owned(),
            JsonValue::String(self.kind.as_str().to_owned()),
        ));
        for (field, value) in self.kind.fields().iter().zip(&self.values) {
            entries.push((field.name().to_owned(), JsonValue::String(value.clone())));
        }
        JsonValue::Object(entries)
    }

    fn from_body(body: &JsonValue) -> Result<Self, ParityError> {
        let kind: ActionKind = decode_security_enum(&required_string(body, "kind")?)?;
        let fields = kind.fields();
        let mut names = Vec::with_capacity(fields.len() + 1);
        names.push("kind");
        names.extend(fields.iter().map(|field| field.name()));
        exact_fields(body, &names)?;
        let mut values = Vec::with_capacity(fields.len());
        for field in fields {
            values.push(required_string(body, field.name())?);
        }
        Self::new(kind, values)
    }
}

/// One engine's decision, at one position in one source event's handling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntendedActionEnvelope {
    scope: String,
    source_key: String,
    engine: ParityEngine,
    sequence: u32,
    action: IntendedAction,
    observed_at_ms: i64,
}

impl IntendedActionEnvelope {
    /// Record one intended action.
    ///
    /// `sequence` orders the actions one engine decided for one source key,
    /// starting at zero. `observed_at_ms` is the caller's clock; this crate
    /// reads none.
    ///
    /// # Errors
    ///
    /// Returns [`ParityError::Field`] for an empty, over-long or control-bearing
    /// scope or source key, and for a negative `observed_at_ms`.
    pub fn new(
        scope: &str,
        source_key: &str,
        engine: ParityEngine,
        sequence: u32,
        action: IntendedAction,
        observed_at_ms: i64,
    ) -> Result<Self, ParityError> {
        validate_identifier(scope, MAX_SCOPE_BYTES, "scope")?;
        validate_identifier(source_key, MAX_SOURCE_KEY_BYTES, "source_key")?;
        if observed_at_ms < 0 {
            return Err(ParityError::Field {
                field: "observed_at_ms",
                error: ValueError::Empty,
            });
        }
        Ok(Self {
            scope: scope.to_owned(),
            source_key: source_key.to_owned(),
            engine,
            sequence,
            action,
            observed_at_ms,
        })
    }

    /// The parity scope this decision belongs to.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The durable source key of the event that provoked the decision.
    #[must_use]
    pub fn source_key(&self) -> &str {
        &self.source_key
    }

    /// Which engine decided.
    #[must_use]
    pub const fn engine(&self) -> ParityEngine {
        self.engine
    }

    /// Position in this engine's decision stream for this source key.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// The action itself.
    #[must_use]
    pub const fn action(&self) -> &IntendedAction {
        &self.action
    }

    /// The caller's clock at the moment of the decision.
    #[must_use]
    pub const fn observed_at_ms(&self) -> i64 {
        self.observed_at_ms
    }

    /// Stable schema identifier for this document version.
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        INTENDED_ACTION_SCHEMA_V1
    }

    /// The document body, with keys the canonical encoder will sort.
    #[must_use]
    pub fn to_document(&self) -> JsonValue {
        JsonValue::Object(vec![
            ("action".to_owned(), self.action.to_body()),
            (
                "engine".to_owned(),
                JsonValue::String(self.engine.as_str().to_owned()),
            ),
            (
                "observed_at_ms".to_owned(),
                JsonValue::Integer(self.observed_at_ms),
            ),
            (
                "schema".to_owned(),
                JsonValue::String(INTENDED_ACTION_SCHEMA_V1.to_owned()),
            ),
            ("scope".to_owned(), JsonValue::String(self.scope.clone())),
            (
                "sequence".to_owned(),
                JsonValue::Integer(i64::from(self.sequence)),
            ),
            (
                "source_key".to_owned(),
                JsonValue::String(self.source_key.clone()),
            ),
        ])
    }

    /// The canonical bytes of this envelope.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.to_document().to_canonical_bytes()
    }

    /// The SHA-256 of this envelope's canonical bytes.
    ///
    /// Derived rather than stored: a carried digest is a second copy of an
    /// answer that can drift from what it names.
    #[must_use]
    pub fn content_digest(&self) -> Sha256Digest {
        Sha256::digest(&self.to_canonical_bytes())
    }

    /// Decode an envelope from canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ParityError::DocumentTooLarge`] above
    /// [`MAX_ENVELOPE_CANONICAL_BYTES`], [`ParityError::Codec`] for
    /// non-canonical JSON or an unknown engine or action kind,
    /// [`ParityError::UnknownSchema`] for a schema this build does not serve,
    /// [`ParityError::InvalidBody`] for a body that is not exact, and every
    /// refusal [`Self::new`] makes.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, ParityError> {
        if payload.len() > MAX_ENVELOPE_CANONICAL_BYTES {
            return Err(ParityError::DocumentTooLarge {
                max_bytes: MAX_ENVELOPE_CANONICAL_BYTES,
                actual_bytes: payload.len(),
            });
        }
        Self::from_document(&parse_canonical(payload)?)
    }

    /// Decode an envelope from a parsed document.
    ///
    /// # Errors
    ///
    /// See [`Self::from_canonical_bytes`].
    pub fn from_document(body: &JsonValue) -> Result<Self, ParityError> {
        exact_fields(
            body,
            &[
                "action",
                "engine",
                "observed_at_ms",
                "schema",
                "scope",
                "sequence",
                "source_key",
            ],
        )?;
        if required_string(body, "schema")? != INTENDED_ACTION_SCHEMA_V1 {
            return Err(ParityError::UnknownSchema);
        }
        let sequence = required_integer(body, "sequence")?;
        let sequence = u32::try_from(sequence).map_err(|_| ParityError::Field {
            field: "sequence",
            error: ValueError::TooLong {
                max_bytes: 0,
                actual_bytes: 0,
            },
        })?;
        Self::new(
            &required_string(body, "scope")?,
            &required_string(body, "source_key")?,
            decode_security_enum(&required_string(body, "engine")?)?,
            sequence,
            IntendedAction::from_body(body.get("action").ok_or(ParityError::InvalidBody)?)?,
            required_integer(body, "observed_at_ms")?,
        )
    }
}

/// The verdict of comparing one pair of envelopes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ComparisonVerdict {
    /// Both engines decided the same normalized action.
    Match,
    /// Both engines decided, and the normalized actions differ.
    Mismatch,
    /// Only the shadow candidate decided anything at this position.
    ShadowOnly,
    /// Only the reference engine decided anything at this position.
    LegacyOnly,
}

impl ComparisonVerdict {
    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Mismatch => "mismatch",
            Self::ShadowOnly => "shadow_only",
            Self::LegacyOnly => "legacy_only",
        }
    }

    /// Every verdict this build defines.
    pub const ALL: [Self; 4] = [
        Self::Match,
        Self::Mismatch,
        Self::ShadowOnly,
        Self::LegacyOnly,
    ];
}

impl SecuritySensitiveEnum for ComparisonVerdict {
    const FIELD: &'static str = "verdict";

    fn from_wire(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|verdict| verdict.as_str() == value)
    }
}

/// One field-level difference, in the oracle's closed vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FieldDifference {
    field: ComparisonField,
    relation: Relation,
}

impl FieldDifference {
    /// Name a difference.
    #[must_use]
    pub const fn new(field: ComparisonField, relation: Relation) -> Self {
        Self { field, relation }
    }

    /// The registered comparison field that differed.
    #[must_use]
    pub const fn field(self) -> ComparisonField {
        self.field
    }

    /// How it differed.
    #[must_use]
    pub const fn relation(self) -> Relation {
        self.relation
    }

    fn to_body(self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "field".to_owned(),
                JsonValue::String(self.field.as_str().to_owned()),
            ),
            (
                "relation".to_owned(),
                JsonValue::String(self.relation.as_str().to_owned()),
            ),
        ])
    }
}

/// The result of comparing one position of two engines' decision streams.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Comparison {
    verdict: ComparisonVerdict,
    differences: Vec<FieldDifference>,
}

impl Comparison {
    /// The verdict.
    #[must_use]
    pub const fn verdict(&self) -> ComparisonVerdict {
        self.verdict
    }

    /// The field-level differences, sorted and deduplicated.
    #[must_use]
    pub fn differences(&self) -> &[FieldDifference] {
        &self.differences
    }

    /// The document body, with keys the canonical encoder will sort.
    #[must_use]
    pub fn to_document(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "differences".to_owned(),
                JsonValue::Array(
                    self.differences
                        .iter()
                        .map(|difference| difference.to_body())
                        .collect(),
                ),
            ),
            (
                "verdict".to_owned(),
                JsonValue::String(self.verdict.as_str().to_owned()),
            ),
        ])
    }

    /// The canonical bytes of this comparison.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.to_document().to_canonical_bytes()
    }

    /// The SHA-256 of this comparison's canonical bytes.
    #[must_use]
    pub fn content_digest(&self) -> Sha256Digest {
        Sha256::digest(&self.to_canonical_bytes())
    }
}

/// Compare one position of two engines' decision streams.
///
/// Both sides are normalized first, so an approved-nondeterministic field can
/// never produce a difference and rendered text differing only in whitespace
/// can never produce one either.
///
/// Absence is a verdict, not a gap. A shadow that decided nothing where the
/// reference engine posted is [`ComparisonVerdict::LegacyOnly`], reported as
/// [`Relation::AbsentInCandidate`] on [`ComparisonField::ActionEffect`] — the
/// property the whole milestone rests on is that silence is diffable.
///
/// Two envelopes of different kinds differ on [`ComparisonField::ActionEffect`]
/// alone: their field sets are not comparable member for member, and reporting
/// per-field differences between a Slack post and an email would be inventing a
/// correspondence that does not exist.
#[must_use]
pub fn compare(
    shadow: Option<&IntendedActionEnvelope>,
    legacy: Option<&IntendedActionEnvelope>,
) -> Comparison {
    let (shadow, legacy) = match (shadow, legacy) {
        (None, None) => {
            return Comparison {
                verdict: ComparisonVerdict::Match,
                differences: Vec::new(),
            };
        }
        (Some(_), None) => {
            return Comparison {
                verdict: ComparisonVerdict::ShadowOnly,
                differences: vec![FieldDifference::new(
                    ComparisonField::ActionEffect,
                    Relation::AbsentInReference,
                )],
            };
        }
        (None, Some(_)) => {
            return Comparison {
                verdict: ComparisonVerdict::LegacyOnly,
                differences: vec![FieldDifference::new(
                    ComparisonField::ActionEffect,
                    Relation::AbsentInCandidate,
                )],
            };
        }
        (Some(shadow), Some(legacy)) => {
            (shadow.action().normalized(), legacy.action().normalized())
        }
    };

    let mut differences = Vec::new();
    if shadow.kind() != legacy.kind() {
        differences.push(FieldDifference::new(
            ComparisonField::ActionEffect,
            Relation::TypeDiffers,
        ));
    } else {
        for (index, field) in shadow.kind().fields().iter().enumerate() {
            let left = shadow.values().get(index);
            let right = legacy.values().get(index);
            if left != right {
                differences.push(FieldDifference::new(
                    field.compared_as(),
                    Relation::ValueDiffers,
                ));
            }
        }
    }
    differences.sort_unstable();
    differences.dedup();
    let verdict = if differences.is_empty() {
        ComparisonVerdict::Match
    } else {
        ComparisonVerdict::Mismatch
    };
    Comparison {
        verdict,
        differences,
    }
}

/// How a difference was accounted for.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Classification {
    /// The two engines agreed.
    Parity,
    /// The difference is registered, with a reason and an owner.
    KnownDeviation,
    /// The difference is unaccounted for.
    ///
    /// The default, and deliberately so: an unmatched mismatch is always a
    /// regression, because a harness that could resolve an unregistered
    /// difference in the candidate's favour would be scoring its own opinion.
    Regression,
}

impl Classification {
    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parity => "parity",
            Self::KnownDeviation => "known_deviation",
            Self::Regression => "regression",
        }
    }

    /// Whether this classification counts towards a passing score.
    #[must_use]
    pub const fn is_accounted(self) -> bool {
        matches!(self, Self::Parity | Self::KnownDeviation)
    }

    /// Every classification this build defines.
    pub const ALL: [Self; 3] = [Self::Parity, Self::KnownDeviation, Self::Regression];
}

impl SecuritySensitiveEnum for Classification {
    const FIELD: &'static str = "classification";

    fn from_wire(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }
}

/// Why a registered deviation is acceptable.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DeviationReason {
    /// The reference engine's behaviour was wrong and this one is not.
    BugFix,
    /// The change was chosen, and the choice is recorded.
    DeliberateImprovement,
}

impl DeviationReason {
    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BugFix => "bug-fix",
            Self::DeliberateImprovement => "deliberate-improvement",
        }
    }

    /// Every reason this build defines.
    pub const ALL: [Self; 2] = [Self::BugFix, Self::DeliberateImprovement];
}

impl SecuritySensitiveEnum for DeviationReason {
    const FIELD: &'static str = "reason";

    fn from_wire(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }
}

/// One registered known deviation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviationEntry {
    id: String,
    scope: String,
    action_kind: ActionKind,
    field: ComparisonField,
    relation: Relation,
    reason: DeviationReason,
}

impl DeviationEntry {
    /// Register one deviation.
    ///
    /// # Errors
    ///
    /// Returns [`ParityError::Field`] for an empty, over-long or control-bearing
    /// identifier or scope.
    pub fn new(
        id: &str,
        scope: &str,
        action_kind: ActionKind,
        field: ComparisonField,
        relation: Relation,
        reason: DeviationReason,
    ) -> Result<Self, ParityError> {
        validate_identifier(id, MAX_DEVIATION_ID_BYTES, "deviation_id")?;
        validate_identifier(scope, MAX_SCOPE_BYTES, "scope")?;
        Ok(Self {
            id: id.to_owned(),
            scope: scope.to_owned(),
            action_kind,
            field,
            relation,
            reason,
        })
    }

    /// The registry identifier a classification cites.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The parity scope this entry covers.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The action kind this entry covers.
    #[must_use]
    pub const fn action_kind(&self) -> ActionKind {
        self.action_kind
    }

    /// The comparison field this entry covers.
    #[must_use]
    pub const fn field(&self) -> ComparisonField {
        self.field
    }

    /// The relation this entry covers.
    #[must_use]
    pub const fn relation(&self) -> Relation {
        self.relation
    }

    /// Why the deviation is acceptable.
    #[must_use]
    pub const fn reason(&self) -> DeviationReason {
        self.reason
    }

    fn to_body(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "action_kind".to_owned(),
                JsonValue::String(self.action_kind.as_str().to_owned()),
            ),
            (
                "field".to_owned(),
                JsonValue::String(self.field.as_str().to_owned()),
            ),
            ("id".to_owned(), JsonValue::String(self.id.clone())),
            (
                "reason".to_owned(),
                JsonValue::String(self.reason.as_str().to_owned()),
            ),
            (
                "relation".to_owned(),
                JsonValue::String(self.relation.as_str().to_owned()),
            ),
            ("scope".to_owned(), JsonValue::String(self.scope.clone())),
        ])
    }

    fn from_body(body: &JsonValue) -> Result<Self, ParityError> {
        exact_fields(
            body,
            &["action_kind", "field", "id", "reason", "relation", "scope"],
        )?;
        Self::new(
            &required_string(body, "id")?,
            &required_string(body, "scope")?,
            decode_security_enum(&required_string(body, "action_kind")?)?,
            decode_security_enum(&required_string(body, "field")?)?,
            decode_security_enum(&required_string(body, "relation")?)?,
            decode_security_enum(&required_string(body, "reason")?)?,
        )
    }
}

/// The digest-pinned set of deviations a gate decision was taken against.
///
/// The registry's own digest is what a [`gate decision`](ParityScore) records,
/// so a later edit to the human registry cannot retroactively rewrite what was
/// known when a scope was promoted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviationRegistry {
    entries: Vec<DeviationEntry>,
}

impl DeviationRegistry {
    /// Build a registry from its entries.
    ///
    /// Entries are sorted into a canonical order, so a registry built in any
    /// order digests identically.
    ///
    /// # Errors
    ///
    /// Returns [`ParityError::TooManyDeviations`] above [`MAX_DEVIATIONS`] and
    /// [`ParityError::DuplicateDeviation`] when one identifier appears twice.
    pub fn new(mut entries: Vec<DeviationEntry>) -> Result<Self, ParityError> {
        if entries.len() > MAX_DEVIATIONS {
            return Err(ParityError::TooManyDeviations {
                max: MAX_DEVIATIONS,
                actual: entries.len(),
            });
        }
        entries.sort();
        if let Some(pair) = entries.windows(2).find(|pair| pair[0].id == pair[1].id) {
            return Err(ParityError::DuplicateDeviation {
                id: pair[0].id.clone(),
            });
        }
        Ok(Self { entries })
    }

    /// An empty registry, under which every mismatch is a regression.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// The registered entries, in canonical order.
    #[must_use]
    pub fn entries(&self) -> &[DeviationEntry] {
        &self.entries
    }

    /// Classify one comparison against this registry.
    ///
    /// A comparison with no differences is [`Classification::Parity`]. A
    /// comparison whose *every* difference is registered for this scope and
    /// action kind is [`Classification::KnownDeviation`], and the matched entry
    /// identifiers are returned beside it. Anything else is
    /// [`Classification::Regression`] — including a comparison where some
    /// differences are registered and one is not, because a partly explained
    /// mismatch is an unexplained mismatch.
    #[must_use]
    pub fn classify(
        &self,
        scope: &str,
        action_kind: ActionKind,
        comparison: &Comparison,
    ) -> (Classification, Vec<String>) {
        if comparison.differences().is_empty() {
            return (Classification::Parity, Vec::new());
        }
        let mut matched = Vec::with_capacity(comparison.differences().len());
        for difference in comparison.differences() {
            let Some(entry) = self.entries.iter().find(|entry| {
                entry.scope == scope
                    && entry.action_kind == action_kind
                    && entry.field == difference.field()
                    && entry.relation == difference.relation()
            }) else {
                return (Classification::Regression, Vec::new());
            };
            matched.push(entry.id.clone());
        }
        matched.sort();
        matched.dedup();
        (Classification::KnownDeviation, matched)
    }

    /// Stable schema identifier for this document version.
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        DEVIATION_REGISTRY_SCHEMA_V1
    }

    /// The document body, with keys the canonical encoder will sort.
    #[must_use]
    pub fn to_document(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "entries".to_owned(),
                JsonValue::Array(self.entries.iter().map(DeviationEntry::to_body).collect()),
            ),
            (
                "schema".to_owned(),
                JsonValue::String(DEVIATION_REGISTRY_SCHEMA_V1.to_owned()),
            ),
        ])
    }

    /// The canonical bytes of this registry.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.to_document().to_canonical_bytes()
    }

    /// The SHA-256 a gate decision pins.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        Sha256::digest(&self.to_canonical_bytes())
    }

    /// Decode a registry from canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ParityError::DocumentTooLarge`] above
    /// [`MAX_REGISTRY_CANONICAL_BYTES`], [`ParityError::Codec`] for
    /// non-canonical JSON or an unknown spelling,
    /// [`ParityError::UnknownSchema`], [`ParityError::InvalidBody`], and every
    /// refusal [`Self::new`] makes.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, ParityError> {
        if payload.len() > MAX_REGISTRY_CANONICAL_BYTES {
            return Err(ParityError::DocumentTooLarge {
                max_bytes: MAX_REGISTRY_CANONICAL_BYTES,
                actual_bytes: payload.len(),
            });
        }
        let body = parse_canonical(payload)?;
        exact_fields(&body, &["entries", "schema"])?;
        if required_string(&body, "schema")? != DEVIATION_REGISTRY_SCHEMA_V1 {
            return Err(ParityError::UnknownSchema);
        }
        let JsonValue::Array(items) = body.get("entries").ok_or(ParityError::InvalidBody)? else {
            return Err(ParityError::InvalidBody);
        };
        let mut entries = Vec::with_capacity(items.len());
        for item in items {
            entries.push(DeviationEntry::from_body(item)?);
        }
        Self::new(entries)
    }
}

/// How representative one comparison is of the traffic a gate is about.
///
/// Category is human judgement recorded in a trace header and reviewed with the
/// fixture, never inferred from the comparison itself. That is why it is an
/// input to the score rather than something the scorer derives.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Category {
    /// The path the feature exists to serve.
    Happy,
    /// A failure the system must handle.
    Error,
    /// A boundary, a bound, or an unusual but legal input.
    Edge,
    /// Breadth across inputs of the same kind.
    Variety,
    /// Captured from real traffic on a live scope.
    ProductionRepresentative,
}

impl Category {
    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Happy => "happy",
            Self::Error => "error",
            Self::Edge => "edge",
            Self::Variety => "variety",
            Self::ProductionRepresentative => "production-representative",
        }
    }

    /// The fixed-point weight this category carries, scaled by [`WEIGHT_SCALE`].
    ///
    /// The plan's weights: happy ×1, error ×2, edge ×2, variety ×1.5,
    /// production-representative ×3.
    #[must_use]
    pub const fn weight(self) -> i64 {
        match self {
            Self::Happy => WEIGHT_SCALE,
            Self::Error | Self::Edge => 2 * WEIGHT_SCALE,
            Self::Variety => 3 * WEIGHT_SCALE / 2,
            Self::ProductionRepresentative => 3 * WEIGHT_SCALE,
        }
    }

    /// Every category this build defines.
    pub const ALL: [Self; 5] = [
        Self::Happy,
        Self::Error,
        Self::Edge,
        Self::Variety,
        Self::ProductionRepresentative,
    ];
}

impl SecuritySensitiveEnum for Category {
    const FIELD: &'static str = "category";

    fn from_wire(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|category| category.as_str() == value)
    }
}

/// What a score licenses.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Band {
    /// 0–30. The scope does not go anywhere.
    Block,
    /// 31–60. Evidence exists and does not support promotion.
    Caution,
    /// 61–85. The scope may run in shadow.
    ShadowReady,
    /// 86–100. The scope may begin *progressive* cutover, on an owner's
    /// acknowledgement per scope. A band is evidence for a decision, never the
    /// decision, and never a flip.
    CutoverReady,
}

/// Highest score in [`Band::Block`].
pub const BAND_BLOCK_MAX: u32 = 30;

/// Highest score in [`Band::Caution`].
pub const BAND_CAUTION_MAX: u32 = 60;

/// Highest score in [`Band::ShadowReady`].
pub const BAND_SHADOW_READY_MAX: u32 = 85;

impl Band {
    /// The band one score falls in.
    ///
    /// # Errors
    ///
    /// Returns [`ParityError::ScoreUnrepresentable`] above [`MAX_SCORE`].
    pub const fn for_score(score: u32) -> Result<Self, ParityError> {
        match score {
            0..=BAND_BLOCK_MAX => Ok(Self::Block),
            31..=BAND_CAUTION_MAX => Ok(Self::Caution),
            61..=BAND_SHADOW_READY_MAX => Ok(Self::ShadowReady),
            86..=MAX_SCORE => Ok(Self::CutoverReady),
            _ => Err(ParityError::ScoreUnrepresentable),
        }
    }

    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Caution => "caution",
            Self::ShadowReady => "shadow-ready",
            Self::CutoverReady => "cutover-ready",
        }
    }

    /// Every band this build defines.
    pub const ALL: [Self; 4] = [
        Self::Block,
        Self::Caution,
        Self::ShadowReady,
        Self::CutoverReady,
    ];
}

impl SecuritySensitiveEnum for Band {
    const FIELD: &'static str = "band";

    fn from_wire(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|band| band.as_str() == value)
    }
}

/// One scored comparison: its category and how it classified.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScoredComparison {
    /// How representative the comparison is.
    pub category: Category,
    /// How the difference was accounted for.
    pub classification: Classification,
}

/// Per-category counts behind one score.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CategoryCount {
    /// Comparisons scored in this category.
    pub total: u32,
    /// Of those, the ones that classified parity or known-deviation.
    pub accounted: u32,
}

/// A weighted parity confidence score over one corpus of comparisons.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParityScore {
    score: u32,
    band: Band,
    counts: [CategoryCount; Category::ALL.len()],
}

impl ParityScore {
    /// Score one corpus.
    ///
    /// The arithmetic is integer end to end: each comparison contributes its
    /// category's fixed-point weight to a denominator, and to the numerator only
    /// when it classified parity or known-deviation. The quotient is truncated
    /// rather than rounded, so a score never rounds *up* into a higher band —
    /// a gate that promoted a scope on a rounding artefact would be a false gate.
    ///
    /// # Errors
    ///
    /// Returns [`ParityError::EmptyCorpus`] for a corpus with no comparisons —
    /// an unmeasured scope is not a scope that measured zero — and
    /// [`ParityError::ScoreUnrepresentable`] when the weighted totals overflow.
    pub fn compute(comparisons: &[ScoredComparison]) -> Result<Self, ParityError> {
        if comparisons.is_empty() {
            return Err(ParityError::EmptyCorpus);
        }
        let mut counts = [CategoryCount::default(); Category::ALL.len()];
        let mut weighted_total: i64 = 0;
        let mut weighted_accounted: i64 = 0;
        for scored in comparisons {
            let index = Category::ALL
                .iter()
                .position(|category| *category == scored.category)
                .ok_or(ParityError::ScoreUnrepresentable)?;
            let weight = scored.category.weight();
            counts[index].total = counts[index]
                .total
                .checked_add(1)
                .ok_or(ParityError::ScoreUnrepresentable)?;
            weighted_total = weighted_total
                .checked_add(weight)
                .ok_or(ParityError::ScoreUnrepresentable)?;
            if scored.classification.is_accounted() {
                counts[index].accounted = counts[index]
                    .accounted
                    .checked_add(1)
                    .ok_or(ParityError::ScoreUnrepresentable)?;
                weighted_accounted = weighted_accounted
                    .checked_add(weight)
                    .ok_or(ParityError::ScoreUnrepresentable)?;
            }
        }
        let scaled = weighted_accounted
            .checked_mul(i64::from(MAX_SCORE))
            .ok_or(ParityError::ScoreUnrepresentable)?;
        let score = u32::try_from(scaled / weighted_total)
            .map_err(|_| ParityError::ScoreUnrepresentable)?;
        Ok(Self {
            score,
            band: Band::for_score(score)?,
            counts,
        })
    }

    /// The score, out of [`MAX_SCORE`].
    #[must_use]
    pub const fn score(self) -> u32 {
        self.score
    }

    /// The band the score falls in.
    #[must_use]
    pub const fn band(self) -> Band {
        self.band
    }

    /// The count recorded for one category.
    #[must_use]
    pub fn count(self, category: Category) -> CategoryCount {
        Category::ALL
            .iter()
            .position(|candidate| *candidate == category)
            .and_then(|index| self.counts.get(index).copied())
            .unwrap_or_default()
    }
}

/// Collapse every run of whitespace to one space and trim the ends.
fn collapse_whitespace(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for word in value.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    out
}

fn validate_field(field: ActionField, value: &str) -> Result<(), ParityError> {
    if field.is_text() {
        validate_text(value, field.max_bytes(), field.name())
    } else {
        validate_identifier(value, field.max_bytes(), field.name())
    }
}

/// Non-empty, bounded, and free of every control character.
fn validate_identifier(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), ParityError> {
    let bounded = |error| ParityError::Field { field, error };
    if value.is_empty() {
        return Err(bounded(ValueError::Empty));
    }
    if value.len() > max_bytes {
        return Err(bounded(ValueError::TooLong {
            max_bytes,
            actual_bytes: value.len(),
        }));
    }
    if value.chars().any(char::is_control) {
        return Err(bounded(ValueError::ControlCharacter));
    }
    Ok(())
}

/// Non-empty, bounded, and free of every control character but tab and newline.
///
/// Rendered messages carry line breaks; refusing them would refuse most of the
/// product's real output. Every other control character stays refused, because a
/// carriage return or an escape in a compared value is a rendering difference
/// nobody can see.
fn validate_text(value: &str, max_bytes: usize, field: &'static str) -> Result<(), ParityError> {
    let bounded = |error| ParityError::Field { field, error };
    if value.is_empty() {
        return Err(bounded(ValueError::Empty));
    }
    if value.len() > max_bytes {
        return Err(bounded(ValueError::TooLong {
            max_bytes,
            actual_bytes: value.len(),
        }));
    }
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(bounded(ValueError::ControlCharacter));
    }
    Ok(())
}

fn required_string(body: &JsonValue, field: &'static str) -> Result<String, ParityError> {
    body.get(field)
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
        .ok_or(ParityError::InvalidBody)
}

fn required_integer(body: &JsonValue, field: &'static str) -> Result<i64, ParityError> {
    body.get(field)
        .and_then(JsonValue::as_integer)
        .ok_or(ParityError::InvalidBody)
}

fn exact_fields(body: &JsonValue, fields: &[&str]) -> Result<(), ParityError> {
    let JsonValue::Object(entries) = body else {
        return Err(ParityError::InvalidBody);
    };
    if entries.len() != fields.len()
        || !fields
            .iter()
            .all(|field| entries.iter().any(|(name, _)| name == field))
    {
        return Err(ParityError::InvalidBody);
    }
    Ok(())
}
