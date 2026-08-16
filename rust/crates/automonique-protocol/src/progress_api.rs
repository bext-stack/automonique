// SPDX-License-Identifier: Elastic-2.0

//! One normalized progress frame: the shape every surface renders a live run
//! from.
//!
//! # Why this exists at all
//!
//! Before this module a live run was legible in exactly one place — the
//! terminal the daemon was started from, because the workload's stdout was
//! inherited — and the durable record held two events: the run started, and the
//! run ended. Every chat surface therefore rendered a spinner and then an
//! answer, and the desktop client had nothing to draw between them.
//!
//! [`ProgressFrame`] is the one thing all of them read. It is not a second
//! vocabulary: the `kind` is [`crate::event::EventKind`], the `authority` is
//! [`crate::event::Authority`], and the body members are the ones those kinds
//! already declare through [`crate::event::EventKind::step_rule`],
//! [`crate::event::EventKind::retry_rule`] and
//! [`crate::event::EventKind::text_rule`]. A renderer that understood the
//! normalized event stream understands this frame by construction.
//!
//! # Where a frame's `sequence` comes from, and why that matters
//!
//! It is the runner spool's sequence — the position of the `adapter_event` this
//! frame's canonical bytes are the payload of. That single choice is what makes
//! resumption cheap: the durable, hash-chained spool is the record, its
//! sequence is the cursor, and a consumer that reconnects with the last
//! sequence it rendered resumes exactly rather than approximately. A frame is
//! therefore *stamped* by the writer that appends it, and a producer upstream
//! of the spool cannot know its own sequence yet — see
//! [`ProgressFrameParts::sequence`].
//!
//! Because the sequence is the spool's, a frame that was never persisted has no
//! sequence to claim, and there is no constructor through which one could
//! borrow a neighbour's.
//!
//! # What a frame deliberately does not carry
//!
//! - **No raw provider line.** A frame's only free text is
//!   [`ProgressText`], which is bounded and refuses control characters. The
//!   provider's own JSONL never reaches a surface: the normalizer that produces
//!   these has one closed grammar, and the token it names back on refusal is
//!   already sanitized (`automonique_agents::UnknownEventKind`).
//! - **No credential, no path, no environment.** Nothing in this shape has a
//!   member one could travel through.
//! - **No transport.** These are canonical payload bytes. The framing, the
//!   socket and the subscriber machinery are deliberately elsewhere — a live
//!   fan-out authority with cursors and bounded per-subscriber queues is its own
//!   change, and this module is what it will carry.
//! - **No terminal claim.** A [`crate::event::EventKind::RunTerminal`] frame is
//!   the provider stream's end, not the supervisor's verdict. The run's terminal
//!   state is the spool's `terminal` event, written by the backend from a
//!   reaped exit status, and no frame can move it.
//!
//! # The one rule that is not a field's own
//!
//! Which body members a kind admits is a relation between `kind` and `body`,
//! and it is enforced by [`ProgressBody::new`] rather than by any member's own
//! constructor. A generated client checks each member's shape and bounds; this
//! rule stays with the Rust decoder, exactly as [`crate::codegen`] says of the
//! other cross-field rules it does not emit.

use core::fmt;
use std::error::Error;

use crate::codec::{CodecError, SecuritySensitiveEnum, decode_security_enum};
use crate::event::{
    Authority, EventError, EventKind, MAX_RETRY_AFTER_MS, MemberRule, RetryCategory, RetryContext,
    StepStatus,
};
use crate::primitives::{EpochMillis, ValueError, bounded_value};
use crate::tools::{MAX_TOOL_FIELD_BYTES, RunId};
use crate::wire::{JsonValue, parse_canonical};

/// Stable protocol name for the normalized progress stream.
pub const PROGRESS_PROTOCOL: &str = "automonique.progress";

/// Stable schema identifier for the version-one frame.
pub const PROGRESS_API_SCHEMA_V1: &str = "automonique.progress/v1";

/// Maximum UTF-8 byte length of one frame's display text.
///
/// Small on purpose. A frame is a thing to *show*, and a surface that could
/// show sixteen kilobytes cannot show more usefully; the whole assistant answer
/// travels the run's answer file, which this stream does not replace.
pub const MAX_PROGRESS_TEXT_BYTES: usize = 16 * 1024;

/// Maximum canonical bytes of one encoded frame.
///
/// The frame is stored as the payload of one runner spool event, so this must
/// stay inside the spool's own payload ceiling. The assertion below is what
/// keeps the two numbers related rather than merely both true today.
pub const MAX_PROGRESS_CANONICAL_BYTES: usize = 40 * 1024;

/// The runner spool's payload ceiling, restated as the bound this must fit.
///
/// Deliberately a literal rather than an import: `automonique-runner` depends on
/// this crate, so the dependency cannot run the other way, and a silent
/// disagreement is what the assertion exists to catch. A spool payload bound
/// that shrank below this would break the build here rather than at the first
/// oversized frame.
pub const SPOOL_PAYLOAD_CEILING_BYTES: usize = 64 * 1024;

/// Display text costs at most two canonical bytes per source byte: a quote, a
/// backslash, a newline and a tab each escape to two, and every other character
/// this type admits is carried as itself.
const TEXT_ENCODED_BYTES: usize = 2 * MAX_PROGRESS_TEXT_BYTES;

/// A run identifier costs at most two canonical bytes per source byte, by the
/// same rule.
const RUN_ID_ENCODED_BYTES: usize = 2 * MAX_TOOL_FIELD_BYTES;

/// Worst-case canonical bytes of everything in a frame that is not text: the
/// six frame members, the three body members, the four retry members, their
/// keys, their longest closed spellings and two decimal integers.
const FRAME_SCAFFOLD_BYTES: usize = 512;

const _: () = assert!(
    TEXT_ENCODED_BYTES + RUN_ID_ENCODED_BYTES + FRAME_SCAFFOLD_BYTES
        <= MAX_PROGRESS_CANONICAL_BYTES,
    "a maximal progress frame must fit the frame ceiling"
);

const _: () = assert!(
    MAX_PROGRESS_CANONICAL_BYTES <= SPOOL_PAYLOAD_CEILING_BYTES,
    "a maximal progress frame must fit one spool event payload"
);

/// A refusal while constructing, encoding or decoding a progress frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgressApiError {
    /// The shared canonical JSON codec refused the payload.
    ///
    /// Includes [`CodecError::UnknownEnumValue`] for a spelling this build does
    /// not define, which fails closed rather than decoding to a default.
    Codec(CodecError),
    /// The normalized event vocabulary refused the kind, authority or body.
    Event(EventError),
    /// A body was not the exact shape defined for its kind.
    InvalidBody,
    /// A bounded value was empty, over-long or control-bearing.
    Field {
        /// Field that was refused.
        field: &'static str,
        /// Why it was refused.
        error: ValueError,
    },
    /// A counter cannot be represented by the integer-only wire codec.
    CounterOutOfRange {
        /// Field that was outside the wire range.
        field: &'static str,
    },
    /// A frame claimed spool sequence zero, which names no appended event.
    UnwrittenSequence,
    /// An instant fell before the Unix epoch, which no observation can.
    TimeBeforeEpoch,
    /// The encoded frame is larger than [`MAX_PROGRESS_CANONICAL_BYTES`].
    FrameTooLarge {
        /// Maximum canonical bytes.
        max_bytes: usize,
        /// Bytes the frame encoded to.
        actual_bytes: usize,
    },
}

impl ProgressApiError {
    /// Stable category suitable for logs and refusal metrics.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Codec(error) => error.category(),
            Self::Event(error) => error.category(),
            Self::InvalidBody => "progress_invalid_body",
            Self::Field { .. } => "progress_invalid_field",
            Self::CounterOutOfRange { .. } => "progress_counter_out_of_range",
            Self::UnwrittenSequence => "progress_unwritten_sequence",
            Self::TimeBeforeEpoch => "progress_time_before_epoch",
            Self::FrameTooLarge { .. } => "progress_frame_too_large",
        }
    }
}

impl fmt::Display for ProgressApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "progress codec refused frame: {error}"),
            Self::Event(error) => write!(formatter, "progress vocabulary refused frame: {error}"),
            Self::InvalidBody => formatter.write_str("progress frame body is invalid"),
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
            Self::CounterOutOfRange { field } => {
                write!(
                    formatter,
                    "progress counter {field} is outside the wire range"
                )
            }
            Self::UnwrittenSequence => {
                formatter.write_str("sequence is zero, which names no appended event")
            }
            Self::TimeBeforeEpoch => formatter.write_str("frame instant is before the Unix epoch"),
            Self::FrameTooLarge {
                max_bytes,
                actual_bytes,
            } => write!(
                formatter,
                "frame is {actual_bytes} canonical bytes; the maximum is {max_bytes}"
            ),
        }
    }
}

impl Error for ProgressApiError {}

impl From<CodecError> for ProgressApiError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<EventError> for ProgressApiError {
    fn from(value: EventError) -> Self {
        Self::Event(value)
    }
}

impl SecuritySensitiveEnum for EventKind {
    const FIELD: &'static str = "kind";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

impl SecuritySensitiveEnum for StepStatus {
    const FIELD: &'static str = "step";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

impl SecuritySensitiveEnum for RetryCategory {
    const FIELD: &'static str = "category";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

impl SecuritySensitiveEnum for Authority {
    const FIELD: &'static str = "authority";

    fn from_wire(value: &str) -> Option<Self> {
        [Self::Authoritative, Self::Synthetic]
            .into_iter()
            .find(|authority| authority.as_str() == value)
    }
}

/// Bounded, displayable text carried by one frame.
///
/// The grammar is one step looser than the crate's usual bounded value and one
/// step tighter than "any string": a newline and a tab are admitted because a
/// tool's output and a model's prose both contain them and a renderer that
/// received them flattened would show a wall of words; every other control
/// character is refused, because a terminal, a Telegram message and a Slack
/// block each interpret at least one of them as an instruction rather than as
/// content.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProgressText(String);

impl ProgressText {
    /// Maximum accepted UTF-8 byte length.
    pub const MAX_BYTES: usize = MAX_PROGRESS_TEXT_BYTES;

    /// Validate and construct the text.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Empty`] for an empty value, [`ValueError::TooLong`]
    /// past [`ProgressText::MAX_BYTES`], and [`ValueError::ControlCharacter`]
    /// for any control character other than a newline or a tab.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ValueError::Empty);
        }
        if value.len() > Self::MAX_BYTES {
            return Err(ValueError::TooLong {
                max_bytes: Self::MAX_BYTES,
                actual_bytes: value.len(),
            });
        }
        if value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
        {
            return Err(ValueError::ControlCharacter);
        }
        Ok(Self(value))
    }

    /// Reduce arbitrary text to something this type admits, or to nothing.
    ///
    /// The producer's half of the refusal-first rule. A frame that cannot be
    /// built is a frame nobody sees, and a run must never fail because its
    /// progress could not be rendered — so an emitter sanitizes here and the
    /// strict constructor stays the gate everything else passes through.
    ///
    /// Forbidden control characters are dropped rather than replaced, and the
    /// remainder is truncated on a character boundary. `None` means nothing
    /// admissible survived, which is a frame not worth sending.
    #[must_use]
    pub fn sanitized(value: &str) -> Option<Self> {
        let mut kept = String::with_capacity(value.len().min(Self::MAX_BYTES));
        for character in value.chars() {
            if character.is_control() && !matches!(character, '\n' | '\t') {
                continue;
            }
            if kept.len() + character.len_utf8() > Self::MAX_BYTES {
                break;
            }
            kept.push(character);
        }
        Self::new(kept).ok()
    }

    /// The validated text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProgressText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The three optional members of a frame body, before their kind judges them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProgressBodyParts {
    /// Display text: the message, or the label of the step.
    pub text: Option<ProgressText>,
    /// Step lifecycle, for a tool call or a subagent.
    pub step: Option<StepStatus>,
    /// Retry semantics, for a warning or a fault.
    pub retry: Option<RetryContext>,
}

/// What one frame says beyond its kind.
///
/// Three members rather than a discriminated union of three shapes, because a
/// fault carries both a retry context and the sentence it came with, and a
/// union would have forced one of those two facts out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgressBody {
    text: Option<ProgressText>,
    step: Option<StepStatus>,
    retry: Option<RetryContext>,
}

impl ProgressBody {
    /// Build the body one kind admits.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::BodyMemberRefused`] for a member the kind requires
    /// and did not get, or forbids and did.
    pub fn new(kind: EventKind, parts: ProgressBodyParts) -> Result<Self, EventError> {
        let ProgressBodyParts { text, step, retry } = parts;
        // Written as three checks rather than a fold so the first refusal names
        // the member, which is the only part of it a caller can act on.
        crate::event::admit_member("text", kind, kind.text_rule(), text.is_some())?;
        crate::event::admit_member("step", kind, kind.step_rule(), step.is_some())?;
        crate::event::admit_member("retry", kind, kind.retry_rule(), retry.is_some())?;
        Ok(Self { text, step, retry })
    }

    /// The body every kind that carries nothing has.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::BodyMemberRefused`] when the kind requires a member
    /// this body does not carry.
    pub fn empty(kind: EventKind) -> Result<Self, EventError> {
        Self::new(
            kind,
            ProgressBodyParts {
                text: None,
                step: None,
                retry: None,
            },
        )
    }

    /// Display text, when the kind carries any.
    #[must_use]
    pub const fn text(&self) -> Option<&ProgressText> {
        self.text.as_ref()
    }

    /// Step lifecycle, when the kind carries one.
    #[must_use]
    pub const fn step(&self) -> Option<StepStatus> {
        self.step
    }

    /// Retry semantics, when the kind carries one.
    #[must_use]
    pub const fn retry(&self) -> Option<RetryContext> {
        self.retry
    }

    fn to_json(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "retry".to_owned(),
                self.retry.map_or(JsonValue::Null, retry_to_json),
            ),
            (
                "step".to_owned(),
                self.step.map_or(JsonValue::Null, |status| {
                    JsonValue::String(status.as_str().to_owned())
                }),
            ),
            (
                "text".to_owned(),
                self.text.as_ref().map_or(JsonValue::Null, |text| {
                    JsonValue::String(text.as_str().to_owned())
                }),
            ),
        ])
    }

    fn from_json(kind: EventKind, body: &JsonValue) -> Result<Self, ProgressApiError> {
        exact_fields(body, &["retry", "step", "text"])?;
        let parts = ProgressBodyParts {
            text: match member(body, "text")? {
                Some(JsonValue::String(text)) => {
                    Some(ProgressText::new(text.clone()).map_err(|error| {
                        ProgressApiError::Field {
                            field: "text",
                            error,
                        }
                    })?)
                }
                Some(_) => return Err(ProgressApiError::InvalidBody),
                None => None,
            },
            step: match member(body, "step")? {
                Some(JsonValue::String(status)) => {
                    Some(decode_security_enum::<StepStatus>(status)?)
                }
                Some(_) => return Err(ProgressApiError::InvalidBody),
                None => None,
            },
            retry: match member(body, "retry")? {
                Some(value @ JsonValue::Object(_)) => Some(retry_from_json(value)?),
                Some(_) => return Err(ProgressApiError::InvalidBody),
                None => None,
            },
        };
        Ok(Self::new(kind, parts)?)
    }
}

/// Everything one progress frame is built from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgressFrameParts {
    /// The run this frame belongs to.
    pub run_id: RunId,
    /// The spool sequence of the event carrying this frame, counted from one.
    ///
    /// Assigned by the writer that appends it, never by the producer that
    /// described it: the spool decides its own positions, and a producer that
    /// guessed one would be handing every consumer a cursor to the wrong event.
    pub sequence: u64,
    /// When the frame was produced.
    pub at_ms: EpochMillis,
    /// How much this frame may be relied upon.
    pub authority: Authority,
    /// What happened.
    pub kind: EventKind,
    /// What it says beyond its kind.
    pub body: ProgressBody,
}

/// One normalized progress event, as every surface renders it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgressFrame {
    run_id: RunId,
    sequence: u64,
    at_ms: EpochMillis,
    authority: Authority,
    kind: EventKind,
    body: ProgressBody,
}

impl ProgressFrame {
    /// Stamp one described frame with its durable position.
    ///
    /// # Errors
    ///
    /// Returns [`ProgressApiError::UnwrittenSequence`] for a sequence of zero,
    /// [`ProgressApiError::TimeBeforeEpoch`] for an instant before the epoch,
    /// and [`ProgressApiError::Event`] wrapping
    /// [`EventError::PreviewClaimedAuthority`] for an authoritative frame of a
    /// preview-only kind.
    pub fn new(parts: ProgressFrameParts) -> Result<Self, ProgressApiError> {
        let ProgressFrameParts {
            run_id,
            sequence,
            at_ms,
            authority,
            kind,
            body,
        } = parts;
        if sequence == 0 {
            return Err(ProgressApiError::UnwrittenSequence);
        }
        if at_ms.as_millis() < 0 {
            return Err(ProgressApiError::TimeBeforeEpoch);
        }
        if kind.is_preview_only() && matches!(authority, Authority::Authoritative) {
            return Err(EventError::PreviewClaimedAuthority { kind }.into());
        }
        Ok(Self {
            run_id,
            sequence,
            at_ms,
            authority,
            kind,
            body,
        })
    }

    /// The run this frame belongs to.
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// The spool sequence this frame was appended at.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// When the frame was produced.
    #[must_use]
    pub const fn at_ms(&self) -> EpochMillis {
        self.at_ms
    }

    /// How much this frame may be relied upon.
    #[must_use]
    pub const fn authority(&self) -> Authority {
        self.authority
    }

    /// What happened.
    #[must_use]
    pub const fn kind(&self) -> EventKind {
        self.kind
    }

    /// What it says beyond its kind.
    #[must_use]
    pub const fn body(&self) -> &ProgressBody {
        &self.body
    }

    /// Encode to canonical payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProgressApiError::CounterOutOfRange`] for a sequence above the
    /// wire's signed ceiling, and [`ProgressApiError::FrameTooLarge`] for an
    /// encoding above [`MAX_PROGRESS_CANONICAL_BYTES`]. The bound is checked
    /// on the bytes rather than predicted from the members, so an encoding that
    /// would not fit a spool payload is refused here rather than by the spool.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ProgressApiError> {
        let encoded = JsonValue::Object(vec![
            (
                "at_ms".to_owned(),
                JsonValue::Integer(self.at_ms.as_millis()),
            ),
            (
                "authority".to_owned(),
                JsonValue::String(self.authority.as_str().to_owned()),
            ),
            ("body".to_owned(), self.body.to_json()),
            (
                "kind".to_owned(),
                JsonValue::String(self.kind.as_str().to_owned()),
            ),
            (
                "run_id".to_owned(),
                JsonValue::String(self.run_id.as_str().to_owned()),
            ),
            ("sequence".to_owned(), integer("sequence", self.sequence)?),
        ])
        .to_canonical_bytes();
        if encoded.len() > MAX_PROGRESS_CANONICAL_BYTES {
            return Err(ProgressApiError::FrameTooLarge {
                max_bytes: MAX_PROGRESS_CANONICAL_BYTES,
                actual_bytes: encoded.len(),
            });
        }
        Ok(encoded)
    }

    /// Decode one frame from canonical payload bytes.
    ///
    /// # Errors
    ///
    /// Returns the parse refusal, [`ProgressApiError::InvalidBody`] for a shape
    /// that is not exact, and the construction refusals [`ProgressFrame::new`]
    /// answers.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, ProgressApiError> {
        if payload.len() > MAX_PROGRESS_CANONICAL_BYTES {
            return Err(ProgressApiError::FrameTooLarge {
                max_bytes: MAX_PROGRESS_CANONICAL_BYTES,
                actual_bytes: payload.len(),
            });
        }
        let value = parse_canonical(payload)?;
        exact_fields(
            &value,
            &["at_ms", "authority", "body", "kind", "run_id", "sequence"],
        )?;
        let kind = decode_security_enum::<EventKind>(&required_string(&value, "kind")?)?;
        let body = value.get("body").ok_or(ProgressApiError::InvalidBody)?;
        Self::new(ProgressFrameParts {
            run_id: RunId::new(required_string(&value, "run_id")?).map_err(|error| {
                ProgressApiError::Field {
                    field: "run_id",
                    error,
                }
            })?,
            sequence: unsigned(&value, "sequence")?,
            at_ms: EpochMillis::from_millis(
                value
                    .get("at_ms")
                    .and_then(JsonValue::as_integer)
                    .ok_or(ProgressApiError::InvalidBody)?,
            ),
            authority: decode_security_enum::<Authority>(&required_string(&value, "authority")?)?,
            kind,
            body: ProgressBody::from_json(kind, body)?,
        })
    }
}

fn retry_to_json(retry: RetryContext) -> JsonValue {
    JsonValue::Object(vec![
        (
            "attempt".to_owned(),
            JsonValue::Integer(i64::from(retry.attempt())),
        ),
        (
            "category".to_owned(),
            JsonValue::String(retry.category().as_str().to_owned()),
        ),
        (
            "retry_after_ms".to_owned(),
            retry.retry_after_ms().map_or(JsonValue::Null, |delay| {
                // The domain is clamped to five minutes at construction, so the
                // conversion cannot narrow; the fallback is the largest wait
                // rather than a panic for a value this type cannot hold.
                JsonValue::Integer(i64::try_from(delay).unwrap_or(MAX_RETRY_AFTER_MS as i64))
            }),
        ),
        ("retryable".to_owned(), JsonValue::Bool(retry.retryable())),
    ])
}

fn retry_from_json(value: &JsonValue) -> Result<RetryContext, ProgressApiError> {
    exact_fields(
        value,
        &["attempt", "category", "retry_after_ms", "retryable"],
    )?;
    let attempt = u32::try_from(unsigned(value, "attempt")?)
        .map_err(|_| ProgressApiError::CounterOutOfRange { field: "attempt" })?;
    let retry_after_ms = match member(value, "retry_after_ms")? {
        Some(JsonValue::Integer(delay)) => {
            Some(u64::try_from(*delay).map_err(|_| ProgressApiError::InvalidBody)?)
        }
        Some(_) => return Err(ProgressApiError::InvalidBody),
        None => None,
    };
    let retryable = match value.get("retryable") {
        Some(JsonValue::Bool(retryable)) => *retryable,
        _ => return Err(ProgressApiError::InvalidBody),
    };
    Ok(RetryContext::new(
        decode_security_enum::<RetryCategory>(&required_string(value, "category")?)?,
        retryable,
        retry_after_ms,
        attempt,
    )?)
}

/// Read one always-present member, distinguishing `null` from a value.
///
/// The wire carries every optional member as an explicit `null` rather than by
/// omission, because absent and present-and-null are different facts and a
/// decoder that accepted both would accept two spellings of one body.
fn member<'a>(
    body: &'a JsonValue,
    field: &'static str,
) -> Result<Option<&'a JsonValue>, ProgressApiError> {
    match body.get(field) {
        Some(JsonValue::Null) => Ok(None),
        Some(value) => Ok(Some(value)),
        None => Err(ProgressApiError::InvalidBody),
    }
}

fn integer(field: &'static str, value: u64) -> Result<JsonValue, ProgressApiError> {
    i64::try_from(value)
        .map(JsonValue::Integer)
        .map_err(|_| ProgressApiError::CounterOutOfRange { field })
}

fn unsigned(body: &JsonValue, field: &'static str) -> Result<u64, ProgressApiError> {
    let value = body
        .get(field)
        .and_then(JsonValue::as_integer)
        .ok_or(ProgressApiError::InvalidBody)?;
    u64::try_from(value).map_err(|_| ProgressApiError::InvalidBody)
}

fn required_string(body: &JsonValue, field: &'static str) -> Result<String, ProgressApiError> {
    body.get(field)
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
        .ok_or(ProgressApiError::InvalidBody)
}

fn exact_fields(body: &JsonValue, fields: &[&str]) -> Result<(), ProgressApiError> {
    let JsonValue::Object(entries) = body else {
        return Err(ProgressApiError::InvalidBody);
    };
    if entries.len() != fields.len()
        || !fields
            .iter()
            .all(|field| entries.iter().any(|(name, _)| name == field))
    {
        return Err(ProgressApiError::InvalidBody);
    }
    Ok(())
}

/// Every member rule this module's bodies are held to, for coverage checks.
///
/// One entry per kind, derived from the kind itself rather than restated, so a
/// kind added to [`EventKind`] appears here without an edit and a test that
/// walks it cannot silently stop covering the new one.
#[must_use]
pub fn member_rules() -> Vec<(EventKind, MemberRule, MemberRule, MemberRule)> {
    EventKind::ALL
        .into_iter()
        .map(|kind| (kind, kind.text_rule(), kind.step_rule(), kind.retry_rule()))
        .collect()
}

/// Validate that `bounds` is the grammar this module's identifiers use.
///
/// Exposed so the identifier bound reaches the generated surface as the Rust
/// constant rather than as a number retyped beside it.
///
/// # Errors
///
/// Returns the bounded-value refusal.
pub fn admit_identifier(value: &str) -> Result<(), ValueError> {
    bounded_value(value, MAX_TOOL_FIELD_BYTES)
}
