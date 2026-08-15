// SPDX-License-Identifier: Elastic-2.0

//! Slack Socket Mode envelope admission and acknowledgement planning.
//!
//! This slice turns one bounded Socket Mode frame into a durable-input
//! candidate plus an explicit acknowledgement plan. Nothing here opens a
//! websocket, holds an app-level or refresh token, sends an acknowledgement, or
//! writes anything durable. [`SlackAckPlan`] is a *plan* the transport layer
//! must execute only after it has atomically persisted the returned
//! [`SlackEnvelope::disposition`]; the store binding arrives with the socket
//! layer, exactly as the Telegram parser predates its HTTP client.
//!
//! # Divergences from the Telegram admission model
//!
//! * **No cursor.** Telegram advances a monotonic `update_id` offset, so one
//!   batch shares a single durable commit point and a malformed member must
//!   refuse the whole response. Slack acknowledges one envelope at a time and
//!   has no offset, so a refusal is scoped to a single frame and can never
//!   wedge unrelated traffic.
//! * **`envelope_id` is not an identity.** Slack mints a fresh `envelope_id`
//!   for every delivery attempt of the same event and signals redelivery with
//!   `retry_attempt`. The deduplication identity is therefore the
//!   event `(team_id, channel, ts)` or slash-command
//!   `(team_id, channel_id, trigger_id)` coordinates exposed as
//!   [`SlackIngress::source_key`]; `envelope_id` is only an acknowledgement key
//!   and is deliberately absent from that key.
//! * **Three coordinates, not two.** A Slack app is installed per workspace and
//!   channel/user IDs are unique only within a workspace, so a principal is
//!   `(team_id, channel, user)` rather than Telegram's `(chat, actor)`.
//! * **String coordinates need a separator rule.** Telegram coordinates are
//!   integers and compose unambiguously. Slack coordinates are opaque strings,
//!   so every admitted identifier is restricted to ASCII graphic bytes
//!   excluding `:`, the separator used by [`SlackIngress::source_key`] and
//!   [`SlackIngress::scope`]. Without that restriction two distinct triples
//!   could collide into one deduplication key.
//! * **Refusals keep the acknowledgement key.** A malformed frame whose
//!   `envelope_id` survived is reported as [`SlackDisposition::Refused`] with
//!   [`SlackAckPlan::AckWithheld`], never as a silent acknowledgement. Only a
//!   frame whose acknowledgement key could not be established at all is a hard
//!   [`SlackError`].
//! * **Open top-level field set.** Telegram's response envelope is a fixed
//!   two-field shape and is checked exactly. Socket Mode frames legitimately
//!   differ per type (`hello` carries connection metadata, `disconnect` carries
//!   a reason) and Slack has added top-level fields over time, so unknown
//!   top-level fields are tolerated while duplicate keys, unknown envelope
//!   types, and unknown payload types are refused.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use serde_json::{Map, Value};

/// Maximum Socket Mode frame accepted from the websocket.
///
/// Slack documents a 256 KiB cap on the payload it delivers for an event, so a
/// larger frame is refused rather than buffered.
pub const MAX_SLACK_ENVELOPE_BYTES: usize = 256 * 1024;
/// Maximum message text retained as a durable input.
///
/// This is a retention bound, not a Slack protocol bound. Text at the limit is
/// admitted byte-exactly; one byte over is refused rather than truncated, so a
/// durable input is never a silently shortened version of what the user sent.
pub const MAX_SLACK_TEXT_BYTES: usize = 16 * 1024;
/// Maximum length of an opaque Slack identifier accepted as a coordinate.
pub const MAX_SLACK_IDENTIFIER_BYTES: usize = 128;
/// Highest redelivery attempt accepted on one envelope.
///
/// Slack documents three redelivery attempts; the headroom here absorbs a
/// platform change without admitting an unbounded counter.
pub const MAX_SLACK_RETRY_ATTEMPT: u32 = 16;
const MAX_RETRY_REASON_BYTES: usize = 64;
const MAX_POLICY_ENTRIES: usize = 1024;

/// Socket Mode acknowledgement key for one delivery attempt.
///
/// Slack mints a new value for every redelivery of the same event, so this is
/// an acknowledgement key only and never a deduplication identity. It carries
/// no principal or content information and is therefore not redacted: the
/// transport layer needs it in logs to reconcile planned and sent acks.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SlackEnvelopeId(String);

impl SlackEnvelopeId {
    /// Construct a bounded opaque acknowledgement key.
    pub fn new(value: &str) -> Result<Self, SlackError> {
        identifier(value, "envelope_id").map_err(SlackError::InvalidField)?;
        Ok(Self(value.to_owned()))
    }

    /// Exact wire value to send back in an acknowledgement.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact Slack app identity, excluding every credential.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct SlackAppId(String);

impl fmt::Debug for SlackAppId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SlackAppId(<redacted>)")
    }
}

impl SlackAppId {
    /// Construct a bounded opaque app identity.
    pub fn new(value: &str) -> Result<Self, SlackError> {
        identifier(value, "app_id").map_err(SlackError::InvalidField)?;
        Ok(Self(value.to_owned()))
    }

    /// Opaque Slack app identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One exact workspace/channel/actor triple allowed to create work.
///
/// All three coordinates are required: Slack channel and user IDs are unique
/// only within a workspace, so a two-coordinate policy would admit a principal
/// from a workspace it was never written for.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct SlackPrincipal {
    team: String,
    channel: String,
    user: String,
}

impl fmt::Debug for SlackPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SlackPrincipal(<redacted>)")
    }
}

impl SlackPrincipal {
    /// Construct a principal from exact non-empty bounded coordinates.
    pub fn new(team: &str, channel: &str, user: &str) -> Result<Self, SlackError> {
        identifier(team, "team_id").map_err(SlackError::InvalidField)?;
        identifier(channel, "channel").map_err(SlackError::InvalidField)?;
        identifier(user, "user").map_err(SlackError::InvalidField)?;
        Ok(Self {
            team: team.to_owned(),
            channel: channel.to_owned(),
            user: user.to_owned(),
        })
    }

    /// Slack workspace coordinate.
    #[must_use]
    pub fn team(&self) -> &str {
        &self.team
    }

    /// Slack conversation coordinate.
    #[must_use]
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// Slack user coordinate.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }
}

/// Immutable exact allowlist for one Slack app.
///
/// There is no default-open construction: an empty allowlist is refused, so a
/// caller cannot reach an admitted disposition without naming the principal.
#[derive(Clone, Eq, PartialEq)]
pub struct SlackAccessPolicy {
    app_id: SlackAppId,
    principals: BTreeSet<SlackPrincipal>,
}

impl fmt::Debug for SlackAccessPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SlackAccessPolicy")
            .field("app_id", &"<redacted>")
            .field("principal_count", &self.principals.len())
            .finish()
    }
}

impl SlackAccessPolicy {
    /// Construct a bounded nonempty allowlist.
    pub fn new(
        app_id: SlackAppId,
        principals: impl IntoIterator<Item = SlackPrincipal>,
    ) -> Result<Self, SlackError> {
        let principals: BTreeSet<_> = principals.into_iter().collect();
        if principals.is_empty() || principals.len() > MAX_POLICY_ENTRIES {
            return Err(SlackError::InvalidField("principals"));
        }
        Ok(Self { app_id, principals })
    }

    /// App identity bound into scopes and dedup keys.
    #[must_use]
    pub const fn app_id(&self) -> &SlackAppId {
        &self.app_id
    }

    fn admits(&self, principal: &SlackPrincipal) -> bool {
        self.principals.contains(principal)
    }
}

/// Closed Socket Mode envelope type vocabulary.
///
/// An unrecognised wire value is never mapped onto a member of this enum; it
/// becomes [`SlackRefusal::UnknownEnvelopeType`] so a future Slack frame type
/// cannot be acknowledged as if it had been understood.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackEnvelopeType {
    /// An Events API delivery carrying an `event_callback` payload.
    EventsApi,
    /// A slash command invocation.
    SlashCommands,
    /// A block action, shortcut, view submission, or similar interaction.
    Interactive,
    /// Connection-established control frame. Never acknowledged.
    Hello,
    /// Connection-teardown control frame. Never acknowledged.
    Disconnect,
}

impl SlackEnvelopeType {
    fn from_wire(value: &str) -> Option<Self> {
        match value {
            "events_api" => Some(Self::EventsApi),
            "slash_commands" => Some(Self::SlashCommands),
            "interactive" => Some(Self::Interactive),
            "hello" => Some(Self::Hello),
            "disconnect" => Some(Self::Disconnect),
            _ => None,
        }
    }

    /// Exact Slack wire spelling.
    #[must_use]
    pub const fn wire_type(self) -> &'static str {
        match self {
            Self::EventsApi => "events_api",
            Self::SlashCommands => "slash_commands",
            Self::Interactive => "interactive",
            Self::Hello => "hello",
            Self::Disconnect => "disconnect",
        }
    }

    /// Whether this type carries an acknowledgement key at all.
    #[must_use]
    pub const fn is_acknowledgeable(self) -> bool {
        matches!(
            self,
            Self::EventsApi | Self::SlashCommands | Self::Interactive
        )
    }
}

/// Slack input class retained without platform markup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackInputKind {
    /// A plain channel message with no subtype and no bot author.
    Message,
    /// A message that mentions the app.
    AppMention,
    /// An explicit `/github_create` invocation.
    GitHubCreate,
    /// An explicit `/github_reply` invocation.
    GitHubReply,
    /// An explicit `/github_check` invocation.
    GitHubCheck,
    /// An explicit `/github_uncheck` invocation.
    GitHubUncheck,
    /// An explicit `/github_issue` invocation.
    GitHubIssue,
    /// An explicit `/github_label` invocation.
    GitHubLabel,
    /// An explicit `/github_milestone` invocation.
    GitHubMilestone,
    /// An explicit `/github_epic` invocation.
    GitHubEpic,
    /// An explicit `/github_project` invocation.
    GitHubProject,
    /// The unified Slack command surface.
    Monique,
    /// A well-formed frame outside this build's admitted input surface.
    Unsupported,
}

impl SlackInputKind {
    /// Exact slash command for a typed GitHub command ingress.
    #[must_use]
    pub const fn slash_command(self) -> Option<&'static str> {
        match self {
            Self::GitHubCreate => Some("/github_create"),
            Self::GitHubReply => Some("/github_reply"),
            Self::GitHubCheck => Some("/github_check"),
            Self::GitHubUncheck => Some("/github_uncheck"),
            Self::GitHubIssue => Some("/github_issue"),
            Self::GitHubLabel => Some("/github_label"),
            Self::GitHubMilestone => Some("/github_milestone"),
            Self::GitHubEpic => Some("/github_epic"),
            Self::GitHubProject => Some("/github_project"),
            Self::Monique => Some("/monique"),
            Self::Message | Self::AppMention | Self::Unsupported => None,
        }
    }
}

/// Why a frame was refused while its acknowledgement key survived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackRefusal {
    /// The frame carried no `type`, or a `type` that was not a string.
    MissingEnvelopeType,
    /// The frame named a type outside the closed vocabulary.
    UnknownEnvelopeType,
    /// A `hello`/`disconnect` control frame carried an acknowledgement key.
    ControlFrameCarriedAckKey,
    /// The `payload` was absent, not an object, or not an `event_callback`.
    InvalidPayload,
    /// The `event` object was absent, not an object, or carried no type.
    InvalidEvent,
    /// A named field was absent, of the wrong type, or out of bounds.
    InvalidField(&'static str),
}

impl SlackRefusal {
    /// Stable refusal category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::MissingEnvelopeType => "slack_missing_envelope_type",
            Self::UnknownEnvelopeType => "slack_unknown_envelope_type",
            Self::ControlFrameCarriedAckKey => "slack_control_frame_carried_ack_key",
            Self::InvalidPayload => "slack_invalid_payload",
            Self::InvalidEvent => "slack_invalid_event",
            Self::InvalidField(_) => "slack_invalid_field",
        }
    }
}

/// Closed disposition that must be persisted before any acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackDisposition {
    /// The exact team/channel/user triple is allowlisted.
    Admitted,
    /// The frame is well-formed but outside the exact allowlist.
    Denied,
    /// The frame is well-formed and acknowledgeable but creates no work.
    IgnoredUnsupported,
    /// The frame is malformed; its acknowledgement key, if any, is preserved.
    Refused(SlackRefusal),
    /// A `hello`/`disconnect` control frame. Not an input and never acked.
    ConnectionControl,
}

impl SlackDisposition {
    /// Stable disposition category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Admitted => "slack_admitted",
            Self::Denied => "slack_denied",
            Self::IgnoredUnsupported => "slack_ignored_unsupported",
            Self::Refused(reason) => reason.category(),
            Self::ConnectionControl => "slack_connection_control",
        }
    }
}

/// Redelivery metadata Slack attached to this delivery attempt.
///
/// Surfaced rather than dropped: it is the only signal that distinguishes a
/// first delivery from a redelivery of the same `(team_id, channel, ts)`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SlackRetry {
    attempt: u32,
    reason: Option<String>,
}

impl SlackRetry {
    /// Zero on first delivery, otherwise Slack's redelivery counter.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Bounded reason Slack gave for redelivering.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Whether Slack has already delivered this event at least once.
    #[must_use]
    pub const fn is_redelivery(&self) -> bool {
        self.attempt > 0
    }
}

/// The acknowledgement this transport must send, and when.
///
/// # Plan-then-ack
///
/// This layer performs no I/O. The transport must, in this order:
///
/// 1. atomically persist [`SlackEnvelope::disposition`] (and the ingress, when
///    present) together with [`SlackIngress::source_key`]; then
/// 2. send the acknowledgement named by [`SlackAckPlan::planned_ack`].
///
/// Acknowledging first would let a crash between the two steps drop an input
/// permanently, because Slack never redelivers an acknowledged envelope.
/// Acknowledging an `events_api` frame is required regardless of whether the
/// input was admitted, denied, or ignored: withholding acknowledgement for a
/// processing outcome produces a redelivery storm. The only frames this layer
/// leaves unacknowledged are control frames, which have nothing to ack, and
/// refusals, whose acknowledgement is an explicit caller policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SlackAckPlan {
    /// `hello`/`disconnect`: no envelope exists to acknowledge.
    NeverAcknowledged,
    /// Send this key once, after the disposition is durable.
    AckAfterDurableRecord(SlackEnvelopeId),
    /// Refused frame whose key survived. This layer plans no acknowledgement;
    /// the caller must apply an explicit refusal policy before sending one.
    AckWithheld(SlackEnvelopeId),
    /// Refused frame with no recoverable key. Nothing can be acknowledged.
    NoAckKey,
}

impl SlackAckPlan {
    /// Key this layer plans to acknowledge, or `None` when it plans none.
    ///
    /// This returns `None` for every refusal. Recovering the key of a refused
    /// frame is [`SlackAckPlan::ack_key`], which a caller must reach for
    /// deliberately.
    #[must_use]
    pub const fn planned_ack(&self) -> Option<&SlackEnvelopeId> {
        match self {
            Self::AckAfterDurableRecord(envelope_id) => Some(envelope_id),
            Self::NeverAcknowledged | Self::AckWithheld(_) | Self::NoAckKey => None,
        }
    }

    /// Acknowledgement key recoverable from this frame, planned or withheld.
    #[must_use]
    pub const fn ack_key(&self) -> Option<&SlackEnvelopeId> {
        match self {
            Self::AckAfterDurableRecord(envelope_id) | Self::AckWithheld(envelope_id) => {
                Some(envelope_id)
            }
            Self::NeverAcknowledged | Self::NoAckKey => None,
        }
    }
}

/// One owned bounded Slack input ready for durable insertion.
#[derive(Clone, Eq, PartialEq)]
pub struct SlackIngress {
    source_key: String,
    scope: String,
    principal: SlackPrincipal,
    kind: SlackInputKind,
    content: Option<String>,
}

impl fmt::Debug for SlackIngress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SlackIngress")
            .field("source_key", &"<redacted>")
            .field("scope", &"<redacted>")
            .field("principal", &self.principal)
            .field("kind", &self.kind)
            .field("content", &self.content.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl SlackIngress {
    /// Stable transport deduplication key.
    ///
    /// Derived from `(app, team_id, channel, ts)` for an event, or
    /// `(app, team_id, channel_id, trigger_id)` for a slash command. It is
    /// therefore identical across redelivery while deliberately excluding the
    /// per-delivery `envelope_id`.
    #[must_use]
    pub fn source_key(&self) -> &str {
        &self.source_key
    }

    /// Exact per-app/team/channel scheduler scope.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Authenticated platform coordinates from the event.
    #[must_use]
    pub const fn principal(&self) -> &SlackPrincipal {
        &self.principal
    }

    /// Input class.
    #[must_use]
    pub const fn kind(&self) -> SlackInputKind {
        self.kind
    }

    /// Exact slash command, present only for one of the four GitHub commands.
    #[must_use]
    pub const fn command(&self) -> Option<&'static str> {
        self.kind.slash_command()
    }

    /// Bounded input text, present only for an admitted disposition.
    #[must_use]
    pub fn content(&self) -> Option<&str> {
        self.content.as_deref()
    }
}

/// One parsed Socket Mode frame with an explicit acknowledgement plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackEnvelope {
    envelope_id: Option<SlackEnvelopeId>,
    envelope_type: Option<SlackEnvelopeType>,
    accepts_response_payload: bool,
    retry: SlackRetry,
    disposition: SlackDisposition,
    ingress: Option<SlackIngress>,
    ack: SlackAckPlan,
}

impl SlackEnvelope {
    /// Per-delivery acknowledgement key, when the frame carried a valid one.
    #[must_use]
    pub const fn envelope_id(&self) -> Option<&SlackEnvelopeId> {
        self.envelope_id.as_ref()
    }

    /// Recognised envelope type, or `None` when the type was absent or unknown.
    #[must_use]
    pub const fn envelope_type(&self) -> Option<SlackEnvelopeType> {
        self.envelope_type
    }

    /// Whether Slack will accept a response payload on the acknowledgement.
    #[must_use]
    pub const fn accepts_response_payload(&self) -> bool {
        self.accepts_response_payload
    }

    /// Redelivery metadata for this delivery attempt.
    #[must_use]
    pub const fn retry(&self) -> &SlackRetry {
        &self.retry
    }

    /// Exact decision that must be persisted before acknowledging.
    #[must_use]
    pub const fn disposition(&self) -> SlackDisposition {
        self.disposition
    }

    /// Durable-input candidate, present only for message-shaped events.
    #[must_use]
    pub const fn ingress(&self) -> Option<&SlackIngress> {
        self.ingress.as_ref()
    }

    /// Acknowledgement this transport must send, and when.
    #[must_use]
    pub const fn ack(&self) -> &SlackAckPlan {
        &self.ack
    }
}

/// Typed fail-closed Slack frame refusal with no recoverable ack key.
///
/// A frame that reaches this type could not yield an `envelope_id`, so there is
/// nothing to acknowledge and no ack policy for the caller to apply. Every
/// refusal that *does* retain a key is reported as a
/// [`SlackDisposition::Refused`] envelope instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackError {
    /// Frame was empty or exceeded its byte bound.
    LimitExceeded,
    /// JSON syntax, duplicate keys, trailing bytes, or a non-object frame.
    InvalidEnvelope,
    /// A named identity/value was invalid.
    InvalidField(&'static str),
}

impl SlackError {
    /// Stable refusal category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::LimitExceeded => "slack_limit_exceeded",
            Self::InvalidEnvelope => "slack_invalid_envelope",
            Self::InvalidField(_) => "slack_invalid_field",
        }
    }
}

impl fmt::Display for SlackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.category())
    }
}

impl Error for SlackError {}

/// Parse exactly one Slack Socket Mode frame.
///
/// Every successful return carries a disposition the caller must persist and a
/// [`SlackAckPlan`] the caller must execute afterwards. A malformed frame is
/// still returned as [`SlackDisposition::Refused`] whenever its `envelope_id`
/// survived, so an unrecognised frame is never silently acknowledged and never
/// silently dropped. Only frames with no recoverable acknowledgement key fail
/// with [`SlackError`].
pub fn parse_slack_envelope(
    bytes: &[u8],
    policy: &SlackAccessPolicy,
) -> Result<SlackEnvelope, SlackError> {
    if bytes.is_empty() || bytes.len() > MAX_SLACK_ENVELOPE_BYTES {
        return Err(SlackError::LimitExceeded);
    }
    // Shares the crate's strict JSON reader: duplicate object keys, trailing
    // bytes, and non-finite numbers are refused before any field is read.
    let document = crate::strict_json(bytes).map_err(|_| SlackError::InvalidEnvelope)?;
    let frame = document.as_object().ok_or(SlackError::InvalidEnvelope)?;

    let mut meta = FrameMeta {
        envelope_id: ack_key(frame)?,
        envelope_type: None,
        accepts_response_payload: false,
        retry: SlackRetry::default(),
    };
    match retry(frame) {
        Ok(value) => meta.retry = value,
        Err(reason) => return Ok(meta.refused(reason)),
    }
    match accepts_response_payload(frame) {
        Ok(value) => meta.accepts_response_payload = value,
        Err(reason) => return Ok(meta.refused(reason)),
    }

    let Some(Value::String(wire_type)) = frame.get("type") else {
        return if meta.envelope_id.is_some() {
            Ok(meta.refused(SlackRefusal::MissingEnvelopeType))
        } else {
            Err(SlackError::InvalidEnvelope)
        };
    };
    let Some(envelope_type) = SlackEnvelopeType::from_wire(wire_type) else {
        return Ok(meta.refused(SlackRefusal::UnknownEnvelopeType));
    };
    meta.envelope_type = Some(envelope_type);

    match envelope_type {
        SlackEnvelopeType::Hello | SlackEnvelopeType::Disconnect => {
            if meta.envelope_id.is_some() {
                // A control frame is not acknowledgeable, so a key on one is an
                // ambiguous shape rather than an ack instruction.
                return Ok(meta.refused(SlackRefusal::ControlFrameCarriedAckKey));
            }
            Ok(meta.connection_control())
        }
        SlackEnvelopeType::Interactive => {
            let ack_key = meta.require_ack_key()?;
            // Recognised and acknowledgeable, but outside this slice's input
            // surface: acknowledged so Slack stops redelivering, recorded
            // content-free so no work is created.
            Ok(meta.acked(ack_key, SlackDisposition::IgnoredUnsupported, None))
        }
        SlackEnvelopeType::SlashCommands => {
            let ack_key = meta.require_ack_key()?;
            Ok(slash_command(frame, meta, ack_key, policy))
        }
        SlackEnvelopeType::EventsApi => {
            let ack_key = meta.require_ack_key()?;
            Ok(events_api(frame, meta, ack_key, policy))
        }
    }
}

fn slash_command(
    frame: &Map<String, Value>,
    meta: FrameMeta,
    ack_key: SlackEnvelopeId,
    policy: &SlackAccessPolicy,
) -> SlackEnvelope {
    let Some(payload) = frame.get("payload").and_then(Value::as_object) else {
        return meta.refused(SlackRefusal::InvalidPayload);
    };
    let Some(command) = required_str(payload, "command") else {
        return meta.refused(SlackRefusal::InvalidField("command"));
    };
    let kind = match command {
        "/github_create" => SlackInputKind::GitHubCreate,
        "/github_reply" => SlackInputKind::GitHubReply,
        "/github_check" => SlackInputKind::GitHubCheck,
        "/github_uncheck" => SlackInputKind::GitHubUncheck,
        "/github_issue" => SlackInputKind::GitHubIssue,
        "/github_label" => SlackInputKind::GitHubLabel,
        "/github_milestone" => SlackInputKind::GitHubMilestone,
        "/github_epic" => SlackInputKind::GitHubEpic,
        "/github_project" => SlackInputKind::GitHubProject,
        "/monique" => SlackInputKind::Monique,
        _ => return meta.acked(ack_key, SlackDisposition::IgnoredUnsupported, None),
    };

    let Some(team) = required_str(payload, "team_id") else {
        return meta.refused(SlackRefusal::InvalidField("team_id"));
    };
    let Some(channel) = required_str(payload, "channel_id") else {
        return meta.refused(SlackRefusal::InvalidField("channel_id"));
    };
    let Some(user) = required_str(payload, "user_id") else {
        return meta.refused(SlackRefusal::InvalidField("user_id"));
    };
    let Some(trigger_id) = required_str(payload, "trigger_id") else {
        return meta.refused(SlackRefusal::InvalidField("trigger_id"));
    };
    if let Err(field) = identifier(trigger_id, "trigger_id") {
        return meta.refused(SlackRefusal::InvalidField(field));
    }
    let principal = match SlackPrincipal::new(team, channel, user) {
        Ok(principal) => principal,
        Err(SlackError::InvalidField("channel")) => {
            return meta.refused(SlackRefusal::InvalidField("channel_id"));
        }
        Err(SlackError::InvalidField("user")) => {
            return meta.refused(SlackRefusal::InvalidField("user_id"));
        }
        Err(SlackError::InvalidField(field)) => {
            return meta.refused(SlackRefusal::InvalidField(field));
        }
        Err(_) => return meta.refused(SlackRefusal::InvalidPayload),
    };
    let text = match payload.get("text") {
        Some(Value::String(text)) => text,
        _ => return meta.refused(SlackRefusal::InvalidField("text")),
    };
    if text.len() > MAX_SLACK_TEXT_BYTES || text.contains('\0') {
        return meta.refused(SlackRefusal::InvalidField("text"));
    }

    let disposition = if policy.admits(&principal) {
        SlackDisposition::Admitted
    } else {
        SlackDisposition::Denied
    };
    let app_id = policy.app_id().as_str();
    let ingress = SlackIngress {
        source_key: format!("slack:{app_id}:{team}:{channel}:command:{trigger_id}"),
        scope: format!("slack:{app_id}:{team}:{channel}"),
        principal,
        kind,
        content: if disposition == SlackDisposition::Admitted {
            Some(text.clone())
        } else {
            None
        },
    };
    meta.acked(ack_key, disposition, Some(ingress))
}

/// Envelope metadata accumulated before the frame body is understood.
///
/// Held separately so that any later refusal can still report the key, retry
/// counter, and type that were already established.
struct FrameMeta {
    envelope_id: Option<SlackEnvelopeId>,
    envelope_type: Option<SlackEnvelopeType>,
    accepts_response_payload: bool,
    retry: SlackRetry,
}

impl FrameMeta {
    fn require_ack_key(&self) -> Result<SlackEnvelopeId, SlackError> {
        self.envelope_id
            .clone()
            .ok_or(SlackError::InvalidField("envelope_id"))
    }

    fn refused(self, reason: SlackRefusal) -> SlackEnvelope {
        let ack = match self.envelope_id.clone() {
            Some(envelope_id) => SlackAckPlan::AckWithheld(envelope_id),
            None => SlackAckPlan::NoAckKey,
        };
        self.finish(SlackDisposition::Refused(reason), None, ack)
    }

    fn connection_control(self) -> SlackEnvelope {
        self.finish(
            SlackDisposition::ConnectionControl,
            None,
            SlackAckPlan::NeverAcknowledged,
        )
    }

    fn acked(
        self,
        ack_key: SlackEnvelopeId,
        disposition: SlackDisposition,
        ingress: Option<SlackIngress>,
    ) -> SlackEnvelope {
        self.finish(
            disposition,
            ingress,
            SlackAckPlan::AckAfterDurableRecord(ack_key),
        )
    }

    fn finish(
        self,
        disposition: SlackDisposition,
        ingress: Option<SlackIngress>,
        ack: SlackAckPlan,
    ) -> SlackEnvelope {
        SlackEnvelope {
            envelope_id: self.envelope_id,
            envelope_type: self.envelope_type,
            accepts_response_payload: self.accepts_response_payload,
            retry: self.retry,
            disposition,
            ingress,
            ack,
        }
    }
}

fn events_api(
    frame: &Map<String, Value>,
    meta: FrameMeta,
    ack_key: SlackEnvelopeId,
    policy: &SlackAccessPolicy,
) -> SlackEnvelope {
    let Some(payload) = frame.get("payload").and_then(Value::as_object) else {
        return meta.refused(SlackRefusal::InvalidPayload);
    };
    if required_str(payload, "type") != Some("event_callback") {
        return meta.refused(SlackRefusal::InvalidPayload);
    }
    let Some(team) = required_str(payload, "team_id") else {
        return meta.refused(SlackRefusal::InvalidField("team_id"));
    };
    let Some(event) = payload.get("event").and_then(Value::as_object) else {
        return meta.refused(SlackRefusal::InvalidEvent);
    };
    let Some(event_type) = required_str(event, "type") else {
        return meta.refused(SlackRefusal::InvalidEvent);
    };
    let kind = match event_type {
        "message" => SlackInputKind::Message,
        "app_mention" => SlackInputKind::AppMention,
        _ => return meta.acked(ack_key, SlackDisposition::IgnoredUnsupported, None),
    };
    // Subtyped messages (joins, edits, deletions, file shares) and bot-authored
    // messages carry different coordinates and would let the app answer itself.
    if event.contains_key("subtype") || event.contains_key("bot_id") {
        return meta.acked(ack_key, SlackDisposition::IgnoredUnsupported, None);
    }

    let Some(channel) = required_str(event, "channel") else {
        return meta.refused(SlackRefusal::InvalidField("channel"));
    };
    let Some(user) = required_str(event, "user") else {
        return meta.refused(SlackRefusal::InvalidField("user"));
    };
    let Some(ts) = required_str(event, "ts") else {
        return meta.refused(SlackRefusal::InvalidField("ts"));
    };
    if let Err(field) = identifier(ts, "ts") {
        return meta.refused(SlackRefusal::InvalidField(field));
    }
    let principal = match SlackPrincipal::new(team, channel, user) {
        Ok(principal) => principal,
        Err(SlackError::InvalidField(field)) => {
            return meta.refused(SlackRefusal::InvalidField(field));
        }
        Err(_) => return meta.refused(SlackRefusal::InvalidEvent),
    };

    let content = match event.get("text") {
        // Slack sends an empty or absent `text` for content this build does not
        // admit (files, blocks-only posts). Telegram omits `text` entirely in
        // that case and refuses an empty string; here an empty string is an
        // ordinary unsupported message, not a hostile frame.
        None => return meta.acked(ack_key, SlackDisposition::IgnoredUnsupported, None),
        Some(Value::String(text)) if text.is_empty() => {
            return meta.acked(ack_key, SlackDisposition::IgnoredUnsupported, None);
        }
        Some(Value::String(text)) => text,
        Some(_) => return meta.refused(SlackRefusal::InvalidField("text")),
    };
    if content.len() > MAX_SLACK_TEXT_BYTES || content.contains('\0') {
        return meta.refused(SlackRefusal::InvalidField("text"));
    }

    let disposition = if policy.admits(&principal) {
        SlackDisposition::Admitted
    } else {
        SlackDisposition::Denied
    };
    let app_id = policy.app_id().as_str();
    let ingress = SlackIngress {
        source_key: format!("slack:{app_id}:{team}:{channel}:{ts}"),
        scope: format!("slack:{app_id}:{team}:{channel}"),
        principal,
        kind,
        content: if disposition == SlackDisposition::Admitted {
            Some(content.clone())
        } else {
            None
        },
    };
    meta.acked(ack_key, disposition, Some(ingress))
}

fn ack_key(frame: &Map<String, Value>) -> Result<Option<SlackEnvelopeId>, SlackError> {
    match frame.get("envelope_id") {
        None => Ok(None),
        Some(Value::String(value)) => SlackEnvelopeId::new(value).map(Some),
        Some(_) => Err(SlackError::InvalidField("envelope_id")),
    }
}

fn retry(frame: &Map<String, Value>) -> Result<SlackRetry, SlackRefusal> {
    let attempt = match frame.get("retry_attempt") {
        None => 0,
        Some(value) => {
            let attempt = value
                .as_u64()
                .and_then(|attempt| u32::try_from(attempt).ok())
                .ok_or(SlackRefusal::InvalidField("retry_attempt"))?;
            if attempt > MAX_SLACK_RETRY_ATTEMPT {
                return Err(SlackRefusal::InvalidField("retry_attempt"));
            }
            attempt
        }
    };
    let reason = match frame.get("retry_reason") {
        None => None,
        Some(Value::String(reason)) => {
            if reason.is_empty()
                || reason.len() > MAX_RETRY_REASON_BYTES
                || !reason
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() || byte == b' ')
            {
                return Err(SlackRefusal::InvalidField("retry_reason"));
            }
            Some(reason.clone())
        }
        Some(_) => return Err(SlackRefusal::InvalidField("retry_reason")),
    };
    Ok(SlackRetry { attempt, reason })
}

fn accepts_response_payload(frame: &Map<String, Value>) -> Result<bool, SlackRefusal> {
    match frame.get("accepts_response_payload") {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(SlackRefusal::InvalidField("accepts_response_payload")),
    }
}

fn required_str<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    match object.get(key) {
        Some(Value::String(value)) => Some(value),
        _ => None,
    }
}

/// Admit one opaque Slack identifier, returning the offending field name.
///
/// `:` is excluded because it separates the components of
/// [`SlackIngress::source_key`]; admitting it would let two distinct
/// `(team, channel, ts)` triples collide into one deduplication key.
fn identifier(value: &str, field: &'static str) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > MAX_SLACK_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b':')
    {
        return Err(field);
    }
    Ok(())
}
