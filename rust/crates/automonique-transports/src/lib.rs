// SPDX-License-Identifier: Elastic-2.0

//! Transport protocol boundaries.
//!
//! This initial slice parses bounded Telegram `getUpdates` responses into
//! durable-input candidates. It performs no network I/O, carries no bot token,
//! and does not advance a remote cursor. The daemon/store must atomically
//! persist every returned disposition before using [`TelegramBatch::next_offset`].

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use automonique_connector_substrate::json::{StrictJsonError, strict_json};
use serde_json::Value;

mod slack;

pub use slack::{
    MAX_SLACK_ENVELOPE_BYTES, MAX_SLACK_IDENTIFIER_BYTES, MAX_SLACK_RETRY_ATTEMPT,
    MAX_SLACK_TEXT_BYTES, SlackAccessPolicy, SlackAckPlan, SlackAppId, SlackDisposition,
    SlackEnvelope, SlackEnvelopeId, SlackEnvelopeType, SlackError, SlackIngress, SlackInputKind,
    SlackPrincipal, SlackRefusal, SlackRetry, parse_slack_envelope,
};

/// Maximum response body accepted from one Telegram long poll.
pub const MAX_TELEGRAM_RESPONSE_BYTES: usize = 1024 * 1024;
/// Maximum updates accepted in one Telegram response.
pub const MAX_TELEGRAM_UPDATES: usize = 100;
/// Maximum text/callback bytes retained as a durable input.
pub const MAX_TELEGRAM_INPUT_BYTES: usize = 16 * 1024;
const MAX_POLICY_ENTRIES: usize = 1024;

/// Exact Telegram bot identity, excluding its bearer token.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct TelegramBotId(i64);

impl fmt::Debug for TelegramBotId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TelegramBotId(<redacted>)")
    }
}

impl TelegramBotId {
    /// Construct a positive Telegram bot identity.
    pub fn new(value: i64) -> Result<Self, TelegramError> {
        positive(value, "bot_id").map(Self)
    }

    /// Numeric Telegram identity.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// One exact chat/actor pair allowed to create work.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct TelegramPrincipal {
    chat_id: i64,
    actor_id: i64,
}

impl fmt::Debug for TelegramPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TelegramPrincipal(<redacted>)")
    }
}

impl TelegramPrincipal {
    /// Construct a principal. Chat IDs may be negative; actor IDs are positive.
    pub fn new(chat_id: i64, actor_id: i64) -> Result<Self, TelegramError> {
        if chat_id == 0 {
            return Err(TelegramError::InvalidField("chat_id"));
        }
        positive(actor_id, "actor_id")?;
        Ok(Self { chat_id, actor_id })
    }

    /// Telegram chat coordinate.
    #[must_use]
    pub const fn chat_id(self) -> i64 {
        self.chat_id
    }

    /// Telegram user coordinate.
    #[must_use]
    pub const fn actor_id(self) -> i64 {
        self.actor_id
    }
}

/// Immutable exact allowlist for one bot.
#[derive(Clone, Eq, PartialEq)]
pub struct TelegramAccessPolicy {
    bot_id: TelegramBotId,
    principals: BTreeSet<TelegramPrincipal>,
}

impl fmt::Debug for TelegramAccessPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelegramAccessPolicy")
            .field("bot_id", &"<redacted>")
            .field("principal_count", &self.principals.len())
            .finish()
    }
}

impl TelegramAccessPolicy {
    /// Construct a bounded nonempty allowlist.
    pub fn new(
        bot_id: TelegramBotId,
        principals: impl IntoIterator<Item = TelegramPrincipal>,
    ) -> Result<Self, TelegramError> {
        let principals: BTreeSet<_> = principals.into_iter().collect();
        if principals.is_empty() || principals.len() > MAX_POLICY_ENTRIES {
            return Err(TelegramError::InvalidField("principals"));
        }
        Ok(Self { bot_id, principals })
    }

    /// Bot identity bound into scopes and policy decisions.
    #[must_use]
    pub const fn bot_id(&self) -> TelegramBotId {
        self.bot_id
    }

    fn admits(&self, principal: TelegramPrincipal) -> bool {
        self.principals.contains(&principal)
    }
}

/// Telegram input class retained without platform markup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelegramInputKind {
    /// A plain message text.
    Message,
    /// An edit to an existing message. Retained, but never treated as a fresh
    /// command by the control bridge.
    EditedMessage,
    /// A message carrying one supported attachment class. Captions are
    /// retained as content but are never executed as commands.
    Attachment,
    /// A Telegram Business deletion notification. Telegram supplies no actor,
    /// so it is durable offset evidence only.
    DeletedMessage,
    /// An inline callback payload.
    Callback,
    /// A fresh Telegram update outside this build's admitted input surface.
    Unsupported,
}

/// Closed attachment classes recognized without downloading Telegram files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelegramAttachmentKind {
    Photo,
    Document,
    Audio,
    Video,
    Voice,
    Animation,
    Sticker,
}

impl TelegramAttachmentKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Photo => "photo",
            Self::Document => "document",
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Voice => "voice",
            Self::Animation => "animation",
            Self::Sticker => "sticker",
        }
    }
}

/// Closed access disposition that must be persisted before cursor advance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelegramDisposition {
    /// The exact bot/chat/actor tuple is allowlisted.
    Admitted,
    /// The update is well-formed but outside the exact allowlist.
    Denied,
    /// The update is durable for offset progress but creates no work.
    IgnoredUnsupported,
}

/// One owned bounded update ready for durable insertion.
#[derive(Clone, Eq, PartialEq)]
pub struct TelegramIngress {
    update_id: u64,
    message_id: Option<i64>,
    reply_to_message_id: Option<i64>,
    source_key: String,
    scope: String,
    principal: Option<TelegramPrincipal>,
    kind: TelegramInputKind,
    attachment_kind: Option<TelegramAttachmentKind>,
    content: Option<String>,
    disposition: TelegramDisposition,
    /// Telegram's identifier for one pressed inline button.
    ///
    /// Present only on a callback update, and only there because it is the one
    /// coordinate `answerCallbackQuery` needs and nothing else in this product
    /// can use. A press that arrives without one is not acknowledgeable, so a
    /// caller must treat `None` as "do not claim to have answered".
    callback_query_id: Option<String>,
}

impl fmt::Debug for TelegramIngress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelegramIngress")
            .field("update_id", &self.update_id)
            .field("message_id", &self.message_id.map(|_| "<redacted>"))
            .field(
                "reply_to_message_id",
                &self.reply_to_message_id.map(|_| "<redacted>"),
            )
            .field("source_key", &"<redacted>")
            .field("scope", &"<redacted>")
            .field("principal", &self.principal.map(|_| "<redacted>"))
            .field("kind", &self.kind)
            .field("attachment_kind", &self.attachment_kind)
            .field("content", &self.content.as_ref().map(|_| "<redacted>"))
            .field("disposition", &self.disposition)
            .field(
                "callback_query_id",
                &self.callback_query_id.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl TelegramIngress {
    /// Telegram's identifier for one pressed inline button.
    ///
    /// `None` for everything that is not an admitted callback. A caller
    /// without one must not claim to have acknowledged a press.
    #[must_use]
    pub fn callback_query_id(&self) -> Option<&str> {
        self.callback_query_id.as_deref()
    }

    /// Telegram update identity.
    #[must_use]
    pub const fn update_id(&self) -> u64 {
        self.update_id
    }

    /// Telegram message identity, when this ingress is a message.
    #[must_use]
    pub const fn message_id(&self) -> Option<i64> {
        self.message_id
    }

    /// Exact Telegram message this input replies to, when present.
    #[must_use]
    pub const fn reply_to_message_id(&self) -> Option<i64> {
        self.reply_to_message_id
    }

    /// Stable transport deduplication key.
    #[must_use]
    pub fn source_key(&self) -> &str {
        &self.source_key
    }

    /// Exact per-bot/chat scheduler scope.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Authenticated platform coordinates from the update.
    #[must_use]
    pub const fn principal(&self) -> Option<TelegramPrincipal> {
        self.principal
    }

    /// Input class.
    #[must_use]
    pub const fn kind(&self) -> TelegramInputKind {
        self.kind
    }

    /// Attachment class, when [`Self::kind`] is
    /// [`TelegramInputKind::Attachment`].
    #[must_use]
    pub const fn attachment_kind(&self) -> Option<TelegramAttachmentKind> {
        self.attachment_kind
    }

    /// Bounded input text/callback data.
    #[must_use]
    pub fn content(&self) -> Option<&str> {
        self.content.as_deref()
    }

    /// Exact access decision.
    #[must_use]
    pub const fn disposition(&self) -> TelegramDisposition {
        self.disposition
    }
}

/// One parsed poll response. The offset is a proposed durable commit value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelegramBatch {
    updates: Vec<TelegramIngress>,
    next_offset: u64,
}

impl TelegramBatch {
    /// Every fresh update, including denied inputs requiring durable evidence.
    #[must_use]
    pub fn updates(&self) -> &[TelegramIngress] {
        &self.updates
    }

    /// First update ID not represented by this batch or the prior cursor.
    #[must_use]
    pub const fn next_offset(&self) -> u64 {
        self.next_offset
    }
}

/// Typed fail-closed Telegram response refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelegramError {
    /// Response exceeded its byte or item bound.
    LimitExceeded,
    /// JSON syntax or exact response shape was invalid.
    InvalidResponse,
    /// A named identity/value was invalid.
    InvalidField(&'static str),
    /// Updates were duplicated or not strictly increasing.
    NonMonotonicUpdates,
    /// `last + 1` cannot be represented.
    OffsetExhausted,
}

impl TelegramError {
    /// Stable refusal category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::LimitExceeded => "telegram_limit_exceeded",
            Self::InvalidResponse => "telegram_invalid_response",
            Self::InvalidField(_) => "telegram_invalid_field",
            Self::NonMonotonicUpdates => "telegram_non_monotonic_updates",
            Self::OffsetExhausted => "telegram_offset_exhausted",
        }
    }
}

impl fmt::Display for TelegramError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.category())
    }
}

impl Error for TelegramError {}

/// A response that is not strictly valid JSON is one refusal, not a taxonomy.
///
/// The distinction that matters to a caller is that the response cannot be
/// trusted; which byte offended is a detail that would only reach a log line as
/// a fragment of a response body.
impl From<StrictJsonError> for TelegramError {
    fn from(_: StrictJsonError) -> Self {
        Self::InvalidResponse
    }
}

/// Parse an exact successful Telegram `getUpdates` response.
///
/// Updates below `current_offset` are ignored as already durable. Every fresh
/// update is returned, including denied principals and content-free unsupported
/// shapes, so the caller can persist the disposition and offset together.
pub fn parse_telegram_updates(
    bytes: &[u8],
    current_offset: u64,
    policy: &TelegramAccessPolicy,
) -> Result<TelegramBatch, TelegramError> {
    if bytes.is_empty() || bytes.len() > MAX_TELEGRAM_RESPONSE_BYTES {
        return Err(TelegramError::LimitExceeded);
    }
    let document = strict_json(bytes)?;
    let object = document.as_object().ok_or(TelegramError::InvalidResponse)?;
    if object.len() != 2 || object.get("ok") != Some(&Value::Bool(true)) {
        return Err(TelegramError::InvalidResponse);
    }
    let result = object
        .get("result")
        .and_then(Value::as_array)
        .ok_or(TelegramError::InvalidResponse)?;
    if result.len() > MAX_TELEGRAM_UPDATES {
        return Err(TelegramError::LimitExceeded);
    }
    let mut previous = None;
    let mut next_offset = current_offset;
    let mut updates = Vec::with_capacity(result.len());
    for value in result {
        let update_id = update_id(value)?;
        if previous.is_some_and(|prior| update_id <= prior) {
            return Err(TelegramError::NonMonotonicUpdates);
        }
        previous = Some(update_id);
        if update_id < current_offset {
            continue;
        }
        next_offset = update_id
            .checked_add(1)
            .ok_or(TelegramError::OffsetExhausted)?;
        updates.push(parse_fresh_update(value, update_id, policy)?);
    }
    Ok(TelegramBatch {
        updates,
        next_offset,
    })
}

fn update_id(value: &Value) -> Result<u64, TelegramError> {
    value
        .as_object()
        .and_then(|object| object.get("update_id"))
        .and_then(Value::as_u64)
        .ok_or(TelegramError::InvalidResponse)
}

fn parse_fresh_update(
    value: &Value,
    update_id: u64,
    policy: &TelegramAccessPolicy,
) -> Result<TelegramIngress, TelegramError> {
    let object = value.as_object().ok_or(TelegramError::InvalidResponse)?;
    let discriminators: Vec<_> = object
        .keys()
        .filter(|key| key.as_str() != "update_id")
        .collect();
    if discriminators.len() > 1 {
        return Err(TelegramError::InvalidResponse);
    }
    if discriminators.is_empty() {
        return Ok(unsupported_ingress(update_id, policy));
    }
    let discriminator = discriminators[0].as_str();
    let mut callback_query_id: Option<String> = None;
    let parsed = match discriminator {
        "message" => parse_message_update(object, "message", TelegramInputKind::Message)?,
        "edited_message" => {
            parse_message_update(object, "edited_message", TelegramInputKind::EditedMessage)?
        }
        "deleted_business_messages" => {
            let deleted = object
                .get("deleted_business_messages")
                .and_then(Value::as_object)
                .ok_or(TelegramError::InvalidResponse)?;
            let chat_id = nested_i64(deleted, &["chat", "id"])?;
            let message_ids = deleted
                .get("message_ids")
                .and_then(Value::as_array)
                .ok_or(TelegramError::InvalidResponse)?;
            if message_ids.is_empty()
                || message_ids.iter().any(|id| {
                    id.as_i64()
                        .is_none_or(|id| positive(id, "message_id").is_err())
                })
            {
                return Err(TelegramError::InvalidResponse);
            }
            return Ok(TelegramIngress {
                update_id,
                message_id: None,
                reply_to_message_id: None,
                source_key: format!("telegram:{}:update:{update_id}", policy.bot_id().get()),
                scope: format!("telegram:{}:{chat_id}", policy.bot_id().get()),
                principal: None,
                kind: TelegramInputKind::DeletedMessage,
                attachment_kind: None,
                callback_query_id: None,
                content: None,
                disposition: TelegramDisposition::IgnoredUnsupported,
            });
        }
        "callback_query" => {
            let Some(callback) = object.get("callback_query") else {
                return Err(TelegramError::InvalidResponse);
            };
            let callback = callback.as_object().ok_or(TelegramError::InvalidResponse)?;
            let has_data = callback.get("data").is_some();
            let has_game = callback.get("game_short_name").is_some();
            let has_message = callback.get("message").is_some();
            let has_inline_message = callback.get("inline_message_id").is_some();
            if has_data == has_game || has_message == has_inline_message {
                return Err(TelegramError::InvalidResponse);
            }
            if !has_data || !has_message {
                return Ok(unsupported_ingress(update_id, policy));
            }
            let actor_id = nested_i64(callback, &["from", "id"])?;
            let chat_id = nested_i64(callback, &["message", "chat", "id"])?;
            // Both coordinates a decision needs to be answered *in place*: the
            // query identifier dismisses the spinner, and the message
            // identifier is the keyboard that has to stop looking live. A
            // callback that carries neither cannot be acknowledged, and this is
            // where that is discovered rather than at send time.
            callback_query_id = Some(string(callback, "id")?.to_owned());
            Some((
                TelegramPrincipal::new(chat_id, actor_id)?,
                TelegramInputKind::Callback,
                string(callback, "data")?,
                Some(nested_i64(callback, &["message", "message_id"])?),
                None,
                None,
            ))
        }
        _ => None,
    };
    let Some((principal, kind, content, message_id, reply_to_message_id, attachment_kind)) = parsed
    else {
        return Ok(unsupported_ingress(update_id, policy));
    };
    if content.is_empty() || content.len() > MAX_TELEGRAM_INPUT_BYTES || content.contains('\0') {
        return Err(TelegramError::InvalidField("content"));
    }
    let disposition = if policy.admits(principal) {
        TelegramDisposition::Admitted
    } else {
        TelegramDisposition::Denied
    };
    Ok(TelegramIngress {
        update_id,
        message_id,
        reply_to_message_id,
        source_key: format!("telegram:{}:update:{update_id}", policy.bot_id().get()),
        scope: format!("telegram:{}:{}", policy.bot_id().get(), principal.chat_id()),
        principal: Some(principal),
        kind,
        attachment_kind,
        content: if disposition == TelegramDisposition::Admitted {
            Some(content.to_owned())
        } else {
            None
        },
        disposition,
        // Acknowledging a press this bot refused would tell whoever pressed it
        // that the button worked, so the coordinate travels only with an
        // admitted update.
        callback_query_id: if disposition == TelegramDisposition::Admitted {
            callback_query_id
        } else {
            None
        },
    })
}

type ParsedTelegramInput<'a> = (
    TelegramPrincipal,
    TelegramInputKind,
    &'a str,
    Option<i64>,
    Option<i64>,
    Option<TelegramAttachmentKind>,
);

fn parse_message_update<'a>(
    update: &'a serde_json::Map<String, Value>,
    field: &str,
    text_kind: TelegramInputKind,
) -> Result<Option<ParsedTelegramInput<'a>>, TelegramError> {
    let message = update
        .get(field)
        .and_then(Value::as_object)
        .ok_or(TelegramError::InvalidResponse)?;
    let attachment_candidates = [
        ("photo", TelegramAttachmentKind::Photo),
        ("document", TelegramAttachmentKind::Document),
        ("audio", TelegramAttachmentKind::Audio),
        ("video", TelegramAttachmentKind::Video),
        ("voice", TelegramAttachmentKind::Voice),
        ("animation", TelegramAttachmentKind::Animation),
        ("sticker", TelegramAttachmentKind::Sticker),
    ];
    let attachments: Vec<_> = attachment_candidates
        .into_iter()
        .filter(|(name, _)| message.contains_key(*name))
        .collect();
    if attachments.len() > 1 || (message.contains_key("text") && !attachments.is_empty()) {
        return Err(TelegramError::InvalidResponse);
    }
    let (kind, attachment_kind, content) = if let Some((_, attachment)) = attachments.first() {
        let content = match message.get("caption") {
            Some(Value::String(caption)) => caption.as_str(),
            Some(_) => return Err(TelegramError::InvalidResponse),
            None => attachment.as_str(),
        };
        let kind = if text_kind == TelegramInputKind::EditedMessage {
            TelegramInputKind::EditedMessage
        } else {
            TelegramInputKind::Attachment
        };
        (kind, Some(*attachment), content)
    } else {
        let content = match message.get("text") {
            Some(Value::String(content)) => content.as_str(),
            Some(_) => return Err(TelegramError::InvalidResponse),
            None => return Ok(None),
        };
        (text_kind, None, content)
    };
    let reply_to_message_id = message
        .get("reply_to_message")
        .map(|value| {
            value
                .as_object()
                .and_then(|reply| reply.get("message_id"))
                .and_then(Value::as_i64)
                .ok_or(TelegramError::InvalidResponse)
                .and_then(|id| positive(id, "reply_to_message_id"))
        })
        .transpose()?;
    let message_id = message
        .get("message_id")
        .map(|value| {
            value
                .as_i64()
                .ok_or(TelegramError::InvalidResponse)
                .and_then(|id| positive(id, "message_id"))
        })
        .transpose()?;
    Ok(Some((
        principal(message)?,
        kind,
        content,
        message_id,
        reply_to_message_id,
        attachment_kind,
    )))
}

fn unsupported_ingress(update_id: u64, policy: &TelegramAccessPolicy) -> TelegramIngress {
    TelegramIngress {
        update_id,
        message_id: None,
        reply_to_message_id: None,
        source_key: format!("telegram:{}:update:{update_id}", policy.bot_id().get()),
        scope: format!("telegram:{}:unsupported", policy.bot_id().get()),
        principal: None,
        callback_query_id: None,
        kind: TelegramInputKind::Unsupported,
        attachment_kind: None,
        content: None,
        disposition: TelegramDisposition::IgnoredUnsupported,
    }
}

fn principal(message: &serde_json::Map<String, Value>) -> Result<TelegramPrincipal, TelegramError> {
    TelegramPrincipal::new(
        nested_i64(message, &["chat", "id"])?,
        nested_i64(message, &["from", "id"])?,
    )
}

fn string<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, TelegramError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(TelegramError::InvalidResponse)
}

fn nested_i64(
    object: &serde_json::Map<String, Value>,
    path: &[&str],
) -> Result<i64, TelegramError> {
    let mut current = object.get(path[0]).ok_or(TelegramError::InvalidResponse)?;
    for key in &path[1..] {
        current = current
            .as_object()
            .and_then(|nested| nested.get(*key))
            .ok_or(TelegramError::InvalidResponse)?;
    }
    current.as_i64().ok_or(TelegramError::InvalidResponse)
}

fn positive(value: i64, field: &'static str) -> Result<i64, TelegramError> {
    if value > 0 {
        Ok(value)
    } else {
        Err(TelegramError::InvalidField(field))
    }
}
