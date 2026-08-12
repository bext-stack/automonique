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

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

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
    /// An inline callback payload.
    Callback,
    /// A fresh Telegram update outside this build's admitted input surface.
    Unsupported,
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
    source_key: String,
    scope: String,
    principal: Option<TelegramPrincipal>,
    kind: TelegramInputKind,
    content: Option<String>,
    disposition: TelegramDisposition,
}

impl fmt::Debug for TelegramIngress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelegramIngress")
            .field("update_id", &self.update_id)
            .field("source_key", &"<redacted>")
            .field("scope", &"<redacted>")
            .field("principal", &self.principal.map(|_| "<redacted>"))
            .field("kind", &self.kind)
            .field("content", &self.content.as_ref().map(|_| "<redacted>"))
            .field("disposition", &self.disposition)
            .finish()
    }
}

impl TelegramIngress {
    /// Telegram update identity.
    #[must_use]
    pub const fn update_id(&self) -> u64 {
        self.update_id
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

struct StrictJson;

impl<'de> DeserializeSeed<'de> for StrictJson {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys or non-finite numbers")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite floating-point value"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictJson)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate object key"));
            }
            values.insert(key, map.next_value_seed(StrictJson)?);
        }
        Ok(Value::Object(values))
    }
}

fn strict_json(bytes: &[u8]) -> Result<Value, TelegramError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJson
        .deserialize(&mut deserializer)
        .map_err(|_| TelegramError::InvalidResponse)?;
    deserializer
        .end()
        .map_err(|_| TelegramError::InvalidResponse)?;
    Ok(value)
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
    let parsed = match discriminator {
        "message" => {
            let Some(message) = object.get("message") else {
                return Err(TelegramError::InvalidResponse);
            };
            let message = message.as_object().ok_or(TelegramError::InvalidResponse)?;
            let content = match message.get("text") {
                None => return Ok(unsupported_ingress(update_id, policy)),
                Some(Value::String(content)) => content.as_str(),
                Some(_) => return Err(TelegramError::InvalidResponse),
            };
            Some((principal(message)?, TelegramInputKind::Message, content))
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
            Some((
                TelegramPrincipal::new(chat_id, actor_id)?,
                TelegramInputKind::Callback,
                string(callback, "data")?,
            ))
        }
        _ => None,
    };
    let Some((principal, kind, content)) = parsed else {
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
        source_key: format!("telegram:{}:update:{update_id}", policy.bot_id().get()),
        scope: format!("telegram:{}:{}", policy.bot_id().get(), principal.chat_id()),
        principal: Some(principal),
        kind,
        content: if disposition == TelegramDisposition::Admitted {
            Some(content.to_owned())
        } else {
            None
        },
        disposition,
    })
}

fn unsupported_ingress(update_id: u64, policy: &TelegramAccessPolicy) -> TelegramIngress {
    TelegramIngress {
        update_id,
        source_key: format!("telegram:{}:update:{update_id}", policy.bot_id().get()),
        scope: format!("telegram:{}:unsupported", policy.bot_id().get()),
        principal: None,
        kind: TelegramInputKind::Unsupported,
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
