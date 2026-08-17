// SPDX-License-Identifier: Elastic-2.0

//! Bounded, refusing decoders for the twelve bot-token methods and Socket Mode
//! bootstrap.
//!
//! Each decoder takes the accepted response bytes and returns either the
//! method's typed payload, Slack's own classified refusal, or a
//! [`SlackFailure`]. Nothing panics on hostile input and nothing is silently
//! repaired.
//!
//! # The envelope every method shares
//!
//! Slack answers every method with an object carrying `ok`. `ok: true` means
//! the rest of the object is the method's payload; `ok: false` means it carries
//! an `error` code instead. Both are well-formed answers, so both are `Ok`
//! here — the refusal as [`crate::SlackOutcome::Rejected`]. A body with no
//! `ok`, or an `ok` that is not a boolean, is not the Slack contract at all and
//! is [`SlackFailure::InvalidResponse`].
//!
//! # Why these refuse where the legacy client repairs
//!
//! The bot this contract came from reads `String(info?.channel?.name || "")`
//! and treats the empty result as "unresolved", and records `userNames.set(id,
//! id)` when a lookup throws — so an id becomes a display name. Each of those
//! turns a contract break into a plausible answer. Here every field the
//! contract names is required, and its absence is
//! [`SlackFailure::MissingField`].
//!
//! Three absences are *not* contract breaks and decode as the empty value they
//! mean:
//!
//! * a message `text` may be absent or empty — a Block Kit message carries no
//!   fallback text, and refusing to read it would hide a message that is
//!   genuinely on the channel;
//! * a message `user` is absent on a message an integration posted, which is
//!   exactly how a caller tells a human's message from an app's;
//! * a profile name Slack has not been given is the empty string, so an empty
//!   `display_name` or `real_name` decodes as absent rather than as a name that
//!   is blank.
//!
//! Unknown extra fields are tolerated. Slack adds fields on its own schedule
//! and refusing them would couple this connector to a platform release.

use automonique_connector_substrate::json::strict_json;
use serde_json::{Map, Value};

use crate::target::{ChannelId, Cursor, MessageTs, TeamId, UserId, is_workspace_url};
use crate::{
    MAX_INBOUND_TEXT_BYTES, MAX_NAME_BYTES, MAX_OPAQUE_BYTES, MAX_PAGE_LIMIT,
    MAX_SLACK_RESPONSE_BYTES, MAX_URL_BYTES, SlackErrorCode, SlackFailure, SlackOutcome,
    SlackRejection, SlackSocketUrl,
};

/// Highest thread reply count retained.
pub const MAX_REPLY_COUNT: u64 = 100_000;

/// Who a credential belongs to, as `auth.test` reports it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthIdentity {
    /// The workspace's own URL.
    pub url: String,
    /// The workspace's human name.
    pub team: String,
    /// The bot's human name.
    pub user: String,
    /// The workspace id.
    pub team_id: TeamId,
    /// The bot's user id.
    ///
    /// The single most load-bearing field here: a caller compares it against
    /// every message author to tell its own messages from everyone else's.
    pub user_id: UserId,
}

/// One conversation, as Slack reports it.
///
/// `Debug` is derived rather than redacted: a channel is the operator-facing
/// payload this connector exists to move. A caller that logs one is logging
/// workspace-adjacent data and must treat the record accordingly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackChannel {
    /// The conversation id.
    pub id: ChannelId,
    /// The channel name, without the leading `#`.
    pub name: String,
    /// Whether Slack calls this a channel.
    ///
    /// Carried as reported rather than asserted: a private channel converted
    /// from a legacy group reports `is_channel: false` and is still a channel a
    /// caller can read.
    pub is_channel: bool,
    /// Whether the channel is private.
    pub is_private: bool,
    /// Whether the channel is archived.
    pub is_archived: bool,
    /// Whether this token's bot is a member.
    ///
    /// Optional because Slack omits it in some listings, and absent is not
    /// `false`: a connector that read "Slack did not say" as "not a member"
    /// would refuse to post to channels it is in.
    pub is_member: Option<bool>,
}

/// One page of conversations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelPage {
    /// The conversations, in the order Slack returned them.
    pub channels: Vec<SlackChannel>,
    /// The cursor for the next page, when there is one.
    ///
    /// Slack spells "no more pages" as an empty cursor string; that decodes to
    /// `None` rather than to an empty cursor nobody could use.
    pub next_cursor: Option<Cursor>,
}

/// One message, as `conversations.history` reports it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackMessage {
    /// Slack's `type`, verbatim.
    pub kind: String,
    /// The author, when a member wrote it.
    ///
    /// Absent on a message an integration posted, which is how a caller tells a
    /// human's message from an app's.
    pub user: Option<UserId>,
    /// The integration that posted it, when one did.
    pub bot_id: Option<String>,
    /// The display name an integration posted under, when it set one.
    pub username: Option<String>,
    /// Slack's `subtype`, when the message is not a plain one.
    ///
    /// A join notice, a channel-topic change and a file share all arrive in
    /// history; the subtype is what tells them from something a human typed.
    pub subtype: Option<String>,
    /// The message text. Empty when Slack reports none.
    pub text: String,
    /// The message's identity and timestamp.
    pub ts: MessageTs,
    /// The thread parent, when the message is in a thread.
    ///
    /// Equal to [`SlackMessage::ts`] on the message that *started* the thread.
    pub thread_ts: Option<MessageTs>,
    /// How many replies the thread has — the count, not the replies.
    pub reply_count: Option<u32>,
    /// Distinct reply authors Slack included in the channel-history summary.
    ///
    /// This field is a summary, not reply order. `None` means Slack omitted the
    /// summary; an empty vector means it explicitly supplied no authors.
    pub reply_users: Option<Vec<UserId>>,
    /// Number of distinct reply authors Slack says the thread contains.
    ///
    /// Comparing this with `reply_users.len()` tells a caller whether Slack's
    /// author summary was complete before it draws a negative conclusion.
    pub reply_users_count: Option<u32>,
    /// Timestamp of the newest thread reply, when Slack supplied one.
    pub latest_reply: Option<MessageTs>,
}

impl SlackMessage {
    /// Whether a member — rather than an integration — wrote this message.
    #[must_use]
    pub const fn is_from_member(&self) -> bool {
        self.user.is_some() && self.bot_id.is_none()
    }

    /// Whether this message starts a thread rather than replying in one.
    ///
    /// A message with no thread, and the parent of a thread, are both
    /// top-level; only a reply is not. This is the same test the legacy bot
    /// spells inline at every call site.
    #[must_use]
    pub fn is_top_level(&self) -> bool {
        self.thread_ts
            .as_ref()
            .is_none_or(|thread| *thread == self.ts)
    }
}

/// One page of a conversation's messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessagePage {
    /// The messages, newest first, in the order Slack returned them.
    pub messages: Vec<SlackMessage>,
    /// Whether Slack has more messages in this window.
    pub has_more: bool,
    /// The cursor for the next page, when there is one.
    pub next_cursor: Option<Cursor>,
}

/// One user, as `users.info` reports them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackUser {
    /// The user id.
    pub id: UserId,
    /// The account handle.
    pub name: String,
    /// The real name, when the profile carries one.
    pub real_name: Option<String>,
    /// The display name, when the profile carries one.
    pub display_name: Option<String>,
    /// Whether the account is an integration, when Slack said.
    pub is_bot: Option<bool>,
    /// Whether the account is deactivated, when Slack said.
    ///
    /// Optional in both directions rather than defaulted: no value is invented
    /// for a field Slack did not send, because "Slack did not say" and "Slack
    /// said no" are different facts and only one of them is safe to act on.
    pub deleted: Option<bool>,
}

impl SlackUser {
    /// The name to show for this user.
    ///
    /// Display name, then real name, then handle — the legacy bot's own
    /// precedence, kept because changing it would rename people in every
    /// transcript this connector feeds.
    #[must_use]
    pub fn display_label(&self) -> &str {
        self.display_name
            .as_deref()
            .or(self.real_name.as_deref())
            .unwrap_or(&self.name)
    }
}

/// The message `chat.postMessage` put on the channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostedMessage {
    /// The conversation it landed in, as Slack resolved it.
    pub channel: ChannelId,
    /// The new message's identity.
    ///
    /// The value a caller keeps: it is what addresses this message again, and
    /// what makes a retry recognizable as a duplicate rather than a second
    /// post.
    pub ts: MessageTs,
    /// The message as Slack stored it.
    pub message: SlackMessage,
}

/// Coordinates Slack assigns to one native assistant stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamMessage {
    pub channel: ChannelId,
    pub ts: MessageTs,
}

/// Decode `auth.test`.
///
/// # Errors
///
/// Returns [`SlackFailure::InvalidResponse`] for a body that is not strict JSON
/// or not the `ok` envelope, [`SlackFailure::MissingField`] for an absent
/// contract field, and [`SlackFailure::FieldOutOfBounds`] for one past its
/// ceiling or outside its grammar.
pub fn decode_auth_test(bytes: &[u8]) -> Result<SlackOutcome<AuthIdentity>, SlackFailure> {
    let object = match envelope(bytes)? {
        Envelope::Accepted(object) => object,
        Envelope::Rejected(rejection) => return Ok(SlackOutcome::Rejected(rejection)),
    };
    let url = nonempty(&object, "url", MAX_URL_BYTES)?;
    if !is_workspace_url(&url) {
        return Err(SlackFailure::FieldOutOfBounds);
    }
    Ok(SlackOutcome::Accepted(AuthIdentity {
        url,
        team: nonempty(&object, "team", MAX_NAME_BYTES)?,
        user: nonempty(&object, "user", MAX_NAME_BYTES)?,
        team_id: TeamId::parse(&nonempty(&object, "team_id", MAX_NAME_BYTES)?)
            .ok_or(SlackFailure::FieldOutOfBounds)?,
        user_id: user_id(&object, "user_id")?,
    }))
}

/// Decode `apps.connections.open` into one credential-like websocket URL.
///
/// The shared Slack `ok` envelope is decoded exactly as the existing Web API
/// methods. A successful answer must contain one URL accepted by
/// [`SlackSocketUrl`]; HTTP, `ws`, non-Slack hosts, ports and missing tickets
/// are all [`SlackFailure::FieldOutOfBounds`].
pub fn decode_apps_connections_open(
    bytes: &[u8],
) -> Result<SlackOutcome<SlackSocketUrl>, SlackFailure> {
    let object = match envelope(bytes)? {
        Envelope::Accepted(object) => object,
        Envelope::Rejected(rejection) => return Ok(SlackOutcome::Rejected(rejection)),
    };
    let url = nonempty(
        &object,
        "url",
        crate::socket_mode::MAX_SOCKET_MODE_URL_BYTES,
    )?;
    SlackSocketUrl::new(&url)
        .map(SlackOutcome::Accepted)
        .map_err(|_| SlackFailure::FieldOutOfBounds)
}

/// Decode `conversations.list`.
///
/// # Errors
///
/// As [`decode_auth_test`], plus [`SlackFailure::TooManyItems`] for a page
/// longer than was asked for.
pub fn decode_conversations_list(
    bytes: &[u8],
    limit: u16,
) -> Result<SlackOutcome<ChannelPage>, SlackFailure> {
    let object = match envelope(bytes)? {
        Envelope::Accepted(object) => object,
        Envelope::Rejected(rejection) => return Ok(SlackOutcome::Rejected(rejection)),
    };
    let rows = rows(&object, "channels", limit)?;
    let mut channels = Vec::with_capacity(rows.len());
    for row in rows {
        channels.push(channel(
            row.as_object().ok_or(SlackFailure::InvalidResponse)?,
        )?);
    }
    Ok(SlackOutcome::Accepted(ChannelPage {
        channels,
        next_cursor: next_cursor(&object)?,
    }))
}

/// Decode `conversations.info`.
///
/// # Errors
///
/// As [`decode_auth_test`].
pub fn decode_conversations_info(bytes: &[u8]) -> Result<SlackOutcome<SlackChannel>, SlackFailure> {
    let object = match envelope(bytes)? {
        Envelope::Accepted(object) => object,
        Envelope::Rejected(rejection) => return Ok(SlackOutcome::Rejected(rejection)),
    };
    let row = object
        .get("channel")
        .ok_or(SlackFailure::MissingField)?
        .as_object()
        .ok_or(SlackFailure::FieldOutOfBounds)?;
    Ok(SlackOutcome::Accepted(channel(row)?))
}

/// Decode `conversations.history`.
///
/// # Errors
///
/// As [`decode_conversations_list`].
pub fn decode_conversations_history(
    bytes: &[u8],
    limit: u16,
) -> Result<SlackOutcome<MessagePage>, SlackFailure> {
    let object = match envelope(bytes)? {
        Envelope::Accepted(object) => object,
        Envelope::Rejected(rejection) => return Ok(SlackOutcome::Rejected(rejection)),
    };
    let rows = rows(&object, "messages", limit)?;
    let mut messages = Vec::with_capacity(rows.len());
    for row in rows {
        messages.push(message(
            row.as_object().ok_or(SlackFailure::InvalidResponse)?,
        )?);
    }
    Ok(SlackOutcome::Accepted(MessagePage {
        messages,
        has_more: flag(&object, "has_more")?,
        next_cursor: next_cursor(&object)?,
    }))
}

/// Decode `users.info`.
///
/// # Errors
///
/// As [`decode_auth_test`].
pub fn decode_users_info(bytes: &[u8]) -> Result<SlackOutcome<SlackUser>, SlackFailure> {
    let object = match envelope(bytes)? {
        Envelope::Accepted(object) => object,
        Envelope::Rejected(rejection) => return Ok(SlackOutcome::Rejected(rejection)),
    };
    let row = object
        .get("user")
        .ok_or(SlackFailure::MissingField)?
        .as_object()
        .ok_or(SlackFailure::FieldOutOfBounds)?;
    let profile = match row.get("profile") {
        None | Some(Value::Null) => None,
        Some(value) => Some(value.as_object().ok_or(SlackFailure::FieldOutOfBounds)?),
    };
    let display_name = match profile {
        Some(profile) => optional_name(profile, "display_name")?,
        None => None,
    };
    Ok(SlackOutcome::Accepted(SlackUser {
        id: user_id(row, "id")?,
        name: nonempty(row, "name", MAX_NAME_BYTES)?,
        real_name: optional_name(row, "real_name")?,
        display_name,
        is_bot: optional_flag(row, "is_bot")?,
        deleted: optional_flag(row, "deleted")?,
    }))
}

/// Decode `chat.postMessage`.
///
/// # Errors
///
/// As [`decode_auth_test`].
pub fn decode_post_message(bytes: &[u8]) -> Result<SlackOutcome<PostedMessage>, SlackFailure> {
    let object = match envelope(bytes)? {
        Envelope::Accepted(object) => object,
        Envelope::Rejected(rejection) => return Ok(SlackOutcome::Rejected(rejection)),
    };
    let row = object
        .get("message")
        .ok_or(SlackFailure::MissingField)?
        .as_object()
        .ok_or(SlackFailure::FieldOutOfBounds)?;
    Ok(SlackOutcome::Accepted(PostedMessage {
        channel: ChannelId::new(&nonempty(&object, "channel", MAX_NAME_BYTES)?)
            .map_err(|_| SlackFailure::FieldOutOfBounds)?,
        ts: timestamp(&object, "ts")?,
        message: message(row)?,
    }))
}

/// Decode the coordinates returned by each native streaming method.
pub fn decode_stream_message(bytes: &[u8]) -> Result<SlackOutcome<StreamMessage>, SlackFailure> {
    let object = match envelope(bytes)? {
        Envelope::Accepted(object) => object,
        Envelope::Rejected(rejection) => return Ok(SlackOutcome::Rejected(rejection)),
    };
    Ok(SlackOutcome::Accepted(StreamMessage {
        channel: ChannelId::new(&nonempty(&object, "channel", MAX_NAME_BYTES)?)
            .map_err(|_| SlackFailure::FieldOutOfBounds)?,
        ts: timestamp(&object, "ts")?,
    }))
}

/// Decode a method whose accepted response needs no returned fields.
pub fn decode_ack(bytes: &[u8]) -> Result<SlackOutcome<()>, SlackFailure> {
    Ok(match envelope(bytes)? {
        Envelope::Accepted(_) => SlackOutcome::Accepted(()),
        Envelope::Rejected(rejection) => SlackOutcome::Rejected(rejection),
    })
}

/// Read the `error` code off a refusal document, or name the fallback.
///
/// Never an error: a refusal that is `text/plain`, empty, or missing its
/// `error` is still a refusal, and the status it arrived with already carries
/// the actionable part. This is how a `429` is classified without demanding
/// that Slack's rate-limit answer be JSON, which it historically is not.
#[must_use]
pub fn decode_error_code(bytes: &[u8], fallback: &str) -> SlackErrorCode {
    let named = if bytes.is_empty() || bytes.len() > MAX_SLACK_RESPONSE_BYTES {
        None
    } else {
        strict_json(bytes).ok().and_then(|value| match value {
            Value::Object(object) => object
                .get("error")
                .and_then(Value::as_str)
                .map(SlackErrorCode::sanitized),
            _ => None,
        })
    };
    named.unwrap_or_else(|| SlackErrorCode::sanitized(fallback))
}

/// One well-formed Slack answer, before the method's own fields are read.
enum Envelope {
    Accepted(Map<String, Value>),
    Rejected(SlackRejection),
}

/// Read the `{"ok": …}` envelope every Slack method answers with.
fn envelope(bytes: &[u8]) -> Result<Envelope, SlackFailure> {
    if bytes.len() > MAX_SLACK_RESPONSE_BYTES {
        return Err(SlackFailure::ResponseTooLarge);
    }
    if bytes.is_empty() {
        return Err(SlackFailure::InvalidResponse);
    }
    let Value::Object(object) = strict_json(bytes)? else {
        return Err(SlackFailure::InvalidResponse);
    };
    match object.get("ok") {
        Some(Value::Bool(true)) => Ok(Envelope::Accepted(object)),
        Some(Value::Bool(false)) => {
            // Slack always names the refusal. A body that says `ok: false` and
            // nothing else is not the contract, and reporting it as an
            // unexplained rejection would invent a reason.
            let code = required_str(&object, "error")?;
            Ok(Envelope::Rejected(SlackRejection::new(
                SlackErrorCode::sanitized(code),
                None,
            )))
        }
        _ => Err(SlackFailure::InvalidResponse),
    }
}

/// Read one bounded array field off an accepted envelope.
fn rows<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    limit: u16,
) -> Result<&'a Vec<Value>, SlackFailure> {
    let rows = object
        .get(key)
        .ok_or(SlackFailure::MissingField)?
        .as_array()
        .ok_or(SlackFailure::InvalidResponse)?;
    if rows.len() > limit as usize || rows.len() > MAX_PAGE_LIMIT as usize {
        return Err(SlackFailure::TooManyItems);
    }
    Ok(rows)
}

/// Read the cursor a cursor-paginated method hands back.
fn next_cursor(object: &Map<String, Value>) -> Result<Option<Cursor>, SlackFailure> {
    let metadata = match object.get("response_metadata") {
        None | Some(Value::Null) => return Ok(None),
        Some(value) => value.as_object().ok_or(SlackFailure::FieldOutOfBounds)?,
    };
    match metadata.get("next_cursor") {
        // Slack spells "no more pages" as the empty string.
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => Cursor::new(value)
            .map(Some)
            .map_err(|_| SlackFailure::FieldOutOfBounds),
        Some(_) => Err(SlackFailure::FieldOutOfBounds),
    }
}

/// Decode one conversation, requiring every field the contract names.
fn channel(row: &Map<String, Value>) -> Result<SlackChannel, SlackFailure> {
    Ok(SlackChannel {
        id: ChannelId::new(&nonempty(row, "id", MAX_NAME_BYTES)?)
            .map_err(|_| SlackFailure::FieldOutOfBounds)?,
        name: nonempty(row, "name", MAX_NAME_BYTES)?,
        is_channel: flag(row, "is_channel")?,
        is_private: flag(row, "is_private")?,
        is_archived: flag(row, "is_archived")?,
        is_member: optional_flag(row, "is_member")?,
    })
}

/// Decode one message, requiring every field the contract names.
fn message(row: &Map<String, Value>) -> Result<SlackMessage, SlackFailure> {
    let reply_count = match row.get("reply_count") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let count = value.as_u64().ok_or(SlackFailure::FieldOutOfBounds)?;
            if count > MAX_REPLY_COUNT {
                return Err(SlackFailure::FieldOutOfBounds);
            }
            Some(u32::try_from(count).map_err(|_| SlackFailure::FieldOutOfBounds)?)
        }
    };
    let reply_users = match row.get("reply_users") {
        None | Some(Value::Null) => None,
        Some(Value::Array(values)) => {
            if values.len() > MAX_REPLY_COUNT as usize {
                return Err(SlackFailure::FieldOutOfBounds);
            }
            Some(
                values
                    .iter()
                    .map(|value| {
                        let user = value.as_str().ok_or(SlackFailure::FieldOutOfBounds)?;
                        UserId::new(user).map_err(|_| SlackFailure::FieldOutOfBounds)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        Some(_) => return Err(SlackFailure::FieldOutOfBounds),
    };
    let reply_users_count = match row.get("reply_users_count") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let count = value.as_u64().ok_or(SlackFailure::FieldOutOfBounds)?;
            if count > MAX_REPLY_COUNT {
                return Err(SlackFailure::FieldOutOfBounds);
            }
            Some(u32::try_from(count).map_err(|_| SlackFailure::FieldOutOfBounds)?)
        }
    };
    Ok(SlackMessage {
        kind: nonempty(row, "type", MAX_OPAQUE_BYTES)?,
        user: optional_user_id(row, "user")?,
        bot_id: optional_bounded(row, "bot_id", MAX_OPAQUE_BYTES)?,
        username: optional_bounded(row, "username", MAX_NAME_BYTES)?,
        subtype: optional_bounded(row, "subtype", MAX_OPAQUE_BYTES)?,
        text: optional_text(row, "text", MAX_INBOUND_TEXT_BYTES)?,
        ts: timestamp(row, "ts")?,
        thread_ts: optional_timestamp(row, "thread_ts")?,
        reply_count,
        reply_users,
        reply_users_count,
        latest_reply: optional_timestamp(row, "latest_reply")?,
    })
}

/// A required string field, present and a string.
fn required_str<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, SlackFailure> {
    object
        .get(key)
        .ok_or(SlackFailure::MissingField)?
        .as_str()
        .ok_or(SlackFailure::FieldOutOfBounds)
}

/// A required string field, bounded and control-free, that may not be empty.
fn nonempty(
    object: &Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<String, SlackFailure> {
    let value = required_str(object, key)?;
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(SlackFailure::FieldOutOfBounds);
    }
    Ok(value.to_owned())
}

/// An optional string field, bounded and control-free.
///
/// Absent, `null` and empty all decode as absent: Slack writes the empty string
/// for a field it has no value for.
fn optional_bounded(
    object: &Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<Option<String>, SlackFailure> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => {
            if value.len() > max_bytes || value.chars().any(char::is_control) {
                return Err(SlackFailure::FieldOutOfBounds);
            }
            Ok(Some(value.clone()))
        }
        Some(_) => Err(SlackFailure::FieldOutOfBounds),
    }
}

/// An optional human name.
fn optional_name(object: &Map<String, Value>, key: &str) -> Result<Option<String>, SlackFailure> {
    optional_bounded(object, key, MAX_NAME_BYTES)
}

/// A message body, whose absence Slack spells as `null` or the empty string.
///
/// Newlines and tabs are admitted — a Slack message is multi-line — but every
/// other control character is refused, so a message can never drive a terminal
/// that prints it.
fn optional_text(
    object: &Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<String, SlackFailure> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => {
            if value.len() > max_bytes
                || value
                    .chars()
                    .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
            {
                return Err(SlackFailure::FieldOutOfBounds);
            }
            Ok(value.clone())
        }
        Some(_) => Err(SlackFailure::FieldOutOfBounds),
    }
}

/// A required boolean.
fn flag(object: &Map<String, Value>, key: &str) -> Result<bool, SlackFailure> {
    object
        .get(key)
        .ok_or(SlackFailure::MissingField)?
        .as_bool()
        .ok_or(SlackFailure::FieldOutOfBounds)
}

/// A boolean Slack may or may not have sent.
fn optional_flag(object: &Map<String, Value>, key: &str) -> Result<Option<bool>, SlackFailure> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(SlackFailure::FieldOutOfBounds),
    }
}

/// A required message timestamp.
fn timestamp(object: &Map<String, Value>, key: &str) -> Result<MessageTs, SlackFailure> {
    MessageTs::new(required_str(object, key)?).map_err(|_| SlackFailure::FieldOutOfBounds)
}

/// A message timestamp Slack sends only when it applies.
fn optional_timestamp(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<MessageTs>, SlackFailure> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => MessageTs::new(value)
            .map(Some)
            .map_err(|_| SlackFailure::FieldOutOfBounds),
        Some(_) => Err(SlackFailure::FieldOutOfBounds),
    }
}

/// A required user id.
fn user_id(object: &Map<String, Value>, key: &str) -> Result<UserId, SlackFailure> {
    UserId::new(required_str(object, key)?).map_err(|_| SlackFailure::FieldOutOfBounds)
}

/// A user id Slack sends only when a member wrote the message.
fn optional_user_id(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<UserId>, SlackFailure> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => UserId::new(value)
            .map(Some)
            .map_err(|_| SlackFailure::FieldOutOfBounds),
        Some(_) => Err(SlackFailure::FieldOutOfBounds),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SlackErrorKind;

    const CHANNEL: &str = "C0RESERVED";
    const USER: &str = "U0RESERVED";
    const TEAM: &str = "T0RESERVED";

    fn auth_json() -> String {
        format!(
            r#"{{"ok":true,"url":"https://exemple-reserve.invalid/","team":"Exemple",
               "user":"monique","team_id":"{TEAM}","user_id":"{USER}",
               "bot_id":"B0RESERVED","is_enterprise_install":false}}"#
        )
    }

    fn channel_json() -> String {
        format!(
            r#"{{"id":"{CHANNEL}","name":"general","is_channel":true,"is_group":false,
               "is_im":false,"created":1723542000,"is_archived":false,"is_general":true,
               "is_private":false,"is_member":true}}"#
        )
    }

    fn message_json() -> String {
        format!(
            r#"{{"type":"message","user":"{USER}","text":"le paiement echoue",
               "ts":"1723542000.000100","thread_ts":"1723542000.000100","reply_count":2,
               "reply_users":["U0MONIQUE9","{USER}"],"reply_users_count":2,
               "latest_reply":"1723542200.000300"}}"#
        )
    }

    fn user_json() -> String {
        format!(
            r#"{{"id":"{USER}","team_id":"{TEAM}","name":"claire","real_name":"Claire Martin",
               "deleted":false,"is_bot":false,
               "profile":{{"display_name":"Claire","real_name":"Claire Martin"}}}}"#
        )
    }

    #[test]
    fn auth_test_decodes_every_contract_field() {
        let identity = decode_auth_test(auth_json().as_bytes())
            .expect("decode")
            .accepted()
            .expect("accepted")
            .clone();
        assert_eq!(identity.url, "https://exemple-reserve.invalid/");
        assert_eq!(identity.team, "Exemple");
        assert_eq!(identity.user, "monique");
        assert_eq!(identity.team_id.as_str(), TEAM);
        assert_eq!(identity.user_id.as_str(), USER);
    }

    #[test]
    fn a_conversation_page_decodes_and_carries_its_cursor() {
        let body = format!(
            r#"{{"ok":true,"channels":[{}],"response_metadata":{{"next_cursor":"dGVhbTpDMg=="}}}}"#,
            channel_json()
        );
        let page = decode_conversations_list(body.as_bytes(), 200)
            .expect("decode")
            .accepted()
            .expect("accepted")
            .clone();
        assert_eq!(page.channels.len(), 1);
        assert_eq!(page.channels[0].id.as_str(), CHANNEL);
        assert_eq!(page.channels[0].name, "general");
        assert!(page.channels[0].is_channel);
        assert!(!page.channels[0].is_private);
        assert!(!page.channels[0].is_archived);
        assert_eq!(page.channels[0].is_member, Some(true));
        assert_eq!(
            page.next_cursor.as_ref().map(Cursor::as_str),
            Some("dGVhbTpDMg==")
        );

        // Slack spells the last page as an empty cursor.
        let last = format!(
            r#"{{"ok":true,"channels":[{}],"response_metadata":{{"next_cursor":""}}}}"#,
            channel_json()
        );
        assert_eq!(
            decode_conversations_list(last.as_bytes(), 200)
                .expect("decode")
                .accepted()
                .expect("accepted")
                .next_cursor,
            None
        );

        // And omits the metadata altogether on some answers.
        let bare = format!(r#"{{"ok":true,"channels":[{}]}}"#, channel_json());
        assert_eq!(
            decode_conversations_list(bare.as_bytes(), 200)
                .expect("decode")
                .accepted()
                .expect("accepted")
                .next_cursor,
            None
        );

        // One conversation on its own decodes by the same path.
        let info = format!(r#"{{"ok":true,"channel":{}}}"#, channel_json());
        assert_eq!(
            decode_conversations_info(info.as_bytes())
                .expect("decode")
                .accepted()
                .expect("accepted")
                .id
                .as_str(),
            CHANNEL
        );
    }

    #[test]
    fn a_history_page_decodes_every_message_shape_history_actually_carries() {
        let integration = r#"{"type":"message","subtype":"bot_message","bot_id":"B0RESERVED",
            "username":"Monique","text":"ticket recu","ts":"1723542100.000200"}"#;
        let body = format!(
            r#"{{"ok":true,"messages":[{},{}],"has_more":true,
               "response_metadata":{{"next_cursor":"bmV4dF90czox"}}}}"#,
            message_json(),
            integration
        );
        let page = decode_conversations_history(body.as_bytes(), 200)
            .expect("decode")
            .accepted()
            .expect("accepted")
            .clone();
        assert!(page.has_more);
        assert_eq!(
            page.next_cursor.as_ref().map(Cursor::as_str),
            Some("bmV4dF90czox")
        );
        assert_eq!(page.messages.len(), 2);

        let human = &page.messages[0];
        assert_eq!(human.kind, "message");
        assert_eq!(human.user.as_ref().map(UserId::as_str), Some(USER));
        assert_eq!(human.text, "le paiement echoue");
        assert_eq!(human.ts.as_str(), "1723542000.000100");
        assert_eq!(human.reply_count, Some(2));
        assert_eq!(
            human
                .reply_users
                .as_ref()
                .expect("reply users")
                .iter()
                .map(UserId::as_str)
                .collect::<Vec<_>>(),
            ["U0MONIQUE9", USER]
        );
        assert_eq!(human.reply_users_count, Some(2));
        assert_eq!(
            human.latest_reply.as_ref().map(MessageTs::as_str),
            Some("1723542200.000300")
        );
        assert!(human.is_from_member());
        assert!(
            human.is_top_level(),
            "a thread parent is still a top-level message"
        );

        let app = &page.messages[1];
        assert_eq!(app.user, None);
        assert_eq!(app.bot_id.as_deref(), Some("B0RESERVED"));
        assert_eq!(app.username.as_deref(), Some("Monique"));
        assert_eq!(app.subtype.as_deref(), Some("bot_message"));
        assert_eq!(app.thread_ts, None);
        assert_eq!(app.reply_count, None);
        assert!(!app.is_from_member());
        assert!(app.is_top_level());

        // A reply is the one shape that is not top level.
        let reply = r#"{"ok":true,"messages":[{"type":"message","user":"U0RESERVED",
            "text":"merci","ts":"1723542200.000300","thread_ts":"1723542000.000100"}],
            "has_more":false}"#;
        let page = decode_conversations_history(reply.as_bytes(), 200)
            .expect("decode")
            .accepted()
            .expect("accepted")
            .clone();
        assert!(!page.messages[0].is_top_level());
        assert!(!page.has_more);
    }

    #[test]
    fn a_blocks_only_message_decodes_as_empty_text_rather_than_being_refused() {
        for absent in ["\"text\":\"\",", "\"text\":null,", ""] {
            let body = format!(
                "{{\"ok\":true,\"messages\":[{{\"type\":\"message\",\"user\":\"{USER}\",\
                 {absent}\"ts\":\"1723542000.000100\"}}],\"has_more\":false}}"
            );
            let page = decode_conversations_history(body.as_bytes(), 200)
                .expect("decode")
                .accepted()
                .expect("accepted")
                .clone();
            assert_eq!(page.messages[0].text, "", "spelling {absent:?}");
        }
    }

    #[test]
    fn a_user_decodes_with_the_legacy_display_precedence() {
        let body = format!(r#"{{"ok":true,"user":{}}}"#, user_json());
        let user = decode_users_info(body.as_bytes())
            .expect("decode")
            .accepted()
            .expect("accepted")
            .clone();
        assert_eq!(user.id.as_str(), USER);
        assert_eq!(user.name, "claire");
        assert_eq!(user.real_name.as_deref(), Some("Claire Martin"));
        assert_eq!(user.display_name.as_deref(), Some("Claire"));
        assert_eq!(user.is_bot, Some(false));
        assert_eq!(user.deleted, Some(false));
        assert_eq!(user.display_label(), "Claire");

        // Slack writes the empty string for a display name nobody set, and the
        // label falls back the way the legacy bot falls back.
        let unset = format!(
            r#"{{"ok":true,"user":{{"id":"{USER}","name":"claire",
               "real_name":"Claire Martin","profile":{{"display_name":""}}}}}}"#
        );
        let user = decode_users_info(unset.as_bytes())
            .expect("decode")
            .accepted()
            .expect("accepted")
            .clone();
        assert_eq!(user.display_name, None);
        assert_eq!(user.display_label(), "Claire Martin");
        assert_eq!(
            user.is_bot, None,
            "a field Slack did not send is absent, never a default"
        );

        let handle_only = format!(r#"{{"ok":true,"user":{{"id":"{USER}","name":"claire"}}}}"#);
        assert_eq!(
            decode_users_info(handle_only.as_bytes())
                .expect("decode")
                .accepted()
                .expect("accepted")
                .display_label(),
            "claire"
        );
    }

    #[test]
    fn a_posted_message_decodes_the_identity_a_caller_keeps() {
        let body = format!(
            r#"{{"ok":true,"channel":"{CHANNEL}","ts":"1723542300.000400",
               "message":{{"type":"message","subtype":"bot_message","bot_id":"B0RESERVED",
               "text":"bonjour","ts":"1723542300.000400"}}}}"#
        );
        let posted = decode_post_message(body.as_bytes())
            .expect("decode")
            .accepted()
            .expect("accepted")
            .clone();
        assert_eq!(posted.channel.as_str(), CHANNEL);
        assert_eq!(posted.ts.as_str(), "1723542300.000400");
        assert_eq!(posted.message.text, "bonjour");
        assert_eq!(posted.message.ts, posted.ts);
    }

    #[test]
    fn an_ok_false_answer_is_a_classified_rejection_rather_than_a_failure() {
        for (code, kind) in [
            ("not_in_channel", SlackErrorKind::NotInChannel),
            ("channel_not_found", SlackErrorKind::ChannelNotFound),
            ("invalid_auth", SlackErrorKind::InvalidAuth),
            ("ratelimited", SlackErrorKind::RateLimited),
        ] {
            let body = format!(r#"{{"ok":false,"error":"{code}"}}"#);
            let rejection = decode_conversations_history(body.as_bytes(), 200)
                .expect("an ok:false answer is well-formed, not a failure")
                .rejected()
                .expect("rejected")
                .clone();
            assert_eq!(rejection.code().as_str(), code);
            assert_eq!(rejection.kind(), kind);
            assert_eq!(rejection.retry_after_seconds(), None);
        }

        // Every method reads the same envelope.
        let body = br#"{"ok":false,"error":"missing_scope","needed":"channels:read"}"#;
        assert!(decode_auth_test(body).expect("decode").rejected().is_some());
        assert!(
            decode_conversations_list(body, 200)
                .expect("decode")
                .rejected()
                .is_some()
        );
        assert!(
            decode_conversations_info(body)
                .expect("decode")
                .rejected()
                .is_some()
        );
        assert!(
            decode_users_info(body)
                .expect("decode")
                .rejected()
                .is_some()
        );
        assert!(
            decode_post_message(body)
                .expect("decode")
                .rejected()
                .is_some()
        );
    }

    #[test]
    fn every_named_field_is_required_and_its_absence_is_a_typed_refusal() {
        for key in ["url", "team", "user", "team_id", "user_id"] {
            let mut row: Value = serde_json::from_str(&auth_json()).expect("row");
            row.as_object_mut().expect("object").remove(key);
            assert_eq!(
                decode_auth_test(row.to_string().as_bytes()),
                Err(SlackFailure::MissingField),
                "dropping {key} must be refused, not decoded"
            );
        }
        for key in ["id", "name", "is_channel", "is_private", "is_archived"] {
            let mut row: Value = serde_json::from_str(&channel_json()).expect("row");
            row.as_object_mut().expect("object").remove(key);
            let body = format!(r#"{{"ok":true,"channel":{row}}}"#);
            assert_eq!(
                decode_conversations_info(body.as_bytes()),
                Err(SlackFailure::MissingField),
                "dropping {key} must be refused, not decoded"
            );
        }
        for key in ["type", "ts"] {
            let mut row: Value = serde_json::from_str(&message_json()).expect("row");
            row.as_object_mut().expect("object").remove(key);
            let body = format!(r#"{{"ok":true,"messages":[{row}],"has_more":false}}"#);
            assert_eq!(
                decode_conversations_history(body.as_bytes(), 200),
                Err(SlackFailure::MissingField),
                "dropping {key} must be refused, not decoded"
            );
        }
        // The page's own fields are required too.
        assert_eq!(
            decode_conversations_history(br#"{"ok":true,"messages":[]}"#, 200),
            Err(SlackFailure::MissingField),
        );
        assert_eq!(
            decode_conversations_history(br#"{"ok":true,"has_more":false}"#, 200),
            Err(SlackFailure::MissingField),
        );
        for key in ["id", "name"] {
            let mut row: Value = serde_json::from_str(&user_json()).expect("row");
            row.as_object_mut().expect("object").remove(key);
            let body = format!(r#"{{"ok":true,"user":{row}}}"#);
            assert_eq!(
                decode_users_info(body.as_bytes()),
                Err(SlackFailure::MissingField),
                "dropping {key} must be refused, not decoded"
            );
        }
    }

    #[test]
    fn a_substituted_value_the_legacy_reader_would_invent_is_refused() {
        // `String(info?.channel?.name || "")` — an empty name is not a name.
        let mut row: Value = serde_json::from_str(&channel_json()).expect("row");
        row.as_object_mut()
            .expect("object")
            .insert("name".to_owned(), Value::String(String::new()));
        let body = format!(r#"{{"ok":true,"channel":{row}}}"#);
        assert_eq!(
            decode_conversations_info(body.as_bytes()),
            Err(SlackFailure::FieldOutOfBounds)
        );

        // An id that is not a Slack id cannot be addressed again.
        let mut row: Value = serde_json::from_str(&channel_json()).expect("row");
        row.as_object_mut()
            .expect("object")
            .insert("id".to_owned(), Value::String("general".to_owned()));
        let body = format!(r#"{{"ok":true,"channel":{row}}}"#);
        assert_eq!(
            decode_conversations_info(body.as_bytes()),
            Err(SlackFailure::FieldOutOfBounds)
        );

        // A timestamp read as a number loses the suffix that identifies it.
        let mut row: Value = serde_json::from_str(&message_json()).expect("row");
        row.as_object_mut()
            .expect("object")
            .insert("ts".to_owned(), Value::Number(1_723_542_000.into()));
        let body = format!(r#"{{"ok":true,"messages":[{row}],"has_more":false}}"#);
        assert_eq!(
            decode_conversations_history(body.as_bytes(), 200),
            Err(SlackFailure::FieldOutOfBounds)
        );
    }

    #[test]
    fn a_page_longer_than_was_asked_for_is_refused() {
        let body = format!(
            r#"{{"ok":true,"messages":[{},{}],"has_more":false}}"#,
            message_json(),
            message_json()
        );
        assert_eq!(
            decode_conversations_history(body.as_bytes(), 1),
            Err(SlackFailure::TooManyItems)
        );
        assert!(decode_conversations_history(body.as_bytes(), 2).is_ok());

        let body = format!(
            r#"{{"ok":true,"channels":[{},{}]}}"#,
            channel_json(),
            channel_json()
        );
        assert_eq!(
            decode_conversations_list(body.as_bytes(), 1),
            Err(SlackFailure::TooManyItems)
        );
    }

    #[test]
    fn malformed_bodies_are_typed_refusals_rather_than_panics() {
        let cases: [(&[u8], SlackFailure); 9] = [
            (b"", SlackFailure::InvalidResponse),
            (b"not json", SlackFailure::InvalidResponse),
            (b"[]", SlackFailure::InvalidResponse),
            (b"null", SlackFailure::InvalidResponse),
            // No `ok` at all is not the Slack envelope.
            (
                br#"{"url":"https://x.invalid/"}"#,
                SlackFailure::InvalidResponse,
            ),
            (br#"{"ok":"true"}"#, SlackFailure::InvalidResponse),
            (br#"{"ok":1}"#, SlackFailure::InvalidResponse),
            // Two `ok` fields would let a reader and this decoder disagree.
            (
                br#"{"ok":false,"ok":true,"error":"x"}"#,
                SlackFailure::InvalidResponse,
            ),
            (br#"{"ok":true}{"ok":true}"#, SlackFailure::InvalidResponse),
        ];
        for (body, expected) in cases {
            assert_eq!(decode_auth_test(body), Err(expected), "body {body:?}");
        }
        // `ok: false` with no reason is not the contract either.
        assert_eq!(
            decode_auth_test(br#"{"ok":false}"#),
            Err(SlackFailure::MissingField)
        );
        // A collection field of the wrong shape is refused, not iterated.
        assert_eq!(
            decode_conversations_history(br#"{"ok":true,"messages":{},"has_more":false}"#, 200),
            Err(SlackFailure::InvalidResponse)
        );
        assert_eq!(
            decode_conversations_history(br#"{"ok":true,"messages":[7],"has_more":false}"#, 200),
            Err(SlackFailure::InvalidResponse)
        );
    }

    #[test]
    fn a_refusal_document_yields_slacks_own_code_or_the_named_stand_in() {
        assert_eq!(
            decode_error_code(br#"{"ok":false,"error":"ratelimited"}"#, "fallback").as_str(),
            "ratelimited"
        );
        // A 429 has historically answered in plain text; the status is still
        // the news.
        assert_eq!(
            decode_error_code(b"Too many requests", "ratelimited").as_str(),
            "ratelimited"
        );
        assert_eq!(
            decode_error_code(b"", "ratelimited").as_str(),
            "ratelimited"
        );
        assert_eq!(
            decode_error_code(br#"{"ok":false}"#, "ratelimited").as_str(),
            "ratelimited"
        );
        // Remote text is sanitized on the way in.
        assert_eq!(
            decode_error_code(br#"{"error":"rate\u001b[2Jlimited"}"#, "x").as_str(),
            "rate [2Jlimited"
        );
        let oversized = vec![b'a'; MAX_SLACK_RESPONSE_BYTES + 1];
        assert_eq!(
            decode_error_code(&oversized, "ratelimited").as_str(),
            "ratelimited"
        );
    }

    #[test]
    fn an_oversized_body_is_refused_before_a_field_is_read() {
        let oversized = vec![b'a'; MAX_SLACK_RESPONSE_BYTES + 1];
        assert_eq!(
            decode_auth_test(&oversized),
            Err(SlackFailure::ResponseTooLarge)
        );
        assert_eq!(
            decode_conversations_history(&oversized, 200),
            Err(SlackFailure::ResponseTooLarge)
        );
    }

    #[test]
    fn a_control_bearing_field_is_refused_so_a_row_cannot_drive_a_terminal() {
        let mut row: Value = serde_json::from_str(&channel_json()).expect("row");
        row.as_object_mut().expect("object").insert(
            "name".to_owned(),
            Value::String("general\u{1b}[2J".to_owned()),
        );
        let body = format!(r#"{{"ok":true,"channel":{row}}}"#);
        assert_eq!(
            decode_conversations_info(body.as_bytes()),
            Err(SlackFailure::FieldOutOfBounds)
        );

        // A message keeps its newlines and refuses everything else.
        let mut row: Value = serde_json::from_str(&message_json()).expect("row");
        row.as_object_mut()
            .expect("object")
            .insert("text".to_owned(), Value::String("ligne\nun".to_owned()));
        let body = format!(r#"{{"ok":true,"messages":[{row}],"has_more":false}}"#);
        assert!(decode_conversations_history(body.as_bytes(), 200).is_ok());

        let mut row: Value = serde_json::from_str(&message_json()).expect("row");
        row.as_object_mut()
            .expect("object")
            .insert("text".to_owned(), Value::String("cloche\u{7}".to_owned()));
        let body = format!(r#"{{"ok":true,"messages":[{row}],"has_more":false}}"#);
        assert_eq!(
            decode_conversations_history(body.as_bytes(), 200),
            Err(SlackFailure::FieldOutOfBounds)
        );
    }

    #[test]
    fn every_field_ceiling_is_exact() {
        for (width, expected) in [(MAX_NAME_BYTES, true), (MAX_NAME_BYTES + 1, false)] {
            let mut row: Value = serde_json::from_str(&channel_json()).expect("row");
            row.as_object_mut()
                .expect("object")
                .insert("name".to_owned(), Value::String("n".repeat(width)));
            let body = format!(r#"{{"ok":true,"channel":{row}}}"#);
            assert_eq!(
                decode_conversations_info(body.as_bytes()).is_ok(),
                expected,
                "name at {width} bytes"
            );
        }
        for (width, expected) in [
            (MAX_INBOUND_TEXT_BYTES, true),
            (MAX_INBOUND_TEXT_BYTES + 1, false),
        ] {
            let mut row: Value = serde_json::from_str(&message_json()).expect("row");
            row.as_object_mut()
                .expect("object")
                .insert("text".to_owned(), Value::String("t".repeat(width)));
            let body = format!(r#"{{"ok":true,"messages":[{row}],"has_more":false}}"#);
            assert_eq!(
                decode_conversations_history(body.as_bytes(), 200).is_ok(),
                expected,
                "text at {width} bytes"
            );
        }
        for (count, expected) in [(MAX_REPLY_COUNT, true), (MAX_REPLY_COUNT + 1, false)] {
            let mut row: Value = serde_json::from_str(&message_json()).expect("row");
            row.as_object_mut()
                .expect("object")
                .insert("reply_count".to_owned(), Value::Number(count.into()));
            let body = format!(r#"{{"ok":true,"messages":[{row}],"has_more":false}}"#);
            assert_eq!(
                decode_conversations_history(body.as_bytes(), 200).is_ok(),
                expected,
                "reply_count {count}"
            );
        }
    }

    #[test]
    fn unknown_extra_fields_are_tolerated_so_a_platform_release_does_not_break_a_read() {
        let mut row: Value = serde_json::from_str(&message_json()).expect("row");
        row.as_object_mut().expect("object").insert(
            "blocks".to_owned(),
            serde_json::json!([{"type": "rich_text", "block_id": "aB1"}]),
        );
        let body = format!(r#"{{"ok":true,"messages":[{row}],"has_more":false}}"#);
        assert!(decode_conversations_history(body.as_bytes(), 200).is_ok());

        // Including a warning riding alongside a successful answer.
        let warned = format!(
            r#"{{"ok":true,"warning":"missing_charset","channel":{}}}"#,
            channel_json()
        );
        assert!(decode_conversations_info(warned.as_bytes()).is_ok());
    }
}
