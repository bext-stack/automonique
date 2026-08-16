// SPDX-License-Identifier: Elastic-2.0

//! The twelve methods, and the exact path and body each renders.
//!
//! [`SlackMethod`] is the second half of the target lock (the first is the
//! origin in `target`). A path is never a caller string: it is one of twelve
//! private constants under a private `/api` prefix, and a layer talked into
//! asking for `chat.delete` or `admin.conversations.archive` cannot spell one,
//! because no variant exists.
//!
//! Every argument travels form-encoded in a `POST` body rather than in a query
//! string. This is not a free choice: Slack's read methods
//! (`conversations.info`, `conversations.history`, `users.info`,
//! `conversations.list`) reject a JSON request body with `invalid_arguments`
//! even under a `Bearer` credential — confirmed against the live API — so
//! `application/x-www-form-urlencoded` is the one spelling every method accepts.
//! A `POST` body keeps every caller value out of the URL entirely, which is what
//! makes the target lock a statement about the whole request, not its path
//! alone. Every value is percent-encoded through the audited
//! [`crate::push_form_value`]; nothing is interpolated raw, and the keys are the
//! fixed ASCII argument names below.
//!
//! Field order within a body is fixed and documented per method. A server reads
//! the fields order-insensitively, so this is a testability property rather than
//! a protocol one: it lets a test assert one exact captured request instead of a
//! set of permutations.

use crate::target::{ChannelId, Cursor, MessageTs, UserId};
use crate::{MAX_MESSAGE_TEXT_BYTES, MAX_PAGE_LIMIT, SlackRefusal, is_body_text, push_form_value};

/// Append one `key=value` field to a form body, prefixed with `&` unless it is
/// the first field.
///
/// The key is one of the fixed ASCII argument names in [`SlackOperation::body`],
/// every one of which is already within the unreserved set, so only the value is
/// percent-encoded.
fn push_form_field(out: &mut String, key: &str, value: &str) {
    if !out.is_empty() {
        out.push('&');
    }
    out.push_str(key);
    out.push('=');
    push_form_value(out, value);
}

/// The prefix every Slack Web API method hangs from.
const API_PREFIX: &str = "/api";

/// The six method names, spelled once each.
const AUTH_TEST: &str = "auth.test";
const CONVERSATIONS_LIST: &str = "conversations.list";
const CONVERSATIONS_INFO: &str = "conversations.info";
const CONVERSATIONS_HISTORY: &str = "conversations.history";
const USERS_INFO: &str = "users.info";
const CHAT_POST_MESSAGE: &str = "chat.postMessage";
const CHAT_UPDATE: &str = "chat.update";
const CHAT_START_STREAM: &str = "chat.startStream";
const CHAT_APPEND_STREAM: &str = "chat.appendStream";
const CHAT_STOP_STREAM: &str = "chat.stopStream";
const VIEWS_OPEN: &str = "views.open";
const VIEWS_PUBLISH: &str = "views.publish";

/// Largest serialized Block Kit document this connector will send.
pub const MAX_BLOCK_KIT_BYTES: usize = 32 * 1024;
/// Slack's documented maximum blocks in a message.
pub const MAX_MESSAGE_BLOCKS: usize = 50;

/// The closed set of Web API methods this connector can address.
///
/// Nothing outside this enum is reachable: the client renders its URL from
/// [`SlackMethod::path`] and from a [`crate::SlackBase`], and neither accepts a
/// caller-supplied string.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SlackMethod {
    /// `auth.test` — identify the credential.
    AuthTest,
    /// `conversations.list` — page the conversations the token can see.
    ConversationsList,
    /// `conversations.info` — read one conversation.
    ConversationsInfo,
    /// `conversations.history` — page a conversation's recent messages.
    ConversationsHistory,
    /// `users.info` — resolve one user.
    UsersInfo,
    /// `chat.postMessage` — post one message.
    ChatPostMessage,
    /// `chat.update` — replace one existing bot message.
    ChatUpdate,
    /// `chat.startStream` — start one native assistant stream in a thread.
    ChatStartStream,
    /// `chat.appendStream` — append bounded content to one native stream.
    ChatAppendStream,
    /// `chat.stopStream` — finish one native stream, optionally with blocks.
    ChatStopStream,
    /// `views.open` — open one modal for an interaction trigger.
    ViewsOpen,
    /// `views.publish` — publish one App Home view.
    ViewsPublish,
}

impl SlackMethod {
    /// The exact method name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthTest => AUTH_TEST,
            Self::ConversationsList => CONVERSATIONS_LIST,
            Self::ConversationsInfo => CONVERSATIONS_INFO,
            Self::ConversationsHistory => CONVERSATIONS_HISTORY,
            Self::UsersInfo => USERS_INFO,
            Self::ChatPostMessage => CHAT_POST_MESSAGE,
            Self::ChatUpdate => CHAT_UPDATE,
            Self::ChatStartStream => CHAT_START_STREAM,
            Self::ChatAppendStream => CHAT_APPEND_STREAM,
            Self::ChatStopStream => CHAT_STOP_STREAM,
            Self::ViewsOpen => VIEWS_OPEN,
            Self::ViewsPublish => VIEWS_PUBLISH,
        }
    }

    /// The exact request path, credential-free and argument-free.
    #[must_use]
    pub fn path(self) -> String {
        format!("{API_PREFIX}/{}", self.as_str())
    }
}

/// One bounded Slack interaction trigger id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerId(String);

impl TriggerId {
    pub fn new(value: &str) -> Result<Self, SlackRefusal> {
        if value.is_empty()
            || value.len() > 256
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(SlackRefusal::TriggerId);
        }
        Ok(Self(value.to_owned()))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One validated Slack modal view JSON object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModalView(String);

impl ModalView {
    pub fn new(json: &str) -> Result<Self, SlackRefusal> {
        if json.is_empty() || json.len() > MAX_BLOCK_KIT_BYTES {
            return Err(SlackRefusal::View);
        }
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|_| SlackRefusal::View)?;
        let object = value.as_object().ok_or(SlackRefusal::View)?;
        if object.get("type").and_then(serde_json::Value::as_str) != Some("modal")
            || !object
                .get("blocks")
                .is_some_and(serde_json::Value::is_array)
        {
            return Err(SlackRefusal::View);
        }
        Ok(Self(json.to_owned()))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One validated Slack App Home view JSON object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HomeView(String);

impl HomeView {
    pub fn new(json: &str) -> Result<Self, SlackRefusal> {
        if json.is_empty() || json.len() > MAX_BLOCK_KIT_BYTES {
            return Err(SlackRefusal::View);
        }
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|_| SlackRefusal::View)?;
        let object = value.as_object().ok_or(SlackRefusal::View)?;
        if object.get("type").and_then(serde_json::Value::as_str) != Some("home")
            || !object
                .get("blocks")
                .is_some_and(serde_json::Value::is_array)
        {
            return Err(SlackRefusal::View);
        }
        Ok(Self(json.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated JSON array of Slack Block Kit message blocks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageBlocks(String);

impl MessageBlocks {
    pub fn new(json: &str) -> Result<Self, SlackRefusal> {
        if json.is_empty() || json.len() > MAX_BLOCK_KIT_BYTES {
            return Err(SlackRefusal::Blocks);
        }
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|_| SlackRefusal::Blocks)?;
        let blocks = value.as_array().ok_or(SlackRefusal::Blocks)?;
        if blocks.is_empty() || blocks.len() > MAX_MESSAGE_BLOCKS {
            return Err(SlackRefusal::Blocks);
        }
        for block in blocks {
            let kind = block
                .as_object()
                .and_then(|row| row.get("type"))
                .and_then(serde_json::Value::as_str)
                .ok_or(SlackRefusal::Blocks)?;
            if !matches!(
                kind,
                "section" | "context" | "actions" | "header" | "divider"
            ) {
                return Err(SlackRefusal::Blocks);
            }
        }
        Ok(Self(json.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Which conversation types a listing covers.
///
/// Only the two channel shapes are selectable. A Slack `im` or `mpim` object
/// carries no `name`, so decoding one through [`crate::SlackChannel`] would
/// mean reporting the empty string as a channel name — the exact repair this
/// crate refuses elsewhere. Reading a direct message is still possible: its id
/// is a [`ChannelId`], and `conversations.history` takes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConversationTypes {
    public_channels: bool,
    private_channels: bool,
}

impl ConversationTypes {
    /// Both channel shapes — what an operator almost always means.
    #[must_use]
    pub const fn all_channels() -> Self {
        Self {
            public_channels: true,
            private_channels: true,
        }
    }

    /// Select the two shapes independently.
    ///
    /// # Errors
    ///
    /// Returns [`SlackRefusal::ConversationTypes`] when neither is selected: an
    /// empty `types` would make Slack apply its own default rather than the
    /// caller's, which is a listing nobody asked for.
    pub const fn new(public_channels: bool, private_channels: bool) -> Result<Self, SlackRefusal> {
        if !public_channels && !private_channels {
            return Err(SlackRefusal::ConversationTypes);
        }
        Ok(Self {
            public_channels,
            private_channels,
        })
    }

    /// The exact wire value of the `types` argument.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match (self.public_channels, self.private_channels) {
            (true, true) => "public_channel,private_channel",
            (true, false) => "public_channel",
            (false, true) => "private_channel",
            // Unreachable through the constructors, which refuse the empty set.
            (false, false) => "public_channel",
        }
    }

    /// Whether public channels are covered.
    #[must_use]
    pub const fn public_channels(self) -> bool {
        self.public_channels
    }

    /// Whether private channels are covered.
    #[must_use]
    pub const fn private_channels(self) -> bool {
        self.private_channels
    }
}

impl Default for ConversationTypes {
    fn default() -> Self {
        Self::all_channels()
    }
}

/// Validate one page size.
///
/// The legacy bot passes whatever number a caller had to hand; a size outside
/// the bound is refused here rather than clamped, because a clamp hides a
/// caller that believed it was paging.
const fn checked_limit(limit: u16) -> Result<u16, SlackRefusal> {
    if limit == 0 || limit > MAX_PAGE_LIMIT {
        return Err(SlackRefusal::Limit);
    }
    Ok(limit)
}

/// Text to post to a channel.
///
/// Bounded at Slack's own [`MAX_MESSAGE_TEXT_BYTES`] ceiling and free of
/// control characters other than tab and newline, so a message this connector
/// sends can never drive a terminal that logs it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageText(String);

impl MessageText {
    /// Validate one message body.
    ///
    /// # Errors
    ///
    /// Returns [`SlackRefusal::Text`] for text that is empty, over
    /// [`MAX_MESSAGE_TEXT_BYTES`], or control-bearing. Empty is refused rather
    /// than sent: Slack answers `no_text`, and a message with nothing in it is
    /// never what a caller meant.
    pub fn new(value: &str) -> Result<Self, SlackRefusal> {
        if is_body_text(value, MAX_MESSAGE_TEXT_BYTES) {
            Ok(Self(value.to_owned()))
        } else {
            Err(SlackRefusal::Text)
        }
    }

    /// The exact text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Markdown carried by one Slack streaming call.
///
/// Slack caps `markdown_text` at 12,000 characters. This byte bound is tighter
/// for non-ASCII input and keeps request sizing deterministic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamText(String);

/// Largest markdown payload accepted by one streaming call.
pub const MAX_STREAM_TEXT_BYTES: usize = 12_000;

impl StreamText {
    pub fn new(value: &str) -> Result<Self, SlackRefusal> {
        if is_body_text(value, MAX_STREAM_TEXT_BYTES) {
            Ok(Self(value.to_owned()))
        } else {
            Err(SlackRefusal::Stream)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A bounded JSON array of Slack streaming chunks.
///
/// Only the two chunk kinds this product emits are admitted: `markdown_text`
/// and `task_update`. Keeping the JSON typed here prevents progress labels from
/// becoming request structure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamChunks(String);

impl StreamChunks {
    pub fn new(json: &str) -> Result<Self, SlackRefusal> {
        if json.is_empty() || json.len() > MAX_BLOCK_KIT_BYTES {
            return Err(SlackRefusal::Stream);
        }
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|_| SlackRefusal::Stream)?;
        let chunks = value.as_array().ok_or(SlackRefusal::Stream)?;
        if chunks.is_empty() || chunks.len() > MAX_MESSAGE_BLOCKS {
            return Err(SlackRefusal::Stream);
        }
        for chunk in chunks {
            let row = chunk.as_object().ok_or(SlackRefusal::Stream)?;
            let kind = row
                .get("type")
                .and_then(serde_json::Value::as_str)
                .ok_or(SlackRefusal::Stream)?;
            match kind {
                "markdown_text" => {
                    let text = row
                        .get("text")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(SlackRefusal::Stream)?;
                    StreamText::new(text)?;
                }
                "task_update" => {
                    let id = row
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(SlackRefusal::Stream)?;
                    let title = row
                        .get("title")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(SlackRefusal::Stream)?;
                    let status = row
                        .get("status")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(SlackRefusal::Stream)?;
                    if id.is_empty()
                        || id.len() > 256
                        || title.is_empty()
                        || title.len() > 256
                        || !matches!(status, "pending" | "in_progress" | "complete" | "error")
                    {
                        return Err(SlackRefusal::Stream);
                    }
                }
                _ => return Err(SlackRefusal::Stream),
            }
        }
        Ok(Self(json.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Page the conversations this token can see.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationsListRequest {
    types: ConversationTypes,
    limit: u16,
    cursor: Option<Cursor>,
}

impl ConversationsListRequest {
    /// Ask for one page of one type selection.
    ///
    /// # Errors
    ///
    /// Returns [`SlackRefusal::Limit`] for a size outside
    /// `1..=`[`MAX_PAGE_LIMIT`].
    pub fn new(types: ConversationTypes, limit: u16) -> Result<Self, SlackRefusal> {
        Ok(Self {
            types,
            limit: checked_limit(limit)?,
            cursor: None,
        })
    }

    /// Continue from the cursor a previous page returned.
    #[must_use]
    pub fn from_cursor(mut self, cursor: Cursor) -> Self {
        self.cursor = Some(cursor);
        self
    }

    /// The type selection.
    #[must_use]
    pub const fn types(&self) -> ConversationTypes {
        self.types
    }

    /// The page size.
    #[must_use]
    pub const fn limit(&self) -> u16 {
        self.limit
    }

    /// The cursor, when this is a continuation.
    #[must_use]
    pub const fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }
}

/// Read one conversation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationsInfoRequest {
    channel: ChannelId,
}

impl ConversationsInfoRequest {
    /// Name one conversation.
    #[must_use]
    pub const fn new(channel: ChannelId) -> Self {
        Self { channel }
    }

    /// The conversation.
    #[must_use]
    pub const fn channel(&self) -> &ChannelId {
        &self.channel
    }
}

/// Page one conversation's recent messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationsHistoryRequest {
    channel: ChannelId,
    limit: u16,
    cursor: Option<Cursor>,
    oldest: Option<MessageTs>,
}

impl ConversationsHistoryRequest {
    /// Ask for one page of one conversation's messages.
    ///
    /// # Errors
    ///
    /// Returns [`SlackRefusal::Limit`] for a size outside
    /// `1..=`[`MAX_PAGE_LIMIT`].
    pub fn new(channel: ChannelId, limit: u16) -> Result<Self, SlackRefusal> {
        Ok(Self {
            channel,
            limit: checked_limit(limit)?,
            cursor: None,
            oldest: None,
        })
    }

    /// Continue from the cursor a previous page returned.
    #[must_use]
    pub fn from_cursor(mut self, cursor: Cursor) -> Self {
        self.cursor = Some(cursor);
        self
    }

    /// Only messages at or after this instant.
    #[must_use]
    pub fn since(mut self, oldest: MessageTs) -> Self {
        self.oldest = Some(oldest);
        self
    }

    /// The conversation.
    #[must_use]
    pub const fn channel(&self) -> &ChannelId {
        &self.channel
    }

    /// The page size.
    #[must_use]
    pub const fn limit(&self) -> u16 {
        self.limit
    }

    /// The cursor, when this is a continuation.
    #[must_use]
    pub const fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    /// The window start, when one is set.
    #[must_use]
    pub const fn oldest(&self) -> Option<&MessageTs> {
        self.oldest.as_ref()
    }
}

/// Resolve one user.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsersInfoRequest {
    user: UserId,
}

impl UsersInfoRequest {
    /// Name one user.
    #[must_use]
    pub const fn new(user: UserId) -> Self {
        Self { user }
    }

    /// The user.
    #[must_use]
    pub const fn user(&self) -> &UserId {
        &self.user
    }
}

/// Post one message to a conversation. An externally visible effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostMessageRequest {
    channel: ChannelId,
    text: MessageText,
    thread_ts: Option<MessageTs>,
    blocks: Option<MessageBlocks>,
}

impl PostMessageRequest {
    /// Bind one conversation to one message body.
    #[must_use]
    pub const fn new(channel: ChannelId, text: MessageText) -> Self {
        Self {
            channel,
            text,
            thread_ts: None,
            blocks: None,
        }
    }

    /// Post as a reply in the thread this message started.
    ///
    /// Named for the parent rather than for the field, because a caller who
    /// passes the *reply's* timestamp here starts a thread on the wrong
    /// message.
    #[must_use]
    pub fn in_thread(mut self, parent: MessageTs) -> Self {
        self.thread_ts = Some(parent);
        self
    }

    /// Attach validated Block Kit while retaining `text` as the accessibility fallback.
    #[must_use]
    pub fn with_blocks(mut self, blocks: MessageBlocks) -> Self {
        self.blocks = Some(blocks);
        self
    }

    /// The conversation.
    #[must_use]
    pub const fn channel(&self) -> &ChannelId {
        &self.channel
    }

    /// The message body.
    #[must_use]
    pub const fn text(&self) -> &MessageText {
        &self.text
    }

    /// The thread parent, when this is a reply.
    #[must_use]
    pub const fn thread_ts(&self) -> Option<&MessageTs> {
        self.thread_ts.as_ref()
    }

    #[must_use]
    pub const fn blocks(&self) -> Option<&MessageBlocks> {
        self.blocks.as_ref()
    }
}

/// Replace one exact bot message with new accessible text and optional blocks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateMessageRequest {
    channel: ChannelId,
    ts: MessageTs,
    text: MessageText,
    blocks: Option<MessageBlocks>,
}

/// Open a modal in response to one short-lived Slack interaction trigger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenViewRequest {
    trigger_id: TriggerId,
    view: ModalView,
}

impl OpenViewRequest {
    #[must_use]
    pub const fn new(trigger_id: TriggerId, view: ModalView) -> Self {
        Self { trigger_id, view }
    }
    #[must_use]
    pub const fn trigger_id(&self) -> &TriggerId {
        &self.trigger_id
    }
    #[must_use]
    pub const fn view(&self) -> &ModalView {
        &self.view
    }
}

/// Publish one user's App Home.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishViewRequest {
    user_id: UserId,
    view: HomeView,
}

impl PublishViewRequest {
    #[must_use]
    pub const fn new(user_id: UserId, view: HomeView) -> Self {
        Self { user_id, view }
    }
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }
    #[must_use]
    pub const fn view(&self) -> &HomeView {
        &self.view
    }
}

impl UpdateMessageRequest {
    #[must_use]
    pub const fn new(channel: ChannelId, ts: MessageTs, text: MessageText) -> Self {
        Self {
            channel,
            ts,
            text,
            blocks: None,
        }
    }

    #[must_use]
    pub fn with_blocks(mut self, blocks: MessageBlocks) -> Self {
        self.blocks = Some(blocks);
        self
    }

    #[must_use]
    pub const fn channel(&self) -> &ChannelId {
        &self.channel
    }
    #[must_use]
    pub const fn ts(&self) -> &MessageTs {
        &self.ts
    }
    #[must_use]
    pub const fn text(&self) -> &MessageText {
        &self.text
    }
    #[must_use]
    pub const fn blocks(&self) -> Option<&MessageBlocks> {
        self.blocks.as_ref()
    }
}

/// Start one native stream as a reply to an existing message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartStreamRequest {
    channel: ChannelId,
    thread_ts: MessageTs,
    markdown_text: Option<StreamText>,
}

impl StartStreamRequest {
    #[must_use]
    pub const fn new(channel: ChannelId, thread_ts: MessageTs) -> Self {
        Self {
            channel,
            thread_ts,
            markdown_text: None,
        }
    }

    #[must_use]
    pub fn with_markdown(mut self, text: StreamText) -> Self {
        self.markdown_text = Some(text);
        self
    }

    #[must_use]
    pub const fn channel(&self) -> &ChannelId {
        &self.channel
    }
    #[must_use]
    pub const fn thread_ts(&self) -> &MessageTs {
        &self.thread_ts
    }
    #[must_use]
    pub const fn markdown_text(&self) -> Option<&StreamText> {
        self.markdown_text.as_ref()
    }
}

/// Append one bounded chunk array to a native stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppendStreamRequest {
    channel: ChannelId,
    ts: MessageTs,
    markdown_text: StreamText,
    chunks: Option<StreamChunks>,
}

impl AppendStreamRequest {
    #[must_use]
    pub const fn new(channel: ChannelId, ts: MessageTs, markdown_text: StreamText) -> Self {
        Self {
            channel,
            ts,
            markdown_text,
            chunks: None,
        }
    }
    #[must_use]
    pub fn with_chunks(mut self, chunks: StreamChunks) -> Self {
        self.chunks = Some(chunks);
        self
    }
    #[must_use]
    pub const fn channel(&self) -> &ChannelId {
        &self.channel
    }
    #[must_use]
    pub const fn ts(&self) -> &MessageTs {
        &self.ts
    }
    #[must_use]
    pub const fn markdown_text(&self) -> &StreamText {
        &self.markdown_text
    }
    #[must_use]
    pub const fn chunks(&self) -> Option<&StreamChunks> {
        self.chunks.as_ref()
    }
}

/// Stop one native stream and attach final accessible content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopStreamRequest {
    channel: ChannelId,
    ts: MessageTs,
    markdown_text: StreamText,
    blocks: Option<MessageBlocks>,
}

impl StopStreamRequest {
    #[must_use]
    pub const fn new(channel: ChannelId, ts: MessageTs, markdown_text: StreamText) -> Self {
        Self {
            channel,
            ts,
            markdown_text,
            blocks: None,
        }
    }
    #[must_use]
    pub fn with_blocks(mut self, blocks: MessageBlocks) -> Self {
        self.blocks = Some(blocks);
        self
    }
    #[must_use]
    pub const fn channel(&self) -> &ChannelId {
        &self.channel
    }
    #[must_use]
    pub const fn ts(&self) -> &MessageTs {
        &self.ts
    }
    #[must_use]
    pub const fn markdown_text(&self) -> &StreamText {
        &self.markdown_text
    }
    #[must_use]
    pub const fn blocks(&self) -> Option<&MessageBlocks> {
        self.blocks.as_ref()
    }
}

/// One validated call, ready to be rendered onto the wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SlackOperation {
    /// `auth.test`
    AuthTest,
    /// `conversations.list`
    ConversationsList(ConversationsListRequest),
    /// `conversations.info`
    ConversationsInfo(ConversationsInfoRequest),
    /// `conversations.history`
    ConversationsHistory(ConversationsHistoryRequest),
    /// `users.info`
    UsersInfo(UsersInfoRequest),
    /// `chat.postMessage`
    ChatPostMessage(PostMessageRequest),
    /// `chat.update`
    ChatUpdate(UpdateMessageRequest),
    /// `chat.startStream`
    ChatStartStream(StartStreamRequest),
    /// `chat.appendStream`
    ChatAppendStream(AppendStreamRequest),
    /// `chat.stopStream`
    ChatStopStream(StopStreamRequest),
    /// `views.open`
    ViewsOpen(OpenViewRequest),
    /// `views.publish`
    ViewsPublish(PublishViewRequest),
}

impl SlackOperation {
    /// The method this call addresses.
    #[must_use]
    pub const fn method(&self) -> SlackMethod {
        match self {
            Self::AuthTest => SlackMethod::AuthTest,
            Self::ConversationsList(_) => SlackMethod::ConversationsList,
            Self::ConversationsInfo(_) => SlackMethod::ConversationsInfo,
            Self::ConversationsHistory(_) => SlackMethod::ConversationsHistory,
            Self::UsersInfo(_) => SlackMethod::UsersInfo,
            Self::ChatPostMessage(_) => SlackMethod::ChatPostMessage,
            Self::ChatUpdate(_) => SlackMethod::ChatUpdate,
            Self::ChatStartStream(_) => SlackMethod::ChatStartStream,
            Self::ChatAppendStream(_) => SlackMethod::ChatAppendStream,
            Self::ChatStopStream(_) => SlackMethod::ChatStopStream,
            Self::ViewsOpen(_) => SlackMethod::ViewsOpen,
            Self::ViewsPublish(_) => SlackMethod::ViewsPublish,
        }
    }

    /// Whether this call changes something other people can see.
    ///
    /// An approval layer keys on this rather than re-deriving it from a verb:
    /// every one of these methods is a `POST`, so the verb says nothing, and
    /// exactly one of them puts a message in front of a human.
    #[must_use]
    pub const fn is_external_effect(&self) -> bool {
        matches!(
            self,
            Self::ChatPostMessage(_)
                | Self::ChatUpdate(_)
                | Self::ChatStartStream(_)
                | Self::ChatAppendStream(_)
                | Self::ChatStopStream(_)
                | Self::ViewsOpen(_)
                | Self::ViewsPublish(_)
        )
    }

    /// The exact form-encoded body, in the documented field order.
    ///
    /// Credential-free by construction, so a host may log or fixture it. Every
    /// value is percent-encoded; `auth.test` takes no argument and sends the
    /// empty body.
    #[must_use]
    pub fn body(&self) -> String {
        let mut body = String::new();
        match self {
            Self::AuthTest => {}
            Self::ConversationsList(request) => {
                push_form_field(&mut body, "types", request.types().as_wire());
                push_form_field(&mut body, "limit", &request.limit().to_string());
                if let Some(cursor) = request.cursor() {
                    push_form_field(&mut body, "cursor", cursor.as_str());
                }
            }
            Self::ConversationsInfo(request) => {
                push_form_field(&mut body, "channel", request.channel().as_str());
            }
            Self::ConversationsHistory(request) => {
                push_form_field(&mut body, "channel", request.channel().as_str());
                push_form_field(&mut body, "limit", &request.limit().to_string());
                if let Some(cursor) = request.cursor() {
                    push_form_field(&mut body, "cursor", cursor.as_str());
                }
                if let Some(oldest) = request.oldest() {
                    push_form_field(&mut body, "oldest", oldest.as_str());
                }
            }
            Self::UsersInfo(request) => {
                push_form_field(&mut body, "user", request.user().as_str());
            }
            Self::ChatPostMessage(request) => {
                push_form_field(&mut body, "channel", request.channel().as_str());
                push_form_field(&mut body, "text", request.text().as_str());
                if let Some(thread) = request.thread_ts() {
                    push_form_field(&mut body, "thread_ts", thread.as_str());
                }
                if let Some(blocks) = request.blocks() {
                    push_form_field(&mut body, "blocks", blocks.as_str());
                }
            }
            Self::ChatUpdate(request) => {
                push_form_field(&mut body, "channel", request.channel().as_str());
                push_form_field(&mut body, "ts", request.ts().as_str());
                push_form_field(&mut body, "text", request.text().as_str());
                if let Some(blocks) = request.blocks() {
                    push_form_field(&mut body, "blocks", blocks.as_str());
                }
            }
            Self::ChatStartStream(request) => {
                push_form_field(&mut body, "channel", request.channel().as_str());
                push_form_field(&mut body, "thread_ts", request.thread_ts().as_str());
                if let Some(text) = request.markdown_text() {
                    push_form_field(&mut body, "markdown_text", text.as_str());
                }
            }
            Self::ChatAppendStream(request) => {
                push_form_field(&mut body, "channel", request.channel().as_str());
                push_form_field(&mut body, "ts", request.ts().as_str());
                push_form_field(&mut body, "markdown_text", request.markdown_text().as_str());
                if let Some(chunks) = request.chunks() {
                    push_form_field(&mut body, "chunks", chunks.as_str());
                }
            }
            Self::ChatStopStream(request) => {
                push_form_field(&mut body, "channel", request.channel().as_str());
                push_form_field(&mut body, "ts", request.ts().as_str());
                push_form_field(&mut body, "markdown_text", request.markdown_text().as_str());
                if let Some(blocks) = request.blocks() {
                    push_form_field(&mut body, "blocks", blocks.as_str());
                }
            }
            Self::ViewsOpen(request) => {
                push_form_field(&mut body, "trigger_id", request.trigger_id().as_str());
                push_form_field(&mut body, "view", request.view().as_str());
            }
            Self::ViewsPublish(request) => {
                push_form_field(&mut body, "user_id", request.user_id().as_str());
                push_form_field(&mut body, "view", request.view().as_str());
            }
        }
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHANNEL: &str = "C0RESERVED";
    const USER: &str = "U0RESERVED";

    fn channel() -> ChannelId {
        ChannelId::new(CHANNEL).expect("channel")
    }

    fn cursor() -> Cursor {
        Cursor::new("dGVhbTpDMFJFU0VSVkVE").expect("cursor")
    }

    #[test]
    fn every_path_is_the_documented_one() {
        for (method, path) in [
            (SlackMethod::AuthTest, "/api/auth.test"),
            (SlackMethod::ConversationsList, "/api/conversations.list"),
            (SlackMethod::ConversationsInfo, "/api/conversations.info"),
            (
                SlackMethod::ConversationsHistory,
                "/api/conversations.history",
            ),
            (SlackMethod::UsersInfo, "/api/users.info"),
            (SlackMethod::ChatPostMessage, "/api/chat.postMessage"),
            (SlackMethod::ChatUpdate, "/api/chat.update"),
            (SlackMethod::ChatStartStream, "/api/chat.startStream"),
            (SlackMethod::ChatAppendStream, "/api/chat.appendStream"),
            (SlackMethod::ChatStopStream, "/api/chat.stopStream"),
            (SlackMethod::ViewsOpen, "/api/views.open"),
            (SlackMethod::ViewsPublish, "/api/views.publish"),
        ] {
            assert_eq!(method.path(), path);
            assert_eq!(format!("{API_PREFIX}/{}", method.as_str()), path);
        }
    }

    #[test]
    fn every_body_is_exact_and_credential_free() {
        // The one method with no argument sends an empty form body.
        assert_eq!(SlackOperation::AuthTest.body(), "");

        let list = SlackOperation::ConversationsList(
            ConversationsListRequest::new(ConversationTypes::all_channels(), 200).expect("list"),
        );
        // The comma between the two channel types is percent-encoded to %2C.
        assert_eq!(
            list.body(),
            "types=public_channel%2Cprivate_channel&limit=200"
        );

        let paged = SlackOperation::ConversationsList(
            ConversationsListRequest::new(ConversationTypes::new(false, true).expect("types"), 50)
                .expect("list")
                .from_cursor(cursor()),
        );
        assert_eq!(
            paged.body(),
            "types=private_channel&limit=50&cursor=dGVhbTpDMFJFU0VSVkVE"
        );

        let info = SlackOperation::ConversationsInfo(ConversationsInfoRequest::new(channel()));
        assert_eq!(info.body(), "channel=C0RESERVED");

        let history = SlackOperation::ConversationsHistory(
            ConversationsHistoryRequest::new(channel(), 40).expect("history"),
        );
        assert_eq!(history.body(), "channel=C0RESERVED&limit=40");

        let windowed = SlackOperation::ConversationsHistory(
            ConversationsHistoryRequest::new(channel(), 200)
                .expect("history")
                .from_cursor(cursor())
                .since(MessageTs::new("1723542000.000100").expect("ts")),
        );
        assert_eq!(
            windowed.body(),
            "channel=C0RESERVED&limit=200&cursor=dGVhbTpDMFJFU0VSVkVE&oldest=1723542000.000100"
        );

        let user =
            SlackOperation::UsersInfo(UsersInfoRequest::new(UserId::new(USER).expect("user")));
        assert_eq!(user.body(), "user=U0RESERVED");

        let post = SlackOperation::ChatPostMessage(PostMessageRequest::new(
            channel(),
            MessageText::new("bonjour").expect("text"),
        ));
        assert_eq!(post.body(), "channel=C0RESERVED&text=bonjour");

        let reply = SlackOperation::ChatPostMessage(
            PostMessageRequest::new(channel(), MessageText::new("suite").expect("text"))
                .in_thread(MessageTs::new("1723542000.000100").expect("ts")),
        );
        assert_eq!(
            reply.body(),
            "channel=C0RESERVED&text=suite&thread_ts=1723542000.000100"
        );

        let blocks = MessageBlocks::new(
            r#"[{"type":"section","text":{"type":"mrkdwn","text":"Approve?"}},{"type":"actions","elements":[]}]"#,
        )
        .expect("blocks");
        let update = SlackOperation::ChatUpdate(
            UpdateMessageRequest::new(
                channel(),
                MessageTs::new("1723542000.000100").expect("ts"),
                MessageText::new("Approval required").expect("text"),
            )
            .with_blocks(blocks),
        );
        assert!(update.body().starts_with(
            "channel=C0RESERVED&ts=1723542000.000100&text=Approval%20required&blocks="
        ));

        let start = SlackOperation::ChatStartStream(
            StartStreamRequest::new(channel(), MessageTs::new("1723542000.000100").expect("ts"))
                .with_markdown(StreamText::new("Thinking…").expect("stream text")),
        );
        assert_eq!(
            start.body(),
            "channel=C0RESERVED&thread_ts=1723542000.000100&markdown_text=Thinking%E2%80%A6"
        );

        let chunks = StreamChunks::new(
            r#"[{"type":"task_update","id":"task-1","title":"read_file","status":"in_progress"}]"#,
        )
        .expect("chunks");
        let append = SlackOperation::ChatAppendStream(
            AppendStreamRequest::new(
                channel(),
                MessageTs::new("1723542300.000400").expect("ts"),
                StreamText::new("read_file in progress").expect("stream text"),
            )
            .with_chunks(chunks),
        );
        assert!(append.body().starts_with(
            "channel=C0RESERVED&ts=1723542300.000400&markdown_text=read_file%20in%20progress&chunks=%5B"
        ));

        let stop = SlackOperation::ChatStopStream(
            StopStreamRequest::new(
                channel(),
                MessageTs::new("1723542300.000400").expect("ts"),
                StreamText::new("Done").expect("stream text"),
            )
            .with_blocks(
                MessageBlocks::new(
                    r#"[{"type":"section","text":{"type":"mrkdwn","text":"Done"}}]"#,
                )
                .expect("blocks"),
            ),
        );
        assert!(
            stop.body().starts_with(
                "channel=C0RESERVED&ts=1723542300.000400&markdown_text=Done&blocks=%5B"
            )
        );

        let modal = ModalView::new(
            r#"{"type":"modal","title":{"type":"plain_text","text":"Reject"},"blocks":[]}"#,
        )
        .expect("modal");
        let open = SlackOperation::ViewsOpen(OpenViewRequest::new(
            TriggerId::new("1337.abc").expect("trigger"),
            modal,
        ));
        assert!(open.body().starts_with("trigger_id=1337.abc&view=%7B"));

        let home = HomeView::new(r#"{"type":"home","blocks":[]}"#).expect("home");
        let publish = SlackOperation::ViewsPublish(PublishViewRequest::new(
            UserId::new(USER).expect("user"),
            home,
        ));
        assert!(publish.body().starts_with("user_id=U0RESERVED&view=%7B"));
    }

    #[test]
    fn hostile_content_is_escaped_rather_than_interpolated() {
        let post = SlackOperation::ChatPostMessage(PostMessageRequest::new(
            channel(),
            MessageText::new("quote\" slash\\ brace} newline\nend\"}").expect("text"),
        ));
        // Every metacharacter that could break out of a form field — the field
        // separator `&`, the pair separator `=`, quotes, backslashes, braces,
        // and the newline — is percent-encoded, so the text can only arrive as
        // the value of `text`, never as structure.
        assert_eq!(
            post.body(),
            "channel=C0RESERVED&text=quote%22%20slash%5C%20brace%7D%20newline%0Aend%22%7D"
        );
    }

    #[test]
    fn every_external_effect_is_marked_apart_from_the_five_reads() {
        let reads = [
            SlackOperation::AuthTest,
            SlackOperation::ConversationsList(
                ConversationsListRequest::new(ConversationTypes::default(), 1).expect("list"),
            ),
            SlackOperation::ConversationsInfo(ConversationsInfoRequest::new(channel())),
            SlackOperation::ConversationsHistory(
                ConversationsHistoryRequest::new(channel(), 1).expect("history"),
            ),
            SlackOperation::UsersInfo(UsersInfoRequest::new(UserId::new(USER).expect("user"))),
        ];
        for read in &reads {
            assert!(!read.is_external_effect(), "{read:?} is a read");
        }
        let ts = || MessageTs::new("1723542300.000400").expect("ts");
        let writes = vec![
            SlackOperation::ChatPostMessage(PostMessageRequest::new(
                channel(),
                MessageText::new("bonjour").expect("text"),
            )),
            SlackOperation::ChatUpdate(UpdateMessageRequest::new(
                channel(),
                ts(),
                MessageText::new("bonjour").expect("text"),
            )),
            SlackOperation::ChatStartStream(StartStreamRequest::new(channel(), ts())),
            SlackOperation::ChatAppendStream(AppendStreamRequest::new(
                channel(),
                ts(),
                StreamText::new("progress").expect("stream text"),
            )),
            SlackOperation::ChatStopStream(StopStreamRequest::new(
                channel(),
                ts(),
                StreamText::new("done").expect("stream text"),
            )),
            SlackOperation::ViewsOpen(OpenViewRequest::new(
                TriggerId::new("1337.abc").expect("trigger"),
                ModalView::new(r#"{"type":"modal","blocks":[]}"#).expect("modal"),
            )),
            SlackOperation::ViewsPublish(PublishViewRequest::new(
                UserId::new(USER).expect("user"),
                HomeView::new(r#"{"type":"home","blocks":[]}"#).expect("home"),
            )),
        ];
        for write in &writes {
            assert!(write.is_external_effect(), "{write:?} is an effect");
        }

        // Every operation names its own method, and no two share one.
        let mut methods: Vec<SlackMethod> = reads
            .iter()
            .map(SlackOperation::method)
            .chain(writes.iter().map(SlackOperation::method))
            .collect();
        methods.sort_unstable();
        let total = methods.len();
        methods.dedup();
        assert_eq!(methods.len(), total, "twelve operations, twelve methods");
    }

    #[test]
    fn a_page_size_is_bounded_and_never_clamped() {
        assert_eq!(
            ConversationsListRequest::new(ConversationTypes::default(), 0).err(),
            Some(SlackRefusal::Limit)
        );
        assert_eq!(
            ConversationsListRequest::new(ConversationTypes::default(), MAX_PAGE_LIMIT + 1).err(),
            Some(SlackRefusal::Limit)
        );
        assert!(
            ConversationsListRequest::new(ConversationTypes::default(), MAX_PAGE_LIMIT).is_ok()
        );
        assert_eq!(
            ConversationsHistoryRequest::new(channel(), 0).err(),
            Some(SlackRefusal::Limit)
        );
        assert_eq!(
            ConversationsHistoryRequest::new(channel(), MAX_PAGE_LIMIT + 1).err(),
            Some(SlackRefusal::Limit)
        );
        assert_eq!(
            ConversationsHistoryRequest::new(channel(), 40)
                .expect("history")
                .limit(),
            40
        );
    }

    #[test]
    fn a_type_selection_is_never_empty_and_renders_one_way() {
        assert_eq!(
            ConversationTypes::new(false, false).err(),
            Some(SlackRefusal::ConversationTypes)
        );
        for (public, private, wire) in [
            (true, true, "public_channel,private_channel"),
            (true, false, "public_channel"),
            (false, true, "private_channel"),
        ] {
            let types = ConversationTypes::new(public, private).expect("types");
            assert_eq!(types.as_wire(), wire);
            assert_eq!(types.public_channels(), public);
            assert_eq!(types.private_channels(), private);
        }
        assert_eq!(
            ConversationTypes::default(),
            ConversationTypes::all_channels()
        );
    }

    #[test]
    fn message_text_is_bounded_and_control_free() {
        assert_eq!(
            MessageText::new("bonjour\nligne deux")
                .expect("text")
                .as_str(),
            "bonjour\nligne deux"
        );
        for refused in ["", "cloche\u{7}", "efface\u{1b}[2J"] {
            assert_eq!(
                MessageText::new(refused).err(),
                Some(SlackRefusal::Text),
                "must refuse {refused:?}"
            );
        }
        assert!(MessageText::new(&"a".repeat(MAX_MESSAGE_TEXT_BYTES)).is_ok());
        assert_eq!(
            MessageText::new(&"a".repeat(MAX_MESSAGE_TEXT_BYTES + 1)).err(),
            Some(SlackRefusal::Text)
        );
    }
}
