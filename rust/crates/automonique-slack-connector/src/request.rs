// SPDX-License-Identifier: Elastic-2.0

//! The six methods, and the exact path and body each renders.
//!
//! [`SlackMethod`] is the second half of the target lock (the first is the
//! origin in `target`). A path is never a caller string: it is one of six
//! private constants under a private `/api` prefix, and a layer talked into
//! asking for `chat.delete` or `admin.conversations.archive` cannot spell one,
//! because no variant exists.
//!
//! Every argument travels in a JSON request body rather than a query string.
//! Slack accepts both, and the legacy bot's SDK form-encodes; JSON is chosen
//! here because it is the spelling Slack documents for a `Bearer`-authenticated
//! call, because it is the only spelling that will carry a Block Kit payload
//! when one is added, and because it lets this crate reuse the same audited
//! [`crate::push_json_string`] escaping the other connectors use. Every string
//! is escaped there; nothing is interpolated raw.
//!
//! Field order within a body is fixed and documented per method. JSON objects
//! are order-insensitive to a server, so this is a testability property rather
//! than a protocol one: it lets a test assert one exact captured request
//! instead of a set of permutations.

use crate::target::{ChannelId, Cursor, MessageTs, UserId};
use crate::{MAX_MESSAGE_TEXT_BYTES, MAX_PAGE_LIMIT, SlackRefusal, is_body_text, push_json_string};

/// The prefix every Slack Web API method hangs from.
const API_PREFIX: &str = "/api";

/// The six method names, spelled once each.
const AUTH_TEST: &str = "auth.test";
const CONVERSATIONS_LIST: &str = "conversations.list";
const CONVERSATIONS_INFO: &str = "conversations.info";
const CONVERSATIONS_HISTORY: &str = "conversations.history";
const USERS_INFO: &str = "users.info";
const CHAT_POST_MESSAGE: &str = "chat.postMessage";

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
    /// `chat.postMessage` — post one message. The one external effect.
    ChatPostMessage,
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
        }
    }

    /// The exact request path, credential-free and argument-free.
    #[must_use]
    pub fn path(self) -> String {
        format!("{API_PREFIX}/{}", self.as_str())
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
}

impl PostMessageRequest {
    /// Bind one conversation to one message body.
    #[must_use]
    pub const fn new(channel: ChannelId, text: MessageText) -> Self {
        Self {
            channel,
            text,
            thread_ts: None,
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
        }
    }

    /// Whether this call changes something other people can see.
    ///
    /// An approval layer keys on this rather than re-deriving it from a verb:
    /// every one of these methods is a `POST`, so the verb says nothing, and
    /// exactly one of them puts a message in front of a human.
    #[must_use]
    pub const fn is_external_effect(&self) -> bool {
        matches!(self, Self::ChatPostMessage(_))
    }

    /// The exact JSON body, in the documented field order.
    ///
    /// Credential-free by construction, so a host may log or fixture it. Every
    /// method carries a body — `auth.test` takes no argument and sends the
    /// empty object.
    #[must_use]
    pub fn body(&self) -> String {
        match self {
            Self::AuthTest => String::from("{}"),
            Self::ConversationsList(request) => {
                let mut body = String::from("{\"types\":");
                push_json_string(&mut body, request.types().as_wire());
                body.push_str(&format!(",\"limit\":{}", request.limit()));
                if let Some(cursor) = request.cursor() {
                    body.push_str(",\"cursor\":");
                    push_json_string(&mut body, cursor.as_str());
                }
                body.push('}');
                body
            }
            Self::ConversationsInfo(request) => {
                let mut body = String::from("{\"channel\":");
                push_json_string(&mut body, request.channel().as_str());
                body.push('}');
                body
            }
            Self::ConversationsHistory(request) => {
                let mut body = String::from("{\"channel\":");
                push_json_string(&mut body, request.channel().as_str());
                body.push_str(&format!(",\"limit\":{}", request.limit()));
                if let Some(cursor) = request.cursor() {
                    body.push_str(",\"cursor\":");
                    push_json_string(&mut body, cursor.as_str());
                }
                if let Some(oldest) = request.oldest() {
                    body.push_str(",\"oldest\":");
                    push_json_string(&mut body, oldest.as_str());
                }
                body.push('}');
                body
            }
            Self::UsersInfo(request) => {
                let mut body = String::from("{\"user\":");
                push_json_string(&mut body, request.user().as_str());
                body.push('}');
                body
            }
            Self::ChatPostMessage(request) => {
                let mut body = String::from("{\"channel\":");
                push_json_string(&mut body, request.channel().as_str());
                body.push_str(",\"text\":");
                push_json_string(&mut body, request.text().as_str());
                if let Some(thread) = request.thread_ts() {
                    body.push_str(",\"thread_ts\":");
                    push_json_string(&mut body, thread.as_str());
                }
                body.push('}');
                body
            }
        }
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
        ] {
            assert_eq!(method.path(), path);
            assert_eq!(format!("{API_PREFIX}/{}", method.as_str()), path);
        }
    }

    #[test]
    fn every_body_is_exact_and_credential_free() {
        assert_eq!(SlackOperation::AuthTest.body(), "{}");

        let list = SlackOperation::ConversationsList(
            ConversationsListRequest::new(ConversationTypes::all_channels(), 200).expect("list"),
        );
        assert_eq!(
            list.body(),
            "{\"types\":\"public_channel,private_channel\",\"limit\":200}"
        );

        let paged = SlackOperation::ConversationsList(
            ConversationsListRequest::new(ConversationTypes::new(false, true).expect("types"), 50)
                .expect("list")
                .from_cursor(cursor()),
        );
        assert_eq!(
            paged.body(),
            "{\"types\":\"private_channel\",\"limit\":50,\"cursor\":\"dGVhbTpDMFJFU0VSVkVE\"}"
        );

        let info = SlackOperation::ConversationsInfo(ConversationsInfoRequest::new(channel()));
        assert_eq!(info.body(), "{\"channel\":\"C0RESERVED\"}");

        let history = SlackOperation::ConversationsHistory(
            ConversationsHistoryRequest::new(channel(), 40).expect("history"),
        );
        assert_eq!(history.body(), "{\"channel\":\"C0RESERVED\",\"limit\":40}");

        let windowed = SlackOperation::ConversationsHistory(
            ConversationsHistoryRequest::new(channel(), 200)
                .expect("history")
                .from_cursor(cursor())
                .since(MessageTs::new("1723542000.000100").expect("ts")),
        );
        assert_eq!(
            windowed.body(),
            "{\"channel\":\"C0RESERVED\",\"limit\":200,\
             \"cursor\":\"dGVhbTpDMFJFU0VSVkVE\",\"oldest\":\"1723542000.000100\"}"
        );

        let user =
            SlackOperation::UsersInfo(UsersInfoRequest::new(UserId::new(USER).expect("user")));
        assert_eq!(user.body(), "{\"user\":\"U0RESERVED\"}");

        let post = SlackOperation::ChatPostMessage(PostMessageRequest::new(
            channel(),
            MessageText::new("bonjour").expect("text"),
        ));
        assert_eq!(
            post.body(),
            "{\"channel\":\"C0RESERVED\",\"text\":\"bonjour\"}"
        );

        let reply = SlackOperation::ChatPostMessage(
            PostMessageRequest::new(channel(), MessageText::new("suite").expect("text"))
                .in_thread(MessageTs::new("1723542000.000100").expect("ts")),
        );
        assert_eq!(
            reply.body(),
            "{\"channel\":\"C0RESERVED\",\"text\":\"suite\",\
             \"thread_ts\":\"1723542000.000100\"}"
        );
    }

    #[test]
    fn hostile_content_is_escaped_rather_than_interpolated() {
        let post = SlackOperation::ChatPostMessage(PostMessageRequest::new(
            channel(),
            MessageText::new("quote\" slash\\ brace} newline\nend\"}").expect("text"),
        ));
        let parsed: serde_json::Value = serde_json::from_str(&post.body()).expect("valid JSON");
        assert_eq!(parsed["channel"], CHANNEL);
        assert_eq!(parsed["text"], "quote\" slash\\ brace} newline\nend\"}");
    }

    #[test]
    fn the_one_external_effect_is_marked_apart_from_the_five_reads() {
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
        let write = SlackOperation::ChatPostMessage(PostMessageRequest::new(
            channel(),
            MessageText::new("bonjour").expect("text"),
        ));
        assert!(write.is_external_effect());
        assert_eq!(write.method(), SlackMethod::ChatPostMessage);

        // Every operation names its own method, and no two share one.
        let mut methods: Vec<SlackMethod> = reads
            .iter()
            .map(SlackOperation::method)
            .chain([write.method()])
            .collect();
        methods.sort_unstable();
        let total = methods.len();
        methods.dedup();
        assert_eq!(methods.len(), total, "six operations, six methods");
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
