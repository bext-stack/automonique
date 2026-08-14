// SPDX-License-Identifier: Elastic-2.0

//! Typed client for the Slack Web API surface Automonique reads and speaks on.
//!
//! Six methods are spelled, and nothing else can be: identify the credential,
//! list the conversations it can see, read one conversation, read a
//! conversation's recent messages, resolve one user, and post one message. Five
//! are reads. The sixth — [`SlackClient::post_message`] — is the only
//! externally visible effect this crate can produce, and it is marked as one by
//! [`SlackOperation::is_external_effect`] so an approval layer never has to
//! re-derive it from a verb.
//!
//! # Target lock
//!
//! No caller supplies a URL, a path, or a method name. [`SlackBase`] admits
//! `slack.com` and the plaintext loopback literals and nothing else; the `/api`
//! prefix is a private constant; and the method segment is rendered only from
//! the closed [`SlackMethod`] enum. A layer that is talked into asking for
//! `chat.delete` or `admin.users.remove` cannot spell one — there is no variant
//! for it, and no caller string ever reaches the URL. Every argument travels in
//! the JSON body, where it is escaped rather than interpolated.
//!
//! # Credential
//!
//! The token rides an `Authorization: Bearer` header. It is held only in
//! [`SlackToken`], which has no `Display`, renders as `<redacted>` under
//! `Debug`, and lends its bytes only through a callback at the HTTP boundary.
//! Neither error vocabulary borrows caller or credential input: both are closed
//! C-like enums, so either is safe to log next to the request it came from.
//!
//! # Separation of building from sending
//!
//! [`SlackOperation`] renders the exact method and body without a socket, and
//! the `decode_*` functions parse the exact wire response the same way.
//! [`SlackClient`] is only the composition of the two around one bounded HTTP
//! call, so the whole contract is provable against fixtures and against a
//! loopback fake.
//!
//! # `ok: false` is an answer, not a failure
//!
//! Slack answers `HTTP 200` with `{"ok": false, "error": "…"}` for a refusal it
//! understood: a channel the bot was never invited to, a revoked token, a
//! spent rate window. That is a well-formed answer, so it decodes into
//! [`SlackOutcome::Rejected`] with the code classified by [`SlackErrorKind`] —
//! a missing invitation, a missing scope and a dead credential are told apart,
//! because each names a different repair. Only a response that is not the
//! contract at all is a [`SlackFailure`].
//!
//! A `429` is the one status Slack uses to carry the same news out of band. It
//! is decoded as a rate-limited rejection carrying
//! [`SlackRejection::retry_after_seconds`] — *carried, never obeyed*: this
//! connector does not sleep inside a request budget, so the wait is the
//! scheduling layer's to take.
//!
//! # Divergences from the legacy TypeScript client
//!
//! The contract was taken from a live Slack bot whose readers are *lossy*.
//! `String(info?.channel?.name || "")` turns an unresolvable channel into the
//! empty name; `userNames.set(id, id)` records an id as if it were a display
//! name when the lookup throws; and every call site swallows the failure in a
//! bare `catch {}` that cannot tell "no messages" from "not in channel". This
//! crate refuses instead: a response missing a field the contract names is
//! [`SlackFailure::MissingField`], and a refusal Slack explained is a typed
//! [`SlackRejection`] rather than an empty list.
//!
//! Two scope decisions are deliberate. Only `public_channel` and
//! `private_channel` are listable ([`ConversationTypes`]): a Slack `im` object
//! carries no `name`, and decoding one as a nameless channel is precisely the
//! empty-string repair this crate exists to avoid. And a posted message is
//! text and an optional thread parent — Block Kit payloads are a later
//! refinement that belongs beside a block model, not inside a text field.

mod client;
mod request;
mod response;
mod target;
mod token;

use std::error::Error;
use std::fmt;

pub use client::{SLACK_ACCEPT, SLACK_CONTENT_TYPE, SLACK_USER_AGENT, SlackClient};
pub use request::{
    ConversationTypes, ConversationsHistoryRequest, ConversationsInfoRequest,
    ConversationsListRequest, MessageText, PostMessageRequest, SlackMethod, SlackOperation,
    UsersInfoRequest,
};
pub use response::{
    AuthIdentity, ChannelPage, MAX_REPLY_COUNT, MessagePage, PostedMessage, SlackChannel,
    SlackMessage, SlackUser, decode_auth_test, decode_conversations_history,
    decode_conversations_info, decode_conversations_list, decode_error_code, decode_post_message,
    decode_users_info,
};
pub use target::{
    ChannelId, Cursor, MAX_CHANNEL_ID_BYTES, MAX_CURSOR_BYTES, MAX_TEAM_ID_BYTES,
    MAX_TIMESTAMP_BYTES, MAX_USER_ID_BYTES, MessageTs, SLACK_API_ORIGIN, SlackBase, TeamId, UserId,
};
pub use token::{MAX_SLACK_TOKEN_BYTES, SLACK_BOT_TOKEN_PREFIX, SlackAuthorization, SlackToken};

/// Longest response body accepted, before any field is read.
///
/// A [`MAX_PAGE_LIMIT`]-message page of ordinary Slack messages fits an order
/// of magnitude inside this; a page of maximal 40,000-character messages does
/// not. That is deliberate: the ceiling bounds what this process will buffer,
/// and a caller who genuinely needs pages of maximal messages asks for a
/// smaller `limit` rather than teaching the connector to stream.
pub const MAX_SLACK_RESPONSE_BYTES: usize = 1024 * 1024;

/// Most items one page may ask for, and the most a response may carry back.
///
/// Both directions share the bound, so a server answering with more rows than
/// were asked for is refused. Slack recommends no more than 200 per page on the
/// cursor-paginated conversation methods, and the legacy bot asks for exactly
/// that.
pub const MAX_PAGE_LIMIT: u16 = 200;

/// Whole-request budget for one Slack call.
///
/// None of the six methods long-polls, so a single bounded budget covers
/// connect, TLS, request and response. It is this crate's own choice rather
/// than a value read off the legacy client, which delegates its timeout to an
/// SDK default.
pub const SLACK_REQUEST_TIMEOUT_SECONDS: u64 = 10;

/// Longest `error` code retained from a refusal.
pub const MAX_ERROR_CODE_BYTES: usize = 80;

/// Longest message text this connector will *send*, matching Slack's own
/// 40,000-character ceiling on `chat.postMessage`.
pub const MAX_MESSAGE_TEXT_BYTES: usize = 40_000;

/// Longest message text this connector will *accept* back.
///
/// The same 40,000 characters, at up to four UTF-8 bytes each. Reading is
/// looser than writing because a message already on the channel was not written
/// by this connector and refusing to read it would leave a caller unable to see
/// what is there.
pub const MAX_INBOUND_TEXT_BYTES: usize = 160_000;

/// Longest human-facing name retained from a response — a channel name, a
/// display name, a workspace name.
pub const MAX_NAME_BYTES: usize = 120;

/// Longest URL retained from a response.
pub const MAX_URL_BYTES: usize = 512;

/// Longest opaque wire identifier retained where no tighter grammar applies,
/// such as a `bot_id` or a message `subtype`.
pub const MAX_OPAQUE_BYTES: usize = 64;

/// Closed refusals raised while *building* a request, before any I/O.
///
/// Each names the field that was wrong and never its value, so a refusal may be
/// logged beside the operator content it was built from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackRefusal {
    /// The base is not an origin this connector may address.
    Base,
    /// The token is empty, over-long, outside the bearer-credential character
    /// set, or not a bot token.
    Token,
    /// The channel id is empty, over-long, or outside Slack's grammar.
    ChannelId,
    /// The user id is empty, over-long, or outside Slack's grammar.
    UserId,
    /// The timestamp is not Slack's `seconds[.fraction]` message identifier.
    Timestamp,
    /// The pagination cursor is empty, over-long, or not base64.
    Cursor,
    /// The requested page size is zero or over [`MAX_PAGE_LIMIT`].
    Limit,
    /// Message text is empty, over [`MAX_MESSAGE_TEXT_BYTES`], or carries a
    /// control character other than tab and newline.
    Text,
    /// No conversation type was selected, so the listing would name nothing.
    ConversationTypes,
}

impl SlackRefusal {
    /// Stable, content-free category for logging and metrics.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Token => "token",
            Self::ChannelId => "channel_id",
            Self::UserId => "user_id",
            Self::Timestamp => "timestamp",
            Self::Cursor => "cursor",
            Self::Limit => "limit",
            Self::Text => "text",
            Self::ConversationTypes => "conversation_types",
        }
    }
}

impl fmt::Display for SlackRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "slack request refused: {}", self.category())
    }
}

impl Error for SlackRefusal {}

/// Closed failures from issuing a call or reading its response.
///
/// Like [`SlackRefusal`], no variant borrows input; a failure never carries a
/// credential, a channel id, or a message body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackFailure {
    /// DNS, connect, TLS, or an unclassified transport error.
    Unavailable,
    /// The bounded request budget elapsed.
    TimedOut,
    /// Slack answered with a redirect.
    ///
    /// Redirects are not followed, and one from the locked origin is the shape
    /// of a call about to leave it, so it is named rather than folded into a
    /// rejection.
    Redirected,
    /// The credential was refused at the HTTP layer (401) or the request was
    /// blocked before Slack saw it (403).
    ///
    /// Named apart because Slack's *own* refusals arrive as `200 {"ok":false}`:
    /// a 401 here is something in front of Slack answering instead of it.
    Unauthorized,
    /// Slack answered with a status that is neither 200 nor a classified
    /// refusal.
    UnexpectedStatus,
    /// The response was not `application/json`.
    UnexpectedContentType,
    /// The response body exceeded [`MAX_SLACK_RESPONSE_BYTES`].
    ResponseTooLarge,
    /// The body was not strict JSON, or not the `{"ok": …}` envelope every
    /// Slack method answers with.
    InvalidResponse,
    /// A field the method's contract names was absent.
    MissingField,
    /// A field was present but outside its documented bound or grammar.
    FieldOutOfBounds,
    /// The page carried more items than were asked for, or more than
    /// [`MAX_PAGE_LIMIT`].
    TooManyItems,
}

impl SlackFailure {
    /// Stable, content-free category for logging and metrics.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::TimedOut => "timed_out",
            Self::Redirected => "redirected",
            Self::Unauthorized => "unauthorized",
            Self::UnexpectedStatus => "unexpected_status",
            Self::UnexpectedContentType => "unexpected_content_type",
            Self::ResponseTooLarge => "response_too_large",
            Self::InvalidResponse => "invalid_response",
            Self::MissingField => "missing_field",
            Self::FieldOutOfBounds => "field_out_of_bounds",
            Self::TooManyItems => "too_many_items",
        }
    }
}

impl fmt::Display for SlackFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "slack call failed: {}", self.category())
    }
}

impl Error for SlackFailure {}

/// The machine-readable `error` code Slack names a refusal with.
///
/// Remote text, so it is bounded at [`MAX_ERROR_CODE_BYTES`] and stripped of
/// control characters on the way in — an operator reading it in a terminal
/// cannot be driven by it. It is not a credential and is therefore rendered by
/// `Debug`, which is the whole point of retaining it: [`SlackErrorKind`] is
/// what a program branches on, and the exact code is what a human needs to look
/// it up in Slack's own table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackErrorCode(String);

impl SlackErrorCode {
    /// Sanitize one remote code into the retained form.
    ///
    /// Control characters are replaced by a space rather than dropped so two
    /// distinct codes cannot collapse onto one, and the result is truncated on a
    /// character boundary.
    #[must_use]
    pub fn sanitized(value: &str) -> Self {
        let mut text = String::new();
        for character in value.chars() {
            let rendered = if character.is_control() {
                ' '
            } else {
                character
            };
            if text.len() + rendered.len_utf8() > MAX_ERROR_CODE_BYTES {
                break;
            }
            text.push(rendered);
        }
        Self(text.trim().to_owned())
    }

    /// The sanitized code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SlackErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// What a Slack refusal means, classified into the repairs they call for.
///
/// Slack's `error` vocabulary is open and grows; this is a closed reading of
/// it, so an unrecognized code is [`SlackErrorKind::Other`] and its exact
/// spelling survives in [`SlackRejection::code`] rather than being lost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackErrorKind {
    /// The credential is not usable at all — replace the token.
    InvalidAuth,
    /// The credential is valid but lacks the scope for this method — reinstall
    /// the app with the scope it needs.
    MissingScope,
    /// The bot is not a member of the channel it addressed — invite it.
    ///
    /// Told apart from [`Self::ChannelNotFound`] because the repair is a human
    /// action in Slack, not a configuration fix.
    NotInChannel,
    /// No such conversation, or none this token can see.
    ChannelNotFound,
    /// No such user.
    UserNotFound,
    /// The rate window is spent — wait, then retry.
    RateLimited,
    /// Slack parsed the call and refused its content.
    Invalid,
    /// Any other code Slack named.
    Other,
}

impl SlackErrorKind {
    /// Classify one `error` code.
    #[must_use]
    pub fn classify(code: &str) -> Self {
        match code {
            "invalid_auth" | "not_authed" | "account_inactive" | "token_revoked"
            | "token_expired" => Self::InvalidAuth,
            "missing_scope" | "not_allowed_token_type" | "no_permission" => Self::MissingScope,
            "not_in_channel" => Self::NotInChannel,
            "channel_not_found" => Self::ChannelNotFound,
            "user_not_found" | "users_not_found" => Self::UserNotFound,
            "ratelimited" | "rate_limited" => Self::RateLimited,
            "invalid_arguments"
            | "invalid_argument_name"
            | "invalid_cursor"
            | "invalid_limit"
            | "invalid_ts_latest"
            | "invalid_ts_oldest"
            | "msg_too_long"
            | "no_text" => Self::Invalid,
            _ => Self::Other,
        }
    }

    /// Stable, content-free category for logging and metrics.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::InvalidAuth => "invalid_auth",
            Self::MissingScope => "missing_scope",
            Self::NotInChannel => "not_in_channel",
            Self::ChannelNotFound => "channel_not_found",
            Self::UserNotFound => "user_not_found",
            Self::RateLimited => "rate_limited",
            Self::Invalid => "invalid",
            Self::Other => "other",
        }
    }
}

/// Slack's own refusal of a method call.
///
/// A rejection is a *parsed* answer, not a failure of this connector, which is
/// why it is an `Ok` outcome. The code is classified rather than reduced to a
/// boolean: `not_in_channel` is an instruction to invite the bot,
/// `missing_scope` is an instruction to reinstall the app, and `invalid_auth`
/// is an instruction to replace the token. Collapsing the three loses the only
/// actionable part.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackRejection {
    code: SlackErrorCode,
    kind: SlackErrorKind,
    retry_after_seconds: Option<u32>,
}

impl SlackRejection {
    /// Classify one refusal Slack named.
    #[must_use]
    pub fn new(code: SlackErrorCode, retry_after_seconds: Option<u32>) -> Self {
        let kind = SlackErrorKind::classify(code.as_str());
        Self {
            code,
            kind,
            retry_after_seconds,
        }
    }

    /// Classify one refusal that arrived as an HTTP 429.
    ///
    /// The status is the news here, whatever the body said: Slack sends the
    /// rate-limit refusal with a `retry-after` header and, historically, a body
    /// that is not always JSON.
    #[must_use]
    pub fn rate_limited(code: SlackErrorCode, retry_after_seconds: Option<u32>) -> Self {
        Self {
            code,
            kind: SlackErrorKind::RateLimited,
            retry_after_seconds,
        }
    }

    /// The exact code Slack named.
    #[must_use]
    pub const fn code(&self) -> &SlackErrorCode {
        &self.code
    }

    /// What the code means.
    #[must_use]
    pub const fn kind(&self) -> SlackErrorKind {
        self.kind
    }

    /// The `retry-after` Slack asked for, when it named one.
    ///
    /// Carried rather than obeyed: this connector never sleeps inside a request
    /// budget, so the wait is the caller's to schedule.
    #[must_use]
    pub const fn retry_after_seconds(&self) -> Option<u32> {
        self.retry_after_seconds
    }
}

/// A well-formed Slack answer: either the method's payload, or Slack's own
/// classified refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SlackOutcome<T> {
    /// Slack answered `ok: true` and returned the method's payload.
    Accepted(T),
    /// Slack answered `ok: false`, or a 429, with a classified reason.
    Rejected(SlackRejection),
}

impl<T> SlackOutcome<T> {
    /// The payload, if Slack accepted the call.
    #[must_use]
    pub const fn accepted(&self) -> Option<&T> {
        match self {
            Self::Accepted(payload) => Some(payload),
            Self::Rejected(_) => None,
        }
    }

    /// The classified refusal, if Slack refused.
    #[must_use]
    pub const fn rejected(&self) -> Option<&SlackRejection> {
        match self {
            Self::Accepted(_) => None,
            Self::Rejected(rejection) => Some(rejection),
        }
    }
}

/// Whether text may be carried in a message body.
///
/// Tab and newline are admitted because a Slack message is multi-line; every
/// other control character is refused rather than escaped, so neither a
/// terminal nor a rendered message can be driven by connector input.
pub(crate) fn is_body_text(text: &str, max_bytes: usize) -> bool {
    !text.is_empty()
        && text.len() <= max_bytes
        && !text
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
}

/// Append one JSON string literal, escaping everything RFC 8259 requires.
///
/// Written out rather than delegated to a serializer so a body's field order is
/// exactly the one this crate documents; a map-backed serializer would reorder
/// it. `DEL` is escaped as well, so no C0/C1-adjacent byte reaches a captured
/// request verbatim.
pub(crate) fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            control if control < '\u{20}' || control == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            plain => out.push(plain),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_and_failure_categories_are_distinct_and_content_free() {
        let refusals = [
            SlackRefusal::Base,
            SlackRefusal::Token,
            SlackRefusal::ChannelId,
            SlackRefusal::UserId,
            SlackRefusal::Timestamp,
            SlackRefusal::Cursor,
            SlackRefusal::Limit,
            SlackRefusal::Text,
            SlackRefusal::ConversationTypes,
        ];
        let mut categories: Vec<&str> = refusals.iter().map(|value| value.category()).collect();
        categories.sort_unstable();
        let total = categories.len();
        categories.dedup();
        assert_eq!(
            categories.len(),
            total,
            "every refusal category is distinct"
        );

        let failures = [
            SlackFailure::Unavailable,
            SlackFailure::TimedOut,
            SlackFailure::Redirected,
            SlackFailure::Unauthorized,
            SlackFailure::UnexpectedStatus,
            SlackFailure::UnexpectedContentType,
            SlackFailure::ResponseTooLarge,
            SlackFailure::InvalidResponse,
            SlackFailure::MissingField,
            SlackFailure::FieldOutOfBounds,
            SlackFailure::TooManyItems,
        ];
        let mut categories: Vec<&str> = failures.iter().map(|value| value.category()).collect();
        categories.sort_unstable();
        let total = categories.len();
        categories.dedup();
        assert_eq!(
            categories.len(),
            total,
            "every failure category is distinct"
        );
    }

    #[test]
    fn an_error_code_is_bounded_and_stripped_of_control_bytes() {
        let code = SlackErrorCode::sanitized("not_in\u{1b}[2J_channel\n");
        assert_eq!(code.as_str(), "not_in [2J_channel");
        assert_eq!(code.to_string(), "not_in [2J_channel");
        let long = SlackErrorCode::sanitized(&"e\u{301}".repeat(MAX_ERROR_CODE_BYTES));
        assert!(long.as_str().len() <= MAX_ERROR_CODE_BYTES);
        // Truncation lands on a character boundary rather than splitting one.
        assert!(long.as_str().chars().all(|c| c == 'e' || c == '\u{301}'));
    }

    #[test]
    fn every_repair_slack_names_is_told_apart_from_the_others() {
        for (code, kind) in [
            ("invalid_auth", SlackErrorKind::InvalidAuth),
            ("token_revoked", SlackErrorKind::InvalidAuth),
            ("account_inactive", SlackErrorKind::InvalidAuth),
            ("missing_scope", SlackErrorKind::MissingScope),
            ("not_allowed_token_type", SlackErrorKind::MissingScope),
            ("not_in_channel", SlackErrorKind::NotInChannel),
            ("channel_not_found", SlackErrorKind::ChannelNotFound),
            ("user_not_found", SlackErrorKind::UserNotFound),
            ("ratelimited", SlackErrorKind::RateLimited),
            ("msg_too_long", SlackErrorKind::Invalid),
            ("invalid_cursor", SlackErrorKind::Invalid),
            ("is_archived", SlackErrorKind::Other),
            ("fatal_error", SlackErrorKind::Other),
        ] {
            assert_eq!(SlackErrorKind::classify(code), kind, "code {code}");
        }
        // The exact spelling survives an unrecognized code, so a caller can
        // still look it up.
        let rejection = SlackRejection::new(SlackErrorCode::sanitized("is_archived"), None);
        assert_eq!(rejection.kind(), SlackErrorKind::Other);
        assert_eq!(rejection.code().as_str(), "is_archived");
        assert_eq!(rejection.retry_after_seconds(), None);

        let mut categories: Vec<&str> = [
            SlackErrorKind::InvalidAuth,
            SlackErrorKind::MissingScope,
            SlackErrorKind::NotInChannel,
            SlackErrorKind::ChannelNotFound,
            SlackErrorKind::UserNotFound,
            SlackErrorKind::RateLimited,
            SlackErrorKind::Invalid,
            SlackErrorKind::Other,
        ]
        .iter()
        .map(|kind| kind.category())
        .collect();
        categories.sort_unstable();
        let total = categories.len();
        categories.dedup();
        assert_eq!(categories.len(), total, "every kind category is distinct");
    }

    #[test]
    fn a_rejection_carries_the_wait_it_was_told_rather_than_taking_it() {
        let rejection =
            SlackRejection::rate_limited(SlackErrorCode::sanitized("ratelimited"), Some(30));
        assert_eq!(rejection.kind(), SlackErrorKind::RateLimited);
        assert_eq!(rejection.retry_after_seconds(), Some(30));
        assert_eq!(rejection.code().as_str(), "ratelimited");
        // A 429 whose body named nothing is still a rate-limited rejection.
        let bare = SlackRejection::rate_limited(SlackErrorCode::sanitized("ratelimited"), None);
        assert_eq!(bare.kind(), SlackErrorKind::RateLimited);
        assert_eq!(bare.retry_after_seconds(), None);
    }

    #[test]
    fn body_text_admits_multi_line_messages_and_refuses_control_bytes() {
        assert!(is_body_text("bonjour\nligne\tdeux", 64));
        assert!(!is_body_text("", 64));
        assert!(!is_body_text("bell\u{7}", 64));
        assert!(is_body_text(&"a".repeat(64), 64));
        assert!(!is_body_text(&"a".repeat(65), 64));
    }

    #[test]
    fn json_escaping_covers_every_control_code_point() {
        let mut rendered = String::new();
        push_json_string(&mut rendered, "\u{0}\u{1}\u{8}\u{c}\u{1f}\u{7f}");
        assert_eq!(rendered, "\"\\u0000\\u0001\\b\\f\\u001f\\u007f\"");
        let mut kept = String::new();
        push_json_string(&mut kept, "re\u{301}ponse \"cite\u{301}e\"");
        assert_eq!(kept, "\"re\u{301}ponse \\\"cite\u{301}e\\\"\"");
    }

    #[test]
    fn an_outcome_exposes_exactly_one_side() {
        let accepted: SlackOutcome<u8> = SlackOutcome::Accepted(7);
        assert_eq!(accepted.accepted(), Some(&7));
        assert!(accepted.rejected().is_none());
        let rejected: SlackOutcome<u8> = SlackOutcome::Rejected(SlackRejection::new(
            SlackErrorCode::sanitized("not_in_channel"),
            None,
        ));
        assert!(rejected.accepted().is_none());
        assert_eq!(
            rejected.rejected().map(|value| value.code().as_str()),
            Some("not_in_channel")
        );
    }
}
