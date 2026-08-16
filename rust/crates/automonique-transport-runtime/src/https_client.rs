// SPDX-License-Identifier: Elastic-2.0

//! Exact, synchronous HTTPS transport for the three Telegram methods this
//! product uses: inbound `getUpdates`, and the outbound pair an operator
//! control surface needs — `sendMessage` and `setMyCommands`.
//!
//! # Target lock
//!
//! No caller supplies a URL, a host, or a method name. The inbound plan names
//! its single method through [`TelegramTarget`], the outbound plan names its
//! closed set through [`TelegramOutbound`], and all funnel into one private
//! [`WireMethod`] enum that is the only thing a request path is ever rendered
//! from. A control layer that is talked into asking for something else cannot
//! spell it: there is no variant for it, and no string from a message ever
//! reaches the URL.
//!
//! # Credential
//!
//! Telegram carries the bot token *in the request path*, so the URL is secret
//! material and is built, used, and dropped inside this module. It is never
//! returned, never rendered by any `Debug`, and never named in a failure — the
//! closed [`HttpFailure`] and [`OutboundRefusal`] vocabularies carry no
//! borrowed input at all. What a host can observe of an outbound request is its
//! method name and its canonical body, neither of which contains the token.

use std::error::Error;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use automonique_connector_substrate::http::{map_ureq_error, read_bounded_body};
use automonique_connector_substrate::json::push_json_string;
use automonique_transports::MAX_TELEGRAM_INPUT_BYTES;
use ureq::tls::{RootCerts, TlsConfig};

use crate::{
    CancellationToken, HttpFailure, HttpMethod, MAX_TELEGRAM_RESPONSE_BYTES, OpaqueBotToken,
    TelegramAuthorization, TelegramHttpClient, TelegramHttpPlan, TelegramHttpResponse,
    TelegramTarget,
};

const TELEGRAM_ORIGIN: &str = "https://api.telegram.org";
const HTTP_TRANSPORT_ALLOWANCE_SECONDS: u64 = 3;
const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const MAX_RETRY_AFTER_SECONDS: u64 = 300;
const _: () = assert!((log::STATIC_MAX_LEVEL as usize) <= (log::LevelFilter::Debug as usize));

/// Whole-request budget for an outbound call, which never long-polls.
const OUTBOUND_REQUEST_TIMEOUT_SECONDS: u64 = 10;
const _: () = assert!(OUTBOUND_REQUEST_TIMEOUT_SECONDS >= HTTP_TRANSPORT_ALLOWANCE_SECONDS);

/// Longest `sendMessage` text Telegram accepts, in UTF-16 code units.
///
/// Telegram counts text in UTF-16 code units, not bytes and not `char`s, so
/// this bound is measured the same way rather than in a unit that would admit
/// a message the API then truncates or refuses.
pub const MAX_SEND_MESSAGE_TEXT_UNITS: usize = 4096;
/// Longest command list `setMyCommands` accepts.
pub const MAX_BOT_COMMANDS: usize = 100;
/// Longest command name `setMyCommands` accepts, in characters.
pub const MAX_BOT_COMMAND_NAME_CHARS: usize = 32;
/// Longest command description `setMyCommands` accepts, in characters.
pub const MAX_BOT_COMMAND_DESCRIPTION_CHARS: usize = 256;

/// A text at the unit ceiling always fits the byte ceiling this crate already
/// applies to Telegram content: the worst case is a BMP character costing three
/// bytes per UTF-16 unit, since an astral character costs four bytes for two.
const _: () = assert!(MAX_SEND_MESSAGE_TEXT_UNITS * 3 <= MAX_TELEGRAM_INPUT_BYTES);

/// Production synchronous Telegram HTTPS client.
///
/// The client holds no credential. Each call materializes Telegram's required
/// token-bearing path only for the duration of the request. Redirects and
/// environment proxies are disabled so that path cannot be forwarded to a
/// different peer. The workspace statically caps the `log` facade at Debug
/// because ureq redacts request paths at Debug but reveals them at Trace;
/// rebuilding with Trace enabled is intentionally unsupported. Cancellation is
/// cooperative: a cancellation observed while blocked in DNS/TCP/TLS/HTTP is
/// returned after the bounded global timeout.
pub struct TelegramHttpsClient {
    agent: ureq::Agent,
}

impl TelegramHttpsClient {
    /// Build a client using rustls verification and ureq's pinned WebPKI roots.
    #[must_use]
    pub fn new() -> Self {
        let tls = TlsConfig::builder().root_certs(RootCerts::WebPki).build();
        let config = ureq::Agent::config_builder()
            .https_only(true)
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .max_response_header_size(MAX_RESPONSE_HEADER_BYTES)
            .tls_config(tls)
            .build();
        Self {
            agent: config.new_agent(),
        }
    }
}

impl Default for TelegramHttpsClient {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TelegramHttpsClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelegramHttpsClient")
            .field("origin", &TELEGRAM_ORIGIN)
            .field("authorization", &"<not retained>")
            .finish()
    }
}

impl TelegramHttpsClient {
    /// Issue one prepared request and validate its response metadata.
    ///
    /// `prepared.url` is token-bearing; it is borrowed here and nowhere else.
    fn post(
        &mut self,
        prepared: &PreparedRequest,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> Result<TelegramHttpResponse, HttpFailure> {
        let mut response = self
            .agent
            .post(&prepared.url)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .config()
            .timeout_global(Some(timeout))
            .build()
            .send(&prepared.body)
            .map_err(map_ureq_error)?;

        if cancellation.is_cancelled() {
            return Err(HttpFailure::Cancelled);
        }
        let status = response.status().as_u16();
        if status == 429 {
            let retry_after_ms = retry_after_millis(
                response
                    .headers()
                    .get("retry-after")
                    .and_then(|value| value.to_str().ok()),
            );
            return Err(HttpFailure::RateLimited { retry_after_ms });
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok());
        validate_response_metadata(status, content_type)?;

        let reader = response
            .body_mut()
            .with_config()
            .limit((MAX_TELEGRAM_RESPONSE_BYTES + 1) as u64)
            .reader();
        let body = read_bounded_body(reader, MAX_TELEGRAM_RESPONSE_BYTES)?;
        if cancellation.is_cancelled() {
            return Err(HttpFailure::Cancelled);
        }

        Ok(TelegramHttpResponse {
            status: 200,
            body,
            completed_ms: unix_millis()?,
        })
    }
}

impl TelegramHttpClient for TelegramHttpsClient {
    fn execute(
        &mut self,
        plan: &TelegramHttpPlan<'_>,
        cancellation: &CancellationToken,
    ) -> Result<TelegramHttpResponse, HttpFailure> {
        if cancellation.is_cancelled() {
            return Err(HttpFailure::Cancelled);
        }
        let prepared = PreparedRequest::from_plan(plan)?;
        let timeout = request_timeout(plan.body.timeout_seconds);
        self.post(&prepared, timeout, cancellation)
    }
}

impl TelegramOutboundClient for TelegramHttpsClient {
    fn send(
        &mut self,
        plan: &TelegramOutboundPlan<'_>,
        cancellation: &CancellationToken,
    ) -> Result<TelegramHttpResponse, HttpFailure> {
        if cancellation.is_cancelled() {
            return Err(HttpFailure::Cancelled);
        }
        let prepared = PreparedRequest::from_outbound(plan)?;
        self.post(
            &prepared,
            Duration::from_secs(OUTBOUND_REQUEST_TIMEOUT_SECONDS),
            cancellation,
        )
    }
}

/// The complete set of request paths this module can render.
///
/// Private on purpose: it is the target lock itself. Every URL is built from
/// one of these constants, so no caller-supplied text can ever become a method
/// name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WireMethod {
    GetUpdates,
    SendMessage,
    SetMessageReaction,
    SetMyCommands,
    AnswerCallbackQuery,
    EditMessageReplyMarkup,
}

impl WireMethod {
    const fn as_str(self) -> &'static str {
        match self {
            Self::GetUpdates => "getUpdates",
            Self::SendMessage => "sendMessage",
            Self::SetMessageReaction => "setMessageReaction",
            Self::SetMyCommands => "setMyCommands",
            Self::AnswerCallbackQuery => "answerCallbackQuery",
            Self::EditMessageReplyMarkup => "editMessageReplyMarkup",
        }
    }
}

struct PreparedRequest {
    url: String,
    body: String,
}

impl PreparedRequest {
    fn from_plan(plan: &TelegramHttpPlan<'_>) -> Result<Self, HttpFailure> {
        if plan.method != HttpMethod::Post
            || plan.target != TelegramTarget::GetUpdates
            || plan.bot_id <= 0
            || plan.body.limit == 0
            || plan.body.limit > 100
            || plan.body.timeout_seconds == 0
            || plan.body.timeout_seconds > 50
        {
            return Err(HttpFailure::Unavailable);
        }

        let url = method_url(&plan.authorization(), plan.bot_id, WireMethod::GetUpdates)?;
        let body = format!(
            "{{\"offset\":{},\"limit\":{},\"timeout\":{}}}",
            plan.body.offset, plan.body.limit, plan.body.timeout_seconds
        );
        Ok(Self { url, body })
    }

    fn from_outbound(plan: &TelegramOutboundPlan<'_>) -> Result<Self, HttpFailure> {
        if plan.method != HttpMethod::Post || plan.bot_id <= 0 {
            return Err(HttpFailure::Unavailable);
        }
        let url = method_url(
            &plan.authorization(),
            plan.bot_id,
            plan.request.wire_method(),
        )?;
        Ok(Self {
            url,
            body: plan.request.canonical_body(),
        })
    }
}

/// Materialize the token-bearing request path for exactly one bot and method.
///
/// The token is checked against the plan's `bot_id` before it is spent: a token
/// whose own numeric prefix names a different bot is refused rather than
/// silently used, so a misconfigured host cannot address another bot's API with
/// this bot's identity. The comparison is against the decimal rendering of
/// `bot_id`, so an alternate spelling such as a leading zero is refused too.
fn method_url(
    authorization: &TelegramAuthorization<'_>,
    bot_id: i64,
    method: WireMethod,
) -> Result<String, HttpFailure> {
    authorization.with_secret(|secret| {
        let token = std::str::from_utf8(secret).map_err(|_| HttpFailure::Unavailable)?;
        let (token_bot, token_secret) = token.split_once(':').ok_or(HttpFailure::Unavailable)?;
        if token_bot != bot_id.to_string()
            || token_secret.is_empty()
            || !token_secret
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(HttpFailure::Unavailable);
        }
        Ok(format!("{TELEGRAM_ORIGIN}/bot{token}/{}", method.as_str()))
    })
}

/// Closed refusals from building an outbound request.
///
/// Each names the field that was wrong and nothing else — never the value, so
/// a refusal is safe to log beside operator content it may have been built
/// from. Every one of these is decided before any I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundRefusal {
    /// The bot id is not a positive Telegram bot identifier.
    BotId,
    /// The chat id is zero, which addresses no Telegram chat.
    ChatId,
    /// The text is empty, over the length ceiling, or carries control
    /// characters other than tab and newline.
    Text,
    /// A reply target was named but is not a positive message id.
    ReplyTarget,
    /// A reaction target is not a positive message id.
    MessageId,
    /// A command name is empty, over-long, repeated, or outside Telegram's
    /// lowercase `a-z0-9_` grammar.
    CommandName,
    /// A command description is empty, over-long, or control-bearing.
    CommandDescription,
    /// The command list is empty or over Telegram's ceiling.
    CommandCount,
    /// An inline approval callback is empty, over Telegram's 64-byte limit,
    /// control-bearing, repeated, or the keyboard is empty or over-wide.
    CallbackData,
    /// A callback query identifier is empty, over-long, or control-bearing.
    CallbackQueryId,
}

impl OutboundRefusal {
    /// Stable, content-free category for logging and metrics.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::BotId => "bot_id",
            Self::ChatId => "chat_id",
            Self::Text => "text",
            Self::ReplyTarget => "reply_target",
            Self::MessageId => "message_id",
            Self::CommandName => "command_name",
            Self::CommandDescription => "command_description",
            Self::CommandCount => "command_count",
            Self::CallbackData => "callback_data",
            Self::CallbackQueryId => "callback_query_id",
        }
    }
}

impl fmt::Display for OutboundRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Telegram outbound refused: {}", self.category())
    }
}

impl Error for OutboundRefusal {}

/// A validated `sendMessage` body.
///
/// Construction is the only validation point: a value of this type is already
/// within Telegram's ceilings, so rendering it cannot fail.
#[derive(Clone, Eq, PartialEq)]
pub struct SendMessageRequest {
    chat_id: i64,
    text: String,
    style: TelegramTextStyle,
    reply_to_message_id: Option<i64>,
    approval_keyboard: Option<ApprovalKeyboard>,
}

/// Telegram's `callback_data` ceiling, in bytes.
///
/// The Bot API's own bound, and it is the reason every reference this product
/// puts on a button is opaque and short rather than descriptive.
pub const MAX_CALLBACK_DATA_BYTES: usize = 64;

/// The closed set of labels an inline button may carry.
///
/// Product vocabulary rather than model output or operator text: a button label
/// is the thing an operator reads before doing something irreversible, and the
/// only part of it that varies is the opaque coordinate behind it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InlineButtonLabel {
    /// Accept the thing.
    Approve,
    /// Send it back for changes. Not a refusal.
    RequestChanges,
    /// Refuse the thing.
    Deny,
}

impl InlineButtonLabel {
    /// The exact text Telegram renders.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "Approve",
            Self::RequestChanges => "Request changes",
            Self::Deny => "Deny",
        }
    }
}

/// Largest number of buttons one inline keyboard carries.
///
/// One row, and three is what approve / deny / request-changes needs. A row a
/// phone cannot show whole is a row whose last button is the one nobody presses.
pub const MAX_INLINE_BUTTONS: usize = 3;

/// A bounded one-row inline keyboard for an exact durable decision.
///
/// Labels come from a closed set and the callbacks are opaque coordinates, so
/// nothing a caller supplies reaches the rendered text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalKeyboard {
    buttons: Vec<(InlineButtonLabel, String)>,
}

impl ApprovalKeyboard {
    /// Bind the approve / request-changes pair a self-improvement gate offers.
    ///
    /// # Errors
    ///
    /// [`OutboundRefusal::CallbackData`] for an empty, over-long,
    /// control-bearing or repeated callback value.
    pub fn new(
        approve_callback: impl Into<String>,
        revise_callback: impl Into<String>,
    ) -> Result<Self, OutboundRefusal> {
        Self::bounded(vec![
            (InlineButtonLabel::Approve, approve_callback.into()),
            (InlineButtonLabel::RequestChanges, revise_callback.into()),
        ])
    }

    /// Bind the approve / deny pair a durable approval proposal offers.
    ///
    /// A separate constructor rather than a label argument, because the two
    /// pairs are two products: "request changes" sends something back and
    /// "deny" ends it, and a caller that could choose between them by passing a
    /// value could choose wrong.
    ///
    /// # Errors
    ///
    /// [`OutboundRefusal::CallbackData`], as [`ApprovalKeyboard::new`].
    pub fn decision(
        approve_callback: impl Into<String>,
        deny_callback: impl Into<String>,
    ) -> Result<Self, OutboundRefusal> {
        Self::bounded(vec![
            (InlineButtonLabel::Approve, approve_callback.into()),
            (InlineButtonLabel::Deny, deny_callback.into()),
        ])
    }

    fn bounded(buttons: Vec<(InlineButtonLabel, String)>) -> Result<Self, OutboundRefusal> {
        if buttons.is_empty() || buttons.len() > MAX_INLINE_BUTTONS {
            return Err(OutboundRefusal::CallbackData);
        }
        for (_, callback) in &buttons {
            if callback.is_empty()
                || callback.len() > MAX_CALLBACK_DATA_BYTES
                || callback.chars().any(char::is_control)
            {
                return Err(OutboundRefusal::CallbackData);
            }
        }
        // Two buttons that answer to the same coordinate are one button wearing
        // two labels, and whichever the operator pressed the effect is the same.
        for (index, (_, callback)) in buttons.iter().enumerate() {
            if buttons[index + 1..]
                .iter()
                .any(|(_, other)| other == callback)
            {
                return Err(OutboundRefusal::CallbackData);
            }
        }
        Ok(Self { buttons })
    }

    /// The buttons, in render order.
    #[must_use]
    pub fn buttons(&self) -> &[(InlineButtonLabel, String)] {
        &self.buttons
    }

    /// Opaque callback bound to the affirmative choice.
    #[must_use]
    pub fn approve_callback(&self) -> &str {
        &self.buttons[0].1
    }

    /// Opaque callback bound to the second choice, whichever it is.
    #[must_use]
    pub fn secondary_callback(&self) -> &str {
        self.buttons
            .get(1)
            .map_or("", |(_, callback)| callback.as_str())
    }
}

/// How Telegram should present a `sendMessage` text.
///
/// The preformatted form is rendered with an explicit `pre` message entity,
/// not a parse mode. That keeps the caller's text unchanged and avoids giving
/// arbitrary output any markup semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelegramTextStyle {
    /// Ordinary Telegram message text.
    Plain,
    /// One monospaced, preformatted block spanning the complete text.
    Preformatted,
}

impl SendMessageRequest {
    /// Validate one outbound message.
    ///
    /// # Errors
    ///
    /// Returns [`OutboundRefusal::ChatId`] for a zero chat,
    /// [`OutboundRefusal::Text`] for text that is empty, longer than
    /// [`MAX_SEND_MESSAGE_TEXT_UNITS`] UTF-16 units or
    /// [`MAX_TELEGRAM_INPUT_BYTES`] bytes, or carries a control character other
    /// than tab or newline, and [`OutboundRefusal::ReplyTarget`] for a
    /// non-positive reply id.
    pub fn new(
        chat_id: i64,
        text: impl Into<String>,
        reply_to_message_id: Option<i64>,
    ) -> Result<Self, OutboundRefusal> {
        Self::with_style(
            chat_id,
            text.into(),
            TelegramTextStyle::Plain,
            reply_to_message_id,
        )
    }

    /// Validate output that Telegram should display as one preformatted block.
    ///
    /// The eventual wire body carries an explicit `pre` entity over the whole
    /// text. The text itself is not escaped or interpreted, so provider and
    /// command output containing Telegram markup characters remains exact.
    ///
    /// # Errors
    ///
    /// Returns the same closed refusals as [`Self::new`].
    pub fn new_preformatted(
        chat_id: i64,
        text: impl Into<String>,
        reply_to_message_id: Option<i64>,
    ) -> Result<Self, OutboundRefusal> {
        Self::with_style(
            chat_id,
            text.into(),
            TelegramTextStyle::Preformatted,
            reply_to_message_id,
        )
    }

    fn with_style(
        chat_id: i64,
        text: String,
        style: TelegramTextStyle,
        reply_to_message_id: Option<i64>,
    ) -> Result<Self, OutboundRefusal> {
        if chat_id == 0 {
            return Err(OutboundRefusal::ChatId);
        }
        if !is_sendable_text(&text) {
            return Err(OutboundRefusal::Text);
        }
        if reply_to_message_id.is_some_and(|id| id <= 0) {
            return Err(OutboundRefusal::ReplyTarget);
        }
        Ok(Self {
            chat_id,
            text,
            style,
            reply_to_message_id,
            approval_keyboard: None,
        })
    }

    /// Attach the fixed approval/request-changes keyboard.
    #[must_use]
    pub fn with_approval_keyboard(mut self, keyboard: ApprovalKeyboard) -> Self {
        self.approval_keyboard = Some(keyboard);
        self
    }

    /// Inline approval controls, when this message presents a gate.
    #[must_use]
    pub const fn approval_keyboard(&self) -> Option<&ApprovalKeyboard> {
        self.approval_keyboard.as_ref()
    }

    /// Chat this message is addressed to.
    #[must_use]
    pub const fn chat_id(&self) -> i64 {
        self.chat_id
    }

    /// The validated text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The presentation attached to this message text.
    #[must_use]
    pub const fn style(&self) -> TelegramTextStyle {
        self.style
    }

    /// The message this reply is threaded under, if any.
    #[must_use]
    pub const fn reply_to_message_id(&self) -> Option<i64> {
        self.reply_to_message_id
    }
}

/// Message text is product content and may quote a run's output, so `Debug`
/// reports its size and never its bytes — the same discipline the durable
/// dispositions in this crate follow.
impl fmt::Debug for SendMessageRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SendMessageRequest")
            .field("chat_id", &self.chat_id)
            .field("reply_to_message_id", &self.reply_to_message_id)
            .field(
                "text",
                &format_args!("<redacted:{} bytes>", self.text.len()),
            )
            .field("style", &self.style)
            .field("approval_keyboard", &self.approval_keyboard.is_some())
            .finish()
    }
}

/// A validated fixed 👀 acknowledgement for one Telegram message.
///
/// The emoji is deliberately not caller-selected: this surface needs one
/// closed acknowledgement and no general reaction vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetMessageReactionRequest {
    chat_id: i64,
    message_id: i64,
}

impl SetMessageReactionRequest {
    /// Validate the exact chat and message coordinates to acknowledge.
    ///
    /// # Errors
    ///
    /// Returns [`OutboundRefusal::ChatId`] for a zero chat and
    /// [`OutboundRefusal::MessageId`] for a non-positive message id.
    pub fn looking(chat_id: i64, message_id: i64) -> Result<Self, OutboundRefusal> {
        if chat_id == 0 {
            return Err(OutboundRefusal::ChatId);
        }
        if message_id <= 0 {
            return Err(OutboundRefusal::MessageId);
        }
        Ok(Self {
            chat_id,
            message_id,
        })
    }

    /// Chat containing the acknowledged message.
    #[must_use]
    pub const fn chat_id(&self) -> i64 {
        self.chat_id
    }

    /// Message receiving the acknowledgement.
    #[must_use]
    pub const fn message_id(&self) -> i64 {
        self.message_id
    }
}

/// A validated acknowledgement of one pressed inline button.
///
/// The identifier is Telegram's own for the press, and the optional text is the
/// toast the operator sees. Product vocabulary only: this is the one place a
/// refusal reaches an operator inside the button they pressed rather than as a
/// new message, and it is bounded so it cannot become a channel for anything
/// longer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnswerCallbackQueryRequest {
    callback_query_id: String,
    text: Option<String>,
}

/// Longest toast one callback acknowledgement carries.
///
/// Telegram's own ceiling is 200 characters; this is the same number in bytes,
/// which is the stricter reading and therefore the safe one.
pub const MAX_CALLBACK_ANSWER_BYTES: usize = 200;

impl AnswerCallbackQueryRequest {
    /// Acknowledge one press, optionally with a toast.
    ///
    /// # Errors
    ///
    /// [`OutboundRefusal::CallbackQueryId`] for an empty, over-long or
    /// control-bearing identifier, and [`OutboundRefusal::Text`] for a toast
    /// outside its own bound.
    pub fn new(
        callback_query_id: impl Into<String>,
        text: Option<&str>,
    ) -> Result<Self, OutboundRefusal> {
        let callback_query_id = callback_query_id.into();
        if callback_query_id.is_empty()
            || callback_query_id.len() > MAX_CALLBACK_QUERY_ID_BYTES
            || callback_query_id.chars().any(char::is_control)
        {
            return Err(OutboundRefusal::CallbackQueryId);
        }
        let text = match text {
            None => None,
            Some(text) => {
                if text.is_empty()
                    || text.len() > MAX_CALLBACK_ANSWER_BYTES
                    || text.chars().any(char::is_control)
                {
                    return Err(OutboundRefusal::Text);
                }
                Some(text.to_owned())
            }
        };
        Ok(Self {
            callback_query_id,
            text,
        })
    }

    /// Telegram's identifier for the press being acknowledged.
    #[must_use]
    pub fn callback_query_id(&self) -> &str {
        &self.callback_query_id
    }

    /// The toast, if one was supplied.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }
}

/// Longest callback query identifier this surface accepts.
pub const MAX_CALLBACK_QUERY_ID_BYTES: usize = 128;

/// A validated replacement of one message's inline keyboard.
///
/// `keyboard` of `None` strips the buttons, which is the whole reason this
/// method exists: a decided proposal must not keep showing a live-looking
/// control.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditMessageReplyMarkupRequest {
    chat_id: i64,
    message_id: i64,
    keyboard: Option<ApprovalKeyboard>,
}

impl EditMessageReplyMarkupRequest {
    /// Remove every button from one exact message.
    ///
    /// # Errors
    ///
    /// [`OutboundRefusal::ChatId`] for a zero chat and
    /// [`OutboundRefusal::MessageId`] for a non-positive message id.
    pub fn strip(chat_id: i64, message_id: i64) -> Result<Self, OutboundRefusal> {
        Self::with_keyboard(chat_id, message_id, None)
    }

    /// Replace one exact message's keyboard, or strip it with `None`.
    ///
    /// # Errors
    ///
    /// [`OutboundRefusal::ChatId`] for a zero chat and
    /// [`OutboundRefusal::MessageId`] for a non-positive message id.
    pub fn with_keyboard(
        chat_id: i64,
        message_id: i64,
        keyboard: Option<ApprovalKeyboard>,
    ) -> Result<Self, OutboundRefusal> {
        if chat_id == 0 {
            return Err(OutboundRefusal::ChatId);
        }
        if message_id <= 0 {
            return Err(OutboundRefusal::MessageId);
        }
        Ok(Self {
            chat_id,
            message_id,
            keyboard,
        })
    }

    /// Chat containing the edited message.
    #[must_use]
    pub const fn chat_id(&self) -> i64 {
        self.chat_id
    }

    /// Message whose keyboard is replaced.
    #[must_use]
    pub const fn message_id(&self) -> i64 {
        self.message_id
    }

    /// The replacement keyboard, or `None` when this strips.
    #[must_use]
    pub const fn keyboard(&self) -> Option<&ApprovalKeyboard> {
        self.keyboard.as_ref()
    }
}

/// One entry of Telegram's advertised command menu.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelegramBotCommand {
    name: String,
    description: String,
}

impl TelegramBotCommand {
    /// Validate one menu entry against Telegram's documented grammar.
    ///
    /// The name is given without its leading slash, is one to
    /// [`MAX_BOT_COMMAND_NAME_CHARS`] characters, and may contain only
    /// lowercase ASCII letters, digits and underscores.
    ///
    /// # Errors
    ///
    /// Returns [`OutboundRefusal::CommandName`] or
    /// [`OutboundRefusal::CommandDescription`] for a field outside those
    /// bounds.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Result<Self, OutboundRefusal> {
        let name = name.into();
        let description = description.into();
        if name.is_empty()
            || name.chars().count() > MAX_BOT_COMMAND_NAME_CHARS
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(OutboundRefusal::CommandName);
        }
        let described = description.chars().count();
        if described == 0
            || described > MAX_BOT_COMMAND_DESCRIPTION_CHARS
            || description.chars().any(char::is_control)
        {
            return Err(OutboundRefusal::CommandDescription);
        }
        Ok(Self { name, description })
    }

    /// The validated name, without its leading slash.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The validated description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
}

/// A validated `setMyCommands` body.
///
/// Only the `commands` array is sent. Telegram's optional `scope` and
/// `language_code` are omitted, which is its documented default scope; a host
/// that needs a narrower scope must have that spelled here rather than passing
/// one through, because this module renders no field it does not validate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetMyCommandsRequest {
    commands: Vec<TelegramBotCommand>,
}

impl SetMyCommandsRequest {
    /// Validate a whole command menu.
    ///
    /// # Errors
    ///
    /// Returns [`OutboundRefusal::CommandCount`] for an empty list or one over
    /// [`MAX_BOT_COMMANDS`], and [`OutboundRefusal::CommandName`] if two
    /// entries share a name — a repeated name is a menu whose meaning depends
    /// on Telegram's tie-breaking, which this product does not rely on.
    pub fn new(
        commands: impl IntoIterator<Item = TelegramBotCommand>,
    ) -> Result<Self, OutboundRefusal> {
        let commands: Vec<TelegramBotCommand> = commands.into_iter().collect();
        if commands.is_empty() || commands.len() > MAX_BOT_COMMANDS {
            return Err(OutboundRefusal::CommandCount);
        }
        for (index, command) in commands.iter().enumerate() {
            if commands[..index]
                .iter()
                .any(|earlier| earlier.name == command.name)
            {
                return Err(OutboundRefusal::CommandName);
            }
        }
        Ok(Self { commands })
    }

    /// The validated menu, in the order it will be sent.
    #[must_use]
    pub fn commands(&self) -> &[TelegramBotCommand] {
        &self.commands
    }
}

/// The closed set of outbound Telegram methods this product may call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TelegramOutbound {
    /// Deliver one message to one chat.
    SendMessage(SendMessageRequest),
    /// Acknowledge one message with the fixed 👀 reaction.
    SetMessageReaction(SetMessageReactionRequest),
    /// Replace the advertised command menu.
    SetMyCommands(SetMyCommandsRequest),
    /// Dismiss the spinner one pressed inline button raised.
    ///
    /// Telegram gives roughly ten seconds to answer a callback query before the
    /// client gives up and the operator sees a button that appears to have done
    /// nothing. That deadline is why this is its own method: it has to be sent
    /// before the durable work the press causes, not after it.
    AnswerCallbackQuery(AnswerCallbackQueryRequest),
    /// Replace, or remove, the inline keyboard on one exact message.
    ///
    /// Sent with no buttons to strip a decided message, which is what turns
    /// "the single-use coordinate refuses a second press" into something the
    /// operator can see rather than discover.
    EditMessageReplyMarkup(EditMessageReplyMarkupRequest),
}

impl TelegramOutbound {
    const fn wire_method(&self) -> WireMethod {
        match self {
            Self::SendMessage(_) => WireMethod::SendMessage,
            Self::SetMessageReaction(_) => WireMethod::SetMessageReaction,
            Self::SetMyCommands(_) => WireMethod::SetMyCommands,
            Self::AnswerCallbackQuery(_) => WireMethod::AnswerCallbackQuery,
            Self::EditMessageReplyMarkup(_) => WireMethod::EditMessageReplyMarkup,
        }
    }

    /// Telegram's method name for this request. Carries no credential.
    #[must_use]
    pub const fn method_name(&self) -> &'static str {
        self.wire_method().as_str()
    }

    /// The exact JSON body that will be sent, in a fixed field order.
    ///
    /// Token-free by construction, so a host may log or fixture it. Every
    /// string is escaped here; nothing is interpolated raw.
    #[must_use]
    pub fn canonical_body(&self) -> String {
        let mut body = String::new();
        match self {
            Self::SendMessage(request) => {
                body.push_str("{\"chat_id\":");
                body.push_str(&request.chat_id.to_string());
                body.push_str(",\"text\":");
                push_json_string(&mut body, &request.text);
                if request.style == TelegramTextStyle::Preformatted {
                    body.push_str(",\"entities\":[{\"type\":\"pre\",\"offset\":0,\"length\":");
                    body.push_str(&utf16_units(&request.text).to_string());
                    body.push_str("}]");
                }
                if let Some(reply_to) = request.reply_to_message_id {
                    body.push_str(",\"reply_to_message_id\":");
                    body.push_str(&reply_to.to_string());
                }
                if let Some(keyboard) = &request.approval_keyboard {
                    body.push_str(",\"reply_markup\":");
                    push_inline_keyboard(&mut body, keyboard.buttons());
                }
                body.push('}');
            }
            Self::SetMessageReaction(request) => {
                body.push_str("{\"chat_id\":");
                body.push_str(&request.chat_id.to_string());
                body.push_str(",\"message_id\":");
                body.push_str(&request.message_id.to_string());
                body.push_str(",\"reaction\":[{\"type\":\"emoji\",\"emoji\":\"👀\"}]}");
            }
            Self::AnswerCallbackQuery(request) => {
                body.push_str("{\"callback_query_id\":");
                push_json_string(&mut body, &request.callback_query_id);
                if let Some(text) = &request.text {
                    body.push_str(",\"text\":");
                    push_json_string(&mut body, text);
                }
                body.push('}');
            }
            Self::EditMessageReplyMarkup(request) => {
                body.push_str("{\"chat_id\":");
                body.push_str(&request.chat_id.to_string());
                body.push_str(",\"message_id\":");
                body.push_str(&request.message_id.to_string());
                body.push_str(",\"reply_markup\":");
                match &request.keyboard {
                    Some(keyboard) => push_inline_keyboard(&mut body, keyboard.buttons()),
                    // An empty row list is Telegram's own spelling for "no
                    // keyboard", and it is what strips a decided message.
                    None => body.push_str("{\"inline_keyboard\":[]}"),
                }
                body.push('}');
            }
            Self::SetMyCommands(request) => {
                body.push_str("{\"commands\":[");
                for (index, command) in request.commands.iter().enumerate() {
                    if index > 0 {
                        body.push(',');
                    }
                    body.push_str("{\"command\":");
                    push_json_string(&mut body, &command.name);
                    body.push_str(",\"description\":");
                    push_json_string(&mut body, &command.description);
                    body.push('}');
                }
                body.push_str("]}");
            }
        }
        body
    }
}

/// Exact outbound request plan handed to a trusted HTTP boundary.
///
/// It mirrors [`TelegramHttpPlan`]: a typed method, a bot, a validated body and
/// a borrowed credential that only the boundary may spend.
pub struct TelegramOutboundPlan<'a> {
    method: HttpMethod,
    bot_id: i64,
    request: TelegramOutbound,
    authorization: &'a OpaqueBotToken,
}

impl<'a> TelegramOutboundPlan<'a> {
    /// Bind one validated request to one bot and its credential.
    ///
    /// # Errors
    ///
    /// Returns [`OutboundRefusal::BotId`] for a non-positive bot id.
    pub fn new(
        bot_id: i64,
        request: TelegramOutbound,
        authorization: &'a OpaqueBotToken,
    ) -> Result<Self, OutboundRefusal> {
        if bot_id <= 0 {
            return Err(OutboundRefusal::BotId);
        }
        Ok(Self {
            method: HttpMethod::Post,
            bot_id,
            request,
            authorization,
        })
    }

    /// The verb this plan is issued with. Always [`HttpMethod::Post`].
    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    /// Bot this request addresses.
    #[must_use]
    pub const fn bot_id(&self) -> i64 {
        self.bot_id
    }

    /// The validated request.
    #[must_use]
    pub const fn request(&self) -> &TelegramOutbound {
        &self.request
    }

    /// The exact token-free JSON body that will be sent.
    #[must_use]
    pub fn canonical_body(&self) -> String {
        self.request.canonical_body()
    }

    /// Whether an opaque authorization capability is present.
    #[must_use]
    pub fn has_authorization(&self) -> bool {
        self.authorization.is_present()
    }

    /// Borrow the credential only at the trusted HTTP boundary.
    ///
    /// The borrow is constructed the same way [`TelegramHttpPlan`] constructs
    /// its own: this module is a child of the one that owns the token, which is
    /// why no wider accessor had to be opened on [`OpaqueBotToken`] to reach it.
    #[must_use]
    pub fn authorization(&self) -> TelegramAuthorization<'_> {
        TelegramAuthorization(&self.authorization.0)
    }
}

impl fmt::Debug for TelegramOutboundPlan<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelegramOutboundPlan")
            .field("method", &self.method)
            .field("bot_id", &self.bot_id)
            .field("method_name", &self.request.method_name())
            .field("request", &self.request)
            .field("authorization", &"<redacted>")
            .finish()
    }
}

/// An outbound implementation consumes only the typed plan and cancellation
/// flag, exactly as [`TelegramHttpClient`] does for the inbound direction.
///
/// A 200 response with a JSON content type is the whole success signal this
/// seam reports: Telegram answers a rejected method call with a non-200 status,
/// which [`HttpFailure::UnexpectedStatus`] already refuses. The body is
/// returned unparsed — this crate does not interpret outbound results.
pub trait TelegramOutboundClient {
    /// Issue one outbound call.
    ///
    /// # Errors
    ///
    /// Returns the closed [`HttpFailure`] vocabulary, including
    /// [`HttpFailure::Cancelled`] when cancellation is observed before the
    /// request is issued or before its body is accepted.
    fn send(
        &mut self,
        plan: &TelegramOutboundPlan<'_>,
        cancellation: &CancellationToken,
    ) -> Result<TelegramHttpResponse, HttpFailure>;
}

/// Whether text may be sent as a Telegram message body.
///
/// Tab and newline are admitted because operators format multi-line replies
/// with them; every other control character is refused rather than escaped, so
/// a terminal rendering the eventual reply cannot be driven by message content.
fn is_sendable_text(text: &str) -> bool {
    if text.is_empty() || text.len() > MAX_TELEGRAM_INPUT_BYTES {
        return false;
    }
    let mut units = 0_usize;
    for character in text.chars() {
        if character.is_control() && !matches!(character, '\n' | '\t') {
            return false;
        }
        units += character.len_utf16();
        if units > MAX_SEND_MESSAGE_TEXT_UNITS {
            return false;
        }
    }
    true
}

fn utf16_units(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

/// Append one JSON string literal, escaping every character JSON requires.
///
/// Written out rather than delegated because this crate carries no JSON
/// serializer; the escape set is the whole of RFC 8259's requirement — the two
/// mandatory escapes plus every code point below `0x20` — with `DEL` escaped as
/// well so no C0/C1-adjacent byte reaches a log verbatim.
/// Render one inline keyboard as Telegram's `reply_markup` value.
///
/// One row, in the order the buttons were bound. Every label comes from the
/// closed set and every callback is escaped here, so nothing interpolated into
/// this fragment is raw.
fn push_inline_keyboard(body: &mut String, buttons: &[(InlineButtonLabel, String)]) {
    body.push_str("{\"inline_keyboard\":[[");
    for (index, (label, callback)) in buttons.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str("{\"text\":");
        push_json_string(body, label.as_str());
        body.push_str(",\"callback_data\":");
        push_json_string(body, callback);
        body.push('}');
    }
    body.push_str("]]}");
}

fn is_json_content_type(value: &str) -> bool {
    let mut fields = value.split(';');
    if !fields
        .next()
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
    {
        return false;
    }
    fields.all(|parameter| {
        let Some((name, value)) = parameter.trim().split_once('=') else {
            return false;
        };
        name.trim().eq_ignore_ascii_case("charset")
            && value.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
    })
}

fn request_timeout(long_poll_seconds: u16) -> Duration {
    Duration::from_secs(u64::from(long_poll_seconds) + HTTP_TRANSPORT_ALLOWANCE_SECONDS)
}

fn validate_response_metadata(status: u16, content_type: Option<&str>) -> Result<(), HttpFailure> {
    if status != 200 {
        return Err(HttpFailure::UnexpectedStatus);
    }
    if !content_type.is_some_and(is_json_content_type) {
        return Err(HttpFailure::UnexpectedContentType);
    }
    Ok(())
}

fn retry_after_millis(value: Option<&str>) -> u64 {
    value
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(1)
        .clamp(1, MAX_RETRY_AFTER_SECONDS)
        .saturating_mul(1_000)
}

fn unix_millis() -> Result<i64, HttpFailure> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HttpFailure::Unavailable)?
        .as_millis();
    i64::try_from(millis).map_err(|_| HttpFailure::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GetUpdatesBody, OpaqueBotToken};

    fn plan<'a>(token: &'a OpaqueBotToken) -> TelegramHttpPlan<'a> {
        TelegramHttpPlan {
            method: HttpMethod::Post,
            target: TelegramTarget::GetUpdates,
            bot_id: 42,
            body: GetUpdatesBody {
                offset: u64::MAX,
                limit: 100,
                timeout_seconds: 50,
            },
            authorization: token,
        }
    }

    #[test]
    fn client_configuration_is_https_direct_verified_and_non_redirecting() {
        let client = TelegramHttpsClient::new();
        let config = client.agent.config();
        assert!(config.https_only());
        assert!(config.proxy().is_none());
        assert_eq!(config.max_redirects(), 0);
        assert!(!config.http_status_as_error());
        assert_eq!(config.max_response_header_size(), MAX_RESPONSE_HEADER_BYTES);
        assert!(matches!(
            config.tls_config().root_certs(),
            RootCerts::WebPki
        ));
        assert!(log::STATIC_MAX_LEVEL <= log::LevelFilter::Debug);
    }

    #[test]
    fn prepared_request_is_exact_post_target_and_numeric_json() {
        let token = OpaqueBotToken::new(b"42:fixture-token".to_vec()).expect("token");
        let prepared = PreparedRequest::from_plan(&plan(&token)).expect("prepare");
        assert_eq!(
            prepared.url,
            "https://api.telegram.org/bot42:fixture-token/getUpdates"
        );
        assert_eq!(
            prepared.body,
            format!("{{\"offset\":{},\"limit\":100,\"timeout\":50}}", u64::MAX)
        );
    }

    #[test]
    fn authorization_never_appears_in_debug_or_closed_errors() {
        let token_text = "42:fixture-secret-never-print";
        let token = OpaqueBotToken::new(token_text.as_bytes().to_vec()).expect("token");
        let client = TelegramHttpsClient::new();
        let plan = plan(&token);
        assert!(!format!("{token:?}{plan:?}{client:?}").contains(token_text));
        assert!(!format!("{:?}", HttpFailure::Unavailable).contains(token_text));
    }

    #[test]
    fn mismatched_bot_and_malformed_token_are_refused_before_io() {
        let wrong_bot = OpaqueBotToken::new(b"41:fixture-token".to_vec()).expect("token");
        assert!(matches!(
            PreparedRequest::from_plan(&plan(&wrong_bot)),
            Err(HttpFailure::Unavailable)
        ));
        let malformed = OpaqueBotToken::new(b"42-no-separator".to_vec()).expect("token");
        assert!(matches!(
            PreparedRequest::from_plan(&plan(&malformed)),
            Err(HttpFailure::Unavailable)
        ));
        let alternate_bot = OpaqueBotToken::new(b"042:fixture-token".to_vec()).expect("token");
        assert!(matches!(
            PreparedRequest::from_plan(&plan(&alternate_bot)),
            Err(HttpFailure::Unavailable)
        ));
    }

    #[test]
    fn response_content_type_is_closed() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("Application/Json; charset=UTF-8"));
        assert!(!is_json_content_type("text/json"));
        assert!(!is_json_content_type("application/json; profile=secret"));
        assert!(!is_json_content_type("application/json; charset=latin1"));
        assert_eq!(
            validate_response_metadata(429, Some("application/json")),
            Err(HttpFailure::UnexpectedStatus)
        );
        assert_eq!(
            validate_response_metadata(200, None),
            Err(HttpFailure::UnexpectedContentType)
        );
    }

    #[test]
    fn retry_after_is_bounded_and_never_becomes_a_busy_loop() {
        assert_eq!(retry_after_millis(None), 1_000);
        assert_eq!(retry_after_millis(Some("0")), 1_000);
        assert_eq!(retry_after_millis(Some(" 12 ")), 12_000);
        assert_eq!(retry_after_millis(Some("999999")), 300_000);
        assert_eq!(retry_after_millis(Some("not-a-number")), 1_000);
    }

    #[test]
    fn response_body_cap_accepts_boundary_and_refuses_one_over() {
        let at_limit = vec![0_u8; MAX_TELEGRAM_RESPONSE_BYTES];
        assert_eq!(
            read_bounded_body(std::io::Cursor::new(&at_limit), MAX_TELEGRAM_RESPONSE_BYTES)
                .expect("at limit"),
            at_limit
        );
        let over_limit = vec![0_u8; MAX_TELEGRAM_RESPONSE_BYTES + 1];
        assert_eq!(
            read_bounded_body(
                std::io::Cursor::new(over_limit),
                MAX_TELEGRAM_RESPONSE_BYTES
            )
            .map_err(HttpFailure::from),
            Err(HttpFailure::ResponseTooLarge)
        );
    }

    #[test]
    fn transport_timeout_stays_inside_lease_margin() {
        let timeout = request_timeout(50);
        assert_eq!(timeout, Duration::from_secs(53));
        assert!(timeout.as_millis() < crate::TELEGRAM_HTTP_LEASE_MARGIN_MS as u128 + 50_000);
    }

    #[test]
    fn cancellation_before_io_is_closed() {
        let token = OpaqueBotToken::new(b"42:fixture-token".to_vec()).expect("token");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut client = TelegramHttpsClient::new();
        assert_eq!(
            client.execute(&plan(&token), &cancellation),
            Err(HttpFailure::Cancelled)
        );
    }

    fn outbound_plan<'a>(
        token: &'a OpaqueBotToken,
        request: TelegramOutbound,
    ) -> TelegramOutboundPlan<'a> {
        TelegramOutboundPlan::new(42, request, token).expect("plan")
    }

    fn send_message(text: &str) -> TelegramOutbound {
        TelegramOutbound::SendMessage(
            SendMessageRequest::new(-1_001, text, None).expect("send message"),
        )
    }

    #[test]
    fn approval_buttons_render_as_fixed_labels_and_opaque_callbacks() {
        let keyboard = ApprovalKeyboard::new("imp:a:plan:opaque-nonce", "imp:r:plan:opaque-nonce")
            .expect("keyboard");
        let outbound = TelegramOutbound::SendMessage(
            SendMessageRequest::new(7, "Plan ready", None)
                .expect("message")
                .with_approval_keyboard(keyboard),
        );
        assert_eq!(
            outbound.canonical_body(),
            r#"{"chat_id":7,"text":"Plan ready","reply_markup":{"inline_keyboard":[[{"text":"Approve","callback_data":"imp:a:plan:opaque-nonce"},{"text":"Request changes","callback_data":"imp:r:plan:opaque-nonce"}]]}}"#
        );
        assert_eq!(
            ApprovalKeyboard::new("same", "same").err(),
            Some(OutboundRefusal::CallbackData)
        );
        assert_eq!(
            ApprovalKeyboard::new("x".repeat(65), "different").err(),
            Some(OutboundRefusal::CallbackData)
        );
    }

    #[test]
    fn outbound_urls_are_exact_and_reach_only_the_permitted_methods() {
        let token = OpaqueBotToken::new(b"42:fixture-token".to_vec()).expect("token");
        let sending = PreparedRequest::from_outbound(&outbound_plan(&token, send_message("hi")))
            .expect("prepare send");
        assert_eq!(
            sending.url,
            "https://api.telegram.org/bot42:fixture-token/sendMessage"
        );
        let reacting = TelegramOutbound::SetMessageReaction(
            SetMessageReactionRequest::looking(-1_001, 17).expect("reaction"),
        );
        let reacting = PreparedRequest::from_outbound(&outbound_plan(&token, reacting))
            .expect("prepare reaction");
        assert_eq!(
            reacting.url,
            "https://api.telegram.org/bot42:fixture-token/setMessageReaction"
        );
        let menu = TelegramOutbound::SetMyCommands(
            SetMyCommandsRequest::new([TelegramBotCommand::new(
                "status",
                "Report the daemon status snapshot",
            )
            .expect("command")])
            .expect("menu"),
        );
        let publishing =
            PreparedRequest::from_outbound(&outbound_plan(&token, menu)).expect("prepare menu");
        assert_eq!(
            publishing.url,
            "https://api.telegram.org/bot42:fixture-token/setMyCommands"
        );

        let answering = TelegramOutbound::AnswerCallbackQuery(
            AnswerCallbackQueryRequest::new("cbq-1", None).expect("acknowledgement"),
        );
        let answering = PreparedRequest::from_outbound(&outbound_plan(&token, answering))
            .expect("prepare acknowledgement");
        assert_eq!(
            answering.url,
            "https://api.telegram.org/bot42:fixture-token/answerCallbackQuery"
        );
        let stripping = TelegramOutbound::EditMessageReplyMarkup(
            EditMessageReplyMarkupRequest::strip(-1_001, 17).expect("strip"),
        );
        let stripping = PreparedRequest::from_outbound(&outbound_plan(&token, stripping))
            .expect("prepare strip");
        assert_eq!(
            stripping.url,
            "https://api.telegram.org/bot42:fixture-token/editMessageReplyMarkup"
        );

        // The lock is the enum: these renderings are the complete set of
        // request paths this module can produce.
        assert_eq!(WireMethod::GetUpdates.as_str(), "getUpdates");
        assert_eq!(WireMethod::SendMessage.as_str(), "sendMessage");
        assert_eq!(
            WireMethod::SetMessageReaction.as_str(),
            "setMessageReaction"
        );
        assert_eq!(WireMethod::SetMyCommands.as_str(), "setMyCommands");
        assert_eq!(
            WireMethod::AnswerCallbackQuery.as_str(),
            "answerCallbackQuery"
        );
        assert_eq!(
            WireMethod::EditMessageReplyMarkup.as_str(),
            "editMessageReplyMarkup"
        );
    }

    #[test]
    fn a_decision_keyboard_renders_approve_and_deny_and_bounds_every_entry() {
        let keyboard = ApprovalKeyboard::decision("apr-aaaa", "apd-aaaa").expect("keyboard");
        let outbound = TelegramOutbound::SendMessage(
            SendMessageRequest::new(7, "Approval waiting", None)
                .expect("message")
                .with_approval_keyboard(keyboard),
        );
        assert_eq!(
            outbound.canonical_body(),
            r#"{"chat_id":7,"text":"Approval waiting","reply_markup":{"inline_keyboard":[[{"text":"Approve","callback_data":"apr-aaaa"},{"text":"Deny","callback_data":"apd-aaaa"}]]}}"#
        );
        // "Deny" and "Request changes" are different products, and the pair a
        // caller picks is a constructor rather than an argument.
        assert_eq!(InlineButtonLabel::Deny.as_str(), "Deny");
        assert_eq!(
            InlineButtonLabel::RequestChanges.as_str(),
            "Request changes"
        );
        assert_eq!(InlineButtonLabel::Approve.as_str(), "Approve");

        // Telegram's own 64-byte ceiling, at the boundary and one past it.
        assert!(ApprovalKeyboard::decision("a".repeat(MAX_CALLBACK_DATA_BYTES), "b").is_ok());
        assert_eq!(
            ApprovalKeyboard::decision("a".repeat(MAX_CALLBACK_DATA_BYTES + 1), "b").err(),
            Some(OutboundRefusal::CallbackData)
        );
        // Two buttons answering to one coordinate are one button wearing two
        // labels, whichever the operator pressed.
        assert_eq!(
            ApprovalKeyboard::decision("same", "same").err(),
            Some(OutboundRefusal::CallbackData)
        );
        assert_eq!(
            ApprovalKeyboard::decision("", "b").err(),
            Some(OutboundRefusal::CallbackData)
        );
        assert_eq!(
            ApprovalKeyboard::decision("bell\u{7}", "b").err(),
            Some(OutboundRefusal::CallbackData)
        );
    }

    #[test]
    fn an_acknowledgement_body_is_canonical_and_bounded() {
        let bare = TelegramOutbound::AnswerCallbackQuery(
            AnswerCallbackQueryRequest::new("cbq-1", None).expect("acknowledgement"),
        );
        assert_eq!(bare.method_name(), "answerCallbackQuery");
        assert_eq!(bare.canonical_body(), r#"{"callback_query_id":"cbq-1"}"#);

        let toast = TelegramOutbound::AnswerCallbackQuery(
            AnswerCallbackQueryRequest::new("cbq-1", Some("Already decided \"by\" somebody"))
                .expect("acknowledgement"),
        );
        assert_eq!(
            toast.canonical_body(),
            r#"{"callback_query_id":"cbq-1","text":"Already decided \"by\" somebody"}"#
        );

        assert_eq!(
            AnswerCallbackQueryRequest::new("", None).err(),
            Some(OutboundRefusal::CallbackQueryId)
        );
        assert_eq!(
            AnswerCallbackQueryRequest::new("x".repeat(MAX_CALLBACK_QUERY_ID_BYTES + 1), None)
                .err(),
            Some(OutboundRefusal::CallbackQueryId)
        );
        assert_eq!(
            AnswerCallbackQueryRequest::new("cbq-1", Some("")).err(),
            Some(OutboundRefusal::Text)
        );
        assert_eq!(
            AnswerCallbackQueryRequest::new(
                "cbq-1",
                Some(&"x".repeat(MAX_CALLBACK_ANSWER_BYTES + 1))
            )
            .err(),
            Some(OutboundRefusal::Text)
        );
    }

    #[test]
    fn a_strip_sends_an_empty_keyboard_and_a_replacement_sends_the_new_one() {
        let strip = TelegramOutbound::EditMessageReplyMarkup(
            EditMessageReplyMarkupRequest::strip(-1_001, 17).expect("strip"),
        );
        // Byte-exact: an empty row list is Telegram's own spelling for "no
        // keyboard", and a decided message must carry no live control.
        assert_eq!(
            strip.canonical_body(),
            r#"{"chat_id":-1001,"message_id":17,"reply_markup":{"inline_keyboard":[]}}"#
        );

        let replace = TelegramOutbound::EditMessageReplyMarkup(
            EditMessageReplyMarkupRequest::with_keyboard(
                7,
                3,
                Some(ApprovalKeyboard::decision("apr-a", "apd-a").expect("keyboard")),
            )
            .expect("replacement"),
        );
        assert_eq!(
            replace.canonical_body(),
            r#"{"chat_id":7,"message_id":3,"reply_markup":{"inline_keyboard":[[{"text":"Approve","callback_data":"apr-a"},{"text":"Deny","callback_data":"apd-a"}]]}}"#
        );

        assert_eq!(
            EditMessageReplyMarkupRequest::strip(0, 17).err(),
            Some(OutboundRefusal::ChatId)
        );
        assert_eq!(
            EditMessageReplyMarkupRequest::strip(7, 0).err(),
            Some(OutboundRefusal::MessageId)
        );
    }

    #[test]
    fn outbound_refuses_a_mismatched_or_malformed_token_before_io() {
        let wrong_bot = OpaqueBotToken::new(b"41:fixture-token".to_vec()).expect("token");
        assert_eq!(
            PreparedRequest::from_outbound(&outbound_plan(&wrong_bot, send_message("hi"))).err(),
            Some(HttpFailure::Unavailable)
        );
        let malformed = OpaqueBotToken::new(b"42-no-separator".to_vec()).expect("token");
        assert_eq!(
            PreparedRequest::from_outbound(&outbound_plan(&malformed, send_message("hi"))).err(),
            Some(HttpFailure::Unavailable)
        );
        assert_eq!(
            TelegramOutboundPlan::new(0, send_message("hi"), &wrong_bot).err(),
            Some(OutboundRefusal::BotId)
        );
    }

    #[test]
    fn the_token_never_reaches_a_rendered_outbound_request() {
        let secret = "42:fixture-secret-never-print";
        let token = OpaqueBotToken::new(secret.as_bytes().to_vec()).expect("token");
        let plan = outbound_plan(&token, send_message("run 7 finished"));
        let rendered = format!(
            "{plan:?}{}{}{:?}{:?}{:?}",
            plan.canonical_body(),
            OutboundRefusal::Text,
            OutboundRefusal::Text,
            token,
            plan.authorization()
        );
        assert!(!rendered.contains("fixture-secret-never-print"));
        assert!(rendered.contains("<redacted"));
        // The message text is the caller's, and the body is the one rendering
        // that must reproduce it exactly; the plan's Debug still withholds it.
        assert!(plan.canonical_body().contains("run 7 finished"));
        assert!(!format!("{plan:?}").contains("run 7 finished"));

        // Only the prepared request holds the credential, and only as the path
        // Telegram requires.
        let prepared = PreparedRequest::from_outbound(&plan).expect("prepare");
        assert!(prepared.url.contains(secret));
        assert!(!prepared.body.contains(secret));
    }

    #[test]
    fn send_message_body_is_canonical_and_escaped() {
        let plain = TelegramOutbound::SendMessage(
            SendMessageRequest::new(-1_001, "run 7 done", None).expect("request"),
        );
        assert_eq!(plain.method_name(), "sendMessage");
        assert_eq!(
            plain.canonical_body(),
            r#"{"chat_id":-1001,"text":"run 7 done"}"#
        );

        let threaded = TelegramOutbound::SendMessage(
            SendMessageRequest::new(7, "ok", Some(31)).expect("request"),
        );
        assert_eq!(
            threaded.canonical_body(),
            r#"{"chat_id":7,"text":"ok","reply_to_message_id":31}"#
        );

        let hostile = TelegramOutbound::SendMessage(
            SendMessageRequest::new(7, "quote\" slash\\ line\n tab\t", None).expect("request"),
        );
        assert_eq!(
            hostile.canonical_body(),
            r#"{"chat_id":7,"text":"quote\" slash\\ line\n tab\t"}"#
        );
    }

    #[test]
    fn eyes_reaction_body_and_bounds_are_exact() {
        let reaction = TelegramOutbound::SetMessageReaction(
            SetMessageReactionRequest::looking(-1_001, 31).expect("reaction"),
        );
        assert_eq!(reaction.method_name(), "setMessageReaction");
        assert_eq!(
            reaction.canonical_body(),
            r#"{"chat_id":-1001,"message_id":31,"reaction":[{"type":"emoji","emoji":"👀"}]}"#
        );
        assert_eq!(
            SetMessageReactionRequest::looking(0, 31).err(),
            Some(OutboundRefusal::ChatId)
        );
        assert_eq!(
            SetMessageReactionRequest::looking(7, 0).err(),
            Some(OutboundRefusal::MessageId)
        );
        assert_eq!(
            SetMessageReactionRequest::looking(7, -1).err(),
            Some(OutboundRefusal::MessageId)
        );
    }

    #[test]
    fn set_my_commands_body_is_canonical_and_ordered() {
        let menu = TelegramOutbound::SetMyCommands(
            SetMyCommandsRequest::new([
                TelegramBotCommand::new("help", "Show \"the\" commands").expect("command"),
                TelegramBotCommand::new("run", "Submit a run").expect("command"),
            ])
            .expect("menu"),
        );
        assert_eq!(menu.method_name(), "setMyCommands");
        assert_eq!(
            menu.canonical_body(),
            r#"{"commands":[{"command":"help","description":"Show \"the\" commands"},{"command":"run","description":"Submit a run"}]}"#
        );
    }

    #[test]
    fn json_escaping_covers_every_control_code_point() {
        let mut rendered = String::new();
        push_json_string(&mut rendered, "\u{0}\u{1}\u{8}\u{c}\u{1f}\u{7f}");
        assert_eq!(rendered, r#""\u0000\u0001\b\f\u001f\u007f""#);
        let mut kept = String::new();
        push_json_string(&mut kept, "héllo 😀");
        assert_eq!(kept, "\"héllo 😀\"");
    }

    #[test]
    fn send_message_bounds_are_exact() {
        assert_eq!(
            SendMessageRequest::new(0, "hi", None).err(),
            Some(OutboundRefusal::ChatId)
        );
        assert_eq!(
            SendMessageRequest::new(7, "", None).err(),
            Some(OutboundRefusal::Text)
        );
        assert_eq!(
            SendMessageRequest::new(7, "bell\u{7}", None).err(),
            Some(OutboundRefusal::Text)
        );
        assert!(SendMessageRequest::new(7, "line\nbreak\tkept", None).is_ok());
        assert_eq!(
            SendMessageRequest::new(7, "hi", Some(0)).err(),
            Some(OutboundRefusal::ReplyTarget)
        );
        assert_eq!(
            SendMessageRequest::new(7, "hi", Some(-1)).err(),
            Some(OutboundRefusal::ReplyTarget)
        );

        let at_limit = "a".repeat(MAX_SEND_MESSAGE_TEXT_UNITS);
        assert!(SendMessageRequest::new(7, at_limit.clone(), None).is_ok());
        assert_eq!(
            SendMessageRequest::new(7, format!("{at_limit}a"), None).err(),
            Some(OutboundRefusal::Text)
        );
        // Telegram counts UTF-16 units, so an astral character costs two.
        let astral = "😀".repeat(MAX_SEND_MESSAGE_TEXT_UNITS / 2);
        assert!(SendMessageRequest::new(7, astral.clone(), None).is_ok());
        assert_eq!(
            SendMessageRequest::new(7, format!("{astral}😀"), None).err(),
            Some(OutboundRefusal::Text)
        );
    }

    #[test]
    fn bot_command_bounds_match_telegrams_grammar() {
        assert_eq!(
            TelegramBotCommand::new("Status", "upper case").err(),
            Some(OutboundRefusal::CommandName)
        );
        assert_eq!(
            TelegramBotCommand::new("with-dash", "dash").err(),
            Some(OutboundRefusal::CommandName)
        );
        assert_eq!(
            TelegramBotCommand::new("", "empty").err(),
            Some(OutboundRefusal::CommandName)
        );
        assert!(TelegramBotCommand::new("a_9", "fine").is_ok());
        assert!(
            TelegramBotCommand::new("n".repeat(MAX_BOT_COMMAND_NAME_CHARS), "at limit").is_ok()
        );
        assert_eq!(
            TelegramBotCommand::new("n".repeat(MAX_BOT_COMMAND_NAME_CHARS + 1), "over").err(),
            Some(OutboundRefusal::CommandName)
        );
        assert_eq!(
            TelegramBotCommand::new("ok", "").err(),
            Some(OutboundRefusal::CommandDescription)
        );
        assert_eq!(
            TelegramBotCommand::new("ok", "control\u{1}").err(),
            Some(OutboundRefusal::CommandDescription)
        );
        assert!(
            TelegramBotCommand::new("ok", "d".repeat(MAX_BOT_COMMAND_DESCRIPTION_CHARS)).is_ok()
        );
        assert_eq!(
            TelegramBotCommand::new("ok", "d".repeat(MAX_BOT_COMMAND_DESCRIPTION_CHARS + 1)).err(),
            Some(OutboundRefusal::CommandDescription)
        );
    }

    #[test]
    fn command_menu_bounds_and_uniqueness_are_exact() {
        let command = |index: usize| {
            TelegramBotCommand::new(format!("c{index}"), "fixture").expect("command")
        };
        assert_eq!(
            SetMyCommandsRequest::new([]).err(),
            Some(OutboundRefusal::CommandCount)
        );
        assert!(SetMyCommandsRequest::new((0..MAX_BOT_COMMANDS).map(command)).is_ok());
        assert_eq!(
            SetMyCommandsRequest::new((0..=MAX_BOT_COMMANDS).map(command)).err(),
            Some(OutboundRefusal::CommandCount)
        );
        assert_eq!(
            SetMyCommandsRequest::new([command(1), command(1)]).err(),
            Some(OutboundRefusal::CommandName)
        );
    }

    #[test]
    fn outbound_cancellation_before_io_is_closed() {
        let token = OpaqueBotToken::new(b"42:fixture-token".to_vec()).expect("token");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut client = TelegramHttpsClient::new();
        assert_eq!(
            client.send(&outbound_plan(&token, send_message("hi")), &cancellation),
            Err(HttpFailure::Cancelled)
        );
    }

    #[test]
    fn the_outbound_budget_is_bounded_and_needs_no_long_poll_allowance() {
        assert_eq!(OUTBOUND_REQUEST_TIMEOUT_SECONDS, 10);
        assert!(
            Duration::from_secs(OUTBOUND_REQUEST_TIMEOUT_SECONDS) < request_timeout(50),
            "an outbound call must never outlive an inbound long poll"
        );
    }
}
