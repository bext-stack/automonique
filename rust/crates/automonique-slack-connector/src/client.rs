// SPDX-License-Identifier: Elastic-2.0

//! The synchronous Slack client.
//!
//! One origin, six methods, one verb. The client is the composition of
//! [`SlackOperation`]'s rendering and the `decode_*` functions around a single
//! bounded HTTP call — it adds no field to a request and repairs no field in a
//! response, so everything it can send or accept is already provable without a
//! socket.
//!
//! The ureq agent mirrors `GitHubClient`, `FleetClient` and
//! `TelegramHttpsClient`: pinned WebPKI roots, no environment proxy, no
//! redirects, a header-size ceiling, and statuses surfaced as values rather
//! than errors. `https_only` is relaxed only for a [`SlackBase`] that proved
//! itself the plaintext-loopback shape, which is how the hermetic tests reach
//! an in-process fake without a certificate.
//!
//! # Why every call is a `POST`
//!
//! Slack accepts `GET` for its read methods, but its arguments then ride in a
//! query string. A `POST` body keeps every caller value out of the URL
//! entirely, which is what makes the target lock a statement about the whole
//! request rather than about its path alone.
//!
//! # Why redirects are refused rather than followed
//!
//! The credential is bound to one origin. A redirect is an instruction to send
//! the next request somewhere else, and a client that follows one has handed
//! the decision about where its token goes to the response it just received.

use std::fmt;
use std::io::Read;
use std::time::Duration;

use ureq::tls::{RootCerts, TlsConfig};

use crate::response::{
    decode_ack, decode_auth_test, decode_conversations_history, decode_conversations_info,
    decode_conversations_list, decode_error_code, decode_post_message, decode_users_info,
};
use crate::{
    AuthIdentity, ChannelPage, ConversationsHistoryRequest, ConversationsInfoRequest,
    ConversationsListRequest, MAX_SLACK_RESPONSE_BYTES, MessagePage, OpenViewRequest,
    PostMessageRequest, PostedMessage, PublishViewRequest, SLACK_REQUEST_TIMEOUT_SECONDS,
    SlackBase, SlackChannel, SlackFailure, SlackMethod, SlackOperation, SlackOutcome,
    SlackRejection, SlackToken, SlackUser, UpdateMessageRequest, UsersInfoRequest,
};

/// The media type every request asks for.
pub const SLACK_ACCEPT: &str = "application/json";

/// The media type every request sends.
///
/// Form-encoded rather than JSON: Slack's read methods reject a JSON request
/// body with `invalid_arguments` (confirmed live), so
/// `application/x-www-form-urlencoded` is the one spelling every method accepts.
/// The body is pure ASCII after percent-encoding, so no charset parameter is
/// carried — the value matches what the live API accepts from a plain
/// form-encoded `POST`.
pub const SLACK_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

/// How this connector identifies itself.
///
/// A distinct user agent rather than the legacy bot's, because a shared one
/// makes two applications' traffic indistinguishable in an audit log.
pub const SLACK_USER_AGENT: &str = "automonique-slack-connector";

/// The code a 429 is reported under when its body did not name one.
const RATE_LIMITED: &str = "ratelimited";

const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;

/// The workspace caps the `log` facade at Debug because ureq redacts request
/// metadata at Debug and reveals more at Trace. Rebuilding with Trace enabled
/// is intentionally unsupported, and this assertion is what says so.
const _: () = assert!((log::STATIC_MAX_LEVEL as usize) <= (log::LevelFilter::Debug as usize));

/// A synchronous client for one Slack origin and one credential.
pub struct SlackClient {
    agent: ureq::Agent,
    base: SlackBase,
    token: SlackToken,
    timeout: Duration,
}

impl SlackClient {
    /// Bind one origin and one credential.
    ///
    /// The request budget is [`SLACK_REQUEST_TIMEOUT_SECONDS`].
    #[must_use]
    pub fn new(base: SlackBase, token: SlackToken) -> Self {
        Self::with_request_timeout(
            base,
            token,
            Duration::from_secs(SLACK_REQUEST_TIMEOUT_SECONDS),
        )
    }

    /// Bind a client with a *tighter* request budget.
    ///
    /// The budget is clamped to [`SLACK_REQUEST_TIMEOUT_SECONDS`], so a caller
    /// may only shorten it, never extend it: a host that is talked into asking
    /// for an hour still gets ten seconds. A zero budget is read as "the
    /// ceiling" rather than "no wait at all", because a zero-length deadline is
    /// never what a caller means.
    #[must_use]
    pub fn with_request_timeout(base: SlackBase, token: SlackToken, timeout: Duration) -> Self {
        let ceiling = Duration::from_secs(SLACK_REQUEST_TIMEOUT_SECONDS);
        let timeout = if timeout.is_zero() {
            ceiling
        } else {
            timeout.min(ceiling)
        };
        let tls = TlsConfig::builder().root_certs(RootCerts::WebPki).build();
        let config = ureq::Agent::config_builder()
            .https_only(!base.is_plaintext_loopback())
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .max_response_header_size(MAX_RESPONSE_HEADER_BYTES)
            .user_agent(SLACK_USER_AGENT)
            .tls_config(tls)
            .build();
        Self {
            agent: config.new_agent(),
            base,
            token,
            timeout,
        }
    }

    /// The origin this client is locked to.
    #[must_use]
    pub const fn base(&self) -> &SlackBase {
        &self.base
    }

    /// The whole-call budget this client issues requests with.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.timeout
    }

    /// The exact URL a method would address, without addressing it.
    #[must_use]
    pub fn endpoint(&self, method: SlackMethod) -> String {
        format!("{}{}", self.base.origin(), method.path())
    }

    /// The exact body an operation would send, without sending it.
    #[must_use]
    pub fn canonical_body(operation: &SlackOperation) -> String {
        operation.body()
    }

    /// Identify the account and workspace the credential belongs to.
    ///
    /// The cheap connectivity and scope probe, and the only method that takes
    /// no argument. Its `user_id` is what a caller compares every message
    /// author against to tell its own messages from everyone else's.
    ///
    /// # Errors
    ///
    /// Returns the closed [`SlackFailure`] vocabulary for a transport problem
    /// or a response that is not this method's contract. Slack's own refusal is
    /// an `Ok` reply carrying a [`SlackRejection`].
    pub fn auth_test(&self) -> Result<SlackOutcome<AuthIdentity>, SlackFailure> {
        self.call(&SlackOperation::AuthTest, decode_auth_test)
    }

    /// Page the conversations this token can see.
    ///
    /// # Errors
    ///
    /// As [`SlackClient::auth_test`], for this method's contract.
    pub fn conversations_list(
        &self,
        request: &ConversationsListRequest,
    ) -> Result<SlackOutcome<ChannelPage>, SlackFailure> {
        let limit = request.limit();
        self.call(
            &SlackOperation::ConversationsList(request.clone()),
            |bytes| decode_conversations_list(bytes, limit),
        )
    }

    /// Read one conversation.
    ///
    /// # Errors
    ///
    /// As [`SlackClient::auth_test`], for this method's contract.
    pub fn conversations_info(
        &self,
        request: &ConversationsInfoRequest,
    ) -> Result<SlackOutcome<SlackChannel>, SlackFailure> {
        self.call(
            &SlackOperation::ConversationsInfo(request.clone()),
            decode_conversations_info,
        )
    }

    /// Read one page of a conversation's recent messages.
    ///
    /// # Errors
    ///
    /// As [`SlackClient::auth_test`], for this method's contract.
    pub fn conversations_history(
        &self,
        request: &ConversationsHistoryRequest,
    ) -> Result<SlackOutcome<MessagePage>, SlackFailure> {
        let limit = request.limit();
        self.call(
            &SlackOperation::ConversationsHistory(request.clone()),
            |bytes| decode_conversations_history(bytes, limit),
        )
    }

    /// Resolve one user, so an author id can be shown as a name.
    ///
    /// # Errors
    ///
    /// As [`SlackClient::auth_test`], for this method's contract.
    pub fn users_info(
        &self,
        request: &UsersInfoRequest,
    ) -> Result<SlackOutcome<SlackUser>, SlackFailure> {
        self.call(
            &SlackOperation::UsersInfo(request.clone()),
            decode_users_info,
        )
    }

    /// Post one message to a conversation.
    ///
    /// The one externally visible effect this client can produce: it puts text
    /// in front of every human in the channel. Call it only from a
    /// confirmed-action path, and treat a [`SlackFailure`] as "unknown" rather
    /// than "not sent" — a timeout can elapse after Slack accepted the message.
    /// [`PostedMessage::ts`] is what makes a retry recognizable as a duplicate.
    ///
    /// # Errors
    ///
    /// As [`SlackClient::auth_test`], for this method's contract.
    pub fn post_message(
        &self,
        request: &PostMessageRequest,
    ) -> Result<SlackOutcome<PostedMessage>, SlackFailure> {
        self.call(
            &SlackOperation::ChatPostMessage(request.clone()),
            decode_post_message,
        )
    }

    /// Replace one exact bot message, normally to retire interactive actions.
    pub fn update_message(
        &self,
        request: &UpdateMessageRequest,
    ) -> Result<SlackOutcome<()>, SlackFailure> {
        self.call(&SlackOperation::ChatUpdate(request.clone()), decode_ack)
    }

    /// Open one validated modal for a Slack interaction trigger.
    pub fn open_view(&self, request: &OpenViewRequest) -> Result<SlackOutcome<()>, SlackFailure> {
        self.call(&SlackOperation::ViewsOpen(request.clone()), decode_ack)
    }

    /// Publish one member's App Home view.
    pub fn publish_view(
        &self,
        request: &PublishViewRequest,
    ) -> Result<SlackOutcome<()>, SlackFailure> {
        self.call(&SlackOperation::ViewsPublish(request.clone()), decode_ack)
    }

    /// Issue one operation and decode its answer.
    fn call<T>(
        &self,
        operation: &SlackOperation,
        decode: impl FnOnce(&[u8]) -> Result<SlackOutcome<T>, SlackFailure>,
    ) -> Result<SlackOutcome<T>, SlackFailure> {
        let answer = self.send(operation)?;
        if (300..400).contains(&answer.status) {
            // The credential is bound to one origin; a redirect is an
            // instruction to send the next one elsewhere.
            return Err(SlackFailure::Redirected);
        }
        if answer.status == 429 {
            // The one refusal Slack reports out of band. The status is the
            // news, whatever the body is written in — historically it is not
            // always JSON — so it is classified before the content type is.
            return Ok(SlackOutcome::Rejected(SlackRejection::rate_limited(
                decode_error_code(&answer.body, RATE_LIMITED),
                answer.retry_after_seconds,
            )));
        }
        if matches!(answer.status, 401 | 403) {
            // Slack's own auth refusals arrive as `200 {"ok":false}`. A status
            // here is something in front of Slack answering instead of it.
            return Err(SlackFailure::Unauthorized);
        }
        if answer.status != 200 {
            return Err(SlackFailure::UnexpectedStatus);
        }
        if !answer.json {
            return Err(SlackFailure::UnexpectedContentType);
        }
        decode(&answer.body)
    }

    /// Issue one request and return its status, wait hint and bounded body.
    ///
    /// The credential is rendered into an `Authorization` header inside the
    /// callback and dropped when it returns; it is never stored on the request
    /// builder beyond that, never logged, and never named in a failure.
    fn send(&self, operation: &SlackOperation) -> Result<Answer, SlackFailure> {
        let url = self.endpoint(operation.method());
        let body = operation.body();
        let mut response = self
            .token
            .authorization()
            .with_header_value(|authorization| {
                self.agent
                    .post(&url)
                    .header("authorization", authorization)
                    .header("content-type", SLACK_CONTENT_TYPE)
                    .header("accept", SLACK_ACCEPT)
                    .header("user-agent", SLACK_USER_AGENT)
                    .config()
                    .timeout_global(Some(self.timeout))
                    .build()
                    .send(&body)
            })
            .map_err(map_ureq_error)?;

        let status = response.status().as_u16();
        let headers = response.headers();
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let retry_after_seconds = header("retry-after").and_then(|value| value.parse().ok());
        let json = header("content-type").is_some_and(|value| is_slack_json(&value));

        let reader = response
            .body_mut()
            .with_config()
            .limit((MAX_SLACK_RESPONSE_BYTES + 1) as u64)
            .reader();
        Ok(Answer {
            status,
            retry_after_seconds,
            json,
            body: read_bounded_body(reader)?,
        })
    }
}

/// One raw answer, before it is classified.
struct Answer {
    status: u16,
    retry_after_seconds: Option<u32>,
    json: bool,
    body: Vec<u8>,
}

/// No field of this client is safe to print except the origin, so `Debug`
/// prints that and says so about the rest.
impl fmt::Debug for SlackClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SlackClient")
            .field("origin", &self.base.origin())
            .field("authorization", &"<redacted>")
            .finish()
    }
}

/// Whether a content type is the JSON Slack answers with.
fn is_slack_json(value: &str) -> bool {
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

fn read_bounded_body(mut reader: impl Read) -> Result<Vec<u8>, SlackFailure> {
    let mut body = Vec::new();
    reader
        .read_to_end(&mut body)
        .map_err(|error| map_ureq_error(ureq::Error::from(error)))?;
    if body.len() > MAX_SLACK_RESPONSE_BYTES {
        return Err(SlackFailure::ResponseTooLarge);
    }
    Ok(body)
}

/// Map a transport error onto the closed vocabulary, borrowing nothing from it.
///
/// ureq's own error rendering can name the URL it was dialling; none of it is
/// carried across this boundary.
fn map_ureq_error(error: ureq::Error) -> SlackFailure {
    match error {
        ureq::Error::Timeout(_) => SlackFailure::TimedOut,
        ureq::Error::BodyExceedsLimit(_) => SlackFailure::ResponseTooLarge,
        _ => SlackFailure::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::{ConversationTypes, MessageText};
    use crate::target::{ChannelId, MessageTs};

    const SECRET: &str = "xoxb-0000000000-0000000000-fixture-never-print";
    const CHANNEL: &str = "C0RESERVED";

    fn client(base: &str) -> SlackClient {
        SlackClient::new(
            SlackBase::new(base).expect("base"),
            SlackToken::new(SECRET.as_bytes().to_vec()).expect("token"),
        )
    }

    fn post() -> SlackOperation {
        SlackOperation::ChatPostMessage(PostMessageRequest::new(
            ChannelId::new(CHANNEL).expect("channel"),
            MessageText::new("bonjour").expect("text"),
        ))
    }

    #[test]
    fn an_endpoint_is_the_locked_origin_plus_the_methods_own_path() {
        let client = client("https://slack.com");
        assert_eq!(
            client.endpoint(SlackMethod::ChatPostMessage),
            "https://slack.com/api/chat.postMessage"
        );
        assert_eq!(
            client.endpoint(SlackMethod::ConversationsHistory),
            "https://slack.com/api/conversations.history"
        );
        assert_eq!(client.base().origin(), "https://slack.com");
    }

    #[test]
    fn every_method_has_an_endpoint_under_the_locked_origin() {
        let client = client("https://slack.com");
        for method in [
            SlackMethod::AuthTest,
            SlackMethod::ConversationsList,
            SlackMethod::ConversationsInfo,
            SlackMethod::ConversationsHistory,
            SlackMethod::UsersInfo,
            SlackMethod::ChatPostMessage,
        ] {
            let endpoint = client.endpoint(method);
            assert!(
                endpoint.starts_with("https://slack.com/api/"),
                "{endpoint} leaves the locked origin"
            );
            assert!(!endpoint.contains(SECRET));
            assert!(!endpoint.contains('?'), "no argument reaches the URL");
        }
    }

    #[test]
    fn a_tls_base_yields_a_direct_verified_non_redirecting_agent() {
        let client = client("https://slack.com");
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
    fn only_a_loopback_base_relaxes_https_only() {
        assert!(client("https://slack.com").agent.config().https_only());
        assert!(!client("http://127.0.0.1:8080").agent.config().https_only());
    }

    #[test]
    fn the_credential_never_reaches_debug_an_endpoint_or_a_body() {
        let client = client("https://slack.com");
        let rendered = format!(
            "{client:?}|{}|{}|{:?}|{}|{:?}",
            client.endpoint(SlackMethod::ChatPostMessage),
            SlackClient::canonical_body(&post()),
            SlackFailure::Unavailable,
            SlackFailure::Unavailable,
            client.base()
        );
        assert!(!rendered.contains(SECRET), "rendered: {rendered}");
        assert!(!rendered.contains("xoxb-"), "rendered: {rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn the_request_budget_may_only_be_tightened_never_extended() {
        let ceiling = Duration::from_secs(SLACK_REQUEST_TIMEOUT_SECONDS);
        let tighten = |timeout| {
            SlackClient::with_request_timeout(
                SlackBase::production(),
                SlackToken::new(b"xoxb-fixture".to_vec()).expect("token"),
                timeout,
            )
            .request_timeout()
        };
        assert_eq!(client("https://slack.com").request_timeout(), ceiling);
        assert_eq!(tighten(Duration::from_secs(1)), Duration::from_secs(1));
        assert_eq!(tighten(Duration::from_secs(3600)), ceiling);
        assert_eq!(tighten(Duration::ZERO), ceiling);
    }

    #[test]
    fn the_response_content_type_is_closed() {
        assert!(is_slack_json("application/json"));
        assert!(is_slack_json("Application/Json; charset=UTF-8"));
        assert!(!is_slack_json("text/json"));
        assert!(!is_slack_json("application/json; profile=secret"));
        assert!(!is_slack_json("application/json; charset=latin1"));
        assert!(!is_slack_json("text/html"));
        assert!(!is_slack_json("text/plain"));
    }

    #[test]
    fn the_body_cap_accepts_the_boundary_and_refuses_one_over() {
        let at_limit = vec![b'a'; MAX_SLACK_RESPONSE_BYTES];
        assert_eq!(
            read_bounded_body(std::io::Cursor::new(&at_limit)).expect("at limit"),
            at_limit
        );
        assert_eq!(
            read_bounded_body(std::io::Cursor::new(vec![
                b'a';
                MAX_SLACK_RESPONSE_BYTES + 1
            ])),
            Err(SlackFailure::ResponseTooLarge)
        );
    }

    #[test]
    fn the_canonical_body_is_the_one_the_wire_would_carry() {
        let reply = SlackOperation::ChatPostMessage(
            PostMessageRequest::new(
                ChannelId::new(CHANNEL).expect("channel"),
                MessageText::new("suite").expect("text"),
            )
            .in_thread(MessageTs::new("1723542000.000100").expect("ts")),
        );
        assert_eq!(SlackClient::canonical_body(&reply), reply.body());
        assert_eq!(
            SlackClient::canonical_body(&SlackOperation::ConversationsList(
                ConversationsListRequest::new(ConversationTypes::all_channels(), 200)
                    .expect("list")
            )),
            "types=public_channel%2Cprivate_channel&limit=200"
        );
    }
}
