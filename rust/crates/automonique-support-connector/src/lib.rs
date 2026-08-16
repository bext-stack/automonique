// SPDX-License-Identifier: Elastic-2.0

//! Typed client for the Support backend's fleet API.
//!
//! One product surface is reachable here: the support board behind the fleet
//! endpoint `POST <base>/api/manage/shelldeck/fleet`. Eight actions are
//! spelled — one per private `WireAction` variant — and nothing else can be.
//!
//! Five work the support queue directly: read it
//! ([`FleetClient::support_issues`]), resolve a mail message to its thread
//! ([`FleetClient::resolve_thread`]), add an internal note
//! ([`FleetClient::add_thread_note`]), reply on a thread
//! ([`FleetClient::reply_thread`]), and send a support email
//! ([`FleetClient::send_email`]).
//!
//! Three drive the backend's own ticket jobs: dispatch one
//! ([`FleetClient::dispatch_ticket`]), record an administrator's terminal
//! decision on a pending gate ([`FleetClient::decide_ticket`]), and read a
//! job's status back ([`FleetClient::ticket_status`]).
//!
//! Three of the eight are reads — `support_issues`, `resolve_thread` and
//! `ticket_status`. The other five change something the backend's users can
//! see, and three of those five (`reply_thread`, `send_email`,
//! `dispatch_ticket`) are visible to a client rather than only to staff.
//!
//! # Target lock
//!
//! No caller supplies a URL, a path, or an action name. [`FleetBase`] admits an
//! origin and nothing after it; the request path is a private constant; and the
//! action string is rendered only from the private `WireAction` enum that
//! [`FleetRequest`] maps onto. A layer that is talked into asking for a
//! different action cannot spell one — there is no variant for it, and no
//! caller string ever reaches the path or the `action` field.
//!
//! # Credential
//!
//! The token rides an `Authorization: Bearer` header. It is held only in
//! [`FleetToken`], which has no `Display`, renders as `<redacted>` under
//! `Debug`, and lends its bytes only through a callback at the HTTP boundary.
//! No refusal or failure in this crate borrows caller or credential input: both
//! error vocabularies are closed C-like enums, so any of them is safe to log
//! next to the request it came from.
//!
//! # Separation of building from sending
//!
//! [`FleetRequest::canonical_body`] renders the exact wire body and the
//! `decode_*` functions parse the exact wire response, both without any socket.
//! [`FleetClient`] is only the composition of the two around one bounded HTTP
//! call, so the whole contract is provable against fixtures and against a
//! loopback fake.
//!
//! # Divergences from the legacy TypeScript client
//!
//! The contract was taken from a live JavaScript client whose normalizers are
//! *lossy*: a support issue missing a required field is silently dropped from
//! the list, absent `status`/`priority` are defaulted, and an unparseable
//! `created_at` falls back to `updated_at`. This crate refuses instead. A
//! response that does not carry every contract field is
//! [`FleetFailure::MissingField`], never a shortened list, because a connector
//! that quietly returns four of five tickets is worse than one that says the
//! response was not the contract.

mod base;
mod client;
mod request;
mod response;
mod token;

use automonique_connector_substrate::http::TransportFailure;
use automonique_connector_substrate::json::StrictJsonError;
use std::error::Error;
// The JSON string escaper is shared: every connector was carrying a
// byte-identical copy, and an escaping rule that differs between two of them is
// a defect nobody would notice until a captured request carried a raw control
// byte. Re-exported rather than imported at each call site so the crate's own
// modules keep referring to it by the name they always used.
pub(crate) use automonique_connector_substrate::json::push_json_string;

use std::fmt;

pub use base::{FleetBase, FleetInstanceId, MAX_FLEET_IDENTIFIER_BYTES};
pub use client::FleetClient;
pub use request::{
    FleetRequest, MAX_EMAIL_BODY_BYTES, MAX_EMAIL_SUBJECT_BYTES, MAX_RECIPIENT_BYTES,
    MAX_THREAD_TEXT_BYTES, MAX_TICKET_DECISION_REASON_BYTES, MAX_TICKET_ISSUE_URL_BYTES,
    MAX_TICKET_SOURCE_KEY_BYTES, SupportEmailRequest, SupportIssuesRequest, SupportReplyRequest,
    SupportThreadNoteRequest, SupportThreadResolveRequest, TicketDecision, TicketDecisionRequest,
    TicketDispatchMode, TicketDispatchRequest, TicketStatusRequest,
};
pub use response::{
    SupportDelivery, SupportIssue, SupportIssues, SupportScope, SupportThreadRef,
    TicketDecisionOutcome, TicketDecisionReceipt, TicketDispatchReceipt, TicketJobStatus,
    TicketStatus, TicketWorkspace, decode_support_delivery, decode_support_issues,
    decode_support_note, decode_support_thread, decode_ticket_decision, decode_ticket_dispatch,
    decode_ticket_status,
};
pub use token::{FleetAuthorization, FleetToken, MAX_FLEET_TOKEN_BYTES};

/// Longest fleet response body accepted, before any field is read.
///
/// A `support-issues` page is at most [`MAX_SUPPORT_ISSUES`] rows of bounded
/// strings, which fits an order of magnitude inside this; anything larger is
/// refused rather than buffered.
pub const MAX_FLEET_RESPONSE_BYTES: usize = 256 * 1024;

/// Largest `support-issues` page the API is asked for, and the most rows a
/// response may carry. Both directions share the bound so a server answering
/// with more rows than were requested is refused.
pub const MAX_SUPPORT_ISSUES: usize = 50;

/// Longest bounded server-supplied message retained from a refusal.
pub const MAX_SERVER_MESSAGE_BYTES: usize = 180;

/// Whole-request budget for one fleet call.
///
/// The fleet endpoint never long-polls on these five actions, so a single
/// bounded budget covers connect, TLS, request and response. It matches the
/// legacy client's own 15-second abort.
pub const FLEET_REQUEST_TIMEOUT_SECONDS: u64 = 15;

/// Closed refusals raised while *building* a request, before any I/O.
///
/// Each names the field that was wrong and never its value, so a refusal may be
/// logged beside the operator content it was built from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FleetRefusal {
    /// The base is not an origin this connector may address.
    Base,
    /// The token is empty, over-long, or outside the bearer-credential
    /// character set.
    Token,
    /// The instance id is empty, over-long, or not an opaque identifier.
    InstanceId,
    /// The requested page size is zero or over [`MAX_SUPPORT_ISSUES`].
    Limit,
    /// The mail message id is outside the fleet's hexadecimal grammar.
    MessageId,
    /// The thread id is outside the fleet's hexadecimal grammar.
    ThreadId,
    /// The confirmed-action id is empty, over-long, or not an opaque
    /// identifier.
    ActionId,
    /// Body text is empty, over its ceiling, or carries a control character
    /// other than tab and newline.
    Text,
    /// The recipient is not a single bounded addr-spec.
    Recipient,
    /// The subject is empty, over its ceiling, or control-bearing.
    Subject,
    /// The value was not one canonical github.com issue URL.
    IssueUrl,
    /// The stable transport key was absent or outside its closed grammar.
    SourceKey,
    /// The exact fleet job id was outside the opaque-id grammar.
    JobId,
    /// The stable idempotency key for a ticket decision was invalid.
    DecisionKey,
    /// The administrator identity key for a ticket decision was invalid.
    ActorKey,
    /// A rejection reason was absent or outside its text bound.
    DecisionReason,
}

impl FleetRefusal {
    /// Stable, content-free category for logging and metrics.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Token => "token",
            Self::InstanceId => "instance_id",
            Self::Limit => "limit",
            Self::MessageId => "message_id",
            Self::ThreadId => "thread_id",
            Self::ActionId => "action_id",
            Self::Text => "text",
            Self::Recipient => "recipient",
            Self::Subject => "subject",
            Self::IssueUrl => "issue_url",
            Self::SourceKey => "source_key",
            Self::JobId => "job_id",
            Self::DecisionKey => "decision_key",
            Self::ActorKey => "actor_key",
            Self::DecisionReason => "decision_reason",
        }
    }
}

impl fmt::Display for FleetRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "support fleet request refused: {}",
            self.category()
        )
    }
}

impl Error for FleetRefusal {}

/// Closed failures from issuing a call or reading its response.
///
/// Like [`FleetRefusal`], no variant borrows input; a failure never carries a
/// credential, a recipient, or a ticket body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FleetFailure {
    /// DNS, connect, TLS, or an unclassified transport error.
    Unavailable,
    /// The bounded request budget elapsed.
    TimedOut,
    /// The fleet answered with a status other than 200.
    UnexpectedStatus,
    /// The fleet rejected the credential (401) or the scope (403).
    ///
    /// Named apart from every other status because a revoked fleet token is the
    /// failure mode that otherwise reads as a quiet outage.
    Unauthorized,
    /// The response was not `application/json`.
    UnexpectedContentType,
    /// The response body exceeded [`MAX_FLEET_RESPONSE_BYTES`].
    ResponseTooLarge,
    /// The body was not strict JSON, or not the envelope shape for the action.
    InvalidResponse,
    /// A field the action's contract names was absent.
    MissingField,
    /// A field was present but outside its documented bound or grammar.
    FieldOutOfBounds,
    /// The page carried more rows than [`MAX_SUPPORT_ISSUES`].
    TooManyIssues,
}

impl FleetFailure {
    /// Stable, content-free category for logging and metrics.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::TimedOut => "timed_out",
            Self::UnexpectedStatus => "unexpected_status",
            Self::Unauthorized => "unauthorized",
            Self::UnexpectedContentType => "unexpected_content_type",
            Self::ResponseTooLarge => "response_too_large",
            Self::InvalidResponse => "invalid_response",
            Self::MissingField => "missing_field",
            Self::FieldOutOfBounds => "field_out_of_bounds",
            Self::TooManyIssues => "too_many_issues",
        }
    }
}

impl fmt::Display for FleetFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "support fleet call failed: {}", self.category())
    }
}

impl Error for FleetFailure {}

/// A response that is not strictly valid JSON is one refusal, not a taxonomy.
///
/// The distinction that matters to a caller is that the response cannot be
/// trusted; which byte offended is a detail that would only reach a log line as
/// a fragment of a response body.
impl From<StrictJsonError> for FleetFailure {
    fn from(_: StrictJsonError) -> Self {
        Self::InvalidResponse
    }
}

impl From<TransportFailure> for FleetFailure {
    fn from(failure: TransportFailure) -> Self {
        match failure {
            TransportFailure::TimedOut => Self::TimedOut,
            TransportFailure::ResponseTooLarge => Self::ResponseTooLarge,
            TransportFailure::Unavailable => Self::Unavailable,
        }
    }
}

/// A bounded, control-free message the fleet supplied with a refusal.
///
/// Remote text, so it is bounded at [`MAX_SERVER_MESSAGE_BYTES`] and stripped
/// of control characters on the way in — an operator reading it in a terminal
/// cannot be driven by it. It is not a credential and is therefore rendered by
/// `Debug`, which is the whole point of retaining it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerMessage(String);

impl ServerMessage {
    /// Sanitize one remote message into the retained form.
    ///
    /// Control characters are replaced by a space rather than dropped so two
    /// distinct messages cannot collapse onto one, and the result is truncated
    /// on a character boundary.
    #[must_use]
    pub fn sanitized(value: &str) -> Self {
        let mut text = String::new();
        for character in value.chars() {
            let rendered = if character.is_control() {
                ' '
            } else {
                character
            };
            if text.len() + rendered.len_utf8() > MAX_SERVER_MESSAGE_BYTES {
                break;
            }
            text.push(rendered);
        }
        Self(text.trim().to_owned())
    }

    /// The sanitized text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ServerMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A well-formed fleet answer: either the action's payload, or the fleet's own
/// bounded refusal.
///
/// A refusal reported by the fleet is a *parsed* response, not a failure of
/// this connector, which is why it is an `Ok` outcome rather than a
/// [`FleetFailure`]. Only a response that is not the contract is an error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FleetOutcome<T> {
    /// The fleet accepted the action and returned its payload.
    Accepted(T),
    /// The fleet answered `ok: false` with a bounded reason.
    Rejected(ServerMessage),
}

impl<T> FleetOutcome<T> {
    /// The payload, if the fleet accepted the action.
    #[must_use]
    pub const fn accepted(&self) -> Option<&T> {
        match self {
            Self::Accepted(payload) => Some(payload),
            Self::Rejected(_) => None,
        }
    }

    /// The bounded reason, if the fleet refused the action.
    #[must_use]
    pub const fn rejected(&self) -> Option<&ServerMessage> {
        match self {
            Self::Accepted(_) => None,
            Self::Rejected(message) => Some(message),
        }
    }
}

/// Whether text may be carried in a fleet request body.
///
/// Tab and newline are admitted because support replies are multi-line; every
/// other control character is refused rather than escaped, so neither a
/// terminal nor a downstream mail body can be driven by connector input.
pub(crate) fn is_body_text(text: &str, max_bytes: usize) -> bool {
    !text.is_empty()
        && text.len() <= max_bytes
        && !text
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_and_failure_categories_are_distinct_and_content_free() {
        let refusals = [
            FleetRefusal::Base,
            FleetRefusal::Token,
            FleetRefusal::InstanceId,
            FleetRefusal::Limit,
            FleetRefusal::MessageId,
            FleetRefusal::ThreadId,
            FleetRefusal::ActionId,
            FleetRefusal::Text,
            FleetRefusal::Recipient,
            FleetRefusal::Subject,
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
            FleetFailure::Unavailable,
            FleetFailure::TimedOut,
            FleetFailure::UnexpectedStatus,
            FleetFailure::Unauthorized,
            FleetFailure::UnexpectedContentType,
            FleetFailure::ResponseTooLarge,
            FleetFailure::InvalidResponse,
            FleetFailure::MissingField,
            FleetFailure::FieldOutOfBounds,
            FleetFailure::TooManyIssues,
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
    fn a_server_message_is_bounded_and_stripped_of_control_bytes() {
        let message = ServerMessage::sanitized("Support\u{1b}[2J indisponible\n");
        assert_eq!(message.as_str(), "Support [2J indisponible");
        let long = ServerMessage::sanitized(&"e\u{301}".repeat(MAX_SERVER_MESSAGE_BYTES));
        assert!(long.as_str().len() <= MAX_SERVER_MESSAGE_BYTES);
        // Truncation lands on a character boundary rather than splitting one.
        assert!(long.as_str().chars().all(|c| c == 'e' || c == '\u{301}'));
    }

    #[test]
    fn body_text_admits_multi_line_support_replies_and_refuses_control_bytes() {
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
        let accepted: FleetOutcome<u8> = FleetOutcome::Accepted(7);
        assert_eq!(accepted.accepted(), Some(&7));
        assert!(accepted.rejected().is_none());
        let rejected: FleetOutcome<u8> = FleetOutcome::Rejected(ServerMessage::sanitized("non"));
        assert!(rejected.accepted().is_none());
        assert_eq!(rejected.rejected().map(ServerMessage::as_str), Some("non"));
    }
}
