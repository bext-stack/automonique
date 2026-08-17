// SPDX-License-Identifier: Elastic-2.0

//! The five support actions, and the exact envelope each renders.
//!
//! Every fleet call is one JSON object: an `action` naming the operation, the
//! `id` of this instance, and the action's own fields. The `action` string is
//! rendered only from [`WireAction`], which is private — that enum *is* the
//! target lock's second half, the first being the origin in `base`.
//!
//! Field order is fixed and documented per action, matching the legacy client's
//! `{ action, id, ... }` spread. JSON objects are unordered by specification,
//! so this is a testability property rather than a protocol one: it lets a test
//! assert one exact captured body instead of a set of permutations.

use crate::base::{FleetInstanceId, is_opaque_identifier};
use crate::{FleetRefusal, MAX_SUPPORT_ISSUES, is_body_text, push_json_string};

/// Longest note or reply body accepted.
///
/// The legacy client bounds a *note* at this value and leaves a *reply*
/// unbounded; both are bounded here, because an unbounded reply is an
/// unbounded outbound email.
pub const MAX_THREAD_TEXT_BYTES: usize = 8_000;
/// Longest support email subject accepted.
pub const MAX_EMAIL_SUBJECT_BYTES: usize = 512;
/// Longest support email body accepted.
pub const MAX_EMAIL_BODY_BYTES: usize = 64 * 1024;
/// Longest recipient address accepted, per RFC 5321's path limit.
pub const MAX_RECIPIENT_BYTES: usize = 254;
/// Longest stable transport key retained for one ticket action.
pub const MAX_TICKET_SOURCE_KEY_BYTES: usize = 180;
/// Longest canonical GitHub issue URL accepted.
pub const MAX_TICKET_ISSUE_URL_BYTES: usize = 240;
/// Longest human reason accepted for rejecting a pending ticket.
pub const MAX_TICKET_DECISION_REASON_BYTES: usize = 500;

/// The complete set of `action` strings this connector can render.
///
/// Private on purpose: it is the target lock. A layer talked into asking for
/// `job`, `claim`, `heartbeat`, or anything else on the same endpoint cannot
/// spell it, because no variant exists and no caller string reaches this field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WireAction {
    Issues,
    ThreadResolve,
    ThreadNote,
    ThreadReply,
    Email,
    TicketDispatch,
    TicketDecision,
    TicketStatus,
}

impl WireAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Issues => "support-issues",
            Self::ThreadResolve => "support-thread-resolve",
            Self::ThreadNote => "support-thread-note",
            Self::ThreadReply => "support-thread-reply",
            Self::Email => "support-email",
            Self::TicketDispatch => "automonique-ticket-dispatch",
            Self::TicketDecision => "automonique-ticket-decision",
            Self::TicketStatus => "automonique-ticket-status",
        }
    }
}

/// The administrator's terminal decision for one pending ticket gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TicketDecision {
    /// Release the already-created job for execution.
    Approve,
    /// Cancel the pending job without ever releasing work.
    Reject { reason: String },
}

impl TicketDecision {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject { .. } => "reject",
        }
    }

    /// Build a rejection with a required, bounded, display-safe reason.
    pub fn reject(reason: &str) -> Result<Self, FleetRefusal> {
        let reason = reason.trim();
        if !is_body_text(reason, MAX_TICKET_DECISION_REASON_BYTES) {
            return Err(FleetRefusal::DecisionReason);
        }
        Ok(Self::Reject {
            reason: reason.to_owned(),
        })
    }

    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Approve => None,
            Self::Reject { reason } => Some(reason),
        }
    }
}

/// Apply one idempotent administrator decision to one exact pending job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketDecisionRequest {
    job_id: String,
    source_key: String,
    decision_key: String,
    actor_key: String,
    decision: TicketDecision,
}

impl TicketDecisionRequest {
    pub fn new(
        job_id: &str,
        source_key: &str,
        decision_key: &str,
        actor_key: &str,
        decision: TicketDecision,
    ) -> Result<Self, FleetRefusal> {
        if !is_opaque_identifier(job_id) {
            return Err(FleetRefusal::JobId);
        }
        if !is_ticket_key(source_key, MAX_TICKET_SOURCE_KEY_BYTES) {
            return Err(FleetRefusal::SourceKey);
        }
        if !is_ticket_key(decision_key, MAX_TICKET_SOURCE_KEY_BYTES) {
            return Err(FleetRefusal::DecisionKey);
        }
        if !is_ticket_key(actor_key, MAX_TICKET_SOURCE_KEY_BYTES) {
            return Err(FleetRefusal::ActorKey);
        }
        Ok(Self {
            job_id: job_id.to_owned(),
            source_key: source_key.to_owned(),
            decision_key: decision_key.to_owned(),
            actor_key: actor_key.to_owned(),
            decision,
        })
    }

    #[must_use]
    pub fn job_id(&self) -> &str {
        &self.job_id
    }
    #[must_use]
    pub fn source_key(&self) -> &str {
        &self.source_key
    }
    #[must_use]
    pub fn decision_key(&self) -> &str {
        &self.decision_key
    }
    #[must_use]
    pub fn actor_key(&self) -> &str {
        &self.actor_key
    }
    #[must_use]
    pub const fn decision(&self) -> &TicketDecision {
        &self.decision
    }
}

/// Whether one ticket dispatch opens a gate or consumes an administrator's
/// confirmation of that exact gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TicketDispatchMode {
    /// Create or recover the pending confirmation request. This never releases
    /// work to the backend's job runner.
    RequestApproval,
    /// Release the exact request after an eligible administrator confirmed it.
    Confirmed,
}

impl TicketDispatchMode {
    const fn confirmed(self) -> bool {
        matches!(self, Self::Confirmed)
    }
}

/// Dispatch one exact GitHub issue through Manage's durable approval gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketDispatchRequest {
    issue_url: String,
    source_key: String,
    mode: TicketDispatchMode,
}

impl TicketDispatchRequest {
    /// Bind a canonical GitHub issue URL to one durable transport source key
    /// and request administrator confirmation.
    ///
    /// The wire shape carries `confirmed:false`. Replaying it recovers the same
    /// pending Manage job; it never upgrades itself into permission to work.
    pub fn new(issue_url: &str, source_key: &str) -> Result<Self, FleetRefusal> {
        Self::with_mode(issue_url, source_key, TicketDispatchMode::RequestApproval)
    }

    /// Bind an eligible administrator's confirmation to the exact issue and
    /// source key that created the pending gate.
    ///
    /// Callers must obtain both coordinates from trusted pending-gate state;
    /// user text alone must never select this constructor.
    pub fn confirmed(issue_url: &str, source_key: &str) -> Result<Self, FleetRefusal> {
        Self::with_mode(issue_url, source_key, TicketDispatchMode::Confirmed)
    }

    fn with_mode(
        issue_url: &str,
        source_key: &str,
        mode: TicketDispatchMode,
    ) -> Result<Self, FleetRefusal> {
        if !is_github_issue_url(issue_url) {
            return Err(FleetRefusal::IssueUrl);
        }
        if !is_ticket_key(source_key, MAX_TICKET_SOURCE_KEY_BYTES) {
            return Err(FleetRefusal::SourceKey);
        }
        Ok(Self {
            issue_url: issue_url.to_owned(),
            source_key: source_key.to_owned(),
            mode,
        })
    }

    #[must_use]
    pub fn issue_url(&self) -> &str {
        &self.issue_url
    }

    #[must_use]
    pub fn source_key(&self) -> &str {
        &self.source_key
    }

    /// Whether this request carries a separately established confirmation.
    #[must_use]
    pub const fn mode(&self) -> TicketDispatchMode {
        self.mode
    }
}

/// Read one exact job created by this connector's configured fleet instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketStatusRequest {
    job_id: String,
}

impl TicketStatusRequest {
    pub fn new(job_id: &str) -> Result<Self, FleetRefusal> {
        if !is_opaque_identifier(job_id) {
            return Err(FleetRefusal::JobId);
        }
        Ok(Self {
            job_id: job_id.to_owned(),
        })
    }

    #[must_use]
    pub fn job_id(&self) -> &str {
        &self.job_id
    }
}

/// Read the support board, bounded to one page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportIssuesRequest {
    limit: usize,
}

impl SupportIssuesRequest {
    /// Ask for at most `limit` issues.
    ///
    /// # Errors
    ///
    /// Returns [`FleetRefusal::Limit`] for zero or more than
    /// [`MAX_SUPPORT_ISSUES`]. The legacy client silently clamps instead; a
    /// clamp hides a caller that believed it was paging.
    pub fn new(limit: usize) -> Result<Self, FleetRefusal> {
        if limit == 0 || limit > MAX_SUPPORT_ISSUES {
            return Err(FleetRefusal::Limit);
        }
        Ok(Self { limit })
    }

    /// The requested page size.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }
}

/// Resolve one inbound mail message to the support thread carrying it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportThreadResolveRequest {
    message_id: String,
}

impl SupportThreadResolveRequest {
    /// Name the mail message to resolve.
    ///
    /// # Errors
    ///
    /// Returns [`FleetRefusal::MessageId`] unless the value is 20 to 120
    /// hexadecimal characters and hyphens, the grammar the legacy client
    /// enforces before it will spend a call.
    pub fn new(message_id: &str) -> Result<Self, FleetRefusal> {
        if !is_message_id(message_id) {
            return Err(FleetRefusal::MessageId);
        }
        Ok(Self {
            message_id: message_id.to_owned(),
        })
    }

    /// The validated mail message id.
    #[must_use]
    pub fn message_id(&self) -> &str {
        &self.message_id
    }
}

/// Add an internal, operator-only note to a support thread.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportThreadNoteRequest {
    thread_id: String,
    text: String,
}

impl SupportThreadNoteRequest {
    /// Bind one note to one thread.
    ///
    /// Surrounding whitespace is trimmed, matching the legacy client. The
    /// length bound is then applied to the trimmed text and a body over it is
    /// refused rather than truncated, so a note is never a silently shortened
    /// version of what the operator wrote.
    ///
    /// # Errors
    ///
    /// Returns [`FleetRefusal::ThreadId`] for a thread id outside the 12-to-80
    /// hexadecimal grammar, and [`FleetRefusal::Text`] for text that is empty
    /// after trimming, over [`MAX_THREAD_TEXT_BYTES`], or control-bearing.
    pub fn new(thread_id: &str, text: &str) -> Result<Self, FleetRefusal> {
        if !is_thread_id(thread_id) {
            return Err(FleetRefusal::ThreadId);
        }
        let text = text.trim();
        if !is_body_text(text, MAX_THREAD_TEXT_BYTES) {
            return Err(FleetRefusal::Text);
        }
        Ok(Self {
            thread_id: thread_id.to_owned(),
            text: text.to_owned(),
        })
    }

    /// The validated thread id.
    #[must_use]
    pub fn thread_id(&self) -> &str {
        &self.thread_id
    }

    /// The validated, trimmed note text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// Reply to the requester on a support thread. Externally visible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportReplyRequest {
    action_id: String,
    thread_id: String,
    text: String,
}

impl SupportReplyRequest {
    /// Bind one confirmed action to one thread and one reply body.
    ///
    /// # Errors
    ///
    /// Returns [`FleetRefusal::ActionId`], [`FleetRefusal::ThreadId`], or
    /// [`FleetRefusal::Text`] naming the field that was outside its bound.
    pub fn new(action_id: &str, thread_id: &str, text: &str) -> Result<Self, FleetRefusal> {
        if !is_opaque_identifier(action_id) {
            return Err(FleetRefusal::ActionId);
        }
        if !is_thread_id(thread_id) {
            return Err(FleetRefusal::ThreadId);
        }
        let text = text.trim();
        if !is_body_text(text, MAX_THREAD_TEXT_BYTES) {
            return Err(FleetRefusal::Text);
        }
        Ok(Self {
            action_id: action_id.to_owned(),
            thread_id: thread_id.to_owned(),
            text: text.to_owned(),
        })
    }

    /// The confirmed-action id this reply is attributed to.
    #[must_use]
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    /// The validated thread id.
    #[must_use]
    pub fn thread_id(&self) -> &str {
        &self.thread_id
    }

    /// The validated, trimmed reply text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// Send one support email. A privileged external effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportEmailRequest {
    action_id: String,
    to: String,
    subject: String,
    text: String,
}

impl SupportEmailRequest {
    /// Bind one confirmed action to one recipient, subject and body.
    ///
    /// The legacy client validates none of these before spending the call and
    /// leaves every check to the server. They are validated here because this
    /// is the connector for an *outbound* effect: a malformed recipient that
    /// reaches the fleet is an email attempt nobody can recall.
    ///
    /// # Errors
    ///
    /// Returns [`FleetRefusal::ActionId`], [`FleetRefusal::Recipient`],
    /// [`FleetRefusal::Subject`], or [`FleetRefusal::Text`] naming the field
    /// that was outside its bound.
    pub fn new(action_id: &str, to: &str, subject: &str, text: &str) -> Result<Self, FleetRefusal> {
        if !is_opaque_identifier(action_id) {
            return Err(FleetRefusal::ActionId);
        }
        if !is_recipient(to) {
            return Err(FleetRefusal::Recipient);
        }
        let subject = subject.trim();
        if subject.is_empty()
            || subject.len() > MAX_EMAIL_SUBJECT_BYTES
            || subject.chars().any(char::is_control)
        {
            return Err(FleetRefusal::Subject);
        }
        let text = text.trim();
        if !is_body_text(text, MAX_EMAIL_BODY_BYTES) {
            return Err(FleetRefusal::Text);
        }
        Ok(Self {
            action_id: action_id.to_owned(),
            to: to.to_owned(),
            subject: subject.to_owned(),
            text: text.to_owned(),
        })
    }

    /// The confirmed-action id this send is attributed to.
    #[must_use]
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    /// The validated recipient.
    #[must_use]
    pub fn to(&self) -> &str {
        &self.to
    }

    /// The validated subject.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The validated body.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// One validated support action, ready to be rendered onto the wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FleetRequest {
    /// Read the support board.
    SupportIssues(SupportIssuesRequest),
    /// Resolve a mail message to its thread.
    SupportThreadResolve(SupportThreadResolveRequest),
    /// Add an internal note.
    SupportThreadNote(SupportThreadNoteRequest),
    /// Reply on a thread.
    SupportThreadReply(SupportReplyRequest),
    /// Send a support email.
    SupportEmail(SupportEmailRequest),
    /// Dispatch one exact, confirmed GitHub ticket.
    TicketDispatch(TicketDispatchRequest),
    /// Approve or reject one exact pending ticket gate.
    TicketDecision(TicketDecisionRequest),
    /// Read the resulting exact job.
    TicketStatus(TicketStatusRequest),
}

impl FleetRequest {
    const fn wire_action(&self) -> WireAction {
        match self {
            Self::SupportIssues(_) => WireAction::Issues,
            Self::SupportThreadResolve(_) => WireAction::ThreadResolve,
            Self::SupportThreadNote(_) => WireAction::ThreadNote,
            Self::SupportThreadReply(_) => WireAction::ThreadReply,
            Self::SupportEmail(_) => WireAction::Email,
            Self::TicketDispatch(_) => WireAction::TicketDispatch,
            Self::TicketDecision(_) => WireAction::TicketDecision,
            Self::TicketStatus(_) => WireAction::TicketStatus,
        }
    }

    /// The exact `action` string this request renders. Carries no credential.
    #[must_use]
    pub const fn action_name(&self) -> &'static str {
        self.wire_action().as_str()
    }

    /// Whether this action performs an externally visible effect.
    ///
    /// A reply and an email leave the organization; a board read and an
    /// internal note do not. An approval layer keys on this rather than
    /// re-deriving it from the action name.
    #[must_use]
    pub const fn is_external_effect(&self) -> bool {
        matches!(
            self,
            Self::SupportThreadReply(_)
                | Self::SupportEmail(_)
                | Self::TicketDispatch(_)
                | Self::TicketDecision(_)
        )
    }

    /// The exact JSON body that will be sent, in the documented field order.
    ///
    /// Credential-free by construction, so a host may log or fixture it. Every
    /// string is escaped here; nothing is interpolated raw.
    #[must_use]
    pub fn canonical_body(&self, instance: &FleetInstanceId) -> String {
        let mut body = String::new();
        body.push_str("{\"action\":");
        push_json_string(&mut body, self.action_name());
        body.push_str(",\"id\":");
        push_json_string(&mut body, instance.as_str());
        match self {
            Self::SupportIssues(request) => {
                body.push_str(",\"limit\":");
                body.push_str(&request.limit.to_string());
            }
            Self::SupportThreadResolve(request) => {
                body.push_str(",\"message_id\":");
                push_json_string(&mut body, &request.message_id);
            }
            Self::SupportThreadNote(request) => {
                body.push_str(",\"thread_id\":");
                push_json_string(&mut body, &request.thread_id);
                body.push_str(",\"text\":");
                push_json_string(&mut body, &request.text);
            }
            Self::SupportThreadReply(request) => {
                body.push_str(",\"action_id\":");
                push_json_string(&mut body, &request.action_id);
                body.push_str(",\"thread_id\":");
                push_json_string(&mut body, &request.thread_id);
                body.push_str(",\"text\":");
                push_json_string(&mut body, &request.text);
            }
            Self::SupportEmail(request) => {
                body.push_str(",\"action_id\":");
                push_json_string(&mut body, &request.action_id);
                body.push_str(",\"to\":");
                push_json_string(&mut body, &request.to);
                body.push_str(",\"subject\":");
                push_json_string(&mut body, &request.subject);
                body.push_str(",\"text\":");
                push_json_string(&mut body, &request.text);
            }
            Self::TicketDispatch(request) => {
                body.push_str(",\"issue_url\":");
                push_json_string(&mut body, &request.issue_url);
                body.push_str(",\"source_key\":");
                push_json_string(&mut body, &request.source_key);
                body.push_str(",\"confirmed\":");
                body.push_str(if request.mode.confirmed() {
                    "true"
                } else {
                    "false"
                });
            }
            Self::TicketDecision(request) => {
                body.push_str(",\"job_id\":");
                push_json_string(&mut body, &request.job_id);
                body.push_str(",\"source_key\":");
                push_json_string(&mut body, &request.source_key);
                body.push_str(",\"decision_key\":");
                push_json_string(&mut body, &request.decision_key);
                body.push_str(",\"actor_key\":");
                push_json_string(&mut body, &request.actor_key);
                body.push_str(",\"decision\":");
                push_json_string(&mut body, request.decision.as_str());
                if let Some(reason) = request.decision.reason() {
                    body.push_str(",\"reason\":");
                    push_json_string(&mut body, reason);
                }
            }
            Self::TicketStatus(request) => {
                body.push_str(",\"job_id\":");
                push_json_string(&mut body, &request.job_id);
            }
        }
        body.push('}');
        body
    }
}

pub(crate) fn is_ticket_key(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'_' | b'-'))
}

pub(crate) fn is_github_issue_url(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_TICKET_ISSUE_URL_BYTES || !value.is_ascii() {
        return false;
    }
    let Some(rest) = value.strip_prefix("https://github.com/") else {
        return false;
    };
    let mut parts = rest.split('/');
    let (Some(owner), Some(repo), Some(kind), Some(number), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return false;
    };
    !owner.is_empty()
        && !repo.is_empty()
        && kind == "issues"
        && number.parse::<u32>().is_ok_and(|value| value > 0)
        && owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && repo
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// The fleet's mail message grammar: 20 to 120 hexadecimal characters and
/// hyphens, either case.
fn is_message_id(value: &str) -> bool {
    (20..=120).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

/// The fleet's thread grammar: 12 to 80 hexadecimal characters, either case.
fn is_thread_id(value: &str) -> bool {
    (12..=80).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Whether a recipient is a single bounded addr-spec.
///
/// Deliberately conservative: one `@`, a non-empty local part, a dotted domain,
/// no whitespace and no control bytes. The fleet and its mailer do the
/// authoritative check; this one exists so an obviously wrong recipient costs
/// nothing and so no bare newline can reach a mail header downstream.
fn is_recipient(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_RECIPIENT_BYTES || !value.is_ascii() {
        return false;
    }
    if value.bytes().any(|byte| !byte.is_ascii_graphic()) {
        return false;
    }
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    if local.is_empty() || domain.contains('@') {
        return false;
    }
    !domain.is_empty()
        && domain.len() <= 253
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE_ID: &str = "a1b2c3d4-e5f6-7890-abcd-ef0123456789";
    const THREAD_ID: &str = "0123456789abcdef";

    fn instance() -> FleetInstanceId {
        FleetInstanceId::new("sd-instance-01").expect("instance")
    }

    #[test]
    fn the_action_vocabulary_is_exactly_the_support_and_ticket_actions() {
        assert_eq!(WireAction::Issues.as_str(), "support-issues");
        assert_eq!(WireAction::ThreadResolve.as_str(), "support-thread-resolve");
        assert_eq!(WireAction::ThreadNote.as_str(), "support-thread-note");
        assert_eq!(WireAction::ThreadReply.as_str(), "support-thread-reply");
        assert_eq!(WireAction::Email.as_str(), "support-email");
        assert_eq!(
            WireAction::TicketDispatch.as_str(),
            "automonique-ticket-dispatch"
        );
        assert_eq!(
            WireAction::TicketDecision.as_str(),
            "automonique-ticket-decision"
        );
        assert_eq!(
            WireAction::TicketStatus.as_str(),
            "automonique-ticket-status"
        );
    }

    #[test]
    fn every_envelope_is_exact_and_credential_free() {
        let instance = instance();

        let issues = FleetRequest::SupportIssues(SupportIssuesRequest::new(10).expect("limit"));
        assert_eq!(
            issues.canonical_body(&instance),
            r#"{"action":"support-issues","id":"sd-instance-01","limit":10}"#
        );

        let resolve = FleetRequest::SupportThreadResolve(
            SupportThreadResolveRequest::new(MESSAGE_ID).expect("resolve"),
        );
        assert_eq!(
            resolve.canonical_body(&instance),
            format!(
                r#"{{"action":"support-thread-resolve","id":"sd-instance-01","message_id":"{MESSAGE_ID}"}}"#
            )
        );

        let note = FleetRequest::SupportThreadNote(
            SupportThreadNoteRequest::new(THREAD_ID, "  vu avec l'equipe  ").expect("note"),
        );
        assert_eq!(
            note.canonical_body(&instance),
            format!(
                r#"{{"action":"support-thread-note","id":"sd-instance-01","thread_id":"{THREAD_ID}","text":"vu avec l'equipe"}}"#
            )
        );

        let reply = FleetRequest::SupportThreadReply(
            SupportReplyRequest::new("legacy-email:abc", THREAD_ID, "bonjour").expect("reply"),
        );
        assert_eq!(
            reply.canonical_body(&instance),
            format!(
                r#"{{"action":"support-thread-reply","id":"sd-instance-01","action_id":"legacy-email:abc","thread_id":"{THREAD_ID}","text":"bonjour"}}"#
            )
        );

        let email = FleetRequest::SupportEmail(
            SupportEmailRequest::new(
                "act-1",
                "client@exemple.invalid",
                "Votre demande",
                "Bonjour,\nc'est regle.",
            )
            .expect("email"),
        );
        assert_eq!(
            email.canonical_body(&instance),
            "{\"action\":\"support-email\",\"id\":\"sd-instance-01\",\"action_id\":\"act-1\",\
             \"to\":\"client@exemple.invalid\",\"subject\":\"Votre demande\",\
             \"text\":\"Bonjour,\\nc'est regle.\"}"
        );

        let ticket = FleetRequest::TicketDispatch(
            TicketDispatchRequest::new(
                "https://github.com/example/repo/issues/1007",
                "telegram:8784297904:update:123",
            )
            .expect("ticket"),
        );
        assert_eq!(
            ticket.canonical_body(&instance),
            "{\"action\":\"automonique-ticket-dispatch\",\"id\":\"sd-instance-01\",\
             \"issue_url\":\"https://github.com/example/repo/issues/1007\",\
             \"source_key\":\"telegram:8784297904:update:123\",\"confirmed\":false}"
        );
        let confirmed = FleetRequest::TicketDispatch(
            TicketDispatchRequest::confirmed(
                "https://github.com/example/repo/issues/1007",
                "telegram:8784297904:update:123",
            )
            .expect("confirmed ticket"),
        );
        assert_eq!(
            confirmed.canonical_body(&instance),
            "{\"action\":\"automonique-ticket-dispatch\",\"id\":\"sd-instance-01\",\
             \"issue_url\":\"https://github.com/example/repo/issues/1007\",\
             \"source_key\":\"telegram:8784297904:update:123\",\"confirmed\":true}"
        );
        let rejected = FleetRequest::TicketDecision(
            TicketDecisionRequest::new(
                "job-123",
                "slack:A1:T1:C1:123.456",
                "slack-decision:A1:T1:C1:123.456:reject:U1",
                "slack:U1",
                TicketDecision::reject("Not authorized for this release").expect("reason"),
            )
            .expect("decision"),
        );
        assert_eq!(
            rejected.canonical_body(&instance),
            "{\"action\":\"automonique-ticket-decision\",\"id\":\"sd-instance-01\",\
             \"job_id\":\"job-123\",\"source_key\":\"slack:A1:T1:C1:123.456\",\
             \"decision_key\":\"slack-decision:A1:T1:C1:123.456:reject:U1\",\
             \"actor_key\":\"slack:U1\",\"decision\":\"reject\",\
             \"reason\":\"Not authorized for this release\"}"
        );
        let status =
            FleetRequest::TicketStatus(TicketStatusRequest::new("job-123").expect("status"));
        assert_eq!(
            status.canonical_body(&instance),
            r#"{"action":"automonique-ticket-status","id":"sd-instance-01","job_id":"job-123"}"#
        );
    }

    #[test]
    fn hostile_content_is_escaped_rather_than_interpolated() {
        let note = FleetRequest::SupportThreadNote(
            SupportThreadNoteRequest::new(THREAD_ID, "quote\" slash\\ end\"}").expect("note"),
        );
        let body = note.canonical_body(&instance());
        assert!(
            body.ends_with("\"quote\\\" slash\\\\ end\\\"}\"}"),
            "{body}"
        );
        // The escaped body is still one JSON object with the intended action.
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["action"], "support-thread-note");
        assert_eq!(parsed["text"], "quote\" slash\\ end\"}");
    }

    #[test]
    fn external_effects_are_marked_apart_from_reads() {
        let read = FleetRequest::SupportIssues(SupportIssuesRequest::new(1).expect("limit"));
        let note = FleetRequest::SupportThreadNote(
            SupportThreadNoteRequest::new(THREAD_ID, "note").expect("note"),
        );
        let reply = FleetRequest::SupportThreadReply(
            SupportReplyRequest::new("a", THREAD_ID, "texte").expect("reply"),
        );
        let email = FleetRequest::SupportEmail(
            SupportEmailRequest::new("a", "c@exemple.invalid", "sujet", "texte").expect("email"),
        );
        let ticket = FleetRequest::TicketDispatch(
            TicketDispatchRequest::new(
                "https://github.com/example/repo/issues/1007",
                "telegram:bot:update:1",
            )
            .expect("ticket"),
        );
        let status =
            FleetRequest::TicketStatus(TicketStatusRequest::new("job-123").expect("status"));
        assert!(!read.is_external_effect());
        assert!(!note.is_external_effect());
        assert!(reply.is_external_effect());
        assert!(email.is_external_effect());
        assert!(ticket.is_external_effect());
        assert!(!status.is_external_effect());
    }

    #[test]
    fn ticket_dispatch_accepts_only_canonical_urls_and_stable_keys() {
        let url = "https://github.com/example/repo/issues/1007";
        let request = TicketDispatchRequest::new(url, "telegram:bot:update:1").expect("request");
        assert_eq!(request.issue_url(), url);
        assert_eq!(request.source_key(), "telegram:bot:update:1");
        assert_eq!(request.mode(), TicketDispatchMode::RequestApproval);
        assert_eq!(
            TicketDispatchRequest::confirmed(url, "telegram:bot:update:1")
                .expect("confirmed")
                .mode(),
            TicketDispatchMode::Confirmed
        );
        for refused in [
            "http://github.com/example/repo/issues/1007",
            "https://github.com/example/repo/pull/1007",
            "https://github.com/example/repo/issues/0",
            "https://example.test/example/repo/issues/1007",
            "https://github.com/example/repo/issues/1007?x=1",
        ] {
            assert_eq!(
                TicketDispatchRequest::new(refused, "telegram:bot:update:1").err(),
                Some(FleetRefusal::IssueUrl),
                "must refuse {refused}"
            );
        }
        for refused in ["", "telegram update 1", "telegram:\nupdate:1"] {
            assert_eq!(
                TicketDispatchRequest::new(url, refused).err(),
                Some(FleetRefusal::SourceKey)
            );
        }
    }

    #[test]
    fn the_page_bound_is_exact_and_never_clamped() {
        assert_eq!(
            SupportIssuesRequest::new(0).err(),
            Some(FleetRefusal::Limit)
        );
        assert!(SupportIssuesRequest::new(1).is_ok());
        assert_eq!(
            SupportIssuesRequest::new(MAX_SUPPORT_ISSUES)
                .expect("limit")
                .limit(),
            MAX_SUPPORT_ISSUES
        );
        assert_eq!(
            SupportIssuesRequest::new(MAX_SUPPORT_ISSUES + 1).err(),
            Some(FleetRefusal::Limit)
        );
    }

    #[test]
    fn identifier_grammars_match_the_fleets() {
        assert!(SupportThreadResolveRequest::new(MESSAGE_ID).is_ok());
        // The fleet's grammar is case-insensitive, so uppercase hex is admitted.
        assert!(SupportThreadResolveRequest::new(&"A".repeat(20)).is_ok());
        assert!(SupportThreadResolveRequest::new(&"a".repeat(120)).is_ok());
        for refused in [
            "a".repeat(19),
            "a".repeat(121),
            "z".repeat(24),
            format!("{MESSAGE_ID} "),
        ] {
            assert_eq!(
                SupportThreadResolveRequest::new(&refused).err(),
                Some(FleetRefusal::MessageId),
                "must refuse {refused:?}"
            );
        }

        assert!(SupportThreadNoteRequest::new(&"a".repeat(12), "t").is_ok());
        assert!(SupportThreadNoteRequest::new(&"a".repeat(80), "t").is_ok());
        for refused in ["a".repeat(11), "a".repeat(81), format!("{THREAD_ID}-")] {
            assert_eq!(
                SupportThreadNoteRequest::new(&refused, "t").err(),
                Some(FleetRefusal::ThreadId),
                "must refuse {refused:?}"
            );
        }
    }

    #[test]
    fn body_text_is_trimmed_bounded_and_refused_rather_than_truncated() {
        assert_eq!(
            SupportThreadNoteRequest::new(THREAD_ID, "   ").err(),
            Some(FleetRefusal::Text)
        );
        assert_eq!(
            SupportThreadNoteRequest::new(THREAD_ID, "belle\u{7}note").err(),
            Some(FleetRefusal::Text)
        );
        assert_eq!(
            SupportThreadNoteRequest::new(THREAD_ID, "  garde\u{a0}moi  ")
                .expect("note")
                .text(),
            "garde\u{a0}moi"
        );
        assert!(
            SupportThreadNoteRequest::new(THREAD_ID, &"n".repeat(MAX_THREAD_TEXT_BYTES)).is_ok()
        );
        assert_eq!(
            SupportThreadNoteRequest::new(THREAD_ID, &"n".repeat(MAX_THREAD_TEXT_BYTES + 1)).err(),
            Some(FleetRefusal::Text)
        );
        assert!(
            SupportReplyRequest::new("a", THREAD_ID, &"r".repeat(MAX_THREAD_TEXT_BYTES)).is_ok()
        );
        assert_eq!(
            SupportReplyRequest::new("a", THREAD_ID, &"r".repeat(MAX_THREAD_TEXT_BYTES + 1)).err(),
            Some(FleetRefusal::Text)
        );
    }

    #[test]
    fn an_email_validates_every_field_the_legacy_client_left_to_the_server() {
        for refused in [
            "",
            "no-at-sign",
            "two@@exemple.invalid",
            "@exemple.invalid",
            "client@",
            "client@localhost",
            "client@exemple..fr",
            "client@-exemple.invalid",
            "client @exemple.invalid",
            "client@exemple.invalid\nBcc: autre@exemple.invalid",
            "accentue\u{301}@exemple.invalid",
        ] {
            assert_eq!(
                SupportEmailRequest::new("a", refused, "sujet", "texte").err(),
                Some(FleetRefusal::Recipient),
                "must refuse recipient {refused:?}"
            );
        }
        // 250 + "@exemple.invalid" is 261 bytes, past the RFC 5321 path limit.
        assert_eq!(
            SupportEmailRequest::new(
                "a",
                &format!("{}@exemple.invalid", "l".repeat(250)),
                "s",
                "t"
            )
            .err(),
            Some(FleetRefusal::Recipient)
        );

        assert_eq!(
            SupportEmailRequest::new("a", "c@exemple.invalid", "   ", "texte").err(),
            Some(FleetRefusal::Subject)
        );
        assert_eq!(
            SupportEmailRequest::new("a", "c@exemple.invalid", "su\njet", "texte").err(),
            Some(FleetRefusal::Subject),
            "a folded subject would be a second mail header"
        );
        assert_eq!(
            SupportEmailRequest::new(
                "a",
                "c@exemple.invalid",
                &"s".repeat(MAX_EMAIL_SUBJECT_BYTES + 1),
                "t"
            )
            .err(),
            Some(FleetRefusal::Subject)
        );
        assert_eq!(
            SupportEmailRequest::new("", "c@exemple.invalid", "sujet", "texte").err(),
            Some(FleetRefusal::ActionId)
        );
        assert_eq!(
            SupportEmailRequest::new("a", "c@exemple.invalid", "sujet", "").err(),
            Some(FleetRefusal::Text)
        );
        assert!(
            SupportEmailRequest::new(
                "a",
                "c@exemple.invalid",
                "sujet",
                &"t".repeat(MAX_EMAIL_BODY_BYTES)
            )
            .is_ok()
        );
        assert_eq!(
            SupportEmailRequest::new(
                "a",
                "c@exemple.invalid",
                "sujet",
                &"t".repeat(MAX_EMAIL_BODY_BYTES + 1)
            )
            .err(),
            Some(FleetRefusal::Text)
        );
    }
}
