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
}

impl WireAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Issues => "support-issues",
            Self::ThreadResolve => "support-thread-resolve",
            Self::ThreadNote => "support-thread-note",
            Self::ThreadReply => "support-thread-reply",
            Self::Email => "support-email",
        }
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
}

impl FleetRequest {
    const fn wire_action(&self) -> WireAction {
        match self {
            Self::SupportIssues(_) => WireAction::Issues,
            Self::SupportThreadResolve(_) => WireAction::ThreadResolve,
            Self::SupportThreadNote(_) => WireAction::ThreadNote,
            Self::SupportThreadReply(_) => WireAction::ThreadReply,
            Self::SupportEmail(_) => WireAction::Email,
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
        matches!(self, Self::SupportThreadReply(_) | Self::SupportEmail(_))
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
        }
        body.push('}');
        body
    }
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
    fn the_action_vocabulary_is_exactly_the_five_support_actions() {
        assert_eq!(WireAction::Issues.as_str(), "support-issues");
        assert_eq!(WireAction::ThreadResolve.as_str(), "support-thread-resolve");
        assert_eq!(WireAction::ThreadNote.as_str(), "support-thread-note");
        assert_eq!(WireAction::ThreadReply.as_str(), "support-thread-reply");
        assert_eq!(WireAction::Email.as_str(), "support-email");
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
            SupportReplyRequest::new("jean-email:abc", THREAD_ID, "bonjour").expect("reply"),
        );
        assert_eq!(
            reply.canonical_body(&instance),
            format!(
                r#"{{"action":"support-thread-reply","id":"sd-instance-01","action_id":"jean-email:abc","thread_id":"{THREAD_ID}","text":"bonjour"}}"#
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
        assert!(!read.is_external_effect());
        assert!(!note.is_external_effect());
        assert!(reply.is_external_effect());
        assert!(email.is_external_effect());
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
