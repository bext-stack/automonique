// SPDX-License-Identifier: Elastic-2.0

//! Bounded, refusing decoders for the seven support and ticket actions.
//!
//! Each decoder takes the response bytes and returns either the action's typed
//! payload, the fleet's own bounded refusal, or a [`FleetFailure`]. Nothing
//! panics on hostile input and nothing is silently repaired.
//!
//! # Why these refuse where the legacy client repairs
//!
//! The TypeScript normalizers this contract came from are lossy in three ways.
//! A support issue missing `id`, `title`, or a parseable `updated_at` is
//! *dropped from the list*; an absent `status` or `priority` is *defaulted* to
//! `open`/`normal`; and an unparseable `created_at` *falls back* to
//! `updated_at`. Each of those turns a contract break into a plausible-looking
//! answer. Here every field the contract names is required, and its absence is
//! [`FleetFailure::MissingField`] — so a server change is a loud failure rather
//! than a support queue that is quietly four rows shorter than it should be.
//!
//! Unknown *extra* fields are tolerated, matching the legacy client: the fleet
//! has added top-level fields over time and refusing them would couple this
//! connector to a server release.

use automonique_connector_substrate::json::strict_json;
use serde_json::{Map, Value};

use crate::request::{is_github_issue_url, is_ticket_key};
use crate::{
    FleetFailure, FleetOutcome, MAX_FLEET_RESPONSE_BYTES, MAX_SUPPORT_ISSUES,
    MAX_TICKET_SOURCE_KEY_BYTES, ServerMessage,
};

/// Longest support issue id retained.
pub const MAX_ISSUE_ID_BYTES: usize = 120;
/// Longest support issue title retained.
pub const MAX_ISSUE_TITLE_BYTES: usize = 240;
/// Longest tenant name retained.
pub const MAX_TENANT_NAME_BYTES: usize = 160;
/// Longest site label retained.
pub const MAX_SITE_LABEL_BYTES: usize = 200;
/// Longest status, priority or source token retained.
pub const MAX_ISSUE_TOKEN_BYTES: usize = 40;
/// Longest requester name retained.
pub const MAX_REQUESTED_BY_BYTES: usize = 160;
/// Highest comment count retained.
pub const MAX_COMMENT_COUNT: u64 = 10_000;
/// Longest timestamp retained.
pub const MAX_TIMESTAMP_BYTES: usize = 60;
/// Longest thread subject retained.
pub const MAX_THREAD_SUBJECT_BYTES: usize = 160;
/// Longest thread contact address retained.
pub const MAX_CONTACT_EMAIL_BYTES: usize = 254;
/// Longest ticket result returned to an operator.
pub const MAX_TICKET_RESULT_BYTES: usize = 2_000;
/// Longest project label in a ticket receipt.
pub const MAX_PROJECT_LABEL_BYTES: usize = 160;

/// Which slice of the support board a response covers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupportScope {
    /// Every tenant this credential is authorized for.
    Staff,
    /// Only the tenant this instance belongs to.
    Tenant,
}

impl SupportScope {
    /// The exact wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staff => "staff",
            Self::Tenant => "tenant",
        }
    }
}

/// One row of the support board.
///
/// Every field the fleet's contract names is present. `site_label` is the only
/// optional one: the legacy client omits it when the fleet sends an empty
/// string, so an empty value and an absent key mean the same thing and are both
/// decoded as `None`.
///
/// The strings are tenant and requester content. `Debug` is derived rather than
/// redacted because a support row is the operator-facing payload this connector
/// exists to deliver — unlike a credential, withholding it would defeat the
/// purpose. A caller that logs these is logging customer-adjacent data and must
/// treat the record accordingly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportIssue {
    /// Fleet identifier for the request.
    pub id: String,
    /// Human title.
    pub title: String,
    /// Tenant the request belongs to.
    pub tenant_name: String,
    /// Site the request concerns, when the fleet names one.
    pub site_label: Option<String>,
    /// Workflow status, verbatim.
    pub status: String,
    /// Priority, verbatim.
    pub priority: String,
    /// Origin channel, verbatim.
    pub source: String,
    /// Who filed it.
    pub requested_by: String,
    /// Comments on the thread.
    pub comment_count: u32,
    /// Creation timestamp, verbatim.
    pub created_at: String,
    /// Last-update timestamp, verbatim.
    pub updated_at: String,
}

/// One accepted `support-issues` page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportIssues {
    /// Which slice of the board the fleet answered with.
    pub scope: SupportScope,
    /// The rows, in the order the fleet returned them.
    pub issues: Vec<SupportIssue>,
}

/// The support thread one mail message belongs to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportThreadRef {
    /// Fleet thread identifier, in the 12-to-80 hexadecimal grammar.
    pub id: String,
    /// Channel the thread lives on.
    pub channel: String,
    /// Thread status.
    pub status: String,
    /// Thread subject.
    pub subject: String,
    /// Contact address on the thread.
    pub contact_email: String,
}

/// The result of a reply or an email send.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupportDelivery {
    /// The fleet accepted the message onto its outbox.
    pub queued: bool,
    /// The fleet recognised this `action_id` as already delivered.
    ///
    /// The idempotency signal: a retried confirmed action reports `duplicate`
    /// rather than sending a second email.
    pub duplicate: bool,
}

/// Closed backend job states exposed to Automonique.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TicketJobStatus {
    PendingApproval,
    Pending,
    Claimed,
    Running,
    Done,
    Failed,
    Cancelled,
}

impl TicketJobStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingApproval => "pending_approval",
            Self::Pending => "pending",
            Self::Claimed => "claimed",
            Self::Running => "running",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Failed | Self::Cancelled)
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "pending_approval" => Some(Self::PendingApproval),
            "pending" => Some(Self::Pending),
            "claimed" => Some(Self::Claimed),
            "running" => Some(Self::Running),
            "done" => Some(Self::Done),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }
}

/// Workspace provenance selected by Manage, never by chat text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TicketWorkspace {
    SiteProfile,
    InstanceDefault,
}

/// Durable receipt for one ticket dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketDispatchReceipt {
    pub issue_id: String,
    pub issue_url: String,
    pub issue_title: String,
    pub project_label: String,
    pub site_label: Option<String>,
    pub workspace: TicketWorkspace,
    pub job_id: String,
    /// Exact transport coordinate that owns the returned Manage job.
    pub source_key: String,
    pub job_status: TicketJobStatus,
    pub duplicate: bool,
    pub approved: bool,
}

/// Terminal administrator choice recorded by Manage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TicketDecisionOutcome {
    Approved,
    Rejected,
}

impl TicketDecisionOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approve",
            Self::Rejected => "reject",
        }
    }
}

/// Durable receipt for an idempotent ticket decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketDecisionReceipt {
    pub job_id: String,
    pub job_status: TicketJobStatus,
    pub decision: TicketDecisionOutcome,
    pub duplicate: bool,
}

/// Current state of one exact dispatched ticket job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketStatus {
    pub issue_id: String,
    pub issue_url: String,
    pub issue_title: String,
    pub job_id: String,
    pub job_status: TicketJobStatus,
    pub result: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Decode a `support-issues` response.
///
/// # Errors
///
/// Returns [`FleetFailure::InvalidResponse`] for a body that is not strict JSON
/// or not the envelope shape, [`FleetFailure::MissingField`] for an absent
/// contract field, [`FleetFailure::FieldOutOfBounds`] for one past its ceiling
/// or outside its grammar, and [`FleetFailure::TooManyIssues`] for a page over
/// [`MAX_SUPPORT_ISSUES`].
pub fn decode_support_issues(bytes: &[u8]) -> Result<FleetOutcome<SupportIssues>, FleetFailure> {
    let envelope = envelope(bytes)?;
    if !is_accepted(&envelope)? {
        return Ok(FleetOutcome::Rejected(rejection(&envelope)));
    }

    let scope = match required_str(&envelope, "scope")? {
        "staff" => SupportScope::Staff,
        "tenant" => SupportScope::Tenant,
        _ => return Err(FleetFailure::FieldOutOfBounds),
    };
    let rows = envelope
        .get("issues")
        .ok_or(FleetFailure::MissingField)?
        .as_array()
        .ok_or(FleetFailure::InvalidResponse)?;
    if rows.len() > MAX_SUPPORT_ISSUES {
        return Err(FleetFailure::TooManyIssues);
    }

    let mut issues = Vec::with_capacity(rows.len());
    for row in rows {
        issues.push(issue(
            row.as_object().ok_or(FleetFailure::InvalidResponse)?,
        )?);
    }
    Ok(FleetOutcome::Accepted(SupportIssues { scope, issues }))
}

/// Decode a `support-thread-resolve` response.
///
/// # Errors
///
/// As [`decode_support_issues`], for this action's contract.
pub fn decode_support_thread(bytes: &[u8]) -> Result<FleetOutcome<SupportThreadRef>, FleetFailure> {
    let envelope = envelope(bytes)?;
    if !is_accepted(&envelope)? {
        return Ok(FleetOutcome::Rejected(rejection(&envelope)));
    }
    let thread = envelope
        .get("thread")
        .ok_or(FleetFailure::MissingField)?
        .as_object()
        .ok_or(FleetFailure::InvalidResponse)?;

    let id = required_str(thread, "id")?;
    if !(12..=80).contains(&id.len()) || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(FleetFailure::FieldOutOfBounds);
    }
    Ok(FleetOutcome::Accepted(SupportThreadRef {
        id: id.to_owned(),
        channel: bounded(thread, "channel", MAX_ISSUE_TOKEN_BYTES)?,
        status: bounded(thread, "status", MAX_ISSUE_TOKEN_BYTES)?,
        subject: bounded(thread, "subject", MAX_THREAD_SUBJECT_BYTES)?,
        contact_email: bounded(thread, "contact_email", MAX_CONTACT_EMAIL_BYTES)?,
    }))
}

/// Decode a `support-thread-note` response, whose accepted payload is empty.
///
/// # Errors
///
/// As [`decode_support_issues`], for this action's contract.
pub fn decode_support_note(bytes: &[u8]) -> Result<FleetOutcome<()>, FleetFailure> {
    let envelope = envelope(bytes)?;
    if is_accepted(&envelope)? {
        Ok(FleetOutcome::Accepted(()))
    } else {
        Ok(FleetOutcome::Rejected(rejection(&envelope)))
    }
}

/// Decode a `support-thread-reply` or `support-email` response.
///
/// `require_queued` is the one place the two actions differ in the legacy
/// client: the email path demands `ok` *and* `queued`, while the reply path
/// treats `ok` alone as queued. That asymmetry is carried here as a parameter
/// rather than silently unified, because unifying it either drops a check the
/// email path has or invents one the reply path does not.
///
/// # Errors
///
/// As [`decode_support_issues`], for this action's contract.
pub fn decode_support_delivery(
    bytes: &[u8],
    require_queued: bool,
) -> Result<FleetOutcome<SupportDelivery>, FleetFailure> {
    let envelope = envelope(bytes)?;
    if !is_accepted(&envelope)? {
        return Ok(FleetOutcome::Rejected(rejection(&envelope)));
    }
    let queued = match envelope.get("queued") {
        Some(Value::Bool(queued)) => *queued,
        // The reply action's contract does not carry `queued`; `ok` is the
        // whole acceptance signal there.
        None if !require_queued => true,
        None => return Err(FleetFailure::MissingField),
        Some(_) => return Err(FleetFailure::FieldOutOfBounds),
    };
    if require_queued && !queued {
        return Ok(FleetOutcome::Rejected(rejection(&envelope)));
    }
    let duplicate = match envelope.get("duplicate") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(duplicate)) => *duplicate,
        Some(_) => return Err(FleetFailure::FieldOutOfBounds),
    };
    Ok(FleetOutcome::Accepted(SupportDelivery {
        queued,
        duplicate,
    }))
}

/// Decode an `automonique-ticket-dispatch` receipt.
pub fn decode_ticket_dispatch(
    bytes: &[u8],
) -> Result<FleetOutcome<TicketDispatchReceipt>, FleetFailure> {
    let envelope = envelope(bytes)?;
    if !is_accepted(&envelope)? {
        return Ok(FleetOutcome::Rejected(rejection(&envelope)));
    }
    let row = envelope
        .get("receipt")
        .ok_or(FleetFailure::MissingField)?
        .as_object()
        .ok_or(FleetFailure::InvalidResponse)?;
    let issue_url = nonempty(row, "issue_url", crate::MAX_TICKET_ISSUE_URL_BYTES)?;
    if !is_github_issue_url(&issue_url) {
        return Err(FleetFailure::FieldOutOfBounds);
    }
    let site_label = optional_bounded(row, "site_label", MAX_SITE_LABEL_BYTES)?;
    let workspace = match required_str(row, "workspace")? {
        "site_profile" => TicketWorkspace::SiteProfile,
        "instance_default" => TicketWorkspace::InstanceDefault,
        _ => return Err(FleetFailure::FieldOutOfBounds),
    };
    let source_key = nonempty(row, "source_key", MAX_TICKET_SOURCE_KEY_BYTES)?;
    if !is_ticket_key(&source_key, MAX_TICKET_SOURCE_KEY_BYTES) {
        return Err(FleetFailure::FieldOutOfBounds);
    }
    Ok(FleetOutcome::Accepted(TicketDispatchReceipt {
        issue_id: nonempty(row, "issue_id", MAX_ISSUE_ID_BYTES)?,
        issue_url,
        issue_title: nonempty(row, "issue_title", 300)?,
        project_label: nonempty(row, "project_label", MAX_PROJECT_LABEL_BYTES)?,
        site_label,
        workspace,
        job_id: nonempty(row, "job_id", crate::MAX_FLEET_IDENTIFIER_BYTES)?,
        source_key,
        job_status: ticket_status(row, "job_status")?,
        duplicate: boolean(row, "duplicate")?,
        approved: boolean(row, "approved")?,
    }))
}

/// Decode an `automonique-ticket-decision` receipt.
pub fn decode_ticket_decision(
    bytes: &[u8],
) -> Result<FleetOutcome<TicketDecisionReceipt>, FleetFailure> {
    let envelope = envelope(bytes)?;
    if !is_accepted(&envelope)? {
        return Ok(FleetOutcome::Rejected(rejection(&envelope)));
    }
    let row = envelope
        .get("decision")
        .ok_or(FleetFailure::MissingField)?
        .as_object()
        .ok_or(FleetFailure::InvalidResponse)?;
    let decision = match required_str(row, "value")? {
        "approve" => TicketDecisionOutcome::Approved,
        "reject" => TicketDecisionOutcome::Rejected,
        _ => return Err(FleetFailure::FieldOutOfBounds),
    };
    let job_status = ticket_status(row, "job_status")?;
    if matches!(decision, TicketDecisionOutcome::Rejected)
        && job_status != TicketJobStatus::Cancelled
    {
        return Err(FleetFailure::FieldOutOfBounds);
    }
    if matches!(decision, TicketDecisionOutcome::Approved)
        && job_status == TicketJobStatus::PendingApproval
    {
        return Err(FleetFailure::FieldOutOfBounds);
    }
    Ok(FleetOutcome::Accepted(TicketDecisionReceipt {
        job_id: nonempty(row, "job_id", crate::MAX_FLEET_IDENTIFIER_BYTES)?,
        job_status,
        decision,
        duplicate: boolean(row, "duplicate")?,
    }))
}

/// Decode an `automonique-ticket-status` response.
pub fn decode_ticket_status(bytes: &[u8]) -> Result<FleetOutcome<TicketStatus>, FleetFailure> {
    let envelope = envelope(bytes)?;
    if !is_accepted(&envelope)? {
        return Ok(FleetOutcome::Rejected(rejection(&envelope)));
    }
    let row = envelope
        .get("status")
        .ok_or(FleetFailure::MissingField)?
        .as_object()
        .ok_or(FleetFailure::InvalidResponse)?;
    let issue_url = nonempty(row, "issue_url", crate::MAX_TICKET_ISSUE_URL_BYTES)?;
    if !is_github_issue_url(&issue_url) {
        return Err(FleetFailure::FieldOutOfBounds);
    }
    Ok(FleetOutcome::Accepted(TicketStatus {
        issue_id: nonempty(row, "issue_id", MAX_ISSUE_ID_BYTES)?,
        issue_url,
        issue_title: nonempty(row, "issue_title", 300)?,
        job_id: nonempty(row, "job_id", crate::MAX_FLEET_IDENTIFIER_BYTES)?,
        job_status: ticket_status(row, "job_status")?,
        result: bounded_multiline(row, "result", MAX_TICKET_RESULT_BYTES)?,
        created_at: timestamp(row, "created_at")?,
        updated_at: timestamp(row, "updated_at")?,
    }))
}

/// Read one bounded, strictly-parsed JSON object off the wire.
fn envelope(bytes: &[u8]) -> Result<Map<String, Value>, FleetFailure> {
    if bytes.is_empty() || bytes.len() > MAX_FLEET_RESPONSE_BYTES {
        return Err(FleetFailure::ResponseTooLarge);
    }
    match strict_json(bytes)? {
        Value::Object(object) => Ok(object),
        _ => Err(FleetFailure::InvalidResponse),
    }
}

/// Whether the fleet said `ok: true`.
///
/// `ok` must be a boolean. A truthy string or a `1` is refused rather than
/// coerced: the legacy client compares with `===`, so anything else was never
/// an acceptance there either.
fn is_accepted(object: &Map<String, Value>) -> Result<bool, FleetFailure> {
    match object.get("ok") {
        Some(Value::Bool(accepted)) => Ok(*accepted),
        None => Err(FleetFailure::MissingField),
        Some(_) => Err(FleetFailure::FieldOutOfBounds),
    }
}

/// The fleet's bounded reason for a refusal, or a fixed stand-in when it gave
/// none. Never an error: a refusal that omits `error` is still a well-formed
/// refusal.
fn rejection(object: &Map<String, Value>) -> ServerMessage {
    object.get("error").and_then(Value::as_str).map_or_else(
        || ServerMessage::sanitized("support refused"),
        ServerMessage::sanitized,
    )
}

fn boolean(object: &Map<String, Value>, key: &str) -> Result<bool, FleetFailure> {
    object
        .get(key)
        .ok_or(FleetFailure::MissingField)?
        .as_bool()
        .ok_or(FleetFailure::FieldOutOfBounds)
}

fn ticket_status(object: &Map<String, Value>, key: &str) -> Result<TicketJobStatus, FleetFailure> {
    TicketJobStatus::parse(required_str(object, key)?).ok_or(FleetFailure::FieldOutOfBounds)
}

fn optional_bounded(
    object: &Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<Option<String>, FleetFailure> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value))
            if value.len() <= max_bytes && !value.chars().any(char::is_control) =>
        {
            Ok((!value.is_empty()).then(|| value.to_owned()))
        }
        Some(_) => Err(FleetFailure::FieldOutOfBounds),
    }
}

fn bounded_multiline(
    object: &Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<String, FleetFailure> {
    let value = required_str(object, key)?;
    if value.len() > max_bytes
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(FleetFailure::FieldOutOfBounds);
    }
    Ok(value.to_owned())
}

/// Decode one support issue, requiring every field the contract names.
fn issue(row: &Map<String, Value>) -> Result<SupportIssue, FleetFailure> {
    let comment_count = row
        .get("comment_count")
        .ok_or(FleetFailure::MissingField)?
        .as_u64()
        .ok_or(FleetFailure::FieldOutOfBounds)?;
    if comment_count > MAX_COMMENT_COUNT {
        return Err(FleetFailure::FieldOutOfBounds);
    }
    let site_label = match row.get("site_label") {
        None | Some(Value::Null) => None,
        Some(Value::String(label)) if label.is_empty() => None,
        Some(Value::String(label)) if label.len() <= MAX_SITE_LABEL_BYTES => Some(label.to_owned()),
        Some(_) => return Err(FleetFailure::FieldOutOfBounds),
    };
    Ok(SupportIssue {
        id: nonempty(row, "id", MAX_ISSUE_ID_BYTES)?,
        title: nonempty(row, "title", MAX_ISSUE_TITLE_BYTES)?,
        tenant_name: bounded(row, "tenant_name", MAX_TENANT_NAME_BYTES)?,
        site_label,
        status: nonempty(row, "status", MAX_ISSUE_TOKEN_BYTES)?,
        priority: nonempty(row, "priority", MAX_ISSUE_TOKEN_BYTES)?,
        source: bounded(row, "source", MAX_ISSUE_TOKEN_BYTES)?,
        requested_by: bounded(row, "requested_by", MAX_REQUESTED_BY_BYTES)?,
        comment_count: u32::try_from(comment_count).map_err(|_| FleetFailure::FieldOutOfBounds)?,
        created_at: timestamp(row, "created_at")?,
        updated_at: timestamp(row, "updated_at")?,
    })
}

/// A required string field, present and within its ceiling.
fn required_str<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, FleetFailure> {
    object
        .get(key)
        .ok_or(FleetFailure::MissingField)?
        .as_str()
        .ok_or(FleetFailure::FieldOutOfBounds)
}

/// A required string field that may be empty.
fn bounded(
    object: &Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<String, FleetFailure> {
    let value = required_str(object, key)?;
    if value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(FleetFailure::FieldOutOfBounds);
    }
    Ok(value.to_owned())
}

/// A required string field that may not be empty.
fn nonempty(
    object: &Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<String, FleetFailure> {
    let value = bounded(object, key, max_bytes)?;
    if value.is_empty() {
        return Err(FleetFailure::FieldOutOfBounds);
    }
    Ok(value)
}

/// A required timestamp, retained verbatim.
///
/// The legacy client validates these with JavaScript's `Date.parse`, which
/// accepts far more than one format and has no faithful Rust equivalent. Rather
/// than guess at RFC 3339 and risk refusing a timestamp the fleet legitimately
/// sends, this checks only that the value is a bounded, non-empty, printable
/// ASCII string and hands it back unparsed. Interpreting it is the caller's,
/// once the exact format is confirmed against a captured response.
fn timestamp(object: &Map<String, Value>, key: &str) -> Result<String, FleetFailure> {
    let value = required_str(object, key)?;
    if value.is_empty()
        || value.len() > MAX_TIMESTAMP_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(FleetFailure::FieldOutOfBounds);
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One complete issue row, as the fleet's contract names it.
    fn issue_json() -> String {
        String::from(
            r#"{"id":"iss-1","title":"Panne de paiement","tenant_name":"Boulangerie Milo",
               "site_label":"milo.invalid","status":"triaging","priority":"high","source":"email",
               "requested_by":"Claire","comment_count":3,
               "created_at":"2026-08-10T09:12:00.000Z","updated_at":"2026-08-13T17:04:11.000Z"}"#,
        )
    }

    fn page(rows: &str) -> String {
        format!(r#"{{"ok":true,"scope":"staff","issues":[{rows}]}}"#)
    }

    #[test]
    fn a_complete_page_decodes_every_contract_field() {
        let outcome = decode_support_issues(page(&issue_json()).as_bytes()).expect("decode");
        let FleetOutcome::Accepted(page) = outcome else {
            panic!("expected an accepted page");
        };
        assert_eq!(page.scope, SupportScope::Staff);
        assert_eq!(page.scope.as_str(), "staff");
        assert_eq!(page.issues.len(), 1);
        let issue = &page.issues[0];
        assert_eq!(issue.id, "iss-1");
        assert_eq!(issue.title, "Panne de paiement");
        assert_eq!(issue.tenant_name, "Boulangerie Milo");
        assert_eq!(issue.site_label.as_deref(), Some("milo.invalid"));
        assert_eq!(issue.status, "triaging");
        assert_eq!(issue.priority, "high");
        assert_eq!(issue.source, "email");
        assert_eq!(issue.requested_by, "Claire");
        assert_eq!(issue.comment_count, 3);
        assert_eq!(issue.created_at, "2026-08-10T09:12:00.000Z");
        assert_eq!(issue.updated_at, "2026-08-13T17:04:11.000Z");
    }

    #[test]
    fn every_named_field_is_required_and_its_absence_is_a_typed_refusal() {
        for key in [
            "id",
            "title",
            "tenant_name",
            "status",
            "priority",
            "source",
            "requested_by",
            "comment_count",
            "created_at",
            "updated_at",
        ] {
            let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
            row.as_object_mut().expect("object").remove(key);
            let body = page(&row.to_string());
            assert_eq!(
                decode_support_issues(body.as_bytes()),
                Err(FleetFailure::MissingField),
                "dropping {key} must be refused, not decoded"
            );
        }
        // The one genuinely optional field, in both of its absent spellings.
        for absent in ["null", ""] {
            let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
            let object = row.as_object_mut().expect("object");
            if absent.is_empty() {
                object.remove("site_label");
            } else {
                object.insert("site_label".to_owned(), Value::Null);
            }
            let body = page(&row.to_string());
            let outcome = decode_support_issues(body.as_bytes()).expect("decode");
            assert_eq!(
                outcome.accepted().expect("accepted").issues[0].site_label,
                None
            );
        }
    }

    #[test]
    fn an_empty_site_label_and_an_absent_one_mean_the_same_thing() {
        let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
        row.as_object_mut()
            .expect("object")
            .insert("site_label".to_owned(), Value::String(String::new()));
        let body = page(&row.to_string());
        let outcome = decode_support_issues(body.as_bytes()).expect("decode");
        assert_eq!(
            outcome.accepted().expect("accepted").issues[0].site_label,
            None
        );
    }

    #[test]
    fn every_field_ceiling_is_exact() {
        let cases: [(&str, usize); 6] = [
            ("id", MAX_ISSUE_ID_BYTES),
            ("title", MAX_ISSUE_TITLE_BYTES),
            ("tenant_name", MAX_TENANT_NAME_BYTES),
            ("site_label", MAX_SITE_LABEL_BYTES),
            ("requested_by", MAX_REQUESTED_BY_BYTES),
            ("status", MAX_ISSUE_TOKEN_BYTES),
        ];
        for (key, max) in cases {
            for (width, expected) in [(max, true), (max + 1, false)] {
                let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
                row.as_object_mut()
                    .expect("object")
                    .insert(key.to_owned(), Value::String("v".repeat(width)));
                let body = page(&row.to_string());
                assert_eq!(
                    decode_support_issues(body.as_bytes()).is_ok(),
                    expected,
                    "{key} at {width} bytes"
                );
            }
        }

        for (count, expected) in [(MAX_COMMENT_COUNT, true), (MAX_COMMENT_COUNT + 1, false)] {
            let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
            row.as_object_mut()
                .expect("object")
                .insert("comment_count".to_owned(), Value::Number(count.into()));
            let body = page(&row.to_string());
            assert_eq!(
                decode_support_issues(body.as_bytes()).is_ok(),
                expected,
                "comment_count {count}"
            );
        }
    }

    #[test]
    fn a_page_over_the_row_ceiling_is_refused_rather_than_truncated() {
        let rows: Vec<String> = (0..=MAX_SUPPORT_ISSUES).map(|_| issue_json()).collect();
        let body = page(&rows.join(","));
        assert_eq!(
            decode_support_issues(body.as_bytes()),
            Err(FleetFailure::TooManyIssues)
        );
        let rows: Vec<String> = (0..MAX_SUPPORT_ISSUES).map(|_| issue_json()).collect();
        let body = page(&rows.join(","));
        assert_eq!(
            decode_support_issues(body.as_bytes())
                .expect("decode")
                .accepted()
                .expect("accepted")
                .issues
                .len(),
            MAX_SUPPORT_ISSUES
        );
    }

    #[test]
    fn malformed_bodies_are_typed_refusals_rather_than_panics() {
        let cases: [(&str, FleetFailure); 10] = [
            ("", FleetFailure::ResponseTooLarge),
            ("not json", FleetFailure::InvalidResponse),
            ("[]", FleetFailure::InvalidResponse),
            ("null", FleetFailure::InvalidResponse),
            (r#"{"ok":true}{"ok":true}"#, FleetFailure::InvalidResponse),
            (
                r#"{"ok":false,"ok":true,"scope":"staff","issues":[]}"#,
                FleetFailure::InvalidResponse,
            ),
            (
                r#"{"scope":"staff","issues":[]}"#,
                FleetFailure::MissingField,
            ),
            (r#"{"ok":1,"issues":[]}"#, FleetFailure::FieldOutOfBounds),
            (r#"{"ok":true,"issues":[]}"#, FleetFailure::MissingField),
            (
                r#"{"ok":true,"scope":"admin","issues":[]}"#,
                FleetFailure::FieldOutOfBounds,
            ),
        ];
        for (body, expected) in cases {
            assert_eq!(
                decode_support_issues(body.as_bytes()),
                Err(expected),
                "body {body:?}"
            );
        }
        // A row that is not an object, and a page whose issues are not a list.
        assert_eq!(
            decode_support_issues(page("7").as_bytes()),
            Err(FleetFailure::InvalidResponse)
        );
        assert_eq!(
            decode_support_issues(br#"{"ok":true,"scope":"staff","issues":7}"#),
            Err(FleetFailure::InvalidResponse)
        );
    }

    #[test]
    fn an_oversized_body_is_refused_before_a_field_is_read() {
        let oversized = vec![b'a'; MAX_FLEET_RESPONSE_BYTES + 1];
        assert_eq!(
            decode_support_issues(&oversized),
            Err(FleetFailure::ResponseTooLarge)
        );
    }

    #[test]
    fn a_fleet_refusal_is_a_parsed_outcome_carrying_a_bounded_reason() {
        let outcome = decode_support_issues(br#"{"ok":false,"error":"API support indisponible"}"#)
            .expect("decode");
        assert_eq!(
            outcome.rejected().map(ServerMessage::as_str),
            Some("API support indisponible")
        );
        // A refusal without a reason is still well-formed.
        let bare = decode_support_issues(br#"{"ok":false}"#).expect("decode");
        assert_eq!(
            bare.rejected().map(ServerMessage::as_str),
            Some("support refused")
        );
    }

    #[test]
    fn a_thread_reference_decodes_and_holds_the_fleets_id_grammar() {
        let body = br#"{"ok":true,"thread":{"id":"0123456789ab","channel":"email",
            "status":"open","subject":"Facture","contact_email":"claire@exemple.invalid"}}"#;
        let outcome = decode_support_thread(body).expect("decode");
        let thread = outcome.accepted().expect("accepted");
        assert_eq!(thread.id, "0123456789ab");
        assert_eq!(thread.channel, "email");
        assert_eq!(thread.status, "open");
        assert_eq!(thread.subject, "Facture");
        assert_eq!(thread.contact_email, "claire@exemple.invalid");

        for hostile in [
            &br#"{"ok":true,"thread":{"id":"short","channel":"e","status":"o","subject":"s","contact_email":"c"}}"#[..],
            &br#"{"ok":true,"thread":{"id":"zzzzzzzzzzzz","channel":"e","status":"o","subject":"s","contact_email":"c"}}"#[..],
        ] {
            assert_eq!(
                decode_support_thread(hostile),
                Err(FleetFailure::FieldOutOfBounds)
            );
        }
        assert_eq!(
            decode_support_thread(br#"{"ok":true}"#),
            Err(FleetFailure::MissingField)
        );
        assert_eq!(
            decode_support_thread(br#"{"ok":true,"thread":{"id":"0123456789ab"}}"#),
            Err(FleetFailure::MissingField)
        );
    }

    #[test]
    fn a_note_response_is_the_bare_acceptance_signal() {
        assert_eq!(
            decode_support_note(br#"{"ok":true}"#).expect("decode"),
            FleetOutcome::Accepted(())
        );
        assert_eq!(
            decode_support_note(br#"{"ok":false,"error":"thread inconnu"}"#)
                .expect("decode")
                .rejected()
                .map(ServerMessage::as_str),
            Some("thread inconnu")
        );
        assert_eq!(
            decode_support_note(br#"{}"#),
            Err(FleetFailure::MissingField)
        );
    }

    #[test]
    fn the_email_path_demands_queued_where_the_reply_path_does_not() {
        // The email contract: ok AND queued.
        assert_eq!(
            decode_support_delivery(br#"{"ok":true,"queued":true}"#, true).expect("decode"),
            FleetOutcome::Accepted(SupportDelivery {
                queued: true,
                duplicate: false
            })
        );
        assert_eq!(
            decode_support_delivery(br#"{"ok":true}"#, true),
            Err(FleetFailure::MissingField),
            "the email contract names queued, so its absence is a contract break"
        );
        let not_queued = decode_support_delivery(
            br#"{"ok":true,"queued":false,"error":"boite pleine"}"#,
            true,
        )
        .expect("decode");
        assert_eq!(
            not_queued.rejected().map(ServerMessage::as_str),
            Some("boite pleine")
        );

        // The reply contract: ok alone.
        assert_eq!(
            decode_support_delivery(br#"{"ok":true}"#, false).expect("decode"),
            FleetOutcome::Accepted(SupportDelivery {
                queued: true,
                duplicate: false
            })
        );
    }

    #[test]
    fn the_duplicate_signal_is_carried_and_never_invented() {
        assert_eq!(
            decode_support_delivery(br#"{"ok":true,"queued":true,"duplicate":true}"#, true)
                .expect("decode"),
            FleetOutcome::Accepted(SupportDelivery {
                queued: true,
                duplicate: true
            })
        );
        assert_eq!(
            decode_support_delivery(br#"{"ok":true,"queued":true,"duplicate":false}"#, true)
                .expect("decode"),
            FleetOutcome::Accepted(SupportDelivery {
                queued: true,
                duplicate: false
            })
        );
        // A truthy non-boolean is refused rather than coerced, so a `"duplicate":"yes"`
        // can never be read as "already sent" by one reader and "not sent" by another.
        assert_eq!(
            decode_support_delivery(br#"{"ok":true,"queued":true,"duplicate":"yes"}"#, true),
            Err(FleetFailure::FieldOutOfBounds)
        );
        assert_eq!(
            decode_support_delivery(br#"{"ok":true,"queued":"yes"}"#, true),
            Err(FleetFailure::FieldOutOfBounds)
        );
    }

    #[test]
    fn unknown_extra_fields_are_tolerated_so_a_server_release_does_not_break_the_read() {
        let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
        row.as_object_mut()
            .expect("object")
            .insert("assigned_to".to_owned(), Value::String("Léa".to_owned()));
        let body = format!(
            r#"{{"ok":true,"scope":"tenant","issues":[{}],"next_cursor":"c1"}}"#,
            row
        );
        let outcome = decode_support_issues(body.as_bytes()).expect("decode");
        let page = outcome.accepted().expect("accepted");
        assert_eq!(page.scope, SupportScope::Tenant);
        assert_eq!(page.issues.len(), 1);
    }

    #[test]
    fn a_control_bearing_field_is_refused_so_a_row_cannot_drive_a_terminal() {
        let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
        row.as_object_mut().expect("object").insert(
            "title".to_owned(),
            Value::String("Panne\u{1b}[2J".to_owned()),
        );
        let body = page(&row.to_string());
        assert_eq!(
            decode_support_issues(body.as_bytes()),
            Err(FleetFailure::FieldOutOfBounds)
        );
    }

    #[test]
    fn ticket_dispatch_receipt_is_strict_and_typed() {
        let bytes = br#"{"ok":true,"receipt":{"issue_id":"issue-1","issue_url":"https://github.com/example/repo/issues/1007","issue_title":"List prism sites","project_id":"ignored","project_label":"Bext platform","site_label":"bext","workspace":"site_profile","job_id":"job-1","source_key":"slack:workspace:event:original","job_status":"pending","duplicate":false,"approved":true}}"#;
        assert_eq!(
            decode_ticket_dispatch(bytes).expect("decode"),
            FleetOutcome::Accepted(TicketDispatchReceipt {
                issue_id: String::from("issue-1"),
                issue_url: String::from("https://github.com/example/repo/issues/1007"),
                issue_title: String::from("List prism sites"),
                project_label: String::from("Bext platform"),
                site_label: Some(String::from("bext")),
                workspace: TicketWorkspace::SiteProfile,
                job_id: String::from("job-1"),
                source_key: String::from("slack:workspace:event:original"),
                job_status: TicketJobStatus::Pending,
                duplicate: false,
                approved: true,
            })
        );
        assert!(TicketJobStatus::Done.is_terminal());
        assert!(!TicketJobStatus::Running.is_terminal());
    }

    #[test]
    fn ticket_status_keeps_multiline_results_but_refuses_unknown_states() {
        let bytes = br#"{"ok":true,"status":{"issue_id":"issue-1","issue_url":"https://github.com/example/repo/issues/1007","issue_title":"List prism sites","job_id":"job-1","job_status":"done","result":"Implemented\nVerified live","created_at":"2026-08-14T20:00:00Z","updated_at":"2026-08-14T20:01:00Z"}}"#;
        let outcome = decode_ticket_status(bytes).expect("decode");
        let status = outcome.accepted().expect("accepted");
        assert_eq!(status.job_status, TicketJobStatus::Done);
        assert_eq!(status.result, "Implemented\nVerified live");

        let unknown = String::from_utf8(bytes.to_vec())
            .expect("utf8")
            .replace("\"done\"", "\"almost_done\"");
        assert_eq!(
            decode_ticket_status(unknown.as_bytes()),
            Err(FleetFailure::FieldOutOfBounds)
        );
    }

    #[test]
    fn ticket_decision_receipt_enforces_terminal_rejection() {
        let rejected = br#"{"ok":true,"decision":{"job_id":"job-1","job_status":"cancelled","value":"reject","duplicate":false}}"#;
        assert_eq!(
            decode_ticket_decision(rejected).expect("decode"),
            FleetOutcome::Accepted(TicketDecisionReceipt {
                job_id: String::from("job-1"),
                job_status: TicketJobStatus::Cancelled,
                decision: TicketDecisionOutcome::Rejected,
                duplicate: false,
            })
        );
        let unsafe_rejection = br#"{"ok":true,"decision":{"job_id":"job-1","job_status":"pending","value":"reject","duplicate":false}}"#;
        assert_eq!(
            decode_ticket_decision(unsafe_rejection),
            Err(FleetFailure::FieldOutOfBounds)
        );
    }
}
