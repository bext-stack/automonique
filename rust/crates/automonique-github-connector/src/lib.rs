// SPDX-License-Identifier: Elastic-2.0

//! Typed client for the GitHub issues surface Automonique works tickets through.
//!
//! Three request vocabularies are spelled, and nothing outside them can be.
//!
//! The **issue surface** is fourteen operations, one per [`GitHubOperation`]
//! variant: create an issue, comment on one, open or close one, replace its
//! labels, read one back, read its comments, read or edit one comment,
//! conditionally replace an issue body, list repository labels or issues, read
//! repository push metadata, search issues, and identify the credential. Six
//! of them are writes, which
//! [`GitHubOperation::is_external_effect`] answers for directly.
//!
//! The **Actions surface** is two repository-scoped operations: read one exact
//! workflow run and re-run that exact workflow run. It cannot dispatch a new
//! workflow, cancel one, select a branch, or name an arbitrary API path.
//!
//! The **pull-request surface** is six repository-scoped operations, three
//! reads and three writes: read one branch, read one pull request, list the
//! open pull requests for one exact head/base pair, open a pull request,
//! retitle one, and merge one. It cannot close a pull request, push a branch,
//! request a review, edit a description, choose a squash or rebase strategy,
//! or merge without naming the exact head commit it was preflighted against.
//! Every write is repository-fixed by [`RepoTarget`] and branch-fixed by
//! [`BranchName`], so a caller that holds one of these requests cannot steer
//! it at another repository or another branch.
//!
//! The **work-management surface** is thirty-seven typed mutations, one per
//! [`ManagementRequest`] constructor, sent through
//! [`GitHubClient::manage`]: labels and milestones (create, update, delete),
//! issue metadata, locking and unlocking, transferring and pinning, the
//! sub-issue hierarchy and issue dependencies, and the Projects surface —
//! projects, fields, views, items, drafts and statuses. That module exposes
//! constructors rather than paths for the same reason the issue surface does,
//! and validates every repository and project coordinate before a request can
//! be rendered. A management plan is bounded at
//! [`MAX_MANAGEMENT_OPERATIONS`], and its bodies are produced by `serde_json`
//! rather than by interpolating operator or model text.
//!
//! Around both sit the two pieces of local contract that decide *which*
//! repository a ticket belongs in and *what* its body says: the [`RepoMap`]
//! resolver and the [`TicketDraft`] body builder.
//!
//! # Target lock
//!
//! No caller supplies a URL or a path. [`GitHubBase`] admits `api.github.com`
//! and the plaintext loopback literals and nothing else; every path is rendered
//! by [`GitHubOperation`] from validated [`Owner`], [`Repo`] and
//! [`IssueNumber`] values, whose grammars exclude `/`, `.`, `?` and `#`, so no
//! caller string can add a segment, escape a repository, or append a query. A
//! layer talked into asking for `/user/repos` or a `DELETE` cannot spell one —
//! there is no variant for it.
//!
//! # Credential
//!
//! The token rides an `Authorization: Bearer` header. It is held only in
//! [`GitHubToken`], which has no `Display`, renders as `<redacted>` under
//! `Debug`, and lends its bytes only through a callback at the HTTP boundary.
//! Neither error vocabulary borrows caller or credential input: both are closed
//! C-like enums, so either is safe to log next to the request it came from.
//!
//! # Separation of building from sending
//!
//! [`GitHubOperation`] renders the exact method, path and body without a
//! socket, and the `decode_*` functions parse the exact wire response the same
//! way. [`GitHubClient`] is only the composition of the two around one bounded
//! HTTP call, so the whole contract is provable against fixtures and against a
//! loopback fake.
//!
//! # A GitHub error is an answer, not a failure
//!
//! GitHub reports a refusal as a non-2xx status with a JSON `message`. That is
//! a well-formed answer, so it is decoded into [`GitHubOutcome::Rejected`] with
//! the status classified by [`RejectionKind`] — a revoked token, an
//! insufficient scope, a spent rate limit and a missing repository are told
//! apart, which is the distinction the legacy client's error helper exists to
//! make. Only a response that is not the contract at all is a
//! [`GitHubFailure`].
//!
//! # Divergences from the legacy TypeScript client
//!
//! The contract was taken from a live JavaScript client whose normalizers are
//! *lossy*, and from an issue store that repairs as it reads. This crate
//! refuses instead:
//!
//! * a missing `number`, `title`, `state` or timestamp is
//!   [`GitHubFailure::MissingField`], where the legacy mapper substitutes `0`,
//!   `""` or `"open"`;
//! * an item whose `html_url` cannot be attributed to an owner and repository
//!   is refused, where the legacy search mapper keeps it with empty strings;
//! * a comment `visibility` is read through [`IssueComment::visibility`], which
//!   answers [`CommentVisibility::Internal`] when the field is absent, so an
//!   unmarked comment can never be published to a client by omission.
//!
//! Two legacy behaviours are deliberately *not* reproduced. The client does not
//! sleep and retry on a rate limit: [`RateLimit`] and
//! [`GitHubRejection::retry_after_seconds`] are carried back on every call so
//! the scheduling layer above can decide, rather than a connector blocking a
//! bounded budget for up to eight seconds of its own accord. And the checklist
//! *inference* heuristic stays out: [`ChecklistItem`] normalizes items a caller
//! already has, and turning a support transcript into a checklist is a later
//! refinement that belongs beside the transcript model, not here.

mod client;
mod draft;
mod management;
mod repo_map;
mod request;
mod response;
mod target;
mod ticket;
mod token;
mod version;

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

pub use client::{GITHUB_ACCEPT, GITHUB_API_VERSION, GITHUB_USER_AGENT, GitHubClient};
pub use draft::{
    Attribution, ChecklistItem, MAX_CHECKLIST_ITEM_CHARS, MAX_CHECKLIST_ITEMS, MAX_EXCHANGE_BYTES,
    MAX_THREAD_ID_BYTES, MAX_TICKET_EXCHANGES, MAX_TICKET_REFERENCES, MIN_CHECKLIST_ITEM_CHARS,
    SUPPORT_THREAD_MARKER_PREFIX, SUPPORT_THREAD_MARKER_SUFFIX, ThreadId, TicketDraft,
    TicketExchange, body_carries_marker, marker_thread_id,
};
pub use management::{
    DatabaseId, IssueManagementPatch, LabelColor, LockReason, MAX_MANAGEMENT_NAME_BYTES,
    MAX_MANAGEMENT_OPERATIONS, MAX_MANAGEMENT_TEXT_BYTES, ManagementName, ManagementReceipt,
    ManagementRequest, ManagementText, ProjectFieldType, ProjectItemType, ProjectOwner,
    ProjectOwnerKind, ProjectRef, ProjectStatus, ProjectViewLayout,
};
pub use repo_map::{
    MAX_REPO_RULES, MAX_SCOPE_IDENTIFIER_BYTES, RepoMap, RepoRule, SiteId, TenantId,
};
pub use request::{
    CommentRequest, CreateIssueRequest, CreatePullRequestRequest, GetBranchRequest,
    GetCommentsRequest, GetIssueCommentRequest, GetIssueRequest, GetPullRequestRequest,
    GetRepositoryRequest, GetWorkflowRunRequest, GitHubOperation, HeadRevision, HttpMethod,
    IssueFilter, IssueListState, ListIssuesRequest, ListLabelsRequest, ListPullRequestsRequest,
    MAX_LIST_PAGE, MAX_SEARCH_PAGE, MergePullRequestRequest, Page, ReplaceLabelsRequest,
    RerunWorkflowRequest, SearchIssuesRequest, SetStateRequest, Since, UpdateIssueBodyRequest,
    UpdateIssueCommentRequest, UpdatePullRequestRequest,
};
pub use response::{
    CommentRef, GitHubBranch, GitHubComment, GitHubIssue, GitHubMergeReceipt, GitHubPullRequest,
    GitHubPullRequestRef, GitHubReply, GitHubRepository, GitHubWorkflowRun, IssueListPage,
    IssueSearchPage, MAX_COMMENT_COUNT, MAX_PULL_REQUEST_MATCHES, MAX_SEARCH_TOTAL,
    PullRequestLifecycle, PullRequestMergeability, Viewer, WorkflowRunStatus, decode_branch,
    decode_comment, decode_comment_ref, decode_comments, decode_error_message, decode_issue,
    decode_issue_list, decode_issue_ref, decode_labels, decode_merge_receipt, decode_pull_request,
    decode_pull_request_matches, decode_pull_request_ref, decode_repository,
    decode_repository_labels, decode_search, decode_viewer, decode_workflow_run,
};
pub use target::{
    BranchName, CommentId, GITHUB_API_ORIGIN, GitHubBase, IssueLocator, IssueNumber, IssueState,
    Label, MAX_BRANCH_BYTES, MAX_ISSUE_NUMBER, MAX_LABEL_BYTES, MAX_OWNER_BYTES, MAX_REPO_BYTES,
    Owner, Repo, RepoTarget, WorkflowRunId,
};
pub use ticket::{
    CommentKind, CommentVisibility, GithubLink, IssueBodyText, IssueComment, IssuePriority,
    IssueSource, IssueStatus, IssueTitle, MAX_COMMENT_BODY_BYTES, MAX_LABEL_SCOPE_CHARS,
    MAX_TICKET_ID_BYTES, MAX_TICKET_NAME_BYTES, TenantIssue, ticket_labels,
};
pub use token::{GitHubAuthorization, GitHubToken, MAX_GITHUB_TOKEN_BYTES};
pub use version::{EntityTag, MAX_ENTITY_TAG_BYTES, Versioned};

/// Longest response body accepted, before any field is read.
///
/// A page is at most [`MAX_PER_PAGE`] items and an issue body is at most
/// [`MAX_ISSUE_BODY_BYTES`], so a maximal page of maximal bodies does not fit
/// here. That is deliberate: the ceiling bounds what this process will buffer,
/// and a caller who genuinely needs pages of full-length bodies asks for a
/// smaller `per_page` rather than teaching the connector to stream.
pub const MAX_GITHUB_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Most items GitHub will return on one page, and the most this crate accepts
/// back. Both directions share the bound, so a server answering with more rows
/// than were asked for is refused.
pub const MAX_PER_PAGE: usize = 100;

/// Whole-request budget for one GitHub call.
///
/// The legacy client aborts each attempt at eight seconds; the same budget
/// covers connect, TLS, request and response here.
pub const GITHUB_REQUEST_TIMEOUT_SECONDS: u64 = 8;

/// Longest bounded server-supplied message retained from a rejection.
pub const MAX_SERVER_MESSAGE_BYTES: usize = 180;

/// Longest issue body accepted in either direction, matching GitHub's own
/// limit on the field.
pub const MAX_ISSUE_BODY_BYTES: usize = 65_536;

/// Longest issue title accepted, matching the legacy store's own truncation
/// point — except that an over-long title is refused here rather than cut.
pub const MAX_ISSUE_TITLE_BYTES: usize = 300;

/// Most labels accepted on one issue, in either direction.
pub const MAX_ISSUE_LABELS: usize = 60;

/// Longest search query accepted.
pub const MAX_SEARCH_QUERY_BYTES: usize = 256;

/// Longest account login retained, per GitHub's own username limit.
pub const MAX_LOGIN_BYTES: usize = 39;

/// Longest URL retained from a response.
pub const MAX_URL_BYTES: usize = 512;

/// Longest timestamp retained from a response.
pub const MAX_TIMESTAMP_BYTES: usize = 60;

/// Closed refusals raised while *building* a request or a draft, before any
/// I/O.
///
/// Each names the field that was wrong and never its value, so a refusal may be
/// logged beside the operator content it was built from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubRefusal {
    /// The base is not an origin this connector may address.
    Base,
    /// The token is empty, over-long, or outside the bearer-credential
    /// character set.
    Token,
    /// The repository owner is empty, over-long, or outside GitHub's grammar.
    Owner,
    /// The repository name is empty, over-long, or outside GitHub's grammar.
    Repo,
    /// The issue number is zero or past the accepted ceiling.
    IssueNumber,
    /// The issue comment id is zero.
    CommentId,
    /// The title is empty after trimming, over its ceiling, or control-bearing.
    Title,
    /// The body is empty, over [`MAX_ISSUE_BODY_BYTES`], or carries a control
    /// character other than tab, newline and carriage return.
    Body,
    /// A label is empty, over [`MAX_LABEL_BYTES`], control-bearing, or the set
    /// is over [`MAX_ISSUE_LABELS`].
    Label,
    /// The search query is empty, over [`MAX_SEARCH_QUERY_BYTES`], or
    /// control-bearing.
    Query,
    /// The page number or page size is outside its bound.
    Paging,
    /// The `since` filter is not a bounded printable timestamp.
    Since,
    /// The tenant id is empty, over-long, or not an opaque identifier.
    TenantId,
    /// The site id is empty, over-long, or not an opaque identifier.
    SiteId,
    /// The support thread id is outside the marker's identifier grammar.
    ThreadId,
    /// A checklist item is too short after normalization, or the list is over
    /// [`MAX_CHECKLIST_ITEMS`].
    Checklist,
    /// A bounded free-text field — an attribution line, a transcript entry, a
    /// requester name — is empty or outside its ceiling.
    Text,
    /// The repository map carries more rules than [`MAX_REPO_RULES`].
    Rules,
    /// An entity tag is empty, over-long, or not a quoted HTTP entity tag.
    EntityTag,
    /// A work-management identifier, value, or combination is invalid.
    Management,
    /// A workflow-run identifier is zero.
    WorkflowRunId,
    /// A branch name is empty, over-long, or outside the accepted grammar.
    BranchName,
    /// A merge names a head revision that is not a commit id.
    HeadRevision,
}

impl GitHubRefusal {
    /// Stable, content-free category for logging and metrics.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Token => "token",
            Self::Owner => "owner",
            Self::Repo => "repo",
            Self::IssueNumber => "issue_number",
            Self::CommentId => "comment_id",
            Self::Title => "title",
            Self::Body => "body",
            Self::Label => "label",
            Self::Query => "query",
            Self::Paging => "paging",
            Self::Since => "since",
            Self::TenantId => "tenant_id",
            Self::SiteId => "site_id",
            Self::ThreadId => "thread_id",
            Self::Checklist => "checklist",
            Self::Text => "text",
            Self::Rules => "rules",
            Self::EntityTag => "entity_tag",
            Self::Management => "management",
            Self::WorkflowRunId => "workflow_run_id",
            Self::BranchName => "branch_name",
            Self::HeadRevision => "head_revision",
        }
    }
}

impl fmt::Display for GitHubRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "github request refused: {}", self.category())
    }
}

impl Error for GitHubRefusal {}

/// Closed failures from issuing a call or reading its response.
///
/// Like [`GitHubRefusal`], no variant borrows input; a failure never carries a
/// credential, a repository name, or a ticket body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubFailure {
    /// DNS, connect, TLS, or an unclassified transport error.
    Unavailable,
    /// The bounded request budget elapsed.
    TimedOut,
    /// GitHub answered with a redirect.
    ///
    /// Redirects are not followed, and one from the locked origin is the shape
    /// of a call about to leave it, so it is named rather than folded into a
    /// rejection.
    Redirected,
    /// The response was not `application/json`.
    UnexpectedContentType,
    /// The response body exceeded [`MAX_GITHUB_RESPONSE_BYTES`].
    ResponseTooLarge,
    /// The body was not strict JSON, or not the shape the operation names.
    InvalidResponse,
    /// A field the operation's contract names was absent.
    MissingField,
    /// A field was present but outside its documented bound or grammar.
    FieldOutOfBounds,
    /// The page carried more items than were asked for, or more than
    /// [`MAX_PER_PAGE`].
    TooManyItems,
    /// The addressed number is a pull request rather than an issue.
    ///
    /// The `/issues` endpoints answer for both, so this is the shape of a
    /// caller working the wrong object, not of a broken response.
    NotAnIssue,
}

impl GitHubFailure {
    /// Stable, content-free category for logging and metrics.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::TimedOut => "timed_out",
            Self::Redirected => "redirected",
            Self::UnexpectedContentType => "unexpected_content_type",
            Self::ResponseTooLarge => "response_too_large",
            Self::InvalidResponse => "invalid_response",
            Self::MissingField => "missing_field",
            Self::FieldOutOfBounds => "field_out_of_bounds",
            Self::TooManyItems => "too_many_items",
            Self::NotAnIssue => "not_an_issue",
        }
    }
}

impl fmt::Display for GitHubFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "github call failed: {}", self.category())
    }
}

impl Error for GitHubFailure {}

/// A response that is not strictly valid JSON is one refusal, not a taxonomy.
///
/// The distinction that matters to a caller is that the response cannot be
/// trusted; which byte offended is a detail that would only reach a log line as
/// a fragment of a response body.
impl From<StrictJsonError> for GitHubFailure {
    fn from(_: StrictJsonError) -> Self {
        Self::InvalidResponse
    }
}

impl From<TransportFailure> for GitHubFailure {
    fn from(failure: TransportFailure) -> Self {
        match failure {
            TransportFailure::TimedOut => Self::TimedOut,
            TransportFailure::ResponseTooLarge => Self::ResponseTooLarge,
            TransportFailure::Unavailable => Self::Unavailable,
        }
    }
}

/// A bounded, control-free message GitHub supplied with a rejection.
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

/// What GitHub's refusal status means, told apart the way the legacy error
/// helper tells them apart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectionKind {
    /// 401 — the credential was not accepted at all.
    Unauthorized,
    /// 403 or 429 with the rate window spent, or a `retry-after`.
    RateLimited,
    /// 403 without a spent window — the token lacks the scope for this
    /// repository.
    Forbidden,
    /// 404 — no such repository or issue, or no read access to it.
    NotFound,
    /// 422 — GitHub parsed the request and refused its content.
    Validation,
    /// Any other non-2xx status.
    Other,
}

impl RejectionKind {
    /// Stable, content-free category for logging and metrics.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::RateLimited => "rate_limited",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Validation => "validation",
            Self::Other => "other",
        }
    }
}

/// GitHub's own refusal of an operation.
///
/// A rejection is a *parsed* answer, not a failure of this connector, which is
/// why it is an `Ok` outcome. The status is classified rather than reduced to
/// a boolean: a spent rate limit is an instruction to wait, a 403 without one
/// is an instruction to fix the token's scope, and a 401 is an instruction to
/// replace the token. Collapsing the three loses the only actionable part.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubRejection {
    status: u16,
    kind: RejectionKind,
    message: ServerMessage,
    retry_after_seconds: Option<u32>,
}

impl GitHubRejection {
    /// Classify one non-2xx answer.
    #[must_use]
    pub fn new(
        status: u16,
        message: ServerMessage,
        rate: &RateLimit,
        retry_after_seconds: Option<u32>,
    ) -> Self {
        let spent = rate.remaining() == Some(0) || retry_after_seconds.is_some();
        let kind = match status {
            401 => RejectionKind::Unauthorized,
            403 if spent => RejectionKind::RateLimited,
            403 => RejectionKind::Forbidden,
            404 => RejectionKind::NotFound,
            422 => RejectionKind::Validation,
            429 => RejectionKind::RateLimited,
            _ => RejectionKind::Other,
        };
        Self {
            status,
            kind,
            message,
            retry_after_seconds,
        }
    }

    /// The status GitHub answered with.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// What the status means.
    #[must_use]
    pub const fn kind(&self) -> RejectionKind {
        self.kind
    }

    /// GitHub's bounded reason.
    #[must_use]
    pub const fn message(&self) -> &ServerMessage {
        &self.message
    }

    /// The `retry-after` GitHub asked for, when it named one.
    ///
    /// Carried rather than obeyed: this connector never sleeps inside a request
    /// budget, so the wait is the caller's to schedule.
    #[must_use]
    pub const fn retry_after_seconds(&self) -> Option<u32> {
        self.retry_after_seconds
    }
}

/// The rate-limit window GitHub reported alongside an answer.
///
/// Every call carries one back, accepted or rejected, because the only way to
/// tell a scope failure from an exhausted window is to read it — and because a
/// caller that can see the window coming can stop before it spends it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RateLimit {
    remaining: Option<u32>,
    limit: Option<u32>,
    reset: Option<u64>,
}

impl RateLimit {
    /// Build a window from three already-parsed header values.
    #[must_use]
    pub const fn new(remaining: Option<u32>, limit: Option<u32>, reset: Option<u64>) -> Self {
        Self {
            remaining,
            limit,
            reset,
        }
    }

    /// Calls left in the window, when GitHub reported one.
    #[must_use]
    pub const fn remaining(&self) -> Option<u32> {
        self.remaining
    }

    /// Size of the window, when GitHub reported one.
    #[must_use]
    pub const fn limit(&self) -> Option<u32> {
        self.limit
    }

    /// Epoch second the window resets at, when GitHub reported one.
    #[must_use]
    pub const fn reset(&self) -> Option<u64> {
        self.reset
    }

    /// Whether the window is spent.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.remaining == Some(0)
    }
}

/// A well-formed GitHub answer: either the operation's payload, or GitHub's own
/// classified refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitHubOutcome<T> {
    /// GitHub accepted the operation and returned its payload.
    Accepted(T),
    /// GitHub refused with a non-2xx status and a bounded reason.
    Rejected(GitHubRejection),
}

impl<T> GitHubOutcome<T> {
    /// The payload, if GitHub accepted the operation.
    #[must_use]
    pub const fn accepted(&self) -> Option<&T> {
        match self {
            Self::Accepted(payload) => Some(payload),
            Self::Rejected(_) => None,
        }
    }

    /// The classified refusal, if GitHub refused.
    #[must_use]
    pub const fn rejected(&self) -> Option<&GitHubRejection> {
        match self {
            Self::Accepted(_) => None,
            Self::Rejected(rejection) => Some(rejection),
        }
    }
}

/// Whether text may be carried in a request body or a ticket draft.
///
/// Tab, newline and carriage return are admitted because an issue body is
/// Markdown and multi-line; every other control character is refused rather
/// than escaped, so neither a terminal nor a rendered ticket can be driven by
/// connector input.
pub(crate) fn is_body_text(text: &str, max_bytes: usize) -> bool {
    !text.is_empty()
        && text.len() <= max_bytes
        && !text
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

/// Whether text may be carried in a single-line field.
pub(crate) fn is_line_text(text: &str, max_bytes: usize) -> bool {
    !text.is_empty() && text.len() <= max_bytes && !text.chars().any(char::is_control)
}

/// Whether a value is a bounded opaque identifier.
///
/// ASCII graphic bytes only, excluding the JSON string metacharacters that make
/// a captured body ambiguous to read.
pub(crate) fn is_opaque_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\'))
}

/// Append one query-string value, percent-encoding everything outside RFC 3986
/// `unreserved`.
///
/// Deliberately stricter than a browser's `URLSearchParams`, which leaves `:`
/// and `/` bare and renders a space as `+`. Encoding the whole reserved set
/// means a search query cannot introduce a parameter, a fragment, or a second
/// path segment, whatever an operator types into it.
pub(crate) fn push_query_encoded(out: &mut String, value: &str) {
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_and_failure_categories_are_distinct_and_content_free() {
        let refusals = [
            GitHubRefusal::Base,
            GitHubRefusal::Token,
            GitHubRefusal::Owner,
            GitHubRefusal::Repo,
            GitHubRefusal::IssueNumber,
            GitHubRefusal::CommentId,
            GitHubRefusal::Title,
            GitHubRefusal::Body,
            GitHubRefusal::Label,
            GitHubRefusal::Query,
            GitHubRefusal::Paging,
            GitHubRefusal::Since,
            GitHubRefusal::TenantId,
            GitHubRefusal::SiteId,
            GitHubRefusal::ThreadId,
            GitHubRefusal::Checklist,
            GitHubRefusal::Text,
            GitHubRefusal::Rules,
            GitHubRefusal::EntityTag,
            GitHubRefusal::Management,
            GitHubRefusal::WorkflowRunId,
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
            GitHubFailure::Unavailable,
            GitHubFailure::TimedOut,
            GitHubFailure::Redirected,
            GitHubFailure::UnexpectedContentType,
            GitHubFailure::ResponseTooLarge,
            GitHubFailure::InvalidResponse,
            GitHubFailure::MissingField,
            GitHubFailure::FieldOutOfBounds,
            GitHubFailure::TooManyItems,
            GitHubFailure::NotAnIssue,
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
        let message = ServerMessage::sanitized("Bad\u{1b}[2J credentials\n");
        assert_eq!(message.as_str(), "Bad [2J credentials");
        let long = ServerMessage::sanitized(&"e\u{301}".repeat(MAX_SERVER_MESSAGE_BYTES));
        assert!(long.as_str().len() <= MAX_SERVER_MESSAGE_BYTES);
        assert!(long.as_str().chars().all(|c| c == 'e' || c == '\u{301}'));
    }

    #[test]
    fn a_rejection_tells_a_spent_window_apart_from_a_missing_scope() {
        let spent = RateLimit::new(Some(0), Some(5000), Some(1_760_000_000));
        let fresh = RateLimit::new(Some(4999), Some(5000), Some(1_760_000_000));
        let message = ServerMessage::sanitized("nope");
        let kind = |status, rate: &RateLimit, retry| {
            GitHubRejection::new(status, message.clone(), rate, retry).kind()
        };
        assert_eq!(kind(401, &fresh, None), RejectionKind::Unauthorized);
        assert_eq!(kind(403, &spent, None), RejectionKind::RateLimited);
        assert_eq!(kind(403, &fresh, Some(30)), RejectionKind::RateLimited);
        assert_eq!(kind(403, &fresh, None), RejectionKind::Forbidden);
        assert_eq!(kind(404, &fresh, None), RejectionKind::NotFound);
        assert_eq!(kind(422, &fresh, None), RejectionKind::Validation);
        assert_eq!(kind(429, &fresh, None), RejectionKind::RateLimited);
        assert_eq!(kind(500, &fresh, None), RejectionKind::Other);
        assert!(spent.is_exhausted());
        assert!(!fresh.is_exhausted());
        assert!(!RateLimit::default().is_exhausted());
    }

    #[test]
    fn a_rejection_carries_the_wait_it_was_told_rather_than_taking_it() {
        let rejection = GitHubRejection::new(
            403,
            ServerMessage::sanitized("API rate limit exceeded"),
            &RateLimit::new(Some(0), Some(60), Some(1_760_000_060)),
            Some(45),
        );
        assert_eq!(rejection.status(), 403);
        assert_eq!(rejection.kind(), RejectionKind::RateLimited);
        assert_eq!(rejection.retry_after_seconds(), Some(45));
        assert_eq!(rejection.message().as_str(), "API rate limit exceeded");
    }

    #[test]
    fn body_text_admits_markdown_and_refuses_control_bytes() {
        assert!(is_body_text("## Titre\n- [ ] faire\r\n", 64));
        assert!(!is_body_text("", 64));
        assert!(!is_body_text("bell\u{7}", 64));
        assert!(is_body_text(&"a".repeat(64), 64));
        assert!(!is_body_text(&"a".repeat(65), 64));
        assert!(is_line_text("une ligne", 64));
        assert!(!is_line_text("deux\nlignes", 64));
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
    fn query_encoding_leaves_no_reserved_byte_bare() {
        let mut rendered = String::new();
        push_query_encoded(&mut rendered, "repo:example-org/example-repo is:issue");
        assert_eq!(
            rendered, "repo%3Aexample-org%2Fexample-repo%20is%3Aissue",
            "a query may never introduce a path segment or a parameter"
        );
        let mut hostile = String::new();
        push_query_encoded(&mut hostile, "a&b=c#d/../e");
        assert_eq!(hostile, "a%26b%3Dc%23d%2F..%2Fe");
        let mut unreserved = String::new();
        push_query_encoded(&mut unreserved, "aZ09-._~");
        assert_eq!(unreserved, "aZ09-._~");
    }

    #[test]
    fn an_outcome_exposes_exactly_one_side() {
        let accepted: GitHubOutcome<u8> = GitHubOutcome::Accepted(7);
        assert_eq!(accepted.accepted(), Some(&7));
        assert!(accepted.rejected().is_none());
        let rejected: GitHubOutcome<u8> = GitHubOutcome::Rejected(GitHubRejection::new(
            404,
            ServerMessage::sanitized("Not Found"),
            &RateLimit::default(),
            None,
        ));
        assert!(rejected.accepted().is_none());
        assert_eq!(
            rejected.rejected().map(|value| value.message().as_str()),
            Some("Not Found")
        );
    }
}
