// SPDX-License-Identifier: Elastic-2.0

//! Bounded, refusing decoders for the issue and Actions read operations.
//!
//! Each decoder takes the accepted response bytes and returns either the
//! operation's typed payload or a [`GitHubFailure`]. Nothing panics on hostile
//! input and nothing is silently repaired. A non-2xx answer never reaches these
//! functions: the client classifies it into a [`crate::GitHubRejection`] first,
//! because GitHub's refusal is a different document from its payload.
//!
//! # Why these refuse where the legacy client repairs
//!
//! The TypeScript mapper this contract came from substitutes rather than
//! refuses. `Number(it?.number) || 0` turns an unreadable number into issue
//! zero; `String(it?.title || "")` turns a missing title into a blank one;
//! `String(it?.state || "open")` reports a closed issue as open when the field
//! is unreadable; and the search mapper keeps an item whose `html_url` it could
//! not parse, with an empty owner and repository — an issue that then cannot be
//! addressed again. Each of those turns a contract break into a plausible
//! answer. Here every field the contract names is required, and its absence is
//! [`GitHubFailure::MissingField`].
//!
//! Two absences are *not* contract breaks and are decoded as the empty value
//! they mean: an issue `body` may be `null` (GitHub's spelling of "no body")
//! and `closed_at` is `null` while an issue is open.
//!
//! Unknown extra fields are tolerated. GitHub adds top-level fields on its own
//! schedule and refusing them would couple this connector to an API release.
//!
//! # Reading labels is looser than writing them
//!
//! An outbound [`crate::Label`] refuses a comma, because a label carrying one
//! cannot be named in GitHub's own `labels` filter. An *inbound* label is kept
//! as a bounded string instead: a human may already have put a comma in a label
//! on the repository, and refusing to read their issue over it would be this
//! connector inventing a rule GitHub does not have.

use automonique_connector_substrate::json::strict_json;
use serde_json::{Map, Value};

use crate::target::{IssueLocator, IssueNumber, IssueState, MAX_LABEL_BYTES, RepoTarget};
use crate::{
    GitHubFailure, GitHubOutcome, MAX_GITHUB_RESPONSE_BYTES, MAX_ISSUE_BODY_BYTES,
    MAX_ISSUE_LABELS, MAX_ISSUE_TITLE_BYTES, MAX_LOGIN_BYTES, MAX_PER_PAGE, MAX_TIMESTAMP_BYTES,
    MAX_URL_BYTES, RateLimit, ServerMessage,
};

/// Highest comment count retained.
pub const MAX_COMMENT_COUNT: u64 = 100_000;

/// Highest search total retained.
pub const MAX_SEARCH_TOTAL: u64 = 100_000_000;

/// One answer from GitHub: the rate-limit window it reported, and either the
/// payload or its classified refusal.
///
/// The window rides along on both sides because the only way to tell an
/// exhausted budget from a missing scope is to read it, and because a caller
/// that watches it can stop before it spends the last call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubReply<T> {
    rate: RateLimit,
    outcome: GitHubOutcome<T>,
}

impl<T> GitHubReply<T> {
    /// Bind one window to one outcome.
    #[must_use]
    pub const fn new(rate: RateLimit, outcome: GitHubOutcome<T>) -> Self {
        Self { rate, outcome }
    }

    /// The rate-limit window GitHub reported.
    #[must_use]
    pub const fn rate(&self) -> &RateLimit {
        &self.rate
    }

    /// The outcome.
    #[must_use]
    pub const fn outcome(&self) -> &GitHubOutcome<T> {
        &self.outcome
    }

    /// The payload, if GitHub accepted the operation.
    #[must_use]
    pub const fn accepted(&self) -> Option<&T> {
        self.outcome.accepted()
    }

    /// The classified refusal, if GitHub refused.
    #[must_use]
    pub const fn rejected(&self) -> Option<&crate::GitHubRejection> {
        self.outcome.rejected()
    }

    /// Take the outcome, dropping the window.
    #[must_use]
    pub fn into_outcome(self) -> GitHubOutcome<T> {
        self.outcome
    }
}

/// One issue, as GitHub reports it.
///
/// `Debug` is derived rather than redacted: an issue is the operator-facing
/// payload this connector exists to move. A caller that logs one is logging
/// customer-adjacent data and must treat the record accordingly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubIssue {
    /// The repository, recovered from the issue's own web URL.
    pub target: RepoTarget,
    /// The issue number.
    pub number: IssueNumber,
    /// The title.
    pub title: String,
    /// Open or closed.
    pub state: IssueState,
    /// The web URL.
    pub url: String,
    /// The label names, in the order GitHub returned them.
    pub labels: Vec<String>,
    /// The author's login.
    pub author: String,
    /// How many comments the issue has — the count, not the bodies.
    pub comment_count: u32,
    /// Creation timestamp, verbatim.
    pub created_at: String,
    /// Last-update timestamp, verbatim.
    pub updated_at: String,
    /// Close timestamp, when the issue is closed.
    pub closed_at: Option<String>,
    /// The body. Empty when GitHub reports none.
    pub body: String,
}

/// One page of a repository's issues.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueListPage {
    /// The issues, in the order GitHub returned them.
    pub issues: Vec<GitHubIssue>,
    /// How many items on the page were pull requests.
    ///
    /// The `/issues` endpoints answer for pull requests too, so they are
    /// dropped — but the count is reported rather than the drop being silent,
    /// which is what lets a caller tell "no issues" from "nothing but pull
    /// requests".
    pub pull_requests_skipped: usize,
    /// Whether a full page came back, so there may be another.
    pub has_more: bool,
}

/// One page of a cross-repository search.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueSearchPage {
    /// The issues, in the order GitHub returned them.
    pub issues: Vec<GitHubIssue>,
    /// How many matches GitHub reports in total.
    pub total: u64,
    /// How many items on the page were pull requests.
    pub pull_requests_skipped: usize,
}

/// Canonical push-activity metadata for one repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubRepository {
    /// The repository named by GitHub's own `full_name` field.
    pub target: RepoTarget,
    /// The web URL.
    pub url: String,
    /// Last push timestamp, verbatim.
    pub pushed_at: String,
    /// Last repository-metadata update timestamp, verbatim.
    pub updated_at: String,
    /// Whether GitHub marks the repository archived.
    pub archived: bool,
    /// Whether GitHub marks the repository disabled.
    pub disabled: bool,
}

/// Closed workflow-run lifecycle values returned by GitHub Actions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowRunStatus {
    Queued,
    InProgress,
    Completed,
    Requested,
    Waiting,
    Pending,
}

impl WorkflowRunStatus {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "queued" => Some(Self::Queued),
            "in_progress" => Some(Self::InProgress),
            "completed" => Some(Self::Completed),
            "requested" => Some(Self::Requested),
            "waiting" => Some(Self::Waiting),
            "pending" => Some(Self::Pending),
            _ => None,
        }
    }
}

/// The immutable and monotonic fields needed to reconcile one workflow rerun.
///
/// The adapter intentionally retains neither logs nor workflow inputs. A later
/// `run_attempt` on the same `id` and `head_sha` is the only positive evidence
/// that an ambiguous rerun request took effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubWorkflowRun {
    pub id: crate::WorkflowRunId,
    pub head_sha: String,
    pub run_attempt: u32,
    pub status: WorkflowRunStatus,
}

/// One comment on an issue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubComment {
    /// GitHub's own comment id.
    ///
    /// Required, unlike in the legacy mapper: it is the only identity stable
    /// across an edit, and a mirror keyed on `(author, created_at)` mistakes an
    /// edited comment for a new one.
    pub id: u64,
    /// The author's login.
    pub author: String,
    /// The comment body.
    pub body: String,
    /// Creation timestamp, verbatim.
    pub created_at: String,
    /// Last-update timestamp, verbatim.
    pub updated_at: String,
}

/// The comment a create returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommentRef {
    /// GitHub's own comment id.
    pub id: u64,
    /// The comment's web URL.
    pub url: String,
}

/// Who the credential belongs to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Viewer {
    /// The account login.
    pub login: String,
}

/// Decode one issue object — the answer to a create, a state change or a read.
///
/// # Errors
///
/// Returns [`GitHubFailure::InvalidResponse`] for a body that is not strict
/// JSON or not an object, [`GitHubFailure::MissingField`] for an absent
/// contract field, [`GitHubFailure::FieldOutOfBounds`] for one past its ceiling
/// or outside its grammar, and [`GitHubFailure::NotAnIssue`] when the object is
/// a pull request.
pub fn decode_issue(bytes: &[u8]) -> Result<GitHubIssue, GitHubFailure> {
    let object = envelope(bytes)?;
    if is_pull_request(&object) {
        return Err(GitHubFailure::NotAnIssue);
    }
    issue(&object)
}

/// Decode one issue object returned by a mutation.
///
/// The same document as [`decode_issue`]; named apart so a caller reads the
/// create and patch paths as returning the issue they just changed rather than
/// an unrelated read.
///
/// # Errors
///
/// As [`decode_issue`].
pub fn decode_issue_ref(bytes: &[u8]) -> Result<GitHubIssue, GitHubFailure> {
    decode_issue(bytes)
}

/// Decode one page of a repository's issues.
///
/// # Errors
///
/// As [`decode_issue`], plus [`GitHubFailure::TooManyItems`] for a page longer
/// than was asked for.
pub fn decode_issue_list(bytes: &[u8], per_page: u32) -> Result<IssueListPage, GitHubFailure> {
    let rows = array(bytes, per_page)?;
    let has_more = rows.len() == per_page as usize;
    let (issues, pull_requests_skipped) = issues(&rows)?;
    Ok(IssueListPage {
        issues,
        pull_requests_skipped,
        has_more,
    })
}

/// Decode one page of a cross-repository search.
///
/// # Errors
///
/// As [`decode_issue_list`].
pub fn decode_search(bytes: &[u8], per_page: u32) -> Result<IssueSearchPage, GitHubFailure> {
    let object = envelope(bytes)?;
    let total = object
        .get("total_count")
        .ok_or(GitHubFailure::MissingField)?
        .as_u64()
        .ok_or(GitHubFailure::FieldOutOfBounds)?;
    if total > MAX_SEARCH_TOTAL {
        return Err(GitHubFailure::FieldOutOfBounds);
    }
    let rows = object
        .get("items")
        .ok_or(GitHubFailure::MissingField)?
        .as_array()
        .ok_or(GitHubFailure::InvalidResponse)?;
    if rows.len() > per_page as usize || rows.len() > MAX_PER_PAGE {
        return Err(GitHubFailure::TooManyItems);
    }
    let (issues, pull_requests_skipped) = issues(rows)?;
    Ok(IssueSearchPage {
        issues,
        total,
        pull_requests_skipped,
    })
}

/// Decode one page of an issue's comments.
///
/// # Errors
///
/// As [`decode_issue_list`].
pub fn decode_comments(bytes: &[u8], per_page: u32) -> Result<Vec<GitHubComment>, GitHubFailure> {
    let rows = array(bytes, per_page)?;
    let mut comments = Vec::with_capacity(rows.len());
    for row in &rows {
        comments.push(comment(
            row.as_object().ok_or(GitHubFailure::InvalidResponse)?,
        )?);
    }
    Ok(comments)
}

/// Decode one issue comment returned by a read or update.
///
/// # Errors
///
/// As [`decode_comments`], for one object rather than a page.
pub fn decode_comment(bytes: &[u8]) -> Result<GitHubComment, GitHubFailure> {
    let object = envelope(bytes)?;
    comment(&object)
}

/// Decode the comment a create returned.
///
/// # Errors
///
/// As [`decode_issue`].
pub fn decode_comment_ref(bytes: &[u8]) -> Result<CommentRef, GitHubFailure> {
    let object = envelope(bytes)?;
    Ok(CommentRef {
        id: identifier(&object, "id")?,
        url: bounded(&object, "html_url", MAX_URL_BYTES)?,
    })
}

/// Decode the complete label set a replace returned.
///
/// # Errors
///
/// As [`decode_issue_list`], for the label array's own ceiling.
pub fn decode_labels(bytes: &[u8]) -> Result<Vec<String>, GitHubFailure> {
    let rows = array(bytes, MAX_ISSUE_LABELS as u32)?;
    label_names(&Value::Array(rows))
}

/// Decode one requested page of repository labels.
///
/// Repository label pages may contain up to [`MAX_PER_PAGE`] rows, unlike an
/// issue's own label set, which is bounded by [`MAX_ISSUE_LABELS`].
///
/// # Errors
///
/// As [`decode_labels`], plus [`GitHubFailure::TooManyItems`] when the server
/// returned more rows than requested.
pub fn decode_repository_labels(bytes: &[u8], per_page: u32) -> Result<Vec<String>, GitHubFailure> {
    let rows = array(bytes, per_page)?;
    label_names_bounded(&Value::Array(rows), per_page as usize)
}

/// Decode the account a credential belongs to.
///
/// # Errors
///
/// As [`decode_issue`].
pub fn decode_viewer(bytes: &[u8]) -> Result<Viewer, GitHubFailure> {
    let object = envelope(bytes)?;
    Ok(Viewer {
        login: nonempty(&object, "login", MAX_LOGIN_BYTES)?,
    })
}

/// Decode one repository metadata document.
///
/// # Errors
///
/// As [`decode_issue`]. The repository coordinate is recovered from
/// `full_name`, so a mismatched or unaddressable response cannot be mistaken
/// for the requested repository by a caller.
pub fn decode_repository(bytes: &[u8]) -> Result<GitHubRepository, GitHubFailure> {
    let object = envelope(bytes)?;
    let full_name = nonempty(
        &object,
        "full_name",
        crate::MAX_OWNER_BYTES + crate::MAX_REPO_BYTES + 1,
    )?;
    let (owner, repo) = full_name
        .split_once('/')
        .ok_or(GitHubFailure::FieldOutOfBounds)?;
    if repo.contains('/') {
        return Err(GitHubFailure::FieldOutOfBounds);
    }
    let target = RepoTarget::parse(owner, repo).map_err(|_| GitHubFailure::FieldOutOfBounds)?;
    Ok(GitHubRepository {
        target,
        url: nonempty(&object, "html_url", MAX_URL_BYTES)?,
        pushed_at: timestamp(&object, "pushed_at")?,
        updated_at: timestamp(&object, "updated_at")?,
        archived: boolean(&object, "archived")?,
        disabled: boolean(&object, "disabled")?,
    })
}

/// Decode the exact workflow-run fields used by rerun reconciliation.
///
/// Unknown fields are ignored, but every retained field is required and
/// bounded. GitHub currently emits SHA-1 commit ids; 64 hexadecimal digits are
/// also admitted so a repository hash migration does not silently disable the
/// reconciliation fence.
pub fn decode_workflow_run(bytes: &[u8]) -> Result<GitHubWorkflowRun, GitHubFailure> {
    let object = envelope(bytes)?;
    let id = crate::WorkflowRunId::new(identifier(&object, "id")?)
        .map_err(|_| GitHubFailure::FieldOutOfBounds)?;
    let head_sha = nonempty(&object, "head_sha", 64)?;
    if !matches!(head_sha.len(), 40 | 64) || !head_sha.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(GitHubFailure::FieldOutOfBounds);
    }
    let run_attempt = object
        .get("run_attempt")
        .ok_or(GitHubFailure::MissingField)?
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or(GitHubFailure::FieldOutOfBounds)?;
    let status = WorkflowRunStatus::parse(required_str(&object, "status")?)
        .ok_or(GitHubFailure::FieldOutOfBounds)?;
    Ok(GitHubWorkflowRun {
        id,
        head_sha,
        run_attempt,
        status,
    })
}

/// Read GitHub's own message off a refusal document.
///
/// Never an error: a refusal that is HTML, empty, or missing its `message` is
/// still a refusal, and the status already carries the actionable part. The
/// stand-in names the status so a log line is never bare.
#[must_use]
pub fn decode_error_message(bytes: &[u8], status: u16) -> ServerMessage {
    let fallback = || ServerMessage::sanitized(&format!("github {status}"));
    if bytes.is_empty() || bytes.len() > MAX_GITHUB_RESPONSE_BYTES {
        return fallback();
    }
    strict_json(bytes)
        .ok()
        .and_then(|value| match value {
            Value::Object(object) => object
                .get("message")
                .and_then(Value::as_str)
                .map(ServerMessage::sanitized),
            _ => None,
        })
        .unwrap_or_else(fallback)
}

/// Read one bounded, strictly-parsed JSON object off the wire.
fn envelope(bytes: &[u8]) -> Result<Map<String, Value>, GitHubFailure> {
    if bytes.is_empty() || bytes.len() > MAX_GITHUB_RESPONSE_BYTES {
        return Err(GitHubFailure::ResponseTooLarge);
    }
    match strict_json(bytes)? {
        Value::Object(object) => Ok(object),
        _ => Err(GitHubFailure::InvalidResponse),
    }
}

/// Read one bounded, strictly-parsed JSON array off the wire.
fn array(bytes: &[u8], per_page: u32) -> Result<Vec<Value>, GitHubFailure> {
    if bytes.is_empty() || bytes.len() > MAX_GITHUB_RESPONSE_BYTES {
        return Err(GitHubFailure::ResponseTooLarge);
    }
    let Value::Array(rows) = strict_json(bytes)? else {
        return Err(GitHubFailure::InvalidResponse);
    };
    if rows.len() > per_page as usize || rows.len() > MAX_PER_PAGE {
        return Err(GitHubFailure::TooManyItems);
    }
    Ok(rows)
}

/// Whether an item from an `/issues` endpoint is really a pull request.
fn is_pull_request(row: &Map<String, Value>) -> bool {
    !matches!(row.get("pull_request"), None | Some(Value::Null))
}

/// Decode every issue of a page, counting the pull requests dropped.
fn issues(rows: &[Value]) -> Result<(Vec<GitHubIssue>, usize), GitHubFailure> {
    let mut issues = Vec::with_capacity(rows.len());
    let mut skipped = 0;
    for row in rows {
        let row = row.as_object().ok_or(GitHubFailure::InvalidResponse)?;
        if is_pull_request(row) {
            skipped += 1;
            continue;
        }
        issues.push(issue(row)?);
    }
    Ok((issues, skipped))
}

/// Decode one issue, requiring every field the contract names.
fn issue(row: &Map<String, Value>) -> Result<GitHubIssue, GitHubFailure> {
    let url = bounded(row, "html_url", MAX_URL_BYTES)?;
    // The repository is recovered from the issue's own URL rather than from the
    // request, so a search result — which names no repository anywhere else —
    // decodes by the same path as a read, and an item nobody could address
    // again is refused instead of kept with an empty owner.
    let locator = IssueLocator::parse(&url).ok_or(GitHubFailure::FieldOutOfBounds)?;
    let number = row
        .get("number")
        .ok_or(GitHubFailure::MissingField)?
        .as_u64()
        .ok_or(GitHubFailure::FieldOutOfBounds)?;
    let number = u32::try_from(number)
        .ok()
        .and_then(|number| IssueNumber::new(number).ok())
        .ok_or(GitHubFailure::FieldOutOfBounds)?;
    let state =
        IssueState::parse(&nonempty(row, "state", 16)?).ok_or(GitHubFailure::FieldOutOfBounds)?;
    let comment_count = row
        .get("comments")
        .ok_or(GitHubFailure::MissingField)?
        .as_u64()
        .ok_or(GitHubFailure::FieldOutOfBounds)?;
    if comment_count > MAX_COMMENT_COUNT {
        return Err(GitHubFailure::FieldOutOfBounds);
    }
    Ok(GitHubIssue {
        target: locator.target().clone(),
        number,
        title: nonempty(row, "title", MAX_ISSUE_TITLE_BYTES)?,
        state,
        url,
        labels: label_names(row.get("labels").ok_or(GitHubFailure::MissingField)?)?,
        author: login(row)?,
        comment_count: u32::try_from(comment_count).map_err(|_| GitHubFailure::FieldOutOfBounds)?,
        created_at: timestamp(row, "created_at")?,
        updated_at: timestamp(row, "updated_at")?,
        closed_at: optional_timestamp(row, "closed_at")?,
        body: optional_text(row, "body", MAX_ISSUE_BODY_BYTES)?,
    })
}

/// Decode one comment, requiring every field the contract names.
fn comment(row: &Map<String, Value>) -> Result<GitHubComment, GitHubFailure> {
    Ok(GitHubComment {
        id: identifier(row, "id")?,
        author: login(row)?,
        body: optional_text(row, "body", MAX_ISSUE_BODY_BYTES)?,
        created_at: timestamp(row, "created_at")?,
        updated_at: timestamp(row, "updated_at")?,
    })
}

/// The author's login, from the nested `user` object.
fn login(row: &Map<String, Value>) -> Result<String, GitHubFailure> {
    let user = row
        .get("user")
        .ok_or(GitHubFailure::MissingField)?
        .as_object()
        .ok_or(GitHubFailure::FieldOutOfBounds)?;
    nonempty(user, "login", MAX_LOGIN_BYTES)
}

/// The label names of a `labels` array.
///
/// GitHub answers with objects; the legacy mapper also accepts bare strings, so
/// both are read here.
fn label_names(value: &Value) -> Result<Vec<String>, GitHubFailure> {
    label_names_bounded(value, MAX_ISSUE_LABELS)
}

fn label_names_bounded(value: &Value, max_items: usize) -> Result<Vec<String>, GitHubFailure> {
    let rows = value.as_array().ok_or(GitHubFailure::InvalidResponse)?;
    if rows.len() > max_items || rows.len() > MAX_PER_PAGE {
        return Err(GitHubFailure::TooManyItems);
    }
    let mut names = Vec::with_capacity(rows.len());
    for row in rows {
        let name = match row {
            Value::String(name) => name.clone(),
            Value::Object(object) => object
                .get("name")
                .ok_or(GitHubFailure::MissingField)?
                .as_str()
                .ok_or(GitHubFailure::FieldOutOfBounds)?
                .to_owned(),
            _ => return Err(GitHubFailure::FieldOutOfBounds),
        };
        if name.is_empty() || name.len() > MAX_LABEL_BYTES || name.chars().any(char::is_control) {
            return Err(GitHubFailure::FieldOutOfBounds);
        }
        names.push(name);
    }
    Ok(names)
}

/// A required non-negative integer identifier.
fn identifier(object: &Map<String, Value>, key: &str) -> Result<u64, GitHubFailure> {
    object
        .get(key)
        .ok_or(GitHubFailure::MissingField)?
        .as_u64()
        .ok_or(GitHubFailure::FieldOutOfBounds)
}

/// A required boolean field.
fn boolean(object: &Map<String, Value>, key: &str) -> Result<bool, GitHubFailure> {
    object
        .get(key)
        .ok_or(GitHubFailure::MissingField)?
        .as_bool()
        .ok_or(GitHubFailure::FieldOutOfBounds)
}

/// A required string field, present and a string.
fn required_str<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, GitHubFailure> {
    object
        .get(key)
        .ok_or(GitHubFailure::MissingField)?
        .as_str()
        .ok_or(GitHubFailure::FieldOutOfBounds)
}

/// A required string field, bounded and control-free, that may be empty.
fn bounded(
    object: &Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<String, GitHubFailure> {
    let value = required_str(object, key)?;
    if value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(GitHubFailure::FieldOutOfBounds);
    }
    Ok(value.to_owned())
}

/// A required string field that may not be empty.
fn nonempty(
    object: &Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<String, GitHubFailure> {
    let value = bounded(object, key, max_bytes)?;
    if value.is_empty() {
        return Err(GitHubFailure::FieldOutOfBounds);
    }
    Ok(value)
}

/// A body-shaped field whose absence GitHub spells `null`.
///
/// Newlines are admitted — this is Markdown — but every other control character
/// is refused, so a body can never drive a terminal that prints it.
fn optional_text(
    object: &Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<String, GitHubFailure> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => {
            if value.len() > max_bytes
                || value.chars().any(|character| {
                    character.is_control() && !matches!(character, '\n' | '\r' | '\t')
                })
            {
                return Err(GitHubFailure::FieldOutOfBounds);
            }
            Ok(value.clone())
        }
        Some(_) => Err(GitHubFailure::FieldOutOfBounds),
    }
}

/// A required timestamp, retained verbatim.
///
/// GitHub documents these as ISO 8601, but this crate has no date type and
/// inventing a parser risks refusing an instant GitHub legitimately sends. The
/// value is checked for boundedness and printability and handed back unparsed;
/// interpreting it is the caller's, once the exact format is confirmed against
/// a captured response.
fn timestamp(object: &Map<String, Value>, key: &str) -> Result<String, GitHubFailure> {
    let value = required_str(object, key)?;
    if !is_timestamp(value) {
        return Err(GitHubFailure::FieldOutOfBounds);
    }
    Ok(value.to_owned())
}

/// A timestamp GitHub spells `null` while it does not apply.
fn optional_timestamp(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<String>, GitHubFailure> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if is_timestamp(value) => Ok(Some(value.clone())),
        Some(_) => Err(GitHubFailure::FieldOutOfBounds),
    }
}

fn is_timestamp(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TIMESTAMP_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One complete issue object, carrying every field the contract names.
    fn issue_json() -> String {
        String::from(
            r###"{"number":42,"title":"Panne de paiement","state":"open",
               "html_url":"https://github.com/example-org/example-repo/issues/42",
               "labels":[{"name":"tenant:Milo"},{"name":"prio:high"}],
               "user":{"login":"octocat"},"comments":3,
               "created_at":"2026-08-10T09:12:00Z","updated_at":"2026-08-13T17:04:11Z",
               "closed_at":null,"body":"## Attribution\n- **Canal :** email"}"###,
        )
    }

    fn comment_json() -> String {
        String::from(
            r#"{"id":9001,"user":{"login":"octocat"},"body":"merci",
               "created_at":"2026-08-13T17:04:11Z","updated_at":"2026-08-13T17:05:11Z"}"#,
        )
    }

    fn repository_json() -> String {
        String::from(
            r#"{"full_name":"example-org/example-repo",
               "html_url":"https://github.com/example-org/example-repo",
               "pushed_at":"2026-08-21T17:04:11Z",
               "updated_at":"2026-08-21T18:04:11Z",
               "archived":false,"disabled":false}"#,
        )
    }

    fn workflow_run_json() -> String {
        String::from(
            r#"{"id":99112233,"head_sha":"0123456789abcdef0123456789abcdef01234567",
               "run_attempt":3,"status":"completed"}"#,
        )
    }

    #[test]
    fn workflow_run_decoding_keeps_only_reconciliation_fields() {
        let run = decode_workflow_run(workflow_run_json().as_bytes()).expect("decode");
        assert_eq!(run.id, crate::WorkflowRunId::new(99_112_233).unwrap());
        assert_eq!(run.run_attempt, 3);
        assert_eq!(run.status, WorkflowRunStatus::Completed);
        assert_eq!(run.head_sha, "0123456789abcdef0123456789abcdef01234567");
    }

    #[test]
    fn workflow_run_decoding_refuses_missing_or_unusable_fences() {
        for key in ["id", "head_sha", "run_attempt", "status"] {
            let mut row: Value = serde_json::from_str(&workflow_run_json()).expect("row");
            row.as_object_mut().expect("object").remove(key);
            assert_eq!(
                decode_workflow_run(row.to_string().as_bytes()),
                Err(GitHubFailure::MissingField),
                "dropping {key} must be refused"
            );
        }
        for (key, value) in [
            ("id", serde_json::json!(0)),
            ("head_sha", serde_json::json!("not-a-commit")),
            ("run_attempt", serde_json::json!(0)),
            ("status", serde_json::json!("mystery")),
        ] {
            let mut row: Value = serde_json::from_str(&workflow_run_json()).expect("row");
            row.as_object_mut()
                .expect("object")
                .insert(key.to_owned(), value);
            assert_eq!(
                decode_workflow_run(row.to_string().as_bytes()),
                Err(GitHubFailure::FieldOutOfBounds),
                "invalid {key} must be refused"
            );
        }
    }

    #[test]
    fn repository_metadata_decodes_canonical_push_activity() {
        let repository = decode_repository(repository_json().as_bytes()).expect("decode");
        assert_eq!(repository.target.to_string(), "example-org/example-repo");
        assert_eq!(
            repository.url,
            "https://github.com/example-org/example-repo"
        );
        assert_eq!(repository.pushed_at, "2026-08-21T17:04:11Z");
        assert_eq!(repository.updated_at, "2026-08-21T18:04:11Z");
        assert!(!repository.archived);
        assert!(!repository.disabled);
    }

    #[test]
    fn repository_metadata_refuses_missing_or_malformed_contract_fields() {
        for key in [
            "full_name",
            "html_url",
            "pushed_at",
            "updated_at",
            "archived",
            "disabled",
        ] {
            let mut row: Value = serde_json::from_str(&repository_json()).expect("row");
            row.as_object_mut().expect("object").remove(key);
            assert_eq!(
                decode_repository(row.to_string().as_bytes()),
                Err(GitHubFailure::MissingField),
                "dropping {key} must be refused"
            );
        }
        let mut row: Value = serde_json::from_str(&repository_json()).expect("row");
        row.as_object_mut().expect("object").insert(
            "full_name".to_owned(),
            Value::String("example-org/example-repo/escape".to_owned()),
        );
        assert_eq!(
            decode_repository(row.to_string().as_bytes()),
            Err(GitHubFailure::FieldOutOfBounds)
        );
    }

    #[test]
    fn a_complete_issue_decodes_every_contract_field() {
        let issue = decode_issue(issue_json().as_bytes()).expect("decode");
        assert_eq!(issue.target.to_string(), "example-org/example-repo");
        assert_eq!(issue.number.get(), 42);
        assert_eq!(issue.title, "Panne de paiement");
        assert_eq!(issue.state, IssueState::Open);
        assert_eq!(
            issue.url,
            "https://github.com/example-org/example-repo/issues/42"
        );
        assert_eq!(issue.labels, vec!["tenant:Milo", "prio:high"]);
        assert_eq!(issue.author, "octocat");
        assert_eq!(issue.comment_count, 3);
        assert_eq!(issue.created_at, "2026-08-10T09:12:00Z");
        assert_eq!(issue.updated_at, "2026-08-13T17:04:11Z");
        assert_eq!(issue.closed_at, None);
        assert_eq!(issue.body, "## Attribution\n- **Canal :** email");
        // The mutation decoder is the same document.
        assert_eq!(
            decode_issue_ref(issue_json().as_bytes()).expect("decode"),
            issue
        );
    }

    #[test]
    fn every_named_field_is_required_and_its_absence_is_a_typed_refusal() {
        for key in [
            "number",
            "title",
            "state",
            "html_url",
            "labels",
            "user",
            "comments",
            "created_at",
            "updated_at",
        ] {
            let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
            row.as_object_mut().expect("object").remove(key);
            assert_eq!(
                decode_issue(row.to_string().as_bytes()),
                Err(GitHubFailure::MissingField),
                "dropping {key} must be refused, not decoded"
            );
        }
        // The author's login is required through the nested object too.
        let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
        row.as_object_mut()
            .expect("object")
            .insert("user".to_owned(), serde_json::json!({}));
        assert_eq!(
            decode_issue(row.to_string().as_bytes()),
            Err(GitHubFailure::MissingField)
        );
    }

    #[test]
    fn the_two_genuinely_absent_fields_decode_as_the_empty_value_they_mean() {
        for absent in ["null", "missing"] {
            let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
            let object = row.as_object_mut().expect("object");
            if absent == "null" {
                object.insert("body".to_owned(), Value::Null);
            } else {
                object.remove("body");
            }
            let issue = decode_issue(row.to_string().as_bytes()).expect("decode");
            assert_eq!(issue.body, "");
            assert_eq!(issue.closed_at, None);
        }
        // A closed issue carries its close timestamp.
        let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
        let object = row.as_object_mut().expect("object");
        object.insert("state".to_owned(), Value::String("closed".to_owned()));
        object.insert(
            "closed_at".to_owned(),
            Value::String("2026-08-14T08:00:00Z".to_owned()),
        );
        let issue = decode_issue(row.to_string().as_bytes()).expect("decode");
        assert_eq!(issue.state, IssueState::Closed);
        assert_eq!(issue.closed_at.as_deref(), Some("2026-08-14T08:00:00Z"));
    }

    #[test]
    fn a_substituted_value_the_legacy_mapper_would_invent_is_refused() {
        let cases: [(&str, Value, GitHubFailure); 5] = [
            // `Number(it?.number) || 0`
            (
                "number",
                Value::String("42".to_owned()),
                GitHubFailure::FieldOutOfBounds,
            ),
            (
                "number",
                Value::Number(0.into()),
                GitHubFailure::FieldOutOfBounds,
            ),
            // `String(it?.title || "")`
            (
                "title",
                Value::String(String::new()),
                GitHubFailure::FieldOutOfBounds,
            ),
            // `String(it?.state || "open")`
            (
                "state",
                Value::String("merged".to_owned()),
                GitHubFailure::FieldOutOfBounds,
            ),
            // An unattributable URL — the legacy search keeps it with an empty owner.
            (
                "html_url",
                Value::String("https://example.invalid/x".to_owned()),
                GitHubFailure::FieldOutOfBounds,
            ),
        ];
        for (key, value, expected) in cases {
            let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
            row.as_object_mut()
                .expect("object")
                .insert(key.to_owned(), value.clone());
            assert_eq!(
                decode_issue(row.to_string().as_bytes()),
                Err(expected),
                "{key} = {value}"
            );
        }
    }

    #[test]
    fn a_pull_request_is_named_rather_than_decoded_as_an_issue() {
        let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
        row.as_object_mut().expect("object").insert(
            "pull_request".to_owned(),
            serde_json::json!({"url": "https://api.github.com/x"}),
        );
        assert_eq!(
            decode_issue(row.to_string().as_bytes()),
            Err(GitHubFailure::NotAnIssue)
        );
        // A null `pull_request` is not a pull request.
        let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
        row.as_object_mut()
            .expect("object")
            .insert("pull_request".to_owned(), Value::Null);
        assert!(decode_issue(row.to_string().as_bytes()).is_ok());
    }

    #[test]
    fn a_listing_drops_pull_requests_but_says_how_many() {
        let mut pull: Value = serde_json::from_str(&issue_json()).expect("row");
        pull.as_object_mut().expect("object").insert(
            "pull_request".to_owned(),
            serde_json::json!({"url": "https://api.github.com/x"}),
        );
        let body = format!("[{},{}]", issue_json(), pull);
        let page = decode_issue_list(body.as_bytes(), 50).expect("decode");
        assert_eq!(page.issues.len(), 1);
        assert_eq!(page.pull_requests_skipped, 1);
        assert!(!page.has_more, "a short page is the last page");

        // A full page means there may be another.
        let full = format!("[{},{}]", issue_json(), issue_json());
        let page = decode_issue_list(full.as_bytes(), 2).expect("decode");
        assert_eq!(page.issues.len(), 2);
        assert!(page.has_more);
    }

    #[test]
    fn a_page_longer_than_was_asked_for_is_refused() {
        let full = format!("[{},{}]", issue_json(), issue_json());
        assert_eq!(
            decode_issue_list(full.as_bytes(), 1),
            Err(GitHubFailure::TooManyItems)
        );
        let comments = format!("[{},{}]", comment_json(), comment_json());
        assert_eq!(
            decode_comments(comments.as_bytes(), 1),
            Err(GitHubFailure::TooManyItems)
        );
    }

    #[test]
    fn a_search_page_carries_its_total_and_recovers_each_repository() {
        let body = format!(
            r#"{{"total_count":7,"incomplete_results":false,"items":[{}]}}"#,
            issue_json()
        );
        let page = decode_search(body.as_bytes(), 30).expect("decode");
        assert_eq!(page.total, 7);
        assert_eq!(page.issues.len(), 1);
        assert_eq!(page.pull_requests_skipped, 0);
        assert_eq!(
            page.issues[0].target.to_string(),
            "example-org/example-repo",
            "a search item names its repository only in its URL"
        );

        assert_eq!(
            decode_search(br#"{"items":[]}"#, 30),
            Err(GitHubFailure::MissingField)
        );
        assert_eq!(
            decode_search(br#"{"total_count":1}"#, 30),
            Err(GitHubFailure::MissingField)
        );
    }

    #[test]
    fn comments_decode_with_the_identity_that_survives_an_edit() {
        let body = format!("[{}]", comment_json());
        let comments = decode_comments(body.as_bytes(), 100).expect("decode");
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].id, 9_001);
        assert_eq!(comments[0].author, "octocat");
        assert_eq!(comments[0].body, "merci");
        assert_eq!(comments[0].created_at, "2026-08-13T17:04:11Z");
        assert_eq!(comments[0].updated_at, "2026-08-13T17:05:11Z");

        // The legacy mapper tolerates a missing id; a mirror keyed without one
        // mistakes an edit for a new comment, so it is required here.
        let mut row: Value = serde_json::from_str(&comment_json()).expect("row");
        row.as_object_mut().expect("object").remove("id");
        assert_eq!(
            decode_comments(format!("[{row}]").as_bytes(), 100),
            Err(GitHubFailure::MissingField)
        );
    }

    #[test]
    fn a_created_comment_and_a_replaced_label_set_decode() {
        let reference = decode_comment_ref(
            br#"{"id":9001,"html_url":"https://github.com/example-org/example-repo/issues/42#issuecomment-9001"}"#,
        )
        .expect("decode");
        assert_eq!(reference.id, 9_001);
        assert!(reference.url.ends_with("#issuecomment-9001"));

        let labels =
            decode_labels(br#"[{"name":"prio:high"},{"name":"tenant:Milo"}]"#).expect("decode");
        assert_eq!(labels, vec!["prio:high", "tenant:Milo"]);
        // Bare strings are read too, matching the legacy mapper.
        assert_eq!(
            decode_labels(br#"["prio:high"]"#).expect("decode"),
            vec!["prio:high"]
        );
        assert_eq!(decode_labels(b"[]").expect("decode"), Vec::<String>::new());
        assert_eq!(
            decode_labels(br#"[{"colour":"f00"}]"#),
            Err(GitHubFailure::MissingField)
        );
    }

    #[test]
    fn an_inbound_label_may_carry_what_an_outbound_one_may_not() {
        // A human's label with a comma is readable, though this crate would
        // never write one.
        assert_eq!(
            decode_labels(br#"[{"name":"milo, sarl"}]"#).expect("decode"),
            vec!["milo, sarl"]
        );
        assert_eq!(
            decode_labels(br#"[{"name":"be\u0007ll"}]"#),
            Err(GitHubFailure::FieldOutOfBounds)
        );
        assert_eq!(
            decode_labels(br#"[{"name":""}]"#),
            Err(GitHubFailure::FieldOutOfBounds)
        );
    }

    #[test]
    fn the_viewer_decodes_and_names_the_account() {
        assert_eq!(
            decode_viewer(br#"{"login":"octocat","id":1}"#).expect("decode"),
            Viewer {
                login: "octocat".to_owned()
            }
        );
        assert_eq!(decode_viewer(br"{}"), Err(GitHubFailure::MissingField));
        assert_eq!(
            decode_viewer(br#"{"login":""}"#),
            Err(GitHubFailure::FieldOutOfBounds)
        );
    }

    #[test]
    fn malformed_bodies_are_typed_refusals_rather_than_panics() {
        let cases: [(&[u8], GitHubFailure); 7] = [
            (b"", GitHubFailure::ResponseTooLarge),
            (b"not json", GitHubFailure::InvalidResponse),
            (b"[]", GitHubFailure::InvalidResponse),
            (b"null", GitHubFailure::InvalidResponse),
            (
                br#"{"number":1}{"number":2}"#,
                GitHubFailure::InvalidResponse,
            ),
            (
                br#"{"number":1,"number":2,"title":"x"}"#,
                GitHubFailure::InvalidResponse,
            ),
            (br#"{"title":"x"}"#, GitHubFailure::MissingField),
        ];
        for (body, expected) in cases {
            assert_eq!(decode_issue(body), Err(expected), "body {body:?}");
        }
        assert_eq!(
            decode_issue_list(br#"{"issues":[]}"#, 50),
            Err(GitHubFailure::InvalidResponse)
        );
        assert_eq!(
            decode_issue_list(b"[7]", 50),
            Err(GitHubFailure::InvalidResponse)
        );
    }

    #[test]
    fn an_oversized_body_is_refused_before_a_field_is_read() {
        let oversized = vec![b'a'; MAX_GITHUB_RESPONSE_BYTES + 1];
        assert_eq!(
            decode_issue(&oversized),
            Err(GitHubFailure::ResponseTooLarge)
        );
        assert_eq!(
            decode_issue_list(&oversized, 50),
            Err(GitHubFailure::ResponseTooLarge)
        );
    }

    #[test]
    fn a_control_bearing_field_is_refused_so_a_row_cannot_drive_a_terminal() {
        let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
        row.as_object_mut().expect("object").insert(
            "title".to_owned(),
            Value::String("Panne\u{1b}[2J".to_owned()),
        );
        assert_eq!(
            decode_issue(row.to_string().as_bytes()),
            Err(GitHubFailure::FieldOutOfBounds)
        );
        // A body keeps its newlines and refuses everything else.
        let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
        row.as_object_mut()
            .expect("object")
            .insert("body".to_owned(), Value::String("a\u{7}b".to_owned()));
        assert_eq!(
            decode_issue(row.to_string().as_bytes()),
            Err(GitHubFailure::FieldOutOfBounds)
        );
    }

    #[test]
    fn every_field_ceiling_is_exact() {
        for (key, max) in [
            ("title", MAX_ISSUE_TITLE_BYTES),
            ("html_url", MAX_URL_BYTES),
        ] {
            for (width, expected) in [(max, true), (max + 1, false)] {
                let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
                let value = if key == "html_url" {
                    let prefix = "https://github.com/example-org/example-repo/issues/42?q=";
                    format!("{prefix}{}", "v".repeat(width - prefix.len()))
                } else {
                    "v".repeat(width)
                };
                row.as_object_mut()
                    .expect("object")
                    .insert(key.to_owned(), Value::String(value));
                assert_eq!(
                    decode_issue(row.to_string().as_bytes()).is_ok(),
                    expected,
                    "{key} at {width} bytes"
                );
            }
        }
        for (count, expected) in [(MAX_COMMENT_COUNT, true), (MAX_COMMENT_COUNT + 1, false)] {
            let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
            row.as_object_mut()
                .expect("object")
                .insert("comments".to_owned(), Value::Number(count.into()));
            assert_eq!(
                decode_issue(row.to_string().as_bytes()).is_ok(),
                expected,
                "comments {count}"
            );
        }
        let many: Vec<String> = (0..=MAX_ISSUE_LABELS)
            .map(|index| format!(r#"{{"name":"l{index}"}}"#))
            .collect();
        let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
        row.as_object_mut().expect("object").insert(
            "labels".to_owned(),
            serde_json::from_str(&format!("[{}]", many.join(","))).expect("labels"),
        );
        assert_eq!(
            decode_issue(row.to_string().as_bytes()),
            Err(GitHubFailure::TooManyItems)
        );
    }

    #[test]
    fn unknown_extra_fields_are_tolerated_so_an_api_release_does_not_break_a_read() {
        let mut row: Value = serde_json::from_str(&issue_json()).expect("row");
        row.as_object_mut().expect("object").insert(
            "sub_issues_summary".to_owned(),
            serde_json::json!({"total": 0}),
        );
        assert!(decode_issue(row.to_string().as_bytes()).is_ok());
    }

    #[test]
    fn a_refusal_document_yields_githubs_own_message_or_a_named_stand_in() {
        assert_eq!(
            decode_error_message(br#"{"message":"Bad credentials"}"#, 401).as_str(),
            "Bad credentials"
        );
        assert_eq!(
            decode_error_message(b"<html>maintenance</html>", 502).as_str(),
            "github 502"
        );
        assert_eq!(decode_error_message(b"", 500).as_str(), "github 500");
        assert_eq!(
            decode_error_message(br#"{"documentation_url":"https://docs.invalid"}"#, 422).as_str(),
            "github 422"
        );
        // Remote text is sanitized on the way in.
        assert_eq!(
            decode_error_message(br#"{"message":"Bad\u001b[2J credentials"}"#, 401).as_str(),
            "Bad [2J credentials"
        );
    }

    #[test]
    fn a_reply_exposes_the_window_on_both_sides() {
        let rate = RateLimit::new(Some(4_999), Some(5_000), Some(1_760_000_000));
        let accepted = GitHubReply::new(rate, GitHubOutcome::Accepted(7_u8));
        assert_eq!(accepted.accepted(), Some(&7));
        assert!(accepted.rejected().is_none());
        assert_eq!(accepted.rate().remaining(), Some(4_999));
        assert_eq!(accepted.outcome(), &GitHubOutcome::Accepted(7));
        assert_eq!(accepted.into_outcome(), GitHubOutcome::Accepted(7));

        let rejected: GitHubReply<u8> = GitHubReply::new(
            RateLimit::new(Some(0), Some(5_000), None),
            GitHubOutcome::Rejected(crate::GitHubRejection::new(
                403,
                ServerMessage::sanitized("API rate limit exceeded"),
                &RateLimit::new(Some(0), None, None),
                None,
            )),
        );
        assert!(rejected.accepted().is_none());
        assert_eq!(rejected.rate().remaining(), Some(0));
        assert!(rejected.rate().is_exhausted());
        assert_eq!(
            rejected.rejected().map(crate::GitHubRejection::kind),
            Some(crate::RejectionKind::RateLimited)
        );
    }
}
