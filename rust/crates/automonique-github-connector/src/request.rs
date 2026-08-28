// SPDX-License-Identifier: Elastic-2.0

//! The sixteen operations, and the exact method, path and body each renders.
//!
//! [`GitHubOperation`] is the second half of the target lock (the first is the
//! origin in `target`). A path is never a caller string: it is assembled here
//! from validated [`Owner`], [`Repo`] and [`IssueNumber`] values whose grammars
//! contain no `/`, `?` or `#`, and every query value is percent-encoded over
//! the full reserved set. A layer talked into asking for
//! `DELETE /repos/{o}/{r}` cannot spell it, because no variant exists.
//!
//! Field and parameter order is fixed and documented per operation, matching
//! the legacy client's own rendering. JSON objects and query strings are
//! order-insensitive to a server, so this is a testability property rather than
//! a protocol one: it lets a test assert one exact captured request instead of
//! a set of permutations.

use crate::target::{CommentId, IssueNumber, Label, RepoTarget, WorkflowRunId};
use crate::ticket::{IssueBodyText, IssueTitle};
use crate::{
    EntityTag, GitHubRefusal, IssueState, MAX_ISSUE_LABELS, MAX_PER_PAGE, MAX_SEARCH_QUERY_BYTES,
    MAX_TIMESTAMP_BYTES, push_json_string, push_query_encoded,
};

/// Highest page number accepted for a repository listing.
pub const MAX_LIST_PAGE: u32 = 1_000;

/// Highest page number accepted for a search.
///
/// GitHub's search API will not page past a thousand results, and the legacy
/// console clamps here; a request past it is refused rather than sent to be
/// refused.
pub const MAX_SEARCH_PAGE: u32 = 100;

/// The five verbs this connector can issue.
///
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    /// A read.
    Get,
    /// A create.
    Post,
    /// A partial update.
    Patch,
    /// A replace.
    Put,
    /// A typed deletion from the work-management surface.
    Delete,
}

impl HttpMethod {
    /// The exact wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Patch => "PATCH",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }

    /// Whether this verb carries a request body.
    #[must_use]
    pub const fn has_body(self) -> bool {
        !matches!(self, Self::Get | Self::Delete)
    }
}

/// One bounded page request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Page {
    number: u32,
    per_page: u32,
}

impl Page {
    /// Ask for page `number` of `per_page` items.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Paging`] for a zero page, a page over
    /// [`MAX_LIST_PAGE`], or a size outside `1..=`[`MAX_PER_PAGE`]. The legacy
    /// console silently clamps all three; a clamp hides a caller that believed
    /// it was paging.
    pub const fn new(number: u32, per_page: u32) -> Result<Self, GitHubRefusal> {
        if number == 0
            || number > MAX_LIST_PAGE
            || per_page == 0
            || per_page as usize > MAX_PER_PAGE
        {
            return Err(GitHubRefusal::Paging);
        }
        Ok(Self { number, per_page })
    }

    /// The page number.
    #[must_use]
    pub const fn number(self) -> u32 {
        self.number
    }

    /// The page size.
    #[must_use]
    pub const fn per_page(self) -> u32 {
        self.per_page
    }
}

/// A bounded `since` filter, carried verbatim.
///
/// GitHub documents this as an ISO 8601 instant. It is bounded and checked for
/// printability rather than parsed: this crate has no date type, and inventing
/// one here would risk refusing an instant GitHub accepts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Since(String);

impl Since {
    /// Validate one filter value.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Since`] for an empty value, one over
    /// [`MAX_TIMESTAMP_BYTES`], or one carrying anything but printable ASCII.
    pub fn new(value: &str) -> Result<Self, GitHubRefusal> {
        let value = value.trim();
        if value.is_empty()
            || value.len() > MAX_TIMESTAMP_BYTES
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(GitHubRefusal::Since);
        }
        Ok(Self(value.to_owned()))
    }

    /// The exact filter value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Which issues a listing covers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum IssueListState {
    /// Open issues only. GitHub's default, and this crate's.
    #[default]
    Open,
    /// Closed issues only.
    Closed,
    /// Both.
    All,
}

impl IssueListState {
    /// The exact wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::All => "all",
        }
    }
}

/// What a repository listing is narrowed to.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IssueFilter {
    state: IssueListState,
    since: Option<Since>,
    labels: Vec<Label>,
}

impl IssueFilter {
    /// List issues in this state.
    #[must_use]
    pub fn new(state: IssueListState) -> Self {
        Self {
            state,
            since: None,
            labels: Vec::new(),
        }
    }

    /// Only issues updated at or after this instant.
    #[must_use]
    pub fn with_since(mut self, since: Since) -> Self {
        self.since = Some(since);
        self
    }

    /// Only issues carrying *every* one of these labels.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Label`] for more than [`MAX_ISSUE_LABELS`].
    pub fn with_labels(mut self, labels: Vec<Label>) -> Result<Self, GitHubRefusal> {
        if labels.len() > MAX_ISSUE_LABELS {
            return Err(GitHubRefusal::Label);
        }
        self.labels = labels;
        Ok(self)
    }

    /// The state filter.
    #[must_use]
    pub const fn state(&self) -> IssueListState {
        self.state
    }

    /// The instant filter, when one is set.
    #[must_use]
    pub const fn since(&self) -> Option<&Since> {
        self.since.as_ref()
    }

    /// The label filter.
    #[must_use]
    pub fn labels(&self) -> &[Label] {
        &self.labels
    }
}

/// Open one issue on one repository. An externally visible effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateIssueRequest {
    target: RepoTarget,
    title: IssueTitle,
    body: IssueBodyText,
    labels: Vec<Label>,
}

impl CreateIssueRequest {
    /// Bind one repository to one title, body and label set.
    ///
    /// Labels are deduplicated in first-seen order, matching the legacy
    /// cleaning pass.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Label`] for more than [`MAX_ISSUE_LABELS`]
    /// distinct labels.
    pub fn new(
        target: RepoTarget,
        title: IssueTitle,
        body: IssueBodyText,
        labels: Vec<Label>,
    ) -> Result<Self, GitHubRefusal> {
        Ok(Self {
            target,
            title,
            body,
            labels: dedup_labels(labels)?,
        })
    }

    /// The repository.
    #[must_use]
    pub const fn target(&self) -> &RepoTarget {
        &self.target
    }

    /// The title.
    #[must_use]
    pub const fn title(&self) -> &IssueTitle {
        &self.title
    }

    /// The body.
    #[must_use]
    pub const fn body(&self) -> &IssueBodyText {
        &self.body
    }

    /// The labels.
    #[must_use]
    pub fn labels(&self) -> &[Label] {
        &self.labels
    }
}

/// Add one comment to one issue. An externally visible effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommentRequest {
    target: RepoTarget,
    number: IssueNumber,
    body: IssueBodyText,
}

impl CommentRequest {
    /// Bind one issue to one comment body.
    #[must_use]
    pub const fn new(target: RepoTarget, number: IssueNumber, body: IssueBodyText) -> Self {
        Self {
            target,
            number,
            body,
        }
    }

    /// The repository.
    #[must_use]
    pub const fn target(&self) -> &RepoTarget {
        &self.target
    }

    /// The issue.
    #[must_use]
    pub const fn number(&self) -> IssueNumber {
        self.number
    }

    /// The comment body.
    #[must_use]
    pub const fn body(&self) -> &IssueBodyText {
        &self.body
    }
}

/// Open or close one issue. An externally visible effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetStateRequest {
    target: RepoTarget,
    number: IssueNumber,
    state: IssueState,
}

impl SetStateRequest {
    /// Bind one issue to the state it should end in.
    #[must_use]
    pub const fn new(target: RepoTarget, number: IssueNumber, state: IssueState) -> Self {
        Self {
            target,
            number,
            state,
        }
    }

    /// The repository.
    #[must_use]
    pub const fn target(&self) -> &RepoTarget {
        &self.target
    }

    /// The issue.
    #[must_use]
    pub const fn number(&self) -> IssueNumber {
        self.number
    }

    /// The state asked for.
    #[must_use]
    pub const fn state(&self) -> IssueState {
        self.state
    }
}

/// Replace *every* label on one issue. An externally visible effect.
///
/// `PUT …/labels` is replace-all: the array becomes the issue's complete label
/// set. The type is named for what it does rather than for the verb, because a
/// caller who reads `set_labels` as "add these" removes every label a human put
/// there.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplaceLabelsRequest {
    target: RepoTarget,
    number: IssueNumber,
    labels: Vec<Label>,
}

impl ReplaceLabelsRequest {
    /// Bind one issue to its complete new label set.
    ///
    /// An empty set is admitted: it is the one way to clear an issue's labels,
    /// and refusing it would leave no way to do so.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Label`] for more than [`MAX_ISSUE_LABELS`]
    /// distinct labels.
    pub fn new(
        target: RepoTarget,
        number: IssueNumber,
        labels: Vec<Label>,
    ) -> Result<Self, GitHubRefusal> {
        Ok(Self {
            target,
            number,
            labels: dedup_labels(labels)?,
        })
    }

    /// The repository.
    #[must_use]
    pub const fn target(&self) -> &RepoTarget {
        &self.target
    }

    /// The issue.
    #[must_use]
    pub const fn number(&self) -> IssueNumber {
        self.number
    }

    /// The complete new label set.
    #[must_use]
    pub fn labels(&self) -> &[Label] {
        &self.labels
    }
}

/// Read one issue back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetIssueRequest {
    target: RepoTarget,
    number: IssueNumber,
}

impl GetIssueRequest {
    /// Name one issue.
    #[must_use]
    pub const fn new(target: RepoTarget, number: IssueNumber) -> Self {
        Self { target, number }
    }

    /// The repository.
    #[must_use]
    pub const fn target(&self) -> &RepoTarget {
        &self.target
    }

    /// The issue.
    #[must_use]
    pub const fn number(&self) -> IssueNumber {
        self.number
    }
}

/// Read one page of an issue's comments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetCommentsRequest {
    target: RepoTarget,
    number: IssueNumber,
    page: Page,
}

/// Read one repository-label page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListLabelsRequest {
    target: RepoTarget,
    page: Page,
}

impl ListLabelsRequest {
    /// Name one repository and one page of its labels.
    #[must_use]
    pub const fn new(target: RepoTarget, page: Page) -> Self {
        Self { target, page }
    }

    /// The repository.
    #[must_use]
    pub const fn target(&self) -> &RepoTarget {
        &self.target
    }

    /// The page.
    #[must_use]
    pub const fn page(&self) -> Page {
        self.page
    }
}

/// Read one issue comment and its current entity tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetIssueCommentRequest {
    target: RepoTarget,
    comment_id: CommentId,
}

impl GetIssueCommentRequest {
    /// Name one repository-scoped issue comment.
    #[must_use]
    pub const fn new(target: RepoTarget, comment_id: CommentId) -> Self {
        Self { target, comment_id }
    }

    /// The repository.
    #[must_use]
    pub const fn target(&self) -> &RepoTarget {
        &self.target
    }

    /// The comment id.
    #[must_use]
    pub const fn comment_id(&self) -> CommentId {
        self.comment_id
    }
}

/// Replace one issue body if it still has the version previously read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateIssueBodyRequest {
    target: RepoTarget,
    number: IssueNumber,
    body: IssueBodyText,
    if_match: EntityTag,
}

impl UpdateIssueBodyRequest {
    /// Bind an issue, complete new body, and previous entity tag.
    #[must_use]
    pub const fn new(
        target: RepoTarget,
        number: IssueNumber,
        body: IssueBodyText,
        if_match: EntityTag,
    ) -> Self {
        Self {
            target,
            number,
            body,
            if_match,
        }
    }

    /// The repository.
    #[must_use]
    pub const fn target(&self) -> &RepoTarget {
        &self.target
    }

    /// The issue number.
    #[must_use]
    pub const fn number(&self) -> IssueNumber {
        self.number
    }

    /// The complete replacement body.
    #[must_use]
    pub const fn body(&self) -> &IssueBodyText {
        &self.body
    }

    /// The version the issue must still have.
    #[must_use]
    pub const fn if_match(&self) -> &EntityTag {
        &self.if_match
    }
}

/// Replace one issue-comment body if it still has the version previously read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateIssueCommentRequest {
    target: RepoTarget,
    comment_id: CommentId,
    body: IssueBodyText,
    if_match: EntityTag,
}

impl UpdateIssueCommentRequest {
    /// Bind a comment, complete new body, and previous entity tag.
    #[must_use]
    pub const fn new(
        target: RepoTarget,
        comment_id: CommentId,
        body: IssueBodyText,
        if_match: EntityTag,
    ) -> Self {
        Self {
            target,
            comment_id,
            body,
            if_match,
        }
    }

    /// The repository.
    #[must_use]
    pub const fn target(&self) -> &RepoTarget {
        &self.target
    }

    /// The comment id.
    #[must_use]
    pub const fn comment_id(&self) -> CommentId {
        self.comment_id
    }

    /// The complete replacement body.
    #[must_use]
    pub const fn body(&self) -> &IssueBodyText {
        &self.body
    }

    /// The version the comment must still have.
    #[must_use]
    pub const fn if_match(&self) -> &EntityTag {
        &self.if_match
    }
}

impl GetCommentsRequest {
    /// Name one issue and one page of its comments.
    #[must_use]
    pub const fn new(target: RepoTarget, number: IssueNumber, page: Page) -> Self {
        Self {
            target,
            number,
            page,
        }
    }

    /// The repository.
    #[must_use]
    pub const fn target(&self) -> &RepoTarget {
        &self.target
    }

    /// The issue.
    #[must_use]
    pub const fn number(&self) -> IssueNumber {
        self.number
    }

    /// The page.
    #[must_use]
    pub const fn page(&self) -> Page {
        self.page
    }
}

/// Read one page of a repository's issues.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListIssuesRequest {
    target: RepoTarget,
    filter: IssueFilter,
    page: Page,
}

/// Read one repository's bounded metadata.
///
/// This deliberately names one validated repository rather than exposing an
/// account- or organization-wide listing. The caller remains bound to its
/// local repository allowlist while still being able to answer push-activity
/// questions from GitHub's canonical `pushed_at` field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetRepositoryRequest {
    target: RepoTarget,
}

/// Read one exact GitHub Actions workflow run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetWorkflowRunRequest {
    target: RepoTarget,
    run_id: WorkflowRunId,
}

impl GetWorkflowRunRequest {
    /// Bind one validated repository and workflow-run id.
    #[must_use]
    pub const fn new(target: RepoTarget, run_id: WorkflowRunId) -> Self {
        Self { target, run_id }
    }

    /// The repository.
    #[must_use]
    pub const fn target(&self) -> &RepoTarget {
        &self.target
    }

    /// The workflow run.
    #[must_use]
    pub const fn run_id(&self) -> WorkflowRunId {
        self.run_id
    }
}

/// Re-run one exact GitHub Actions workflow run.
///
/// This type has no body because debug logging and alternate rerun modes are
/// intentionally outside the Mobile review capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RerunWorkflowRequest {
    target: RepoTarget,
    run_id: WorkflowRunId,
}

impl RerunWorkflowRequest {
    /// Bind one validated repository and workflow-run id.
    #[must_use]
    pub const fn new(target: RepoTarget, run_id: WorkflowRunId) -> Self {
        Self { target, run_id }
    }

    /// The repository.
    #[must_use]
    pub const fn target(&self) -> &RepoTarget {
        &self.target
    }

    /// The workflow run.
    #[must_use]
    pub const fn run_id(&self) -> WorkflowRunId {
        self.run_id
    }
}

impl GetRepositoryRequest {
    /// Name the exact repository to read.
    #[must_use]
    pub const fn new(target: RepoTarget) -> Self {
        Self { target }
    }

    /// The repository.
    #[must_use]
    pub const fn target(&self) -> &RepoTarget {
        &self.target
    }
}

impl ListIssuesRequest {
    /// Name one repository, one filter and one page.
    #[must_use]
    pub const fn new(target: RepoTarget, filter: IssueFilter, page: Page) -> Self {
        Self {
            target,
            filter,
            page,
        }
    }

    /// The repository.
    #[must_use]
    pub const fn target(&self) -> &RepoTarget {
        &self.target
    }

    /// The filter.
    #[must_use]
    pub const fn filter(&self) -> &IssueFilter {
        &self.filter
    }

    /// The page.
    #[must_use]
    pub const fn page(&self) -> Page {
        self.page
    }
}

/// Search issues across repositories.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchIssuesRequest {
    query: String,
    page: Page,
}

impl SearchIssuesRequest {
    /// Bind one query to one page.
    ///
    /// `is:issue` is appended by the renderer, not stored here, so the
    /// qualifier is on the wire exactly once however the caller phrased the
    /// query.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Query`] for a query that is empty after
    /// trimming, over [`MAX_SEARCH_QUERY_BYTES`], or control-bearing, and
    /// [`GitHubRefusal::Paging`] for a page past [`MAX_SEARCH_PAGE`].
    pub fn new(query: &str, page: Page) -> Result<Self, GitHubRefusal> {
        let query = query.trim();
        if query.is_empty()
            || query.len() > MAX_SEARCH_QUERY_BYTES
            || query.chars().any(char::is_control)
        {
            return Err(GitHubRefusal::Query);
        }
        if page.number() > MAX_SEARCH_PAGE {
            return Err(GitHubRefusal::Paging);
        }
        Ok(Self {
            query: query.to_owned(),
            page,
        })
    }

    /// The query, without the appended qualifier.
    #[must_use]
    pub fn query(&self) -> &str {
        &self.query
    }

    /// The page.
    #[must_use]
    pub const fn page(&self) -> Page {
        self.page
    }
}

/// One validated operation, ready to be rendered onto the wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitHubOperation {
    /// `POST /repos/{owner}/{repo}/issues`
    CreateIssue(CreateIssueRequest),
    /// `POST /repos/{owner}/{repo}/issues/{number}/comments`
    Comment(CommentRequest),
    /// `PATCH /repos/{owner}/{repo}/issues/{number}`
    SetState(SetStateRequest),
    /// `PUT /repos/{owner}/{repo}/issues/{number}/labels`
    ReplaceLabels(ReplaceLabelsRequest),
    /// `GET /repos/{owner}/{repo}/issues/{number}`
    GetIssue(GetIssueRequest),
    /// `PATCH /repos/{owner}/{repo}/issues/{number}` with `If-Match`
    UpdateIssueBody(UpdateIssueBodyRequest),
    /// `GET /repos/{owner}/{repo}/issues/{number}/comments`
    GetComments(GetCommentsRequest),
    /// `GET /repos/{owner}/{repo}/issues/comments/{comment_id}`
    GetIssueComment(GetIssueCommentRequest),
    /// `PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}` with `If-Match`
    UpdateIssueComment(UpdateIssueCommentRequest),
    /// `GET /repos/{owner}/{repo}/labels`
    ListLabels(ListLabelsRequest),
    /// `GET /repos/{owner}/{repo}/issues`
    ListIssues(ListIssuesRequest),
    /// `GET /repos/{owner}/{repo}`
    GetRepository(GetRepositoryRequest),
    /// `GET /repos/{owner}/{repo}/actions/runs/{run_id}`
    GetWorkflowRun(GetWorkflowRunRequest),
    /// `POST /repos/{owner}/{repo}/actions/runs/{run_id}/rerun`
    RerunWorkflow(RerunWorkflowRequest),
    /// `GET /search/issues`
    SearchIssues(SearchIssuesRequest),
    /// `GET /user`
    Whoami,
}

impl GitHubOperation {
    /// The exact verb.
    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        match self {
            Self::CreateIssue(_) | Self::Comment(_) | Self::RerunWorkflow(_) => HttpMethod::Post,
            Self::SetState(_) | Self::UpdateIssueBody(_) | Self::UpdateIssueComment(_) => {
                HttpMethod::Patch
            }
            Self::ReplaceLabels(_) => HttpMethod::Put,
            Self::GetIssue(_)
            | Self::GetComments(_)
            | Self::GetIssueComment(_)
            | Self::ListLabels(_)
            | Self::ListIssues(_)
            | Self::GetRepository(_)
            | Self::GetWorkflowRun(_)
            | Self::SearchIssues(_)
            | Self::Whoami => HttpMethod::Get,
        }
    }

    /// Whether this operation changes something other people can see.
    ///
    /// An approval layer keys on this rather than re-deriving it from the verb:
    /// every write here lands in a repository a client reads.
    #[must_use]
    pub const fn is_external_effect(&self) -> bool {
        matches!(
            self,
            Self::CreateIssue(_)
                | Self::Comment(_)
                | Self::SetState(_)
                | Self::ReplaceLabels(_)
                | Self::UpdateIssueBody(_)
                | Self::UpdateIssueComment(_)
                | Self::RerunWorkflow(_)
        )
    }

    /// The exact path and query, credential-free.
    #[must_use]
    pub fn path(&self) -> String {
        match self {
            Self::CreateIssue(request) => issues_path(request.target()),
            Self::Comment(request) => {
                format!(
                    "{}/{}/comments",
                    issues_path(request.target()),
                    request.number()
                )
            }
            Self::SetState(request) => {
                format!("{}/{}", issues_path(request.target()), request.number())
            }
            Self::ReplaceLabels(request) => {
                format!(
                    "{}/{}/labels",
                    issues_path(request.target()),
                    request.number()
                )
            }
            Self::GetIssue(request) => {
                format!("{}/{}", issues_path(request.target()), request.number())
            }
            Self::UpdateIssueBody(request) => {
                format!("{}/{}", issues_path(request.target()), request.number())
            }
            Self::GetComments(request) => {
                let page = request.page();
                format!(
                    "{}/{}/comments?per_page={}&page={}",
                    issues_path(request.target()),
                    request.number(),
                    page.per_page(),
                    page.number()
                )
            }
            Self::GetIssueComment(request) => {
                issue_comment_path(request.target(), request.comment_id())
            }
            Self::UpdateIssueComment(request) => {
                issue_comment_path(request.target(), request.comment_id())
            }
            Self::ListLabels(request) => {
                let page = request.page();
                format!(
                    "/repos/{}/{}/labels?per_page={}&page={}",
                    request.target().owner().as_str(),
                    request.target().repo().as_str(),
                    page.per_page(),
                    page.number()
                )
            }
            Self::ListIssues(request) => {
                let page = request.page();
                let filter = request.filter();
                let mut path = format!(
                    "{}?state={}&per_page={}&page={}&sort=created&direction=desc",
                    issues_path(request.target()),
                    filter.state().as_str(),
                    page.per_page(),
                    page.number()
                );
                if let Some(since) = filter.since() {
                    path.push_str("&since=");
                    push_query_encoded(&mut path, since.as_str());
                }
                if !filter.labels().is_empty() {
                    let joined = filter
                        .labels()
                        .iter()
                        .map(Label::as_str)
                        .collect::<Vec<_>>()
                        .join(",");
                    path.push_str("&labels=");
                    push_query_encoded(&mut path, &joined);
                }
                path
            }
            Self::GetRepository(request) => repository_path(request.target()),
            Self::GetWorkflowRun(request) => workflow_run_path(request.target(), request.run_id()),
            Self::RerunWorkflow(request) => {
                format!(
                    "{}/rerun",
                    workflow_run_path(request.target(), request.run_id())
                )
            }
            Self::SearchIssues(request) => {
                let page = request.page();
                let mut path = String::from("/search/issues?q=");
                push_query_encoded(&mut path, request.query());
                // The qualifier the legacy console appends to every search, so
                // a pull request can never come back from an issue search.
                push_query_encoded(&mut path, " is:issue");
                path.push_str(&format!(
                    "&per_page={}&page={}",
                    page.per_page(),
                    page.number()
                ));
                path
            }
            Self::Whoami => String::from("/user"),
        }
    }

    /// The exact JSON body, in the documented field order, or `None` for a
    /// read.
    ///
    /// Credential-free by construction, so a host may log or fixture it. Every
    /// string is escaped here; nothing is interpolated raw.
    #[must_use]
    pub fn body(&self) -> Option<String> {
        match self {
            Self::CreateIssue(request) => {
                let mut body = String::from("{\"title\":");
                push_json_string(&mut body, request.title().as_str());
                body.push_str(",\"body\":");
                push_json_string(&mut body, request.body().as_str());
                body.push_str(",\"labels\":");
                push_label_array(&mut body, request.labels());
                body.push('}');
                Some(body)
            }
            Self::Comment(request) => {
                let mut body = String::from("{\"body\":");
                push_json_string(&mut body, request.body().as_str());
                body.push('}');
                Some(body)
            }
            Self::SetState(request) => {
                let mut body = String::from("{\"state\":");
                push_json_string(&mut body, request.state().as_str());
                body.push('}');
                Some(body)
            }
            Self::ReplaceLabels(request) => {
                let mut body = String::from("{\"labels\":");
                push_label_array(&mut body, request.labels());
                body.push('}');
                Some(body)
            }
            Self::UpdateIssueBody(request) => Some(body_json(request.body())),
            Self::UpdateIssueComment(request) => Some(body_json(request.body())),
            Self::GetIssue(_)
            | Self::GetComments(_)
            | Self::GetIssueComment(_)
            | Self::ListLabels(_)
            | Self::ListIssues(_)
            | Self::GetRepository(_)
            | Self::GetWorkflowRun(_)
            | Self::RerunWorkflow(_)
            | Self::SearchIssues(_)
            | Self::Whoami => None,
        }
    }

    /// The optimistic-concurrency precondition, when this is an update.
    #[must_use]
    pub const fn if_match(&self) -> Option<&EntityTag> {
        match self {
            Self::UpdateIssueBody(request) => Some(request.if_match()),
            Self::UpdateIssueComment(request) => Some(request.if_match()),
            _ => None,
        }
    }
}

/// `/repos/{owner}/{repo}/issues`, the prefix every repository path shares.
fn issues_path(target: &RepoTarget) -> String {
    format!("{}/issues", repository_path(target))
}

/// `/repos/{owner}/{repo}`, the fixed repository metadata endpoint.
fn repository_path(target: &RepoTarget) -> String {
    format!(
        "/repos/{}/{}",
        target.owner().as_str(),
        target.repo().as_str()
    )
}

/// One exact repository-scoped GitHub Actions workflow-run endpoint.
fn workflow_run_path(target: &RepoTarget, run_id: WorkflowRunId) -> String {
    format!("{}/actions/runs/{run_id}", repository_path(target))
}

/// One repository-scoped issue-comment endpoint.
fn issue_comment_path(target: &RepoTarget, comment_id: CommentId) -> String {
    format!(
        "/repos/{}/{}/issues/comments/{comment_id}",
        target.owner().as_str(),
        target.repo().as_str()
    )
}

/// Render the shared body-only patch document.
fn body_json(value: &IssueBodyText) -> String {
    let mut body = String::from("{\"body\":");
    push_json_string(&mut body, value.as_str());
    body.push('}');
    body
}

/// Append a JSON array of labels.
fn push_label_array(out: &mut String, labels: &[Label]) {
    out.push('[');
    for (index, label) in labels.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_json_string(out, label.as_str());
    }
    out.push(']');
}

/// Drop repeated labels, keeping first-seen order, and bound the set.
fn dedup_labels(labels: Vec<Label>) -> Result<Vec<Label>, GitHubRefusal> {
    let mut kept: Vec<Label> = Vec::with_capacity(labels.len());
    for label in labels {
        if !kept.contains(&label) {
            kept.push(label);
        }
    }
    if kept.len() > MAX_ISSUE_LABELS {
        return Err(GitHubRefusal::Label);
    }
    Ok(kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> RepoTarget {
        RepoTarget::parse("example-org", "example-repo").expect("target")
    }

    fn number() -> IssueNumber {
        IssueNumber::new(42).expect("number")
    }

    fn label(value: &str) -> Label {
        Label::new(value).expect("label")
    }

    fn title() -> IssueTitle {
        IssueTitle::new("Panne de paiement").expect("title")
    }

    fn body() -> IssueBodyText {
        IssueBodyText::new("## Attribution\n- **Canal :** email").expect("body")
    }

    fn page() -> Page {
        Page::new(1, 50).expect("page")
    }

    #[test]
    fn every_path_is_the_documented_one() {
        let create = GitHubOperation::CreateIssue(
            CreateIssueRequest::new(target(), title(), body(), vec![label("prio:high")])
                .expect("create"),
        );
        assert_eq!(create.path(), "/repos/example-org/example-repo/issues");
        assert_eq!(create.method(), HttpMethod::Post);

        let comment = GitHubOperation::Comment(CommentRequest::new(target(), number(), body()));
        assert_eq!(
            comment.path(),
            "/repos/example-org/example-repo/issues/42/comments"
        );
        assert_eq!(comment.method(), HttpMethod::Post);

        let state =
            GitHubOperation::SetState(SetStateRequest::new(target(), number(), IssueState::Closed));
        assert_eq!(state.path(), "/repos/example-org/example-repo/issues/42");
        assert_eq!(state.method(), HttpMethod::Patch);

        let labels = GitHubOperation::ReplaceLabels(
            ReplaceLabelsRequest::new(target(), number(), vec![label("prio:low")]).expect("labels"),
        );
        assert_eq!(
            labels.path(),
            "/repos/example-org/example-repo/issues/42/labels"
        );
        assert_eq!(labels.method(), HttpMethod::Put);

        let issue = GitHubOperation::GetIssue(GetIssueRequest::new(target(), number()));
        assert_eq!(issue.path(), "/repos/example-org/example-repo/issues/42");
        assert_eq!(issue.method(), HttpMethod::Get);

        let update_issue = GitHubOperation::UpdateIssueBody(UpdateIssueBodyRequest::new(
            target(),
            number(),
            IssueBodyText::new("nouveau corps").expect("body"),
            EntityTag::new("\"issue-v1\"").expect("etag"),
        ));
        assert_eq!(
            update_issue.path(),
            "/repos/example-org/example-repo/issues/42"
        );
        assert_eq!(update_issue.method(), HttpMethod::Patch);
        assert_eq!(
            update_issue.if_match().map(EntityTag::as_str),
            Some("\"issue-v1\"")
        );

        let comments = GitHubOperation::GetComments(GetCommentsRequest::new(
            target(),
            number(),
            Page::new(2, 100).expect("page"),
        ));
        assert_eq!(
            comments.path(),
            "/repos/example-org/example-repo/issues/42/comments?per_page=100&page=2"
        );

        let comment_id = CommentId::new(9_001).expect("comment id");
        let comment =
            GitHubOperation::GetIssueComment(GetIssueCommentRequest::new(target(), comment_id));
        assert_eq!(
            comment.path(),
            "/repos/example-org/example-repo/issues/comments/9001"
        );
        assert_eq!(comment.method(), HttpMethod::Get);

        let update_comment = GitHubOperation::UpdateIssueComment(UpdateIssueCommentRequest::new(
            target(),
            comment_id,
            IssueBodyText::new("fait").expect("body"),
            EntityTag::new("\"comment-v1\"").expect("etag"),
        ));
        assert_eq!(
            update_comment.path(),
            "/repos/example-org/example-repo/issues/comments/9001"
        );
        assert_eq!(update_comment.method(), HttpMethod::Patch);

        let repo_labels = GitHubOperation::ListLabels(ListLabelsRequest::new(
            target(),
            Page::new(3, 100).expect("page"),
        ));
        assert_eq!(
            repo_labels.path(),
            "/repos/example-org/example-repo/labels?per_page=100&page=3"
        );

        let repository = GitHubOperation::GetRepository(GetRepositoryRequest::new(target()));
        assert_eq!(repository.path(), "/repos/example-org/example-repo");
        assert_eq!(repository.method(), HttpMethod::Get);
        assert!(!repository.is_external_effect());

        let list = GitHubOperation::ListIssues(ListIssuesRequest::new(
            target(),
            IssueFilter::new(IssueListState::All),
            page(),
        ));
        assert_eq!(
            list.path(),
            "/repos/example-org/example-repo/issues\
             ?state=all&per_page=50&page=1&sort=created&direction=desc"
        );

        let search = GitHubOperation::SearchIssues(
            SearchIssuesRequest::new("repo:example-org/example-repo panne", page())
                .expect("search"),
        );
        assert_eq!(
            search.path(),
            "/search/issues?q=repo%3Aexample-org%2Fexample-repo%20panne%20is%3Aissue\
             &per_page=50&page=1"
        );

        assert_eq!(GitHubOperation::Whoami.path(), "/user");
        assert_eq!(GitHubOperation::Whoami.method(), HttpMethod::Get);
        assert!(GitHubOperation::Whoami.body().is_none());
    }

    #[test]
    fn a_filtered_listing_renders_every_parameter_in_order() {
        let filter = IssueFilter::new(IssueListState::Closed)
            .with_since(Since::new("2026-08-01T00:00:00Z").expect("since"))
            .with_labels(vec![label("prio:high"), label("tenant:Milo")])
            .expect("labels");
        let list = GitHubOperation::ListIssues(ListIssuesRequest::new(target(), filter, page()));
        assert_eq!(
            list.path(),
            "/repos/example-org/example-repo/issues\
             ?state=closed&per_page=50&page=1&sort=created&direction=desc\
             &since=2026-08-01T00%3A00%3A00Z&labels=prio%3Ahigh%2Ctenant%3AMilo"
        );
    }

    #[test]
    fn every_body_is_exact_and_credential_free() {
        let create = GitHubOperation::CreateIssue(
            CreateIssueRequest::new(
                target(),
                title(),
                IssueBodyText::new("Corps\n\"cite\"").expect("body"),
                vec![label("tenant:Milo"), label("prio:high")],
            )
            .expect("create"),
        );
        assert_eq!(
            create.body().expect("body"),
            "{\"title\":\"Panne de paiement\",\"body\":\"Corps\\n\\\"cite\\\"\",\
             \"labels\":[\"tenant:Milo\",\"prio:high\"]}"
        );

        let comment = GitHubOperation::Comment(CommentRequest::new(
            target(),
            number(),
            IssueBodyText::new("merci").expect("body"),
        ));
        assert_eq!(comment.body().expect("body"), "{\"body\":\"merci\"}");

        let state =
            GitHubOperation::SetState(SetStateRequest::new(target(), number(), IssueState::Closed));
        assert_eq!(state.body().expect("body"), "{\"state\":\"closed\"}");

        let labels = GitHubOperation::ReplaceLabels(
            ReplaceLabelsRequest::new(target(), number(), Vec::new()).expect("labels"),
        );
        assert_eq!(
            labels.body().expect("body"),
            "{\"labels\":[]}",
            "clearing every label must remain expressible"
        );

        let update_issue = GitHubOperation::UpdateIssueBody(UpdateIssueBodyRequest::new(
            target(),
            number(),
            IssueBodyText::new("ligne 1\nligne 2").expect("body"),
            EntityTag::new("\"issue-v1\"").expect("etag"),
        ));
        assert_eq!(
            update_issue.body().expect("body"),
            "{\"body\":\"ligne 1\\nligne 2\"}"
        );

        let update_comment = GitHubOperation::UpdateIssueComment(UpdateIssueCommentRequest::new(
            target(),
            CommentId::new(9_001).expect("comment id"),
            IssueBodyText::new("fait").expect("body"),
            EntityTag::new("\"comment-v1\"").expect("etag"),
        ));
        assert_eq!(update_comment.body().expect("body"), "{\"body\":\"fait\"}");
    }

    #[test]
    fn hostile_content_is_escaped_rather_than_interpolated() {
        let create = GitHubOperation::CreateIssue(
            CreateIssueRequest::new(
                target(),
                IssueTitle::new("quote\" slash\\ end").expect("title"),
                IssueBodyText::new("brace} newline\nend\"}").expect("body"),
                Vec::new(),
            )
            .expect("create"),
        );
        let body = create.body().expect("body");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["title"], "quote\" slash\\ end");
        assert_eq!(parsed["body"], "brace} newline\nend\"}");
        assert_eq!(parsed["labels"].as_array().expect("labels").len(), 0);
    }

    #[test]
    fn external_effects_are_marked_apart_from_reads() {
        let reads = [
            GitHubOperation::GetIssue(GetIssueRequest::new(target(), number())),
            GitHubOperation::GetComments(GetCommentsRequest::new(target(), number(), page())),
            GitHubOperation::GetIssueComment(GetIssueCommentRequest::new(
                target(),
                CommentId::new(9_001).expect("comment id"),
            )),
            GitHubOperation::ListLabels(ListLabelsRequest::new(target(), page())),
            GitHubOperation::ListIssues(ListIssuesRequest::new(
                target(),
                IssueFilter::default(),
                page(),
            )),
            GitHubOperation::SearchIssues(
                SearchIssuesRequest::new("panne", page()).expect("search"),
            ),
            GitHubOperation::Whoami,
        ];
        for read in reads {
            assert!(!read.is_external_effect(), "{read:?} is a read");
            assert_eq!(read.method(), HttpMethod::Get);
            assert!(!read.method().has_body());
        }
        let writes = [
            GitHubOperation::CreateIssue(
                CreateIssueRequest::new(target(), title(), body(), Vec::new()).expect("create"),
            ),
            GitHubOperation::Comment(CommentRequest::new(target(), number(), body())),
            GitHubOperation::SetState(SetStateRequest::new(target(), number(), IssueState::Open)),
            GitHubOperation::ReplaceLabels(
                ReplaceLabelsRequest::new(target(), number(), Vec::new()).expect("labels"),
            ),
            GitHubOperation::UpdateIssueBody(UpdateIssueBodyRequest::new(
                target(),
                number(),
                body(),
                EntityTag::new("\"issue-v1\"").expect("etag"),
            )),
            GitHubOperation::UpdateIssueComment(UpdateIssueCommentRequest::new(
                target(),
                CommentId::new(9_001).expect("comment id"),
                body(),
                EntityTag::new("\"comment-v1\"").expect("etag"),
            )),
        ];
        for write in writes {
            assert!(write.is_external_effect(), "{write:?} is a write");
            assert!(write.method().has_body());
            assert!(write.body().is_some());
        }
    }

    #[test]
    fn a_page_is_bounded_and_never_clamped() {
        assert_eq!(Page::new(0, 50).err(), Some(GitHubRefusal::Paging));
        assert_eq!(Page::new(1, 0).err(), Some(GitHubRefusal::Paging));
        assert_eq!(
            Page::new(1, MAX_PER_PAGE as u32 + 1).err(),
            Some(GitHubRefusal::Paging)
        );
        assert_eq!(
            Page::new(MAX_LIST_PAGE + 1, 1).err(),
            Some(GitHubRefusal::Paging)
        );
        assert!(Page::new(MAX_LIST_PAGE, MAX_PER_PAGE as u32).is_ok());

        // Search pages past GitHub's own ceiling are refused before the call.
        assert!(
            SearchIssuesRequest::new("panne", Page::new(MAX_SEARCH_PAGE, 1).expect("page")).is_ok()
        );
        assert_eq!(
            SearchIssuesRequest::new("panne", Page::new(MAX_SEARCH_PAGE + 1, 1).expect("page"))
                .err(),
            Some(GitHubRefusal::Paging)
        );
    }

    #[test]
    fn a_query_and_a_since_are_bounded_and_control_free() {
        for refused in ["", "   ", "panne\u{7}"] {
            assert_eq!(
                SearchIssuesRequest::new(refused, page()).err(),
                Some(GitHubRefusal::Query),
                "must refuse query {refused:?}"
            );
        }
        assert_eq!(
            SearchIssuesRequest::new(&"q".repeat(MAX_SEARCH_QUERY_BYTES + 1), page()).err(),
            Some(GitHubRefusal::Query)
        );
        assert_eq!(
            SearchIssuesRequest::new("  panne  ", page())
                .expect("search")
                .query(),
            "panne"
        );

        for refused in ["", "a b", "\u{7}"] {
            assert_eq!(
                Since::new(refused).err(),
                Some(GitHubRefusal::Since),
                "must refuse since {refused:?}"
            );
        }
        assert_eq!(
            Since::new(&"s".repeat(MAX_TIMESTAMP_BYTES + 1)).err(),
            Some(GitHubRefusal::Since)
        );
    }

    #[test]
    fn labels_are_deduplicated_and_bounded() {
        let create = CreateIssueRequest::new(
            target(),
            title(),
            body(),
            vec![label("a"), label("b"), label("a")],
        )
        .expect("create");
        assert_eq!(
            create
                .labels()
                .iter()
                .map(Label::as_str)
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );

        let many: Vec<Label> = (0..=MAX_ISSUE_LABELS)
            .map(|index| label(&format!("l{index}")))
            .collect();
        assert_eq!(
            ReplaceLabelsRequest::new(target(), number(), many).err(),
            Some(GitHubRefusal::Label)
        );
        assert_eq!(
            IssueFilter::default()
                .with_labels(
                    (0..=MAX_ISSUE_LABELS)
                        .map(|index| label(&format!("l{index}")))
                        .collect()
                )
                .err(),
            Some(GitHubRefusal::Label)
        );
    }
}
