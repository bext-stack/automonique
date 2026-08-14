// SPDX-License-Identifier: Elastic-2.0

//! The hosted ticket a GitHub issue mirrors.
//!
//! [`TenantIssue`] is the local record: the tenant and site it belongs to, its
//! lifecycle, its comments, and the GitHub issue it is linked to when one
//! exists. It is the *source* of an outbound create — its title, its body and
//! its tenant/site/priority become the issue — and the *destination* of a
//! refresh.
//!
//! Two details of the legacy model are load-bearing and are encoded rather than
//! documented:
//!
//! * a comment's `visibility` is optional on the wire and its absence means
//!   **internal**, so [`IssueComment::visibility`] answers
//!   [`CommentVisibility::Internal`] for an unmarked comment and there is no
//!   way to read the raw field; and
//! * `github` is `None` until a remote issue exists, so a linked ticket and an
//!   unlinked one are different values rather than one value with an empty
//!   string in it.

use crate::target::{IssueNumber, Label, MAX_LABEL_BYTES, RepoTarget};
use crate::{
    GitHubRefusal, IssueState, MAX_ISSUE_BODY_BYTES, MAX_ISSUE_TITLE_BYTES, MAX_TIMESTAMP_BYTES,
    MAX_URL_BYTES, is_body_text, is_line_text, is_opaque_identifier,
};

/// Longest tenant name, site label, requester or assignee retained.
pub const MAX_TICKET_NAME_BYTES: usize = 200;

/// Longest ticket identifier retained.
pub const MAX_TICKET_ID_BYTES: usize = 120;

/// Longest comment body retained.
pub const MAX_COMMENT_BODY_BYTES: usize = 20_000;

/// Most characters of a tenant name or site label carried into a label.
///
/// The legacy console cuts at forty UTF-16 units; this cuts at forty
/// *characters* and then again at whatever fits [`MAX_LABEL_BYTES`], so an
/// accented or non-Latin name yields a shorter but always valid label rather
/// than one GitHub would refuse.
pub const MAX_LABEL_SCOPE_CHARS: usize = 40;

/// A validated issue title.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueTitle(String);

impl IssueTitle {
    /// Validate one title.
    ///
    /// Surrounding whitespace is trimmed. An over-long title is refused rather
    /// than cut, because a title cut mid-sentence is a ticket nobody can search
    /// for.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Title`] for a title that is empty after
    /// trimming, over [`MAX_ISSUE_TITLE_BYTES`], or control-bearing.
    pub fn new(value: &str) -> Result<Self, GitHubRefusal> {
        let value = value.trim();
        if !is_line_text(value, MAX_ISSUE_TITLE_BYTES) {
            return Err(GitHubRefusal::Title);
        }
        Ok(Self(value.to_owned()))
    }

    /// The exact title.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated issue or comment body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueBodyText(String);

impl IssueBodyText {
    /// Validate one Markdown body.
    ///
    /// Interior newlines are kept — a body is Markdown — but every other
    /// control character is refused.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Body`] for a body that is empty, over
    /// [`MAX_ISSUE_BODY_BYTES`], or control-bearing.
    pub fn new(value: &str) -> Result<Self, GitHubRefusal> {
        if !is_body_text(value, MAX_ISSUE_BODY_BYTES) {
            return Err(GitHubRefusal::Body);
        }
        Ok(Self(value.to_owned()))
    }

    /// The exact body.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Where a hosted ticket is in its lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueStatus {
    /// Filed, not yet triaged.
    Open,
    /// Being triaged.
    Triaging,
    /// Being worked.
    InProgress,
    /// Waiting on something outside the team.
    Blocked,
    /// Finished.
    Done,
    /// Finished and archived.
    Closed,
}

impl IssueStatus {
    /// The exact wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Triaging => "triaging",
            Self::InProgress => "in_progress",
            Self::Blocked => "blocked",
            Self::Done => "done",
            Self::Closed => "closed",
        }
    }

    /// Read one wire spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "open" => Some(Self::Open),
            "triaging" => Some(Self::Triaging),
            "in_progress" => Some(Self::InProgress),
            "blocked" => Some(Self::Blocked),
            "done" => Some(Self::Done),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }
}

/// How urgent a hosted ticket is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuePriority {
    /// Whenever.
    Low,
    /// The default.
    Normal,
    /// Ahead of normal work.
    High,
    /// Interrupt work.
    Urgent,
}

impl IssuePriority {
    /// The exact wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
            Self::Urgent => "urgent",
        }
    }

    /// Read one wire spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "low" => Some(Self::Low),
            "normal" => Some(Self::Normal),
            "high" => Some(Self::High),
            "urgent" => Some(Self::Urgent),
            _ => None,
        }
    }
}

/// Which intake surface a ticket arrived through.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueSource {
    /// Filed by the tenant.
    User,
    /// Filed from the support inbox.
    Support,
    /// Filed from the desktop client.
    Shelldeck,
    /// Filed from Slack.
    Slack,
    /// Filed from the management console.
    Manage,
    /// Imported from GitHub.
    Github,
}

impl IssueSource {
    /// The exact wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Support => "support",
            Self::Shelldeck => "shelldeck",
            Self::Slack => "slack",
            Self::Manage => "manage",
            Self::Github => "github",
        }
    }

    /// Read one wire spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "support" => Some(Self::Support),
            "shelldeck" => Some(Self::Shelldeck),
            "slack" => Some(Self::Slack),
            "manage" => Some(Self::Manage),
            "github" => Some(Self::Github),
            _ => None,
        }
    }
}

/// Who may read one comment.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CommentVisibility {
    /// Staff only. The default, and the value an absent field means.
    #[default]
    Internal,
    /// Also visible to the requester in the client portal.
    Client,
}

impl CommentVisibility {
    /// The exact wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::Client => "client",
        }
    }

    /// Read one wire spelling.
    ///
    /// Only the two exact spellings are visibility; anything else — including
    /// an absent field, which never reaches here — is not a grant.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "internal" => Some(Self::Internal),
            "client" => Some(Self::Client),
            _ => None,
        }
    }
}

/// What produced one comment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommentKind {
    /// A person wrote it.
    Comment,
    /// A lifecycle transition recorded it.
    Status,
    /// The platform recorded it.
    System,
    /// Mirrored from GitHub.
    Github,
}

impl CommentKind {
    /// The exact wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Comment => "comment",
            Self::Status => "status",
            Self::System => "system",
            Self::Github => "github",
        }
    }
}

/// One comment on a hosted ticket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueComment {
    id: String,
    author: String,
    body: String,
    kind: CommentKind,
    at: String,
    visibility: Option<CommentVisibility>,
    github_id: Option<u64>,
}

impl IssueComment {
    /// Record one comment.
    ///
    /// `visibility` is `None` for a comment written before the field existed,
    /// and that is not a gap to be filled in: [`IssueComment::visibility`]
    /// answers `Internal` for it.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Text`] for an identifier, author or timestamp
    /// outside its bound, and [`GitHubRefusal::Body`] for a body outside
    /// [`MAX_COMMENT_BODY_BYTES`].
    pub fn new(
        id: &str,
        author: &str,
        body: &str,
        kind: CommentKind,
        at: &str,
        visibility: Option<CommentVisibility>,
    ) -> Result<Self, GitHubRefusal> {
        if !is_opaque_identifier(id, MAX_TICKET_ID_BYTES)
            || !is_line_text(author, MAX_TICKET_NAME_BYTES)
            || !is_line_text(at, MAX_TIMESTAMP_BYTES)
        {
            return Err(GitHubRefusal::Text);
        }
        if !is_body_text(body, MAX_COMMENT_BODY_BYTES) {
            return Err(GitHubRefusal::Body);
        }
        Ok(Self {
            id: id.to_owned(),
            author: author.to_owned(),
            body: body.to_owned(),
            kind,
            at: at.to_owned(),
            visibility,
            github_id: None,
        })
    }

    /// Attach GitHub's own comment id — the only identity stable across an
    /// upstream edit.
    #[must_use]
    pub fn with_github_id(mut self, github_id: u64) -> Self {
        self.github_id = Some(github_id);
        self
    }

    /// The local comment identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Who wrote it.
    #[must_use]
    pub fn author(&self) -> &str {
        &self.author
    }

    /// What it says.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }

    /// What produced it.
    #[must_use]
    pub const fn kind(&self) -> CommentKind {
        self.kind
    }

    /// When it was written.
    #[must_use]
    pub fn at(&self) -> &str {
        &self.at
    }

    /// Who may read it.
    ///
    /// The only reader of the underlying field. An absent value is
    /// [`CommentVisibility::Internal`], so a comment can never become
    /// client-visible by omission — which is what an "optional for migration"
    /// field would otherwise allow.
    #[must_use]
    pub fn visibility(&self) -> CommentVisibility {
        self.visibility.unwrap_or_default()
    }

    /// Whether the requester may read this comment.
    #[must_use]
    pub fn is_client_visible(&self) -> bool {
        self.visibility() == CommentVisibility::Client
    }

    /// GitHub's own comment id, on a mirrored comment.
    #[must_use]
    pub const fn github_id(&self) -> Option<u64> {
        self.github_id
    }
}

/// The GitHub issue a hosted ticket is linked to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubLink {
    target: RepoTarget,
    number: IssueNumber,
    url: String,
    state: IssueState,
    synced_at: String,
}

impl GithubLink {
    /// Record one link.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Text`] for a URL or timestamp outside its
    /// bound.
    pub fn new(
        target: RepoTarget,
        number: IssueNumber,
        url: &str,
        state: IssueState,
        synced_at: &str,
    ) -> Result<Self, GitHubRefusal> {
        if !is_line_text(url, MAX_URL_BYTES) || !is_line_text(synced_at, MAX_TIMESTAMP_BYTES) {
            return Err(GitHubRefusal::Text);
        }
        Ok(Self {
            target,
            number,
            url: url.to_owned(),
            state,
            synced_at: synced_at.to_owned(),
        })
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

    /// The issue's web URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The state at the last sync.
    #[must_use]
    pub const fn state(&self) -> IssueState {
        self.state
    }

    /// When the link was last reconciled.
    #[must_use]
    pub fn synced_at(&self) -> &str {
        &self.synced_at
    }
}

/// One hosted ticket.
///
/// `Debug` is derived rather than redacted: a ticket is the operator-facing
/// payload this connector exists to move, and withholding it would defeat the
/// purpose. A caller that logs one is logging customer-adjacent data and must
/// treat the record accordingly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantIssue {
    id: String,
    tenant_id: crate::repo_map::TenantId,
    tenant_name: String,
    site_id: Option<crate::repo_map::SiteId>,
    site_label: Option<String>,
    title: IssueTitle,
    body: IssueBodyText,
    status: IssueStatus,
    priority: IssuePriority,
    source: IssueSource,
    requested_by: String,
    assignee: Option<String>,
    comments: Vec<IssueComment>,
    github: Option<GithubLink>,
}

impl TenantIssue {
    /// Record one ticket.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Text`] for an identifier, tenant name or
    /// requester outside its bound.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: &str,
        tenant_id: crate::repo_map::TenantId,
        tenant_name: &str,
        title: IssueTitle,
        body: IssueBodyText,
        status: IssueStatus,
        priority: IssuePriority,
        source: IssueSource,
        requested_by: &str,
    ) -> Result<Self, GitHubRefusal> {
        if !is_opaque_identifier(id, MAX_TICKET_ID_BYTES)
            || !is_line_text(tenant_name, MAX_TICKET_NAME_BYTES)
            || !is_line_text(requested_by, MAX_TICKET_NAME_BYTES)
        {
            return Err(GitHubRefusal::Text);
        }
        Ok(Self {
            id: id.to_owned(),
            tenant_id,
            tenant_name: tenant_name.to_owned(),
            site_id: None,
            site_label: None,
            title,
            body,
            status,
            priority,
            source,
            requested_by: requested_by.to_owned(),
            assignee: None,
            comments: Vec::new(),
            github: None,
        })
    }

    /// Name the site this ticket concerns.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Text`] for a label outside its bound.
    pub fn with_site(
        mut self,
        site_id: Option<crate::repo_map::SiteId>,
        site_label: Option<&str>,
    ) -> Result<Self, GitHubRefusal> {
        self.site_label = match site_label.map(str::trim) {
            None | Some("") => None,
            Some(label) if is_line_text(label, MAX_TICKET_NAME_BYTES) => Some(label.to_owned()),
            Some(_) => return Err(GitHubRefusal::Text),
        };
        self.site_id = site_id;
        Ok(self)
    }

    /// Name the assignee.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Text`] for an assignee outside its bound. An
    /// empty assignee is `None` — the legacy record spells "unassigned" as an
    /// empty string, and the two must not be different values here.
    pub fn with_assignee(mut self, assignee: &str) -> Result<Self, GitHubRefusal> {
        let assignee = assignee.trim();
        self.assignee = if assignee.is_empty() {
            None
        } else if is_line_text(assignee, MAX_TICKET_NAME_BYTES) {
            Some(assignee.to_owned())
        } else {
            return Err(GitHubRefusal::Text);
        };
        Ok(self)
    }

    /// Attach the comment thread.
    #[must_use]
    pub fn with_comments(mut self, comments: Vec<IssueComment>) -> Self {
        self.comments = comments;
        self
    }

    /// Link the ticket to a GitHub issue.
    #[must_use]
    pub fn with_github(mut self, github: GithubLink) -> Self {
        self.github = Some(github);
        self
    }

    /// The ticket identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &crate::repo_map::TenantId {
        &self.tenant_id
    }

    /// The tenant's display name.
    #[must_use]
    pub fn tenant_name(&self) -> &str {
        &self.tenant_name
    }

    /// The site, when the ticket names one.
    #[must_use]
    pub const fn site_id(&self) -> Option<&crate::repo_map::SiteId> {
        self.site_id.as_ref()
    }

    /// The site's display label, when the ticket names one.
    #[must_use]
    pub fn site_label(&self) -> Option<&str> {
        self.site_label.as_deref()
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

    /// The lifecycle state.
    #[must_use]
    pub const fn status(&self) -> IssueStatus {
        self.status
    }

    /// The priority.
    #[must_use]
    pub const fn priority(&self) -> IssuePriority {
        self.priority
    }

    /// The intake surface.
    #[must_use]
    pub const fn source(&self) -> IssueSource {
        self.source
    }

    /// Who filed it.
    #[must_use]
    pub fn requested_by(&self) -> &str {
        &self.requested_by
    }

    /// Who owns it, when someone does.
    #[must_use]
    pub fn assignee(&self) -> Option<&str> {
        self.assignee.as_deref()
    }

    /// The comment thread.
    #[must_use]
    pub fn comments(&self) -> &[IssueComment] {
        &self.comments
    }

    /// Only the comments the requester may read.
    #[must_use]
    pub fn client_visible_comments(&self) -> Vec<&IssueComment> {
        self.comments
            .iter()
            .filter(|comment| comment.is_client_visible())
            .collect()
    }

    /// The linked GitHub issue, when one exists.
    #[must_use]
    pub const fn github(&self) -> Option<&GithubLink> {
        self.github.as_ref()
    }
}

/// The labels a mapped ticket carries onto its GitHub issue.
///
/// `tenant:<name>`, then `site:<label>` when the ticket names a site, then
/// `prio:<priority>` — the legacy set, in the legacy order.
///
/// Scope text is *sanitized* rather than refused: a control character or comma
/// becomes a space and the result is cut to [`MAX_LABEL_SCOPE_CHARS`]
/// characters, then to whatever fits [`MAX_LABEL_BYTES`]. A label is a filter
/// key, not a message, so a tenant whose name contains a comma still gets a
/// usable label instead of a ticket that cannot be filed. The ticket body,
/// where the name is *communicated*, keeps it verbatim.
///
/// The caller supplies this only for a repository the repo map resolved. A
/// shared fallback repository has no such labels defined, so filing into one
/// carries the caller's own allow-listed labels instead — the same split the
/// legacy push makes.
///
/// # Errors
///
/// Returns [`GitHubRefusal::Label`] when a scope is empty after sanitizing, so
/// a nameless tenant is a refusal rather than a bare `tenant:` label.
pub fn ticket_labels(issue: &TenantIssue) -> Result<Vec<Label>, GitHubRefusal> {
    let mut labels = Vec::with_capacity(3);
    let tenant = if issue.tenant_name().trim().is_empty() {
        issue.tenant_id().as_str()
    } else {
        issue.tenant_name()
    };
    labels.push(scoped_label("tenant:", tenant)?);
    if let Some(site_label) = issue.site_label() {
        labels.push(scoped_label("site:", site_label)?);
    }
    labels.push(Label::new(&format!("prio:{}", issue.priority().as_str()))?);
    Ok(labels)
}

/// Render one `prefix:scope` label within both the character and byte ceiling.
fn scoped_label(prefix: &str, scope: &str) -> Result<Label, GitHubRefusal> {
    let budget = MAX_LABEL_BYTES.saturating_sub(prefix.len());
    let mut text = String::with_capacity(prefix.len() + budget);
    text.push_str(prefix);
    let mut used = 0;
    for (index, character) in scope.chars().enumerate() {
        if index >= MAX_LABEL_SCOPE_CHARS {
            break;
        }
        let rendered = if character.is_control() || character == ',' {
            ' '
        } else {
            character
        };
        if used + rendered.len_utf8() > budget {
            break;
        }
        used += rendered.len_utf8();
        text.push(rendered);
    }
    let text = text.trim_end();
    if text.len() <= prefix.len() {
        // Nothing of the scope survived: a bare `tenant:` is not a label.
        return Err(GitHubRefusal::Label);
    }
    Label::new(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo_map::{SiteId, TenantId};

    fn sample() -> TenantIssue {
        TenantIssue::new(
            "iss-1",
            TenantId::new("tenant-a").expect("tenant"),
            "Boulangerie Milo",
            IssueTitle::new("Panne de paiement").expect("title"),
            IssueBodyText::new("## Attribution\n- **Canal :** email").expect("body"),
            IssueStatus::Triaging,
            IssuePriority::High,
            IssueSource::Support,
            "Claire",
        )
        .expect("ticket")
    }

    #[test]
    fn a_ticket_carries_every_field_the_legacy_record_names() {
        let ticket = sample()
            .with_site(
                Some(SiteId::new("site-1").expect("site")),
                Some("  Milo Paris  "),
            )
            .expect("site")
            .with_assignee("lea@exemple.invalid")
            .expect("assignee")
            .with_github(
                GithubLink::new(
                    RepoTarget::parse("example-org", "example-repo").expect("target"),
                    IssueNumber::new(42).expect("number"),
                    "https://github.com/example-org/example-repo/issues/42",
                    IssueState::Open,
                    "2026-08-13T17:04:11.000Z",
                )
                .expect("link"),
            );
        assert_eq!(ticket.id(), "iss-1");
        assert_eq!(ticket.tenant_id().as_str(), "tenant-a");
        assert_eq!(ticket.tenant_name(), "Boulangerie Milo");
        assert_eq!(ticket.site_id().map(SiteId::as_str), Some("site-1"));
        assert_eq!(ticket.site_label(), Some("Milo Paris"));
        assert_eq!(ticket.title().as_str(), "Panne de paiement");
        assert_eq!(ticket.status(), IssueStatus::Triaging);
        assert_eq!(ticket.priority(), IssuePriority::High);
        assert_eq!(ticket.source(), IssueSource::Support);
        assert_eq!(ticket.requested_by(), "Claire");
        assert_eq!(ticket.assignee(), Some("lea@exemple.invalid"));
        let link = ticket.github().expect("link");
        assert_eq!(link.number().get(), 42);
        assert_eq!(link.state(), IssueState::Open);
        assert_eq!(link.target().to_string(), "example-org/example-repo");
        assert_eq!(link.synced_at(), "2026-08-13T17:04:11.000Z");
        assert!(link.url().ends_with("/issues/42"));

        // Unassigned is absence, not an empty string.
        assert_eq!(
            sample().with_assignee("   ").expect("assignee").assignee(),
            None
        );
        assert!(sample().github().is_none());
    }

    #[test]
    fn an_unmarked_comment_is_internal_and_can_never_become_client_visible() {
        let unmarked = IssueComment::new(
            "c-1",
            "Support",
            "note interne",
            CommentKind::Comment,
            "2026-08-13T17:04:11.000Z",
            None,
        )
        .expect("comment");
        assert_eq!(unmarked.visibility(), CommentVisibility::Internal);
        assert!(!unmarked.is_client_visible());

        let client = IssueComment::new(
            "c-2",
            "Support",
            "reponse au client",
            CommentKind::Comment,
            "2026-08-13T17:05:11.000Z",
            Some(CommentVisibility::Client),
        )
        .expect("comment");
        assert!(client.is_client_visible());

        let ticket = sample().with_comments(vec![unmarked, client]);
        assert_eq!(ticket.comments().len(), 2);
        let visible = ticket.client_visible_comments();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id(), "c-2");
        assert_eq!(CommentVisibility::default(), CommentVisibility::Internal);
        assert_eq!(
            CommentVisibility::parse("client"),
            Some(CommentVisibility::Client)
        );
        assert_eq!(CommentVisibility::parse("Client"), None);
        assert_eq!(CommentVisibility::parse(""), None);
    }

    #[test]
    fn a_mirrored_comment_keeps_githubs_own_identity() {
        let comment = IssueComment::new(
            "c-3",
            "octocat",
            "upstream",
            CommentKind::Github,
            "2026-08-13T17:06:11.000Z",
            None,
        )
        .expect("comment")
        .with_github_id(9_001);
        assert_eq!(comment.github_id(), Some(9_001));
        assert_eq!(comment.kind(), CommentKind::Github);
        assert_eq!(comment.author(), "octocat");
        assert_eq!(comment.body(), "upstream");
        assert_eq!(comment.at(), "2026-08-13T17:06:11.000Z");
    }

    #[test]
    fn the_ticket_vocabularies_round_trip_and_refuse_everything_else() {
        for status in [
            IssueStatus::Open,
            IssueStatus::Triaging,
            IssueStatus::InProgress,
            IssueStatus::Blocked,
            IssueStatus::Done,
            IssueStatus::Closed,
        ] {
            assert_eq!(IssueStatus::parse(status.as_str()), Some(status));
        }
        for priority in [
            IssuePriority::Low,
            IssuePriority::Normal,
            IssuePriority::High,
            IssuePriority::Urgent,
        ] {
            assert_eq!(IssuePriority::parse(priority.as_str()), Some(priority));
        }
        for source in [
            IssueSource::User,
            IssueSource::Support,
            IssueSource::Shelldeck,
            IssueSource::Slack,
            IssueSource::Manage,
            IssueSource::Github,
        ] {
            assert_eq!(IssueSource::parse(source.as_str()), Some(source));
        }
        assert_eq!(IssueStatus::parse("archived"), None);
        assert_eq!(IssuePriority::parse("critical"), None);
        assert_eq!(IssueSource::parse("email"), None);
        assert_eq!(CommentKind::System.as_str(), "system");
    }

    #[test]
    fn a_title_and_a_body_are_bounded_and_refused_rather_than_cut() {
        assert_eq!(
            IssueTitle::new("  Panne  ").expect("title").as_str(),
            "Panne"
        );
        assert_eq!(IssueTitle::new("   ").err(), Some(GitHubRefusal::Title));
        assert_eq!(
            IssueTitle::new("deux\nlignes").err(),
            Some(GitHubRefusal::Title),
            "a title is one line"
        );
        assert!(IssueTitle::new(&"t".repeat(MAX_ISSUE_TITLE_BYTES)).is_ok());
        assert_eq!(
            IssueTitle::new(&"t".repeat(MAX_ISSUE_TITLE_BYTES + 1)).err(),
            Some(GitHubRefusal::Title)
        );

        assert!(IssueBodyText::new("## Titre\n\n- [ ] faire").is_ok());
        assert_eq!(IssueBodyText::new("").err(), Some(GitHubRefusal::Body));
        assert_eq!(
            IssueBodyText::new("cloche\u{7}").err(),
            Some(GitHubRefusal::Body)
        );
        assert!(IssueBodyText::new(&"b".repeat(MAX_ISSUE_BODY_BYTES)).is_ok());
        assert_eq!(
            IssueBodyText::new(&"b".repeat(MAX_ISSUE_BODY_BYTES + 1)).err(),
            Some(GitHubRefusal::Body)
        );
    }

    #[test]
    fn the_labels_are_the_legacy_set_in_the_legacy_order() {
        let ticket = sample().with_site(None, Some("Milo Paris")).expect("site");
        let labels = ticket_labels(&ticket).expect("labels");
        let rendered: Vec<&str> = labels.iter().map(Label::as_str).collect();
        assert_eq!(
            rendered,
            vec!["tenant:Boulangerie Milo", "site:Milo Paris", "prio:high"]
        );

        // No site named: no site label, and the order of the other two holds.
        let labels = ticket_labels(&sample()).expect("labels");
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0].as_str(), "tenant:Boulangerie Milo");
        assert_eq!(labels[1].as_str(), "prio:high");
    }

    #[test]
    fn a_label_scope_is_cut_to_a_valid_label_rather_than_refused() {
        // Forty characters of scope, and never more bytes than GitHub accepts.
        let long = TenantIssue::new(
            "iss-2",
            TenantId::new("tenant-b").expect("tenant"),
            &"e\u{301}".repeat(60),
            IssueTitle::new("Titre").expect("title"),
            IssueBodyText::new("corps").expect("body"),
            IssueStatus::Open,
            IssuePriority::Normal,
            IssueSource::Manage,
            "Claire",
        )
        .expect("ticket");
        let labels = ticket_labels(&long).expect("labels");
        assert!(labels[0].as_str().starts_with("tenant:"));
        assert!(
            labels[0].as_str().len() <= MAX_LABEL_BYTES,
            "label {} is {} bytes",
            labels[0].as_str(),
            labels[0].as_str().len()
        );
        assert!(
            labels[0]
                .as_str()
                .is_char_boundary(labels[0].as_str().len())
        );

        // A comma would make the label unfilterable, so it is replaced.
        let comma = TenantIssue::new(
            "iss-3",
            TenantId::new("tenant-c").expect("tenant"),
            "Milo, SARL",
            IssueTitle::new("Titre").expect("title"),
            IssueBodyText::new("corps").expect("body"),
            IssueStatus::Open,
            IssuePriority::Urgent,
            IssueSource::Manage,
            "Claire",
        )
        .expect("ticket");
        let labels = ticket_labels(&comma).expect("labels");
        assert_eq!(labels[0].as_str(), "tenant:Milo  SARL");
        assert_eq!(labels[1].as_str(), "prio:urgent");
    }

    #[test]
    fn a_nameless_tenant_falls_back_to_its_identifier() {
        let unnamed = TenantIssue::new(
            "iss-4",
            TenantId::new("tenant-d").expect("tenant"),
            " ",
            IssueTitle::new("Titre").expect("title"),
            IssueBodyText::new("corps").expect("body"),
            IssueStatus::Open,
            IssuePriority::Low,
            IssueSource::Manage,
            "Claire",
        )
        .expect("ticket");
        assert_eq!(
            ticket_labels(&unnamed).expect("labels")[0].as_str(),
            "tenant:tenant-d"
        );
    }
}
