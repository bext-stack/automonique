// SPDX-License-Identifier: Elastic-2.0

//! Bounded GitHub issue facts and typed operational mutations.
//!
//! The credential is deployment configuration, never model context. The
//! connector fixes the network origin to `api.github.com` and exposes typed
//! issue reads; this module narrows that surface to one bounded rendering.
//!
//! Write actions require an owner-only configuration. The v4 management shape
//! adds owner/project aliases and capability groups:
//! addressed from chat through a local alias, never an `owner/repo` supplied by
//! the model:
//!
//! ```text
//! schema=automonique.github/v4
//! credential=gh-cli-active-account
//! repo=automonique:example/automonique
//! owner=example:organization:example
//! project=roadmap:example:7
//! action=create-issue
//! action=reply
//! action=checklist
//! capability=issues
//! capability=taxonomy
//! capability=hierarchy
//! capability=projects
//! end=1
//! ```

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use automonique_core::conversation::utc_rfc3339_from_unix_millis;
use automonique_github_connector::{
    CommentId, CommentRequest, CreateIssueRequest, DatabaseId, GetCommentsRequest,
    GetIssueCommentRequest, GetIssueRequest, GetRepositoryRequest, GitHubBase, GitHubClient,
    GitHubComment, GitHubOutcome, GitHubToken, IssueBodyText, IssueLocator, IssueManagementPatch,
    IssueState, IssueTitle, Label, LabelColor, ListLabelsRequest, LockReason, ManagementName,
    ManagementRequest, ManagementText, Owner, Page, ProjectFieldType, ProjectItemType,
    ProjectOwner, ProjectOwnerKind, ProjectRef, ProjectStatus, ProjectViewLayout, RepoTarget,
    SearchIssuesRequest, SetStateRequest, UpdateIssueBodyRequest, UpdateIssueCommentRequest,
};
use automonique_protocol::digest::Sha256;
use serde::Deserialize;

const CONFIG_RELATIVE: &str = "github/github.conf";
const JOURNAL_RELATIVE: &str = "github/action-journal.log";
const READ_CONFIG_HEADER: &str = "schema=automonique.github-read/v1";
const ACTION_CONFIG_HEADER: &str = "schema=automonique.github/v2";
const TOOL_CONFIG_HEADER: &str = "schema=automonique.github/v3";
const MANAGEMENT_CONFIG_HEADER: &str = "schema=automonique.github/v4";
const CONFIG_TERMINATOR: &str = "end=1";
const PRISM_INVENTORY_ACTION: &str = "complete-prism-inventory";
const CREATE_ISSUE_ACTION: &str = "create-issue";
const REPLY_ACTION: &str = "reply";
const CHECKLIST_ACTION: &str = "checklist";
const MAX_CONFIG_BYTES: u64 = 16_384;
const MAX_ISSUE_BODY_CONTEXT_BYTES: usize = 2_000;
const MAX_ISSUE_FACT_COMMENTS: usize = 5;
const MAX_ISSUE_COMMENT_CONTEXT_BYTES: usize = 1_000;
const MAX_CONFIGURED_REPOSITORIES: usize = 16;
const MAX_REPOSITORY_ALIAS_BYTES: usize = 32;
const MAX_ACTION_COMMENTS: u32 = 1_000;
const PAGE_SIZE: u32 = 100;
const GH_EXECUTABLE: &str = "/usr/bin/gh";
const GH_CREDENTIAL: &str = "gh-cli-active-account";
const UTC_DAY_MILLIS: i64 = 86_400_000;

/// Closed push-activity windows accepted by the GitHub read surface.
///
/// Conversation text is mapped to one of these before the surface is called;
/// no model-produced timestamp or date arithmetic reaches the filter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryActivityWindow {
    /// Every configured repository whose last push predates the snapshot.
    All,
    /// Monday 00:00 UTC through the snapshot instant.
    ThisWeek,
    /// Current UTC day through the snapshot instant.
    Today,
    /// The complete previous UTC calendar day.
    Yesterday,
    /// The rolling seven days ending at the snapshot instant.
    Last7Days,
}

impl RepositoryActivityWindow {
    /// Stable rendering used in bounded facts and tool schemas.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::ThisWeek => "this_week",
            Self::Today => "today",
            Self::Yesterday => "yesterday",
            Self::Last7Days => "last_7_days",
        }
    }
}

/// An allowlisted issue source plus explicitly configured typed actions.
pub trait GitHubSurface: Send {
    /// Credential-free repository coordinates admitted by local policy.
    ///
    /// These are configuration entries, not a live organization inventory.
    fn configured_repositories(&self) -> Vec<String> {
        Vec::new()
    }

    /// Read push activity for the locally allowlisted repositories in one
    /// closed host-computed UTC window.
    ///
    /// The safe default keeps injected issue-only surfaces issue-only. The
    /// production workspace implements this with one fixed-origin typed
    /// repository-metadata read per configured repository; it never expands
    /// credential scope into an account- or organization-wide inventory.
    fn repository_push_activity(
        &mut self,
        _window: RepositoryActivityWindow,
        _now_ms: i64,
    ) -> Result<String, String> {
        Err(String::from(
            "status=unavailable reason=github_repository_activity_unavailable",
        ))
    }

    /// Read one exact issue and render bounded, untrusted facts.
    fn issue_facts(
        &mut self,
        locator: &IssueLocator,
        detail: IssueFactDetail,
    ) -> Result<String, String>;

    /// Complete an exact inventory-only issue with a deterministic report.
    ///
    /// The default keeps read-only injected surfaces read-only. Production
    /// overrides this with a typed comment + close sequence.
    fn complete_prism_inventory(
        &mut self,
        _locator: &IssueLocator,
        _report: &str,
    ) -> Result<String, String> {
        Err(String::from(
            "status=refused reason=github_actions_unavailable",
        ))
    }
}

/// Read one canonical issue URL through an already configured typed surface.
///
/// Keeping URL parsing beside the connector prevents presentation layers from
/// growing their own GitHub URL grammar or reaching for an unbounded web tool.
pub fn issue_facts_from_url(
    surface: &mut dyn GitHubSurface,
    issue_url: &str,
    detail: IssueFactDetail,
) -> Result<String, String> {
    let locator = IssueLocator::parse(issue_url)
        .ok_or_else(|| String::from("status=refused reason=github_issue_url_not_canonical"))?;
    surface.issue_facts(&locator, detail)
}

/// Bounded issue context supplied to the GitHub drafting worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubIssueContext {
    pub url: String,
    pub title: String,
    pub body: String,
    pub comments: Vec<GitHubContextComment>,
    pub comments_truncated: bool,
}

/// One recent, untrusted GitHub comment in a drafting prompt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubContextComment {
    pub author: String,
    pub body: String,
    pub updated_at: String,
}

/// Confirmed result of one externally visible GitHub action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubMutationReceipt {
    pub url: String,
    pub recovered: bool,
    pub unchanged: bool,
}

/// Locally authorized coordinates exposed to the drafting model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubManagementInventory {
    pub repositories: Vec<String>,
    pub owners: Vec<String>,
    pub projects: Vec<String>,
    pub capabilities: Vec<String>,
}

/// One closed operation from a strict model-produced management plan.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum GitHubManagementOperation {
    CreateLabel {
        repo: String,
        name: String,
        color: String,
        description: Option<String>,
    },
    UpdateLabel {
        repo: String,
        current: String,
        name: String,
        color: String,
        description: Option<String>,
    },
    DeleteLabel {
        repo: String,
        name: String,
    },
    CreateMilestone {
        repo: String,
        title: String,
        description: Option<String>,
        due_on: Option<String>,
    },
    UpdateMilestone {
        repo: String,
        milestone: u64,
        title: Option<String>,
        description: Option<String>,
        due_on: Option<String>,
        open: Option<bool>,
    },
    DeleteMilestone {
        repo: String,
        milestone: u64,
    },
    UpdateIssue {
        issue_url: String,
        title: Option<String>,
        body: Option<String>,
        open: Option<bool>,
        completed: Option<bool>,
        milestone: Option<u64>,
        clear_milestone: Option<bool>,
        labels: Option<Vec<String>>,
        assignees: Option<Vec<String>>,
        issue_type: Option<String>,
        clear_issue_type: Option<bool>,
    },
    LockIssue {
        issue_url: String,
        reason: Option<String>,
    },
    UnlockIssue {
        issue_url: String,
    },
    AddSubIssue {
        issue_url: String,
        sub_issue_id: u64,
    },
    RemoveSubIssue {
        issue_url: String,
        sub_issue_id: u64,
    },
    ReprioritizeSubIssue {
        issue_url: String,
        sub_issue_id: u64,
        after_id: Option<u64>,
        before_id: Option<u64>,
    },
    AddDependency {
        issue_url: String,
        blocking_issue_id: u64,
    },
    RemoveDependency {
        issue_url: String,
        blocking_issue_id: u64,
    },
    TransferIssue {
        issue_url: String,
        repository: String,
    },
    SetIssuePinned {
        issue_url: String,
        pinned: bool,
    },
    CreateProject {
        owner: String,
        title: String,
        public: Option<bool>,
    },
    UpdateProject {
        project: String,
        title: Option<String>,
        description: Option<String>,
        public: Option<bool>,
        closed: Option<bool>,
    },
    DeleteProject {
        project: String,
    },
    CreateProjectField {
        project: String,
        name: String,
        data_type: String,
    },
    UpdateProjectField {
        project: String,
        field_id: u64,
        name: String,
    },
    DeleteProjectField {
        project: String,
        field_id: u64,
    },
    CreateProjectView {
        project: String,
        name: String,
        layout: String,
        filter: Option<String>,
    },
    UpdateProjectView {
        project: String,
        view_id: u64,
        name: Option<String>,
        filter: Option<String>,
    },
    DeleteProjectView {
        project: String,
        view_id: u64,
    },
    AddProjectItem {
        project: String,
        content_type: String,
        content_id: u64,
    },
    AddProjectDraft {
        project: String,
        title: String,
        body: Option<String>,
    },
    UpdateProjectItem {
        project: String,
        item_id: u64,
        field_id: u64,
        value: serde_json::Value,
    },
    ArchiveProjectItem {
        project: String,
        item_node_id: String,
        archived: bool,
    },
    DeleteProjectItem {
        project: String,
        item_id: u64,
    },
    CreateProjectStatus {
        project: String,
        body: String,
        status: Option<String>,
    },
}

/// Per-item batch result. Earlier successful items are never rolled back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubManagementItemReceipt {
    pub index: usize,
    pub successful: bool,
    pub detail: String,
}

/// Narrow action seam used by Telegram and Slack GitHub workers.
pub trait GitHubActionSurface: Send {
    fn repository_aliases(&self) -> Vec<String>;

    fn repository_labels(&mut self, alias: &str) -> Result<Vec<String>, String>;

    fn issue_context(
        &mut self,
        locator: &IssueLocator,
        recent_comments: usize,
    ) -> Result<GitHubIssueContext, String>;

    fn create_issue(
        &mut self,
        action_id: &str,
        alias: &str,
        title: &str,
        body: &str,
        labels: &[String],
    ) -> Result<GitHubMutationReceipt, String>;

    fn reply_to_issue(
        &mut self,
        action_id: &str,
        locator: &IssueLocator,
        body: &str,
    ) -> Result<GitHubMutationReceipt, String>;

    fn set_checklist_item(
        &mut self,
        locator: &IssueLocator,
        item: &str,
        checked: bool,
    ) -> Result<GitHubMutationReceipt, String>;

    fn management_inventory(&self) -> GitHubManagementInventory {
        GitHubManagementInventory {
            repositories: Vec::new(),
            owners: Vec::new(),
            projects: Vec::new(),
            capabilities: Vec::new(),
        }
    }

    fn execute_management(
        &mut self,
        _action_id: &str,
        operations: &[GitHubManagementOperation],
    ) -> Vec<GitHubManagementItemReceipt> {
        operations
            .iter()
            .enumerate()
            .map(|(index, _)| GitHubManagementItemReceipt {
                index,
                successful: false,
                detail: String::from("status=refused reason=github_management_unavailable"),
            })
            .collect()
    }
}

/// How much of one authorized issue an operational question needs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueFactDetail {
    /// State/title/link metadata for multi-issue audits.
    Summary,
    /// Include the bounded issue body for a direct issue question.
    Full,
}

/// GitHub capability composed from an owner-only deployment file.
pub enum GitHubHost {
    Disabled,
    Configured(Box<GitHubWorkspace>),
}

impl GitHubHost {
    /// Compose the fixed-origin client without contacting GitHub.
    pub fn load(state_dir: &Path) -> Result<Self, GitHubConfigError> {
        let Some(config) = GitHubConfig::load(state_dir)? else {
            return Ok(Self::Disabled);
        };
        let token = active_gh_token()?;
        Ok(Self::Configured(Box::new(GitHubWorkspace {
            client: GitHubClient::new(GitHubBase::production(), token),
            repositories: config.repositories,
            aliases: config.aliases,
            owners: config.owners,
            projects: config.projects,
            management_capabilities: config.management_capabilities,
            journal_path: state_dir.join(JOURNAL_RELATIVE),
            prism_inventory_action: config.prism_inventory_action,
            create_issue_action: config.create_issue_action,
            reply_action: config.reply_action,
            checklist_action: config.checklist_action,
        })))
    }

    #[must_use]
    pub fn into_surface(self) -> Option<Box<dyn GitHubSurface + Send>> {
        match self {
            Self::Disabled => None,
            Self::Configured(workspace) => Some(workspace),
        }
    }

    #[must_use]
    pub fn into_action_surface(self) -> Option<Box<dyn GitHubActionSurface + Send>> {
        match self {
            Self::Disabled => None,
            Self::Configured(workspace)
                if workspace.create_issue_action
                    || workspace.reply_action
                    || workspace.checklist_action
                    || !workspace.management_capabilities.is_empty() =>
            {
                Some(workspace)
            }
            Self::Configured(_) => None,
        }
    }
}

impl fmt::Debug for GitHubHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Disabled => "GitHubHost::Disabled",
            Self::Configured(_) => "GitHubHost::Configured(<redacted>)",
        })
    }
}

/// Present configuration failures refuse startup rather than silently
/// degrading a deployment whose owner intended GitHub reads to work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubConfigError {
    Insecure,
    Unreadable,
    Malformed,
    TokenInvalid,
}

impl GitHubConfigError {
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Insecure => "github_config_insecure",
            Self::Unreadable => "github_config_unreadable",
            Self::Malformed => "github_config_malformed",
            Self::TokenInvalid => "github_config_token",
        }
    }
}

impl fmt::Display for GitHubConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "GitHub configuration refused: {}",
            self.category()
        )
    }
}

impl std::error::Error for GitHubConfigError {}

struct GitHubConfig {
    repositories: Vec<RepoTarget>,
    aliases: Vec<(String, RepoTarget)>,
    prism_inventory_action: bool,
    create_issue_action: bool,
    reply_action: bool,
    checklist_action: bool,
    owners: Vec<(String, ProjectOwner)>,
    projects: Vec<(String, ProjectRef)>,
    management_capabilities: BTreeSet<String>,
}

impl GitHubConfig {
    fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(CONFIG_RELATIVE)
    }

    fn load(state_dir: &Path) -> Result<Option<Self>, GitHubConfigError> {
        let path = Self::path(state_dir);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(GitHubConfigError::Unreadable),
        };
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() > MAX_CONFIG_BYTES
        {
            return Err(GitHubConfigError::Insecure);
        }
        let bytes = fs::read(path).map_err(|_| GitHubConfigError::Unreadable)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| GitHubConfigError::Malformed)?;
        parse_config(text).map(Some)
    }
}

fn parse_config(text: &str) -> Result<GitHubConfig, GitHubConfigError> {
    let mut lines = text.lines();
    let schema = match lines.next() {
        Some(READ_CONFIG_HEADER) => 1,
        Some(ACTION_CONFIG_HEADER) => 2,
        Some(TOOL_CONFIG_HEADER) => 3,
        Some(MANAGEMENT_CONFIG_HEADER) => 4,
        _ => return Err(GitHubConfigError::Malformed),
    };
    let mut credential = None;
    let mut repositories = Vec::new();
    let mut aliases = Vec::new();
    let mut prism_inventory_action = false;
    let mut create_issue_action = false;
    let mut reply_action = false;
    let mut checklist_action = false;
    let mut owners: Vec<(String, ProjectOwner)> = Vec::new();
    let mut pending_projects: Vec<(String, String, u64)> = Vec::new();
    let mut management_capabilities = BTreeSet::new();
    let mut ended = false;
    for line in lines {
        if ended {
            return Err(GitHubConfigError::Malformed);
        }
        if line == CONFIG_TERMINATOR {
            ended = true;
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(GitHubConfigError::Malformed)?;
        match key {
            "credential" if credential.is_none() && value == GH_CREDENTIAL => {
                credential = Some(());
            }
            "repo" => {
                let (alias, value) = if schema >= 3 {
                    let (alias, target) =
                        value.split_once(':').ok_or(GitHubConfigError::Malformed)?;
                    if !valid_repository_alias(alias)
                        || aliases.iter().any(|(seen, _)| seen == alias)
                    {
                        return Err(GitHubConfigError::Malformed);
                    }
                    (Some(alias.to_owned()), target)
                } else {
                    (None, value)
                };
                let (owner, repo) = value.split_once('/').ok_or(GitHubConfigError::Malformed)?;
                let target =
                    RepoTarget::parse(owner, repo).map_err(|_| GitHubConfigError::Malformed)?;
                if repositories.contains(&target)
                    || repositories.len() >= MAX_CONFIGURED_REPOSITORIES
                {
                    return Err(GitHubConfigError::Malformed);
                }
                repositories.push(target.clone());
                if let Some(alias) = alias {
                    aliases.push((alias, target));
                }
            }
            "action"
                if schema >= 2 && !prism_inventory_action && value == PRISM_INVENTORY_ACTION =>
            {
                prism_inventory_action = true;
            }
            "action" if schema >= 3 && !create_issue_action && value == CREATE_ISSUE_ACTION => {
                create_issue_action = true;
            }
            "action" if schema >= 3 && !reply_action && value == REPLY_ACTION => {
                reply_action = true;
            }
            "action" if schema >= 3 && !checklist_action && value == CHECKLIST_ACTION => {
                checklist_action = true;
            }
            "owner" if schema == 4 => {
                let mut fields = value.split(':');
                let alias = fields.next().ok_or(GitHubConfigError::Malformed)?;
                let kind = match fields.next() {
                    Some("organization") => ProjectOwnerKind::Organization,
                    Some("user") => ProjectOwnerKind::User,
                    _ => return Err(GitHubConfigError::Malformed),
                };
                let login = fields.next().ok_or(GitHubConfigError::Malformed)?;
                if fields.next().is_some()
                    || !valid_repository_alias(alias)
                    || owners.iter().any(|(seen, _)| seen == alias)
                {
                    return Err(GitHubConfigError::Malformed);
                }
                let login = Owner::new(login).map_err(|_| GitHubConfigError::Malformed)?;
                owners.push((alias.to_owned(), ProjectOwner::new(kind, login)));
            }
            "project" if schema == 4 => {
                let mut fields = value.split(':');
                let alias = fields.next().ok_or(GitHubConfigError::Malformed)?;
                let owner = fields.next().ok_or(GitHubConfigError::Malformed)?;
                let number = fields
                    .next()
                    .and_then(|value| value.parse().ok())
                    .ok_or(GitHubConfigError::Malformed)?;
                if fields.next().is_some()
                    || !valid_repository_alias(alias)
                    || pending_projects.iter().any(|(seen, _, _)| seen == alias)
                {
                    return Err(GitHubConfigError::Malformed);
                }
                pending_projects.push((alias.to_owned(), owner.to_owned(), number));
            }
            "capability"
                if schema == 4
                    && matches!(value, "issues" | "taxonomy" | "hierarchy" | "projects") =>
            {
                if !management_capabilities.insert(value.to_owned()) {
                    return Err(GitHubConfigError::Malformed);
                }
            }
            _ => return Err(GitHubConfigError::Malformed),
        }
    }
    if !ended {
        return Err(GitHubConfigError::Malformed);
    }
    if repositories.is_empty() && (schema != 4 || owners.is_empty()) {
        return Err(GitHubConfigError::Malformed);
    }
    credential.ok_or(GitHubConfigError::Malformed)?;
    let projects = pending_projects
        .into_iter()
        .map(|(alias, owner_alias, number)| {
            let owner = owners
                .iter()
                .find(|(seen, _)| seen == &owner_alias)
                .map(|(_, owner)| owner.clone())
                .ok_or(GitHubConfigError::Malformed)?;
            let number = DatabaseId::new(number).map_err(|_| GitHubConfigError::Malformed)?;
            Ok((alias, ProjectRef::new(owner, number)))
        })
        .collect::<Result<Vec<_>, GitHubConfigError>>()?;
    Ok(GitHubConfig {
        repositories,
        aliases,
        prism_inventory_action,
        create_issue_action,
        reply_action,
        checklist_action,
        owners,
        projects,
        management_capabilities,
    })
}

fn valid_repository_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REPOSITORY_ALIAS_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn management_capability(operation: &GitHubManagementOperation) -> &'static str {
    use GitHubManagementOperation as Op;
    match operation {
        Op::CreateLabel { .. }
        | Op::UpdateLabel { .. }
        | Op::DeleteLabel { .. }
        | Op::CreateMilestone { .. }
        | Op::UpdateMilestone { .. }
        | Op::DeleteMilestone { .. } => "taxonomy",
        Op::AddSubIssue { .. }
        | Op::RemoveSubIssue { .. }
        | Op::ReprioritizeSubIssue { .. }
        | Op::AddDependency { .. }
        | Op::RemoveDependency { .. } => "hierarchy",
        Op::CreateProject { .. }
        | Op::UpdateProject { .. }
        | Op::DeleteProject { .. }
        | Op::CreateProjectField { .. }
        | Op::UpdateProjectField { .. }
        | Op::DeleteProjectField { .. }
        | Op::CreateProjectView { .. }
        | Op::UpdateProjectView { .. }
        | Op::DeleteProjectView { .. }
        | Op::AddProjectItem { .. }
        | Op::AddProjectDraft { .. }
        | Op::UpdateProjectItem { .. }
        | Op::ArchiveProjectItem { .. }
        | Op::DeleteProjectItem { .. }
        | Op::CreateProjectStatus { .. } => "projects",
        Op::UpdateIssue { .. }
        | Op::LockIssue { .. }
        | Op::UnlockIssue { .. }
        | Op::TransferIssue { .. }
        | Op::SetIssuePinned { .. } => "issues",
    }
}

fn management_action_name(operation: &GitHubManagementOperation) -> &'static str {
    use GitHubManagementOperation as Op;
    match operation {
        Op::CreateLabel { .. } => "create_label",
        Op::UpdateLabel { .. } => "update_label",
        Op::DeleteLabel { .. } => "delete_label",
        Op::CreateMilestone { .. } => "create_milestone",
        Op::UpdateMilestone { .. } => "update_milestone",
        Op::DeleteMilestone { .. } => "delete_milestone",
        Op::UpdateIssue { .. } => "update_issue",
        Op::LockIssue { .. } => "lock_issue",
        Op::UnlockIssue { .. } => "unlock_issue",
        Op::AddSubIssue { .. } => "add_sub_issue",
        Op::RemoveSubIssue { .. } => "remove_sub_issue",
        Op::ReprioritizeSubIssue { .. } => "reprioritize_sub_issue",
        Op::AddDependency { .. } => "add_dependency",
        Op::RemoveDependency { .. } => "remove_dependency",
        Op::TransferIssue { .. } => "transfer_issue",
        Op::SetIssuePinned { .. } => "set_issue_pinned",
        Op::CreateProject { .. } => "create_project",
        Op::UpdateProject { .. } => "update_project",
        Op::DeleteProject { .. } => "delete_project",
        Op::CreateProjectField { .. } => "create_project_field",
        Op::UpdateProjectField { .. } => "update_project_field",
        Op::DeleteProjectField { .. } => "delete_project_field",
        Op::CreateProjectView { .. } => "create_project_view",
        Op::UpdateProjectView { .. } => "update_project_view",
        Op::DeleteProjectView { .. } => "delete_project_view",
        Op::AddProjectItem { .. } => "add_project_item",
        Op::AddProjectDraft { .. } => "add_project_draft",
        Op::UpdateProjectItem { .. } => "update_project_item",
        Op::ArchiveProjectItem { .. } => "archive_project_item",
        Op::DeleteProjectItem { .. } => "delete_project_item",
        Op::CreateProjectStatus { .. } => "create_project_status",
    }
}

fn exact_management_locator(url: &str) -> Result<IssueLocator, String> {
    let locator = IssueLocator::parse(url)
        .ok_or_else(|| String::from("status=refused reason=github_issue_url_invalid"))?;
    let canonical = format!(
        "https://github.com/{}/issues/{}",
        locator.target(),
        locator.number()
    );
    let pull = format!(
        "https://github.com/{}/pull/{}",
        locator.target(),
        locator.number()
    );
    (canonical == url || pull == url)
        .then_some(locator)
        .ok_or_else(|| String::from("status=refused reason=github_issue_url_not_canonical"))
}

fn parse_lock_reason(value: &str) -> Result<LockReason, String> {
    match value {
        "off_topic" | "off-topic" => Ok(LockReason::OffTopic),
        "too_heated" | "too heated" => Ok(LockReason::TooHeated),
        "resolved" => Ok(LockReason::Resolved),
        "spam" => Ok(LockReason::Spam),
        _ => Err(String::from(
            "status=refused reason=management_plan_invalid",
        )),
    }
}

fn parse_field_type(value: &str) -> Result<ProjectFieldType, String> {
    match value {
        "text" => Ok(ProjectFieldType::Text),
        "number" => Ok(ProjectFieldType::Number),
        "date" => Ok(ProjectFieldType::Date),
        "single_select" => Ok(ProjectFieldType::SingleSelect),
        "multi_select" => Ok(ProjectFieldType::MultiSelect),
        "iteration" => Ok(ProjectFieldType::Iteration),
        _ => Err(String::from(
            "status=refused reason=management_plan_invalid",
        )),
    }
}

fn parse_view_layout(value: &str) -> Result<ProjectViewLayout, String> {
    match value {
        "table" => Ok(ProjectViewLayout::Table),
        "board" => Ok(ProjectViewLayout::Board),
        "roadmap" => Ok(ProjectViewLayout::Roadmap),
        _ => Err(String::from(
            "status=refused reason=management_plan_invalid",
        )),
    }
}

fn parse_project_status(value: &str) -> Result<ProjectStatus, String> {
    match value {
        "on_track" => Ok(ProjectStatus::OnTrack),
        "at_risk" => Ok(ProjectStatus::AtRisk),
        "off_track" => Ok(ProjectStatus::OffTrack),
        "complete" => Ok(ProjectStatus::Complete),
        "inactive" => Ok(ProjectStatus::Inactive),
        _ => Err(String::from(
            "status=refused reason=management_plan_invalid",
        )),
    }
}

fn parse_project_item_type(value: &str) -> Result<ProjectItemType, String> {
    match value {
        "issue" => Ok(ProjectItemType::Issue),
        "pull_request" | "pr" => Ok(ProjectItemType::PullRequest),
        _ => Err(String::from(
            "status=refused reason=management_plan_invalid",
        )),
    }
}

fn recent_comment_pages(comment_count: u32, keep: usize) -> Option<(u32, u32)> {
    let keep = u32::try_from(keep).ok()?.min(comment_count);
    if keep == 0 {
        return None;
    }
    let first = (comment_count.saturating_sub(keep) / PAGE_SIZE) + 1;
    let last = ((comment_count - 1) / PAGE_SIZE) + 1;
    Some((first, last))
}

/// Borrow the task-relevant credential already managed by the GitHub CLI.
///
/// The executable and argv are compile-time constants; no model or chat text
/// can become a command string. stderr is discarded, stdout is immediately
/// validated by the connector's credential type, and neither is rendered.
fn active_gh_token() -> Result<GitHubToken, GitHubConfigError> {
    let metadata = fs::metadata(GH_EXECUTABLE).map_err(|_| GitHubConfigError::Unreadable)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o022 != 0 {
        return Err(GitHubConfigError::Insecure);
    }
    let mut output = Command::new(GH_EXECUTABLE)
        .args(["auth", "token"])
        .output()
        .map_err(|_| GitHubConfigError::Unreadable)?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(GitHubConfigError::TokenInvalid);
    }
    while matches!(output.stdout.last(), Some(b'\n' | b'\r')) {
        output.stdout.pop();
    }
    GitHubToken::new(output.stdout).map_err(|_| GitHubConfigError::TokenInvalid)
}

/// Fixed-origin production implementation.
pub struct GitHubWorkspace {
    client: GitHubClient,
    repositories: Vec<RepoTarget>,
    aliases: Vec<(String, RepoTarget)>,
    prism_inventory_action: bool,
    create_issue_action: bool,
    reply_action: bool,
    checklist_action: bool,
    owners: Vec<(String, ProjectOwner)>,
    projects: Vec<(String, ProjectRef)>,
    management_capabilities: BTreeSet<String>,
    journal_path: PathBuf,
}

impl fmt::Debug for GitHubWorkspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitHubWorkspace(<redacted>)")
    }
}

impl GitHubSurface for GitHubWorkspace {
    fn configured_repositories(&self) -> Vec<String> {
        self.repositories.iter().map(ToString::to_string).collect()
    }

    fn repository_push_activity(
        &mut self,
        window: RepositoryActivityWindow,
        now_ms: i64,
    ) -> Result<String, String> {
        let bounds = RepositoryActivityBounds::new(window, now_ms)
            .ok_or_else(|| String::from("status=refused reason=github_activity_clock_invalid"))?;
        if self.repositories.is_empty() {
            return Err(String::from(
                "status=refused reason=github_repository_allowlist_empty",
            ));
        }

        let mut active = Vec::new();
        let mut unavailable = Vec::new();
        for target in &self.repositories {
            let reply = match self
                .client
                .get_repository(&GetRepositoryRequest::new(target.clone()))
            {
                Ok(reply) => reply,
                Err(failure) => {
                    unavailable.push(format!("{target}:{}", failure.category()));
                    continue;
                }
            };
            let repository = match reply.into_outcome() {
                GitHubOutcome::Accepted(repository) => repository,
                GitHubOutcome::Rejected(rejection) => {
                    unavailable.push(format!("{target}:{}", rejection.kind().category()));
                    continue;
                }
            };
            if repository.target != *target {
                unavailable.push(format!("{target}:repository_identity_mismatch"));
                continue;
            }
            let Some(pushed_key) = utc_timestamp_sort_key(&repository.pushed_at) else {
                unavailable.push(format!("{target}:pushed_at_invalid"));
                continue;
            };
            if bounds.contains(&pushed_key) {
                active.push((target.to_string(), repository.pushed_at));
            }
        }

        Ok(render_repository_push_activity(
            &bounds,
            self.repositories.len(),
            &active,
            &unavailable,
        ))
    }

    fn issue_facts(
        &mut self,
        locator: &IssueLocator,
        detail: IssueFactDetail,
    ) -> Result<String, String> {
        if !self
            .repositories
            .iter()
            .any(|target| target == locator.target())
        {
            return Err(String::from(
                "status=refused reason=repository_not_configured",
            ));
        }
        let request = GetIssueRequest::new(locator.target().clone(), locator.number());
        let reply = self
            .client
            .get_issue(&request)
            .map_err(|failure| format!("status=unavailable reason={}", failure.category()))?;
        let issue = match reply.into_outcome() {
            GitHubOutcome::Accepted(issue) => issue,
            GitHubOutcome::Rejected(rejection) => {
                return Err(format!(
                    "status=refused reason={}",
                    rejection.kind().category()
                ));
            }
        };
        let mut facts = format!(
            "status=available\nreference={}#{}\nurl={}\nstate={}\ntitle_untrusted={}\nlabels={}\ncomments={}\nupdated={}",
            issue.target,
            issue.number,
            single_line(&issue.url),
            issue.state.as_str(),
            single_line(&issue.title),
            issue
                .labels
                .iter()
                .map(|label| single_line(label))
                .collect::<Vec<_>>()
                .join(", "),
            issue.comment_count,
            single_line(&issue.updated_at),
        );
        if detail == IssueFactDetail::Full {
            facts.push_str("\nauthor=");
            facts.push_str(&single_line(&issue.author));
            facts.push_str("\ncreated=");
            facts.push_str(&single_line(&issue.created_at));
            facts.push_str("\nbody_untrusted=");
            facts.push_str(&bounded_field(&issue.body, MAX_ISSUE_BODY_CONTEXT_BYTES));
            match self.recent_issue_comments(locator, issue.comment_count, MAX_ISSUE_FACT_COMMENTS)
            {
                Ok(comments) => append_recent_comment_facts(
                    &mut facts,
                    &comments,
                    issue.comment_count as usize > comments.len(),
                ),
                Err(error) => {
                    facts.push_str("\nrecent_comments_status=unavailable\nrecent_comments_reason=");
                    facts.push_str(&single_line(&error));
                }
            }
        }
        Ok(facts)
    }

    fn complete_prism_inventory(
        &mut self,
        locator: &IssueLocator,
        report: &str,
    ) -> Result<String, String> {
        if !self.prism_inventory_action {
            return Err(String::from(
                "status=refused reason=github_actions_unavailable",
            ));
        }
        if !self
            .repositories
            .iter()
            .any(|target| target == locator.target())
        {
            return Err(String::from(
                "status=refused reason=repository_not_configured",
            ));
        }
        let issue = accepted(
            self.client
                .get_issue(&GetIssueRequest::new(
                    locator.target().clone(),
                    locator.number(),
                ))
                .map_err(|failure| format!("status=unavailable reason={}", failure.category()))?,
        )?;
        if !is_prism_inventory_issue(&issue.title, &issue.body) {
            return Err(String::from(
                "status=refused reason=issue_requires_workspace_execution",
            ));
        }

        let digest = Sha256::digest(report.as_bytes()).to_hex();
        let marker = format!("<!-- automonique:prism-inventory:{digest} -->");
        let comments = accepted(
            self.client
                .get_comments(&GetCommentsRequest::new(
                    locator.target().clone(),
                    locator.number(),
                    Page::new(1, 100).map_err(|_| {
                        String::from("status=unavailable reason=invalid_reconciliation_page")
                    })?,
                ))
                .map_err(|failure| format!("status=unavailable reason={}", failure.category()))?,
        )?;
        let existing = comments
            .iter()
            .find(|comment| comment.body.contains(&marker));
        let comment_url = if let Some(comment) = existing {
            format!(
                "https://github.com/{}/issues/{}#issuecomment-{}",
                locator.target(),
                locator.number(),
                comment.id
            )
        } else {
            let body = IssueBodyText::new(&format!("{report}\n\n{marker}"))
                .map_err(|_| String::from("status=refused reason=inventory_report_invalid"))?;
            let request = CommentRequest::new(locator.target().clone(), locator.number(), body);
            let reply = self.client.comment(&request).map_err(|failure| {
                // A transport failure after the request left the host has an
                // unknown result. A later explicit retry first reads the marker
                // and reconciles instead of blindly posting again.
                format!(
                    "status=ambiguous reason={} action=retry_to_reconcile",
                    failure.category()
                )
            })?;
            accepted(reply)?.url
        };

        if issue.state != IssueState::Closed {
            let close = SetStateRequest::new(
                locator.target().clone(),
                locator.number(),
                IssueState::Closed,
            );
            match self.client.set_state(&close) {
                Ok(reply) => {
                    let closed = accepted(reply)?;
                    if closed.state != IssueState::Closed {
                        return Err(String::from(
                            "status=ambiguous reason=state_not_closed action=retry_to_reconcile",
                        ));
                    }
                }
                Err(failure) => {
                    // Re-read before declaring the close ambiguous: GitHub may
                    // have applied it before the response was lost.
                    let observed = self.client.get_issue(&GetIssueRequest::new(
                        locator.target().clone(),
                        locator.number(),
                    ));
                    let reconciled = match observed {
                        Ok(reply) => matches!(
                            reply.into_outcome(),
                            GitHubOutcome::Accepted(issue) if issue.state == IssueState::Closed
                        ),
                        Err(_) => false,
                    };
                    if !reconciled {
                        return Err(format!(
                            "status=ambiguous reason={} action=retry_to_reconcile",
                            failure.category()
                        ));
                    }
                }
            }
        }
        Ok(format!(
            "Ticket {}#{} completed: the current Prism inventory was posted and the issue is closed.\n{}",
            locator.target(),
            locator.number(),
            comment_url
        ))
    }
}

/// Normalize GitHub's UTC RFC 3339 timestamps to a lexically sortable
/// millisecond key. GitHub currently answers with whole seconds while the
/// daemon clock includes milliseconds; accepting both avoids a false boundary
/// match without introducing a general date parser into the connector.
fn utc_timestamp_sort_key(value: &str) -> Option<String> {
    let value = value.trim();
    if !value.ends_with('Z') || !(20..=32).contains(&value.len()) {
        return None;
    }
    let base = value.get(..19)?;
    let bytes = base.as_bytes();
    let shaped = bytes.len() == 19
        && matches!(bytes[4], b'-')
        && matches!(bytes[7], b'-')
        && matches!(bytes[10], b'T')
        && matches!(bytes[13], b':')
        && matches!(bytes[16], b':')
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7 | 10 | 13 | 16) || byte.is_ascii_digit());
    if !shaped {
        return None;
    }
    let month = base.get(5..7)?.parse::<u8>().ok()?;
    let day = base.get(8..10)?.parse::<u8>().ok()?;
    let hour = base.get(11..13)?.parse::<u8>().ok()?;
    let minute = base.get(14..16)?.parse::<u8>().ok()?;
    let second = base.get(17..19)?.parse::<u8>().ok()?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let fraction = value.get(19..value.len() - 1)?;
    let milliseconds = if fraction.is_empty() {
        String::from("000")
    } else {
        let digits = fraction.strip_prefix('.')?;
        if digits.is_empty()
            || digits.len() > 3
            || !digits.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        format!("{digits:0<3}").chars().take(3).collect()
    };
    Some(format!("{base}.{milliseconds}Z"))
}

/// One exact half-open UTC interval, computed solely from the injected clock.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RepositoryActivityBounds {
    window: RepositoryActivityWindow,
    lower_inclusive: Option<String>,
    upper_exclusive: String,
}

impl RepositoryActivityBounds {
    fn new(window: RepositoryActivityWindow, now_ms: i64) -> Option<Self> {
        if now_ms < 0 {
            return None;
        }
        let today_ms = now_ms.checked_sub(now_ms.rem_euclid(UTC_DAY_MILLIS))?;
        let lower_ms = match window {
            RepositoryActivityWindow::All => None,
            RepositoryActivityWindow::ThisWeek => {
                let unix_day = today_ms.div_euclid(UTC_DAY_MILLIS);
                // 1970-01-01 was Thursday: three complete days after Monday.
                let days_since_monday = (unix_day + 3).rem_euclid(7);
                Some(today_ms.checked_sub(days_since_monday * UTC_DAY_MILLIS)?)
            }
            RepositoryActivityWindow::Today => Some(today_ms),
            RepositoryActivityWindow::Yesterday => Some(today_ms.checked_sub(UTC_DAY_MILLIS)?),
            RepositoryActivityWindow::Last7Days => Some(now_ms.checked_sub(7 * UTC_DAY_MILLIS)?),
        };
        let upper_ms = if window == RepositoryActivityWindow::Yesterday {
            today_ms
        } else {
            now_ms
        };
        let lower_inclusive = match lower_ms {
            Some(milliseconds) => Some(utc_rfc3339_from_unix_millis(milliseconds)?),
            None => None,
        };
        let upper_exclusive = utc_rfc3339_from_unix_millis(upper_ms)?;
        Some(Self {
            window,
            lower_inclusive,
            upper_exclusive,
        })
    }

    fn contains(&self, pushed_key: &str) -> bool {
        self.lower_inclusive
            .as_ref()
            .is_none_or(|lower| pushed_key >= lower.as_str())
            && pushed_key < self.upper_exclusive.as_str()
    }
}

/// Render a bounded, provenance-explicit projection for conversational use.
fn render_repository_push_activity(
    bounds: &RepositoryActivityBounds,
    checked: usize,
    active: &[(String, String)],
    unavailable: &[String],
) -> String {
    let mut facts = format!(
        "status=available\nscope=configured_repository_allowlist\nactivity_basis=github_repository_pushed_at\nwindow={}\nlower_inclusive={}\nupper_exclusive={}\nrepositories_checked={checked}\nrepositories_with_push_activity={}",
        bounds.window.as_str(),
        bounds.lower_inclusive.as_deref().unwrap_or("unbounded"),
        bounds.upper_exclusive,
        active.len(),
    );
    for (repository, pushed_at) in active {
        facts.push_str("\nactive_repository=");
        facts.push_str(repository);
        facts.push_str(" pushed_at=");
        facts.push_str(&single_line(pushed_at));
    }
    facts.push_str("\nrepositories_unavailable=");
    facts.push_str(&unavailable.len().to_string());
    for entry in unavailable {
        facts.push_str("\nunavailable_repository=");
        facts.push_str(entry);
    }
    facts.push_str(
        "\nscope_note=This is the configured local allowlist, not an organization-wide inventory. pushed_at proves Git push activity, not issue, project, or local unpushed work.",
    );
    facts
}

impl GitHubActionSurface for GitHubWorkspace {
    fn repository_aliases(&self) -> Vec<String> {
        self.aliases
            .iter()
            .map(|(alias, _)| alias.clone())
            .collect()
    }

    fn repository_labels(&mut self, alias: &str) -> Result<Vec<String>, String> {
        let target = self.target_for_alias(alias)?.clone();
        let mut labels = Vec::new();
        for number in 1..=10 {
            let page = Page::new(number, PAGE_SIZE)
                .map_err(|_| String::from("status=unavailable reason=invalid_label_page"))?;
            let rows = accepted(
                self.client
                    .list_labels(&ListLabelsRequest::new(target.clone(), page))
                    .map_err(unavailable)?,
            )?;
            let full = rows.len() == PAGE_SIZE as usize;
            labels.extend(rows);
            if !full {
                labels.sort();
                labels.dedup();
                return Ok(labels);
            }
        }
        Err(String::from(
            "status=refused reason=repository_label_inventory_too_large",
        ))
    }

    fn issue_context(
        &mut self,
        locator: &IssueLocator,
        recent_comments: usize,
    ) -> Result<GitHubIssueContext, String> {
        self.require_repository(locator.target())?;
        let issue = accepted(
            self.client
                .get_issue(&GetIssueRequest::new(
                    locator.target().clone(),
                    locator.number(),
                ))
                .map_err(unavailable)?,
        )?;
        let keep = recent_comments.min(PAGE_SIZE as usize);
        let comments = self.recent_issue_comments(locator, issue.comment_count, keep)?;
        let comments = comments
            .into_iter()
            .rev()
            .take(keep)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(|comment| GitHubContextComment {
                author: comment.author,
                body: comment.body,
                updated_at: comment.updated_at,
            })
            .collect();
        Ok(GitHubIssueContext {
            url: issue.url,
            title: issue.title,
            body: issue.body,
            comments,
            comments_truncated: issue.comment_count as usize > keep,
        })
    }

    fn create_issue(
        &mut self,
        action_id: &str,
        alias: &str,
        title: &str,
        body: &str,
        labels: &[String],
    ) -> Result<GitHubMutationReceipt, String> {
        if !self.create_issue_action {
            return Err(actions_unavailable());
        }
        let target = self.target_for_alias(alias)?.clone();
        let marker = action_marker(action_id);
        if let Some(url) = self.find_issue_marker(&target, &marker)? {
            return Ok(GitHubMutationReceipt {
                url,
                recovered: true,
                unchanged: false,
            });
        }
        let title = IssueTitle::new(title)
            .map_err(|_| String::from("status=refused reason=generated_issue_title_invalid"))?;
        let body = IssueBodyText::new(&format!("{}\n\n{}", body.trim(), marker))
            .map_err(|_| String::from("status=refused reason=generated_issue_body_invalid"))?;
        let labels = labels
            .iter()
            .map(|label| {
                Label::new(label).map_err(|_| {
                    String::from("status=refused reason=generated_issue_label_invalid")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let request = CreateIssueRequest::new(target.clone(), title, body, labels)
            .map_err(|_| String::from("status=refused reason=generated_issue_invalid"))?;
        let reply = match self.client.create_issue(&request) {
            Ok(reply) => reply,
            Err(failure) => {
                if let Some(url) = self.find_issue_marker(&target, &marker)? {
                    return Ok(GitHubMutationReceipt {
                        url,
                        recovered: true,
                        unchanged: false,
                    });
                }
                return Err(format!(
                    "status=ambiguous reason={} action=do_not_retry_blindly",
                    failure.category()
                ));
            }
        };
        let issue = accepted(reply)?;
        Ok(GitHubMutationReceipt {
            url: issue.url,
            recovered: false,
            unchanged: false,
        })
    }

    fn reply_to_issue(
        &mut self,
        action_id: &str,
        locator: &IssueLocator,
        body: &str,
    ) -> Result<GitHubMutationReceipt, String> {
        if !self.reply_action {
            return Err(actions_unavailable());
        }
        self.require_repository(locator.target())?;
        let marker = action_marker(action_id);
        if let Some(url) = self.find_comment_marker(locator, &marker)? {
            return Ok(GitHubMutationReceipt {
                url,
                recovered: true,
                unchanged: false,
            });
        }
        let body = IssueBodyText::new(&format!("{}\n\n{}", body.trim(), marker))
            .map_err(|_| String::from("status=refused reason=generated_comment_invalid"))?;
        let request = CommentRequest::new(locator.target().clone(), locator.number(), body);
        let reply = match self.client.comment(&request) {
            Ok(reply) => reply,
            Err(failure) => {
                if let Some(url) = self.find_comment_marker(locator, &marker)? {
                    return Ok(GitHubMutationReceipt {
                        url,
                        recovered: true,
                        unchanged: false,
                    });
                }
                return Err(format!(
                    "status=ambiguous reason={} action=do_not_retry_blindly",
                    failure.category()
                ));
            }
        };
        let comment = accepted(reply)?;
        Ok(GitHubMutationReceipt {
            url: comment.url,
            recovered: false,
            unchanged: false,
        })
    }

    fn set_checklist_item(
        &mut self,
        locator: &IssueLocator,
        item: &str,
        checked: bool,
    ) -> Result<GitHubMutationReceipt, String> {
        if !self.checklist_action {
            return Err(actions_unavailable());
        }
        self.require_repository(locator.target())?;
        let issue = accepted(
            self.client
                .get_issue(&GetIssueRequest::new(
                    locator.target().clone(),
                    locator.number(),
                ))
                .map_err(unavailable)?,
        )?;
        let comments = self.all_comments(locator, issue.comment_count)?;
        let mut matches = Vec::new();
        if checklist_match_count(&issue.body, item) > 0 {
            matches.push(ChecklistTarget::Issue);
        }
        for comment in &comments {
            if checklist_match_count(&comment.body, item) > 0 {
                matches.push(ChecklistTarget::Comment(comment.id));
            }
        }
        let [target] = matches.as_slice() else {
            return Err(String::from(if matches.is_empty() {
                "status=refused reason=checklist_item_not_found"
            } else {
                "status=refused reason=checklist_item_ambiguous"
            }));
        };
        match target {
            ChecklistTarget::Issue => self.update_issue_checklist(locator, item, checked),
            ChecklistTarget::Comment(id) => {
                self.update_comment_checklist(locator, *id, item, checked)
            }
        }
    }

    fn management_inventory(&self) -> GitHubManagementInventory {
        GitHubManagementInventory {
            repositories: self
                .aliases
                .iter()
                .map(|(alias, _)| alias.clone())
                .collect(),
            owners: self.owners.iter().map(|(alias, _)| alias.clone()).collect(),
            projects: self
                .projects
                .iter()
                .map(|(alias, _)| alias.clone())
                .collect(),
            capabilities: self.management_capabilities.iter().cloned().collect(),
        }
    }

    fn execute_management(
        &mut self,
        action_id: &str,
        operations: &[GitHubManagementOperation],
    ) -> Vec<GitHubManagementItemReceipt> {
        operations
            .iter()
            .enumerate()
            .map(|(index, operation)| {
                match self.execute_management_operation(action_id, index, operation) {
                    Ok(detail) => GitHubManagementItemReceipt {
                        index,
                        successful: true,
                        detail,
                    },
                    Err(detail) => GitHubManagementItemReceipt {
                        index,
                        successful: false,
                        detail,
                    },
                }
            })
            .collect()
    }
}

impl GitHubWorkspace {
    fn recent_issue_comments(
        &self,
        locator: &IssueLocator,
        comment_count: u32,
        keep: usize,
    ) -> Result<Vec<GitHubComment>, String> {
        if comment_count == 0 || keep == 0 {
            return Ok(Vec::new());
        }
        let (first_page, last_page) = recent_comment_pages(comment_count, keep)
            .ok_or_else(|| String::from("status=refused reason=issue_history_too_large"))?;
        let mut comments = Vec::new();
        for number in first_page..=last_page {
            let page = Page::new(number, PAGE_SIZE)
                .map_err(|_| String::from("status=refused reason=issue_history_too_large"))?;
            comments.extend(accepted(
                self.client
                    .get_comments(&GetCommentsRequest::new(
                        locator.target().clone(),
                        locator.number(),
                        page,
                    ))
                    .map_err(unavailable)?,
            )?);
        }
        Ok(comments
            .into_iter()
            .rev()
            .take(keep)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect())
    }
}

fn append_recent_comment_facts(facts: &mut String, comments: &[GitHubComment], truncated: bool) {
    facts.push_str("\nrecent_comments_status=available\nrecent_comments_returned=");
    facts.push_str(&comments.len().to_string());
    facts.push_str("\nrecent_comments_truncated=");
    facts.push_str(if truncated { "true" } else { "false" });
    for (index, comment) in comments.iter().enumerate() {
        let number = index + 1;
        facts.push_str(&format!("\ncomment_{number}_author="));
        facts.push_str(&single_line(&comment.author));
        facts.push_str(&format!("\ncomment_{number}_updated="));
        facts.push_str(&single_line(&comment.updated_at));
        facts.push_str(&format!("\ncomment_{number}_body_untrusted="));
        facts.push_str(&bounded_field(
            &comment.body,
            MAX_ISSUE_COMMENT_CONTEXT_BYTES,
        ));
    }
}

enum ChecklistTarget {
    Issue,
    Comment(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalState {
    Absent,
    Started,
    Completed,
    Failed,
}

impl GitHubWorkspace {
    fn execute_management_operation(
        &mut self,
        action_id: &str,
        index: usize,
        operation: &GitHubManagementOperation,
    ) -> Result<String, String> {
        let capability = management_capability(operation);
        if !self.management_capabilities.contains(capability) {
            return Err(format!(
                "status=refused reason=github_{capability}_capability_disabled"
            ));
        }
        let (request, mut audit_target) = self.management_request(operation)?;
        let path = request.path().to_owned();
        match self.journal_state(action_id, index)? {
            JournalState::Completed => return Ok(format!("recovered {path}")),
            JournalState::Started => {
                return Err(String::from(
                    "status=ambiguous reason=management_action_started action=inspect_before_retry",
                ));
            }
            JournalState::Absent | JournalState::Failed => {}
        }
        self.append_journal(
            action_id,
            index,
            "started",
            management_action_name(operation),
            &path,
        )?;
        let reply = self.client.manage(&request).map_err(unavailable)?;
        let receipt = match accepted(reply) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.append_journal(
                    action_id,
                    index,
                    "failed",
                    management_action_name(operation),
                    &path,
                )?;
                return Err(error);
            }
        };

        if matches!(operation, GitHubManagementOperation::TransferIssue { .. }) {
            let transferred_url = receipt
                .value()
                .and_then(|value| value.pointer("/data/transferIssue/issue/url"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    String::from(
                        "status=ambiguous reason=transferred_issue_url_missing action=inspect_before_retry",
                    )
                })?;
            audit_target = Some(exact_management_locator(transferred_url).map_err(|_| {
                String::from(
                    "status=ambiguous reason=transferred_issue_url_invalid action=inspect_before_retry",
                )
            })?);
        }

        if matches!(
            operation,
            GitHubManagementOperation::CreateProject {
                public: Some(true),
                ..
            }
        ) {
            let project_node = receipt
                .value()
                .and_then(|value| value.pointer("/data/createProjectV2/projectV2/id"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    String::from(
                        "status=ambiguous reason=created_project_node_missing action=inspect_before_retry",
                    )
                })?;
            let project_node = ManagementName::new(project_node).map_err(|_| {
                String::from(
                    "status=ambiguous reason=created_project_node_invalid action=inspect_before_retry",
                )
            })?;
            let publish =
                ManagementRequest::update_project(project_node, None, None, Some(true), None);
            let publish_reply = self.client.manage(&publish).map_err(|_| {
                String::from(
                    "status=ambiguous reason=public_project_followup_unavailable action=inspect_before_retry",
                )
            })?;
            accepted(publish_reply).map_err(|_| {
                String::from(
                    "status=ambiguous reason=public_project_followup_failed action=inspect_before_retry",
                )
            })?;
        }
        if let Some(locator) = audit_target {
            let marker = action_marker(action_id);
            let body = IssueBodyText::new(&format!(
                "Automonique applied the requested GitHub management change (`{}`).\n\n{}",
                management_action_name(operation),
                marker
            ))
            .map_err(|_| String::from("status=refused reason=management_audit_invalid"))?;
            let comment = CommentRequest::new(locator.target().clone(), locator.number(), body);
            accepted(self.client.comment(&comment).map_err(unavailable)?)?;
        }
        self.append_journal(
            action_id,
            index,
            "completed",
            management_action_name(operation),
            &path,
        )?;
        Ok(format!("completed {path}"))
    }

    fn journal_state(&self, action_id: &str, index: usize) -> Result<JournalState, String> {
        let bytes = match fs::read(&self.journal_path) {
            Ok(bytes) if bytes.len() <= 4 * 1024 * 1024 => bytes,
            Ok(_) => {
                return Err(String::from(
                    "status=unavailable reason=github_journal_too_large",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(JournalState::Absent);
            }
            Err(_) => {
                return Err(String::from(
                    "status=unavailable reason=github_journal_unreadable",
                ));
            }
        };
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| String::from("status=unavailable reason=github_journal_invalid"))?;
        let key = Sha256::digest(action_id.as_bytes()).to_hex();
        let prefix = format!("{key}\t{index}\t");
        let mut state = JournalState::Absent;
        for line in text.lines().filter(|line| line.starts_with(&prefix)) {
            state = if line[prefix.len()..].starts_with("completed\t") {
                JournalState::Completed
            } else if line[prefix.len()..].starts_with("started\t") {
                JournalState::Started
            } else {
                JournalState::Failed
            };
        }
        Ok(state)
    }

    fn append_journal(
        &self,
        action_id: &str,
        index: usize,
        state: &str,
        action: &str,
        path: &str,
    ) -> Result<(), String> {
        let key = Sha256::digest(action_id.as_bytes()).to_hex();
        let parent = self
            .journal_path
            .parent()
            .ok_or_else(|| String::from("status=unavailable reason=github_journal_path"))?;
        fs::create_dir_all(parent)
            .map_err(|_| String::from("status=unavailable reason=github_journal_unwritable"))?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&self.journal_path)
            .map_err(|_| String::from("status=unavailable reason=github_journal_unwritable"))?;
        let metadata = file
            .metadata()
            .map_err(|_| String::from("status=unavailable reason=github_journal_unreadable"))?;
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(String::from(
                "status=unavailable reason=github_journal_insecure",
            ));
        }
        writeln!(
            file,
            "{key}\t{index}\t{state}\t{action}\t{}",
            single_line(path)
        )
        .and_then(|()| file.sync_data())
        .map_err(|_| String::from("status=unavailable reason=github_journal_unwritable"))
    }

    fn management_request(
        &self,
        operation: &GitHubManagementOperation,
    ) -> Result<(ManagementRequest, Option<IssueLocator>), String> {
        use GitHubManagementOperation as Op;
        let invalid = |_| String::from("status=refused reason=management_plan_invalid");
        let name = |value: &str| ManagementName::new(value).map_err(invalid);
        let text = |value: &str| ManagementText::new(value).map_err(invalid);
        let optional_text = |value: &Option<String>| value.as_deref().map(&text).transpose();
        let id = |value| DatabaseId::new(value).map_err(invalid);
        let repo = |alias: &str| self.target_for_alias(alias).cloned();
        let project = |alias: &str| self.project_for_coordinate(alias);
        let issue = |url: &str| exact_management_locator(url);

        let (request, audit) = match operation {
            Op::CreateLabel {
                repo: alias,
                name: label,
                color,
                description,
            } => (
                ManagementRequest::create_label(
                    repo(alias)?,
                    name(label)?,
                    LabelColor::new(color).map_err(invalid)?,
                    optional_text(description)?,
                ),
                None,
            ),
            Op::UpdateLabel {
                repo: alias,
                current,
                name: label,
                color,
                description,
            } => (
                ManagementRequest::update_label(
                    repo(alias)?,
                    name(current)?,
                    name(label)?,
                    LabelColor::new(color).map_err(invalid)?,
                    optional_text(description)?,
                ),
                None,
            ),
            Op::DeleteLabel {
                repo: alias,
                name: label,
            } => (
                ManagementRequest::delete_label(repo(alias)?, name(label)?),
                None,
            ),
            Op::CreateMilestone {
                repo: alias,
                title,
                description,
                due_on,
            } => (
                ManagementRequest::create_milestone(
                    repo(alias)?,
                    name(title)?,
                    optional_text(description)?,
                    optional_text(due_on)?,
                ),
                None,
            ),
            Op::UpdateMilestone {
                repo: alias,
                milestone,
                title,
                description,
                due_on,
                open,
            } => {
                if title.is_none() && description.is_none() && due_on.is_none() && open.is_none() {
                    return Err(String::from(
                        "status=refused reason=management_plan_empty_update",
                    ));
                }
                (
                    ManagementRequest::update_milestone(
                        repo(alias)?,
                        id(*milestone)?,
                        title.as_deref().map(&name).transpose()?,
                        optional_text(description)?,
                        optional_text(due_on)?,
                        *open,
                    ),
                    None,
                )
            }
            Op::DeleteMilestone {
                repo: alias,
                milestone,
            } => (
                ManagementRequest::delete_milestone(repo(alias)?, id(*milestone)?),
                None,
            ),
            Op::UpdateIssue {
                issue_url,
                title,
                body,
                open,
                completed,
                milestone,
                clear_milestone,
                labels,
                assignees,
                issue_type,
                clear_issue_type,
            } => {
                if clear_milestone.unwrap_or(false) && milestone.is_some()
                    || clear_issue_type.unwrap_or(false) && issue_type.is_some()
                    || completed.is_some() && open.is_none()
                    || matches!(open, Some(true)) && completed.is_some()
                {
                    return Err(String::from(
                        "status=refused reason=management_plan_conflicting_update",
                    ));
                }
                if title.is_none()
                    && body.is_none()
                    && open.is_none()
                    && milestone.is_none()
                    && !clear_milestone.unwrap_or(false)
                    && labels.is_none()
                    && assignees.is_none()
                    && issue_type.is_none()
                    && !clear_issue_type.unwrap_or(false)
                {
                    return Err(String::from(
                        "status=refused reason=management_plan_empty_update",
                    ));
                }
                let locator = issue(issue_url)?;
                self.require_repository(locator.target())?;
                let mut patch = IssueManagementPatch::new();
                if let Some(value) = title {
                    patch = patch.title(name(value)?);
                }
                if let Some(value) = body {
                    patch = patch.body(text(value)?);
                }
                if let Some(open) = open {
                    patch = patch.state(*open, completed.unwrap_or(true));
                }
                if clear_milestone.unwrap_or(false) {
                    patch = patch.milestone(None);
                } else if let Some(value) = milestone {
                    patch = patch.milestone(Some(id(*value)?));
                }
                if let Some(values) = labels {
                    patch = patch
                        .labels(
                            values
                                .iter()
                                .map(|value| name(value))
                                .collect::<Result<Vec<_>, _>>()?,
                        )
                        .map_err(invalid)?;
                }
                if let Some(values) = assignees {
                    patch = patch
                        .assignees(
                            values
                                .iter()
                                .map(|value| Owner::new(value).map_err(invalid))
                                .collect::<Result<Vec<_>, _>>()?,
                        )
                        .map_err(invalid)?;
                }
                if clear_issue_type.unwrap_or(false) {
                    patch = patch.issue_type(None);
                } else if let Some(value) = issue_type {
                    patch = patch.issue_type(Some(name(value)?));
                }
                (
                    ManagementRequest::update_issue(
                        locator.target().clone(),
                        locator.number(),
                        patch,
                        None,
                    ),
                    Some(locator),
                )
            }
            Op::LockIssue { issue_url, reason } => {
                let locator = issue(issue_url)?;
                self.require_repository(locator.target())?;
                let reason = reason.as_deref().map(parse_lock_reason).transpose()?;
                (
                    ManagementRequest::lock_issue(
                        locator.target().clone(),
                        locator.number(),
                        reason,
                    ),
                    Some(locator),
                )
            }
            Op::UnlockIssue { issue_url } => {
                let locator = issue(issue_url)?;
                self.require_repository(locator.target())?;
                (
                    ManagementRequest::unlock_issue(locator.target().clone(), locator.number()),
                    Some(locator),
                )
            }
            Op::AddSubIssue {
                issue_url,
                sub_issue_id,
            } => {
                let locator = issue(issue_url)?;
                self.require_repository(locator.target())?;
                (
                    ManagementRequest::add_sub_issue(
                        locator.target().clone(),
                        locator.number(),
                        id(*sub_issue_id)?,
                    ),
                    Some(locator),
                )
            }
            Op::RemoveSubIssue {
                issue_url,
                sub_issue_id,
            } => {
                let locator = issue(issue_url)?;
                self.require_repository(locator.target())?;
                (
                    ManagementRequest::remove_sub_issue(
                        locator.target().clone(),
                        locator.number(),
                        id(*sub_issue_id)?,
                    ),
                    Some(locator),
                )
            }
            Op::ReprioritizeSubIssue {
                issue_url,
                sub_issue_id,
                after_id,
                before_id,
            } => {
                let locator = issue(issue_url)?;
                self.require_repository(locator.target())?;
                (
                    ManagementRequest::reprioritize_sub_issue(
                        locator.target().clone(),
                        locator.number(),
                        id(*sub_issue_id)?,
                        after_id.map(&id).transpose()?,
                        before_id.map(&id).transpose()?,
                    )
                    .map_err(invalid)?,
                    Some(locator),
                )
            }
            Op::AddDependency {
                issue_url,
                blocking_issue_id,
            } => {
                let locator = issue(issue_url)?;
                self.require_repository(locator.target())?;
                (
                    ManagementRequest::add_dependency(
                        locator.target().clone(),
                        locator.number(),
                        id(*blocking_issue_id)?,
                    ),
                    Some(locator),
                )
            }
            Op::RemoveDependency {
                issue_url,
                blocking_issue_id,
            } => {
                let locator = issue(issue_url)?;
                self.require_repository(locator.target())?;
                (
                    ManagementRequest::remove_dependency(
                        locator.target().clone(),
                        locator.number(),
                        id(*blocking_issue_id)?,
                    ),
                    Some(locator),
                )
            }
            Op::TransferIssue {
                issue_url,
                repository,
            } => {
                let locator = issue(issue_url)?;
                self.require_repository(locator.target())?;
                let issue_node = self.resolve_rest_node(ManagementRequest::lookup_issue_node(
                    locator.target().clone(),
                    locator.number(),
                ))?;
                let repository_node = self.resolve_rest_node(
                    ManagementRequest::lookup_repository_node(repo(repository)?),
                )?;
                (
                    ManagementRequest::transfer_issue(issue_node, repository_node),
                    Some(locator),
                )
            }
            Op::SetIssuePinned { issue_url, pinned } => {
                let locator = issue(issue_url)?;
                self.require_repository(locator.target())?;
                let issue_node = self.resolve_rest_node(ManagementRequest::lookup_issue_node(
                    locator.target().clone(),
                    locator.number(),
                ))?;
                (
                    ManagementRequest::set_issue_pinned(issue_node, *pinned),
                    Some(locator),
                )
            }
            Op::CreateProject {
                owner,
                title,
                public: _,
            } => (
                ManagementRequest::create_project_by_node(
                    self.resolve_owner_node(self.owner_for_alias(owner)?.clone())?,
                    name(title)?,
                ),
                None,
            ),
            Op::UpdateProject {
                project: alias,
                title,
                description,
                public,
                closed,
            } => {
                if title.is_none() && description.is_none() && public.is_none() && closed.is_none()
                {
                    return Err(String::from(
                        "status=refused reason=management_plan_empty_update",
                    ));
                }
                (
                    ManagementRequest::update_project(
                        self.resolve_project_node(project(alias)?)?,
                        title.as_deref().map(&name).transpose()?,
                        optional_text(description)?,
                        *public,
                        *closed,
                    ),
                    None,
                )
            }
            Op::DeleteProject { project: alias } => (
                ManagementRequest::delete_project(self.resolve_project_node(project(alias)?)?),
                None,
            ),
            Op::CreateProjectField {
                project: alias,
                name: field,
                data_type,
            } => (
                ManagementRequest::create_project_field(
                    project(alias)?,
                    name(field)?,
                    parse_field_type(data_type)?,
                ),
                None,
            ),
            Op::UpdateProjectField {
                project: alias,
                field_id,
                name: field,
            } => (
                ManagementRequest::update_project_field(
                    self.resolve_project_field_node(project(alias)?, id(*field_id)?)?,
                    name(field)?,
                ),
                None,
            ),
            Op::DeleteProjectField {
                project: alias,
                field_id,
            } => (
                ManagementRequest::delete_project_field(
                    self.resolve_project_field_node(project(alias)?, id(*field_id)?)?,
                ),
                None,
            ),
            Op::CreateProjectView {
                project: alias,
                name: view,
                layout,
                filter,
            } => (
                ManagementRequest::create_project_view(
                    project(alias)?,
                    name(view)?,
                    parse_view_layout(layout)?,
                    optional_text(filter)?,
                ),
                None,
            ),
            Op::UpdateProjectView {
                project: alias,
                view_id,
                name: view,
                filter,
            } => {
                if view.is_none() && filter.is_none() {
                    return Err(String::from(
                        "status=refused reason=management_plan_empty_update",
                    ));
                }
                (
                    ManagementRequest::update_project_view(
                        self.resolve_project_view_node(project(alias)?, id(*view_id)?)?,
                        view.as_deref().map(&name).transpose()?,
                        optional_text(filter)?,
                    ),
                    None,
                )
            }
            Op::DeleteProjectView {
                project: alias,
                view_id,
            } => (
                ManagementRequest::delete_project_view(
                    self.resolve_project_view_node(project(alias)?, id(*view_id)?)?,
                ),
                None,
            ),
            Op::AddProjectItem {
                project: alias,
                content_type,
                content_id,
            } => (
                ManagementRequest::add_project_item(
                    project(alias)?,
                    parse_project_item_type(content_type)?,
                    id(*content_id)?,
                ),
                None,
            ),
            Op::AddProjectDraft {
                project: alias,
                title,
                body,
            } => (
                ManagementRequest::add_project_draft(
                    project(alias)?,
                    name(title)?,
                    optional_text(body)?,
                ),
                None,
            ),
            Op::UpdateProjectItem {
                project: alias,
                item_id,
                field_id,
                value,
            } => (
                ManagementRequest::update_project_item(
                    project(alias)?,
                    id(*item_id)?,
                    id(*field_id)?,
                    value.clone(),
                )
                .map_err(invalid)?,
                None,
            ),
            Op::ArchiveProjectItem {
                project: alias,
                item_node_id,
                archived,
            } => (
                ManagementRequest::archive_project_item(
                    self.resolve_project_node(project(alias)?)?,
                    name(item_node_id)?,
                    *archived,
                ),
                None,
            ),
            Op::DeleteProjectItem {
                project: alias,
                item_id,
            } => (
                ManagementRequest::delete_project_item(project(alias)?, id(*item_id)?),
                None,
            ),
            Op::CreateProjectStatus {
                project: alias,
                body,
                status,
            } => (
                ManagementRequest::create_project_status(
                    self.resolve_project_node(project(alias)?)?,
                    text(body)?,
                    status.as_deref().map(parse_project_status).transpose()?,
                ),
                None,
            ),
        };
        Ok((request, audit))
    }

    fn require_repository(&self, target: &RepoTarget) -> Result<(), String> {
        self.repositories
            .contains(target)
            .then_some(())
            .ok_or_else(|| String::from("status=refused reason=repository_not_configured"))
    }

    fn target_for_alias(&self, alias: &str) -> Result<&RepoTarget, String> {
        self.aliases
            .iter()
            .find(|(configured, _)| configured == alias)
            .map(|(_, target)| target)
            .ok_or_else(|| String::from("status=refused reason=repository_alias_not_configured"))
    }

    fn owner_for_alias(&self, alias: &str) -> Result<&ProjectOwner, String> {
        self.owners
            .iter()
            .find(|(configured, _)| configured == alias)
            .map(|(_, owner)| owner)
            .ok_or_else(|| String::from("status=refused reason=project_owner_alias_not_configured"))
    }

    fn project_for_alias(&self, alias: &str) -> Result<&ProjectRef, String> {
        self.projects
            .iter()
            .find(|(configured, _)| configured == alias)
            .map(|(_, project)| project)
            .ok_or_else(|| String::from("status=refused reason=project_alias_not_configured"))
    }

    fn project_for_coordinate(&self, coordinate: &str) -> Result<ProjectRef, String> {
        if let Ok(project) = self.project_for_alias(coordinate) {
            return Ok(project.clone());
        }
        let (owner_alias, number) = coordinate
            .split_once(':')
            .ok_or_else(|| String::from("status=refused reason=project_alias_not_configured"))?;
        let number = number
            .parse::<u64>()
            .ok()
            .and_then(|value| DatabaseId::new(value).ok())
            .ok_or_else(|| String::from("status=refused reason=project_coordinate_invalid"))?;
        Ok(ProjectRef::new(
            self.owner_for_alias(owner_alias)?.clone(),
            number,
        ))
    }

    fn resolve_owner_node(&self, owner: ProjectOwner) -> Result<ManagementName, String> {
        self.resolve_rest_node(ManagementRequest::lookup_project_owner(owner))
    }

    fn resolve_project_node(&self, project: ProjectRef) -> Result<ManagementName, String> {
        self.resolve_rest_node(ManagementRequest::lookup_project(project))
    }

    fn resolve_project_field_node(
        &self,
        project: ProjectRef,
        field: DatabaseId,
    ) -> Result<ManagementName, String> {
        self.resolve_rest_node(ManagementRequest::lookup_project_field(project, field))
    }

    fn resolve_project_view_node(
        &self,
        project: ProjectRef,
        view: DatabaseId,
    ) -> Result<ManagementName, String> {
        let project_node = self.resolve_project_node(project)?;
        let receipt = accepted(
            self.client
                .manage(&ManagementRequest::lookup_project_view(project_node, view))
                .map_err(unavailable)?,
        )?;
        let node = receipt
            .value()
            .and_then(|value| value.pointer("/data/node/view/id"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| String::from("status=refused reason=project_view_not_found"))?;
        ManagementName::new(node)
            .map_err(|_| String::from("status=refused reason=project_view_node_invalid"))
    }

    fn resolve_rest_node(&self, request: ManagementRequest) -> Result<ManagementName, String> {
        let receipt = accepted(self.client.manage(&request).map_err(unavailable)?)?;
        let node = receipt
            .value()
            .and_then(|value| value.get("node_id"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| String::from("status=refused reason=github_node_id_missing"))?;
        ManagementName::new(node)
            .map_err(|_| String::from("status=refused reason=github_node_id_invalid"))
    }

    fn find_issue_marker(
        &self,
        target: &RepoTarget,
        marker: &str,
    ) -> Result<Option<String>, String> {
        let query = format!("repo:{target} \"{marker}\" in:body");
        let page = Page::new(1, PAGE_SIZE)
            .map_err(|_| String::from("status=unavailable reason=invalid_search_page"))?;
        let request = SearchIssuesRequest::new(&query, page)
            .map_err(|_| String::from("status=unavailable reason=invalid_marker_search"))?;
        let results = accepted(self.client.search_issues(&request).map_err(unavailable)?)?;
        let mut matches = results
            .issues
            .into_iter()
            .filter(|issue| issue.target == *target && issue.body.contains(marker));
        let first = matches.next().map(|issue| issue.url);
        if matches.next().is_some() {
            return Err(String::from(
                "status=ambiguous reason=duplicate_action_marker",
            ));
        }
        Ok(first)
    }

    fn find_comment_marker(
        &self,
        locator: &IssueLocator,
        marker: &str,
    ) -> Result<Option<String>, String> {
        let issue = accepted(
            self.client
                .get_issue(&GetIssueRequest::new(
                    locator.target().clone(),
                    locator.number(),
                ))
                .map_err(unavailable)?,
        )?;
        let comments = self.all_comments(locator, issue.comment_count)?;
        let mut matches = comments
            .into_iter()
            .filter(|comment| comment.body.contains(marker));
        let first = matches.next().map(|comment| {
            format!(
                "https://github.com/{}/issues/{}#issuecomment-{}",
                locator.target(),
                locator.number(),
                comment.id
            )
        });
        if matches.next().is_some() {
            return Err(String::from(
                "status=ambiguous reason=duplicate_action_marker",
            ));
        }
        Ok(first)
    }

    fn all_comments(
        &self,
        locator: &IssueLocator,
        count: u32,
    ) -> Result<Vec<GitHubComment>, String> {
        if count > MAX_ACTION_COMMENTS {
            return Err(String::from(
                "status=refused reason=issue_comment_history_too_large",
            ));
        }
        let mut comments = Vec::with_capacity(count as usize);
        let pages = count.div_ceil(PAGE_SIZE);
        for number in 1..=pages {
            let page = Page::new(number, PAGE_SIZE)
                .map_err(|_| String::from("status=unavailable reason=invalid_comment_page"))?;
            comments.extend(accepted(
                self.client
                    .get_comments(&GetCommentsRequest::new(
                        locator.target().clone(),
                        locator.number(),
                        page,
                    ))
                    .map_err(unavailable)?,
            )?);
        }
        Ok(comments)
    }

    fn update_issue_checklist(
        &self,
        locator: &IssueLocator,
        item: &str,
        checked: bool,
    ) -> Result<GitHubMutationReceipt, String> {
        let request = GetIssueRequest::new(locator.target().clone(), locator.number());
        let versioned = accepted(
            self.client
                .get_issue_versioned(&request)
                .map_err(unavailable)?,
        )?;
        let etag = versioned.etag().clone();
        let issue = versioned.into_value();
        let edit = edit_checklist(&issue.body, item, checked)?;
        if !edit.changed {
            return Ok(GitHubMutationReceipt {
                url: issue.url,
                recovered: false,
                unchanged: true,
            });
        }
        let body = IssueBodyText::new(&edit.body)
            .map_err(|_| String::from("status=refused reason=checklist_body_invalid"))?;
        let update =
            UpdateIssueBodyRequest::new(locator.target().clone(), locator.number(), body, etag);
        let reply = self
            .client
            .update_issue_body(&update)
            .map_err(unavailable)?;
        match reply.into_outcome() {
            GitHubOutcome::Accepted(updated) => Ok(GitHubMutationReceipt {
                url: updated.into_value().url,
                recovered: false,
                unchanged: false,
            }),
            GitHubOutcome::Rejected(rejection) if rejection.status() == 412 => Err(String::from(
                "status=conflict reason=github_resource_changed",
            )),
            GitHubOutcome::Rejected(rejection) => Err(format!(
                "status=refused reason={}",
                rejection.kind().category()
            )),
        }
    }

    fn update_comment_checklist(
        &self,
        locator: &IssueLocator,
        id: u64,
        item: &str,
        checked: bool,
    ) -> Result<GitHubMutationReceipt, String> {
        let id = CommentId::new(id)
            .map_err(|_| String::from("status=refused reason=comment_id_invalid"))?;
        let request = GetIssueCommentRequest::new(locator.target().clone(), id);
        let versioned = accepted(
            self.client
                .get_issue_comment(&request)
                .map_err(unavailable)?,
        )?;
        let etag = versioned.etag().clone();
        let comment = versioned.into_value();
        let edit = edit_checklist(&comment.body, item, checked)?;
        let url = format!(
            "https://github.com/{}/issues/{}#issuecomment-{}",
            locator.target(),
            locator.number(),
            id
        );
        if !edit.changed {
            return Ok(GitHubMutationReceipt {
                url,
                recovered: false,
                unchanged: true,
            });
        }
        let body = IssueBodyText::new(&edit.body)
            .map_err(|_| String::from("status=refused reason=checklist_body_invalid"))?;
        let update = UpdateIssueCommentRequest::new(locator.target().clone(), id, body, etag);
        let reply = self
            .client
            .update_issue_comment(&update)
            .map_err(unavailable)?;
        match reply.into_outcome() {
            GitHubOutcome::Accepted(_) => Ok(GitHubMutationReceipt {
                url,
                recovered: false,
                unchanged: false,
            }),
            GitHubOutcome::Rejected(rejection) if rejection.status() == 412 => Err(String::from(
                "status=conflict reason=github_resource_changed",
            )),
            GitHubOutcome::Rejected(rejection) => Err(format!(
                "status=refused reason={}",
                rejection.kind().category()
            )),
        }
    }
}

struct ChecklistEdit {
    body: String,
    changed: bool,
}

fn normalized_checklist_item(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn checklist_line(line: &str) -> Option<(bool, &str)> {
    let trimmed = line.trim_start();
    for (prefix, checked) in [
        ("- [ ]", false),
        ("* [ ]", false),
        ("- [x]", true),
        ("- [X]", true),
        ("* [x]", true),
        ("* [X]", true),
    ] {
        if let Some(item) = trimmed.strip_prefix(prefix) {
            return Some((checked, item.trim()));
        }
    }
    None
}

fn checklist_match_count(body: &str, item: &str) -> usize {
    let item = normalized_checklist_item(item);
    body.lines()
        .filter_map(checklist_line)
        .filter(|(_, label)| normalized_checklist_item(label) == item)
        .count()
}

fn edit_checklist(body: &str, item: &str, checked: bool) -> Result<ChecklistEdit, String> {
    if item.trim().is_empty() {
        return Err(String::from("status=refused reason=checklist_item_invalid"));
    }
    if checklist_match_count(body, item) != 1 {
        return Err(String::from(
            "status=conflict reason=checklist_item_changed",
        ));
    }
    let wanted = if checked { 'x' } else { ' ' };
    let item = normalized_checklist_item(item);
    let mut changed = false;
    let mut output = String::with_capacity(body.len());
    for segment in body.split_inclusive('\n') {
        let (line, newline) = segment
            .strip_suffix('\n')
            .map_or((segment, ""), |line| (line, "\n"));
        let matches =
            checklist_line(line).is_some_and(|(_, label)| normalized_checklist_item(label) == item);
        if matches {
            let marker = line
                .find("[ ]")
                .or_else(|| line.find("[x]"))
                .or_else(|| line.find("[X]"));
            if let Some(marker) = marker {
                let current = line.as_bytes()[marker + 1] as char;
                output.push_str(&line[..marker + 1]);
                output.push(wanted);
                output.push_str(&line[marker + 2..]);
                changed = current != wanted;
            } else {
                output.push_str(line);
            }
        } else {
            output.push_str(line);
        }
        output.push_str(newline);
    }
    Ok(ChecklistEdit {
        body: output,
        changed,
    })
}

fn action_marker(action_id: &str) -> String {
    let digest = Sha256::digest(action_id.as_bytes()).to_hex();
    format!("<!-- automonique:github-action:{digest} -->")
}

fn actions_unavailable() -> String {
    String::from("status=refused reason=github_actions_unavailable")
}

fn unavailable(failure: automonique_github_connector::GitHubFailure) -> String {
    format!("status=unavailable reason={}", failure.category())
}

fn accepted<T>(reply: automonique_github_connector::GitHubReply<T>) -> Result<T, String> {
    match reply.into_outcome() {
        GitHubOutcome::Accepted(value) => Ok(value),
        GitHubOutcome::Rejected(rejection) => Err(format!(
            "status=refused reason={}",
            rejection.kind().category()
        )),
    }
}

fn is_prism_inventory_issue(title: &str, body: &str) -> bool {
    fn normalized(value: &str) -> String {
        value
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase()
    }
    normalized(title) == "list prism sites" && normalized(body) == "list the prism sites"
}

fn single_line(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn bounded_field(value: &str, max_bytes: usize) -> String {
    let value = single_line(value);
    if value.len() <= max_bytes {
        return value;
    }
    let mark = "[…truncated]";
    let mut end = max_bytes.saturating_sub(mark.len());
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}{mark}", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_complete_config_loads_only_the_repository_allowlist() {
        let root = tempfile::tempdir().expect("root");
        fs::create_dir(root.path().join("github")).expect("github dir");
        let path = GitHubConfig::path(root.path());
        fs::write(
            &path,
            format!(
                "{READ_CONFIG_HEADER}\ncredential={GH_CREDENTIAL}\nrepo=example-org/example-repo\n{CONFIG_TERMINATOR}\n"
            ),
        )
        .expect("config");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private config");
        let config = GitHubConfig::load(root.path())
            .expect("config")
            .expect("configured");
        assert_eq!(
            config.repositories[0].to_string(),
            "example-org/example-repo"
        );
        assert!(!config.prism_inventory_action);

        let action = parse_config(&format!(
            "{ACTION_CONFIG_HEADER}\ncredential={GH_CREDENTIAL}\nrepo=example-org/example-repo\naction={PRISM_INVENTORY_ACTION}\n{CONFIG_TERMINATOR}\n"
        ))
        .expect("action config");
        assert!(action.prism_inventory_action);

        let tools = parse_config(&format!(
            "{TOOL_CONFIG_HEADER}\ncredential={GH_CREDENTIAL}\nrepo=automonique:example-org/example-repo\naction={CREATE_ISSUE_ACTION}\naction={REPLY_ACTION}\naction={CHECKLIST_ACTION}\n{CONFIG_TERMINATOR}\n"
        ))
        .expect("tool config");
        assert_eq!(tools.aliases[0].0, "automonique");
        assert_eq!(tools.aliases[0].1.to_string(), "example-org/example-repo");
        assert!(tools.create_issue_action);
        assert!(tools.reply_action);
        assert!(tools.checklist_action);

        let management = parse_config(&format!(
            "{MANAGEMENT_CONFIG_HEADER}\ncredential={GH_CREDENTIAL}\nrepo=automonique:example-org/example-repo\nowner=example:organization:example-org\nproject=roadmap:example:7\ncapability=issues\ncapability=taxonomy\ncapability=hierarchy\ncapability=projects\n{CONFIG_TERMINATOR}\n"
        ))
        .expect("management config");
        assert_eq!(management.owners[0].0, "example");
        assert_eq!(management.projects[0].0, "roadmap");
        assert_eq!(management.management_capabilities.len(), 4);
    }

    #[test]
    fn tool_config_requires_unique_safe_aliases_and_explicit_actions() {
        for repo in [
            "repo=Upper:example-org/example-repo",
            "repo=with space:example-org/example-repo",
            "repo=missing-alias",
        ] {
            assert_eq!(
                parse_config(&format!(
                    "{TOOL_CONFIG_HEADER}\ncredential={GH_CREDENTIAL}\n{repo}\n{CONFIG_TERMINATOR}\n"
                ))
                .err(),
                Some(GitHubConfigError::Malformed),
                "{repo}"
            );
        }
        assert_eq!(
            parse_config(&format!(
                "{ACTION_CONFIG_HEADER}\ncredential={GH_CREDENTIAL}\nrepo=example-org/example-repo\naction={CREATE_ISSUE_ACTION}\n{CONFIG_TERMINATOR}\n"
            ))
            .err(),
            Some(GitHubConfigError::Malformed)
        );
    }

    #[test]
    fn checklist_edit_is_exact_and_preserves_surrounding_markdown() {
        let body = "before\n- [ ] First item\n  * [X] Second   item\nafter\n";
        let checked = edit_checklist(body, "First item", true).expect("check");
        assert!(checked.changed);
        assert_eq!(
            checked.body,
            "before\n- [x] First item\n  * [X] Second   item\nafter\n"
        );
        let unchanged = edit_checklist(&checked.body, "First item", true).expect("idempotent");
        assert!(!unchanged.changed);
        assert!(edit_checklist(body, "missing", true).is_err());
        assert_eq!(checklist_match_count(body, "Second item"), 1);
    }

    #[test]
    fn recent_comments_cross_a_page_boundary_when_needed() {
        assert_eq!(recent_comment_pages(100, 20), Some((1, 1)));
        assert_eq!(recent_comment_pages(101, 20), Some((1, 2)));
        assert_eq!(recent_comment_pages(150, 20), Some((2, 2)));
        assert_eq!(recent_comment_pages(0, 20), None);
        assert_eq!(recent_comment_pages(10, 0), None);
    }

    #[test]
    fn repository_activity_timestamps_compare_at_millisecond_precision() {
        assert_eq!(
            utc_timestamp_sort_key("2026-08-15T18:24:00Z").as_deref(),
            Some("2026-08-15T18:24:00.000Z")
        );
        assert_eq!(
            utc_timestamp_sort_key("2026-08-15T18:24:00.125Z").as_deref(),
            Some("2026-08-15T18:24:00.125Z")
        );
        assert!(utc_timestamp_sort_key("2026-13-15T18:24:00Z").is_none());
        assert!(utc_timestamp_sort_key("not-a-timestamp").is_none());
        assert!(utc_timestamp_sort_key("2026-08-15T18:24:00.12345678901234567890Z").is_none());
    }

    #[test]
    fn repository_activity_projection_names_its_allowlisted_push_scope() {
        let bounds =
            RepositoryActivityBounds::new(RepositoryActivityWindow::Last7Days, 1_787_423_040_000)
                .expect("bounds");
        let facts = render_repository_push_activity(
            &bounds,
            3,
            &[
                (
                    String::from("example/active"),
                    String::from("2026-08-21T17:04:11Z"),
                ),
                (
                    String::from("example/also-active"),
                    String::from("2026-08-20T09:00:00Z"),
                ),
            ],
            &[String::from("example/unavailable:rate_limited")],
        );
        assert!(facts.contains("scope=configured_repository_allowlist"));
        assert!(facts.contains("activity_basis=github_repository_pushed_at"));
        assert!(facts.contains("window=last_7_days"));
        assert!(facts.contains("lower_inclusive=2026-08-15T18:24:00.000Z"));
        assert!(facts.contains("upper_exclusive=2026-08-22T18:24:00.000Z"));
        assert!(facts.contains("repositories_checked=3"));
        assert!(facts.contains("repositories_with_push_activity=2"));
        assert!(facts.contains("active_repository=example/active pushed_at=2026-08-21T17:04:11Z"));
        assert!(facts.contains("repositories_unavailable=1"));
        assert!(facts.contains("not an organization-wide inventory"));
        assert!(facts.contains("not issue, project, or local unpushed work"));
    }

    #[test]
    fn repository_activity_windows_are_host_computed_and_half_open() {
        let now_ms = 1_787_423_040_000;
        let cases = [
            (RepositoryActivityWindow::All, None),
            (
                RepositoryActivityWindow::ThisWeek,
                Some("2026-08-17T00:00:00.000Z"),
            ),
            (
                RepositoryActivityWindow::Today,
                Some("2026-08-22T00:00:00.000Z"),
            ),
            (
                RepositoryActivityWindow::Yesterday,
                Some("2026-08-21T00:00:00.000Z"),
            ),
            (
                RepositoryActivityWindow::Last7Days,
                Some("2026-08-15T18:24:00.000Z"),
            ),
        ];
        for (window, lower) in cases {
            let bounds = RepositoryActivityBounds::new(window, now_ms).expect("bounds");
            assert_eq!(bounds.lower_inclusive.as_deref(), lower, "{window:?}");
            let upper = if window == RepositoryActivityWindow::Yesterday {
                "2026-08-22T00:00:00.000Z"
            } else {
                "2026-08-22T18:24:00.000Z"
            };
            assert_eq!(bounds.upper_exclusive, upper, "{window:?}");
            assert!(!bounds.contains(upper), "upper bound is exclusive");
        }

        let this_week = RepositoryActivityBounds::new(RepositoryActivityWindow::ThisWeek, now_ms)
            .expect("this week");
        assert!(this_week.contains("2026-08-21T17:04:11.000Z"));
        assert!(!this_week.contains("2019-06-01T12:00:00.000Z"));
        assert!(!this_week.contains("2026-08-16T23:59:59.999Z"));

        let yesterday = RepositoryActivityBounds::new(RepositoryActivityWindow::Yesterday, now_ms)
            .expect("yesterday");
        assert!(yesterday.contains("2026-08-21T00:00:00.000Z"));
        assert!(yesterday.contains("2026-08-21T23:59:59.999Z"));
        assert!(!yesterday.contains("2026-08-22T00:00:00.000Z"));
        assert!(RepositoryActivityBounds::new(RepositoryActivityWindow::All, -1).is_none());
    }

    #[test]
    fn recent_issue_comment_facts_are_bounded_and_marked_untrusted() {
        let comments = vec![
            GitHubComment {
                id: 1,
                author: String::from("operator"),
                body: String::from("Older progress"),
                created_at: String::from("2026-08-18T10:00:00Z"),
                updated_at: String::from("2026-08-18T10:00:00Z"),
            },
            GitHubComment {
                id: 2,
                author: String::from("delivery"),
                body: "verified ".repeat(300),
                created_at: String::from("2026-08-18T11:00:00Z"),
                updated_at: String::from("2026-08-18T11:30:00Z"),
            },
        ];
        let mut facts = String::from("status=available");
        append_recent_comment_facts(&mut facts, &comments, true);
        assert!(facts.contains("recent_comments_returned=2"));
        assert!(facts.contains("recent_comments_truncated=true"));
        assert!(facts.contains("comment_1_body_untrusted=Older progress"));
        assert!(facts.contains("comment_2_author=delivery"));
        assert!(facts.contains("comment_2_body_untrusted=verified"));
        assert!(facts.contains("[…truncated]"));
        assert!(facts.len() < 1_500);
    }

    #[test]
    fn absent_is_disabled_and_permissive_or_trailing_config_is_refused() {
        let root = tempfile::tempdir().expect("root");
        assert!(matches!(
            GitHubHost::load(root.path()).expect("absent"),
            GitHubHost::Disabled
        ));
        fs::create_dir(root.path().join("github")).expect("github dir");
        let path = GitHubConfig::path(root.path());
        fs::write(
            &path,
            format!(
                "{READ_CONFIG_HEADER}\ncredential={GH_CREDENTIAL}\nrepo=example-org/example-repo\n{CONFIG_TERMINATOR}\ntrailing=1\n"
            ),
        )
        .expect("config");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private config");
        assert_eq!(
            GitHubHost::load(root.path()).expect_err("trailing refused"),
            GitHubConfigError::Malformed
        );
        fs::write(
            &path,
            format!(
                "{READ_CONFIG_HEADER}\ncredential={GH_CREDENTIAL}\nrepo=example-org/example-repo\n{CONFIG_TERMINATOR}\n"
            ),
        )
        .expect("config");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("permissive");
        assert_eq!(
            GitHubHost::load(root.path()).expect_err("mode refused"),
            GitHubConfigError::Insecure
        );
    }

    #[test]
    fn only_the_exact_inventory_issue_contract_is_actionable() {
        assert!(is_prism_inventory_issue(
            "List prism sites",
            "List the prism sites"
        ));
        assert!(!is_prism_inventory_issue(
            "Fix prism sites",
            "List the prism sites"
        ));
        assert!(!is_prism_inventory_issue(
            "List prism sites",
            "List the prism sites and deploy them"
        ));
    }
}
