// SPDX-License-Identifier: Elastic-2.0

//! Typed GitHub work-management mutations.
//!
//! This module deliberately exposes constructors, not arbitrary HTTP paths.
//! Every repository and project coordinate is validated before a request can
//! be rendered, while request bodies are produced by `serde_json` rather than
//! interpolating operator or model text.

use serde_json::{Map, Value, json};

use crate::{EntityTag, GitHubRefusal, HttpMethod, IssueNumber, Owner, RepoTarget};

/// Most operations accepted in one model-produced management plan.
pub const MAX_MANAGEMENT_OPERATIONS: usize = 20;
/// Longest management name (label, milestone, project, field, or view).
pub const MAX_MANAGEMENT_NAME_BYTES: usize = 256;
/// Longest management description, note, filter, or status text.
pub const MAX_MANAGEMENT_TEXT_BYTES: usize = 8_192;

/// A positive REST database identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseId(u64);

impl DatabaseId {
    /// Validate a non-zero identifier.
    pub const fn new(value: u64) -> Result<Self, GitHubRefusal> {
        if value == 0 {
            return Err(GitHubRefusal::Management);
        }
        Ok(Self(value))
    }

    /// Return the wire integer.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A bounded printable name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementName(String);

impl ManagementName {
    /// Validate one name.
    pub fn new(value: &str) -> Result<Self, GitHubRefusal> {
        bounded_text(value, MAX_MANAGEMENT_NAME_BYTES).map(Self)
    }

    /// Borrow the exact trimmed name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded optional prose used by management objects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementText(String);

impl ManagementText {
    /// Validate non-empty prose.
    pub fn new(value: &str) -> Result<Self, GitHubRefusal> {
        bounded_text(value, MAX_MANAGEMENT_TEXT_BYTES).map(Self)
    }

    /// Borrow the exact trimmed prose.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A six-digit RGB label colour without `#`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabelColor(String);

impl LabelColor {
    /// Validate one GitHub label colour.
    pub fn new(value: &str) -> Result<Self, GitHubRefusal> {
        let value = value.trim().trim_start_matches('#');
        if value.len() != 6 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(GitHubRefusal::Management);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Borrow the lowercase wire spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether a Projects owner is an organization or a user.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectOwnerKind {
    /// An organization-owned project.
    Organization,
    /// A user-owned project.
    User,
}

/// One configured Projects owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectOwner {
    kind: ProjectOwnerKind,
    login: Owner,
}

impl ProjectOwner {
    /// Bind a validated login to its owner kind.
    #[must_use]
    pub const fn new(kind: ProjectOwnerKind, login: Owner) -> Self {
        Self { kind, login }
    }

    fn prefix(&self) -> String {
        match self.kind {
            ProjectOwnerKind::Organization => format!("/orgs/{}", self.login.as_str()),
            ProjectOwnerKind::User => format!("/users/{}", self.login.as_str()),
        }
    }

    fn lookup_path(&self) -> String {
        self.prefix()
    }
}

/// One numbered project under an authorized owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectRef {
    owner: ProjectOwner,
    number: DatabaseId,
}

impl ProjectRef {
    /// Bind a project number to an owner.
    #[must_use]
    pub const fn new(owner: ProjectOwner, number: DatabaseId) -> Self {
        Self { owner, number }
    }

    fn path(&self) -> String {
        format!("{}/projectsV2/{}", self.owner.prefix(), self.number.get())
    }
}

/// GitHub-supported issue lock reasons.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockReason {
    OffTopic,
    TooHeated,
    Resolved,
    Spam,
}

impl LockReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::OffTopic => "off-topic",
            Self::TooHeated => "too heated",
            Self::Resolved => "resolved",
            Self::Spam => "spam",
        }
    }
}

/// GitHub-supported project field data types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectFieldType {
    Text,
    Number,
    Date,
    SingleSelect,
    MultiSelect,
    Iteration,
}

impl ProjectFieldType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Number => "number",
            Self::Date => "date",
            Self::SingleSelect => "single_select",
            Self::MultiSelect => "multi_select",
            Self::Iteration => "iteration",
        }
    }
}

/// GitHub-supported project view layouts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectViewLayout {
    Table,
    Board,
    Roadmap,
}

impl ProjectViewLayout {
    fn as_str(self) -> &'static str {
        match self {
            Self::Table => "table",
            Self::Board => "board",
            Self::Roadmap => "roadmap",
        }
    }
}

/// GitHub-supported project status update states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectStatus {
    OnTrack,
    AtRisk,
    OffTrack,
    Complete,
    Inactive,
}

/// Content types accepted by the Projects REST item endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectItemType {
    Issue,
    PullRequest,
}

impl ProjectItemType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "Issue",
            Self::PullRequest => "PullRequest",
        }
    }
}

impl ProjectStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::OnTrack => "ON_TRACK",
            Self::AtRisk => "AT_RISK",
            Self::OffTrack => "OFF_TRACK",
            Self::Complete => "COMPLETE",
            Self::Inactive => "INACTIVE",
        }
    }
}

/// A closed, validated work-management request.
#[derive(Clone, Debug, PartialEq)]
pub struct ManagementRequest {
    method: HttpMethod,
    path: String,
    body: Option<String>,
    if_match: Option<EntityTag>,
}

impl ManagementRequest {
    fn json(method: HttpMethod, path: String, value: Value) -> Self {
        Self {
            method,
            path,
            body: Some(value.to_string()),
            if_match: None,
        }
    }

    fn empty(method: HttpMethod, path: String) -> Self {
        Self {
            method,
            path,
            body: None,
            if_match: None,
        }
    }

    fn repo_path(target: &RepoTarget, suffix: &str) -> String {
        format!(
            "/repos/{}/{}{}",
            target.owner().as_str(),
            target.repo().as_str(),
            suffix
        )
    }

    fn issue_path(target: &RepoTarget, number: IssueNumber, suffix: &str) -> String {
        Self::repo_path(target, &format!("/issues/{number}{suffix}"))
    }

    /// Create a repository label definition.
    #[must_use]
    pub fn create_label(
        target: RepoTarget,
        name: ManagementName,
        color: LabelColor,
        description: Option<ManagementText>,
    ) -> Self {
        let mut body = Map::new();
        body.insert("name".into(), Value::String(name.0));
        body.insert("color".into(), Value::String(color.0));
        if let Some(description) = description {
            body.insert("description".into(), Value::String(description.0));
        }
        Self::json(
            HttpMethod::Post,
            Self::repo_path(&target, "/labels"),
            Value::Object(body),
        )
    }

    /// Update a repository label definition.
    #[must_use]
    pub fn update_label(
        target: RepoTarget,
        current: ManagementName,
        new_name: ManagementName,
        color: LabelColor,
        description: Option<ManagementText>,
    ) -> Self {
        let mut body = Map::new();
        body.insert("new_name".into(), Value::String(new_name.0));
        body.insert("color".into(), Value::String(color.0));
        if let Some(description) = description {
            body.insert("description".into(), Value::String(description.0));
        }
        Self::json(
            HttpMethod::Patch,
            Self::repo_path(
                &target,
                &format!("/labels/{}", encode_segment(current.as_str())),
            ),
            Value::Object(body),
        )
    }

    /// Delete a repository label definition.
    #[must_use]
    pub fn delete_label(target: RepoTarget, name: ManagementName) -> Self {
        Self::empty(
            HttpMethod::Delete,
            Self::repo_path(
                &target,
                &format!("/labels/{}", encode_segment(name.as_str())),
            ),
        )
    }

    /// Create a milestone definition. `due_on` is a bounded ISO-8601 instant supplied by the caller.
    #[must_use]
    pub fn create_milestone(
        target: RepoTarget,
        title: ManagementName,
        description: Option<ManagementText>,
        due_on: Option<ManagementText>,
    ) -> Self {
        let mut body = Map::new();
        body.insert("title".into(), Value::String(title.0));
        if let Some(description) = description {
            body.insert("description".into(), Value::String(description.0));
        }
        if let Some(due_on) = due_on {
            body.insert("due_on".into(), Value::String(due_on.0));
        }
        Self::json(
            HttpMethod::Post,
            Self::repo_path(&target, "/milestones"),
            Value::Object(body),
        )
    }

    /// Update or close/open a milestone definition.
    #[must_use]
    pub fn update_milestone(
        target: RepoTarget,
        milestone: DatabaseId,
        title: Option<ManagementName>,
        description: Option<ManagementText>,
        due_on: Option<ManagementText>,
        open: Option<bool>,
    ) -> Self {
        let mut body = Map::new();
        if let Some(title) = title {
            body.insert("title".into(), Value::String(title.0));
        }
        if let Some(description) = description {
            body.insert("description".into(), Value::String(description.0));
        }
        if let Some(due_on) = due_on {
            body.insert("due_on".into(), Value::String(due_on.0));
        }
        if let Some(open) = open {
            body.insert(
                "state".into(),
                Value::String(if open { "open" } else { "closed" }.into()),
            );
        }
        Self::json(
            HttpMethod::Patch,
            Self::repo_path(&target, &format!("/milestones/{}", milestone.get())),
            Value::Object(body),
        )
    }

    /// Delete a milestone definition.
    #[must_use]
    pub fn delete_milestone(target: RepoTarget, milestone: DatabaseId) -> Self {
        Self::empty(
            HttpMethod::Delete,
            Self::repo_path(&target, &format!("/milestones/{}", milestone.get())),
        )
    }

    /// Apply issue or pull-request metadata through GitHub's shared issue endpoint.
    #[must_use]
    pub fn update_issue(
        target: RepoTarget,
        number: IssueNumber,
        patch: IssueManagementPatch,
        if_match: Option<EntityTag>,
    ) -> Self {
        let mut request = Self::json(
            HttpMethod::Patch,
            Self::issue_path(&target, number, ""),
            patch.into_json(),
        );
        request.if_match = if_match;
        request
    }

    /// Lock an issue or pull request.
    #[must_use]
    pub fn lock_issue(target: RepoTarget, number: IssueNumber, reason: Option<LockReason>) -> Self {
        let mut body = Map::new();
        if let Some(reason) = reason {
            body.insert("lock_reason".into(), Value::String(reason.as_str().into()));
        }
        Self::json(
            HttpMethod::Put,
            Self::issue_path(&target, number, "/lock"),
            Value::Object(body),
        )
    }

    /// Unlock an issue or pull request.
    #[must_use]
    pub fn unlock_issue(target: RepoTarget, number: IssueNumber) -> Self {
        Self::empty(
            HttpMethod::Delete,
            Self::issue_path(&target, number, "/lock"),
        )
    }

    /// Read an issue or pull request node id before a GraphQL-only mutation.
    #[must_use]
    pub fn lookup_issue_node(target: RepoTarget, number: IssueNumber) -> Self {
        Self::empty(HttpMethod::Get, Self::issue_path(&target, number, ""))
    }

    /// Read a configured repository node id before a transfer.
    #[must_use]
    pub fn lookup_repository_node(target: RepoTarget) -> Self {
        Self::empty(HttpMethod::Get, Self::repo_path(&target, ""))
    }

    /// Attach an existing issue as a native sub-issue.
    #[must_use]
    pub fn add_sub_issue(target: RepoTarget, parent: IssueNumber, sub_issue: DatabaseId) -> Self {
        Self::json(
            HttpMethod::Post,
            Self::issue_path(&target, parent, "/sub_issues"),
            json!({"sub_issue_id": sub_issue.get()}),
        )
    }

    /// Remove an existing native sub-issue.
    #[must_use]
    pub fn remove_sub_issue(
        target: RepoTarget,
        parent: IssueNumber,
        sub_issue: DatabaseId,
    ) -> Self {
        Self::json(
            HttpMethod::Delete,
            Self::issue_path(&target, parent, "/sub_issue"),
            json!({"sub_issue_id": sub_issue.get()}),
        )
    }

    /// Move a sub-issue before or after another item. Exactly one position must be supplied.
    pub fn reprioritize_sub_issue(
        target: RepoTarget,
        parent: IssueNumber,
        sub_issue: DatabaseId,
        after: Option<DatabaseId>,
        before: Option<DatabaseId>,
    ) -> Result<Self, GitHubRefusal> {
        if after.is_some() == before.is_some() {
            return Err(GitHubRefusal::Management);
        }
        Ok(Self::json(
            HttpMethod::Patch,
            Self::issue_path(&target, parent, "/sub_issues/priority"),
            json!({
                "sub_issue_id": sub_issue.get(), "after_id": after.map(DatabaseId::get), "before_id": before.map(DatabaseId::get)
            }),
        ))
    }

    /// Add a native blocked-by relationship.
    #[must_use]
    pub fn add_dependency(
        target: RepoTarget,
        number: IssueNumber,
        blocking_issue: DatabaseId,
    ) -> Self {
        Self::json(
            HttpMethod::Post,
            Self::issue_path(&target, number, "/dependencies/blocked_by"),
            json!({"issue_id": blocking_issue.get()}),
        )
    }

    /// Remove a native blocked-by relationship.
    #[must_use]
    pub fn remove_dependency(
        target: RepoTarget,
        number: IssueNumber,
        blocking_issue: DatabaseId,
    ) -> Self {
        Self::empty(
            HttpMethod::Delete,
            Self::issue_path(
                &target,
                number,
                &format!("/dependencies/blocked_by/{}", blocking_issue.get()),
            ),
        )
    }

    /// Read the configured owner so its node id can be used by fixed GraphQL mutations.
    #[must_use]
    pub fn lookup_project_owner(owner: ProjectOwner) -> Self {
        Self::empty(HttpMethod::Get, owner.lookup_path())
    }

    /// Read one authorized project and its node id.
    #[must_use]
    pub fn lookup_project(project: ProjectRef) -> Self {
        Self::empty(HttpMethod::Get, project.path())
    }

    /// Read one project field and its node id.
    #[must_use]
    pub fn lookup_project_field(project: ProjectRef, field: DatabaseId) -> Self {
        Self::empty(
            HttpMethod::Get,
            format!("{}/fields/{}", project.path(), field.get()),
        )
    }

    /// Create a private project under a previously resolved configured owner.
    #[must_use]
    pub fn create_project_by_node(owner_node_id: ManagementName, title: ManagementName) -> Self {
        Self::json(
            HttpMethod::Post,
            String::from("/graphql"),
            json!({
                "query": "mutation($owner:ID!,$title:String!){createProjectV2(input:{ownerId:$owner,title:$title}){projectV2{id url public}}}",
                "variables": {"owner": owner_node_id.as_str(), "title": title.as_str()}
            }),
        )
    }

    /// Resolve a view node under an already authorized project.
    #[must_use]
    pub fn lookup_project_view(project_node_id: ManagementName, number: DatabaseId) -> Self {
        Self::json(
            HttpMethod::Post,
            String::from("/graphql"),
            json!({
                "query": "query($project:ID!,$number:Int!){node(id:$project){... on ProjectV2{view(number:$number){id}}}}",
                "variables": {"project": project_node_id.as_str(), "number": number.get()}
            }),
        )
    }

    /// Update project metadata and visibility.
    #[must_use]
    pub fn update_project(
        project_node_id: ManagementName,
        title: Option<ManagementName>,
        short_description: Option<ManagementText>,
        public: Option<bool>,
        closed: Option<bool>,
    ) -> Self {
        let mut input = Map::new();
        input.insert("projectId".into(), Value::String(project_node_id.0));
        if let Some(title) = title {
            input.insert("title".into(), Value::String(title.0));
        }
        if let Some(short_description) = short_description {
            input.insert(
                "shortDescription".into(),
                Value::String(short_description.0),
            );
        }
        if let Some(public) = public {
            input.insert("public".into(), Value::Bool(public));
        }
        if let Some(closed) = closed {
            input.insert("closed".into(), Value::Bool(closed));
        }
        Self::json(
            HttpMethod::Post,
            String::from("/graphql"),
            json!({
                "query": "mutation($input:UpdateProjectV2Input!){updateProjectV2(input:$input){projectV2{id url}}}",
                "variables": {"input": Value::Object(input)}
            }),
        )
    }

    /// Delete a project.
    #[must_use]
    pub fn delete_project(project_node_id: ManagementName) -> Self {
        Self::json(
            HttpMethod::Post,
            String::from("/graphql"),
            json!({
                "query": "mutation($project:ID!){deleteProjectV2(input:{projectId:$project}){projectV2{id}}}",
                "variables": {"project": project_node_id.as_str()}
            }),
        )
    }

    /// Add a project field.
    #[must_use]
    pub fn create_project_field(
        project: ProjectRef,
        name: ManagementName,
        data_type: ProjectFieldType,
    ) -> Self {
        Self::json(
            HttpMethod::Post,
            format!("{}/fields", project.path()),
            json!({"name": name.as_str(), "data_type": data_type.as_str()}),
        )
    }

    /// Update a project field's name.
    #[must_use]
    pub fn update_project_field(field_node_id: ManagementName, name: ManagementName) -> Self {
        Self::json(
            HttpMethod::Post,
            String::from("/graphql"),
            json!({
                "query": "mutation($field:ID!,$name:String){updateProjectV2Field(input:{fieldId:$field,name:$name}){projectV2Field{id}}}",
                "variables": {"field": field_node_id.as_str(), "name": name.as_str()}
            }),
        )
    }

    /// Delete a project field.
    #[must_use]
    pub fn delete_project_field(field_node_id: ManagementName) -> Self {
        Self::json(
            HttpMethod::Post,
            String::from("/graphql"),
            json!({
                "query": "mutation($field:ID!){deleteProjectV2Field(input:{fieldId:$field}){projectV2Field{id}}}",
                "variables": {"field": field_node_id.as_str()}
            }),
        )
    }

    /// Create a project view.
    #[must_use]
    pub fn create_project_view(
        project: ProjectRef,
        name: ManagementName,
        layout: ProjectViewLayout,
        filter: Option<ManagementText>,
    ) -> Self {
        let mut body = Map::new();
        body.insert("name".into(), Value::String(name.0));
        body.insert("layout".into(), Value::String(layout.as_str().into()));
        if let Some(filter) = filter {
            body.insert("filter".into(), Value::String(filter.0));
        }
        Self::json(
            HttpMethod::Post,
            format!("{}/views", project.path()),
            Value::Object(body),
        )
    }

    /// Update a project view.
    #[must_use]
    pub fn update_project_view(
        view_node_id: ManagementName,
        name: Option<ManagementName>,
        filter: Option<ManagementText>,
    ) -> Self {
        let mut input = Map::new();
        input.insert("viewId".into(), Value::String(view_node_id.0));
        if let Some(name) = name {
            input.insert("name".into(), Value::String(name.0));
        }
        if let Some(filter) = filter {
            input.insert("filter".into(), Value::String(filter.0));
        }
        Self::json(
            HttpMethod::Post,
            String::from("/graphql"),
            json!({
                "query": "mutation($input:UpdateProjectV2ViewInput!){updateProjectV2View(input:$input){projectV2View{id}}}",
                "variables": {"input": Value::Object(input)}
            }),
        )
    }

    /// Delete a project view.
    #[must_use]
    pub fn delete_project_view(view_node_id: ManagementName) -> Self {
        Self::json(
            HttpMethod::Post,
            String::from("/graphql"),
            json!({
                "query": "mutation($view:ID!){deleteProjectV2View(input:{viewId:$view}){deletedViewId}}",
                "variables": {"view": view_node_id.as_str()}
            }),
        )
    }

    /// Add an issue or pull request node to a project.
    #[must_use]
    pub fn add_project_item(
        project: ProjectRef,
        content_type: ProjectItemType,
        content_id: DatabaseId,
    ) -> Self {
        Self::json(
            HttpMethod::Post,
            format!("{}/items", project.path()),
            json!({"type": content_type.as_str(), "id": content_id.get()}),
        )
    }

    /// Add a draft issue to a project.
    #[must_use]
    pub fn add_project_draft(
        project: ProjectRef,
        title: ManagementName,
        body: Option<ManagementText>,
    ) -> Self {
        let mut document = Map::new();
        document.insert("title".into(), Value::String(title.0));
        if let Some(body) = body {
            document.insert("body".into(), Value::String(body.0));
        }
        Self::json(
            HttpMethod::Post,
            format!("{}/drafts", project.path()),
            Value::Object(document),
        )
    }

    /// Update one project item's field value with an API-shaped, bounded JSON value.
    pub fn update_project_item(
        project: ProjectRef,
        item: DatabaseId,
        field: DatabaseId,
        value: Value,
    ) -> Result<Self, GitHubRefusal> {
        let encoded = value.to_string();
        if encoded.len() > MAX_MANAGEMENT_TEXT_BYTES {
            return Err(GitHubRefusal::Management);
        }
        Ok(Self::json(
            HttpMethod::Patch,
            format!("{}/items/{}", project.path(), item.get()),
            json!({"fields": [{"id": field.get(), "value": value}]}),
        ))
    }

    /// Archive or restore a project item.
    #[must_use]
    pub fn archive_project_item(
        project_node_id: ManagementName,
        item_node_id: ManagementName,
        archived: bool,
    ) -> Self {
        let query = if archived {
            "mutation($project:ID!,$item:ID!){archiveProjectV2Item(input:{projectId:$project,itemId:$item}){item{id}}}"
        } else {
            "mutation($project:ID!,$item:ID!){unarchiveProjectV2Item(input:{projectId:$project,itemId:$item}){item{id}}}"
        };
        Self::json(
            HttpMethod::Post,
            String::from("/graphql"),
            json!({
                "query": query, "variables": {"project": project_node_id.as_str(), "item": item_node_id.as_str()}
            }),
        )
    }

    /// Remove a project item.
    #[must_use]
    pub fn delete_project_item(project: ProjectRef, item: DatabaseId) -> Self {
        Self::empty(
            HttpMethod::Delete,
            format!("{}/items/{}", project.path(), item.get()),
        )
    }

    /// Create a project status update for contextual auditing.
    #[must_use]
    pub fn create_project_status(
        project_node_id: ManagementName,
        body: ManagementText,
        status: Option<ProjectStatus>,
    ) -> Self {
        let mut input = Map::new();
        input.insert("projectId".into(), Value::String(project_node_id.0));
        input.insert("body".into(), Value::String(body.0));
        if let Some(status) = status {
            input.insert("status".into(), Value::String(status.as_str().into()));
        }
        Self::json(
            HttpMethod::Post,
            String::from("/graphql"),
            json!({
                "query": "mutation($input:CreateProjectV2StatusUpdateInput!){createProjectV2StatusUpdate(input:$input){statusUpdate{id}}}",
                "variables": {"input": Value::Object(input)}
            }),
        )
    }

    /// Transfer an issue using a fixed GraphQL document.
    #[must_use]
    pub fn transfer_issue(
        issue_node_id: ManagementName,
        repository_node_id: ManagementName,
    ) -> Self {
        Self::json(
            HttpMethod::Post,
            String::from("/graphql"),
            json!({
                "query": "mutation($issue:ID!,$repository:ID!){transferIssue(input:{issueId:$issue,repositoryId:$repository}){issue{id url}}}",
                "variables": {"issue": issue_node_id.as_str(), "repository": repository_node_id.as_str()}
            }),
        )
    }

    /// Pin or unpin an issue using fixed GraphQL documents.
    #[must_use]
    pub fn set_issue_pinned(issue_node_id: ManagementName, pinned: bool) -> Self {
        let query = if pinned {
            "mutation($issue:ID!){pinIssue(input:{issueId:$issue}){issue{id url}}}"
        } else {
            "mutation($issue:ID!){unpinIssue(input:{issueId:$issue}){issue{id url}}}"
        };
        Self::json(
            HttpMethod::Post,
            String::from("/graphql"),
            json!({"query": query, "variables": {"issue": issue_node_id.as_str()}}),
        )
    }

    /// The exact method.
    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        self.method
    }
    /// The locked path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    /// The optional JSON body.
    #[must_use]
    pub fn body(&self) -> Option<&str> {
        self.body.as_deref()
    }
    /// The optimistic concurrency precondition.
    #[must_use]
    pub const fn if_match(&self) -> Option<&EntityTag> {
        self.if_match.as_ref()
    }
}

/// A builder for issue and pull-request metadata changes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IssueManagementPatch {
    title: Option<ManagementName>,
    body: Option<ManagementText>,
    state: Option<&'static str>,
    state_reason: Option<&'static str>,
    milestone: Option<Option<u64>>,
    labels: Option<Vec<ManagementName>>,
    assignees: Option<Vec<Owner>>,
    issue_type: Option<Option<ManagementName>>,
}

impl IssueManagementPatch {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn title(mut self, value: ManagementName) -> Self {
        self.title = Some(value);
        self
    }
    #[must_use]
    pub fn body(mut self, value: ManagementText) -> Self {
        self.body = Some(value);
        self
    }
    #[must_use]
    pub fn state(mut self, open: bool, completed: bool) -> Self {
        self.state = Some(if open { "open" } else { "closed" });
        self.state_reason = (!open).then_some(if completed {
            "completed"
        } else {
            "not_planned"
        });
        self
    }
    #[must_use]
    pub fn milestone(mut self, value: Option<DatabaseId>) -> Self {
        self.milestone = Some(value.map(DatabaseId::get));
        self
    }
    pub fn labels(mut self, values: Vec<ManagementName>) -> Result<Self, GitHubRefusal> {
        if values.len() > 60 {
            return Err(GitHubRefusal::Management);
        }
        self.labels = Some(values);
        Ok(self)
    }
    pub fn assignees(mut self, values: Vec<Owner>) -> Result<Self, GitHubRefusal> {
        if values.len() > 10 {
            return Err(GitHubRefusal::Management);
        }
        self.assignees = Some(values);
        Ok(self)
    }
    #[must_use]
    pub fn issue_type(mut self, value: Option<ManagementName>) -> Self {
        self.issue_type = Some(value);
        self
    }

    fn into_json(self) -> Value {
        let mut body = Map::new();
        if let Some(title) = self.title {
            body.insert("title".into(), Value::String(title.0));
        }
        if let Some(issue_body) = self.body {
            body.insert("body".into(), Value::String(issue_body.0));
        }
        if let Some(state) = self.state {
            body.insert("state".into(), Value::String(state.into()));
        }
        if let Some(state_reason) = self.state_reason {
            body.insert("state_reason".into(), Value::String(state_reason.into()));
        }
        if let Some(milestone) = self.milestone {
            body.insert(
                "milestone".into(),
                milestone.map_or(Value::Null, Value::from),
            );
        }
        if let Some(labels) = self.labels {
            body.insert(
                "labels".into(),
                Value::Array(
                    labels
                        .into_iter()
                        .map(|label| Value::String(label.0))
                        .collect(),
                ),
            );
        }
        if let Some(assignees) = self.assignees {
            body.insert(
                "assignees".into(),
                Value::Array(
                    assignees
                        .into_iter()
                        .map(|assignee| Value::String(assignee.as_str().to_owned()))
                        .collect(),
                ),
            );
        }
        if let Some(issue_type) = self.issue_type {
            body.insert(
                "type".into(),
                issue_type.map_or(Value::Null, |issue_type| Value::String(issue_type.0)),
            );
        }
        Value::Object(body)
    }
}

/// Accepted management response. Empty `204` responses carry no document.
#[derive(Clone, Debug, PartialEq)]
pub struct ManagementReceipt {
    document: Option<Value>,
}

impl ManagementReceipt {
    pub(crate) const fn empty() -> Self {
        Self { document: None }
    }
    pub(crate) const fn document(value: Value) -> Self {
        Self {
            document: Some(value),
        }
    }
    /// Borrow the decoded GitHub document, if the endpoint returned one.
    #[must_use]
    pub const fn value(&self) -> Option<&Value> {
        self.document.as_ref()
    }
}

fn bounded_text(value: &str, max: usize) -> Result<String, GitHubRefusal> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > max
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(GitHubRefusal::Management);
    }
    Ok(value.to_owned())
}

fn encode_segment(value: &str) -> String {
    let mut out = String::new();
    crate::push_query_encoded(&mut out, value);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> RepoTarget {
        RepoTarget::parse("acme", "roadmap").expect("repo")
    }
    fn issue() -> IssueNumber {
        IssueNumber::new(12).expect("issue")
    }
    fn id(value: u64) -> DatabaseId {
        DatabaseId::new(value).expect("id")
    }

    #[test]
    fn label_names_are_encoded_and_bodies_are_json() {
        let request = ManagementRequest::update_label(
            repo(),
            ManagementName::new("needs docs").expect("name"),
            ManagementName::new("documentation").expect("name"),
            LabelColor::new("#AABBCC").expect("color"),
            None,
        );
        assert_eq!(request.method(), HttpMethod::Patch);
        assert_eq!(request.path(), "/repos/acme/roadmap/labels/needs%20docs");
        assert!(request.body().expect("body").contains("aabbcc"));
    }

    #[test]
    fn hierarchy_and_dependency_paths_are_fixed() {
        assert_eq!(
            ManagementRequest::add_sub_issue(repo(), issue(), id(88)).path(),
            "/repos/acme/roadmap/issues/12/sub_issues"
        );
        assert_eq!(
            ManagementRequest::remove_dependency(repo(), issue(), id(91)).path(),
            "/repos/acme/roadmap/issues/12/dependencies/blocked_by/91"
        );
    }

    #[test]
    fn project_owner_lookups_are_typed_and_creation_uses_a_fixed_graphql_document() {
        let organization = ProjectOwner::new(
            ProjectOwnerKind::Organization,
            Owner::new("acme").expect("owner"),
        );
        assert_eq!(
            ManagementRequest::lookup_project_owner(organization).path(),
            "/orgs/acme"
        );
        let request = ManagementRequest::create_project_by_node(
            ManagementName::new("O_acme").expect("node"),
            ManagementName::new("Roadmap").expect("title"),
        );
        assert_eq!(request.path(), "/graphql");
        assert!(request.body().expect("body").contains("createProjectV2"));
    }

    #[test]
    fn metadata_updates_emit_only_explicit_fields_and_keep_explicit_clears() {
        let patch = IssueManagementPatch::new()
            .title(ManagementName::new("New title").expect("title"))
            .milestone(None)
            .labels(Vec::new())
            .expect("labels");
        let request = ManagementRequest::update_issue(repo(), issue(), patch, None);
        let body: Value = serde_json::from_str(request.body().expect("body")).expect("json");
        let body = body.as_object().expect("object");
        assert_eq!(body.len(), 3);
        assert_eq!(body.get("title").and_then(Value::as_str), Some("New title"));
        assert_eq!(body.get("milestone"), Some(&Value::Null));
        assert_eq!(body.get("labels"), Some(&Value::Array(Vec::new())));
        assert!(!body.contains_key("assignees"));
        assert!(!body.contains_key("state"));
    }

    #[test]
    fn optional_rest_and_graphql_update_fields_are_omitted_not_null() {
        let milestone =
            ManagementRequest::update_milestone(repo(), id(4), None, None, None, Some(false));
        let body: Value =
            serde_json::from_str(milestone.body().expect("body")).expect("milestone json");
        assert_eq!(body, json!({"state": "closed"}));

        let project = ManagementRequest::update_project(
            ManagementName::new("PVT_project").expect("project"),
            None,
            None,
            Some(true),
            None,
        );
        let body: Value =
            serde_json::from_str(project.body().expect("body")).expect("project json");
        assert_eq!(
            body.pointer("/variables/input"),
            Some(&json!({"projectId": "PVT_project", "public": true}))
        );
    }

    #[test]
    fn a_batch_boundary_and_position_are_refused_locally() {
        assert_eq!(DatabaseId::new(0), Err(GitHubRefusal::Management));
        assert_eq!(
            ManagementRequest::reprioritize_sub_issue(repo(), issue(), id(1), None, None),
            Err(GitHubRefusal::Management)
        );
    }
}
