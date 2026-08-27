// SPDX-License-Identifier: Elastic-2.0

//! Negotiated Platform v2 work-context identities and bounded read model.
//!
//! This module is deliberately separate from [`crate::platform`]. Platform v1
//! is an installed exact wire contract: adding work-context kinds or fields to
//! its closed enums and records would make old clients reject otherwise valid
//! messages. V2 therefore owns new identities, relations, queries, and pages.
//! The existing execution [`crate::workspace::Workspace`] is not used here;
//! [`AttemptWorkspaceId`] names that security boundary in the user-facing
//! graph without changing its internal implementation type.

use core::fmt;

use crate::primitives::{BoundedString, IdDomain, OpaqueId, Revision, ValueError};

pub const PLATFORM_SCHEMA_V2: &str = "automonique.platform/v2";
pub const MIN_PLATFORM_VERSION: u16 = 1;
pub const MAX_PLATFORM_VERSION: u16 = 2;
pub const MAX_PLATFORM_VERSION_OFFERS: usize = 8;
pub const MAX_WORK_CONTEXT_FIELD_BYTES: usize = 256;
pub const MAX_WORK_CONTEXT_LABEL_BYTES: usize = 512;
pub const MAX_WORK_CONTEXT_RELATIONS: usize = 16;
pub const MAX_WORK_CONTEXT_QUERY_KINDS: usize = 7;
pub const MAX_WORK_CONTEXT_QUERY_LIFECYCLES: usize = 9;
pub const MAX_WORK_CONTEXT_PAGE_ITEMS: usize = 128;

macro_rules! id_domain {
    ($domain:ident, $name:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $domain;
        impl IdDomain for $domain {}
        pub type $name = OpaqueId<$domain, MAX_WORK_CONTEXT_FIELD_BYTES>;
    };
}

id_domain!(ProjectIdDomain, ProjectId);
id_domain!(HostSetupIdDomain, HostSetupId);
id_domain!(CheckoutIdDomain, CheckoutId);
id_domain!(UserWorkspaceIdDomain, UserWorkspaceId);
id_domain!(AttemptWorkspaceIdDomain, AttemptWorkspaceId);
id_domain!(WorkSessionIdDomain, WorkSessionId);
id_domain!(PaneIdDomain, PaneId);
id_domain!(RepositoryIdDomain, WorkContextRepositoryId);
id_domain!(PlatformSessionIdDomain, PlatformSessionId);
id_domain!(WorkContextCursorDomain, WorkContextCursor);

pub type WorkContextLabel = BoundedString<MAX_WORK_CONTEXT_LABEL_BYTES>;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PlatformVersion {
    V1,
    V2,
}

impl PlatformVersion {
    pub const ALL: [Self; 2] = [Self::V1, Self::V2];

    #[must_use]
    pub const fn number(self) -> u16 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }

    #[must_use]
    pub const fn schema(self) -> &'static str {
        match self {
            Self::V1 => crate::platform::PLATFORM_SCHEMA_V1,
            Self::V2 => PLATFORM_SCHEMA_V2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformVersionOffer {
    versions: Vec<PlatformVersion>,
}

impl PlatformVersionOffer {
    pub fn new(mut versions: Vec<PlatformVersion>) -> Result<Self, WorkContextError> {
        if versions.is_empty() || versions.len() > MAX_PLATFORM_VERSION_OFFERS {
            return Err(WorkContextError::VersionOfferInvalid);
        }
        versions.sort();
        versions.dedup();
        Ok(Self { versions })
    }

    #[must_use]
    pub fn versions(&self) -> &[PlatformVersion] {
        &self.versions
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkContextAvailability {
    /// V1 services remain fully usable, but structured work context is absent.
    V1ExistingResourcesOnly,
    /// V2 structured work-context queries are available.
    V2Structured,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegotiatedPlatform {
    pub version: PlatformVersion,
    pub schema: &'static str,
    pub work_context: WorkContextAvailability,
}

pub fn negotiate_platform_version(
    client: &PlatformVersionOffer,
    server: &PlatformVersionOffer,
) -> Result<NegotiatedPlatform, WorkContextError> {
    let version = client
        .versions()
        .iter()
        .rev()
        .find(|candidate| server.versions().contains(candidate))
        .copied()
        .ok_or(WorkContextError::VersionOverlapMissing)?;
    Ok(NegotiatedPlatform {
        version,
        schema: version.schema(),
        work_context: match version {
            PlatformVersion::V1 => WorkContextAvailability::V1ExistingResourcesOnly,
            PlatformVersion::V2 => WorkContextAvailability::V2Structured,
        },
    })
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkContextKind {
    Project,
    HostSetup,
    Checkout,
    UserWorkspace,
    AttemptWorkspace,
    Session,
    Pane,
}

impl WorkContextKind {
    pub const ALL: [Self; 7] = [
        Self::Project,
        Self::HostSetup,
        Self::Checkout,
        Self::UserWorkspace,
        Self::AttemptWorkspace,
        Self::Session,
        Self::Pane,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::HostSetup => "host_setup",
            Self::Checkout => "checkout",
            Self::UserWorkspace => "user_workspace",
            Self::AttemptWorkspace => "attempt_workspace",
            Self::Session => "session",
            Self::Pane => "pane",
        }
    }

    pub fn parse(value: &str) -> Result<Self, WorkContextError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or(WorkContextError::UnknownKind)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkContextTargetKind {
    Project,
    HostSetup,
    Checkout,
    UserWorkspace,
    AttemptWorkspace,
    Session,
    Pane,
    Repository,
    PlatformSession,
}

impl WorkContextTargetKind {
    pub const ALL: [Self; 9] = [
        Self::Project,
        Self::HostSetup,
        Self::Checkout,
        Self::UserWorkspace,
        Self::AttemptWorkspace,
        Self::Session,
        Self::Pane,
        Self::Repository,
        Self::PlatformSession,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::HostSetup => "host_setup",
            Self::Checkout => "checkout",
            Self::UserWorkspace => "user_workspace",
            Self::AttemptWorkspace => "attempt_workspace",
            Self::Session => "session",
            Self::Pane => "pane",
            Self::Repository => "repository",
            Self::PlatformSession => "platform_session",
        }
    }

    pub fn parse(value: &str) -> Result<Self, WorkContextError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or(WorkContextError::UnknownTargetKind)
    }
}

impl From<WorkContextKind> for WorkContextTargetKind {
    fn from(value: WorkContextKind) -> Self {
        match value {
            WorkContextKind::Project => Self::Project,
            WorkContextKind::HostSetup => Self::HostSetup,
            WorkContextKind::Checkout => Self::Checkout,
            WorkContextKind::UserWorkspace => Self::UserWorkspace,
            WorkContextKind::AttemptWorkspace => Self::AttemptWorkspace,
            WorkContextKind::Session => Self::Session,
            WorkContextKind::Pane => Self::Pane,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkContextIdentity {
    Project(ProjectId),
    HostSetup(HostSetupId),
    Checkout(CheckoutId),
    UserWorkspace(UserWorkspaceId),
    AttemptWorkspace(AttemptWorkspaceId),
    Session(WorkSessionId),
    Pane(PaneId),
    Repository(WorkContextRepositoryId),
    PlatformSession(PlatformSessionId),
}

impl WorkContextIdentity {
    #[must_use]
    pub const fn kind(&self) -> WorkContextTargetKind {
        match self {
            Self::Project(_) => WorkContextTargetKind::Project,
            Self::HostSetup(_) => WorkContextTargetKind::HostSetup,
            Self::Checkout(_) => WorkContextTargetKind::Checkout,
            Self::UserWorkspace(_) => WorkContextTargetKind::UserWorkspace,
            Self::AttemptWorkspace(_) => WorkContextTargetKind::AttemptWorkspace,
            Self::Session(_) => WorkContextTargetKind::Session,
            Self::Pane(_) => WorkContextTargetKind::Pane,
            Self::Repository(_) => WorkContextTargetKind::Repository,
            Self::PlatformSession(_) => WorkContextTargetKind::PlatformSession,
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Project(value) => value.as_str(),
            Self::HostSetup(value) => value.as_str(),
            Self::Checkout(value) => value.as_str(),
            Self::UserWorkspace(value) => value.as_str(),
            Self::AttemptWorkspace(value) => value.as_str(),
            Self::Session(value) => value.as_str(),
            Self::Pane(value) => value.as_str(),
            Self::Repository(value) => value.as_str(),
            Self::PlatformSession(value) => value.as_str(),
        }
    }

    pub fn parse(kind: WorkContextTargetKind, id: &str) -> Result<Self, WorkContextError> {
        macro_rules! build {
            ($variant:ident, $type:ident) => {
                Self::$variant($type::new(id.to_owned()).map_err(WorkContextError::Field)?)
            };
        }
        Ok(match kind {
            WorkContextTargetKind::Project => build!(Project, ProjectId),
            WorkContextTargetKind::HostSetup => build!(HostSetup, HostSetupId),
            WorkContextTargetKind::Checkout => build!(Checkout, CheckoutId),
            WorkContextTargetKind::UserWorkspace => build!(UserWorkspace, UserWorkspaceId),
            WorkContextTargetKind::AttemptWorkspace => {
                build!(AttemptWorkspace, AttemptWorkspaceId)
            }
            WorkContextTargetKind::Session => build!(Session, WorkSessionId),
            WorkContextTargetKind::Pane => build!(Pane, PaneId),
            WorkContextTargetKind::Repository => build!(Repository, WorkContextRepositoryId),
            WorkContextTargetKind::PlatformSession => {
                build!(PlatformSession, PlatformSessionId)
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkContextLifecycle {
    Active,
    Archived,
    Preparing,
    Running,
    Hibernated,
    Completed,
    Failed,
    Cancelled,
    Closed,
}

impl WorkContextLifecycle {
    pub const ALL: [Self; 9] = [
        Self::Active,
        Self::Archived,
        Self::Preparing,
        Self::Running,
        Self::Hibernated,
        Self::Completed,
        Self::Failed,
        Self::Cancelled,
        Self::Closed,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
            Self::Preparing => "preparing",
            Self::Running => "running",
            Self::Hibernated => "hibernated",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Closed => "closed",
        }
    }

    pub fn parse(value: &str) -> Result<Self, WorkContextError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or(WorkContextError::UnknownLifecycle)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HostSetupKind {
    Local,
    Ssh,
    RemoteRuntime,
}

impl HostSetupKind {
    pub const ALL: [Self; 3] = [Self::Local, Self::Ssh, Self::RemoteRuntime];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Ssh => "ssh",
            Self::RemoteRuntime => "remote_runtime",
        }
    }
    pub fn parse(value: &str) -> Result<Self, WorkContextError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or(WorkContextError::UnknownHostSetupKind)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CheckoutKind {
    GitWorktree,
    AuthorizedFolder,
}

impl CheckoutKind {
    pub const ALL: [Self; 2] = [Self::GitWorktree, Self::AuthorizedFolder];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GitWorktree => "git_worktree",
            Self::AuthorizedFolder => "authorized_folder",
        }
    }
    pub fn parse(value: &str) -> Result<Self, WorkContextError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or(WorkContextError::UnknownCheckoutKind)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkContextRelationKind {
    ProjectRepository,
    HostSetupProject,
    CheckoutProject,
    CheckoutHostSetup,
    CheckoutRepository,
    UserWorkspaceProject,
    UserWorkspaceCheckout,
    AttemptUserWorkspace,
    SessionAttemptWorkspace,
    SessionPlatformSession,
    PaneSession,
}

impl WorkContextRelationKind {
    pub const ALL: [Self; 11] = [
        Self::ProjectRepository,
        Self::HostSetupProject,
        Self::CheckoutProject,
        Self::CheckoutHostSetup,
        Self::CheckoutRepository,
        Self::UserWorkspaceProject,
        Self::UserWorkspaceCheckout,
        Self::AttemptUserWorkspace,
        Self::SessionAttemptWorkspace,
        Self::SessionPlatformSession,
        Self::PaneSession,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProjectRepository => "project_repository",
            Self::HostSetupProject => "host_setup_project",
            Self::CheckoutProject => "checkout_project",
            Self::CheckoutHostSetup => "checkout_host_setup",
            Self::CheckoutRepository => "checkout_repository",
            Self::UserWorkspaceProject => "user_workspace_project",
            Self::UserWorkspaceCheckout => "user_workspace_checkout",
            Self::AttemptUserWorkspace => "attempt_user_workspace",
            Self::SessionAttemptWorkspace => "session_attempt_workspace",
            Self::SessionPlatformSession => "session_platform_session",
            Self::PaneSession => "pane_session",
        }
    }

    pub fn parse(value: &str) -> Result<Self, WorkContextError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or(WorkContextError::UnknownRelation)
    }

    #[must_use]
    pub const fn source(self) -> WorkContextKind {
        match self {
            Self::ProjectRepository => WorkContextKind::Project,
            Self::HostSetupProject => WorkContextKind::HostSetup,
            Self::CheckoutProject | Self::CheckoutHostSetup | Self::CheckoutRepository => {
                WorkContextKind::Checkout
            }
            Self::UserWorkspaceProject | Self::UserWorkspaceCheckout => {
                WorkContextKind::UserWorkspace
            }
            Self::AttemptUserWorkspace => WorkContextKind::AttemptWorkspace,
            Self::SessionAttemptWorkspace | Self::SessionPlatformSession => {
                WorkContextKind::Session
            }
            Self::PaneSession => WorkContextKind::Pane,
        }
    }

    #[must_use]
    pub const fn target(self) -> WorkContextTargetKind {
        match self {
            Self::ProjectRepository | Self::CheckoutRepository => WorkContextTargetKind::Repository,
            Self::HostSetupProject | Self::CheckoutProject | Self::UserWorkspaceProject => {
                WorkContextTargetKind::Project
            }
            Self::CheckoutHostSetup => WorkContextTargetKind::HostSetup,
            Self::UserWorkspaceCheckout => WorkContextTargetKind::Checkout,
            Self::AttemptUserWorkspace => WorkContextTargetKind::UserWorkspace,
            Self::SessionAttemptWorkspace => WorkContextTargetKind::AttemptWorkspace,
            Self::SessionPlatformSession => WorkContextTargetKind::PlatformSession,
            Self::PaneSession => WorkContextTargetKind::Session,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkContextRelation {
    pub kind: WorkContextRelationKind,
    pub target: WorkContextIdentity,
}

impl WorkContextRelation {
    pub fn new(
        kind: WorkContextRelationKind,
        target: WorkContextIdentity,
    ) -> Result<Self, WorkContextError> {
        if target.kind() != kind.target() {
            return Err(WorkContextError::RelationTargetInvalid);
        }
        Ok(Self { kind, target })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkContextAttributes {
    pub host_setup: Option<HostSetupKind>,
    pub checkout: Option<CheckoutKind>,
}

impl WorkContextAttributes {
    pub const EMPTY: Self = Self {
        host_setup: None,
        checkout: None,
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkContextRecord {
    pub identity: WorkContextIdentity,
    pub revision: Revision,
    pub lifecycle: WorkContextLifecycle,
    pub label: WorkContextLabel,
    pub attributes: WorkContextAttributes,
    pub relations: Vec<WorkContextRelation>,
}

impl WorkContextRecord {
    pub fn new(
        identity: WorkContextIdentity,
        revision: Revision,
        lifecycle: WorkContextLifecycle,
        label: WorkContextLabel,
        attributes: WorkContextAttributes,
        mut relations: Vec<WorkContextRelation>,
    ) -> Result<Self, WorkContextError> {
        let kind = record_kind(&identity)?;
        if !lifecycle_allowed(kind, lifecycle) {
            return Err(WorkContextError::LifecycleInvalid);
        }
        if relations.len() > MAX_WORK_CONTEXT_RELATIONS {
            return Err(WorkContextError::TooManyRelations);
        }
        if relations
            .iter()
            .any(|relation| relation.kind.source() != kind)
        {
            return Err(WorkContextError::RelationSourceInvalid);
        }
        relations.sort();
        if relations.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(WorkContextError::DuplicateRelation);
        }
        validate_required_relations(kind, &relations)?;
        match kind {
            WorkContextKind::HostSetup
                if attributes.host_setup.is_some() && attributes.checkout.is_none() => {}
            WorkContextKind::Checkout
                if attributes.checkout.is_some() && attributes.host_setup.is_none() => {}
            WorkContextKind::HostSetup | WorkContextKind::Checkout => {
                return Err(WorkContextError::AttributesInvalid);
            }
            _ if attributes != WorkContextAttributes::EMPTY => {
                return Err(WorkContextError::AttributesInvalid);
            }
            _ => {}
        }
        Ok(Self {
            identity,
            revision,
            lifecycle,
            label,
            attributes,
            relations,
        })
    }

    #[must_use]
    pub fn kind(&self) -> WorkContextKind {
        record_kind(&self.identity).expect("record constructors exclude relation-only identities")
    }
}

fn record_kind(identity: &WorkContextIdentity) -> Result<WorkContextKind, WorkContextError> {
    Ok(match identity {
        WorkContextIdentity::Project(_) => WorkContextKind::Project,
        WorkContextIdentity::HostSetup(_) => WorkContextKind::HostSetup,
        WorkContextIdentity::Checkout(_) => WorkContextKind::Checkout,
        WorkContextIdentity::UserWorkspace(_) => WorkContextKind::UserWorkspace,
        WorkContextIdentity::AttemptWorkspace(_) => WorkContextKind::AttemptWorkspace,
        WorkContextIdentity::Session(_) => WorkContextKind::Session,
        WorkContextIdentity::Pane(_) => WorkContextKind::Pane,
        WorkContextIdentity::Repository(_) | WorkContextIdentity::PlatformSession(_) => {
            return Err(WorkContextError::RecordIdentityInvalid);
        }
    })
}

const fn lifecycle_allowed(kind: WorkContextKind, lifecycle: WorkContextLifecycle) -> bool {
    match kind {
        WorkContextKind::Project
        | WorkContextKind::HostSetup
        | WorkContextKind::Checkout
        | WorkContextKind::UserWorkspace => {
            matches!(
                lifecycle,
                WorkContextLifecycle::Active | WorkContextLifecycle::Archived
            )
        }
        WorkContextKind::AttemptWorkspace => matches!(
            lifecycle,
            WorkContextLifecycle::Preparing
                | WorkContextLifecycle::Running
                | WorkContextLifecycle::Hibernated
                | WorkContextLifecycle::Completed
                | WorkContextLifecycle::Failed
                | WorkContextLifecycle::Cancelled
        ),
        WorkContextKind::Session => matches!(
            lifecycle,
            WorkContextLifecycle::Active
                | WorkContextLifecycle::Hibernated
                | WorkContextLifecycle::Completed
                | WorkContextLifecycle::Failed
                | WorkContextLifecycle::Cancelled
        ),
        WorkContextKind::Pane => {
            matches!(
                lifecycle,
                WorkContextLifecycle::Active | WorkContextLifecycle::Closed
            )
        }
    }
}

fn validate_required_relations(
    kind: WorkContextKind,
    relations: &[WorkContextRelation],
) -> Result<(), WorkContextError> {
    let required: &[WorkContextRelationKind] = match kind {
        WorkContextKind::Project => &[],
        WorkContextKind::HostSetup => &[WorkContextRelationKind::HostSetupProject],
        WorkContextKind::Checkout => &[
            WorkContextRelationKind::CheckoutProject,
            WorkContextRelationKind::CheckoutHostSetup,
            WorkContextRelationKind::CheckoutRepository,
        ],
        WorkContextKind::UserWorkspace => &[
            WorkContextRelationKind::UserWorkspaceProject,
            WorkContextRelationKind::UserWorkspaceCheckout,
        ],
        WorkContextKind::AttemptWorkspace => &[WorkContextRelationKind::AttemptUserWorkspace],
        WorkContextKind::Session => &[
            WorkContextRelationKind::SessionAttemptWorkspace,
            WorkContextRelationKind::SessionPlatformSession,
        ],
        WorkContextKind::Pane => &[WorkContextRelationKind::PaneSession],
    };
    for relation_kind in WorkContextRelationKind::ALL {
        let count = relations
            .iter()
            .filter(|relation| relation.kind == relation_kind)
            .count();
        let expected = if required.contains(&relation_kind) {
            1
        } else if kind == WorkContextKind::Project
            && relation_kind == WorkContextRelationKind::ProjectRepository
        {
            usize::from(count > 0)
        } else {
            0
        };
        if (expected == 1 && count == 0) || count > 1 && kind != WorkContextKind::Project {
            return Err(WorkContextError::RequiredRelationInvalid);
        }
        if expected == 0 && count > 0 {
            return Err(WorkContextError::RelationSourceInvalid);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkContextQuery {
    pub kinds: Vec<WorkContextKind>,
    pub lifecycles: Vec<WorkContextLifecycle>,
    pub project: Option<ProjectId>,
    pub parent: Option<WorkContextIdentity>,
    pub after: Option<WorkContextCursor>,
    pub limit: u16,
}

impl WorkContextQuery {
    pub fn new(
        mut kinds: Vec<WorkContextKind>,
        mut lifecycles: Vec<WorkContextLifecycle>,
        project: Option<ProjectId>,
        parent: Option<WorkContextIdentity>,
        after: Option<WorkContextCursor>,
        limit: u16,
    ) -> Result<Self, WorkContextError> {
        kinds.sort();
        kinds.dedup();
        lifecycles.sort();
        lifecycles.dedup();
        if kinds.is_empty() || kinds.len() > MAX_WORK_CONTEXT_QUERY_KINDS {
            return Err(WorkContextError::QueryKindsInvalid);
        }
        if lifecycles.len() > MAX_WORK_CONTEXT_QUERY_LIFECYCLES {
            return Err(WorkContextError::QueryLifecyclesInvalid);
        }
        if limit == 0 || usize::from(limit) > MAX_WORK_CONTEXT_PAGE_ITEMS {
            return Err(WorkContextError::QueryLimitInvalid);
        }
        Ok(Self {
            kinds,
            lifecycles,
            project,
            parent,
            after,
            limit,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkContextPage {
    pub requested_limit: u16,
    pub after: Option<WorkContextCursor>,
    pub next_cursor: Option<WorkContextCursor>,
    pub has_more: bool,
    pub items: Vec<WorkContextRecord>,
}

impl WorkContextPage {
    pub fn new(
        requested_limit: u16,
        after: Option<WorkContextCursor>,
        next_cursor: Option<WorkContextCursor>,
        has_more: bool,
        items: Vec<WorkContextRecord>,
    ) -> Result<Self, WorkContextError> {
        if requested_limit == 0
            || usize::from(requested_limit) > MAX_WORK_CONTEXT_PAGE_ITEMS
            || items.len() > usize::from(requested_limit)
        {
            return Err(WorkContextError::PageLimitInvalid);
        }
        if has_more != next_cursor.is_some() || (has_more && items.is_empty()) {
            return Err(WorkContextError::PageCursorInvalid);
        }
        if after.is_some() && after == next_cursor {
            return Err(WorkContextError::PageCursorInvalid);
        }
        Ok(Self {
            requested_limit,
            after,
            next_cursor,
            has_more,
            items,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkContextError {
    Field(ValueError),
    VersionOfferInvalid,
    VersionOverlapMissing,
    UnknownKind,
    UnknownTargetKind,
    UnknownLifecycle,
    UnknownHostSetupKind,
    UnknownCheckoutKind,
    UnknownRelation,
    RecordIdentityInvalid,
    LifecycleInvalid,
    AttributesInvalid,
    TooManyRelations,
    RelationSourceInvalid,
    RelationTargetInvalid,
    DuplicateRelation,
    RequiredRelationInvalid,
    QueryKindsInvalid,
    QueryLifecyclesInvalid,
    QueryLimitInvalid,
    PageLimitInvalid,
    PageCursorInvalid,
}

impl fmt::Display for WorkContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Field(_) => "work-context field is invalid",
            Self::VersionOfferInvalid => "platform version offer is invalid",
            Self::VersionOverlapMissing => "platform versions do not overlap",
            Self::UnknownKind => "work-context kind is unknown",
            Self::UnknownTargetKind => "work-context target kind is unknown",
            Self::UnknownLifecycle => "work-context lifecycle is unknown",
            Self::UnknownHostSetupKind => "host setup kind is unknown",
            Self::UnknownCheckoutKind => "checkout kind is unknown",
            Self::UnknownRelation => "work-context relation is unknown",
            Self::RecordIdentityInvalid => "relation-only identity cannot be a record",
            Self::LifecycleInvalid => "lifecycle is invalid for work-context kind",
            Self::AttributesInvalid => "attributes are invalid for work-context kind",
            Self::TooManyRelations => "work-context relation limit exceeded",
            Self::RelationSourceInvalid => "relation is invalid for source kind",
            Self::RelationTargetInvalid => "relation target kind is invalid",
            Self::DuplicateRelation => "work-context relation is duplicated",
            Self::RequiredRelationInvalid => {
                "required work-context relation is missing or repeated"
            }
            Self::QueryKindsInvalid => "work-context query kinds are invalid",
            Self::QueryLifecyclesInvalid => "work-context lifecycle filter is invalid",
            Self::QueryLimitInvalid => "work-context query limit is invalid",
            Self::PageLimitInvalid => "work-context page limit is invalid",
            Self::PageCursorInvalid => "work-context page cursor is incoherent",
        })
    }
}

impl std::error::Error for WorkContextError {}

impl From<ValueError> for WorkContextError {
    fn from(value: ValueError) -> Self {
        Self::Field(value)
    }
}
