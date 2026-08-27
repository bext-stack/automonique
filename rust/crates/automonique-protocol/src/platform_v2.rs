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

use crate::digest::Sha256;
use crate::platform::{ResourceCoordinate, ResourceKind};
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

    pub const fn from_number(value: u16) -> Result<Self, WorkContextError> {
        match value {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            _ => Err(WorkContextError::VersionOfferInvalid),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformVersionOffer {
    versions: Vec<PlatformVersion>,
}

impl PlatformVersionOffer {
    pub fn new(versions: Vec<PlatformVersion>) -> Result<Self, WorkContextError> {
        if versions.is_empty() || versions.len() > MAX_PLATFORM_VERSION_OFFERS {
            return Err(WorkContextError::VersionOfferInvalid);
        }
        if !strictly_increasing(&versions) {
            return Err(WorkContextError::VersionOfferInvalid);
        }
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

impl WorkContextAvailability {
    pub const ALL: [Self; 2] = [Self::V1ExistingResourcesOnly, Self::V2Structured];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1ExistingResourcesOnly => "v1_existing_resources_only",
            Self::V2Structured => "v2_structured",
        }
    }

    pub fn parse(value: &str) -> Result<Self, WorkContextError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or(WorkContextError::UnknownAvailability)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegotiatedPlatform {
    version: PlatformVersion,
    schema: &'static str,
    work_context: WorkContextAvailability,
}

impl NegotiatedPlatform {
    pub fn new(
        version: PlatformVersion,
        schema: &'static str,
        work_context: WorkContextAvailability,
    ) -> Result<Self, WorkContextError> {
        let expected = match version {
            PlatformVersion::V1 => WorkContextAvailability::V1ExistingResourcesOnly,
            PlatformVersion::V2 => WorkContextAvailability::V2Structured,
        };
        if schema != version.schema() || work_context != expected {
            return Err(WorkContextError::NegotiatedPlatformInvalid);
        }
        Ok(Self {
            version,
            schema,
            work_context,
        })
    }

    #[must_use]
    pub const fn version(&self) -> PlatformVersion {
        self.version
    }

    #[must_use]
    pub const fn schema(&self) -> &'static str {
        self.schema
    }

    #[must_use]
    pub const fn work_context(&self) -> WorkContextAvailability {
        self.work_context
    }
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
    NegotiatedPlatform::new(
        version,
        version.schema(),
        match version {
            PlatformVersion::V1 => WorkContextAvailability::V1ExistingResourcesOnly,
            PlatformVersion::V2 => WorkContextAvailability::V2Structured,
        },
    )
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
pub struct V1RepositoryRef(ResourceCoordinate);

impl V1RepositoryRef {
    pub fn new(coordinate: ResourceCoordinate) -> Result<Self, WorkContextError> {
        if coordinate.kind != ResourceKind::Repository {
            return Err(WorkContextError::V1CoordinateKindInvalid);
        }
        Ok(Self(coordinate))
    }

    #[must_use]
    pub const fn coordinate(&self) -> &ResourceCoordinate {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct V1SessionRef(ResourceCoordinate);

impl V1SessionRef {
    pub fn new(coordinate: ResourceCoordinate) -> Result<Self, WorkContextError> {
        if coordinate.kind != ResourceKind::Session {
            return Err(WorkContextError::V1CoordinateKindInvalid);
        }
        Ok(Self(coordinate))
    }

    #[must_use]
    pub const fn coordinate(&self) -> &ResourceCoordinate {
        &self.0
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
    Repository(V1RepositoryRef),
    PlatformSession(V1SessionRef),
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
            Self::Repository(value) => value.coordinate().id.as_str(),
            Self::PlatformSession(value) => value.coordinate().id.as_str(),
        }
    }

    pub fn parse_local(kind: WorkContextTargetKind, id: &str) -> Result<Self, WorkContextError> {
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
            WorkContextTargetKind::Repository | WorkContextTargetKind::PlatformSession => {
                return Err(WorkContextError::V1CoordinateRequired);
            }
        })
    }

    #[must_use]
    pub const fn v1_coordinate(&self) -> Option<&ResourceCoordinate> {
        match self {
            Self::Repository(value) => Some(value.coordinate()),
            Self::PlatformSession(value) => Some(value.coordinate()),
            _ => None,
        }
    }
}

/// Issue one authority-owned work-context identity from an independently
/// generated 128-bit nonce.
///
/// The authoritative issuer must obtain `random_nonce` directly from a
/// cryptographically secure random generator. It must never derive these
/// bytes from a path, repository slug, host address, provider/session token,
/// display label, or other sensitive input. This narrow issuance signature is
/// separate from wire decoding: [`OpaqueId`] deliberately accepts legitimate
/// opaque Unicode spellings and cannot determine what semantic source an
/// already-issued identifier came from.
#[must_use]
pub fn issue_work_context_identity_from_random_nonce(
    kind: WorkContextKind,
    random_nonce: [u8; 16],
) -> WorkContextIdentity {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(4 + kind.as_str().len() + random_nonce.len() * 2);
    value.push_str("wc2_");
    value.push_str(kind.as_str());
    value.push('_');
    for byte in random_nonce {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    WorkContextIdentity::parse_local(kind.into(), &value)
        .expect("fixed issuer rendering satisfies the opaque identifier bound")
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
    kind: WorkContextRelationKind,
    target: WorkContextIdentity,
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

    #[must_use]
    pub const fn kind(&self) -> WorkContextRelationKind {
        self.kind
    }

    #[must_use]
    pub const fn target(&self) -> &WorkContextIdentity {
        &self.target
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkContextAttributes {
    host_setup: Option<HostSetupKind>,
    checkout: Option<CheckoutKind>,
}

impl WorkContextAttributes {
    pub const EMPTY: Self = Self {
        host_setup: None,
        checkout: None,
    };

    #[must_use]
    pub const fn host_setup(kind: HostSetupKind) -> Self {
        Self {
            host_setup: Some(kind),
            checkout: None,
        }
    }

    #[must_use]
    pub const fn checkout(kind: CheckoutKind) -> Self {
        Self {
            host_setup: None,
            checkout: Some(kind),
        }
    }

    #[must_use]
    pub const fn host_setup_kind(self) -> Option<HostSetupKind> {
        self.host_setup
    }

    #[must_use]
    pub const fn checkout_kind(self) -> Option<CheckoutKind> {
        self.checkout
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkContextRecord {
    identity: WorkContextIdentity,
    revision: Revision,
    lifecycle: WorkContextLifecycle,
    label: WorkContextLabel,
    attributes: WorkContextAttributes,
    relations: Vec<WorkContextRelation>,
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

    #[must_use]
    pub const fn identity(&self) -> &WorkContextIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn lifecycle(&self) -> WorkContextLifecycle {
        self.lifecycle
    }

    #[must_use]
    pub const fn label(&self) -> &WorkContextLabel {
        &self.label
    }

    #[must_use]
    pub const fn attributes(&self) -> WorkContextAttributes {
        self.attributes
    }

    #[must_use]
    pub fn relations(&self) -> &[WorkContextRelation] {
        &self.relations
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
    kinds: Vec<WorkContextKind>,
    lifecycles: Vec<WorkContextLifecycle>,
    project: Option<ProjectId>,
    parent: Option<WorkContextIdentity>,
    after: Option<WorkContextCursor>,
    limit: u16,
}

impl WorkContextQuery {
    pub fn new(
        kinds: Vec<WorkContextKind>,
        lifecycles: Vec<WorkContextLifecycle>,
        project: Option<ProjectId>,
        parent: Option<WorkContextIdentity>,
        after: Option<WorkContextCursor>,
        limit: u16,
    ) -> Result<Self, WorkContextError> {
        if kinds.is_empty() || kinds.len() > MAX_WORK_CONTEXT_QUERY_KINDS {
            return Err(WorkContextError::QueryKindsInvalid);
        }
        if lifecycles.len() > MAX_WORK_CONTEXT_QUERY_LIFECYCLES {
            return Err(WorkContextError::QueryLifecyclesInvalid);
        }
        if !strictly_increasing(&kinds) || !strictly_increasing_or_empty(&lifecycles) {
            return Err(WorkContextError::QueryOrderInvalid);
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

    #[must_use]
    pub fn kinds(&self) -> &[WorkContextKind] {
        &self.kinds
    }

    #[must_use]
    pub fn lifecycles(&self) -> &[WorkContextLifecycle] {
        &self.lifecycles
    }

    #[must_use]
    pub const fn project(&self) -> Option<&ProjectId> {
        self.project.as_ref()
    }

    #[must_use]
    pub const fn parent(&self) -> Option<&WorkContextIdentity> {
        self.parent.as_ref()
    }

    #[must_use]
    pub const fn after(&self) -> Option<&WorkContextCursor> {
        self.after.as_ref()
    }

    #[must_use]
    pub const fn limit(&self) -> u16 {
        self.limit
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkContextPage {
    requested_limit: u16,
    after: Option<WorkContextCursor>,
    next_cursor: Option<WorkContextCursor>,
    has_more: bool,
    items: Vec<WorkContextRecord>,
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
        if !items
            .windows(2)
            .all(|pair| pair[0].identity() < pair[1].identity())
        {
            return Err(WorkContextError::PageOrderInvalid);
        }
        Ok(Self {
            requested_limit,
            after,
            next_cursor,
            has_more,
            items,
        })
    }

    #[must_use]
    pub const fn requested_limit(&self) -> u16 {
        self.requested_limit
    }

    #[must_use]
    pub const fn after(&self) -> Option<&WorkContextCursor> {
        self.after.as_ref()
    }

    #[must_use]
    pub const fn next_cursor(&self) -> Option<&WorkContextCursor> {
        self.next_cursor.as_ref()
    }

    #[must_use]
    pub const fn has_more(&self) -> bool {
        self.has_more
    }

    #[must_use]
    pub fn items(&self) -> &[WorkContextRecord] {
        &self.items
    }

    #[must_use]
    pub fn into_items(self) -> Vec<WorkContextRecord> {
        self.items
    }
}

/// One already-authorized record plus server-resolved ancestry used for
/// deterministic filtering. This type does not decide authorization: callers
/// must remove forbidden records before constructing it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedWorkContextRecord {
    record: WorkContextRecord,
    project: ProjectId,
    parents: Vec<WorkContextIdentity>,
}

impl AuthorizedWorkContextRecord {
    pub fn new(
        record: WorkContextRecord,
        project: ProjectId,
        mut parents: Vec<WorkContextIdentity>,
    ) -> Result<Self, WorkContextError> {
        if parents.len() > MAX_WORK_CONTEXT_RELATIONS {
            return Err(WorkContextError::InventoryInvalid);
        }
        parents.sort();
        if parents.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(WorkContextError::InventoryInvalid);
        }
        if let WorkContextIdentity::Project(identity) = record.identity()
            && identity != &project
        {
            return Err(WorkContextError::InventoryInvalid);
        }
        let direct_projects: Vec<&WorkContextIdentity> = record
            .relations()
            .iter()
            .filter(|relation| relation.target().kind() == WorkContextTargetKind::Project)
            .map(WorkContextRelation::target)
            .collect();
        if direct_projects.iter().any(|identity| {
            !matches!(identity, WorkContextIdentity::Project(value) if value == &project)
        }) {
            return Err(WorkContextError::InventoryInvalid);
        }
        Ok(Self {
            record,
            project,
            parents,
        })
    }

    #[must_use]
    pub const fn record(&self) -> &WorkContextRecord {
        &self.record
    }

    #[must_use]
    pub const fn project(&self) -> &ProjectId {
        &self.project
    }

    #[must_use]
    pub fn parents(&self) -> &[WorkContextIdentity] {
        &self.parents
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkContextResync {
    expired_after: WorkContextCursor,
}

impl WorkContextResync {
    #[must_use]
    pub const fn new(expired_after: WorkContextCursor) -> Self {
        Self { expired_after }
    }

    #[must_use]
    pub const fn expired_after(&self) -> &WorkContextCursor {
        &self.expired_after
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkContextQueryResult {
    Page(WorkContextPage),
    Resync(WorkContextResync),
}

/// Page a deterministic set of records the caller has already authorization-
/// filtered. The cursor binds the filter and complete input revision set, so a
/// changed filter or inventory returns `Resync` rather than skipping records.
pub fn page_authorized_work_context(
    query: &WorkContextQuery,
    records: &[AuthorizedWorkContextRecord],
) -> Result<WorkContextQueryResult, WorkContextError> {
    let mut ordered: Vec<&AuthorizedWorkContextRecord> = records.iter().collect();
    ordered.sort_by_key(|item| identity_order_key(item.record().identity()));
    if ordered.windows(2).any(|pair| {
        identity_order_key(pair[0].record().identity())
            == identity_order_key(pair[1].record().identity())
    }) {
        return Err(WorkContextError::InventoryInvalid);
    }
    let inventory = inventory_fingerprint(&ordered);
    let filter = query_filter_fingerprint(query);
    let start = match query.after() {
        None => 0,
        Some(after) => match decode_bound_cursor(after) {
            Some((cursor_filter, cursor_inventory, offset))
                if cursor_filter == filter && cursor_inventory == inventory =>
            {
                offset
            }
            _ => {
                return Ok(WorkContextQueryResult::Resync(WorkContextResync {
                    expired_after: after.clone(),
                }));
            }
        },
    };
    let filtered: Vec<&AuthorizedWorkContextRecord> = ordered
        .into_iter()
        .filter(|item| query.kinds().contains(&item.record().kind()))
        .filter(|item| {
            query.lifecycles().is_empty() || query.lifecycles().contains(&item.record().lifecycle())
        })
        .filter(|item| {
            query
                .project()
                .is_none_or(|project| project == item.project())
        })
        .filter(|item| {
            query
                .parent()
                .is_none_or(|parent| item.parents().contains(parent))
        })
        .collect();
    if start > filtered.len() {
        return Ok(WorkContextQueryResult::Resync(WorkContextResync {
            expired_after: query
                .after()
                .expect("nonzero start comes from a cursor")
                .clone(),
        }));
    }
    let end = start
        .saturating_add(usize::from(query.limit()))
        .min(filtered.len());
    let has_more = end < filtered.len();
    let next_cursor = has_more
        .then(|| encode_bound_cursor(&filter, &inventory, end))
        .transpose()?;
    Ok(WorkContextQueryResult::Page(WorkContextPage::new(
        query.limit(),
        query.after().cloned(),
        next_cursor,
        has_more,
        filtered[start..end]
            .iter()
            .map(|item| item.record().clone())
            .collect(),
    )?))
}

fn identity_order_key(identity: &WorkContextIdentity) -> String {
    let mut key = identity.kind().as_str().to_owned();
    key.push('\0');
    if let Some(coordinate) = identity.v1_coordinate() {
        key.push_str(coordinate.authority.as_str());
        key.push('\0');
        key.push_str(coordinate.kind.as_str());
        key.push('\0');
    }
    key.push_str(identity.id());
    key
}

fn inventory_fingerprint(records: &[&AuthorizedWorkContextRecord]) -> String {
    let mut bytes = Vec::new();
    for item in records {
        bytes.extend_from_slice(identity_order_key(item.record().identity()).as_bytes());
        bytes.push(0xff);
        bytes.extend_from_slice(item.record().revision().get().to_string().as_bytes());
        bytes.push(0xfe);
        bytes.extend_from_slice(item.project().as_str().as_bytes());
        for parent in item.parents() {
            bytes.push(0xfd);
            bytes.extend_from_slice(identity_order_key(parent).as_bytes());
        }
        bytes.push(0xfc);
    }
    Sha256::digest(&bytes).to_hex()
}

fn query_filter_fingerprint(query: &WorkContextQuery) -> String {
    let mut bytes = Vec::new();
    for kind in query.kinds() {
        bytes.extend_from_slice(kind.as_str().as_bytes());
        bytes.push(0xff);
    }
    bytes.push(0xfe);
    for lifecycle in query.lifecycles() {
        bytes.extend_from_slice(lifecycle.as_str().as_bytes());
        bytes.push(0xff);
    }
    if let Some(project) = query.project() {
        bytes.push(0xfd);
        bytes.extend_from_slice(project.as_str().as_bytes());
    }
    if let Some(parent) = query.parent() {
        bytes.push(0xfc);
        bytes.extend_from_slice(identity_order_key(parent).as_bytes());
    }
    Sha256::digest(&bytes).to_hex()
}

fn encode_bound_cursor(
    filter: &str,
    inventory: &str,
    offset: usize,
) -> Result<WorkContextCursor, WorkContextError> {
    WorkContextCursor::new(format!("wc2.{filter}.{inventory}.{offset}"))
        .map_err(WorkContextError::Field)
}

fn decode_bound_cursor(cursor: &WorkContextCursor) -> Option<(&str, &str, usize)> {
    let mut parts = cursor.as_str().split('.');
    let prefix = parts.next()?;
    let filter = parts.next()?;
    let inventory = parts.next()?;
    let offset = parts.next()?;
    if prefix != "wc2"
        || filter.len() != 64
        || inventory.len() != 64
        || parts.next().is_some()
        || offset.starts_with('0') && offset != "0"
        || !filter
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || !inventory
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    Some((filter, inventory, offset.parse().ok()?))
}

fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    !values.is_empty() && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_increasing_or_empty<T: Ord>(values: &[T]) -> bool {
    values.is_empty() || strictly_increasing(values)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkContextError {
    Field(ValueError),
    VersionOfferInvalid,
    VersionOverlapMissing,
    NegotiatedPlatformInvalid,
    UnknownKind,
    UnknownTargetKind,
    UnknownLifecycle,
    UnknownAvailability,
    UnknownHostSetupKind,
    UnknownCheckoutKind,
    UnknownRelation,
    RecordIdentityInvalid,
    LifecycleInvalid,
    AttributesInvalid,
    TooManyRelations,
    RelationSourceInvalid,
    RelationTargetInvalid,
    V1CoordinateRequired,
    V1CoordinateKindInvalid,
    DuplicateRelation,
    RelationOrderInvalid,
    RequiredRelationInvalid,
    QueryKindsInvalid,
    QueryLifecyclesInvalid,
    QueryLimitInvalid,
    QueryOrderInvalid,
    PageLimitInvalid,
    PageCursorInvalid,
    PageOrderInvalid,
    InventoryInvalid,
}

impl fmt::Display for WorkContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Field(_) => "work-context field is invalid",
            Self::VersionOfferInvalid => "platform version offer is invalid",
            Self::VersionOverlapMissing => "platform versions do not overlap",
            Self::NegotiatedPlatformInvalid => "negotiated platform result is incoherent",
            Self::UnknownKind => "work-context kind is unknown",
            Self::UnknownTargetKind => "work-context target kind is unknown",
            Self::UnknownLifecycle => "work-context lifecycle is unknown",
            Self::UnknownAvailability => "work-context availability is unknown",
            Self::UnknownHostSetupKind => "host setup kind is unknown",
            Self::UnknownCheckoutKind => "checkout kind is unknown",
            Self::UnknownRelation => "work-context relation is unknown",
            Self::RecordIdentityInvalid => "relation-only identity cannot be a record",
            Self::LifecycleInvalid => "lifecycle is invalid for work-context kind",
            Self::AttributesInvalid => "attributes are invalid for work-context kind",
            Self::TooManyRelations => "work-context relation limit exceeded",
            Self::RelationSourceInvalid => "relation is invalid for source kind",
            Self::RelationTargetInvalid => "relation target kind is invalid",
            Self::V1CoordinateRequired => "v1 relation target requires a full coordinate",
            Self::V1CoordinateKindInvalid => "v1 relation coordinate kind is invalid",
            Self::DuplicateRelation => "work-context relation is duplicated",
            Self::RelationOrderInvalid => "work-context relations are unordered",
            Self::RequiredRelationInvalid => {
                "required work-context relation is missing or repeated"
            }
            Self::QueryKindsInvalid => "work-context query kinds are invalid",
            Self::QueryLifecyclesInvalid => "work-context lifecycle filter is invalid",
            Self::QueryLimitInvalid => "work-context query limit is invalid",
            Self::QueryOrderInvalid => "work-context query filters are repeated or unordered",
            Self::PageLimitInvalid => "work-context page limit is invalid",
            Self::PageCursorInvalid => "work-context page cursor is incoherent",
            Self::PageOrderInvalid => "work-context page identities are repeated or unordered",
            Self::InventoryInvalid => "authorized work-context inventory is invalid",
        })
    }
}

impl std::error::Error for WorkContextError {}

impl From<ValueError> for WorkContextError {
    fn from(value: ValueError) -> Self {
        Self::Field(value)
    }
}
