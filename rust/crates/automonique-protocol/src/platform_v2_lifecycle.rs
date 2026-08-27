// SPDX-License-Identifier: Elastic-2.0

//! Platform v2 work-context lifecycle requests and checked review artifacts.
//!
//! Callers describe intent; they never supply a new authoritative identity or
//! a replacement [`WorkContextRecord`]. A serving authority issues an identity,
//! loads current records and parents, and then creates a [`MutationPreview`].
//! The preview is the exact object an approval and submission bind.
//!
//! This module performs no authentication, policy lookup, persistence, clock,
//! random-number generation, filesystem access, or external effect. In
//! particular, an [`Actor`] value is a claim until a transport binds it to an
//! authenticated principal. The checked values make drift and authority
//! widening unrepresentable once authoritative inputs have been supplied.

use core::fmt;
use core::str::FromStr;

use crate::digest::{DigestError, Sha256, Sha256Digest};
use crate::identity::Actor;
use crate::platform::{IdempotencyKey, ReceiptId, ReceiptOutcome, ResourceAuthority};
use crate::platform_v2::{
    CheckoutKind, HostSetupKind, ProjectId, WorkContextAttributes, WorkContextIdentity,
    WorkContextKind, WorkContextLabel, WorkContextLifecycle, WorkContextRecord,
    WorkContextRelation, WorkContextRelationKind,
};
use crate::primitives::{BoundedString, EpochMillis, IdDomain, OpaqueId, Revision, ValueError};

pub const MAX_AUTHORITY_GRANTS_PER_AXIS: usize = 64;
pub const MAX_REGISTRY_SELECTOR_BYTES: usize = 128;
pub const MAX_MUTATION_EXPLANATION_BYTES: usize = 512;
pub const MAX_MUTATION_CANONICAL_BYTES: usize = 256 * 1024;

macro_rules! lifecycle_id_domain {
    ($domain:ident, $name:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $domain;
        impl IdDomain for $domain {}
        pub type $name = OpaqueId<$domain, { crate::platform_v2::MAX_WORK_CONTEXT_FIELD_BYTES }>;
    };
}

lifecycle_id_domain!(MutationPreviewIdDomain, MutationPreviewId);
lifecycle_id_domain!(MutationApprovalIdDomain, MutationApprovalId);

pub type MutationExplanation = BoundedString<MAX_MUTATION_EXPLANATION_BYTES>;

/// An opaque grant or private-registry selector that cannot carry a host path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityGrantId(String);

impl AuthorityGrantId {
    pub fn new(value: impl Into<String>) -> Result<Self, LifecycleError> {
        let value = value.into();
        validate_safe_token(&value, "authority_grant")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A private registry handle. Resolution may yield a path or endpoint, but
/// this wire-safe value never contains either.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkContextRegistrySelector(String);

impl WorkContextRegistrySelector {
    pub fn new(value: impl Into<String>) -> Result<Self, LifecycleError> {
        let value = value.into();
        validate_safe_token(&value, "registry_selector")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_safe_token(value: &str, field: &'static str) -> Result<(), LifecycleError> {
    if value.is_empty() || value.len() > MAX_REGISTRY_SELECTOR_BYTES {
        return Err(LifecycleError::Field { field });
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        || matches!(value.as_bytes().first(), Some(b'.' | b':' | b'-'))
        || value.contains("..")
    {
        return Err(LifecycleError::UnsafeToken { field });
    }
    Ok(())
}

/// Explicit attempt authority. Each axis is canonical, bounded, and opaque;
/// filesystem grants name registry policy and never contain a path.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkContextAuthority {
    filesystem: Vec<AuthorityGrantId>,
    credentials: Vec<AuthorityGrantId>,
    network: Vec<AuthorityGrantId>,
    tools: Vec<AuthorityGrantId>,
    providers: Vec<AuthorityGrantId>,
    models: Vec<AuthorityGrantId>,
}

impl WorkContextAuthority {
    pub const EMPTY: Self = Self {
        filesystem: Vec::new(),
        credentials: Vec::new(),
        network: Vec::new(),
        tools: Vec::new(),
        providers: Vec::new(),
        models: Vec::new(),
    };

    pub fn new(
        filesystem: Vec<AuthorityGrantId>,
        credentials: Vec<AuthorityGrantId>,
        network: Vec<AuthorityGrantId>,
        tools: Vec<AuthorityGrantId>,
        providers: Vec<AuthorityGrantId>,
        models: Vec<AuthorityGrantId>,
    ) -> Result<Self, LifecycleError> {
        for (field, grants) in [
            ("filesystem", &filesystem),
            ("credentials", &credentials),
            ("network", &network),
            ("tools", &tools),
            ("providers", &providers),
            ("models", &models),
        ] {
            if grants.len() > MAX_AUTHORITY_GRANTS_PER_AXIS {
                return Err(LifecycleError::AuthorityLimit { field });
            }
            if grants.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(LifecycleError::AuthorityOrder { field });
            }
        }
        Ok(Self {
            filesystem,
            credentials,
            network,
            tools,
            providers,
            models,
        })
    }

    #[must_use]
    pub fn filesystem(&self) -> &[AuthorityGrantId] {
        &self.filesystem
    }
    #[must_use]
    pub fn credentials(&self) -> &[AuthorityGrantId] {
        &self.credentials
    }
    #[must_use]
    pub fn network(&self) -> &[AuthorityGrantId] {
        &self.network
    }
    #[must_use]
    pub fn tools(&self) -> &[AuthorityGrantId] {
        &self.tools
    }
    #[must_use]
    pub fn providers(&self) -> &[AuthorityGrantId] {
        &self.providers
    }
    #[must_use]
    pub fn models(&self) -> &[AuthorityGrantId] {
        &self.models
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.filesystem.is_empty()
            && self.credentials.is_empty()
            && self.network.is_empty()
            && self.tools.is_empty()
            && self.providers.is_empty()
            && self.models.is_empty()
    }

    #[must_use]
    pub fn is_subset_of(&self, ceiling: &Self) -> bool {
        is_subset(&self.filesystem, &ceiling.filesystem)
            && is_subset(&self.credentials, &ceiling.credentials)
            && is_subset(&self.network, &ceiling.network)
            && is_subset(&self.tools, &ceiling.tools)
            && is_subset(&self.providers, &ceiling.providers)
            && is_subset(&self.models, &ceiling.models)
    }
}

fn is_subset(requested: &[AuthorityGrantId], ceiling: &[AuthorityGrantId]) -> bool {
    requested
        .iter()
        .all(|grant| ceiling.binary_search(grant).is_ok())
}

/// Exact revision of an existing record or v1 relation target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedWorkContext {
    identity: WorkContextIdentity,
    revision: Revision,
}

impl ExpectedWorkContext {
    #[must_use]
    pub const fn new(identity: WorkContextIdentity, revision: Revision) -> Self {
        Self { identity, revision }
    }
    #[must_use]
    pub const fn identity(&self) -> &WorkContextIdentity {
        &self.identity
    }
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

/// Whether an authority-qualified external relation target was resolved while
/// the server assembled a mutation preview.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ExternalParentResolution {
    Available,
    Unavailable,
}

impl ExternalParentResolution {
    pub const ALL: [Self; 2] = [Self::Available, Self::Unavailable];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
        }
    }

    pub fn parse(value: &str) -> Result<Self, LifecycleError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or(LifecycleError::UnknownExternalResolution)
    }
}

/// An authoritative parent observation captured by the server when it builds
/// a preview. Work-context parents carry their entire record. Only repository
/// relations may use the external form, which preserves the exact v1 identity,
/// revision, resolution result, and optional informational project owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolvedParentSnapshot {
    WorkContext {
        record: WorkContextRecord,
    },
    External {
        identity: WorkContextIdentity,
        revision: Revision,
        resolution: ExternalParentResolution,
        owning_project: Option<ProjectId>,
    },
}

impl ResolvedParentSnapshot {
    #[must_use]
    pub const fn identity(&self) -> &WorkContextIdentity {
        match self {
            Self::WorkContext { record } => record.identity(),
            Self::External { identity, .. } => identity,
        }
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        match self {
            Self::WorkContext { record } => record.revision(),
            Self::External { revision, .. } => *revision,
        }
    }
}

macro_rules! expected_kind {
    ($value:expr, $kind:ident) => {
        if $value.identity().kind() != crate::platform_v2::WorkContextTargetKind::$kind {
            return Err(LifecycleError::TargetKindInvalid);
        }
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateProjectIntent {
    label: WorkContextLabel,
    repositories: Vec<ExpectedWorkContext>,
}

impl CreateProjectIntent {
    pub fn new(
        label: WorkContextLabel,
        repositories: Vec<ExpectedWorkContext>,
    ) -> Result<Self, LifecycleError> {
        if repositories.len() > crate::platform_v2::MAX_WORK_CONTEXT_RELATIONS {
            return Err(LifecycleError::RelationLimit);
        }
        for repository in &repositories {
            expected_kind!(repository, Repository);
        }
        if repositories
            .windows(2)
            .any(|pair| pair[0].identity() >= pair[1].identity())
        {
            return Err(LifecycleError::RelationOrder);
        }
        Ok(Self {
            label,
            repositories,
        })
    }
    #[must_use]
    pub const fn label(&self) -> &WorkContextLabel {
        &self.label
    }
    #[must_use]
    pub fn repositories(&self) -> &[ExpectedWorkContext] {
        &self.repositories
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateHostSetupIntent {
    label: WorkContextLabel,
    project: ExpectedWorkContext,
    setup_kind: HostSetupKind,
    registry: WorkContextRegistrySelector,
}

impl CreateHostSetupIntent {
    pub fn new(
        label: WorkContextLabel,
        project: ExpectedWorkContext,
        setup_kind: HostSetupKind,
        registry: WorkContextRegistrySelector,
    ) -> Result<Self, LifecycleError> {
        expected_kind!(project, Project);
        Ok(Self {
            label,
            project,
            setup_kind,
            registry,
        })
    }
    #[must_use]
    pub const fn label(&self) -> &WorkContextLabel {
        &self.label
    }
    #[must_use]
    pub const fn project(&self) -> &ExpectedWorkContext {
        &self.project
    }
    #[must_use]
    pub const fn setup_kind(&self) -> HostSetupKind {
        self.setup_kind
    }
    #[must_use]
    pub const fn registry(&self) -> &WorkContextRegistrySelector {
        &self.registry
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateCheckoutIntent {
    label: WorkContextLabel,
    project: ExpectedWorkContext,
    host_setup: ExpectedWorkContext,
    repository: ExpectedWorkContext,
    checkout_kind: CheckoutKind,
    registry: WorkContextRegistrySelector,
}

impl CreateCheckoutIntent {
    pub fn new(
        label: WorkContextLabel,
        project: ExpectedWorkContext,
        host_setup: ExpectedWorkContext,
        repository: ExpectedWorkContext,
        checkout_kind: CheckoutKind,
        registry: WorkContextRegistrySelector,
    ) -> Result<Self, LifecycleError> {
        expected_kind!(project, Project);
        expected_kind!(host_setup, HostSetup);
        expected_kind!(repository, Repository);
        Ok(Self {
            label,
            project,
            host_setup,
            repository,
            checkout_kind,
            registry,
        })
    }
    #[must_use]
    pub const fn label(&self) -> &WorkContextLabel {
        &self.label
    }
    #[must_use]
    pub const fn project(&self) -> &ExpectedWorkContext {
        &self.project
    }
    #[must_use]
    pub const fn host_setup(&self) -> &ExpectedWorkContext {
        &self.host_setup
    }
    #[must_use]
    pub const fn repository(&self) -> &ExpectedWorkContext {
        &self.repository
    }
    #[must_use]
    pub const fn checkout_kind(&self) -> CheckoutKind {
        self.checkout_kind
    }
    #[must_use]
    pub const fn registry(&self) -> &WorkContextRegistrySelector {
        &self.registry
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateUserWorkspaceIntent {
    label: WorkContextLabel,
    project: ExpectedWorkContext,
    checkout: ExpectedWorkContext,
}

impl CreateUserWorkspaceIntent {
    pub fn new(
        label: WorkContextLabel,
        project: ExpectedWorkContext,
        checkout: ExpectedWorkContext,
    ) -> Result<Self, LifecycleError> {
        expected_kind!(project, Project);
        expected_kind!(checkout, Checkout);
        Ok(Self {
            label,
            project,
            checkout,
        })
    }
    #[must_use]
    pub const fn label(&self) -> &WorkContextLabel {
        &self.label
    }
    #[must_use]
    pub const fn project(&self) -> &ExpectedWorkContext {
        &self.project
    }
    #[must_use]
    pub const fn checkout(&self) -> &ExpectedWorkContext {
        &self.checkout
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateAttemptWorkspaceIntent {
    label: WorkContextLabel,
    user_workspace: ExpectedWorkContext,
    requested_authority: WorkContextAuthority,
}

impl CreateAttemptWorkspaceIntent {
    pub fn new(
        label: WorkContextLabel,
        user_workspace: ExpectedWorkContext,
        requested_authority: WorkContextAuthority,
    ) -> Result<Self, LifecycleError> {
        expected_kind!(user_workspace, UserWorkspace);
        Ok(Self {
            label,
            user_workspace,
            requested_authority,
        })
    }
    #[must_use]
    pub const fn label(&self) -> &WorkContextLabel {
        &self.label
    }
    #[must_use]
    pub const fn user_workspace(&self) -> &ExpectedWorkContext {
        &self.user_workspace
    }
    #[must_use]
    pub const fn requested_authority(&self) -> &WorkContextAuthority {
        &self.requested_authority
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeAttemptWorkspaceIntent {
    target: ExpectedWorkContext,
    requested_authority: WorkContextAuthority,
}

impl ResumeAttemptWorkspaceIntent {
    pub fn new(
        target: ExpectedWorkContext,
        requested_authority: WorkContextAuthority,
    ) -> Result<Self, LifecycleError> {
        expected_kind!(target, AttemptWorkspace);
        Ok(Self {
            target,
            requested_authority,
        })
    }
    #[must_use]
    pub const fn target(&self) -> &ExpectedWorkContext {
        &self.target
    }
    #[must_use]
    pub const fn requested_authority(&self) -> &WorkContextAuthority {
        &self.requested_authority
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeSessionIntent {
    target: ExpectedWorkContext,
    requested_authority: WorkContextAuthority,
}

impl ResumeSessionIntent {
    pub fn new(
        target: ExpectedWorkContext,
        requested_authority: WorkContextAuthority,
    ) -> Result<Self, LifecycleError> {
        expected_kind!(target, Session);
        Ok(Self {
            target,
            requested_authority,
        })
    }
    #[must_use]
    pub const fn target(&self) -> &ExpectedWorkContext {
        &self.target
    }
    #[must_use]
    pub const fn requested_authority(&self) -> &WorkContextAuthority {
        &self.requested_authority
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveIntent {
    target: ExpectedWorkContext,
}

impl ArchiveIntent {
    pub fn new(target: ExpectedWorkContext) -> Result<Self, LifecycleError> {
        if !matches!(
            target.identity().kind(),
            crate::platform_v2::WorkContextTargetKind::Project
                | crate::platform_v2::WorkContextTargetKind::HostSetup
                | crate::platform_v2::WorkContextTargetKind::Checkout
                | crate::platform_v2::WorkContextTargetKind::UserWorkspace
        ) {
            return Err(LifecycleError::TargetKindInvalid);
        }
        Ok(Self { target })
    }
    #[must_use]
    pub const fn target(&self) -> &ExpectedWorkContext {
        &self.target
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkContextMutationIntent {
    CreateProject(CreateProjectIntent),
    CreateHostSetup(CreateHostSetupIntent),
    CreateCheckout(CreateCheckoutIntent),
    CreateUserWorkspace(CreateUserWorkspaceIntent),
    CreateAttemptWorkspace(CreateAttemptWorkspaceIntent),
    ResumeAttemptWorkspace(ResumeAttemptWorkspaceIntent),
    ResumeSession(ResumeSessionIntent),
    ArchiveProject(ArchiveIntent),
    ArchiveHostSetup(ArchiveIntent),
    ArchiveCheckout(ArchiveIntent),
    ArchiveUserWorkspace(ArchiveIntent),
}

impl WorkContextMutationIntent {
    pub fn validate(&self) -> Result<(), LifecycleError> {
        let expected = match self {
            Self::ArchiveProject(_) => Some(crate::platform_v2::WorkContextTargetKind::Project),
            Self::ArchiveHostSetup(_) => Some(crate::platform_v2::WorkContextTargetKind::HostSetup),
            Self::ArchiveCheckout(_) => Some(crate::platform_v2::WorkContextTargetKind::Checkout),
            Self::ArchiveUserWorkspace(_) => {
                Some(crate::platform_v2::WorkContextTargetKind::UserWorkspace)
            }
            _ => None,
        };
        if let Some(expected) = expected
            && self
                .expected_target()
                .is_none_or(|target| target.identity().kind() != expected)
        {
            return Err(LifecycleError::TargetKindInvalid);
        }
        Ok(())
    }

    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::CreateProject(_) => "create_project",
            Self::CreateHostSetup(_) => "create_host_setup",
            Self::CreateCheckout(_) => "create_checkout",
            Self::CreateUserWorkspace(_) => "create_user_workspace",
            Self::CreateAttemptWorkspace(_) => "create_attempt_workspace",
            Self::ResumeAttemptWorkspace(_) => "resume_attempt_workspace",
            Self::ResumeSession(_) => "resume_session",
            Self::ArchiveProject(_) => "archive_project",
            Self::ArchiveHostSetup(_) => "archive_host_setup",
            Self::ArchiveCheckout(_) => "archive_checkout",
            Self::ArchiveUserWorkspace(_) => "archive_user_workspace",
        }
    }

    #[must_use]
    pub const fn is_create(&self) -> bool {
        matches!(
            self,
            Self::CreateProject(_)
                | Self::CreateHostSetup(_)
                | Self::CreateCheckout(_)
                | Self::CreateUserWorkspace(_)
                | Self::CreateAttemptWorkspace(_)
        )
    }

    #[must_use]
    pub const fn requested_authority(&self) -> Option<&WorkContextAuthority> {
        match self {
            Self::CreateAttemptWorkspace(value) => Some(value.requested_authority()),
            Self::ResumeAttemptWorkspace(value) => Some(value.requested_authority()),
            Self::ResumeSession(value) => Some(value.requested_authority()),
            _ => None,
        }
    }

    #[must_use]
    pub const fn expected_target(&self) -> Option<&ExpectedWorkContext> {
        match self {
            Self::ResumeAttemptWorkspace(value) => Some(value.target()),
            Self::ResumeSession(value) => Some(value.target()),
            Self::ArchiveProject(value)
            | Self::ArchiveHostSetup(value)
            | Self::ArchiveCheckout(value)
            | Self::ArchiveUserWorkspace(value) => Some(value.target()),
            _ => None,
        }
    }

    fn resulting_record(
        &self,
        current: Option<&WorkContextRecord>,
        issued: Option<WorkContextIdentity>,
    ) -> Result<WorkContextRecord, LifecycleError> {
        let relation =
            |kind, target| WorkContextRelation::new(kind, target).map_err(LifecycleError::Context);
        let create = |identity, lifecycle, label, attributes, relations| {
            WorkContextRecord::new(
                identity,
                Revision::FIRST,
                lifecycle,
                label,
                attributes,
                relations,
            )
            .map_err(LifecycleError::Context)
        };
        match self {
            Self::CreateProject(value) => create(
                issued_for(issued, WorkContextKind::Project)?,
                WorkContextLifecycle::Active,
                value.label.clone(),
                WorkContextAttributes::EMPTY,
                value
                    .repositories
                    .iter()
                    .map(|repository| {
                        relation(
                            WorkContextRelationKind::ProjectRepository,
                            repository.identity.clone(),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Self::CreateHostSetup(value) => create(
                issued_for(issued, WorkContextKind::HostSetup)?,
                WorkContextLifecycle::Active,
                value.label.clone(),
                WorkContextAttributes::host_setup(value.setup_kind),
                vec![relation(
                    WorkContextRelationKind::HostSetupProject,
                    value.project.identity.clone(),
                )?],
            ),
            Self::CreateCheckout(value) => create(
                issued_for(issued, WorkContextKind::Checkout)?,
                WorkContextLifecycle::Active,
                value.label.clone(),
                WorkContextAttributes::checkout(value.checkout_kind),
                vec![
                    relation(
                        WorkContextRelationKind::CheckoutProject,
                        value.project.identity.clone(),
                    )?,
                    relation(
                        WorkContextRelationKind::CheckoutHostSetup,
                        value.host_setup.identity.clone(),
                    )?,
                    relation(
                        WorkContextRelationKind::CheckoutRepository,
                        value.repository.identity.clone(),
                    )?,
                ],
            ),
            Self::CreateUserWorkspace(value) => create(
                issued_for(issued, WorkContextKind::UserWorkspace)?,
                WorkContextLifecycle::Active,
                value.label.clone(),
                WorkContextAttributes::EMPTY,
                vec![
                    relation(
                        WorkContextRelationKind::UserWorkspaceProject,
                        value.project.identity.clone(),
                    )?,
                    relation(
                        WorkContextRelationKind::UserWorkspaceCheckout,
                        value.checkout.identity.clone(),
                    )?,
                ],
            ),
            Self::CreateAttemptWorkspace(value) => create(
                issued_for(issued, WorkContextKind::AttemptWorkspace)?,
                WorkContextLifecycle::Preparing,
                value.label.clone(),
                WorkContextAttributes::EMPTY,
                vec![relation(
                    WorkContextRelationKind::AttemptUserWorkspace,
                    value.user_workspace.identity.clone(),
                )?],
            ),
            Self::ResumeAttemptWorkspace(_) => transition(
                current_for(self, current)?,
                WorkContextLifecycle::Hibernated,
                WorkContextLifecycle::Running,
            ),
            Self::ResumeSession(_) => transition(
                current_for(self, current)?,
                WorkContextLifecycle::Hibernated,
                WorkContextLifecycle::Active,
            ),
            Self::ArchiveProject(_)
            | Self::ArchiveHostSetup(_)
            | Self::ArchiveCheckout(_)
            | Self::ArchiveUserWorkspace(_) => transition(
                current_for(self, current)?,
                WorkContextLifecycle::Active,
                WorkContextLifecycle::Archived,
            ),
        }
    }
}

fn issued_for(
    issued: Option<WorkContextIdentity>,
    kind: WorkContextKind,
) -> Result<WorkContextIdentity, LifecycleError> {
    let issued = issued.ok_or(LifecycleError::IssuedIdentityRequired)?;
    if issued.kind() != kind.into() {
        return Err(LifecycleError::IssuedIdentityKindInvalid);
    }
    Ok(issued)
}

fn current_for<'a>(
    intent: &WorkContextMutationIntent,
    current: Option<&'a WorkContextRecord>,
) -> Result<&'a WorkContextRecord, LifecycleError> {
    let current = current.ok_or(LifecycleError::CurrentRecordRequired)?;
    let expected = intent
        .expected_target()
        .ok_or(LifecycleError::CurrentRecordUnexpected)?;
    if current.identity() != expected.identity() {
        return Err(LifecycleError::TargetMismatch);
    }
    if current.revision() != expected.revision() {
        return Err(LifecycleError::ExpectedRevisionMismatch);
    }
    Ok(current)
}

fn transition(
    current: &WorkContextRecord,
    from: WorkContextLifecycle,
    to: WorkContextLifecycle,
) -> Result<WorkContextRecord, LifecycleError> {
    if current.lifecycle() != from {
        return Err(LifecycleError::LifecycleTransitionInvalid);
    }
    let revision = current
        .revision()
        .checked_next()
        .map_err(|_| LifecycleError::RevisionOverflow)?;
    WorkContextRecord::new(
        current.identity().clone(),
        revision,
        to,
        current.label().clone(),
        current.attributes(),
        current.relations().to_vec(),
    )
    .map_err(LifecycleError::Context)
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkContextRequestDigest(Sha256Digest);

impl WorkContextRequestDigest {
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.0
    }
}

/// SHA-256 of the exact canonical preview document. This is distinct from the
/// proposal request digest because it also binds server-resolved parents,
/// current/resulting records, authority ceilings, policy, and expiry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MutationPreviewDigest(Sha256Digest);

impl MutationPreviewDigest {
    #[must_use]
    pub const fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }
    #[must_use]
    pub const fn digest(self) -> Sha256Digest {
        self.0
    }
}

impl fmt::Display for MutationPreviewDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for MutationPreviewDigest {
    type Err = DigestError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse().map(Self)
    }
}

impl fmt::Display for WorkContextRequestDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for WorkContextRequestDigest {
    type Err = DigestError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse().map(Self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkContextMutationProposal {
    actor: Actor,
    authority: ResourceAuthority,
    actor_authority: WorkContextAuthority,
    idempotency_key: IdempotencyKey,
    request_digest: WorkContextRequestDigest,
    intent: WorkContextMutationIntent,
}

impl WorkContextMutationProposal {
    pub fn new(
        actor: Actor,
        authority: ResourceAuthority,
        actor_authority: WorkContextAuthority,
        idempotency_key: IdempotencyKey,
        intent: WorkContextMutationIntent,
    ) -> Result<Self, LifecycleError> {
        intent.validate()?;
        let request_digest = digest_proposal(
            &actor,
            authority,
            &actor_authority,
            &idempotency_key,
            &intent,
        );
        Ok(Self {
            actor,
            authority,
            actor_authority,
            idempotency_key,
            request_digest,
            intent,
        })
    }
    #[must_use]
    pub const fn actor(&self) -> &Actor {
        &self.actor
    }
    #[must_use]
    pub const fn authority(&self) -> ResourceAuthority {
        self.authority
    }
    #[must_use]
    pub const fn actor_authority(&self) -> &WorkContextAuthority {
        &self.actor_authority
    }
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
    #[must_use]
    pub const fn request_digest(&self) -> WorkContextRequestDigest {
        self.request_digest
    }
    #[must_use]
    pub const fn intent(&self) -> &WorkContextMutationIntent {
        &self.intent
    }
}

fn digest_proposal(
    actor: &Actor,
    authority: ResourceAuthority,
    grants: &WorkContextAuthority,
    key: &IdempotencyKey,
    intent: &WorkContextMutationIntent,
) -> WorkContextRequestDigest {
    let mut material = DigestMaterial::default();
    material.text("automonique.platform/v2/work-context-mutation-request/v1");
    material.text(actor.tenant());
    material.text(actor.id());
    material.text(authority.as_str());
    material.authority(grants);
    material.text(key.as_str());
    material.intent(intent);
    WorkContextRequestDigest(Sha256::digest(&material.0))
}

#[derive(Default)]
struct DigestMaterial(Vec<u8>);

impl DigestMaterial {
    fn text(&mut self, value: &str) {
        self.0
            .extend_from_slice(&(value.len() as u64).to_be_bytes());
        self.0.extend_from_slice(value.as_bytes());
    }
    fn number(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    fn identity(&mut self, identity: &WorkContextIdentity) {
        self.text(identity.kind().as_str());
        if let Some(coordinate) = identity.v1_coordinate() {
            self.text(coordinate.authority.as_str());
            self.text(coordinate.kind.as_str());
        }
        self.text(identity.id());
    }
    fn expected(&mut self, value: &ExpectedWorkContext) {
        self.identity(value.identity());
        self.number(value.revision().get());
    }
    fn authority(&mut self, authority: &WorkContextAuthority) {
        for grants in [
            authority.filesystem(),
            authority.credentials(),
            authority.network(),
            authority.tools(),
            authority.providers(),
            authority.models(),
        ] {
            self.number(grants.len() as u64);
            for grant in grants {
                self.text(grant.as_str());
            }
        }
    }
    fn intent(&mut self, intent: &WorkContextMutationIntent) {
        self.text(intent.kind());
        match intent {
            WorkContextMutationIntent::CreateProject(value) => {
                self.text(value.label().as_str());
                self.number(value.repositories().len() as u64);
                for item in value.repositories() {
                    self.expected(item);
                }
            }
            WorkContextMutationIntent::CreateHostSetup(value) => {
                self.text(value.label().as_str());
                self.expected(value.project());
                self.text(value.setup_kind().as_str());
                self.text(value.registry().as_str());
            }
            WorkContextMutationIntent::CreateCheckout(value) => {
                self.text(value.label().as_str());
                self.expected(value.project());
                self.expected(value.host_setup());
                self.expected(value.repository());
                self.text(value.checkout_kind().as_str());
                self.text(value.registry().as_str());
            }
            WorkContextMutationIntent::CreateUserWorkspace(value) => {
                self.text(value.label().as_str());
                self.expected(value.project());
                self.expected(value.checkout());
            }
            WorkContextMutationIntent::CreateAttemptWorkspace(value) => {
                self.text(value.label().as_str());
                self.expected(value.user_workspace());
                self.authority(value.requested_authority());
            }
            WorkContextMutationIntent::ResumeAttemptWorkspace(value) => {
                self.expected(value.target());
                self.authority(value.requested_authority());
            }
            WorkContextMutationIntent::ResumeSession(value) => {
                self.expected(value.target());
                self.authority(value.requested_authority());
            }
            WorkContextMutationIntent::ArchiveProject(value)
            | WorkContextMutationIntent::ArchiveHostSetup(value)
            | WorkContextMutationIntent::ArchiveCheckout(value)
            | WorkContextMutationIntent::ArchiveUserWorkspace(value) => {
                self.expected(value.target())
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationPreviewRef {
    id: MutationPreviewId,
    revision: Revision,
}
impl MutationPreviewRef {
    #[must_use]
    pub const fn new(id: MutationPreviewId, revision: Revision) -> Self {
        Self { id, revision }
    }
    #[must_use]
    pub const fn id(&self) -> &MutationPreviewId {
        &self.id
    }
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MutationApprovalRequirement {
    NotRequired,
    Required,
}
impl MutationApprovalRequirement {
    pub const ALL: [Self; 2] = [Self::NotRequired, Self::Required];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::Required => "required",
        }
    }
    pub fn parse(value: &str) -> Result<Self, LifecycleError> {
        Self::ALL
            .into_iter()
            .find(|item| item.as_str() == value)
            .ok_or(LifecycleError::UnknownApprovalRequirement)
    }
}

fn parent_expectations(intent: &WorkContextMutationIntent) -> Vec<&ExpectedWorkContext> {
    match intent {
        WorkContextMutationIntent::CreateProject(value) => value.repositories().iter().collect(),
        WorkContextMutationIntent::CreateHostSetup(value) => vec![value.project()],
        WorkContextMutationIntent::CreateCheckout(value) => {
            vec![value.project(), value.host_setup(), value.repository()]
        }
        WorkContextMutationIntent::CreateUserWorkspace(value) => {
            vec![value.project(), value.checkout()]
        }
        WorkContextMutationIntent::CreateAttemptWorkspace(value) => vec![value.user_workspace()],
        WorkContextMutationIntent::ResumeAttemptWorkspace(_)
        | WorkContextMutationIntent::ResumeSession(_)
        | WorkContextMutationIntent::ArchiveProject(_)
        | WorkContextMutationIntent::ArchiveHostSetup(_)
        | WorkContextMutationIntent::ArchiveCheckout(_)
        | WorkContextMutationIntent::ArchiveUserWorkspace(_) => Vec::new(),
    }
}

fn validate_parent_snapshots(
    intent: &WorkContextMutationIntent,
    snapshots: &[ResolvedParentSnapshot],
) -> Result<(), LifecycleError> {
    let expected = parent_expectations(intent);
    if expected.len() != snapshots.len() {
        return Err(LifecycleError::ParentSnapshotMismatch);
    }
    for (expected, snapshot) in expected.into_iter().zip(snapshots) {
        if expected.identity() != snapshot.identity() || expected.revision() != snapshot.revision()
        {
            return Err(LifecycleError::ParentSnapshotMismatch);
        }
        match snapshot {
            ResolvedParentSnapshot::WorkContext { record } => {
                if matches!(
                    record.identity().kind(),
                    crate::platform_v2::WorkContextTargetKind::Repository
                        | crate::platform_v2::WorkContextTargetKind::PlatformSession
                ) {
                    return Err(LifecycleError::ParentSnapshotMismatch);
                }
            }
            ResolvedParentSnapshot::External {
                identity,
                resolution,
                owning_project,
                ..
            } => {
                if identity.kind() != crate::platform_v2::WorkContextTargetKind::Repository {
                    return Err(LifecycleError::ParentSnapshotMismatch);
                }
                if *resolution == ExternalParentResolution::Unavailable {
                    return Err(LifecycleError::ParentUnavailable);
                }
                if let WorkContextMutationIntent::CreateCheckout(value) = intent {
                    let WorkContextIdentity::Project(selected_project) = value.project().identity()
                    else {
                        return Err(LifecycleError::ParentSnapshotMismatch);
                    };
                    if owning_project
                        .as_ref()
                        .is_some_and(|owner| owner != selected_project)
                    {
                        return Err(LifecycleError::ParentProjectMismatch);
                    }
                }
            }
        }
    }
    let work_context = |index: usize| match snapshots.get(index) {
        Some(ResolvedParentSnapshot::WorkContext { record }) => Ok(record),
        _ => Err(LifecycleError::ParentSnapshotMismatch),
    };
    let active = |record: &WorkContextRecord| {
        if record.lifecycle() == WorkContextLifecycle::Active {
            Ok(())
        } else {
            Err(LifecycleError::ParentLifecycleInvalid)
        }
    };
    let has_relation = |record: &WorkContextRecord,
                        kind: WorkContextRelationKind,
                        target: &WorkContextIdentity| {
        record
            .relations()
            .iter()
            .any(|relation| relation.kind() == kind && relation.target() == target)
    };
    match intent {
        WorkContextMutationIntent::CreateProject(_) => {}
        WorkContextMutationIntent::CreateHostSetup(_) => active(work_context(0)?)?,
        WorkContextMutationIntent::CreateCheckout(value) => {
            let project = work_context(0)?;
            let host_setup = work_context(1)?;
            active(project)?;
            active(host_setup)?;
            if !has_relation(
                host_setup,
                WorkContextRelationKind::HostSetupProject,
                value.project().identity(),
            ) || !has_relation(
                project,
                WorkContextRelationKind::ProjectRepository,
                value.repository().identity(),
            ) {
                return Err(LifecycleError::ParentProjectMismatch);
            }
        }
        WorkContextMutationIntent::CreateUserWorkspace(value) => {
            let project = work_context(0)?;
            let checkout = work_context(1)?;
            active(project)?;
            active(checkout)?;
            if !has_relation(
                checkout,
                WorkContextRelationKind::CheckoutProject,
                value.project().identity(),
            ) {
                return Err(LifecycleError::ParentProjectMismatch);
            }
        }
        WorkContextMutationIntent::CreateAttemptWorkspace(_) => active(work_context(0)?)?,
        WorkContextMutationIntent::ResumeAttemptWorkspace(_)
        | WorkContextMutationIntent::ResumeSession(_)
        | WorkContextMutationIntent::ArchiveProject(_)
        | WorkContextMutationIntent::ArchiveHostSetup(_)
        | WorkContextMutationIntent::ArchiveCheckout(_)
        | WorkContextMutationIntent::ArchiveUserWorkspace(_) => {}
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationPreview {
    preview: MutationPreviewRef,
    proposal: WorkContextMutationProposal,
    current: Option<WorkContextRecord>,
    parent_snapshots: Vec<ResolvedParentSnapshot>,
    resulting: WorkContextRecord,
    inherited_authority: WorkContextAuthority,
    effective_authority: WorkContextAuthority,
    approval: MutationApprovalRequirement,
    issued_at: EpochMillis,
    expires_at: EpochMillis,
}

impl MutationPreview {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        preview: MutationPreviewRef,
        proposal: WorkContextMutationProposal,
        current: Option<WorkContextRecord>,
        issued_identity: Option<WorkContextIdentity>,
        parent_snapshots: Vec<ResolvedParentSnapshot>,
        inherited_authority: WorkContextAuthority,
        effective_authority: WorkContextAuthority,
        approval: MutationApprovalRequirement,
        issued_at: EpochMillis,
        expires_at: EpochMillis,
    ) -> Result<Self, LifecycleError> {
        if issued_at.as_millis() < 0 || expires_at.as_millis() <= issued_at.as_millis() {
            return Err(LifecycleError::ExpiryInvalid);
        }
        if proposal.intent().is_create() != issued_identity.is_some()
            || proposal.intent().is_create() == current.is_some()
        {
            return Err(LifecycleError::CurrentRecordMismatch);
        }
        validate_parent_snapshots(proposal.intent(), &parent_snapshots)?;
        match proposal.intent().requested_authority() {
            Some(requested) => {
                if requested != &effective_authority
                    || !effective_authority.is_subset_of(proposal.actor_authority())
                    || !effective_authority.is_subset_of(&inherited_authority)
                {
                    return Err(LifecycleError::AuthorityWidening);
                }
            }
            None if !effective_authority.is_empty() || !inherited_authority.is_empty() => {
                return Err(LifecycleError::AuthorityUnexpected);
            }
            None => {}
        }
        let resulting = proposal
            .intent()
            .resulting_record(current.as_ref(), issued_identity)?;
        Ok(Self {
            preview,
            proposal,
            current,
            parent_snapshots,
            resulting,
            inherited_authority,
            effective_authority,
            approval,
            issued_at,
            expires_at,
        })
    }
    #[must_use]
    pub const fn preview(&self) -> &MutationPreviewRef {
        &self.preview
    }
    #[must_use]
    pub const fn proposal(&self) -> &WorkContextMutationProposal {
        &self.proposal
    }
    #[must_use]
    pub const fn current(&self) -> Option<&WorkContextRecord> {
        self.current.as_ref()
    }
    #[must_use]
    pub fn parent_snapshots(&self) -> &[ResolvedParentSnapshot] {
        &self.parent_snapshots
    }
    #[must_use]
    pub const fn resulting(&self) -> &WorkContextRecord {
        &self.resulting
    }
    #[must_use]
    pub const fn inherited_authority(&self) -> &WorkContextAuthority {
        &self.inherited_authority
    }
    #[must_use]
    pub const fn effective_authority(&self) -> &WorkContextAuthority {
        &self.effective_authority
    }
    #[must_use]
    pub const fn approval(&self) -> MutationApprovalRequirement {
        self.approval
    }
    #[must_use]
    pub const fn issued_at(&self) -> EpochMillis {
        self.issued_at
    }
    #[must_use]
    pub const fn expires_at(&self) -> EpochMillis {
        self.expires_at
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MutationApprovalDecision {
    Granted,
    Denied,
}
impl MutationApprovalDecision {
    pub const ALL: [Self; 2] = [Self::Granted, Self::Denied];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Denied => "denied",
        }
    }
    pub fn parse(value: &str) -> Result<Self, LifecycleError> {
        Self::ALL
            .into_iter()
            .find(|item| item.as_str() == value)
            .ok_or(LifecycleError::UnknownApprovalDecision)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationApproval {
    id: MutationApprovalId,
    preview: MutationPreviewRef,
    request_digest: WorkContextRequestDigest,
    preview_digest: MutationPreviewDigest,
    idempotency_key: IdempotencyKey,
    decision: MutationApprovalDecision,
    decided_by: Actor,
    decided_at: EpochMillis,
    expires_at: EpochMillis,
}

impl MutationApproval {
    pub fn new(
        id: MutationApprovalId,
        preview: &MutationPreview,
        preview_digest: MutationPreviewDigest,
        decision: MutationApprovalDecision,
        decided_by: Actor,
        decided_at: EpochMillis,
        expires_at: EpochMillis,
    ) -> Result<Self, LifecycleError> {
        if decided_at.as_millis() < preview.issued_at().as_millis()
            || expires_at.as_millis() <= decided_at.as_millis()
            || expires_at.as_millis() > preview.expires_at().as_millis()
        {
            return Err(LifecycleError::ExpiryInvalid);
        }
        Ok(Self {
            id,
            preview: preview.preview.clone(),
            request_digest: preview.proposal.request_digest,
            preview_digest,
            idempotency_key: preview.proposal.idempotency_key.clone(),
            decision,
            decided_by,
            decided_at,
            expires_at,
        })
    }
    #[must_use]
    pub const fn id(&self) -> &MutationApprovalId {
        &self.id
    }
    #[must_use]
    pub const fn preview(&self) -> &MutationPreviewRef {
        &self.preview
    }
    #[must_use]
    pub const fn request_digest(&self) -> WorkContextRequestDigest {
        self.request_digest
    }
    #[must_use]
    pub const fn preview_digest(&self) -> MutationPreviewDigest {
        self.preview_digest
    }
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
    #[must_use]
    pub const fn decision(&self) -> MutationApprovalDecision {
        self.decision
    }
    #[must_use]
    pub const fn decided_by(&self) -> &Actor {
        &self.decided_by
    }
    #[must_use]
    pub const fn decided_at(&self) -> EpochMillis {
        self.decided_at
    }
    #[must_use]
    pub const fn expires_at(&self) -> EpochMillis {
        self.expires_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationSubmission {
    preview: MutationPreviewRef,
    request_digest: WorkContextRequestDigest,
    preview_digest: MutationPreviewDigest,
    idempotency_key: IdempotencyKey,
    approval_id: Option<MutationApprovalId>,
    submitted_at: EpochMillis,
}

impl MutationSubmission {
    pub fn new(
        preview: &MutationPreview,
        preview_digest: MutationPreviewDigest,
        approval: Option<&MutationApproval>,
        submitted_at: EpochMillis,
    ) -> Result<Self, LifecycleError> {
        if submitted_at.as_millis() < preview.issued_at().as_millis()
            || submitted_at.as_millis() >= preview.expires_at().as_millis()
        {
            return Err(LifecycleError::PreviewExpired);
        }
        let approval_id = match (preview.approval(), approval) {
            (MutationApprovalRequirement::NotRequired, None) => None,
            (MutationApprovalRequirement::NotRequired, Some(_)) => {
                return Err(LifecycleError::ApprovalUnexpected);
            }
            (MutationApprovalRequirement::Required, None) => {
                return Err(LifecycleError::ApprovalRequired);
            }
            (MutationApprovalRequirement::Required, Some(approval)) => {
                if approval.preview() != preview.preview()
                    || approval.request_digest() != preview.proposal().request_digest()
                    || approval.preview_digest() != preview_digest
                    || approval.idempotency_key() != preview.proposal().idempotency_key()
                {
                    return Err(LifecycleError::ApprovalMismatch);
                }
                if approval.decision() != MutationApprovalDecision::Granted {
                    return Err(LifecycleError::ApprovalDenied);
                }
                if submitted_at.as_millis() >= approval.expires_at().as_millis() {
                    return Err(LifecycleError::ApprovalExpired);
                }
                Some(approval.id.clone())
            }
        };
        Ok(Self {
            preview: preview.preview.clone(),
            request_digest: preview.proposal.request_digest,
            preview_digest,
            idempotency_key: preview.proposal.idempotency_key.clone(),
            approval_id,
            submitted_at,
        })
    }
    #[must_use]
    pub const fn preview(&self) -> &MutationPreviewRef {
        &self.preview
    }
    #[must_use]
    pub const fn request_digest(&self) -> WorkContextRequestDigest {
        self.request_digest
    }
    #[must_use]
    pub const fn preview_digest(&self) -> MutationPreviewDigest {
        self.preview_digest
    }
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
    #[must_use]
    pub const fn approval_id(&self) -> Option<&MutationApprovalId> {
        self.approval_id.as_ref()
    }
    #[must_use]
    pub const fn submitted_at(&self) -> EpochMillis {
        self.submitted_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationReceipt {
    id: ReceiptId,
    preview: MutationPreviewRef,
    request_digest: WorkContextRequestDigest,
    preview_digest: MutationPreviewDigest,
    idempotency_key: IdempotencyKey,
    approval_id: Option<MutationApprovalId>,
    outcome: ReceiptOutcome,
    resulting_revision: Option<Revision>,
    recorded_at: EpochMillis,
}

impl MutationReceipt {
    pub fn new(
        id: ReceiptId,
        submission: &MutationSubmission,
        preview: &MutationPreview,
        preview_digest: MutationPreviewDigest,
        outcome: ReceiptOutcome,
        recorded_at: EpochMillis,
    ) -> Result<Self, LifecycleError> {
        if submission.preview() != preview.preview()
            || submission.request_digest() != preview.proposal().request_digest()
            || submission.preview_digest() != preview_digest
            || submission.idempotency_key() != preview.proposal().idempotency_key()
        {
            return Err(LifecycleError::SubmissionMismatch);
        }
        if recorded_at.as_millis() < submission.submitted_at().as_millis() {
            return Err(LifecycleError::ReceiptTimeInvalid);
        }
        let resulting_revision = match outcome {
            ReceiptOutcome::Completed => Some(preview.resulting().revision()),
            ReceiptOutcome::Accepted | ReceiptOutcome::Rejected | ReceiptOutcome::Conflict => None,
            ReceiptOutcome::Unknown | ReceiptOutcome::ResyncRequired => {
                return Err(LifecycleError::ReceiptOutcomeInvalid);
            }
        };
        Ok(Self {
            id,
            preview: submission.preview.clone(),
            request_digest: submission.request_digest,
            preview_digest: submission.preview_digest,
            idempotency_key: submission.idempotency_key.clone(),
            approval_id: submission.approval_id.clone(),
            outcome,
            resulting_revision,
            recorded_at,
        })
    }
    #[must_use]
    pub const fn id(&self) -> &ReceiptId {
        &self.id
    }
    #[must_use]
    pub const fn preview(&self) -> &MutationPreviewRef {
        &self.preview
    }
    #[must_use]
    pub const fn request_digest(&self) -> WorkContextRequestDigest {
        self.request_digest
    }
    #[must_use]
    pub const fn preview_digest(&self) -> MutationPreviewDigest {
        self.preview_digest
    }
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
    #[must_use]
    pub const fn approval_id(&self) -> Option<&MutationApprovalId> {
        self.approval_id.as_ref()
    }
    #[must_use]
    pub const fn outcome(&self) -> ReceiptOutcome {
        self.outcome
    }
    #[must_use]
    pub const fn resulting_revision(&self) -> Option<Revision> {
        self.resulting_revision
    }
    #[must_use]
    pub const fn recorded_at(&self) -> EpochMillis {
        self.recorded_at
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MutationRefusalCategory {
    InvalidRequest,
    Unauthorized,
    AuthorityWidening,
    StaleRevision,
    Conflict,
    PreviewExpired,
    ApprovalRequired,
    ApprovalUnexpected,
    ApprovalMismatch,
    ApprovalDenied,
    ApprovalExpired,
    Unknown,
    ResyncRequired,
    Unavailable,
}
impl MutationRefusalCategory {
    pub const ALL: [Self; 14] = [
        Self::InvalidRequest,
        Self::Unauthorized,
        Self::AuthorityWidening,
        Self::StaleRevision,
        Self::Conflict,
        Self::PreviewExpired,
        Self::ApprovalRequired,
        Self::ApprovalUnexpected,
        Self::ApprovalMismatch,
        Self::ApprovalDenied,
        Self::ApprovalExpired,
        Self::Unknown,
        Self::ResyncRequired,
        Self::Unavailable,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthorized => "unauthorized",
            Self::AuthorityWidening => "authority_widening",
            Self::StaleRevision => "stale_revision",
            Self::Conflict => "conflict",
            Self::PreviewExpired => "preview_expired",
            Self::ApprovalRequired => "approval_required",
            Self::ApprovalUnexpected => "approval_unexpected",
            Self::ApprovalMismatch => "approval_mismatch",
            Self::ApprovalDenied => "approval_denied",
            Self::ApprovalExpired => "approval_expired",
            Self::Unknown => "unknown",
            Self::ResyncRequired => "resync_required",
            Self::Unavailable => "unavailable",
        }
    }
    pub fn parse(value: &str) -> Result<Self, LifecycleError> {
        Self::ALL
            .into_iter()
            .find(|item| item.as_str() == value)
            .ok_or(LifecycleError::UnknownRefusalCategory)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationRefusal {
    category: MutationRefusalCategory,
    request_digest: Option<WorkContextRequestDigest>,
    explanation: MutationExplanation,
}
impl MutationRefusal {
    #[must_use]
    pub const fn new(
        category: MutationRefusalCategory,
        request_digest: Option<WorkContextRequestDigest>,
        explanation: MutationExplanation,
    ) -> Self {
        Self {
            category,
            request_digest,
            explanation,
        }
    }
    #[must_use]
    pub const fn category(&self) -> MutationRefusalCategory {
        self.category
    }
    #[must_use]
    pub const fn request_digest(&self) -> Option<WorkContextRequestDigest> {
        self.request_digest
    }
    #[must_use]
    pub const fn explanation(&self) -> &MutationExplanation {
        &self.explanation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    Field { field: &'static str },
    UnsafeToken { field: &'static str },
    AuthorityLimit { field: &'static str },
    AuthorityOrder { field: &'static str },
    AuthorityWidening,
    AuthorityUnexpected,
    TargetKindInvalid,
    TargetMismatch,
    ExpectedRevisionMismatch,
    ParentSnapshotMismatch,
    ParentProjectMismatch,
    ParentLifecycleInvalid,
    ParentUnavailable,
    RelationLimit,
    RelationOrder,
    IssuedIdentityRequired,
    IssuedIdentityKindInvalid,
    CurrentRecordRequired,
    CurrentRecordUnexpected,
    CurrentRecordMismatch,
    LifecycleTransitionInvalid,
    RevisionOverflow,
    ExpiryInvalid,
    PreviewExpired,
    UnknownApprovalRequirement,
    UnknownApprovalDecision,
    UnknownExternalResolution,
    ApprovalRequired,
    ApprovalUnexpected,
    ApprovalMismatch,
    ApprovalDenied,
    ApprovalExpired,
    SubmissionMismatch,
    ReceiptTimeInvalid,
    ReceiptOutcomeInvalid,
    UnknownRefusalCategory,
    RequestDigestMismatch,
    Context(crate::platform_v2::WorkContextError),
    Value(ValueError),
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Field { .. } => "lifecycle field is invalid",
            Self::UnsafeToken { .. } => "lifecycle token is not wire-safe",
            Self::AuthorityLimit { .. } => "authority grant limit exceeded",
            Self::AuthorityOrder { .. } => "authority grants are repeated or unordered",
            Self::AuthorityWidening => "effective authority widens actor or inherited authority",
            Self::AuthorityUnexpected => "operation unexpectedly carries attempt authority",
            Self::TargetKindInvalid => "operation target kind is invalid",
            Self::TargetMismatch => "current record does not match operation target",
            Self::ExpectedRevisionMismatch => {
                "current record revision does not match expected revision"
            }
            Self::ParentSnapshotMismatch => "resolved parent snapshot does not match the intent",
            Self::ParentProjectMismatch => "resolved parent belongs to another project",
            Self::ParentLifecycleInvalid => "resolved parent lifecycle does not admit children",
            Self::ParentUnavailable => "resolved external parent is unavailable",
            Self::RelationLimit => "operation relation limit exceeded",
            Self::RelationOrder => "operation relations are repeated or unordered",
            Self::IssuedIdentityRequired => "create preview requires an issued identity",
            Self::IssuedIdentityKindInvalid => "issued identity has the wrong kind",
            Self::CurrentRecordRequired => {
                "mutation preview requires the authoritative current record"
            }
            Self::CurrentRecordUnexpected => "create preview cannot carry a current record",
            Self::CurrentRecordMismatch => "preview current/issued record shape is incoherent",
            Self::LifecycleTransitionInvalid => "lifecycle transition is invalid",
            Self::RevisionOverflow => "lifecycle revision cannot advance",
            Self::ExpiryInvalid => "lifecycle expiry is invalid",
            Self::PreviewExpired => "mutation preview has expired",
            Self::UnknownApprovalRequirement => "approval requirement is unknown",
            Self::UnknownApprovalDecision => "approval decision is unknown",
            Self::UnknownExternalResolution => "external parent resolution is unknown",
            Self::ApprovalRequired => "approval is required",
            Self::ApprovalUnexpected => "approval is unexpected",
            Self::ApprovalMismatch => "approval does not bind the exact preview",
            Self::ApprovalDenied => "mutation was denied",
            Self::ApprovalExpired => "approval has expired",
            Self::SubmissionMismatch => "submission does not bind the exact preview",
            Self::ReceiptTimeInvalid => "receipt predates its submission",
            Self::ReceiptOutcomeInvalid => "lookup-only outcome cannot be persisted as a receipt",
            Self::UnknownRefusalCategory => "mutation refusal category is unknown",
            Self::RequestDigestMismatch => "request digest does not bind the proposal",
            Self::Context(_) => "work-context value is invalid",
            Self::Value(_) => "bounded lifecycle value is invalid",
        })
    }
}
impl std::error::Error for LifecycleError {}
impl From<crate::platform_v2::WorkContextError> for LifecycleError {
    fn from(value: crate::platform_v2::WorkContextError) -> Self {
        Self::Context(value)
    }
}
impl From<ValueError> for LifecycleError {
    fn from(value: ValueError) -> Self {
        Self::Value(value)
    }
}
