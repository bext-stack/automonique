// SPDX-License-Identifier: Elastic-2.0

//! Authoritative, source-atomic attention navigation for Platform v2.
//!
//! This read model deliberately contains no pane, tab, window, terminal, host
//! path, or other client-local target. A client may resolve the exact project,
//! user workspace, and optional Platform session against its own current
//! catalogue only after decoding this document.

use core::fmt;

use crate::platform::{ResourceAuthority, ResourceCoordinate};
use crate::platform_v2::{ProjectId, UserWorkspaceId, V1SessionRef};
use crate::primitives::{BoundedString, IdDomain, OpaqueId, Revision, ValueError};

pub const PLATFORM_ATTENTION_SCHEMA_V1: &str = "automonique.platform/attention/v1";
pub const PLATFORM_ATTENTION_REQUIRES_PLATFORM_MAJOR: u16 = 2;
pub const ATTENTION_READ_METHOD_V1: &str = "get_attention_source_snapshot";
pub const MAX_ATTENTION_FIELD_BYTES: usize = 256;
pub const MAX_ATTENTION_ITEMS: usize = 256;
pub const MAX_NESTED_AGENT_DEPTH: usize = 16;

macro_rules! id_domain {
    ($domain:ident, $name:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $domain;
        impl IdDomain for $domain {}
        pub type $name = OpaqueId<$domain, MAX_ATTENTION_FIELD_BYTES>;
    };
}

id_domain!(AttentionSourceIdDomain, AttentionSourceId);
id_domain!(AttentionItemIdDomain, AttentionItemId);
id_domain!(AttentionAgentIdDomain, AttentionAgentId);

pub type AttentionField = BoundedString<MAX_ATTENTION_FIELD_BYTES>;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AttentionSourceKind {
    Review,
    Orchestration,
    ProviderSession,
}

impl AttentionSourceKind {
    pub const ALL: [Self; 3] = [Self::Review, Self::Orchestration, Self::ProviderSession];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::Orchestration => "orchestration",
            Self::ProviderSession => "provider_session",
        }
    }

    pub fn parse(value: &str) -> Result<Self, AttentionContractError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or(AttentionContractError::UnknownEnum)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AttentionItemState {
    NeedsYou,
    Working,
    Done,
    Blocked,
}

impl AttentionItemState {
    pub const ALL: [Self; 4] = [Self::NeedsYou, Self::Working, Self::Done, Self::Blocked];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NeedsYou => "needs_you",
            Self::Working => "working",
            Self::Done => "done",
            Self::Blocked => "blocked",
        }
    }

    pub fn parse(value: &str) -> Result<Self, AttentionContractError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or(AttentionContractError::UnknownEnum)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AttentionItemReason {
    ReviewRequested,
    CommentReply,
    ApprovalRequired,
    AgentWorking,
    CheckRunning,
    DeliveryPending,
    Complete,
    Conflict,
    CheckFailed,
    ExternalBlocker,
}

impl AttentionItemReason {
    pub const ALL: [Self; 10] = [
        Self::ReviewRequested,
        Self::CommentReply,
        Self::ApprovalRequired,
        Self::AgentWorking,
        Self::CheckRunning,
        Self::DeliveryPending,
        Self::Complete,
        Self::Conflict,
        Self::CheckFailed,
        Self::ExternalBlocker,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReviewRequested => "review_requested",
            Self::CommentReply => "comment_reply",
            Self::ApprovalRequired => "approval_required",
            Self::AgentWorking => "agent_working",
            Self::CheckRunning => "check_running",
            Self::DeliveryPending => "delivery_pending",
            Self::Complete => "complete",
            Self::Conflict => "conflict",
            Self::CheckFailed => "check_failed",
            Self::ExternalBlocker => "external_blocker",
        }
    }

    pub fn parse(value: &str) -> Result<Self, AttentionContractError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or(AttentionContractError::UnknownEnum)
    }

    #[must_use]
    pub const fn state(self) -> AttentionItemState {
        match self {
            Self::ReviewRequested | Self::CommentReply | Self::ApprovalRequired => {
                AttentionItemState::NeedsYou
            }
            Self::AgentWorking | Self::CheckRunning | Self::DeliveryPending => {
                AttentionItemState::Working
            }
            Self::Complete => AttentionItemState::Done,
            Self::Conflict | Self::CheckFailed | Self::ExternalBlocker => {
                AttentionItemState::Blocked
            }
        }
    }
}

/// Stable identity of one authoritative source. Item identifiers are scoped
/// by this identity and have no meaning without it.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AttentionSource {
    kind: AttentionSourceKind,
    id: AttentionSourceId,
}

/// Exact source and workspace selected by an attention read. The client does
/// not submit a pane, tab, or other presentation coordinate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttentionReadRequest {
    source: AttentionSource,
    project: ProjectId,
    user_workspace: UserWorkspaceId,
}

impl AttentionReadRequest {
    #[must_use]
    pub const fn new(
        source: AttentionSource,
        project: ProjectId,
        user_workspace: UserWorkspaceId,
    ) -> Self {
        Self {
            source,
            project,
            user_workspace,
        }
    }

    #[must_use]
    pub const fn source(&self) -> &AttentionSource {
        &self.source
    }
    #[must_use]
    pub const fn project(&self) -> &ProjectId {
        &self.project
    }
    #[must_use]
    pub const fn user_workspace(&self) -> &UserWorkspaceId {
        &self.user_workspace
    }
}

impl AttentionSource {
    #[must_use]
    pub const fn new(kind: AttentionSourceKind, id: AttentionSourceId) -> Self {
        Self { kind, id }
    }

    #[must_use]
    pub const fn kind(&self) -> AttentionSourceKind {
        self.kind
    }

    #[must_use]
    pub const fn id(&self) -> &AttentionSourceId {
        &self.id
    }
}

/// One item from a complete source snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttentionItem {
    id: AttentionItemId,
    revision: Revision,
    observed_at_ms: u64,
    state: AttentionItemState,
    reason: AttentionItemReason,
    unread: bool,
    nested_agent_path: Vec<AttentionAgentId>,
    platform_session: Option<V1SessionRef>,
}

impl AttentionItem {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: AttentionItemId,
        revision: Revision,
        observed_at_ms: u64,
        state: AttentionItemState,
        reason: AttentionItemReason,
        unread: bool,
        nested_agent_path: Vec<AttentionAgentId>,
        platform_session: Option<V1SessionRef>,
    ) -> Result<Self, AttentionContractError> {
        if observed_at_ms > i64::MAX as u64
            || state != reason.state()
            || nested_agent_path.len() > MAX_NESTED_AGENT_DEPTH
            || nested_agent_path
                .iter()
                .enumerate()
                .any(|(index, id)| nested_agent_path[index + 1..].contains(id))
        {
            return Err(AttentionContractError::ItemInvalid);
        }
        Ok(Self {
            id,
            revision,
            observed_at_ms,
            state,
            reason,
            unread,
            nested_agent_path,
            platform_session,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &AttentionItemId {
        &self.id
    }
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
    #[must_use]
    pub const fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }
    #[must_use]
    pub const fn state(&self) -> AttentionItemState {
        self.state
    }
    #[must_use]
    pub const fn reason(&self) -> AttentionItemReason {
        self.reason
    }
    #[must_use]
    pub const fn unread(&self) -> bool {
        self.unread
    }
    #[must_use]
    pub fn nested_agent_path(&self) -> &[AttentionAgentId] {
        &self.nested_agent_path
    }
    #[must_use]
    pub const fn platform_session(&self) -> Option<&V1SessionRef> {
        self.platform_session.as_ref()
    }
}

/// Complete atomic replacement for exactly one source and user workspace.
///
/// `previous_revision` forms a compare-and-replace chain. Absence is valid
/// only for revision one; successors must name the exact revision they replace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttentionSourceSnapshot {
    source: AttentionSource,
    project: ProjectId,
    user_workspace: UserWorkspaceId,
    revision: Revision,
    previous_revision: Option<Revision>,
    observed_at_ms: u64,
    items: Vec<AttentionItem>,
}

impl AttentionSourceSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source: AttentionSource,
        project: ProjectId,
        user_workspace: UserWorkspaceId,
        revision: Revision,
        previous_revision: Option<Revision>,
        observed_at_ms: u64,
        items: Vec<AttentionItem>,
    ) -> Result<Self, AttentionContractError> {
        if observed_at_ms > i64::MAX as u64
            || (revision == Revision::FIRST) != previous_revision.is_none()
            || previous_revision.is_some_and(|previous| previous >= revision)
            || items.len() > MAX_ATTENTION_ITEMS
            || !strict_by(&items, |item| item.id().as_str())
            || items.iter().any(|item| {
                item.revision() > revision
                    || item.observed_at_ms() > observed_at_ms
                    || (source.kind() == AttentionSourceKind::ProviderSession)
                        != item.platform_session().is_some()
            })
        {
            return Err(AttentionContractError::SnapshotInvalid);
        }
        Ok(Self {
            source,
            project,
            user_workspace,
            revision,
            previous_revision,
            observed_at_ms,
            items,
        })
    }

    /// Verify that `next` is a monotone, atomic replacement of this snapshot.
    pub fn validate_successor(&self, next: &Self) -> Result<(), AttentionContractError> {
        if next.source != self.source
            || next.project != self.project
            || next.user_workspace != self.user_workspace
            || next.previous_revision != Some(self.revision)
            || next.revision <= self.revision
            || next.observed_at_ms < self.observed_at_ms
        {
            return Err(AttentionContractError::SuccessorInvalid);
        }
        for next_item in &next.items {
            if let Some(current) = self.items.iter().find(|item| item.id() == next_item.id())
                && (next_item.revision() < current.revision()
                    || next_item.observed_at_ms() < current.observed_at_ms()
                    || (next_item.revision() == current.revision() && next_item != current))
            {
                return Err(AttentionContractError::SuccessorInvalid);
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn source(&self) -> &AttentionSource {
        &self.source
    }
    #[must_use]
    pub const fn project(&self) -> &ProjectId {
        &self.project
    }
    #[must_use]
    pub const fn user_workspace(&self) -> &UserWorkspaceId {
        &self.user_workspace
    }
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
    #[must_use]
    pub const fn previous_revision(&self) -> Option<Revision> {
        self.previous_revision
    }
    #[must_use]
    pub const fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }
    #[must_use]
    pub fn items(&self) -> &[AttentionItem] {
        &self.items
    }
}

fn strict_by<T>(values: &[T], key: impl Fn(&T) -> &str) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttentionContractError {
    Field(ValueError),
    UnknownEnum,
    ItemInvalid,
    SnapshotInvalid,
    SuccessorInvalid,
}

impl From<ValueError> for AttentionContractError {
    fn from(value: ValueError) -> Self {
        Self::Field(value)
    }
}

impl fmt::Display for AttentionContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "attention contract refused value: {self:?}")
    }
}

impl std::error::Error for AttentionContractError {}

/// Validate and retain an exact v1 session coordinate without accepting an
/// unqualified provider/session string.
pub fn platform_session(
    coordinate: ResourceCoordinate,
) -> Result<V1SessionRef, AttentionContractError> {
    if coordinate.authority == ResourceAuthority::Client {
        return Err(AttentionContractError::ItemInvalid);
    }
    V1SessionRef::new(coordinate).map_err(|_| AttentionContractError::ItemInvalid)
}
