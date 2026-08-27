// SPDX-License-Identifier: Elastic-2.0

//! Platform v2 external-work and internal-orchestration lineage values.
//!
//! External provider identity and Automonique orchestration identity are
//! deliberately separate domains. Both may bind to a [`UserWorkspaceId`], but
//! neither can be converted into the other or into workspace authority.

use core::fmt;

use crate::platform_v2::{AttemptWorkspaceId, PaneId, UserWorkspaceId, WorkSessionId};
use crate::primitives::{BoundedString, IdDomain, OpaqueId, Revision, ValueError};

pub const MAX_LINEAGE_FIELD_BYTES: usize = 256;
pub const MAX_LINEAGE_MESSAGE_BYTES: usize = 1_024;
pub const MAX_LINEAGE_RECORDS: usize = 128;
pub const MAX_LINEAGE_COUNTER: u64 = i64::MAX as u64;

macro_rules! lineage_id_domain {
    ($domain:ident, $name:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $domain;
        impl IdDomain for $domain {}
        pub type $name = OpaqueId<$domain, MAX_LINEAGE_FIELD_BYTES>;
    };
}

lineage_id_domain!(ExternalWorkScopeDomain, ExternalWorkScope);
lineage_id_domain!(ExternalWorkKeyDomain, ExternalWorkKey);
lineage_id_domain!(ExternalWorkAuthorityIdDomain, ExternalWorkAuthorityId);
lineage_id_domain!(OrchestrationRunIdDomain, OrchestrationRunId);
lineage_id_domain!(OrchestrationTaskIdDomain, OrchestrationTaskId);
lineage_id_domain!(OrchestrationDispatchIdDomain, OrchestrationDispatchId);
lineage_id_domain!(OrchestrationWorkerIdDomain, OrchestrationWorkerId);
lineage_id_domain!(OrchestrationHeartbeatIdDomain, OrchestrationHeartbeatId);
lineage_id_domain!(OrchestrationQuestionIdDomain, OrchestrationQuestionId);
lineage_id_domain!(
    OrchestrationDecisionGateIdDomain,
    OrchestrationDecisionGateId
);
lineage_id_domain!(WorkspaceIntentIdDomain, WorkspaceIntentId);
lineage_id_domain!(BaseSelectorIdDomain, BaseSelectorId);
lineage_id_domain!(BranchSelectorIdDomain, BranchSelectorId);

pub type LineageMessage = BoundedString<MAX_LINEAGE_MESSAGE_BYTES>;

/// Exact, path-free origin used by clients when jumping back into retained work.
/// Optional descendants form a strict prefix: pane requires session, and session
/// requires attempt.  Every lineage relation must preserve this coordinate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LineageOrigin {
    workspace: UserWorkspaceId,
    attempt: Option<AttemptWorkspaceId>,
    session: Option<WorkSessionId>,
    pane: Option<PaneId>,
}

impl LineageOrigin {
    pub fn new(
        workspace: UserWorkspaceId,
        attempt: Option<AttemptWorkspaceId>,
        session: Option<WorkSessionId>,
        pane: Option<PaneId>,
    ) -> Result<Self, LineageError> {
        if session.is_some() && attempt.is_none() || pane.is_some() && session.is_none() {
            return Err(LineageError::OriginInvalid);
        }
        Ok(Self {
            workspace,
            attempt,
            session,
            pane,
        })
    }
    #[must_use]
    pub fn workspace_only(workspace: UserWorkspaceId) -> Self {
        Self {
            workspace,
            attempt: None,
            session: None,
            pane: None,
        }
    }
    #[must_use]
    pub const fn workspace(&self) -> &UserWorkspaceId {
        &self.workspace
    }
    #[must_use]
    pub const fn attempt(&self) -> Option<&AttemptWorkspaceId> {
        self.attempt.as_ref()
    }
    #[must_use]
    pub const fn session(&self) -> Option<&WorkSessionId> {
        self.session.as_ref()
    }
    #[must_use]
    pub const fn pane(&self) -> Option<&PaneId> {
        self.pane.as_ref()
    }

    /// A child may refine its parent's coordinate, but may not change or drop it.
    #[must_use]
    pub fn refines(&self, parent: &Self) -> bool {
        self.workspace == parent.workspace
            && parent
                .attempt
                .as_ref()
                .is_none_or(|v| self.attempt.as_ref() == Some(v))
            && parent
                .session
                .as_ref()
                .is_none_or(|v| self.session.as_ref() == Some(v))
            && parent
                .pane
                .as_ref()
                .is_none_or(|v| self.pane.as_ref() == Some(v))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ExternalWorkProvider {
    GitHub,
    GitLab,
    Linear,
    JiraCompatible,
}

impl ExternalWorkProvider {
    pub const ALL: [Self; 4] = [
        Self::GitHub,
        Self::GitLab,
        Self::Linear,
        Self::JiraCompatible,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::GitLab => "gitlab",
            Self::Linear => "linear",
            Self::JiraCompatible => "jira_compatible",
        }
    }

    pub fn parse(value: &str) -> Result<Self, LineageError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or(LineageError::UnknownProvider)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExternalWorkIdentity {
    provider: ExternalWorkProvider,
    authority: ExternalWorkAuthorityId,
    scope: ExternalWorkScope,
    key: ExternalWorkKey,
}

impl ExternalWorkIdentity {
    #[must_use]
    pub const fn new(
        provider: ExternalWorkProvider,
        authority: ExternalWorkAuthorityId,
        scope: ExternalWorkScope,
        key: ExternalWorkKey,
    ) -> Self {
        Self {
            provider,
            authority,
            scope,
            key,
        }
    }

    #[must_use]
    pub const fn provider(&self) -> ExternalWorkProvider {
        self.provider
    }
    #[must_use]
    pub const fn authority(&self) -> &ExternalWorkAuthorityId {
        &self.authority
    }
    #[must_use]
    pub const fn scope(&self) -> &ExternalWorkScope {
        &self.scope
    }
    #[must_use]
    pub const fn key(&self) -> &ExternalWorkKey {
        &self.key
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ExternalWorkState {
    Open,
    Moved,
    Closed,
}

impl ExternalWorkState {
    pub const ALL: [Self; 3] = [Self::Open, Self::Moved, Self::Closed];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Moved => "moved",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LineageFreshnessState {
    Fresh,
    Stale,
}

impl LineageFreshnessState {
    pub const ALL: [Self; 2] = [Self::Fresh, Self::Stale];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LineageFreshness {
    observed_at_ms: u64,
    stale_after_ms: u64,
    state: LineageFreshnessState,
}

impl LineageFreshness {
    pub fn new(
        observed_at_ms: u64,
        stale_after_ms: u64,
        state: LineageFreshnessState,
    ) -> Result<Self, LineageError> {
        if observed_at_ms == 0
            || observed_at_ms > MAX_LINEAGE_COUNTER
            || stale_after_ms == 0
            || stale_after_ms > MAX_LINEAGE_COUNTER
        {
            return Err(LineageError::FreshnessInvalid);
        }
        Ok(Self {
            observed_at_ms,
            stale_after_ms,
            state,
        })
    }
    #[must_use]
    pub const fn observed_at_ms(self) -> u64 {
        self.observed_at_ms
    }
    #[must_use]
    pub const fn stale_after_ms(self) -> u64 {
        self.stale_after_ms
    }
    #[must_use]
    pub const fn state(self) -> LineageFreshnessState {
        self.state
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LatestUsefulMessage {
    text: LineageMessage,
    observed_at_ms: u64,
}

impl LatestUsefulMessage {
    pub fn new(text: LineageMessage, observed_at_ms: u64) -> Result<Self, LineageError> {
        if observed_at_ms == 0 || observed_at_ms > MAX_LINEAGE_COUNTER {
            return Err(LineageError::FreshnessInvalid);
        }
        Ok(Self {
            text,
            observed_at_ms,
        })
    }
    #[must_use]
    pub const fn text(&self) -> &LineageMessage {
        &self.text
    }
    #[must_use]
    pub const fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalWorkItem {
    identity: ExternalWorkIdentity,
    workspace: UserWorkspaceId,
    revision: Revision,
    state: ExternalWorkState,
    moved_to: Option<ExternalWorkIdentity>,
    freshness: LineageFreshness,
    latest_useful_message: Option<LatestUsefulMessage>,
    origin: LineageOrigin,
}

impl ExternalWorkItem {
    pub fn new(
        identity: ExternalWorkIdentity,
        workspace: UserWorkspaceId,
        revision: Revision,
        state: ExternalWorkState,
        moved_to: Option<ExternalWorkIdentity>,
        freshness: LineageFreshness,
        latest_useful_message: Option<LatestUsefulMessage>,
    ) -> Result<Self, LineageError> {
        Self::new_with_origin(
            identity,
            LineageOrigin::workspace_only(workspace),
            revision,
            state,
            moved_to,
            freshness,
            latest_useful_message,
        )
    }

    pub fn new_with_origin(
        identity: ExternalWorkIdentity,
        origin: LineageOrigin,
        revision: Revision,
        state: ExternalWorkState,
        moved_to: Option<ExternalWorkIdentity>,
        freshness: LineageFreshness,
        latest_useful_message: Option<LatestUsefulMessage>,
    ) -> Result<Self, LineageError> {
        if (state == ExternalWorkState::Moved) != moved_to.is_some()
            || moved_to.as_ref().is_some_and(|target| target == &identity)
            || latest_useful_message
                .as_ref()
                .is_some_and(|message| message.observed_at_ms() > freshness.observed_at_ms())
        {
            return Err(LineageError::ExternalWorkTransitionInvalid);
        }
        Ok(Self {
            identity,
            workspace: origin.workspace().clone(),
            revision,
            state,
            moved_to,
            freshness,
            latest_useful_message,
            origin,
        })
    }
    #[must_use]
    pub const fn identity(&self) -> &ExternalWorkIdentity {
        &self.identity
    }
    #[must_use]
    pub const fn workspace(&self) -> &UserWorkspaceId {
        &self.workspace
    }
    #[must_use]
    pub const fn state(&self) -> ExternalWorkState {
        self.state
    }
    #[must_use]
    pub const fn moved_to(&self) -> Option<&ExternalWorkIdentity> {
        self.moved_to.as_ref()
    }
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
    #[must_use]
    pub const fn freshness(&self) -> LineageFreshness {
        self.freshness
    }
    #[must_use]
    pub const fn latest_useful_message(&self) -> Option<&LatestUsefulMessage> {
        self.latest_useful_message.as_ref()
    }
    #[must_use]
    pub const fn origin(&self) -> &LineageOrigin {
        &self.origin
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OrchestrationKind {
    Run,
    Task,
    Dispatch,
    Worker,
    Heartbeat,
    Question,
    DecisionGate,
}

impl OrchestrationKind {
    pub const ALL: [Self; 7] = [
        Self::Run,
        Self::Task,
        Self::Dispatch,
        Self::Worker,
        Self::Heartbeat,
        Self::Question,
        Self::DecisionGate,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Task => "task",
            Self::Dispatch => "dispatch",
            Self::Worker => "worker",
            Self::Heartbeat => "heartbeat",
            Self::Question => "question",
            Self::DecisionGate => "decision_gate",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OrchestrationIdentity {
    Run(OrchestrationRunId),
    Task(OrchestrationTaskId),
    Dispatch(OrchestrationDispatchId),
    Worker(OrchestrationWorkerId),
    Heartbeat(OrchestrationHeartbeatId),
    Question(OrchestrationQuestionId),
    DecisionGate(OrchestrationDecisionGateId),
}

impl OrchestrationIdentity {
    #[must_use]
    pub const fn kind(&self) -> OrchestrationKind {
        match self {
            Self::Run(_) => OrchestrationKind::Run,
            Self::Task(_) => OrchestrationKind::Task,
            Self::Dispatch(_) => OrchestrationKind::Dispatch,
            Self::Worker(_) => OrchestrationKind::Worker,
            Self::Heartbeat(_) => OrchestrationKind::Heartbeat,
            Self::Question(_) => OrchestrationKind::Question,
            Self::DecisionGate(_) => OrchestrationKind::DecisionGate,
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Run(id) => id.as_str(),
            Self::Task(id) => id.as_str(),
            Self::Dispatch(id) => id.as_str(),
            Self::Worker(id) => id.as_str(),
            Self::Heartbeat(id) => id.as_str(),
            Self::Question(id) => id.as_str(),
            Self::DecisionGate(id) => id.as_str(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LineageStatus {
    Working,
    Blocked(LineageMessage),
    Waiting(LineageMessage),
    Done(LineageMessage),
}

impl LineageStatus {
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Working => "working",
            Self::Blocked(_) => "blocked",
            Self::Waiting(_) => "waiting",
            Self::Done(_) => "done",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrchestrationRecord {
    identity: OrchestrationIdentity,
    workspace: UserWorkspaceId,
    external_work: Option<ExternalWorkIdentity>,
    parent: Option<OrchestrationIdentity>,
    status: LineageStatus,
    freshness: LineageFreshness,
    latest_useful_message: Option<LatestUsefulMessage>,
    origin: LineageOrigin,
    revision: Revision,
}

impl OrchestrationRecord {
    pub fn new(
        identity: OrchestrationIdentity,
        workspace: UserWorkspaceId,
        external_work: Option<ExternalWorkIdentity>,
        parent: Option<OrchestrationIdentity>,
        status: LineageStatus,
        freshness: LineageFreshness,
        latest_useful_message: Option<LatestUsefulMessage>,
    ) -> Result<Self, LineageError> {
        Self::new_with_origin(
            identity,
            LineageOrigin::workspace_only(workspace),
            external_work,
            parent,
            status,
            freshness,
            latest_useful_message,
            Revision::FIRST,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_origin(
        identity: OrchestrationIdentity,
        origin: LineageOrigin,
        external_work: Option<ExternalWorkIdentity>,
        parent: Option<OrchestrationIdentity>,
        status: LineageStatus,
        freshness: LineageFreshness,
        latest_useful_message: Option<LatestUsefulMessage>,
        revision: Revision,
    ) -> Result<Self, LineageError> {
        if !parent_allowed(
            identity.kind(),
            parent.as_ref().map(OrchestrationIdentity::kind),
        ) || parent.as_ref() == Some(&identity)
            || latest_useful_message
                .as_ref()
                .is_some_and(|message| message.observed_at_ms() > freshness.observed_at_ms())
        {
            return Err(LineageError::OrchestrationParentInvalid);
        }
        Ok(Self {
            identity,
            workspace: origin.workspace().clone(),
            external_work,
            parent,
            status,
            freshness,
            latest_useful_message,
            origin,
            revision,
        })
    }
    #[must_use]
    pub const fn identity(&self) -> &OrchestrationIdentity {
        &self.identity
    }
    #[must_use]
    pub const fn workspace(&self) -> &UserWorkspaceId {
        &self.workspace
    }
    #[must_use]
    pub const fn external_work(&self) -> Option<&ExternalWorkIdentity> {
        self.external_work.as_ref()
    }
    #[must_use]
    pub const fn parent(&self) -> Option<&OrchestrationIdentity> {
        self.parent.as_ref()
    }
    #[must_use]
    pub const fn status(&self) -> &LineageStatus {
        &self.status
    }
    #[must_use]
    pub const fn freshness(&self) -> LineageFreshness {
        self.freshness
    }
    #[must_use]
    pub const fn latest_useful_message(&self) -> Option<&LatestUsefulMessage> {
        self.latest_useful_message.as_ref()
    }
    #[must_use]
    pub const fn origin(&self) -> &LineageOrigin {
        &self.origin
    }
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineageProjection {
    workspace: UserWorkspaceId,
    external_work_items: Vec<ExternalWorkItem>,
    orchestration: Vec<OrchestrationRecord>,
}

impl LineageProjection {
    pub fn new(
        workspace: UserWorkspaceId,
        mut external_work_items: Vec<ExternalWorkItem>,
        mut orchestration: Vec<OrchestrationRecord>,
    ) -> Result<Self, LineageError> {
        if external_work_items
            .len()
            .saturating_add(orchestration.len())
            > MAX_LINEAGE_RECORDS
            || external_work_items
                .iter()
                .any(|item| item.workspace() != &workspace)
            || orchestration
                .iter()
                .any(|item| item.workspace() != &workspace)
        {
            return Err(LineageError::InventoryInvalid);
        }
        external_work_items.sort_by(|left, right| {
            external_identity_key(left.identity()).cmp(&external_identity_key(right.identity()))
        });
        orchestration.sort_by(|left, right| {
            orchestration_identity_key(left.identity())
                .cmp(&orchestration_identity_key(right.identity()))
        });
        if external_work_items
            .windows(2)
            .any(|pair| pair[0].identity() == pair[1].identity())
            || orchestration
                .windows(2)
                .any(|pair| pair[0].identity() == pair[1].identity())
        {
            return Err(LineageError::InventoryInvalid);
        }
        for item in &external_work_items {
            if item.origin().workspace() != &workspace {
                return Err(LineageError::OriginInvalid);
            }
            if let Some(moved) = item.moved_to() {
                let Some(target) = external_work_items
                    .iter()
                    .find(|candidate| candidate.identity() == moved)
                else {
                    return Err(LineageError::ExternalLinkInvalid);
                };
                if !target.origin().refines(item.origin()) {
                    return Err(LineageError::OriginInvalid);
                }
            }
        }
        for item in &external_work_items {
            let mut cursor = item.moved_to();
            let mut steps = 0usize;
            while let Some(identity) = cursor {
                if identity == item.identity() || steps >= external_work_items.len() {
                    return Err(LineageError::ExternalLinkInvalid);
                }
                cursor = external_work_items
                    .iter()
                    .find(|candidate| candidate.identity() == identity)
                    .and_then(ExternalWorkItem::moved_to);
                steps += 1;
            }
        }
        for record in &orchestration {
            if record.origin().workspace() != &workspace {
                return Err(LineageError::OriginInvalid);
            }
            if let Some(external) = record.external_work() {
                let Some(target) = external_work_items
                    .iter()
                    .find(|item| item.identity() == external)
                else {
                    return Err(LineageError::ExternalLinkInvalid);
                };
                if !record.origin().refines(target.origin()) {
                    return Err(LineageError::OriginInvalid);
                }
            }
            if let Some(parent) = record.parent() {
                let Some(target) = orchestration.iter().find(|item| item.identity() == parent)
                else {
                    return Err(LineageError::OrchestrationParentInvalid);
                };
                if !record.origin().refines(target.origin()) {
                    return Err(LineageError::OriginInvalid);
                }
            }
        }
        // A parent-kind matrix is insufficient for task-to-task cycles.
        for record in &orchestration {
            let mut cursor = record.parent();
            let mut traversed = 0usize;
            while let Some(parent) = cursor {
                if parent == record.identity() || traversed >= orchestration.len() {
                    return Err(LineageError::OrchestrationCycle);
                }
                cursor = orchestration
                    .iter()
                    .find(|item| item.identity() == parent)
                    .and_then(OrchestrationRecord::parent);
                traversed += 1;
            }
        }
        Ok(Self {
            workspace,
            external_work_items,
            orchestration,
        })
    }

    #[must_use]
    pub const fn workspace(&self) -> &UserWorkspaceId {
        &self.workspace
    }
    #[must_use]
    pub fn external_work_items(&self) -> &[ExternalWorkItem] {
        &self.external_work_items
    }
    #[must_use]
    pub fn orchestration(&self) -> &[OrchestrationRecord] {
        &self.orchestration
    }
}

fn external_identity_key(identity: &ExternalWorkIdentity) -> (&str, &str, &str, &str) {
    (
        identity.provider().as_str(),
        identity.authority().as_str(),
        identity.scope().as_str(),
        identity.key().as_str(),
    )
}

fn orchestration_identity_key(identity: &OrchestrationIdentity) -> (&str, &str) {
    (identity.kind().as_str(), identity.id())
}

const fn parent_allowed(kind: OrchestrationKind, parent: Option<OrchestrationKind>) -> bool {
    matches!(
        (kind, parent),
        (OrchestrationKind::Run, None)
            | (
                OrchestrationKind::Task,
                Some(OrchestrationKind::Run | OrchestrationKind::Task)
            )
            | (OrchestrationKind::Dispatch, Some(OrchestrationKind::Task))
            | (OrchestrationKind::Worker, Some(OrchestrationKind::Dispatch))
            | (
                OrchestrationKind::Heartbeat,
                Some(OrchestrationKind::Worker)
            )
            | (OrchestrationKind::Question, Some(OrchestrationKind::Task))
            | (
                OrchestrationKind::DecisionGate,
                Some(OrchestrationKind::Question | OrchestrationKind::Task)
            )
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceCreateIntent {
    intent_id: WorkspaceIntentId,
    task: OrchestrationTaskId,
    external_work: ExternalWorkIdentity,
    base_selector: BaseSelectorId,
    branch_selector: BranchSelectorId,
}

impl WorkspaceCreateIntent {
    #[must_use]
    pub const fn new(
        intent_id: WorkspaceIntentId,
        task: OrchestrationTaskId,
        external_work: ExternalWorkIdentity,
        base_selector: BaseSelectorId,
        branch_selector: BranchSelectorId,
    ) -> Self {
        Self {
            intent_id,
            task,
            external_work,
            base_selector,
            branch_selector,
        }
    }
    #[must_use]
    pub const fn intent_id(&self) -> &WorkspaceIntentId {
        &self.intent_id
    }
    #[must_use]
    pub const fn task(&self) -> &OrchestrationTaskId {
        &self.task
    }
    #[must_use]
    pub const fn external_work(&self) -> &ExternalWorkIdentity {
        &self.external_work
    }
    #[must_use]
    pub const fn base_selector(&self) -> &BaseSelectorId {
        &self.base_selector
    }
    #[must_use]
    pub const fn branch_selector(&self) -> &BranchSelectorId {
        &self.branch_selector
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceResumeIntent {
    intent_id: WorkspaceIntentId,
    task: OrchestrationTaskId,
    workspace: UserWorkspaceId,
    expected_revision: Revision,
}

impl WorkspaceResumeIntent {
    #[must_use]
    pub const fn new(
        intent_id: WorkspaceIntentId,
        task: OrchestrationTaskId,
        workspace: UserWorkspaceId,
        expected_revision: Revision,
    ) -> Self {
        Self {
            intent_id,
            task,
            workspace,
            expected_revision,
        }
    }
    #[must_use]
    pub const fn intent_id(&self) -> &WorkspaceIntentId {
        &self.intent_id
    }
    #[must_use]
    pub const fn task(&self) -> &OrchestrationTaskId {
        &self.task
    }
    #[must_use]
    pub const fn workspace(&self) -> &UserWorkspaceId {
        &self.workspace
    }
    #[must_use]
    pub const fn expected_revision(&self) -> Revision {
        self.expected_revision
    }
}

/// Idempotent request to cancel one still-pending workspace intent.
///
/// The cancellation has its own identity so retries cannot be confused with
/// the target operation. The target workspace and durable intent revision are
/// carried explicitly; possession of an intent ID alone is never authority to
/// cancel it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceCancelIntent {
    intent_id: WorkspaceIntentId,
    target_intent_id: WorkspaceIntentId,
    workspace: UserWorkspaceId,
    expected_revision: Revision,
}

impl WorkspaceCancelIntent {
    pub fn new(
        intent_id: WorkspaceIntentId,
        target_intent_id: WorkspaceIntentId,
        workspace: UserWorkspaceId,
        expected_revision: Revision,
    ) -> Result<Self, LineageError> {
        if intent_id == target_intent_id {
            return Err(LineageError::InventoryInvalid);
        }
        Ok(Self {
            intent_id,
            target_intent_id,
            workspace,
            expected_revision,
        })
    }
    #[must_use]
    pub const fn intent_id(&self) -> &WorkspaceIntentId {
        &self.intent_id
    }
    #[must_use]
    pub const fn target_intent_id(&self) -> &WorkspaceIntentId {
        &self.target_intent_id
    }
    #[must_use]
    pub const fn workspace(&self) -> &UserWorkspaceId {
        &self.workspace
    }
    #[must_use]
    pub const fn expected_revision(&self) -> Revision {
        self.expected_revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkspaceIntent {
    Create(WorkspaceCreateIntent),
    Resume(WorkspaceResumeIntent),
    Cancel(WorkspaceCancelIntent),
}
impl WorkspaceIntent {
    #[must_use]
    pub const fn intent_id(&self) -> &WorkspaceIntentId {
        match self {
            Self::Create(v) => v.intent_id(),
            Self::Resume(v) => v.intent_id(),
            Self::Cancel(v) => v.intent_id(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkspaceIntentConflict {
    DuplicateIntake,
    TaskAlreadyBound,
    WorkspaceNotFound,
    RevisionMismatch,
    ExternalWorkMoved,
    ExternalWorkClosed,
    OrphanDispatch,
    StaleHeartbeat,
    QuestionPending,
    CreationCancelled,
}

impl WorkspaceIntentConflict {
    pub const ALL: [Self; 10] = [
        Self::DuplicateIntake,
        Self::TaskAlreadyBound,
        Self::WorkspaceNotFound,
        Self::RevisionMismatch,
        Self::ExternalWorkMoved,
        Self::ExternalWorkClosed,
        Self::OrphanDispatch,
        Self::StaleHeartbeat,
        Self::QuestionPending,
        Self::CreationCancelled,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateIntake => "duplicate_intake",
            Self::TaskAlreadyBound => "task_already_bound",
            Self::WorkspaceNotFound => "workspace_not_found",
            Self::RevisionMismatch => "revision_mismatch",
            Self::ExternalWorkMoved => "external_work_moved",
            Self::ExternalWorkClosed => "external_work_closed",
            Self::OrphanDispatch => "orphan_dispatch",
            Self::StaleHeartbeat => "stale_heartbeat",
            Self::QuestionPending => "question_pending",
            Self::CreationCancelled => "creation_cancelled",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkspaceIntentOutcome {
    Accepted,
    Unknown,
    Created(UserWorkspaceId),
    Resumed(UserWorkspaceId),
    Cancelled(WorkspaceIntentId),
    Conflict(WorkspaceIntentConflict),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceIntentReconciliation {
    Final,
    PollReceipt,
}
impl WorkspaceIntentReconciliation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Final => "final",
            Self::PollReceipt => "poll_receipt",
        }
    }
}

impl WorkspaceIntentOutcome {
    #[must_use]
    pub const fn reconciliation(&self) -> WorkspaceIntentReconciliation {
        match self {
            Self::Accepted | Self::Unknown => WorkspaceIntentReconciliation::PollReceipt,
            Self::Created(_) | Self::Resumed(_) | Self::Cancelled(_) | Self::Conflict(_) => {
                WorkspaceIntentReconciliation::Final
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineageError {
    Field(ValueError),
    UnknownProvider,
    FreshnessInvalid,
    ExternalWorkTransitionInvalid,
    OrchestrationParentInvalid,
    OrchestrationCycle,
    ExternalLinkInvalid,
    OriginInvalid,
    InventoryInvalid,
}

impl fmt::Display for LineageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Field(_) => "lineage field is invalid",
            Self::UnknownProvider => "external work provider is unknown",
            Self::FreshnessInvalid => "lineage freshness is invalid",
            Self::ExternalWorkTransitionInvalid => "external work transition is invalid",
            Self::OrchestrationParentInvalid => "orchestration parent is invalid",
            Self::OrchestrationCycle => "orchestration lineage contains a cycle",
            Self::ExternalLinkInvalid => "external lineage target is absent",
            Self::OriginInvalid => "lineage origin coordinate is invalid",
            Self::InventoryInvalid => {
                "lineage projection is duplicated, oversized, or crosses workspaces"
            }
        })
    }
}

impl std::error::Error for LineageError {}
impl From<ValueError> for LineageError {
    fn from(value: ValueError) -> Self {
        Self::Field(value)
    }
}
