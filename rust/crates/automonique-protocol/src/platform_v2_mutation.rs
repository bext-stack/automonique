// SPDX-License-Identifier: Elastic-2.0

//! Platform v2 work-context mutation values and admission semantics.
//!
//! This is a protocol contract, not a store. A server persists previews,
//! idempotency bindings, approval consumption, and receipts before using these
//! decisions. The pure constructors make the exact relationships independently
//! testable without pretending that an in-memory value is durable authority.

use core::fmt;

use crate::identity::Actor;
use crate::platform::{IdempotencyKey, ReceiptId, ReceiptOutcome};
use crate::platform_v2::{
    AttemptWorkspaceId, WorkContextError, WorkContextIdentity, WorkContextKind,
    WorkContextLifecycle, WorkContextRecord,
};
use crate::primitives::{IdDomain, OpaqueId, Revision, ValueError};

pub const MAX_WORK_CONTEXT_MUTATION_FIELD_BYTES: usize = 256;

macro_rules! mutation_id_domain {
    ($domain:ident, $name:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $domain;
        impl IdDomain for $domain {}
        pub type $name = OpaqueId<$domain, MAX_WORK_CONTEXT_MUTATION_FIELD_BYTES>;
    };
}

mutation_id_domain!(WorkContextPreviewIdDomain, WorkContextPreviewId);
mutation_id_domain!(WorkContextApprovalIdDomain, WorkContextApprovalId);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkContextMutationKind {
    Create,
    Resume,
    Archive,
}

impl WorkContextMutationKind {
    pub const ALL: [Self; 3] = [Self::Create, Self::Resume, Self::Archive];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Resume => "resume",
            Self::Archive => "archive",
        }
    }

    pub fn parse(value: &str) -> Result<Self, WorkContextMutationError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or(WorkContextMutationError::UnknownMutationKind)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpectedWorkContextRevision {
    Absent,
    Exact(Revision),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkContextMutationOperation {
    Create(WorkContextRecord),
    Resume(WorkContextRecord),
    Archive(WorkContextRecord),
}

impl WorkContextMutationOperation {
    #[must_use]
    pub const fn kind(&self) -> WorkContextMutationKind {
        match self {
            Self::Create(_) => WorkContextMutationKind::Create,
            Self::Resume(_) => WorkContextMutationKind::Resume,
            Self::Archive(_) => WorkContextMutationKind::Archive,
        }
    }

    #[must_use]
    pub fn current(&self) -> &WorkContextRecord {
        match self {
            Self::Create(record) | Self::Resume(record) | Self::Archive(record) => record,
        }
    }

    #[must_use]
    pub fn target(&self) -> &WorkContextIdentity {
        &self.current().identity
    }

    pub fn expected_revision(
        &self,
    ) -> Result<ExpectedWorkContextRevision, WorkContextMutationError> {
        match self {
            Self::Create(record) => {
                validate_initial_record(record)?;
                Ok(ExpectedWorkContextRevision::Absent)
            }
            Self::Resume(record) => {
                resumed_lifecycle(record.kind(), record.lifecycle)?;
                Ok(ExpectedWorkContextRevision::Exact(record.revision))
            }
            Self::Archive(record) => {
                archived_lifecycle(record.kind(), record.lifecycle)?;
                Ok(ExpectedWorkContextRevision::Exact(record.revision))
            }
        }
    }

    pub fn resulting_record(&self) -> Result<WorkContextRecord, WorkContextMutationError> {
        match self {
            Self::Create(record) => {
                validate_initial_record(record)?;
                Ok(record.clone())
            }
            Self::Resume(record) => {
                transition_record(record, resumed_lifecycle(record.kind(), record.lifecycle)?)
            }
            Self::Archive(record) => {
                transition_record(record, archived_lifecycle(record.kind(), record.lifecycle)?)
            }
        }
    }
}

fn validate_initial_record(record: &WorkContextRecord) -> Result<(), WorkContextMutationError> {
    let initial = match record.kind() {
        WorkContextKind::AttemptWorkspace => WorkContextLifecycle::Preparing,
        WorkContextKind::Project
        | WorkContextKind::HostSetup
        | WorkContextKind::Checkout
        | WorkContextKind::UserWorkspace
        | WorkContextKind::Session
        | WorkContextKind::Pane => WorkContextLifecycle::Active,
    };
    if record.revision != Revision::FIRST || record.lifecycle != initial {
        return Err(WorkContextMutationError::CreateStateInvalid);
    }
    Ok(())
}

fn resumed_lifecycle(
    kind: WorkContextKind,
    from: WorkContextLifecycle,
) -> Result<WorkContextLifecycle, WorkContextMutationError> {
    match (kind, from) {
        (WorkContextKind::AttemptWorkspace, WorkContextLifecycle::Hibernated) => {
            Ok(WorkContextLifecycle::Running)
        }
        (WorkContextKind::Session, WorkContextLifecycle::Hibernated) => {
            Ok(WorkContextLifecycle::Active)
        }
        _ => Err(WorkContextMutationError::LifecycleTransitionInvalid),
    }
}

fn archived_lifecycle(
    kind: WorkContextKind,
    from: WorkContextLifecycle,
) -> Result<WorkContextLifecycle, WorkContextMutationError> {
    match (kind, from) {
        (
            WorkContextKind::Project
            | WorkContextKind::HostSetup
            | WorkContextKind::Checkout
            | WorkContextKind::UserWorkspace,
            WorkContextLifecycle::Active,
        ) => Ok(WorkContextLifecycle::Archived),
        _ => Err(WorkContextMutationError::LifecycleTransitionInvalid),
    }
}

fn transition_record(
    current: &WorkContextRecord,
    lifecycle: WorkContextLifecycle,
) -> Result<WorkContextRecord, WorkContextMutationError> {
    let next = current
        .revision
        .get()
        .checked_add(1)
        .ok_or(WorkContextMutationError::RevisionOverflow)?;
    WorkContextRecord::new(
        current.identity.clone(),
        Revision::new(next).map_err(WorkContextError::Field)?,
        lifecycle,
        current.label.clone(),
        current.attributes,
        current.relations.clone(),
    )
    .map_err(Into::into)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkContextMutationProposal {
    pub actor: Actor,
    pub idempotency_key: IdempotencyKey,
    pub expected_revision: ExpectedWorkContextRevision,
    pub operation: WorkContextMutationOperation,
}

impl WorkContextMutationProposal {
    pub fn new(
        actor: Actor,
        idempotency_key: IdempotencyKey,
        expected_revision: ExpectedWorkContextRevision,
        operation: WorkContextMutationOperation,
    ) -> Result<Self, WorkContextMutationError> {
        if operation.expected_revision()? != expected_revision {
            return Err(WorkContextMutationError::ExpectedRevisionMismatch);
        }
        Ok(Self {
            actor,
            idempotency_key,
            expected_revision,
            operation,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkContextAuthorityEffect {
    Unchanged,
    Narrowed,
}

impl WorkContextAuthorityEffect {
    pub const ALL: [Self; 2] = [Self::Unchanged, Self::Narrowed];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Narrowed => "narrowed",
        }
    }
    pub fn parse(value: &str) -> Result<Self, WorkContextMutationError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or(WorkContextMutationError::UnknownAuthorityEffect)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkContextApprovalRequirement {
    NotRequired,
    Required,
}

impl WorkContextApprovalRequirement {
    pub const ALL: [Self; 2] = [Self::NotRequired, Self::Required];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::Required => "required",
        }
    }
    pub fn parse(value: &str) -> Result<Self, WorkContextMutationError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or(WorkContextMutationError::UnknownApprovalRequirement)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkContextPreviewRef {
    pub id: WorkContextPreviewId,
    pub revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkContextMutationPreview {
    pub preview: WorkContextPreviewRef,
    pub proposal: WorkContextMutationProposal,
    pub resulting: WorkContextRecord,
    pub authority_effect: WorkContextAuthorityEffect,
    pub approval: WorkContextApprovalRequirement,
}

impl WorkContextMutationPreview {
    pub fn new(
        preview: WorkContextPreviewRef,
        proposal: WorkContextMutationProposal,
        resulting: WorkContextRecord,
        authority_effect: WorkContextAuthorityEffect,
        approval: WorkContextApprovalRequirement,
    ) -> Result<Self, WorkContextMutationError> {
        if proposal.operation.resulting_record()? != resulting {
            return Err(WorkContextMutationError::PreviewResultMismatch);
        }
        Ok(Self {
            preview,
            proposal,
            resulting,
            authority_effect,
            approval,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkContextApprovalDecision {
    Granted,
    Denied,
}

impl WorkContextApprovalDecision {
    pub const ALL: [Self; 2] = [Self::Granted, Self::Denied];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Denied => "denied",
        }
    }
    pub fn parse(value: &str) -> Result<Self, WorkContextMutationError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or(WorkContextMutationError::UnknownApprovalDecision)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkContextMutationApproval {
    pub id: WorkContextApprovalId,
    pub preview: WorkContextPreviewRef,
    pub idempotency_key: IdempotencyKey,
    pub decision: WorkContextApprovalDecision,
    pub decided_by: Actor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkContextMutationSubmission {
    pub proposal: WorkContextMutationProposal,
    pub preview: WorkContextPreviewRef,
    pub approval: Option<WorkContextMutationApproval>,
}

impl WorkContextMutationSubmission {
    pub fn new(
        proposal: WorkContextMutationProposal,
        preview: WorkContextPreviewRef,
        approval: Option<WorkContextMutationApproval>,
    ) -> Self {
        Self {
            proposal,
            preview,
            approval,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedWorkContextMutation {
    pub submission: WorkContextMutationSubmission,
    pub resulting: WorkContextRecord,
}

pub fn admit_work_context_mutation(
    submission: WorkContextMutationSubmission,
    preview: &WorkContextMutationPreview,
) -> Result<AdmittedWorkContextMutation, WorkContextMutationError> {
    if submission.proposal != preview.proposal || submission.preview != preview.preview {
        return Err(WorkContextMutationError::PreviewMismatch);
    }
    match (preview.approval, submission.approval.as_ref()) {
        (WorkContextApprovalRequirement::NotRequired, None) => {}
        (WorkContextApprovalRequirement::NotRequired, Some(_)) => {
            return Err(WorkContextMutationError::ApprovalUnexpected);
        }
        (WorkContextApprovalRequirement::Required, None) => {
            return Err(WorkContextMutationError::ApprovalRequired);
        }
        (WorkContextApprovalRequirement::Required, Some(approval)) => {
            if approval.preview != preview.preview
                || approval.idempotency_key != submission.proposal.idempotency_key
            {
                return Err(WorkContextMutationError::ApprovalMismatch);
            }
            if approval.decision != WorkContextApprovalDecision::Granted {
                return Err(WorkContextMutationError::ApprovalDenied);
            }
        }
    }
    Ok(AdmittedWorkContextMutation {
        submission,
        resulting: preview.resulting.clone(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkContextMutationReceipt {
    pub id: ReceiptId,
    pub proposal: WorkContextMutationProposal,
    pub preview: WorkContextPreviewRef,
    pub approval_id: Option<WorkContextApprovalId>,
    pub outcome: ReceiptOutcome,
    pub resulting_revision: Option<Revision>,
}

impl WorkContextMutationReceipt {
    pub fn new(
        id: ReceiptId,
        admitted: &AdmittedWorkContextMutation,
        outcome: ReceiptOutcome,
    ) -> Result<Self, WorkContextMutationError> {
        let resulting_revision = match outcome {
            ReceiptOutcome::Completed => Some(admitted.resulting.revision),
            ReceiptOutcome::Accepted
            | ReceiptOutcome::Rejected
            | ReceiptOutcome::Conflict
            | ReceiptOutcome::Unknown
            | ReceiptOutcome::ResyncRequired => None,
        };
        Ok(Self {
            id,
            proposal: admitted.submission.proposal.clone(),
            preview: admitted.submission.preview.clone(),
            approval_id: admitted
                .submission
                .approval
                .as_ref()
                .map(|approval| approval.id.clone()),
            outcome,
            resulting_revision,
        })
    }

    pub fn from_parts(
        id: ReceiptId,
        proposal: WorkContextMutationProposal,
        preview: WorkContextPreviewRef,
        approval_id: Option<WorkContextApprovalId>,
        outcome: ReceiptOutcome,
        resulting_revision: Option<Revision>,
    ) -> Result<Self, WorkContextMutationError> {
        let expected_result = proposal.operation.resulting_record()?.revision;
        match (outcome, resulting_revision) {
            (ReceiptOutcome::Completed, Some(revision)) if revision == expected_result => {}
            (ReceiptOutcome::Completed, _) => {
                return Err(WorkContextMutationError::ReceiptResultMismatch);
            }
            (_, None) => {}
            (_, Some(_)) => return Err(WorkContextMutationError::ReceiptResultMismatch),
        }
        Ok(Self {
            id,
            proposal,
            preview,
            approval_id,
            outcome,
            resulting_revision,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkContextReceiptQuery {
    pub actor: Actor,
    pub idempotency_key: IdempotencyKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkContextRetryDisposition {
    SubmitOnce,
    ReturnRecorded,
    Conflict,
}

pub fn reconcile_work_context_retry(
    submission: &WorkContextMutationSubmission,
    recorded: Option<&WorkContextMutationReceipt>,
) -> WorkContextRetryDisposition {
    let Some(recorded) = recorded else {
        return WorkContextRetryDisposition::SubmitOnce;
    };
    let approval_id = submission
        .approval
        .as_ref()
        .map(|approval| approval.id.clone());
    if recorded.proposal == submission.proposal
        && recorded.preview == submission.preview
        && recorded.approval_id == approval_id
    {
        WorkContextRetryDisposition::ReturnRecorded
    } else {
        WorkContextRetryDisposition::Conflict
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkContextMutationError {
    Field(ValueError),
    Context(WorkContextError),
    UnknownMutationKind,
    UnknownAuthorityEffect,
    UnknownApprovalRequirement,
    UnknownApprovalDecision,
    CreateStateInvalid,
    LifecycleTransitionInvalid,
    RevisionOverflow,
    ExpectedRevisionMismatch,
    PreviewResultMismatch,
    PreviewMismatch,
    ApprovalRequired,
    ApprovalUnexpected,
    ApprovalMismatch,
    ApprovalDenied,
    ReceiptResultMismatch,
}

impl fmt::Display for WorkContextMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Field(_) => "work-context mutation field is invalid",
            Self::Context(_) => "work-context record is invalid",
            Self::UnknownMutationKind => "work-context mutation kind is unknown",
            Self::UnknownAuthorityEffect => "authority effect is unknown",
            Self::UnknownApprovalRequirement => "approval requirement is unknown",
            Self::UnknownApprovalDecision => "approval decision is unknown",
            Self::CreateStateInvalid => "created record does not begin at its initial state",
            Self::LifecycleTransitionInvalid => "lifecycle transition is invalid",
            Self::RevisionOverflow => "work-context revision cannot advance",
            Self::ExpectedRevisionMismatch => "expected revision does not match the operation",
            Self::PreviewResultMismatch => "preview result does not match the operation",
            Self::PreviewMismatch => "submission does not match the reviewed preview",
            Self::ApprovalRequired => "the reviewed preview requires approval",
            Self::ApprovalUnexpected => "the reviewed preview does not accept approval",
            Self::ApprovalMismatch => "approval does not target this exact mutation",
            Self::ApprovalDenied => "the exact mutation was denied",
            Self::ReceiptResultMismatch => "receipt result does not match the mutation",
        })
    }
}

impl std::error::Error for WorkContextMutationError {}

impl From<ValueError> for WorkContextMutationError {
    fn from(value: ValueError) -> Self {
        Self::Field(value)
    }
}

impl From<WorkContextError> for WorkContextMutationError {
    fn from(value: WorkContextError) -> Self {
        Self::Context(value)
    }
}

// Keep this type referenced in generated documentation examples without
// conflating it with the internal execution Workspace.
#[allow(dead_code)]
fn _attempt_identity_example(value: AttemptWorkspaceId) -> WorkContextIdentity {
    WorkContextIdentity::AttemptWorkspace(value)
}
