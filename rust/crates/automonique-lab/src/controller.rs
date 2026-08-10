// SPDX-License-Identifier: Elastic-2.0

//! Durable synthetic lab controller. External build work is available only
//! through the typed, idempotent broker boundary in this module.

use std::error::Error;
use std::fmt;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::canonical_json::encode_request;
use crate::program::RunnableProposal;
use crate::protocol::{
    ActionCoordinates, ActionOperation, ActionOutcome, ActionReceipt, ActionResponse, ActionStatus,
    DeniedResponse, EventType, Execution, GitSha1, LabBudget, LabEvent, LabRequest, LabResponse,
    ObserveRequest, ObservedResponse, OpaqueId, ResumeRequest, SelectRequest, SelectedResponse,
    Sha256Digest, UnitSnapshot, UnitState,
};
use crate::state::{
    AcquirePaths, AppendRecord, AttemptSnapshot, AttemptState, BrokerAuthority, ControllerRoot,
    JournalKind, StateError, StateStore, TransitionAttempt,
};
use crate::workspace_lease::{
    ActionId, AttemptId, BaseRevision, LeaseId, Mutation, RepoPath, Revision,
};
use crate::worktree::{WorktreeAllocator, WorktreeError, WorktreeReceipt, WorktreeRequest};

const ADMITTED_WORKTREE_BYTES: u64 = 64 * 1024 * 1024;

/// Coordinates for one idempotent, fixed synthetic build operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticBuildRequest {
    operation_id: OpaqueId,
    objective_id: OpaqueId,
    expected_base: GitSha1,
    budget: LabBudget,
    selection_digest: Sha256Digest,
}

impl SyntheticBuildRequest {
    pub fn operation_id(&self) -> &OpaqueId {
        &self.operation_id
    }
    pub fn objective_id(&self) -> &OpaqueId {
        &self.objective_id
    }
    pub fn expected_base(&self) -> &GitSha1 {
        &self.expected_base
    }
    pub fn budget(&self) -> &LabBudget {
        &self.budget
    }
    pub fn selection_digest(&self) -> &Sha256Digest {
        &self.selection_digest
    }
}

/// Evidence from a build that the broker actually completed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticBuildEvidence {
    digest: Sha256Digest,
    request_digest: Sha256Digest,
    output_digest: Sha256Digest,
    output_bytes: u64,
    output_truncated: bool,
    wall_accounting: AccountingCapability,
    cpu_accounting: AccountingCapability,
    pid_accounting: AccountingCapability,
    written_bytes_accounting: AccountingCapability,
    tree_accounting: AccountingCapability,
}

impl SyntheticBuildEvidence {
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
    pub fn request_digest(&self) -> &Sha256Digest {
        &self.request_digest
    }
    pub fn output_digest(&self) -> &Sha256Digest {
        &self.output_digest
    }
    pub const fn output_bytes(&self) -> u64 {
        self.output_bytes
    }
    pub const fn output_truncated(&self) -> bool {
        self.output_truncated
    }
    pub const fn wall_accounting(&self) -> AccountingCapability {
        self.wall_accounting
    }
    pub const fn cpu_accounting(&self) -> AccountingCapability {
        self.cpu_accounting
    }
    pub const fn pid_accounting(&self) -> AccountingCapability {
        self.pid_accounting
    }
    pub const fn written_bytes_accounting(&self) -> AccountingCapability {
        self.written_bytes_accounting
    }
    pub const fn tree_accounting(&self) -> AccountingCapability {
        self.tree_accounting
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountingCapability {
    Observed,
    Unavailable,
}

/// A deliberately non-diagnostic denial: provider, process and credential data
/// must not cross this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildUnavailable;

impl fmt::Display for BuildUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("synthetic build broker unavailable")
    }
}

impl Error for BuildUnavailable {}

/// Implementations must treat `operation_id` as an idempotency key. A retry
/// after an ambiguous crash must return the same evidence without duplicating
/// the external effect.
pub trait SyntheticBuildBroker {
    fn execute(
        &mut self,
        request: &SyntheticBuildRequest,
    ) -> Result<SyntheticBuildEvidence, BuildUnavailable>;
}

/// Production-safe default. It cannot manufacture build success.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableBuildBroker;

impl SyntheticBuildBroker for UnavailableBuildBroker {
    fn execute(
        &mut self,
        _request: &SyntheticBuildRequest,
    ) -> Result<SyntheticBuildEvidence, BuildUnavailable> {
        Err(BuildUnavailable)
    }
}

impl SyntheticBuildBroker for crate::build::BuildBroker {
    fn execute(
        &mut self,
        request: &SyntheticBuildRequest,
    ) -> Result<SyntheticBuildEvidence, BuildUnavailable> {
        let cpu_ms = request.budget.max_cpu_ms().get();
        let build_request = crate::build::BuildRequest {
            action_id: request.operation_id.as_str().to_owned(),
            recipe: crate::build::Recipe::Success,
            limits: crate::build::BuildLimits {
                wall_ms: request.budget.max_wall_ms().get(),
                term_grace_ms: 100,
                cpu_seconds: cpu_ms.saturating_add(999) / 1_000,
                output_bytes: request.budget.max_output_bytes().get(),
                file_bytes: request.budget.max_disk_bytes().get(),
                max_pids: u32::try_from(request.budget.max_pids().get())
                    .map_err(|_| BuildUnavailable)?,
                max_open_files: 32,
            },
        };
        let mutation = self
            .run(build_request.clone())
            .map_err(|_| BuildUnavailable)?;
        let receipt = mutation.receipt();
        if receipt.outcome != crate::build::BuildOutcome::Success {
            return Err(BuildUnavailable);
        }
        Ok(build_evidence(request, &build_request, receipt))
    }
}

#[derive(Debug)]
pub enum ControllerError {
    State(StateError),
    Domain(crate::protocol::ValidationError),
    InvalidCoordinate,
    Program(crate::program::ProgramError),
    Worktree(WorktreeError),
    InjectedFault(ControllerFault),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerFault {
    AfterLease,
}

impl fmt::Display for ControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("lab controller denied the operation")
    }
}

impl Error for ControllerError {}

impl From<StateError> for ControllerError {
    fn from(value: StateError) -> Self {
        Self::State(value)
    }
}

impl From<crate::protocol::ValidationError> for ControllerError {
    fn from(value: crate::protocol::ValidationError) -> Self {
        Self::Domain(value)
    }
}

impl From<crate::program::ProgramError> for ControllerError {
    fn from(value: crate::program::ProgramError) -> Self {
        Self::Program(value)
    }
}

impl From<WorktreeError> for ControllerError {
    fn from(value: WorktreeError) -> Self {
        Self::Worktree(value)
    }
}

/// Durable result of binding an admitted packet to an isolated checkout.
#[derive(Clone, Debug)]
pub struct AdmittedSelection {
    proposal: RunnableProposal,
    attempt: AttemptSnapshot,
    worktree: WorktreeReceipt,
}

impl AdmittedSelection {
    pub fn proposal(&self) -> &RunnableProposal {
        &self.proposal
    }
    pub fn attempt(&self) -> &AttemptSnapshot {
        &self.attempt
    }
    pub fn worktree(&self) -> &WorktreeReceipt {
        &self.worktree
    }
}

/// One durable controller instance. Reopening the same database reconstructs
/// all protocol-visible state from the journal.
pub struct LabController<B> {
    store: StateStore,
    authority: BrokerAuthority,
    expected_base: BaseRevision,
    allowed_paths: Vec<RepoPath>,
    broker: B,
    admitted_attempt: Option<(OpaqueId, AttemptId)>,
}

struct ActionTransition<'a> {
    request_id: &'a OpaqueId,
    objective_id: &'a OpaqueId,
    unit_id: &'a OpaqueId,
    checkpoint_id: Option<&'a OpaqueId>,
    expected_revision: u64,
    idempotency_key: &'a OpaqueId,
    operation: ActionOperation,
    target: AttemptState,
    attempt_id: &'a AttemptId,
}

impl<B: SyntheticBuildBroker> LabController<B> {
    pub fn open(
        state_path: impl AsRef<Path>,
        expected_base: GitSha1,
        allowed_paths: Vec<RepoPath>,
        broker: B,
    ) -> Result<Self, ControllerError> {
        if allowed_paths.is_empty() {
            return Err(ControllerError::InvalidCoordinate);
        }
        let root = ControllerRoot { seal: () };
        let store = StateStore::open(&root, state_path)?;
        let authority = store.broker_authority();
        let expected_base = BaseRevision::parse(expected_base.as_str())
            .map_err(|_| ControllerError::InvalidCoordinate)?;
        Ok(Self {
            store,
            authority,
            expected_base,
            allowed_paths,
            broker,
            admitted_attempt: None,
        })
    }

    pub fn handle(&mut self, request: LabRequest) -> Result<LabResponse, ControllerError> {
        self.handle_with_fault(request, None)
    }

    /// Bind the fixed current harness claim to durable state and one worktree.
    pub fn select_admitted_worktree(
        &mut self,
        repository: &Path,
        worktree_state: &Path,
    ) -> Result<AdmittedSelection, ControllerError> {
        if repository.canonicalize().ok()
            != std::env::current_dir()
                .ok()
                .and_then(|path| path.canonicalize().ok())
        {
            return Err(ControllerError::InvalidCoordinate);
        }
        let proposal = crate::program::select_admitted()?;
        if proposal.immutable_base().as_str() != self.expected_base.as_str() {
            return Err(ControllerError::InvalidCoordinate);
        }
        let proposal_paths = proposal
            .allowed_paths()
            .iter()
            .map(|path| RepoPath::parse(path.as_str().trim_end_matches('/')))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ControllerError::InvalidCoordinate)?;
        if proposal_paths != self.allowed_paths {
            return Err(ControllerError::InvalidCoordinate);
        }
        let attempt_id = AttemptId::parse(proposal.run_id().as_str().to_owned())
            .map_err(|_| ControllerError::InvalidCoordinate)?;
        self.store.create_attempt(
            &self.authority,
            attempt_id.clone(),
            proposal.objective_id().clone(),
            self.expected_base.clone(),
        )?;
        let admission_id = stable_id("admission", proposal.packet_digest().as_str());
        if !self.has_record(&attempt_id, &admission_id)? {
            let current = self.require_attempt(&attempt_id)?;
            self.append(
                &current,
                &admission_id,
                JournalKind::Evidence,
                proposal.packet_digest().clone(),
            )?;
        }
        let lease_id = LeaseId::parse(stable_id("lease", proposal.packet_digest().as_str()))
            .map_err(|_| ControllerError::InvalidCoordinate)?;
        let acquire_id = ActionId::parse(stable_id(
            "lease-acquire",
            proposal.packet_digest().as_str(),
        ))
        .map_err(|_| ControllerError::InvalidCoordinate)?;
        let acquired = self.store.acquire_paths(
            &self.authority,
            AcquirePaths {
                action_id: acquire_id,
                lease_id: lease_id.clone(),
                attempt_id: attempt_id.clone(),
                base_revision: self.expected_base.clone(),
                expected_revision: Revision::from_u64(1),
                paths: proposal_paths.clone(),
            },
        )?;
        let epoch = acquired.receipt().epoch;
        let verified = self.store.verify_active_lease(
            &self.authority,
            &attempt_id,
            &lease_id,
            epoch,
            &self.expected_base,
            proposal_paths,
        )?;
        let current = self.require_attempt(&attempt_id)?;
        if current.state() == AttemptState::Queued {
            self.transition(
                &current,
                AttemptState::Running,
                &stable_id("admitted-start", proposal.packet_digest().as_str()),
            )?;
        }
        let allocator = WorktreeAllocator::open(repository, worktree_state)?;
        let request = WorktreeRequest::new(verified, ADMITTED_WORKTREE_BYTES)?;
        let worktree = allocator.allocate(&request)?;
        let evidence_id = stable_id("allocation-evidence", proposal.packet_digest().as_str());
        if !self.has_record(&attempt_id, &evidence_id)? {
            let current = self.require_attempt(&attempt_id)?;
            self.append(
                &current,
                &evidence_id,
                JournalKind::Evidence,
                digest(worktree.request_digest()),
            )?;
        }
        let checkpoint_id = stable_id("allocation-checkpoint", proposal.packet_digest().as_str());
        if !self.has_record(&attempt_id, &checkpoint_id)? {
            let current = self.require_attempt(&attempt_id)?;
            self.append(
                &current,
                &checkpoint_id,
                JournalKind::Checkpoint,
                digest(&format!(
                    "{}:{}",
                    proposal.packet_digest().as_str(),
                    worktree.request_digest()
                )),
            )?;
        }
        let current = self.require_attempt(&attempt_id)?;
        if current.state() == AttemptState::Running {
            self.transition(
                &current,
                AttemptState::Paused,
                &stable_id("admitted-pause", proposal.packet_digest().as_str()),
            )?;
        }
        self.admitted_attempt = Some((proposal.objective_id().clone(), attempt_id.clone()));
        Ok(AdmittedSelection {
            proposal,
            attempt: self.require_attempt(&attempt_id)?,
            worktree,
        })
    }

    pub fn handle_with_fault(
        &mut self,
        request: LabRequest,
        fault: Option<ControllerFault>,
    ) -> Result<LabResponse, ControllerError> {
        let response = match &request {
            LabRequest::Select(value) => self.select(value, fault)?,
            LabRequest::Observe(value) => self.observe(value)?,
            LabRequest::Resume(value) => self.resume(value)?,
            LabRequest::Cancel(value) => self.cancel(value)?,
        };
        response.validate_for(&request)?;
        Ok(response)
    }

    fn select(
        &mut self,
        request: &SelectRequest,
        fault: Option<ControllerFault>,
    ) -> Result<LabResponse, ControllerError> {
        if request.execution() != Execution::Synthetic {
            return self.denied(
                request.request_id(),
                "inventory_unverified",
                "inventory execution requires verified host policy",
            );
        }
        if request.expected_base().as_str() != self.expected_base.as_str() {
            return self.denied(
                request.request_id(),
                "base_mismatch",
                "immutable base does not match controller base",
            );
        }
        let attempt_id = AttemptId::parse(request.objective_id().as_str().to_owned())
            .map_err(|_| ControllerError::InvalidCoordinate)?;
        self.store.create_attempt(
            &self.authority,
            attempt_id.clone(),
            request.objective_id().clone(),
            self.expected_base.clone(),
        )?;

        let selection_digest = digest_bytes(
            &encode_request(&LabRequest::Select(request.clone()))
                .map_err(|_| ControllerError::InvalidCoordinate)?,
        );
        let binding = self.store.append_record(
            &self.authority,
            AppendRecord {
                attempt_id: attempt_id.clone(),
                base_revision: self.expected_base.clone(),
                expected_revision: Revision::default(),
                record_id: ActionId::parse(stable_id(
                    "select-request",
                    request.objective_id().as_str(),
                ))
                .map_err(|_| ControllerError::InvalidCoordinate)?,
                kind: JournalKind::Evidence,
                payload_digest: selection_digest.clone(),
            },
        );
        match binding {
            Ok(_) => {}
            Err(StateError::RecordConflict) => {
                return self.denied(
                    request.request_id(),
                    "selection_conflict",
                    "selection differs from durable request",
                );
            }
            Err(error) => return Err(error.into()),
        }

        let mut current = self.require_attempt(&attempt_id)?;
        if current.state() == AttemptState::Queued {
            let lease_result = self.store.acquire_paths(
                &self.authority,
                AcquirePaths {
                    action_id: ActionId::parse(stable_id(
                        "lease-acquire",
                        request.objective_id().as_str(),
                    ))
                    .map_err(|_| ControllerError::InvalidCoordinate)?,
                    lease_id: LeaseId::parse(stable_id("lease", request.objective_id().as_str()))
                        .map_err(|_| ControllerError::InvalidCoordinate)?,
                    attempt_id: attempt_id.clone(),
                    base_revision: self.expected_base.clone(),
                    expected_revision: Revision::from_u64(1),
                    paths: self.allowed_paths.clone(),
                },
            );
            match lease_result {
                Ok(_) => {}
                Err(StateError::LeaseConflict { .. }) => {
                    return self.denied(
                        request.request_id(),
                        "lease_conflict",
                        "allowed paths overlap an active unit",
                    );
                }
                Err(error) => return Err(error.into()),
            }
            current = self.require_attempt(&attempt_id)?;
            if fault == Some(ControllerFault::AfterLease) {
                return Err(ControllerError::InjectedFault(ControllerFault::AfterLease));
            }
            self.transition(
                &current,
                AttemptState::Running,
                &stable_id("select-start", request.objective_id().as_str()),
            )?;
            current = self.require_attempt(&attempt_id)?;
        }

        if current.state() == AttemptState::Running
            && !self.has_record_prefix(&attempt_id, "resume-")?
        {
            let evidence_id = stable_id("build-evidence", request.objective_id().as_str());
            if !self.has_record(&attempt_id, &evidence_id)? {
                let operation_id = OpaqueId::new(stable_id("build", selection_digest.as_str()))?;
                let build_request = SyntheticBuildRequest {
                    operation_id,
                    objective_id: request.objective_id().clone(),
                    expected_base: request.expected_base().clone(),
                    budget: request.budget().clone(),
                    selection_digest: selection_digest.clone(),
                };
                let evidence = match self.broker.execute(&build_request) {
                    Ok(value) => value,
                    Err(_) => {
                        return self.denied(
                            request.request_id(),
                            "build_unavailable",
                            "synthetic build broker unavailable",
                        );
                    }
                };
                self.append(
                    &current,
                    &evidence_id,
                    JournalKind::Evidence,
                    evidence.digest().clone(),
                )?;
                current = self.require_attempt(&attempt_id)?;
            }
            let checkpoint = stable_id("checkpoint", request.objective_id().as_str());
            if !self.has_record(&attempt_id, &checkpoint)? {
                self.append(
                    &current,
                    &checkpoint,
                    JournalKind::Checkpoint,
                    digest("synthetic-checkpoint"),
                )?;
                current = self.require_attempt(&attempt_id)?;
            }
            self.transition(
                &current,
                AttemptState::Paused,
                &stable_id("select-pause", request.objective_id().as_str()),
            )?;
            current = self.require_attempt(&attempt_id)?;
        }

        Ok(LabResponse::Selected(SelectedResponse::new(
            request.request_id().clone(),
            self.snapshot(&current)?,
        )))
    }

    fn observe(&self, request: &ObserveRequest) -> Result<LabResponse, ControllerError> {
        let attempt_id = self.coordinates(request.objective_id(), request.unit_id())?;
        let current = self.require_attempt(&attempt_id)?;
        if request.after_sequence().get() > current.last_sequence() {
            return self.denied(
                request.request_id(),
                "cursor_conflict",
                "observe cursor is beyond durable state",
            );
        }
        let records = self.store.journal(&attempt_id)?;
        let mut events = Vec::new();
        for record in records
            .iter()
            .filter(|record| record.sequence() > request.after_sequence().get())
            .take(request.limit().get() as usize)
        {
            events.push(LabEvent::new(
                event_type(record.record_id().as_str())?,
                request.objective_id().clone(),
                request.unit_id().clone(),
                record.sequence(),
                record.attempt_revision().get(),
            )?);
        }
        let next = events
            .last()
            .map_or(request.after_sequence().get(), |event| {
                event.sequence().get()
            });
        Ok(LabResponse::Observed(ObservedResponse::new(
            request.request_id().clone(),
            self.snapshot(&current)?,
            events,
            next,
        )?))
    }

    fn resume(&mut self, request: &ResumeRequest) -> Result<LabResponse, ControllerError> {
        let attempt_id = self.coordinates(request.objective_id(), request.unit_id())?;
        let checkpoint = stable_id("checkpoint", request.objective_id().as_str());
        if request.checkpoint_id().as_str() != checkpoint {
            return self
                .action_denied_resume(request, "checkpoint does not match durable selection");
        }
        self.action_transition(ActionTransition {
            request_id: request.request_id(),
            objective_id: request.objective_id(),
            unit_id: request.unit_id(),
            checkpoint_id: Some(request.checkpoint_id()),
            expected_revision: request.expected_revision().get(),
            idempotency_key: request.idempotency_key(),
            operation: ActionOperation::Resume,
            target: AttemptState::Running,
            attempt_id: &attempt_id,
        })
    }

    fn cancel(
        &mut self,
        request: &crate::protocol::CancelRequest,
    ) -> Result<LabResponse, ControllerError> {
        let attempt_id = self.coordinates(request.objective_id(), request.unit_id())?;
        self.action_transition(ActionTransition {
            request_id: request.request_id(),
            objective_id: request.objective_id(),
            unit_id: request.unit_id(),
            checkpoint_id: None,
            expected_revision: request.expected_revision().get(),
            idempotency_key: request.idempotency_key(),
            operation: ActionOperation::Cancel,
            target: AttemptState::Cancelled,
            attempt_id: &attempt_id,
        })
    }

    fn action_transition(
        &mut self,
        coordinates: ActionTransition<'_>,
    ) -> Result<LabResponse, ControllerError> {
        let ActionTransition {
            request_id,
            objective_id,
            unit_id,
            checkpoint_id,
            expected_revision,
            idempotency_key,
            operation,
            target,
            attempt_id,
        } = coordinates;
        let prefix = match operation {
            ActionOperation::Resume => "resume",
            ActionOperation::Cancel => "cancel",
        };
        let action_text = stable_id(
            prefix,
            &format!("{}:{}", unit_id.as_str(), idempotency_key.as_str()),
        );
        let mutation = self.store.transition(
            &self.authority,
            TransitionAttempt {
                action_id: ActionId::parse(action_text.clone())
                    .map_err(|_| ControllerError::InvalidCoordinate)?,
                attempt_id: attempt_id.clone(),
                base_revision: self.expected_base.clone(),
                expected_revision: Revision::from_u64(expected_revision),
                target,
                event_digest: digest(prefix),
            },
        );
        let (status, effect_count, reason) = match mutation {
            Ok(Mutation::Applied(_)) => (ActionStatus::Accepted, 1, None),
            Ok(Mutation::Replayed(_)) => (ActionStatus::AlreadyApplied, 1, None),
            Err(StateError::RevisionConflict { .. }) => (
                ActionStatus::Conflict,
                0,
                Some("revision conflict".to_owned()),
            ),
            Err(StateError::TerminalImmutable | StateError::InvalidTransition { .. }) => (
                ActionStatus::Denied,
                0,
                Some("state transition denied".to_owned()),
            ),
            Err(error) => return Err(error.into()),
        };
        let current = self.require_attempt(attempt_id)?;
        let receipt = ActionReceipt::new(
            ActionCoordinates {
                action_id: OpaqueId::new(action_text)?,
                operation,
                objective_id: objective_id.clone(),
                unit_id: unit_id.clone(),
                checkpoint_id: checkpoint_id.cloned(),
                expected_revision,
                idempotency_key: idempotency_key.clone(),
            },
            ActionOutcome {
                status,
                effect_count,
                reason,
            },
        )?;
        Ok(LabResponse::Action(ActionResponse::new(
            request_id.clone(),
            receipt,
            self.snapshot(&current)?,
        )))
    }

    fn action_denied_resume(
        &self,
        request: &ResumeRequest,
        reason: &str,
    ) -> Result<LabResponse, ControllerError> {
        let attempt_id = self.coordinates(request.objective_id(), request.unit_id())?;
        let current = self.require_attempt(&attempt_id)?;
        let action_id = stable_id(
            "resume",
            &format!("{}:{}", request.unit_id(), request.idempotency_key()),
        );
        let receipt = ActionReceipt::new(
            ActionCoordinates {
                action_id: OpaqueId::new(action_id)?,
                operation: ActionOperation::Resume,
                objective_id: request.objective_id().clone(),
                unit_id: request.unit_id().clone(),
                checkpoint_id: Some(request.checkpoint_id().clone()),
                expected_revision: request.expected_revision().get(),
                idempotency_key: request.idempotency_key().clone(),
            },
            ActionOutcome {
                status: ActionStatus::Denied,
                effect_count: 0,
                reason: Some(reason.to_owned()),
            },
        )?;
        Ok(LabResponse::Action(ActionResponse::new(
            request.request_id().clone(),
            receipt,
            self.snapshot(&current)?,
        )))
    }

    fn transition(
        &mut self,
        current: &AttemptSnapshot,
        target: AttemptState,
        action_id: &str,
    ) -> Result<(), ControllerError> {
        self.store.transition(
            &self.authority,
            TransitionAttempt {
                action_id: ActionId::parse(action_id.to_owned())
                    .map_err(|_| ControllerError::InvalidCoordinate)?,
                attempt_id: current.attempt_id().clone(),
                base_revision: self.expected_base.clone(),
                expected_revision: current.revision(),
                target,
                event_digest: digest(action_id),
            },
        )?;
        Ok(())
    }

    fn append(
        &mut self,
        current: &AttemptSnapshot,
        record_id: &str,
        kind: JournalKind,
        payload_digest: Sha256Digest,
    ) -> Result<(), ControllerError> {
        self.store.append_record(
            &self.authority,
            AppendRecord {
                attempt_id: current.attempt_id().clone(),
                base_revision: self.expected_base.clone(),
                expected_revision: current.revision(),
                record_id: ActionId::parse(record_id.to_owned())
                    .map_err(|_| ControllerError::InvalidCoordinate)?,
                kind,
                payload_digest,
            },
        )?;
        Ok(())
    }

    fn require_attempt(&self, attempt_id: &AttemptId) -> Result<AttemptSnapshot, ControllerError> {
        self.store
            .attempt(attempt_id)?
            .ok_or(ControllerError::InvalidCoordinate)
    }

    fn coordinates(
        &self,
        objective: &OpaqueId,
        unit: &OpaqueId,
    ) -> Result<AttemptId, ControllerError> {
        if objective != unit {
            return Err(ControllerError::InvalidCoordinate);
        }
        if let Some((admitted_objective, attempt_id)) = &self.admitted_attempt
            && objective == admitted_objective
        {
            return Ok(attempt_id.clone());
        }
        AttemptId::parse(objective.as_str().to_owned())
            .map_err(|_| ControllerError::InvalidCoordinate)
    }

    fn has_record(&self, attempt: &AttemptId, id: &str) -> Result<bool, ControllerError> {
        Ok(self
            .store
            .journal(attempt)?
            .iter()
            .any(|record| record.record_id().as_str() == id))
    }

    fn has_record_prefix(
        &self,
        attempt: &AttemptId,
        prefix: &str,
    ) -> Result<bool, ControllerError> {
        Ok(self
            .store
            .journal(attempt)?
            .iter()
            .any(|record| record.record_id().as_str().starts_with(prefix)))
    }

    fn snapshot(&self, attempt: &AttemptSnapshot) -> Result<UnitSnapshot, ControllerError> {
        let checkpoint = if attempt.state() == AttemptState::Paused {
            Some(OpaqueId::new(stable_id(
                "checkpoint",
                attempt.objective_id().as_str(),
            ))?)
        } else {
            None
        };
        Ok(UnitSnapshot::new(
            attempt.objective_id().clone(),
            attempt.objective_id().clone(),
            match attempt.state() {
                AttemptState::Queued => UnitState::Queued,
                AttemptState::Running => UnitState::Running,
                AttemptState::Paused => UnitState::Paused,
                AttemptState::Succeeded => UnitState::Succeeded,
                AttemptState::Failed => UnitState::Failed,
                AttemptState::Blocked => UnitState::Blocked,
                AttemptState::Cancelled => UnitState::Cancelled,
            },
            attempt.revision().get(),
            checkpoint,
            attempt.last_sequence(),
        )?)
    }

    fn denied(
        &self,
        request_id: &OpaqueId,
        code: &str,
        reason: &str,
    ) -> Result<LabResponse, ControllerError> {
        Ok(LabResponse::Denied(DeniedResponse::new(
            request_id.clone(),
            OpaqueId::new(code)?,
            reason,
        )?))
    }
}

fn stable_id(prefix: &str, material: &str) -> String {
    let hash = Sha256::digest(material.as_bytes());
    format!("{prefix}-{}", hex::encode(&hash[..16]))
}

fn digest(material: &str) -> Sha256Digest {
    digest_bytes(material.as_bytes())
}

fn digest_bytes(material: &[u8]) -> Sha256Digest {
    Sha256Digest::new(hex::encode(Sha256::digest(material)))
        .unwrap_or_else(|_| unreachable!("SHA-256 hex is always a valid digest"))
}

fn build_evidence(
    request: &SyntheticBuildRequest,
    build_request: &crate::build::BuildRequest,
    receipt: &crate::build::BuildReceipt,
) -> SyntheticBuildEvidence {
    let mut request_binding = EvidenceBinding::new("automonique.synthetic-build-request/v1");
    request_binding.text("operation_id", request.operation_id.as_str());
    request_binding.text("selection_digest", request.selection_digest.as_str());
    request_binding.text("objective_id", request.objective_id.as_str());
    request_binding.text("immutable_base", request.expected_base.as_str());
    request_binding.text("execution", "synthetic");
    request_binding.text("provider_policy", "synthetic");
    request_binding.u64("budget.max_wall_ms", request.budget.max_wall_ms().get());
    request_binding.u64("budget.max_cpu_ms", request.budget.max_cpu_ms().get());
    request_binding.u64(
        "budget.max_disk_bytes",
        request.budget.max_disk_bytes().get(),
    );
    request_binding.u64(
        "budget.max_output_bytes",
        request.budget.max_output_bytes().get(),
    );
    request_binding.u64("budget.max_pids", request.budget.max_pids().get());
    request_binding.u64(
        "budget.max_model_calls",
        request.budget.max_model_calls().get(),
    );
    request_binding.u64(
        "budget.max_cost_microunits",
        request.budget.max_cost_microunits().get(),
    );
    request_binding.text(
        "budget.enforcement",
        match request.budget.enforcement() {
            crate::protocol::BudgetEnforcement::SyntheticInProcess => "synthetic_in_process",
            crate::protocol::BudgetEnforcement::HostBrokerRequired => "host_broker_required",
        },
    );
    request_binding.text("build.action_id", &build_request.action_id);
    request_binding.text("build.recipe", recipe_wire(build_request.recipe));
    request_binding.u64("limits.wall_ms", build_request.limits.wall_ms);
    request_binding.u64("limits.term_grace_ms", build_request.limits.term_grace_ms);
    request_binding.u64("limits.cpu_seconds", build_request.limits.cpu_seconds);
    request_binding.u64("limits.output_bytes", build_request.limits.output_bytes);
    request_binding.u64("limits.file_bytes", build_request.limits.file_bytes);
    request_binding.u64("limits.max_pids", u64::from(build_request.limits.max_pids));
    request_binding.u64("limits.max_open_files", build_request.limits.max_open_files);
    let request_digest = request_binding.finish();

    let mut output_binding = EvidenceBinding::new("automonique.synthetic-output/v1");
    output_binding.bytes("stdout", &receipt.stdout);
    output_binding.bytes("stderr", &receipt.stderr);
    let output_digest = output_binding.finish();
    let output_bytes = u64::try_from(receipt.stdout.len().saturating_add(receipt.stderr.len()))
        .unwrap_or(u64::MAX);
    let output_truncated = receipt.outcome == crate::build::BuildOutcome::OutputLimit;

    let mut evidence = EvidenceBinding::new("automonique.synthetic-build-evidence/v1");
    evidence.text("request_digest", request_digest.as_str());
    evidence.text("immutable_base", request.expected_base.as_str());
    evidence.text("operation_id", request.operation_id.as_str());
    evidence.text("selection_digest", request.selection_digest.as_str());
    evidence.text("outcome", outcome_wire(receipt.outcome));
    evidence.optional_i32("exit_code", receipt.exit_code);
    evidence.optional_i32("signal", receipt.signal);
    evidence.u64("wall_ms", receipt.wall_ms);
    evidence.text("output_digest", output_digest.as_str());
    evidence.u64("output_bytes", output_bytes);
    evidence.text(
        "output_truncated",
        if output_truncated { "true" } else { "false" },
    );
    evidence.text("wall_accounting", "observed");
    evidence.text("cpu_accounting", "unavailable");
    evidence.text("pid_accounting", "unavailable");
    evidence.text("written_bytes_accounting", "unavailable");
    evidence.text("tree_accounting", "unavailable");
    SyntheticBuildEvidence {
        digest: evidence.finish(),
        request_digest,
        output_digest,
        output_bytes,
        output_truncated,
        wall_accounting: AccountingCapability::Observed,
        cpu_accounting: AccountingCapability::Unavailable,
        pid_accounting: AccountingCapability::Unavailable,
        written_bytes_accounting: AccountingCapability::Unavailable,
        tree_accounting: AccountingCapability::Unavailable,
    }
}

struct EvidenceBinding(Sha256);

impl EvidenceBinding {
    fn new(schema: &str) -> Self {
        let mut binding = Self(Sha256::new());
        binding.text("schema", schema);
        binding
    }

    fn text(&mut self, name: &str, value: &str) {
        self.bytes(name, value.as_bytes());
    }

    fn bytes(&mut self, name: &str, value: &[u8]) {
        self.0.update((name.len() as u64).to_be_bytes());
        self.0.update(name.as_bytes());
        self.0.update((value.len() as u64).to_be_bytes());
        self.0.update(value);
    }

    fn u64(&mut self, name: &str, value: u64) {
        self.bytes(name, &value.to_be_bytes());
    }

    fn optional_i32(&mut self, name: &str, value: Option<i32>) {
        match value {
            Some(value) => self.bytes(name, &[b"some".as_slice(), &value.to_be_bytes()].concat()),
            None => self.text(name, "none"),
        }
    }

    fn finish(self) -> Sha256Digest {
        Sha256Digest::new(hex::encode(self.0.finalize()))
            .unwrap_or_else(|_| unreachable!("SHA-256 hex is always a valid digest"))
    }
}

fn recipe_wire(recipe: crate::build::Recipe) -> &'static str {
    match recipe {
        crate::build::Recipe::Success => "success",
        crate::build::Recipe::Sleep => "sleep",
        crate::build::Recipe::CpuHog => "cpu_hog",
        crate::build::Recipe::OutputFlood => "output_flood",
        crate::build::Recipe::DiskFlood => "disk_flood",
        crate::build::Recipe::PidBurst => "pid_burst",
        crate::build::Recipe::Descendant => "descendant",
        crate::build::Recipe::OpenFiles => "open_files",
    }
}

fn outcome_wire(outcome: crate::build::BuildOutcome) -> &'static str {
    match outcome {
        crate::build::BuildOutcome::Success => "success",
        crate::build::BuildOutcome::WallLimit => "wall_limit",
        crate::build::BuildOutcome::CpuLimit => "cpu_limit",
        crate::build::BuildOutcome::OutputLimit => "output_limit",
        crate::build::BuildOutcome::DiskLimit => "disk_limit",
        crate::build::BuildOutcome::PidLimit => "pid_limit",
        crate::build::BuildOutcome::FileCountLimit => "file_count_limit",
        crate::build::BuildOutcome::Failed => "failed",
    }
}

fn event_type(record_id: &str) -> Result<EventType, crate::protocol::ValidationError> {
    let value = if record_id.starts_with("select-start-") {
        "unit.selected"
    } else if record_id.starts_with("resume-") {
        "unit.resumed"
    } else if record_id.starts_with("cancel-") {
        "unit.cancelled"
    } else if record_id.starts_with("checkpoint-") {
        "checkpoint.ready"
    } else if record_id.starts_with("build-evidence-") {
        "evidence.recorded"
    } else {
        "journal.recorded"
    };
    EventType::from_wire(value)
}
