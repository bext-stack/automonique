// SPDX-License-Identifier: Elastic-2.0

//! One bounded Stage-A scheduler tick over durable-store traits.
//!
//! This crate performs no external I/O and exposes no executor extension
//! point. Its only executor is a deterministic fixture that produces a closed
//! terminal result and a fake effect intent. The durable implementation remains
//! responsible for fencing, idempotency, atomic terminal/effect commit, and
//! reconciliation evidence.

pub mod scheduler_conformance;

use std::error::Error;
use std::fmt;

const MAX_ID_BYTES: usize = 160;

/// Exact scheduler lease authority supplied by the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchedulerFence {
    generation_id: String,
    holder_id: String,
    epoch: u64,
}

impl SchedulerFence {
    /// Construct a non-zero, bounded fence coordinate.
    pub fn new(
        generation_id: impl Into<String>,
        holder_id: impl Into<String>,
        epoch: u64,
    ) -> Result<Self, CoordinateError> {
        let generation_id = generation_id.into();
        let holder_id = holder_id.into();
        validate_id(&generation_id, "generation_id")?;
        validate_id(&holder_id, "holder_id")?;
        if epoch == 0 {
            return Err(CoordinateError::ZeroEpoch);
        }
        Ok(Self {
            generation_id,
            holder_id,
            epoch,
        })
    }

    /// Generation coordinate.
    #[must_use]
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }

    /// Lease holder coordinate.
    #[must_use]
    pub fn holder_id(&self) -> &str {
        &self.holder_id
    }

    /// Fencing epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Closed deterministic programs accepted by the fixture executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeProgram {
    /// Produce the fixed successful terminal result.
    Succeed,
    /// Produce the fixed failed terminal result.
    Fail,
}

/// One durable item already admitted for Stage-A fixture execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableWorkItem {
    work_id: String,
    request_key: String,
    program: FakeProgram,
}

impl DurableWorkItem {
    /// Construct one bounded fixture item.
    pub fn new(
        work_id: impl Into<String>,
        request_key: impl Into<String>,
        program: FakeProgram,
    ) -> Result<Self, CoordinateError> {
        let work_id = work_id.into();
        let request_key = request_key.into();
        validate_id(&work_id, "work_id")?;
        validate_id(&request_key, "request_key")?;
        Ok(Self {
            work_id,
            request_key,
            program,
        })
    }

    /// Durable work identity.
    #[must_use]
    pub fn work_id(&self) -> &str {
        &self.work_id
    }

    /// Stable request/idempotency identity.
    #[must_use]
    pub fn request_key(&self) -> &str {
        &self.request_key
    }

    /// Closed fixture program.
    #[must_use]
    pub const fn program(&self) -> FakeProgram {
        self.program
    }
}

/// Coordinate validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinateError {
    /// A named field was empty, too long, or contained control characters.
    InvalidField(&'static str),
    /// Fencing epoch zero carries no authority.
    ZeroEpoch,
}

impl fmt::Display for CoordinateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(formatter, "invalid coordinate: {field}"),
            Self::ZeroEpoch => formatter.write_str("scheduler fence epoch is zero"),
        }
    }
}

impl Error for CoordinateError {}

/// Closed terminal vocabulary emitted by the deterministic fixture executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeTerminal {
    /// Fixed successful result.
    Succeeded,
    /// Fixed failure result.
    Failed,
}

/// A fake effect intent. It is durable test evidence, not an external effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FakeEffectIntent {
    idempotency_key: String,
}

impl FakeEffectIntent {
    /// Stable key derived only from the durable request identity.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
}

/// Terminal record passed to one atomic durable commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalCommit {
    work_id: String,
    request_key: String,
    terminal: FakeTerminal,
    fake_effect: FakeEffectIntent,
}

impl TerminalCommit {
    /// Work identity.
    #[must_use]
    pub fn work_id(&self) -> &str {
        &self.work_id
    }

    /// Stable request identity.
    #[must_use]
    pub fn request_key(&self) -> &str {
        &self.request_key
    }

    /// Deterministic terminal outcome.
    #[must_use]
    pub const fn terminal(&self) -> FakeTerminal {
        self.terminal
    }

    /// Fake-only effect intent committed with the terminal transition.
    #[must_use]
    pub const fn fake_effect(&self) -> &FakeEffectIntent {
        &self.fake_effect
    }
}

/// Durable identity of an atomically stored terminal and fake receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    terminal_id: String,
    fake_effect_receipt_id: String,
}

impl CommitReceipt {
    /// Construct a receipt returned by a durable adapter.
    pub fn new(
        terminal_id: impl Into<String>,
        fake_effect_receipt_id: impl Into<String>,
    ) -> Result<Self, CoordinateError> {
        let terminal_id = terminal_id.into();
        let fake_effect_receipt_id = fake_effect_receipt_id.into();
        validate_id(&terminal_id, "terminal_id")?;
        validate_id(&fake_effect_receipt_id, "fake_effect_receipt_id")?;
        Ok(Self {
            terminal_id,
            fake_effect_receipt_id,
        })
    }

    /// Terminal record identity.
    #[must_use]
    pub fn terminal_id(&self) -> &str {
        &self.terminal_id
    }

    /// Fake effect receipt identity.
    #[must_use]
    pub fn fake_effect_receipt_id(&self) -> &str {
        &self.fake_effect_receipt_id
    }
}

/// Durable claim result. A prior ambiguous execution is never returned as new.
///
/// A generic queue poll is not required to rediscover work that was already
/// committed before a process restart. It may omit that terminal item and
/// return [`ClaimOutcome::Empty`] or the next ready item. Exact replay is
/// available only when the adapter has a stable operation coordinate that
/// identifies the prior terminal receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimOutcome {
    /// No admitted fixture item is ready.
    Empty,
    /// Exactly one newly fenced fixture item was claimed.
    Claimed(DurableWorkItem),
    /// The adapter identified this same stable operation as already terminal.
    TerminalReplay(CommitReceipt),
    /// Prior execution liveness/outcome must be reconciled before progress.
    ReconciliationRequired(Reconciliation),
}

/// Why a claim cannot safely be repeated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reconciliation {
    work_id: String,
    reason: ReconciliationReason,
}

impl Reconciliation {
    /// Construct bounded reconciliation evidence.
    pub fn new(
        work_id: impl Into<String>,
        reason: ReconciliationReason,
    ) -> Result<Self, CoordinateError> {
        let work_id = work_id.into();
        validate_id(&work_id, "work_id")?;
        Ok(Self { work_id, reason })
    }

    /// Affected work identity.
    #[must_use]
    pub fn work_id(&self) -> &str {
        &self.work_id
    }

    /// Exact ambiguity class.
    #[must_use]
    pub const fn reason(&self) -> ReconciliationReason {
        self.reason
    }
}

/// Closed ambiguity classes for this slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationReason {
    /// A claim exists but no authoritative execution outcome is durable.
    ClaimedOutcomeUnknown,
}

/// Durable adapter failure. Retry and fencing are not conflated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableError {
    /// The supplied holder/epoch is no longer live; reacquisition is external.
    StaleFence,
    /// A bounded later tick may retry the same durable operation.
    TemporarilyUnavailable,
    /// Durable state violates the adapter contract and must not be retried.
    InvariantViolation,
}

/// Result of atomically storing terminal state and its fake effect receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    /// This call created the one terminal transition and fake receipt.
    Committed(CommitReceipt),
    /// An exact earlier commit is replayed.
    Replayed(CommitReceipt),
}

/// Minimal durable operations needed by one bounded tick.
pub trait DurableScheduler {
    /// Renew and admit the exact caller-supplied scheduler fence.
    fn renew_fence(&mut self, fence: &SchedulerFence) -> Result<(), DurableError>;

    /// Claim at most one durable item under that exact fence.
    ///
    /// Completed work may be absent after restart. An adapter returns
    /// [`ClaimOutcome::TerminalReplay`] only when its own stable operation
    /// coordinate proves which exact receipt is being replayed.
    fn claim_one(&mut self, fence: &SchedulerFence) -> Result<ClaimOutcome, DurableError>;

    /// Atomically commit terminal state and one fake effect receipt.
    fn commit_terminal(
        &mut self,
        fence: &SchedulerFence,
        terminal: &TerminalCommit,
    ) -> Result<CommitOutcome, DurableError>;
}

/// Durable operation that needs a bounded retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryStage {
    /// Fence renewal/admission could not complete.
    RenewFence,
    /// Claim could not complete.
    Claim,
    /// Atomic terminal/fake-receipt commit could not complete.
    Commit,
}

/// Observable result of one bounded controller tick.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TickOutcome {
    /// Fence was renewed, but no fixture item was ready.
    Idle,
    /// This tick durably committed one terminal and fake receipt.
    Completed(CommitReceipt),
    /// The adapter explicitly replayed an exact prior terminal/fake receipt.
    Replayed(CommitReceipt),
    /// The caller must acquire fresh authority; this tick did not continue.
    FenceRejected { stage: RetryStage },
    /// A transient durable failure permits a later bounded retry.
    RetryRequired { stage: RetryStage },
    /// Ambiguous prior execution requires explicit reconciliation, not retry.
    ReconciliationRequired(Reconciliation),
}

/// Non-retryable controller failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerError {
    /// The durable adapter reported structurally inconsistent state.
    DurableInvariant { stage: RetryStage },
}

impl fmt::Display for ControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DurableInvariant { stage } => {
                write!(formatter, "durable invariant failed during {stage:?}")
            }
        }
    }
}

impl Error for ControllerError {}

/// Closed deterministic executor. It cannot run processes or external effects.
#[derive(Clone, Debug, Default)]
pub struct DeterministicFakeExecutor {
    executions: u64,
}

impl DeterministicFakeExecutor {
    fn execute(&mut self, work: &DurableWorkItem) -> TerminalCommit {
        self.executions = self.executions.saturating_add(1);
        let terminal = match work.program {
            FakeProgram::Succeed => FakeTerminal::Succeeded,
            FakeProgram::Fail => FakeTerminal::Failed,
        };
        TerminalCommit {
            work_id: work.work_id.clone(),
            request_key: work.request_key.clone(),
            terminal,
            fake_effect: FakeEffectIntent {
                idempotency_key: format!("fixture-receipt:{}", work.request_key),
            },
        }
    }

    /// Number of fixture executions performed by this controller instance.
    #[must_use]
    pub const fn execution_count(&self) -> u64 {
        self.executions
    }
}

/// One-tick Stage-A scheduler/controller.
#[derive(Clone, Debug, Default)]
pub struct Controller {
    executor: DeterministicFakeExecutor,
}

impl Controller {
    /// Construct an idle controller.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            executor: DeterministicFakeExecutor { executions: 0 },
        }
    }

    /// Execute at most one durable fixture item.
    pub fn tick(
        &mut self,
        durable: &mut impl DurableScheduler,
        fence: &SchedulerFence,
    ) -> Result<TickOutcome, ControllerError> {
        match durable.renew_fence(fence) {
            Ok(()) => {}
            Err(error) => return classify_error(error, RetryStage::RenewFence),
        }
        let claim = match durable.claim_one(fence) {
            Ok(claim) => claim,
            Err(error) => return classify_error(error, RetryStage::Claim),
        };
        let work = match claim {
            ClaimOutcome::Empty => return Ok(TickOutcome::Idle),
            ClaimOutcome::TerminalReplay(receipt) => return Ok(TickOutcome::Replayed(receipt)),
            ClaimOutcome::ReconciliationRequired(reconciliation) => {
                return Ok(TickOutcome::ReconciliationRequired(reconciliation));
            }
            ClaimOutcome::Claimed(work) => work,
        };
        let terminal = self.executor.execute(&work);
        let committed = match durable.commit_terminal(fence, &terminal) {
            Ok(committed) => committed,
            Err(error) => return classify_error(error, RetryStage::Commit),
        };
        Ok(match committed {
            CommitOutcome::Committed(receipt) => TickOutcome::Completed(receipt),
            CommitOutcome::Replayed(receipt) => TickOutcome::Replayed(receipt),
        })
    }

    /// Number of deterministic fake executions performed.
    #[must_use]
    pub const fn fake_execution_count(&self) -> u64 {
        self.executor.execution_count()
    }
}

fn classify_error(error: DurableError, stage: RetryStage) -> Result<TickOutcome, ControllerError> {
    match error {
        DurableError::StaleFence => Ok(TickOutcome::FenceRejected { stage }),
        DurableError::TemporarilyUnavailable => Ok(TickOutcome::RetryRequired { stage }),
        DurableError::InvariantViolation => Err(ControllerError::DurableInvariant { stage }),
    }
}

fn validate_id(value: &str, field: &'static str) -> Result<(), CoordinateError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES || value.chars().any(char::is_control) {
        Err(CoordinateError::InvalidField(field))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MemoryDurable {
        expected_fence: Option<SchedulerFence>,
        work: Option<DurableWorkItem>,
        active: Option<String>,
        terminals: BTreeMap<String, (TerminalCommit, CommitReceipt)>,
        fail_renew: Option<DurableError>,
        fail_claim: Option<DurableError>,
        fail_commit: Option<DurableError>,
        replay_terminal_on_claim: bool,
        commit_calls: u64,
    }

    impl MemoryDurable {
        fn with(fence: &SchedulerFence, work: Option<DurableWorkItem>) -> Self {
            Self {
                expected_fence: Some(fence.clone()),
                work,
                ..Self::default()
            }
        }

        fn receipt(work: &DurableWorkItem) -> CommitReceipt {
            CommitReceipt::new(
                format!("terminal:{}", work.request_key()),
                format!("fake-effect:{}", work.request_key()),
            )
            .expect("fixture receipt")
        }

        fn terminal_count(&self) -> usize {
            self.terminals.len()
        }
    }

    impl DurableScheduler for MemoryDurable {
        fn renew_fence(&mut self, fence: &SchedulerFence) -> Result<(), DurableError> {
            if let Some(error) = self.fail_renew.take() {
                return Err(error);
            }
            if self.expected_fence.as_ref() != Some(fence) {
                return Err(DurableError::StaleFence);
            }
            Ok(())
        }

        fn claim_one(&mut self, _fence: &SchedulerFence) -> Result<ClaimOutcome, DurableError> {
            if let Some(error) = self.fail_claim.take() {
                return Err(error);
            }
            let Some(work) = self.work.clone() else {
                return Ok(ClaimOutcome::Empty);
            };
            if let Some((_, receipt)) = self.terminals.get(work.request_key()) {
                return Ok(if self.replay_terminal_on_claim {
                    ClaimOutcome::TerminalReplay(receipt.clone())
                } else {
                    ClaimOutcome::Empty
                });
            }
            if self.active.as_deref() == Some(work.work_id()) {
                return Ok(ClaimOutcome::ReconciliationRequired(
                    Reconciliation::new(
                        work.work_id().to_owned(),
                        ReconciliationReason::ClaimedOutcomeUnknown,
                    )
                    .expect("fixture reconciliation"),
                ));
            }
            self.active = Some(work.work_id().to_owned());
            Ok(ClaimOutcome::Claimed(work))
        }

        fn commit_terminal(
            &mut self,
            _fence: &SchedulerFence,
            terminal: &TerminalCommit,
        ) -> Result<CommitOutcome, DurableError> {
            self.commit_calls += 1;
            if let Some(error) = self.fail_commit.take() {
                return Err(error);
            }
            if let Some((recorded, receipt)) = self.terminals.get(terminal.request_key()) {
                return if recorded == terminal {
                    Ok(CommitOutcome::Replayed(receipt.clone()))
                } else {
                    Err(DurableError::InvariantViolation)
                };
            }
            let work = self.work.as_ref().ok_or(DurableError::InvariantViolation)?;
            if self.active.as_deref() != Some(terminal.work_id())
                || work.request_key() != terminal.request_key()
            {
                return Err(DurableError::InvariantViolation);
            }
            let receipt = Self::receipt(work);
            self.terminals.insert(
                terminal.request_key().to_owned(),
                (terminal.clone(), receipt.clone()),
            );
            self.active = None;
            Ok(CommitOutcome::Committed(receipt))
        }
    }

    fn fence() -> SchedulerFence {
        SchedulerFence::new("generation-a", "holder-a", 7).expect("fence")
    }

    fn work() -> DurableWorkItem {
        DurableWorkItem::new("work-a", "request-a", FakeProgram::Succeed).expect("work")
    }

    #[test]
    fn zero_and_one_item_ticks_are_bounded() {
        let fence = fence();
        let mut controller = Controller::new();
        let mut empty = MemoryDurable::with(&fence, None);
        assert_eq!(
            controller.tick(&mut empty, &fence).expect("idle"),
            TickOutcome::Idle
        );
        assert_eq!(controller.fake_execution_count(), 0);

        let item = work();
        let expected = MemoryDurable::receipt(&item);
        let mut one = MemoryDurable::with(&fence, Some(item));
        assert_eq!(
            controller.tick(&mut one, &fence).expect("complete"),
            TickOutcome::Completed(expected)
        );
        assert_eq!(controller.fake_execution_count(), 1);
        assert_eq!(one.terminal_count(), 1);
        assert_eq!(one.commit_calls, 1);
    }

    #[test]
    fn stable_operation_replays_when_adapter_returns_its_exact_receipt() {
        let fence = fence();
        let item = work();
        let expected = MemoryDurable::receipt(&item);
        let mut durable = MemoryDurable::with(&fence, Some(item));
        durable.replay_terminal_on_claim = true;
        let mut controller = Controller::new();
        assert_eq!(
            controller.tick(&mut durable, &fence).expect("first"),
            TickOutcome::Completed(expected.clone())
        );
        assert_eq!(
            controller.tick(&mut durable, &fence).expect("replay"),
            TickOutcome::Replayed(expected)
        );
        assert_eq!(controller.fake_execution_count(), 1);
        assert_eq!(durable.terminal_count(), 1);
        assert_eq!(durable.commit_calls, 1);
    }

    #[test]
    fn crash_after_claim_before_execution_requires_reconciliation() {
        let fence = fence();
        let mut durable = MemoryDurable::with(&fence, Some(work()));
        let mut controller = Controller::new();
        durable.renew_fence(&fence).expect("fence before crash");
        assert!(matches!(
            durable
                .claim_one(&fence)
                .expect("durable claim before crash"),
            ClaimOutcome::Claimed(_)
        ));
        assert_eq!(controller.fake_execution_count(), 0);
        assert!(matches!(
            controller.tick(&mut durable, &fence).expect("classified"),
            TickOutcome::ReconciliationRequired(Reconciliation {
                reason: ReconciliationReason::ClaimedOutcomeUnknown,
                ..
            })
        ));
        assert_eq!(durable.terminal_count(), 0);
    }

    #[test]
    fn crash_after_execution_before_commit_requires_reconciliation() {
        let fence = fence();
        let mut durable = MemoryDurable::with(&fence, Some(work()));
        let mut controller = Controller::new();
        durable.renew_fence(&fence).expect("fence before crash");
        let ClaimOutcome::Claimed(claimed) = durable
            .claim_one(&fence)
            .expect("durable claim before crash")
        else {
            panic!("fixture work was not claimed")
        };
        let _uncommitted = controller.executor.execute(&claimed);
        assert_eq!(controller.fake_execution_count(), 1);
        assert!(matches!(
            controller.tick(&mut durable, &fence).expect("classified"),
            TickOutcome::ReconciliationRequired(_)
        ));
        assert_eq!(controller.fake_execution_count(), 1);
        assert_eq!(durable.terminal_count(), 0);
    }

    #[test]
    fn crash_after_commit_never_duplicates_and_a_restart_may_idle() {
        let fence = fence();
        let item = work();
        let expected = MemoryDurable::receipt(&item);
        let mut durable = MemoryDurable::with(&fence, Some(item));
        let mut controller = Controller::new();
        durable.renew_fence(&fence).expect("fence before crash");
        let ClaimOutcome::Claimed(claimed) = durable
            .claim_one(&fence)
            .expect("durable claim before crash")
        else {
            panic!("fixture work was not claimed")
        };
        let terminal = controller.executor.execute(&claimed);
        assert_eq!(
            durable
                .commit_terminal(&fence, &terminal)
                .expect("durable commit before crash"),
            CommitOutcome::Committed(expected)
        );
        assert_eq!(durable.terminal_count(), 1);
        assert_eq!(controller.fake_execution_count(), 1);

        let mut restarted = Controller::new();
        assert_eq!(
            restarted
                .tick(&mut durable, &fence)
                .expect("poll after restart"),
            TickOutcome::Idle
        );
        assert_eq!(restarted.fake_execution_count(), 0);
        assert_eq!(durable.terminal_count(), 1);
        assert_eq!(durable.commit_calls, 1);
    }

    #[test]
    fn stale_fence_stops_before_claim_or_execution() {
        let live = fence();
        let stale = SchedulerFence::new("generation-a", "holder-a", 6).expect("stale");
        let mut durable = MemoryDurable::with(&live, Some(work()));
        let mut controller = Controller::new();
        assert_eq!(
            controller
                .tick(&mut durable, &stale)
                .expect("typed refusal"),
            TickOutcome::FenceRejected {
                stage: RetryStage::RenewFence
            }
        );
        assert!(durable.active.is_none());
        assert_eq!(controller.fake_execution_count(), 0);
    }

    #[test]
    fn retry_reconciliation_and_invariant_failure_remain_distinct() {
        let fence = fence();
        let mut retry = MemoryDurable::with(&fence, Some(work()));
        retry.fail_claim = Some(DurableError::TemporarilyUnavailable);
        let mut controller = Controller::new();
        assert_eq!(
            controller.tick(&mut retry, &fence).expect("retry outcome"),
            TickOutcome::RetryRequired {
                stage: RetryStage::Claim
            }
        );

        let mut reconcile = MemoryDurable::with(&fence, Some(work()));
        reconcile.active = Some("work-a".to_owned());
        assert!(matches!(
            controller
                .tick(&mut reconcile, &fence)
                .expect("reconciliation outcome"),
            TickOutcome::ReconciliationRequired(_)
        ));

        let mut broken = MemoryDurable::with(&fence, Some(work()));
        broken.fail_renew = Some(DurableError::InvariantViolation);
        assert_eq!(
            controller.tick(&mut broken, &fence),
            Err(ControllerError::DurableInvariant {
                stage: RetryStage::RenewFence
            })
        );
    }

    #[test]
    fn failed_fixture_is_still_one_terminal_and_one_fake_receipt() {
        let fence = fence();
        let item = DurableWorkItem::new("work-f", "request-f", FakeProgram::Fail).expect("work");
        let mut durable = MemoryDurable::with(&fence, Some(item));
        let mut controller = Controller::new();
        assert!(matches!(
            controller.tick(&mut durable, &fence).expect("completed"),
            TickOutcome::Completed(_)
        ));
        let (terminal, _) = durable.terminals.get("request-f").expect("terminal");
        assert_eq!(terminal.terminal(), FakeTerminal::Failed);
        assert_eq!(
            terminal.fake_effect().idempotency_key(),
            "fixture-receipt:request-f"
        );
        assert_eq!(durable.terminal_count(), 1);
        assert_eq!(durable.commit_calls, 1);
    }
}
