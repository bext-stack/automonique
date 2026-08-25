// SPDX-License-Identifier: Elastic-2.0

//! Transaction-shaped orchestration for one generation reload epoch.
//!
//! Process, lease, transport and execution-host operations are deliberately
//! hooks. The orchestrator owns their order, the durable phase record and the
//! failure partition: before transfer the source remains authoritative; after
//! transfer a failure must either return authority or be recorded as requiring
//! external recovery. A hook cannot skip a phase or report success without the
//! corresponding audit transition.

use std::error::Error;
use std::fmt;

use automonique_store::reload_audit::{
    AdvanceReload, BeginReload, ReloadAudit, ReloadAuditError, ReloadPhase, ReloadRecord,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReloadRefusal {
    category: &'static str,
}

impl ReloadRefusal {
    #[must_use]
    pub const fn new(category: &'static str) -> Self {
        Self { category }
    }

    #[must_use]
    pub const fn category(self) -> &'static str {
        self.category
    }
}

/// Side effects the active generation performs around the durable state
/// machine. Each operation must be bounded and idempotent under its reload ID.
pub trait ReloadHooks {
    fn verify_target(&mut self) -> Result<(), ReloadRefusal>;
    fn spawn_candidate(&mut self) -> Result<(), ReloadRefusal>;
    fn warm_candidate(&mut self) -> Result<(), ReloadRefusal>;
    fn quiesce_source(&mut self) -> Result<(), ReloadRefusal>;
    fn transfer_leases(&mut self) -> Result<(), ReloadRefusal>;
    fn activate_candidate(&mut self) -> Result<(), ReloadRefusal>;
    fn prove_active(&mut self) -> Result<(), ReloadRefusal>;
    fn drain_source(&mut self) -> Result<(), ReloadRefusal>;
    fn stop_candidate(&mut self);
    fn resume_source(&mut self);
    fn return_leases(&mut self) -> Result<(), ReloadRefusal>;
}

pub struct ReloadExecution<'a> {
    pub reload_id: &'a str,
    pub source_generation_id: &'a str,
    pub source_lease_epoch: u64,
    pub target_generation_id: &'a str,
    pub target_release_digest: &'a str,
}

#[derive(Debug)]
pub enum ReloadExecutionError {
    Refused(String),
    Audit(ReloadAuditError),
}

impl ReloadExecutionError {
    #[must_use]
    pub fn category(&self) -> &str {
        match self {
            Self::Refused(category) => category,
            Self::Audit(error) => error.category(),
        }
    }
}

impl fmt::Display for ReloadExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.category())
    }
}

impl Error for ReloadExecutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Audit(error) => Some(error),
            Self::Refused(_) => None,
        }
    }
}

impl From<ReloadAuditError> for ReloadExecutionError {
    fn from(error: ReloadAuditError) -> Self {
        Self::Audit(error)
    }
}

/// Execute the exact ten-step handoff skeleton and durably record each phase.
///
/// Target verification precedes epoch creation, matching the protocol: an
/// untrusted or incompatible release never becomes a reload in progress.
pub fn execute_reload(
    audit: &mut ReloadAudit,
    execution: ReloadExecution<'_>,
    hooks: &mut impl ReloadHooks,
    mut now_ms: impl FnMut() -> Result<i64, ReloadRefusal>,
) -> Result<ReloadRecord, ReloadExecutionError> {
    hooks
        .verify_target()
        .map_err(|error| ReloadExecutionError::Refused(error.category().to_owned()))?;
    let mut record = audit.begin(BeginReload {
        reload_id: execution.reload_id,
        source_generation_id: execution.source_generation_id,
        source_lease_epoch: execution.source_lease_epoch,
        target_generation_id: execution.target_generation_id,
        target_release_digest: execution.target_release_digest,
        created_at_ms: now_ms()
            .map_err(|error| ReloadExecutionError::Refused(error.category().to_owned()))?,
    })?;
    if record.phase.is_terminal() {
        return terminal_outcome(record);
    }

    if let Err(error) = hooks.spawn_candidate() {
        return fail_for_phase(audit, record, error, hooks, &mut now_ms);
    }
    record = advance_if_needed(audit, record, ReloadPhase::CandidateStarted, &mut now_ms)?;

    if let Err(error) = hooks.warm_candidate() {
        return fail_for_phase(audit, record, error, hooks, &mut now_ms);
    }
    record = advance_if_needed(audit, record, ReloadPhase::Warm, &mut now_ms)?;

    if let Err(error) = hooks.quiesce_source() {
        return fail_for_phase(audit, record, error, hooks, &mut now_ms);
    }
    record = advance_if_needed(audit, record, ReloadPhase::Quiescing, &mut now_ms)?;

    if let Err(error) = hooks.transfer_leases() {
        return fail_for_phase(audit, record, error, hooks, &mut now_ms);
    }
    record = advance_if_needed(audit, record, ReloadPhase::Transferred, &mut now_ms)?;

    if let Err(error) = hooks.activate_candidate() {
        return fail_after_transfer(audit, record, error, hooks, &mut now_ms);
    }
    if let Err(error) = hooks.prove_active() {
        return fail_after_transfer(audit, record, error, hooks, &mut now_ms);
    }
    record = advance_if_needed(audit, record, ReloadPhase::ActiveProven, &mut now_ms)?;

    if let Err(error) = hooks.drain_source() {
        return fail_after_transfer(audit, record, error, hooks, &mut now_ms);
    }
    record = advance_if_needed(audit, record, ReloadPhase::Draining, &mut now_ms)?;
    advance_if_needed(audit, record, ReloadPhase::Succeeded, &mut now_ms)
}

fn terminal_outcome(record: ReloadRecord) -> Result<ReloadRecord, ReloadExecutionError> {
    if record.phase == ReloadPhase::Succeeded {
        Ok(record)
    } else {
        Err(ReloadExecutionError::Refused(
            record
                .failure_category
                .clone()
                .unwrap_or_else(|| "reload_audit_corrupt".to_owned()),
        ))
    }
}

fn fail_for_phase(
    audit: &mut ReloadAudit,
    record: ReloadRecord,
    error: ReloadRefusal,
    hooks: &mut impl ReloadHooks,
    now_ms: &mut impl FnMut() -> Result<i64, ReloadRefusal>,
) -> Result<ReloadRecord, ReloadExecutionError> {
    if phase_rank(record.phase) >= phase_rank(ReloadPhase::Transferred) {
        fail_after_transfer(audit, record, error, hooks, now_ms)
    } else {
        hooks.resume_source();
        hooks.stop_candidate();
        fail_before_transfer(audit, record, error, now_ms)
    }
}

fn fail_before_transfer(
    audit: &mut ReloadAudit,
    record: ReloadRecord,
    error: ReloadRefusal,
    now_ms: &mut impl FnMut() -> Result<i64, ReloadRefusal>,
) -> Result<ReloadRecord, ReloadExecutionError> {
    advance(
        audit,
        record,
        ReloadPhase::Failed,
        Some(error.category()),
        now_ms,
    )?;
    Err(ReloadExecutionError::Refused(error.category().to_owned()))
}

fn fail_after_transfer(
    audit: &mut ReloadAudit,
    record: ReloadRecord,
    error: ReloadRefusal,
    hooks: &mut impl ReloadHooks,
    now_ms: &mut impl FnMut() -> Result<i64, ReloadRefusal>,
) -> Result<ReloadRecord, ReloadExecutionError> {
    match hooks.return_leases() {
        Ok(()) => {
            hooks.resume_source();
            hooks.stop_candidate();
            advance(
                audit,
                record,
                ReloadPhase::RolledBack,
                Some(error.category()),
                now_ms,
            )?;
            Err(ReloadExecutionError::Refused(error.category().to_owned()))
        }
        Err(_) => {
            let _ = advance(
                audit,
                record,
                ReloadPhase::Failed,
                Some("reload_recovery_required"),
                now_ms,
            )?;
            Err(ReloadExecutionError::Refused(
                "reload_recovery_required".to_owned(),
            ))
        }
    }
}

fn advance_if_needed(
    audit: &mut ReloadAudit,
    record: ReloadRecord,
    phase: ReloadPhase,
    now_ms: &mut impl FnMut() -> Result<i64, ReloadRefusal>,
) -> Result<ReloadRecord, ReloadExecutionError> {
    if phase_rank(record.phase) >= phase_rank(phase) {
        return Ok(record);
    }
    advance(audit, record, phase, None, now_ms)
}

const fn phase_rank(phase: ReloadPhase) -> u8 {
    match phase {
        ReloadPhase::Created => 0,
        ReloadPhase::CandidateStarted => 1,
        ReloadPhase::Warm => 2,
        ReloadPhase::Quiescing => 3,
        ReloadPhase::Transferred => 4,
        ReloadPhase::ActiveProven => 5,
        ReloadPhase::Draining => 6,
        ReloadPhase::Succeeded => 7,
        ReloadPhase::Failed | ReloadPhase::RolledBack => u8::MAX,
    }
}

fn advance(
    audit: &mut ReloadAudit,
    record: ReloadRecord,
    phase: ReloadPhase,
    failure_category: Option<&str>,
    now_ms: &mut impl FnMut() -> Result<i64, ReloadRefusal>,
) -> Result<ReloadRecord, ReloadExecutionError> {
    audit
        .advance(AdvanceReload {
            reload_id: &record.reload_id,
            expected_revision: record.revision,
            phase,
            failure_category,
            observed_at_ms: now_ms()
                .map_err(|error| ReloadExecutionError::Refused(error.category().to_owned()))?,
        })
        .map_err(Into::into)
}
