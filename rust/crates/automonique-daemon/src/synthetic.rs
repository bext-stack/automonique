// SPDX-License-Identifier: Elastic-2.0

//! Durable adapter for the daemon's deliberately no-effect synthetic lane.
//!
//! Public so an integration test can drive the same controller tick the serve
//! loop drives, against the same store the automation scheduler worker submits
//! to; nothing outside this crate composes one in production.

use automonique_core::{
    ClaimOutcome, CommitOutcome, CommitReceipt, DurableError, DurableScheduler, DurableWorkItem,
    FakeProgram, FakeTerminal, Reconciliation, ReconciliationReason, SchedulerFence,
    TerminalCommit,
};
use automonique_store::{
    LeaseRenewal, SchedulerClaim, Store, StoreError, TerminalRun, TerminalState,
};

pub struct StoreScheduler<'a> {
    store: &'a mut Store,
    now_ms: i64,
    lease_now_ms: i64,
    ttl_ms: i64,
    lease_expires_ms: &'a mut i64,
    active: Option<(i64, String)>,
}

impl<'a> StoreScheduler<'a> {
    pub fn new(
        store: &'a mut Store,
        now_ms: i64,
        lease_now_ms: i64,
        ttl_ms: i64,
        lease_expires_ms: &'a mut i64,
    ) -> Self {
        Self {
            store,
            now_ms,
            lease_now_ms,
            ttl_ms,
            lease_expires_ms,
            active: None,
        }
    }
}

impl DurableScheduler for StoreScheduler<'_> {
    fn renew_fence(&mut self, fence: &SchedulerFence) -> Result<(), DurableError> {
        // The store revalidates the fence transactionally in `claim_next` and
        // `finish_run`. Avoid turning an idle 25 ms poll into a durable lease
        // renewal/event storm; renew only as the lease enters its normal
        // renewal window.
        if *self.lease_expires_ms > self.lease_now_ms.saturating_add(self.ttl_ms / 3) {
            return Ok(());
        }
        let lease = self
            .store
            .renew_generation_lease(LeaseRenewal {
                generation_id: fence.generation_id(),
                holder_id: fence.holder_id(),
                epoch: fence.epoch(),
                now_ms: self.now_ms,
                ttl_ms: self.ttl_ms,
            })
            .map_err(classify_store_error)?;
        *self.lease_expires_ms = lease.expires_ms;
        Ok(())
    }

    fn claim_one(&mut self, fence: &SchedulerFence) -> Result<ClaimOutcome, DurableError> {
        let claim = match self.store.claim_next(SchedulerClaim {
            transport: "local.synthetic",
            generation_id: fence.generation_id(),
            holder_id: fence.holder_id(),
            lease_epoch: fence.epoch(),
            now_ms: self.now_ms,
        }) {
            Ok(claim) => claim,
            Err(StoreError::ReconciliationRequired { run_id }) => {
                return Ok(ClaimOutcome::ReconciliationRequired(
                    Reconciliation::new(
                        run_id.to_string(),
                        ReconciliationReason::ClaimedOutcomeUnknown,
                    )
                    .map_err(|_| DurableError::InvariantViolation)?,
                ));
            }
            Err(error) => return Err(classify_store_error(error)),
        };
        let Some(claim) = claim else {
            return Ok(ClaimOutcome::Empty);
        };
        if claim.duplicate {
            return Ok(ClaimOutcome::ReconciliationRequired(
                Reconciliation::new(
                    claim.run_id.to_string(),
                    ReconciliationReason::ClaimedOutcomeUnknown,
                )
                .map_err(|_| DurableError::InvariantViolation)?,
            ));
        }
        let inbox = self
            .store
            .claimed_inbox(
                claim.run_id,
                fence.generation_id(),
                fence.holder_id(),
                fence.epoch(),
                self.now_ms,
            )
            .map_err(classify_store_error)?;
        if inbox.transport != "local.synthetic" || inbox.scope != claim.scope {
            return Err(DurableError::InvariantViolation);
        }
        let program = if inbox.payload == b"fail" {
            FakeProgram::Fail
        } else {
            FakeProgram::Succeed
        };
        self.active = Some((claim.run_id, inbox.transport_key.clone()));
        DurableWorkItem::new(claim.run_id.to_string(), inbox.transport_key, program)
            .map(ClaimOutcome::Claimed)
            .map_err(|_| DurableError::InvariantViolation)
    }

    fn commit_terminal(
        &mut self,
        fence: &SchedulerFence,
        terminal: &TerminalCommit,
    ) -> Result<CommitOutcome, DurableError> {
        let run_id = terminal
            .work_id()
            .parse::<i64>()
            .map_err(|_| DurableError::InvariantViolation)?;
        if self.active.as_ref() != Some(&(run_id, terminal.request_key().to_owned())) {
            return Err(DurableError::InvariantViolation);
        }
        let (state, event_kind, payload): (TerminalState, &str, &[u8]) = match terminal.terminal() {
            FakeTerminal::Succeeded => (
                TerminalState::Succeeded,
                "run.synthetic_succeeded",
                b"automonique.synthetic/v1:succeeded",
            ),
            FakeTerminal::Failed => (
                TerminalState::Failed,
                "run.synthetic_failed",
                b"automonique.synthetic/v1:failed",
            ),
        };
        let receipt = self
            .store
            .finish_run(TerminalRun {
                run_id,
                generation_id: fence.generation_id(),
                holder_id: fence.holder_id(),
                lease_epoch: fence.epoch(),
                expected_revision: 1,
                now_ms: self.now_ms,
                state,
                event_kind,
                event_payload: payload,
                outbox_intent_key: terminal.fake_effect().idempotency_key(),
                outbox_kind: "fake.receipt",
                outbox_payload: payload,
            })
            .map_err(classify_store_error)?;
        let duplicate = receipt.duplicate;
        let receipt = CommitReceipt::new(
            format!("event:{}", receipt.event_id),
            format!("outbox:{}", receipt.outbox_id),
        )
        .map_err(|_| DurableError::InvariantViolation)?;
        Ok(if duplicate {
            CommitOutcome::Replayed(receipt)
        } else {
            CommitOutcome::Committed(receipt)
        })
    }
}

fn classify_store_error(error: StoreError) -> DurableError {
    match error {
        StoreError::StaleEpoch | StoreError::LeaseHeld => DurableError::StaleFence,
        StoreError::ScopeLocked => DurableError::TemporarilyUnavailable,
        StoreError::Sqlite(rusqlite::Error::SqliteFailure(code, _))
            if matches!(
                code.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            DurableError::TemporarilyUnavailable
        }
        _ => DurableError::InvariantViolation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_busy_and_locked_sqlite_failures_are_retryable() {
        for code in [rusqlite::ffi::SQLITE_BUSY, rusqlite::ffi::SQLITE_LOCKED] {
            assert_eq!(
                classify_store_error(StoreError::Sqlite(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(code),
                    None,
                ))),
                DurableError::TemporarilyUnavailable
            );
        }
        assert_eq!(
            classify_store_error(StoreError::Sqlite(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
                None,
            ))),
            DurableError::InvariantViolation
        );
        assert_eq!(
            classify_store_error(StoreError::Io(std::io::Error::other("permanent"))),
            DurableError::InvariantViolation
        );
    }
}
