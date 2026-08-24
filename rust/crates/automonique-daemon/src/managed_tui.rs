// SPDX-License-Identifier: Elastic-2.0

//! Durable execution worker for the managed terminal client.
//!
//! Platform actions commit an accepted receipt and enqueue one inbox item on
//! the daemon's serve thread.  This worker owns a second store connection,
//! claims those items under the same generation fence, runs the existing local
//! socket lane, commits the scheduler terminal plus a platform-receipt outbox
//! intent, and then delivers that intent idempotently into `PlatformStore`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use automonique_protocol::platform::{IdempotencyKey, ReceiptOutcome};
use automonique_store::platform_store::PlatformStore;
use automonique_store::run_index::{RunIndex, RunSpoolState};
use automonique_store::{
    LeaseTimeSource, OutboxClaimRequest, OutboxDelivery, OutboxPayloadRequest,
    OutboxReconciliationDecision, OutboxReconciliationRequest, ReconciliationDecision,
    ReconciliationRequest, SchedulerClaim, Store, StoreError, TerminalRun, TerminalState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::compose::ManagedSessionMode;
use crate::managed_sessions::ManagedSessionStore;
use crate::run_lane::SocketRunLane;

pub const NEW_REQUEST_TRANSPORT: &str = "local.tui";
pub const FOLLOW_UP_TRANSPORT: &str = "local.tui.follow_up";
const RECEIPT_KIND: &str = "platform.managed_tui_receipt";
const OUTBOX_LEASE_MS: i64 = 30_000;
const IDLE_POLL: Duration = Duration::from_millis(50);

#[derive(Clone)]
pub struct ManagedTuiParams<'a> {
    pub database_path: &'a Path,
    pub platform_store_path: &'a Path,
    pub managed_sessions_path: &'a Path,
    pub state_dir: &'a Path,
    pub admin_socket: &'a Path,
    pub run_index_path: &'a Path,
    pub generation_id: &'a str,
    pub holder_id: &'a str,
    pub lease_epoch: u64,
    pub lease_time_source: Arc<dyn LeaseTimeSource>,
}

#[derive(Debug)]
pub enum ManagedTuiError {
    Store(&'static str),
    Platform(&'static str),
    Session(&'static str),
    Lane(&'static str),
    Thread,
}

impl ManagedTuiError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Store(category)
            | Self::Platform(category)
            | Self::Session(category)
            | Self::Lane(category) => category,
            Self::Thread => "managed_tui_thread",
        }
    }
}

#[derive(Clone)]
struct OwnedParams {
    database_path: PathBuf,
    platform_store_path: PathBuf,
    managed_sessions_path: PathBuf,
    state_dir: PathBuf,
    admin_socket: PathBuf,
    run_index_path: PathBuf,
    generation_id: String,
    holder_id: String,
    lease_epoch: u64,
    lease_time_source: Arc<dyn LeaseTimeSource>,
}

pub struct ManagedTuiHost {
    composed: Option<ManagedTuiWorker>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl ManagedTuiHost {
    pub fn open(params: &ManagedTuiParams<'_>) -> Result<Self, ManagedTuiError> {
        let owned = OwnedParams {
            database_path: params.database_path.to_path_buf(),
            platform_store_path: params.platform_store_path.to_path_buf(),
            managed_sessions_path: params.managed_sessions_path.to_path_buf(),
            state_dir: params.state_dir.to_path_buf(),
            admin_socket: params.admin_socket.to_path_buf(),
            run_index_path: params.run_index_path.to_path_buf(),
            generation_id: params.generation_id.to_owned(),
            holder_id: params.holder_id.to_owned(),
            lease_epoch: params.lease_epoch,
            lease_time_source: Arc::clone(&params.lease_time_source),
        };
        Ok(Self {
            composed: Some(ManagedTuiWorker::open(owned)?),
            stop: Arc::new(AtomicBool::new(false)),
            worker: None,
        })
    }

    pub fn start(&mut self) -> Result<(), ManagedTuiError> {
        if self.worker.is_some() {
            return Ok(());
        }
        let mut composed = self.composed.take().ok_or(ManagedTuiError::Thread)?;
        let stop = Arc::clone(&self.stop);
        let worker = std::thread::Builder::new()
            .name("automonique-managed-tui".to_owned())
            .spawn(move || {
                composed.run(&stop);
            })
            .map_err(|_| ManagedTuiError::Thread)?;
        self.worker = Some(worker);
        Ok(())
    }

    pub fn shutdown(&mut self) {
        if let Some(worker) = self.begin_shutdown() {
            let _ = worker.join();
        }
    }

    /// Signal the worker and return its join handle to an external drainer.
    ///
    /// The daemon uses this form so all transport workers can drain together
    /// while the serve thread keeps their shared generation lease renewed.
    pub(crate) fn begin_shutdown(&mut self) -> Option<JoinHandle<()>> {
        self.stop.store(true, Ordering::Release);
        self.worker.take()
    }
}

impl Drop for ManagedTuiHost {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct ManagedTuiWorker {
    params: OwnedParams,
    store: Store,
    platform: PlatformStore,
    sessions: ManagedSessionStore,
    lane: SocketRunLane,
    run_index: RunIndex,
    follow_up_first: bool,
}

#[derive(Serialize, Deserialize)]
struct ReceiptIntent {
    idempotency_key: String,
    outcome: String,
    explanation: Option<String>,
}

impl ManagedTuiWorker {
    fn open(params: OwnedParams) -> Result<Self, ManagedTuiError> {
        let store = Store::open_with_lease_time_source(
            &params.database_path,
            Arc::clone(&params.lease_time_source),
        )
        .map_err(|error| ManagedTuiError::Store(error.category()))?;
        let platform = PlatformStore::open(&params.platform_store_path)
            .map_err(|error| ManagedTuiError::Platform(error.category()))?;
        let sessions = ManagedSessionStore::open(&params.managed_sessions_path)
            .map_err(|error| ManagedTuiError::Session(error.category()))?;
        let lane = SocketRunLane::open(
            &params.state_dir,
            &params.admin_socket,
            &params.run_index_path,
        )
        .map_err(|_| ManagedTuiError::Lane("managed_tui_run_index"))?;
        let run_index = RunIndex::open(&params.run_index_path)
            .map_err(|error| ManagedTuiError::Lane(error.category()))?;
        Ok(Self {
            params,
            store,
            platform,
            sessions,
            lane,
            run_index,
            follow_up_first: false,
        })
    }

    fn run(&mut self, stop: &AtomicBool) {
        while !stop.load(Ordering::Acquire) {
            let now_ms = match crate::unix_millis() {
                Ok(value) => value,
                Err(_) => {
                    std::thread::sleep(IDLE_POLL);
                    continue;
                }
            };
            let delivered = match self.deliver_one_receipt(now_ms) {
                Ok(delivered) => delivered,
                Err(_) => {
                    std::thread::sleep(IDLE_POLL);
                    continue;
                }
            };
            let processed = if delivered {
                false
            } else {
                match self.process_one(now_ms) {
                    Ok(processed) => processed,
                    Err(_) => {
                        std::thread::sleep(IDLE_POLL);
                        continue;
                    }
                }
            };
            if !delivered && !processed {
                std::thread::sleep(IDLE_POLL);
            }
        }
    }

    fn process_one(&mut self, now_ms: i64) -> Result<bool, ManagedTuiError> {
        let transports = if self.follow_up_first {
            [FOLLOW_UP_TRANSPORT, NEW_REQUEST_TRANSPORT]
        } else {
            [NEW_REQUEST_TRANSPORT, FOLLOW_UP_TRANSPORT]
        };
        self.follow_up_first = !self.follow_up_first;
        for transport in transports {
            let claim = match self.store.claim_next(SchedulerClaim {
                transport,
                generation_id: &self.params.generation_id,
                holder_id: &self.params.holder_id,
                lease_epoch: self.params.lease_epoch,
                now_ms,
            }) {
                Ok(Some(claim)) => claim,
                Ok(None) | Err(StoreError::ScopeLocked) => continue,
                Err(StoreError::ReconciliationRequired { run_id }) => {
                    return self.reconcile_interrupted(run_id, now_ms).map(|()| true);
                }
                Err(error) => return Err(ManagedTuiError::Store(error.category())),
            };
            let inbox = self
                .store
                .claimed_inbox(
                    claim.run_id,
                    &self.params.generation_id,
                    &self.params.holder_id,
                    self.params.lease_epoch,
                    now_ms,
                )
                .map_err(|error| ManagedTuiError::Store(error.category()))?;
            if inbox.transport != transport || inbox.scope != claim.scope {
                return Err(ManagedTuiError::Store("managed_tui_claim_mismatch"));
            }
            let task = std::str::from_utf8(&inbox.payload)
                .map_err(|_| ManagedTuiError::Store("managed_tui_payload"))?;
            let inner_run_id = deterministic_run_id(&inbox.transport_key);
            let resume_session = if transport == NEW_REQUEST_TRANSPORT {
                None
            } else {
                let session = self
                    .sessions
                    .by_id(&inbox.scope)
                    .map_err(|error| ManagedTuiError::Session(error.category()))?
                    .filter(|session| session.open);
                let Some(session) = session else {
                    self.finish(
                        claim.run_id,
                        &inbox.transport_key,
                        &inner_run_id,
                        None,
                        Err("session_not_resumable"),
                    )?;
                    return Ok(true);
                };
                Some(session.provider_session_id)
            };
            let mode = match resume_session.as_deref() {
                Some(session_id) => ManagedSessionMode::Resume(session_id),
                None => ManagedSessionMode::New,
            };
            let outcome = self.lane.run_managed(&inner_run_id, task, mode);
            match outcome {
                Ok(_) => {
                    let session = self
                        .sessions
                        .by_run(&inner_run_id)
                        .map_err(|error| ManagedTuiError::Session(error.category()))?;
                    let session_id = session
                        .as_ref()
                        .map(|value| value.provider_session_id.as_str());
                    if session_id.is_none() {
                        self.finish(
                            claim.run_id,
                            &inbox.transport_key,
                            &inner_run_id,
                            None,
                            Err("provider_session_missing"),
                        )?;
                    } else {
                        self.finish(
                            claim.run_id,
                            &inbox.transport_key,
                            &inner_run_id,
                            session_id,
                            Ok(()),
                        )?;
                    }
                }
                Err(error) => self.finish(
                    claim.run_id,
                    &inbox.transport_key,
                    &inner_run_id,
                    None,
                    Err(error.category()),
                )?,
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn finish(
        &mut self,
        scheduler_run_id: i64,
        idempotency_key: &str,
        inner_run_id: &str,
        session_id: Option<&str>,
        outcome: Result<(), &'static str>,
    ) -> Result<(), ManagedTuiError> {
        let now_ms = crate::unix_millis().map_err(|_| ManagedTuiError::Store("clock"))?;
        let (state, receipt_outcome, explanation) = match outcome {
            Ok(()) => (
                TerminalState::Succeeded,
                ReceiptOutcome::Completed,
                session_id.map(|session| format!("run={inner_run_id};session={session}")),
            ),
            Err(category) => (
                TerminalState::Failed,
                ReceiptOutcome::Rejected,
                Some(category.to_owned()),
            ),
        };
        let payload = receipt_payload(idempotency_key, receipt_outcome, explanation.as_deref())?;
        let event_kind = if state == TerminalState::Succeeded {
            "run.managed_tui_completed"
        } else {
            "run.managed_tui_failed"
        };
        let outbox_key = deterministic_outbox_key(idempotency_key);
        self.sessions
            .record_receipt_intent(
                &outbox_key,
                idempotency_key,
                receipt_outcome,
                explanation.as_deref(),
                now_ms,
            )
            .map_err(|error| ManagedTuiError::Session(error.category()))?;
        self.store
            .finish_run(TerminalRun {
                run_id: scheduler_run_id,
                generation_id: &self.params.generation_id,
                holder_id: &self.params.holder_id,
                lease_epoch: self.params.lease_epoch,
                expected_revision: 1,
                now_ms,
                state,
                event_kind,
                event_payload: &payload,
                outbox_intent_key: &outbox_key,
                outbox_kind: RECEIPT_KIND,
                outbox_payload: &payload,
            })
            .map_err(|error| ManagedTuiError::Store(error.category()))?;
        Ok(())
    }

    fn reconcile_interrupted(
        &mut self,
        scheduler_run_id: i64,
        now_ms: i64,
    ) -> Result<(), ManagedTuiError> {
        let evidence = self
            .store
            .inspect_reconciliation(scheduler_run_id)
            .map_err(|error| ManagedTuiError::Store(error.category()))?;
        if !matches!(
            evidence.transport.as_str(),
            NEW_REQUEST_TRANSPORT | FOLLOW_UP_TRANSPORT
        ) {
            return Err(ManagedTuiError::Store(
                "managed_tui_reconciliation_transport",
            ));
        }
        let inner_run_id = deterministic_run_id(&evidence.transport_key);
        let inner = self
            .run_index
            .by_run_id(&inner_run_id)
            .map_err(|error| ManagedTuiError::Lane(error.category()))?
            .into_iter()
            .last();
        let (platform_outcome, explanation) = match inner.map(|row| row.spool_state) {
            Some(RunSpoolState::Completed) => {
                let session = self
                    .sessions
                    .by_run(&inner_run_id)
                    .map_err(|error| ManagedTuiError::Session(error.category()))?;
                session.map_or_else(
                    || {
                        (
                            ReceiptOutcome::Rejected,
                            "provider_session_missing".to_owned(),
                        )
                    },
                    |session| {
                        (
                            ReceiptOutcome::Completed,
                            format!("run={inner_run_id};session={}", session.provider_session_id),
                        )
                    },
                )
            }
            Some(RunSpoolState::Failed) => (ReceiptOutcome::Rejected, "run_failed".to_owned()),
            Some(RunSpoolState::TimedOut) => (ReceiptOutcome::Rejected, "run_timed_out".to_owned()),
            Some(RunSpoolState::Cancelled) => {
                (ReceiptOutcome::Rejected, "run_cancelled".to_owned())
            }
            Some(RunSpoolState::Ready) | None => (
                ReceiptOutcome::Rejected,
                "interrupted_before_provider_custody".to_owned(),
            ),
            Some(RunSpoolState::Running) => (
                ReceiptOutcome::Rejected,
                "provider_outcome_unknown_after_restart".to_owned(),
            ),
        };
        let payload = receipt_payload(
            &evidence.transport_key,
            platform_outcome,
            Some(&explanation),
        )?;
        let outbox_key = deterministic_outbox_key(&evidence.transport_key);
        self.sessions
            .record_receipt_intent(
                &outbox_key,
                &evidence.transport_key,
                platform_outcome,
                Some(&explanation),
                now_ms,
            )
            .map_err(|error| ManagedTuiError::Session(error.category()))?;
        let decision = if platform_outcome == ReceiptOutcome::Completed {
            ReconciliationDecision::Complete {
                event_kind: "run.managed_tui_completed",
                event_payload: &payload,
                outbox_kind: RECEIPT_KIND,
                outbox_payload: &payload,
            }
        } else {
            ReconciliationDecision::FailWithIntent {
                reason: &explanation,
                outbox_kind: RECEIPT_KIND,
                outbox_payload: &payload,
            }
        };
        self.store
            .reconcile_run(ReconciliationRequest {
                run_id: scheduler_run_id,
                authority_generation_id: &self.params.generation_id,
                authority_holder_id: &self.params.holder_id,
                authority_lease_epoch: self.params.lease_epoch,
                expected_generation_id: &evidence.generation_id,
                expected_lease_epoch: evidence.lease_epoch,
                expected_revision: evidence.run_revision,
                decision_key: &outbox_key,
                now_ms,
                decision,
            })
            .map_err(|error| ManagedTuiError::Store(error.category()))?;
        Ok(())
    }

    fn deliver_one_receipt(&mut self, now_ms: i64) -> Result<bool, ManagedTuiError> {
        let claim = self.store.claim_outbox(OutboxClaimRequest {
            transport: "platform",
            kind: RECEIPT_KIND,
            generation_id: &self.params.generation_id,
            holder_id: &self.params.holder_id,
            lease_epoch: self.params.lease_epoch,
            now_ms,
            ttl_ms: OUTBOX_LEASE_MS,
        });
        let lease = match claim {
            Ok(Some(lease)) => lease,
            Ok(None) => return Ok(false),
            Err(StoreError::OutboxReconciliationRequired { outbox_id }) => {
                self.reconcile_receipt_outbox(outbox_id, now_ms)?;
                return Ok(true);
            }
            Err(error) => return Err(ManagedTuiError::Store(error.category())),
        };
        let payload = self
            .store
            .leased_outbox_payload(OutboxPayloadRequest {
                outbox_id: lease.outbox_id,
                generation_id: &self.params.generation_id,
                holder_id: &self.params.holder_id,
                lease_epoch: self.params.lease_epoch,
                lease_token: &lease.lease_token,
                now_ms,
            })
            .map_err(|error| ManagedTuiError::Store(error.category()))?;
        let intent: ReceiptIntent = serde_json::from_slice(&payload.payload)
            .map_err(|_| ManagedTuiError::Store("managed_tui_receipt_decode"))?;
        let key = IdempotencyKey::new(intent.idempotency_key)
            .map_err(|_| ManagedTuiError::Platform("managed_tui_receipt_key"))?;
        let outcome = match intent.outcome.as_str() {
            "completed" => ReceiptOutcome::Completed,
            "rejected" => ReceiptOutcome::Rejected,
            _ => return Err(ManagedTuiError::Platform("managed_tui_receipt_outcome")),
        };
        let receipt = self
            .platform
            .finalize_execute(&key, outcome, intent.explanation.as_deref(), now_ms)
            .map_err(|error| ManagedTuiError::Platform(error.category()))?;
        let delivery_key = format!("receipt:{}", receipt.id.as_str());
        self.store
            .deliver_outbox(OutboxDelivery {
                outbox_id: lease.outbox_id,
                generation_id: &self.params.generation_id,
                holder_id: &self.params.holder_id,
                lease_epoch: self.params.lease_epoch,
                lease_token: &lease.lease_token,
                expected_attempt: lease.attempt,
                receipt_key: &delivery_key,
                now_ms,
            })
            .map_err(|error| ManagedTuiError::Store(error.category()))?;
        Ok(true)
    }

    fn reconcile_receipt_outbox(
        &mut self,
        outbox_id: i64,
        now_ms: i64,
    ) -> Result<(), ManagedTuiError> {
        let evidence = self
            .store
            .inspect_outbox_reconciliation(outbox_id)
            .map_err(|error| ManagedTuiError::Store(error.category()))?;
        if evidence.transport != "platform"
            || evidence.kind != RECEIPT_KIND
            || evidence.state != "in_flight"
        {
            return Err(ManagedTuiError::Store("managed_tui_outbox_reconciliation"));
        }
        let intent = self
            .sessions
            .receipt_intent(&evidence.intent_key)
            .map_err(|error| ManagedTuiError::Session(error.category()))?
            .ok_or(ManagedTuiError::Session(
                "managed_tui_receipt_intent_missing",
            ))?;
        let key = IdempotencyKey::new(intent.idempotency_key)
            .map_err(|_| ManagedTuiError::Platform("managed_tui_receipt_key"))?;
        let receipt = self
            .platform
            .finalize_execute(&key, intent.outcome, intent.explanation.as_deref(), now_ms)
            .map_err(|error| ManagedTuiError::Platform(error.category()))?;
        if receipt.outcome != intent.outcome
            || receipt.explanation.as_ref().map(|value| value.as_str())
                != intent.explanation.as_deref()
        {
            return Err(ManagedTuiError::Platform("managed_tui_receipt_conflict"));
        }
        let expected_generation_id = evidence
            .lease_generation_id
            .as_deref()
            .ok_or(ManagedTuiError::Store("managed_tui_outbox_generation"))?;
        let expected_lease_epoch = evidence
            .lease_epoch
            .ok_or(ManagedTuiError::Store("managed_tui_outbox_epoch"))?;
        let expected_lease_token = evidence
            .lease_token
            .as_deref()
            .ok_or(ManagedTuiError::Store("managed_tui_outbox_token"))?;
        let delivery_key = format!("receipt:{}", receipt.id.as_str());
        self.store
            .reconcile_outbox(OutboxReconciliationRequest {
                outbox_id,
                authority_generation_id: &self.params.generation_id,
                authority_holder_id: &self.params.holder_id,
                authority_lease_epoch: self.params.lease_epoch,
                expected_generation_id,
                expected_lease_epoch,
                expected_lease_token,
                expected_attempt: evidence.attempt,
                expected_revision: evidence.revision,
                now_ms,
                decision: OutboxReconciliationDecision::Delivered {
                    receipt_key: &delivery_key,
                },
            })
            .map_err(|error| ManagedTuiError::Store(error.category()))?;
        Ok(())
    }
}

fn receipt_payload(
    idempotency_key: &str,
    outcome: ReceiptOutcome,
    explanation: Option<&str>,
) -> Result<Vec<u8>, ManagedTuiError> {
    serde_json::to_vec(&ReceiptIntent {
        idempotency_key: idempotency_key.to_owned(),
        outcome: outcome.as_str().to_owned(),
        explanation: explanation.map(str::to_owned),
    })
    .map_err(|_| ManagedTuiError::Store("managed_tui_receipt_encode"))
}

fn deterministic_run_id(key: &str) -> String {
    let digest = Sha256::digest(format!("automonique.managed-tui.run.v1\0{key}").as_bytes());
    format!("tui-{}", hex_prefix(&digest, 24))
}

fn deterministic_outbox_key(key: &str) -> String {
    let digest = Sha256::digest(format!("automonique.managed-tui.receipt.v1\0{key}").as_bytes());
    format!("tui-receipt-{}", hex_prefix(&digest, 24))
}

fn hex_prefix(bytes: &[u8], length: usize) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(length);
    for byte in bytes {
        if output.len() >= length {
            break;
        }
        let _ = write!(output, "{byte:02x}");
    }
    output.truncate(length);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_coordinates_are_stable_and_distinct() {
        assert_eq!(deterministic_run_id("one"), deterministic_run_id("one"));
        assert_ne!(deterministic_run_id("one"), deterministic_run_id("two"));
        assert_ne!(deterministic_run_id("one"), deterministic_outbox_key("one"));
    }
}
