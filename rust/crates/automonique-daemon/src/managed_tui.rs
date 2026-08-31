// SPDX-License-Identifier: Elastic-2.0

//! Durable execution worker for the managed terminal client.
//!
//! Platform actions commit an accepted receipt and enqueue one inbox item on
//! the daemon's serve thread. This worker owns a second store connection,
//! claims those items under the same generation fence, and runs the existing
//! local socket lane. Platform v1 actions additionally deliver a receipt into
//! `PlatformStore`; retained-review Platform v2 actions use an isolated lane
//! whose terminal marker never enters that v1 receipt pipeline.

use crate::shutdown_signal::ShutdownSignal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use automonique_protocol::platform::{IdempotencyKey, ReceiptOutcome};
use automonique_protocol::platform_v2::{
    ProjectId, WorkContextIdentity, WorkContextTargetKind, WorkSessionId,
};
use automonique_protocol::primitives::Revision;
use automonique_store::platform_store::PlatformStore;
use automonique_store::run_index::{RunIndex, RunSpoolState};
use automonique_store::work_context_store::WorkContextStore;
use automonique_store::{
    LeaseTimeSource, OutboxClaimRequest, OutboxDelivery, OutboxPayloadRequest,
    OutboxReconciliationDecision, OutboxReconciliationRequest, ReconciliationDecision,
    ReconciliationRequest, SchedulerClaim, Store, StoreError, TerminalRun, TerminalState,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::compose::ManagedSessionMode;
use crate::managed_sessions::{ManagedHistorySource, ManagedSessionStore};
use crate::run_lane::SocketRunLane;

pub const NEW_REQUEST_TRANSPORT: &str = "local.tui";
pub const FOLLOW_UP_TRANSPORT: &str = "local.tui.follow_up";
pub const RETAINED_REVIEW_TRANSPORT: &str = "platform_v2.retained_review";
/// The scheduler validates this limit against the complete stored envelope,
/// not merely the embedded provider payload.
pub(crate) const MAX_RETAINED_REVIEW_ENVELOPE_BYTES: usize = 1_048_576;
const RECEIPT_KIND: &str = "platform.managed_tui_receipt";
const RETAINED_REVIEW_TERMINAL_KIND: &str = "platform_v2.retained_review_terminal";
const OUTBOX_LEASE_MS: i64 = 30_000;
const IDLE_POLL: Duration = Duration::from_millis(50);

#[derive(Clone)]
pub struct ManagedTuiParams<'a> {
    pub database_path: &'a Path,
    pub platform_store_path: &'a Path,
    pub managed_sessions_path: &'a Path,
    pub work_context_path: &'a Path,
    pub review_registry_path: &'a Path,
    pub expected_uid: u32,
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
    work_context_path: PathBuf,
    review_registry_path: PathBuf,
    expected_uid: u32,
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
    stop: Arc<ShutdownSignal>,
    worker: Option<JoinHandle<()>>,
}

impl ManagedTuiHost {
    pub fn open(params: &ManagedTuiParams<'_>) -> Result<Self, ManagedTuiError> {
        let owned = OwnedParams {
            database_path: params.database_path.to_path_buf(),
            platform_store_path: params.platform_store_path.to_path_buf(),
            managed_sessions_path: params.managed_sessions_path.to_path_buf(),
            work_context_path: params.work_context_path.to_path_buf(),
            review_registry_path: params.review_registry_path.to_path_buf(),
            expected_uid: params.expected_uid,
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
            stop: ShutdownSignal::new(),
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
        self.stop.stop();
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
    work_contexts: WorkContextStore,
    lane: SocketRunLane,
    run_index: RunIndex,
    next_transport: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct RetainedReviewEnvelopeInput<'a> {
    pub tenant: &'a str,
    pub project: &'a ProjectId,
    pub review_workspace: &'a WorkContextIdentity,
    pub expected_registry_generation: [u8; 32],
    pub work_session_id: &'a WorkSessionId,
    pub expected_work_session_revision: Revision,
    pub provider: &'a str,
    pub provider_session_id: &'a str,
    pub expected_provider_session_revision: Revision,
    pub payload: &'a [u8],
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedReviewEnvelope {
    tenant: String,
    project: String,
    review_workspace_kind: String,
    review_workspace_id: String,
    expected_registry_generation: String,
    work_session_id: String,
    expected_work_session_revision: u64,
    provider: String,
    provider_session_id: String,
    expected_provider_session_revision: u64,
    payload: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetainedReviewDisposition {
    Pending,
    Completed,
    RefusedNotStarted,
    Ambiguous,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedReviewTerminal {
    outcome: String,
    category: Option<String>,
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
        let work_contexts = WorkContextStore::open(&params.work_context_path)
            .map_err(|error| ManagedTuiError::Store(error.category()))?;
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
            work_contexts,
            lane,
            run_index,
            next_transport: 0,
        })
    }

    fn run(&mut self, stop: &ShutdownSignal) {
        while !stop.is_stopped() {
            let now_ms = match crate::unix_millis() {
                Ok(value) => value,
                Err(_) => {
                    stop.stopped_within(IDLE_POLL);
                    continue;
                }
            };
            let delivered = match self.deliver_one_terminal(now_ms) {
                Ok(delivered) => delivered,
                Err(_) => {
                    stop.stopped_within(IDLE_POLL);
                    continue;
                }
            };
            let processed = if delivered {
                false
            } else {
                match self.process_one(now_ms) {
                    Ok(processed) => processed,
                    Err(_) => {
                        stop.stopped_within(IDLE_POLL);
                        continue;
                    }
                }
            };
            if !delivered && !processed {
                stop.stopped_within(IDLE_POLL);
            }
        }
    }

    fn process_one(&mut self, now_ms: i64) -> Result<bool, ManagedTuiError> {
        const TRANSPORTS: [&str; 3] = [
            NEW_REQUEST_TRANSPORT,
            FOLLOW_UP_TRANSPORT,
            RETAINED_REVIEW_TRANSPORT,
        ];
        let first = self.next_transport;
        self.next_transport = (self.next_transport + 1) % TRANSPORTS.len();
        for offset in 0..TRANSPORTS.len() {
            let transport = TRANSPORTS[(first + offset) % TRANSPORTS.len()];
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
            if transport == RETAINED_REVIEW_TRANSPORT {
                self.process_retained_review(claim.run_id, &inbox, now_ms)?;
                return Ok(true);
            }
            let task = std::str::from_utf8(&inbox.payload)
                .map_err(|_| ManagedTuiError::Store("managed_tui_payload"))?;
            let inner_run_id = deterministic_run_id(transport, &inbox.transport_key);
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
                Ok(answer) => {
                    let session = self
                        .sessions
                        .by_run(&inner_run_id)
                        .map_err(|error| ManagedTuiError::Session(error.category()))?;
                    let session_id = session.map(|value| value.provider_session_id);
                    if session_id.is_none() {
                        self.finish(
                            claim.run_id,
                            &inbox.transport_key,
                            &inner_run_id,
                            None,
                            Err("provider_session_missing"),
                        )?;
                    } else {
                        self.sessions
                            .record_completed_turn(
                                session_id.as_deref().expect("checked session id"),
                                ManagedHistorySource::PlatformV1(&inbox.transport_key),
                                task,
                                &answer,
                                &self.lane.recorded_events(&inner_run_id),
                                now_ms,
                            )
                            .map_err(|error| ManagedTuiError::Session(error.category()))?;
                        self.finish(
                            claim.run_id,
                            &inbox.transport_key,
                            &inner_run_id,
                            session_id.as_deref(),
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

    fn process_retained_review(
        &mut self,
        scheduler_run_id: i64,
        inbox: &automonique_store::ClaimedInbox,
        now_ms: i64,
    ) -> Result<(), ManagedTuiError> {
        let envelope: RetainedReviewEnvelope = match serde_json::from_slice(&inbox.payload) {
            Ok(value) => value,
            Err(_) => {
                return self.finish_retained_review(
                    scheduler_run_id,
                    &inbox.transport_key,
                    RetainedReviewDisposition::RefusedNotStarted,
                    Some("retained_review_envelope_refused"),
                );
            }
        };
        if envelope.provider != "jcode" || envelope.provider_session_id != inbox.scope {
            return self.finish_retained_review(
                scheduler_run_id,
                &inbox.transport_key,
                RetainedReviewDisposition::RefusedNotStarted,
                Some("retained_review_target_refused"),
            );
        }
        let provider_session = self
            .sessions
            .by_id(&envelope.provider_session_id)
            .map_err(|error| ManagedTuiError::Session(error.category()))?;
        let provider_matches = provider_session.as_ref().is_some_and(|session| {
            session.open && session.revision == envelope.expected_provider_session_revision
        });
        if !provider_matches {
            return self.finish_retained_review(
                scheduler_run_id,
                &inbox.transport_key,
                RetainedReviewDisposition::RefusedNotStarted,
                Some("retained_review_provider_revision_changed"),
            );
        }
        let project = ProjectId::new(envelope.project.clone());
        let workspace_kind = WorkContextTargetKind::parse(&envelope.review_workspace_kind);
        let review_workspace = workspace_kind
            .and_then(|kind| WorkContextIdentity::parse_local(kind, &envelope.review_workspace_id));
        let work_session_id = WorkSessionId::new(envelope.work_session_id.clone());
        let expected_work_revision = Revision::new(envelope.expected_work_session_revision);
        let expected_registry_generation = parse_digest_hex(&envelope.expected_registry_generation);
        let (
            Ok(project),
            Ok(review_workspace),
            Ok(work_session_id),
            Ok(expected_work_revision),
            Some(expected_registry_generation),
        ) = (
            project,
            review_workspace,
            work_session_id,
            expected_work_revision,
            expected_registry_generation,
        )
        else {
            return self.finish_retained_review(
                scheduler_run_id,
                &inbox.transport_key,
                RetainedReviewDisposition::RefusedNotStarted,
                Some("retained_review_lineage_coordinate_refused"),
            );
        };
        let work_revision = self.work_contexts.validate_retained_session_lineage(
            &envelope.tenant,
            &project,
            &review_workspace,
            &work_session_id,
            &envelope.provider_session_id,
        );
        if !matches!(work_revision, Ok(revision) if revision == expected_work_revision) {
            return self.finish_retained_review(
                scheduler_run_id,
                &inbox.transport_key,
                RetainedReviewDisposition::RefusedNotStarted,
                Some("retained_review_work_lineage_changed"),
            );
        }

        if crate::platform_v2_review_adapter::verify_registry_generation(
            &self.params.review_registry_path,
            self.params.expected_uid,
            expected_registry_generation,
        )
        .is_err()
        {
            return self.finish_retained_review(
                scheduler_run_id,
                &inbox.transport_key,
                RetainedReviewDisposition::RefusedNotStarted,
                Some("retained_review_registry_generation_changed"),
            );
        }

        // These are the last reads before provider custody. Everything above
        // is durable and revision-bound; no queued plan can silently retarget
        // a session or workspace after admission.
        let inner_run_id = deterministic_run_id(RETAINED_REVIEW_TRANSPORT, &inbox.transport_key);
        let outcome = self.lane.run_managed(
            &inner_run_id,
            &envelope.payload,
            ManagedSessionMode::Resume(&envelope.provider_session_id),
        );
        match outcome {
            Ok(answer) => {
                let session = self
                    .sessions
                    .by_run(&inner_run_id)
                    .map_err(|error| ManagedTuiError::Session(error.category()))?;
                let Some(session) = session else {
                    return self.finish_retained_review(
                        scheduler_run_id,
                        &inbox.transport_key,
                        RetainedReviewDisposition::Ambiguous,
                        Some("retained_review_provider_session_missing"),
                    );
                };
                if session.provider_session_id != envelope.provider_session_id {
                    return self.finish_retained_review(
                        scheduler_run_id,
                        &inbox.transport_key,
                        RetainedReviewDisposition::Ambiguous,
                        Some("retained_review_provider_session_changed"),
                    );
                }
                self.sessions
                    .record_completed_turn(
                        &envelope.provider_session_id,
                        ManagedHistorySource::RetainedReviewV2(
                            &deterministic_retained_review_history_key(&inner_run_id),
                        ),
                        &envelope.payload,
                        &answer,
                        &self.lane.recorded_events(&inner_run_id),
                        now_ms,
                    )
                    .map_err(|error| ManagedTuiError::Session(error.category()))?;
                self.finish_retained_review(
                    scheduler_run_id,
                    &inbox.transport_key,
                    RetainedReviewDisposition::Completed,
                    None,
                )
            }
            Err(error) => {
                let disposition = self
                    .run_index
                    .by_run_id(&inner_run_id)
                    .map_err(|index_error| ManagedTuiError::Lane(index_error.category()))?
                    .into_iter()
                    .last()
                    .map_or(RetainedReviewDisposition::RefusedNotStarted, |row| {
                        retained_review_run_disposition(row.spool_state)
                    });
                self.finish_retained_review(
                    scheduler_run_id,
                    &inbox.transport_key,
                    disposition,
                    Some(error.category()),
                )
            }
        }
    }

    fn finish_retained_review(
        &mut self,
        scheduler_run_id: i64,
        idempotency_key: &str,
        disposition: RetainedReviewDisposition,
        category: Option<&str>,
    ) -> Result<(), ManagedTuiError> {
        let now_ms = crate::unix_millis().map_err(|_| ManagedTuiError::Store("clock"))?;
        let outcome = match disposition {
            RetainedReviewDisposition::Completed => "completed",
            RetainedReviewDisposition::RefusedNotStarted => "refused_not_started",
            RetainedReviewDisposition::Ambiguous => "ambiguous",
            RetainedReviewDisposition::Pending => {
                return Err(ManagedTuiError::Store("retained_review_terminal_pending"));
            }
        };
        let payload = serde_json::to_vec(&RetainedReviewTerminal {
            outcome: outcome.to_owned(),
            category: category.map(str::to_owned),
        })
        .map_err(|_| ManagedTuiError::Store("retained_review_terminal_encode"))?;
        let succeeded = disposition == RetainedReviewDisposition::Completed;
        self.store
            .finish_run(TerminalRun {
                run_id: scheduler_run_id,
                generation_id: &self.params.generation_id,
                holder_id: &self.params.holder_id,
                lease_epoch: self.params.lease_epoch,
                expected_revision: 1,
                now_ms,
                state: if succeeded {
                    TerminalState::Succeeded
                } else {
                    TerminalState::Failed
                },
                event_kind: if succeeded {
                    "run.retained_review_completed"
                } else {
                    "run.retained_review_failed"
                },
                event_payload: &payload,
                outbox_intent_key: &deterministic_v2_terminal_key(idempotency_key),
                outbox_kind: RETAINED_REVIEW_TERMINAL_KIND,
                outbox_payload: &payload,
            })
            .map_err(|error| ManagedTuiError::Store(error.category()))?;
        Ok(())
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
        if evidence.transport == RETAINED_REVIEW_TRANSPORT {
            return self.reconcile_interrupted_retained_review(&evidence, now_ms);
        }
        if !matches!(
            evidence.transport.as_str(),
            NEW_REQUEST_TRANSPORT | FOLLOW_UP_TRANSPORT
        ) {
            return Err(ManagedTuiError::Store(
                "managed_tui_reconciliation_transport",
            ));
        }
        let inner_run_id = deterministic_run_id(&evidence.transport, &evidence.transport_key);
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

    fn reconcile_interrupted_retained_review(
        &mut self,
        evidence: &automonique_store::ReconciliationEvidence,
        now_ms: i64,
    ) -> Result<(), ManagedTuiError> {
        let inner_run_id = deterministic_run_id(RETAINED_REVIEW_TRANSPORT, &evidence.transport_key);
        let inner = self
            .run_index
            .by_run_id(&inner_run_id)
            .map_err(|error| ManagedTuiError::Lane(error.category()))?
            .into_iter()
            .last();
        let disposition = inner.map_or(RetainedReviewDisposition::RefusedNotStarted, |row| {
            retained_review_run_disposition(row.spool_state)
        });
        let category = match disposition {
            RetainedReviewDisposition::Completed => None,
            RetainedReviewDisposition::RefusedNotStarted => {
                Some("interrupted_before_provider_custody")
            }
            RetainedReviewDisposition::Ambiguous => Some("provider_outcome_unknown_after_restart"),
            RetainedReviewDisposition::Pending => unreachable!("terminal reconciliation"),
        };
        let outcome = match disposition {
            RetainedReviewDisposition::Completed => "completed",
            RetainedReviewDisposition::RefusedNotStarted => "refused_not_started",
            RetainedReviewDisposition::Ambiguous => "ambiguous",
            RetainedReviewDisposition::Pending => unreachable!("terminal reconciliation"),
        };
        let payload = serde_json::to_vec(&RetainedReviewTerminal {
            outcome: outcome.to_owned(),
            category: category.map(str::to_owned),
        })
        .map_err(|_| ManagedTuiError::Store("retained_review_terminal_encode"))?;
        let decision_key = deterministic_v2_terminal_key(&evidence.transport_key);
        let decision = if disposition == RetainedReviewDisposition::Completed {
            ReconciliationDecision::Complete {
                event_kind: "run.retained_review_completed",
                event_payload: &payload,
                outbox_kind: RETAINED_REVIEW_TERMINAL_KIND,
                outbox_payload: &payload,
            }
        } else {
            ReconciliationDecision::FailWithIntent {
                reason: category.expect("failed reconciliation category"),
                outbox_kind: RETAINED_REVIEW_TERMINAL_KIND,
                outbox_payload: &payload,
            }
        };
        self.store
            .reconcile_run(ReconciliationRequest {
                run_id: evidence.run_id,
                authority_generation_id: &self.params.generation_id,
                authority_holder_id: &self.params.holder_id,
                authority_lease_epoch: self.params.lease_epoch,
                expected_generation_id: &evidence.generation_id,
                expected_lease_epoch: evidence.lease_epoch,
                expected_revision: evidence.run_revision,
                decision_key: &decision_key,
                now_ms,
                decision,
            })
            .map_err(|error| ManagedTuiError::Store(error.category()))?;
        Ok(())
    }

    fn deliver_one_terminal(&mut self, now_ms: i64) -> Result<bool, ManagedTuiError> {
        if self.deliver_one_retained_review_terminal(now_ms)? {
            return Ok(true);
        }
        self.deliver_one_receipt(now_ms)
    }

    fn deliver_one_retained_review_terminal(
        &mut self,
        now_ms: i64,
    ) -> Result<bool, ManagedTuiError> {
        let claim = self.store.claim_outbox(OutboxClaimRequest {
            transport: "platform_v2",
            kind: RETAINED_REVIEW_TERMINAL_KIND,
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
                self.reconcile_retained_review_terminal(outbox_id, now_ms)?;
                return Ok(true);
            }
            Err(error) => return Err(ManagedTuiError::Store(error.category())),
        };
        self.store
            .leased_outbox_payload(OutboxPayloadRequest {
                outbox_id: lease.outbox_id,
                generation_id: &self.params.generation_id,
                holder_id: &self.params.holder_id,
                lease_epoch: self.params.lease_epoch,
                lease_token: &lease.lease_token,
                now_ms,
            })
            .map_err(|error| ManagedTuiError::Store(error.category()))?;
        let receipt_key = format!("retained-review-terminal:{}", lease.outbox_id);
        self.store
            .deliver_outbox(OutboxDelivery {
                outbox_id: lease.outbox_id,
                generation_id: &self.params.generation_id,
                holder_id: &self.params.holder_id,
                lease_epoch: self.params.lease_epoch,
                lease_token: &lease.lease_token,
                expected_attempt: lease.attempt,
                receipt_key: &receipt_key,
                now_ms,
            })
            .map_err(|error| ManagedTuiError::Store(error.category()))?;
        Ok(true)
    }

    fn reconcile_retained_review_terminal(
        &mut self,
        outbox_id: i64,
        now_ms: i64,
    ) -> Result<(), ManagedTuiError> {
        let evidence = self
            .store
            .inspect_outbox_reconciliation(outbox_id)
            .map_err(|error| ManagedTuiError::Store(error.category()))?;
        if evidence.transport != "platform_v2"
            || evidence.kind != RETAINED_REVIEW_TERMINAL_KIND
            || evidence.state != "in_flight"
        {
            return Err(ManagedTuiError::Store(
                "retained_review_outbox_reconciliation",
            ));
        }
        let generation_id = evidence
            .lease_generation_id
            .as_deref()
            .ok_or(ManagedTuiError::Store("retained_review_outbox_generation"))?;
        let lease_epoch = evidence
            .lease_epoch
            .ok_or(ManagedTuiError::Store("retained_review_outbox_epoch"))?;
        let lease_token = evidence
            .lease_token
            .as_deref()
            .ok_or(ManagedTuiError::Store("retained_review_outbox_token"))?;
        let receipt_key = format!("retained-review-terminal:{outbox_id}");
        self.store
            .reconcile_outbox(OutboxReconciliationRequest {
                outbox_id,
                authority_generation_id: &self.params.generation_id,
                authority_holder_id: &self.params.holder_id,
                authority_lease_epoch: self.params.lease_epoch,
                expected_generation_id: generation_id,
                expected_lease_epoch: lease_epoch,
                expected_lease_token: lease_token,
                expected_attempt: evidence.attempt,
                expected_revision: evidence.revision,
                now_ms,
                decision: OutboxReconciliationDecision::Delivered {
                    receipt_key: &receipt_key,
                },
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

pub(crate) fn retained_review_envelope(
    input: RetainedReviewEnvelopeInput<'_>,
) -> Result<Vec<u8>, ManagedTuiError> {
    if input.provider != "jcode" {
        return Err(ManagedTuiError::Session("retained_review_provider"));
    }
    let payload = std::str::from_utf8(input.payload)
        .map_err(|_| ManagedTuiError::Store("retained_review_payload"))?;
    let envelope = serde_json::to_vec(&RetainedReviewEnvelope {
        tenant: input.tenant.to_owned(),
        project: input.project.as_str().to_owned(),
        review_workspace_kind: input.review_workspace.kind().as_str().to_owned(),
        review_workspace_id: input.review_workspace.id().to_owned(),
        expected_registry_generation: digest_hex(&input.expected_registry_generation),
        work_session_id: input.work_session_id.as_str().to_owned(),
        expected_work_session_revision: input.expected_work_session_revision.get(),
        provider: input.provider.to_owned(),
        provider_session_id: input.provider_session_id.to_owned(),
        expected_provider_session_revision: input.expected_provider_session_revision.get(),
        payload: payload.to_owned(),
    })
    .map_err(|_| ManagedTuiError::Store("retained_review_envelope_encode"))?;
    if envelope.len() > MAX_RETAINED_REVIEW_ENVELOPE_BYTES {
        return Err(ManagedTuiError::Store("retained_review_envelope_size"));
    }
    Ok(envelope)
}

/// Read one exact v2 delivery coordinate without trusting its key alone.
///
/// This opens an independent read connection because the scheduler store's
/// public disposition intentionally exposes only key/state. The immutable
/// scope and envelope bytes are compared before any state is returned.
pub(crate) fn retained_review_disposition(
    database_path: &Path,
    transport_key: &str,
    scope: &str,
    envelope: &[u8],
) -> Result<Option<RetainedReviewDisposition>, ManagedTuiError> {
    let connection = Connection::open_with_flags(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| ManagedTuiError::Store("retained_review_disposition_open"))?;
    let row = connection
        .query_row(
            "SELECT i.scope,i.payload,i.state,
                    (SELECT r.terminal_payload FROM runs r
                     WHERE r.inbox_id=i.inbox_id ORDER BY r.run_id DESC LIMIT 1)
             FROM inbox i WHERE i.transport=?1 AND i.transport_key=?2",
            rusqlite::params![RETAINED_REVIEW_TRANSPORT, transport_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ManagedTuiError::Store("retained_review_disposition_read"))?;
    let Some((stored_scope, stored_envelope, state, terminal)) = row else {
        return Ok(None);
    };
    if stored_scope != scope || stored_envelope != envelope {
        return Err(ManagedTuiError::Store(
            "retained_review_coordinate_conflict",
        ));
    }
    match state.as_str() {
        "pending" | "claimed" => Ok(Some(RetainedReviewDisposition::Pending)),
        "completed" | "failed" => retained_review_terminal_disposition(
            &state,
            terminal.as_deref().ok_or(ManagedTuiError::Store(
                "retained_review_terminal_unavailable",
            ))?,
        )
        .map(Some),
        _ => Err(ManagedTuiError::Store("retained_review_inbox_state")),
    }
}

fn retained_review_terminal_disposition(
    state: &str,
    payload: &[u8],
) -> Result<RetainedReviewDisposition, ManagedTuiError> {
    let terminal: RetainedReviewTerminal = serde_json::from_slice(payload)
        .map_err(|_| ManagedTuiError::Store("retained_review_terminal_unavailable"))?;
    match terminal.outcome.as_str() {
        "completed" if state == "completed" => Ok(RetainedReviewDisposition::Completed),
        "refused_not_started" if state == "failed" => {
            Ok(RetainedReviewDisposition::RefusedNotStarted)
        }
        "ambiguous" if state == "failed" => Ok(RetainedReviewDisposition::Ambiguous),
        _ => Err(ManagedTuiError::Store("retained_review_terminal_conflict")),
    }
}

fn retained_review_run_disposition(state: RunSpoolState) -> RetainedReviewDisposition {
    match state {
        RunSpoolState::Ready => RetainedReviewDisposition::RefusedNotStarted,
        RunSpoolState::Completed => RetainedReviewDisposition::Completed,
        RunSpoolState::Running
        | RunSpoolState::Failed
        | RunSpoolState::TimedOut
        | RunSpoolState::Cancelled => RetainedReviewDisposition::Ambiguous,
    }
}

fn digest_hex(value: &[u8; 32]) -> String {
    hex_prefix(value, 64)
}

fn parse_digest_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || value
            .as_bytes()
            .iter()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16).ok()?;
    }
    Some(output)
}

fn deterministic_run_id(transport: &str, key: &str) -> String {
    let digest = if transport == RETAINED_REVIEW_TRANSPORT {
        Sha256::digest(format!("automonique.platform-v2.retained-review.run.v1\0{key}").as_bytes())
    } else {
        // Preserve the already-shipped v1 recovery coordinate exactly. A
        // generation may restart while an older new/follow-up run is in the
        // spool, so changing this domain would turn known evidence into an
        // apparent pre-custody interruption.
        Sha256::digest(format!("automonique.managed-tui.run.v1\0{key}").as_bytes())
    };
    format!("tui-{}", hex_prefix(&digest, 24))
}

/// Keep retained-v2 history idempotency out of the globally unique v1 source
/// key namespace. The inner run is already transport-domain-separated; this
/// second domain gives its durable prompt/answer history an explicit identity
/// that cannot collide merely because v1 and v2 received the same transport
/// key.
fn deterministic_retained_review_history_key(inner_run_id: &str) -> String {
    let digest = Sha256::digest(
        format!("automonique.platform-v2.retained-review.history.v1\0{inner_run_id}").as_bytes(),
    );
    format!("v2-review-history-{}", hex_prefix(&digest, 24))
}

fn deterministic_outbox_key(key: &str) -> String {
    let digest = Sha256::digest(format!("automonique.managed-tui.receipt.v1\0{key}").as_bytes());
    format!("tui-receipt-{}", hex_prefix(&digest, 24))
}

fn deterministic_v2_terminal_key(key: &str) -> String {
    let digest = Sha256::digest(
        format!("automonique.platform-v2.retained-review.terminal.v1\0{key}").as_bytes(),
    );
    format!("v2-review-terminal-{}", hex_prefix(&digest, 24))
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
    use crate::managed_sessions::{ManagedHistoryRead, ManagedSessionStore};
    use automonique_store::InboxSubmission;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn deterministic_coordinates_are_stable_and_distinct() {
        assert_eq!(
            deterministic_run_id(FOLLOW_UP_TRANSPORT, "one"),
            deterministic_run_id(FOLLOW_UP_TRANSPORT, "one")
        );
        assert_ne!(
            deterministic_run_id(FOLLOW_UP_TRANSPORT, "one"),
            deterministic_run_id(FOLLOW_UP_TRANSPORT, "two")
        );
        assert_ne!(
            deterministic_run_id(FOLLOW_UP_TRANSPORT, "one"),
            deterministic_run_id(RETAINED_REVIEW_TRANSPORT, "one")
        );
        assert_ne!(
            deterministic_run_id(FOLLOW_UP_TRANSPORT, "one"),
            deterministic_outbox_key("one")
        );
        let v2_run = deterministic_run_id(RETAINED_REVIEW_TRANSPORT, "one");
        assert_eq!(
            deterministic_retained_review_history_key(&v2_run),
            deterministic_retained_review_history_key(&v2_run)
        );
        assert_ne!(deterministic_retained_review_history_key(&v2_run), "one");
    }

    fn history_head(store: &ManagedSessionStore, session_id: &str) -> u64 {
        match store.history(session_id, 0, 16).unwrap() {
            ManagedHistoryRead::Page { head, .. } => head,
            ManagedHistoryRead::Resync { .. } => panic!("fresh history must be readable"),
        }
    }

    #[test]
    fn retained_review_history_isolated_from_same_session_v1_key_across_restart() {
        let private = tempfile::tempdir().unwrap();
        std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = private.path().join("managed.sqlite3");
        let transport_key = "shared-v1-v2-key";
        let inner_run_id = deterministic_run_id(RETAINED_REVIEW_TRANSPORT, transport_key);
        let v2_history_key = deterministic_retained_review_history_key(&inner_run_id);
        {
            let mut sessions = ManagedSessionStore::open(&path).unwrap();
            sessions
                .record_completed_turn(
                    "provider-session",
                    ManagedHistorySource::PlatformV1(&v2_history_key),
                    "v1 prompt",
                    "v1 answer",
                    &[],
                    1,
                )
                .unwrap();
            sessions
                .record_completed_turn(
                    "provider-session",
                    ManagedHistorySource::RetainedReviewV2(&v2_history_key),
                    "v2 prompt",
                    "v2 answer",
                    &[],
                    2,
                )
                .unwrap();
            assert_eq!(history_head(&sessions, "provider-session"), 4);
        }

        let mut restarted = ManagedSessionStore::open(&path).unwrap();
        restarted
            .record_completed_turn(
                "provider-session",
                ManagedHistorySource::RetainedReviewV2(&deterministic_retained_review_history_key(
                    &inner_run_id,
                )),
                "v2 prompt",
                "v2 answer",
                &[],
                3,
            )
            .unwrap();
        assert_eq!(history_head(&restarted, "provider-session"), 4);
    }

    #[test]
    fn retained_review_history_isolated_from_cross_session_v1_key() {
        let private = tempfile::tempdir().unwrap();
        std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = private.path().join("managed.sqlite3");
        let transport_key = "shared-cross-session-key";
        let inner_run_id = deterministic_run_id(RETAINED_REVIEW_TRANSPORT, transport_key);
        let mut sessions = ManagedSessionStore::open(&path).unwrap();
        sessions
            .record_completed_turn(
                "v1-provider-session",
                ManagedHistorySource::PlatformV1(&deterministic_retained_review_history_key(
                    &inner_run_id,
                )),
                "v1 prompt",
                "v1 answer",
                &[],
                1,
            )
            .unwrap();
        sessions
            .record_completed_turn(
                "v2-provider-session",
                ManagedHistorySource::RetainedReviewV2(&deterministic_retained_review_history_key(
                    &inner_run_id,
                )),
                "v2 prompt",
                "v2 answer",
                &[],
                2,
            )
            .unwrap();

        assert_eq!(history_head(&sessions, "v1-provider-session"), 2);
        assert_eq!(history_head(&sessions, "v2-provider-session"), 2);
    }

    #[test]
    fn retained_review_disposition_matches_scope_and_payload_not_key_alone() {
        let private = tempfile::tempdir().unwrap();
        std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let database = private.path().join("scheduler.sqlite3");
        let mut store = Store::open(&database).unwrap();
        store
            .submit_inbox(InboxSubmission {
                transport: RETAINED_REVIEW_TRANSPORT,
                transport_key: "review-key",
                scope: "provider-session",
                payload: b"exact-envelope",
                received_ms: 1,
            })
            .unwrap();
        assert_eq!(
            retained_review_disposition(
                &database,
                "review-key",
                "provider-session",
                b"exact-envelope"
            )
            .unwrap(),
            Some(RetainedReviewDisposition::Pending)
        );
        for (scope, payload) in [
            ("other-session", b"exact-envelope".as_slice()),
            ("provider-session", b"other-envelope".as_slice()),
        ] {
            assert_eq!(
                retained_review_disposition(&database, "review-key", scope, payload)
                    .unwrap_err()
                    .category(),
                "retained_review_coordinate_conflict"
            );
        }
        assert_eq!(
            retained_review_disposition(
                &database,
                "missing-key",
                "provider-session",
                b"exact-envelope"
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn retained_review_terminal_distinguishes_refusal_from_ambiguity() {
        assert_eq!(
            retained_review_terminal_disposition(
                "failed",
                br#"{"outcome":"refused_not_started","category":"revision_changed"}"#,
            )
            .unwrap(),
            RetainedReviewDisposition::RefusedNotStarted
        );
        assert_eq!(
            retained_review_terminal_disposition(
                "failed",
                br#"{"outcome":"ambiguous","category":"provider_outcome_unknown"}"#,
            )
            .unwrap(),
            RetainedReviewDisposition::Ambiguous
        );
        assert_eq!(
            retained_review_terminal_disposition(
                "completed",
                br#"{"outcome":"completed","category":null}"#,
            )
            .unwrap(),
            RetainedReviewDisposition::Completed
        );
    }

    #[test]
    fn retained_review_run_evidence_distinguishes_pre_custody_from_ambiguity() {
        assert_eq!(
            retained_review_run_disposition(RunSpoolState::Ready),
            RetainedReviewDisposition::RefusedNotStarted
        );
        assert_eq!(
            retained_review_run_disposition(RunSpoolState::Completed),
            RetainedReviewDisposition::Completed
        );
        for state in [
            RunSpoolState::Running,
            RunSpoolState::Failed,
            RunSpoolState::TimedOut,
            RunSpoolState::Cancelled,
        ] {
            assert_eq!(
                retained_review_run_disposition(state),
                RetainedReviewDisposition::Ambiguous
            );
        }
    }

    #[test]
    fn registry_generation_envelope_is_exact_lowercase_hex() {
        let generation = [0xab; 32];
        let encoded = digest_hex(&generation);
        assert_eq!(encoded, "ab".repeat(32));
        assert_eq!(parse_digest_hex(&encoded), Some(generation));
        assert_eq!(parse_digest_hex(&encoded.to_uppercase()), None);
        assert_eq!(parse_digest_hex("ab"), None);
    }

    #[test]
    fn retained_review_envelope_limit_includes_json_escaping_and_metadata() {
        let project = ProjectId::new("project-envelope-boundary".to_owned()).unwrap();
        let work_session = WorkSessionId::new("work-session-envelope-boundary".to_owned()).unwrap();
        let workspace = WorkContextIdentity::Session(work_session.clone());
        let revision = Revision::new(1).unwrap();
        let safely_bounded = vec![b'\n'; 500_000];
        let escaping_heavy = vec![b'\n'; MAX_RETAINED_REVIEW_ENVELOPE_BYTES / 2];
        let input = |payload| RetainedReviewEnvelopeInput {
            tenant: "tenant-envelope-boundary",
            project: &project,
            review_workspace: &workspace,
            expected_registry_generation: [0xab; 32],
            work_session_id: &work_session,
            expected_work_session_revision: revision,
            provider: "jcode",
            provider_session_id: "provider-session-envelope-boundary",
            expected_provider_session_revision: revision,
            payload,
        };

        assert!(retained_review_envelope(input(&safely_bounded)).is_ok());
        assert_eq!(
            retained_review_envelope(input(&escaping_heavy))
                .unwrap_err()
                .category(),
            "retained_review_envelope_size"
        );
    }
}
